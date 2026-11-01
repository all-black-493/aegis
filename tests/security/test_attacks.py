import io
import logging
import os
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import errors
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from aegis.apps.api.app import create_app
from aegis.apps.api.context import ApiContext
from aegis.audit.events import Source
from aegis.audit.recorder import AuditRecorder
from aegis.authorization.access import ActorContext
from aegis.authorization.catalog import Action, IdentityKind, ResourceType, Role
from aegis.authorization.contract import Effect, SecurityDecision, Stage
from aegis.config.logs import Redactor, configure_logging
from aegis.config.settings import (
    CommonSettings,
    DatabaseRole,
    DatabaseSettings,
    Environment,
    LogLevel,
    WorkerSettings,
    load_database_settings,
    load_token_pepper,
)
from aegis.identity.admin import IdentityAdministration
from aegis.jobs.handlers import HandlerContext
from aegis.jobs.repository import create_job
from aegis.jobs.worker import Settled, Worker
from aegis.policy.rules import MAX_JOB_ATTEMPTS
from aegis.policy.version import CURRENT_POLICY
from aegis.tasks.repository import NewTask, get_task, insert_task, record_decision, transaction_time
from aegis.tasks.service import Submission, TaskService
from aegis.tasks.states import TaskKind, TaskState
from aegis.tasks.transitions import PolicyRef, Transition, apply_transition

PEPPER = load_token_pepper(os.environ)
RECORDER = AuditRecorder(Redactor([PEPPER.reveal()]))
FAST = WorkerSettings(
    poll_seconds=0.05,
    lease_seconds=10,
    heartbeat_seconds=0.1,
    shutdown_grace_seconds=0.3,
    max_attempts=3,
)
POLICY = PolicyRef(CURRENT_POLICY.version, CURRENT_POLICY.digest)
S = TaskState
pytestmark = pytest.mark.usefixtures("isolated_jobs")

# The Phase 1 plan, §3.4: what the API and worker's database role may do, and nothing more.
TABLE_PRIVILEGES = {
    "alembic_version": {"SELECT"},
    "audit_events": set(),
    "credentials": {"SELECT"},
    "identities": {"SELECT"},
    "identity_roles": {"SELECT"},
    "jobs": {"SELECT"},
    "security_decisions": {"SELECT"},
    "task_state_transitions": {"SELECT"},
    "task_transition_rules": {"SELECT"},
    "tasks": {"SELECT"},
}
COLUMN_PRIVILEGES = {
    ("audit_events", "INSERT"): {
        "event_id",
        "event_type",
        "source",
        "outcome",
        "actor_id",
        "actor_kind",
        "target_type",
        "target_id",
        "task_id",
        "job_id",
        "decision_id",
        "request_id",
        "reason_code",
        "policy_version",
        "details",
    },
    ("jobs", "INSERT"): {"id", "task_id", "max_attempts", "run_after", "correlation_id"},
    ("jobs", "UPDATE"): {
        "state",
        "attempt",
        "run_after",
        "lease_owner",
        "lease_expires_at",
        "heartbeat_at",
        "last_error_code",
    },
    ("security_decisions", "INSERT"): {
        "id",
        "actor_id",
        "actor_kind",
        "actor_credential_id",
        "subject_id",
        "action",
        "resource_type",
        "resource_id",
        "resource_owner_id",
        "task_id",
        "effect",
        "stage",
        "reason_codes",
        "policy_version",
        "policy_digest",
        "request_id",
        "job_id",
        "job_attempt",
        "inputs",
    },
    ("task_state_transitions", "INSERT"): {
        "task_id",
        "to_version",
        "from_state",
        "to_state",
        "actor_id",
        "reason_code",
        "decision_id",
        "decision_action",
        "decision_effect",
        "decision_stage",
        "decision_decided_at",
        "job_id",
        "job_attempt",
        "request_id",
    },
    ("tasks", "INSERT"): {
        "id",
        "initiator_id",
        "owner_id",
        "submitted_credential_id",
        "kind",
        "input",
        "idempotency_key",
        "request_fingerprint",
    },
    ("tasks", "UPDATE"): {"state", "version", "cancel_requested_by", "result", "failure_code"},
}


@dataclass(frozen=True)
class Caller:
    name: str
    actor: ActorContext
    token: str

    @property
    def id(self) -> UUID:
        return self.actor.identity_id

    @property
    def credential_id(self) -> UUID:
        assert self.actor.credential_id is not None
        return self.actor.credential_id


class Spy:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, _input: Mapping[str, Any], _context: HandlerContext) -> Mapping[str, Any]:
        self.calls += 1
        return {}


@pytest.fixture
def log_output() -> Iterator[io.StringIO]:
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    stream = io.StringIO()
    configure_logging(CommonSettings(Environment.TEST, LogLevel.DEBUG), stream=stream)
    yield stream
    root.handlers[:] = handlers
    root.setLevel(level)


def _caller(owner_engine: Engine, *roles: Role) -> Caller:
    name = f"attack-{uuid4().hex[:12]}"
    with owner_engine.begin() as connection:
        administration = IdentityAdministration(connection, AuditRecorder(Redactor()))
        identity_id = administration.create_identity(name, IdentityKind.HUMAN, roles)
        issued = administration.issue_credential(name, PEPPER)
    actor = ActorContext(identity_id, IdentityKind.HUMAN, frozenset(roles), issued.credential_id)
    return Caller(name, actor, issued.token.reveal())


def _submit(
    app_engine: Engine, caller: Caller, kind: str = "noop", task_input: dict[str, Any] | None = None
) -> UUID:
    submission = Submission(kind, {} if task_input is None else task_input, f"key-{uuid4().hex}")
    return (
        TaskService(app_engine, RECORDER).submit(caller.actor, submission, uuid4().hex).task.task_id
    )


def _state(app_engine: Engine, task_id: UUID) -> TaskState:
    with app_engine.connect() as connection:
        task = get_task(connection, task_id)
    assert task is not None
    return task.state


def _refused(
    error: type[psycopg.Error], match: str, engine: Engine, sql: str, **params: Any
) -> None:
    with engine.connect() as connection, pytest.raises(DBAPIError) as excinfo:
        connection.execute(text(sql), params)
    assert isinstance(excinfo.value.orig, error), excinfo.value.orig
    assert match in str(excinfo.value.orig)


def _forge_queued_task(app_engine: Engine, caller: Caller) -> UUID:
    # Everything a holder of the aegis_app password could write: a task, a fabricated allow
    # decision that satisfies every database rule, its history row and a job.
    with app_engine.begin() as connection:
        task = insert_task(
            connection,
            NewTask(
                task_id=uuid4(),
                initiator_id=caller.id,
                submitted_credential_id=caller.credential_id,
                kind=TaskKind.NOOP,
                input={},
                idempotency_key=f"forged-{uuid4().hex}",
                request_fingerprint="0" * 64,
            ),
        )
        decision = SecurityDecision(
            decision_id=uuid4(),
            decided_at=transaction_time(connection),
            actor_id=caller.id,
            actor_kind=IdentityKind.HUMAN,
            actor_credential_id=caller.credential_id,
            subject_id=caller.id,
            action=Action.TASK_SUBMIT,
            resource_type=ResourceType.TASK,
            resource_id=str(task.task_id),
            resource_owner_id=caller.id,
            task_id=task.task_id,
            effect=Effect.ALLOW,
            stage=Stage.POLICY,
            reason_codes=("forged",),
            policy_version=POLICY.version,
            policy_digest=POLICY.digest,
        )
        record_decision(connection, decision)
        transition = Transition(
            task_id=task.task_id,
            expected_state=S.CREATED,
            expected_version=0,
            target=S.QUEUED,
            actor_id=caller.id,
            actor_kind=IdentityKind.HUMAN,
            source=Source.API,
            reason_code="forged",
            decision=decision,
        )
        apply_transition(connection, transition, POLICY, RECORDER)
        create_job(connection, task.task_id, max_attempts=MAX_JOB_ATTEMPTS, correlation_id=None)
    return task.task_id


def test_the_application_role_holds_exactly_the_planned_privileges(owner_engine: Engine) -> None:
    with owner_engine.connect() as connection:
        tables = connection.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'aegis'")
        ).scalars()
        held = {
            table: {
                privilege
                for privilege in (
                    "SELECT",
                    "INSERT",
                    "UPDATE",
                    "DELETE",
                    "TRUNCATE",
                    "REFERENCES",
                    "TRIGGER",
                )
                if connection.execute(
                    text("SELECT has_table_privilege('aegis_app', :table, :privilege)"),
                    {"table": f"aegis.{table}", "privilege": privilege},
                ).scalar_one()
            }
            for table in tables
        }
        columns: dict[tuple[str, str], set[str]] = {}
        for table, column, privilege in connection.execute(
            text(
                "SELECT table_name, column_name, privilege_type"
                " FROM information_schema.column_privileges"
                " WHERE grantee = 'aegis_app' AND table_schema = 'aegis'"
                " AND privilege_type IN ('INSERT', 'UPDATE', 'REFERENCES')"
            )
        ):
            columns.setdefault((table, privilege), set()).add(column)
        functions = set(
            connection.execute(
                text(
                    "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
                    " WHERE n.nspname = 'aegis'"
                    " AND has_function_privilege('aegis_app', p.oid, 'EXECUTE')"
                )
            ).scalars()
        )
        role = connection.execute(
            text(
                "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication,"
                " has_schema_privilege('aegis_app', 'aegis', 'CREATE') AS creates,"
                " (SELECT count(*) FROM pg_class WHERE relowner = r.oid) AS owned"
                " FROM pg_roles r WHERE rolname = 'aegis_app'"
            )
        ).one()

    assert held == TABLE_PRIVILEGES
    assert columns == COLUMN_PRIVILEGES
    assert functions == {"valid_reason_codes"}
    assert tuple(role) == (False, False, False, False, False, False, 0)


def test_approval_cannot_be_bypassed_with_application_credentials(
    app_engine: Engine, owner_engine: Engine
) -> None:
    caller = _caller(owner_engine, Role.OPERATOR)
    task_id = _submit(app_engine, caller, "wait", {"seconds": 60})
    assert _state(app_engine, task_id) is S.AWAITING_APPROVAL

    _refused(
        errors.RaiseException,
        "illegal task transition from awaiting_approval to queued",
        app_engine,
        "UPDATE aegis.tasks SET state = 'queued', version = version + 1 WHERE id = :id",
        id=task_id,
    )
    _refused(
        errors.RaiseException,
        "no rule allows awaiting_approval to queued",
        app_engine,
        "INSERT INTO aegis.task_state_transitions (task_id, to_version, from_state, to_state,"
        " actor_id, reason_code) VALUES (:id, 2, 'awaiting_approval', 'queued', :actor, 'forged')",
        id=task_id,
        actor=caller.id,
    )
    with app_engine.begin() as connection:
        create_job(connection, task_id, max_attempts=3, correlation_id=None)

    assert Worker(app_engine, RECORDER, FAST).claim() is None
    assert _state(app_engine, task_id) is S.AWAITING_APPROVAL


@pytest.mark.parametrize(
    ("change", "reason"),
    [("disable", "initiator_disabled"), ("auditor", "initiator_not_authorized")],
)
def test_a_forged_task_still_faces_the_workers_own_checks(
    app_engine: Engine, owner_engine: Engine, change: str, reason: str
) -> None:
    caller = _caller(owner_engine, Role.AUDITOR if change == "auditor" else Role.OPERATOR)
    if change == "disable":
        with owner_engine.begin() as connection:
            IdentityAdministration(connection, RECORDER).disable_identity(caller.name)
    task_id = _forge_queued_task(app_engine, caller)
    spy = Spy()

    outcome = Worker(app_engine, RECORDER, FAST, handlers=dict.fromkeys(TaskKind, spy)).claim()

    assert isinstance(outcome, Settled)
    assert (outcome.task.task_id, outcome.task.state) == (task_id, S.FAILED)
    assert outcome.task.failure_code == reason
    assert spy.calls == 0


def test_unregistered_kinds_cannot_be_stored(app_engine: Engine, owner_engine: Engine) -> None:
    caller = _caller(owner_engine, Role.OPERATOR)

    _refused(
        errors.CheckViolation,
        "ck_tasks_kind",
        app_engine,
        "INSERT INTO aegis.tasks (id, initiator_id, owner_id, submitted_credential_id, kind, input,"
        " idempotency_key, request_fingerprint) VALUES (gen_random_uuid(), :id, :id, :credential,"
        " 'shell', '{\"command\": \"id\"}', 'forged-key-0001', repeat('0', 64))",
        id=caller.id,
        credential=caller.credential_id,
    )


def test_client_supplied_request_ids_are_ignored(app_engine: Engine, owner_engine: Engine) -> None:
    caller = _caller(owner_engine, Role.OPERATOR)
    chosen = "attacker-chosen-0001"
    app = create_app(ApiContext(app_engine, PEPPER, RECORDER), Environment.TEST)

    with TestClient(app) as client:
        response = client.post(
            "/v1/tasks",
            json={"kind": "noop", "input": {}},
            headers={
                "Authorization": f"Bearer {caller.token}",
                "Idempotency-Key": "request-id-key-0001",
                "X-Request-ID": chosen,
            },
        )

    assert response.status_code == 201
    assert response.headers["x-request-id"] != chosen
    with owner_engine.connect() as connection:
        mentions = connection.execute(
            text(
                "SELECT (SELECT count(*) FROM aegis.security_decisions WHERE request_id = :id)"
                " + (SELECT count(*) FROM aegis.audit_events WHERE request_id = :id)"
            ),
            {"id": chosen},
        ).scalar_one()
    assert mentions == 0


def test_no_credential_or_secret_is_stored_logged_or_returned(
    app_engine: Engine,
    owner_engine: Engine,
    app_settings: DatabaseSettings,
    log_output: io.StringIO,
) -> None:
    operator, auditor = _caller(owner_engine, Role.OPERATOR), _caller(owner_engine, Role.AUDITOR)
    wrong = operator.token[:-1] + ("a" if operator.token[-1] != "a" else "b")
    app = create_app(ApiContext(app_engine, PEPPER, RECORDER), Environment.TEST)
    responses = []
    with TestClient(app) as client:
        for token, method, path, body in (
            (operator.token, "POST", "/v1/tasks", {"kind": "noop", "input": {}}),
            (operator.token, "POST", "/v1/tasks", {"kind": "wait", "input": {"seconds": 45}}),
            (operator.token, "POST", "/v1/tasks", {"kind": "shell", "input": {}}),
            (operator.token, "GET", "/v1/me", None),
            (operator.token, "GET", "/v1/tasks", None),
            (auditor.token, "GET", "/v1/tasks?scope=all", None),
            (wrong, "GET", "/v1/me", None),
        ):
            headers = {"Authorization": f"Bearer {token}", "Idempotency-Key": f"k-{uuid4().hex}"}
            responses.append(client.request(method, path, json=body, headers=headers))
        Worker(app_engine, RECORDER, FAST).step(threading.Event())

    owner = load_database_settings(os.environ, DatabaseRole.OWNER)
    admin = load_database_settings(os.environ, DatabaseRole.ADMIN)
    secrets = {
        "token": operator.token,
        "token secret": operator.token.rsplit("_", 1)[1],
        "auditor token secret": auditor.token.rsplit("_", 1)[1],
        "pepper": PEPPER.reveal(),
        "app password": app_settings.password.reveal(),
        "owner password": owner.password.reveal(),
        "admin password": admin.password.reveal(),
    }
    with owner_engine.connect() as connection:
        tables = (
            connection.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'aegis'"))
            .scalars()
            .all()
        )
        stored = {
            table: "\n".join(
                connection.execute(text(f"SELECT t::text FROM aegis.{table} AS t")).scalars()
            )
            for table in tables
        }

    assert [r.status_code for r in responses] == [201, 201, 403, 200, 200, 200, 401]
    for name, secret in secrets.items():
        for table, content in stored.items():
            assert secret not in content, f"{name} stored in aegis.{table}"
        assert secret not in log_output.getvalue(), f"{name} logged"
        assert not any(secret in r.text for r in responses), f"{name} returned"
    assert "auth.failed" in stored["audit_events"]
    assert '"path": "/v1/tasks"' in log_output.getvalue()

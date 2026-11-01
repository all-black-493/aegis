from collections.abc import Iterator
from dataclasses import dataclass, replace
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Connection, Engine, select, text

from aegis.audit.events import Source
from aegis.audit.recorder import AuditRecorder
from aegis.audit.schema import audit_events
from aegis.authorization.access import ActorContext
from aegis.authorization.catalog import IdentityKind, Role
from aegis.authorization.contract import DecisionMismatchError, Effect, Stage
from aegis.config.logs import Redactor
from aegis.config.settings import Secret
from aegis.identity.admin import IdentityAdministration
from aegis.identity.schema import SYSTEM_WORKER_ID
from aegis.jobs.repository import claim, create_job
from aegis.policy.rules import ACTIVE_TASK_QUOTA, Outcome
from aegis.policy.service import Decided, DecisionService, ReplayError
from aegis.policy.version import CURRENT_POLICY
from aegis.tasks.repository import NewTask, TaskRecord, insert_task
from aegis.tasks.schema import security_decisions
from aegis.tasks.states import TaskKind, TaskState
from aegis.tasks.transitions import (
    JobRef,
    Transition,
    apply_transition,
)

RECORDER = AuditRecorder(Redactor())
SERVICE = DecisionService(RECORDER)
S = TaskState


@dataclass(frozen=True)
class Person:
    name: str
    actor: ActorContext


def _person(owner_engine: Engine, *roles: Role) -> Person:
    name = f"policy-{uuid4().hex[:12]}"
    with owner_engine.begin() as connection:
        administration = IdentityAdministration(connection, AuditRecorder(Redactor()))
        identity_id = administration.create_identity(name, IdentityKind.HUMAN, roles)
        issued = administration.issue_credential(name, Secret("p" * 32))
    return Person(
        name, ActorContext(identity_id, IdentityKind.HUMAN, frozenset(roles), issued.credential_id)
    )


@pytest.fixture
def operator(owner_engine: Engine) -> Person:
    return _person(owner_engine, Role.OPERATOR)


@pytest.fixture
def app_tx(app_engine: Engine) -> Iterator[Connection]:
    with app_engine.connect() as connection:
        transaction = connection.begin()
        yield connection
        if transaction.is_active:
            transaction.rollback()


def _submit(
    connection: Connection,
    person: Person,
    kind: str = "noop",
    task_input: Any = None,
    service: DecisionService = SERVICE,
) -> tuple[Decided, TaskRecord | None]:
    task_id = uuid4()
    task_input = {} if task_input is None else task_input
    decided = service.submission(connection, person.actor, task_id, kind, task_input)
    if decided.decision.effect is Effect.DENY:
        service.record(connection, decided)
        return decided, None
    task = insert_task(
        connection,
        NewTask(
            task_id=task_id,
            initiator_id=person.actor.identity_id,
            submitted_credential_id=person.actor.credential_id or uuid4(),
            kind=TaskKind(kind),
            input=task_input,
            idempotency_key=f"key-{uuid4().hex}",
            request_fingerprint="0" * 64,
        ),
    )
    service.record(connection, decided)
    target = S.QUEUED if decided.decision.effect is Effect.ALLOW else S.AWAITING_APPROVAL
    return decided, _apply(connection, task, target, decided, service=service)


def _apply(
    connection: Connection,
    task: TaskRecord,
    target: TaskState,
    decided: Decided,
    job: JobRef | None = None,
    service: DecisionService = SERVICE,
) -> TaskRecord:
    worker = job is not None
    return apply_transition(
        connection,
        Transition(
            task_id=task.task_id,
            expected_state=task.state,
            expected_version=task.version,
            target=target,
            actor_id=SYSTEM_WORKER_ID if worker else task.initiator_id,
            actor_kind=IdentityKind.SYSTEM if worker else IdentityKind.HUMAN,
            source=Source.WORKER if worker else Source.API,
            reason_code=decided.decision.reason_codes[0],
            decision=decided.decision,
            job=job,
            failure_code=decided.decision.reason_codes[0] if target is S.FAILED else None,
        ),
        service.policy,
        RECORDER,
    )


def _job(connection: Connection, task: TaskRecord) -> JobRef:
    job = claim(
        connection,
        create_job(connection, task.task_id, max_attempts=3, correlation_id=None),
        "test-worker",
        60,
    )
    assert job is not None
    return job.ref


def _queued(app_engine: Engine, person: Person) -> TaskRecord:
    with app_engine.begin() as connection:
        _, task = _submit(connection, person)
    assert task is not None
    return task


def _saved(connection: Connection, decision_id: UUID) -> dict[str, Any]:
    row = (
        connection.execute(select(security_decisions).where(security_decisions.c.id == decision_id))
        .mappings()
        .one()
    )
    return dict(row)


def test_an_allowed_submission_is_saved_with_its_inputs_and_audited(
    app_engine: Engine, owner_engine: Engine, operator: Person
) -> None:
    with app_engine.begin() as connection:
        decided, task = _submit(connection, operator)

    with owner_engine.connect() as connection:
        saved = _saved(connection, decided.decision.decision_id)
        audited = connection.execute(
            select(audit_events.c.details).where(
                audit_events.c.decision_id == decided.decision.decision_id,
                audit_events.c.event_type == "security.decision",
            )
        ).scalar_one()
    assert task is not None
    assert task.state is S.QUEUED
    assert (saved["effect"], saved["stage"], saved["reason_codes"]) == (
        "allow",
        "policy",
        ["submission_allowed"],
    )
    assert (saved["policy_version"], saved["policy_digest"]) == (
        CURRENT_POLICY.version,
        CURRENT_POLICY.digest,
    )
    assert saved["inputs"]["submission"]["task"] == {"kind": "noop", "input": {}, "input_bytes": 2}
    assert audited == {"action": "task.submit", "effect": "allow", "stage": "policy"}


def test_a_denied_submission_is_saved_without_a_task(
    app_tx: Connection, owner_engine: Engine
) -> None:
    auditor = _person(owner_engine, Role.AUDITOR)

    decided, task = _submit(app_tx, auditor)

    saved = _saved(app_tx, decided.decision.decision_id)
    assert task is None
    assert (saved["effect"], saved["stage"], saved["task_id"]) == ("deny", "authorization", None)
    assert saved["reason_codes"] == ["missing_permission"]


def test_approval_required_never_leads_to_queued(app_tx: Connection, operator: Person) -> None:
    decided, task = _submit(app_tx, operator, "wait", {"seconds": 120})

    assert decided.decision.effect is Effect.APPROVAL_REQUIRED
    assert task is not None
    assert task.state is S.AWAITING_APPROVAL

    task_id = uuid4()
    pending = SERVICE.submission(app_tx, operator.actor, task_id, "wait", {"seconds": 120})
    created = insert_task(
        app_tx,
        NewTask(
            task_id,
            operator.actor.identity_id,
            operator.actor.credential_id or uuid4(),
            TaskKind.WAIT,
            {"seconds": 120},
            f"key-{uuid4().hex}",
            "0" * 64,
        ),
    )
    SERVICE.record(app_tx, pending)
    with pytest.raises(DecisionMismatchError) as excinfo:
        _apply(app_tx, created, S.QUEUED, pending)
    assert "C3" in excinfo.value.rules


def test_the_active_task_quota_denies_further_submissions(
    app_tx: Connection, operator: Person
) -> None:
    for _ in range(ACTIVE_TASK_QUOTA):
        _submit(app_tx, operator)

    decided, task = _submit(app_tx, operator)

    assert task is None
    assert decided.decision.reason_codes == ("active_task_quota_exceeded",)


def test_evaluator_errors_are_denied_and_saved(app_tx: Connection, operator: Person) -> None:
    def broken(_facts: object) -> Outcome | None:
        raise RuntimeError("rule bug")

    faulty = DecisionService(RECORDER, replace(CURRENT_POLICY, submission_rules=(broken,)))

    decided, task = _submit(app_tx, operator, service=faulty)

    assert task is None
    assert _saved(app_tx, decided.decision.decision_id)["reason_codes"] == ["evaluation_error"]


def test_an_allowed_execution_runs_the_task(app_tx: Connection, operator: Person) -> None:
    _, task = _submit(app_tx, operator)
    assert task is not None
    job = _job(app_tx, task)

    decided = SERVICE.execution(app_tx, task, job)
    SERVICE.record(app_tx, decided)
    running = _apply(app_tx, task, S.RUNNING, decided, job)

    assert decided.decision.reason_codes == ("execution_allowed",)
    assert decided.decision.actor_id == SYSTEM_WORKER_ID
    assert decided.decision.subject_id == operator.actor.identity_id
    assert running.state is S.RUNNING


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("disable", "initiator_disabled"),
        ("revoke_role", "initiator_not_authorized"),
        ("revoke_credential", "submitting_credential_revoked"),
    ],
)
def test_execution_rules_e2_to_e4_fail_the_task(
    app_engine: Engine, owner_engine: Engine, operator: Person, change: str, reason: str
) -> None:
    task = _queued(app_engine, operator)
    with owner_engine.begin() as connection:
        administration = IdentityAdministration(connection, AuditRecorder(Redactor()))
        if change == "disable":
            administration.disable_identity(operator.name)
        elif change == "revoke_role":
            administration.revoke_role(operator.name, Role.OPERATOR)
        else:
            assert operator.actor.credential_id is not None
            administration.revoke_credential(operator.actor.credential_id)
    with app_engine.begin() as connection:
        job = _job(connection, task)
        decided = SERVICE.execution(connection, task, job)
        SERVICE.record(connection, decided)
        failed = _apply(connection, task, S.FAILED, decided, job)

    assert decided.decision.effect is Effect.DENY
    assert decided.decision.stage is Stage.POLICY
    assert decided.decision.reason_codes == (reason,)
    assert failed.state is S.FAILED


def test_an_executor_without_the_worker_role_is_refused(
    app_engine: Engine, owner_engine: Engine, operator: Person
) -> None:
    task = _queued(app_engine, operator)

    with owner_engine.connect() as connection:
        connection.execute(
            text("DELETE FROM aegis.identity_roles WHERE identity_id = :id"),
            {"id": SYSTEM_WORKER_ID},
        )
        decided = SERVICE.execution(connection, task, JobRef(uuid4(), 1))
        connection.rollback()

    assert (decided.decision.effect, decided.decision.stage) == (Effect.DENY, Stage.AUTHORIZATION)
    assert decided.decision.reason_codes == ("executor_not_authorized",)


def test_cancellation_decisions_are_saved_whatever_their_effect(
    app_tx: Connection, owner_engine: Engine, operator: Person
) -> None:
    _, task = _submit(app_tx, operator)
    assert task is not None
    stranger = _person(owner_engine, Role.OPERATOR)

    denied = SERVICE.cancellation(app_tx, stranger.actor, task)
    SERVICE.record(app_tx, denied)
    allowed = SERVICE.cancellation(app_tx, operator.actor, task)
    SERVICE.record(app_tx, allowed)
    cancelled = _apply(app_tx, task, S.CANCELLED, allowed)

    assert (denied.decision.effect, denied.decision.reason_codes) == (
        Effect.DENY,
        ("missing_permission",),
    )
    assert denied.decision.subject_id == operator.actor.identity_id
    assert cancelled.state is S.CANCELLED


def test_saved_decisions_replay_identically(
    app_tx: Connection, owner_engine: Engine, operator: Person
) -> None:
    auditor = _person(owner_engine, Role.AUDITOR)
    decisions = [
        _submit(app_tx, operator)[0],
        _submit(app_tx, operator, "wait", {"seconds": 45})[0],
        _submit(app_tx, operator, "wait", {"seconds": "soon"})[0],
        _submit(app_tx, operator, "shell", {"command": "id"})[0],
        _submit(app_tx, operator, "noop", {"pad": "x" * 20_000})[0],
        _submit(app_tx, auditor)[0],
    ]
    _, task = _submit(app_tx, operator)
    assert task is not None
    execution = SERVICE.execution(app_tx, task, _job(app_tx, task))
    SERVICE.record(app_tx, execution)

    for decided in [*decisions, execution]:
        saved, replayed = SERVICE.replay(app_tx, decided.decision.decision_id)
        assert replayed == saved


def test_replay_refuses_decisions_from_another_policy(app_tx: Connection, operator: Person) -> None:
    decided, _ = _submit(app_tx, operator)
    newer = DecisionService(RECORDER, replace(CURRENT_POLICY, version="later", digest="b" * 64))

    with pytest.raises(ReplayError):
        newer.replay(app_tx, decided.decision.decision_id)

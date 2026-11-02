import threading
import time
from collections.abc import Callable, Iterator
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, select, text
from sqlalchemy.exc import OperationalError

from aegis.apps.api.app import create_app
from aegis.apps.api.context import ApiContext
from aegis.audit.events import AuditEvent, AuditEventType, Source
from aegis.audit.recorder import AuditRecorder
from aegis.authorization.catalog import Action, IdentityKind, ResourceType, Role
from aegis.authorization.contract import (
    DecisionRequirement,
    Effect,
    SecurityDecision,
    Stage,
    TaskRef,
    require_consistent,
)
from aegis.config.logs import Redactor
from aegis.config.settings import Environment
from aegis.identity.admin import IdentityAdministration
from aegis.identity.schema import SYSTEM_WORKER_ID
from aegis.jobs.repository import claim, lock_job
from aegis.jobs.schema import jobs
from aegis.policy.rules import ACTIVE_TASK_QUOTA, MAX_INPUT_BYTES, input_bytes
from aegis.policy.service import SUBMISSION_LOCK, DecisionService
from aegis.policy.version import CURRENT_POLICY
from aegis.tasks.repository import get_task
from aegis.tasks.schema import security_decisions, task_state_transitions
from aegis.tasks.service import IdempotencyConflictError, Submission, Submitted, TaskService
from aegis.tasks.states import TaskState
from aegis.tasks.transitions import JobRef, Transition, apply_transition
from tests.fixtures import records
from tests.fixtures.services import PEPPER, RECORDER, Caller, make_caller

DECISIONS = DecisionService(RECORDER)
S = TaskState


class FailingOn(AuditRecorder):
    def __init__(self, event_type: AuditEventType) -> None:
        super().__init__(Redactor())
        self.event_type = event_type

    def record(self, connection: Connection, event: AuditEvent) -> None:
        if event.event_type is self.event_type:
            raise OperationalError("INSERT INTO aegis.audit_events", {}, Exception("audit down"))
        super().record(connection, event)


def _app(engine: Engine, recorder: AuditRecorder = RECORDER) -> TestClient:
    app = create_app(ApiContext(engine, PEPPER, recorder), Environment.TEST)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def client(app_engine: Engine) -> Iterator[TestClient]:
    with _app(app_engine) as client:
        yield client


def _submit(
    client: TestClient,
    caller: Caller,
    kind: str = "noop",
    task_input: dict[str, Any] | None = None,
    key: str | None = None,
) -> Any:
    return client.post(
        "/v1/tasks",
        json={"kind": kind, "input": {} if task_input is None else task_input},
        headers={**caller.headers, "Idempotency-Key": key or f"key-{uuid4().hex}"},
    )


def _created(client: TestClient, caller: Caller, **kwargs: Any) -> UUID:
    response = _submit(client, caller, **kwargs)
    assert response.status_code == 201, response.text
    return UUID(response.json()["id"])


def _decisions(owner_engine: Engine, request_id: str) -> list[dict[str, Any]]:
    return records.rows(
        owner_engine,
        "SELECT * FROM aegis.security_decisions WHERE request_id = :request_id",
        request_id=request_id,
    )


def _events(owner_engine: Engine, request_id: str) -> list[str]:
    rows = records.rows(
        owner_engine,
        "SELECT event_type FROM aegis.audit_events WHERE request_id = :request_id ORDER BY id",
        request_id=request_id,
    )
    return [row["event_type"] for row in rows]


def _tasks_with_key(owner_engine: Engine, caller: Caller, key: str) -> list[dict[str, Any]]:
    return records.rows(
        owner_engine,
        "SELECT * FROM aegis.tasks WHERE initiator_id = :initiator AND idempotency_key = :key",
        initiator=caller.id,
        key=key,
    )


def _state(app_engine: Engine, task_id: UUID) -> TaskState:
    with app_engine.connect() as connection:
        task = get_task(connection, task_id)
    assert task is not None
    return task.state


def _run(app_engine: Engine, task_id: UUID) -> JobRef:
    with app_engine.begin() as connection:
        task = get_task(connection, task_id)
        assert task is not None
        pending = connection.execute(
            select(jobs.c.id).where(jobs.c.task_id == task_id, jobs.c.state == "pending")
        ).scalar_one()
        record = lock_job(connection, pending)
        assert record is not None
        claimed = claim(connection, record, "test-worker", 60)
        assert claimed is not None
        job = claimed.ref
        decided = DECISIONS.execution(connection, task, job)
        DECISIONS.record(connection, decided)
        apply_transition(
            connection,
            _worker_step(task_id, S.QUEUED, task.version, S.RUNNING, job, decided.decision),
            DECISIONS.policy,
            RECORDER,
        )
    return job


def _worker(app_engine: Engine, task_id: UUID, job: JobRef, target: TaskState) -> None:
    with app_engine.begin() as connection:
        task = get_task(connection, task_id)
        assert task is not None
        transition = _worker_step(task_id, task.state, task.version, target, job)
        apply_transition(connection, transition, DECISIONS.policy, RECORDER)


def _worker_step(
    task_id: UUID,
    source: TaskState,
    version: int,
    target: TaskState,
    job: JobRef,
    decision: SecurityDecision | None = None,
) -> Transition:
    return Transition(
        task_id=task_id,
        expected_state=source,
        expected_version=version,
        target=target,
        actor_id=SYSTEM_WORKER_ID,
        actor_kind=IdentityKind.SYSTEM,
        source=Source.WORKER,
        reason_code="test_step",
        decision=decision,
        job=job,
        result={} if target is S.SUCCEEDED else None,
    )


def _saved_decision(connection: Connection, decision_id: UUID) -> SecurityDecision:
    row = (
        connection.execute(select(security_decisions).where(security_decisions.c.id == decision_id))
        .mappings()
        .one()
    )
    return SecurityDecision(
        decision_id=row["id"],
        decided_at=row["decided_at"],
        actor_id=row["actor_id"],
        actor_kind=IdentityKind(row["actor_kind"]),
        actor_credential_id=row["actor_credential_id"],
        subject_id=row["subject_id"],
        action=Action(row["action"]),
        resource_type=ResourceType(row["resource_type"]),
        resource_id=row["resource_id"],
        resource_owner_id=row["resource_owner_id"],
        task_id=row["task_id"],
        effect=Effect(row["effect"]),
        stage=Stage(row["stage"]),
        reason_codes=tuple(row["reason_codes"]),
        policy_version=row["policy_version"],
        policy_digest=row["policy_digest"],
        request_id=row["request_id"],
        job_id=row["job_id"],
        job_attempt=row["job_attempt"],
    )


def test_a_submitted_task_is_queued_with_its_decision_history_and_audit(
    owner_engine: Engine, client: TestClient, operator: Caller
) -> None:
    response = _submit(client, operator, "wait", {"seconds": 5})

    assert response.status_code == 201
    body = response.json()
    assert response.headers["location"] == f"/v1/tasks/{body['id']}"
    assert (body["kind"], body["state"], body["version"]) == ("wait", "queued", 1)
    assert (body["owner_id"], body["input"]) == (str(operator.id), {"seconds": 5})
    request_id = response.headers["x-request-id"]
    [decision] = _decisions(owner_engine, request_id)
    assert (decision["action"], decision["effect"], decision["stage"]) == (
        "task.submit",
        "allow",
        "policy",
    )
    assert decision["reason_codes"] == ["submission_allowed"]
    assert str(decision["task_id"]) == body["id"]
    assert decision["actor_credential_id"] == operator.actor.credential_id
    assert _events(owner_engine, request_id) == [
        "security.decision",
        "task.created",
        "task.transitioned",
    ]
    assert operator.token not in response.text


def test_a_long_wait_is_created_awaiting_approval(
    client: TestClient, owner_engine: Engine, operator: Caller
) -> None:
    response = _submit(client, operator, "wait", {"seconds": 31})

    assert (response.status_code, response.json()["state"]) == (201, "awaiting_approval")
    [decision] = _decisions(owner_engine, response.headers["x-request-id"])
    assert (decision["effect"], decision["reason_codes"]) == (
        "approval_required",
        ["long_wait_needs_approval"],
    )


def test_a_repeated_request_replays_without_a_new_decision(
    client: TestClient, owner_engine: Engine, operator: Caller
) -> None:
    key = f"key-{uuid4().hex}"
    first = _submit(client, operator, "wait", {"seconds": 1}, key=key)

    again = _submit(client, operator, "wait", {"seconds": 1}, key=key)

    assert (first.status_code, again.status_code) == (201, 200)
    assert again.headers["idempotent-replayed"] == "true"
    assert "idempotent-replayed" not in first.headers
    assert again.json()["id"] == first.json()["id"]
    assert _decisions(owner_engine, again.headers["x-request-id"]) == []
    assert _events(owner_engine, again.headers["x-request-id"]) == []
    assert len(_tasks_with_key(owner_engine, operator, key)) == 1


def test_a_reused_key_with_a_different_body_conflicts_without_disclosure(
    client: TestClient, owner_engine: Engine, operator: Caller
) -> None:
    key = f"key-{uuid4().hex}"
    first = _submit(client, operator, "wait", {"seconds": 1}, key=key)

    conflict = _submit(client, operator, "wait", {"seconds": 2}, key=key)

    assert conflict.status_code == 409
    assert conflict.json() == {
        "type": "about:blank",
        "title": "Conflict",
        "status": 409,
        "code": "idempotency_key_conflict",
    }
    assert first.json()["id"] not in conflict.text
    assert _decisions(owner_engine, conflict.headers["x-request-id"]) == []


def test_keys_belong_to_each_initiator(
    client: TestClient, owner_engine: Engine, operator: Caller
) -> None:
    other = make_caller(owner_engine, Role.OPERATOR)
    key = f"key-{uuid4().hex}"

    mine = _submit(client, operator, key=key)
    theirs = _submit(client, other, "wait", {"seconds": 3}, key=key)

    assert (mine.status_code, theirs.status_code) == (201, 201)
    assert mine.json()["id"] != theirs.json()["id"]


def test_a_denied_submission_creates_nothing_and_leaves_the_key_unused(
    client: TestClient, owner_engine: Engine, operator: Caller
) -> None:
    key = f"key-{uuid4().hex}"

    denied = _submit(client, operator, "shell", {"command": "id"}, key=key)
    retried = _submit(client, operator, key=key)

    assert denied.status_code == 403
    assert denied.json()["code"] == "denied"
    assert denied.json()["reasons"] == ["kind_not_registered"]
    [decision] = _decisions(owner_engine, denied.headers["x-request-id"])
    assert (decision["effect"], decision["task_id"]) == ("deny", None)
    assert _events(owner_engine, denied.headers["x-request-id"]) == ["security.decision"]
    assert retried.status_code == 201
    assert len(_tasks_with_key(owner_engine, operator, key)) == 1


def test_auditors_cannot_create_tasks(client: TestClient, owner_engine: Engine) -> None:
    auditor = make_caller(owner_engine, Role.AUDITOR)
    key = f"key-{uuid4().hex}"

    response = _submit(client, auditor, key=key)

    assert (response.status_code, response.json()["reasons"]) == (403, ["missing_permission"])
    [decision] = _decisions(owner_engine, response.headers["x-request-id"])
    assert (decision["stage"], decision["effect"]) == ("authorization", "deny")
    assert _tasks_with_key(owner_engine, auditor, key) == []


def test_the_active_task_quota_is_enforced(client: TestClient, operator: Caller) -> None:
    for seconds in range(ACTIVE_TASK_QUOTA):
        _created(client, operator, kind="wait", task_input={"seconds": seconds * 10})

    response = _submit(client, operator)

    assert (response.status_code, response.json()["reasons"]) == (
        403,
        ["active_task_quota_exceeded"],
    )


def test_a_caller_who_lost_the_right_to_submit_cannot_replay(
    client: TestClient, owner_engine: Engine, operator: Caller
) -> None:
    key = f"key-{uuid4().hex}"
    _created(client, operator, key=key)
    with owner_engine.begin() as connection:
        IdentityAdministration(connection, RECORDER).revoke_role(operator.name, Role.OPERATOR)

    response = _submit(client, operator, key=key)

    assert (response.status_code, response.json()["reasons"]) == (403, ["missing_permission"])
    assert len(_tasks_with_key(owner_engine, operator, key)) == 1


@pytest.mark.parametrize("change", ["disable", "revoke"])
def test_disabled_identities_and_revoked_credentials_get_401(
    client: TestClient, owner_engine: Engine, operator: Caller, change: str
) -> None:
    with owner_engine.begin() as connection:
        administration = IdentityAdministration(connection, RECORDER)
        if change == "disable":
            administration.disable_identity(operator.name)
        else:
            assert operator.actor.credential_id is not None
            administration.revoke_credential(operator.actor.credential_id)

    key = f"key-{uuid4().hex}"
    response = _submit(client, operator, key=key)

    assert response.status_code == 401
    assert _tasks_with_key(owner_engine, operator, key) == []


def test_bad_keys_and_ownership_fields_are_refused_before_anything_is_saved(
    client: TestClient, owner_engine: Engine, operator: Caller
) -> None:
    key = f"key-{uuid4().hex}"
    body = {"kind": "noop", "input": {}}
    responses = [
        client.post("/v1/tasks", json=body, headers=operator.headers),
        client.post("/v1/tasks", json=body, headers={**operator.headers, "Idempotency-Key": "x"}),
        *(
            client.post(
                "/v1/tasks",
                json={**body, field: str(operator.id)},
                headers={**operator.headers, "Idempotency-Key": key},
            )
            for field in ("owner_id", "initiator_id")
        ),
    ]

    assert [r.status_code for r in responses] == [400, 400, 422, 422]
    assert [r.json()["code"] for r in responses[:2]] == [
        "idempotency_key_required",
        "idempotency_key_invalid",
    ]
    for response in responses:
        assert _decisions(owner_engine, response.headers["x-request-id"]) == []
    assert _tasks_with_key(owner_engine, operator, key) == []


def test_other_users_tasks_are_hidden(
    client: TestClient, owner_engine: Engine, operator: Caller
) -> None:
    other = make_caller(owner_engine, Role.OPERATOR)
    task_id = _created(client, operator)
    missing = uuid4()

    get = client.get(f"/v1/tasks/{task_id}", headers=other.headers)
    cancel = client.post(f"/v1/tasks/{task_id}/cancel", headers=other.headers)
    listed = client.get("/v1/tasks?limit=100", headers=other.headers)

    assert (get.status_code, cancel.status_code) == (404, 404)
    assert get.content == client.get(f"/v1/tasks/{missing}", headers=other.headers).content
    assert (
        cancel.content == client.post(f"/v1/tasks/{missing}/cancel", headers=other.headers).content
    )
    assert listed.status_code == 200
    assert str(task_id) not in listed.text
    for response, action in ((get, "task.read"), (cancel, "task.cancel")):
        [decision] = _decisions(owner_engine, response.headers["x-request-id"])
        assert (decision["action"], decision["effect"], decision["task_id"]) == (
            action,
            "deny",
            task_id,
        )
        assert decision["actor_id"] == other.id
    assert client.get(f"/v1/tasks/{task_id}", headers=operator.headers).status_code == 200


def test_listing_everything_requires_permission_and_is_audited(
    client: TestClient, owner_engine: Engine, operator: Caller
) -> None:
    auditor = make_caller(owner_engine, Role.AUDITOR)
    task_id = _created(client, operator)

    refused = client.get("/v1/tasks?scope=all", headers=operator.headers)
    allowed = client.get("/v1/tasks?scope=all&limit=5", headers=auditor.headers)
    own_only = client.get("/v1/tasks", headers=auditor.headers)

    assert (refused.status_code, refused.json()["reasons"]) == (403, ["missing_permission"])
    [denial] = _decisions(owner_engine, refused.headers["x-request-id"])
    assert (denial["action"], denial["resource_id"], denial["task_id"]) == (
        "task.list_all",
        None,
        None,
    )
    assert allowed.status_code == 200
    assert str(task_id) in [item["id"] for item in allowed.json()["items"]]
    [event] = records.rows(
        owner_engine,
        "SELECT actor_id, details FROM aegis.audit_events WHERE request_id = :request_id",
        request_id=allowed.headers["x-request-id"],
    )
    assert event == {"actor_id": auditor.id, "details": {"scope": "all"}}
    assert own_only.status_code == 403


def test_privileged_reads_of_one_task_are_audited(
    client: TestClient, owner_engine: Engine, operator: Caller
) -> None:
    auditor = make_caller(owner_engine, Role.AUDITOR)
    task_id = _created(client, operator)

    by_auditor = client.get(f"/v1/tasks/{task_id}", headers=auditor.headers)
    by_owner = client.get(f"/v1/tasks/{task_id}", headers=operator.headers)

    assert (by_auditor.status_code, by_owner.status_code) == (200, 200)
    assert by_auditor.json() == by_owner.json()
    [event] = records.rows(
        owner_engine,
        "SELECT event_type, task_id, details FROM aegis.audit_events"
        " WHERE request_id = :request_id",
        request_id=by_auditor.headers["x-request-id"],
    )
    assert event == {
        "event_type": "task.read_privileged",
        "task_id": task_id,
        "details": {"scope": "task"},
    }
    assert _events(owner_engine, by_owner.headers["x-request-id"]) == []


def test_lists_page_through_own_tasks_newest_first(
    client: TestClient, owner_engine: Engine
) -> None:
    caller = make_caller(owner_engine, Role.OPERATOR)
    created = {_created(client, caller, kind="wait", task_input={"seconds": n}) for n in range(5)}

    items: list[dict[str, Any]] = []
    cursor: str | None = None
    pages = 0
    while True:
        query = "/v1/tasks?limit=2" + (f"&cursor={cursor}" if cursor else "")
        page = client.get(query, headers=caller.headers).json()
        items.extend(page["items"])
        pages += 1
        cursor = page["next_cursor"]
        if cursor is None:
            break

    assert pages == 3
    assert {UUID(item["id"]) for item in items} == created
    assert len(items) == len(created)
    order = [(item["created_at"], item["id"]) for item in items]
    assert order == sorted(order, reverse=True)


@pytest.mark.parametrize("state", [S.QUEUED, S.AWAITING_APPROVAL, S.INTERRUPTED])
def test_cancelling_a_task_that_is_not_running(
    client: TestClient, app_engine: Engine, owner_engine: Engine, operator: Caller, state: S
) -> None:
    seconds = 60 if state is S.AWAITING_APPROVAL else 1
    task_id = _created(client, operator, kind="wait", task_input={"seconds": seconds})
    if state is S.INTERRUPTED:
        _worker(app_engine, task_id, _run(app_engine, task_id), S.INTERRUPTED)

    response = client.post(f"/v1/tasks/{task_id}/cancel", headers=operator.headers)

    assert response.status_code == 200
    assert response.json()["state"] == "cancelled"
    assert response.json()["finished_at"] is not None
    request_id = response.headers["x-request-id"]
    [decision] = _decisions(owner_engine, request_id)
    assert (decision["action"], decision["effect"], decision["stage"]) == (
        "task.cancel",
        "allow",
        "authorization",
    )
    assert _events(owner_engine, request_id) == ["security.decision", "task.transitioned"]


def test_cancelling_a_running_task_records_a_request(
    client: TestClient, app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task_id = _created(client, operator)
    _run(app_engine, task_id)

    first = client.post(f"/v1/tasks/{task_id}/cancel", headers=operator.headers)
    second = client.post(f"/v1/tasks/{task_id}/cancel", headers=operator.headers)

    assert (first.status_code, second.status_code) == (202, 202)
    assert first.json()["state"] == "running"
    assert first.json()["cancel_requested_at"] is not None
    assert second.json()["cancel_requested_at"] == first.json()["cancel_requested_at"]
    assert _events(owner_engine, first.headers["x-request-id"]) == [
        "security.decision",
        "task.cancel_requested",
    ]
    assert _events(owner_engine, second.headers["x-request-id"]) == ["security.decision"]
    [task] = records.rows(owner_engine, "SELECT * FROM aegis.tasks WHERE id = :id", id=task_id)
    assert task["cancel_requested_by"] == operator.id


@pytest.mark.parametrize("final", [S.SUCCEEDED, S.CANCELLED])
def test_finished_tasks_cannot_be_cancelled(
    client: TestClient, app_engine: Engine, operator: Caller, final: S
) -> None:
    task_id = _created(client, operator)
    if final is S.SUCCEEDED:
        _worker(app_engine, task_id, _run(app_engine, task_id), S.SUCCEEDED)
    else:
        client.post(f"/v1/tasks/{task_id}/cancel", headers=operator.headers)

    response = client.post(f"/v1/tasks/{task_id}/cancel", headers=operator.headers)

    assert (response.status_code, response.json()["code"]) == (409, "task_finished")
    assert _state(app_engine, task_id) is final


def test_who_may_cancel_someone_elses_task(
    client: TestClient, app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    auditor, admin = make_caller(owner_engine, Role.AUDITOR), make_caller(owner_engine, Role.ADMIN)
    task_id = _created(client, operator)

    by_auditor = client.post(f"/v1/tasks/{task_id}/cancel", headers=auditor.headers)
    by_admin = client.post(f"/v1/tasks/{task_id}/cancel", headers=admin.headers)

    assert (by_auditor.status_code, by_auditor.json()["reasons"]) == (403, ["missing_permission"])
    assert (by_admin.status_code, by_admin.json()["state"]) == (200, "cancelled")
    [decision] = _decisions(owner_engine, by_admin.headers["x-request-id"])
    assert (decision["actor_id"], decision["subject_id"], decision["reason_codes"]) == (
        admin.id,
        operator.id,
        ["permitted"],
    )


def test_saved_decisions_satisfy_c1_to_c9(
    client: TestClient, owner_engine: Engine, operator: Caller
) -> None:
    task_id = _created(client, operator)
    client.post(f"/v1/tasks/{task_id}/cancel", headers=operator.headers)
    expected = {
        S.QUEUED: (Action.TASK_SUBMIT, Effect.ALLOW, Stage.POLICY),
        S.CANCELLED: (Action.TASK_CANCEL, Effect.ALLOW, Stage.AUTHORIZATION),
    }

    with owner_engine.connect() as connection:
        history = connection.execute(
            select(task_state_transitions).where(task_state_transitions.c.task_id == task_id)
        ).mappings()
        checked = set()
        for row in history:
            target = S(row["to_state"])
            action, effect, stage = expected[target]
            decision = _saved_decision(connection, row["decision_id"])
            require_consistent(
                decision,
                DecisionRequirement(
                    task=TaskRef(task_id, operator.id, operator.id),
                    action=action,
                    effect=effect,
                    stage=stage,
                    actor_id=operator.id,
                    policy_version=CURRENT_POLICY.version,
                    policy_digest=CURRENT_POLICY.digest,
                    decided_at=row["occurred_at"],
                ),
            )
            assert decision.actor_credential_id == operator.actor.credential_id
            assert decision.request_id == row["request_id"]
            checked.add(target)

    assert checked == set(expected)


def _submit_failing_on(
    app_engine: Engine, owner_engine: Engine, event_type: AuditEventType, kind: str = "noop"
) -> tuple[Any, Caller, str]:
    caller = make_caller(owner_engine, Role.OPERATOR)
    key = f"key-{uuid4().hex}"
    with _app(app_engine, FailingOn(event_type)) as failing:
        response = _submit(failing, caller, kind, key=key)
    return response, caller, key


@pytest.mark.parametrize(
    "event_type",
    [
        AuditEventType.SECURITY_DECISION,
        AuditEventType.TASK_CREATED,
        AuditEventType.TASK_TRANSITIONED,
    ],
)
def test_a_failed_audit_write_gives_503_and_no_task(
    app_engine: Engine, owner_engine: Engine, event_type: AuditEventType
) -> None:
    response, caller, key = _submit_failing_on(app_engine, owner_engine, event_type)

    assert (response.status_code, response.json()["code"]) == (503, "service_unavailable")
    assert _tasks_with_key(owner_engine, caller, key) == []
    assert _decisions(owner_engine, response.headers["x-request-id"]) == []
    assert _events(owner_engine, response.headers["x-request-id"]) == []


def test_a_denial_that_cannot_be_saved_gives_503(app_engine: Engine, owner_engine: Engine) -> None:
    response, _, _ = _submit_failing_on(
        app_engine, owner_engine, AuditEventType.SECURITY_DECISION, kind="shell"
    )

    assert response.status_code == 503
    assert _decisions(owner_engine, response.headers["x-request-id"]) == []


@pytest.mark.parametrize(
    ("event_type", "route"),
    [
        (AuditEventType.TASK_TRANSITIONED, "cancel"),
        (AuditEventType.TASK_READ_PRIVILEGED, "read"),
        (AuditEventType.TASK_READ_PRIVILEGED, "list"),
    ],
)
def test_reads_and_cancellations_fail_closed_when_audit_fails(
    client: TestClient,
    app_engine: Engine,
    owner_engine: Engine,
    operator: Caller,
    event_type: AuditEventType,
    route: str,
) -> None:
    task_id = _created(client, operator)
    caller = operator if route == "cancel" else make_caller(owner_engine, Role.ADMIN)

    with _app(app_engine, FailingOn(event_type)) as failing:
        if route == "cancel":
            response = failing.post(f"/v1/tasks/{task_id}/cancel", headers=caller.headers)
        elif route == "read":
            response = failing.get(f"/v1/tasks/{task_id}", headers=caller.headers)
        else:
            response = failing.get("/v1/tasks?scope=all", headers=caller.headers)

    assert response.status_code == 503
    assert str(task_id) not in response.text
    assert _state(app_engine, task_id) is S.QUEUED
    assert _decisions(owner_engine, response.headers["x-request-id"]) == []


def _race(
    app_engine: Engine, caller: Caller, submissions: list[Submission]
) -> list[Submitted | Exception]:
    service = TaskService(app_engine, RECORDER)
    results: list[Submitted | Exception] = []

    def submit(submission: Submission) -> Callable[[], None]:
        def run() -> None:
            try:
                results.append(service.submit(caller.actor, submission, uuid4().hex))
            except Exception as error:
                results.append(error)

        return run

    threads = [threading.Thread(target=submit(s)) for s in submissions]
    # Holding the initiator's submission lock lines both requests up behind it, so they
    # genuinely overlap; releasing it lets them through one after the other.
    with app_engine.begin() as holder:
        DECISIONS.lock_submissions(holder, caller.id)
        for thread in threads:
            thread.start()
        _wait_for_waiters(app_engine, len(threads))
    for thread in threads:
        thread.join(timeout=30)
    return results


def _wait_for_waiters(app_engine: Engine, expected: int) -> None:
    deadline = time.monotonic() + 15
    with app_engine.connect() as connection:
        while True:
            waiting = connection.execute(
                text(
                    "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'"
                    " AND classid = :lock AND objsubid = 2 AND NOT granted"
                ),
                {"lock": SUBMISSION_LOCK},
            ).scalar_one()
            if waiting >= expected:
                return
            if time.monotonic() > deadline:
                pytest.fail(f"only {waiting} of {expected} submissions reached the lock")
            time.sleep(0.02)


def test_concurrent_identical_requests_create_one_task(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    key = f"key-{uuid4().hex}"
    submission = Submission("noop", {}, key)

    results = _race(app_engine, operator, [submission, submission])

    assert all(isinstance(result, Submitted) for result in results), results
    submitted = [result for result in results if isinstance(result, Submitted)]
    assert sorted(result.replayed for result in submitted) == [False, True]
    assert submitted[0].task.task_id == submitted[1].task.task_id
    assert len(_tasks_with_key(owner_engine, operator, key)) == 1


def test_concurrent_requests_with_different_bodies_create_one_task(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    key = f"key-{uuid4().hex}"
    submissions = [Submission("wait", {"seconds": n}, key) for n in (1, 2)]

    results = _race(app_engine, operator, submissions)

    assert sorted(type(result).__name__ for result in results) == [
        IdempotencyConflictError.__name__,
        Submitted.__name__,
    ]
    assert len(_tasks_with_key(owner_engine, operator, key)) == 1


def test_saved_read_and_list_denials_replay_identically(
    client: TestClient, app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    other = make_caller(owner_engine, Role.OPERATOR)
    task_id = _created(client, operator)
    responses = [
        client.get(f"/v1/tasks/{task_id}", headers=other.headers),
        client.get("/v1/tasks?scope=all", headers=other.headers),
    ]

    with app_engine.connect() as connection:
        for response in responses:
            [decision] = _decisions(owner_engine, response.headers["x-request-id"])
            saved, replayed = DECISIONS.replay(connection, decision["id"])
            assert saved == replayed
            assert saved.effect is Effect.DENY


def test_a_refused_input_at_the_size_limit_is_saved_with_its_decision(
    client: TestClient, owner_engine: Engine, operator: Caller
) -> None:
    # The densest JSON PostgreSQL widens: "," becomes ", " in jsonb's text form.
    task_input = {"ab": [0] * ((MAX_INPUT_BYTES - 8) // 2)}
    assert input_bytes(task_input) == MAX_INPUT_BYTES

    response = _submit(client, operator, "noop", task_input)

    assert (response.status_code, response.json()["reasons"]) == (403, ["input_invalid"])
    [decision] = _decisions(owner_engine, response.headers["x-request-id"])
    assert decision["inputs"]["submission"]["task"]["input"] == task_input

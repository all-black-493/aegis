import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import errors
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import DBAPIError

from aegis.apps.api.app import create_app
from aegis.apps.api.context import ApiContext
from aegis.audit.recorder import AuditRecorder
from aegis.authorization.access import ActorContext
from aegis.authorization.catalog import IdentityKind, Role
from aegis.authorization.contract import Effect
from aegis.config.logs import Redactor
from aegis.config.settings import (
    DatabaseRole,
    DatabaseSettings,
    Environment,
    WorkerSettings,
    load_database_settings,
    load_token_pepper,
)
from aegis.identity.admin import IdentityAdministration
from aegis.identity.schema import SYSTEM_CLI_ID, SYSTEM_WORKER_ID
from aegis.jobs import repository as jobs_repository
from aegis.jobs.handlers import REGISTRY, Handler, HandlerContext, RetryableError
from aegis.jobs.schema import jobs
from aegis.jobs.worker import Claim, Settled, Worker
from aegis.policy.rules import MAX_JOB_ATTEMPTS, Outcome
from aegis.policy.service import DecisionService
from aegis.policy.version import CURRENT_POLICY
from aegis.tasks.repository import TaskRecord, get_task
from aegis.tasks.service import Submission, TaskService
from aegis.tasks.states import TaskKind, TaskState
from aegis.tasks.transitions import JobRef

PEPPER = load_token_pepper(os.environ)
RECORDER = AuditRecorder(Redactor([PEPPER.reveal()]))
FAST = WorkerSettings(
    poll_seconds=0.05,
    lease_seconds=10,
    heartbeat_seconds=0.1,
    shutdown_grace_seconds=0.3,
    max_attempts=3,
)
S = TaskState
pytestmark = pytest.mark.usefixtures("isolated_jobs")


@dataclass(frozen=True)
class Caller:
    name: str
    actor: ActorContext
    token: str

    @property
    def id(self) -> UUID:
        return self.actor.identity_id


class Spy:
    def __init__(self, behaviour: Handler | None = None) -> None:
        self.calls = 0
        self._behaviour = behaviour or (lambda _input, _context: {})

    def __call__(self, task_input: Mapping[str, Any], context: HandlerContext) -> Mapping[str, Any]:
        self.calls += 1
        return self._behaviour(task_input, context)


@pytest.fixture
def operator(owner_engine: Engine) -> Caller:
    return _caller(owner_engine, Role.OPERATOR)


def _caller(owner_engine: Engine, *roles: Role) -> Caller:
    name = f"worker-test-{uuid4().hex[:12]}"
    with owner_engine.begin() as connection:
        administration = IdentityAdministration(connection, AuditRecorder(Redactor()))
        identity_id = administration.create_identity(name, IdentityKind.HUMAN, roles)
        issued = administration.issue_credential(name, PEPPER)
    actor = ActorContext(identity_id, IdentityKind.HUMAN, frozenset(roles), issued.credential_id)
    return Caller(name, actor, issued.token.reveal())


def _worker(
    app_engine: Engine,
    settings: WorkerSettings = FAST,
    handlers: Mapping[TaskKind, Handler] = REGISTRY,
    **kwargs: Any,
) -> Worker:
    return Worker(app_engine, RECORDER, settings, handlers=handlers, backoff=lambda _: 0, **kwargs)


def _every_kind(handler: Handler) -> dict[TaskKind, Handler]:
    return dict.fromkeys(TaskKind, handler)


def _submit(
    app_engine: Engine, caller: Caller, kind: str = "noop", task_input: dict[str, Any] | None = None
) -> TaskRecord:
    submission = Submission(kind, {} if task_input is None else task_input, f"key-{uuid4().hex}")
    return TaskService(app_engine, RECORDER).submit(caller.actor, submission, uuid4().hex).task


def _task(app_engine: Engine, task_id: UUID) -> TaskRecord:
    with app_engine.connect() as connection:
        task = get_task(connection, task_id)
    assert task is not None
    return task


def _rows(owner_engine: Engine, sql: str, **params: Any) -> list[dict[str, Any]]:
    with owner_engine.connect() as connection:
        return [dict(row) for row in connection.execute(text(sql), params).mappings()]


def _job(owner_engine: Engine, task_id: UUID) -> dict[str, Any]:
    rows = _rows(
        owner_engine,
        "SELECT * FROM aegis.jobs WHERE task_id = :id ORDER BY created_at DESC",
        id=task_id,
    )
    assert rows, "the task has no job"
    return rows[0]


def _history(owner_engine: Engine, task_id: UUID) -> list[tuple[Any, ...]]:
    rows = _rows(
        owner_engine,
        "SELECT from_state, to_state, actor_id, job_attempt, reason_code"
        " FROM aegis.task_state_transitions WHERE task_id = :id ORDER BY to_version",
        id=task_id,
    )
    return [tuple(row.values()) for row in rows]


def _events(owner_engine: Engine, task_id: UUID) -> list[str]:
    rows = _rows(
        owner_engine,
        "SELECT event_type FROM aegis.audit_events WHERE task_id = :id ORDER BY id",
        id=task_id,
    )
    return [row["event_type"] for row in rows]


def _execution_decisions(owner_engine: Engine, task_id: UUID) -> list[dict[str, Any]]:
    return _rows(
        owner_engine,
        "SELECT * FROM aegis.security_decisions WHERE task_id = :id AND action = 'task.execute'"
        " ORDER BY job_attempt",
        id=task_id,
    )


def _refused(
    error: type[psycopg.Error], match: str, engine: Engine, sql: str, **params: Any
) -> None:
    with engine.connect() as connection, pytest.raises(DBAPIError) as excinfo:
        connection.execute(text(sql), params)
    assert isinstance(excinfo.value.orig, error), excinfo.value.orig
    assert match in str(excinfo.value.orig)


def _wait_for(condition: Callable[[], bool], timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            pytest.fail(f"timed out waiting for {what}")
        time.sleep(0.05)


def _claimed(worker: Worker) -> Claim:
    outcome = worker.claim()
    assert isinstance(outcome, Claim), outcome
    return outcome


def _in_thread(target: Callable[..., None], *args: Any) -> threading.Thread:
    thread = threading.Thread(target=target, args=args, daemon=True)
    thread.start()
    return thread


def test_a_submitted_task_runs_to_succeeded_with_a_complete_audit_chain(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    app = create_app(ApiContext(app_engine, PEPPER, RECORDER), Environment.TEST)
    with TestClient(app) as client:
        submitted = client.post(
            "/v1/tasks",
            json={"kind": "wait", "input": {"seconds": 0}},
            headers={"Authorization": f"Bearer {operator.token}", "Idempotency-Key": "chain-0001"},
        )
        task_id = UUID(submitted.json()["id"])

        assert _worker(app_engine).step(threading.Event()) is True

        shown = client.get(
            f"/v1/tasks/{task_id}", headers={"Authorization": f"Bearer {operator.token}"}
        )

    assert (shown.json()["state"], shown.json()["result"]) == ("succeeded", {"waited_seconds": 0})
    assert _history(owner_engine, task_id) == [
        ("created", "queued", operator.id, None, "submission_allowed"),
        ("queued", "running", SYSTEM_WORKER_ID, 1, "execution_allowed"),
        ("running", "succeeded", SYSTEM_WORKER_ID, 1, "completed"),
    ]
    assert _events(owner_engine, task_id) == [
        "security.decision",
        "task.created",
        "task.transitioned",
        "security.decision",
        "task.transitioned",
        "task.transitioned",
    ]
    [execution] = _execution_decisions(owner_engine, task_id)
    assert (execution["actor_id"], execution["actor_kind"], execution["subject_id"]) == (
        SYSTEM_WORKER_ID,
        "system",
        operator.id,
    )
    assert (execution["actor_credential_id"], execution["job_attempt"]) == (None, 1)
    job = _job(owner_engine, task_id)
    assert (job["state"], job["attempt"], job["last_error_code"]) == ("finished", 1, None)
    assert job["correlation_id"] == submitted.headers["x-request-id"]


def test_racing_workers_claim_a_job_exactly_once(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator)
    workers = [_worker(app_engine, owner=f"racer-{n}") for n in range(4)]
    barrier = threading.Barrier(len(workers), timeout=30)
    outcomes: list[object] = []

    def race(worker: Worker) -> None:
        barrier.wait()
        outcomes.append(worker.claim())

    threads = [_in_thread(race, worker) for worker in workers]
    for thread in threads:
        thread.join(30)

    claims = [outcome for outcome in outcomes if isinstance(outcome, Claim)]
    assert len(claims) == 1
    assert outcomes.count(None) == len(workers) - 1
    job = _job(owner_engine, task.task_id)
    assert (job["state"], job["attempt"]) == ("running", 1)
    assert job["lease_owner"] in {worker.owner for worker in workers}


def test_a_stale_worker_cannot_heartbeat_complete_or_write_history(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator)
    spy = Spy()
    stale = _worker(app_engine, replace(FAST, lease_seconds=0.5), _every_kind(spy), owner="stale")
    claim = _claimed(stale)
    time.sleep(0.7)

    _refused(
        errors.RaiseException,
        "expired lease cannot be renewed",
        app_engine,
        "UPDATE aegis.jobs SET lease_expires_at = now() + interval '1 minute' WHERE id = :id",
        id=claim.job.job_id,
    )
    completion = (
        "INSERT INTO aegis.task_state_transitions (task_id, to_version, from_state, to_state,"
        " actor_id, reason_code, job_id, job_attempt) VALUES (:task, :version, 'running',"
        " 'succeeded', :actor, 'completed', :job, :attempt)"
    )
    params = {"task": task.task_id, "actor": SYSTEM_WORKER_ID, "job": claim.job.job_id}
    _refused(
        errors.RaiseException,
        "lease has expired",
        app_engine,
        completion,
        version=3,
        attempt=1,
        **params,
    )
    stale.execute(claim, threading.Event())
    assert spy.calls == 1
    assert _task(app_engine, task.task_id).state is S.RUNNING
    assert "job.fence_lost" in _events(owner_engine, task.task_id)

    fresh = _worker(app_engine)
    assert fresh.recover() == 1
    reclaimed = _claimed(fresh)

    assert reclaimed.job == JobRef(claim.job.job_id, 2)
    _refused(
        errors.RaiseException,
        "current attempt",
        app_engine,
        completion,
        version=6,
        attempt=1,
        **params,
    )
    with app_engine.begin() as connection:
        assert jobs_repository.renew(connection, claim.job, 10) is None
    stale.execute(claim, threading.Event())
    assert _task(app_engine, task.task_id).state is S.RUNNING
    assert _job(owner_engine, task.task_id)["attempt"] == 2


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE aegis.jobs SET attempt = attempt - 1 WHERE id = :id",
        "UPDATE aegis.jobs SET attempt = attempt + 1 WHERE id = :id",
        "UPDATE aegis.jobs SET state = 'pending', lease_owner = NULL, lease_expires_at = NULL,"
        " attempt = 0 WHERE id = :id",
    ],
)
def test_the_attempt_number_never_goes_down_or_jumps(
    app_engine: Engine, operator: Caller, statement: str
) -> None:
    _submit(app_engine, operator)
    claim = _claimed(_worker(app_engine))

    _refused(
        errors.RaiseException, "rises by exactly 1", app_engine, statement, id=claim.job.job_id
    )


def test_a_pending_job_cannot_skip_an_attempt(app_engine: Engine, operator: Caller) -> None:
    task = _submit(app_engine, operator)

    _refused(
        errors.RaiseException,
        "rises by exactly 1",
        app_engine,
        "UPDATE aegis.jobs SET state = 'running', attempt = 2, lease_owner = 'w',"
        " lease_expires_at = now() + interval '1 minute' WHERE task_id = :id",
        id=task.task_id,
    )


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("disable", "initiator_disabled"),
        ("revoke_role", "initiator_not_authorized"),
        ("revoke_credential", "submitting_credential_revoked"),
    ],
)
def test_initiator_changes_before_the_claim_fail_the_task_without_running_it(
    app_engine: Engine, owner_engine: Engine, operator: Caller, change: str, reason: str
) -> None:
    task = _submit(app_engine, operator)
    with owner_engine.begin() as connection:
        administration = IdentityAdministration(connection, RECORDER)
        if change == "disable":
            administration.disable_identity(operator.name)
        elif change == "revoke_role":
            administration.revoke_role(operator.name, Role.OPERATOR)
        else:
            assert operator.actor.credential_id is not None
            administration.revoke_credential(operator.actor.credential_id)
    spy = Spy()

    outcome = _worker(app_engine, handlers=_every_kind(spy)).claim()

    assert isinstance(outcome, Settled)
    assert (outcome.task.state, outcome.task.failure_code) == (S.FAILED, reason)
    assert spy.calls == 0
    [decision] = _execution_decisions(owner_engine, task.task_id)
    assert (decision["effect"], decision["reason_codes"]) == ("deny", [reason])
    assert (decision["actor_id"], decision["subject_id"]) == (SYSTEM_WORKER_ID, operator.id)
    job = _job(owner_engine, task.task_id)
    assert (job["state"], job["last_error_code"]) == ("finished", reason)
    assert _events(owner_engine, task.task_id)[-1] == "job.failed"


def test_an_executor_without_the_worker_role_fails_the_task(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator)
    spy = Spy()
    with owner_engine.begin() as connection:
        connection.execute(
            text("DELETE FROM aegis.identity_roles WHERE identity_id = :id"),
            {"id": SYSTEM_WORKER_ID},
        )
    try:
        outcome = _worker(app_engine, handlers=_every_kind(spy)).claim()
    finally:
        with owner_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO aegis.identity_roles (identity_id, role, granted_by)"
                    " VALUES (:id, 'worker', :cli)"
                ),
                {"id": SYSTEM_WORKER_ID, "cli": SYSTEM_CLI_ID},
            )

    assert isinstance(outcome, Settled)
    assert (outcome.task.state, outcome.task.failure_code) == (S.FAILED, "executor_not_authorized")
    assert spy.calls == 0
    [decision] = _execution_decisions(owner_engine, task.task_id)
    assert (decision["stage"], decision["effect"]) == ("authorization", "deny")


def test_approval_required_at_claim_holds_the_task(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator, "wait", {"seconds": 5})
    stricter = replace(
        CURRENT_POLICY,
        execution_rules=(lambda _facts: Outcome(Effect.APPROVAL_REQUIRED, "needs_review"),),
    )
    spy = Spy()

    outcome = _worker(
        app_engine, handlers=_every_kind(spy), decisions=DecisionService(RECORDER, stricter)
    ).claim()

    assert isinstance(outcome, Settled)
    assert outcome.task.state is S.AWAITING_APPROVAL
    assert spy.calls == 0
    job = _job(owner_engine, task.task_id)
    assert (job["state"], job["last_error_code"]) == ("finished", "approval_required")


def test_a_cancellation_requested_before_the_claim_cancels_the_task(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator)
    with app_engine.begin() as connection:
        connection.execute(
            text("UPDATE aegis.tasks SET cancel_requested_by = initiator_id WHERE id = :id"),
            {"id": task.task_id},
        )
    spy = Spy()

    outcome = _worker(app_engine, handlers=_every_kind(spy)).claim()

    assert isinstance(outcome, Settled)
    assert outcome.task.state is S.CANCELLED
    assert spy.calls == 0
    assert [row[:2] for row in _history(owner_engine, task.task_id)][-2:] == [
        ("queued", "running"),
        ("running", "cancelled"),
    ]


def test_cancellation_is_noticed_at_the_next_heartbeat(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator, "wait", {"seconds": 20})
    worker = _worker(app_engine)
    claim = _claimed(worker)
    started = time.monotonic()
    thread = _in_thread(worker.execute, claim, threading.Event())

    cancelled = TaskService(app_engine, RECORDER).cancel(operator.actor, task.task_id, uuid4().hex)
    thread.join(10)

    assert cancelled.pending
    assert not thread.is_alive()
    assert time.monotonic() - started < 5
    assert _task(app_engine, task.task_id).state is S.CANCELLED
    assert _history(owner_engine, task.task_id)[-1] == (
        "running",
        "cancelled",
        SYSTEM_WORKER_ID,
        1,
        "cancel_requested",
    )
    assert _job(owner_engine, task.task_id)["last_error_code"] == "cancelled"


def test_a_disabled_initiator_stops_a_running_task(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator, "wait", {"seconds": 20})
    worker = _worker(app_engine)
    claim = _claimed(worker)
    thread = _in_thread(worker.execute, claim, threading.Event())

    with owner_engine.begin() as connection:
        IdentityAdministration(connection, RECORDER).disable_identity(operator.name)
    thread.join(10)

    assert not thread.is_alive()
    final = _task(app_engine, task.task_id)
    assert (final.state, final.failure_code) == (S.FAILED, "initiator_disabled")


def test_shutdown_releases_the_job_for_another_attempt(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator, "wait", {"seconds": 20})
    worker = _worker(app_engine)
    stop = threading.Event()
    claim = _claimed(worker)
    thread = _in_thread(worker.execute, claim, stop)

    time.sleep(0.2)
    stop.set()
    thread.join(10)

    assert not thread.is_alive()
    assert _task(app_engine, task.task_id).state is S.QUEUED
    job = _job(owner_engine, task.task_id)
    assert (job["state"], job["attempt"], job["lease_owner"]) == ("pending", 1, None)
    assert [row[:2] for row in _history(owner_engine, task.task_id)][-2:] == [
        ("running", "interrupted"),
        ("interrupted", "queued"),
    ]
    assert [e for e in _events(owner_engine, task.task_id) if e.startswith("job.")] == [
        "job.interrupted",
        "job.retried",
    ]


def test_an_idle_worker_stops_promptly(app_engine: Engine) -> None:
    stop = threading.Event()
    thread = _in_thread(_worker(app_engine).run, stop)

    time.sleep(0.2)
    stop.set()
    thread.join(5)

    assert not thread.is_alive()


def test_retryable_failures_are_retried_until_attempts_run_out(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    def flaky(_input: Mapping[str, Any], _context: HandlerContext) -> Mapping[str, Any]:
        raise RetryableError("try again")

    task = _submit(app_engine, operator)
    spy = Spy(flaky)
    worker = _worker(app_engine, replace(FAST, max_attempts=2), _every_kind(spy))

    assert worker.step(threading.Event())
    assert _task(app_engine, task.task_id).state is S.QUEUED
    assert worker.step(threading.Event())

    final = _task(app_engine, task.task_id)
    assert (final.state, final.failure_code) == (S.FAILED, "attempts_exhausted")
    assert spy.calls == 2
    job = _job(owner_engine, task.task_id)
    assert (job["state"], job["attempt"], job["max_attempts"]) == ("finished", 2, MAX_JOB_ATTEMPTS)
    assert [row[:2] for row in _history(owner_engine, task.task_id)][1:] == [
        ("queued", "running"),
        ("running", "interrupted"),
        ("interrupted", "queued"),
        ("queued", "running"),
        ("running", "interrupted"),
        ("interrupted", "failed"),
    ]
    assert [e for e in _events(owner_engine, task.task_id) if e.startswith("job.")] == [
        "job.interrupted",
        "job.retried",
        "job.interrupted",
        "job.failed",
    ]


@pytest.mark.parametrize(
    ("behaviour", "code"),
    [
        ("raise", "handler_error"),
        ("nan", "invalid_result"),
        ("list", "invalid_result"),
    ],
)
def test_handler_errors_and_invalid_results_fail_without_retry(
    app_engine: Engine, operator: Caller, behaviour: str, code: str
) -> None:
    def broken(_input: Mapping[str, Any], _context: HandlerContext) -> Any:
        if behaviour == "raise":
            raise ValueError("bug")
        return {"x": float("nan")} if behaviour == "nan" else [1, 2]

    task = _submit(app_engine, operator)
    spy = Spy(broken)

    assert _worker(app_engine, handlers=_every_kind(spy)).step(threading.Event())

    final = _task(app_engine, task.task_id)
    assert (final.state, final.failure_code, spy.calls) == (S.FAILED, code, 1)


def test_recovery_cancels_a_running_task_whose_cancellation_was_requested(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator)
    _claimed(_worker(app_engine, replace(FAST, lease_seconds=0.5)))
    TaskService(app_engine, RECORDER).cancel(operator.actor, task.task_id, uuid4().hex)
    time.sleep(0.7)

    assert _worker(app_engine).recover() == 1

    assert _task(app_engine, task.task_id).state is S.CANCELLED
    assert _job(owner_engine, task.task_id)["last_error_code"] == "cancelled"


def test_cancelling_a_queued_task_closes_its_job(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator)

    TaskService(app_engine, RECORDER).cancel(operator.actor, task.task_id, uuid4().hex)

    job = _job(owner_engine, task.task_id)
    assert (job["state"], job["attempt"], job["last_error_code"]) == ("finished", 0, "cancelled")
    assert _worker(app_engine).claim() is None


def test_a_task_awaiting_approval_gets_no_job(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator, "wait", {"seconds": 60})

    assert task.state is S.AWAITING_APPROVAL
    assert (
        _rows(owner_engine, "SELECT id FROM aegis.jobs WHERE task_id = :id", id=task.task_id) == []
    )


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM aegis.jobs WHERE task_id = :id",
        "TRUNCATE aegis.jobs CASCADE",
        "UPDATE aegis.jobs SET task_id = task_id WHERE task_id = :id",
        "UPDATE aegis.jobs SET max_attempts = 10 WHERE task_id = :id",
        "UPDATE aegis.jobs SET correlation_id = 'x' WHERE task_id = :id",
        "INSERT INTO aegis.jobs (id, task_id, max_attempts, state, attempt)"
        " VALUES (gen_random_uuid(), :id, 3, 'running', 1)",
    ],
)
def test_the_application_role_cannot_change_a_jobs_fixed_data(
    app_engine: Engine, operator: Caller, statement: str
) -> None:
    task = _submit(app_engine, operator)

    _refused(
        errors.InsufficientPrivilege, "permission denied", app_engine, statement, id=task.task_id
    )


@pytest.mark.parametrize(
    ("error", "match", "statement"),
    [
        (errors.RaiseException, "never deleted", "DELETE FROM aegis.jobs WHERE task_id = :id"),
        (
            errors.RaiseException,
            "fixed columns",
            "UPDATE aegis.jobs SET max_attempts = 1 WHERE task_id = :id",
        ),
        (
            errors.RaiseException,
            "start pending at attempt 0",
            "INSERT INTO aegis.jobs (id, task_id, max_attempts, state, attempt)"
            " VALUES (gen_random_uuid(), :id, 3, 'running', 1)",
        ),
        (
            errors.CheckViolation,
            "ck_jobs_max_attempts",
            "INSERT INTO aegis.jobs (id, task_id, max_attempts)"
            " VALUES (gen_random_uuid(), :id, 11)",
        ),
        (
            errors.UniqueViolation,
            "uq_jobs_active_task_id",
            "INSERT INTO aegis.jobs (id, task_id, max_attempts) VALUES (gen_random_uuid(), :id, 3)",
        ),
    ],
)
def test_the_database_protects_jobs_from_every_role(
    app_engine: Engine,
    owner_engine: Engine,
    operator: Caller,
    error: type[psycopg.Error],
    match: str,
    statement: str,
) -> None:
    task = _submit(app_engine, operator)

    _refused(error, match, owner_engine, statement, id=task.task_id)


def test_a_finished_job_cannot_change(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator)
    assert _worker(app_engine).step(threading.Event())

    _refused(
        errors.RaiseException,
        "finished job cannot change",
        owner_engine,
        "UPDATE aegis.jobs SET last_error_code = 'x' WHERE task_id = :id",
        id=task.task_id,
    )


def _worker_environ(
    app_settings: DatabaseSettings, test_database: str, **extra: str
) -> dict[str, str]:
    return {
        **os.environ,
        "AEGIS_ENV": "production",
        "AEGIS_POSTGRES_DB": test_database,
        "AEGIS_WORKER_POLL_SECONDS": "1",
        **extra,
    }


def test_the_worker_process_runs_tasks_and_stops_on_sigterm(
    app_engine: Engine, test_database: str, app_settings: DatabaseSettings, operator: Caller
) -> None:
    process = subprocess.Popen(
        [sys.executable, "-m", "aegis.apps.worker"],
        env=_worker_environ(app_settings, test_database),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        task = _submit(app_engine, operator)
        _wait_for(lambda: _task(app_engine, task.task_id).state is S.SUCCEEDED, 20, "success")
    finally:
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=20)

    assert process.returncode == 0
    output = stdout + stderr
    for message in ("worker started", "succeeded", "worker stopped"):
        assert message in output
    owner = load_database_settings(os.environ, DatabaseRole.OWNER)
    for secret in (app_settings.password.reveal(), owner.password.reveal(), PEPPER.reveal()):
        assert secret not in output


def test_a_killed_workers_task_is_interrupted_retried_and_succeeds(
    app_engine: Engine,
    owner_engine: Engine,
    test_database: str,
    app_settings: DatabaseSettings,
    operator: Caller,
) -> None:
    environ = _worker_environ(
        app_settings,
        test_database,
        AEGIS_WORKER_LEASE_SECONDS="10",
        AEGIS_WORKER_HEARTBEAT_SECONDS="1",
    )
    victim = subprocess.Popen(
        [sys.executable, "-m", "aegis.apps.worker"],
        env=environ,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        task = _submit(app_engine, operator, "wait", {"seconds": 2})
        _wait_for(lambda: _task(app_engine, task.task_id).state is S.RUNNING, 20, "the claim")
    finally:
        victim.kill()
        victim.wait(10)
    stop = threading.Event()
    rescuer = _in_thread(_worker(app_engine).run, stop)
    try:
        _wait_for(lambda: _task(app_engine, task.task_id).state is S.SUCCEEDED, 40, "recovery")
    finally:
        stop.set()
        rescuer.join(10)

    assert victim.returncode == -signal.SIGKILL
    assert [row[:2] for row in _history(owner_engine, task.task_id)][1:] == [
        ("queued", "running"),
        ("running", "interrupted"),
        ("interrupted", "queued"),
        ("queued", "running"),
        ("running", "succeeded"),
    ]
    assert _history(owner_engine, task.task_id)[2][4] == "lease_expired"
    job = _job(owner_engine, task.task_id)
    assert (job["state"], job["attempt"]) == ("finished", 2)
    assert len(_execution_decisions(owner_engine, task.task_id)) == 2


def test_the_jobs_table_matches_the_policy_cap(app_engine: Engine, operator: Caller) -> None:
    task = _submit(app_engine, operator)
    with app_engine.connect() as connection:
        max_attempts = connection.execute(
            select(jobs.c.max_attempts).where(jobs.c.task_id == task.task_id)
        ).scalar_one()

    assert max_attempts == MAX_JOB_ATTEMPTS

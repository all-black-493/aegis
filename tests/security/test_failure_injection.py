import logging
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import replace
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, event
from sqlalchemy.exc import OperationalError

from aegis.apps.api.app import create_app
from aegis.apps.api.context import ApiContext
from aegis.audit.events import AuditEvent, AuditEventType
from aegis.audit.recorder import AuditRecorder
from aegis.config.logs import Redactor
from aegis.config.settings import DatabaseSettings, Environment, WorkerSettings
from aegis.db.admin import bootstrap, recreate_test_database
from aegis.db.engine import create_database_engine
from aegis.db.migrate import upgrade
from aegis.jobs.handlers import REGISTRY, HandlerContext
from aegis.jobs.worker import Settled, Worker
from aegis.policy.facts import ExecutionFacts, SubmissionFacts
from aegis.policy.rules import Outcome
from aegis.policy.service import DecisionService
from aegis.policy.version import CURRENT_POLICY
from aegis.tasks.repository import TaskRecord
from aegis.tasks.service import AccessDeniedError, Submission, TaskService
from aegis.tasks.states import TaskKind, TaskState
from tests.fixtures import records
from tests.fixtures.processes import unused_port
from tests.fixtures.services import FAST_WORKER, PEPPER, RECORDER, Caller

TOKEN = "aegis_pat_" + "a" * 26 + "_" + "b" * 52
S = TaskState
pytestmark = pytest.mark.usefixtures("isolated_jobs")


class Spy:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, task_input: Mapping[str, Any], context: HandlerContext) -> Mapping[str, Any]:
        self.calls += 1
        return REGISTRY[TaskKind.WAIT](task_input, context) if task_input else {}


class FailingWhen(AuditRecorder):
    def __init__(self, failing: Callable[[AuditEvent], bool]) -> None:
        super().__init__(Redactor())
        self._failing = failing

    def record(self, connection: Connection, event: AuditEvent) -> None:
        if self._failing(event):
            raise OperationalError("INSERT INTO aegis.audit_events", {}, Exception("audit down"))
        super().record(connection, event)


@pytest.fixture
def dead_engine(app_settings: DatabaseSettings) -> Iterator[Engine]:
    port = unused_port()
    engine = create_database_engine(
        replace(app_settings, port=port), application_name="aegis-tests"
    )
    yield engine
    engine.dispose()


def _submit(
    app_engine: Engine,
    caller: Caller,
    kind: str = "noop",
    task_input: dict[str, Any] | None = None,
    decisions: DecisionService | None = None,
) -> TaskRecord:
    submission = Submission(kind, {} if task_input is None else task_input, f"key-{uuid4().hex}")
    service = TaskService(app_engine, RECORDER, decisions)
    return service.submit(caller.actor, submission, uuid4().hex).task


def _worker(
    engine: Engine,
    recorder: AuditRecorder = RECORDER,
    settings: WorkerSettings = FAST_WORKER,
    **kwargs: Any,
) -> Worker:
    return Worker(engine, recorder, settings, backoff=lambda _: 0, **kwargs)


def _moves(owner_engine: Engine, task_id: UUID) -> list[tuple[str, str]]:
    rows = records.rows(
        owner_engine,
        "SELECT from_state, to_state FROM aegis.task_state_transitions WHERE task_id = :id"
        " ORDER BY to_version",
        id=task_id,
    )
    return [(row["from_state"], row["to_state"]) for row in rows]


def test_with_the_database_down_the_api_serves_no_task_request(dead_engine: Engine) -> None:
    app = create_app(ApiContext(dead_engine, PEPPER, RECORDER), Environment.TEST)
    headers = {"Authorization": f"Bearer {TOKEN}", "Idempotency-Key": "outage-key-0001"}
    task_id = uuid4()

    with TestClient(app, raise_server_exceptions=False) as client:
        responses = [
            client.post("/v1/tasks", json={"kind": "noop", "input": {}}, headers=headers),
            client.get("/v1/tasks", headers=headers),
            client.get(f"/v1/tasks/{task_id}", headers=headers),
            client.post(f"/v1/tasks/{task_id}/cancel", headers=headers),
            client.get("/health/ready"),
        ]
        live = client.get("/health/live")

    assert [response.status_code for response in responses] == [503] * len(responses)
    assert live.status_code == 200


def test_with_the_database_down_the_worker_waits_without_failing(
    dead_engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    worker = _worker(dead_engine)
    stop = threading.Event()

    with caplog.at_level(logging.ERROR, logger="aegis.worker"):
        assert worker.step(stop) is False
        thread = threading.Thread(target=worker.run, args=(stop,), daemon=True)
        thread.start()
        time.sleep(0.3)
        stop.set()
        thread.join(10)

    assert not thread.is_alive()
    assert "database unavailable" in caplog.text


def test_an_outage_during_a_run_discards_the_result_and_recovery_retries_the_task(
    app_engine: Engine, app_settings: DatabaseSettings, owner_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator, "wait", {"seconds": 2})
    outage = threading.Event()
    flaky = create_database_engine(app_settings, application_name="aegis-tests")

    @event.listens_for(flaky, "before_cursor_execute")
    def _drop(*_args: object) -> None:
        if outage.is_set():
            raise OperationalError("SELECT 1", {}, Exception("connection lost"))

    try:
        cut_off = _worker(
            flaky, settings=replace(FAST_WORKER, lease_seconds=1, heartbeat_seconds=0.2)
        )
        claimed = cut_off.claim()
        assert not isinstance(claimed, Settled)
        assert claimed is not None
        outage.set()
        started = time.monotonic()
        cut_off.execute(claimed, threading.Event())
        gave_up_after = time.monotonic() - started
    finally:
        flaky.dispose()

    assert gave_up_after < 2
    assert records.task(app_engine, task.task_id).state is S.RUNNING
    assert ("running", "succeeded") not in _moves(owner_engine, task.task_id)

    time.sleep(0.5)
    assert _worker(app_engine).step(threading.Event())

    assert records.task(app_engine, task.task_id).state is S.SUCCEEDED
    assert _moves(owner_engine, task.task_id)[2:] == [
        ("running", "interrupted"),
        ("interrupted", "queued"),
        ("queued", "running"),
        ("running", "succeeded"),
    ]
    assert records.latest_job(owner_engine, task.task_id)["attempt"] == 2


def test_an_audit_failure_at_claim_leaves_the_task_queued_and_unrun(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator)
    spy = Spy()
    failing = FailingWhen(lambda event: event.event_type is AuditEventType.SECURITY_DECISION)

    assert (
        _worker(app_engine, failing, handlers=dict.fromkeys(TaskKind, spy)).step(threading.Event())
        is False
    )

    assert spy.calls == 0
    assert records.task(app_engine, task.task_id).state is S.QUEUED
    job = records.latest_job(owner_engine, task.task_id)
    assert (job["state"], job["attempt"]) == ("pending", 0)
    assert (
        records.rows(
            owner_engine,
            "SELECT id FROM aegis.security_decisions"
            " WHERE task_id = :id AND action = 'task.execute'",
            id=task.task_id,
        )
        == []
    )

    assert _worker(app_engine).step(threading.Event())
    assert records.task(app_engine, task.task_id).state is S.SUCCEEDED


def test_an_audit_failure_at_completion_commits_nothing_and_the_task_is_retried(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator)
    failing = FailingWhen(lambda event: event.details.get("to_state") == "succeeded")

    _worker(app_engine, failing, replace(FAST_WORKER, lease_seconds=0.5)).step(threading.Event())

    assert records.task(app_engine, task.task_id).state is S.RUNNING
    assert ("running", "succeeded") not in _moves(owner_engine, task.task_id)
    time.sleep(0.6)
    assert _worker(app_engine).step(threading.Event())
    final = records.task(app_engine, task.task_id)
    assert (final.state, records.latest_job(owner_engine, task.task_id)["attempt"]) == (
        S.SUCCEEDED,
        2,
    )


def _boom(_facts: SubmissionFacts | ExecutionFacts) -> Outcome | None:
    raise RuntimeError("rule bug")


def test_an_evaluator_error_at_submission_is_a_saved_denial(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    broken = DecisionService(RECORDER, replace(CURRENT_POLICY, submission_rules=(_boom,)))

    with pytest.raises(AccessDeniedError) as denied:
        _submit(app_engine, operator, decisions=broken)

    decision = denied.value.decision
    assert decision.reason_codes == ("evaluation_error",)
    [saved] = records.rows(
        owner_engine,
        "SELECT effect, task_id FROM aegis.security_decisions WHERE id = :id",
        id=decision.decision_id,
    )
    assert saved == {"effect": "deny", "task_id": None}
    assert (
        records.rows(
            owner_engine,
            "SELECT id FROM aegis.tasks WHERE initiator_id = :id",
            id=operator.actor.identity_id,
        )
        == []
    )


def test_an_evaluator_error_at_execution_fails_the_task_without_running_it(
    app_engine: Engine, operator: Caller
) -> None:
    task = _submit(app_engine, operator)
    broken = DecisionService(RECORDER, replace(CURRENT_POLICY, execution_rules=(_boom,)))
    spy = Spy()

    outcome = _worker(app_engine, decisions=broken, handlers=dict.fromkeys(TaskKind, spy)).claim()

    assert isinstance(outcome, Settled)
    assert (outcome.task.task_id, outcome.task.state) == (task.task_id, S.FAILED)
    assert outcome.task.failure_code == "evaluation_error"
    assert spy.calls == 0


def test_the_worker_refuses_to_start_on_a_schema_that_is_not_current(
    admin_settings: DatabaseSettings,
    owner_settings: DatabaseSettings,
    app_settings: DatabaseSettings,
) -> None:
    name = f"{admin_settings.name.removesuffix('_test')}_outdated_test"
    recreate_test_database(admin_settings, name)
    bootstrap(admin_settings, name, owner_settings.password, app_settings.password)

    def start() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "aegis.apps.worker"],
            env={**os.environ, "AEGIS_POSTGRES_DB": name, "AEGIS_ENV": "production"},
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    unmigrated = start()
    owner = create_database_engine(
        replace(owner_settings, name=name), application_name="aegis-tests"
    )
    try:
        upgrade(owner, "0005")
    finally:
        owner.dispose()
    outdated = start()

    for result in (unmigrated, outdated):
        assert result.returncode == 1
        assert "worker started" not in result.stdout + result.stderr
    assert "schema is not current" in outdated.stdout + outdated.stderr

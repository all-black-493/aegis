import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine

from aegis.apps.api.app import create_app
from aegis.apps.api.context import ApiContext
from aegis.audit.events import AuditEvent, AuditEventType
from aegis.audit.recorder import AuditRecorder
from aegis.authorization.catalog import Role
from aegis.config.logs import Redactor
from aegis.config.settings import Environment
from aegis.jobs.handlers import REGISTRY, HandlerContext
from aegis.jobs.worker import Worker
from aegis.policy.rules import TASK_KINDS
from aegis.runtime.disabled import DisabledRuntime
from aegis.runtime.probes.catalog import PROBES
from aegis.tasks.service import AccessDeniedError, Submission, TaskService
from aegis.tasks.states import TaskKind, TaskState
from tests.fixtures import records
from tests.fixtures.enforcement import RUN, checked, checker, submit, worker
from tests.fixtures.fake_openshell import FakeOpenShell
from tests.fixtures.probe_answers import argv, control_hits, enforce_everything, fill
from tests.fixtures.services import FAST_WORKER, PEPPER, RECORDER, Caller, make_caller

S = TaskState
BY_ID = {probe.check_id: probe for probe in PROBES}
pytestmark = pytest.mark.usefixtures("isolated_jobs")


@pytest.fixture
def fake(tmp_path: Path) -> FakeOpenShell:
    return enforce_everything(FakeOpenShell(tmp_path / "bin"), RUN)


def _failed(app_engine: Engine, task_id: Any) -> tuple[TaskState, str | None]:
    found = records.task(app_engine, task_id)
    return found.state, found.failure_code


def test_without_a_runtime_an_enforcement_check_fails_closed_and_runs_nothing(
    app_engine: Engine, operator: Caller, fake: FakeOpenShell
) -> None:
    task = submit(app_engine, operator.actor)

    worker(app_engine, None).step(threading.Event())

    assert _failed(app_engine, task.task_id) == (S.FAILED, "sandbox_unavailable")
    assert fake.calls() == []


def test_a_disabled_runtime_refuses_before_anything_is_created(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    task = submit(app_engine, operator.actor)

    worker(app_engine, checker(app_engine, DisabledRuntime())).step(threading.Event())

    assert _failed(app_engine, task.task_id) == (S.FAILED, "disabled")
    assert "sandbox.created" not in records.task_events(owner_engine, task.task_id)


@pytest.mark.parametrize("change", [{"status_exit": 1}, {"status": "not_configured"}])
def test_an_unavailable_runtime_is_retried_and_never_executes_anything(
    app_engine: Engine, operator: Caller, fake: FakeOpenShell, change: dict[str, Any]
) -> None:
    task = submit(app_engine, operator.actor)
    fake.update(**change)
    checking = worker(app_engine, checker(app_engine, fake.runtime()))

    for _ in range(FAST_WORKER.max_attempts):
        assert checking.step(threading.Event())

    assert _failed(app_engine, task.task_id) == (S.FAILED, "attempts_exhausted")
    assert [c for c in fake.calls() if {"create", "exec"} & set(c["argv"])] == []


@pytest.mark.parametrize(
    "check_id", ["network.other_binary", "network.request_method", "network.other_port"]
)
def test_a_request_the_canary_saw_fails_the_task_as_a_violation_and_is_audited(
    app_engine: Engine, owner_engine: Engine, operator: Caller, fake: FakeOpenShell, check_id: str
) -> None:
    # The sandbox claims to have refused the request, but AEGIS's canary received it.
    canary = BY_ID[check_id].canary
    assert canary is not None
    hits = control_hits(RUN) | {(canary[0], fill(canary[1], RUN))}
    task = submit(app_engine, operator.actor)

    worker(app_engine, checker(app_engine, fake.runtime(), hits)).step(threading.Event())

    assert _failed(app_engine, task.task_id) == (S.FAILED, "enforcement_violation")
    assert records.task(app_engine, task.task_id).result is None
    violation = checked(owner_engine, task.task_id)[check_id]
    assert (violation["outcome"], violation["reason_code"]) == ("failure", "violated")
    assert (violation["details"]["expected"], violation["details"]["observed"]) == (
        "refused",
        "allowed",
    )
    [failed] = records.rows(
        owner_engine,
        "SELECT details FROM aegis.audit_events WHERE task_id = :id AND event_type = 'job.failed'",
        id=task.task_id,
    )
    assert failed["details"]["error_code"] == "enforcement_violation"
    assert fake.state["sandboxes"] == {}


def test_a_write_that_succeeded_inside_the_sandbox_fails_the_task(
    app_engine: Engine, owner_engine: Engine, operator: Caller, fake: FakeOpenShell
) -> None:
    answers = fake.state["exec"]
    answers[" ".join(argv(BY_ID["filesystem.readonly_truncate"], RUN))] = {"exit": 0}
    fake.update(exec=answers)
    task = submit(app_engine, operator.actor)

    worker(app_engine, checker(app_engine, fake.runtime())).step(threading.Event())

    assert _failed(app_engine, task.task_id) == (S.FAILED, "enforcement_violation")
    assert checked(owner_engine, task.task_id)["filesystem.readonly_truncate"]["reason_code"] == (
        "violated"
    )


def test_runtime_records_without_the_canary_never_make_a_check_succeed(
    app_engine: Engine, owner_engine: Engine, operator: Caller, fake: FakeOpenShell
) -> None:
    task = submit(app_engine, operator.actor)

    worker(app_engine, checker(app_engine, fake.runtime(), hits=set())).step(threading.Event())

    assert _failed(app_engine, task.task_id) == (S.FAILED, "enforcement_inconclusive")
    assert checked(owner_engine, task.task_id)["network.canary_get"]["reason_code"] == (
        "inconclusive"
    )


def test_a_check_whose_results_cannot_be_audited_never_succeeds(
    app_engine: Engine, owner_engine: Engine, operator: Caller, fake: FakeOpenShell
) -> None:
    class Failing(AuditRecorder):
        def record(self, connection: Connection, event: AuditEvent) -> None:
            if event.event_type is AuditEventType.ENFORCEMENT_CHECKED:
                raise OSError("the audit store refused the write")
            super().record(connection, event)

    task = submit(app_engine, operator.actor)
    failing = checker(app_engine, fake.runtime(), recorder=Failing(Redactor()))

    worker(app_engine, failing).step(threading.Event())

    assert _failed(app_engine, task.task_id) == (S.FAILED, "handler_error")
    assert checked(owner_engine, task.task_id) == {}
    assert fake.state["sandboxes"] == {}


def test_only_an_enforcement_check_task_can_create_a_sandbox(
    app_engine: Engine, operator: Caller, fake: FakeOpenShell
) -> None:
    def borrowing(task_input: Mapping[str, Any], context: HandlerContext) -> Mapping[str, Any]:
        context.check_enforcement()
        return {}

    task = (
        TaskService(app_engine, RECORDER)
        .submit(operator.actor, Submission("noop", {}, f"key-{uuid4().hex}"), uuid4().hex)
        .task
    )
    handlers = {**REGISTRY, TaskKind.NOOP: borrowing}
    Worker(
        app_engine,
        RECORDER,
        FAST_WORKER,
        handlers=handlers,
        enforcement=checker(app_engine, fake.runtime()),
    ).step(threading.Event())

    assert _failed(app_engine, task.task_id) == (S.FAILED, "sandbox_unavailable")
    assert fake.calls() == []


def test_decisions_are_identical_whichever_runtime_is_configured(
    app_engine: Engine, owner_engine: Engine, operator: Caller, fake: FakeOpenShell
) -> None:
    configured = [None, checker(app_engine, DisabledRuntime()), checker(app_engine, fake.runtime())]
    decided = []
    for enforcement in configured:
        task = submit(app_engine, operator.actor)
        worker(app_engine, enforcement).step(threading.Event())
        decided.append(
            [
                tuple(row.values())
                for row in records.rows(
                    owner_engine,
                    "SELECT action, effect, stage, reason_codes, policy_version, policy_digest"
                    " FROM aegis.security_decisions WHERE task_id = :id ORDER BY decided_at",
                    id=task.task_id,
                )
            ]
        )

    assert decided[0] == decided[1] == decided[2]
    assert [row[:2] for row in decided[0]] == [("task.submit", "allow"), ("task.execute", "allow")]


def test_the_registry_matches_the_policy_and_input_is_refused_before_any_sandbox(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    assert set(REGISTRY) == set(TaskKind) == TASK_KINDS
    app = create_app(ApiContext(app_engine, PEPPER, RECORDER), Environment.TEST)
    headers = {"Authorization": f"Bearer {operator.token}"}
    with TestClient(app) as client:
        refused = client.post(
            "/v1/tasks",
            json={"kind": "enforcement_check", "input": {"image": "sha256:" + "0" * 64}},
            headers={**headers, "Idempotency-Key": f"enforcement-{uuid4().hex}"},
        )

    assert (refused.status_code, refused.json()["reasons"]) == (403, ["input_invalid"])


def test_an_auditor_cannot_start_an_enforcement_check(
    app_engine: Engine, owner_engine: Engine
) -> None:
    auditor = make_caller(owner_engine, Role.AUDITOR, prefix="enforcement-auditor")

    with pytest.raises(AccessDeniedError):
        submit(app_engine, auditor.actor)

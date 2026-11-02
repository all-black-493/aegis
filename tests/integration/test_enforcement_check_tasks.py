import threading
from dataclasses import replace
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from aegis.apps.api.app import create_app
from aegis.apps.api.context import ApiContext
from aegis.config.settings import Environment
from aegis.jobs.enforcement import sandbox_name
from aegis.jobs.sandboxes import OrphanSweep
from aegis.jobs.settlement import Claim
from aegis.jobs.worker import Worker
from aegis.runtime.gate import load_policies
from aegis.runtime.probes.catalog import PROBES
from aegis.tasks.service import TaskService
from aegis.tasks.states import TaskState
from aegis.tasks.transitions import JobRef
from tests.fixtures import records
from tests.fixtures.enforcement import IMAGE, RUN, checked, checker, submit, worker
from tests.fixtures.fake_openshell import DEFAULT_STATE, FakeOpenShell
from tests.fixtures.probe_answers import argv, enforce_everything
from tests.fixtures.processes import wait_for
from tests.fixtures.services import FAST_WORKER, PEPPER, RECORDER, Caller

S = TaskState
pytestmark = pytest.mark.usefixtures("isolated_jobs")


@pytest.fixture
def fake(tmp_path: Path) -> FakeOpenShell:
    return enforce_everything(FakeOpenShell(tmp_path / "bin"), RUN)


def _probe_execs(fake: FakeOpenShell) -> int:
    probes = {" ".join(argv(probe, RUN)) for probe in PROBES}
    return sum(
        1
        for call in fake.calls()
        if "exec" in call["argv"]
        and " ".join(call["argv"][call["argv"].index("--") + 1 :]) in probes
    )


def test_an_enforcement_check_runs_through_the_api_and_the_worker_with_a_full_audit_chain(
    app_engine: Engine, owner_engine: Engine, operator: Caller, fake: FakeOpenShell
) -> None:
    headers = {"Authorization": f"Bearer {operator.token}"}
    app = create_app(ApiContext(app_engine, PEPPER, RECORDER), Environment.TEST)
    with TestClient(app) as client:
        submitted = client.post(
            "/v1/tasks",
            json={"kind": "enforcement_check", "input": {}},
            headers={**headers, "Idempotency-Key": f"enforcement-{uuid4().hex}"},
        )
        assert submitted.status_code == 201, submitted.text
        task_id = UUID(submitted.json()["id"])

        assert worker(app_engine, checker(app_engine, fake.runtime())).step(threading.Event())

        shown = client.get(f"/v1/tasks/{task_id}", headers=headers).json()

    assert (shown["state"], shown["failure_code"]) == ("succeeded", None)
    assert shown["result"] == {
        "verdict": "verified",
        "checks": {probe.check_id: "held" for probe in PROBES},
    }
    job = records.latest_job(owner_engine, task_id)
    name = sandbox_name(JobRef(job["id"], 1))
    assert records.task_events(owner_engine, task_id) == [
        "security.decision",
        "task.created",
        "task.transitioned",
        "security.decision",
        "task.transitioned",
        "sandbox.created",
        "sandbox.deleted",
        *["enforcement.checked"] * len(PROBES),
        "task.transitioned",
    ]
    [created, deleted] = records.rows(
        owner_engine,
        "SELECT target_id, job_id, reason_code, details FROM aegis.audit_events"
        " WHERE task_id = :id AND event_type LIKE 'sandbox.%' ORDER BY id",
        id=task_id,
    )
    policies = load_policies()
    assert (created["target_id"], created["job_id"], created["reason_code"]) == (
        name,
        job["id"],
        "verified",
    )
    assert {key: created["details"][key] for key in ("image", "policy_version")} == {
        "image": IMAGE,
        "policy_version": policies.version,
    }
    assert created["details"]["policy_fingerprint"] == policies.fingerprint
    assert (deleted["target_id"], deleted["reason_code"]) == (name, "completed")
    checks = checked(owner_engine, task_id)
    assert list(checks) == [probe.check_id for probe in PROBES]
    assert {(row["outcome"], row["reason_code"], row["target_id"]) for row in checks.values()} == {
        ("success", "held", name)
    }
    assert checks["network.request_method"]["details"] == {
        "attempt": 1,
        "check": "network.request_method",
        "kind": "network",
        "expected": "refused",
        "observed": "refused",
        "exit_code": 0,
        "corroborated": True,
    }
    assert checks["filesystem.scratch_write"]["details"]["expected"] == "allowed"
    assert fake.state["sandboxes"] == {}


def test_the_sandbox_is_labelled_with_its_task_job_and_attempt(
    app_engine: Engine, owner_engine: Engine, operator: Caller, fake: FakeOpenShell
) -> None:
    task = submit(app_engine, operator.actor)

    worker(app_engine, checker(app_engine, fake.runtime())).step(threading.Event())

    [create] = [c["argv"] for c in fake.calls() if "create" in c["argv"]]
    labels = {create[i + 1] for i, item in enumerate(create) if item == "--label"}
    job = records.latest_job(owner_engine, task.task_id)
    assert records.task(app_engine, task.task_id).state is S.SUCCEEDED
    assert labels == {
        f"aegis.task={task.task_id}",
        f"aegis.job={job['id']}",
        "aegis.attempt=1",
        "aegis.managed=true",
    }


def test_an_unreachable_gateway_is_retried_and_the_next_attempt_gets_its_own_sandbox(
    app_engine: Engine, owner_engine: Engine, operator: Caller, fake: FakeOpenShell
) -> None:
    task = submit(app_engine, operator.actor)
    fake.update(status_exit=1)
    checking = worker(app_engine, checker(app_engine, fake.runtime()))

    assert checking.step(threading.Event())
    assert records.task(app_engine, task.task_id).state is S.QUEUED
    assert ("openshell", "sandbox", "create") not in fake.commands()

    fake.update(status_exit=0)
    assert checking.step(threading.Event())

    assert records.task(app_engine, task.task_id).state is S.SUCCEEDED
    events = records.task_events(owner_engine, task.task_id)
    assert events.count("job.retried") == 1
    assert events.count("sandbox.created") == 1
    job = records.latest_job(owner_engine, task.task_id)
    assert {row["target_id"] for row in checked(owner_engine, task.task_id).values()} == {
        sandbox_name(JobRef(job["id"], 2))
    }


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"verdict": {**DEFAULT_STATE["verdict"], "result": "exceeds_boundary"}}, "policy_refused"),
        ({"version": "0.1.7"}, "version_mismatch"),
        ({"global_policy": True}, "global_policy_active"),
    ],
)
def test_a_refused_sandbox_fails_the_task_without_running_a_probe(
    app_engine: Engine,
    owner_engine: Engine,
    operator: Caller,
    fake: FakeOpenShell,
    change: dict[str, object],
    code: str,
) -> None:
    task = submit(app_engine, operator.actor)
    fake.update(**change)

    worker(app_engine, checker(app_engine, fake.runtime())).step(threading.Event())

    found = records.task(app_engine, task.task_id)
    assert (found.state, found.failure_code) == (S.FAILED, code)
    assert _probe_execs(fake) == 0
    assert checked(owner_engine, task.task_id) == {}
    assert fake.state["sandboxes"] == {}


def test_a_missing_probe_image_fails_the_task(
    app_engine: Engine, operator: Caller, fake: FakeOpenShell
) -> None:
    task = submit(app_engine, operator.actor)

    worker(app_engine, checker(app_engine, fake.runtime(), image=None)).step(threading.Event())

    found = records.task(app_engine, task.task_id)
    assert (found.state, found.failure_code) == (S.FAILED, "image_missing")
    assert ("openshell", "sandbox", "create") not in fake.commands()


def test_cancelling_a_check_stops_the_probes_and_deletes_the_sandbox(
    app_engine: Engine, owner_engine: Engine, operator: Caller, fake: FakeOpenShell
) -> None:
    task = submit(app_engine, operator.actor)
    checking = worker(app_engine, checker(app_engine, fake.runtime()))
    claim = checking.claim()
    assert isinstance(claim, Claim)
    thread = threading.Thread(target=checking.execute, args=(claim, threading.Event()), daemon=True)
    thread.start()

    TaskService(app_engine, RECORDER).cancel(operator.actor, task.task_id, uuid4().hex)
    thread.join(30)

    assert not thread.is_alive()
    assert records.task(app_engine, task.task_id).state is S.CANCELLED
    # The handler finishes on its own: it deletes the sandbox and records the unobserved checks.
    wait_for(lambda: len(checked(owner_engine, task.task_id)) == len(PROBES), 30, "the checks")
    assert fake.state["sandboxes"] == {}
    executed = _probe_execs(fake)
    outcomes = [row["reason_code"] for row in checked(owner_engine, task.task_id).values()]
    assert executed < len(PROBES)
    assert outcomes.count("inconclusive") == len(PROBES) - executed


def test_the_worker_sweeps_orphaned_sandboxes_between_tasks(
    app_engine: Engine, owner_engine: Engine, fake: FakeOpenShell
) -> None:
    fake.add_sandbox("aegis-orphan", **{"aegis.managed": "true", "aegis.job": str(uuid4())})
    runtime = fake.runtime()
    sweeping = Worker(
        app_engine, RECORDER, FAST_WORKER, sweep=OrphanSweep(app_engine, RECORDER, runtime)
    )

    sweeping.step(threading.Event())

    assert fake.state["sandboxes"] == {}
    [event] = records.rows(
        owner_engine,
        "SELECT reason_code FROM aegis.audit_events"
        " WHERE event_type = 'sandbox.deleted' AND target_id = 'aegis-orphan'",
    )
    assert event["reason_code"] == "orphaned"


def test_attempts_are_bounded_when_the_runtime_never_recovers(
    app_engine: Engine, operator: Caller, fake: FakeOpenShell
) -> None:
    task = submit(app_engine, operator.actor)
    fake.update(status_exit=1)
    checking = worker(
        app_engine, checker(app_engine, fake.runtime()), replace(FAST_WORKER, max_attempts=2)
    )

    for _ in range(2):
        assert checking.step(threading.Event())

    found = records.task(app_engine, task.task_id)
    assert (found.state, found.failure_code) == (S.FAILED, "attempts_exhausted")
    assert ("openshell", "sandbox", "create") not in fake.commands()

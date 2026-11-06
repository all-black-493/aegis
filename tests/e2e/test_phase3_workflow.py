import os
import signal
from collections.abc import Callable
from typing import Any

import httpx2
import pytest
from sqlalchemy import Engine

from aegis.config.settings import (
    DatabaseRole,
    DatabaseSettings,
    load_database_settings,
    load_token_pepper,
)
from aegis.integrations.openshell.cli import VERIFIED_VERSION
from aegis.integrations.openshell.runtime import OpenShellRuntime
from aegis.policy.version import CURRENT_POLICY
from aegis.runtime.gate import load_policies
from aegis.runtime.probes.catalog import PROBES
from aegis.runtime.probes.model import Kind
from tests.fixtures import records
from tests.fixtures.processes import Process, identity, live, wait_for

PROVEN = "within_boundary"
EVENTS = [
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
DECISIONS = [
    ("task.submit", "allow", ["submission_allowed"]),
    ("task.execute", "allow", ["execution_allowed"]),
]
# Not a workspace on any gateway, so a worker started by these tests leaves real sandboxes alone.
ABSENT_WORKSPACE = "aegis-e2e-absent"
pytestmark = pytest.mark.usefixtures("isolated_jobs")

type Submit = Callable[[str, dict[str, Any], str], httpx2.Response]


def _run(
    environ: dict[str, str],
    processes: list[Process],
    scenario: Callable[[Submit, Callable[[str], dict[str, Any]]], None],
) -> tuple[Process, Process, str]:
    operator = identity(environ, "operator")
    api, worker = Process("aegis.apps.api", environ), Process("aegis.apps.worker", environ)
    processes.extend([api, worker])
    base = f"http://127.0.0.1:{environ['AEGIS_API_PORT']}"
    wait_for(lambda: live(base), 20, "the API")
    headers = {"Authorization": f"Bearer {operator}"}

    with httpx2.Client(base_url=base, timeout=10) as http:

        def submit(kind: str, task_input: dict[str, Any], key: str) -> httpx2.Response:
            return http.post(
                "/v1/tasks",
                json={"kind": kind, "input": task_input},
                headers={**headers, "Idempotency-Key": key},
            )

        def finished(task_id: str) -> dict[str, Any]:
            def shown() -> dict[str, Any]:
                task: dict[str, Any] = http.get(f"/v1/tasks/{task_id}", headers=headers).json()
                return task

            wait_for(lambda: shown()["finished_at"] is not None, 120, f"task {task_id}")
            return shown()

        scenario(submit, finished)

    assert worker.stop(signal.SIGTERM) == 0
    assert api.stop(signal.SIGINT) == 0
    return api, worker, operator


def _sandbox_rows(owner_engine: Engine, task_id: str) -> list[dict[str, Any]]:
    return records.rows(
        owner_engine,
        "SELECT event_type, outcome, reason_code, target_id, details FROM aegis.audit_events"
        " WHERE task_id = :id AND event_type LIKE 'sandbox.%' ORDER BY id",
        id=task_id,
    )


@pytest.mark.openshell
def test_an_enforcement_check_runs_from_the_api_through_the_worker_under_openshell(
    environ: dict[str, str],
    processes: list[Process],
    owner_engine: Engine,
    app_settings: DatabaseSettings,
    openshell_runtime: OpenShellRuntime,
    probe_image: str,
) -> None:
    environ = {
        **environ,
        "AEGIS_SANDBOX_RUNTIME": "openshell",
        "AEGIS_OPENSHELL_IMAGE": probe_image,
    }
    outcome: dict[str, Any] = {}

    def scenario(submit: Submit, finished: Callable[[str], dict[str, Any]]) -> None:
        outcome["refused"] = submit(
            "enforcement_check", {"image": "ubuntu:24.04"}, "e2e-check-refused"
        )
        created = submit("enforcement_check", {}, "e2e-check-0001")
        assert created.status_code == 201, created.text
        outcome["task"] = finished(created.json()["id"])

    api, worker, operator = _run(environ, processes, scenario)

    refused, task = outcome["refused"], outcome["task"]
    task_id = task["id"]
    assert (refused.status_code, refused.json()["reasons"]) == (403, ["input_invalid"])
    assert (task["state"], task["failure_code"]) == ("succeeded", None)
    assert task["result"] == {
        "verdict": "verified",
        "checks": {probe.check_id: "held" for probe in PROBES},
    }
    assert records.task_events(owner_engine, task_id) == EVENTS

    created, deleted = _sandbox_rows(owner_engine, task_id)
    policies = load_policies()
    assert {key: created["details"][key] for key in created["details"] if key != "policy_hash"} == {
        "sandbox_id": created["details"]["sandbox_id"],
        "runtime_version": VERIFIED_VERSION,
        "image": probe_image,
        "policy_version": policies.version,
        "policy_fingerprint": policies.fingerprint,
        "prover_result": PROVEN,
    }
    assert (deleted["outcome"], deleted["reason_code"]) == ("success", "completed")
    assert deleted["target_id"] == created["target_id"]

    checks = records.rows(
        owner_engine,
        "SELECT outcome, reason_code, details FROM aegis.audit_events"
        " WHERE task_id = :id AND event_type = 'enforcement.checked' ORDER BY id",
        id=task_id,
    )
    assert [row["details"]["check"] for row in checks] == [probe.check_id for probe in PROBES]
    assert {(row["outcome"], row["reason_code"]) for row in checks} == {("success", "held")}
    assert all(
        row["details"]["corroborated"] is True
        for row in checks
        if row["details"]["kind"] == Kind.NETWORK.value
    )

    decisions = records.rows(
        owner_engine,
        "SELECT action, effect, reason_codes, policy_version, policy_digest"
        " FROM aegis.security_decisions WHERE task_id = :id ORDER BY decided_at",
        id=task_id,
    )
    assert [(row["action"], row["effect"], row["reason_codes"]) for row in decisions] == DECISIONS
    assert {(row["policy_version"], row["policy_digest"]) for row in decisions} == {
        (CURRENT_POLICY.version, CURRENT_POLICY.digest)
    }
    assert openshell_runtime.managed() == ()

    output = api.output + worker.output
    owner = load_database_settings(os.environ, DatabaseRole.OWNER)
    for value in (
        operator.rsplit("_", 1)[1],
        load_token_pepper(os.environ).reveal(),
        app_settings.password.reveal(),
        owner.password.reveal(),
    ):
        assert value not in output


def test_a_worker_without_a_runtime_refuses_checks_and_still_runs_other_tasks(
    environ: dict[str, str], processes: list[Process], owner_engine: Engine
) -> None:
    outcome: dict[str, dict[str, Any]] = {}

    def scenario(submit: Submit, finished: Callable[[str], dict[str, Any]]) -> None:
        checking = submit("enforcement_check", {}, "e2e-none-check")
        other = submit("noop", {}, "e2e-none-noop")
        outcome["check"] = finished(checking.json()["id"])
        outcome["other"] = finished(other.json()["id"])

    _run({**environ, "AEGIS_SANDBOX_RUNTIME": "none"}, processes, scenario)

    check = outcome["check"]
    assert (check["state"], check["failure_code"]) == ("failed", "sandbox_unavailable")
    assert outcome["other"]["state"] == "succeeded"
    events = records.task_events(owner_engine, check["id"])
    assert "job.failed" in events
    assert not [event for event in events if event.startswith(("sandbox.", "enforcement."))]


def test_a_worker_configured_for_openshell_without_an_image_refuses_checks(
    environ: dict[str, str], processes: list[Process], owner_engine: Engine
) -> None:
    outcome: dict[str, dict[str, Any]] = {}

    def scenario(submit: Submit, finished: Callable[[str], dict[str, Any]]) -> None:
        outcome["check"] = finished(submit("enforcement_check", {}, "e2e-image").json()["id"])

    environ = {
        **environ,
        "AEGIS_SANDBOX_RUNTIME": "openshell",
        "AEGIS_OPENSHELL_WORKSPACE": ABSENT_WORKSPACE,
    }
    _, worker, _ = _run(environ, processes, scenario)

    check = outcome["check"]
    assert (check["state"], check["failure_code"]) == ("failed", "image_missing")
    assert _sandbox_rows(owner_engine, check["id"]) == []
    assert "sandbox cleanup skipped" in worker.output

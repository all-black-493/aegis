import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from typing import Any
from uuid import uuid4

import httpx2
import pytest
from sqlalchemy import Engine, text

from aegis.config.settings import (
    DatabaseRole,
    DatabaseSettings,
    load_database_settings,
    load_token_pepper,
)

pytestmark = pytest.mark.usefixtures("isolated_jobs")


class Process:
    def __init__(self, module: str, environ: dict[str, str]) -> None:
        self.popen = subprocess.Popen(
            [sys.executable, "-m", module],
            env=environ,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.output = ""

    def stop(self, sig: signal.Signals) -> int:
        if self.popen.poll() is None:
            self.popen.send_signal(sig)
        self.output, _ = self.popen.communicate(timeout=30)
        return self.popen.returncode


@pytest.fixture
def environ(test_database: str) -> dict[str, str]:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return {
        **os.environ,
        "AEGIS_ENV": "production",
        "AEGIS_POSTGRES_DB": test_database,
        "AEGIS_API_PORT": str(port),
        "AEGIS_WORKER_POLL_SECONDS": "1",
        "AEGIS_WORKER_LEASE_SECONDS": "10",
        "AEGIS_WORKER_HEARTBEAT_SECONDS": "1",
    }


@pytest.fixture
def processes() -> Iterator[list[Process]]:
    started: list[Process] = []
    yield started
    for process in started:
        if process.popen.poll() is None:
            process.popen.kill()
            process.popen.communicate(timeout=30)


def _cli(environ: dict[str, str], *args: str) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "aegis.apps.cli", *args, "--database", environ["AEGIS_POSTGRES_DB"]],
        env=environ,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _identity(environ: dict[str, str], role: str) -> str:
    name = f"e2e-{role}-{uuid4().hex[:8]}"
    _cli(environ, "identity", "create", name, "--kind", "human", "--role", role)
    return _cli(environ, "credential", "issue", name)


def _wait_for(condition: Callable[[], bool], timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            pytest.fail(f"timed out waiting for {what}")
        time.sleep(0.1)


def test_tasks_flow_from_the_api_through_crashing_workers_to_their_final_state(
    environ: dict[str, str],
    processes: list[Process],
    owner_engine: Engine,
    app_settings: DatabaseSettings,
) -> None:
    operator, auditor = _identity(environ, "operator"), _identity(environ, "auditor")
    api = Process("aegis.apps.api", environ)
    first_worker = Process("aegis.apps.worker", environ)
    processes.extend([api, first_worker])
    base = f"http://127.0.0.1:{environ['AEGIS_API_PORT']}"
    _wait_for(lambda: _live(base), 20, "the API")

    with httpx2.Client(base_url=base, timeout=10) as http:

        def submit(key: str, kind: str, task_input: dict[str, Any]) -> str:
            response = http.post(
                "/v1/tasks",
                json={"kind": kind, "input": task_input},
                headers={"Authorization": f"Bearer {operator}", "Idempotency-Key": key},
            )
            assert response.status_code == 201, response.text
            task_id: str = response.json()["id"]
            return task_id

        def state(task_id: str) -> str:
            response = http.get(
                f"/v1/tasks/{task_id}", headers={"Authorization": f"Bearer {operator}"}
            )
            value: str = response.json()["state"]
            return value

        quick = submit("e2e-quick-0001", "noop", {})
        _wait_for(lambda: state(quick) == "succeeded", 20, "the noop task")

        survivor = submit("e2e-survivor-0001", "wait", {"seconds": 3})
        _wait_for(lambda: state(survivor) == "running", 20, "the claim")
        assert first_worker.stop(signal.SIGKILL) == -signal.SIGKILL
        second_worker = Process("aegis.apps.worker", environ)
        processes.append(second_worker)
        _wait_for(lambda: state(survivor) == "succeeded", 40, "recovery after the crash")

        held = submit("e2e-held-0001", "wait", {"seconds": 120})
        assert state(held) == "awaiting_approval"
        cancel = http.post(
            f"/v1/tasks/{held}/cancel", headers={"Authorization": f"Bearer {operator}"}
        )
        everything = http.get(
            "/v1/tasks?scope=all&limit=100", headers={"Authorization": f"Bearer {auditor}"}
        )
        refused = http.get("/v1/tasks?scope=all", headers={"Authorization": f"Bearer {operator}"})

    assert (cancel.status_code, cancel.json()["state"]) == (200, "cancelled")
    assert {quick, survivor, held} <= {item["id"] for item in everything.json()["items"]}
    assert refused.status_code == 403
    assert second_worker.stop(signal.SIGTERM) == 0
    assert api.stop(signal.SIGINT) == 0

    with owner_engine.connect() as connection:
        moves = (
            connection.execute(
                text(
                    "SELECT from_state || '>' || to_state FROM aegis.task_state_transitions"
                    " WHERE task_id = :id ORDER BY to_version"
                ),
                {"id": survivor},
            )
            .scalars()
            .all()
        )
        events = (
            connection.execute(
                text("SELECT event_type FROM aegis.audit_events WHERE task_id = :id ORDER BY id"),
                {"id": survivor},
            )
            .scalars()
            .all()
        )
    assert moves == [
        "created>queued",
        "queued>running",
        "running>interrupted",
        "interrupted>queued",
        "queued>running",
        "running>succeeded",
    ]
    assert events.count("security.decision") == 3
    assert {"task.created", "job.interrupted", "job.retried"} <= set(events)

    owner = load_database_settings(os.environ, DatabaseRole.OWNER)
    output = api.output + second_worker.output + first_worker.output
    for secret in (
        operator.rsplit("_", 1)[1],
        auditor.rsplit("_", 1)[1],
        load_token_pepper(os.environ).reveal(),
        app_settings.password.reveal(),
        owner.password.reveal(),
    ):
        assert secret not in output
    assert "worker stopped" in second_worker.output


def _live(base: str) -> bool:
    try:
        return httpx2.get(f"{base}/health/live").status_code == 200
    except httpx2.TransportError:
        return False

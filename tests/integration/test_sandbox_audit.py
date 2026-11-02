from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import Engine, text

from aegis.authorization.catalog import Role
from aegis.config.settings import WorkerSettings
from aegis.identity.schema import SYSTEM_WORKER_ID
from aegis.jobs.sandboxes import audit_sink, clean_orphaned_sandboxes
from aegis.jobs.worker import Claim, Worker
from aegis.runtime.gate import RELEASE, SandboxGate, load_policies
from aegis.tasks.service import Submission, TaskService
from tests.fixtures.fake_openshell import FakeOpenShell
from tests.fixtures.services import RECORDER, make_caller

IMAGE = "sha256:" + "c" * 64
pytestmark = pytest.mark.usefixtures("isolated_jobs")


@pytest.fixture
def fake(tmp_path: Path) -> FakeOpenShell:
    fake = FakeOpenShell(tmp_path / "bin")
    fake.update(exec={"/usr/bin/cat /etc/aegis-probe-release": {"stdout": RELEASE + "\n"}})
    return fake


def _events(owner_engine: Engine, name: str) -> list[dict[str, Any]]:
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT event_type, outcome, actor_id, actor_kind, target_type, reason_code,"
                " details FROM aegis.audit_events WHERE target_id = :name ORDER BY id"
            ),
            {"name": name},
        )
        return [dict(row) for row in rows.mappings()]


def test_an_admitted_sandbox_is_audited_from_creation_to_deletion(
    app_engine: Engine, owner_engine: Engine, fake: FakeOpenShell
) -> None:
    name = f"aegis-audit-{uuid4().hex[:8]}"
    gate = SandboxGate(fake.runtime(), load_policies(), IMAGE, audit_sink(app_engine, RECORDER))

    with gate.open(name, {"aegis.purpose": "test"}):
        pass

    created, deleted = _events(owner_engine, name)
    assert (created["event_type"], created["outcome"], created["reason_code"]) == (
        "sandbox.created",
        "success",
        "verified",
    )
    assert (created["actor_id"], created["actor_kind"], created["target_type"]) == (
        SYSTEM_WORKER_ID,
        "system",
        "sandbox",
    )
    assert created["details"]["image"] == IMAGE
    assert created["details"]["policy_fingerprint"] == load_policies().fingerprint
    assert created["details"]["prover_result"] == "within_boundary"
    assert (deleted["event_type"], deleted["reason_code"]) == ("sandbox.deleted", "completed")
    assert fake.state["sandboxes"] == {}


def _running_job(app_engine: Engine, owner_engine: Engine) -> str:
    operator = make_caller(owner_engine, Role.OPERATOR, prefix="sandbox-owner")
    TaskService(app_engine, RECORDER).submit(
        operator.actor, Submission("noop", {}, f"key-{uuid4().hex}"), uuid4().hex
    )
    claim = Worker(app_engine, RECORDER, WorkerSettings(lease_seconds=60)).claim()
    assert isinstance(claim, Claim)
    return str(claim.job.job_id)


def test_orphans_are_deleted_and_audited_but_running_jobs_keep_their_sandbox(
    app_engine: Engine, owner_engine: Engine, fake: FakeOpenShell
) -> None:
    live = _running_job(app_engine, owner_engine)
    managed = {"aegis.managed": "true"}
    fake.add_sandbox("aegis-live", **managed, **{"aegis.job": live})
    fake.add_sandbox("aegis-dead", **managed, **{"aegis.job": str(uuid4())})
    fake.add_sandbox("aegis-nojob", **managed)
    fake.add_sandbox("someone-else", **managed)
    fake.add_sandbox("aegis-elsewhere", workspace="default", **managed)
    fake.update(ignore_selector=True)

    deleted = clean_orphaned_sandboxes(app_engine, RECORDER, fake.runtime())

    assert deleted == 2
    assert set(fake.state["sandboxes"]) == {"aegis-live", "someone-else", "aegis-elsewhere"}
    for name in ("aegis-dead", "aegis-nojob"):
        [event] = _events(owner_engine, name)
        assert (event["event_type"], event["reason_code"]) == ("sandbox.deleted", "orphaned")
    assert _events(owner_engine, "aegis-live") == []

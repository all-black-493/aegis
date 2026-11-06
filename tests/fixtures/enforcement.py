from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Engine

from aegis.audit.recorder import AuditRecorder
from aegis.authorization.access import ActorContext
from aegis.config.settings import WorkerSettings
from aegis.jobs.enforcement import EnforcementCheck
from aegis.jobs.worker import Worker
from aegis.runtime.contract import SandboxRuntime
from aegis.runtime.probes.catalog import PROBES
from aegis.tasks.repository import TaskRecord
from aegis.tasks.service import Submission, TaskService
from tests.fixtures import records
from tests.fixtures.fake_openshell import FakeOpenShell
from tests.fixtures.probe_answers import FakeCanary, argv, control_hits
from tests.fixtures.services import FAST_WORKER, RECORDER

RUN = "c4ec4ec4"
IMAGE = "sha256:" + "e" * 64


def checker(
    app_engine: Engine,
    runtime: SandboxRuntime,
    hits: set[tuple[int, str]] | None = None,
    recorder: AuditRecorder = RECORDER,
    image: str | None = IMAGE,
) -> EnforcementCheck:
    # By default the canary sees exactly what the controls send when they succeed.
    seen = control_hits(RUN) if hits is None else hits
    return EnforcementCheck(
        app_engine, recorder, runtime, image, canary=lambda: FakeCanary(seen), nonce=RUN
    )


def worker(
    app_engine: Engine,
    enforcement: EnforcementCheck | None,
    settings: WorkerSettings = FAST_WORKER,
) -> Worker:
    return Worker(app_engine, RECORDER, settings, backoff=lambda _: 0, enforcement=enforcement)


def submit(app_engine: Engine, actor: ActorContext) -> TaskRecord:
    submission = Submission("enforcement_check", {}, f"key-{uuid4().hex}")
    return TaskService(app_engine, RECORDER).submit(actor, submission, uuid4().hex).task


def checked(owner_engine: Engine, task_id: UUID) -> dict[str, dict[str, Any]]:
    # The enforcement.checked events of a task, by check.
    found = records.rows(
        owner_engine,
        "SELECT outcome, target_id, job_id, reason_code, details FROM aegis.audit_events"
        " WHERE task_id = :id AND event_type = 'enforcement.checked' ORDER BY id",
        id=task_id,
    )
    return {row["details"]["check"]: row for row in found}


def probe_execs(fake: FakeOpenShell) -> int:
    probes = {" ".join(argv(probe, RUN)) for probe in PROBES}
    commands = [c["argv"] for c in fake.calls() if "exec" in c["argv"]]
    return sum(" ".join(command[command.index("--") + 1 :]) in probes for command in commands)

import logging
import time
from collections.abc import Callable
from uuid import UUID

from sqlalchemy import Engine

from aegis.audit.events import ActorKind, AuditEvent, AuditEventType, Outcome, Source
from aegis.audit.recorder import AuditRecorder
from aegis.identity.schema import SYSTEM_WORKER_ID
from aegis.jobs import repository as jobs
from aegis.runtime.contract import SandboxRuntime, SandboxRuntimeError
from aegis.runtime.gate import EventSink, SandboxEvent, SandboxEventKind, clean_orphans

ORPHAN_SWEEP_SECONDS = 60.0

logger = logging.getLogger("aegis.worker")
_EVENT_TYPES = {
    SandboxEventKind.CREATED: AuditEventType.SANDBOX_CREATED,
    SandboxEventKind.DELETED: AuditEventType.SANDBOX_DELETED,
}


def audit_sink(
    engine: Engine,
    recorder: AuditRecorder,
    task_id: UUID | None = None,
    job_id: UUID | None = None,
) -> EventSink:
    # Each sandbox event is recorded in its own transaction as it happens. A failed write raises,
    # so the gate deletes a sandbox whose creation could not be audited (fail closed).
    def record(event: SandboxEvent) -> None:
        audit = AuditEvent(
            event_type=_EVENT_TYPES[event.kind],
            source=Source.WORKER,
            outcome=Outcome.SUCCESS if event.succeeded else Outcome.FAILURE,
            actor_id=SYSTEM_WORKER_ID,
            actor_kind=ActorKind.SYSTEM,
            target_type="sandbox",
            target_id=event.name,
            task_id=task_id,
            job_id=job_id,
            reason_code=event.reason,
            details=event.details,
        )
        with engine.begin() as connection:
            recorder.record(connection, audit)

    return record


def clean_orphaned_sandboxes(
    engine: Engine, recorder: AuditRecorder, runtime: SandboxRuntime
) -> int:
    # A sandbox is in use only while its job is running under an unexpired lease; every other
    # AEGIS sandbox is an orphan of a crashed or stopped worker.
    def live_jobs() -> frozenset[str]:
        with engine.connect() as connection:
            return frozenset(str(job_id) for job_id in jobs.live_job_ids(connection))

    deleted = clean_orphans(runtime, live_jobs, audit_sink(engine, recorder))
    if deleted:
        logger.warning("orphaned sandboxes deleted", extra={"count": deleted})
    return deleted


class OrphanSweep:
    # Run by the worker between tasks: at its first step, then once a minute (ADR-0019).
    def __init__(
        self,
        engine: Engine,
        recorder: AuditRecorder,
        runtime: SandboxRuntime,
        interval: float = ORPHAN_SWEEP_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._engine = engine
        self._recorder = recorder
        self._runtime = runtime
        self._interval = interval
        self._clock = clock
        self._due: float | None = None

    def __call__(self) -> int:
        now = self._clock()
        if self._due is not None and now < self._due:
            return 0
        self._due = now + self._interval
        try:
            return clean_orphaned_sandboxes(self._engine, self._recorder, self._runtime)
        except SandboxRuntimeError as error:
            # No sandbox can be created while the runtime is unusable, so cleanup can wait.
            logger.warning("sandbox cleanup skipped", extra={"detail": error.code})
            return 0

import logging
from uuid import UUID

from sqlalchemy import Engine

from aegis.audit.events import ActorKind, AuditEvent, AuditEventType, Outcome, Source
from aegis.audit.recorder import AuditRecorder
from aegis.identity.schema import SYSTEM_WORKER_ID
from aegis.jobs import repository as jobs
from aegis.runtime.contract import Sandbox, SandboxRuntime
from aegis.runtime.gate import EventSink, SandboxEvent, SandboxEventKind, clean_orphans

logger = logging.getLogger("aegis.worker")
_EVENT_TYPES = {
    SandboxEventKind.CREATED: AuditEventType.SANDBOX_CREATED,
    SandboxEventKind.DELETED: AuditEventType.SANDBOX_DELETED,
}


def audit_sink(engine: Engine, recorder: AuditRecorder) -> EventSink:
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
    with engine.connect() as connection:
        live = jobs.live_job_ids(connection)

    def in_use(sandbox: Sandbox) -> bool:
        try:
            return UUID(sandbox.labels.get("aegis.job", "")) in live
        except ValueError:
            return False

    deleted = clean_orphans(runtime, in_use, audit_sink(engine, recorder))
    if deleted:
        logger.warning("orphaned sandboxes deleted", extra={"count": deleted})
    return deleted

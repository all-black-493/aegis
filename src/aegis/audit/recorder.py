from sqlalchemy import Connection, insert

from aegis.audit.events import AuditEvent
from aegis.audit.schema import audit_events
from aegis.config.logs import Redactor


class AuditError(RuntimeError):
    pass


class AuditRecorder:
    def __init__(self, redactor: Redactor) -> None:
        self._redactor = redactor

    def record(self, connection: Connection, event: AuditEvent) -> None:
        if not connection.in_transaction():
            raise AuditError("audit events must be recorded inside the caller's transaction")
        connection.execute(insert(audit_events).values(self.row(event)))

    def row(self, event: AuditEvent) -> dict[str, object]:
        redact = self._redactor.redact
        return {
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "source": event.source.value,
            "outcome": event.outcome.value,
            "actor_id": event.actor_id,
            "actor_kind": event.actor_kind.value if event.actor_kind else None,
            "target_type": event.target_type,
            "target_id": redact(event.target_id) if event.target_id is not None else None,
            "task_id": event.task_id,
            "job_id": event.job_id,
            "decision_id": event.decision_id,
            "request_id": event.request_id,
            "reason_code": event.reason_code,
            "policy_version": event.policy_version,
            "details": {
                key: redact(value) if isinstance(value, str) else value
                for key, value in event.details.items()
            },
        }

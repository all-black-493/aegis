from sqlalchemy import BigInteger, Column, ForeignKey, Identity, Index, Table, Text, text
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP, UUID

from aegis.db.metadata import metadata

audit_events = Table(
    "audit_events",
    metadata,
    Column("event_id", UUID(as_uuid=True), primary_key=True),
    Column("id", BigInteger, Identity(always=True), nullable=False, unique=True),
    Column("occurred_at", TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")),
    Column("event_type", Text, nullable=False),
    Column("source", Text, nullable=False),
    Column("outcome", Text, nullable=False),
    Column("actor_id", UUID(as_uuid=True), ForeignKey("aegis.identities.id")),
    Column("actor_kind", Text),
    Column("target_type", Text),
    Column("target_id", Text),
    Column("task_id", UUID(as_uuid=True)),
    Column("job_id", UUID(as_uuid=True)),
    Column("decision_id", UUID(as_uuid=True)),
    Column("request_id", Text),
    Column("reason_code", Text),
    Column("policy_version", Text),
    Column("details", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Index("ix_audit_events_occurred_at", "occurred_at"),
    Index("ix_audit_events_event_type_occurred_at", "event_type", "occurred_at"),
    Index("ix_audit_events_actor_id_occurred_at", "actor_id", "occurred_at"),
    Index("ix_audit_events_task_id", "task_id"),
    # aegis_app may insert but not select, so inserts must not use RETURNING.
    implicit_returning=False,
)

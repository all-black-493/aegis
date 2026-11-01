from sqlalchemy import (
    Column,
    ForeignKey,
    Index,
    Integer,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import TIMESTAMP, UUID

from aegis.db.metadata import metadata

jobs = Table(
    "jobs",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("task_id", UUID(as_uuid=True), ForeignKey("aegis.tasks.id"), nullable=False),
    Column("state", Text, nullable=False, server_default=text("'pending'")),
    Column("attempt", Integer, nullable=False, server_default=text("0")),
    Column("max_attempts", Integer, nullable=False),
    Column("run_after", TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")),
    Column("lease_owner", Text),
    Column("lease_expires_at", TIMESTAMP(timezone=True)),
    Column("heartbeat_at", TIMESTAMP(timezone=True)),
    Column("last_error_code", Text),
    Column("correlation_id", Text),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")),
    Column("updated_at", TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")),
    Column("finished_at", TIMESTAMP(timezone=True)),
    UniqueConstraint("id", "task_id", name="uq_jobs_id_task_id"),
    Index(
        "uq_jobs_active_task_id",
        "task_id",
        unique=True,
        postgresql_where=text("state IN ('pending', 'running')"),
    ),
    Index("ix_jobs_pending", "run_after", "id", postgresql_where=text("state = 'pending'")),
    Index("ix_jobs_running", "lease_expires_at", postgresql_where=text("state = 'running'")),
)

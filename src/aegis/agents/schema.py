from sqlalchemy import (
    BigInteger,
    Column,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    Integer,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TIMESTAMP, UUID

from aegis.db.metadata import metadata

agent_runs = Table(
    "agent_runs",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("task_id", UUID(as_uuid=True), nullable=False),
    Column("job_id", UUID(as_uuid=True), nullable=False),
    Column("job_attempt", Integer, nullable=False),
    Column("agent_id", UUID(as_uuid=True), ForeignKey("aegis.identities.id"), nullable=False),
    Column("scenario", Text, nullable=False),
    Column("capabilities", ARRAY(Text), nullable=False),
    Column("sandbox", Text, nullable=False),
    Column("policy_version", Text, nullable=False),
    Column("policy_digest", Text, nullable=False),
    Column("started_at", TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")),
    UniqueConstraint("job_id", "job_attempt", name="uq_agent_runs_job_attempt"),
    ForeignKeyConstraint(
        ["job_id", "task_id"],
        ["aegis.jobs.id", "aegis.jobs.task_id"],
        name="fk_agent_runs_job_id_jobs",
    ),
    Index("ix_agent_runs_task_id", "task_id"),
)

agent_steps = Table(
    "agent_steps",
    metadata,
    Column("id", BigInteger, Identity(always=True), primary_key=True),
    Column("run_id", UUID(as_uuid=True), ForeignKey("aegis.agent_runs.id"), nullable=False),
    Column("sequence", Integer, nullable=False),
    Column("kind", Text, nullable=False),
    Column("code", Text, nullable=False),
    Column("tool_name", Text),
    Column("tool_version", Text),
    Column("decision_id", UUID(as_uuid=True), ForeignKey("aegis.security_decisions.id")),
    Column("content", JSONB, nullable=False),
    Column("content_sha256", Text, nullable=False),
    Column("content_bytes", Integer, nullable=False),
    Column("prompt_tokens", Integer),
    Column("output_tokens", Integer),
    Column("duration_ms", Integer),
    Column("occurred_at", TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")),
    UniqueConstraint("run_id", "sequence", name="uq_agent_steps_run_id_sequence"),
    UniqueConstraint("decision_id", name="uq_agent_steps_decision_id"),
)

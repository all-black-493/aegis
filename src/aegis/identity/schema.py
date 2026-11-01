from uuid import UUID

from sqlalchemy import Column, ForeignKey, Index, LargeBinary, Table, Text, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from aegis.db.metadata import metadata

SYSTEM_WORKER_ID = UUID("00000000-0000-4000-8000-000000000001")
SYSTEM_CLI_ID = UUID("00000000-0000-4000-8000-000000000002")

identities = Table(
    "identities",
    metadata,
    Column("id", PG_UUID(as_uuid=True), primary_key=True),
    Column("kind", Text, nullable=False),
    Column("name", Text, nullable=False, unique=True),
    Column("status", Text, nullable=False, server_default=text("'active'")),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")),
    Column("created_by", PG_UUID(as_uuid=True), ForeignKey("aegis.identities.id")),
    Column("disabled_at", TIMESTAMP(timezone=True)),
)

identity_roles = Table(
    "identity_roles",
    metadata,
    Column(
        "identity_id",
        PG_UUID(as_uuid=True),
        ForeignKey("aegis.identities.id"),
        primary_key=True,
    ),
    Column("role", Text, primary_key=True),
    Column("granted_at", TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")),
    Column("granted_by", PG_UUID(as_uuid=True), ForeignKey("aegis.identities.id"), nullable=False),
)

credentials = Table(
    "credentials",
    metadata,
    Column("id", PG_UUID(as_uuid=True), primary_key=True),
    Column("identity_id", PG_UUID(as_uuid=True), ForeignKey("aegis.identities.id"), nullable=False),
    Column("lookup_id", Text, nullable=False, unique=True),
    Column("secret_hash", LargeBinary, nullable=False),
    Column("hash_scheme", Text, nullable=False),
    Column("description", Text),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")),
    Column("created_by", PG_UUID(as_uuid=True), ForeignKey("aegis.identities.id"), nullable=False),
    Column("expires_at", TIMESTAMP(timezone=True), nullable=False),
    Column("revoked_at", TIMESTAMP(timezone=True)),
    Column("revoked_by", PG_UUID(as_uuid=True), ForeignKey("aegis.identities.id")),
    Index("ix_credentials_identity_id", "identity_id"),
)

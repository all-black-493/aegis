from alembic import context
from sqlalchemy import Connection, text

from aegis.db.metadata import SCHEMA, metadata

MIGRATION_LOCK = 7_301_002

if context.is_offline_mode():
    raise RuntimeError("offline migrations are not supported; use `aegis db migrate`")

connection = context.config.attributes.get("connection")
if not isinstance(connection, Connection):
    raise RuntimeError("migrations must be run through `aegis db migrate`")

connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK})
context.configure(
    connection=connection,
    target_metadata=metadata,
    version_table_schema=SCHEMA,
    transactional_ddl=True,
)
with context.begin_transaction():
    context.run_migrations()

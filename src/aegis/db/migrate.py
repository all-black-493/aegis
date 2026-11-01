from dataclasses import dataclass

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Engine

from aegis.db.metadata import SCHEMA

SCRIPT_LOCATION = "aegis.db:migrations"


@dataclass(frozen=True)
class SchemaStatus:
    current: str | None
    head: str

    @property
    def ready(self) -> bool:
        return self.current == self.head


def alembic_config(connection: Connection | None = None) -> Config:
    config = Config()
    config.set_main_option("script_location", SCRIPT_LOCATION)
    if connection is not None:
        config.attributes["connection"] = connection
    return config


def head_revision() -> str:
    head = ScriptDirectory.from_config(alembic_config()).get_current_head()
    if head is None:
        raise RuntimeError("no migrations found")
    return head


def schema_status(connection: Connection) -> SchemaStatus:
    context = MigrationContext.configure(connection, opts={"version_table_schema": SCHEMA})
    return SchemaStatus(current=context.get_current_revision(), head=head_revision())


def upgrade(engine: Engine, revision: str = "head") -> None:
    with engine.begin() as connection:
        command.upgrade(alembic_config(connection), revision)


def downgrade(engine: Engine, revision: str) -> None:
    with engine.begin() as connection:
        command.downgrade(alembic_config(connection), revision)

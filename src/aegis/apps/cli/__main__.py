import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import replace

import psycopg
from alembic.util import CommandError
from sqlalchemy.exc import SQLAlchemyError

from aegis.config.logs import configure_logging
from aegis.config.settings import (
    CommonSettings,
    DatabaseRole,
    SettingsError,
    load_common_settings,
    load_database_settings,
)
from aegis.db.admin import bootstrap
from aegis.db.engine import create_database_engine
from aegis.db.migrate import schema_status, upgrade


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    environ = dict(os.environ)
    try:
        common = load_common_settings(environ)
        if args.command == "bootstrap":
            return _bootstrap(environ, common, args.database)
        return _migrate(environ, common, args.database)
    except SettingsError as error:
        print(f"error: {error}", file=sys.stderr)
    except (psycopg.Error, SQLAlchemyError, CommandError) as error:
        lines = str(error).strip().splitlines()
        print(f"error: {type(error).__name__}: {lines[0] if lines else ''}", file=sys.stderr)
    return 1


def _bootstrap(environ: Mapping[str, str], common: CommonSettings, database: str | None) -> int:
    admin = load_database_settings(environ, DatabaseRole.ADMIN)
    owner = load_database_settings(environ, DatabaseRole.OWNER)
    app = load_database_settings(environ, DatabaseRole.APP)
    configure_logging(common, secrets=[s.password.reveal() for s in (admin, owner, app)])
    for action in bootstrap(admin, database or admin.name, owner.password, app.password):
        print(action)
    return 0


def _migrate(environ: Mapping[str, str], common: CommonSettings, database: str | None) -> int:
    owner = load_database_settings(environ, DatabaseRole.OWNER)
    configure_logging(common, secrets=[owner.password.reveal()])
    target = replace(owner, name=database or owner.name)
    engine = create_database_engine(target, application_name="aegis-migrate")
    try:
        with engine.connect() as connection:
            before = schema_status(connection).current
        upgrade(engine)
        with engine.connect() as connection:
            after = schema_status(connection).current
    finally:
        engine.dispose()
    if before == after:
        print(f"database {target.name}: already at revision {after}")
    else:
        print(f"database {target.name}: migrated from {before or 'empty'} to revision {after}")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description="AEGIS administration")
    groups = parser.add_subparsers(dest="group", required=True)
    database = groups.add_parser("db", help="database administration")
    commands = database.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("bootstrap", "create or update the AEGIS roles and schema (database superuser)"),
        ("migrate", "apply pending migrations (database owner)"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--database", help="target database (default: AEGIS_POSTGRES_DB)")
    return parser


if __name__ == "__main__":
    sys.exit(main())

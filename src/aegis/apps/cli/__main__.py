import argparse
import os
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import replace
from uuid import UUID

import psycopg
from alembic.util import CommandError
from sqlalchemy.exc import SQLAlchemyError

from aegis.audit.recorder import AuditRecorder
from aegis.authorization.catalog import IdentityKind, Role
from aegis.config.logs import Redactor, configure_logging
from aegis.config.settings import (
    CommonSettings,
    DatabaseRole,
    SettingsError,
    load_common_settings,
    load_database_settings,
    load_token_pepper,
)
from aegis.db.admin import bootstrap
from aegis.db.engine import create_database_engine
from aegis.db.migrate import schema_status, upgrade
from aegis.identity.admin import AdministrationError, IdentityAdministration

type Handler = Callable[[Mapping[str, str], CommonSettings, argparse.Namespace], int]


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    environ = dict(os.environ)
    handler: Handler = args.handler
    try:
        return handler(environ, load_common_settings(environ), args)
    except (SettingsError, AdministrationError) as error:
        print(f"error: {error}", file=sys.stderr)
    except (psycopg.Error, SQLAlchemyError, CommandError) as error:
        lines = str(error).strip().splitlines()
        print(f"error: {type(error).__name__}: {lines[0] if lines else ''}", file=sys.stderr)
    return 1


def _bootstrap(environ: Mapping[str, str], common: CommonSettings, args: argparse.Namespace) -> int:
    admin = load_database_settings(environ, DatabaseRole.ADMIN)
    owner = load_database_settings(environ, DatabaseRole.OWNER)
    app = load_database_settings(environ, DatabaseRole.APP)
    configure_logging(common, secrets=[s.password.reveal() for s in (admin, owner, app)])
    for action in bootstrap(admin, args.database or admin.name, owner.password, app.password):
        print(action)
    return 0


def _migrate(environ: Mapping[str, str], common: CommonSettings, args: argparse.Namespace) -> int:
    owner = load_database_settings(environ, DatabaseRole.OWNER)
    configure_logging(common, secrets=[owner.password.reveal()])
    target = replace(owner, name=args.database or owner.name)
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


@contextmanager
def _administration(
    environ: Mapping[str, str], common: CommonSettings, database: str | None, *secrets: str
) -> Iterator[IdentityAdministration]:
    owner = load_database_settings(environ, DatabaseRole.OWNER)
    configure_logging(common, secrets=[owner.password.reveal(), *secrets])
    target = replace(owner, name=database or owner.name)
    engine = create_database_engine(target, application_name="aegis-admin")
    redactor = Redactor([owner.password.reveal(), *secrets])
    try:
        with engine.begin() as connection:
            if not schema_status(connection).ready:
                raise AdministrationError(
                    f"database {target.name} is not at the current schema revision;"
                    " run `make migrate`"
                )
            yield IdentityAdministration(connection, AuditRecorder(redactor))
    finally:
        engine.dispose()


def _identity_create(
    environ: Mapping[str, str], common: CommonSettings, args: argparse.Namespace
) -> int:
    with _administration(environ, common, args.database) as admin:
        admin.create_identity(args.name, IdentityKind(args.kind), [Role(r) for r in args.role])
    print(f"identity {args.name}: created")
    return 0


def _identity_disable(
    environ: Mapping[str, str], common: CommonSettings, args: argparse.Namespace
) -> int:
    with _administration(environ, common, args.database) as admin:
        admin.disable_identity(args.name)
    print(f"identity {args.name}: disabled")
    return 0


def _identity_enable(
    environ: Mapping[str, str], common: CommonSettings, args: argparse.Namespace
) -> int:
    with _administration(environ, common, args.database) as admin:
        admin.enable_identity(args.name)
    print(f"identity {args.name}: enabled")
    return 0


def _credential_issue(
    environ: Mapping[str, str], common: CommonSettings, args: argparse.Namespace
) -> int:
    pepper = load_token_pepper(environ)
    with _administration(environ, common, args.database, pepper.reveal()) as admin:
        issued = admin.issue_credential(
            args.name, pepper, days=args.days, description=args.description
        )
    print(
        f"credential {issued.credential_id} issued to {issued.identity_name};"
        f" expires {issued.expires_at.isoformat()}. It is shown only once.",
        file=sys.stderr,
    )
    print(issued.token.reveal())
    return 0


def _credential_revoke(
    environ: Mapping[str, str], common: CommonSettings, args: argparse.Namespace
) -> int:
    with _administration(environ, common, args.database) as admin:
        admin.revoke_credential(args.credential_id)
    print(f"credential {args.credential_id}: revoked")
    return 0


def _credential_list(
    environ: Mapping[str, str], common: CommonSettings, args: argparse.Namespace
) -> int:
    with _administration(environ, common, args.database) as admin:
        listed = admin.list_credentials(args.name)
    for credential in listed:
        print(
            f"{credential.credential_id}  {credential.state:<7}"
            f"  created {credential.created_at.isoformat()}"
            f"  expires {credential.expires_at.isoformat()}"
            f"  {credential.description or ''}".rstrip()
        )
    return 0


def _role_grant(
    environ: Mapping[str, str], common: CommonSettings, args: argparse.Namespace
) -> int:
    with _administration(environ, common, args.database) as admin:
        admin.grant_role(args.name, Role(args.role))
    print(f"identity {args.name}: granted role {args.role}")
    return 0


def _role_revoke(
    environ: Mapping[str, str], common: CommonSettings, args: argparse.Namespace
) -> int:
    with _administration(environ, common, args.database) as admin:
        admin.revoke_role(args.name, Role(args.role))
    print(f"identity {args.name}: revoked role {args.role}")
    return 0


type Subcommands = argparse._SubParsersAction[argparse.ArgumentParser]


def _command(
    group: Subcommands, name: str, handler: Handler, help_text: str
) -> argparse.ArgumentParser:
    subparser = group.add_parser(name, help=help_text)
    subparser.add_argument("--database", help="target database (default: AEGIS_POSTGRES_DB)")
    subparser.set_defaults(handler=handler)
    return subparser


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description="AEGIS administration")
    groups = parser.add_subparsers(dest="group", required=True)

    database = groups.add_parser("db", help="database administration").add_subparsers(
        dest="command", required=True
    )
    _command(
        database,
        "bootstrap",
        _bootstrap,
        "create or update the AEGIS roles and schema (database superuser)",
    )
    _command(database, "migrate", _migrate, "apply pending migrations (database owner)")

    roles = [role.value for role in Role]
    identity = groups.add_parser("identity", help="manage identities").add_subparsers(
        dest="command", required=True
    )
    create = _command(identity, "create", _identity_create, "create a human or service identity")
    create.add_argument("name")
    create.add_argument(
        "--kind", required=True, choices=[IdentityKind.HUMAN.value, IdentityKind.SERVICE.value]
    )
    create.add_argument("--role", action="append", default=[], choices=roles)
    _command(identity, "disable", _identity_disable, "disable an identity").add_argument("name")
    _command(identity, "enable", _identity_enable, "enable a disabled identity").add_argument(
        "name"
    )

    credential = groups.add_parser("credential", help="manage API credentials").add_subparsers(
        dest="command", required=True
    )
    issue = _command(credential, "issue", _credential_issue, "issue an API token (printed once)")
    issue.add_argument("name")
    issue.add_argument("--days", type=int, help="lifetime in days (default 30, maximum 90)")
    issue.add_argument("--description")
    _command(credential, "revoke", _credential_revoke, "revoke a credential").add_argument(
        "credential_id", type=UUID
    )
    _command(credential, "list", _credential_list, "list an identity's credentials").add_argument(
        "name"
    )

    role = groups.add_parser("role", help="manage role assignments").add_subparsers(
        dest="command", required=True
    )
    for name, handler, help_text in (
        ("grant", _role_grant, "grant a role to an identity"),
        ("revoke", _role_revoke, "revoke a role from an identity"),
    ):
        subparser = _command(role, name, handler, help_text)
        subparser.add_argument("name")
        subparser.add_argument("role", choices=roles)
    return parser


if __name__ == "__main__":
    sys.exit(main())

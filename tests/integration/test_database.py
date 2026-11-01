import os
import subprocess
import sys

import psycopg
import pytest
from psycopg import errors
from psycopg.rows import TupleRow
from sqlalchemy import Engine

from aegis.config.settings import APP_ROLE, OWNER_ROLE, DatabaseSettings
from aegis.db.admin import bootstrap
from aegis.db.engine import connect
from aegis.db.migrate import downgrade, head_revision, schema_status, upgrade

ROLES = (OWNER_ROLE, APP_ROLE)


def _cli(*args: str, environ: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "aegis.apps.cli", *args],
        env=environ if environ is not None else dict(os.environ),
        capture_output=True,
        text=True,
        check=False,
    )


def _autocommit(settings: DatabaseSettings) -> psycopg.Connection[TupleRow]:
    return connect(settings, autocommit=True, application_name="aegis-tests")


def test_migrations_reach_the_latest_revision(app_engine: Engine) -> None:
    with app_engine.connect() as connection:
        status = schema_status(connection)

    assert status.ready
    assert status.current == head_revision()


def test_migrating_again_changes_nothing(owner_engine: Engine) -> None:
    upgrade(owner_engine)
    upgrade(owner_engine)

    with owner_engine.connect() as connection:
        assert schema_status(connection).ready


def test_downgrade_then_upgrade_round_trip(owner_engine: Engine, app_engine: Engine) -> None:
    downgrade(owner_engine, "base")
    with owner_engine.connect() as connection:
        assert schema_status(connection).current is None

    upgrade(owner_engine)

    with app_engine.connect() as connection:
        assert schema_status(connection).ready


def test_bootstrap_is_repeatable_and_restores_role_attributes(
    test_database: str,
    admin_settings: DatabaseSettings,
    owner_settings: DatabaseSettings,
    app_settings: DatabaseSettings,
) -> None:
    with _autocommit(admin_settings) as connection:
        connection.execute("ALTER ROLE aegis_app CREATEDB")

    actions = bootstrap(
        admin_settings, test_database, owner_settings.password, app_settings.password
    )

    assert "role aegis_owner: updated" in actions
    assert "role aegis_app: updated" in actions
    with _autocommit(admin_settings) as connection:
        row = connection.execute(
            "SELECT rolcreatedb FROM pg_roles WHERE rolname = 'aegis_app'"
        ).fetchone()
    assert row == (False,)


@pytest.mark.parametrize("role", ROLES)
def test_roles_have_no_elevated_attributes(admin_settings: DatabaseSettings, role: str) -> None:
    with _autocommit(admin_settings) as connection:
        row = connection.execute(
            "SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolreplication, "
            "rolbypassrls FROM pg_roles WHERE rolname = %s",
            (role,),
        ).fetchone()

    assert row == (True, False, False, False, False, False)


def test_passwords_are_stored_only_as_scram_verifiers(
    admin_settings: DatabaseSettings,
    owner_settings: DatabaseSettings,
    app_settings: DatabaseSettings,
) -> None:
    with _autocommit(admin_settings) as connection:
        rows = connection.execute(
            "SELECT rolname, rolpassword FROM pg_authid WHERE rolname = ANY(%s)", (list(ROLES),)
        ).fetchall()
    stored = {str(name): str(verifier) for name, verifier in rows}

    for settings in (owner_settings, app_settings):
        verifier = stored[settings.user]
        assert verifier.startswith("SCRAM-SHA-256$")
        assert settings.password.reveal() not in verifier


@pytest.mark.parametrize(
    "statement", ["CREATE ROLE aegis_forbidden_role", "CREATE DATABASE aegis_forbidden_db"]
)
def test_owner_cannot_create_roles_or_databases(
    owner_settings: DatabaseSettings, statement: str
) -> None:
    with _autocommit(owner_settings) as connection, pytest.raises(errors.InsufficientPrivilege):
        connection.execute(statement.encode())


@pytest.mark.parametrize(
    "statement",
    [
        "CREATE TABLE aegis.forbidden (id int)",
        "CREATE TABLE public.forbidden (id int)",
        "CREATE TABLE forbidden (id int)",
        "SET ROLE aegis_owner",
    ],
)
def test_app_cannot_create_tables_or_become_owner(
    app_settings: DatabaseSettings, statement: str
) -> None:
    with _autocommit(app_settings) as connection, pytest.raises(errors.InsufficientPrivilege):
        connection.execute(statement.encode())


def test_app_has_no_access_to_the_public_schema(app_settings: DatabaseSettings) -> None:
    with _autocommit(app_settings) as connection:
        row = connection.execute(
            "SELECT has_schema_privilege('public', 'USAGE'), "
            "has_schema_privilege('public', 'CREATE')"
        ).fetchone()

    assert row == (False, False)


def test_public_cannot_connect_to_the_database(
    admin_settings: DatabaseSettings, test_database: str
) -> None:
    with _autocommit(admin_settings) as connection:
        row = connection.execute(
            "SELECT count(*) FROM pg_database d, aclexplode(d.datacl) a "
            "WHERE d.datname = %s AND a.grantee = 0",
            (test_database,),
        ).fetchone()

    assert row == (0,)


@pytest.mark.parametrize("fixture", ["owner_settings", "app_settings"])
def test_roles_resolve_names_in_the_aegis_schema_only(
    request: pytest.FixtureRequest, fixture: str
) -> None:
    settings: DatabaseSettings = request.getfixturevalue(fixture)

    with _autocommit(settings) as connection:
        assert connection.execute("SHOW search_path").fetchone() == ("aegis",)


def test_cli_never_prints_passwords(
    test_database: str,
    admin_settings: DatabaseSettings,
    owner_settings: DatabaseSettings,
    app_settings: DatabaseSettings,
) -> None:
    results = [
        _cli("db", "bootstrap", "--database", test_database),
        _cli("db", "migrate", "--database", test_database),
    ]

    output = "".join(result.stdout + result.stderr for result in results)
    assert [result.returncode for result in results] == [0, 0], output
    assert "role aegis_app: updated" in output
    assert f"database {test_database}: already at revision {head_revision()}" in output
    for settings in (admin_settings, owner_settings, app_settings):
        assert settings.password.reveal() not in output


def test_migrate_needs_only_the_owner_credentials(test_database: str) -> None:
    environ = {
        name: value
        for name, value in os.environ.items()
        if name not in {"AEGIS_POSTGRES_PASSWORD", "AEGIS_DB_APP_PASSWORD", "AEGIS_POSTGRES_USER"}
    }

    result = _cli("db", "migrate", "--database", test_database, environ=environ)

    assert result.returncode == 0, result.stderr


def test_migrate_with_a_wrong_password_fails_without_a_traceback(test_database: str) -> None:
    wrong = "wrong-owner-password-000000"
    environ = {**os.environ, "AEGIS_DB_OWNER_PASSWORD": wrong}

    result = _cli("db", "migrate", "--database", test_database, environ=environ)

    assert result.returncode == 1
    assert result.stderr.startswith("error: OperationalError")
    assert "Traceback" not in result.stderr
    assert wrong not in result.stdout + result.stderr

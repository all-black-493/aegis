import os
import subprocess
import sys
from uuid import UUID, uuid4

from sqlalchemy import Engine, text

from aegis.config.settings import DatabaseSettings
from aegis.db.migrate import downgrade, upgrade
from aegis.identity.authentication import authenticate
from aegis.identity.tokens import TOKEN_PREFIX, parse_token
from tests.fixtures.services import PEPPER


def _cli(database: str, *args: str, **overrides: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "aegis.apps.cli", *args, "--database", database],
        env={**os.environ, **overrides},
        capture_output=True,
        text=True,
        check=False,
    )


def _secrets(owner_settings: DatabaseSettings) -> list[str]:
    return [owner_settings.password.reveal(), PEPPER.reveal()]


def test_credential_lifecycle_through_the_cli(
    test_database: str, owner_settings: DatabaseSettings, app_engine: Engine
) -> None:
    name = f"svc-{uuid4().hex[:12]}"
    created = _cli(
        test_database, "identity", "create", name, "--kind", "service", "--role", "operator"
    )
    issued = _cli(test_database, "credential", "issue", name, "--days", "7", "--description", "ci")
    token = issued.stdout.strip()

    with app_engine.connect() as connection:
        actor = authenticate(connection, token, PEPPER)
    credential_id = str(actor.credential_id)
    listed = _cli(test_database, "credential", "list", name)
    revoked = _cli(test_database, "credential", "revoke", credential_id)
    relisted = _cli(test_database, "credential", "list", name)

    results = [created, issued, listed, revoked, relisted]
    assert [result.returncode for result in results] == [0] * 5, [r.stderr for r in results]
    assert parse_token(token) is not None
    assert issued.stdout == token + "\n"
    assert f"issued to {name}" in issued.stderr
    assert "shown only once" in issued.stderr
    assert listed.stdout.startswith(f"{credential_id}  active")
    assert listed.stdout.rstrip().endswith("ci")
    assert relisted.stdout.startswith(f"{credential_id}  revoked")
    everything = "".join(r.stdout + r.stderr for r in results)
    for secret in _secrets(owner_settings):
        assert secret not in everything
    others = "".join(r.stdout + r.stderr for r in results if r is not issued) + issued.stderr
    assert token.rsplit("_", 1)[1] not in others
    assert TOKEN_PREFIX not in others


def test_identity_and_role_commands(test_database: str, owner_engine: Engine) -> None:
    name = f"ops-{uuid4().hex[:12]}"
    results = [
        _cli(test_database, "identity", "create", name, "--kind", "human"),
        _cli(test_database, "role", "grant", name, "auditor"),
        _cli(test_database, "role", "revoke", name, "auditor"),
        _cli(test_database, "identity", "disable", name),
        _cli(test_database, "identity", "enable", name),
    ]

    assert [result.returncode for result in results] == [0] * 5, [r.stderr for r in results]
    with owner_engine.connect() as connection:
        identity_id = connection.execute(
            text("SELECT id FROM aegis.identities WHERE name = :name"), {"name": name}
        ).scalar_one()
        events = connection.execute(
            text(
                "SELECT event_type FROM aegis.audit_events WHERE target_id = :id"
                " AND source = 'cli' ORDER BY id"
            ),
            {"id": str(identity_id)},
        ).scalars()
        assert list(events) == [
            "identity.created",
            "role.granted",
            "role.revoked",
            "identity.disabled",
            "identity.enabled",
        ]


def test_the_cli_refuses_lifetimes_over_90_days(test_database: str, owner_engine: Engine) -> None:
    name = f"user-{uuid4().hex[:12]}"
    _cli(test_database, "identity", "create", name, "--kind", "human")

    result = _cli(test_database, "credential", "issue", name, "--days", "91")

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "error: credential lifetime must be 1 to 90 days\n"
    with owner_engine.connect() as connection:
        count = connection.execute(
            text(
                "SELECT count(*) FROM aegis.credentials c JOIN aegis.identities i"
                " ON i.id = c.identity_id WHERE i.name = :name"
            ),
            {"name": name},
        ).scalar_one()
    assert count == 0


def test_the_cli_refuses_the_worker_role_for_humans(test_database: str) -> None:
    name = f"user-{uuid4().hex[:12]}"

    rejected = _cli(
        test_database, "identity", "create", name, "--kind", "human", "--role", "worker"
    )
    system = _cli(test_database, "credential", "issue", "system:worker")

    assert rejected.returncode == 1
    assert "reserved for system identities" in rejected.stderr
    assert system.returncode == 1
    assert "system identities cannot be changed or given credentials" in system.stderr


def test_issuing_needs_a_valid_pepper(test_database: str) -> None:
    result = _cli(
        test_database, "credential", "issue", "system:cli", AEGIS_TOKEN_PEPPER="too-short"
    )

    assert result.returncode == 1
    assert result.stderr.startswith("error: invalid configuration: AEGIS_TOKEN_PEPPER")
    assert "too-short" not in result.stderr


def test_database_errors_do_not_echo_secrets(
    test_database: str, owner_settings: DatabaseSettings
) -> None:
    result = _cli(test_database, "credential", "revoke", str(UUID(int=0)))

    assert result.returncode == 1
    assert result.stderr == f"error: credential {UUID(int=0)} not found\n"
    for secret in _secrets(owner_settings):
        assert secret not in result.stdout + result.stderr


def test_administration_refuses_an_outdated_schema(
    test_database: str, owner_engine: Engine
) -> None:
    downgrade(owner_engine, "0007")
    try:
        result = _cli(test_database, "identity", "create", "late-user", "--kind", "human")
    finally:
        upgrade(owner_engine)

    assert result.returncode == 1
    assert "not at the current schema revision; run `make migrate`" in result.stderr

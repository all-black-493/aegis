from collections.abc import Iterator
from uuid import uuid4

import psycopg
import pytest
from psycopg import errors
from psycopg.rows import TupleRow

from aegis.config.settings import DatabaseSettings
from aegis.db.engine import connect
from aegis.identity.schema import SYSTEM_CLI_ID, SYSTEM_WORKER_ID

CLI = str(SYSTEM_CLI_ID)
WORKER = str(SYSTEM_WORKER_ID)
HASH = "decode(repeat('ab', 32), 'hex')"
LOOKUP = "'" + "a" * 26 + "'"


def _connect(settings: DatabaseSettings) -> psycopg.Connection[TupleRow]:
    return connect(settings, application_name="aegis-tests")


@pytest.fixture
def owner(owner_settings: DatabaseSettings) -> Iterator[psycopg.Connection[TupleRow]]:
    with _connect(owner_settings) as connection:
        yield connection
        connection.rollback()


def _human(connection: psycopg.Connection[TupleRow]) -> str:
    identity_id = str(uuid4())
    connection.execute(
        "INSERT INTO aegis.identities (id, kind, name, created_by) VALUES (%s, 'human', %s, %s)",
        (identity_id, f"human-{identity_id[:8]}", CLI),
    )
    return identity_id


def _insert_credential(
    connection: psycopg.Connection[TupleRow],
    identity_id: str,
    *,
    expires: str = "now() + interval '30 days'",
    created: str = "now()",
    lookup: str = LOOKUP,
    secret_hash: str = HASH,
) -> str:
    credential_id = str(uuid4())
    connection.execute(
        "INSERT INTO aegis.credentials (id, identity_id, lookup_id, secret_hash, hash_scheme,"
        f" created_by, created_at, expires_at) VALUES (%s, %s, {lookup}, {secret_hash},"
        f" 'hmac-sha256-v1', %s, {created}, {expires})",
        (credential_id, identity_id, CLI),
    )
    return credential_id


def test_system_identities_are_seeded_with_fixed_ids(owner: psycopg.Connection[TupleRow]) -> None:
    rows = owner.execute(
        "SELECT i.id::text, i.kind, i.name, i.status, array_remove(array_agg(r.role), NULL)"
        " FROM aegis.identities i LEFT JOIN aegis.identity_roles r ON r.identity_id = i.id"
        " WHERE i.kind = 'system' GROUP BY i.id ORDER BY i.name"
    ).fetchall()

    assert rows == [
        (CLI, "system", "system:cli", "active", []),
        (WORKER, "system", "system:worker", "active", ["worker"]),
    ]


@pytest.mark.parametrize(
    ("table", "column"),
    [("identities", "status"), ("identity_roles", "role"), ("credentials", "revoked_at")],
)
@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO aegis.{table} DEFAULT VALUES",
        "UPDATE aegis.{table} SET {column} = {column}",
        "DELETE FROM aegis.{table}",
        "TRUNCATE aegis.{table}",
    ],
)
def test_application_role_cannot_write_identity_tables(
    app_settings: DatabaseSettings, table: str, column: str, statement: str
) -> None:
    sql = statement.format(table=table, column=column)

    with _connect(app_settings) as connection, pytest.raises(errors.InsufficientPrivilege):
        connection.execute(sql.encode())


def test_application_role_can_read_identity_tables(app_settings: DatabaseSettings) -> None:
    with _connect(app_settings) as connection:
        for table in ("identities", "identity_roles", "credentials"):
            connection.execute(f"SELECT count(*) FROM aegis.{table}".encode())


@pytest.mark.parametrize(
    ("expires", "created"),
    [
        ("now() + interval '90 days 1 second'", "now()"),
        ("now() + interval '10 years'", "now()"),
        ("now()", "now()"),
        ("now() - interval '1 day'", "now()"),
        ("now() + interval '120 days'", "now() + interval '60 days'"),
    ],
)
def test_database_refuses_lifetimes_outside_90_days(
    owner: psycopg.Connection[TupleRow], expires: str, created: str
) -> None:
    identity_id = _human(owner)

    with pytest.raises(errors.CheckViolation, match="ck_credentials_lifetime"):
        _insert_credential(owner, identity_id, expires=expires, created=created)


def test_database_accepts_exactly_90_days_and_stamps_creation(
    owner: psycopg.Connection[TupleRow],
) -> None:
    credential_id = _insert_credential(
        owner,
        _human(owner),
        expires="now() + interval '90 days'",
        created="'2000-01-01'",
    )

    row = owner.execute(
        "SELECT created_at = now(), expires_at - created_at FROM aegis.credentials WHERE id = %s",
        (credential_id,),
    ).fetchone()
    assert row is not None
    assert row[0] is True
    assert row[1].days == 90


@pytest.mark.parametrize(
    ("column", "value"),
    [("lookup", "'UPPERCASE0000000000000000A'"), ("lookup", "'short'"), ("hash", "'\\x00'")],
)
def test_database_rejects_malformed_credentials(
    owner: psycopg.Connection[TupleRow], column: str, value: str
) -> None:
    identity_id = _human(owner)
    overrides = {"lookup": value} if column == "lookup" else {"secret_hash": value}

    with pytest.raises(errors.CheckViolation):
        _insert_credential(owner, identity_id, **overrides)


def test_system_identities_cannot_hold_credentials(owner: psycopg.Connection[TupleRow]) -> None:
    with pytest.raises(errors.RaiseException, match="system identities cannot hold credentials"):
        _insert_credential(owner, WORKER)


@pytest.mark.parametrize(
    ("identity", "role"),
    [("human", "worker"), ("system", "admin"), ("system", "operator")],
)
def test_database_reserves_the_worker_role_for_system_identities(
    owner: psycopg.Connection[TupleRow], identity: str, role: str
) -> None:
    identity_id = _human(owner) if identity == "human" else CLI

    with pytest.raises(errors.RaiseException, match="cannot be held"):
        owner.execute(
            "INSERT INTO aegis.identity_roles (identity_id, role, granted_by) VALUES (%s, %s, %s)",
            (identity_id, role, CLI),
        )


@pytest.mark.parametrize(
    ("kind", "name"),
    [("human", "system:admin"), ("system", "worker-2"), ("human", "Upper"), ("service", "")],
)
def test_database_rejects_invalid_identity_names(
    owner: psycopg.Connection[TupleRow], kind: str, name: str
) -> None:
    with pytest.raises(errors.CheckViolation):
        owner.execute(
            "INSERT INTO aegis.identities (id, kind, name) VALUES (gen_random_uuid(), %s, %s)",
            (kind, name),
        )


@pytest.mark.parametrize(
    "change",
    [
        "SET expires_at = expires_at + interval '1 day'",
        "SET secret_hash = decode(repeat('cd', 32), 'hex')",
        "SET identity_id = '{cli}'",
        "SET lookup_id = '" + "b" * 26 + "'",
    ],
)
def test_credentials_cannot_be_altered(owner: psycopg.Connection[TupleRow], change: str) -> None:
    credential_id = _insert_credential(owner, _human(owner))

    with pytest.raises(errors.RaiseException, match="can only be revoked"):
        owner.execute(
            f"UPDATE aegis.credentials {change.format(cli=CLI)} WHERE id = %s".encode(),
            (credential_id,),
        )


def test_revocation_is_permanent(owner: psycopg.Connection[TupleRow]) -> None:
    credential_id = _insert_credential(owner, _human(owner))
    owner.execute(
        "UPDATE aegis.credentials SET revoked_at = now(), revoked_by = %s WHERE id = %s",
        (CLI, credential_id),
    )

    with pytest.raises(errors.RaiseException, match="revoked credential cannot be changed"):
        owner.execute(
            "UPDATE aegis.credentials SET revoked_at = NULL, revoked_by = NULL WHERE id = %s",
            (credential_id,),
        )


@pytest.mark.parametrize(
    ("statement", "message"),
    [
        ("DELETE FROM aegis.credentials", "never deleted"),
        ("DELETE FROM aegis.identities WHERE kind = 'human'", "never deleted"),
        ("TRUNCATE aegis.credentials CASCADE", "never deleted"),
        ("TRUNCATE aegis.identities CASCADE", "never deleted"),
        ("UPDATE aegis.identities SET name = name || '-x'", "only an identity's status"),
        ("UPDATE aegis.identities SET kind = 'service' WHERE kind = 'human'", "status can change"),
    ],
)
def test_identities_and_credentials_are_never_deleted_or_renamed(
    owner: psycopg.Connection[TupleRow], statement: str, message: str
) -> None:
    _insert_credential(owner, _human(owner))

    with pytest.raises(errors.RaiseException, match=message):
        owner.execute(statement.encode())


def test_audit_actors_must_be_known_identities(app_settings: DatabaseSettings) -> None:
    with _connect(app_settings) as connection, pytest.raises(errors.ForeignKeyViolation):
        connection.execute(
            "INSERT INTO aegis.audit_events (event_id, event_type, source, outcome, actor_id,"
            " actor_kind) VALUES (gen_random_uuid(), 'task.created', 'api', 'success',"
            " gen_random_uuid(), 'human')"
        )

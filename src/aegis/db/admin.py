import re

from psycopg import sql

from aegis.config.settings import APP_ROLE, OWNER_ROLE, DatabaseSettings, Secret
from aegis.db.engine import connect
from aegis.db.metadata import SCHEMA

BOOTSTRAP_LOCK = 7_301_001
TEST_DATABASE = re.compile(r"[a-z][a-z0-9_]*_test")
ROLE_ATTRIBUTES = sql.SQL("LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS")


def bootstrap(
    admin: DatabaseSettings, database: str, owner_password: Secret, app_password: Secret
) -> list[str]:
    actions = []
    with (
        connect(admin, database=database, application_name="aegis-bootstrap") as connection,
        connection.transaction(),
    ):
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (BOOTSTRAP_LOCK,))
        for role, password in ((OWNER_ROLE, owner_password), (APP_ROLE, app_password)):
            # Hashed client-side so the plaintext password never reaches the server or its logs.
            verifier = connection.pgconn.encrypt_password(
                password.reveal().encode(), role.encode(), b"scram-sha-256"
            ).decode()
            exists = (
                connection.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
                is not None
            )
            verb = sql.SQL("ALTER" if exists else "CREATE")
            connection.execute(
                sql.SQL("{} ROLE {} WITH {} PASSWORD {}").format(
                    verb, sql.Identifier(role), ROLE_ATTRIBUTES, sql.Literal(verifier)
                )
            )
            actions.append(f"role {role}: {'updated' if exists else 'created'}")
        target, schema = sql.Identifier(database), sql.Identifier(SCHEMA)
        owner, app = sql.Identifier(OWNER_ROLE), sql.Identifier(APP_ROLE)
        for statement in (
            sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(target),
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}, {}").format(target, owner, app),
            sql.SQL("REVOKE ALL ON SCHEMA public FROM PUBLIC"),
            sql.SQL("CREATE SCHEMA IF NOT EXISTS {} AUTHORIZATION {}").format(schema, owner),
            sql.SQL("ALTER SCHEMA {} OWNER TO {}").format(schema, owner),
            sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(schema),
            sql.SQL("ALTER ROLE {} IN DATABASE {} SET search_path = {}").format(
                owner, target, schema
            ),
            sql.SQL("ALTER ROLE {} IN DATABASE {} SET search_path = {}").format(
                app, target, schema
            ),
        ):
            connection.execute(statement)
        actions.append(
            f"database {database}: schema {SCHEMA} owned by {OWNER_ROLE}; PUBLIC access revoked"
        )
    return actions


def recreate_test_database(admin: DatabaseSettings, name: str) -> None:
    if not TEST_DATABASE.fullmatch(name) or name == admin.name:
        raise ValueError(f"refusing to recreate {name!r}: only databases named *_test may be reset")
    with connect(
        admin, database="postgres", autocommit=True, application_name="aegis-test-setup"
    ) as connection:
        target = sql.Identifier(name)
        connection.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(target))
        connection.execute(sql.SQL("CREATE DATABASE {}").format(target))

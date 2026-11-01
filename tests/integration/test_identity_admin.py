from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Connection, Engine, select, text

from aegis.audit.recorder import AuditRecorder
from aegis.audit.schema import audit_events
from aegis.authorization.catalog import IdentityKind, Role
from aegis.config.logs import Redactor
from aegis.config.settings import Secret
from aegis.identity.admin import AdministrationError, IdentityAdministration, IssuedCredential
from aegis.identity.authentication import AuthenticationError, FailureReason, authenticate
from aegis.identity.schema import SYSTEM_CLI_ID, credentials
from aegis.identity.tokens import TOKEN_PREFIX

PEPPER = Secret("identity-test-pepper-0123456789abcdef0123")
HUMAN, SERVICE = IdentityKind.HUMAN, IdentityKind.SERVICE


def _name(prefix: str = "user") -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


def _administration(connection: Connection) -> IdentityAdministration:
    return IdentityAdministration(connection, AuditRecorder(Redactor([PEPPER.reveal()])))


@pytest.fixture
def connection(owner_engine: Engine) -> Iterator[Connection]:
    with owner_engine.connect() as connection:
        transaction = connection.begin()
        yield connection
        transaction.rollback()


@pytest.fixture
def admin(connection: Connection) -> IdentityAdministration:
    return _administration(connection)


def _events(connection: Connection, target_id: UUID) -> list[tuple[Any, ...]]:
    rows = connection.execute(
        select(
            audit_events.c.event_type,
            audit_events.c.source,
            audit_events.c.actor_id,
            audit_events.c.actor_kind,
            audit_events.c.details,
        )
        .where(audit_events.c.target_id == str(target_id))
        .order_by(audit_events.c.id)
    )
    return [tuple(row) for row in rows]


def _issue(owner_engine: Engine, kind: IdentityKind = HUMAN, *roles: Role) -> IssuedCredential:
    name = _name()
    with owner_engine.begin() as connection:
        administration = _administration(connection)
        administration.create_identity(name, kind, roles)
        return administration.issue_credential(name, PEPPER)


def _failure(engine: Engine, token: str | None, **options: Any) -> AuthenticationError:
    with engine.connect() as connection, pytest.raises(AuthenticationError) as excinfo:
        authenticate(connection, token, options.pop("pepper", PEPPER), **options)
    return excinfo.value


def test_created_identities_and_roles_are_audited(
    admin: IdentityAdministration, connection: Connection
) -> None:
    name = _name()

    identity_id = admin.create_identity(name, HUMAN, [Role.OPERATOR, Role.AUDITOR])

    cli = (SYSTEM_CLI_ID, "system")
    assert _events(connection, identity_id) == [
        ("identity.created", "cli", *cli, {"kind": "human", "name": name}),
        ("role.granted", "cli", *cli, {"role": "auditor"}),
        ("role.granted", "cli", *cli, {"role": "operator"}),
    ]


@pytest.mark.parametrize(
    ("name", "kind", "roles", "message"),
    [
        ("system:extra", HUMAN, (), "created only by migrations"),
        ("robot", IdentityKind.SYSTEM, (), "created only by migrations"),
        ("Bad Name", HUMAN, (), "identity names"),
        ("alice-worker", HUMAN, (Role.WORKER,), "reserved for system identities"),
        ("ci-worker", SERVICE, (Role.OPERATOR, Role.WORKER), "reserved for system identities"),
    ],
)
def test_invalid_identities_are_refused(
    admin: IdentityAdministration,
    name: str,
    kind: IdentityKind,
    roles: tuple[Role, ...],
    message: str,
) -> None:
    with pytest.raises(AdministrationError, match=message):
        admin.create_identity(name, kind, roles)


def test_duplicate_identities_are_refused(admin: IdentityAdministration) -> None:
    name = _name()
    admin.create_identity(name, SERVICE)

    with pytest.raises(AdministrationError, match="already exists"):
        admin.create_identity(name, HUMAN)


def test_humans_cannot_be_granted_the_worker_role(admin: IdentityAdministration) -> None:
    name = _name()
    admin.create_identity(name, HUMAN)

    with pytest.raises(AdministrationError, match="reserved for system identities"):
        admin.grant_role(name, Role.WORKER)


@pytest.mark.parametrize("name", ["system:worker", "system:cli"])
def test_system_identities_cannot_be_changed(admin: IdentityAdministration, name: str) -> None:
    for change in (
        lambda: admin.disable_identity(name),
        lambda: admin.grant_role(name, Role.ADMIN),
        lambda: admin.revoke_role(name, Role.WORKER),
        lambda: admin.issue_credential(name, PEPPER),
    ):
        with pytest.raises(AdministrationError, match="system identities cannot be changed"):
            change()


@pytest.mark.parametrize("days", [0, -1, 91, 365])
def test_lifetimes_outside_1_to_90_days_are_refused(
    admin: IdentityAdministration, days: int
) -> None:
    name = _name()
    admin.create_identity(name, HUMAN)

    with pytest.raises(AdministrationError, match="1 to 90 days"):
        admin.issue_credential(name, PEPPER, days=days)


@pytest.mark.parametrize(("days", "expected"), [(None, 30), (1, 1), (90, 90)])
def test_credentials_expire_after_the_requested_lifetime(
    admin: IdentityAdministration, connection: Connection, days: int | None, expected: int
) -> None:
    name = _name()
    admin.create_identity(name, HUMAN)

    issued = admin.issue_credential(name, PEPPER, days=days)

    created_at = connection.execute(text("SELECT now()")).scalar_one()
    assert issued.expires_at - created_at == timedelta(days=expected)
    assert _events(connection, issued.credential_id) == [
        (
            "credential.issued",
            "cli",
            SYSTEM_CLI_ID,
            "system",
            {"expires_at": issued.expires_at.isoformat()},
        )
    ]


def test_disabled_identities_cannot_be_issued_credentials(admin: IdentityAdministration) -> None:
    name = _name()
    admin.create_identity(name, HUMAN, [Role.OPERATOR])
    admin.disable_identity(name)

    with pytest.raises(AdministrationError, match="is disabled"):
        admin.issue_credential(name, PEPPER)


def test_tokens_are_stored_only_as_peppered_hashes(owner_engine: Engine) -> None:
    issued = _issue(owner_engine)
    token = issued.token.reveal()
    secret = token.rsplit("_", 1)[1]

    with owner_engine.connect() as connection:
        stored = connection.execute(
            select(credentials).where(credentials.c.id == issued.credential_id)
        ).one()
        dump = connection.execute(
            text(
                "SELECT string_agg(t::text, ' ') FROM ("
                " SELECT row_to_json(c)::text AS t FROM aegis.credentials c"
                " UNION ALL SELECT row_to_json(a)::text FROM aegis.audit_events a) rows"
            )
        ).scalar_one()

    assert stored.secret_hash == issued.token.digest(PEPPER)
    assert stored.hash_scheme == "hmac-sha256-v1"
    assert secret not in dump
    assert secret.encode().hex() not in dump
    assert secret not in repr(issued)
    assert secret not in repr(issued.token) + str(issued.token)


def test_a_valid_token_authenticates_through_the_application_role(
    owner_engine: Engine, app_engine: Engine
) -> None:
    issued = _issue(owner_engine, HUMAN, Role.OPERATOR, Role.AUDITOR)

    with app_engine.connect() as connection:
        actor = authenticate(connection, issued.token.reveal(), PEPPER)

    assert actor.kind is HUMAN
    assert actor.roles == {Role.OPERATOR, Role.AUDITOR}
    assert actor.credential_id == issued.credential_id


@pytest.mark.parametrize(
    ("token", "reason"),
    [
        (None, FailureReason.MISSING),
        ("", FailureReason.MISSING),
        ("Bearer something", FailureReason.MALFORMED),
        (TOKEN_PREFIX + "a" * 26, FailureReason.MALFORMED),
        (TOKEN_PREFIX + "A" * 26 + "_" + "a" * 52, FailureReason.MALFORMED),
        (TOKEN_PREFIX + "a" * 26 + "_" + "a" * 5000, FailureReason.MALFORMED),
        (TOKEN_PREFIX + "a" * 26 + "_" + "a" * 52, FailureReason.UNKNOWN),
    ],
)
def test_missing_malformed_and_unknown_tokens_are_rejected(
    app_engine: Engine, token: str | None, reason: FailureReason
) -> None:
    failure = _failure(app_engine, token)

    assert failure.reason is reason
    assert (failure.credential_id, failure.identity_id) == (None, None)


def test_a_wrong_secret_or_pepper_is_rejected(owner_engine: Engine, app_engine: Engine) -> None:
    issued = _issue(owner_engine)
    token = issued.token.reveal()
    forged = token[:-1] + ("a" if token[-1] != "a" else "b")

    for failure in (
        _failure(app_engine, forged),
        _failure(app_engine, token, pepper=Secret("another-pepper-0123456789abcdef01234")),
    ):
        assert failure.reason is FailureReason.INVALID_SECRET
        assert failure.credential_id == issued.credential_id


def test_revoked_tokens_are_rejected(owner_engine: Engine, app_engine: Engine) -> None:
    issued = _issue(owner_engine)
    with owner_engine.begin() as connection:
        _administration(connection).revoke_credential(issued.credential_id)

    assert _failure(app_engine, issued.token.reveal()).reason is FailureReason.REVOKED


def test_expired_tokens_are_rejected(owner_engine: Engine, app_engine: Engine) -> None:
    issued = _issue(owner_engine)
    token = issued.token.reveal()

    with app_engine.connect() as connection:
        authenticate(connection, token, PEPPER, now=issued.expires_at - timedelta(seconds=1))
    failure = _failure(app_engine, token, now=issued.expires_at)

    assert failure.reason is FailureReason.EXPIRED


def test_disabled_identities_are_rejected_until_enabled(
    owner_engine: Engine, app_engine: Engine
) -> None:
    issued = _issue(owner_engine)
    with owner_engine.begin() as connection:
        _administration(connection).disable_identity(issued.identity_name)

    assert _failure(app_engine, issued.token.reveal()).reason is FailureReason.IDENTITY_DISABLED

    with owner_engine.begin() as connection:
        _administration(connection).enable_identity(issued.identity_name)
    with app_engine.connect() as connection:
        assert authenticate(connection, issued.token.reveal(), PEPPER).credential_id


def test_revocation_is_audited_and_cannot_be_repeated(
    admin: IdentityAdministration, connection: Connection
) -> None:
    name = _name()
    admin.create_identity(name, HUMAN)
    issued = admin.issue_credential(name, PEPPER, description="laptop")

    admin.revoke_credential(issued.credential_id)

    assert [event[0] for event in _events(connection, issued.credential_id)] == [
        "credential.issued",
        "credential.revoked",
    ]
    with pytest.raises(AdministrationError, match="already revoked"):
        admin.revoke_credential(issued.credential_id)
    with pytest.raises(AdministrationError, match="not found"):
        admin.revoke_credential(uuid4())


def test_listing_shows_state_without_secrets_and_is_audited(
    admin: IdentityAdministration, connection: Connection
) -> None:
    name = _name()
    identity_id = admin.create_identity(name, SERVICE)
    kept = admin.issue_credential(name, PEPPER, description="ci runner")
    revoked = admin.issue_credential(name, PEPPER)
    admin.revoke_credential(revoked.credential_id)

    listed = admin.list_credentials(name)

    assert {(c.credential_id, c.state, c.description) for c in listed} == {
        (kept.credential_id, "active", "ci runner"),
        (revoked.credential_id, "revoked", None),
    }
    assert TOKEN_PREFIX not in repr(listed)
    assert _events(connection, identity_id)[-1][0] == "credential.listed"


@pytest.mark.parametrize("description", ["", "x" * 201, "line\nbreak"])
def test_invalid_descriptions_are_refused(admin: IdentityAdministration, description: str) -> None:
    name = _name()
    admin.create_identity(name, HUMAN)

    with pytest.raises(AdministrationError, match="descriptions"):
        admin.issue_credential(name, PEPPER, description=description)


def _only_admin(admin: IdentityAdministration, connection: Connection) -> str:
    name = _name("admin")
    admin.create_identity(name, HUMAN, [Role.ADMIN])
    others = connection.execute(
        text(
            "SELECT i.name FROM aegis.identities i JOIN aegis.identity_roles r"
            " ON r.identity_id = i.id WHERE r.role = 'admin' AND i.status = 'active'"
            " AND i.name <> :name"
        ),
        {"name": name},
    ).scalars()
    for other in list(others):
        admin.disable_identity(other)
    return name


def test_the_last_admin_cannot_be_disabled_or_demoted(
    admin: IdentityAdministration, connection: Connection
) -> None:
    last = _only_admin(admin, connection)

    with pytest.raises(AdministrationError, match="last active admin"):
        admin.disable_identity(last)
    with pytest.raises(AdministrationError, match="last active admin"):
        admin.revoke_role(last, Role.ADMIN)


def test_an_admin_can_be_removed_while_another_remains(
    admin: IdentityAdministration, connection: Connection
) -> None:
    first = _only_admin(admin, connection)
    second = _name("admin")
    admin.create_identity(second, HUMAN, [Role.ADMIN])

    admin.revoke_role(first, Role.ADMIN)

    with pytest.raises(AdministrationError, match="last active admin"):
        admin.disable_identity(second)


def test_disabled_admins_do_not_count(
    admin: IdentityAdministration, connection: Connection
) -> None:
    active = _only_admin(admin, connection)
    disabled = _name("admin")
    admin.create_identity(disabled, HUMAN, [Role.ADMIN])
    admin.disable_identity(disabled)

    with pytest.raises(AdministrationError, match="last active admin"):
        admin.revoke_role(active, Role.ADMIN)
    admin.revoke_role(disabled, Role.ADMIN)


def _create_then_refuse(engine: Engine, name: str) -> None:
    with engine.begin() as connection:
        administration = _administration(connection)
        administration.create_identity(name, HUMAN)
        administration.issue_credential(name, PEPPER, days=91)


def test_refused_changes_record_nothing(owner_engine: Engine) -> None:
    name = _name()
    before = datetime.now(UTC)

    with pytest.raises(AdministrationError):
        _create_then_refuse(owner_engine, name)

    with owner_engine.connect() as connection:
        found = connection.execute(
            text(
                "SELECT count(*) FROM aegis.audit_events"
                " WHERE occurred_at >= :before AND details->>'name' = :name"
            ),
            {"before": before, "name": name},
        ).scalar_one()
        exists = connection.execute(
            text("SELECT count(*) FROM aegis.identities WHERE name = :name"), {"name": name}
        ).scalar_one()
    assert (found, exists) == (0, 0)


def test_administration_requires_a_transaction(owner_engine: Engine) -> None:
    with owner_engine.connect() as connection:
        connection.execute(text("SELECT 1"))
        connection.commit()
        with pytest.raises(AdministrationError, match="requires a transaction"):
            _administration(connection)

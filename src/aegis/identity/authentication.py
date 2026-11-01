from datetime import datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy import Connection, func, literal, select
from sqlalchemy.dialects.postgresql import TIMESTAMP

from aegis.authorization.access import ActorContext
from aegis.authorization.catalog import IdentityKind, Role
from aegis.config.settings import Secret
from aegis.identity.schema import credentials, identities, identity_roles
from aegis.identity.tokens import HASH_SCHEME, generate_token, parse_token

_UNKNOWN_DIGEST = bytes(32)


class FailureReason(StrEnum):
    MISSING = "missing"
    MALFORMED = "malformed"
    UNKNOWN = "unknown"
    INVALID_SECRET = "invalid_secret"  # noqa: S105
    REVOKED = "revoked"
    EXPIRED = "expired"
    IDENTITY_DISABLED = "identity_disabled"


class AuthenticationError(Exception):
    def __init__(
        self,
        reason: FailureReason,
        credential_id: UUID | None = None,
        identity_id: UUID | None = None,
    ) -> None:
        super().__init__(f"authentication failed: {reason}")
        self.reason = reason
        self.credential_id = credential_id
        self.identity_id = identity_id


def authenticate(
    connection: Connection, raw_token: str | None, pepper: Secret, *, now: datetime | None = None
) -> ActorContext:
    if not raw_token:
        raise AuthenticationError(FailureReason.MISSING)
    token = parse_token(raw_token)
    if token is None:
        raise AuthenticationError(FailureReason.MALFORMED)
    at = func.now() if now is None else literal(now, TIMESTAMP(timezone=True))
    row = connection.execute(
        select(
            credentials.c.id,
            credentials.c.identity_id,
            credentials.c.secret_hash,
            credentials.c.hash_scheme,
            credentials.c.revoked_at,
            (credentials.c.expires_at <= at).label("expired"),
            identities.c.kind,
            identities.c.status,
        )
        .join(identities, identities.c.id == credentials.c.identity_id)
        .where(credentials.c.lookup_id == token.lookup_id)
    ).first()
    if row is None:
        # Spend the same hashing work as a known lookup ID would.
        generate_token().matches(pepper, _UNKNOWN_DIGEST)
        raise AuthenticationError(FailureReason.UNKNOWN)
    known = {"credential_id": row.id, "identity_id": row.identity_id}
    if row.hash_scheme != HASH_SCHEME or not token.matches(pepper, row.secret_hash):
        raise AuthenticationError(FailureReason.INVALID_SECRET, **known)
    if row.revoked_at is not None:
        raise AuthenticationError(FailureReason.REVOKED, **known)
    if row.expired:
        raise AuthenticationError(FailureReason.EXPIRED, **known)
    if row.status != "active":
        raise AuthenticationError(FailureReason.IDENTITY_DISABLED, **known)
    roles = connection.execute(
        select(identity_roles.c.role).where(identity_roles.c.identity_id == row.identity_id)
    ).scalars()
    return ActorContext(
        identity_id=row.identity_id,
        kind=IdentityKind(row.kind),
        roles=frozenset(Role(role) for role in roles),
        credential_id=row.id,
    )

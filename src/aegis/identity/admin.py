import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Connection, delete, func, insert, select, text, update

from aegis.audit.events import ActorKind, AuditEvent, AuditEventType, DetailValue, Outcome, Source
from aegis.audit.recorder import AuditRecorder
from aegis.authorization.catalog import SYSTEM_ROLES, IdentityKind, Role
from aegis.config.settings import Secret
from aegis.identity.schema import SYSTEM_CLI_ID, credentials, identities, identity_roles
from aegis.identity.tokens import HASH_SCHEME, Token, generate_token, lifetime

ADMINISTRATION_LOCK = 7_301_003
MAX_DESCRIPTION_LENGTH = 200
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9._:-]{0,62}")
SYSTEM_PREFIX = "system:"


class AdministrationError(ValueError):
    pass


@dataclass(frozen=True)
class _Identity:
    id: UUID
    kind: IdentityKind
    status: str


@dataclass(frozen=True)
class IssuedCredential:
    credential_id: UUID
    identity_name: str
    expires_at: datetime
    token: Token


@dataclass(frozen=True)
class CredentialInfo:
    credential_id: UUID
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    expired: bool
    description: str | None

    @property
    def state(self) -> str:
        if self.revoked_at is not None:
            return "revoked"
        return "expired" if self.expired else "active"


class IdentityAdministration:
    def __init__(self, connection: Connection, recorder: AuditRecorder) -> None:
        if not connection.in_transaction():
            raise AdministrationError("administration requires a transaction")
        self._connection = connection
        self._recorder = recorder

    def create_identity(self, name: str, kind: IdentityKind, roles: Iterable[Role] = ()) -> UUID:
        if kind is IdentityKind.SYSTEM or name.startswith(SYSTEM_PREFIX):
            raise AdministrationError("system identities are created only by migrations")
        if not NAME_PATTERN.fullmatch(name):
            raise AdministrationError(
                "identity names are 1 to 63 characters of a-z, 0-9, '.', '_', ':' and '-',"
                " starting with a letter or digit"
            )
        roles = sorted(set(roles))
        self._refuse_system_roles(roles)
        self._lock()
        if self._find(name) is not None:
            raise AdministrationError(f"identity {name} already exists")
        identity_id = uuid4()
        self._connection.execute(
            insert(identities).values(
                id=identity_id, kind=kind.value, name=name, created_by=SYSTEM_CLI_ID
            )
        )
        self._audit(
            AuditEventType.IDENTITY_CREATED, "identity", identity_id, kind=kind.value, name=name
        )
        for role in roles:
            self._insert_role(identity_id, role)
        return identity_id

    def disable_identity(self, name: str) -> None:
        self._lock()
        identity = self._require_changeable(name)
        if identity.status == "disabled":
            raise AdministrationError(f"identity {name} is already disabled")
        if self._holds(identity.id, Role.ADMIN):
            self._require_another_admin(identity.id)
        self._connection.execute(
            update(identities)
            .where(identities.c.id == identity.id)
            .values(status="disabled", disabled_at=func.now())
        )
        self._audit(AuditEventType.IDENTITY_DISABLED, "identity", identity.id)

    def enable_identity(self, name: str) -> None:
        self._lock()
        identity = self._require_changeable(name)
        if identity.status == "active":
            raise AdministrationError(f"identity {name} is already active")
        self._connection.execute(
            update(identities)
            .where(identities.c.id == identity.id)
            .values(status="active", disabled_at=None)
        )
        self._audit(AuditEventType.IDENTITY_ENABLED, "identity", identity.id)

    def issue_credential(
        self,
        name: str,
        pepper: Secret,
        *,
        days: int | None = None,
        description: str | None = None,
    ) -> IssuedCredential:
        try:
            duration = lifetime(days)
        except ValueError as error:
            raise AdministrationError(str(error)) from None
        if description is not None and not (
            1 <= len(description) <= MAX_DESCRIPTION_LENGTH and description.isprintable()
        ):
            raise AdministrationError(
                f"descriptions are 1 to {MAX_DESCRIPTION_LENGTH} printable characters"
            )
        self._lock()
        identity = self._require_changeable(name)
        if identity.status != "active":
            raise AdministrationError(f"identity {name} is disabled")
        token = generate_token()
        credential_id = uuid4()
        expires_at = self._connection.execute(
            insert(credentials)
            .values(
                id=credential_id,
                identity_id=identity.id,
                lookup_id=token.lookup_id,
                secret_hash=token.digest(pepper),
                hash_scheme=HASH_SCHEME,
                description=description,
                created_by=SYSTEM_CLI_ID,
                expires_at=func.now() + duration,
            )
            .returning(credentials.c.expires_at)
        ).scalar_one()
        self._audit(
            AuditEventType.CREDENTIAL_ISSUED,
            "credential",
            credential_id,
            expires_at=expires_at.isoformat(),
        )
        return IssuedCredential(credential_id, name, expires_at, token)

    def revoke_credential(self, credential_id: UUID) -> None:
        self._lock()
        row = self._connection.execute(
            select(credentials.c.revoked_at).where(credentials.c.id == credential_id)
        ).first()
        if row is None:
            raise AdministrationError(f"credential {credential_id} not found")
        if row.revoked_at is not None:
            raise AdministrationError(f"credential {credential_id} is already revoked")
        self._connection.execute(
            update(credentials)
            .where(credentials.c.id == credential_id)
            .values(revoked_at=func.now(), revoked_by=SYSTEM_CLI_ID)
        )
        self._audit(AuditEventType.CREDENTIAL_REVOKED, "credential", credential_id)

    def list_credentials(self, name: str) -> list[CredentialInfo]:
        identity = self._require(name)
        rows = self._connection.execute(
            select(
                credentials.c.id,
                credentials.c.created_at,
                credentials.c.expires_at,
                credentials.c.revoked_at,
                (credentials.c.expires_at <= func.now()).label("expired"),
                credentials.c.description,
            )
            .where(credentials.c.identity_id == identity.id)
            .order_by(credentials.c.created_at, credentials.c.id)
        )
        self._audit(AuditEventType.CREDENTIAL_LISTED, "identity", identity.id)
        return [CredentialInfo(*row) for row in rows]

    def grant_role(self, name: str, role: Role) -> None:
        self._refuse_system_roles([role])
        self._lock()
        identity = self._require_changeable(name)
        if self._holds(identity.id, role):
            raise AdministrationError(f"identity {name} already holds role {role}")
        self._insert_role(identity.id, role)

    def revoke_role(self, name: str, role: Role) -> None:
        self._lock()
        identity = self._require_changeable(name)
        if not self._holds(identity.id, role):
            raise AdministrationError(f"identity {name} does not hold role {role}")
        if role is Role.ADMIN and identity.status == "active":
            self._require_another_admin(identity.id)
        self._connection.execute(
            delete(identity_roles).where(
                identity_roles.c.identity_id == identity.id, identity_roles.c.role == role.value
            )
        )
        self._audit(AuditEventType.ROLE_REVOKED, "identity", identity.id, role=role.value)

    def _lock(self) -> None:
        # Serialises administration so concurrent changes cannot remove the last admin.
        self._connection.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": ADMINISTRATION_LOCK}
        )

    def _find(self, name: str) -> _Identity | None:
        row = self._connection.execute(
            select(identities.c.id, identities.c.kind, identities.c.status).where(
                identities.c.name == name
            )
        ).first()
        return None if row is None else _Identity(row.id, IdentityKind(row.kind), row.status)

    def _require(self, name: str) -> _Identity:
        identity = self._find(name)
        if identity is None:
            raise AdministrationError(f"identity {name} not found")
        return identity

    def _require_changeable(self, name: str) -> _Identity:
        identity = self._require(name)
        if identity.kind is IdentityKind.SYSTEM:
            raise AdministrationError("system identities cannot be changed or given credentials")
        return identity

    def _holds(self, identity_id: UUID, role: Role) -> bool:
        return (
            self._connection.execute(
                select(identity_roles.c.role).where(
                    identity_roles.c.identity_id == identity_id,
                    identity_roles.c.role == role.value,
                )
            ).first()
            is not None
        )

    def _require_another_admin(self, identity_id: UUID) -> None:
        others = self._connection.execute(
            select(func.count())
            .select_from(
                identity_roles.join(identities, identities.c.id == identity_roles.c.identity_id)
            )
            .where(
                identity_roles.c.role == Role.ADMIN.value,
                identities.c.status == "active",
                identities.c.id != identity_id,
            )
        ).scalar_one()
        if others == 0:
            raise AdministrationError("refusing to remove the last active admin")

    def _refuse_system_roles(self, roles: Iterable[Role]) -> None:
        reserved = sorted(set(roles) & SYSTEM_ROLES)
        if reserved:
            raise AdministrationError(
                f"role {', '.join(reserved)} is reserved for system identities"
            )

    def _insert_role(self, identity_id: UUID, role: Role) -> None:
        self._connection.execute(
            insert(identity_roles).values(
                identity_id=identity_id, role=role.value, granted_by=SYSTEM_CLI_ID
            )
        )
        self._audit(AuditEventType.ROLE_GRANTED, "identity", identity_id, role=role.value)

    def _audit(
        self, event_type: AuditEventType, target_type: str, target_id: UUID, **details: DetailValue
    ) -> None:
        self._recorder.record(
            self._connection,
            AuditEvent(
                event_type=event_type,
                source=Source.CLI,
                outcome=Outcome.SUCCESS,
                actor_id=SYSTEM_CLI_ID,
                actor_kind=ActorKind.SYSTEM,
                target_type=target_type,
                target_id=str(target_id),
                details=details,
            ),
        )

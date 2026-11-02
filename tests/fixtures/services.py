import os
from dataclasses import dataclass
from uuid import UUID, uuid4

from sqlalchemy import Engine

from aegis.audit.recorder import AuditRecorder
from aegis.authorization.access import ActorContext
from aegis.authorization.catalog import IdentityKind, Role
from aegis.config.logs import Redactor
from aegis.config.settings import WorkerSettings, load_token_pepper
from aegis.identity.admin import IdentityAdministration

# Shared by the database-backed suites, which run with the settings from .env.
PEPPER = load_token_pepper(os.environ)
RECORDER = AuditRecorder(Redactor([PEPPER.reveal()]))
FAST_WORKER = WorkerSettings(
    poll_seconds=0.05,
    lease_seconds=10,
    heartbeat_seconds=0.1,
    shutdown_grace_seconds=0.3,
    max_attempts=3,
)


@dataclass(frozen=True)
class Caller:
    name: str
    actor: ActorContext
    token: str

    @property
    def id(self) -> UUID:
        return self.actor.identity_id

    @property
    def credential_id(self) -> UUID:
        assert self.actor.credential_id is not None
        return self.actor.credential_id

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


def make_caller(owner_engine: Engine, *roles: Role, prefix: str = "caller") -> Caller:
    name = f"{prefix}-{uuid4().hex[:12]}"
    with owner_engine.begin() as connection:
        administration = IdentityAdministration(connection, AuditRecorder(Redactor()))
        identity_id = administration.create_identity(name, IdentityKind.HUMAN, roles)
        issued = administration.issue_credential(name, PEPPER)
    actor = ActorContext(identity_id, IdentityKind.HUMAN, frozenset(roles), issued.credential_id)
    return Caller(name, actor, issued.token.reveal())

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from uuid import UUID

from aegis.authorization.catalog import (
    ROLE_PERMISSIONS,
    SYSTEM_ROLES,
    Action,
    IdentityKind,
    Permission,
    ResourceType,
    Role,
)
from aegis.authorization.contract import Effect


class InvalidActorError(ValueError):
    pass


@dataclass(frozen=True)
class ActorContext:
    identity_id: UUID
    kind: IdentityKind
    roles: frozenset[Role]
    credential_id: UUID | None = None

    def __post_init__(self) -> None:
        roles = frozenset(self.roles)
        if self.kind is IdentityKind.SYSTEM:
            if roles - SYSTEM_ROLES:
                raise InvalidActorError("system identities may hold only system roles")
            if self.credential_id is not None:
                raise InvalidActorError("system identities have no credentials")
        elif roles & SYSTEM_ROLES:
            raise InvalidActorError("only system identities may hold system roles")
        object.__setattr__(self, "roles", roles)

    @property
    def permissions(self) -> frozenset[Permission]:
        return frozenset(permission for role in self.roles for permission in ROLE_PERMISSIONS[role])


@dataclass(frozen=True)
class ResourceRef:
    type: ResourceType
    id: str
    owner_id: UUID


@dataclass(frozen=True)
class Authorization:
    effect: Effect
    reason: str
    permission: Permission | None

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW


@dataclass(frozen=True)
class _Requirement:
    needs_resource: bool
    for_owner: Permission | None = None
    for_anyone: Permission | None = None


_REQUIREMENTS: Mapping[Action, _Requirement] = MappingProxyType(
    {
        Action.TASK_SUBMIT: _Requirement(True, for_owner=Permission.TASK_CREATE),
        Action.TASK_READ: _Requirement(
            True, for_owner=Permission.TASK_READ, for_anyone=Permission.TASK_READ_ANY
        ),
        Action.TASK_LIST: _Requirement(False, for_anyone=Permission.TASK_READ),
        Action.TASK_LIST_ALL: _Requirement(False, for_anyone=Permission.TASK_READ_ANY),
        Action.TASK_CANCEL: _Requirement(
            True, for_owner=Permission.TASK_CANCEL, for_anyone=Permission.TASK_CANCEL_ANY
        ),
        Action.TASK_EXECUTE: _Requirement(True, for_anyone=Permission.TASK_EXECUTE),
        Action.TOOL_INVOKE: _Requirement(True, for_anyone=Permission.TOOL_INVOKE),
    }
)


def authorize(
    actor: ActorContext, action: Action, resource: ResourceRef | None = None
) -> Authorization:
    requirement = _REQUIREMENTS.get(action)
    if requirement is None:
        return Authorization(Effect.DENY, "unknown_action", None)
    if requirement.needs_resource and resource is None:
        return Authorization(Effect.DENY, "resource_missing", None)
    permissions = actor.permissions
    if requirement.for_anyone is not None and requirement.for_anyone in permissions:
        return Authorization(Effect.ALLOW, "permitted", requirement.for_anyone)
    owns = resource is not None and resource.owner_id == actor.identity_id
    if owns and requirement.for_owner is not None and requirement.for_owner in permissions:
        return Authorization(Effect.ALLOW, "permitted_as_owner", requirement.for_owner)
    if not owns and requirement.for_anyone is None:
        return Authorization(Effect.DENY, "owner_only", requirement.for_owner)
    needed = requirement.for_owner if owns else requirement.for_anyone
    return Authorization(Effect.DENY, "missing_permission", needed)

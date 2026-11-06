from uuid import UUID, uuid4

import pytest

from aegis.authorization.access import (
    ActorContext,
    InvalidActorError,
    ResourceRef,
    authorize,
)
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

RESOURCE_ACTIONS = (
    Action.TASK_SUBMIT,
    Action.TASK_READ,
    Action.TASK_CANCEL,
    Action.TASK_EXECUTE,
    Action.TOOL_INVOKE,
)
COLLECTION_ACTIONS = (Action.TASK_LIST, Action.TASK_LIST_ALL)
CASES = [(action, owner) for action in RESOURCE_ACTIONS for owner in ("own", "other")] + [
    (action, None) for action in COLLECTION_ACTIONS
]

ALLOWED: dict[Role, set[tuple[Action, str | None]]] = {
    Role.ADMIN: {
        (Action.TASK_SUBMIT, "own"),
        (Action.TASK_READ, "own"),
        (Action.TASK_READ, "other"),
        (Action.TASK_LIST, None),
        (Action.TASK_LIST_ALL, None),
        (Action.TASK_CANCEL, "own"),
        (Action.TASK_CANCEL, "other"),
    },
    Role.OPERATOR: {
        (Action.TASK_SUBMIT, "own"),
        (Action.TASK_READ, "own"),
        (Action.TASK_LIST, None),
        (Action.TASK_CANCEL, "own"),
    },
    Role.AUDITOR: {
        (Action.TASK_READ, "own"),
        (Action.TASK_READ, "other"),
        (Action.TASK_LIST_ALL, None),
    },
    Role.WORKER: {
        (Action.TASK_EXECUTE, "own"),
        (Action.TASK_EXECUTE, "other"),
    },
    Role.AGENT: {
        (Action.TOOL_INVOKE, "own"),
        (Action.TOOL_INVOKE, "other"),
    },
}


def actor(*roles: Role) -> ActorContext:
    kind = IdentityKind.SYSTEM if SYSTEM_ROLES & set(roles) else IdentityKind.HUMAN
    return ActorContext(uuid4(), kind, frozenset(roles))


def resource_for(subject: ActorContext, owner: str | None) -> ResourceRef | None:
    if owner is None:
        return None
    owner_id: UUID = subject.identity_id if owner == "own" else uuid4()
    return ResourceRef(ResourceType.TASK, str(uuid4()), owner_id)


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize(("action", "owner"), CASES)
def test_role_action_ownership_matrix(role: Role, action: Action, owner: str | None) -> None:
    subject = actor(role)

    result = authorize(subject, action, resource_for(subject, owner))

    assert result.allowed == ((action, owner) in ALLOWED[role])
    assert result.effect in (Effect.ALLOW, Effect.DENY)


@pytest.mark.parametrize(("action", "owner"), CASES)
def test_identities_without_roles_are_denied_everything(action: Action, owner: str | None) -> None:
    subject = actor()

    assert not authorize(subject, action, resource_for(subject, owner)).allowed


def test_worker_role_grants_only_task_execute() -> None:
    assert ROLE_PERMISSIONS[Role.WORKER] == {Permission.TASK_EXECUTE}
    for role, permissions in ROLE_PERMISSIONS.items():
        if role is not Role.WORKER:
            assert Permission.TASK_EXECUTE not in permissions


def test_agent_role_grants_only_tool_invoke() -> None:
    assert ROLE_PERMISSIONS[Role.AGENT] == {Permission.TOOL_INVOKE}
    for role, permissions in ROLE_PERMISSIONS.items():
        if role is not Role.AGENT:
            assert Permission.TOOL_INVOKE not in permissions


def test_only_a_system_identity_can_hold_the_agent_role() -> None:
    with pytest.raises(InvalidActorError):
        ActorContext(uuid4(), IdentityKind.HUMAN, frozenset({Role.AGENT}))
    with pytest.raises(InvalidActorError):
        ActorContext(uuid4(), IdentityKind.SYSTEM, frozenset({Role.AGENT, Role.OPERATOR}))


def test_roles_combine_their_permissions() -> None:
    subject = actor(Role.OPERATOR, Role.AUDITOR)

    assert subject.permissions == ROLE_PERMISSIONS[Role.OPERATOR] | ROLE_PERMISSIONS[Role.AUDITOR]
    assert authorize(subject, Action.TASK_LIST_ALL).allowed


def test_unknown_actions_are_denied() -> None:
    result = authorize(actor(Role.ADMIN), "task.delete")  # type: ignore[arg-type]

    assert (result.effect, result.reason) == (Effect.DENY, "unknown_action")


@pytest.mark.parametrize("action", RESOURCE_ACTIONS)
def test_resource_actions_require_a_resource(action: Action) -> None:
    result = authorize(actor(Role.ADMIN), action, None)

    assert (result.effect, result.reason) == (Effect.DENY, "resource_missing")


def test_submitting_a_task_for_someone_else_is_refused() -> None:
    subject = actor(Role.ADMIN)

    result = authorize(subject, Action.TASK_SUBMIT, resource_for(subject, "other"))

    assert (result.reason, result.permission) == ("owner_only", Permission.TASK_CREATE)


def test_denials_name_the_missing_permission() -> None:
    subject = actor(Role.OPERATOR)

    result = authorize(subject, Action.TASK_READ, resource_for(subject, "other"))

    assert (result.reason, result.permission) == ("missing_permission", Permission.TASK_READ_ANY)


@pytest.mark.parametrize(
    ("kind", "roles", "credential"),
    [
        (IdentityKind.HUMAN, {Role.WORKER}, None),
        (IdentityKind.SERVICE, {Role.WORKER, Role.OPERATOR}, None),
        (IdentityKind.SYSTEM, {Role.ADMIN}, None),
        (IdentityKind.SYSTEM, {Role.WORKER}, uuid4()),
    ],
)
def test_invalid_actor_contexts_are_rejected(
    kind: IdentityKind, roles: set[Role], credential: UUID | None
) -> None:
    with pytest.raises(InvalidActorError):
        ActorContext(uuid4(), kind, frozenset(roles), credential)


def test_actor_roles_cannot_change_after_creation() -> None:
    roles = {Role.OPERATOR}
    subject = ActorContext(uuid4(), IdentityKind.HUMAN, roles)  # type: ignore[arg-type]
    roles.add(Role.ADMIN)

    assert subject.roles == frozenset({Role.OPERATOR})
    assert isinstance(subject.roles, frozenset)

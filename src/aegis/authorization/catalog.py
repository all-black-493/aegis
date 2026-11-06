from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType


class IdentityKind(StrEnum):
    HUMAN = "human"
    SERVICE = "service"
    SYSTEM = "system"


class Role(StrEnum):
    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    WORKER = "worker"
    AGENT = "agent"


class Permission(StrEnum):
    TASK_CREATE = "task:create"
    TASK_READ = "task:read"
    TASK_READ_ANY = "task:read_any"
    TASK_CANCEL = "task:cancel"
    TASK_CANCEL_ANY = "task:cancel_any"
    TASK_EXECUTE = "task:execute"
    TOOL_INVOKE = "tool:invoke"


class Action(StrEnum):
    TASK_SUBMIT = "task.submit"
    TASK_READ = "task.read"
    TASK_LIST = "task.list"
    TASK_LIST_ALL = "task.list_all"
    TASK_CANCEL = "task.cancel"
    TASK_EXECUTE = "task.execute"
    TOOL_INVOKE = "tool.invoke"


class ResourceType(StrEnum):
    TASK = "task"


ROLE_PERMISSIONS: Mapping[Role, frozenset[Permission]] = MappingProxyType(
    {
        Role.ADMIN: frozenset(
            {
                Permission.TASK_CREATE,
                Permission.TASK_READ,
                Permission.TASK_READ_ANY,
                Permission.TASK_CANCEL,
                Permission.TASK_CANCEL_ANY,
            }
        ),
        Role.OPERATOR: frozenset(
            {Permission.TASK_CREATE, Permission.TASK_READ, Permission.TASK_CANCEL}
        ),
        Role.AUDITOR: frozenset({Permission.TASK_READ_ANY}),
        Role.WORKER: frozenset({Permission.TASK_EXECUTE}),
        Role.AGENT: frozenset({Permission.TOOL_INVOKE}),
    }
)

SYSTEM_ROLES = frozenset({Role.WORKER, Role.AGENT})

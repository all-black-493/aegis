from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SideEffect(StrEnum):
    NONE = "none"
    WORKSPACE = "workspace"
    EXTERNAL = "external"


class NetworkAccess(StrEnum):
    NONE = "none"
    RESTRICTED = "restricted"


class Approval(StrEnum):
    NONE = "none"
    REQUIRED = "required"


class Boundary(StrEnum):
    SANDBOX = "sandbox"


class Capability(StrEnum):
    WORKSPACE_READ = "workspace:read"
    WORKSPACE_WRITE = "workspace:write"


class ToolStatus(StrEnum):
    OK = "ok"
    REFUSED = "refused"
    FAILED = "failed"


class ArgumentError(ValueError):
    # A proposal AEGIS refuses before anything runs. The code goes back to the model.
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ToolLimits:
    timeout_seconds: int
    max_output_bytes: int


@dataclass(frozen=True)
class RegisteredTool:
    name: str
    version: str
    description: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    capabilities: frozenset[Capability]
    risk: Risk
    side_effect: SideEffect
    network: NetworkAccess
    limits: ToolLimits
    approval: Approval
    permitted_roles: frozenset[str]
    boundary: Boundary
    # A fixed command for checked arguments. Proposed text reaches it only as separate arguments,
    # never as part of the program or its script.
    command: Callable[[Mapping[str, Any], ToolLimits], tuple[str, ...]]
    # What a successful command's output becomes.
    output: Callable[[Mapping[str, Any], str, ToolLimits], Mapping[str, Any]]


@dataclass(frozen=True)
class ToolResult:
    tool: str
    version: str | None
    status: ToolStatus
    code: str
    output: Mapping[str, Any]
    exit_code: int | None = None

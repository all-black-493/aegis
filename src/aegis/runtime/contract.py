import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import ClassVar, Protocol

# Every sandbox AEGIS creates is named aegis-*, so cleanup can never reach anyone else's.
SANDBOX_NAME = re.compile(r"aegis-[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?")
MANAGED_LABEL = "aegis.managed"
MAX_EXEC_SECONDS = 300
MAX_EXEC_ARGS = 64
MAX_EXEC_ARG_BYTES = 4096
MAX_EXEC_OUTPUT_BYTES = 64 * 1024
# The parts of a policy the prover must have checked for a verdict to count (ADR-0016).
REQUIRED_PROVER_DOMAINS = frozenset(
    {"filesystem", "network_l4", "network_rest", "process", "landlock"}
)
_IMAGE = re.compile(r"[a-z0-9][a-z0-9._/:@-]{0,254}")
_LABEL_KEY = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")
_LABEL_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
_CPU = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,2}|m)?")
_MEMORY = re.compile(r"[0-9]{1,5}(?:Mi|Gi)")
_DETAIL = re.compile(r"[a-z][a-z0-9_]{0,63}")


class SandboxRuntimeError(Exception):
    retryable: ClassVar[bool] = False
    default_code: ClassVar[str] = "runtime_error"

    def __init__(self, message: str = "", *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code or self.default_code


class RuntimeUnavailableError(SandboxRuntimeError):
    retryable = True
    default_code = "unavailable"


class RuntimeRefusedError(SandboxRuntimeError):
    default_code = "refused"


class RuntimeProtocolError(SandboxRuntimeError):
    default_code = "protocol_error"


class InvalidSandboxError(ValueError):
    pass


def check_sandbox_name(name: str) -> str:
    if not SANDBOX_NAME.fullmatch(name):
        raise InvalidSandboxError("sandbox names must match aegis-[a-z0-9-]")
    return name


@dataclass(frozen=True)
class SandboxSpec:
    name: str
    image: str
    policy: Path
    labels: Mapping[str, str] = field(default_factory=dict)
    cpu: str = "1"
    memory: str = "512Mi"

    def __post_init__(self) -> None:
        check_sandbox_name(self.name)
        if not _IMAGE.fullmatch(self.image):
            raise InvalidSandboxError("the image must be a plain image reference")
        if not self.policy.is_absolute():
            raise InvalidSandboxError("the policy must be an absolute path")
        if not _CPU.fullmatch(self.cpu) or not _MEMORY.fullmatch(self.memory):
            raise InvalidSandboxError("cpu and memory must be limits such as 1 and 512Mi")
        for key, value in self.labels.items():
            if not _LABEL_KEY.fullmatch(key) or not _LABEL_VALUE.fullmatch(value):
                raise InvalidSandboxError("labels must be short key=value pairs")
            if key == MANAGED_LABEL:
                raise InvalidSandboxError(f"{MANAGED_LABEL} is set by the runtime")
        object.__setattr__(self, "labels", MappingProxyType(dict(self.labels)))


@dataclass(frozen=True)
class Sandbox:
    name: str
    sandbox_id: str
    phase: str
    policy_hash: str | None
    labels: Mapping[str, str]

    @property
    def ready(self) -> bool:
        return self.phase == "Ready"


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False


@dataclass(frozen=True)
class RuntimeStatus:
    healthy: bool
    detail: str
    version: str | None = None

    def __post_init__(self) -> None:
        if not _DETAIL.fullmatch(self.detail):
            raise InvalidSandboxError("a status detail must be a short lowercase code")


class ProverResult(StrEnum):
    WITHIN_BOUNDARY = "within_boundary"
    EXCEEDS_BOUNDARY = "exceeds_boundary"
    ERROR = "error"
    UNSUPPORTED = "unsupported"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class ProverVerdict:
    result: ProverResult
    domains: frozenset[str]
    reason_code: str | None = None
    counterexample: str | None = None

    @property
    def passed(self) -> bool:
        # Only a within_boundary verdict covering every domain passes (ADR-0016).
        return (
            self.result is ProverResult.WITHIN_BOUNDARY and self.domains >= REQUIRED_PROVER_DOMAINS
        )


class SandboxRuntime(Protocol):
    def check(self) -> RuntimeStatus: ...

    def create(self, spec: SandboxSpec) -> Sandbox: ...

    def get(self, name: str) -> Sandbox | None: ...

    def exec(self, name: str, argv: Sequence[str], timeout_seconds: int) -> ExecResult: ...

    def effective_policy(self, name: str) -> str: ...

    def delete(self, name: str) -> None: ...

    def managed(self) -> tuple[Sandbox, ...]: ...

    def check_policy(self, candidate: Path, boundary: Path) -> ProverVerdict: ...


def check_exec(argv: Sequence[str], timeout_seconds: int) -> None:
    if not argv or len(argv) > MAX_EXEC_ARGS:
        raise InvalidSandboxError(f"a command needs 1 to {MAX_EXEC_ARGS} arguments")
    for arg in argv:
        if "\x00" in arg or len(arg.encode()) > MAX_EXEC_ARG_BYTES:
            raise InvalidSandboxError("command arguments must be short and contain no NUL")
    if not argv[0].startswith("/"):
        raise InvalidSandboxError("the program must be an absolute path")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= MAX_EXEC_SECONDS
    ):
        raise InvalidSandboxError(f"timeouts must be 1 to {MAX_EXEC_SECONDS} seconds")

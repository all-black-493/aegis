from dataclasses import dataclass
from enum import StrEnum

# Written into each probe's argument list and expectations, and replaced by the run's nonce, so
# every canary request and runtime record can be attributed to one run.
NONCE = "{nonce}"


class Kind(StrEnum):
    FILESYSTEM = "filesystem"
    PROCESS = "process"
    NETWORK = "network"


class Role(StrEnum):
    # A control must succeed for the run to mean anything; a restriction must be refused.
    CONTROL = "control"
    RESTRICTION = "restriction"


class Outcome(StrEnum):
    HELD = "held"
    VIOLATED = "violated"
    INCONCLUSIVE = "inconclusive"


class Verdict(StrEnum):
    VERIFIED = "verified"
    VIOLATED = "violated"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Signature:
    # What an observation must show; every field that is set must match.
    exit_zero: bool | None = None
    stdout_is: str | None = None
    stdout_has: tuple[str, ...] = ()
    stderr_has: tuple[str, ...] = ()


@dataclass(frozen=True)
class RecordPattern:
    category: str
    action: str
    detail_has: str


@dataclass(frozen=True)
class Probe:
    check_id: str
    kind: Kind
    role: Role
    argv: tuple[str, ...]
    # For a control, what success looks like; for a restriction, what a refusal looks like.
    expected: Signature
    # For a restriction, what shows that the action happened anyway.
    breached: Signature | None = None
    # A canary request this probe must make (control) or must never make (restriction).
    canary: tuple[int, str] | None = None
    # The runtime record that should corroborate the outcome.
    record: RecordPattern | None = None


@dataclass(frozen=True)
class Observation:
    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class ProbeResult:
    check_id: str
    kind: Kind
    role: Role
    outcome: Outcome
    exit_code: int | None
    corroborated: bool | None


@dataclass(frozen=True)
class ProbeReport:
    verdict: Verdict
    results: tuple[ProbeResult, ...]

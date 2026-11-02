from dataclasses import dataclass
from enum import StrEnum


class Requirement(StrEnum):
    REQUIRED = "required"
    OPTIONAL = "optional"


class Status(StrEnum):
    PASS = "pass"  # noqa: S105
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


REQUIRED, OPTIONAL = Requirement.REQUIRED, Requirement.OPTIONAL
PASS, WARN, FAIL, SKIP = Status.PASS, Status.WARN, Status.FAIL, Status.SKIP


@dataclass(frozen=True)
class CheckResult:
    name: str
    requirement: Requirement
    status: Status
    detail: str

    @property
    def blocks(self) -> bool:
        # A required check that could not run has not passed.
        return self.requirement is Requirement.REQUIRED and self.status in (
            Status.FAIL,
            Status.SKIP,
        )


@dataclass(frozen=True)
class Diagnosis:
    results: tuple[CheckResult, ...]
    secrets: frozenset[str]

    @property
    def exit_code(self) -> int:
        return 1 if any(result.blocks for result in self.results) else 0

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from aegis.runtime.contract import (
    REQUIRED_PROVER_DOMAINS,
    EnforcementRecord,
    ExecResult,
    ProverResult,
    ProverVerdict,
    RuntimeStatus,
    Sandbox,
    SandboxSpec,
)
from aegis.runtime.gate import RELEASE, RELEASE_FILE

PASS = ProverVerdict(ProverResult.WITHIN_BOUNDARY, frozenset(REQUIRED_PROVER_DOMAINS))


@dataclass
class FakeRuntime:
    # An in-process SandboxRuntime: every call is recorded, and each answer can be scripted.
    status: RuntimeStatus = field(default_factory=lambda: RuntimeStatus(True, "ok", "0.1.6"))
    verdicts: list[ProverVerdict] = field(default_factory=lambda: [PASS, PASS])
    effective: str = "version: 1\n"
    release: str = RELEASE + "\n"
    delete_error: Exception | None = None
    calls: list[str] = field(default_factory=list)
    specs: list[SandboxSpec] = field(default_factory=list)
    live: dict[str, Sandbox] = field(default_factory=dict)
    checked: list[str] = field(default_factory=list)
    results: dict[tuple[str, ...], ExecResult] = field(default_factory=dict)
    enforcement: list[EnforcementRecord] = field(default_factory=list)

    def check(self) -> RuntimeStatus:
        self.calls.append("check")
        return self.status

    def create(self, spec: SandboxSpec) -> Sandbox:
        self.calls.append("create")
        self.specs.append(spec)
        labels = MappingProxyType({**spec.labels, "aegis.managed": "true"})
        self.live[spec.name] = Sandbox(spec.name, "id-1", "Ready", "ab" * 32, labels)
        return self.live[spec.name]

    def get(self, name: str) -> Sandbox | None:
        return self.live.get(name)

    def exec(self, name: str, argv: Sequence[str], timeout_seconds: int) -> ExecResult:
        self.calls.append("exec " + " ".join(argv))
        if list(argv) == ["/usr/bin/cat", RELEASE_FILE]:
            return ExecResult(0, self.release, "")
        return self.results.get(tuple(argv), ExecResult(0, "", ""))

    def effective_policy(self, name: str) -> str:
        self.calls.append("effective_policy")
        return self.effective

    def delete(self, name: str) -> None:
        self.calls.append("delete")
        if self.delete_error is not None:
            raise self.delete_error
        self.live.pop(name, None)

    def managed(self) -> tuple[Sandbox, ...]:
        return tuple(self.live.values())

    def records(self, name: str) -> tuple[EnforcementRecord, ...]:
        self.calls.append("records")
        return tuple(self.enforcement)

    def check_policy(self, candidate: Path, boundary: Path) -> ProverVerdict:
        self.calls.append("check_policy")
        self.checked.append(candidate.read_text())
        return self.verdicts.pop(0)

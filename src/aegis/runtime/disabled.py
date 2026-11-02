from collections.abc import Sequence
from pathlib import Path

from aegis.runtime.contract import (
    ExecResult,
    ProverVerdict,
    RuntimeRefusedError,
    RuntimeStatus,
    Sandbox,
    SandboxSpec,
)


class DisabledRuntime:
    # AEGIS_SANDBOX_RUNTIME=none: every sandbox operation is refused, and nothing ever runs
    # outside a sandbox instead (README, fail-closed behaviour).
    def check(self) -> RuntimeStatus:
        return RuntimeStatus(healthy=False, detail="disabled")

    def create(self, spec: SandboxSpec) -> Sandbox:
        raise _refused()

    def get(self, name: str) -> Sandbox | None:
        raise _refused()

    def exec(self, name: str, argv: Sequence[str], timeout_seconds: int) -> ExecResult:
        raise _refused()

    def effective_policy(self, name: str) -> str:
        raise _refused()

    def delete(self, name: str) -> None:
        raise _refused()

    def managed(self) -> tuple[Sandbox, ...]:
        return ()

    def check_policy(self, candidate: Path, boundary: Path) -> ProverVerdict:
        raise _refused()


def _refused() -> RuntimeRefusedError:
    return RuntimeRefusedError("the sandbox runtime is disabled", code="sandbox_unavailable")

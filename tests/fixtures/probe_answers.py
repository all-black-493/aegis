from aegis.runtime.contract import EnforcementRecord, ExecResult
from aegis.runtime.probes.catalog import PROBES
from aegis.runtime.probes.model import NONCE, Probe, Role, Signature


def fill(text: str, nonce: str) -> str:
    return text.replace(NONCE, nonce)


def argv(probe: Probe, nonce: str) -> tuple[str, ...]:
    return tuple(fill(arg, nonce) for arg in probe.argv)


def obeying(signature: Signature, nonce: str) -> ExecResult:
    stdout = (
        signature.stdout_is if signature.stdout_is is not None else "\n".join(signature.stdout_has)
    )
    return ExecResult(
        0 if signature.exit_zero is not False else 1,
        fill(stdout, nonce),
        fill("\n".join(signature.stderr_has), nonce),
    )


def enforcing_answers(nonce: str) -> dict[tuple[str, ...], ExecResult]:
    # What a runtime that enforces every restriction answers to each probe.
    return {argv(probe, nonce): obeying(probe.expected, nonce) for probe in PROBES}


def enforcing_records(nonce: str) -> list[EnforcementRecord]:
    return [
        EnforcementRecord(
            probe.record.category,
            probe.record.action,
            f"x {fill(probe.record.detail_has, nonce)} y",
        )
        for probe in PROBES
        if probe.record is not None
    ]


def control_hits(nonce: str) -> set[tuple[int, str]]:
    # The canary requests the controls make when they succeed.
    return {
        (probe.canary[0], fill(probe.canary[1], nonce))
        for probe in PROBES
        if probe.canary is not None and probe.role is Role.CONTROL
    }


class FakeCanary:
    def __init__(self, hits: set[tuple[int, str]]) -> None:
        self._hits = frozenset(hits)
        self.closed = False

    def __enter__(self) -> "FakeCanary":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.closed = True

    def hits(self) -> frozenset[tuple[int, str]]:
        return self._hits

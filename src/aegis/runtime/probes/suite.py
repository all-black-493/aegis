import secrets
import time
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from typing import Protocol

from aegis.runtime.contract import EnforcementRecord, SandboxRuntime
from aegis.runtime.gate import SandboxGate
from aegis.runtime.probes.canary import Canary
from aegis.runtime.probes.catalog import CANARY_HOST, CANARY_OTHER_PORT, CANARY_PORT, PROBES
from aegis.runtime.probes.model import NONCE, Observation, Probe, ProbeReport
from aegis.runtime.probes.verdicts import corroborated, judge, summarize

PROBE_TIMEOUT_SECONDS = 15
# The supervisor flushes its records asynchronously, so the last ones can lag the probes.
RECORD_ATTEMPTS = 5
RECORD_INTERVAL_SECONDS = 1.0


class CanaryLog(Protocol):
    def hits(self) -> frozenset[tuple[int, str]]: ...


def run_probes(
    runtime: SandboxRuntime,
    name: str,
    canary: CanaryLog,
    nonce: str,
    probes: tuple[Probe, ...] = PROBES,
    sleep: Callable[[float], None] = time.sleep,
    stop: Callable[[], bool] = lambda: False,
) -> ProbeReport:
    observations: dict[str, Observation | None] = {}
    for probe in probes:
        if stop():
            # A probe that never ran is unobserved, so a stopped run is never verified.
            observations[probe.check_id] = None
            continue
        # One exec per action, so each result is the kernel's and the runtime's, not a report
        # written by code inside the sandbox.
        result = runtime.exec(
            name, [arg.replace(NONCE, nonce) for arg in probe.argv], PROBE_TIMEOUT_SECONDS
        )
        observations[probe.check_id] = (
            None
            if result.timed_out
            else Observation(result.exit_code, result.stdout, result.stderr)
        )
    hits = canary.hits()
    records = () if stop() else _records(runtime, name, probes, nonce, sleep)
    return summarize(
        tuple(judge(probe, observations[probe.check_id], hits, records, nonce) for probe in probes)
    )


def verify_enforcement(
    gate: SandboxGate,
    runtime: SandboxRuntime,
    name: str,
    labels: Mapping[str, str],
    canary: Callable[[], AbstractContextManager[CanaryLog]] | None = None,
    stop: Callable[[], bool] = lambda: False,
    nonce: str | None = None,
) -> ProbeReport:
    nonce = nonce or secrets.token_hex(8)
    start = canary or (lambda: Canary(CANARY_HOST, (CANARY_PORT, CANARY_OTHER_PORT)))
    with start() as listening, gate.open(name, labels):
        return run_probes(runtime, name, listening, nonce, stop=stop)


def _records(
    runtime: SandboxRuntime,
    name: str,
    probes: tuple[Probe, ...],
    nonce: str,
    sleep: Callable[[float], None],
) -> tuple[EnforcementRecord, ...]:
    expected = [probe.record for probe in probes if probe.record is not None]
    records: tuple[EnforcementRecord, ...] = ()
    for attempt in range(RECORD_ATTEMPTS):
        records = runtime.records(name)
        if all(corroborated(pattern, records, nonce) for pattern in expected):
            break
        if attempt + 1 < RECORD_ATTEMPTS:
            sleep(RECORD_INTERVAL_SECONDS)
    return records

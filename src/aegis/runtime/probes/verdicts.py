from collections.abc import Iterable

from aegis.runtime.contract import EnforcementRecord
from aegis.runtime.probes.model import (
    NONCE,
    Observation,
    Outcome,
    Probe,
    ProbeReport,
    ProbeResult,
    RecordPattern,
    Role,
    Signature,
    Verdict,
)


def matches(signature: Signature, observation: Observation, nonce: str) -> bool:
    if signature.exit_zero is not None and (observation.exit_code == 0) != signature.exit_zero:
        return False
    if signature.stdout_is is not None and observation.stdout.strip() != _fill(
        signature.stdout_is, nonce
    ):
        return False
    return all(_fill(text, nonce) in observation.stdout for text in signature.stdout_has) and all(
        _fill(text, nonce) in observation.stderr for text in signature.stderr_has
    )


def judge(
    probe: Probe,
    observation: Observation | None,
    canary_hits: frozenset[tuple[int, str]],
    records: Iterable[EnforcementRecord],
    nonce: str,
) -> ProbeResult:
    # AEGIS decides from what it observed itself: the command's result and the canary. The
    # runtime's own records only corroborate (ADR-0018).
    seen = (
        None
        if probe.canary is None
        else (probe.canary[0], _fill(probe.canary[1], nonce)) in canary_hits
    )
    if observation is None:
        outcome = Outcome.INCONCLUSIVE
    elif probe.role is Role.CONTROL:
        succeeded = matches(probe.expected, observation, nonce) and seen is not False
        outcome = Outcome.HELD if succeeded else Outcome.INCONCLUSIVE
    elif seen:
        outcome = Outcome.VIOLATED
    elif matches(probe.expected, observation, nonce):
        outcome = Outcome.HELD
    elif probe.breached is not None and matches(probe.breached, observation, nonce):
        outcome = Outcome.VIOLATED
    else:
        outcome = Outcome.INCONCLUSIVE
    return ProbeResult(
        probe.check_id,
        probe.kind,
        probe.role,
        outcome,
        None if observation is None else observation.exit_code,
        None if probe.record is None else corroborated(probe.record, records, nonce),
    )


def corroborated(pattern: RecordPattern, records: Iterable[EnforcementRecord], nonce: str) -> bool:
    detail = _fill(pattern.detail_has, nonce)
    return any(
        record.category == pattern.category
        and record.action == pattern.action
        and detail in record.detail
        for record in records
    )


def summarize(results: tuple[ProbeResult, ...]) -> ProbeReport:
    outcomes = {result.outcome for result in results}
    if Outcome.VIOLATED in outcomes:
        verdict = Verdict.VIOLATED
    elif Outcome.INCONCLUSIVE in outcomes or not results:
        verdict = Verdict.INCONCLUSIVE
    else:
        verdict = Verdict.VERIFIED
    return ProbeReport(verdict, results)


def _fill(text: str, nonce: str) -> str:
    return text.replace(NONCE, nonce)

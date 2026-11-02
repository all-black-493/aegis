import json
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from aegis.integrations.openshell.cli import VERIFIED_VERSION, Completed
from aegis.runtime.contract import (
    EnforcementRecord,
    ProverResult,
    ProverVerdict,
    RuntimeProtocolError,
    RuntimeRefusedError,
    Sandbox,
)

MAX_COUNTEREXAMPLE_CHARS = 1024
MAX_DETAIL_CHARS = 512
# The OCSF shorthand OpenShell writes to the sandbox log, for example
# "[ocsf] NET:OPEN [MED] DENIED /usr/bin/curl(64) -> httpbin.org:443 [reason:...]" (ADR-0018).
_SHORTHAND = re.compile(
    r"\[ocsf\] (?P<category>[A-Z]+:[A-Z_]+) \[[A-Z]+\] "
    r"(?P<action>ALLOWED|DENIED|BLOCKED) (?P<detail>.+)$"
)


def parse_sandbox(value: object) -> Sandbox:
    if not isinstance(value, Mapping):
        raise RuntimeProtocolError("a sandbox record is malformed")
    name, sandbox_id, phase = value.get("name"), value.get("id"), value.get("phase")
    labels = value.get("labels") or {}
    admission = value.get("configuration_admission") or {}
    if not all(isinstance(item, str) and item for item in (name, sandbox_id, phase)):
        raise RuntimeProtocolError("a sandbox record is malformed")
    if not isinstance(labels, Mapping) or not isinstance(admission, Mapping):
        raise RuntimeProtocolError("a sandbox record is malformed")
    policy_hash = admission.get("policy_hash")
    return Sandbox(
        name=str(name),
        sandbox_id=str(sandbox_id),
        phase=str(phase),
        policy_hash=policy_hash if isinstance(policy_hash, str) and policy_hash else None,
        labels=MappingProxyType({str(k): str(v) for k, v in labels.items()}),
    )


def parse_verdict(value: Mapping[str, Any], exit_code: int) -> ProverVerdict:
    if value.get("schema_version") != 1 or value.get("prover_version") != VERIFIED_VERSION:
        raise RuntimeRefusedError(
            "the prover output is not the verified schema", code="version_mismatch"
        )
    try:
        result = ProverResult(str(value.get("result")))
    except ValueError:
        raise RuntimeProtocolError("the prover reported an unknown result") from None
    if value.get("exit_code") != exit_code:
        raise RuntimeProtocolError("the prover's result and exit status disagree")
    coverage = value.get("coverage")
    domains = coverage.get("domains") if isinstance(coverage, Mapping) else None
    if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains):
        raise RuntimeProtocolError("the prover coverage is malformed")
    reason_code = value.get("reason_code")
    counterexample = value.get("counterexample")
    return ProverVerdict(
        result=result,
        domains=frozenset(domains),
        reason_code=reason_code if isinstance(reason_code, str) else None,
        counterexample=(
            json.dumps(counterexample, sort_keys=True)[:MAX_COUNTEREXAMPLE_CHARS]
            if counterexample is not None
            else None
        ),
    )


def json_object(completed: Completed) -> dict[str, Any]:
    if completed.truncated:
        raise RuntimeProtocolError("OpenShell's output exceeded its size limit")
    try:
        value = json.loads(completed.stdout)
    except ValueError:
        raise RuntimeProtocolError("OpenShell's output is not JSON") from None
    if not isinstance(value, dict):
        raise RuntimeProtocolError("OpenShell's output is not a JSON object")
    return value


def admission_state(completed: Completed) -> object:
    admission = json_object(completed).get("configuration_admission")
    return admission.get("state") if isinstance(admission, Mapping) else None


def not_found(completed: Completed) -> bool:
    return "not found" in error_message(completed)


def error_message(completed: Completed) -> str:
    # The CLI wraps errors at 80 columns inside a box border (ADR-0016).
    return " ".join(completed.stderr.replace("\u2502", " ").split())


def parse_records(log: str) -> tuple[EnforcementRecord, ...]:
    found = []
    for line in log.splitlines():
        match = _SHORTHAND.search(line)
        if match:
            detail = match["detail"].strip()[:MAX_DETAIL_CHARS]
            found.append(EnforcementRecord(match["category"], match["action"], detail))
    return tuple(found)

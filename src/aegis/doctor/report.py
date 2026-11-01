from collections.abc import Iterable

from aegis.doctor.model import Diagnosis, Requirement, Status

REDACTED = "[REDACTED]"

NOT_CHECKED = (
    ("Model provider (mock, Ollama)", "Phase 2"),
    ("NVIDIA OpenShell", "Phase 3; untrusted execution is unavailable until then"),
    ("Langfuse and OpenTelemetry", "Phase 8"),
)


def render(diagnosis: Diagnosis) -> str:
    lines = ["AEGIS doctor (Phase 1)", ""]
    for requirement in Requirement:
        results = [result for result in diagnosis.results if result.requirement is requirement]
        if not results:
            continue
        width = max(len(result.name) for result in results)
        lines.append(f"{requirement.value.capitalize()} checks")
        lines.extend(
            f"  [{result.status.value.upper()}] {result.name:<{width}}  {result.detail}"
            for result in results
        )
        lines.append("")
    width = max(len(name) for name, _ in NOT_CHECKED)
    lines.append("Not checked (not implemented yet)")
    lines.extend(f"  [----] {name:<{width}}  {phase}" for name, phase in NOT_CHECKED)
    lines.append("")
    lines.append(_summary(diagnosis))
    return redact("\n".join(lines), diagnosis.secrets)


def redact(text: str, secrets: Iterable[str]) -> str:
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, REDACTED)
    return text


def _summary(diagnosis: Diagnosis) -> str:
    blocking = sum(result.blocks for result in diagnosis.results)
    warnings = sum(result.status is Status.WARN for result in diagnosis.results)
    if blocking:
        return f"Result: FAILED ({blocking} required check(s) did not pass)"
    return f"Result: OK (all required checks passed, {warnings} warning(s))"

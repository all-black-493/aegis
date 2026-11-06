import logging
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from uuid import UUID

from sqlalchemy import Engine

from aegis.audit.events import ActorKind, AuditEvent, AuditEventType, Outcome, Source
from aegis.audit.recorder import AuditRecorder
from aegis.identity.schema import SYSTEM_WORKER_ID
from aegis.jobs.sandboxes import audit_sink
from aegis.runtime.contract import SandboxRuntime
from aegis.runtime.gate import POLICY_DIR, SandboxGate, load_policies
from aegis.runtime.probes import model as checks
from aegis.runtime.probes.model import ProbeReport, ProbeResult, Role, Verdict
from aegis.runtime.probes.suite import CanaryLog, verify_enforcement
from aegis.tasks.transitions import JobRef

logger = logging.getLogger("aegis.worker")

_EXPECTED = {Role.CONTROL: "allowed", Role.RESTRICTION: "refused"}
_OBSERVED = {
    (Role.CONTROL, checks.Outcome.HELD): "allowed",
    (Role.RESTRICTION, checks.Outcome.HELD): "refused",
    (Role.RESTRICTION, checks.Outcome.VIOLATED): "allowed",
}


def sandbox_name(job: JobRef) -> str:
    # 19 characters at most, as OpenShell requires, and different for every attempt.
    return f"aegis-{job.job_id.hex[:10]}-{job.attempt}"


class EnforcementCheck:
    # One per worker process. It runs AEGIS's fixed probes (ADR-0018) in a gated sandbox for an
    # enforcement_check task and records every check before the handler sees the report.
    def __init__(
        self,
        engine: Engine,
        recorder: AuditRecorder,
        runtime: SandboxRuntime,
        image: str | None,
        *,
        policy_dir: Path = POLICY_DIR,
        canary: Callable[[], AbstractContextManager[CanaryLog]] | None = None,
        nonce: str | None = None,
    ) -> None:
        self._engine = engine
        self._recorder = recorder
        self._runtime = runtime
        self._image = image
        self._policy_dir = policy_dir
        # The worker never sets these; tests fix the canary and the nonce to script a runtime.
        self._canary = canary
        self._nonce = nonce

    def run(self, task_id: UUID, job: JobRef, stop: Callable[[], bool]) -> ProbeReport:
        name = sandbox_name(job)
        labels = {
            "aegis.task": str(task_id),
            "aegis.job": str(job.job_id),
            "aegis.attempt": str(job.attempt),
        }
        # Loaded for every run, so the fingerprint audited is that of the files the gate submits.
        gate = SandboxGate(
            self._runtime,
            load_policies(self._policy_dir),
            self._image,
            audit_sink(self._engine, self._recorder, task_id, job.job_id),
        )
        report = verify_enforcement(
            gate, self._runtime, name, labels, canary=self._canary, stop=stop, nonce=self._nonce
        )
        self._record(task_id, job, name, report)
        if report.verdict is Verdict.VIOLATED:
            violated = [r.check_id for r in report.results if r.outcome is checks.Outcome.VIOLATED]
            logger.error(
                "enforcement violated",
                extra={"task_id": str(task_id), "job_id": str(job.job_id), "checks": violated},
            )
        return report

    def _record(self, task_id: UUID, job: JobRef, name: str, report: ProbeReport) -> None:
        # One transaction for the whole report: either every check is recorded or none is, and a
        # failed write fails the task (fail closed).
        with self._engine.begin() as connection:
            for result in report.results:
                self._recorder.record(connection, _checked(task_id, job, name, result))


def _checked(task_id: UUID, job: JobRef, name: str, result: ProbeResult) -> AuditEvent:
    held = result.outcome is checks.Outcome.HELD
    return AuditEvent(
        event_type=AuditEventType.ENFORCEMENT_CHECKED,
        source=Source.WORKER,
        outcome=Outcome.SUCCESS if held else Outcome.FAILURE,
        actor_id=SYSTEM_WORKER_ID,
        actor_kind=ActorKind.SYSTEM,
        target_type="sandbox",
        target_id=name,
        task_id=task_id,
        job_id=job.job_id,
        reason_code=result.outcome.value,
        details={
            "attempt": job.attempt,
            "check": result.check_id,
            "kind": result.kind.value,
            "expected": _EXPECTED[result.role],
            "observed": _OBSERVED.get((result.role, result.outcome), "unclear"),
            "exit_code": result.exit_code,
            "corroborated": result.corroborated,
        },
    )

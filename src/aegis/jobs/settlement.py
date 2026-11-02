import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError

from aegis.audit.events import (
    ALLOWED_DETAILS,
    ActorKind,
    AuditEvent,
    AuditEventType,
    DetailValue,
    Outcome,
    Source,
)
from aegis.audit.recorder import AuditRecorder
from aegis.authorization.catalog import IdentityKind
from aegis.authorization.contract import SecurityDecision
from aegis.config.settings import WorkerSettings
from aegis.identity.schema import SYSTEM_WORKER_ID
from aegis.jobs import repository as jobs
from aegis.jobs.handlers import HandlerFailure, RetryableError
from aegis.jobs.repository import JobRecord
from aegis.tasks.repository import TaskRecord, lock_task
from aegis.tasks.states import TaskKind, TaskState
from aegis.tasks.transitions import JobRef, PolicyRef, Transition, apply_transition

MAX_RESULT_BYTES = 8 * 1024
SUCCESS_EVENTS = frozenset({AuditEventType.JOB_RETRIED, AuditEventType.MODEL_GENERATED})

logger = logging.getLogger("aegis.worker")


class Stop(StrEnum):
    FENCE_LOST = "fence_lost"
    CANCEL_REQUESTED = "cancel_requested"
    INITIATOR_DISABLED = "initiator_disabled"
    SHUTDOWN = "worker_shutdown"


class FenceLostError(RuntimeError):
    pass


@dataclass(frozen=True)
class Claim:
    task: TaskRecord
    job: JobRef


@dataclass
class HandlerRun:
    result: object = None
    error: Exception | None = None


class Settlement:
    # Every change the worker makes to a task it holds, with the audit records that go with it.
    def __init__(
        self,
        engine: Engine,
        recorder: AuditRecorder,
        settings: WorkerSettings,
        policy: PolicyRef,
        backoff: Callable[[int], float],
    ) -> None:
        self._engine = engine
        self._recorder = recorder
        self._settings = settings
        self._policy = policy
        self._backoff = backoff

    def complete(self, claim: Claim, run: HandlerRun) -> None:
        def settle(connection: Connection, task: TaskRecord, job: JobRecord) -> None:
            if isinstance(run.error, RetryableError):
                delay = self._backoff(job.attempt)
                self.interrupt(connection, task, job, "handler_retryable_error", delay)
            elif isinstance(run.error, HandlerFailure):
                self.fail(connection, task, claim.job, run.error.code)
            elif run.error is not None:
                logger.warning(
                    "handler failed: %s", type(run.error).__name__, extra=claim_ids(claim)
                )
                self.fail(connection, task, claim.job, "handler_error")
            elif not _valid_result(run.result):
                self.fail(connection, task, claim.job, "invalid_result")
            else:
                result = dict(run.result) if isinstance(run.result, Mapping) else {}
                done = self.move(
                    connection, task, TaskState.SUCCEEDED, claim.job, "completed", result=result
                )
                jobs.finish(connection, claim.job, None)
                if done.kind is TaskKind.GENERATE:
                    self._audit_generation(connection, done, claim.job, result)
                log_task("succeeded", done, claim.job)

        self._fenced(claim, settle)

    def stop_early(self, claim: Claim, reason: str) -> None:
        if reason == Stop.FENCE_LOST:
            self.fence_lost(claim)
            return

        def settle(connection: Connection, task: TaskRecord, job: JobRecord) -> None:
            if reason == Stop.CANCEL_REQUESTED:
                self.move(connection, task, TaskState.CANCELLED, claim.job, reason)
                jobs.finish(connection, claim.job, "cancelled")
            elif reason == Stop.SHUTDOWN:
                self.interrupt(connection, task, job, reason, 0)
            else:
                self.fail(connection, task, claim.job, reason)

        self._fenced(claim, settle)

    def interrupt(
        self,
        connection: Connection,
        task: TaskRecord,
        job: JobRecord,
        reason: str,
        delay: float,
    ) -> None:
        ref = job.ref
        task = self.move(connection, task, TaskState.INTERRUPTED, ref, reason)
        self._audit(connection, AuditEventType.JOB_INTERRUPTED, task, ref, reason)
        if ref.attempt < min(job.max_attempts, self._settings.max_attempts):
            task = self.move(connection, task, TaskState.QUEUED, ref, "retry_scheduled")
            pending = jobs.reschedule(connection, ref, delay)
            if pending is None:
                raise FenceLostError
            self._audit(
                connection,
                AuditEventType.JOB_RETRIED,
                task,
                ref,
                reason,
                run_after=pending.run_after.isoformat(),
            )
        else:
            self.fail(connection, task, ref, "attempts_exhausted")

    def fail(self, connection: Connection, task: TaskRecord, ref: JobRef, code: str) -> None:
        failed = self.move(connection, task, TaskState.FAILED, ref, code, failure=code)
        self.finish(connection, failed, ref, code)

    def finish(self, connection: Connection, task: TaskRecord, ref: JobRef, code: str) -> None:
        if jobs.finish(connection, ref, code) is None:
            raise FenceLostError
        self._audit(connection, AuditEventType.JOB_FAILED, task, ref, code, error_code=code)
        log_task("failed", task, ref)

    def move(
        self,
        connection: Connection,
        task: TaskRecord,
        target: TaskState,
        job: JobRef,
        reason: str,
        *,
        decision: SecurityDecision | None = None,
        result: Mapping[str, Any] | None = None,
        failure: str | None = None,
    ) -> TaskRecord:
        return apply_transition(
            connection,
            Transition(
                task_id=task.task_id,
                expected_state=task.state,
                expected_version=task.version,
                target=target,
                actor_id=SYSTEM_WORKER_ID,
                actor_kind=IdentityKind.SYSTEM,
                source=Source.WORKER,
                reason_code=reason,
                decision=decision,
                job=job,
                result=result,
                failure_code=failure,
            ),
            self._policy,
            self._recorder,
        )

    def fence_lost(self, claim: Claim) -> None:
        logger.warning("fence lost; the handler's result is discarded", extra=claim_ids(claim))
        event = _event(
            AuditEventType.JOB_FENCE_LOST,
            claim.task.task_id,
            claim.job,
            Stop.FENCE_LOST.value,
            {"attempt": claim.job.attempt},
        )
        try:
            with self._engine.begin() as connection:
                self._recorder.record(connection, event)
        except SQLAlchemyError:
            logger.error("could not record job.fence_lost", extra=claim_ids(claim))

    def _fenced(
        self, claim: Claim, settle: Callable[[Connection, TaskRecord, JobRecord], None]
    ) -> None:
        try:
            with self._engine.begin() as connection:
                task = lock_task(connection, claim.task.task_id)
                job = jobs.lock_fenced(connection, claim.job)
                if task is None or job is None:
                    raise FenceLostError
                settle(connection, task, job)
        except FenceLostError:
            self.fence_lost(claim)
        except SQLAlchemyError as error:
            logger.error(
                "could not record the outcome (%s); the lease will expire and recovery will"
                " retry the task",
                type(error).__name__,
                extra=claim_ids(claim),
            )

    def _audit(
        self,
        connection: Connection,
        event_type: AuditEventType,
        task: TaskRecord,
        ref: JobRef,
        reason: str,
        **details: DetailValue,
    ) -> None:
        self._recorder.record(
            connection,
            _event(event_type, task.task_id, ref, reason, {"attempt": ref.attempt, **details}),
        )

    def _audit_generation(
        self, connection: Connection, task: TaskRecord, ref: JobRef, result: Mapping[str, Any]
    ) -> None:
        # The model's identity and usage only; the text itself never reaches the audit store.
        details: dict[str, DetailValue] = {
            key: value
            for key in ALLOWED_DETAILS[AuditEventType.MODEL_GENERATED]
            if isinstance(value := result.get(key), str | int) or value is None
        }
        self._recorder.record(
            connection,
            _event(AuditEventType.MODEL_GENERATED, task.task_id, ref, "completed", details),
        )


def claim_ids(claim: Claim) -> dict[str, object]:
    return {
        "task_id": str(claim.task.task_id),
        "job_id": str(claim.job.job_id),
        "attempt": claim.job.attempt,
    }


def log_task(message: str, task: TaskRecord, ref: JobRef) -> None:
    logger.info(
        message,
        extra={
            "task_id": str(task.task_id),
            "job_id": str(ref.job_id),
            "attempt": ref.attempt,
            "state": task.state.value,
        },
    )


def _valid_result(result: object) -> bool:
    if not isinstance(result, Mapping):
        return False
    # Measured as UTF-8, as PostgreSQL stores it; text that cannot be encoded is refused.
    try:
        encoded = json.dumps(result, allow_nan=False, ensure_ascii=False, separators=(",", ":"))
        size = len(encoded.encode())
    except (TypeError, ValueError):
        return False
    return size <= MAX_RESULT_BYTES and "\\u0000" not in encoded


def _event(
    event_type: AuditEventType,
    task_id: UUID,
    ref: JobRef,
    reason: str,
    details: Mapping[str, DetailValue],
) -> AuditEvent:
    outcome = Outcome.SUCCESS if event_type in SUCCESS_EVENTS else Outcome.FAILURE
    return AuditEvent(
        event_type=event_type,
        source=Source.WORKER,
        outcome=outcome,
        actor_id=SYSTEM_WORKER_ID,
        actor_kind=ActorKind.SYSTEM,
        target_type="task",
        target_id=str(task_id),
        task_id=task_id,
        job_id=ref.job_id,
        reason_code=reason,
        details=details,
    )

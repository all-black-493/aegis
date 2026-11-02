import json
import logging
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine, select
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
from aegis.authorization.contract import Effect, SecurityDecision
from aegis.config.settings import WorkerSettings
from aegis.identity.schema import SYSTEM_WORKER_ID, identities
from aegis.jobs import repository as jobs
from aegis.jobs.handlers import (
    REGISTRY,
    Handler,
    HandlerContext,
    HandlerFailure,
    RetryableError,
)
from aegis.jobs.repository import JobRecord, JobState
from aegis.model_providers.contract import ModelProvider
from aegis.policy.service import DecisionService
from aegis.tasks.repository import TaskRecord, lock_task, transaction_time
from aegis.tasks.schema import tasks
from aegis.tasks.states import TaskKind, TaskState
from aegis.tasks.transitions import JobRef, Transition, apply_transition

BACKOFF_BASE_SECONDS = 2.0
BACKOFF_MAX_SECONDS = 60.0
MAX_RESULT_BYTES = 8 * 1024
RECOVERY_BATCH = 10
SUPERVISION_TICK_SECONDS = 0.25
SUCCESS_EVENTS = frozenset({AuditEventType.JOB_RETRIED, AuditEventType.MODEL_GENERATED})

logger = logging.getLogger("aegis.worker")


def exponential_backoff(attempt: int) -> float:
    return min(BACKOFF_BASE_SECONDS * 2.0 ** (attempt - 1), BACKOFF_MAX_SECONDS)


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


@dataclass(frozen=True)
class Settled:
    task: TaskRecord


@dataclass
class _Run:
    result: object = None
    error: Exception | None = None


class Worker:
    def __init__(
        self,
        engine: Engine,
        recorder: AuditRecorder,
        settings: WorkerSettings,
        *,
        handlers: Mapping[TaskKind, Handler] = REGISTRY,
        decisions: DecisionService | None = None,
        owner: str | None = None,
        backoff: Callable[[int], float] = exponential_backoff,
        provider: ModelProvider | None = None,
    ) -> None:
        self._engine = engine
        self._recorder = recorder
        self._settings = settings
        self._handlers = handlers
        self._decisions = decisions or DecisionService(recorder)
        self._backoff = backoff
        # One provider per worker process, shared by every task's handler context.
        self._provider = provider
        self.owner = owner or f"worker-{uuid4().hex}"

    def run(self, stop: threading.Event) -> None:
        logger.info("worker started", extra={"worker": self.owner})
        while not stop.is_set():
            if not self.step(stop):
                stop.wait(self._settings.poll_seconds)
        logger.info("worker stopped", extra={"worker": self.owner})

    def step(self, stop: threading.Event) -> bool:
        try:
            recovered = self.recover()
            claimed = self.claim()
        except SQLAlchemyError as error:
            logger.error("database unavailable: %s", type(error).__name__)
            return False
        if isinstance(claimed, Claim):
            self.execute(claimed, stop)
        return recovered > 0 or claimed is not None

    def recover(self) -> int:
        count = 0
        while count < RECOVERY_BATCH and self._recover_one():
            count += 1
        return count

    def claim(self) -> Claim | Settled | None:
        with self._engine.begin() as connection:
            found = jobs.next_due(connection)
            if found is None:
                return None
            task, job = lock_task(connection, found[0]), jobs.lock_job(connection, found[1])
            claimed = None
            if task is not None and job is not None:
                claimed = jobs.claim(connection, job, self.owner, self._settings.lease_seconds)
            if task is None or claimed is None:
                return None
            ref = claimed.ref
            decided = self._decisions.execution(connection, task, ref)
            self._decisions.record(connection, decided)
            outcome = self._admit(connection, task, ref, decided.decision)
        _log("claimed" if isinstance(outcome, Claim) else "settled at claim", outcome.task, ref)
        return outcome

    def execute(self, claim: Claim, stop: threading.Event) -> None:
        handler = self._handlers.get(claim.task.kind)
        if handler is None:
            self._stop_early(claim, "kind_not_registered")
            return
        halt, run = threading.Event(), _Run()
        thread = threading.Thread(
            target=_call,
            args=(handler, dict(claim.task.input), HandlerContext(halt, self._provider), run),
            name=f"handler-{claim.task.task_id}",
            daemon=True,
        )
        thread.start()
        stopped = self._supervise(claim, thread, stop)
        if stopped is None:
            self._complete(claim, run)
            return
        halt.set()
        thread.join(self._settings.shutdown_grace_seconds)
        self._stop_early(claim, stopped.value)

    def _admit(
        self, connection: Connection, task: TaskRecord, ref: JobRef, decision: SecurityDecision
    ) -> Claim | Settled:
        reason = decision.reason_codes[0]
        if decision.effect is Effect.DENY:
            failed = self._move(
                connection, task, TaskState.FAILED, ref, reason, decision=decision, failure=reason
            )
            self._finish(connection, failed, ref, reason)
            return Settled(failed)
        if decision.effect is Effect.APPROVAL_REQUIRED:
            held = self._move(
                connection, task, TaskState.AWAITING_APPROVAL, ref, reason, decision=decision
            )
            jobs.finish(connection, ref, "approval_required")
            return Settled(held)
        running = self._move(connection, task, TaskState.RUNNING, ref, reason, decision=decision)
        if running.cancel_requested_by is not None:
            # E5: cancellation was requested before the task ever ran; the handler never starts.
            cancelled = self._move(
                connection, running, TaskState.CANCELLED, ref, "cancel_requested"
            )
            jobs.finish(connection, ref, "cancelled")
            return Settled(cancelled)
        return Claim(running, ref)

    def _recover_one(self) -> bool:
        with self._engine.begin() as connection:
            found = jobs.next_expired(connection)
            if found is None:
                return False
            task, job = lock_task(connection, found[0]), jobs.lock_job(connection, found[1])
            if task is None or job is None or job.state is not JobState.RUNNING:
                return True
            if job.lease_expires_at is None or job.lease_expires_at > transaction_time(connection):
                return True
            logger.warning(
                "lease expired",
                extra={"task_id": str(task.task_id), "job_id": str(job.job_id)},
            )
            if task.state is not TaskState.RUNNING:
                jobs.finish(connection, job.ref, "task_not_running")
            elif task.cancel_requested_by is not None:
                self._move(connection, task, TaskState.CANCELLED, job.ref, "cancel_requested")
                jobs.finish(connection, job.ref, "cancelled")
            else:
                self._interrupt(connection, task, job, "lease_expired", self._backoff(job.attempt))
        return True

    def _supervise(
        self, claim: Claim, thread: threading.Thread, stop: threading.Event
    ) -> Stop | None:
        settings = self._settings
        tick = min(settings.heartbeat_seconds, SUPERVISION_TICK_SECONDS)
        lease_deadline = time.monotonic() + settings.lease_seconds
        next_beat = time.monotonic() + settings.heartbeat_seconds
        shutdown_at: float | None = None
        while True:
            thread.join(tick)
            if not thread.is_alive():
                return None
            now = time.monotonic()
            if stop.is_set() and shutdown_at is None:
                shutdown_at = now + settings.shutdown_grace_seconds
            if shutdown_at is not None and now >= shutdown_at:
                return Stop.SHUTDOWN
            if now < next_beat:
                continue
            next_beat = now + settings.heartbeat_seconds
            try:
                stopped = self._heartbeat(claim)
            except SQLAlchemyError as error:
                logger.warning("heartbeat failed: %s", type(error).__name__, extra=_ids(claim))
                if now >= lease_deadline:
                    return Stop.FENCE_LOST
                continue
            if stopped is not None:
                return stopped
            lease_deadline = now + settings.lease_seconds

    def _heartbeat(self, claim: Claim) -> Stop | None:
        with self._engine.begin() as connection:
            if jobs.renew(connection, claim.job, self._settings.lease_seconds) is None:
                return Stop.FENCE_LOST
            row = connection.execute(
                select(tasks.c.cancel_requested_by, identities.c.status)
                .join(identities, identities.c.id == tasks.c.initiator_id)
                .where(tasks.c.id == claim.task.task_id)
            ).one()
        if row.cancel_requested_by is not None:
            return Stop.CANCEL_REQUESTED
        if row.status != "active":
            return Stop.INITIATOR_DISABLED
        return None

    def _complete(self, claim: Claim, run: _Run) -> None:
        def settle(connection: Connection, task: TaskRecord, job: JobRecord) -> None:
            if isinstance(run.error, RetryableError):
                delay = self._backoff(job.attempt)
                self._interrupt(connection, task, job, "handler_retryable_error", delay)
            elif isinstance(run.error, HandlerFailure):
                self._fail(connection, task, claim.job, run.error.code)
            elif run.error is not None:
                logger.warning("handler failed: %s", type(run.error).__name__, extra=_ids(claim))
                self._fail(connection, task, claim.job, "handler_error")
            elif not _valid_result(run.result):
                self._fail(connection, task, claim.job, "invalid_result")
            else:
                result = dict(run.result) if isinstance(run.result, Mapping) else {}
                done = self._move(
                    connection, task, TaskState.SUCCEEDED, claim.job, "completed", result=result
                )
                jobs.finish(connection, claim.job, None)
                if done.kind is TaskKind.GENERATE:
                    self._audit_generation(connection, done, claim.job, result)
                _log("succeeded", done, claim.job)

        self._fenced(claim, settle)

    def _stop_early(self, claim: Claim, reason: str) -> None:
        if reason == Stop.FENCE_LOST:
            self._fence_lost(claim)
            return

        def settle(connection: Connection, task: TaskRecord, job: JobRecord) -> None:
            if reason == Stop.CANCEL_REQUESTED:
                self._move(connection, task, TaskState.CANCELLED, claim.job, reason)
                jobs.finish(connection, claim.job, "cancelled")
            elif reason == Stop.SHUTDOWN:
                self._interrupt(connection, task, job, reason, 0)
            else:
                self._fail(connection, task, claim.job, reason)

        self._fenced(claim, settle)

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
            self._fence_lost(claim)
        except SQLAlchemyError as error:
            logger.error(
                "could not record the outcome (%s); the lease will expire and recovery will"
                " retry the task",
                type(error).__name__,
                extra=_ids(claim),
            )

    def _interrupt(
        self,
        connection: Connection,
        task: TaskRecord,
        job: JobRecord,
        reason: str,
        delay: float,
    ) -> None:
        ref = job.ref
        task = self._move(connection, task, TaskState.INTERRUPTED, ref, reason)
        self._audit(connection, AuditEventType.JOB_INTERRUPTED, task, ref, reason)
        if ref.attempt < min(job.max_attempts, self._settings.max_attempts):
            task = self._move(connection, task, TaskState.QUEUED, ref, "retry_scheduled")
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
            self._fail(connection, task, ref, "attempts_exhausted")

    def _fail(self, connection: Connection, task: TaskRecord, ref: JobRef, code: str) -> None:
        failed = self._move(connection, task, TaskState.FAILED, ref, code, failure=code)
        self._finish(connection, failed, ref, code)

    def _finish(self, connection: Connection, task: TaskRecord, ref: JobRef, code: str) -> None:
        if jobs.finish(connection, ref, code) is None:
            raise FenceLostError
        self._audit(connection, AuditEventType.JOB_FAILED, task, ref, code, error_code=code)
        _log("failed", task, ref)

    def _move(
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
            self._decisions.policy,
            self._recorder,
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

    def _fence_lost(self, claim: Claim) -> None:
        logger.warning("fence lost; the handler's result is discarded", extra=_ids(claim))
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
            logger.error("could not record job.fence_lost", extra=_ids(claim))


def _call(
    handler: Handler, task_input: Mapping[str, Any], context: HandlerContext, run: _Run
) -> None:
    try:
        run.result = handler(task_input, context)
    except Exception as error:
        run.error = error


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


def _ids(claim: Claim) -> dict[str, object]:
    return {
        "task_id": str(claim.task.task_id),
        "job_id": str(claim.job.job_id),
        "attempt": claim.job.attempt,
    }


def _log(message: str, task: TaskRecord, ref: JobRef) -> None:
    logger.info(
        message,
        extra={
            "task_id": str(task.task_id),
            "job_id": str(ref.job_id),
            "attempt": ref.attempt,
            "state": task.state.value,
        },
    )

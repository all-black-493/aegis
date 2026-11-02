import logging
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from uuid import uuid4

from sqlalchemy import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError

from aegis.audit.recorder import AuditRecorder
from aegis.authorization.contract import Effect, SecurityDecision
from aegis.config.settings import WorkerSettings
from aegis.jobs import repository as jobs
from aegis.jobs.handlers import REGISTRY, Handler, HandlerContext
from aegis.jobs.repository import JobState
from aegis.jobs.settlement import Claim, HandlerRun, Settlement, log_task
from aegis.jobs.supervision import Supervisor, call
from aegis.model_providers.contract import ModelProvider
from aegis.policy.service import DecisionService
from aegis.tasks.repository import TaskRecord, lock_task, transaction_time
from aegis.tasks.states import TaskKind, TaskState
from aegis.tasks.transitions import JobRef

BACKOFF_BASE_SECONDS = 2.0
BACKOFF_MAX_SECONDS = 60.0
RECOVERY_BATCH = 10

logger = logging.getLogger("aegis.worker")


def exponential_backoff(attempt: int) -> float:
    return min(BACKOFF_BASE_SECONDS * 2.0 ** (attempt - 1), BACKOFF_MAX_SECONDS)


@dataclass(frozen=True)
class Settled:
    task: TaskRecord


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
        self._settings = settings
        self._handlers = handlers
        self._decisions = decisions or DecisionService(recorder)
        self._backoff = backoff
        # One provider per worker process, shared by every task's handler context.
        self._provider = provider
        self._settlement = Settlement(engine, recorder, settings, self._decisions.policy, backoff)
        self._supervisor = Supervisor(engine, settings)
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
        log_task("claimed" if isinstance(outcome, Claim) else "settled at claim", outcome.task, ref)
        return outcome

    def execute(self, claim: Claim, stop: threading.Event) -> None:
        handler = self._handlers.get(claim.task.kind)
        if handler is None:
            self._settlement.stop_early(claim, "kind_not_registered")
            return
        halt, run = threading.Event(), HandlerRun()
        thread = threading.Thread(
            target=call,
            args=(handler, dict(claim.task.input), HandlerContext(halt, self._provider), run),
            name=f"handler-{claim.task.task_id}",
            daemon=True,
        )
        thread.start()
        stopped = self._supervisor.watch(claim, thread, stop)
        if stopped is None:
            self._settlement.complete(claim, run)
            return
        halt.set()
        thread.join(self._settings.shutdown_grace_seconds)
        self._settlement.stop_early(claim, stopped.value)

    def _admit(
        self, connection: Connection, task: TaskRecord, ref: JobRef, decision: SecurityDecision
    ) -> Claim | Settled:
        settlement = self._settlement
        reason = decision.reason_codes[0]
        if decision.effect is Effect.DENY:
            failed = settlement.move(
                connection, task, TaskState.FAILED, ref, reason, decision=decision, failure=reason
            )
            settlement.finish(connection, failed, ref, reason)
            return Settled(failed)
        if decision.effect is Effect.APPROVAL_REQUIRED:
            held = settlement.move(
                connection, task, TaskState.AWAITING_APPROVAL, ref, reason, decision=decision
            )
            jobs.finish(connection, ref, "approval_required")
            return Settled(held)
        running = settlement.move(
            connection, task, TaskState.RUNNING, ref, reason, decision=decision
        )
        if running.cancel_requested_by is not None:
            # E5: cancellation was requested before the task ever ran; the handler never starts.
            cancelled = settlement.move(
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
            settlement = self._settlement
            if task.state is not TaskState.RUNNING:
                jobs.finish(connection, job.ref, "task_not_running")
            elif task.cancel_requested_by is not None:
                settlement.move(connection, task, TaskState.CANCELLED, job.ref, "cancel_requested")
                jobs.finish(connection, job.ref, "cancelled")
            else:
                settlement.interrupt(
                    connection, task, job, "lease_expired", self._backoff(job.attempt)
                )
        return True

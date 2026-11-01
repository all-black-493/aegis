import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, Engine

from aegis.audit.events import ActorKind, AuditEvent, AuditEventType, Outcome, Source
from aegis.audit.recorder import AuditRecorder
from aegis.authorization.access import ActorContext, ResourceRef, authorize
from aegis.authorization.catalog import Action, ResourceType
from aegis.authorization.contract import Effect, SecurityDecision
from aegis.jobs.repository import create_job, finish_pending
from aegis.policy.rules import MAX_JOB_ATTEMPTS
from aegis.policy.service import Decided, DecisionService
from aegis.tasks.repository import (
    NewTask,
    Position,
    TaskRecord,
    find_by_idempotency_key,
    get_task,
    insert_task,
    list_tasks,
    lock_task,
    request_cancellation,
)
from aegis.tasks.states import TERMINAL_STATES, TaskKind, TaskState
from aegis.tasks.transitions import (
    TaskNotFoundError,
    Transition,
    TransitionConflictError,
    apply_transition,
)

MAX_PAGE_SIZE = 100
SUBMIT_METHOD, SUBMIT_PATH = "POST", "/v1/tasks"


class AccessDeniedError(Exception):
    def __init__(self, decision: SecurityDecision, *, visible: bool) -> None:
        super().__init__(f"{decision.action} denied")
        self.decision = decision
        self.visible = visible


class IdempotencyConflictError(Exception):
    pass


class TaskFinishedError(Exception):
    pass


@dataclass(frozen=True)
class Submission:
    kind: str
    input: Mapping[str, Any]
    idempotency_key: str


@dataclass(frozen=True)
class Submitted:
    task: TaskRecord
    replayed: bool


@dataclass(frozen=True)
class Page:
    tasks: tuple[TaskRecord, ...]
    next: Position | None


@dataclass(frozen=True)
class Cancelled:
    task: TaskRecord
    pending: bool


def request_fingerprint(kind: str, task_input: Mapping[str, Any]) -> str:
    document = {"method": SUBMIT_METHOD, "path": SUBMIT_PATH, "kind": kind, "input": task_input}
    canonical = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class TaskService:
    def __init__(
        self,
        engine: Engine,
        recorder: AuditRecorder,
        decisions: DecisionService | None = None,
    ) -> None:
        self._engine = engine
        self._recorder = recorder
        self._decisions = decisions or DecisionService(recorder)

    def submit(self, actor: ActorContext, submission: Submission, request_id: str) -> Submitted:
        fingerprint = request_fingerprint(submission.kind, submission.input)
        with self._engine.begin() as connection:
            self._decisions.lock_submissions(connection, actor.identity_id)
            existing = find_by_idempotency_key(
                connection, actor.identity_id, submission.idempotency_key
            )
            # A caller who may no longer submit falls through to a fresh decision, which denies.
            if existing is not None and _allowed(actor, Action.TASK_SUBMIT, existing):
                if existing.request_fingerprint != fingerprint:
                    raise IdempotencyConflictError
                return Submitted(existing, replayed=True)
            decided = self._decisions.submission(
                connection, actor, uuid4(), submission.kind, submission.input, request_id
            )
            task = None
            if decided.decision.effect is Effect.DENY:
                self._decisions.record(connection, decided)
            else:
                task = self._admit(connection, actor, submission, fingerprint, decided)
        if task is None:
            raise AccessDeniedError(decided.decision, visible=False)
        return Submitted(task, replayed=False)

    def get(self, actor: ActorContext, task_id: UUID, request_id: str) -> TaskRecord:
        with self._engine.begin() as connection:
            task = get_task(connection, task_id)
            if task is None:
                raise TaskNotFoundError(f"task {task_id} not found")
            decided = self._decisions.read(connection, actor, task, request_id)
            if decided.decision.effect is Effect.DENY:
                self._decisions.record(connection, decided)
            elif task.owner_id != actor.identity_id:
                self._privileged_read(connection, actor, decided.decision, task)
        if decided.decision.effect is Effect.DENY:
            raise AccessDeniedError(decided.decision, visible=False)
        return task

    def page(
        self,
        actor: ActorContext,
        *,
        everyone: bool,
        limit: int,
        after: Position | None,
        request_id: str,
    ) -> Page:
        if not 1 <= limit <= MAX_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")
        with self._engine.begin() as connection:
            decided = self._decisions.listing(
                connection, actor, everyone=everyone, request_id=request_id
            )
            rows = None
            if decided.decision.effect is Effect.DENY:
                self._decisions.record(connection, decided)
            else:
                if everyone:
                    self._privileged_read(connection, actor, decided.decision, None)
                rows = list_tasks(
                    connection,
                    owner_id=None if everyone else actor.identity_id,
                    limit=limit + 1,
                    after=after,
                )
        if rows is None:
            raise AccessDeniedError(decided.decision, visible=False)
        found = tuple(rows[:limit])
        last = found[-1] if len(rows) > limit else None
        return Page(found, None if last is None else Position(last.created_at, last.task_id))

    def cancel(self, actor: ActorContext, task_id: UUID, request_id: str) -> Cancelled:
        with self._engine.begin() as connection:
            task = lock_task(connection, task_id)
            if task is None:
                raise TaskNotFoundError(f"task {task_id} not found")
            decided = self._decisions.cancellation(connection, actor, task, request_id)
            self._decisions.record(connection, decided)
            cancelled = None
            if decided.decision.effect is Effect.ALLOW:
                cancelled = self._cancel(connection, actor, task, decided.decision)
        if decided.decision.effect is not Effect.ALLOW:
            visible = _allowed(actor, Action.TASK_READ, task)
            raise AccessDeniedError(decided.decision, visible=visible)
        if cancelled is None:
            raise TaskFinishedError(f"task {task_id} has already finished")
        return cancelled

    def _admit(
        self,
        connection: Connection,
        actor: ActorContext,
        submission: Submission,
        fingerprint: str,
        decided: Decided,
    ) -> TaskRecord:
        decision = decided.decision
        if decision.task_id is None or actor.credential_id is None:
            raise ValueError("an admitted submission needs a task and a submitting credential")
        task = insert_task(
            connection,
            NewTask(
                task_id=decision.task_id,
                initiator_id=actor.identity_id,
                submitted_credential_id=actor.credential_id,
                kind=TaskKind(submission.kind),
                input=submission.input,
                idempotency_key=submission.idempotency_key,
                request_fingerprint=fingerprint,
            ),
        )
        self._decisions.record(connection, decided)
        self._recorder.record(
            connection,
            _event(AuditEventType.TASK_CREATED, actor, decision, task, {"kind": task.kind.value}),
        )
        if decision.effect is not Effect.ALLOW:
            return self._transition(connection, actor, task, TaskState.AWAITING_APPROVAL, decision)
        queued = self._transition(connection, actor, task, TaskState.QUEUED, decision)
        create_job(
            connection,
            task.task_id,
            max_attempts=MAX_JOB_ATTEMPTS,
            correlation_id=decision.request_id,
        )
        return queued

    def _cancel(
        self,
        connection: Connection,
        actor: ActorContext,
        task: TaskRecord,
        decision: SecurityDecision,
    ) -> Cancelled | None:
        if task.state in TERMINAL_STATES:
            return None
        if task.state is not TaskState.RUNNING:
            cancelled = self._transition(connection, actor, task, TaskState.CANCELLED, decision)
            finish_pending(connection, task.task_id, "cancelled")
            return Cancelled(cancelled, pending=False)
        # A running task stops at the worker's next heartbeat; the request is recorded once.
        if task.cancel_requested_by is not None:
            return Cancelled(task, pending=True)
        requested = request_cancellation(connection, task, actor.identity_id)
        if requested is None:
            raise TransitionConflictError(f"task {task.task_id} changed since it was read")
        self._recorder.record(
            connection, _event(AuditEventType.TASK_CANCEL_REQUESTED, actor, decision, requested)
        )
        return Cancelled(requested, pending=True)

    def _transition(
        self,
        connection: Connection,
        actor: ActorContext,
        task: TaskRecord,
        target: TaskState,
        decision: SecurityDecision,
    ) -> TaskRecord:
        return apply_transition(
            connection,
            Transition(
                task_id=task.task_id,
                expected_state=task.state,
                expected_version=task.version,
                target=target,
                actor_id=actor.identity_id,
                actor_kind=actor.kind,
                source=Source.API,
                reason_code=decision.reason_codes[0],
                decision=decision,
                request_id=decision.request_id,
            ),
            self._decisions.policy,
            self._recorder,
        )

    def _privileged_read(
        self,
        connection: Connection,
        actor: ActorContext,
        decision: SecurityDecision,
        task: TaskRecord | None,
    ) -> None:
        self._recorder.record(
            connection,
            _event(
                AuditEventType.TASK_READ_PRIVILEGED,
                actor,
                decision,
                task,
                {"scope": "all" if task is None else "task"},
                saved=False,
            ),
        )


def _allowed(actor: ActorContext, action: Action, task: TaskRecord) -> bool:
    resource = ResourceRef(ResourceType.TASK, str(task.task_id), task.owner_id)
    return authorize(actor, action, resource).allowed


def _event(
    event_type: AuditEventType,
    actor: ActorContext,
    decision: SecurityDecision,
    task: TaskRecord | None,
    details: Mapping[str, str] | None = None,
    *,
    saved: bool = True,
) -> AuditEvent:
    return AuditEvent(
        event_type=event_type,
        source=Source.API,
        outcome=Outcome.SUCCESS,
        actor_id=actor.identity_id,
        actor_kind=ActorKind(actor.kind.value),
        target_type=None if task is None else "task",
        target_id=None if task is None else str(task.task_id),
        task_id=None if task is None else task.task_id,
        decision_id=decision.decision_id if saved else None,
        request_id=decision.request_id,
        reason_code=decision.reason_codes[0],
        policy_version=decision.policy_version,
        details=details or {},
    )

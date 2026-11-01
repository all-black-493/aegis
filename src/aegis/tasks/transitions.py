from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import Connection

from aegis.audit.events import ActorKind, AuditEvent, AuditEventType, Outcome, Source
from aegis.audit.recorder import AuditRecorder
from aegis.authorization.catalog import IdentityKind
from aegis.authorization.contract import (
    DecisionRequirement,
    SecurityDecision,
    TaskRef,
    require_consistent,
)
from aegis.tasks.repository import (
    TaskRecord,
    TransitionRow,
    insert_transition,
    lock_task,
    transaction_time,
    update_state,
)
from aegis.tasks.states import TaskState, TransitionRule, rules_for


class IllegalTransitionError(ValueError):
    pass


class TaskNotFoundError(LookupError):
    pass


class TransitionConflictError(RuntimeError):
    pass


@dataclass(frozen=True)
class PolicyRef:
    version: str
    digest: str


@dataclass(frozen=True)
class JobRef:
    job_id: UUID
    attempt: int


@dataclass(frozen=True)
class Transition:
    task_id: UUID
    expected_state: TaskState
    expected_version: int
    target: TaskState
    actor_id: UUID
    actor_kind: IdentityKind
    source: Source
    reason_code: str
    decision: SecurityDecision | None = None
    job: JobRef | None = None
    request_id: str | None = None
    result: Mapping[str, Any] | None = None
    failure_code: str | None = None


def apply_transition(
    connection: Connection, transition: Transition, policy: PolicyRef, recorder: AuditRecorder
) -> TaskRecord:
    if not connection.in_transaction():
        raise IllegalTransitionError("task transitions must run inside a transaction")
    source, target = transition.expected_state, transition.target
    rule = _rule(source, target, transition.decision)
    if rule.requires_job != (transition.job is not None):
        need = "needs" if rule.requires_job else "takes no"
        raise IllegalTransitionError(f"{source} to {target} {need} job")
    task = lock_task(connection, transition.task_id)
    if task is None:
        raise TaskNotFoundError(f"task {transition.task_id} not found")
    if (task.state, task.version) != (source, transition.expected_version):
        raise TransitionConflictError(f"task {task.task_id} changed since it was read")
    _check_decision(rule, transition, task, policy, connection)
    job = transition.job
    insert_transition(
        connection,
        TransitionRow(
            task_id=task.task_id,
            to_version=task.version + 1,
            from_state=source,
            to_state=target,
            actor_id=transition.actor_id,
            reason_code=transition.reason_code,
            decision=transition.decision,
            job_id=job.job_id if job else None,
            job_attempt=job.attempt if job else None,
            request_id=transition.request_id,
        ),
    )
    updated = update_state(
        connection, task, target, result=transition.result, failure_code=transition.failure_code
    )
    if updated is None:
        raise TransitionConflictError(f"task {task.task_id} changed since it was read")
    decision = transition.decision
    recorder.record(
        connection,
        AuditEvent(
            event_type=AuditEventType.TASK_TRANSITIONED,
            source=transition.source,
            outcome=Outcome.SUCCESS,
            actor_id=transition.actor_id,
            actor_kind=ActorKind(transition.actor_kind.value),
            target_type="task",
            target_id=str(task.task_id),
            task_id=task.task_id,
            job_id=job.job_id if job else None,
            decision_id=decision.decision_id if decision else None,
            request_id=transition.request_id,
            reason_code=transition.reason_code,
            policy_version=decision.policy_version if decision else None,
            details={"from_state": source.value, "to_state": target.value},
        ),
    )
    return updated


def _rule(
    source: TaskState, target: TaskState, decision: SecurityDecision | None
) -> TransitionRule:
    candidates = rules_for(source, target)
    if not candidates:
        raise IllegalTransitionError(f"no transition from {source} to {target}")
    if decision is not None:
        for rule in candidates:
            if rule.decision and (
                rule.decision.action,
                rule.decision.effect,
                rule.decision.stage,
            ) == (
                decision.action,
                decision.effect,
                decision.stage,
            ):
                return rule
    for rule in candidates:
        if (rule.decision is None) == (decision is None):
            return rule
    return candidates[0]


def _check_decision(
    rule: TransitionRule,
    transition: Transition,
    task: TaskRecord,
    policy: PolicyRef,
    connection: Connection,
) -> None:
    decision = transition.decision
    if rule.decision is None:
        if decision is not None:
            raise IllegalTransitionError(f"{rule.source} to {rule.target} takes no decision")
        return
    if decision is None:
        raise IllegalTransitionError(
            f"{rule.source} to {rule.target} needs a {rule.decision.action} decision"
        )
    job = transition.job
    require_consistent(
        decision,
        DecisionRequirement(
            task=TaskRef(task.task_id, task.initiator_id, task.owner_id),
            action=rule.decision.action,
            effect=rule.decision.effect,
            stage=rule.decision.stage,
            actor_id=transition.actor_id,
            policy_version=policy.version,
            policy_digest=policy.digest,
            decided_at=transaction_time(connection),
            job_id=job.job_id if job else None,
            job_attempt=job.attempt if job else None,
        ),
    )

from dataclasses import dataclass
from enum import StrEnum

from aegis.authorization.catalog import Action
from aegis.authorization.contract import Effect, Stage


class TaskKind(StrEnum):
    NOOP = "noop"
    WAIT = "wait"
    GENERATE = "generate"


class TaskState(StrEnum):
    CREATED = "created"
    QUEUED = "queued"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


TERMINAL_STATES = frozenset({TaskState.SUCCEEDED, TaskState.FAILED, TaskState.CANCELLED})


@dataclass(frozen=True)
class DecisionRule:
    action: Action
    effect: Effect
    stage: Stage


@dataclass(frozen=True)
class TransitionRule:
    source: TaskState
    target: TaskState
    decision: DecisionRule | None
    requires_job: bool


def _rule(
    source: TaskState,
    target: TaskState,
    decision: tuple[Action, Effect, Stage] | None,
    *,
    job: bool,
) -> TransitionRule:
    return TransitionRule(source, target, DecisionRule(*decision) if decision else None, job)


_S = TaskState
_SUBMIT, _EXECUTE, _CANCEL = Action.TASK_SUBMIT, Action.TASK_EXECUTE, Action.TASK_CANCEL
_ALLOW, _DENY, _APPROVAL = Effect.ALLOW, Effect.DENY, Effect.APPROVAL_REQUIRED
_AUTHORIZATION, _POLICY = Stage.AUTHORIZATION, Stage.POLICY

# Mirrored by aegis.task_transition_rules; a test keeps the two identical.
# awaiting_approval -> queued is deliberately absent until approvals exist (Phase 6, rule D9).
TRANSITION_RULES = (
    _rule(_S.CREATED, _S.QUEUED, (_SUBMIT, _ALLOW, _POLICY), job=False),
    _rule(_S.CREATED, _S.AWAITING_APPROVAL, (_SUBMIT, _APPROVAL, _POLICY), job=False),
    _rule(_S.AWAITING_APPROVAL, _S.CANCELLED, (_CANCEL, _ALLOW, _AUTHORIZATION), job=False),
    _rule(_S.QUEUED, _S.RUNNING, (_EXECUTE, _ALLOW, _POLICY), job=True),
    _rule(_S.QUEUED, _S.AWAITING_APPROVAL, (_EXECUTE, _APPROVAL, _POLICY), job=True),
    _rule(_S.QUEUED, _S.FAILED, (_EXECUTE, _DENY, _AUTHORIZATION), job=True),
    _rule(_S.QUEUED, _S.FAILED, (_EXECUTE, _DENY, _POLICY), job=True),
    _rule(_S.QUEUED, _S.CANCELLED, (_CANCEL, _ALLOW, _AUTHORIZATION), job=False),
    _rule(_S.RUNNING, _S.SUCCEEDED, None, job=True),
    _rule(_S.RUNNING, _S.FAILED, None, job=True),
    _rule(_S.RUNNING, _S.CANCELLED, None, job=True),
    _rule(_S.RUNNING, _S.INTERRUPTED, None, job=True),
    _rule(_S.INTERRUPTED, _S.QUEUED, None, job=True),
    _rule(_S.INTERRUPTED, _S.FAILED, None, job=True),
    _rule(_S.INTERRUPTED, _S.CANCELLED, (_CANCEL, _ALLOW, _AUTHORIZATION), job=False),
)


def rules_for(source: TaskState, target: TaskState) -> tuple[TransitionRule, ...]:
    return tuple(
        rule for rule in TRANSITION_RULES if (rule.source, rule.target) == (source, target)
    )

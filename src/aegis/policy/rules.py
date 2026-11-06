import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from aegis.authorization.access import ActorContext, InvalidActorError, ResourceRef, authorize
from aegis.authorization.catalog import (
    ROLE_PERMISSIONS,
    Action,
    IdentityKind,
    Permission,
    ResourceType,
    Role,
)
from aegis.authorization.contract import Effect, Stage
from aegis.policy.facts import (
    DecisionInputs,
    ExecutionFacts,
    SubmissionFacts,
    TaskFacts,
    ToolFacts,
)

ACTIVE_TASK_QUOTA = 10
APPROVAL_WAIT_SECONDS = 30
MAX_WAIT_SECONDS = 300
MAX_INPUT_BYTES = 16 * 1024
MAX_JOB_ATTEMPTS = 10
MAX_PROMPT_CHARS = 8000
MAX_GENERATE_TOKENS = 512
GENERATE_TEMPERATURE = 0.0
GENERATE_SEED = 0
TASK_KINDS = frozenset({"noop", "wait", "generate", "enforcement_check"})
# All an agent may do until the risk engine and approvals exist (README, Phase 4).
ALLOWED_TOOL_RISK = "low"
ALLOWED_TOOL_NETWORK = "none"
ALLOWED_TOOL_APPROVAL = "none"
ALLOWED_TOOL_BOUNDARY = "sandbox"


@dataclass(frozen=True)
class Outcome:
    effect: Effect
    reason: str


@dataclass(frozen=True)
class Verdict:
    effect: Effect
    stage: Stage
    reason_codes: tuple[str, ...]


type Rule[F] = Callable[[F], Outcome | None]


@dataclass(frozen=True)
class Policy:
    version: str
    digest: str
    submission_rules: tuple[Rule[SubmissionFacts], ...]
    execution_rules: tuple[Rule[ExecutionFacts], ...]
    tool_rules: tuple[Rule[ToolFacts], ...] = ()


class _AboutTask(Protocol):
    @property
    def task(self) -> TaskFacts: ...


class _AboutInitiator(Protocol):
    @property
    def initiator_active(self) -> bool: ...

    @property
    def initiator_roles(self) -> frozenset[Role]: ...

    @property
    def submitting_credential_revoked(self) -> bool: ...


def input_bytes(task_input: Any) -> int:
    canonical = json.dumps(task_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return len(canonical.encode())


def decide(policy: Policy, inputs: DecisionInputs) -> Verdict:
    try:
        actor = ActorContext(inputs.actor_id, inputs.actor_kind, inputs.actor_roles)
        resource = (
            None
            if inputs.resource_id is None or inputs.resource_owner_id is None
            else ResourceRef(ResourceType.TASK, inputs.resource_id, inputs.resource_owner_id)
        )
        authorization = authorize(actor, inputs.action, resource)
    except InvalidActorError:
        return Verdict(Effect.DENY, Stage.AUTHORIZATION, ("invalid_actor",))
    except Exception:
        return Verdict(Effect.DENY, Stage.AUTHORIZATION, ("evaluation_error",))
    if not authorization.allowed:
        reason = authorization.reason
        if inputs.action is Action.TASK_EXECUTE:
            reason = "executor_not_authorized"
        elif inputs.action is Action.TOOL_INVOKE:
            reason = "agent_not_authorized"
        return Verdict(Effect.DENY, Stage.AUTHORIZATION, (reason,))
    if inputs.action is Action.TASK_SUBMIT:
        return _evaluate(policy.submission_rules, inputs.submission)
    if inputs.action is Action.TASK_EXECUTE:
        return _evaluate(policy.execution_rules, inputs.execution)
    if inputs.action is Action.TOOL_INVOKE:
        return _evaluate(policy.tool_rules, inputs.tool)
    return Verdict(Effect.ALLOW, Stage.AUTHORIZATION, (authorization.reason,))


def _evaluate[F](rules: tuple[Rule[F], ...], facts: F | None) -> Verdict:
    try:
        if facts is None:
            raise ValueError("no facts to evaluate")
        outcomes = [outcome for rule in rules if (outcome := rule(facts)) is not None]
    except Exception:
        return Verdict(Effect.DENY, Stage.POLICY, ("evaluation_error",))
    for effect in (Effect.DENY, Effect.APPROVAL_REQUIRED, Effect.ALLOW):
        reasons = tuple(dict.fromkeys(o.reason for o in outcomes if o.effect is effect))
        if reasons:
            return Verdict(effect, Stage.POLICY, reasons)
    return Verdict(Effect.DENY, Stage.POLICY, ("no_matching_rule",))


def _registered(task: TaskFacts) -> bool:
    return task.kind in TASK_KINDS


def _within_limits(task: TaskFacts) -> bool:
    return task.input_bytes <= MAX_INPUT_BYTES


def _well_formed(task: TaskFacts) -> bool:
    if not isinstance(task.input, Mapping):
        return False
    if task.kind in ("noop", "enforcement_check"):
        return not task.input
    if task.kind == "generate":
        prompt, tokens = task.input.get("prompt"), task.input.get("max_output_tokens")
        return (
            set(task.input) == {"prompt", "max_output_tokens"}
            and isinstance(prompt, str)
            and bool(prompt.strip())
            and len(prompt) <= MAX_PROMPT_CHARS
            and type(tokens) is int
            and 1 <= tokens <= MAX_GENERATE_TOKENS
        )
    seconds = task.input.get("seconds")
    return (
        set(task.input) == {"seconds"} and type(seconds) is int and 0 <= seconds <= MAX_WAIT_SECONDS
    )


def _runnable(task: TaskFacts) -> bool:
    return _registered(task) and _within_limits(task) and _well_formed(task)


def kind_not_registered(facts: _AboutTask) -> Outcome | None:
    return None if _registered(facts.task) else Outcome(Effect.DENY, "kind_not_registered")


def input_too_large(facts: _AboutTask) -> Outcome | None:
    return None if _within_limits(facts.task) else Outcome(Effect.DENY, "input_too_large")


def input_invalid(facts: _AboutTask) -> Outcome | None:
    task = facts.task
    if _registered(task) and _within_limits(task) and not _well_formed(task):
        return Outcome(Effect.DENY, "input_invalid")
    return None


def long_wait(facts: _AboutTask) -> Outcome | None:
    task = facts.task
    if (
        _runnable(task)
        and task.kind == "wait"
        and task.input is not None
        and task.input["seconds"] > APPROVAL_WAIT_SECONDS
    ):
        return Outcome(Effect.APPROVAL_REQUIRED, "long_wait_needs_approval")
    return None


def system_submitter(facts: SubmissionFacts) -> Outcome | None:
    if facts.submitter_kind is IdentityKind.SYSTEM:
        return Outcome(Effect.DENY, "system_submitter")
    return None


def active_task_quota(facts: SubmissionFacts) -> Outcome | None:
    if facts.active_tasks >= ACTIVE_TASK_QUOTA:
        return Outcome(Effect.DENY, "active_task_quota_exceeded")
    return None


def submission_allowed(facts: SubmissionFacts) -> Outcome | None:
    return Outcome(Effect.ALLOW, "submission_allowed") if _runnable(facts.task) else None


def initiator_disabled(facts: _AboutInitiator) -> Outcome | None:
    return None if facts.initiator_active else Outcome(Effect.DENY, "initiator_disabled")


def initiator_not_authorized(facts: _AboutInitiator) -> Outcome | None:
    if any(Permission.TASK_CREATE in ROLE_PERMISSIONS[role] for role in facts.initiator_roles):
        return None
    return Outcome(Effect.DENY, "initiator_not_authorized")


def submitting_credential_revoked(facts: _AboutInitiator) -> Outcome | None:
    if facts.submitting_credential_revoked:
        return Outcome(Effect.DENY, "submitting_credential_revoked")
    return None


def execution_allowed(facts: ExecutionFacts) -> Outcome | None:
    return Outcome(Effect.ALLOW, "execution_allowed") if _runnable(facts.task) else None


def run_not_active(facts: ToolFacts) -> Outcome | None:
    return None if facts.request.run_active else Outcome(Effect.DENY, "run_not_active")


def tool_not_registered(facts: ToolFacts) -> Outcome | None:
    return None if facts.request.registered else Outcome(Effect.DENY, "tool_not_registered")


def tool_role_not_permitted(facts: ToolFacts) -> Outcome | None:
    request = facts.request
    if request.registered and Role.AGENT.value not in request.permitted_roles:
        return Outcome(Effect.DENY, "tool_role_not_permitted")
    return None


def capability_not_granted(facts: ToolFacts) -> Outcome | None:
    request = facts.request
    if request.registered and not request.required_capabilities <= request.granted_capabilities:
        return Outcome(Effect.DENY, "capability_not_granted")
    return None


def tool_beyond_low_risk(facts: ToolFacts) -> Outcome | None:
    request = facts.request
    if not request.registered:
        return None
    if (request.risk, request.network, request.approval, request.boundary) != (
        ALLOWED_TOOL_RISK,
        ALLOWED_TOOL_NETWORK,
        ALLOWED_TOOL_APPROVAL,
        ALLOWED_TOOL_BOUNDARY,
    ):
        return Outcome(Effect.DENY, "tool_beyond_low_risk")
    return None


def tool_allowed(facts: ToolFacts) -> Outcome | None:
    return Outcome(Effect.ALLOW, "tool_allowed") if facts.request.registered else None


SUBMISSION_RULES: tuple[Rule[SubmissionFacts], ...] = (
    system_submitter,
    kind_not_registered,
    input_too_large,
    input_invalid,
    active_task_quota,
    long_wait,
    submission_allowed,
)

EXECUTION_RULES: tuple[Rule[ExecutionFacts], ...] = (
    initiator_disabled,
    initiator_not_authorized,
    submitting_credential_revoked,
    kind_not_registered,
    input_too_large,
    input_invalid,
    long_wait,
    execution_allowed,
)

TOOL_RULES: tuple[Rule[ToolFacts], ...] = (
    initiator_disabled,
    initiator_not_authorized,
    submitting_credential_revoked,
    run_not_active,
    tool_not_registered,
    tool_role_not_permitted,
    capability_not_granted,
    tool_beyond_low_risk,
    tool_allowed,
)

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID

from aegis.authorization.catalog import Action, IdentityKind, ResourceType

_REASON_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_POLICY_DIGEST = re.compile(r"[0-9a-f]{64}")
_REQUEST_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


class Stage(StrEnum):
    AUTHORIZATION = "authorization"
    POLICY = "policy"


CONSISTENCY_RULES: Mapping[str, str] = MappingProxyType(
    {
        "C1": "the decision is for this task and job attempt",
        "C2": "the decision's action matches the transition",
        "C3": "the decision's effect matches the target state",
        "C4": "the decision's subject is the task's initiator",
        "C5": "the decision's actor is the expected actor",
        "C6": "the decision's resource is this task and its owner",
        "C7": "the decision used the current policy version and fingerprint",
        "C8": "the decision was made in this transaction",
        "C9": "the decision was made at the required stage",
    }
)


class InvalidDecisionError(ValueError):
    pass


class DecisionMismatchError(ValueError):
    def __init__(self, rules: tuple[str, ...]) -> None:
        self.rules = rules
        failed = "; ".join(f"{rule} ({CONSISTENCY_RULES[rule]})" for rule in rules)
        super().__init__(f"decision does not justify this transition: {failed}")


@dataclass(frozen=True)
class SecurityDecision:
    decision_id: UUID
    decided_at: datetime
    actor_id: UUID
    actor_kind: IdentityKind
    actor_credential_id: UUID | None
    subject_id: UUID
    action: Action
    resource_type: ResourceType
    resource_id: str | None
    resource_owner_id: UUID | None
    task_id: UUID | None
    effect: Effect
    stage: Stage
    reason_codes: tuple[str, ...]
    policy_version: str
    policy_digest: str
    request_id: str | None = None
    job_id: UUID | None = None
    job_attempt: int | None = None

    def __post_init__(self) -> None:
        problems = []
        if self.decided_at.tzinfo is None:
            problems.append("decided_at must include a time zone")
        if not self.reason_codes or not all(
            _REASON_CODE.fullmatch(code) for code in self.reason_codes
        ):
            problems.append("reason_codes must be one or more lowercase codes")
        if not 1 <= len(self.policy_version) <= 64:
            problems.append("policy_version must be 1 to 64 characters")
        if not _POLICY_DIGEST.fullmatch(self.policy_digest):
            problems.append("policy_digest must be 64 lowercase hex characters")
        if self.stage is Stage.AUTHORIZATION and self.effect is Effect.APPROVAL_REQUIRED:
            problems.append("authorization can only allow or deny")
        if (self.job_id is None) != (self.job_attempt is None):
            problems.append("job_id and job_attempt must be given together")
        if self.job_attempt is not None and self.job_attempt < 1:
            problems.append("job_attempt must be at least 1")
        if (self.resource_id is None) != (self.resource_owner_id is None):
            problems.append("resource_id and resource_owner_id must be given together")
        if self.task_id is not None and self.resource_id != str(self.task_id):
            problems.append("a task decision's resource must be that task")
        if self.actor_kind is IdentityKind.SYSTEM and self.actor_credential_id is not None:
            problems.append("system actors have no credentials")
        if self.request_id is not None and not _REQUEST_ID.fullmatch(self.request_id):
            problems.append("request_id has an invalid format")
        if problems:
            raise InvalidDecisionError("; ".join(problems))
        object.__setattr__(self, "reason_codes", tuple(self.reason_codes))


@dataclass(frozen=True)
class TaskRef:
    task_id: UUID
    initiator_id: UUID
    owner_id: UUID


@dataclass(frozen=True)
class DecisionRequirement:
    task: TaskRef
    action: Action
    effect: Effect
    stage: Stage
    actor_id: UUID
    policy_version: str
    policy_digest: str
    decided_at: datetime
    job_id: UUID | None = None
    job_attempt: int | None = None


def require_consistent(decision: SecurityDecision, requirement: DecisionRequirement) -> None:
    task = requirement.task
    checks = {
        "C1": decision.task_id == task.task_id
        and (decision.job_id, decision.job_attempt)
        == (requirement.job_id, requirement.job_attempt),
        "C2": decision.action is requirement.action,
        "C3": decision.effect is requirement.effect,
        "C4": decision.subject_id == task.initiator_id,
        "C5": decision.actor_id == requirement.actor_id
        and (
            requirement.action is not Action.TASK_EXECUTE
            or decision.actor_kind is IdentityKind.SYSTEM
        ),
        "C6": decision.resource_type is ResourceType.TASK
        and decision.resource_id == str(task.task_id)
        and decision.resource_owner_id == task.owner_id,
        "C7": (decision.policy_version, decision.policy_digest)
        == (requirement.policy_version, requirement.policy_digest),
        "C8": decision.decided_at == requirement.decided_at,
        "C9": decision.stage is requirement.stage,
    }
    failed = tuple(rule for rule, satisfied in checks.items() if not satisfied)
    if failed:
        raise DecisionMismatchError(failed)

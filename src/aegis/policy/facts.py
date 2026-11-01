from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from aegis.authorization.catalog import Action, IdentityKind, Role


@dataclass(frozen=True)
class TaskFacts:
    kind: str
    input: Mapping[str, Any] | None
    input_bytes: int


@dataclass(frozen=True)
class SubmissionFacts:
    task: TaskFacts
    submitter_kind: IdentityKind
    active_tasks: int


@dataclass(frozen=True)
class ExecutionFacts:
    task: TaskFacts
    initiator_active: bool
    initiator_roles: frozenset[Role]
    submitting_credential_revoked: bool


@dataclass(frozen=True)
class DecisionInputs:
    action: Action
    actor_id: UUID
    actor_kind: IdentityKind
    actor_roles: frozenset[Role]
    resource_id: str | None
    resource_owner_id: UUID | None
    submission: SubmissionFacts | None = None
    execution: ExecutionFacts | None = None


def to_document(inputs: DecisionInputs) -> dict[str, Any]:
    return {
        "action": inputs.action.value,
        "actor": {
            "id": str(inputs.actor_id),
            "kind": inputs.actor_kind.value,
            "roles": sorted(role.value for role in inputs.actor_roles),
        },
        "resource": None
        if inputs.resource_id is None
        else {"id": inputs.resource_id, "owner_id": str(inputs.resource_owner_id)},
        "submission": None
        if inputs.submission is None
        else {
            "task": _task_document(inputs.submission.task),
            "submitter_kind": inputs.submission.submitter_kind.value,
            "active_tasks": inputs.submission.active_tasks,
        },
        "execution": None
        if inputs.execution is None
        else {
            "task": _task_document(inputs.execution.task),
            "initiator_active": inputs.execution.initiator_active,
            "initiator_roles": sorted(role.value for role in inputs.execution.initiator_roles),
            "submitting_credential_revoked": inputs.execution.submitting_credential_revoked,
        },
    }


def from_document(document: Mapping[str, Any]) -> DecisionInputs:
    actor, resource = document["actor"], document["resource"]
    submission, execution = document["submission"], document["execution"]
    return DecisionInputs(
        action=Action(document["action"]),
        actor_id=UUID(actor["id"]),
        actor_kind=IdentityKind(actor["kind"]),
        actor_roles=frozenset(Role(role) for role in actor["roles"]),
        resource_id=None if resource is None else resource["id"],
        resource_owner_id=None if resource is None else UUID(resource["owner_id"]),
        submission=None
        if submission is None
        else SubmissionFacts(
            task=_task_facts(submission["task"]),
            submitter_kind=IdentityKind(submission["submitter_kind"]),
            active_tasks=submission["active_tasks"],
        ),
        execution=None
        if execution is None
        else ExecutionFacts(
            task=_task_facts(execution["task"]),
            initiator_active=execution["initiator_active"],
            initiator_roles=frozenset(Role(role) for role in execution["initiator_roles"]),
            submitting_credential_revoked=execution["submitting_credential_revoked"],
        ),
    )


def _task_document(task: TaskFacts) -> dict[str, Any]:
    return {"kind": task.kind, "input": task.input, "input_bytes": task.input_bytes}


def _task_facts(document: Mapping[str, Any]) -> TaskFacts:
    return TaskFacts(document["kind"], document["input"], document["input_bytes"])

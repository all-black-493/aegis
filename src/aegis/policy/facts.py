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
class ToolRequest:
    # What the agent layer knows about one proposed call. It carries a digest and a size, never
    # the arguments: decisions are saved, and a tool's content stays in the run records.
    name: str
    registered: bool
    version: str | None
    risk: str | None
    network: str | None
    approval: str | None
    boundary: str | None
    required_capabilities: frozenset[str]
    permitted_roles: frozenset[str]
    granted_capabilities: frozenset[str]
    run_active: bool
    arguments_sha256: str
    arguments_bytes: int


@dataclass(frozen=True)
class ToolFacts:
    request: ToolRequest
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
    tool: ToolFacts | None = None


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
        "tool": None if inputs.tool is None else _tool_document(inputs.tool),
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
        tool=None if document.get("tool") is None else _tool_facts(document["tool"]),
    )


def _tool_document(tool: ToolFacts) -> dict[str, Any]:
    request = tool.request
    return {
        "request": {
            "name": request.name,
            "registered": request.registered,
            "version": request.version,
            "risk": request.risk,
            "network": request.network,
            "approval": request.approval,
            "boundary": request.boundary,
            "required_capabilities": sorted(request.required_capabilities),
            "permitted_roles": sorted(request.permitted_roles),
            "granted_capabilities": sorted(request.granted_capabilities),
            "run_active": request.run_active,
            "arguments_sha256": request.arguments_sha256,
            "arguments_bytes": request.arguments_bytes,
        },
        "initiator_active": tool.initiator_active,
        "initiator_roles": sorted(role.value for role in tool.initiator_roles),
        "submitting_credential_revoked": tool.submitting_credential_revoked,
    }


def _tool_facts(document: Mapping[str, Any]) -> ToolFacts:
    request = document["request"]
    return ToolFacts(
        request=ToolRequest(
            name=request["name"],
            registered=request["registered"],
            version=request["version"],
            risk=request["risk"],
            network=request["network"],
            approval=request["approval"],
            boundary=request["boundary"],
            required_capabilities=frozenset(request["required_capabilities"]),
            permitted_roles=frozenset(request["permitted_roles"]),
            granted_capabilities=frozenset(request["granted_capabilities"]),
            run_active=request["run_active"],
            arguments_sha256=request["arguments_sha256"],
            arguments_bytes=request["arguments_bytes"],
        ),
        initiator_active=document["initiator_active"],
        initiator_roles=frozenset(Role(role) for role in document["initiator_roles"]),
        submitting_credential_revoked=document["submitting_credential_revoked"],
    )


def _task_document(task: TaskFacts) -> dict[str, Any]:
    return {"kind": task.kind, "input": task.input, "input_bytes": task.input_bytes}


def _task_facts(document: Mapping[str, Any]) -> TaskFacts:
    return TaskFacts(document["kind"], document["input"], document["input_bytes"])

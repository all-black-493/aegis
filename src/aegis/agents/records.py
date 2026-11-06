import hashlib
import json
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, func, insert, select

from aegis.agents.schema import agent_runs, agent_steps
from aegis.audit.events import (
    ActorKind,
    AuditEvent,
    AuditEventType,
    DetailValue,
    Outcome,
    Source,
)
from aegis.audit.recorder import AuditRecorder
from aegis.authorization.contract import SecurityDecision
from aegis.identity.schema import SYSTEM_AGENT_ID
from aegis.jobs import repository as jobs
from aegis.model_providers.steps import StepReply, ToolCall
from aegis.tasks.transitions import JobRef, PolicyRef
from aegis.tool_registry.model import ToolResult, ToolStatus

# Must match the check in migration 0009.
MAX_STEP_CONTENT_BYTES = 80 * 1024
NOT_AUTHORIZED = "not_authorized"
FINISHED = "finished"


class StepKind(StrEnum):
    MODEL = "model"
    TOOL = "tool"
    END = "end"


@dataclass(frozen=True)
class AgentRun:
    run_id: UUID
    task_id: UUID
    job: JobRef
    scenario: str
    capabilities: frozenset[str]
    sandbox: str


@dataclass(frozen=True)
class RunRecord:
    run_id: UUID
    attempt: int
    scenario: str
    capabilities: tuple[str, ...]
    sandbox: str
    policy_version: str
    started_at: datetime


@dataclass(frozen=True)
class StepRecord:
    step_id: int
    run_id: UUID
    sequence: int
    kind: str
    code: str
    tool_name: str | None
    tool_version: str | None
    decision_id: UUID | None
    content: Mapping[str, Any]
    content_sha256: str
    content_bytes: int
    prompt_tokens: int | None
    output_tokens: int | None
    duration_ms: int | None
    occurred_at: datetime


def _storable(value: Any) -> Any:
    # jsonb can't hold NUL, which model or tool text may contain.
    if isinstance(value, str):
        return value.replace("\x00", "\ufffd")
    if isinstance(value, Mapping):
        return {_storable(key): _storable(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_storable(item) for item in value]
    return value


def canonical(content: Mapping[str, Any]) -> str:
    # One encoding, so a digest can be checked later. Cleaned before the digest is taken, so the
    # digest is always of what was stored.
    return json.dumps(_storable(content), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(content: Mapping[str, Any]) -> tuple[str, int]:
    encoded = canonical(content).encode()
    return hashlib.sha256(encoded).hexdigest(), len(encoded)


class RunRecords:
    # Everything an agent does is written here and only here: the content in the run records,
    # and in the audit store just identifiers, digests and sizes (ADR-0022).
    def __init__(self, recorder: AuditRecorder, policy: PolicyRef) -> None:
        self._recorder = recorder
        self._policy = policy

    def start(
        self,
        connection: Connection,
        task_id: UUID,
        job: JobRef,
        scenario: str,
        capabilities: Collection[str],
        sandbox: str,
    ) -> AgentRun:
        run = AgentRun(uuid4(), task_id, job, scenario, frozenset(capabilities), sandbox)
        connection.execute(
            insert(agent_runs).values(
                id=run.run_id,
                task_id=task_id,
                job_id=job.job_id,
                job_attempt=job.attempt,
                agent_id=SYSTEM_AGENT_ID,
                scenario=scenario,
                capabilities=sorted(capabilities),
                sandbox=sandbox,
                policy_version=self._policy.version,
                policy_digest=self._policy.digest,
            )
        )
        self._audit(
            connection,
            AuditEventType.AGENT_STARTED,
            run,
            Outcome.SUCCESS,
            "started",
            scenario=scenario,
            capabilities=",".join(sorted(capabilities)),
            sandbox=sandbox,
        )
        return run

    def model_step(self, connection: Connection, run: AgentRun, reply: StepReply) -> int:
        generation = reply.generation
        identity = generation.identity
        content = {
            "text": generation.text,
            "finish_reason": generation.finish_reason.value,
            "tool_calls": [_proposal(call) for call in reply.tool_calls],
            "model": {
                "provider": identity.provider,
                "model": identity.model,
                "digest": identity.digest,
                "runtime_version": identity.runtime_version,
            },
        }
        sequence, _, _ = self._step(
            connection,
            run,
            StepKind.MODEL,
            generation.finish_reason.value,
            content,
            prompt_tokens=generation.prompt_tokens,
            output_tokens=generation.output_tokens,
            duration_ms=generation.duration_ms,
        )
        return sequence

    def tool_step(
        self,
        connection: Connection,
        run: AgentRun,
        call: ToolCall,
        result: ToolResult,
        decision: SecurityDecision,
    ) -> int:
        content = {
            "arguments": dict(call.arguments),
            "status": result.status.value,
            "output": dict(result.output),
        }
        sequence, sha256, size = self._step(
            connection,
            run,
            StepKind.TOOL,
            result.code,
            content,
            tool_name=call.name,
            tool_version=result.version,
            decision_id=decision.decision_id,
        )
        self._audit(
            connection,
            AuditEventType.TOOL_INVOKED,
            run,
            _tool_outcome(result),
            result.code,
            decision_id=decision.decision_id,
            step=sequence,
            tool=call.name,
            version=result.version,
            exit_code=result.exit_code,
            content_sha256=sha256,
            content_bytes=size,
        )
        return sequence

    def end(
        self, connection: Connection, run: AgentRun, code: str, content: Mapping[str, Any]
    ) -> int:
        sequence, sha256, size = self._step(connection, run, StepKind.END, code, content)
        self._audit(
            connection,
            AuditEventType.AGENT_FINISHED,
            run,
            Outcome.SUCCESS if code == FINISHED else Outcome.FAILURE,
            code,
            steps=sequence,
            content_sha256=sha256,
            content_bytes=size,
        )
        return sequence

    def active(self, connection: Connection, run: AgentRun) -> bool:
        job = jobs.lock_fenced(connection, run.job)
        if job is None:
            return False
        ended = connection.execute(
            select(agent_steps.c.id).where(
                agent_steps.c.run_id == run.run_id, agent_steps.c.kind == StepKind.END.value
            )
        ).first()
        return ended is None

    def _step(
        self,
        connection: Connection,
        run: AgentRun,
        kind: StepKind,
        code: str,
        content: Mapping[str, Any],
        **columns: Any,
    ) -> tuple[int, str, int]:
        sequence = (
            1
            + connection.execute(
                select(func.coalesce(func.max(agent_steps.c.sequence), 0)).where(
                    agent_steps.c.run_id == run.run_id
                )
            ).scalar_one()
        )
        sha256, size = digest(content)
        if size > MAX_STEP_CONTENT_BYTES:
            raise ValueError("an agent step's content exceeds its limit")
        connection.execute(
            insert(agent_steps).values(
                run_id=run.run_id,
                sequence=sequence,
                kind=kind.value,
                code=code,
                content=json.loads(canonical(content)),
                content_sha256=sha256,
                content_bytes=size,
                **columns,
            )
        )
        return sequence, sha256, size

    def _audit(
        self,
        connection: Connection,
        event_type: AuditEventType,
        run: AgentRun,
        outcome: Outcome,
        reason: str,
        *,
        decision_id: UUID | None = None,
        **details: DetailValue,
    ) -> None:
        self._recorder.record(
            connection,
            AuditEvent(
                event_type=event_type,
                source=Source.WORKER,
                outcome=outcome,
                actor_id=SYSTEM_AGENT_ID,
                actor_kind=ActorKind.SYSTEM,
                target_type="agent_run",
                target_id=str(run.run_id),
                task_id=run.task_id,
                job_id=run.job.job_id,
                decision_id=decision_id,
                reason_code=reason,
                policy_version=self._policy.version,
                details={"attempt": run.job.attempt, **details},
            ),
        )


def read_runs(connection: Connection, task_id: UUID) -> tuple[RunRecord, ...]:
    rows = connection.execute(
        select(agent_runs)
        .where(agent_runs.c.task_id == task_id)
        .order_by(agent_runs.c.job_attempt, agent_runs.c.started_at)
    ).mappings()
    return tuple(
        RunRecord(
            run_id=row["id"],
            attempt=row["job_attempt"],
            scenario=row["scenario"],
            capabilities=tuple(row["capabilities"]),
            sandbox=row["sandbox"],
            policy_version=row["policy_version"],
            started_at=row["started_at"],
        )
        for row in rows
    )


def read_steps(
    connection: Connection, task_id: UUID, *, after: int, limit: int
) -> tuple[StepRecord, ...]:
    rows = connection.execute(
        select(agent_steps)
        .join(agent_runs, agent_runs.c.id == agent_steps.c.run_id)
        .where(agent_runs.c.task_id == task_id, agent_steps.c.id > after)
        .order_by(agent_steps.c.id)
        .limit(limit)
    ).mappings()
    return tuple(
        StepRecord(
            step_id=row["id"],
            run_id=row["run_id"],
            sequence=row["sequence"],
            kind=row["kind"],
            code=row["code"],
            tool_name=row["tool_name"],
            tool_version=row["tool_version"],
            decision_id=row["decision_id"],
            content=row["content"],
            content_sha256=row["content_sha256"],
            content_bytes=row["content_bytes"],
            prompt_tokens=row["prompt_tokens"],
            output_tokens=row["output_tokens"],
            duration_ms=row["duration_ms"],
            occurred_at=row["occurred_at"],
        )
        for row in rows
    )


def _proposal(call: ToolCall) -> dict[str, Any]:
    return {"name": call.name, "arguments": dict(call.arguments)}


def _tool_outcome(result: ToolResult) -> Outcome:
    if result.code == NOT_AUTHORIZED:
        return Outcome.DENIED
    return Outcome.SUCCESS if result.status is ToolStatus.OK else Outcome.FAILURE

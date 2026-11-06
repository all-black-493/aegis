from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from aegis.agents.records import RunRecord, StepRecord


class RunView(BaseModel):
    id: UUID
    attempt: int
    scenario: str
    capabilities: list[str]
    sandbox: str
    policy_version: str
    started_at: datetime


class StepView(BaseModel):
    id: int
    run_id: UUID
    sequence: int
    kind: str
    code: str
    tool_name: str | None
    tool_version: str | None
    decision_id: UUID | None
    content: dict[str, Any]
    content_sha256: str
    content_bytes: int
    prompt_tokens: int | None
    output_tokens: int | None
    duration_ms: int | None
    occurred_at: datetime


class StepPage(BaseModel):
    runs: list[RunView]
    steps: list[StepView]
    next_after: int | None


def run_view(run: RunRecord) -> RunView:
    return RunView(
        id=run.run_id,
        attempt=run.attempt,
        scenario=run.scenario,
        capabilities=list(run.capabilities),
        sandbox=run.sandbox,
        policy_version=run.policy_version,
        started_at=run.started_at,
    )


def step_view(step: StepRecord) -> StepView:
    return StepView(
        id=step.step_id,
        run_id=step.run_id,
        sequence=step.sequence,
        kind=step.kind,
        code=step.code,
        tool_name=step.tool_name,
        tool_version=step.tool_version,
        decision_id=step.decision_id,
        content=dict(step.content),
        content_sha256=step.content_sha256,
        content_bytes=step.content_bytes,
        prompt_tokens=step.prompt_tokens,
        output_tokens=step.output_tokens,
        duration_ms=step.duration_ms,
        occurred_at=step.occurred_at,
    )

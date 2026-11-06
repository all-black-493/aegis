from collections.abc import Mapping
from uuid import uuid4

from sqlalchemy import Engine

from aegis.agents.records import AgentRun, RunRecords
from aegis.agents.tools import GovernedTools
from aegis.audit.recorder import AuditRecorder
from aegis.authorization.access import ActorContext
from aegis.config.settings import WorkerSettings
from aegis.jobs.settlement import Claim
from aegis.jobs.worker import Worker
from aegis.policy.service import DecisionService
from aegis.policy.version import CURRENT_POLICY
from aegis.tasks.service import Submission, TaskService
from aegis.tasks.transitions import PolicyRef
from aegis.tool_registry.catalog import TOOLS
from aegis.tool_registry.model import Capability, RegisteredTool
from aegis.tool_registry.runner import ToolRunner
from tests.fixtures.agent_sandbox import AGENT_SANDBOX, admitted
from tests.fixtures.fake_runtime import FakeRuntime
from tests.fixtures.services import RECORDER

SCENARIO = "fix-config-typo"
EVERY_CAPABILITY = frozenset(capability.value for capability in Capability)


def claimed(app_engine: Engine, actor: ActorContext) -> Claim:
    # A task with a running job: what an agent run needs, until the agent_run kind exists.
    submission = Submission("noop", {}, f"key-{uuid4().hex}")
    TaskService(app_engine, RECORDER).submit(actor, submission, uuid4().hex)
    claim = Worker(app_engine, RECORDER, WorkerSettings(lease_seconds=60)).claim()
    assert isinstance(claim, Claim)
    return claim


def run_records(recorder: AuditRecorder = RECORDER) -> RunRecords:
    return RunRecords(recorder, PolicyRef(CURRENT_POLICY.version, CURRENT_POLICY.digest))


def started(
    app_engine: Engine, claim: Claim, capabilities: frozenset[str] = EVERY_CAPABILITY
) -> AgentRun:
    with app_engine.begin() as connection:
        return run_records().start(
            connection,
            claim.task.task_id,
            claim.job,
            SCENARIO,
            capabilities,
            AGENT_SANDBOX,
        )


def governed(
    app_engine: Engine,
    claim: Claim,
    run: AgentRun,
    runtime: FakeRuntime | None = None,
    tools: Mapping[str, RegisteredTool] = TOOLS,
    recorder: AuditRecorder = RECORDER,
) -> GovernedTools:
    runner = ToolRunner(runtime or FakeRuntime(), admitted(), tools)
    return GovernedTools(
        app_engine,
        DecisionService(recorder),
        run_records(recorder),
        runner,
        claim.task,
        run,
        tools,
    )

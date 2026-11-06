from collections.abc import Mapping

from sqlalchemy import Connection, Engine

from aegis.agents.records import NOT_AUTHORIZED, AgentRun, RunRecords, digest
from aegis.authorization.contract import Effect
from aegis.model_providers.steps import ToolCall
from aegis.policy.facts import ToolRequest
from aegis.policy.service import DecisionService
from aegis.tasks.repository import TaskRecord
from aegis.tool_registry.catalog import TOOLS
from aegis.tool_registry.model import RegisteredTool, ToolResult, ToolStatus
from aegis.tool_registry.runner import ToolRunner


class GovernedTools:
    # The only way an agent's proposal becomes an action: a saved decision first, the tool only
    # if it allows, and a step and audit event either way. A write that fails raises, so no
    # caller can carry on as if the call had been recorded (ADR-0022).
    def __init__(
        self,
        engine: Engine,
        decisions: DecisionService,
        records: RunRecords,
        runner: ToolRunner,
        task: TaskRecord,
        run: AgentRun,
        tools: Mapping[str, RegisteredTool] = TOOLS,
    ) -> None:
        self._engine = engine
        self._decisions = decisions
        self._records = records
        self._runner = runner
        self._task = task
        self._run = run
        self._tools = tools

    def invoke(self, call: ToolCall) -> ToolResult:
        tool = self._tools.get(call.name)
        with self._engine.begin() as connection:
            request = self._request(connection, call, tool)
            decided = self._decisions.tool_invocation(
                connection, self._task, self._run.job, request
            )
            self._decisions.record(connection, decided)
            decision = decided.decision
            if decision.effect is not Effect.ALLOW:
                refused = ToolResult(
                    call.name,
                    None if tool is None else tool.version,
                    ToolStatus.REFUSED,
                    NOT_AUTHORIZED,
                    {"reasons": list(decision.reason_codes)},
                )
                # A run that has ended takes no more steps; the saved decision is its record.
                if request.run_active:
                    self._records.tool_step(connection, self._run, call, refused, decision)
                return refused
        result = self._runner.run(call)
        with self._engine.begin() as connection:
            self._records.tool_step(connection, self._run, call, result, decision)
        return result

    def _request(
        self, connection: Connection, call: ToolCall, tool: RegisteredTool | None
    ) -> ToolRequest:
        sha256, size = digest(call.arguments)
        run = self._run
        active = self._records.active(connection, run)
        if tool is None:
            return ToolRequest(
                name=call.name,
                registered=False,
                version=None,
                risk=None,
                network=None,
                approval=None,
                boundary=None,
                required_capabilities=frozenset(),
                permitted_roles=frozenset(),
                granted_capabilities=run.capabilities,
                run_active=active,
                arguments_sha256=sha256,
                arguments_bytes=size,
            )
        return ToolRequest(
            name=tool.name,
            registered=True,
            version=tool.version,
            risk=tool.risk.value,
            network=tool.network.value,
            approval=tool.approval.value,
            boundary=tool.boundary.value,
            required_capabilities=frozenset(c.value for c in tool.capabilities),
            permitted_roles=tool.permitted_roles,
            granted_capabilities=run.capabilities,
            run_active=active,
            arguments_sha256=sha256,
            arguments_bytes=size,
        )

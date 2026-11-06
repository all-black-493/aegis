from collections.abc import Mapping

from aegis.model_providers.steps import ToolCall
from aegis.runtime.contract import ExecResult, RuntimeRefusedError, SandboxRuntime
from aegis.runtime.gate import AGENT_PROFILE, AdmittedSandbox
from aegis.tool_registry.arguments import check_arguments
from aegis.tool_registry.catalog import EXIT_CODES, TOOLS
from aegis.tool_registry.model import ArgumentError, RegisteredTool, ToolResult, ToolStatus

_DENIED = "Permission denied"


class ToolRunner:
    # The only way a tool runs, and it takes only a sandbox the gate admitted under the agent
    # profile. Whether a call is allowed at all is decided before this (ADR-0021).
    def __init__(
        self,
        runtime: SandboxRuntime,
        admitted: AdmittedSandbox,
        tools: Mapping[str, RegisteredTool] = TOOLS,
    ) -> None:
        if admitted.profile != AGENT_PROFILE:
            raise RuntimeRefusedError("tools run only in an agent sandbox", code="wrong_profile")
        self._runtime = runtime
        self._name = admitted.sandbox.name
        self._tools = tools

    def run(self, call: ToolCall) -> ToolResult:
        tool = self._tools.get(call.name)
        if tool is None:
            return ToolResult(call.name, None, ToolStatus.REFUSED, "unknown_tool", {})
        try:
            check_arguments(tool.input_schema, call.arguments)
            argv = tool.command(call.arguments, tool.limits)
        except ArgumentError as error:
            return ToolResult(tool.name, tool.version, ToolStatus.REFUSED, error.code, {})
        result = self._runtime.exec(self._name, argv, tool.limits.timeout_seconds)
        return _outcome(tool, call, result)


def _outcome(tool: RegisteredTool, call: ToolCall, result: ExecResult) -> ToolResult:
    if result.timed_out:
        return ToolResult(tool.name, tool.version, ToolStatus.FAILED, "timed_out", {})
    if result.exit_code == 0:
        output = tool.output(call.arguments, result.stdout, tool.limits)
        return ToolResult(tool.name, tool.version, ToolStatus.OK, "ok", output, 0)
    code = EXIT_CODES.get(result.exit_code)
    if code is None:
        code = "denied" if _DENIED in result.stderr else "failed"
    return ToolResult(tool.name, tool.version, ToolStatus.FAILED, code, {}, result.exit_code)

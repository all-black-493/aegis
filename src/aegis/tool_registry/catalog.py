from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from aegis.model_providers.contract import bounded_text
from aegis.model_providers.steps import ToolDefinition
from aegis.runtime.contract import MAX_EXEC_ARG_BYTES
from aegis.tool_registry.arguments import MAX_PATH_BYTES, workspace_path
from aegis.tool_registry.model import (
    Approval,
    Boundary,
    Capability,
    NetworkAccess,
    RegisteredTool,
    Risk,
    SideEffect,
    ToolLimits,
)

# deploy/openshell/agent.yaml makes this the only writable path in an agent sandbox.
WORKSPACE = "/srv/aegis/workspace"
AGENT_ROLE = "agent"
MAX_LISTED_FILES = 256
MAX_WRITE_BYTES = MAX_EXEC_ARG_BYTES
# Exit codes of the fixed scripts below.
EXIT_CODES: Mapping[int, str] = MappingProxyType(
    {3: "not_found", 4: "outside_workspace", 5: "not_a_file", 6: "write_failed"}
)

# Fixed text: $1 is the workspace, and $2 and $3 are arguments, which bash never re-reads as code.
# Each resolves symlinks first, so a link cannot lead a tool out of the workspace.
_READ = (
    'target=$(/usr/bin/realpath -e -- "$2" 2>/dev/null) || exit 3; '
    'case "$target" in "$1"/*) ;; *) exit 4 ;; esac; '
    '[ -f "$target" ] || exit 5; '
    'exec /usr/bin/head -c "$3" -- "$target"'
)
_WRITE = (
    'target=$(/usr/bin/realpath -m -- "$2" 2>/dev/null) || exit 3; '
    'case "$target" in "$1"/*) ;; *) exit 4 ;; esac; '
    '[ ! -d "$target" ] || exit 5; '
    '/usr/bin/mkdir -p -- "$(/usr/bin/dirname -- "$target")" 2>/dev/null || exit 6; '
    'printf %s "$3" > "$target" 2>/dev/null || exit 6'
)
_PATH = {
    "type": "string",
    "maxLength": MAX_PATH_BYTES,
    "description": "A path relative to the workspace, such as notes/todo.txt.",
}


def _absolute(arguments: Mapping[str, Any]) -> str:
    return f"{WORKSPACE}/{workspace_path(arguments['path'])}"


def _list_command(_arguments: Mapping[str, Any], _limits: ToolLimits) -> tuple[str, ...]:
    return ("/usr/bin/find", WORKSPACE, "-type", "f", "-printf", "%P\\n")


def _list_output(
    _arguments: Mapping[str, Any], stdout: str, _limits: ToolLimits
) -> Mapping[str, Any]:
    files = sorted(line for line in stdout.splitlines() if line)
    return {"files": files[:MAX_LISTED_FILES], "truncated": len(files) > MAX_LISTED_FILES}


def _read_command(arguments: Mapping[str, Any], limits: ToolLimits) -> tuple[str, ...]:
    # One byte over the limit, to tell a file of exactly the limit from a longer one.
    size = str(limits.max_output_bytes + 1)
    return ("/usr/bin/bash", "-c", _READ, "read_file", WORKSPACE, _absolute(arguments), size)


def _read_output(
    _arguments: Mapping[str, Any], stdout: str, limits: ToolLimits
) -> Mapping[str, Any]:
    content, truncated = bounded_text(stdout, limits.max_output_bytes)
    return {"content": content, "truncated": truncated}


def _write_command(arguments: Mapping[str, Any], _limits: ToolLimits) -> tuple[str, ...]:
    path, content = _absolute(arguments), arguments["content"]
    return ("/usr/bin/bash", "-c", _WRITE, "write_file", WORKSPACE, path, content)


def _write_output(
    arguments: Mapping[str, Any], _stdout: str, _limits: ToolLimits
) -> Mapping[str, Any]:
    return {"path": arguments["path"], "bytes": len(arguments["content"].encode())}


def _tool(
    name: str,
    description: str,
    capability: Capability,
    side_effect: SideEffect,
    input_properties: Mapping[str, Any],
    output_properties: Mapping[str, Any],
    command: Any,
    output: Any,
) -> RegisteredTool:
    # Every Phase 4 tool is low risk, stays in the sandbox and needs no network or approval.
    # Anything else needs the risk engine and approvals of Phase 6.
    return RegisteredTool(
        name=name,
        version="1",
        description=description,
        input_schema={
            "type": "object",
            "properties": input_properties,
            "required": list(input_properties),
            "additionalProperties": False,
        },
        output_schema={"type": "object", "properties": output_properties},
        capabilities=frozenset({capability}),
        risk=Risk.LOW,
        side_effect=side_effect,
        network=NetworkAccess.NONE,
        limits=ToolLimits(timeout_seconds=15, max_output_bytes=8 * 1024),
        approval=Approval.NONE,
        permitted_roles=frozenset({AGENT_ROLE}),
        boundary=Boundary.SANDBOX,
        command=command,
        output=output,
    )


TOOLS: Mapping[str, RegisteredTool] = MappingProxyType(
    {
        tool.name: tool
        for tool in (
            _tool(
                "list_files",
                "List every file in the workspace.",
                Capability.WORKSPACE_READ,
                SideEffect.NONE,
                {},
                {
                    "files": {"type": "array", "items": {"type": "string"}},
                    "truncated": {"type": "boolean"},
                },
                _list_command,
                _list_output,
            ),
            _tool(
                "read_file",
                "Read one file from the workspace.",
                Capability.WORKSPACE_READ,
                SideEffect.NONE,
                {"path": _PATH},
                {"content": {"type": "string"}, "truncated": {"type": "boolean"}},
                _read_command,
                _read_output,
            ),
            _tool(
                "write_file",
                "Create one file in the workspace, or replace it with new content.",
                Capability.WORKSPACE_WRITE,
                SideEffect.WORKSPACE,
                {
                    "path": _PATH,
                    "content": {
                        "type": "string",
                        "maxLength": MAX_WRITE_BYTES,
                        "description": "The whole new content of the file.",
                    },
                },
                {"path": {"type": "string"}, "bytes": {"type": "integer"}},
                _write_command,
                _write_output,
            ),
        )
    }
)


def offered_tools(tools: Mapping[str, RegisteredTool] = TOOLS) -> tuple[ToolDefinition, ...]:
    return tuple(
        ToolDefinition(tool.name, tool.description, tool.input_schema) for tool in tools.values()
    )

from typing import Any

import pytest

from aegis.model_providers.steps import MAX_STEP_TOOLS, ToolCall
from aegis.runtime.contract import MAX_EXEC_ARG_BYTES, ExecResult, RuntimeRefusedError
from aegis.runtime.gate import POLICY_DIR, PROBE_PROFILE
from aegis.tool_registry.arguments import (
    MAX_PATH_BYTES,
    MAX_PATH_SEGMENTS,
    check_arguments,
    workspace_path,
)
from aegis.tool_registry.catalog import (
    AGENT_ROLE,
    EXIT_CODES,
    MAX_LISTED_FILES,
    MAX_WRITE_BYTES,
    TOOLS,
    WORKSPACE,
    offered_tools,
)
from aegis.tool_registry.model import (
    Approval,
    ArgumentError,
    Boundary,
    NetworkAccess,
    Risk,
    ToolStatus,
)
from aegis.tool_registry.runner import ToolRunner
from tests.fixtures.agent_sandbox import AGENT_SANDBOX, admitted
from tests.fixtures.fake_runtime import FakeRuntime

READ_LIMIT = TOOLS["read_file"].limits.max_output_bytes


def _runner(runtime: FakeRuntime) -> ToolRunner:
    return ToolRunner(runtime, admitted())


def _answering(tool: str, arguments: dict[str, Any], result: ExecResult) -> FakeRuntime:
    registered = TOOLS[tool]
    argv = registered.command(arguments, registered.limits)
    return FakeRuntime(results={argv: result})


def test_the_registry_is_closed_and_holds_exactly_the_approved_tools() -> None:
    assert set(TOOLS) == {"list_files", "read_file", "write_file"}
    with pytest.raises(TypeError):
        TOOLS["shell"] = TOOLS["read_file"]  # type: ignore[index]


@pytest.mark.parametrize("tool", TOOLS.values(), ids=lambda tool: tool.name)
def test_every_tool_is_fully_described_and_low_risk(tool: Any) -> None:
    assert tool.version
    assert tool.description
    assert tool.capabilities
    assert tool.input_schema["additionalProperties"] is False
    assert tool.output_schema["properties"]
    assert tool.limits.timeout_seconds > 0
    assert tool.limits.max_output_bytes > 0
    assert tool.permitted_roles == {AGENT_ROLE}
    assert (tool.risk, tool.network, tool.approval, tool.boundary) == (
        Risk.LOW,
        NetworkAccess.NONE,
        Approval.NONE,
        Boundary.SANDBOX,
    )


def test_the_model_is_offered_what_the_registry_describes() -> None:
    offered = offered_tools()

    assert [tool.name for tool in offered] == list(TOOLS)
    assert len(offered) <= MAX_STEP_TOOLS
    assert offered[1].parameters == TOOLS["read_file"].input_schema


@pytest.mark.parametrize(
    "path", ["a.txt", "notes/todo.txt", "a-b_c.d", "..hidden", "a/b/c", "x" * MAX_PATH_BYTES]
)
def test_relative_normal_paths_are_accepted(path: str) -> None:
    assert workspace_path(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "",
        ".",
        "..",
        "/",
        "/a.txt",
        "/etc/passwd",
        "../a.txt",
        "a/../../b",
        "a/./b",
        "a//b",
        "a/",
        "a b",
        "a\nb",
        "a\\b",
        "~/a",
        "$(id)",
        "`id`",
        "a;b",
        "a|b",
        "a&b",
        "*",
        "é",
        "x" * (MAX_PATH_BYTES + 1),
        "/".join("a" * (MAX_PATH_SEGMENTS + 1)),
    ],
)
def test_every_other_path_is_refused(path: str) -> None:
    with pytest.raises(ArgumentError) as refused:
        workspace_path(path)

    assert refused.value.code == "path_not_allowed"


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("list_files", {"path": "a"}),
        ("read_file", {}),
        ("read_file", {"path": "a", "mode": "r"}),
        ("read_file", {"path": 7}),
        ("read_file", {"path": ["a"]}),
        ("read_file", {"path": None}),
        ("read_file", {"path": "a\x00b"}),
        ("write_file", {"path": "a"}),
        ("write_file", {"path": "a", "content": 7}),
        ("write_file", {"path": "a", "content": "x\x00y"}),
        ("write_file", {"path": "a", "content": "x" * (MAX_WRITE_BYTES + 1)}),
        ("write_file", {"path": "a", "content": "é" * (MAX_WRITE_BYTES // 2 + 1)}),
    ],
)
def test_arguments_that_break_the_schema_are_refused(tool: str, arguments: dict[str, Any]) -> None:
    with pytest.raises(ArgumentError) as refused:
        check_arguments(TOOLS[tool].input_schema, arguments)

    assert refused.value.code == "invalid_arguments"


def test_the_largest_write_fits_in_one_exec_argument() -> None:
    assert MAX_WRITE_BYTES == MAX_EXEC_ARG_BYTES
    check_arguments(
        TOOLS["write_file"].input_schema, {"path": "a", "content": "x" * MAX_WRITE_BYTES}
    )


def test_proposed_text_reaches_a_command_only_as_separate_arguments() -> None:
    hostile = {"path": "a", "content": "$(touch /tmp/pwned); `id` && rm -rf /"}
    tool = TOOLS["write_file"]

    argv = tool.command(hostile, tool.limits)

    assert argv[:2] == ("/usr/bin/bash", "-c")
    assert hostile["content"] not in argv[2]
    assert "a" not in argv[3].split("_")
    assert argv[4:] == (WORKSPACE, f"{WORKSPACE}/a", hostile["content"])


def test_listing_sorts_and_bounds_what_it_returns() -> None:
    names = [f"f{n:04}.txt" for n in reversed(range(MAX_LISTED_FILES + 1))]
    runtime = _answering("list_files", {}, ExecResult(0, "\n".join(names) + "\n", ""))

    result = _runner(runtime).run(ToolCall("list_files", {}))

    assert (result.status, result.code) == (ToolStatus.OK, "ok")
    assert result.output["files"] == sorted(names)[:MAX_LISTED_FILES]
    assert result.output["truncated"] is True


def test_reading_returns_content_and_says_when_it_was_cut() -> None:
    arguments = {"path": "a.txt"}
    whole = _answering("read_file", arguments, ExecResult(0, "x" * READ_LIMIT, ""))
    long = _answering("read_file", arguments, ExecResult(0, "x" * (READ_LIMIT + 1), ""))

    assert _runner(whole).run(ToolCall("read_file", arguments)).output == {
        "content": "x" * READ_LIMIT,
        "truncated": False,
    }
    assert _runner(long).run(ToolCall("read_file", arguments)).output == {
        "content": "x" * READ_LIMIT,
        "truncated": True,
    }


def test_writing_reports_the_path_and_size() -> None:
    arguments = {"path": "notes/a.txt", "content": "héllo"}
    runtime = _answering("write_file", arguments, ExecResult(0, "", ""))

    result = _runner(runtime).run(ToolCall("write_file", arguments))

    assert result.output == {"path": "notes/a.txt", "bytes": 6}
    assert result.version == "1"


@pytest.mark.parametrize(("exit_code", "code"), sorted(EXIT_CODES.items()))
def test_each_script_exit_has_a_stable_code(exit_code: int, code: str) -> None:
    arguments = {"path": "a.txt"}
    runtime = _answering("read_file", arguments, ExecResult(exit_code, "", ""))

    result = _runner(runtime).run(ToolCall("read_file", arguments))

    assert (result.status, result.code, result.exit_code) == (ToolStatus.FAILED, code, exit_code)
    assert result.output == {}


@pytest.mark.parametrize(
    ("result", "code"),
    [
        (ExecResult(1, "", "head: Permission denied"), "denied"),
        (ExecResult(2, "", "unexpected"), "failed"),
        (ExecResult(124, "", "", timed_out=True), "timed_out"),
    ],
)
def test_other_failures_never_look_like_success(result: ExecResult, code: str) -> None:
    arguments = {"path": "a.txt"}
    runtime = _answering("read_file", arguments, result)

    reply = _runner(runtime).run(ToolCall("read_file", arguments))

    assert (reply.status, reply.code) == (ToolStatus.FAILED, code)


@pytest.mark.parametrize(
    ("call", "code"),
    [
        (ToolCall("shell", {"command": "id"}), "unknown_tool"),
        (ToolCall("read_file", {"path": "/etc/passwd"}), "path_not_allowed"),
        (ToolCall("read_file", {"path": "a", "extra": "b"}), "invalid_arguments"),
    ],
)
def test_a_refused_proposal_runs_nothing(call: ToolCall, code: str) -> None:
    runtime = FakeRuntime()

    result = _runner(runtime).run(call)

    assert (result.status, result.code) == (ToolStatus.REFUSED, code)
    assert runtime.calls == []


def test_a_tool_runs_in_the_sandbox_it_was_given() -> None:
    runtime = FakeRuntime()
    runtime.live[AGENT_SANDBOX] = admitted().sandbox

    _runner(runtime).run(ToolCall("list_files", {}))

    assert [call for call in runtime.calls if call.startswith("exec ")] == [
        f"exec /usr/bin/find {WORKSPACE} -type f -printf %P\\n"
    ]


def test_tools_refuse_a_sandbox_under_any_other_profile() -> None:
    with pytest.raises(RuntimeRefusedError) as refused:
        ToolRunner(FakeRuntime(), admitted(PROBE_PROFILE))

    assert refused.value.code == "wrong_profile"


def test_the_workspace_is_the_only_writable_path_in_the_agent_policy() -> None:
    for name in ("agent.yaml", "agent-boundary.yaml"):
        policy = (POLICY_DIR / name).read_text()

        assert f"read_write: [{WORKSPACE}, /dev/null]" in policy
        assert "compatibility: hard_requirement" in policy
        assert "network_policies" not in "\n".join(
            line for line in policy.splitlines() if not line.startswith("#")
        )

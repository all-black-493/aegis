from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from aegis.model_providers.steps import ToolCall
from aegis.runtime.contract import RuntimeRefusedError
from aegis.runtime.gate import (
    AGENT_PROFILE,
    RELEASE,
    RELEASE_FILE,
    SandboxEvent,
    SandboxGate,
    load_policies,
)
from aegis.tool_registry.catalog import MAX_WRITE_BYTES, TOOLS, WORKSPACE
from aegis.tool_registry.model import ToolStatus
from aegis.tool_registry.runner import ToolRunner
from tests.fixtures.fake_openshell import FakeOpenShell

IMAGE = "sha256:" + "a" * 64
NAME = "aegis-tools-1"


@pytest.fixture
def fake(tmp_path: Path) -> FakeOpenShell:
    fake = FakeOpenShell(tmp_path / "bin")
    fake.update(exec={f"/usr/bin/cat {RELEASE_FILE}": {"stdout": RELEASE + "\n"}})
    return fake


@pytest.fixture
def events() -> list[SandboxEvent]:
    return []


@pytest.fixture
def runner(fake: FakeOpenShell, events: list[SandboxEvent]) -> Iterator[ToolRunner]:
    runtime = fake.runtime()
    gate = SandboxGate(runtime, load_policies(), IMAGE, events.append, AGENT_PROFILE)
    with gate.open(NAME, {}) as admitted:
        yield ToolRunner(runtime, admitted)


def _tool_execs(fake: FakeOpenShell) -> list[list[str]]:
    commands = [c["argv"] for c in fake.calls() if "exec" in c["argv"]]
    arguments = [command[command.index("--") + 1 :] for command in commands]
    return [argv for argv in arguments if argv != ["/usr/bin/cat", RELEASE_FILE]]


@pytest.mark.parametrize(
    "path",
    [
        "../unlisted/private",
        "../../etc/passwd",
        "notes/../../../etc/shadow",
        "/etc/passwd",
        "/srv/aegis/unlisted/private",
        "/a.txt",
        "~/.ssh/id_rsa",
        "%2e%2e/%2e%2e/etc/passwd",
        "$(cat /etc/passwd)",
        "`id`",
        "a;touch /tmp/pwned",
        "a b",
        "a\nb",
    ],
)
@pytest.mark.parametrize("tool", ["read_file", "write_file"])
def test_a_path_out_of_the_workspace_is_refused_before_the_sandbox_is_touched(
    fake: FakeOpenShell, runner: ToolRunner, tool: str, path: str
) -> None:
    arguments = {"path": path} if tool == "read_file" else {"path": path, "content": "x"}

    result = runner.run(ToolCall(tool, arguments))

    assert (result.status, result.code) == (ToolStatus.REFUSED, "path_not_allowed")
    assert _tool_execs(fake) == []


@pytest.mark.parametrize(
    ("name", "arguments", "code"),
    [
        ("shell", {"command": "id"}, "unknown_tool"),
        ("run_command", {}, "unknown_tool"),
        ("write_file", {"path": "a", "content": "x" * (MAX_WRITE_BYTES + 1)}, "invalid_arguments"),
        ("read_file", {"path": "x" * 4096}, "invalid_arguments"),
        ("read_file", {"path": "a", "follow_symlinks": "yes"}, "invalid_arguments"),
        ("list_files", {"path": "/"}, "invalid_arguments"),
    ],
)
def test_an_unregistered_tool_or_oversized_argument_runs_nothing(
    fake: FakeOpenShell, runner: ToolRunner, name: str, arguments: dict[str, Any], code: str
) -> None:
    result = runner.run(ToolCall(name, arguments))

    assert (result.status, result.code) == (ToolStatus.REFUSED, code)
    assert _tool_execs(fake) == []


def test_hostile_content_stays_one_literal_argument(
    fake: FakeOpenShell, runner: ToolRunner
) -> None:
    content = "$(touch /tmp/pwned)\n`id`; rm -rf / && echo 'x' \"y\""

    result = runner.run(ToolCall("write_file", {"path": "a.txt", "content": content}))

    assert result.status is ToolStatus.OK
    [argv] = _tool_execs(fake)
    assert argv[-3:] == [WORKSPACE, f"{WORKSPACE}/a.txt", content]
    assert content not in argv[2]


def test_the_agent_sandbox_is_proven_against_the_agent_boundary(
    fake: FakeOpenShell, runner: ToolRunner, events: list[SandboxEvent]
) -> None:
    proven = [call["argv"] for call in fake.calls() if call["program"] == "openshell-prover"]

    checks = [argv for argv in proven if argv[:1] == ["check"]]
    assert len(checks) == 2
    assert all(
        argv[argv.index("--boundary") + 1].endswith("agent-boundary.yaml") for argv in checks
    )
    assert checks[0][1].endswith("agent.yaml")
    assert events[0].details["profile"] == "agent"
    assert (
        "network_policies"
        not in next(iter(fake.state["sandboxes"].values()))["policy"]
        .replace("no network rules", "")
        .split("version: 1")[1]
    )


def test_a_sandbox_opened_under_the_probe_profile_cannot_run_tools(fake: FakeOpenShell) -> None:
    runtime = fake.runtime()
    gate = SandboxGate(runtime, load_policies(), IMAGE, lambda event: None)

    with gate.open(NAME, {}) as admitted, pytest.raises(RuntimeRefusedError) as refused:
        ToolRunner(runtime, admitted)

    assert refused.value.code == "wrong_profile"
    assert _tool_execs(fake) == []


def test_the_registry_offers_no_command_execution() -> None:
    assert not {"shell", "bash", "exec", "run", "run_command"} & set(TOOLS)

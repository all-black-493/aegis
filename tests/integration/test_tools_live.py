from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import pytest

from aegis.integrations.openshell.runtime import OpenShellRuntime
from aegis.model_providers.steps import ToolCall
from aegis.runtime.gate import AGENT_PROFILE, POLICY_DIR, SandboxGate, load_policies
from aegis.runtime.probes.canary import Canary
from aegis.runtime.probes.catalog import CANARY_HOST, CANARY_OTHER_PORT, CANARY_PORT, UNROUTED_HOST
from aegis.tool_registry.catalog import WORKSPACE
from aegis.tool_registry.model import ToolStatus
from aegis.tool_registry.runner import ToolRunner

pytestmark = pytest.mark.openshell
UNLISTED = "/srv/aegis/unlisted/private"
SCENARIO = "/srv/aegis/scenarios/fix-config-typo"
OUTSIDE_DIRECTORY = "/tmp"  # noqa: S108 - a path inside the sandbox, not on this host
OUTSIDE = f"{OUTSIDE_DIRECTORY}/outside"


@dataclass
class Workspace:
    runtime: OpenShellRuntime
    name: str
    tools: ToolRunner

    def raw(self, *argv: str) -> tuple[int, str, str]:
        # Straight to the sandbox, past every AEGIS check: only OpenShell stands in the way.
        result = self.runtime.exec(self.name, argv, 15)
        return result.exit_code, result.stdout, result.stderr


@pytest.fixture
def workspace(openshell_runtime: OpenShellRuntime, probe_image: str) -> Iterator[Workspace]:
    name = f"aegis-tools-{uuid4().hex[:7]}"
    gate = SandboxGate(
        openshell_runtime, load_policies(), probe_image, lambda event: None, AGENT_PROFILE
    )
    with gate.open(name, {"aegis.purpose": "test"}) as admitted:
        found = Workspace(openshell_runtime, name, ToolRunner(openshell_runtime, admitted))
        assert found.raw("/usr/bin/cp", "-r", "--", f"{SCENARIO}/.", WORKSPACE)[0] == 0
        yield found


def test_the_tools_list_read_and_write_in_a_real_sandbox(workspace: Workspace) -> None:
    tools = workspace.tools

    listed = tools.run(ToolCall("list_files", {}))
    read = tools.run(ToolCall("read_file", {"path": "config.txt"}))
    written = tools.run(
        ToolCall("write_file", {"path": "deep/er/config.txt", "content": "port=8080\n"})
    )
    again = tools.run(ToolCall("read_file", {"path": "deep/er/config.txt"}))

    assert listed.output == {"files": ["config.txt", "notes.txt"], "truncated": False}
    assert read.output == {"content": "prot=8080\nhost=local\n", "truncated": False}
    assert written.output == {"path": "deep/er/config.txt", "bytes": 10}
    assert again.output == {"content": "port=8080\n", "truncated": False}


def test_hostile_content_is_stored_and_never_run(workspace: Workspace) -> None:
    content = "$(touch /srv/aegis/workspace/pwned)\n`id`; echo 'x' \"y\"\n"

    written = workspace.tools.run(ToolCall("write_file", {"path": "a.txt", "content": content}))
    read = workspace.tools.run(ToolCall("read_file", {"path": "a.txt"}))
    listed = workspace.tools.run(ToolCall("list_files", {}))

    assert written.status is ToolStatus.OK
    assert read.output["content"] == content
    assert "pwned" not in listed.output["files"]


def test_missing_files_and_directories_have_stable_codes(workspace: Workspace) -> None:
    assert workspace.raw("/usr/bin/mkdir", f"{WORKSPACE}/folder")[0] == 0

    missing = workspace.tools.run(ToolCall("read_file", {"path": "absent.txt"}))
    folder = workspace.tools.run(ToolCall("read_file", {"path": "folder"}))
    over = workspace.tools.run(ToolCall("write_file", {"path": "folder", "content": "x"}))

    assert (missing.status, missing.code) == (ToolStatus.FAILED, "not_found")
    assert folder.code == "not_a_file"
    assert over.code == "not_a_file"


@pytest.mark.parametrize("target", ["/etc/passwd", UNLISTED])
def test_a_symlink_cannot_lead_a_tool_out_of_the_workspace(
    workspace: Workspace, target: str
) -> None:
    assert workspace.raw("/usr/bin/ln", "-s", target, f"{WORKSPACE}/link")[0] == 0

    read = workspace.tools.run(ToolCall("read_file", {"path": "link"}))
    written = workspace.tools.run(ToolCall("write_file", {"path": "link", "content": "x"}))

    assert (read.status, read.code) == (ToolStatus.FAILED, "outside_workspace")
    assert (written.status, written.code) == (ToolStatus.FAILED, "outside_workspace")


def test_a_dangling_symlink_out_of_the_workspace_reveals_nothing(workspace: Workspace) -> None:
    assert workspace.raw("/usr/bin/ln", "-s", OUTSIDE, f"{WORKSPACE}/link")[0] == 0

    read = workspace.tools.run(ToolCall("read_file", {"path": "link"}))
    written = workspace.tools.run(ToolCall("write_file", {"path": "link", "content": "x"}))

    assert (read.status, read.code, read.output) == (ToolStatus.FAILED, "not_found", {})
    assert (written.status, written.code) == (ToolStatus.FAILED, "outside_workspace")


def test_a_symlinked_directory_cannot_lead_a_write_out_of_the_workspace(
    workspace: Workspace,
) -> None:
    assert workspace.raw("/usr/bin/ln", "-s", OUTSIDE_DIRECTORY, f"{WORKSPACE}/out")[0] == 0

    written = workspace.tools.run(ToolCall("write_file", {"path": "out/a.txt", "content": "x"}))

    assert written.code == "outside_workspace"


@pytest.mark.parametrize(
    "argv",
    [
        ("/usr/bin/cat", UNLISTED),
        ("/usr/bin/cat", f"{WORKSPACE}/../unlisted/private"),
        ("/usr/bin/cat", "/srv/aegis/readonly/marker"),
        ("/usr/bin/touch", OUTSIDE),
        ("/usr/bin/touch", f"{WORKSPACE}/../outside"),
        ("/usr/bin/touch", "/srv/aegis/scenarios/outside"),
        ("/usr/bin/touch", "/etc/outside"),
    ],
)
def test_openshell_refuses_what_aegis_would_refuse_even_without_aegis(
    workspace: Workspace, argv: tuple[str, ...]
) -> None:
    exit_code, stdout, stderr = workspace.raw(*argv)

    assert (exit_code, stdout) == (1, "")
    assert "Permission denied" in stderr


def test_openshell_refuses_a_symlink_out_of_the_workspace_even_without_aegis(
    workspace: Workspace,
) -> None:
    assert workspace.raw("/usr/bin/ln", "-s", UNLISTED, f"{WORKSPACE}/link")[0] == 0

    exit_code, stdout, stderr = workspace.raw("/usr/bin/cat", f"{WORKSPACE}/link")

    assert (exit_code, stdout) == (1, "")
    assert "Permission denied" in stderr


def test_only_aegis_stops_a_symlink_to_a_path_the_policy_lists(workspace: Workspace) -> None:
    # Landlock allows this read, because /etc is listed, so the tool's own check is what matters.
    assert workspace.raw("/usr/bin/ln", "-s", "/etc/passwd", f"{WORKSPACE}/link")[0] == 0

    exit_code, stdout, _ = workspace.raw("/usr/bin/cat", f"{WORKSPACE}/link")
    read = workspace.tools.run(ToolCall("read_file", {"path": "link"}))

    assert (exit_code, "root:" in stdout) == (0, True)
    assert (read.status, read.code, read.output) == (ToolStatus.FAILED, "outside_workspace", {})


def test_an_agent_sandbox_has_no_network(workspace: Workspace) -> None:
    def connect(host: str, port: int) -> tuple[int, str, str]:
        return workspace.raw("/usr/bin/bash", "-c", f"exec 3<>/dev/tcp/{host}/{port} || exit 9")

    with Canary(CANARY_HOST, (CANARY_PORT, CANARY_OTHER_PORT)) as canary:
        attempts = [
            connect(CANARY_HOST, CANARY_PORT),
            connect(CANARY_HOST, CANARY_OTHER_PORT),
            connect(UNROUTED_HOST, 443),
        ]
        received = canary.hits()

    assert [attempt[0] for attempt in attempts] == [9, 9, 9]
    assert all("Permission denied" in attempt[2] for attempt in attempts)
    assert received == frozenset()


def test_the_real_prover_keeps_network_rules_out_of_an_agent_sandbox(
    openshell_runtime: OpenShellRuntime,
) -> None:
    verdict = openshell_runtime.check_policy(
        POLICY_DIR / "probe.yaml", Path(POLICY_DIR / "agent-boundary.yaml")
    )

    assert not verdict.passed
    assert verdict.result.value == "exceeds_boundary"

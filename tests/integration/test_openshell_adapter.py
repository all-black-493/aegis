from pathlib import Path
from typing import Any

import pytest

from aegis.config.settings import OpenShellSettings
from aegis.integrations.openshell.cli import OpenShellCli
from aegis.integrations.openshell.runtime import OpenShellRuntime
from aegis.runtime.contract import (
    MAX_EXEC_OUTPUT_BYTES,
    ProverResult,
    RuntimeProtocolError,
    RuntimeRefusedError,
    RuntimeUnavailableError,
    SandboxSpec,
)
from tests.fixtures.fake_openshell import FakeOpenShell


@pytest.fixture
def fake(tmp_path: Path) -> FakeOpenShell:
    return FakeOpenShell(tmp_path / "bin")


@pytest.fixture
def policy(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\nlandlock:\n  compatibility: hard_requirement\n")
    return path


def _spec(policy: Path, name: str = "aegis-test-1") -> SandboxSpec:
    return SandboxSpec(name, "ubuntu:24.04", policy, {"aegis.task": "t1"})


def test_a_connected_gateway_at_the_verified_version_is_healthy(fake: FakeOpenShell) -> None:
    status = fake.runtime().check()

    assert (status.healthy, status.detail, status.version) == (True, "ok", "0.1.6")


@pytest.mark.parametrize(
    ("change", "detail"),
    [
        ({"version": "0.1.7"}, "version_mismatch"),
        ({"prover_version": "0.1.5"}, "version_mismatch"),
        ({"gateway_version": "0.2.0"}, "version_mismatch"),
        ({"status": "not_configured"}, "not_connected"),
        ({"status_exit": 1}, "unreachable"),
        ({"workspaces": ["default"]}, "workspace_missing"),
        ({"global_policy": True}, "global_policy_active"),
    ],
)
def test_check_explains_why_the_runtime_cannot_be_used(
    fake: FakeOpenShell, change: dict[str, Any], detail: str
) -> None:
    fake.update(**change)

    status = fake.runtime().check()

    assert (status.healthy, status.detail) == (False, detail)


def test_a_missing_cli_is_reported(tmp_path: Path) -> None:
    cli = OpenShellCli(
        "openshell", "aegis", executable=tmp_path / "absent", prover=tmp_path / "absent"
    )

    status = OpenShellRuntime(OpenShellSettings(), cli=cli).check()

    assert (status.healthy, status.detail) == (False, "cli_missing")


def test_create_requests_a_detached_labelled_sandbox_with_the_policy(
    fake: FakeOpenShell, policy: Path
) -> None:
    sandbox = fake.runtime().create(_spec(policy))

    assert (sandbox.name, sandbox.phase, sandbox.ready) == ("aegis-test-1", "Ready", True)
    assert dict(sandbox.labels) == {"aegis.task": "t1", "aegis.managed": "true"}
    [create] = [call["argv"] for call in fake.calls() if "create" in call["argv"]]
    assert create[:6] == ["--gateway", "openshell", "--workspace", "aegis", "--color", "never"]
    assert create[create.index("--policy") + 1] == str(policy)
    assert {"--detach", "--no-tty", "--no-auto-providers"} <= set(create)
    assert create[-3:] == ["--", "/usr/bin/sleep", "infinity"]


@pytest.mark.parametrize(
    ("change", "error", "code"),
    [
        ({"version": "0.1.7"}, RuntimeRefusedError, "version_mismatch"),
        ({"status": "not_configured"}, RuntimeUnavailableError, "not_connected"),
        ({"create_exit": 1}, RuntimeRefusedError, "sandbox_rejected"),
        ({"create_phase": "Error"}, RuntimeRefusedError, "sandbox_not_ready"),
        ({"admission": "rejected"}, RuntimeRefusedError, "sandbox_not_ready"),
    ],
)
def test_a_refused_creation_leaves_no_sandbox(
    fake: FakeOpenShell,
    policy: Path,
    change: dict[str, Any],
    error: type[Exception],
    code: str,
) -> None:
    fake.update(**change)

    with pytest.raises(error) as refused:
        fake.runtime().create(_spec(policy))

    assert getattr(refused.value, "code", None) == code
    assert fake.state["sandboxes"] == {}


def test_a_missing_policy_file_is_rejected_by_openshell(
    fake: FakeOpenShell, tmp_path: Path
) -> None:
    with pytest.raises(RuntimeRefusedError) as refused:
        fake.runtime().create(_spec(tmp_path / "absent.yaml"))

    assert refused.value.code == "sandbox_rejected"


def test_exec_passes_the_command_and_returns_its_exit_status(
    fake: FakeOpenShell, policy: Path
) -> None:
    fake.update(exec={"/usr/bin/id -u": {"stdout": "1000\n", "stderr": "", "exit": 3}})
    runtime = fake.runtime()
    runtime.create(_spec(policy))

    result = runtime.exec("aegis-test-1", ["/usr/bin/id", "-u"], 10)

    assert (result.exit_code, result.stdout, result.timed_out) == (3, "1000\n", False)
    [call] = [c["argv"] for c in fake.calls() if "exec" in c["argv"]]
    assert call[call.index("--timeout") + 1] == "10"
    assert {"--no-tty", "--no-login-shell"} <= set(call)


def test_exec_needs_a_ready_sandbox(fake: FakeOpenShell) -> None:
    with pytest.raises(RuntimeUnavailableError) as refused:
        fake.runtime().exec("aegis-test-1", ["/usr/bin/true"], 5)

    assert refused.value.code == "sandbox_not_ready"
    assert not [c for c in fake.calls() if "exec" in c["argv"]]


def test_an_exec_timeout_is_reported(fake: FakeOpenShell, policy: Path) -> None:
    fake.update(exec={"/usr/bin/sleep 30": {"sleep": 30}})
    runtime = fake.runtime()
    runtime.create(_spec(policy))

    result = runtime.exec("aegis-test-1", ["/usr/bin/sleep", "30"], 1)

    assert (result.exit_code, result.timed_out) == (124, True)


def test_exec_output_is_bounded(fake: FakeOpenShell, policy: Path) -> None:
    fake.update(exec={"/usr/bin/yes": {"flood": 4 * MAX_EXEC_OUTPUT_BYTES}})
    runtime = fake.runtime()
    runtime.create(_spec(policy))

    result = runtime.exec("aegis-test-1", ["/usr/bin/yes"], 10)

    assert result.truncated
    assert len(result.stdout.encode()) == MAX_EXEC_OUTPUT_BYTES


def test_get_and_delete_follow_the_sandbox(fake: FakeOpenShell, policy: Path) -> None:
    runtime = fake.runtime()
    runtime.create(_spec(policy))

    assert runtime.get("aegis-test-1") is not None
    assert runtime.effective_policy("aegis-test-1") == policy.read_text() + "\n"
    runtime.delete("aegis-test-1")
    runtime.delete("aegis-test-1")
    assert runtime.get("aegis-test-1") is None


def test_a_deletion_that_never_completes_is_reported(fake: FakeOpenShell, policy: Path) -> None:
    runtime = fake.runtime()
    runtime.create(_spec(policy))
    fake.update(delete_lingers=True)

    with pytest.raises(RuntimeUnavailableError) as pending:
        runtime.delete("aegis-test-1")

    assert pending.value.code == "delete_pending"


def test_managed_follows_pages_and_keeps_only_aegis_sandboxes(fake: FakeOpenShell) -> None:
    for index in range(5):
        fake.add_sandbox(f"aegis-old-{index}", **{"aegis.managed": "true"})
    fake.add_sandbox("aegis-unlabelled")
    fake.add_sandbox("someone-else", **{"aegis.managed": "true"})
    fake.add_sandbox("aegis-elsewhere", workspace="default", **{"aegis.managed": "true"})
    fake.update(page_size=2, ignore_selector=True)

    names = sorted(sandbox.name for sandbox in fake.runtime().managed())

    assert names == [f"aegis-old-{index}" for index in range(5)]


@pytest.mark.parametrize(
    ("verdict", "result", "passed"),
    [
        ({}, ProverResult.WITHIN_BOUNDARY, True),
        (
            {
                "result": "exceeds_boundary",
                "exit_code": 1,
                "counterexample": {"domain": "landlock"},
            },
            ProverResult.EXCEEDS_BOUNDARY,
            False,
        ),
        (
            {"result": "unsupported", "exit_code": 3, "reason_code": "unresolved_filesystem_path"},
            ProverResult.UNSUPPORTED,
            False,
        ),
        ({"coverage": {"domains": ["filesystem"]}}, ProverResult.WITHIN_BOUNDARY, False),
    ],
)
def test_prover_verdicts_are_read_and_only_full_passes_count(
    fake: FakeOpenShell,
    policy: Path,
    verdict: dict[str, Any],
    result: ProverResult,
    passed: bool,
) -> None:
    fake.update(verdict={**fake.state["verdict"], **verdict})

    found = fake.runtime().check_policy(policy, policy)

    assert (found.result, found.passed) == (result, passed)


def test_a_prover_of_another_version_is_refused(fake: FakeOpenShell, policy: Path) -> None:
    fake.update(prover_version="0.2.0")

    with pytest.raises(RuntimeRefusedError):
        fake.runtime().check_policy(policy, policy)


def test_a_disagreeing_prover_report_is_a_protocol_error(fake: FakeOpenShell, policy: Path) -> None:
    fake.update(verdict={**fake.state["verdict"], "exit_code": 1}, prover_exit=0)

    with pytest.raises(RuntimeProtocolError):
        fake.runtime().check_policy(policy, policy)


def test_the_workspace_is_created_only_when_missing(fake: FakeOpenShell) -> None:
    fake.update(workspaces=["default"])
    runtime = fake.runtime()

    assert runtime.ensure_workspace() is True
    assert runtime.ensure_workspace() is False
    assert fake.state["workspaces"] == ["default", "aegis"]

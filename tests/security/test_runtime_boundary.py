import subprocess
from pathlib import Path
from typing import Any, NoReturn

import pytest

from aegis.config.settings import RuntimeSettings, SandboxRuntimeKind
from aegis.config.variables import SECRET_NAMES
from aegis.integrations.openshell.cli import ALLOWED_COMMANDS
from aegis.runtime.contract import (
    InvalidSandboxError,
    RuntimeRefusedError,
    RuntimeUnavailableError,
    SandboxRuntimeError,
    SandboxSpec,
)
from aegis.runtime.factory import build_runtime
from tests.fixtures.fake_openshell import FakeOpenShell

SECRET = "s3cret-value-that-must-stay-in-aegis"


@pytest.fixture
def fake(tmp_path: Path) -> FakeOpenShell:
    return FakeOpenShell(tmp_path / "bin")


@pytest.fixture
def policy(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\n")
    return path


def _lifecycle(fake: FakeOpenShell, policy: Path, environ: dict[str, str] | None = None) -> None:
    runtime = fake.runtime(environ=environ)
    runtime.check()
    runtime.create(SandboxSpec("aegis-probe-1", "ubuntu:24.04", policy))
    runtime.exec("aegis-probe-1", ["/usr/bin/id"], 5)
    runtime.effective_policy("aegis-probe-1")
    runtime.check_policy(policy, policy)
    runtime.managed()
    runtime.delete("aegis-probe-1")


def test_no_aegis_secret_or_openshell_override_reaches_the_cli(
    fake: FakeOpenShell, policy: Path
) -> None:
    environ = {
        **dict.fromkeys(SECRET_NAMES, SECRET),
        "AEGIS_POSTGRES_DB": "aegis",
        "OPENSHELL_GATEWAY_INSECURE": "1",
        "OPENSHELL_GATEWAY_ENDPOINT": "https://203.0.113.9:17670",
        "HOME": "/home/aegis",
        "PATH": "/home/attacker/bin:/usr/bin",
    }

    _lifecycle(fake, policy, environ)

    calls = fake.calls()
    assert calls
    for call in calls:
        assert SECRET not in repr(call)
        assert set(call["env"]) <= {"PATH", "LANG", "NO_COLOR", "HOME"}
        assert call["env"]["PATH"] == "/usr/bin:/bin"


def test_only_allow_listed_commands_run_and_always_in_aegis_scope(
    fake: FakeOpenShell, policy: Path
) -> None:
    _lifecycle(fake, policy)

    for call in fake.calls():
        if call["program"] == "openshell-prover":
            assert call["argv"][0] in ("--version", "check")
            continue
        argv = call["argv"]
        if argv == ["--version"]:
            continue
        assert argv[:6] == ["--gateway", "openshell", "--workspace", "aegis", "--color", "never"]
    commands = {command[1:] for command in fake.commands() if command[0] == "openshell"}
    assert commands - {("--version",)} <= ALLOWED_COMMANDS
    assert not any(
        "--global" in call["argv"] and "get" not in call["argv"] for call in fake.calls()
    )


def test_other_sandboxes_are_never_listed_or_deleted(fake: FakeOpenShell) -> None:
    fake.add_sandbox("someone-else", **{"aegis.managed": "true"})
    fake.add_sandbox("aegis-unlabelled")
    fake.add_sandbox("aegis-elsewhere", workspace="default", **{"aegis.managed": "true"})
    fake.add_sandbox("aegis-stale", **{"aegis.managed": "true"})
    fake.update(ignore_selector=True)
    runtime = fake.runtime()

    for sandbox in runtime.managed():
        runtime.delete(sandbox.name)
    for name in ("someone-else", "default", "../aegis-stale", "aegis-stale --all"):
        with pytest.raises(InvalidSandboxError):
            runtime.delete(name)

    assert set(fake.state["sandboxes"]) == {"someone-else", "aegis-unlabelled", "aegis-elsewhere"}
    deleted = [c["argv"] for c in fake.calls() if "delete" in c["argv"]]
    assert deleted == [[*deleted[0][:6], "sandbox", "delete", "aegis-stale"]]


@pytest.mark.parametrize(
    ("change", "error", "code"),
    [
        ({"version": "0.1.8"}, RuntimeRefusedError, "version_mismatch"),
        ({"version": "0.1.6"}, RuntimeRefusedError, "version_mismatch"),
        ({"prover_version": "0.2.0"}, RuntimeRefusedError, "version_mismatch"),
        ({"gateway_version": "0.1.5"}, RuntimeRefusedError, "version_mismatch"),
        ({"status_exit": 1}, RuntimeUnavailableError, "unreachable"),
        ({"status": "not_configured"}, RuntimeUnavailableError, "not_connected"),
    ],
)
def test_an_unverified_or_unreachable_runtime_creates_nothing(
    fake: FakeOpenShell,
    policy: Path,
    change: dict[str, Any],
    error: type[SandboxRuntimeError],
    code: str,
) -> None:
    fake.update(**change)

    with pytest.raises(error) as refused:
        fake.runtime().create(SandboxSpec("aegis-probe-1", "ubuntu:24.04", policy))

    assert refused.value.code == code
    assert ("openshell", "sandbox", "create") not in fake.commands()
    assert fake.state["sandboxes"] == {}


def test_a_disabled_runtime_executes_nothing(monkeypatch: pytest.MonkeyPatch, policy: Path) -> None:
    def refuse(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("a disabled runtime must not start a process")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    runtime = build_runtime(RuntimeSettings(SandboxRuntimeKind.NONE))

    assert not runtime.check().healthy
    for operation in (
        lambda: runtime.create(SandboxSpec("aegis-probe-1", "ubuntu:24.04", policy)),
        lambda: runtime.exec("aegis-probe-1", ["/usr/bin/id"], 5),
        lambda: runtime.check_policy(policy, policy),
    ):
        with pytest.raises(RuntimeRefusedError) as refused:
            operation()
        assert refused.value.code == "sandbox_unavailable"

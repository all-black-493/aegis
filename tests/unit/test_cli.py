import os

import pytest

from aegis.apps.cli import __main__ as cli
from aegis.apps.cli.__main__ import main
from aegis.config.settings import OpenShellSettings
from aegis.runtime.contract import RuntimeStatus


@pytest.fixture
def environment(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in list(os.environ):
        if name.startswith("AEGIS_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("AEGIS_POSTGRES_DB", "aegis")
    monkeypatch.setenv("AEGIS_POSTGRES_PORT", "5433")
    return monkeypatch


@pytest.mark.parametrize(
    ("command", "missing"),
    [("migrate", "AEGIS_DB_OWNER_PASSWORD"), ("bootstrap", "AEGIS_POSTGRES_USER")],
)
def test_missing_credentials_fail_cleanly_before_connecting(
    environment: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    missing: str,
) -> None:
    assert main(["db", command]) == 1

    error = capsys.readouterr().err
    assert error.startswith("error: ")
    assert missing in error
    assert "Traceback" not in error


def test_unknown_aegis_variables_are_rejected(
    environment: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    environment.setenv("AEGIS_DB_OWNER_PASWORD", "y" * 24)

    assert main(["db", "migrate"]) == 1
    assert "AEGIS_DB_OWNER_PASWORD is not a known AEGIS variable" in capsys.readouterr().err


def test_issuing_without_a_pepper_fails_before_connecting(
    environment: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    environment.setenv("AEGIS_DB_OWNER_PASSWORD", "o" * 24)

    assert main(["credential", "issue", "alice"]) == 1

    assert "AEGIS_TOKEN_PEPPER is required" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["identity", "create", "robot", "--kind", "system"],
        ["identity", "create", "alice", "--kind", "human", "--role", "superuser"],
        ["credential", "issue", "alice", "--days", "thirty"],
        ["credential", "revoke", "not-a-uuid"],
        ["role", "grant", "alice", "root"],
    ],
)
def test_invalid_arguments_are_rejected_by_the_parser(
    environment: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(argv)

    assert excinfo.value.code == 2
    assert "invalid" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("model", "message"),
    [
        (None, "set AEGIS_OLLAMA_MODEL"),
        ("registry.example.com/team/model:1", "must be a local model name"),
    ],
)
def test_pulling_a_model_fails_cleanly_before_connecting(
    environment: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    model: str | None,
    message: str,
) -> None:
    if model is not None:
        environment.setenv("AEGIS_OLLAMA_MODEL", model)

    assert main(["model", "pull"]) == 1

    error = capsys.readouterr().err
    assert error.startswith("error: ")
    assert message in error
    assert "Traceback" not in error


class StubRuntime:
    workspace_exists = False
    status = RuntimeStatus(True, "ok", "0.1.7")

    def __init__(self, settings: OpenShellSettings) -> None:
        self.settings = settings

    def ensure_workspace(self) -> bool:
        return not self.workspace_exists

    def check(self) -> RuntimeStatus:
        return self.status


def test_openshell_init_refuses_the_default_workspace_before_running_anything(
    environment: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def never(settings: OpenShellSettings) -> None:
        raise AssertionError("the runtime must not be built from invalid settings")

    environment.setenv("AEGIS_OPENSHELL_WORKSPACE", "default")
    environment.setattr(cli, "OpenShellRuntime", never)

    assert main(["openshell", "init"]) == 1

    assert "must not be the default workspace" in capsys.readouterr().err


@pytest.mark.parametrize(("exists", "action"), [(False, "created"), (True, "already exists")])
def test_openshell_init_creates_the_workspace_and_checks_the_runtime(
    environment: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    exists: bool,
    action: str,
) -> None:
    environment.setattr(cli, "OpenShellRuntime", StubRuntime)
    environment.setattr(StubRuntime, "workspace_exists", exists)

    assert main(["openshell", "init"]) == 0

    assert capsys.readouterr().out == (
        f"workspace aegis {action} on gateway openshell; OpenShell 0.1.7 is ready\n"
    )


def test_openshell_init_fails_when_the_runtime_is_unusable(
    environment: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    environment.setattr(cli, "OpenShellRuntime", StubRuntime)
    environment.setattr(StubRuntime, "status", RuntimeStatus(False, "global_policy_active"))

    assert main(["openshell", "init"]) == 1

    assert "OpenShell is not usable: global_policy_active" in capsys.readouterr().err

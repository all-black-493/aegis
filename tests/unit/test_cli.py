import os

import pytest

from aegis.apps.cli.__main__ import main


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

import re
import stat
from pathlib import Path

import pytest

from aegis.config.envfile import PLACEHOLDER, parse_env_file
from aegis.config.envtool import EnvToolError, create_env_file, main, upgrade_env_file

TEMPLATE = f"""# a comment that mentions KEY={PLACEHOLDER}
AEGIS_ENV=development
AEGIS_POSTGRES_USER=aegis
AEGIS_POSTGRES_DB=aegis
AEGIS_POSTGRES_PASSWORD={PLACEHOLDER}
AEGIS_POSTGRES_PORT=5433
"""
OLD_ENV = (
    "AEGIS_POSTGRES_USER=aegis\n"
    "AEGIS_POSTGRES_DB=aegis\n"
    f"AEGIS_POSTGRES_PASSWORD={'a' * 48}\n"
    "AEGIS_POSTGRES_PORT=5433\n"
)
HEX64 = re.compile(r"[0-9a-f]{64}")


@pytest.fixture
def template(tmp_path: Path) -> Path:
    path = tmp_path / ".env.example"
    path.write_text(TEMPLATE)
    return path


def write_env(tmp_path: Path, text: str, mode: int = 0o600, name: str = ".env") -> Path:
    path = tmp_path / name
    path.write_text(text)
    path.chmod(mode)
    return path


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_create_generates_every_placeholder_with_mode_600(tmp_path: Path, template: Path) -> None:
    target = tmp_path / ".env"

    result = create_env_file(template, target)

    assert result.created
    assert result.generated == ("AEGIS_POSTGRES_PASSWORD",)
    values = parse_env_file(target)
    assert HEX64.fullmatch(values["AEGIS_POSTGRES_PASSWORD"])
    assert values["AEGIS_ENV"] == "development"
    assert PLACEHOLDER not in values.values()
    assert target.read_text().startswith(f"# a comment that mentions KEY={PLACEHOLDER}\n")
    assert mode_of(target) == 0o600


def test_create_never_overwrites_an_existing_file(tmp_path: Path, template: Path) -> None:
    target = write_env(tmp_path, "AEGIS_ENV=test\n")

    result = create_env_file(template, target)

    assert not result.created
    assert target.read_text() == "AEGIS_ENV=test\n"


def test_create_does_not_follow_a_dangling_symlink(tmp_path: Path, template: Path) -> None:
    victim = tmp_path / "victim"
    link = tmp_path / ".env"
    link.symlink_to(victim)

    assert not create_env_file(template, link).created
    assert not victim.exists()


def test_each_file_gets_its_own_secrets(tmp_path: Path, template: Path) -> None:
    first, second = tmp_path / "first.env", tmp_path / "second.env"
    create_env_file(template, first)
    create_env_file(template, second)

    key = "AEGIS_POSTGRES_PASSWORD"
    assert parse_env_file(first)[key] != parse_env_file(second)[key]


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("AEGIS_POSTGRES_PASSWORD=literal-password-value", "must use the placeholder"),
        (f"AEGIS_ENV={PLACEHOLDER}", "must not use the placeholder"),
        ("AEGIS_UNKNOWN=1", "not a known AEGIS variable"),
    ],
)
def test_invalid_templates_are_refused_without_writing(
    tmp_path: Path, line: str, message: str
) -> None:
    template = tmp_path / ".env.example"
    template.write_text(line + "\n")

    with pytest.raises(EnvToolError, match=message) as excinfo:
        create_env_file(template, tmp_path / ".env")

    assert not (tmp_path / ".env").exists()
    assert "literal-password-value" not in str(excinfo.value)


def test_upgrade_appends_only_missing_variables(tmp_path: Path, template: Path) -> None:
    target = write_env(tmp_path, OLD_ENV)

    result = upgrade_env_file(template, target)

    assert result.added == ("AEGIS_ENV",)
    assert result.generated == ()
    assert target.read_text() == OLD_ENV + "AEGIS_ENV=development\n"
    assert mode_of(target) == 0o600


def test_upgrade_generates_missing_secrets(tmp_path: Path, template: Path) -> None:
    target = write_env(tmp_path, "AEGIS_ENV=development\nAEGIS_POSTGRES_PORT=5433\n")

    result = upgrade_env_file(template, target)

    assert result.generated == ("AEGIS_POSTGRES_PASSWORD",)
    assert HEX64.fullmatch(parse_env_file(target)["AEGIS_POSTGRES_PASSWORD"])


def test_upgrade_is_safe_to_rerun(tmp_path: Path, template: Path) -> None:
    target = write_env(tmp_path, OLD_ENV)
    upgrade_env_file(template, target)
    after_first = target.read_bytes()

    result = upgrade_env_file(template, target)

    assert result.added == ()
    assert target.read_bytes() == after_first


def test_upgrade_handles_a_missing_final_newline(tmp_path: Path, template: Path) -> None:
    target = write_env(tmp_path, OLD_ENV.rstrip("\n"))

    upgrade_env_file(template, target)

    assert target.read_text() == OLD_ENV + "AEGIS_ENV=development\n"


def test_upgrade_reports_unknown_aegis_variables_and_keeps_them(
    tmp_path: Path, template: Path
) -> None:
    original = OLD_ENV + "AEGIS_LEGACY=1\nCOMPOSE_PROJECT_NAME=second\n"
    target = write_env(tmp_path, original)

    result = upgrade_env_file(template, target)

    assert result.unknown == ("AEGIS_LEGACY",)
    assert target.read_text().startswith(original)


def test_upgrade_requires_an_existing_env_file(tmp_path: Path, template: Path) -> None:
    with pytest.raises(EnvToolError, match="make setup"):
        upgrade_env_file(template, tmp_path / ".env")

    assert not (tmp_path / ".env").exists()


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o666])
def test_upgrade_refuses_files_other_users_can_access(
    tmp_path: Path, template: Path, mode: int
) -> None:
    target = write_env(tmp_path, OLD_ENV, mode)

    with pytest.raises(EnvToolError, match="chmod 600"):
        upgrade_env_file(template, target)

    assert target.read_text() == OLD_ENV


def test_upgrade_refuses_an_unparseable_file_without_echoing_it(
    tmp_path: Path, template: Path
) -> None:
    original = "AEGIS_POSTGRES_PASSWORD=has space secret\n"
    target = write_env(tmp_path, original)

    with pytest.raises(EnvToolError, match="line 1") as excinfo:
        upgrade_env_file(template, target)

    assert target.read_text() == original
    assert "has space secret" not in str(excinfo.value)


def test_upgrade_refuses_a_symlinked_env_file(tmp_path: Path, template: Path) -> None:
    real = write_env(tmp_path, OLD_ENV, name="real.env")
    (tmp_path / ".env").symlink_to(real)

    with pytest.raises(EnvToolError, match="symlink"):
        upgrade_env_file(template, tmp_path / ".env")

    assert real.read_text() == OLD_ENV


def test_cli_reports_names_but_never_values(
    tmp_path: Path,
    template: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)

    assert main(["create"]) == 0
    created = capsys.readouterr().out
    write_env(tmp_path, "AEGIS_ENV=development\n")
    assert main(["upgrade"]) == 0
    upgraded = capsys.readouterr().out

    password = parse_env_file(tmp_path / ".env")["AEGIS_POSTGRES_PASSWORD"]
    assert "1 generated secret" in created
    assert "Generated secrets for: AEGIS_POSTGRES_PASSWORD" in upgraded
    assert password not in created + upgraded


def test_cli_reports_errors_without_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)

    assert main(["upgrade"]) == 1
    error = capsys.readouterr().err
    assert error.startswith("error: ")
    assert "Traceback" not in error

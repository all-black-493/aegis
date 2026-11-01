import re
import shutil
import stat
import subprocess
from pathlib import Path

from aegis.config.envfile import PLACEHOLDER, parse_env_file, parse_env_text

ROOT = Path(__file__).resolve().parents[2]
PASSWORD_KEY = "AEGIS_POSTGRES_PASSWORD"
PHASE_0_ENV = (
    "AEGIS_POSTGRES_USER=aegis\n"
    "AEGIS_POSTGRES_DB=aegis\n"
    f"{PASSWORD_KEY}={'b' * 48}\n"
    "AEGIS_POSTGRES_PORT=5433\n"
)


def _make(workdir: Path, target: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["make", "--no-print-directory", "-f", str(ROOT / "Makefile"), target],
        cwd=workdir,
        capture_output=True,
        text=True,
        check=False,
    )


def _workdir(tmp_path: Path, name: str) -> Path:
    workdir = tmp_path / name
    workdir.mkdir()
    shutil.copy(ROOT / ".env.example", workdir)
    return workdir


def test_setup_creates_env_with_generated_secrets(tmp_path: Path) -> None:
    workdir = _workdir(tmp_path, "fresh")

    result = _make(workdir, "env-file")

    assert result.returncode == 0, result.stderr
    env_path = workdir / ".env"
    values = parse_env_file(env_path)
    template = parse_env_file(workdir / ".env.example")
    secrets = [name for name, value in template.items() if value == PLACEHOLDER]
    assert PASSWORD_KEY in secrets
    for name in secrets:
        assert re.fullmatch(r"[0-9a-f]{64}", values[name])
        assert values[name] not in result.stdout + result.stderr
    assert len({values[name] for name in secrets}) == len(secrets)
    assert {k: v for k, v in values.items() if k not in secrets} == {
        k: v for k, v in template.items() if k not in secrets
    }
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600


def test_each_environment_gets_its_own_password(tmp_path: Path) -> None:
    passwords = set()
    for name in ("first", "second"):
        workdir = _workdir(tmp_path, name)
        assert _make(workdir, "env-file").returncode == 0
        passwords.add(parse_env_file(workdir / ".env")[PASSWORD_KEY])

    assert len(passwords) == 2


def test_setup_never_modifies_an_existing_env(tmp_path: Path) -> None:
    workdir = _workdir(tmp_path, "existing")
    env_path = workdir / ".env"
    env_path.write_text(f"{PASSWORD_KEY}=keep-this-value\n")
    original = env_path.read_bytes()

    result = _make(workdir, "env-file")

    assert result.returncode == 0, result.stderr
    assert env_path.read_bytes() == original
    assert "leaving it unchanged" in result.stdout


def test_setup_refuses_a_template_with_a_literal_secret(tmp_path: Path) -> None:
    workdir = tmp_path / "broken"
    workdir.mkdir()
    (workdir / ".env.example").write_text(f"{PASSWORD_KEY}=literal-value\n")

    result = _make(workdir, "env-file")

    assert result.returncode != 0
    assert not (workdir / ".env").exists()
    assert "literal-value" not in result.stdout + result.stderr


def test_env_upgrade_adds_new_variables_to_a_phase_0_env(tmp_path: Path) -> None:
    workdir = _workdir(tmp_path, "upgrade")
    env_path = workdir / ".env"
    env_path.write_text(PHASE_0_ENV)
    env_path.chmod(0o600)

    first = _make(workdir, "env-upgrade")
    after_first = env_path.read_bytes()
    second = _make(workdir, "env-upgrade")

    assert first.returncode == 0, first.stderr
    template = parse_env_file(workdir / ".env.example")
    missing = [name for name in template if name not in parse_env_text(PHASE_0_ENV)]
    assert f"Added to .env: {', '.join(missing)}" in first.stdout
    text = env_path.read_text()
    assert text.startswith(PHASE_0_ENV)
    appended = dict(line.split("=", 1) for line in text[len(PHASE_0_ENV) :].splitlines())
    assert list(appended) == missing
    for name in missing:
        if template[name] == PLACEHOLDER:
            assert re.fullmatch(r"[0-9a-f]{64}", appended[name])
            assert appended[name] not in first.stdout + first.stderr
        else:
            assert appended[name] == template[name]
    assert second.returncode == 0, second.stderr
    assert "No changes" in second.stdout
    assert env_path.read_bytes() == after_first
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600


def test_env_upgrade_requires_an_existing_env(tmp_path: Path) -> None:
    workdir = _workdir(tmp_path, "missing")

    result = _make(workdir, "env-upgrade")

    assert result.returncode != 0
    assert "make setup" in result.stderr
    assert not (workdir / ".env").exists()

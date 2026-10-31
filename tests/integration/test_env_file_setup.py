import re
import shutil
import stat
import subprocess
from pathlib import Path

from aegis.doctor.envfile import parse_env_file

ROOT = Path(__file__).resolve().parents[2]
PASSWORD_KEY = "AEGIS_POSTGRES_PASSWORD"


def _make_env_file(workdir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["make", "--no-print-directory", "-f", str(ROOT / "Makefile"), "env-file"],
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


def test_creates_env_with_generated_password(tmp_path: Path) -> None:
    workdir = _workdir(tmp_path, "fresh")

    result = _make_env_file(workdir)

    assert result.returncode == 0, result.stderr
    env_path = workdir / ".env"
    values = parse_env_file(env_path)
    template = parse_env_file(workdir / ".env.example")
    password = values.pop(PASSWORD_KEY)
    template.pop(PASSWORD_KEY)
    assert re.fullmatch(r"[0-9a-f]{48}", password)
    assert values == template
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600
    assert password not in result.stdout + result.stderr


def test_each_environment_gets_its_own_password(tmp_path: Path) -> None:
    passwords = set()
    for name in ("first", "second"):
        workdir = _workdir(tmp_path, name)
        assert _make_env_file(workdir).returncode == 0
        passwords.add(parse_env_file(workdir / ".env")[PASSWORD_KEY])

    assert len(passwords) == 2


def test_existing_env_is_never_modified(tmp_path: Path) -> None:
    workdir = _workdir(tmp_path, "existing")
    env_path = workdir / ".env"
    env_path.write_text(f"{PASSWORD_KEY}=keep-this-value\n")
    original = env_path.read_bytes()

    result = _make_env_file(workdir)

    assert result.returncode == 0, result.stderr
    assert env_path.read_bytes() == original
    assert "leaving it unchanged" in result.stdout


def test_template_without_placeholder_is_refused(tmp_path: Path) -> None:
    workdir = tmp_path / "broken"
    workdir.mkdir()
    (workdir / ".env.example").write_text("AEGIS_POSTGRES_USER=aegis\n")

    result = _make_env_file(workdir)

    assert result.returncode != 0
    assert not (workdir / ".env").exists()

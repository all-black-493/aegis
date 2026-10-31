import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _ignored(path: str) -> bool:
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", path], cwd=ROOT, check=False
    )
    assert result.returncode in (0, 1), "git check-ignore failed; is this a git checkout?"
    return result.returncode == 0


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        ".env.local",
        ".venv/",
        "src/aegis/__pycache__/module.cpython-313.pyc",
        ".mypy_cache/",
        "models/model.gguf",
        "backup.dump",
    ],
)
def test_secret_and_generated_paths_are_ignored(path: str) -> None:
    assert _ignored(path)


def test_env_template_is_tracked() -> None:
    assert not _ignored(".env.example")

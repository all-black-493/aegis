from pathlib import Path

import pytest

from aegis.doctor.envfile import EnvFileError, parse_env_file

SECRET = "s3cr3t-value-that-must-not-leak"


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / ".env"
    path.write_text(text)
    return path


def test_parses_assignments_comments_and_quotes(tmp_path: Path) -> None:
    path = _write(tmp_path, "# comment\n\nA=1\nB='two words'\nC=\"x\"\nD=\n")

    assert parse_env_file(path) == {"A": "1", "B": "two words", "C": "x", "D": ""}


@pytest.mark.parametrize(
    "line",
    [
        SECRET,
        f"BAD KEY={SECRET}",
        f"export A={SECRET}",
        f"A={SECRET} # inline comment",
        f"A='{SECRET}",
    ],
)
def test_rejects_malformed_lines_without_echoing_values(tmp_path: Path, line: str) -> None:
    with pytest.raises(EnvFileError) as excinfo:
        parse_env_file(_write(tmp_path, f"OK=1\n{line}\n"))

    assert "line 2" in str(excinfo.value)
    assert SECRET not in str(excinfo.value)


def test_rejects_duplicate_keys(tmp_path: Path) -> None:
    with pytest.raises(EnvFileError, match="duplicate key A"):
        parse_env_file(_write(tmp_path, "A=1\nA=2\n"))

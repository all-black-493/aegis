import socket
import subprocess
import sys
from pathlib import Path

import pytest

import aegis

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_runs_on_python_3_13() -> None:
    assert sys.version_info[:2] == (3, 13)


def test_package_is_imported_from_src_layout() -> None:
    assert Path(aegis.__file__).resolve().parent == REPO_ROOT / "src" / "aegis"


def test_hermetic_guard_blocks_network_access() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
        pytest.raises(AssertionError, match="must not open network connections"),
    ):
        sock.connect(("127.0.0.1", 9))


def test_hermetic_guard_blocks_subprocesses() -> None:
    with pytest.raises(AssertionError, match="start subprocesses"):
        subprocess.run(["true"], check=False)

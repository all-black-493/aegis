import socket
import subprocess
from typing import NoReturn

import pytest


def _refuse(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError(
        "unit tests must not open network connections or start subprocesses; "
        "inject a fake or move the test to tests/integration"
    )


@pytest.fixture(autouse=True)
def _forbid_external_access(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket.socket, "connect", _refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", _refuse)
    monkeypatch.setattr(socket.socket, "bind", _refuse)
    monkeypatch.setattr(subprocess, "Popen", _refuse)

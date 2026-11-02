import socket
import subprocess
import sys
import time
from collections.abc import Callable
from uuid import uuid4

import httpx2
import pytest


class Process:
    def __init__(self, module: str, environ: dict[str, str]) -> None:
        self.popen = subprocess.Popen(
            [sys.executable, "-m", module],
            env=environ,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.output = ""

    def stop(self, sig: int) -> int:
        if self.popen.poll() is None:
            self.popen.send_signal(sig)
        self.output, _ = self.popen.communicate(timeout=30)
        return self.popen.returncode


def cli(environ: dict[str, str], *args: str) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "aegis.apps.cli", *args, "--database", environ["AEGIS_POSTGRES_DB"]],
        env=environ,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def identity(environ: dict[str, str], role: str) -> str:
    name = f"e2e-{role}-{uuid4().hex[:8]}"
    cli(environ, "identity", "create", name, "--kind", "human", "--role", role)
    return cli(environ, "credential", "issue", name)


def wait_for(condition: Callable[[], bool], timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            pytest.fail(f"timed out waiting for {what}")
        time.sleep(0.1)


def live(base: str) -> bool:
    try:
        return httpx2.get(f"{base}/health/live").status_code == 200
    except httpx2.TransportError:
        return False


def unused_port() -> int:
    # A loopback port that was free a moment ago: for servers to bind, or as a closed port.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port

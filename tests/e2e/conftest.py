import os
import socket
from collections.abc import Iterator

import pytest

from tests.fixtures.processes import Process


@pytest.fixture
def environ(test_database: str) -> dict[str, str]:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return {
        **os.environ,
        "AEGIS_ENV": "production",
        "AEGIS_POSTGRES_DB": test_database,
        "AEGIS_API_PORT": str(port),
        "AEGIS_WORKER_POLL_SECONDS": "1",
        "AEGIS_WORKER_LEASE_SECONDS": "10",
        "AEGIS_WORKER_HEARTBEAT_SECONDS": "1",
    }


@pytest.fixture
def processes() -> Iterator[list[Process]]:
    started: list[Process] = []
    yield started
    for process in started:
        if process.popen.poll() is None:
            process.popen.kill()
            process.popen.communicate(timeout=30)

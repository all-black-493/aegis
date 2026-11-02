import os
from collections.abc import Iterator

import pytest

from tests.fixtures.processes import Process, unused_port


@pytest.fixture
def environ(test_database: str) -> dict[str, str]:
    port = unused_port()
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

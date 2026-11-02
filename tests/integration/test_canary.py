import http.client
import socket

import pytest

from aegis.runtime.contract import RuntimeUnavailableError
from aegis.runtime.probes.canary import Canary
from tests.fixtures.processes import unused_port


def _request(port: int, method: str, path: str) -> tuple[int, str]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        return response.status, response.read().decode()
    finally:
        connection.close()


def test_the_canary_answers_and_records_every_request_on_every_port() -> None:
    first, second = unused_port(), unused_port()

    with Canary("127.0.0.1", (first, second)) as canary:
        assert _request(first, "GET", "/probe/n1/get") == (200, "aegis-canary /probe/n1/get\n")
        _request(second, "POST", "/probe/n1/post")
        hits = canary.hits()

    assert hits == {(first, "/probe/n1/get"), (second, "/probe/n1/post")}
    with socket.socket() as probe, pytest.raises(ConnectionRefusedError):
        probe.connect(("127.0.0.1", first))


def test_a_busy_port_makes_the_canary_unavailable_and_leaves_nothing_listening() -> None:
    free = unused_port()
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        taken = busy.getsockname()[1]

        with pytest.raises(RuntimeUnavailableError) as refused, Canary("127.0.0.1", (free, taken)):
            pytest.fail("the canary must not start")

    assert refused.value.code == "canary_unavailable"
    with socket.socket() as probe, pytest.raises(ConnectionRefusedError):
        probe.connect(("127.0.0.1", free))

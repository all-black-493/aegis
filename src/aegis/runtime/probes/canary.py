import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from typing import Self

from aegis.runtime.contract import RuntimeUnavailableError
from aegis.runtime.probes.catalog import CANARY_REPLY

MAX_HITS = 256
MAX_PATH_CHARS = 256


class Canary:
    # Listens on the host while the probes run and records every request that reaches it, so
    # AEGIS can see for itself whether a refused connection or request got through (ADR-0018).
    def __init__(self, host: str, ports: tuple[int, ...]) -> None:
        self._host = host
        self._ports = ports
        self._hits: set[tuple[int, str]] = set()
        self._lock = threading.Lock()
        self._servers: list[ThreadingHTTPServer] = []

    def __enter__(self) -> Self:
        try:
            for port in self._ports:
                self._servers.append(_Server((self._host, port), self))
        except OSError:
            # None of these is serving yet, so closing their sockets is enough; shutdown() would
            # wait forever for a serve loop that never started.
            for server in self._servers:
                server.server_close()
            self._servers.clear()
            raise RuntimeUnavailableError(
                "the canary could not listen", code="canary_unavailable"
            ) from None
        for server in self._servers:
            threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        for server in self._servers:
            server.shutdown()
            server.server_close()
        self._servers.clear()

    def hits(self) -> frozenset[tuple[int, str]]:
        with self._lock:
            return frozenset(self._hits)

    def record(self, port: int, path: str) -> None:
        with self._lock:
            if len(self._hits) < MAX_HITS:
                self._hits.add((port, path[:MAX_PATH_CHARS]))


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], canary: Canary) -> None:
        super().__init__(address, _Handler)
        self.canary = canary


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, *_args: object) -> None:
        pass

    def _answer(self) -> None:
        self.server.canary.record(self.server.server_address[1], self.path)
        body = f"{CANARY_REPLY} {self.path[:MAX_PATH_CHARS]}\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _answer

import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

MODEL = "qwen3:0.6b"
DIGEST = "c" * 64


def ndjson_line(**chunk: Any) -> bytes:
    return json.dumps(chunk).encode() + b"\n"


def content_line(text: str) -> bytes:
    return ndjson_line(model=MODEL, message={"role": "assistant", "content": text}, done=False)


def done_line(reason: str = "stop") -> bytes:
    return ndjson_line(
        model=MODEL,
        message={"role": "assistant", "content": ""},
        done=True,
        done_reason=reason,
        prompt_eval_count=12,
        eval_count=3,
    )


@dataclass
class FakeOllama:
    # Speaks the parts of the Ollama 0.34.2 API that the adapter uses (ADR-0014).
    capabilities: list[str] = field(default_factory=lambda: ["completion", "thinking"])
    models: list[str] = field(default_factory=lambda: [MODEL])
    digest: str = DIGEST
    version: object = "0.34.2"
    show_extra: dict[str, Any] = field(default_factory=dict)
    tags_extra: dict[str, Any] = field(default_factory=dict)
    status: dict[str, int] = field(default_factory=dict)
    lines: list[bytes] = field(default_factory=lambda: [content_line("Red."), done_line()])
    pull_lines: list[bytes] = field(
        default_factory=lambda: [
            ndjson_line(status="pulling manifest"),
            ndjson_line(status="pulling 7f4030143c1c", total=100, completed=50),
            ndjson_line(status="pulling 7f4030143c1c", total=100, completed=100),
            ndjson_line(status="verifying sha256 digest"),
            ndjson_line(status="success"),
        ]
    )
    delay: float = 0
    requests: list[dict[str, Any]] = field(default_factory=list)
    # Every request as received: request line, headers and body.
    seen: list[str] = field(default_factory=list)
    disconnected: threading.Event = field(default_factory=threading.Event)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: "_Server"

    def log_message(self, *_args: object) -> None:
        pass

    def do_GET(self) -> None:
        fake = self.server.fake
        self._record(b"")
        if self.path == "/api/version":
            self._json(200, {"version": fake.version})
        elif self.path == "/api/tags":
            models = [
                {"name": n, "model": n, "digest": fake.digest, "size": 1, **fake.tags_extra}
                for n in fake.models
            ]
            self._json(200, {"models": models})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        fake = self.server.fake
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        self._record(raw)
        body = json.loads(raw)
        if self.path == "/api/show":
            if body["model"] not in fake.models:
                self._json(404, {"error": f"model '{body['model']}' not found"})
                return
            show = {"capabilities": fake.capabilities, "details": {}, **fake.show_extra}
            self._json(200, show)
            return
        fake.requests.append(body)
        lines = fake.pull_lines if self.path == "/api/pull" else fake.lines
        if fake.status.get(self.path, 200) != 200:
            self._json(fake.status[self.path], {"error": "refused"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            for line in lines:
                if fake.delay:
                    time.sleep(fake.delay)
                self.wfile.write(f"{len(line):x}\r\n".encode() + line + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
        except OSError:
            fake.disconnected.set()

    def _record(self, body: bytes) -> None:
        self.server.fake.seen.append(
            f"{self.requestline}\n{self.headers}\n{body.decode(errors='replace')}"
        )

    def _json(self, status: int, value: dict[str, Any]) -> None:
        if self.path in self.server.fake.status and self.path != "/api/chat":
            status = self.server.fake.status[self.path]
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, fake: FakeOllama) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.fake = fake

    def handle_error(self, request: object, client_address: object) -> None:
        # The adapter closes connections early on purpose; resets are expected, not failures.
        pass


@contextmanager
def serve(fake: FakeOllama) -> Iterator[int]:
    server = _Server(fake)
    thread = threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()

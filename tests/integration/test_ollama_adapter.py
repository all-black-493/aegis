import json
import logging
import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from aegis.config.settings import OllamaSettings
from aegis.integrations.ollama.provider import MAX_LINE_BYTES, MAX_STREAM_BYTES, OllamaProvider
from aegis.model_providers.contract import (
    MAX_OUTPUT_BYTES,
    FinishReason,
    GenerationRequest,
    GenerationStoppedError,
    ModelProviderError,
    ModelUnavailableError,
    ProviderProtocolError,
    ProviderUnavailableError,
)

MODEL = "qwen3:0.6b"
DIGEST = "c" * 64
PROMPT_MARKER = "PROMPT-MARKER-6f1d"
OUTPUT_MARKER = "OUTPUT-MARKER-92ab"


def _line(**chunk: Any) -> bytes:
    return json.dumps(chunk).encode() + b"\n"


def _content(text: str) -> bytes:
    return _line(model=MODEL, message={"role": "assistant", "content": text}, done=False)


def _done(reason: str = "stop") -> bytes:
    return _line(
        model=MODEL,
        message={"role": "assistant", "content": ""},
        done=True,
        done_reason=reason,
        prompt_eval_count=12,
        eval_count=3,
    )


@dataclass
class FakeOllama:
    capabilities: list[str] = field(default_factory=lambda: ["completion", "thinking"])
    models: list[str] = field(default_factory=lambda: [MODEL])
    digest: str = DIGEST
    show_extra: dict[str, Any] = field(default_factory=dict)
    tags_extra: dict[str, Any] = field(default_factory=dict)
    status: dict[str, int] = field(default_factory=dict)
    lines: list[bytes] = field(default_factory=lambda: [_content("Red."), _done()])
    delay: float = 0
    requests: list[dict[str, Any]] = field(default_factory=list)
    disconnected: threading.Event = field(default_factory=threading.Event)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: "_Server"

    def log_message(self, *_args: object) -> None:
        pass

    def do_GET(self) -> None:
        fake = self.server.fake
        if self.path == "/api/version":
            self._json(200, {"version": "0.34.2"})
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
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/api/show":
            if body["model"] not in fake.models:
                self._json(404, {"error": f"model '{body['model']}' not found"})
                return
            show = {"capabilities": fake.capabilities, "details": {}, **fake.show_extra}
            self._json(200, show)
            return
        fake.requests.append(body)
        if fake.status.get(self.path, 200) != 200:
            self._json(fake.status[self.path], {"error": "refused"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            for line in fake.lines:
                if fake.delay:
                    time.sleep(fake.delay)
                self.wfile.write(f"{len(line):x}\r\n".encode() + line + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
        except OSError:
            fake.disconnected.set()

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


@pytest.fixture
def fake() -> FakeOllama:
    return FakeOllama()


@pytest.fixture
def port(fake: FakeOllama) -> Iterator[int]:
    server = _Server(fake)
    thread = threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def _provider(port: int, *, digest: str | None = None, timeout: float = 5) -> OllamaProvider:
    return OllamaProvider(OllamaSettings(port, MODEL, digest), timeout_seconds=timeout)


def _request(prompt: str = "Name a colour.", tokens: int = 32) -> GenerationRequest:
    return GenerationRequest(prompt, tokens)


def _never() -> bool:
    return False


def _closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed: int = probe.getsockname()[1]
    return closed


def test_check_reports_the_local_model_and_its_identity(port: int) -> None:
    status = _provider(port, digest=DIGEST).check()

    assert (status.healthy, status.detail) == (True, "ok")
    assert status.identity is not None
    assert (status.identity.model, status.identity.digest) == (MODEL, DIGEST)
    assert status.identity.runtime_version == "0.34.2"


@pytest.mark.parametrize(
    ("change", "detail"),
    [
        ({"show_extra": {"remote_host": "https://ollama.com:443"}}, "remote_model"),
        ({"show_extra": {"remote_model": "gpt-oss:120b"}}, "remote_model"),
        ({"tags_extra": {"remote_host": "https://ollama.com:443"}}, "remote_model"),
        ({"capabilities": ["embedding"]}, "not_generative"),
        ({"models": ["smollm2:135m"]}, "model_missing"),
        ({"digest": "not-a-digest"}, "protocol_error"),
        ({"status": {"/api/version": 500}}, "unavailable"),
    ],
)
def test_check_explains_why_a_model_cannot_be_used(
    fake: FakeOllama, port: int, change: dict[str, Any], detail: str
) -> None:
    for name, value in change.items():
        setattr(fake, name, value)

    status = _provider(port).check()

    assert (status.healthy, status.detail, status.identity) == (False, detail, None)


def test_a_pinned_digest_must_match_and_a_missing_server_is_unreachable(port: int) -> None:
    assert _provider(port, digest="d" * 64).check().detail == "digest_mismatch"
    assert _provider(_closed_port()).check().detail == "unreachable"


def test_generation_streams_text_with_counts_and_identity(fake: FakeOllama, port: int) -> None:
    fake.lines = [_content("Red, "), _content("green."), _done()]

    generation = _provider(port).generate(_request(), _never)

    assert (generation.text, generation.finish_reason) == ("Red, green.", FinishReason.STOP)
    assert (generation.prompt_tokens, generation.output_tokens) == (12, 3)
    assert (generation.identity.digest, generation.identity.runtime_version) == (DIGEST, "0.34.2")


@pytest.mark.parametrize("thinking", [True, False])
def test_requests_carry_no_tools_format_or_system_prompt(
    fake: FakeOllama, port: int, thinking: bool
) -> None:
    fake.capabilities = ["completion", "thinking"] if thinking else ["completion"]

    _provider(port).generate(GenerationRequest("Say hi.", 16, temperature=0.0, seed=7), _never)

    [body] = fake.requests
    expected = {"model", "messages", "stream", "options"} | ({"think"} if thinking else set())
    assert set(body) == expected
    assert body["messages"] == [{"role": "user", "content": "Say hi."}]
    assert body["options"] == {"temperature": 0.0, "seed": 7, "num_predict": 16}
    assert body.get("think", False) is False


def test_output_beyond_the_limit_is_cut_and_the_stream_closed(fake: FakeOllama, port: int) -> None:
    fake.lines = [_content("x" * 1000) for _ in range(2000)] + [_done()]

    generation = _provider(port).generate(_request(), _never)

    assert generation.finish_reason is FinishReason.LIMIT
    assert len(generation.text.encode()) <= MAX_OUTPUT_BYTES
    assert fake.disconnected.wait(5)


@pytest.mark.parametrize(
    ("lines", "error", "code"),
    [
        (
            [_line(message={"role": "assistant", "content": "", "tool_calls": [{}]}, done=False)],
            ProviderProtocolError,
            "tool_call",
        ),
        (
            [_line(message={"content": "x"}, remote_host="https://ollama.com", done=False)],
            ModelUnavailableError,
            "remote_model",
        ),
        ([b"{not json\n"], ProviderProtocolError, "protocol_error"),
        (
            [b'{"message": {"content": "' + b"y" * MAX_LINE_BYTES + b'"}}\n'],
            ProviderProtocolError,
            "protocol_error",
        ),
        ([_content("half an answer")], ProviderUnavailableError, "unavailable"),
        (
            [_line(error="model runner has unexpectedly stopped")],
            ProviderUnavailableError,
            "unavailable",
        ),
        ([_done("unload")], ProviderProtocolError, "protocol_error"),
    ],
)
def test_unsafe_or_broken_streams_are_refused(
    fake: FakeOllama, port: int, lines: list[bytes], error: type[ModelProviderError], code: str
) -> None:
    fake.lines = lines

    with pytest.raises(error) as refused:
        _provider(port).generate(_request(), _never)

    assert refused.value.code == code


def test_a_model_that_only_thinks_cannot_stream_forever(fake: FakeOllama, port: int) -> None:
    thought = _line(message={"role": "assistant", "content": "", "thinking": "z" * 60_000})
    fake.lines = [thought] * (MAX_STREAM_BYTES // 60_000 + 2) + [_done()]

    with pytest.raises(ProviderProtocolError):
        _provider(port).generate(_request(), _never)


@pytest.mark.parametrize(
    ("status", "error", "code"),
    [
        (500, ProviderUnavailableError, "unavailable"),
        (503, ProviderUnavailableError, "unavailable"),
        (400, ProviderProtocolError, "protocol_error"),
        (404, ModelUnavailableError, "model_missing"),
    ],
)
def test_http_errors_map_to_retry_classes(
    fake: FakeOllama, port: int, status: int, error: type[ModelProviderError], code: str
) -> None:
    fake.status = {"/api/chat": status}

    with pytest.raises(error) as refused:
        _provider(port).generate(_request(), _never)

    assert refused.value.code == code
    assert refused.value.retryable is (status >= 500)


def test_a_silent_server_times_out_as_retryable(fake: FakeOllama, port: int) -> None:
    fake.delay = 3
    started = time.monotonic()

    with pytest.raises(ProviderUnavailableError) as refused:
        _provider(port, timeout=0.5).generate(_request(), _never)

    assert refused.value.retryable
    assert time.monotonic() - started < 2.5


def test_an_unreachable_server_is_retryable() -> None:
    with pytest.raises(ProviderUnavailableError) as refused:
        _provider(_closed_port()).generate(_request(), _never)

    assert refused.value.retryable


def test_a_stop_request_ends_generation_and_closes_the_stream(fake: FakeOllama, port: int) -> None:
    fake.lines = [_content("tick ") for _ in range(200)] + [_done()]
    fake.delay = 0.02
    checks = 0

    def stop_after_three() -> bool:
        nonlocal checks
        checks += 1
        return checks > 3

    started = time.monotonic()
    with pytest.raises(GenerationStoppedError):
        _provider(port).generate(_request(), stop_after_three)

    assert time.monotonic() - started < 1
    assert fake.disconnected.wait(5)


def test_prompts_and_outputs_never_reach_logs_or_errors(
    fake: FakeOllama, port: int, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    fake.lines = [_content(OUTPUT_MARKER), _done()]
    provider = _provider(port)

    generation = provider.generate(_request(f"Repeat {PROMPT_MARKER}"), _never)
    fake.lines = [_content(OUTPUT_MARKER), b"{broken\n"]
    with pytest.raises(ProviderProtocolError) as refused:
        provider.generate(_request(f"Repeat {PROMPT_MARKER}"), _never)

    assert OUTPUT_MARKER in generation.text
    for marker in (PROMPT_MARKER, OUTPUT_MARKER):
        assert marker not in caplog.text
        assert marker not in str(refused.value)

import logging
import socket
import time
from collections.abc import Iterator
from typing import Any

import pytest

from aegis.config.settings import OllamaSettings
from aegis.integrations.ollama.provider import (
    MAX_LINE_BYTES,
    MAX_STREAM_BYTES,
    OllamaProvider,
    pull_model,
)
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
from tests.fixtures.fake_ollama import (
    DIGEST,
    MODEL,
    FakeOllama,
    content_line,
    done_line,
    ndjson_line,
    serve,
)

PROMPT_MARKER = "PROMPT-MARKER-6f1d"
OUTPUT_MARKER = "OUTPUT-MARKER-92ab"


@pytest.fixture
def fake() -> FakeOllama:
    return FakeOllama()


@pytest.fixture
def port(fake: FakeOllama) -> Iterator[int]:
    with serve(fake) as bound:
        yield bound


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
        ({"version": "0.34.2 " + "x" * 300}, "protocol_error"),
        ({"version": None}, "protocol_error"),
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
    fake.lines = [content_line("Red, "), content_line("green."), done_line()]

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
    fake.lines = [content_line("x" * 1000) for _ in range(2000)] + [done_line()]

    generation = _provider(port).generate(_request(), _never)

    assert generation.finish_reason is FinishReason.LIMIT
    assert len(generation.text.encode()) <= MAX_OUTPUT_BYTES
    assert fake.disconnected.wait(5)


@pytest.mark.parametrize(
    ("lines", "error", "code"),
    [
        (
            [
                ndjson_line(
                    message={"role": "assistant", "content": "", "tool_calls": [{}]}, done=False
                )
            ],
            ProviderProtocolError,
            "tool_call",
        ),
        (
            [ndjson_line(message={"content": "x"}, remote_host="https://ollama.com", done=False)],
            ModelUnavailableError,
            "remote_model",
        ),
        ([b"{not json\n"], ProviderProtocolError, "protocol_error"),
        (
            [b'{"message": {"content": "' + b"y" * MAX_LINE_BYTES + b'"}}\n'],
            ProviderProtocolError,
            "protocol_error",
        ),
        ([content_line("half an answer")], ProviderUnavailableError, "unavailable"),
        (
            [ndjson_line(error="model runner has unexpectedly stopped")],
            ProviderUnavailableError,
            "unavailable",
        ),
        ([done_line("unload")], ProviderProtocolError, "protocol_error"),
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
    thought = ndjson_line(message={"role": "assistant", "content": "", "thinking": "z" * 60_000})
    fake.lines = [thought] * (MAX_STREAM_BYTES // 60_000 + 2) + [done_line()]

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
    fake.lines = [content_line("tick ") for _ in range(200)] + [done_line()]
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
    fake.lines = [content_line(OUTPUT_MARKER), done_line()]
    provider = _provider(port)

    generation = provider.generate(_request(f"Repeat {PROMPT_MARKER}"), _never)
    fake.lines = [content_line(OUTPUT_MARKER), b"{broken\n"]
    with pytest.raises(ProviderProtocolError) as refused:
        provider.generate(_request(f"Repeat {PROMPT_MARKER}"), _never)

    assert OUTPUT_MARKER in generation.text
    for marker in (PROMPT_MARKER, OUTPUT_MARKER):
        assert marker not in caplog.text
        assert marker not in str(refused.value)


def test_a_pull_reports_each_new_status_once(fake: FakeOllama, port: int) -> None:
    fake.pull_lines.insert(1, ndjson_line(status="pulling \x1b[31mlayer\x07"))
    reported: list[str] = []

    pull_model(OllamaSettings(port, MODEL, None), reported.append)

    assert reported == [
        "pulling manifest",
        "pulling [31mlayer",
        "pulling 7f4030143c1c",
        "verifying sha256 digest",
        "success",
    ]
    assert fake.requests == [{"model": MODEL, "stream": True}]


@pytest.mark.parametrize(
    ("lines", "error", "code"),
    [
        (
            [ndjson_line(status="pulling manifest"), ndjson_line(error="file does not exist")],
            ModelUnavailableError,
            "pull_failed",
        ),
        ([ndjson_line(status="pulling manifest")], ProviderUnavailableError, "unavailable"),
    ],
)
def test_a_failed_pull_is_reported(
    fake: FakeOllama, port: int, lines: list[bytes], error: type[ModelProviderError], code: str
) -> None:
    fake.pull_lines = lines

    with pytest.raises(error) as refused:
        pull_model(OllamaSettings(port, MODEL, None), lambda _status: None)

    assert refused.value.code == code


def test_pulling_from_an_unreachable_server_is_retryable() -> None:
    with pytest.raises(ProviderUnavailableError) as refused:
        pull_model(OllamaSettings(_closed_port(), MODEL, None), lambda _status: None)

    assert refused.value.code == "unreachable"

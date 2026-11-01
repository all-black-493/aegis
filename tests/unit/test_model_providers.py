import builtins
import socket
import time
from typing import Any

import pytest

from aegis.config.settings import (
    DEFAULT_OLLAMA_PORT,
    MODEL_HOST,
    ModelProviderKind,
    ModelSettings,
    OllamaSettings,
    SettingsError,
    load_model_settings,
)
from aegis.model_providers.contract import (
    MAX_OUTPUT_BYTES,
    MAX_OUTPUT_TOKENS,
    MAX_PROMPT_BYTES,
    FinishReason,
    Generation,
    GenerationRequest,
    GenerationStoppedError,
    InvalidGenerationError,
    ModelIdentity,
    ModelProvider,
    ModelUnavailableError,
    ProviderProtocolError,
    ProviderStatus,
    ProviderUnavailableError,
    bounded_text,
)
from aegis.model_providers.factory import build_provider
from aegis.model_providers.mock import MOCK_IDENTITY, MockProvider

DIGEST = "a" * 64


def _never() -> bool:
    return False


def _request(prompt: str = "Summarise the release notes.", tokens: int = 64) -> GenerationRequest:
    return GenerationRequest(prompt=prompt, max_output_tokens=tokens)


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"prompt": " \n"}, "prompt must not be empty"),
        ({"prompt": "x" * (MAX_PROMPT_BYTES + 1)}, "at most"),
        ({"prompt": "é" * (MAX_PROMPT_BYTES // 2 + 1)}, "at most"),
        ({"max_output_tokens": 0}, "max_output_tokens"),
        ({"max_output_tokens": MAX_OUTPUT_TOKENS + 1}, "max_output_tokens"),
        ({"max_output_tokens": True}, "max_output_tokens"),
        ({"temperature": -0.1}, "temperature"),
        ({"temperature": 2.5}, "temperature"),
        ({"temperature": float("nan")}, "temperature"),
        ({"seed": -1}, "seed"),
        ({"seed": 2**31}, "seed"),
    ],
)
def test_requests_outside_the_contract_are_refused(fields: dict[str, Any], message: str) -> None:
    values: dict[str, Any] = {"prompt": "hello", "max_output_tokens": 16, **fields}

    with pytest.raises(InvalidGenerationError, match=message):
        GenerationRequest(**values)


def test_generations_never_exceed_the_output_limit() -> None:
    with pytest.raises(InvalidGenerationError, match="at most"):
        Generation("x" * (MAX_OUTPUT_BYTES + 1), FinishReason.STOP, 1, 1, 1, MOCK_IDENTITY)
    with pytest.raises(InvalidGenerationError, match="negative"):
        Generation("ok", FinishReason.STOP, -1, 1, 1, MOCK_IDENTITY)


def test_bounded_text_cuts_at_a_character_boundary() -> None:
    text = "ab" + "€" * 2000

    cut, truncated = bounded_text(text, 7)

    assert (cut, truncated) == ("ab€", True)
    assert bounded_text("short") == ("short", False)
    assert len(bounded_text("€" * 5000)[0].encode()) <= MAX_OUTPUT_BYTES


def test_identities_and_statuses_are_validated() -> None:
    with pytest.raises(InvalidGenerationError, match="digest"):
        ModelIdentity("ollama", "qwen3:0.6b", "sha256:" + DIGEST, "0.34.2")
    with pytest.raises(InvalidGenerationError, match="provider and a model"):
        ModelIdentity("", "x", None, None)
    with pytest.raises(InvalidGenerationError, match="short lowercase code"):
        ProviderStatus(healthy=False, detail="Connection refused to 10.0.0.1")


def test_only_unavailability_is_retryable() -> None:
    assert ProviderUnavailableError.retryable
    assert not ModelUnavailableError.retryable
    assert not ProviderProtocolError.retryable
    assert not GenerationStoppedError.retryable


def test_the_mock_is_deterministic_and_offline() -> None:
    provider: ModelProvider = MockProvider()

    first = provider.generate(_request(), _never)
    again = provider.generate(_request(), _never)
    other = provider.generate(_request("A different prompt."), _never)

    assert (first.text, first.finish_reason) == (again.text, again.finish_reason)
    assert first.text != other.text
    assert first.identity == MOCK_IDENTITY
    assert (first.prompt_tokens, first.output_tokens) == (4, len(first.text.split()))
    assert provider.check() == ProviderStatus(healthy=True, detail="ok", identity=MOCK_IDENTITY)


def test_the_mock_honours_the_token_and_byte_limits() -> None:
    short = MockProvider().generate(_request(tokens=2), _never)
    flood = MockProvider(repeat_output=1000).generate(_request(tokens=MAX_OUTPUT_TOKENS), _never)

    assert (short.output_tokens, short.finish_reason) == (2, FinishReason.LENGTH)
    assert flood.finish_reason is FinishReason.LIMIT
    assert len(flood.text.encode()) <= MAX_OUTPUT_BYTES


def test_scripted_failures_and_stops_surface_as_contract_errors() -> None:
    down = MockProvider(failure=ProviderUnavailableError("unreachable"))
    started = time.monotonic()

    with pytest.raises(ProviderUnavailableError):
        down.generate(_request(), _never)
    with pytest.raises(GenerationStoppedError):
        MockProvider(delay_seconds=30).generate(_request(), lambda: True)

    assert down.check().healthy is False
    assert time.monotonic() - started < 1


def test_model_settings_default_to_the_offline_mock() -> None:
    settings = load_model_settings({})

    assert settings == ModelSettings(ModelProviderKind.MOCK, 120, None)
    assert MODEL_HOST == "127.0.0.1"


def test_ollama_settings_are_parsed() -> None:
    settings = load_model_settings(
        {
            "AEGIS_MODEL_PROVIDER": "ollama",
            "AEGIS_OLLAMA_MODEL": "qwen3:0.6b",
            "AEGIS_OLLAMA_MODEL_DIGEST": DIGEST,
            "AEGIS_MODEL_TIMEOUT_SECONDS": "30",
        }
    )

    assert settings == ModelSettings(
        ModelProviderKind.OLLAMA, 30, OllamaSettings(DEFAULT_OLLAMA_PORT, "qwen3:0.6b", DIGEST)
    )


@pytest.mark.parametrize(
    ("environ", "name"),
    [
        ({"AEGIS_MODEL_PROVIDER": "openai"}, "AEGIS_MODEL_PROVIDER"),
        ({"AEGIS_MODEL_PROVIDER": "ollama"}, "AEGIS_OLLAMA_MODEL is required"),
        ({"AEGIS_OLLAMA_PORT": "80"}, "AEGIS_OLLAMA_PORT"),
        ({"AEGIS_MODEL_TIMEOUT_SECONDS": "4"}, "AEGIS_MODEL_TIMEOUT_SECONDS"),
        ({"AEGIS_MODEL_TIMEOUT_SECONDS": "601"}, "AEGIS_MODEL_TIMEOUT_SECONDS"),
        ({"AEGIS_OLLAMA_MODEL_DIGEST": "sha256:" + DIGEST}, "AEGIS_OLLAMA_MODEL_DIGEST"),
        ({"AEGIS_OLLAMA_MODEL_DIGEST": DIGEST.upper()}, "AEGIS_OLLAMA_MODEL_DIGEST"),
        ({"AEGIS_OLLAMA_HOST": "10.0.0.5"}, "AEGIS_OLLAMA_HOST is not a known"),
        ({"AEGIS_OLLAMA_URL": "http://evil.example"}, "AEGIS_OLLAMA_URL is not a known"),
        *(
            ({"AEGIS_OLLAMA_MODEL": name}, "AEGIS_OLLAMA_MODEL must be a local model name")
            for name in (
                "registry.example.com/team/model:1",
                "hf.co/user/model",
                "example.com/model",
                "../model",
                "model name",
                "http://evil/model",
                "m" * 129,
            )
        ),
    ],
)
def test_invalid_model_settings_are_refused(environ: dict[str, str], name: str) -> None:
    with pytest.raises(SettingsError) as refused:
        load_model_settings(environ)

    assert name in str(refused.value)


@pytest.mark.parametrize(
    "model", ["qwen3:0.6b", "smollm2:135m", "library/qwen3:0.6b", "llama3.1:8b-instruct-q4_K_M"]
)
def test_local_model_names_are_accepted(model: str) -> None:
    settings = load_model_settings({"AEGIS_MODEL_PROVIDER": "ollama", "AEGIS_OLLAMA_MODEL": model})

    assert settings.ollama is not None
    assert settings.ollama.model == model


def test_the_factory_builds_the_mock_and_refuses_what_does_not_exist_yet() -> None:
    ollama = load_model_settings({"AEGIS_MODEL_PROVIDER": "ollama", "AEGIS_OLLAMA_MODEL": "x:1"})

    assert isinstance(build_provider(load_model_settings({})), MockProvider)
    with pytest.raises(ModelUnavailableError, match="not available yet"):
        build_provider(ollama)


def test_the_mock_opens_no_files_or_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the mock provider must not perform I/O")

    monkeypatch.setattr(builtins, "open", refuse)
    monkeypatch.setattr(socket, "socket", refuse)

    assert MockProvider().check().healthy
    assert MockProvider().generate(_request(), _never).text

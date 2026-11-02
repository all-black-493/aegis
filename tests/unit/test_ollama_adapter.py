from typing import Any

import pytest

from aegis.config.settings import load_model_settings
from aegis.integrations.ollama.provider import ChatStream, OllamaProvider, chat_body, same_model
from aegis.model_providers.contract import (
    MAX_OUTPUT_BYTES,
    FinishReason,
    GenerationRequest,
    GenerationStoppedError,
    ModelIdentity,
    ModelProviderError,
    ModelUnavailableError,
    ProviderProtocolError,
    ProviderUnavailableError,
)
from aegis.model_providers.factory import build_provider

IDENTITY = ModelIdentity("ollama", "qwen3:0.6b", "b" * 64, "0.34.2")


def _chunk(content: str = "", **fields: Any) -> dict[str, Any]:
    return {"message": {"role": "assistant", "content": content}, "done": False, **fields}


def _done(reason: str = "stop", prompt: int = 7, output: int = 3) -> dict[str, Any]:
    return {
        "message": {"role": "assistant", "content": ""},
        "done": True,
        "done_reason": reason,
        "prompt_eval_count": prompt,
        "eval_count": output,
    }


def test_the_request_carries_only_the_prompt_and_fixed_options() -> None:
    request = GenerationRequest("Name three colours.", 64, temperature=0.0, seed=0)

    plain = chat_body("smollm2:135m", request, thinking=False)
    thinking = chat_body("qwen3:0.6b", request, thinking=True)

    assert plain == {
        "model": "smollm2:135m",
        "messages": [{"role": "user", "content": "Name three colours."}],
        "stream": True,
        "options": {"temperature": 0.0, "seed": 0, "num_predict": 64},
    }
    assert thinking == {**plain, "model": "qwen3:0.6b", "think": False}
    for forbidden in ("tools", "format", "system", "keep_alive", "template", "raw"):
        assert forbidden not in thinking


def test_a_stream_is_assembled_with_its_counts() -> None:
    stream = ChatStream()

    finished = [stream.feed(c) for c in (_chunk("Red, "), _chunk("blue."), _done("stop", 9, 4))]
    generation = stream.result(IDENTITY, 12)

    assert finished == [False, False, True]
    assert (generation.text, generation.finish_reason) == ("Red, blue.", FinishReason.STOP)
    assert (generation.prompt_tokens, generation.output_tokens) == (9, 4)
    assert generation.identity == IDENTITY


def test_a_length_finish_is_reported() -> None:
    stream = ChatStream()
    stream.feed(_chunk("Once"))
    stream.feed(_done("length", 5, 1))

    assert stream.result(IDENTITY, 1).finish_reason is FinishReason.LENGTH


def test_output_beyond_the_limit_is_cut_and_reported() -> None:
    stream = ChatStream()
    finished = False
    for _ in range(MAX_OUTPUT_BYTES):
        finished = stream.feed(_chunk("€€"))
        if finished:
            break

    generation = stream.result(IDENTITY, 1)

    assert finished
    assert generation.finish_reason is FinishReason.LIMIT
    assert len(generation.text.encode()) <= MAX_OUTPUT_BYTES


def test_thinking_text_is_never_kept() -> None:
    stream = ChatStream()
    stream.feed({"message": {"role": "assistant", "content": "", "thinking": "secret plan"}})
    stream.feed(_chunk("Answer."))
    stream.feed(_done())

    assert stream.result(IDENTITY, 1).text == "Answer."


@pytest.mark.parametrize(
    ("chunk", "error", "code"),
    [
        (
            {"message": {"role": "assistant", "content": "", "tool_calls": [{"function": {}}]}},
            ProviderProtocolError,
            "tool_call",
        ),
        (_chunk("x", remote_host="https://ollama.com"), ModelUnavailableError, "remote_model"),
        (_chunk("x", remote_model="gpt-oss:120b"), ModelUnavailableError, "remote_model"),
        (
            {"error": "model runner has unexpectedly stopped"},
            ProviderUnavailableError,
            "unavailable",
        ),
        ({"message": "not an object"}, ProviderProtocolError, "protocol_error"),
        ({"message": {"content": 3}}, ProviderProtocolError, "protocol_error"),
        ({"message": {"content": "\ud800"}}, ProviderProtocolError, "protocol_error"),
        (_done("unload"), ProviderProtocolError, "protocol_error"),
        ({**_done(), "eval_count": -1}, ProviderProtocolError, "protocol_error"),
        ({**_done(), "eval_count": True}, ProviderProtocolError, "protocol_error"),
    ],
)
def test_unsafe_or_malformed_chunks_are_refused(
    chunk: dict[str, Any], error: type[ModelProviderError], code: str
) -> None:
    with pytest.raises(error) as refused:
        ChatStream().feed(chunk)

    assert refused.value.code == code


@pytest.mark.parametrize(
    ("listed", "configured", "same"),
    [
        ("qwen3:0.6b", "qwen3:0.6b", True),
        ("qwen3:latest", "qwen3", True),
        ("qwen3:0.6b", "library/qwen3:0.6b", True),
        ("qwen3:1.7b", "qwen3:0.6b", False),
        ("qwen3:0.6b-cloud", "qwen3:0.6b", False),
        (None, "qwen3:0.6b", False),
    ],
)
def test_model_names_match_only_the_configured_model(
    listed: object, configured: str, same: bool
) -> None:
    assert same_model(listed, configured) is same


def test_every_error_class_has_a_stable_code() -> None:
    assert ProviderUnavailableError().code == "unavailable"
    assert ModelUnavailableError().code == "model_unavailable"
    assert ProviderProtocolError().code == "protocol_error"
    assert GenerationStoppedError().code == "stopped"
    assert ModelUnavailableError("x", code="digest_mismatch").code == "digest_mismatch"


def test_the_factory_builds_the_ollama_adapter_without_connecting() -> None:
    settings = load_model_settings(
        {"AEGIS_MODEL_PROVIDER": "ollama", "AEGIS_OLLAMA_MODEL": "qwen3:0.6b"}
    )

    assert isinstance(build_provider(settings), OllamaProvider)

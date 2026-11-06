from collections.abc import Callable, Iterator, Sequence
from typing import Any

import pytest

from aegis.config.settings import OllamaSettings
from aegis.integrations.ollama.provider import OllamaProvider
from aegis.model_providers.contract import (
    FinishReason,
    GenerationStoppedError,
    ProviderUnavailableError,
)
from aegis.model_providers.mock import MockProvider, ScriptedStep, scripted
from aegis.model_providers.steps import StepProvider, StepReply, StepRequest, ToolCall
from tests.fixtures.fake_ollama import (
    MODEL,
    FakeOllama,
    content_line,
    done_line,
    serve,
    tool_call_line,
)
from tests.fixtures.model_steps import READ_A, WRITE_B, following_a_proposal, step_request

type Backend = Callable[[ScriptedStep], StepProvider]


def _never() -> bool:
    return False


def _lines(planned: ScriptedStep) -> list[bytes]:
    if isinstance(planned, str):
        return [content_line(planned), done_line()]
    return [
        *(
            tool_call_line(call.name, dict(call.arguments), index)
            for index, call in enumerate(planned)
        ),
        done_line(),
    ]


@pytest.fixture(params=["mock", "ollama"])
def backend(request: pytest.FixtureRequest) -> Iterator[Backend]:
    # Each provider is given the same planned reply, then held to the same assertions.
    if request.param == "mock":
        yield lambda planned: MockProvider(script=scripted(planned))
        return
    fake = FakeOllama(capabilities=["completion", "tools", "thinking"])
    with serve(fake) as port:

        def ollama(planned: ScriptedStep) -> StepProvider:
            fake.lines = _lines(planned)
            return OllamaProvider(OllamaSettings(port, MODEL, None), timeout_seconds=5)

        yield ollama


def _step(provider: StepProvider, request: StepRequest | None = None) -> StepReply:
    return provider.step(request or step_request(), _never)


def test_a_text_reply_proposes_nothing(backend: Backend) -> None:
    reply = _step(backend("Finished."))

    assert (reply.generation.text, reply.tool_calls) == ("Finished.", ())
    assert reply.generation.finish_reason is FinishReason.STOP


@pytest.mark.parametrize("planned", [(READ_A,), (READ_A, WRITE_B)])
def test_proposals_come_back_whole_and_in_order(
    backend: Backend, planned: Sequence[ToolCall]
) -> None:
    reply = _step(backend(planned))

    assert reply.tool_calls == tuple(planned)
    assert reply.generation.text == ""
    assert reply.generation.finish_reason is FinishReason.STOP


def test_a_reply_names_the_model_and_counts_its_tokens(backend: Backend) -> None:
    generation = _step(backend((READ_A,))).generation

    assert generation.identity.provider in ("mock", "ollama")
    assert generation.identity.digest is not None
    assert generation.prompt_tokens > 0
    assert generation.output_tokens > 0
    assert generation.duration_ms >= 0


def test_a_conversation_with_proposals_and_results_is_accepted(backend: Backend) -> None:
    reply = _step(backend("Finished."), following_a_proposal())

    assert isinstance(reply.generation.text, str)


def test_a_stop_request_ends_the_step(backend: Backend) -> None:
    with pytest.raises(GenerationStoppedError):
        backend((READ_A,)).step(step_request(), lambda: True)


def test_an_unavailable_model_can_be_retried() -> None:
    fake = FakeOllama(capabilities=["completion", "tools"], status={"/api/chat": 500})
    failures: list[Any] = []
    with serve(fake) as port:
        for provider in (
            MockProvider(failure=ProviderUnavailableError()),
            OllamaProvider(OllamaSettings(port, MODEL, None), timeout_seconds=5),
        ):
            with pytest.raises(ProviderUnavailableError) as failed:
                provider.step(step_request(), _never)
            failures.append(failed.value)

    assert [failure.retryable for failure in failures] == [True, True]

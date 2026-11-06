import threading
from typing import Any

import pytest

from aegis.model_providers.contract import (
    FinishReason,
    Generation,
    GenerationRequest,
    GenerationStoppedError,
    InvalidGenerationError,
    ProviderUnavailableError,
)
from aegis.model_providers.mock import MOCK_IDENTITY, MockProvider, scripted
from aegis.model_providers.steps import (
    MAX_STEP_MESSAGES,
    MAX_STEP_REQUEST_BYTES,
    MAX_STEP_TOOL_CALLS,
    MAX_STEP_TOOLS,
    MAX_TOOL_ARGUMENT_BYTES,
    Message,
    Role,
    StepReply,
    StepRequest,
    ToolCall,
    ToolDefinition,
)
from tests.fixtures.model_steps import (
    GOAL,
    READ_A,
    READ_FILE,
    SYSTEM,
    WRITE_B,
    following_a_proposal,
    step_request,
)

OBJECT = {"type": "object", "properties": {}}


def _never() -> bool:
    return False


def _nested(levels: int) -> dict[str, Any]:
    value: Any = "leaf"
    for _ in range(levels):
        value = [value]
    return {"deep": value}


@pytest.mark.parametrize("name", ["", "Read", "read file", "1read", "a" * 65, None, 7, "rm;ls"])
def test_a_tool_name_must_be_a_short_identifier(name: Any) -> None:
    with pytest.raises(InvalidGenerationError, match="tool name"):
        ToolCall(name, {})


@pytest.mark.parametrize(
    "arguments",
    [
        None,
        "{}",
        ["a.txt"],
        {"path": float("nan")},
        {"path": float("inf")},
        {"path": object()},
        {"path": "\ud800"},
        {"text": "x" * (MAX_TOOL_ARGUMENT_BYTES + 1)},
        _nested(8),
    ],
)
def test_tool_arguments_must_be_a_bounded_json_object(arguments: Any) -> None:
    with pytest.raises(InvalidGenerationError):
        ToolCall("read_file", arguments)


def test_arguments_at_the_limits_are_accepted() -> None:
    text = "x" * (MAX_TOOL_ARGUMENT_BYTES - len('{"text":""}'))

    assert ToolCall("write_file", {"text": text}).arguments["text"] == text
    assert ToolCall("write_file", _nested(5)).name == "write_file"


def test_a_proposal_cannot_be_changed_after_it_is_checked() -> None:
    arguments: dict[str, Any] = {"paths": ["a.txt"]}
    call = ToolCall("read_file", arguments)

    arguments["paths"].append("/etc/shadow")

    assert call.arguments == {"paths": ["a.txt"]}
    with pytest.raises(TypeError):
        call.arguments["paths"] = []  # type: ignore[index]


@pytest.mark.parametrize(
    ("description", "parameters"),
    [("", OBJECT), ("  ", OBJECT), ("x" * 1025, OBJECT), ("Reads.", {"type": "string"})],
)
def test_tool_definitions_are_validated(description: str, parameters: dict[str, Any]) -> None:
    with pytest.raises(InvalidGenerationError):
        ToolDefinition("read_file", description, parameters)


@pytest.mark.parametrize(
    "fields",
    [
        {"role": Role.USER, "tool_calls": (READ_A,)},
        {"role": Role.TOOL, "tool_calls": (READ_A,), "tool_name": "read_file"},
        {"role": Role.TOOL},
        {"role": Role.USER, "tool_name": "read_file"},
    ],
)
def test_only_the_assistant_proposes_and_only_a_tool_message_names_a_tool(
    fields: dict[str, Any],
) -> None:
    with pytest.raises(InvalidGenerationError):
        Message(**fields)


@pytest.mark.parametrize(
    "fields",
    [
        {"messages": ()},
        {"messages": (GOAL,) * (MAX_STEP_MESSAGES + 1)},
        {"messages": (GOAL, Message(Role.ASSISTANT, "done"))},
        {"messages": (Message(Role.USER, "x" * (MAX_STEP_REQUEST_BYTES + 1)),)},
        {"tools": ()},
        {"tools": (READ_FILE, READ_FILE)},
        {"tools": tuple(ToolDefinition(f"t{n}", "x", OBJECT) for n in range(MAX_STEP_TOOLS + 1))},
        {"max_output_tokens": 0},
        {"max_output_tokens": True},
        {"temperature": 3.0},
        {"seed": -1},
    ],
)
def test_step_requests_are_validated(fields: dict[str, Any]) -> None:
    good: dict[str, Any] = {
        "messages": (SYSTEM, GOAL),
        "tools": (READ_FILE,),
        "max_output_tokens": 64,
    }

    with pytest.raises(InvalidGenerationError):
        StepRequest(**{**good, **fields})


def test_a_reply_is_limited_in_how_many_calls_it_proposes() -> None:
    generation = Generation("", FinishReason.STOP, 0, 0, 0, MOCK_IDENTITY)

    with pytest.raises(InvalidGenerationError, match="at most"):
        StepReply(generation, (READ_A,) * (MAX_STEP_TOOL_CALLS + 1))


def test_the_mock_answers_in_text_without_a_script() -> None:
    first = MockProvider().step(step_request(), _never)
    again = MockProvider().step(step_request(), _never)

    assert first.tool_calls == ()
    assert first.generation.text.startswith("mock-1 reply ")
    assert first.generation.text == again.generation.text
    assert first.generation.identity == MOCK_IDENTITY


def test_a_script_follows_the_requests_own_history() -> None:
    provider = MockProvider(script=scripted((READ_A,), (WRITE_B,), "Finished."))

    first = provider.step(step_request(), _never)
    repeated = provider.step(step_request(), _never)
    second = provider.step(following_a_proposal(), _never)
    last = provider.step(
        step_request(
            *following_a_proposal().messages,
            Message(Role.ASSISTANT, "", (WRITE_B,)),
            Message(Role.TOOL, "written", tool_name="write_file"),
        ),
        _never,
    )

    assert first.tool_calls == repeated.tool_calls == (READ_A,)
    assert second.tool_calls == (WRITE_B,)
    assert (last.tool_calls, last.generation.text) == ((), "Finished.")


def test_a_script_past_its_end_answers_in_text() -> None:
    reply = MockProvider(script=scripted()).step(step_request(), _never)

    assert reply.tool_calls == ()
    assert reply.generation.finish_reason is FinishReason.STOP


def test_a_scripted_text_respects_the_token_limit() -> None:
    provider = MockProvider(script=scripted("one two three four"))

    reply = provider.step(step_request(tokens=2), _never)

    assert (reply.generation.text, reply.generation.finish_reason) == (
        "one two",
        FinishReason.LENGTH,
    )


def test_the_mock_stops_on_request_and_can_fail_a_step() -> None:
    halt = threading.Event()
    halt.set()

    with pytest.raises(GenerationStoppedError):
        MockProvider(delay_seconds=30).step(step_request(), halt.is_set)
    with pytest.raises(ProviderUnavailableError):
        MockProvider(failure=ProviderUnavailableError()).step(step_request(), _never)


def test_generate_is_unchanged_by_a_script() -> None:
    plain = MockProvider().generate(GenerationRequest("Name a colour.", 32), _never)
    with_script = MockProvider(script=scripted((READ_A,))).generate(
        GenerationRequest("Name a colour.", 32), _never
    )

    assert plain.text == with_script.text

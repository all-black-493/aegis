import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol

from aegis.model_providers.contract import (
    Generation,
    InvalidGenerationError,
    ModelProvider,
    StopCheck,
    sampling_problems,
)

# Technical ceilings of the provider layer, like those of the contract. The agent's policy sets
# tighter limits.
MAX_STEP_REQUEST_BYTES = 64 * 1024
MAX_STEP_MESSAGES = 128
MAX_STEP_TOOLS = 16
MAX_STEP_TOOL_CALLS = 8
MAX_TOOL_DESCRIPTION_CHARS = 1024
MAX_TOOL_ARGUMENT_BYTES = 8 * 1024
MAX_TOOL_ARGUMENT_LEVELS = 8
_TOOL_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")


class Role(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass(frozen=True)
class ToolCall:
    # A proposal from the model, and untrusted. It is bounded here so that it can be carried and
    # recorded; whether it may run is decided elsewhere (ADR-0020).
    name: str
    arguments: Mapping[str, Any]

    def __post_init__(self) -> None:
        _check_tool_name(self.name)
        if not isinstance(self.arguments, Mapping):
            raise InvalidGenerationError("tool arguments must be a JSON object")
        encoded = _encoded(dict(self.arguments))
        if len(encoded.encode()) > MAX_TOOL_ARGUMENT_BYTES:
            raise InvalidGenerationError(f"tool arguments are at most {MAX_TOOL_ARGUMENT_BYTES}")
        # A private copy: nothing outside can change a proposal once it has been checked.
        arguments = json.loads(encoded)
        if _levels(arguments) > MAX_TOOL_ARGUMENT_LEVELS:
            raise InvalidGenerationError("tool arguments are nested too deeply")
        object.__setattr__(self, "arguments", MappingProxyType(arguments))


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    parameters: Mapping[str, Any]

    def __post_init__(self) -> None:
        _check_tool_name(self.name)
        if not self.description.strip() or len(self.description) > MAX_TOOL_DESCRIPTION_CHARS:
            raise InvalidGenerationError(
                f"a tool description has 1 to {MAX_TOOL_DESCRIPTION_CHARS} characters"
            )
        if self.parameters.get("type") != "object":
            raise InvalidGenerationError("tool parameters must describe a JSON object")


@dataclass(frozen=True)
class Message:
    role: Role
    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    tool_name: str | None = None

    def __post_init__(self) -> None:
        if self.tool_calls and self.role is not Role.ASSISTANT:
            raise InvalidGenerationError("only the assistant proposes tool calls")
        if (self.tool_name is not None) != (self.role is Role.TOOL):
            raise InvalidGenerationError("a tool message, and only one, names its tool")


@dataclass(frozen=True)
class StepRequest:
    messages: tuple[Message, ...]
    tools: tuple[ToolDefinition, ...]
    max_output_tokens: int
    temperature: float = 0.0
    seed: int = 0

    def __post_init__(self) -> None:
        problems = sampling_problems(self.max_output_tokens, self.temperature, self.seed)
        if not 1 <= len(self.messages) <= MAX_STEP_MESSAGES:
            problems.append(f"a step has 1 to {MAX_STEP_MESSAGES} messages")
        elif self.messages[-1].role not in (Role.USER, Role.TOOL):
            problems.append("a step must end with a user or tool message")
        names = [tool.name for tool in self.tools]
        if not 1 <= len(names) <= MAX_STEP_TOOLS or len(set(names)) != len(names):
            problems.append(f"a step offers 1 to {MAX_STEP_TOOLS} tools with distinct names")
        if self._size() > MAX_STEP_REQUEST_BYTES:
            problems.append(f"a step request is at most {MAX_STEP_REQUEST_BYTES} bytes")
        if problems:
            raise InvalidGenerationError("; ".join(problems))

    def _size(self) -> int:
        sizes = [len(message.content.encode()) for message in self.messages]
        sizes += [
            len(_encoded(dict(call.arguments)).encode())
            for message in self.messages
            for call in message.tool_calls
        ]
        sizes += [
            len(tool.description.encode()) + len(_encoded(dict(tool.parameters)).encode())
            for tool in self.tools
        ]
        return sum(sizes)


@dataclass(frozen=True)
class StepReply:
    generation: Generation
    tool_calls: tuple[ToolCall, ...] = ()

    def __post_init__(self) -> None:
        if len(self.tool_calls) > MAX_STEP_TOOL_CALLS:
            raise InvalidGenerationError(f"a step proposes at most {MAX_STEP_TOOL_CALLS} calls")


class StepProvider(ModelProvider, Protocol):
    def step(self, request: StepRequest, stop_requested: StopCheck) -> StepReply: ...


def _check_tool_name(name: object) -> None:
    if not isinstance(name, str) or not _TOOL_NAME.fullmatch(name):
        raise InvalidGenerationError("a tool name must be a short lowercase identifier")


def _encoded(value: Mapping[str, Any]) -> str:
    try:
        encoded = json.dumps(value, allow_nan=False, ensure_ascii=False, separators=(",", ":"))
        encoded.encode()
    except (TypeError, ValueError, RecursionError):
        raise InvalidGenerationError("tool data must be valid JSON") from None
    return encoded


def _levels(value: object) -> int:
    levels, current = 0, [value]
    while current:
        levels += 1
        current = [
            child
            for item in current
            if isinstance(item, dict | list)
            for child in (item.values() if isinstance(item, dict) else item)
        ]
    return levels

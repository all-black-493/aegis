import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar, Protocol

# Technical ceilings of the provider layer. Task policy (Increment 4) sets tighter limits.
MAX_PROMPT_BYTES = 16 * 1024
MAX_OUTPUT_TOKENS = 2048
MAX_OUTPUT_BYTES = 4 * 1024
MAX_SEED = 2**31 - 1
MAX_TEMPERATURE = 2.0
_DIGEST = re.compile(r"[0-9a-f]{64}")
_DETAIL = re.compile(r"[a-z][a-z0-9_]{0,63}")

type StopCheck = Callable[[], bool]


class FinishReason(StrEnum):
    STOP = "stop"
    LENGTH = "length"
    LIMIT = "limit"


class ModelProviderError(Exception):
    retryable: ClassVar[bool] = False
    default_code: ClassVar[str] = "model_error"

    def __init__(self, message: str = "", *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code or self.default_code


class ProviderUnavailableError(ModelProviderError):
    retryable = True
    default_code = "unavailable"


class ModelUnavailableError(ModelProviderError):
    default_code = "model_unavailable"


class ProviderProtocolError(ModelProviderError):
    default_code = "protocol_error"


class GenerationStoppedError(ModelProviderError):
    default_code = "stopped"


class InvalidGenerationError(ValueError):
    pass


@dataclass(frozen=True)
class ModelIdentity:
    provider: str
    model: str
    digest: str | None
    runtime_version: str | None

    def __post_init__(self) -> None:
        if not self.provider or not self.model:
            raise InvalidGenerationError("a model identity needs a provider and a model")
        if self.digest is not None and not _DIGEST.fullmatch(self.digest):
            raise InvalidGenerationError("a model digest must be 64 lowercase hex characters")


@dataclass(frozen=True)
class GenerationRequest:
    prompt: str
    max_output_tokens: int
    temperature: float = 0.0
    seed: int = 0

    def __post_init__(self) -> None:
        problems = []
        if not self.prompt.strip():
            problems.append("prompt must not be empty")
        if len(self.prompt.encode()) > MAX_PROMPT_BYTES:
            problems.append(f"prompt must be at most {MAX_PROMPT_BYTES} bytes")
        if not _integer_between(self.max_output_tokens, 1, MAX_OUTPUT_TOKENS):
            problems.append(f"max_output_tokens must be from 1 to {MAX_OUTPUT_TOKENS}")
        if isinstance(self.temperature, bool) or not 0 <= self.temperature <= MAX_TEMPERATURE:
            problems.append(f"temperature must be from 0 to {MAX_TEMPERATURE}")
        if not _integer_between(self.seed, 0, MAX_SEED):
            problems.append(f"seed must be from 0 to {MAX_SEED}")
        if problems:
            raise InvalidGenerationError("; ".join(problems))


@dataclass(frozen=True)
class Generation:
    text: str
    finish_reason: FinishReason
    prompt_tokens: int
    output_tokens: int
    duration_ms: int
    identity: ModelIdentity

    def __post_init__(self) -> None:
        if len(self.text.encode()) > MAX_OUTPUT_BYTES:
            raise InvalidGenerationError(f"output must be at most {MAX_OUTPUT_BYTES} bytes")
        if min(self.prompt_tokens, self.output_tokens, self.duration_ms) < 0:
            raise InvalidGenerationError("token counts and duration cannot be negative")


@dataclass(frozen=True)
class ProviderStatus:
    healthy: bool
    detail: str
    identity: ModelIdentity | None = None

    def __post_init__(self) -> None:
        if not _DETAIL.fullmatch(self.detail):
            raise InvalidGenerationError("a status detail must be a short lowercase code")


class ModelProvider(Protocol):
    def check(self) -> ProviderStatus: ...

    def generate(self, request: GenerationRequest, stop_requested: StopCheck) -> Generation: ...


def bounded_text(text: str, limit: int = MAX_OUTPUT_BYTES) -> tuple[str, bool]:
    encoded = text.encode()
    if len(encoded) <= limit:
        return text, False
    # Cut at a character boundary so the result is still valid UTF-8.
    return encoded[:limit].decode(errors="ignore"), True


def _integer_between(value: object, low: int, high: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high

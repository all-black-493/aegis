import re
import threading
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any

from aegis.model_providers.contract import (
    Generation,
    GenerationRequest,
    GenerationStoppedError,
    ModelProvider,
    ModelProviderError,
    ProviderUnavailableError,
)
from aegis.policy.rules import (
    GENERATE_SEED,
    GENERATE_TEMPERATURE,
    MAX_GENERATE_TOKENS,
    MAX_PROMPT_CHARS,
)
from aegis.tasks.states import TaskKind

MAX_WAIT_SECONDS = 300
_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")


class RetryableError(Exception):
    pass


class HandlerFailure(Exception):
    # Ends the task as failed with a specific, stable failure code.
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code if _CODE.fullmatch(code) else "handler_error"


class HandlerContext:
    # The whole interface a handler gets: no database, settings or credentials (H6). The model
    # is reachable only through generate(), bound to this task's stop signal.
    def __init__(self, halt: threading.Event, provider: ModelProvider | None = None) -> None:
        self._halt = halt
        self._provider = provider

    def stop_requested(self) -> bool:
        return self._halt.is_set()

    def wait(self, seconds: float) -> bool:
        return not self._halt.wait(seconds)

    def generate(self, request: GenerationRequest) -> Generation:
        if self._provider is None:
            raise HandlerFailure("model_unavailable")
        return self._provider.generate(request, self._halt.is_set)


type Handler = Callable[[Mapping[str, Any], HandlerContext], Mapping[str, Any]]


def noop(task_input: Mapping[str, Any], context: HandlerContext) -> Mapping[str, Any]:
    if task_input:
        raise ValueError("noop takes no input")
    return {}


def wait(task_input: Mapping[str, Any], context: HandlerContext) -> Mapping[str, Any]:
    seconds = task_input.get("seconds")
    if (
        set(task_input) != {"seconds"}
        or not isinstance(seconds, int)
        or isinstance(seconds, bool)
        or not 0 <= seconds <= MAX_WAIT_SECONDS
    ):
        raise ValueError("wait takes {'seconds': n} with n from 0 to 300")
    context.wait(seconds)
    return {"waited_seconds": seconds}


def generate(task_input: Mapping[str, Any], context: HandlerContext) -> Mapping[str, Any]:
    prompt, tokens = task_input.get("prompt"), task_input.get("max_output_tokens")
    if (
        set(task_input) != {"prompt", "max_output_tokens"}
        or not isinstance(prompt, str)
        or not prompt.strip()
        or len(prompt) > MAX_PROMPT_CHARS
        or not isinstance(tokens, int)
        or isinstance(tokens, bool)
        or not 1 <= tokens <= MAX_GENERATE_TOKENS
    ):
        raise ValueError("generate takes {'prompt': text, 'max_output_tokens': n}")
    request = GenerationRequest(prompt, tokens, GENERATE_TEMPERATURE, GENERATE_SEED)
    try:
        generation = context.generate(request)
    except GenerationStoppedError:
        raise
    except ProviderUnavailableError as error:
        raise RetryableError(error.code) from None
    except ModelProviderError as error:
        raise HandlerFailure(error.code) from None
    identity = generation.identity
    # The text is untrusted model output: stored as the result, never interpreted.
    return {
        "text": generation.text,
        "finish_reason": generation.finish_reason.value,
        "provider": identity.provider,
        "model": identity.model,
        "model_digest": identity.digest,
        "runtime_version": identity.runtime_version,
        "prompt_tokens": generation.prompt_tokens,
        "output_tokens": generation.output_tokens,
        "duration_ms": generation.duration_ms,
        "temperature": request.temperature,
        "seed": request.seed,
    }


REGISTRY: Mapping[TaskKind, Handler] = MappingProxyType(
    {TaskKind.NOOP: noop, TaskKind.WAIT: wait, TaskKind.GENERATE: generate}
)

import hashlib
import time
from collections.abc import Callable, Sequence

from aegis.model_providers.contract import (
    FinishReason,
    Generation,
    GenerationRequest,
    GenerationStoppedError,
    ModelIdentity,
    ModelProviderError,
    ProviderStatus,
    StopCheck,
    bounded_text,
)
from aegis.model_providers.steps import Role, StepReply, StepRequest, ToolCall

MOCK_PROVIDER = "mock"
MOCK_MODEL = "mock-1"
MOCK_IDENTITY = ModelIdentity(
    provider=MOCK_PROVIDER,
    model=MOCK_MODEL,
    digest=hashlib.sha256(b"aegis mock model 1").hexdigest(),
    runtime_version=None,
)
_STEP_SECONDS = 0.01

type ScriptedStep = str | Sequence[ToolCall]
type StepScript = Callable[[StepRequest], ScriptedStep]


def scripted(*steps: ScriptedStep) -> StepScript:
    # The position comes from the request's own history, so the mock keeps no state between
    # steps and stays a pure function of the request. Past the end, it answers in plain text.
    def next_step(request: StepRequest) -> ScriptedStep:
        taken = sum(message.role is Role.ASSISTANT for message in request.messages)
        return steps[taken] if taken < len(steps) else ()

    return next_step


class MockProvider:
    # Deterministic and offline: the output is a pure function of the request. The scripted
    # behaviours exist for tests and are reachable only through this constructor.
    def __init__(
        self,
        *,
        failure: ModelProviderError | None = None,
        delay_seconds: float = 0,
        repeat_output: int = 1,
        script: StepScript | None = None,
    ) -> None:
        self._failure = failure
        self._delay_seconds = delay_seconds
        self._repeat_output = repeat_output
        self._script = script

    def check(self) -> ProviderStatus:
        if self._failure is not None:
            return ProviderStatus(healthy=False, detail="unavailable", identity=MOCK_IDENTITY)
        return ProviderStatus(healthy=True, detail="ok", identity=MOCK_IDENTITY)

    def generate(self, request: GenerationRequest, stop_requested: StopCheck) -> Generation:
        started = time.monotonic()
        self._wait(stop_requested)
        if self._failure is not None:
            raise self._failure
        return self._reply(request.prompt, None, request.max_output_tokens, started)

    def step(self, request: StepRequest, stop_requested: StopCheck) -> StepReply:
        started = time.monotonic()
        self._wait(stop_requested)
        if self._failure is not None:
            raise self._failure
        prompt = "\n".join(message.content for message in request.messages)
        planned = self._script(request) if self._script is not None else ()
        if isinstance(planned, str):
            return StepReply(self._reply(prompt, planned, request.max_output_tokens, started))
        calls = tuple(planned)
        if not calls:
            return StepReply(self._reply(prompt, None, request.max_output_tokens, started))
        generation = Generation(
            text="",
            finish_reason=FinishReason.STOP,
            prompt_tokens=len(prompt.split()),
            output_tokens=len(calls),
            duration_ms=_elapsed_ms(started),
            identity=MOCK_IDENTITY,
        )
        return StepReply(generation, calls)

    def _reply(
        self, prompt: str, scripted_text: str | None, max_output_tokens: int, started: float
    ) -> Generation:
        words = prompt.split()
        fingerprint = hashlib.sha256(prompt.encode()).hexdigest()[:16]
        default = f"{MOCK_MODEL} reply {fingerprint}: {len(words)} words received."
        reply = (default if scripted_text is None else scripted_text).split()
        reply *= self._repeat_output
        finish = FinishReason.STOP
        if len(reply) > max_output_tokens:
            reply, finish = reply[:max_output_tokens], FinishReason.LENGTH
        text, cut = bounded_text(" ".join(reply))
        if cut:
            finish = FinishReason.LIMIT
        return Generation(
            text=text,
            finish_reason=finish,
            prompt_tokens=len(words),
            output_tokens=len(text.split()),
            duration_ms=_elapsed_ms(started),
            identity=MOCK_IDENTITY,
        )

    def _wait(self, stop_requested: StopCheck) -> None:
        deadline = time.monotonic() + self._delay_seconds
        while True:
            if stop_requested():
                raise GenerationStoppedError("generation stopped on request")
            if time.monotonic() >= deadline:
                return
            time.sleep(_STEP_SECONDS)


def _elapsed_ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)

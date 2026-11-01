import hashlib
import time

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

MOCK_PROVIDER = "mock"
MOCK_MODEL = "mock-1"
MOCK_IDENTITY = ModelIdentity(
    provider=MOCK_PROVIDER,
    model=MOCK_MODEL,
    digest=hashlib.sha256(b"aegis mock model 1").hexdigest(),
    runtime_version=None,
)
_STEP_SECONDS = 0.01


class MockProvider:
    # Deterministic and offline: the output is a pure function of the request. The scripted
    # behaviours exist for tests and are reachable only through this constructor.
    def __init__(
        self,
        *,
        failure: ModelProviderError | None = None,
        delay_seconds: float = 0,
        repeat_output: int = 1,
    ) -> None:
        self._failure = failure
        self._delay_seconds = delay_seconds
        self._repeat_output = repeat_output

    def check(self) -> ProviderStatus:
        if self._failure is not None:
            return ProviderStatus(healthy=False, detail="unavailable", identity=MOCK_IDENTITY)
        return ProviderStatus(healthy=True, detail="ok", identity=MOCK_IDENTITY)

    def generate(self, request: GenerationRequest, stop_requested: StopCheck) -> Generation:
        started = time.monotonic()
        self._wait(stop_requested)
        if self._failure is not None:
            raise self._failure
        words = request.prompt.split()
        fingerprint = hashlib.sha256(request.prompt.encode()).hexdigest()[:16]
        reply = f"{MOCK_MODEL} reply {fingerprint}: {len(words)} words received.".split()
        reply *= self._repeat_output
        finish = FinishReason.STOP
        if len(reply) > request.max_output_tokens:
            reply, finish = reply[: request.max_output_tokens], FinishReason.LENGTH
        text, cut = bounded_text(" ".join(reply))
        if cut:
            finish = FinishReason.LIMIT
        return Generation(
            text=text,
            finish_reason=finish,
            prompt_tokens=len(words),
            output_tokens=len(text.split()),
            duration_ms=round((time.monotonic() - started) * 1000),
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

import os
import threading
import time
from typing import Any

import pytest

from aegis.apps.api.routes import health, v1
from aegis.apps.worker.__main__ import main
from aegis.config.settings import (
    MAX_WORKER_ATTEMPTS,
    SettingsError,
    WorkerSettings,
    forget_secrets,
    load_worker_settings,
)
from aegis.config.variables import SECRET_NAMES
from aegis.jobs.handlers import (
    REGISTRY,
    HandlerContext,
    HandlerFailure,
    RetryableError,
    generate,
    noop,
    wait,
)
from aegis.jobs.worker import BACKOFF_MAX_SECONDS, exponential_backoff
from aegis.model_providers.contract import (
    GenerationRequest,
    GenerationStoppedError,
    ModelProviderError,
    ModelUnavailableError,
    ProviderProtocolError,
    ProviderUnavailableError,
)
from aegis.model_providers.mock import MOCK_IDENTITY, MockProvider
from aegis.policy.rules import (
    GENERATE_SEED,
    GENERATE_TEMPERATURE,
    MAX_JOB_ATTEMPTS,
    MAX_PROMPT_CHARS,
    TASK_KINDS,
)
from aegis.tasks.states import TaskKind

PROMPT = {"prompt": "Name three colours.", "max_output_tokens": 64}


class RecordingProvider(MockProvider):
    def __init__(self, failure: ModelProviderError | None = None) -> None:
        super().__init__(failure=failure)
        self.requests: list[GenerationRequest] = []

    def generate(self, request: GenerationRequest, stop_requested: Any) -> Any:
        self.requests.append(request)
        return super().generate(request, stop_requested)


def _context(halted: bool = False, provider: MockProvider | None = None) -> HandlerContext:
    halt = threading.Event()
    if halted:
        halt.set()
    return HandlerContext(halt, provider)


def test_the_registry_holds_exactly_the_policy_kinds() -> None:
    assert dict(REGISTRY) == {
        TaskKind.NOOP: noop,
        TaskKind.WAIT: wait,
        TaskKind.GENERATE: generate,
    }
    assert set(REGISTRY) == set(TaskKind) == TASK_KINDS
    with pytest.raises(TypeError):
        REGISTRY[TaskKind.NOOP] = wait  # type: ignore[index]


def test_the_handler_context_offers_no_database_settings_or_credentials() -> None:
    public = {name for name in dir(HandlerContext) if not name.startswith("_")}

    assert public == {"stop_requested", "wait", "generate"}


def test_noop_returns_an_empty_result() -> None:
    assert noop({}, _context()) == {}
    with pytest.raises(ValueError, match="no input"):
        noop({"x": 1}, _context())


def test_wait_waits_and_reports_how_long() -> None:
    started = time.monotonic()

    result = wait({"seconds": 0}, _context())

    assert result == {"waited_seconds": 0}
    assert time.monotonic() - started < 1


def test_wait_returns_early_when_halted() -> None:
    started = time.monotonic()

    wait({"seconds": 300}, _context(halted=True))

    assert time.monotonic() - started < 1


@pytest.mark.parametrize(
    "task_input",
    [
        {},
        {"seconds": 301},
        {"seconds": -1},
        {"seconds": True},
        {"seconds": 1.5},
        {"seconds": 1, "x": 2},
    ],
)
def test_wait_refuses_input_the_policy_would_refuse(task_input: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="seconds"):
        wait(task_input, _context())


def test_generate_records_the_model_and_fixed_sampling() -> None:
    provider = RecordingProvider()

    result = generate(PROMPT, _context(provider=provider))

    assert provider.requests == [
        GenerationRequest("Name three colours.", 64, GENERATE_TEMPERATURE, GENERATE_SEED)
    ]
    assert result["text"].startswith("mock-1 reply ")
    assert {key: result[key] for key in ("provider", "model", "model_digest")} == {
        "provider": MOCK_IDENTITY.provider,
        "model": MOCK_IDENTITY.model,
        "model_digest": MOCK_IDENTITY.digest,
    }
    assert (result["finish_reason"], result["temperature"], result["seed"]) == ("stop", 0.0, 0)
    assert set(result) == {
        "text",
        "finish_reason",
        "provider",
        "model",
        "model_digest",
        "runtime_version",
        "prompt_tokens",
        "output_tokens",
        "duration_ms",
        "temperature",
        "seed",
    }


@pytest.mark.parametrize(
    "task_input",
    [
        {},
        {"prompt": "x"},
        {"prompt": "", "max_output_tokens": 1},
        {"prompt": "   ", "max_output_tokens": 1},
        {"prompt": "p" * (MAX_PROMPT_CHARS + 1), "max_output_tokens": 1},
        {"prompt": "x", "max_output_tokens": 0},
        {"prompt": "x", "max_output_tokens": 513},
        {"prompt": "x", "max_output_tokens": True},
        {"prompt": "x", "max_output_tokens": 1, "temperature": 1},
    ],
)
def test_generate_refuses_input_the_policy_would_refuse(task_input: dict[str, Any]) -> None:
    provider = RecordingProvider()

    with pytest.raises(ValueError, match="generate takes"):
        generate(task_input, _context(provider=provider))

    assert provider.requests == []


def test_generate_without_a_provider_fails_the_task() -> None:
    with pytest.raises(HandlerFailure) as failed:
        generate(PROMPT, _context())

    assert failed.value.code == "model_unavailable"


@pytest.mark.parametrize(
    ("failure", "raised", "code"),
    [
        (ProviderUnavailableError(), RetryableError, "unavailable"),
        (ModelUnavailableError(code="digest_mismatch"), HandlerFailure, "digest_mismatch"),
        (ProviderProtocolError(code="tool_call"), HandlerFailure, "tool_call"),
    ],
)
def test_only_an_unavailable_provider_is_retried(
    failure: ModelProviderError, raised: type[Exception], code: str
) -> None:
    with pytest.raises(raised) as stopped:
        generate(PROMPT, _context(provider=RecordingProvider(failure)))

    assert getattr(stopped.value, "code", str(stopped.value)) == code


def test_a_halted_generation_stops_before_the_model_answers() -> None:
    with pytest.raises(GenerationStoppedError):
        generate(PROMPT, _context(halted=True, provider=MockProvider(delay_seconds=30)))


def test_failure_codes_are_short_lowercase_codes() -> None:
    assert HandlerFailure("tool_call").code == "tool_call"
    assert HandlerFailure("Refused: see /etc/passwd").code == "handler_error"


def test_worker_settings_have_safe_defaults() -> None:
    assert load_worker_settings({}) == WorkerSettings(1, 30, 5, 10, 3)


def test_worker_settings_are_parsed() -> None:
    settings = load_worker_settings(
        {
            "AEGIS_WORKER_POLL_SECONDS": "2",
            "AEGIS_WORKER_LEASE_SECONDS": "60",
            "AEGIS_WORKER_HEARTBEAT_SECONDS": "20",
            "AEGIS_WORKER_SHUTDOWN_GRACE_SECONDS": "0",
            "AEGIS_WORKER_MAX_ATTEMPTS": "1",
        }
    )

    assert settings == WorkerSettings(2, 60, 20, 0, 1)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("AEGIS_WORKER_POLL_SECONDS", "0"),
        ("AEGIS_WORKER_LEASE_SECONDS", "9"),
        ("AEGIS_WORKER_LEASE_SECONDS", "601"),
        ("AEGIS_WORKER_HEARTBEAT_SECONDS", "11"),
        ("AEGIS_WORKER_SHUTDOWN_GRACE_SECONDS", "301"),
        ("AEGIS_WORKER_MAX_ATTEMPTS", "0"),
        ("AEGIS_WORKER_MAX_ATTEMPTS", "11"),
        ("AEGIS_WORKER_LEASE_SECONDS", "30s"),
    ],
)
def test_worker_settings_outside_their_bounds_are_refused(name: str, value: str) -> None:
    with pytest.raises(SettingsError) as refused:
        load_worker_settings({name: value})

    assert name in str(refused.value)


def test_configuration_cannot_raise_attempts_above_the_policy() -> None:
    assert MAX_WORKER_ATTEMPTS == MAX_JOB_ATTEMPTS
    with pytest.raises(SettingsError):
        load_worker_settings({"AEGIS_WORKER_MAX_ATTEMPTS": str(MAX_JOB_ATTEMPTS + 1)})


def test_backoff_doubles_up_to_a_cap() -> None:
    delays = [exponential_backoff(attempt) for attempt in range(1, 10)]

    assert delays[:4] == [2, 4, 8, 16]
    assert max(delays) == BACKOFF_MAX_SECONDS
    assert delays == sorted(delays)


def test_no_route_retries_or_manages_jobs() -> None:
    paths = {route.path for router in (health, v1) for route in router.routes}  # type: ignore[attr-defined]

    assert not [path for path in paths if "retry" in path or "job" in path]


def test_the_worker_refuses_invalid_settings_before_connecting(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AEGIS_WORKER_LEASE_SECONDS", "5")

    assert main() == 1
    assert "AEGIS_WORKER_LEASE_SECONDS" in capsys.readouterr().err


def test_the_worker_forgets_every_secret_before_running_handlers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in SECRET_NAMES:
        monkeypatch.setenv(name, "s" * 32)
    monkeypatch.setenv("AEGIS_POSTGRES_DB", "kept")

    forget_secrets(os.environ)

    assert not SECRET_NAMES & os.environ.keys()
    assert os.environ["AEGIS_POSTGRES_DB"] == "kept"

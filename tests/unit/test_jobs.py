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
from aegis.jobs.handlers import REGISTRY, HandlerContext, noop, wait
from aegis.jobs.worker import BACKOFF_MAX_SECONDS, exponential_backoff
from aegis.policy.rules import MAX_JOB_ATTEMPTS, TASK_KINDS
from aegis.tasks.states import TaskKind


def _context(halted: bool = False) -> HandlerContext:
    halt = threading.Event()
    if halted:
        halt.set()
    return HandlerContext(halt)


def test_the_registry_holds_exactly_noop_and_wait() -> None:
    assert dict(REGISTRY) == {TaskKind.NOOP: noop, TaskKind.WAIT: wait}
    assert set(REGISTRY) == set(TaskKind) == TASK_KINDS
    with pytest.raises(TypeError):
        REGISTRY[TaskKind.NOOP] = wait  # type: ignore[index]


def test_the_handler_context_offers_no_database_settings_or_credentials() -> None:
    public = {name for name in dir(HandlerContext) if not name.startswith("_")}

    assert public == {"stop_requested", "wait"}


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

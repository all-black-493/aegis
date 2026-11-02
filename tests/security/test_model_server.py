import json
import os
import threading
from collections.abc import Iterator
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, text

from aegis.audit.recorder import AuditRecorder
from aegis.authorization.access import ActorContext
from aegis.authorization.catalog import IdentityKind, Role
from aegis.config.logs import Redactor
from aegis.config.settings import (
    MODEL_HOST,
    DatabaseRole,
    OllamaSettings,
    SettingsError,
    WorkerSettings,
    load_database_settings,
    load_model_settings,
    load_token_pepper,
)
from aegis.identity.admin import IdentityAdministration
from aegis.integrations.ollama.provider import OllamaProvider
from aegis.jobs.worker import Worker
from aegis.model_providers.contract import MAX_OUTPUT_BYTES
from aegis.tasks.repository import TaskRecord, get_task
from aegis.tasks.service import Submission, TaskService
from aegis.tasks.states import TaskState
from tests.fixtures.fake_ollama import (
    DIGEST,
    MODEL,
    FakeOllama,
    content_line,
    done_line,
    ndjson_line,
    serve,
)

PEPPER = load_token_pepper(os.environ)
RECORDER = AuditRecorder(Redactor([PEPPER.reveal()]))
FAST = WorkerSettings(
    poll_seconds=0.05,
    lease_seconds=10,
    heartbeat_seconds=0.1,
    shutdown_grace_seconds=0.3,
    max_attempts=1,
)
PROMPT = "PROMPT-7a3c: name three colours."
pytestmark = pytest.mark.usefixtures("isolated_jobs")


@pytest.fixture
def operator(owner_engine: Engine) -> tuple[ActorContext, str]:
    name = f"model-server-{uuid4().hex[:12]}"
    with owner_engine.begin() as connection:
        administration = IdentityAdministration(connection, AuditRecorder(Redactor()))
        identity_id = administration.create_identity(name, IdentityKind.HUMAN, [Role.OPERATOR])
        issued = administration.issue_credential(name, PEPPER)
    actor = ActorContext(
        identity_id, IdentityKind.HUMAN, frozenset({Role.OPERATOR}), issued.credential_id
    )
    return actor, issued.token.reveal()


@pytest.fixture
def fake() -> FakeOllama:
    return FakeOllama()


@pytest.fixture
def port(fake: FakeOllama) -> Iterator[int]:
    with serve(fake) as bound:
        yield bound


def _run(app_engine: Engine, actor: ActorContext, port: int) -> TaskRecord:
    # The digest is pinned, as an operator who followed `make model-pull` would pin it.
    provider = OllamaProvider(OllamaSettings(port, MODEL, DIGEST), timeout_seconds=5)
    worker = Worker(app_engine, RECORDER, FAST, backoff=lambda _: 0, provider=provider)
    submission = Submission(
        "generate", {"prompt": PROMPT, "max_output_tokens": 64}, f"key-{uuid4().hex}"
    )
    task = TaskService(app_engine, RECORDER).submit(actor, submission, uuid4().hex).task
    assert worker.step(threading.Event())
    with app_engine.connect() as connection:
        done = get_task(connection, task.task_id)
    assert done is not None
    return done


def _stored(owner_engine: Engine, task_id: UUID) -> str:
    rows: list[str] = []
    with owner_engine.connect() as connection:
        for table in ("tasks", "audit_events", "security_decisions", "task_state_transitions"):
            column = "id" if table == "tasks" else "task_id"
            rows += connection.execute(
                text(f"SELECT row_to_json(t)::text FROM aegis.{table} t WHERE {column} = :id"),
                {"id": task_id},
            ).scalars()
    return "\n".join(rows)


def test_only_the_prompt_and_fixed_options_reach_the_model_server(
    app_engine: Engine, operator: tuple[ActorContext, str], fake: FakeOllama, port: int
) -> None:
    task = _run(app_engine, operator[0], port)

    assert task.state is TaskState.SUCCEEDED
    assert task.result is not None
    assert task.result["text"] == "Red."
    assert {request.split("\n", 1)[0] for request in fake.seen} == {
        "GET /api/version HTTP/1.1",
        "POST /api/show HTTP/1.1",
        "GET /api/tags HTTP/1.1",
        "POST /api/chat HTTP/1.1",
    }
    assert fake.requests == [
        {
            "model": MODEL,
            "messages": [{"role": "user", "content": PROMPT}],
            "stream": True,
            "options": {"temperature": 0.0, "seed": 0, "num_predict": 64},
            "think": False,
        }
    ]
    received = "\n".join(fake.seen)
    secrets = [PEPPER.reveal(), operator[1]] + [
        load_database_settings(os.environ, role).password.reveal() for role in DatabaseRole
    ]
    for secret in secrets:
        assert secret not in received


@pytest.mark.parametrize("variable", ["AEGIS_OLLAMA_HOST", "AEGIS_MODEL_HOST", "AEGIS_OLLAMA_URL"])
def test_the_model_server_cannot_be_moved_off_this_host(
    monkeypatch: pytest.MonkeyPatch, fake: FakeOllama, port: int, variable: str
) -> None:
    environ = {"AEGIS_MODEL_PROVIDER": "ollama", "AEGIS_OLLAMA_MODEL": MODEL}
    with pytest.raises(SettingsError, match=f"{variable} is not a known AEGIS variable"):
        load_model_settings({**environ, variable: "203.0.113.9"})
    # Ollama's own client variable is ignored: the adapter still reaches the loopback server.
    monkeypatch.setenv("OLLAMA_HOST", "http://203.0.113.9:11434")

    status = OllamaProvider(OllamaSettings(port, MODEL, None), timeout_seconds=5).check()

    assert MODEL_HOST == "127.0.0.1"
    assert (status.healthy, len(fake.seen)) == (True, 3)


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"show_extra": {"remote_host": "https://ollama.com:443"}}, "remote_model"),
        ({"tags_extra": {"remote_model": "gpt-oss:120b"}}, "remote_model"),
        ({"digest": "d" * 64}, "digest_mismatch"),
        ({"models": ["qwen3:1.7b"]}, "model_missing"),
        ({"capabilities": ["embedding"]}, "not_generative"),
        ({"version": "0.34.2\nforged: yes"}, "protocol_error"),
    ],
)
def test_a_remote_swapped_or_unusable_model_never_receives_the_prompt(
    app_engine: Engine,
    operator: tuple[ActorContext, str],
    fake: FakeOllama,
    port: int,
    change: dict[str, Any],
    code: str,
) -> None:
    for name, value in change.items():
        setattr(fake, name, value)

    task = _run(app_engine, operator[0], port)

    assert (task.state, task.failure_code, task.result) == (TaskState.FAILED, code, None)
    assert fake.requests == []
    assert PROMPT not in "\n".join(fake.seen)


def test_a_tool_call_from_the_model_fails_the_task_and_stores_nothing(
    app_engine: Engine,
    owner_engine: Engine,
    operator: tuple[ActorContext, str],
    fake: FakeOllama,
    port: int,
) -> None:
    call = {"function": {"name": "shell", "arguments": {"command": "TOOL-CALL-4e2d"}}}
    fake.lines = [
        content_line("Running it now."),
        ndjson_line(message={"role": "assistant", "content": "", "tool_calls": [call]}),
        done_line(),
    ]

    task = _run(app_engine, operator[0], port)

    assert (task.state, task.failure_code, task.result) == (TaskState.FAILED, "tool_call", None)
    stored = _stored(owner_engine, task.task_id)
    assert "TOOL-CALL-4e2d" not in stored
    assert "Running it now." not in stored
    assert "model.generated" not in stored


def test_a_stream_that_ends_early_stores_no_partial_answer(
    app_engine: Engine,
    owner_engine: Engine,
    operator: tuple[ActorContext, str],
    fake: FakeOllama,
    port: int,
) -> None:
    fake.lines = [content_line("PARTIAL-ANSWER-91f0 and then")]

    task = _run(app_engine, operator[0], port)

    assert (task.state, task.failure_code, task.result) == (
        TaskState.FAILED,
        "attempts_exhausted",
        None,
    )
    assert "PARTIAL-ANSWER-91f0" not in _stored(owner_engine, task.task_id)


def test_an_endless_stream_is_cut_to_the_output_limit(
    app_engine: Engine, operator: tuple[ActorContext, str], fake: FakeOllama, port: int
) -> None:
    fake.lines = [content_line("y" * 1000) for _ in range(2000)] + [done_line()]

    task = _run(app_engine, operator[0], port)

    assert task.state is TaskState.SUCCEEDED
    assert task.result is not None
    assert task.result["finish_reason"] == "limit"
    assert len(task.result["text"].encode()) <= MAX_OUTPUT_BYTES
    assert len(json.dumps(task.result).encode()) <= 8 * 1024
    assert fake.disconnected.wait(5)

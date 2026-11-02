import os
import re
import signal
from typing import Any

import httpx2
import pytest
from sqlalchemy import Engine, text

from aegis.config.settings import (
    DatabaseRole,
    DatabaseSettings,
    load_database_settings,
    load_token_pepper,
)
from aegis.integrations.ollama.provider import VERIFIED_VERSION
from aegis.model_providers.contract import GenerationRequest
from aegis.model_providers.mock import MockProvider
from aegis.policy.version import CURRENT_POLICY
from tests.fixtures.processes import Process, identity, live, wait_for

PROMPT = "Describe the colour of a clear midday sky in one sentence."
INPUT = {"prompt": PROMPT, "max_output_tokens": 64}
RESULT_KEYS = {
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
AUDITED_KEYS = RESULT_KEYS - {"text", "temperature", "seed"}
EVENTS = [
    "security.decision",
    "task.created",
    "task.transitioned",
    "security.decision",
    "task.transitioned",
    "task.transitioned",
    "model.generated",
]
DECISIONS = [
    ("task.submit", "allow", ["submission_allowed"]),
    ("task.execute", "allow", ["execution_allowed"]),
]
PROVIDERS = [
    pytest.param("mock", id="mock"),
    pytest.param("ollama", id="ollama", marks=pytest.mark.local_ai),
]
pytestmark = pytest.mark.usefixtures("isolated_jobs")


def _model_environ(provider: str) -> dict[str, str]:
    if provider == "ollama" and not os.environ.get("AEGIS_OLLAMA_MODEL"):
        pytest.fail(
            "set AEGIS_OLLAMA_MODEL, then run `make up-local-ai` and `make model-pull`;"
            " see the getting-started guide"
        )
    return {"AEGIS_MODEL_PROVIDER": provider}


@pytest.mark.parametrize("provider", PROVIDERS)
def test_a_generate_task_completes_the_same_workflow_on_each_provider(
    provider: str,
    environ: dict[str, str],
    processes: list[Process],
    owner_engine: Engine,
    app_settings: DatabaseSettings,
) -> None:
    environ = {**environ, **_model_environ(provider)}
    operator = identity(environ, "operator")
    api, worker = Process("aegis.apps.api", environ), Process("aegis.apps.worker", environ)
    processes.extend([api, worker])
    base = f"http://127.0.0.1:{environ['AEGIS_API_PORT']}"
    wait_for(lambda: live(base), 20, "the API")
    headers = {"Authorization": f"Bearer {operator}"}

    with httpx2.Client(base_url=base, timeout=10) as http:
        refused = http.post(
            "/v1/tasks",
            json={"kind": "generate", "input": {**INPUT, "model": "llama3:70b"}},
            headers={**headers, "Idempotency-Key": "e2e-refused-0001"},
        )
        created = http.post(
            "/v1/tasks",
            json={"kind": "generate", "input": INPUT},
            headers={**headers, "Idempotency-Key": "e2e-generate-0001"},
        )
        assert created.status_code == 201, created.text
        task_id = created.json()["id"]

        def shown() -> dict[str, Any]:
            task: dict[str, Any] = http.get(f"/v1/tasks/{task_id}", headers=headers).json()
            return task

        wait_for(lambda: shown()["finished_at"] is not None, 180, "the generate task")
        task = shown()

    assert worker.stop(signal.SIGTERM) == 0
    assert api.stop(signal.SIGINT) == 0
    assert (refused.status_code, refused.json()["reasons"]) == (403, ["input_invalid"])
    assert (task["state"], task["failure_code"]) == ("succeeded", None)
    result = task["result"]
    assert set(result) == RESULT_KEYS
    assert result["provider"] == provider
    assert re.fullmatch(r"[0-9a-f]{64}", result["model_digest"])
    assert (result["temperature"], result["seed"]) == (0.0, 0)
    assert result["finish_reason"] in ("stop", "length")
    assert 1 <= result["output_tokens"] <= 64
    assert result["prompt_tokens"] >= 1
    assert result["text"].strip()
    if provider == "mock":
        expected = MockProvider().generate(GenerationRequest(PROMPT, 64), lambda: False)
        assert (result["text"], result["model"], result["runtime_version"]) == (
            expected.text,
            "mock-1",
            None,
        )
    else:
        assert result["model"] == os.environ["AEGIS_OLLAMA_MODEL"]
        assert result["runtime_version"] == VERIFIED_VERSION
        pinned = os.environ.get("AEGIS_OLLAMA_MODEL_DIGEST")
        if pinned:
            assert result["model_digest"] == pinned

    with owner_engine.connect() as connection:
        moves = (
            connection.execute(
                text(
                    "SELECT from_state || '>' || to_state FROM aegis.task_state_transitions"
                    " WHERE task_id = :id ORDER BY to_version"
                ),
                {"id": task_id},
            )
            .scalars()
            .all()
        )
        events = connection.execute(
            text(
                "SELECT event_type, details FROM aegis.audit_events WHERE task_id = :id ORDER BY id"
            ),
            {"id": task_id},
        ).all()
        decisions = connection.execute(
            text(
                "SELECT action, effect, reason_codes, policy_version, policy_digest"
                " FROM aegis.security_decisions WHERE task_id = :id ORDER BY decided_at"
            ),
            {"id": task_id},
        ).all()
    assert moves == ["created>queued", "queued>running", "running>succeeded"]
    assert [event_type for event_type, _ in events] == EVENTS
    assert events[-1][1] == {key: result[key] for key in AUDITED_KEYS}
    assert [tuple(row[:3]) for row in decisions] == DECISIONS
    assert {tuple(row[3:]) for row in decisions} == {
        (CURRENT_POLICY.version, CURRENT_POLICY.digest)
    }

    output = api.output + worker.output
    assert "model provider unavailable" not in output
    owner = load_database_settings(os.environ, DatabaseRole.OWNER)
    private = [
        PROMPT,
        operator.rsplit("_", 1)[1],
        load_token_pepper(os.environ).reveal(),
        app_settings.password.reveal(),
        owner.password.reveal(),
    ]
    # Very short answers could match ordinary log text by chance; the prompt check still applies.
    if len(result["text"]) >= 16:
        private.append(result["text"])
    for value in private:
        assert value not in output

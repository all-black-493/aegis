import hashlib
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from aegis.agents.records import FINISHED, NOT_AUTHORIZED, canonical, digest, read_runs, read_steps
from aegis.apps.api.app import create_app
from aegis.apps.api.context import ApiContext
from aegis.authorization.catalog import Role
from aegis.config.settings import Environment
from aegis.jobs import repository as jobs
from aegis.jobs.settlement import Claim
from aegis.model_providers.contract import FinishReason, Generation
from aegis.model_providers.mock import MOCK_IDENTITY
from aegis.model_providers.steps import StepReply, ToolCall
from aegis.runtime.contract import ExecResult
from aegis.tool_registry.catalog import TOOLS
from aegis.tool_registry.model import Capability, ToolStatus
from tests.fixtures import records
from tests.fixtures.agent_runs import SCENARIO, claimed, governed, run_records, started
from tests.fixtures.agent_sandbox import AGENT_SANDBOX
from tests.fixtures.fake_runtime import FakeRuntime
from tests.fixtures.services import PEPPER, RECORDER, Caller, make_caller

READ = ToolCall("read_file", {"path": "config.txt"})
pytestmark = pytest.mark.usefixtures("isolated_jobs")


def _reply(*calls: ToolCall, text: str = "") -> StepReply:
    generation = Generation(text, FinishReason.STOP, 12, 3, 40, MOCK_IDENTITY)
    return StepReply(generation, calls)


def _reading(stdout: str) -> FakeRuntime:
    tool = TOOLS["read_file"]
    argv = tool.command(READ.arguments, tool.limits)
    return FakeRuntime(results={argv: ExecResult(0, stdout, "")})


def _complete_run(app_engine: Engine, claim: Claim) -> Any:
    run = started(app_engine, claim)
    with app_engine.begin() as connection:
        run_records().model_step(connection, run, _reply(READ))
    governed(app_engine, claim, run, _reading("prot=8080\n")).invoke(READ)
    with app_engine.begin() as connection:
        run_records().model_step(connection, run, _reply(text="Done."))
        run_records().end(connection, run, FINISHED, {"workspace_sha256": "a" * 64})
    return run


def test_a_run_records_its_model_steps_tools_decisions_and_end(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)

    run = _complete_run(app_engine, claim)

    with app_engine.connect() as connection:
        [stored] = read_runs(connection, claim.task.task_id)
        steps = read_steps(connection, claim.task.task_id, after=0, limit=10)
    assert (stored.run_id, stored.attempt, stored.scenario, stored.sandbox) == (
        run.run_id,
        1,
        SCENARIO,
        AGENT_SANDBOX,
    )
    assert [(s.sequence, s.kind, s.code, s.tool_name) for s in steps] == [
        (1, "model", "stop", None),
        (2, "tool", "ok", "read_file"),
        (3, "model", "stop", None),
        (4, "end", FINISHED, None),
    ]
    assert steps[0].content["tool_calls"] == [
        {"name": "read_file", "arguments": {"path": "config.txt"}}
    ]
    assert steps[0].content["model"]["digest"] == MOCK_IDENTITY.digest
    assert (steps[0].prompt_tokens, steps[0].output_tokens) == (12, 3)
    assert steps[1].content == {
        "arguments": {"path": "config.txt"},
        "status": "ok",
        "output": {"content": "prot=8080\n", "truncated": False},
    }
    [decision] = records.rows(
        owner_engine,
        "SELECT id, actor_id, action, effect, stage, reason_codes, job_attempt"
        " FROM aegis.security_decisions WHERE task_id = :id AND action = 'tool.invoke'",
        id=claim.task.task_id,
    )
    assert decision["id"] == steps[1].decision_id
    assert decision["actor_id"] == UUID("00000000-0000-4000-8000-000000000003")
    assert (decision["effect"], decision["stage"], decision["reason_codes"]) == (
        "allow",
        "policy",
        ["tool_allowed"],
    )
    assert decision["job_attempt"] == 1
    assert [
        event
        for event in records.task_events(owner_engine, claim.task.task_id)
        if event.startswith(("agent.", "tool."))
    ] == ["agent.started", "tool.invoked", "agent.finished"]


def test_each_stored_digest_is_the_digest_of_the_stored_content(
    app_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)
    _complete_run(app_engine, claim)

    with app_engine.connect() as connection:
        steps = read_steps(connection, claim.task.task_id, after=0, limit=10)

    for step in steps:
        encoded = canonical(step.content).encode()
        assert step.content_sha256 == hashlib.sha256(encoded).hexdigest()
        assert step.content_bytes == len(encoded)


def test_nul_in_tool_output_is_stored_as_a_replacement_character(
    app_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)

    result = governed(app_engine, claim, run, _reading("a\x00b")).invoke(READ)

    assert result.status is ToolStatus.OK
    with app_engine.connect() as connection:
        [step] = read_steps(connection, claim.task.task_id, after=0, limit=10)
    assert step.content["output"]["content"] == "a�b"


def test_text_that_only_looks_like_an_escape_is_stored_as_it_is(
    app_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)

    governed(app_engine, claim, run, _reading("a\\u0000b")).invoke(READ)

    with app_engine.connect() as connection:
        [step] = read_steps(connection, claim.task.task_id, after=0, limit=10)
    assert step.content["output"]["content"] == "a\\u0000b"


def test_nul_in_a_models_reply_is_stored_as_a_replacement_character(
    app_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)
    proposal = ToolCall("read_file", {"a\x00b": "c"})

    with app_engine.begin() as connection:
        run_records().model_step(connection, run, _reply(proposal, text="a\x00b"))

    with app_engine.connect() as connection:
        [step] = read_steps(connection, claim.task.task_id, after=0, limit=10)
    assert step.content["text"] == "a\ufffdb"
    assert step.content["tool_calls"] == [{"name": "read_file", "arguments": {"a\ufffdb": "c"}}]


def test_arguments_digest_is_stable_whatever_the_key_order() -> None:
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE aegis.agent_steps SET code = 'forged'",
        "DELETE FROM aegis.agent_steps",
        "UPDATE aegis.agent_runs SET scenario = 'forged'",
        "DELETE FROM aegis.agent_runs",
    ],
)
def test_the_application_role_cannot_change_or_delete_records(
    app_engine: Engine, operator: Caller, statement: str
) -> None:
    _complete_run(app_engine, claimed(app_engine, operator.actor))

    with pytest.raises(DBAPIError, match="permission denied"), app_engine.begin() as connection:
        connection.execute(text(statement))


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE aegis.agent_steps SET code = 'forged'",
        "DELETE FROM aegis.agent_steps",
        "TRUNCATE aegis.agent_steps",
        "UPDATE aegis.agent_runs SET scenario = 'forged'",
        "DELETE FROM aegis.agent_runs",
        "TRUNCATE aegis.agent_runs CASCADE",
    ],
)
def test_even_the_owner_cannot_change_or_delete_records(
    app_engine: Engine, owner_engine: Engine, operator: Caller, statement: str
) -> None:
    _complete_run(app_engine, claimed(app_engine, operator.actor))

    with pytest.raises(DBAPIError, match="append-only"), owner_engine.begin() as connection:
        connection.execute(text(statement))


def _insert_step(app_engine: Engine, run_id: UUID, sequence: int, **columns: Any) -> None:
    values = {
        "run": run_id,
        "sequence": sequence,
        "kind": "model",
        "code": "stop",
        "tool_name": None,
        "decision": None,
        **columns,
    }
    with app_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO aegis.agent_steps (run_id, sequence, kind, code, tool_name,"
                " decision_id, content, content_sha256, content_bytes)"
                " VALUES (:run, :sequence, :kind, :code, :tool_name, :decision, '{}',"
                " repeat('a', 64), 2)"
            ),
            values,
        )


def _tool_decision(app_engine: Engine, claim: Claim, run: Any, call: ToolCall = READ) -> UUID:
    # A real decision for this attempt, with no step of its own yet.
    tools = governed(app_engine, claim, run, _reading("x"))
    with app_engine.begin() as connection:
        decisions = tools._decisions
        decided = decisions.tool_invocation(
            connection,
            claim.task,
            claim.job,
            tools._request(connection, call, TOOLS[call.name]),
        )
        decisions.record(connection, decided)
    return decided.decision.decision_id


def test_steps_cannot_skip_a_number(app_engine: Engine, operator: Caller) -> None:
    run = started(app_engine, claimed(app_engine, operator.actor))

    with pytest.raises(DBAPIError, match="without gaps"):
        _insert_step(app_engine, run.run_id, 2)


def test_a_finished_run_takes_no_more_steps(app_engine: Engine, operator: Caller) -> None:
    run = _complete_run(app_engine, claimed(app_engine, operator.actor))

    with pytest.raises(DBAPIError, match="finished agent run"):
        _insert_step(app_engine, run.run_id, 5)


def test_a_stale_attempt_cannot_add_a_step_or_start_a_run(
    app_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)
    with app_engine.begin() as connection:
        jobs.finish(connection, claim.job, "test_stale")

    with pytest.raises(DBAPIError, match="needs its job running"):
        _insert_step(app_engine, run.run_id, 1)
    with pytest.raises(DBAPIError, match="needs its job running"):
        started(app_engine, claim)


def test_a_job_attempt_has_only_one_run(app_engine: Engine, operator: Caller) -> None:
    claim = claimed(app_engine, operator.actor)
    started(app_engine, claim)

    with pytest.raises(DBAPIError, match="uq_agent_runs_job_attempt"):
        started(app_engine, claim)


def test_a_tool_step_needs_a_decision(app_engine: Engine, operator: Caller) -> None:
    run = started(app_engine, claimed(app_engine, operator.actor))

    with pytest.raises(DBAPIError, match="ck_agent_steps_tool"):
        _insert_step(app_engine, run.run_id, 1, kind="tool", code="ok", tool_name="read_file")


def test_a_tool_step_cannot_use_a_decision_from_another_run(
    app_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)
    decision = _tool_decision(app_engine, claim, run)
    with app_engine.begin() as connection:
        jobs.finish(connection, claim.job, "test_done")
    other = started(app_engine, claimed(app_engine, operator.actor))

    with pytest.raises(DBAPIError, match="tool decision for this run"):
        _insert_step(
            app_engine,
            other.run_id,
            1,
            kind="tool",
            code="ok",
            tool_name="read_file",
            decision=decision,
        )


def test_a_decision_can_justify_only_one_step(app_engine: Engine, operator: Caller) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)
    decision = _tool_decision(app_engine, claim, run)
    step = {"kind": "tool", "code": "ok", "tool_name": "read_file", "decision": decision}
    _insert_step(app_engine, run.run_id, 1, **step)

    with pytest.raises(DBAPIError, match="uq_agent_steps_decision_id"):
        _insert_step(app_engine, run.run_id, 2, **step)


def test_an_allowed_decision_cannot_be_recorded_as_a_refusal(
    app_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)
    allowed = _tool_decision(app_engine, claim, run)

    with pytest.raises(DBAPIError, match="must match its decision"):
        _insert_step(
            app_engine,
            run.run_id,
            1,
            kind="tool",
            code=NOT_AUTHORIZED,
            tool_name="read_file",
            decision=allowed,
        )


def test_a_denied_decision_cannot_be_recorded_as_a_success(
    app_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim, frozenset({Capability.WORKSPACE_READ.value}))
    denied = _tool_decision(
        app_engine, claim, run, ToolCall("write_file", {"path": "a", "content": "x"})
    )

    with pytest.raises(DBAPIError, match="must match its decision"):
        _insert_step(
            app_engine,
            run.run_id,
            1,
            kind="tool",
            code="ok",
            tool_name="write_file",
            decision=denied,
        )


@pytest.fixture
def client(app_engine: Engine) -> TestClient:
    return TestClient(create_app(ApiContext(app_engine, PEPPER, RECORDER), Environment.TEST))


def _headers(caller: Caller) -> dict[str, str]:
    return {"Authorization": f"Bearer {caller.token}"}


def test_the_task_owner_reads_a_runs_steps(
    app_engine: Engine, operator: Caller, client: TestClient
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = _complete_run(app_engine, claim)

    body = client.get(f"/v1/tasks/{claim.task.task_id}/steps", headers=_headers(operator)).json()

    assert [(item["id"], item["attempt"], item["scenario"]) for item in body["runs"]] == [
        (str(run.run_id), 1, SCENARIO)
    ]
    assert [step["kind"] for step in body["steps"]] == ["model", "tool", "model", "end"]
    assert body["steps"][1]["content"]["output"]["content"] == "prot=8080\n"
    assert body["next_after"] is None


def test_steps_are_read_a_page_at_a_time(
    app_engine: Engine, operator: Caller, client: TestClient
) -> None:
    claim = claimed(app_engine, operator.actor)
    _complete_run(app_engine, claim)
    url = f"/v1/tasks/{claim.task.task_id}/steps"

    first = client.get(url, params={"limit": 3}, headers=_headers(operator)).json()
    rest = client.get(
        url, params={"limit": 3, "after": first["next_after"]}, headers=_headers(operator)
    ).json()

    assert [step["sequence"] for step in first["steps"]] == [1, 2, 3]
    assert [step["sequence"] for step in rest["steps"]] == [4]
    assert rest["next_after"] is None


def test_a_task_without_a_run_has_no_steps(
    app_engine: Engine, operator: Caller, client: TestClient
) -> None:
    claim = claimed(app_engine, operator.actor)

    body = client.get(f"/v1/tasks/{claim.task.task_id}/steps", headers=_headers(operator)).json()

    assert (body["runs"], body["steps"], body["next_after"]) == ([], [], None)


def test_another_operators_steps_look_like_a_missing_task(
    app_engine: Engine, owner_engine: Engine, operator: Caller, client: TestClient
) -> None:
    claim = claimed(app_engine, operator.actor)
    _complete_run(app_engine, claim)
    other = make_caller(owner_engine, Role.OPERATOR, prefix="steps-other")

    response = client.get(f"/v1/tasks/{claim.task.task_id}/steps", headers=_headers(other))
    missing = client.get(f"/v1/tasks/{uuid4()}/steps", headers=_headers(other))

    assert response.status_code == missing.status_code == 404
    assert response.json()["code"] == missing.json()["code"]


def test_an_auditors_read_is_audited_as_privileged(
    app_engine: Engine, owner_engine: Engine, operator: Caller, client: TestClient
) -> None:
    claim = claimed(app_engine, operator.actor)
    _complete_run(app_engine, claim)
    auditor = make_caller(owner_engine, Role.AUDITOR, prefix="steps-auditor")

    response = client.get(f"/v1/tasks/{claim.task.task_id}/steps", headers=_headers(auditor))

    assert response.status_code == 200
    assert "task.read_privileged" in records.task_events(owner_engine, claim.task.task_id)

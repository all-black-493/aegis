import logging
from dataclasses import replace
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError

from aegis.agents.records import FINISHED, NOT_AUTHORIZED
from aegis.audit.events import AuditEvent, AuditEventType
from aegis.audit.recorder import AuditRecorder
from aegis.authorization.catalog import IdentityKind, Role
from aegis.config.logs import Redactor
from aegis.identity.admin import IdentityAdministration
from aegis.jobs import repository as jobs
from aegis.jobs.settlement import Claim
from aegis.model_providers.steps import ToolCall
from aegis.runtime.contract import ExecResult
from aegis.tool_registry.catalog import TOOLS
from aegis.tool_registry.model import (
    Approval,
    Capability,
    NetworkAccess,
    Risk,
    ToolStatus,
)
from tests.fixtures import records
from tests.fixtures.agent_runs import claimed, governed, run_records, started
from tests.fixtures.fake_runtime import FakeRuntime
from tests.fixtures.services import RECORDER, Caller

READ = ToolCall("read_file", {"path": "a.txt"})
SECRET_ARGUMENT = "ARGUMENT-MARKER-5c1e"
SECRET_OUTPUT = "OUTPUT-MARKER-a07d"
pytestmark = pytest.mark.usefixtures("isolated_jobs")


def _decisions(owner_engine: Engine, claim: Claim) -> list[dict[str, Any]]:
    return records.rows(
        owner_engine,
        "SELECT effect, stage, reason_codes FROM aegis.security_decisions"
        " WHERE task_id = :id AND action = 'tool.invoke' ORDER BY decided_at",
        id=claim.task.task_id,
    )


def _denied_events(owner_engine: Engine, claim: Claim) -> list[dict[str, Any]]:
    return records.rows(
        owner_engine,
        "SELECT event_type, reason_code FROM aegis.audit_events"
        " WHERE task_id = :id AND outcome = 'denied' ORDER BY id",
        id=claim.task.task_id,
    )


def _execs(runtime: FakeRuntime) -> list[str]:
    return [call for call in runtime.calls if call.startswith("exec ")]


def test_a_registered_tool_inside_the_runs_capabilities_runs(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)
    runtime = FakeRuntime()

    result = governed(app_engine, claim, run, runtime).invoke(READ)

    assert result.status is ToolStatus.OK
    assert len(_execs(runtime)) == 1
    assert _decisions(owner_engine, claim)[0]["reason_codes"] == ["tool_allowed"]


def test_an_unregistered_tool_is_denied_audited_and_never_run(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)
    runtime = FakeRuntime()

    result = governed(app_engine, claim, run, runtime).invoke(ToolCall("shell", {"command": "id"}))

    assert (result.status, result.code) == (ToolStatus.REFUSED, NOT_AUTHORIZED)
    assert result.output == {"reasons": ["tool_not_registered"]}
    assert _execs(runtime) == []
    assert _decisions(owner_engine, claim) == [
        {"effect": "deny", "stage": "policy", "reason_codes": ["tool_not_registered"]}
    ]
    assert {event["event_type"] for event in _denied_events(owner_engine, claim)} == {
        "security.decision",
        "tool.invoked",
    }


def test_a_tool_outside_the_runs_capabilities_is_denied(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim, frozenset({Capability.WORKSPACE_READ.value}))
    runtime = FakeRuntime()
    write = ToolCall("write_file", {"path": "a.txt", "content": "x"})

    result = governed(app_engine, claim, run, runtime).invoke(write)
    allowed = governed(app_engine, claim, run, runtime).invoke(READ)

    assert result.output == {"reasons": ["capability_not_granted"]}
    assert allowed.status is ToolStatus.OK
    assert len(_execs(runtime)) == 1


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"risk": Risk.HIGH}, "tool_beyond_low_risk"),
        ({"risk": Risk.MEDIUM}, "tool_beyond_low_risk"),
        ({"network": NetworkAccess.RESTRICTED}, "tool_beyond_low_risk"),
        ({"approval": Approval.REQUIRED}, "tool_beyond_low_risk"),
        ({"permitted_roles": frozenset({"operator"})}, "tool_role_not_permitted"),
    ],
)
def test_a_tool_beyond_what_phase_4_permits_is_denied_however_it_is_registered(
    app_engine: Engine, operator: Caller, change: dict[str, Any], reason: str
) -> None:
    # Escalation by registration: a riskier definition must not get through because it exists.
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)
    runtime = FakeRuntime()
    tools = {"read_file": replace(TOOLS["read_file"], **change)}

    result = governed(app_engine, claim, run, runtime, tools).invoke(READ)

    assert result.code == NOT_AUTHORIZED
    assert result.output == {"reasons": [reason]}
    assert _execs(runtime) == []


def _disable(owner_engine: Engine, caller: Caller) -> None:
    with owner_engine.begin() as connection:
        IdentityAdministration(connection, RECORDER).disable_identity(caller.name)


def _revoke(owner_engine: Engine, caller: Caller) -> None:
    with owner_engine.begin() as connection:
        IdentityAdministration(connection, RECORDER).revoke_credential(caller.credential_id)


def _drop_role(owner_engine: Engine, caller: Caller) -> None:
    with owner_engine.begin() as connection:
        IdentityAdministration(connection, RECORDER).revoke_role(caller.name, Role.OPERATOR)


@pytest.mark.parametrize(
    ("withdraw", "reason"),
    [
        (_disable, "initiator_disabled"),
        (_revoke, "submitting_credential_revoked"),
        (_drop_role, "initiator_not_authorized"),
    ],
)
def test_an_agent_loses_its_delegation_the_moment_its_initiator_does(
    app_engine: Engine, owner_engine: Engine, operator: Caller, withdraw: Any, reason: str
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)
    runtime = FakeRuntime()
    tools = governed(app_engine, claim, run, runtime)
    assert tools.invoke(READ).status is ToolStatus.OK

    withdraw(owner_engine, operator)
    result = tools.invoke(READ)

    assert result.output == {"reasons": [reason]}
    assert len(_execs(runtime)) == 1
    assert reason in [event["reason_code"] for event in _denied_events(owner_engine, claim)]


def test_a_finished_run_can_invoke_nothing_and_the_refusal_is_still_recorded(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)
    runtime = FakeRuntime()
    with app_engine.begin() as connection:
        run_records().end(connection, run, FINISHED, {})

    result = governed(app_engine, claim, run, runtime).invoke(READ)

    assert result.output == {"reasons": ["run_not_active"]}
    assert _execs(runtime) == []
    assert _decisions(owner_engine, claim)[0]["reason_codes"] == ["run_not_active"]


def test_a_stale_attempt_can_invoke_nothing(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)
    runtime = FakeRuntime()
    with app_engine.begin() as connection:
        jobs.finish(connection, claim.job, "test_stale")

    result = governed(app_engine, claim, run, runtime).invoke(READ)

    assert result.output == {"reasons": ["run_not_active"]}
    assert _execs(runtime) == []


def test_tool_content_stays_in_the_run_records(
    app_engine: Engine,
    owner_engine: Engine,
    operator: Caller,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)
    call = ToolCall("read_file", {"path": f"{SECRET_ARGUMENT}.txt"})
    tool = TOOLS["read_file"]
    argv = tool.command(call.arguments, tool.limits)
    runtime = FakeRuntime(results={argv: ExecResult(0, SECRET_OUTPUT, "")})
    denied = ToolCall("shell", {"command": SECRET_ARGUMENT})

    governed(app_engine, claim, run, runtime).invoke(call)
    governed(app_engine, claim, run, runtime).invoke(denied)

    def stored(table: str) -> str:
        found = records.rows(
            owner_engine,
            f"SELECT row_to_json(t)::text AS row FROM aegis.{table} t WHERE task_id = :id",
            id=claim.task.task_id,
        )
        return "\n".join(row["row"] for row in found)

    for secret in (SECRET_ARGUMENT, SECRET_OUTPUT):
        assert secret not in stored("audit_events")
        assert secret not in stored("security_decisions")
        assert secret not in caplog.text
    steps = records.rows(
        owner_engine,
        "SELECT content::text AS content FROM aegis.agent_steps WHERE run_id = :id",
        id=run.run_id,
    )
    assert SECRET_OUTPUT in "\n".join(row["content"] for row in steps)


class _Refusing(AuditRecorder):
    def __init__(self, refused: AuditEventType) -> None:
        super().__init__(Redactor())
        self._refused = refused

    def record(self, connection: Connection, event: AuditEvent) -> None:
        if event.event_type is self._refused:
            raise OSError("the audit store refused the write")
        super().record(connection, event)


def test_a_call_whose_decision_cannot_be_audited_never_runs(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)
    runtime = FakeRuntime()
    tools = governed(
        app_engine,
        claim,
        run,
        runtime,
        recorder=_Refusing(AuditEventType.SECURITY_DECISION),
    )

    with pytest.raises(OSError, match="refused the write"):
        tools.invoke(READ)

    assert _execs(runtime) == []
    assert _decisions(owner_engine, claim) == []


def test_a_failed_audit_write_raises_and_leaves_no_step(
    app_engine: Engine, owner_engine: Engine, operator: Caller
) -> None:
    claim = claimed(app_engine, operator.actor)
    run = started(app_engine, claim)
    tools = governed(
        app_engine,
        claim,
        run,
        FakeRuntime(),
        recorder=_Refusing(AuditEventType.TOOL_INVOKED),
    )

    with pytest.raises(OSError, match="refused the write"):
        tools.invoke(READ)

    steps = records.rows(
        owner_engine, "SELECT id FROM aegis.agent_steps WHERE run_id = :id", id=run.run_id
    )
    assert steps == []


def test_the_agent_identity_cannot_hold_a_credential_or_a_human_role(
    owner_engine: Engine,
) -> None:
    agent = "00000000-0000-4000-8000-000000000003"
    with (
        pytest.raises(DBAPIError, match="role operator cannot be held"),
        owner_engine.begin() as connection,
    ):
        connection.execute(
            text(
                "INSERT INTO aegis.identity_roles (identity_id, role, granted_by)"
                " VALUES (:agent, 'operator', :agent)"
            ),
            {"agent": agent},
        )
    with (
        pytest.raises(DBAPIError, match="credentials"),
        owner_engine.begin() as connection,
    ):
        connection.execute(
            text(
                "INSERT INTO aegis.credentials (id, identity_id, lookup_id, secret_hash,"
                " hash_scheme, expires_at)"
                " VALUES (:id, :agent, :lookup, :secret, 'x', now() + interval '1 day')"
            ),
            {"id": uuid4(), "agent": agent, "lookup": uuid4().hex, "secret": b"x" * 32},
        )
    [row] = records.rows(
        owner_engine,
        "SELECT i.kind, array_agg(r.role) AS roles FROM aegis.identities i"
        " JOIN aegis.identity_roles r ON r.identity_id = i.id WHERE i.id = :agent GROUP BY i.kind",
        agent=agent,
    )
    assert (row["kind"], row["roles"]) == (IdentityKind.SYSTEM.value, ["agent"])

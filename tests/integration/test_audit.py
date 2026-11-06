from collections.abc import Iterator
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from psycopg import errors
from psycopg.rows import TupleRow
from sqlalchemy import Engine, create_engine, select, text
from sqlalchemy.exc import IntegrityError

from aegis.agents.schema import agent_runs, agent_steps
from aegis.audit.events import ALLOWED_DETAILS, AuditEvent, AuditEventType, Outcome, Source
from aegis.audit.recorder import AuditError, AuditRecorder
from aegis.audit.schema import audit_events
from aegis.config.logs import REDACTED, Redactor
from aegis.config.settings import DatabaseSettings
from aegis.db.engine import connect
from aegis.db.metadata import SCHEMA, metadata
from aegis.identity.schema import credentials, identities, identity_roles
from aegis.jobs.schema import jobs
from aegis.tasks.schema import (
    security_decisions,
    task_state_transitions,
    task_transition_rules,
    tasks,
)

FAKE_SECRET = "fake-secret-value-0123456789abcdef"
INSERT_COLUMNS = "event_id, event_type, source, outcome"
VALID_VALUES = "gen_random_uuid(), 'task.created', 'api', 'success'"


def _event(event_type: AuditEventType = AuditEventType.TASK_CREATED, **extra: Any) -> AuditEvent:
    details = dict.fromkeys(ALLOWED_DETAILS[event_type], "x")
    return AuditEvent(
        event_type=event_type,
        source=Source.SYSTEM,
        outcome=Outcome.SUCCESS,
        details=details,
        **extra,
    )


def _stored(engine: Engine, *event_ids: UUID) -> list[dict[str, Any]]:
    with engine.connect() as connection:
        rows = connection.execute(
            select(audit_events).where(audit_events.c.event_id.in_(event_ids))
        ).mappings()
        return [dict(row) for row in rows]


def _autocommit(settings: DatabaseSettings) -> psycopg.Connection[TupleRow]:
    return connect(settings, autocommit=True, application_name="aegis-tests")


@pytest.fixture
def probe(owner_engine: Engine) -> Iterator[None]:
    with owner_engine.begin() as connection:
        connection.execute(text("CREATE TABLE aegis.audit_probe (id uuid PRIMARY KEY)"))
        connection.execute(text("GRANT INSERT, SELECT ON aegis.audit_probe TO aegis_app"))
    yield
    with owner_engine.begin() as connection:
        connection.execute(text("DROP TABLE aegis.audit_probe"))


def _probe_exists(engine: Engine, probe_id: UUID) -> bool:
    with engine.connect() as connection:
        found = connection.execute(
            text("SELECT 1 FROM aegis.audit_probe WHERE id = :id"), {"id": probe_id}
        ).first()
        return found is not None


def test_application_role_can_record_every_event_type(
    app_engine: Engine, owner_engine: Engine
) -> None:
    events = [_event(event_type) for event_type in AuditEventType]

    with app_engine.begin() as connection:
        for event in events:
            AuditRecorder(Redactor()).record(connection, event)

    stored = _stored(owner_engine, *(event.event_id for event in events))
    assert {row["event_type"] for row in stored} == {
        event_type.value for event_type in AuditEventType
    }
    assert all(row["occurred_at"] is not None for row in stored)


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT * FROM aegis.audit_events",
        "UPDATE aegis.audit_events SET outcome = 'failure'",
        "DELETE FROM aegis.audit_events",
        "TRUNCATE aegis.audit_events",
        f"INSERT INTO aegis.audit_events ({INSERT_COLUMNS}, occurred_at)"
        f" VALUES ({VALID_VALUES}, '2000-01-01')",
        f"INSERT INTO aegis.audit_events (id, {INSERT_COLUMNS}) OVERRIDING SYSTEM VALUE"
        f" VALUES (1, {VALID_VALUES})",
    ],
)
def test_application_role_cannot_read_change_or_backdate_events(
    app_settings: DatabaseSettings, statement: str
) -> None:
    with _autocommit(app_settings) as connection, pytest.raises(errors.InsufficientPrivilege):
        connection.execute(statement.encode())


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE aegis.audit_events SET outcome = 'failure'",
        "DELETE FROM aegis.audit_events",
        "TRUNCATE aegis.audit_events",
    ],
)
def test_triggers_stop_even_the_owner_from_changing_events(
    owner_settings: DatabaseSettings, owner_engine: Engine, statement: str
) -> None:
    event = _event()
    with owner_engine.begin() as connection:
        AuditRecorder(Redactor()).record(connection, event)

    with (
        _autocommit(owner_settings) as connection,
        pytest.raises(errors.RaiseException, match="append-only"),
    ):
        connection.execute(statement.encode())

    assert len(_stored(owner_engine, event.event_id)) == 1


def test_database_sets_the_event_time(owner_settings: DatabaseSettings) -> None:
    with _autocommit(owner_settings) as connection, connection.transaction():
        row = connection.execute(
            f"INSERT INTO aegis.audit_events ({INSERT_COLUMNS}, occurred_at)"
            f" VALUES ({VALID_VALUES}, '2000-01-01') RETURNING occurred_at, now()"
        ).fetchone()

    assert row is not None
    assert row[0] == row[1]


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("details", "'[]'::jsonb"),
        ("details", "jsonb_build_object('a', repeat('x', 5000))"),
        ("event_type", "'Bad Type'"),
        ("source", "'browser'"),
        ("actor_id", "gen_random_uuid()"),
        ("reason_code", "'Bad Code'"),
        ("target_type", "'task'"),
    ],
)
def test_database_rejects_malformed_events(
    app_settings: DatabaseSettings, column: str, value: str
) -> None:
    values = {
        "event_id": "gen_random_uuid()",
        "event_type": "'task.created'",
        "source": "'api'",
        "outcome": "'success'",
        column: value,
    }
    statement = (
        f"INSERT INTO aegis.audit_events ({', '.join(values)})"
        f" VALUES ({', '.join(values.values())})"
    )

    with _autocommit(app_settings) as connection, pytest.raises(errors.CheckViolation):
        connection.execute(statement.encode())


@pytest.mark.usefixtures("probe")
def test_audit_events_commit_with_the_operation(app_engine: Engine, owner_engine: Engine) -> None:
    probe_id, event = uuid4(), _event()

    with app_engine.begin() as connection:
        connection.execute(
            text("INSERT INTO aegis.audit_probe (id) VALUES (:id)"), {"id": probe_id}
        )
        AuditRecorder(Redactor()).record(connection, event)

    assert _probe_exists(owner_engine, probe_id)
    assert len(_stored(owner_engine, event.event_id)) == 1


def _operation_whose_audit_write_fails(engine: Engine, probe_id: UUID, event: AuditEvent) -> None:
    recorder = AuditRecorder(Redactor())
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO aegis.audit_probe (id) VALUES (:id)"), {"id": probe_id}
        )
        recorder.record(connection, event)
        recorder.record(connection, event)


@pytest.mark.usefixtures("probe")
def test_a_failed_audit_write_rolls_back_the_operation(
    app_engine: Engine, owner_engine: Engine
) -> None:
    probe_id, event = uuid4(), _event()

    with pytest.raises(IntegrityError):
        _operation_whose_audit_write_fails(app_engine, probe_id, event)

    assert not _probe_exists(owner_engine, probe_id)
    assert _stored(owner_engine, event.event_id) == []


def test_recording_outside_a_transaction_is_refused(
    app_engine: Engine, owner_engine: Engine
) -> None:
    event = _event()

    with app_engine.connect() as connection, pytest.raises(AuditError, match="transaction"):
        AuditRecorder(Redactor()).record(connection, event)

    assert _stored(owner_engine, event.event_id) == []


def test_secrets_are_redacted_before_storage(app_engine: Engine, owner_engine: Engine) -> None:
    event = AuditEvent(
        event_type=AuditEventType.IDENTITY_CREATED,
        source=Source.CLI,
        outcome=Outcome.SUCCESS,
        target_type="identity",
        target_id=f"password={FAKE_SECRET[:20]}",
        details={"kind": "human", "name": f"named {FAKE_SECRET}"},
    )

    with app_engine.begin() as connection:
        AuditRecorder(Redactor([FAKE_SECRET])).record(connection, event)

    [row] = _stored(owner_engine, event.event_id)
    assert FAKE_SECRET[:20] not in str(row)
    assert row["details"]["name"] == f"named {REDACTED}"


def _include_name(name: str | None, kind: str, _parents: Any) -> bool:
    return kind != "schema" or name == SCHEMA


def _include_object(_obj: Any, name: str | None, kind: str, _reflected: bool, _other: Any) -> bool:
    return not (kind == "table" and name == "alembic_version")


def test_table_definitions_match_the_migrated_schema(owner_engine: Engine) -> None:
    assert set(metadata.tables.values()) == {
        agent_runs,
        agent_steps,
        audit_events,
        identities,
        identity_roles,
        credentials,
        tasks,
        security_decisions,
        task_transition_rules,
        task_state_transitions,
        jobs,
    }
    engine = create_engine(owner_engine.url, connect_args={"options": "-c search_path=public"})
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection,
                opts={
                    "include_schemas": True,
                    "include_name": _include_name,
                    "include_object": _include_object,
                },
            )
            differences = compare_metadata(context, metadata)
    finally:
        engine.dispose()

    assert differences == []

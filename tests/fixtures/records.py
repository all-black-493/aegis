from typing import Any
from uuid import UUID

from sqlalchemy import Connection, Engine, text

from aegis.jobs.repository import claim, create_job
from aegis.tasks.repository import TaskRecord, get_task
from aegis.tasks.transitions import JobRef


def rows(engine: Engine, sql: str, **params: Any) -> list[dict[str, Any]]:
    with engine.connect() as connection:
        return [dict(row) for row in connection.execute(text(sql), params).mappings()]


def task(app_engine: Engine, task_id: UUID) -> TaskRecord:
    with app_engine.connect() as connection:
        found = get_task(connection, task_id)
    assert found is not None
    return found


def task_events(owner_engine: Engine, task_id: UUID) -> list[str]:
    found = rows(
        owner_engine,
        "SELECT event_type FROM aegis.audit_events WHERE task_id = :id ORDER BY id",
        id=task_id,
    )
    return [row["event_type"] for row in found]


def latest_job(owner_engine: Engine, task_id: UUID) -> dict[str, Any]:
    found = rows(
        owner_engine,
        "SELECT * FROM aegis.jobs WHERE task_id = :id ORDER BY created_at DESC",
        id=task_id,
    )
    assert found, "the task has no job"
    return found[0]


def claim_job(connection: Connection, task: TaskRecord) -> JobRef:
    job = claim(
        connection,
        create_job(connection, task.task_id, max_attempts=3, correlation_id=None),
        "test-worker",
        60,
    )
    assert job is not None
    return job.ref

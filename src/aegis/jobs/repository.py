from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import (
    ColumnElement,
    Connection,
    Interval,
    RowMapping,
    func,
    insert,
    literal,
    select,
    update,
)

from aegis.jobs.schema import jobs
from aegis.tasks.schema import tasks
from aegis.tasks.states import TaskState
from aegis.tasks.transitions import JobRef


class JobState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    FINISHED = "finished"


@dataclass(frozen=True)
class JobRecord:
    job_id: UUID
    task_id: UUID
    state: JobState
    attempt: int
    max_attempts: int
    run_after: datetime
    lease_owner: str | None
    lease_expires_at: datetime | None
    heartbeat_at: datetime | None
    last_error_code: str | None
    correlation_id: str | None
    created_at: datetime
    updated_at: datetime
    finished_at: datetime | None

    @property
    def ref(self) -> JobRef:
        return JobRef(self.job_id, self.attempt)


def create_job(
    connection: Connection, task_id: UUID, *, max_attempts: int, correlation_id: str | None
) -> JobRecord:
    row = connection.execute(
        insert(jobs)
        .values(
            id=uuid4(),
            task_id=task_id,
            max_attempts=max_attempts,
            correlation_id=correlation_id,
        )
        .returning(jobs)
    ).mappings()
    return _record(row.one())


def get_job(connection: Connection, job_id: UUID) -> JobRecord | None:
    row = connection.execute(select(jobs).where(jobs.c.id == job_id)).mappings().first()
    return None if row is None else _record(row)


def next_due(connection: Connection) -> tuple[UUID, UUID] | None:
    # Every writer locks a task before its job; locking the task here, skipping tasks another
    # worker holds, keeps that order and lets racing workers each take a different task.
    row = connection.execute(
        select(tasks.c.id, jobs.c.id)
        .join(jobs, jobs.c.task_id == tasks.c.id)
        .where(
            jobs.c.state == JobState.PENDING.value,
            jobs.c.run_after <= func.now(),
            tasks.c.state == TaskState.QUEUED.value,
        )
        .order_by(jobs.c.run_after, jobs.c.id)
        .limit(1)
        .with_for_update(of=tasks, key_share=True, skip_locked=True)
    ).first()
    return None if row is None else (row[0], row[1])


def next_expired(connection: Connection) -> tuple[UUID, UUID] | None:
    row = connection.execute(
        select(tasks.c.id, jobs.c.id)
        .join(jobs, jobs.c.task_id == tasks.c.id)
        .where(jobs.c.state == JobState.RUNNING.value, jobs.c.lease_expires_at <= func.now())
        .order_by(jobs.c.lease_expires_at, jobs.c.id)
        .limit(1)
        .with_for_update(of=tasks, key_share=True, skip_locked=True)
    ).first()
    return None if row is None else (row[0], row[1])


def live_job_ids(connection: Connection) -> frozenset[UUID]:
    rows = connection.execute(
        select(jobs.c.id).where(_running(), jobs.c.lease_expires_at > func.now())
    )
    return frozenset(rows.scalars())


def lock_job(connection: Connection, job_id: UUID) -> JobRecord | None:
    row = (
        connection.execute(select(jobs).where(jobs.c.id == job_id).with_for_update(key_share=True))
        .mappings()
        .first()
    )
    return None if row is None else _record(row)


def lock_fenced(connection: Connection, ref: JobRef) -> JobRecord | None:
    row = (
        connection.execute(select(jobs).where(*_fence(ref)).with_for_update(key_share=True))
        .mappings()
        .first()
    )
    return None if row is None else _record(row)


def claim(
    connection: Connection, job: JobRecord, owner: str, lease_seconds: float
) -> JobRecord | None:
    return _update(
        connection,
        (
            jobs.c.id == job.job_id,
            jobs.c.state == JobState.PENDING.value,
            jobs.c.attempt == job.attempt,
        ),
        state=JobState.RUNNING.value,
        attempt=job.attempt + 1,
        lease_owner=owner,
        lease_expires_at=_after(lease_seconds),
        heartbeat_at=func.now(),
    )


def renew(connection: Connection, ref: JobRef, lease_seconds: float) -> JobRecord | None:
    return _update(
        connection,
        _fence(ref),
        lease_expires_at=_after(lease_seconds),
        heartbeat_at=func.now(),
    )


def reschedule(connection: Connection, ref: JobRef, delay_seconds: float) -> JobRecord | None:
    return _update(
        connection,
        (jobs.c.id == ref.job_id, jobs.c.attempt == ref.attempt, _running()),
        state=JobState.PENDING.value,
        run_after=_after(delay_seconds),
        lease_owner=None,
        lease_expires_at=None,
    )


def finish(connection: Connection, ref: JobRef, error_code: str | None) -> JobRecord | None:
    return _update(
        connection,
        (jobs.c.id == ref.job_id, jobs.c.attempt == ref.attempt, _running()),
        state=JobState.FINISHED.value,
        lease_owner=None,
        lease_expires_at=None,
        last_error_code=error_code,
    )


def finish_pending(connection: Connection, task_id: UUID, error_code: str) -> JobRecord | None:
    return _update(
        connection,
        (jobs.c.task_id == task_id, jobs.c.state == JobState.PENDING.value),
        state=JobState.FINISHED.value,
        last_error_code=error_code,
    )


def _fence(ref: JobRef) -> tuple[ColumnElement[bool], ...]:
    return (
        jobs.c.id == ref.job_id,
        jobs.c.attempt == ref.attempt,
        _running(),
        jobs.c.lease_expires_at > func.now(),
    )


def _running() -> ColumnElement[bool]:
    return jobs.c.state == JobState.RUNNING.value


def _after(seconds: float) -> ColumnElement[datetime]:
    return func.now() + literal(timedelta(seconds=seconds), Interval())


def _update(
    connection: Connection, conditions: tuple[ColumnElement[bool], ...], **values: object
) -> JobRecord | None:
    row = (
        connection.execute(update(jobs).where(*conditions).values(values).returning(jobs))
        .mappings()
        .first()
    )
    return None if row is None else _record(row)


def _record(row: RowMapping) -> JobRecord:
    return JobRecord(
        job_id=row["id"],
        task_id=row["task_id"],
        state=JobState(row["state"]),
        attempt=row["attempt"],
        max_attempts=row["max_attempts"],
        run_after=row["run_after"],
        lease_owner=row["lease_owner"],
        lease_expires_at=row["lease_expires_at"],
        heartbeat_at=row["heartbeat_at"],
        last_error_code=row["last_error_code"],
        correlation_id=row["correlation_id"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        finished_at=row["finished_at"],
    )

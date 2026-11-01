from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, RowMapping, func, insert, select, tuple_, update

from aegis.authorization.contract import DecisionMismatchError, SecurityDecision
from aegis.tasks.schema import security_decisions, task_state_transitions, tasks
from aegis.tasks.states import TaskKind, TaskState


@dataclass(frozen=True)
class NewTask:
    task_id: UUID
    initiator_id: UUID
    submitted_credential_id: UUID
    kind: TaskKind
    input: Mapping[str, Any]
    idempotency_key: str
    request_fingerprint: str


@dataclass(frozen=True)
class TaskRecord:
    task_id: UUID
    initiator_id: UUID
    owner_id: UUID
    submitted_credential_id: UUID
    kind: TaskKind
    input: Mapping[str, Any]
    state: TaskState
    version: int
    idempotency_key: str
    request_fingerprint: str
    cancel_requested_at: datetime | None
    cancel_requested_by: UUID | None
    result: Mapping[str, Any] | None
    failure_code: str | None
    created_at: datetime
    updated_at: datetime
    finished_at: datetime | None


@dataclass(frozen=True)
class TransitionRow:
    task_id: UUID
    to_version: int
    from_state: TaskState
    to_state: TaskState
    actor_id: UUID
    reason_code: str
    decision: SecurityDecision | None
    job_id: UUID | None
    job_attempt: int | None
    request_id: str | None


@dataclass(frozen=True)
class Position:
    created_at: datetime
    task_id: UUID


def transaction_time(connection: Connection) -> datetime:
    now: datetime = connection.execute(select(func.now())).scalar_one()
    return now


def insert_task(connection: Connection, new: NewTask) -> TaskRecord:
    row = connection.execute(
        insert(tasks)
        .values(
            id=new.task_id,
            initiator_id=new.initiator_id,
            owner_id=new.initiator_id,
            submitted_credential_id=new.submitted_credential_id,
            kind=new.kind.value,
            input=dict(new.input),
            idempotency_key=new.idempotency_key,
            request_fingerprint=new.request_fingerprint,
        )
        .returning(tasks)
    ).mappings()
    return _record(row.one())


def get_task(connection: Connection, task_id: UUID) -> TaskRecord | None:
    row = connection.execute(select(tasks).where(tasks.c.id == task_id)).mappings().first()
    return None if row is None else _record(row)


def find_by_idempotency_key(
    connection: Connection, initiator_id: UUID, idempotency_key: str
) -> TaskRecord | None:
    row = (
        connection.execute(
            select(tasks).where(
                tasks.c.initiator_id == initiator_id, tasks.c.idempotency_key == idempotency_key
            )
        )
        .mappings()
        .first()
    )
    return None if row is None else _record(row)


def list_tasks(
    connection: Connection, *, owner_id: UUID | None, limit: int, after: Position | None
) -> list[TaskRecord]:
    query = select(tasks).order_by(tasks.c.created_at.desc(), tasks.c.id.desc()).limit(limit)
    if owner_id is not None:
        query = query.where(tasks.c.owner_id == owner_id)
    if after is not None:
        query = query.where(
            tuple_(tasks.c.created_at, tasks.c.id) < tuple_(after.created_at, after.task_id)
        )
    return [_record(row) for row in connection.execute(query).mappings()]


def lock_task(connection: Connection, task_id: UUID) -> TaskRecord | None:
    # FOR NO KEY UPDATE does not conflict with the key-share locks taken by foreign keys from
    # decisions and history, so concurrent transitions conflict instead of deadlocking.
    row = (
        connection.execute(
            select(tasks).where(tasks.c.id == task_id).with_for_update(key_share=True)
        )
        .mappings()
        .first()
    )
    return None if row is None else _record(row)


def record_decision(
    connection: Connection,
    decision: SecurityDecision,
    inputs: Mapping[str, Any] | None = None,
) -> None:
    decided_at = connection.execute(
        insert(security_decisions)
        .values(
            id=decision.decision_id,
            actor_id=decision.actor_id,
            actor_kind=decision.actor_kind.value,
            actor_credential_id=decision.actor_credential_id,
            subject_id=decision.subject_id,
            action=decision.action.value,
            resource_type=decision.resource_type.value,
            resource_id=decision.resource_id,
            resource_owner_id=decision.resource_owner_id,
            task_id=decision.task_id,
            effect=decision.effect.value,
            stage=decision.stage.value,
            reason_codes=list(decision.reason_codes),
            policy_version=decision.policy_version,
            policy_digest=decision.policy_digest,
            request_id=decision.request_id,
            job_id=decision.job_id,
            job_attempt=decision.job_attempt,
            inputs=dict(inputs or {}),
        )
        .returning(security_decisions.c.decided_at)
    ).scalar_one()
    if decided_at != decision.decided_at:
        raise DecisionMismatchError(("C8",))


def insert_transition(connection: Connection, row: TransitionRow) -> None:
    decision = row.decision
    connection.execute(
        insert(task_state_transitions).values(
            task_id=row.task_id,
            to_version=row.to_version,
            from_state=row.from_state.value,
            to_state=row.to_state.value,
            actor_id=row.actor_id,
            reason_code=row.reason_code,
            decision_id=decision.decision_id if decision else None,
            decision_action=decision.action.value if decision else None,
            decision_effect=decision.effect.value if decision else None,
            decision_stage=decision.stage.value if decision else None,
            decision_decided_at=decision.decided_at if decision else None,
            job_id=row.job_id,
            job_attempt=row.job_attempt,
            request_id=row.request_id,
        )
    )


def update_state(
    connection: Connection,
    task: TaskRecord,
    target: TaskState,
    *,
    result: Mapping[str, Any] | None = None,
    failure_code: str | None = None,
) -> TaskRecord | None:
    values: dict[str, Any] = {"state": target.value, "version": task.version + 1}
    if result is not None:
        values["result"] = dict(result)
    if failure_code is not None:
        values["failure_code"] = failure_code
    row = (
        connection.execute(
            update(tasks)
            .where(
                tasks.c.id == task.task_id,
                tasks.c.state == task.state.value,
                tasks.c.version == task.version,
            )
            .values(values)
            .returning(tasks)
        )
        .mappings()
        .first()
    )
    return None if row is None else _record(row)


def request_cancellation(
    connection: Connection, task: TaskRecord, requested_by: UUID
) -> TaskRecord | None:
    row = (
        connection.execute(
            update(tasks)
            .where(
                tasks.c.id == task.task_id,
                tasks.c.state == task.state.value,
                tasks.c.version == task.version,
                tasks.c.cancel_requested_by.is_(None),
            )
            .values(cancel_requested_by=requested_by)
            .returning(tasks)
        )
        .mappings()
        .first()
    )
    return None if row is None else _record(row)


def _record(row: RowMapping) -> TaskRecord:
    return TaskRecord(
        task_id=row["id"],
        initiator_id=row["initiator_id"],
        owner_id=row["owner_id"],
        submitted_credential_id=row["submitted_credential_id"],
        kind=TaskKind(row["kind"]),
        input=row["input"],
        state=TaskState(row["state"]),
        version=row["version"],
        idempotency_key=row["idempotency_key"],
        request_fingerprint=row["request_fingerprint"],
        cancel_requested_at=row["cancel_requested_at"],
        cancel_requested_by=row["cancel_requested_by"],
        result=row["result"],
        failure_code=row["failure_code"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        finished_at=row["finished_at"],
    )

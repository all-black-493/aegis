import re
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg import errors
from sqlalchemy import Connection, Engine, select, text
from sqlalchemy.exc import DBAPIError

from aegis.audit.events import Source
from aegis.audit.recorder import AuditRecorder
from aegis.audit.schema import audit_events
from aegis.authorization.catalog import Action, IdentityKind, ResourceType, Role
from aegis.authorization.contract import (
    DecisionMismatchError,
    Effect,
    SecurityDecision,
    Stage,
)
from aegis.config.logs import Redactor
from aegis.config.settings import Secret
from aegis.identity.admin import IdentityAdministration
from aegis.identity.schema import SYSTEM_WORKER_ID
from aegis.tasks.repository import (
    NewTask,
    TaskRecord,
    get_task,
    insert_task,
    record_decision,
    transaction_time,
)
from aegis.tasks.schema import task_state_transitions
from aegis.tasks.states import TRANSITION_RULES, TaskKind, TaskState
from aegis.tasks.transitions import (
    IllegalTransitionError,
    JobRef,
    PolicyRef,
    Transition,
    TransitionConflictError,
    apply_transition,
)

POLICY = PolicyRef("test-policy-1", "a" * 64)
RECORDER = AuditRecorder(Redactor())
S = TaskState


@dataclass(frozen=True)
class Person:
    identity_id: UUID
    credential_id: UUID


@pytest.fixture
def person(owner_engine: Engine) -> Person:
    return _person(owner_engine)


@pytest.fixture
def app_tx(app_engine: Engine) -> Iterator[Connection]:
    with app_engine.connect() as connection:
        transaction = connection.begin()
        yield connection
        if transaction.is_active:
            transaction.rollback()


def _person(owner_engine: Engine) -> Person:
    name = f"tasks-{uuid4().hex[:12]}"
    with owner_engine.begin() as connection:
        administration = IdentityAdministration(connection, AuditRecorder(Redactor()))
        identity_id = administration.create_identity(name, IdentityKind.HUMAN, [Role.OPERATOR])
        issued = administration.issue_credential(name, Secret("p" * 32))
    return Person(identity_id, issued.credential_id)


def _new_task(connection: Connection, person: Person) -> TaskRecord:
    return insert_task(
        connection,
        NewTask(
            task_id=uuid4(),
            initiator_id=person.identity_id,
            submitted_credential_id=person.credential_id,
            kind=TaskKind.NOOP,
            input={},
            idempotency_key=f"key-{uuid4().hex}",
            request_fingerprint="0" * 64,
        ),
    )


def _decision(
    connection: Connection,
    task: TaskRecord,
    action: Action = Action.TASK_SUBMIT,
    effect: Effect = Effect.ALLOW,
    stage: Stage = Stage.POLICY,
    job: JobRef | None = None,
    **overrides: Any,
) -> SecurityDecision:
    worker = action is Action.TASK_EXECUTE
    decision = SecurityDecision(
        decision_id=uuid4(),
        decided_at=transaction_time(connection),
        actor_id=SYSTEM_WORKER_ID if worker else task.initiator_id,
        actor_kind=IdentityKind.SYSTEM if worker else IdentityKind.HUMAN,
        actor_credential_id=None if worker else task.submitted_credential_id,
        subject_id=task.initiator_id,
        action=action,
        resource_type=ResourceType.TASK,
        resource_id=str(task.task_id),
        resource_owner_id=task.owner_id,
        task_id=task.task_id,
        effect=effect,
        stage=stage,
        reason_codes=("test_rule",),
        policy_version=POLICY.version,
        policy_digest=POLICY.digest,
        job_id=job.job_id if job else None,
        job_attempt=job.attempt if job else None,
    )
    return replace(decision, **overrides)


def _move(
    connection: Connection,
    task: TaskRecord,
    target: TaskState,
    decision: SecurityDecision | None = None,
    job: JobRef | None = None,
    **extra: Any,
) -> TaskRecord:
    worker = job is not None
    transition = Transition(
        task_id=task.task_id,
        expected_state=task.state,
        expected_version=task.version,
        target=target,
        actor_id=SYSTEM_WORKER_ID if worker else task.initiator_id,
        actor_kind=IdentityKind.SYSTEM if worker else IdentityKind.HUMAN,
        source=Source.WORKER if worker else Source.API,
        reason_code="test_transition",
        decision=decision,
        job=job,
        **extra,
    )
    return apply_transition(connection, transition, POLICY, RECORDER)


def _decide_and_move(
    connection: Connection,
    task: TaskRecord,
    target: TaskState,
    action: Action,
    effect: Effect,
    stage: Stage,
    job: JobRef | None = None,
) -> TaskRecord:
    decision = _decision(connection, task, action, effect, stage, job)
    record_decision(connection, decision)
    return _move(connection, task, target, decision, job)


def _submit(connection: Connection, person: Person) -> TaskRecord:
    task = _new_task(connection, person)
    return _decide_and_move(
        connection, task, S.QUEUED, Action.TASK_SUBMIT, Effect.ALLOW, Stage.POLICY
    )


def _queued(app_engine: Engine, person: Person) -> TaskRecord:
    with app_engine.begin() as connection:
        return _submit(connection, person)


def _run(connection: Connection, task: TaskRecord, job: JobRef) -> TaskRecord:
    return _decide_and_move(
        connection, task, S.RUNNING, Action.TASK_EXECUTE, Effect.ALLOW, Stage.POLICY, job
    )


def _refused(error: type[psycopg.Error], match: str, statement: Callable[[], object]) -> None:
    with pytest.raises(DBAPIError) as excinfo:
        statement()
    assert isinstance(excinfo.value.orig, error), excinfo.value.orig
    assert match in str(excinfo.value.orig)


def _sql(connection: Connection, statement: str, **parameters: Any) -> Callable[[], object]:
    return lambda: connection.execute(text(statement), parameters)


def _history(connection: Connection, task: TaskRecord, **values: Any) -> Callable[[], object]:
    row = {
        "task_id": task.task_id,
        "to_version": task.version + 1,
        "from_state": task.state.value,
        "to_state": "queued",
        "actor_id": task.initiator_id,
        "reason_code": "forged",
        **values,
    }
    columns = ", ".join(row)
    placeholders = ", ".join(f":{name}" for name in row)
    return _sql(
        connection,
        f"INSERT INTO aegis.task_state_transitions ({columns}) VALUES ({placeholders})",
        **row,
    )


def _decision_columns(decision: SecurityDecision) -> dict[str, Any]:
    return {
        "decision_id": decision.decision_id,
        "decision_action": decision.action.value,
        "decision_effect": decision.effect.value,
        "decision_stage": decision.stage.value,
        "decision_decided_at": decision.decided_at,
    }


# Service path: apply_transition refuses before anything is written.


def test_a_submission_writes_state_history_and_audit_together(
    app_engine: Engine, owner_engine: Engine, person: Person
) -> None:
    task = _queued(app_engine, person)

    with owner_engine.connect() as connection:
        history = (
            connection.execute(
                select(task_state_transitions).where(
                    task_state_transitions.c.task_id == task.task_id
                )
            )
            .mappings()
            .one()
        )
        audit = connection.execute(
            select(audit_events.c.event_type, audit_events.c.details).where(
                audit_events.c.task_id == task.task_id
            )
        ).one()
    assert (task.state, task.version) == (S.QUEUED, 1)
    assert (history["from_state"], history["to_state"], history["to_version"]) == (
        "created",
        "queued",
        1,
    )
    assert history["decision_action"] == "task.submit"
    assert history["occurred_at"] == history["decision_decided_at"]
    assert tuple(audit) == (
        "task.transitioned",
        {"from_state": "created", "to_state": "queued"},
    )


@pytest.mark.parametrize(
    ("source", "target"),
    [
        (S.CREATED, S.SUCCEEDED),
        (S.CREATED, S.RUNNING),
        (S.QUEUED, S.SUCCEEDED),
        (S.AWAITING_APPROVAL, S.QUEUED),
        (S.SUCCEEDED, S.QUEUED),
        (S.CANCELLED, S.QUEUED),
    ],
)
def test_illegal_transitions_are_refused_by_the_service(
    app_tx: Connection, person: Person, source: TaskState, target: TaskState
) -> None:
    task = _new_task(app_tx, person)

    with pytest.raises(IllegalTransitionError):
        _move(app_tx, replace(task, state=source), target)


def test_queuing_without_a_decision_is_refused_by_the_service(
    app_tx: Connection, person: Person
) -> None:
    task = _new_task(app_tx, person)

    with pytest.raises(IllegalTransitionError, match=r"needs a task\.submit decision"):
        _move(app_tx, task, S.QUEUED)


@pytest.mark.parametrize(
    ("change", "rules"),
    [
        ({"action": Action.TASK_CANCEL, "stage": Stage.AUTHORIZATION}, {"C2", "C9"}),
        ({"effect": Effect.DENY}, {"C3"}),
        ({"effect": Effect.APPROVAL_REQUIRED}, {"C3"}),
        ({"stage": Stage.AUTHORIZATION}, {"C9"}),
        ({"policy_version": "older-policy"}, {"C7"}),
    ],
)
def test_mismatched_decisions_are_refused_by_the_service(
    app_tx: Connection, person: Person, change: dict[str, Any], rules: set[str]
) -> None:
    task = _new_task(app_tx, person)
    decision = _decision(app_tx, task, **change)

    with pytest.raises(DecisionMismatchError) as excinfo:
        _move(app_tx, task, S.QUEUED, decision)

    assert set(excinfo.value.rules) == rules


def test_a_decision_for_another_task_is_refused_by_the_service(
    app_tx: Connection, person: Person
) -> None:
    task, other = _new_task(app_tx, person), _new_task(app_tx, person)
    decision = _decision(app_tx, other)
    record_decision(app_tx, decision)

    with pytest.raises(DecisionMismatchError) as excinfo:
        _move(app_tx, task, S.QUEUED, decision)

    assert {"C1", "C6"} <= set(excinfo.value.rules)


def test_a_subject_other_than_the_initiator_is_refused_by_the_service(
    app_tx: Connection, person: Person, owner_engine: Engine
) -> None:
    stranger = _person(owner_engine)
    task = _new_task(app_tx, person)
    decision = _decision(app_tx, task, subject_id=stranger.identity_id)

    with pytest.raises(DecisionMismatchError) as excinfo:
        _move(app_tx, task, S.QUEUED, decision)

    assert excinfo.value.rules == ("C4",)


def test_a_stale_decision_is_refused_by_the_service(app_engine: Engine, person: Person) -> None:
    task = _queued(app_engine, person)
    with app_engine.begin() as connection:
        decision = _decision(
            connection, task, Action.TASK_CANCEL, Effect.ALLOW, Stage.AUTHORIZATION
        )
        record_decision(connection, decision)

    with app_engine.begin() as connection, pytest.raises(DecisionMismatchError) as excinfo:
        _move(connection, task, S.CANCELLED, decision)

    assert excinfo.value.rules == ("C8",)


def test_jobs_are_required_exactly_where_the_rules_say(app_tx: Connection, person: Person) -> None:
    task = _submit(app_tx, person)
    execute = _decision(app_tx, task, Action.TASK_EXECUTE)
    cancel = _decision(app_tx, task, Action.TASK_CANCEL, stage=Stage.AUTHORIZATION)

    with pytest.raises(IllegalTransitionError, match="needs job"):
        _move(app_tx, task, S.RUNNING, execute)
    with pytest.raises(IllegalTransitionError, match="takes no job"):
        _move(app_tx, task, S.CANCELLED, cancel, JobRef(uuid4(), 1))


def test_an_outdated_version_is_a_conflict(app_tx: Connection, person: Person) -> None:
    task = _submit(app_tx, person)
    decision = _decision(app_tx, task, Action.TASK_CANCEL, stage=Stage.AUTHORIZATION)
    record_decision(app_tx, decision)

    with pytest.raises(TransitionConflictError):
        _move(app_tx, replace(task, version=0), S.CANCELLED, decision)


def test_a_full_worker_lifecycle_is_accepted(app_tx: Connection, person: Person) -> None:
    job = JobRef(uuid4(), 1)
    task = _run(app_tx, _submit(app_tx, person), job)

    finished = _move(app_tx, task, S.SUCCEEDED, job=job, result={"ok": True})

    assert (finished.state, finished.version, finished.result) == (S.SUCCEEDED, 3, {"ok": True})
    assert finished.finished_at is not None


def test_concurrent_transitions_let_exactly_one_win(app_engine: Engine, person: Person) -> None:
    task = _queued(app_engine, person)
    barrier = threading.Barrier(2, timeout=30)
    outcomes: list[str] = []

    def cancel() -> None:
        try:
            with app_engine.begin() as connection:
                decision = _decision(
                    connection, task, Action.TASK_CANCEL, stage=Stage.AUTHORIZATION
                )
                record_decision(connection, decision)
                barrier.wait()
                _move(connection, task, S.CANCELLED, decision)
            outcomes.append("won")
        except TransitionConflictError:
            outcomes.append("conflict")

    threads = [threading.Thread(target=cancel) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert sorted(outcomes) == ["conflict", "won"]
    with app_engine.connect() as connection:
        final = get_task(connection, task.task_id)
    assert final is not None
    assert (final.state, final.version) == (S.CANCELLED, 2)


# Direct SQL as aegis_app: the database refuses the same attacks.


def test_the_database_refuses_illegal_jumps(app_engine: Engine, person: Person) -> None:
    task = _queued(app_engine, person)

    with app_engine.connect() as connection:
        _refused(
            errors.RaiseException,
            "illegal task transition from queued to succeeded",
            _sql(
                connection,
                "UPDATE aegis.tasks SET state = 'succeeded', version = 2 WHERE id = :id",
                id=task.task_id,
            ),
        )


@pytest.mark.parametrize(
    ("action", "effect", "stage"),
    [
        (None, None, None),
        ("task.cancel", "allow", "authorization"),
        ("task.submit", "deny", "policy"),
        ("task.submit", "approval_required", "policy"),
        ("task.submit", "allow", "authorization"),
    ],
)
def test_the_database_refuses_queuing_without_a_matching_decision(
    app_tx: Connection, person: Person, action: str | None, effect: str | None, stage: str | None
) -> None:
    task = _new_task(app_tx, person)
    columns: dict[str, Any] = {}
    if action is not None:
        decision = _decision(app_tx, task, Action(action), Effect(str(effect)), Stage(str(stage)))
        record_decision(app_tx, decision)
        columns = _decision_columns(decision)

    _refused(
        errors.RaiseException, "no rule allows created to queued", _history(app_tx, task, **columns)
    )


def test_the_database_refuses_a_decision_for_another_task(
    app_tx: Connection, person: Person
) -> None:
    task, other = _new_task(app_tx, person), _new_task(app_tx, person)
    decision = _decision(app_tx, other)
    record_decision(app_tx, decision)

    _refused(
        errors.ForeignKeyViolation,
        "fk_task_state_transitions_decision_id_security_decisions",
        _history(app_tx, task, **_decision_columns(decision)),
    )


def test_the_database_refuses_a_decision_whose_subject_is_not_the_initiator(
    app_tx: Connection, person: Person, owner_engine: Engine
) -> None:
    stranger = _person(owner_engine)
    task = _new_task(app_tx, person)
    decision = _decision(app_tx, task, subject_id=stranger.identity_id)

    _refused(
        errors.ForeignKeyViolation,
        "fk_security_decisions_task_id_tasks",
        lambda: record_decision(app_tx, decision),
    )


def test_the_database_refuses_a_stale_decision(app_engine: Engine, person: Person) -> None:
    task = _queued(app_engine, person)
    with app_engine.begin() as connection:
        decision = _decision(connection, task, Action.TASK_CANCEL, stage=Stage.AUTHORIZATION)
        record_decision(connection, decision)

    with app_engine.connect() as connection:
        _refused(
            errors.CheckViolation,
            "ck_task_state_transitions_fresh_decision",
            _history(connection, task, to_state="cancelled", **_decision_columns(decision)),
        )


def test_the_database_refuses_a_reused_decision(app_tx: Connection, person: Person) -> None:
    job = JobRef(uuid4(), 1)
    task = _submit(app_tx, person)
    execute = _decision(app_tx, task, Action.TASK_EXECUTE, job=job)
    record_decision(app_tx, execute)
    task = _move(app_tx, task, S.RUNNING, execute, job)
    task = _move(app_tx, task, S.INTERRUPTED, job=job)
    task = _move(app_tx, task, S.QUEUED, job=job)

    _refused(
        errors.UniqueViolation,
        "uq_task_state_transitions_decision_id",
        lambda: _move(app_tx, task, S.RUNNING, execute, job),
    )


def test_the_database_refuses_a_decision_for_another_job_attempt(
    app_tx: Connection, person: Person
) -> None:
    task = _submit(app_tx, person)
    decision = _decision(app_tx, task, Action.TASK_EXECUTE, job=JobRef(uuid4(), 1))
    record_decision(app_tx, decision)

    _refused(
        errors.RaiseException,
        "different job attempt",
        _history(
            app_tx,
            task,
            to_state="running",
            job_id=decision.job_id,
            job_attempt=2,
            **_decision_columns(decision),
        ),
    )


def test_the_database_refuses_a_state_change_without_history(
    app_engine: Engine, person: Person
) -> None:
    task = _queued(app_engine, person)

    with app_engine.connect() as connection:
        _refused(
            errors.RaiseException,
            "needs its history row",
            _sql(
                connection,
                "UPDATE aegis.tasks SET state = 'cancelled', version = 2 WHERE id = :id",
                id=task.task_id,
            ),
        )


def test_the_database_refuses_history_without_a_state_change(
    app_engine: Engine, person: Person
) -> None:
    task = _queued(app_engine, person)

    with app_engine.connect() as connection:
        decision = _decision(connection, task, Action.TASK_CANCEL, stage=Stage.AUTHORIZATION)
        record_decision(connection, decision)
        _history(connection, task, to_state="cancelled", **_decision_columns(decision))()

        _refused(errors.RaiseException, "has no state change", connection.commit)


def test_the_database_refuses_a_task_left_in_created(app_engine: Engine, person: Person) -> None:
    with app_engine.connect() as connection:
        _new_task(connection, person)

        _refused(errors.RaiseException, "cannot be committed in state created", connection.commit)


@pytest.mark.parametrize(
    ("version_change", "match"),
    [("version + 2", "by exactly 1"), ("version", "by exactly 1")],
)
def test_the_database_refuses_version_skips(
    app_engine: Engine, person: Person, version_change: str, match: str
) -> None:
    task = _queued(app_engine, person)

    with app_engine.connect() as connection:
        _refused(
            errors.RaiseException,
            match,
            _sql(
                connection,
                f"UPDATE aegis.tasks SET state = 'cancelled', version = {version_change}"
                " WHERE id = :id",
                id=task.task_id,
            ),
        )


def test_the_database_refuses_a_version_change_without_a_state_change(
    app_engine: Engine, person: Person
) -> None:
    task = _queued(app_engine, person)

    with app_engine.connect() as connection:
        _refused(
            errors.RaiseException,
            "changes only with the state",
            _sql(connection, "UPDATE aegis.tasks SET version = 2 WHERE id = :id", id=task.task_id),
        )


def test_the_database_refuses_changes_to_final_tasks(app_engine: Engine, person: Person) -> None:
    task = _queued(app_engine, person)
    with app_engine.begin() as connection:
        _decide_and_move(
            connection, task, S.CANCELLED, Action.TASK_CANCEL, Effect.ALLOW, Stage.AUTHORIZATION
        )

    with app_engine.connect() as connection:
        _refused(
            errors.RaiseException,
            "final state cannot change",
            _sql(
                connection,
                "UPDATE aegis.tasks SET cancel_requested_by = initiator_id WHERE id = :id",
                id=task.task_id,
            ),
        )


def test_a_running_task_is_cancelled_only_after_a_request(
    app_tx: Connection, person: Person
) -> None:
    job = JobRef(uuid4(), 1)
    task = _run(app_tx, _submit(app_tx, person), job)

    _refused(
        errors.RaiseException,
        "only after a cancellation request",
        lambda: _move(app_tx, task, S.CANCELLED, job=job),
    )


def test_a_cancellation_request_is_stamped_and_permanent(
    app_tx: Connection, person: Person
) -> None:
    job = JobRef(uuid4(), 1)
    task = _run(app_tx, _submit(app_tx, person), job)
    stamp = app_tx.execute(
        text(
            "UPDATE aegis.tasks SET cancel_requested_by = initiator_id WHERE id = :id"
            " RETURNING cancel_requested_at = now()"
        ),
        {"id": task.task_id},
    ).scalar_one()

    cancelled = _move(app_tx, task, S.CANCELLED, job=job)

    assert stamp is True
    assert cancelled.state is S.CANCELLED


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE aegis.tasks SET input = '{\"x\": 1}' WHERE id = :id",
        "UPDATE aegis.tasks SET owner_id = owner_id WHERE id = :id",
        "UPDATE aegis.tasks SET initiator_id = initiator_id WHERE id = :id",
        "UPDATE aegis.tasks SET kind = 'wait' WHERE id = :id",
        "UPDATE aegis.tasks SET created_at = now() WHERE id = :id",
        "UPDATE aegis.tasks SET finished_at = now() WHERE id = :id",
        "DELETE FROM aegis.tasks WHERE id = :id",
        "UPDATE aegis.security_decisions SET effect = 'allow' WHERE task_id = :id",
        "DELETE FROM aegis.security_decisions WHERE task_id = :id",
        "UPDATE aegis.task_state_transitions SET reason_code = 'x' WHERE task_id = :id",
        "DELETE FROM aegis.task_state_transitions WHERE task_id = :id",
        "UPDATE aegis.task_transition_rules SET to_state = 'queued' WHERE id = :rule",
        "INSERT INTO aegis.task_transition_rules VALUES (:rule, 'awaiting_approval', 'queued',"
        " NULL, NULL, NULL, false)",
        "TRUNCATE aegis.tasks CASCADE",
    ],
)
def test_the_application_role_cannot_change_fixed_data(
    app_engine: Engine, person: Person, statement: str
) -> None:
    task = _queued(app_engine, person)

    with app_engine.connect() as connection:
        _refused(
            errors.InsufficientPrivilege,
            "permission denied",
            _sql(connection, statement, id=task.task_id, rule=99),
        )


@pytest.mark.parametrize(
    ("statement", "match"),
    [
        ("UPDATE aegis.tasks SET input = '{\"x\": 1}' WHERE id = :id", "fixed columns"),
        ("DELETE FROM aegis.tasks WHERE id = :id", "never deleted"),
        ("UPDATE aegis.security_decisions SET effect = 'deny' WHERE task_id = :id", "append-only"),
        ("DELETE FROM aegis.task_state_transitions WHERE task_id = :id", "append-only"),
        ("UPDATE aegis.task_transition_rules SET to_state = 'queued' WHERE id = 3", "append-only"),
        ("TRUNCATE aegis.task_state_transitions", "append-only"),
        ("TRUNCATE aegis.task_transition_rules", "append-only"),
    ],
)
def test_triggers_stop_even_the_owner(
    app_engine: Engine, owner_engine: Engine, person: Person, statement: str, match: str
) -> None:
    task = _queued(app_engine, person)

    with owner_engine.connect() as connection:
        _refused(errors.RaiseException, match, _sql(connection, statement, id=task.task_id))


# The Python and SQL definitions are the same.


def test_python_and_sql_transition_tables_are_identical(owner_engine: Engine) -> None:
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT from_state, to_state, action, effect, stage, requires_job"
                " FROM aegis.task_transition_rules"
            )
        ).all()

    python = {
        (
            rule.source.value,
            rule.target.value,
            rule.decision.action.value if rule.decision else None,
            rule.decision.effect.value if rule.decision else None,
            rule.decision.stage.value if rule.decision else None,
            rule.requires_job,
        )
        for rule in TRANSITION_RULES
    }
    assert {tuple(row) for row in rows} == python
    assert len(rows) == len(TRANSITION_RULES)


@pytest.mark.parametrize(
    ("constraint", "values"),
    [
        ("ck_tasks_state", {state.value for state in TaskState}),
        ("ck_tasks_kind", {kind.value for kind in TaskKind}),
        ("ck_security_decisions_action", {action.value for action in Action}),
        ("ck_security_decisions_effect", {effect.value for effect in Effect}),
        ("ck_security_decisions_actor_kind", {kind.value for kind in IdentityKind}),
    ],
)
def test_sql_value_lists_match_the_python_enums(
    owner_engine: Engine, constraint: str, values: set[str]
) -> None:
    with owner_engine.connect() as connection:
        definition = connection.execute(
            text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = :name"),
            {"name": constraint},
        ).scalar_one()

    assert set(re.findall(r"'([a-z_.]+)'::text", definition)) == values

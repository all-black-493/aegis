from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, func, select, text

from aegis.audit.events import ActorKind, AuditEvent, AuditEventType, Outcome, Source
from aegis.audit.recorder import AuditRecorder
from aegis.authorization.access import ActorContext
from aegis.authorization.catalog import Action, IdentityKind, ResourceType, Role
from aegis.authorization.contract import Effect, SecurityDecision, Stage
from aegis.identity.schema import (
    SYSTEM_AGENT_ID,
    SYSTEM_WORKER_ID,
    credentials,
    identities,
    identity_roles,
)
from aegis.policy.facts import (
    DecisionInputs,
    ExecutionFacts,
    SubmissionFacts,
    TaskFacts,
    ToolFacts,
    ToolRequest,
    from_document,
    to_document,
)
from aegis.policy.rules import MAX_INPUT_BYTES, Policy, Verdict, decide, input_bytes
from aegis.policy.version import CURRENT_POLICY
from aegis.tasks.repository import TaskRecord, record_decision, transaction_time
from aegis.tasks.schema import security_decisions, tasks
from aegis.tasks.states import TERMINAL_STATES, TaskState
from aegis.tasks.transitions import JobRef, PolicyRef

SUBMISSION_LOCK = 7_301_004
WORKER_ACTIONS = frozenset({Action.TASK_EXECUTE, Action.TOOL_INVOKE})
ACTIVE_STATES = tuple(s.value for s in TaskState if s not in TERMINAL_STATES | {TaskState.CREATED})


class ReplayError(ValueError):
    pass


@dataclass(frozen=True)
class Decided:
    decision: SecurityDecision
    inputs: DecisionInputs


class DecisionService:
    def __init__(self, recorder: AuditRecorder, policy: Policy = CURRENT_POLICY) -> None:
        self._recorder = recorder
        self._policy = policy

    @property
    def policy(self) -> PolicyRef:
        return PolicyRef(self._policy.version, self._policy.digest)

    def lock_submissions(self, connection: Connection, identity_id: UUID) -> None:
        # Serialises one initiator's submissions, so concurrent requests cannot exceed the quota
        # or reuse an idempotency key. The lock is re-entrant within a transaction.
        connection.execute(
            text("SELECT pg_advisory_xact_lock(:lock, hashtext(:identity))"),
            {"lock": SUBMISSION_LOCK, "identity": str(identity_id)},
        )

    def submission(
        self,
        connection: Connection,
        actor: ActorContext,
        task_id: UUID,
        kind: str,
        task_input: Any,
        request_id: str | None = None,
    ) -> Decided:
        self.lock_submissions(connection, actor.identity_id)
        active = connection.execute(
            select(func.count())
            .select_from(tasks)
            .where(tasks.c.initiator_id == actor.identity_id, tasks.c.state.in_(ACTIVE_STATES))
        ).scalar_one()
        inputs = DecisionInputs(
            action=Action.TASK_SUBMIT,
            actor_id=actor.identity_id,
            actor_kind=actor.kind,
            actor_roles=actor.roles,
            resource_id=str(task_id),
            resource_owner_id=actor.identity_id,
            submission=SubmissionFacts(_task_facts(kind, task_input), actor.kind, active),
        )
        verdict = decide(self._policy, inputs)
        decision = self._decision(
            connection,
            inputs,
            verdict,
            actor_credential_id=actor.credential_id,
            subject_id=actor.identity_id,
            task_id=None if verdict.effect is Effect.DENY else task_id,
            request_id=request_id,
        )
        return Decided(decision, inputs)

    def execution(self, connection: Connection, task: TaskRecord, job: JobRef) -> Decided:
        active, roles, revoked = _initiator(connection, task)
        inputs = DecisionInputs(
            action=Action.TASK_EXECUTE,
            actor_id=SYSTEM_WORKER_ID,
            actor_kind=IdentityKind.SYSTEM,
            actor_roles=_roles(connection, SYSTEM_WORKER_ID),
            resource_id=str(task.task_id),
            resource_owner_id=task.owner_id,
            execution=ExecutionFacts(
                task=_task_facts(task.kind.value, task.input),
                initiator_active=active,
                initiator_roles=roles,
                submitting_credential_revoked=revoked,
            ),
        )
        decision = self._decision(
            connection,
            inputs,
            decide(self._policy, inputs),
            actor_credential_id=None,
            subject_id=task.initiator_id,
            task_id=task.task_id,
            job=job,
        )
        return Decided(decision, inputs)

    def tool_invocation(
        self, connection: Connection, task: TaskRecord, job: JobRef, request: ToolRequest
    ) -> Decided:
        # The initiator's standing is read again for every call: a task's agent acts for them,
        # and loses that the moment they do.
        active, roles, revoked = _initiator(connection, task)
        inputs = DecisionInputs(
            action=Action.TOOL_INVOKE,
            actor_id=SYSTEM_AGENT_ID,
            actor_kind=IdentityKind.SYSTEM,
            actor_roles=_roles(connection, SYSTEM_AGENT_ID),
            resource_id=str(task.task_id),
            resource_owner_id=task.owner_id,
            tool=ToolFacts(request, active, roles, revoked),
        )
        decision = self._decision(
            connection,
            inputs,
            decide(self._policy, inputs),
            actor_credential_id=None,
            subject_id=task.initiator_id,
            task_id=task.task_id,
            job=job,
        )
        return Decided(decision, inputs)

    def cancellation(
        self,
        connection: Connection,
        actor: ActorContext,
        task: TaskRecord,
        request_id: str | None = None,
    ) -> Decided:
        return self._about_task(connection, Action.TASK_CANCEL, actor, task, request_id)

    def read(
        self,
        connection: Connection,
        actor: ActorContext,
        task: TaskRecord,
        request_id: str | None = None,
    ) -> Decided:
        return self._about_task(connection, Action.TASK_READ, actor, task, request_id)

    def listing(
        self,
        connection: Connection,
        actor: ActorContext,
        *,
        everyone: bool,
        request_id: str | None = None,
    ) -> Decided:
        inputs = DecisionInputs(
            action=Action.TASK_LIST_ALL if everyone else Action.TASK_LIST,
            actor_id=actor.identity_id,
            actor_kind=actor.kind,
            actor_roles=actor.roles,
            resource_id=None,
            resource_owner_id=None,
        )
        decision = self._decision(
            connection,
            inputs,
            decide(self._policy, inputs),
            actor_credential_id=actor.credential_id,
            subject_id=actor.identity_id,
            task_id=None,
            request_id=request_id,
        )
        return Decided(decision, inputs)

    def record(self, connection: Connection, decided: Decided) -> None:
        decision = decided.decision
        record_decision(connection, decision, to_document(decided.inputs))
        self._recorder.record(
            connection,
            AuditEvent(
                event_type=AuditEventType.SECURITY_DECISION,
                source=Source.WORKER if decision.action in WORKER_ACTIONS else Source.API,
                outcome=Outcome.DENIED if decision.effect is Effect.DENY else Outcome.SUCCESS,
                actor_id=decision.actor_id,
                actor_kind=ActorKind(decision.actor_kind.value),
                target_type=None if decision.resource_id is None else "task",
                target_id=decision.resource_id,
                task_id=decision.task_id,
                job_id=decision.job_id,
                decision_id=decision.decision_id,
                request_id=decision.request_id,
                reason_code=decision.reason_codes[0],
                policy_version=decision.policy_version,
                details={
                    "action": decision.action.value,
                    "effect": decision.effect.value,
                    "stage": decision.stage.value,
                },
            ),
        )

    def replay(self, connection: Connection, decision_id: UUID) -> tuple[Verdict, Verdict]:
        row = (
            connection.execute(
                select(security_decisions).where(security_decisions.c.id == decision_id)
            )
            .mappings()
            .one()
        )
        if (row["policy_version"], row["policy_digest"]) != (
            self._policy.version,
            self._policy.digest,
        ):
            raise ReplayError(f"decision {decision_id} was made under another policy")
        saved = Verdict(Effect(row["effect"]), Stage(row["stage"]), tuple(row["reason_codes"]))
        return saved, decide(self._policy, from_document(row["inputs"]))

    def _about_task(
        self,
        connection: Connection,
        action: Action,
        actor: ActorContext,
        task: TaskRecord,
        request_id: str | None,
    ) -> Decided:
        inputs = DecisionInputs(
            action=action,
            actor_id=actor.identity_id,
            actor_kind=actor.kind,
            actor_roles=actor.roles,
            resource_id=str(task.task_id),
            resource_owner_id=task.owner_id,
        )
        decision = self._decision(
            connection,
            inputs,
            decide(self._policy, inputs),
            actor_credential_id=actor.credential_id,
            subject_id=task.initiator_id,
            task_id=task.task_id,
            request_id=request_id,
        )
        return Decided(decision, inputs)

    def _decision(
        self,
        connection: Connection,
        inputs: DecisionInputs,
        verdict: Verdict,
        *,
        actor_credential_id: UUID | None,
        subject_id: UUID,
        task_id: UUID | None,
        request_id: str | None = None,
        job: JobRef | None = None,
    ) -> SecurityDecision:
        return SecurityDecision(
            decision_id=uuid4(),
            decided_at=transaction_time(connection),
            actor_id=inputs.actor_id,
            actor_kind=inputs.actor_kind,
            actor_credential_id=actor_credential_id,
            subject_id=subject_id,
            action=inputs.action,
            resource_type=ResourceType.TASK,
            resource_id=inputs.resource_id,
            resource_owner_id=inputs.resource_owner_id,
            task_id=task_id,
            effect=verdict.effect,
            stage=verdict.stage,
            reason_codes=verdict.reason_codes,
            policy_version=self._policy.version,
            policy_digest=self._policy.digest,
            request_id=request_id,
            job_id=job.job_id if job else None,
            job_attempt=job.attempt if job else None,
        )


def _initiator(connection: Connection, task: TaskRecord) -> tuple[bool, frozenset[Role], bool]:
    status = connection.execute(
        select(identities.c.status).where(identities.c.id == task.initiator_id)
    ).scalar_one()
    revoked_at = connection.execute(
        select(credentials.c.revoked_at).where(credentials.c.id == task.submitted_credential_id)
    ).scalar_one()
    return status == "active", _roles(connection, task.initiator_id), revoked_at is not None


def _roles(connection: Connection, identity_id: UUID) -> frozenset[Role]:
    rows = connection.execute(
        select(identity_roles.c.role).where(identity_roles.c.identity_id == identity_id)
    ).scalars()
    return frozenset(Role(role) for role in rows)


def _task_facts(kind: str, task_input: Any) -> TaskFacts:
    size = input_bytes(task_input)
    stored: Mapping[str, Any] | None = None
    if size <= MAX_INPUT_BYTES and isinstance(task_input, Mapping):
        stored = task_input
    return TaskFacts(kind, stored, size)

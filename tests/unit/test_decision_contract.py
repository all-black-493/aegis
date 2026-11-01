import dataclasses
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from aegis.authorization.catalog import Action, IdentityKind, ResourceType
from aegis.authorization.contract import (
    CONSISTENCY_RULES,
    DecisionMismatchError,
    DecisionRequirement,
    Effect,
    InvalidDecisionError,
    SecurityDecision,
    Stage,
    TaskRef,
    require_consistent,
)

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
DIGEST = "a" * 64
INITIATOR = uuid4()
WORKER = uuid4()
JOB = uuid4()
TASK = TaskRef(task_id=uuid4(), initiator_id=INITIATOR, owner_id=INITIATOR)


def decision(**overrides: object) -> SecurityDecision:
    values: dict[str, object] = {
        "decision_id": uuid4(),
        "decided_at": NOW,
        "actor_id": WORKER,
        "actor_kind": IdentityKind.SYSTEM,
        "actor_credential_id": None,
        "subject_id": INITIATOR,
        "action": Action.TASK_EXECUTE,
        "resource_type": ResourceType.TASK,
        "resource_id": str(TASK.task_id),
        "resource_owner_id": TASK.owner_id,
        "task_id": TASK.task_id,
        "effect": Effect.ALLOW,
        "stage": Stage.POLICY,
        "reason_codes": ("permitted",),
        "policy_version": "p1.0",
        "policy_digest": DIGEST,
        "request_id": None,
        "job_id": JOB,
        "job_attempt": 1,
    }
    values.update(overrides)
    return SecurityDecision(**values)  # type: ignore[arg-type]


REQUIREMENT = DecisionRequirement(
    task=TASK,
    action=Action.TASK_EXECUTE,
    effect=Effect.ALLOW,
    stage=Stage.POLICY,
    actor_id=WORKER,
    policy_version="p1.0",
    policy_digest=DIGEST,
    decided_at=NOW,
    job_id=JOB,
    job_attempt=1,
)


def test_a_consistent_decision_is_accepted() -> None:
    require_consistent(decision(), REQUIREMENT)


@pytest.mark.parametrize(
    ("rule", "overrides"),
    [
        ("C1", {"job_attempt": 2}),
        ("C2", {"action": Action.TASK_SUBMIT}),
        ("C3", {"effect": Effect.DENY}),
        ("C4", {"subject_id": uuid4()}),
        ("C5", {"actor_id": uuid4()}),
        ("C5", {"actor_kind": IdentityKind.SERVICE}),
        ("C6", {"resource_owner_id": uuid4()}),
        ("C7", {"policy_version": "p0.9"}),
        ("C7", {"policy_digest": "b" * 64}),
        ("C8", {"decided_at": NOW + timedelta(seconds=1)}),
        ("C9", {"stage": Stage.AUTHORIZATION}),
    ],
)
def test_each_rule_rejects_a_mismatched_decision(rule: str, overrides: dict[str, object]) -> None:
    with pytest.raises(DecisionMismatchError) as excinfo:
        require_consistent(decision(**overrides), REQUIREMENT)

    assert excinfo.value.rules == (rule,)


def test_a_decision_for_another_task_fails_the_task_and_resource_rules() -> None:
    other = uuid4()

    with pytest.raises(DecisionMismatchError) as excinfo:
        require_consistent(decision(task_id=other, resource_id=str(other)), REQUIREMENT)

    assert excinfo.value.rules == ("C1", "C6")


@pytest.mark.parametrize("effect", [Effect.DENY, Effect.APPROVAL_REQUIRED])
def test_deny_and_approval_required_never_satisfy_an_allow_requirement(effect: Effect) -> None:
    with pytest.raises(DecisionMismatchError) as excinfo:
        require_consistent(decision(effect=effect), REQUIREMENT)

    assert "C3" in excinfo.value.rules


def test_every_rule_is_described_and_errors_never_echo_values() -> None:
    assert list(CONSISTENCY_RULES) == [f"C{number}" for number in range(1, 10)]
    other = uuid4()

    with pytest.raises(DecisionMismatchError) as excinfo:
        require_consistent(decision(subject_id=other), REQUIREMENT)

    assert str(other) not in str(excinfo.value)
    assert CONSISTENCY_RULES["C4"] in str(excinfo.value)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"reason_codes": ()}, "reason_codes"),
        ({"reason_codes": ("Not A Code",)}, "reason_codes"),
        ({"policy_version": ""}, "policy_version"),
        ({"policy_digest": "xyz"}, "policy_digest"),
        ({"stage": Stage.AUTHORIZATION, "effect": Effect.APPROVAL_REQUIRED}, "only allow or deny"),
        ({"job_attempt": None}, "job_id and job_attempt"),
        ({"job_attempt": 0}, "at least 1"),
        ({"decided_at": NOW.replace(tzinfo=None)}, "time zone"),
        ({"resource_id": str(uuid4())}, "resource must be that task"),
        ({"resource_owner_id": None}, "resource_id and resource_owner_id"),
        ({"actor_credential_id": uuid4()}, "no credentials"),
        ({"request_id": "has space"}, "request_id"),
    ],
)
def test_malformed_decisions_cannot_be_created(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(InvalidDecisionError, match=message):
        decision(**overrides)


def test_decisions_without_a_task_are_valid_for_collection_actions() -> None:
    listing = decision(
        action=Action.TASK_LIST_ALL,
        actor_kind=IdentityKind.HUMAN,
        task_id=None,
        resource_id=None,
        resource_owner_id=None,
        job_id=None,
        job_attempt=None,
        stage=Stage.AUTHORIZATION,
        effect=Effect.DENY,
        reason_codes=("missing_permission",),
    )

    assert listing.task_id is None


def test_decisions_are_immutable() -> None:
    made = decision()

    with pytest.raises(dataclasses.FrozenInstanceError):
        made.effect = Effect.DENY  # type: ignore[misc]

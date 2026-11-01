import itertools
import json
from dataclasses import replace
from typing import Any
from uuid import UUID, uuid4

import pytest

from aegis.authorization.catalog import Action, IdentityKind, Role
from aegis.authorization.contract import Effect, Stage
from aegis.policy import facts as facts_module
from aegis.policy import rules as rules_module
from aegis.policy.facts import (
    DecisionInputs,
    ExecutionFacts,
    SubmissionFacts,
    TaskFacts,
    from_document,
    to_document,
)
from aegis.policy.rules import (
    ACTIVE_TASK_QUOTA,
    MAX_INPUT_BYTES,
    Outcome,
    Policy,
    Verdict,
    decide,
    input_bytes,
)
from aegis.policy.version import CURRENT_POLICY, POLICY_VERSION, fingerprint

PINNED_VERSION = "2026.11.01-1"
PINNED_DIGEST = "76a35e26d17a2c5b9bb306b374678ebca08ba2eef6b43a0fb3149d42fc619181"
SUBMITTER = UUID("00000000-0000-4000-8000-0000000000aa")
WORKER = UUID("00000000-0000-4000-8000-000000000001")


def _task(kind: str = "noop", task_input: Any = None) -> TaskFacts:
    task_input = {} if task_input is None else task_input
    return TaskFacts(kind, task_input, input_bytes(task_input))


def _submit(
    task: TaskFacts | None = None,
    *,
    roles: frozenset[Role] = frozenset({Role.OPERATOR}),
    active: int = 0,
) -> DecisionInputs:
    return DecisionInputs(
        action=Action.TASK_SUBMIT,
        actor_id=SUBMITTER,
        actor_kind=IdentityKind.HUMAN,
        actor_roles=roles,
        resource_id=str(uuid4()),
        resource_owner_id=SUBMITTER,
        submission=SubmissionFacts(task or _task(), IdentityKind.HUMAN, active),
    )


def _execute(
    task: TaskFacts | None = None,
    *,
    worker_roles: frozenset[Role] = frozenset({Role.WORKER}),
    active: bool = True,
    initiator_roles: frozenset[Role] = frozenset({Role.OPERATOR}),
    revoked: bool = False,
) -> DecisionInputs:
    return DecisionInputs(
        action=Action.TASK_EXECUTE,
        actor_id=WORKER,
        actor_kind=IdentityKind.SYSTEM,
        actor_roles=worker_roles,
        resource_id=str(uuid4()),
        resource_owner_id=SUBMITTER,
        execution=ExecutionFacts(task or _task(), active, initiator_roles, revoked),
    )


def _verdict(inputs: DecisionInputs, policy: Policy = CURRENT_POLICY) -> Verdict:
    return decide(policy, inputs)


def test_the_policy_fingerprint_is_pinned() -> None:
    assert (POLICY_VERSION, CURRENT_POLICY.digest) == (PINNED_VERSION, PINNED_DIGEST), (
        "aegis.policy.facts or aegis.policy.rules changed: bump POLICY_VERSION, then pin the new "
        "version and fingerprint here"
    )


def test_the_fingerprint_covers_the_version_and_the_rule_sources() -> None:
    assert fingerprint("another-version") != CURRENT_POLICY.digest
    assert fingerprint(POLICY_VERSION, (facts_module,)) != CURRENT_POLICY.digest
    assert fingerprint(POLICY_VERSION, (facts_module, rules_module)) == CURRENT_POLICY.digest


@pytest.mark.parametrize(
    ("task", "verdict"),
    [
        (_task("noop", {}), (Effect.ALLOW, ("submission_allowed",))),
        (_task("wait", {"seconds": 0}), (Effect.ALLOW, ("submission_allowed",))),
        (_task("wait", {"seconds": 30}), (Effect.ALLOW, ("submission_allowed",))),
        (
            _task("wait", {"seconds": 31}),
            (Effect.APPROVAL_REQUIRED, ("long_wait_needs_approval",)),
        ),
        (
            _task("wait", {"seconds": 300}),
            (Effect.APPROVAL_REQUIRED, ("long_wait_needs_approval",)),
        ),
        (_task("wait", {"seconds": 301}), (Effect.DENY, ("input_invalid",))),
        (_task("wait", {"seconds": -1}), (Effect.DENY, ("input_invalid",))),
        (_task("wait", {"seconds": True}), (Effect.DENY, ("input_invalid",))),
        (_task("wait", {"seconds": 1.5}), (Effect.DENY, ("input_invalid",))),
        (_task("wait", {"seconds": "5"}), (Effect.DENY, ("input_invalid",))),
        (_task("wait", {"seconds": 5, "extra": 1}), (Effect.DENY, ("input_invalid",))),
        (_task("wait", {}), (Effect.DENY, ("input_invalid",))),
        (_task("noop", {"x": 1}), (Effect.DENY, ("input_invalid",))),
        (TaskFacts("noop", None, 2), (Effect.DENY, ("input_invalid",))),
        (_task("shell", {"command": "id"}), (Effect.DENY, ("kind_not_registered",))),
        (
            TaskFacts("noop", None, MAX_INPUT_BYTES + 1),
            (Effect.DENY, ("input_too_large",)),
        ),
    ],
)
def test_submission_rules(task: TaskFacts, verdict: tuple[Effect, tuple[str, ...]]) -> None:
    result = _verdict(_submit(task))

    assert (result.effect, result.reason_codes) == verdict
    assert result.stage is Stage.POLICY


def test_the_active_task_quota_is_enforced() -> None:
    assert _verdict(_submit(active=ACTIVE_TASK_QUOTA - 1)).effect is Effect.ALLOW
    over = _verdict(_submit(active=ACTIVE_TASK_QUOTA))

    assert (over.effect, over.reason_codes) == (Effect.DENY, ("active_task_quota_exceeded",))


def test_any_deny_overrides_approval_and_allow() -> None:
    result = _verdict(_submit(_task("wait", {"seconds": 60}), active=ACTIVE_TASK_QUOTA))

    assert (result.effect, result.reason_codes) == (Effect.DENY, ("active_task_quota_exceeded",))


def test_every_deny_reason_is_reported() -> None:
    result = _verdict(_execute(active=False, initiator_roles=frozenset(), revoked=True))

    assert result.reason_codes == (
        "initiator_disabled",
        "initiator_not_authorized",
        "submitting_credential_revoked",
    )


def test_system_identities_cannot_submit() -> None:
    facts = SubmissionFacts(_task(), IdentityKind.SYSTEM, 0)

    outcome = rules_module.system_submitter(facts)

    assert outcome == Outcome(Effect.DENY, "system_submitter")


def test_the_authorization_stage_runs_first() -> None:
    result = _verdict(_submit(roles=frozenset({Role.AUDITOR})))

    assert result == Verdict(Effect.DENY, Stage.AUTHORIZATION, ("missing_permission",))


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"active": False}, "initiator_disabled"),
        ({"initiator_roles": frozenset({Role.AUDITOR})}, "initiator_not_authorized"),
        ({"initiator_roles": frozenset()}, "initiator_not_authorized"),
        ({"revoked": True}, "submitting_credential_revoked"),
    ],
)
def test_execution_rules_e2_to_e4(change: dict[str, Any], reason: str) -> None:
    result = _verdict(_execute(**change))

    assert result == Verdict(Effect.DENY, Stage.POLICY, (reason,))


def test_an_executor_without_the_worker_role_is_refused_e1() -> None:
    result = _verdict(_execute(worker_roles=frozenset()))

    assert result == Verdict(Effect.DENY, Stage.AUTHORIZATION, ("executor_not_authorized",))


def test_execution_re_applies_the_current_task_rules_e6() -> None:
    allowed = _verdict(_execute())
    long_wait = _verdict(_execute(_task("wait", {"seconds": 120})))
    invalid = _verdict(_execute(_task("noop", {"x": 1})))

    assert allowed == Verdict(Effect.ALLOW, Stage.POLICY, ("execution_allowed",))
    assert long_wait.effect is Effect.APPROVAL_REQUIRED
    assert invalid.effect is Effect.DENY


@pytest.mark.parametrize(
    ("roles", "owner", "verdict"),
    [
        (
            frozenset({Role.OPERATOR}),
            SUBMITTER,
            Verdict(Effect.ALLOW, Stage.AUTHORIZATION, ("permitted_as_owner",)),
        ),
        (
            frozenset({Role.OPERATOR}),
            uuid4(),
            Verdict(Effect.DENY, Stage.AUTHORIZATION, ("missing_permission",)),
        ),
        (
            frozenset({Role.ADMIN}),
            uuid4(),
            Verdict(Effect.ALLOW, Stage.AUTHORIZATION, ("permitted",)),
        ),
    ],
)
def test_cancellation_is_decided_by_authorization_alone(
    roles: frozenset[Role], owner: UUID, verdict: Verdict
) -> None:
    inputs = DecisionInputs(
        Action.TASK_CANCEL, SUBMITTER, IdentityKind.HUMAN, roles, str(uuid4()), owner
    )

    assert _verdict(inputs) == verdict


def test_unmatched_requests_are_denied() -> None:
    empty = replace(CURRENT_POLICY, submission_rules=(), execution_rules=())

    assert _verdict(_submit(), empty) == Verdict(Effect.DENY, Stage.POLICY, ("no_matching_rule",))
    assert _verdict(_execute(), empty).reason_codes == ("no_matching_rule",)


def test_evaluation_errors_become_a_deny() -> None:
    def broken(_facts: SubmissionFacts) -> Outcome | None:
        raise RuntimeError("rule bug")

    def allow(_facts: SubmissionFacts) -> Outcome | None:
        return Outcome(Effect.ALLOW, "always")

    faulty = replace(CURRENT_POLICY, submission_rules=(allow, broken))

    assert _verdict(_submit(), faulty) == Verdict(Effect.DENY, Stage.POLICY, ("evaluation_error",))


def test_missing_facts_become_a_deny() -> None:
    inputs = replace(_submit(), submission=None)

    assert _verdict(inputs).reason_codes == ("evaluation_error",)


def test_approval_is_never_an_authorization_outcome() -> None:
    cases = [_submit(_task("wait", {"seconds": s})) for s in (0, 31)] + [_execute()]

    for inputs in cases:
        result = _verdict(inputs)
        assert not (
            result.stage is Stage.AUTHORIZATION and result.effect is Effect.APPROVAL_REQUIRED
        )


def _corpus() -> list[DecisionInputs]:
    tasks = [
        _task("noop", {}),
        _task("wait", {"seconds": 31}),
        _task("wait", {"seconds": "x"}),
        _task("shell", {}),
        TaskFacts("noop", None, MAX_INPUT_BYTES + 1),
    ]
    return [
        *(_submit(task, active=active) for task in tasks for active in (0, ACTIVE_TASK_QUOTA)),
        _submit(roles=frozenset({Role.AUDITOR})),
        *(_execute(task) for task in tasks),
        _execute(active=False, revoked=True),
        _execute(worker_roles=frozenset()),
    ]


def test_inputs_round_trip_through_their_stored_form() -> None:
    for inputs in _corpus():
        document = json.loads(json.dumps(to_document(inputs)))

        assert from_document(document) == inputs
        assert _verdict(from_document(document)) == _verdict(inputs)


def test_decisions_do_not_depend_on_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    corpus = _corpus()
    expected = [_verdict(inputs) for inputs in corpus]
    settings = itertools.product(
        ["development", "test", "production"],
        ["DEBUG", "INFO", "WARNING", "ERROR"],
        ["1024", "8000", "65535"],
    )

    for environment, level, port in settings:
        monkeypatch.setenv("AEGIS_ENV", environment)
        monkeypatch.setenv("AEGIS_LOG_LEVEL", level)
        monkeypatch.setenv("AEGIS_API_PORT", port)
        assert [_verdict(inputs) for inputs in corpus] == expected
        assert fingerprint(POLICY_VERSION) == PINNED_DIGEST

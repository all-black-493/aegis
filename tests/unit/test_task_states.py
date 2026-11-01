from aegis.authorization.catalog import Action
from aegis.authorization.contract import Effect, Stage
from aegis.tasks.states import TERMINAL_STATES, TRANSITION_RULES, TaskState, rules_for


def _pairs() -> set[tuple[TaskState, TaskState]]:
    return {(rule.source, rule.target) for rule in TRANSITION_RULES}


def test_rules_are_unique() -> None:
    keys = [(rule.source, rule.target, rule.decision) for rule in TRANSITION_RULES]

    assert len(keys) == len(set(keys))


def test_final_states_are_final_and_created_is_only_a_start() -> None:
    assert not {source for source, _ in _pairs()} & TERMINAL_STATES
    assert TaskState.CREATED not in {target for _, target in _pairs()}


def test_every_other_state_can_be_left() -> None:
    sources = {source for source, _ in _pairs()}

    assert sources == set(TaskState) - TERMINAL_STATES


def test_approval_cannot_lead_to_queued_before_phase_6() -> None:
    assert rules_for(TaskState.AWAITING_APPROVAL, TaskState.QUEUED) == ()


def test_only_a_policy_allow_admits_or_starts_a_task() -> None:
    admitting = [
        rule
        for rule in TRANSITION_RULES
        if rule.target in {TaskState.QUEUED, TaskState.RUNNING} and rule.decision is not None
    ]

    assert admitting
    for rule in admitting:
        assert rule.decision is not None
        assert (rule.decision.effect, rule.decision.stage) == (Effect.ALLOW, Stage.POLICY)


def test_authorization_decisions_only_allow_or_deny() -> None:
    for rule in TRANSITION_RULES:
        if rule.decision is not None and rule.decision.stage is Stage.AUTHORIZATION:
            assert rule.decision.effect is not Effect.APPROVAL_REQUIRED


def test_execution_and_worker_transitions_need_a_job() -> None:
    for rule in TRANSITION_RULES:
        executes = rule.decision is not None and rule.decision.action is Action.TASK_EXECUTE
        if executes or rule.decision is None:
            assert rule.requires_job, rule
        else:
            assert not rule.requires_job, rule


def test_an_execution_denial_may_come_from_either_stage() -> None:
    stages = {
        rule.decision.stage
        for rule in rules_for(TaskState.QUEUED, TaskState.FAILED)
        if rule.decision is not None
    }

    assert stages == {Stage.AUTHORIZATION, Stage.POLICY}

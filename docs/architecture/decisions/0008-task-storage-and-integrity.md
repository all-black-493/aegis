# ADR-0008: Task and decision storage with integrity rules

- **Status:** Accepted
- **Date:** 2026-11-01

## Context

Tasks change state only when a security decision justifies the change (ADR-0006). If that link were checked only in Python, a bug or a direct SQL session as `aegis_app` could queue or run a task without a valid decision, or change a task without leaving history. The database must refuse those changes too, so that the history of every task is internally consistent whatever code wrote it.

## Decisions

| Area | Decision |
|---|---|
| Tables | `aegis.tasks`, `aegis.security_decisions` (one row per saved `SecurityDecision`), `aegis.task_state_transitions` (the history) and `aegis.task_transition_rules` (the legal transitions, as reference data). |
| State machine | `aegis.tasks.states.TRANSITION_RULES` lists every legal transition with the decision it needs (action, effect, stage) or none, and whether it needs a job. The migration writes the same rows into `task_transition_rules`, and a test proves the two identical. A second test proves the SQL value lists for states, kinds, actions, effects and actor kinds equal the Python enums. |
| Timestamps | Triggers stamp `tasks.created_at` and `updated_at`, `finished_at` on entering a final state, `cancel_requested_at`, `security_decisions.decided_at` and `task_state_transitions.occurred_at` with the transaction time. No caller can supply them. |
| Writes | `apply_transition()` locks the task with `FOR NO KEY UPDATE`, checks the expected state and version (else `TransitionConflictError`), checks the transition and its decision against C1–C9 in Python, writes the history row, then updates the task only if its state and version are still the expected ones, and records `task.transitioned` in the same transaction. `FOR NO KEY UPDATE` does not conflict with the key-share locks that foreign keys from decisions and history take, so concurrent transitions conflict instead of deadlocking. |
| Privileges | `aegis_app` may read all four tables. It may insert tasks (fixed columns only), decisions and history rows, and update only `state`, `version`, `cancel_requested_by`, `result` and `failure_code`. It cannot update or delete decisions, history or rules, or delete tasks. This is narrower than the plan's list: the timestamp columns are stamped by triggers, so they need no grant. |

## Integrity rules

| Rule | Requirement | Enforcement in the database |
|---|---|---|
| D1 | Only legal state changes, and the version rises by exactly 1 with each change and never otherwise | `tasks_before_update` checks `task_transition_rules` and the version |
| D2 | Every state change has its history row, written earlier in the same transaction with the same task, states and new version | `tasks_before_update` requires the row, matching `occurred_at = now()` |
| D3 | A decision's fields fit together | `CHECK` constraints on `security_decisions`; the actor's kind must match the identity, the actor's credential must belong to the actor, and a task decision's subject and resource owner must be that task's initiator and owner (composite foreign keys) |
| D4 | The decision justifies the transition | The history row's decision columns are a composite foreign key to the decision (same task, action, effect, stage and time); `task_state_transitions_before_insert` requires a matching rule, including whether a job is present, and that the decision's job attempt equals the row's |
| D5 | The decision was made in the same transaction and justifies only one transition | `CHECK (decision_decided_at = occurred_at)` and a unique `decision_id` |
| D6 | No history row without a real state change | A deferred constraint trigger checks at commit that the task reached the row's version |
| D7 | The fixed parts of a task never change | Column grants for `aegis_app`; `tasks_before_update` for every role |
| D9 | No transition from `awaiting_approval` to `queued` | Absent from the rules table until Phase 6 |

Further rules enforced the same way:
- A task is inserted only in state `created` at version 0, and a deferred trigger refuses to commit a task still in `created`.
- A task in a final state cannot change at all.
- A cancellation request, once made, cannot change, and a running task can be cancelled only after one.
- Tasks are never deleted, and decisions, history and rules are append-only, including for the owner and including `TRUNCATE`.

D8 (job attempts and fencing) arrives with the jobs table in Increment 10.

## Consequences and limitations

- These rules prove internal consistency, not legitimacy. Anyone holding `aegis_app` credentials can insert a consistent but fabricated allow decision and use it (ADR-0010, N1). The backstops are the worker's independent re-check at claim time (Increment 10) and tamper-evidence (Phase 5).
- C5 (the expected actor) and C7 (the current policy) are checked only in Python: the database cannot know who should be acting or which policy is running.
- D5 compares transaction start times, so a decision from another transaction that started in the same microsecond would pass. Reaching that requires `aegis_app` credentials, which already allow fabrication.
- Single use is enforced by the database alone; `apply_transition()` relies on the unique `decision_id`.
- Callers pass the running policy's version and fingerprint (`PolicyRef`), which `DecisionService.policy` provides (ADR-0007). The task API arrives in Increment 9.
- The owner and superuser can disable the triggers (ADR-0010, N3).

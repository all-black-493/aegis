# ADR-0007: Policy evaluation and the decision service

- **Status:** Accepted
- **Date:** 2026-11-01

## Context

Authorization (ADR-0006) answers whether an identity may attempt an action. Some actions also need rules about the request itself: what is being submitted, how much the submitter already has running, and whether the task may still run when the worker picks it up. Those rules must be deterministic, versioned and auditable. They must not depend on configuration, and the decisions they produce must be saved so they can be checked again later.

## Decisions

| Area | Decision | Rationale |
|---|---|---|
| Two stages | `decide(policy, inputs)` runs `authorize()` first. An authorization deny ends evaluation at the `authorization` stage. `task.submit` and `task.execute` then run their policy rules at the `policy` stage. Every other action, such as `task.cancel`, is decided by authorization alone. | The decision contract and the transition rules (ADR-0008) already expect this split. |
| Combining | Every rule returns allow, deny, approval required or nothing. Any deny wins, then approval required, then allow, and the decision carries every reason of the winning effect. If no rule matches, the result is deny `no_matching_rule`. If a rule raises an error, or facts are missing, the result is deny `evaluation_error`. | Deny overrides everything, and the default is deny. |
| Submission rules | `system_submitter`, `kind_not_registered`, `input_too_large` (16 KiB), `input_invalid` (`noop` takes `{}`; `wait` takes `{"seconds": n}` with an integer from 0 to 300; `generate` takes exactly `{"prompt": text, "max_output_tokens": n}` with 1 to 8,000 characters that are not all whitespace and an integer from 1 to 512, ADR-0015), `active_task_quota_exceeded` (10 active tasks per initiator) and `long_wait_needs_approval` (`wait` over 30 s) deny or require approval. `submission_allowed` allows a well-formed task of a registered kind. | The Phase 1 plan, §4.2. |
| Execution rules | E1, whether the worker holds `task:execute`, is the authorization stage, with reason `executor_not_authorized`. E2 `initiator_disabled`, E3 `initiator_not_authorized` (the initiator no longer holds `task:create`) and E4 `submitting_credential_revoked` deny. An expired credential is not a reason to deny. E6 re-applies the current task rules, so a newer policy can turn an earlier allow into approval required or deny. `execution_allowed` allows the rest. | The Phase 1 plan, §4.7. E5 (cancellation requested) is not a policy rule: the worker cancels the task instead of failing it (ADR-0009). |
| Purity | The rules see only explicit facts: no clock, randomness, configuration or environment. `aegis.policy` may not import `aegis.config` or read the environment (`tests/unit/test_layering.py`). A test shows decisions and the fingerprint are identical under every `AEGIS_ENV`, log level and API port. | Configuration cannot weaken security policy. |
| Version and fingerprint | `POLICY_VERSION` is a label. The fingerprint is SHA-256 over that label and the source bytes of `aegis.policy.facts` and `aegis.policy.rules`. A test pins both, so any change to a rule, threshold or fact fails CI until the version is bumped and the new fingerprint is pinned in the same reviewed change. Version `2026.11.01-2` added the job-attempt cap `MAX_JOB_ATTEMPTS` (ADR-0009). Version `2026.11.02-1` added the `generate` kind, its input limits and its fixed sampling (ADR-0015). | A rule cannot change without a new version, and decisions record exactly which rules made them. |
| Decision service | `DecisionService` gathers facts from the database as `aegis_app`, evaluates them, and builds a `SecurityDecision` stamped with the transaction time and the policy's version and fingerprint. `record()` saves the decision, its inputs and a `security.decision` audit event in the caller's transaction. Submission decisions take a per-initiator advisory lock before counting active tasks, so concurrent submissions cannot exceed the quota. | One place builds every decision, and it is saved with everything needed to check it again. |
| Saved inputs | Every saved decision stores its inputs in `security_decisions.inputs` (migration 0005): the actor, the resource, and the submission or execution facts. Those include the task's kind and input, but an input over 16 KiB, or one that isn't a JSON object, is stored only as its size. The column must be a JSON object of at most 64 KiB. | Replay needs the exact facts. Inputs never contain credentials or tokens. |
| Replay | `DecisionService.replay(decision_id)` re-runs the saved inputs through the current policy and returns the saved and replayed verdicts. It refuses a decision made under another version or fingerprint. | Saved decisions can be shown to follow from their inputs. |
| What is saved | The service decides state-changing actions (submit, execute, cancel), and the caller saves every such decision, whatever its effect, including denials and evaluation errors. A denied submission is saved without a task. It also decides reads and listings (`task.read`, `task.list`, `task.list_all`) at the authorization stage; only their denials are saved (ADR-0011). | The Phase 1 plan, §4.1: every decision about a change, and every denial, is saved. |

## Consequences and limitations

- Only the current policy is in the code, so replay works only for decisions made under it. Decisions made under an earlier version stay in the database, labelled with that version and fingerprint.
- The fingerprint changes with any byte of the two modules, including comments and formatting. That is deliberate: every edit needs a version bump.
- Task inputs that are rejected are kept in the decision record, as accepted ones are in `tasks`. No task kind takes secrets, but a client could still put one in an input, including a `generate` prompt (ADR-0015).
- Facts are read at the time of the decision. Role changes or revocations after an allow are seen at the next decision (for example, when the worker claims the task), not during a run (ADR-0009, Increment 10).
- The task API (ADR-0011) and the worker (ADR-0009) make every decision through the service.
- `authz.denied` events are not emitted yet: every denial here is a saved decision with a `security.decision` event.

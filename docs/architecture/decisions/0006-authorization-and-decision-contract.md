# ADR-0006: Authorization model and security-decision contract

- **Status:** Accepted
- **Date:** 2026-11-01

## Context

Every governed action in AEGIS passes, in order:

1. authentication;
2. authorization;
3. a policy decision;
4. human approval (Phase 6);
5. runtime enforcement by OpenShell (Phase 3).

Authorization must be default-deny, independent of configuration and storage, and identical for the API, services and worker. Decisions must share one contract, so that any component can check whether a decision really justifies a given state change. A decision ID alone does not prove that.

## Decisions

| Area | Decision | Rationale |
|---|---|---|
| Roles and permissions | Defined in code (`aegis.authorization.catalog`). See the table below. Only role *assignments* will be stored in the database (Increment 5). | The permission catalog can only change through reviewed code. Nothing at runtime can invent a permission. |
| System roles | `worker` is a system role. Only system identities may hold it, and system identities may hold no other role and no credentials. `ActorContext` rejects any other combination when it is created. | The execution identity cannot be given human powers, and humans cannot become the executor. |
| Actions | `task.submit`, `task.read`, `task.list`, `task.list_all`, `task.cancel`, `task.execute`. Ownership decides which permission applies: reading or cancelling your own task needs `task:read` or `task:cancel`, and anyone else's needs `task:read_any` or `task:cancel_any`. | Actions are verbs. "Own" versus "any" is a property of the permission, not a separate action. |
| `authorize()` | A pure function of the actor, the action and the resource. It returns **allow or deny only**, never approval-required, with a stable reason code and the permission that granted or would have granted the action. Reasons: `permitted`, `permitted_as_owner`, `missing_permission`, `owner_only` (submitting a task owned by someone else), `resource_missing`, `unknown_action`. Unknown actions and missing resources are denied. | Default deny, and a result that is easy to audit. Approval belongs to the policy stage. |
| Purity | `aegis.authorization` may not import configuration, the database, audit, identity, tasks, jobs, SQLAlchemy, psycopg or Alembic, and may not read environment variables. `tests/unit/test_layering.py` enforces this. | Authorization answers depend only on their inputs and can be tested exhaustively. |
| Decision contract | `SecurityDecision` is an immutable record with these fields: `decision_id`, `decided_at`, `actor_id`, `actor_kind`, `actor_credential_id`, `subject_id`, `action`, `resource_type`, `resource_id`, `resource_owner_id`, `task_id`, `effect`, `stage`, `reason_codes`, `policy_version`, `policy_digest`, `request_id`, `job_id` and `job_attempt`. | The same record is used by the API, the services and the worker, and maps one-to-one onto the `security_decisions` table (Increment 7). |
| Decision invariants | Checked when a decision is created: at least one well-formed reason code; a policy version of 1–64 characters; a 64-hex-character fingerprint; an authorization-stage decision can only allow or deny; job ID and attempt together, attempt at least 1; timestamps with a time zone; a task decision's resource is that task; system actors have no credential; a well-formed request ID. | A malformed decision cannot exist in memory. |
| Consistency rules | `require_consistent(decision, requirement)` checks C1–C9 against what a transition needs. It reports every failed rule by ID, never values. | A decision is accepted only if it matches the task, action, effect, subject, actor, resource, policy, transaction and stage. |

| Permission | admin | operator | auditor | worker (system only) |
|---|---|---|---|---|
| `task:create` | ✓ | ✓ | – | – |
| `task:read` (own) | ✓ | ✓ | – | – |
| `task:read_any` | ✓ | – | ✓ | – |
| `task:cancel` (own) | ✓ | ✓ | – | – |
| `task:cancel_any` | ✓ | – | – | – |
| `task:execute` | – | – | – | ✓ |

## Consistency rules and where they are enforced

| Rule | Requirement | In code (now) | In the database |
|---|---|---|---|
| C1 | Same task and job attempt | `require_consistent` | Composite foreign key (Increment 7) and the job-attempt check (Increment 10) |
| C2 | Action matches the transition | `require_consistent` | Transition `CHECK` mapping (Increment 7) |
| C3 | Effect matches the target state; deny and approval-required never justify `queued` or `running` | `require_consistent` | Transition `CHECK` mapping (Increment 7) |
| C4 | Subject is the task's initiator | `require_consistent` | Composite foreign key to the task's initiator (Increment 7) |
| C5 | Actor is the expected actor; execution is by a system identity | `require_consistent` | Not enforceable without cross-table checks; tests only |
| C6 | Resource is this task and its owner | `require_consistent` and decision invariants | `CHECK` constraints (Increment 7) |
| C7 | Current policy version and fingerprint | `require_consistent`, against the running policy (Increment 8) | Not enforceable: the database does not know the current policy |
| C8 | Decided in this transaction, used once | `require_consistent` compares `decided_at` with the transaction time | `decided_at = occurred_at` and a unique decision reference (Increment 7) |
| C9 | Required stage | `require_consistent` | Transition `CHECK` mapping (Increment 7) |

## Consequences and limitations

- Nothing calls `authorize()` or `require_consistent()` yet. The services, API and worker adopt them in Increments 7–10.
- Authentication, not authorization, rejects disabled identities and revoked credentials (Increment 5). The checks the worker repeats about the initiator happen at the policy stage (Increment 8).
- C5 checks the actor's identity and kind, not its roles. Whether the worker holds `task:execute` is decided by `authorize()` when the decision is made.
- Single use under C8 can only be enforced by the database (Increment 7).
- Per-task grants for agent identities are not modelled yet. `authorize()` already takes the resource, so they can be added without changing its signature (Phase 4).

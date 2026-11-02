# ADR-0019: The `enforcement_check` task kind

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

The probes (ADR-0018) verify OpenShell's enforcement from outside the sandbox, but only tests run them. Phase 3 needs operators to be able to ask, through the ordinary API and worker, whether the configured runtime enforces what AEGIS expects, and to get an answer that is decided by policy, run under a fenced lease and fully audited. The answer must fail closed: a run that is not clearly verified must never look like a success.

## Decisions

| Area | Decision | Rationale |
|---|---|---|
| Kind and input | `enforcement_check` takes exactly `{}`. Policy `2026.11.02-2` registers it, and any input is refused with `input_invalid`. Migration 0008 adds the kind to the `CHECK` on `tasks.kind`. | A task cannot choose the image, the policy, the probes or the sandbox. What runs is AEGIS's own fixed code. |
| Who may run it | Anyone with `task:create` (operators and administrators), with no approval, under the existing quota of 10 active tasks (decision U6). Auditors cannot. | The check only proves restrictions. Its sandbox has no secrets, and its only network peer is AEGIS's canary. |
| Where it runs | `aegis.jobs.enforcement.EnforcementCheck` holds the runtime, the probe image and the audit store. The worker builds one at startup when `AEGIS_SANDBOX_RUNTIME=openshell`, and none otherwise. It reloads the sandbox policies for every run, so the fingerprint it audits belongs to the files the gate submits. | One instance per process, built at the entry point and injected. The policies are hashed when they are used, not when the worker starts. |
| Handler capability | `HandlerContext.check_enforcement()` is bound to the task, its job and its halt signal. The worker grants it only to `enforcement_check` tasks; any other handler that calls it fails with `sandbox_unavailable`. Without a runtime it fails the same way. | H6: no handler gets the runtime, the database or settings, and no other kind can create a sandbox. |
| Sandbox | Named `aegis-<first 10 hex digits of the job ID>-<attempt>`, at most 19 characters (ADR-0016), and labelled `aegis.task`, `aegis.job` and `aegis.attempt`. It is opened through the gate (ADR-0017) and always deleted. | Every attempt gets its own sandbox, and orphan cleanup can tell whose it is. |
| Verdict to outcome | `verified` gives `succeeded`, with the result `{"verdict": "verified", "checks": {check: "held", ...}}`. `violated` fails the task with `enforcement_violation`; `inconclusive` fails it with `enforcement_inconclusive`. | Only every check holding counts as success, as ADR-0018 decides. |
| Runtime errors | A retryable runtime error (`unreachable`, `not_connected`, `canary_unavailable`, a stalled exec or delete) is retried with backoff up to the attempt limit, then `attempts_exhausted`. Every other error fails the task with its own code, such as `policy_refused`, `effective_policy_refused`, `image_missing`, `image_unrecognised`, `version_mismatch`, `global_policy_active`, `disabled` or `policy_missing`. A new `RuntimeStatus.retryable` lets the gate tell an unreachable gateway (retried) from a refused one. | Transient gateway failures are retried; everything else fails closed with a reason. |
| Audit | After the run, one `enforcement.checked` event per check, all written in one transaction. Each has outcome `success` only if the check held, and reason `held`, `violated` or `inconclusive`. The target is the sandbox. The details are `attempt`, `check`, `kind`, `expected` (`allowed` or `refused`), `observed` (`allowed`, `refused` or `unclear`), `exit_code` and `corroborated`. The sandbox's own `sandbox.created` and `sandbox.deleted` events now carry the task and job IDs. If the checks cannot be recorded, the task fails with `handler_error`. | The full chain for one task is: decision, creation, admission, sandbox creation, sandbox deletion, every check, then the final transition or `job.failed`. |
| Violations | A violation is logged at `ERROR` (`enforcement violated`, with the failing checks). Its `enforcement.checked` events have outcome `failure`, and `job.failed` carries `enforcement_violation`. | It is a security event, visible in the logs and the audit store, and never retried. |
| Stopping | Cancellation, a disabled initiator and shutdown set the halt signal. The suite checks it before each probe: probes that did not run are unobserved (`inconclusive`), and the runtime's records are not polled. The sandbox is deleted as usual. | A stop ends the run within one probe, and a stopped run is never verified. |
| Orphans | The worker's loop sweeps orphaned sandboxes at its first step and then once a minute (`OrphanSweep`), replacing the start-up-only cleanup. `clean_orphans` lists the sandboxes before it reads which jobs are live. | A job is running before its sandbox exists, so a claim that lands between the two reads can never lose its sandbox. |
| Worker structure | `jobs/worker.py` was split by responsibility: the loop, recovery and admission (`worker.py`), the handler thread and heartbeats (`supervision.py`), and task transitions with their audit records (`settlement.py`). | No module mixes scheduling, supervision and record keeping. |
| Downgrade | Migration 0008's downgrade (development only, ADR-0003) is refused while any `enforcement_check` task is unfinished. Finished ones are kept under a `NOT VALID` constraint, as in 0007. | History is never lost. |

## Handler contract (ADR-0009), revised

- **H1:** handlers have no outside effects, with two exceptions: `generate` (the local model server, ADR-0015) and `enforcement_check`. The latter creates and deletes one sandbox through the runtime contract, and its only network peer is AEGIS's canary.
- **H5:** the registry holds exactly `noop`, `wait`, `generate` and `enforcement_check`, the same set as the policy's `TASK_KINDS`.
- **H6:** the handler context offers `stop_requested()`, `wait(seconds)`, `generate(request)` and `check_enforcement()`, and still no database, settings or credentials.

## Consequences and limitations

- **The check proves the configured runtime, not a task's own sandbox.** No other task kind runs in a sandbox yet. Agent workloads arrive in Phase 4 and will run under the same gate and policies.
- **One check at a time per host.** The canary's ports are fixed (ADR-0018). A second concurrent check gets `canary_unavailable` and is retried.
- **A host whose Docker bridge is not `172.17.0.1`** retries `canary_unavailable` until the attempts run out (ADR-0018).
- **A check stopped by shutdown can leave its sandbox behind** if the deletion outlasts the worker's grace period. The next sweep removes it.
- **A running worker's sweep deletes the live tests' sandboxes**, because they belong to no job in its database (ADR-0017). Stop the worker before `make test-openshell`.
- **At-least-once delivery.** A check may run again after a crash or a lost lease. Each attempt has its own sandbox and its own `enforcement.checked` events.

# Phase 3 threat model

- **Status:** Draft. Phase 3 is in progress; this document grows with it and is completed in Increment 5.
- **Date:** 2026-11-02
- **Covers:** the `enforcement_check` task kind (Increment 4) and the sandbox machinery it uses (ADR-0016 to ADR-0019).
- **Extends:** the [Phase 1](phase-1-threat-model.md) and [Phase 2](phase-2-threat-model.md) threat models. Everything there still holds unless this document says otherwise.

## 1. Scope

**What Phase 3 adds so far.**

- **NVIDIA OpenShell 0.1.6** as the runtime enforcement boundary, reached only through a version-pinned CLI adapter (ADR-0016).
- **AEGIS's sandbox policies, the probe image and the prover gate** (ADR-0017).
- **Enforcement probes** that check OpenShell's restrictions from outside the sandbox (ADR-0018).
- **A fourth task kind, `enforcement_check`**, which runs the probes through the API and the worker and audits every check (ADR-0019).

**Still out of scope:** agents and their workloads (Phase 4), provenance (Phase 5), approvals (Phase 6) and evidence verification (Phase 7). No task but `enforcement_check` runs in a sandbox, and nothing a task supplies ever runs in one.

## 2. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| The enforcement verdict | The task's result and outcome, and one `enforcement.checked` event per check | Operators and later phases rely on it to know whether the runtime enforces what AEGIS expects |
| The sandbox policies and their fingerprint | `deploy/openshell/`, pinned by a unit test, audited in `sandbox.created` | They define what a sandbox may do |
| The OpenShell gateway | The host, shared with the user's other sandboxes | The CLI identity is a Platform Admin on a local gateway (ADR-0016) |

## 3. Trust boundaries

| Boundary | Between | Controls |
|---|---|---|
| B5, revised | The worker and its handlers | The closed registry now holds `noop`, `wait`, `generate` and `enforcement_check`. `check_enforcement()` is granted only to `enforcement_check` tasks and offers no runtime, database or settings |
| B8 | The worker and OpenShell | Allow-listed CLI commands in AEGIS's workspace only, a scrubbed environment, version checks on every sandbox, and the prover gate before any sandbox is used (ADR-0016, ADR-0017) |
| B9 | The sandbox and AEGIS's judgement | Results come from the exit status and output the runtime reports and from what AEGIS's canary received, never from a report written inside the sandbox (ADR-0018) |

## 4. Threats and mitigations: `enforcement_check`

| ID | Threat | Mitigations | Verified by |
|---|---|---|---|
| S1 | A task chooses what runs in the sandbox, or under which policy or image | The input is exactly `{}`, refused otherwise at submission and again by the handler. The probes, policies and image are AEGIS's own and fixed | `security/test_enforcement_check.py::test_the_registry_matches_the_policy_and_input_is_refused_before_any_sandbox`, `unit/test_policy.py::test_submission_rules`, `unit/test_jobs.py::test_an_enforcement_check_takes_no_input` |
| S2 | A broken or permissive runtime is reported as enforcing | A task succeeds only if every check held. A request the canary received, or an action that evidently happened, is a violation whatever the sandbox printed. Runtime records alone never verify a check | `security/test_enforcement_check.py::test_a_request_the_canary_saw_fails_the_task_as_a_violation_and_is_audited`, `::test_a_write_that_succeeded_inside_the_sandbox_fails_the_task`, `::test_runtime_records_without_the_canary_never_make_a_check_succeed` |
| S3 | A disabled, misconfigured or unavailable runtime lets work run outside a sandbox | Without a runtime the task fails with `sandbox_unavailable`. A disabled runtime refuses before anything is created. An unreachable gateway is retried, then fails with `attempts_exhausted`, having created and executed nothing | `security/test_enforcement_check.py::test_without_a_runtime_an_enforcement_check_fails_closed_and_runs_nothing`, `::test_a_disabled_runtime_refuses_before_anything_is_created`, `::test_an_unavailable_runtime_is_retried_and_never_executes_anything` |
| S4 | A refused policy, image or OpenShell version is used anyway | The gate refuses before or right after creation and deletes the sandbox. The task fails with the refusal's code and runs no probe | `integration/test_enforcement_check_tasks.py::test_a_refused_sandbox_fails_the_task_without_running_a_probe`, `::test_a_missing_probe_image_fails_the_task`, `security/test_sandbox_gate.py` |
| S5 | A check's results go unrecorded | All checks are written in one transaction after the run. If that write fails, the task fails with `handler_error`, and the sandbox is still deleted | `security/test_enforcement_check.py::test_a_check_whose_results_cannot_be_audited_never_succeeds` |
| S6 | Another task kind creates sandboxes through the handler context | The worker grants the capability to `enforcement_check` tasks only; any other handler gets `sandbox_unavailable` | `security/test_enforcement_check.py::test_only_an_enforcement_check_task_can_create_a_sandbox` |
| S7 | The configured runtime changes security decisions | Policy cannot import the runtime or configuration. Decisions for the same task are identical with no runtime, a disabled one and OpenShell | `security/test_enforcement_check.py::test_decisions_are_identical_whichever_runtime_is_configured`, `unit/test_policy.py::test_decisions_do_not_depend_on_the_environment`, `unit/test_layering.py` |
| S8 | Someone without `task:create` starts checks | Submission requires `task:create`: operators and administrators, not auditors. The quota of 10 active tasks applies | `security/test_enforcement_check.py::test_an_auditor_cannot_start_an_enforcement_check` |
| S9 | A sandbox outlives its task, or a running task loses its sandbox | The gate always deletes it. A stopped run deletes it too. The worker sweeps orphans once a minute, and lists sandboxes before reading which jobs are live | `integration/test_enforcement_check_tasks.py::test_cancelling_a_check_stops_the_probes_and_deletes_the_sandbox`, `::test_the_worker_sweeps_orphaned_sandboxes_between_tasks`, `unit/test_sandbox_gate.py::test_live_jobs_are_read_only_after_the_sandboxes_are_listed` |

## 5. Failure behaviour

| Failure | Behaviour | Verified by |
|---|---|---|
| No runtime configured (`AEGIS_SANDBOX_RUNTIME=none`) | `failed` (`sandbox_unavailable`) | `security/test_enforcement_check.py::test_without_a_runtime_an_enforcement_check_fails_closed_and_runs_nothing` |
| Gateway unreachable or not connected | Retried with backoff, then `failed` (`attempts_exhausted`); each attempt gets its own sandbox | `integration/test_enforcement_check_tasks.py::test_an_unreachable_gateway_is_retried_and_the_next_attempt_gets_its_own_sandbox`, `::test_attempts_are_bounded_when_the_runtime_never_recovers` |
| Policy, image, version or global policy refused | `failed` with the refusal's code; no probe runs | `integration/test_enforcement_check_tasks.py::test_a_refused_sandbox_fails_the_task_without_running_a_probe` |
| A check violated | `failed` (`enforcement_violation`), logged at `ERROR`, never retried | `security/test_enforcement_check.py::test_a_request_the_canary_saw_fails_the_task_as_a_violation_and_is_audited` |
| A check inconclusive (a failed control, a timeout, an unexplained error) | `failed` (`enforcement_inconclusive`) | `security/test_enforcement_check.py::test_runtime_records_without_the_canary_never_make_a_check_succeed` |
| Cancellation or shutdown during a run | Probes stop before the next one; unrun checks are `inconclusive`; the sandbox is deleted | `integration/test_enforcement_check_tasks.py::test_cancelling_a_check_stops_the_probes_and_deletes_the_sandbox` |
| Audit write fails | `failed` (`handler_error`); nothing is reported as verified | `security/test_enforcement_check.py::test_a_check_whose_results_cannot_be_audited_never_succeeds` |

## 6. Residual risks

- **The check proves the configured runtime, not a workload.** No other task runs in a sandbox yet (Phase 4).
- **The canary is host-specific and single-run.** It needs `docker0` at `172.17.0.1` and free ports 18901 and 18902; otherwise checks are retried and then fail (ADR-0018).
- **The probes cover OpenShell's default enforcement surface,** not providers, middleware, other protocols or GPUs (ADR-0018).
- **A shutdown can leave a sandbox behind** until the next sweep, at most a minute while a worker runs.
- **The gateway is shared.** AEGIS restricts itself in code; the workspace is a scope, not an access boundary (ADR-0016).

## 7. Running the tests

```bash
make up
make migrate
make test-security      # includes the enforcement_check boundary
make test-integration   # includes enforcement_check tasks through the API and the worker

# Optional: the same task against the real OpenShell gateway (stop any running worker first)
make openshell-init
make test-openshell
```

CI runs the fake-runtime tests and the security suite on every pull request. CI never uses a real OpenShell, so the live run is local, and its evidence is recorded in the pull request.

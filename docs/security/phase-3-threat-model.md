# Phase 3 threat model

- **Status:** Accepted for Phase 3
- **Date:** 2026-11-06
- **Covers:** the code as built at the end of Phase 3, against NVIDIA OpenShell 0.1.6 and re-verified on 0.1.7 in Phase 4 (ADR-0016 to ADR-0019).
- **Extends:** the [Phase 1](phase-1-threat-model.md) and [Phase 2](phase-2-threat-model.md) threat models. Everything there still holds unless this document says otherwise.

## 1. Scope

**What Phase 3 adds.**

- **NVIDIA OpenShell** as the runtime enforcement boundary, reached only through a version-pinned CLI adapter (ADR-0016).
- **AEGIS's sandbox policies, the probe image and the prover gate** (ADR-0017).
- **Enforcement probes** that check OpenShell's restrictions from outside the sandbox (ADR-0018).
- **A fourth task kind, `enforcement_check`**, which runs the probes through the API and the worker and audits every check (ADR-0019).

**The controlled workload is AEGIS's own.** A task carries no code, commands, image or policy. What runs in a sandbox is the fixed probe catalog, as the acceptance criterion defines it.

**Still out of scope:**

- agents, tools and any task-supplied commands (Phase 4);
- providers and credentials inside sandboxes;
- provenance (Phase 5), approvals (Phase 6) and evidence verification beyond the probes (Phase 7);
- network middleware, GPUs, and OpenShell's VM and Kubernetes drivers;
- a CI workflow against real OpenShell.

No task but `enforcement_check` runs in a sandbox. `noop`, `wait` and `generate` still run in the worker process, and AEGIS claims no isolation for them.

## 2. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| The enforcement verdict | The task's result and outcome, and one `enforcement.checked` event per check | Operators and later phases rely on it to know whether the runtime enforces what AEGIS expects |
| The sandbox policies and their fingerprint | `deploy/openshell/`, pinned by a unit test, audited in `sandbox.created` | They define what a sandbox may do |
| The probe image | A local image ID in `AEGIS_OPENSHELL_IMAGE`, with a release marker | It is the only thing AEGIS runs in a sandbox |
| The OpenShell gateway and its mTLS keys | The host, shared with the user's other sandboxes | The CLI identity is a Platform Admin on a local gateway (ADR-0016) |
| AEGIS's own secrets | `.env` and the worker's memory | They must never reach a sandbox |

## 3. Trust boundaries

| Boundary | Between | Controls |
|---|---|---|
| B5, revised | The worker and its handlers | The closed registry now holds `noop`, `wait`, `generate` and `enforcement_check`. `check_enforcement()` is granted only to `enforcement_check` tasks and offers no runtime, database or settings |
| B8 | The worker and OpenShell | Allow-listed CLI commands in AEGIS's workspace only, a scrubbed environment, version checks on every sandbox, and the prover gate before any sandbox is used (ADR-0016, ADR-0017) |
| B9 | The sandbox and AEGIS's judgement | Results come from the exit status and output the runtime reports and from what AEGIS's canary received, never from a report written inside the sandbox (ADR-0018) |

## 4. Threats and mitigations

Paths are relative to `tests/`. Tests marked *live* run only through `make test-openshell`, against real OpenShell.

### The runtime boundary

| ID | Threat | Mitigations | Verified by |
|---|---|---|---|
| R1 | AEGIS's secrets reach the OpenShell CLI or a sandbox | The CLI runs with a scrubbed environment. The sandbox gets no provider, and nothing on the host is mounted into it | `security/test_runtime_boundary.py::test_no_aegis_secret_or_openshell_override_reaches_the_cli`, `integration/test_sandbox_gate_live.py::test_no_host_secret_reaches_a_sandbox` (*live*) |
| R2 | AEGIS touches sandboxes that are not its own, or uses commands it should not | Only allow-listed commands run, always in AEGIS's workspace, and only on sandboxes named `aegis-*` and labelled `aegis.managed=true` | `security/test_runtime_boundary.py::test_only_allow_listed_commands_run_and_always_in_aegis_scope`, `::test_other_sandboxes_are_never_listed_or_deleted`, `security/test_sandbox_gate.py::test_orphan_cleanup_never_touches_sandboxes_that_are_not_aegis` |
| R3 | An unverified OpenShell version behaves differently from what was verified | The CLI, prover and gateway must each report exactly the verified version, checked before every sandbox | `security/test_runtime_boundary.py::test_an_unverified_or_unreachable_runtime_creates_nothing`, `security/test_enforcement_check.py::test_a_runtime_refused_before_use_fails_the_task_with_its_code_and_runs_no_probe` |
| R4 | A widened or unproven policy is used | The prover must find both the submitted policy and the sandbox's effective policy `within_boundary`, covering all five domains. A global policy stops the gate | `security/test_sandbox_gate.py::test_a_submitted_policy_that_is_not_proven_never_creates_a_sandbox`, `::test_an_effective_policy_widened_by_a_provider_is_refused_and_deleted`, `::test_a_global_policy_stops_the_gate_before_anything_is_created` |
| R5 | A sandbox policy changes silently | A fingerprint over the version, both policies and the Dockerfile is pinned by a test, and every sandbox's fingerprint is audited | `unit/test_sandbox_gate.py::test_the_sandbox_policies_are_pinned` |
| R6 | Another image runs in place of AEGIS's probe | The image must carry AEGIS's release marker; otherwise the sandbox is deleted unused | `security/test_sandbox_gate.py::test_an_unrecognised_image_is_deleted_unused` |

### `enforcement_check`

| ID | Threat | Mitigations | Verified by |
|---|---|---|---|
| S1 | A task chooses what runs in the sandbox, or under which policy or image | The input is exactly `{}`, refused otherwise at submission and again by the handler. The probes, policies and image are AEGIS's own and fixed | `security/test_enforcement_check.py::test_the_registry_matches_the_policy_and_input_is_refused_before_any_sandbox`, `unit/test_policy.py::test_submission_rules`, `unit/test_jobs.py::test_an_enforcement_check_takes_no_input` |
| S2 | A broken or permissive runtime is reported as enforcing | A task succeeds only if every check held. A request the canary received, or an action that evidently happened, is a violation whatever the sandbox printed. Runtime records alone never verify a check. A deliberately widened policy is caught by the probes | `security/test_enforcement_check.py::test_a_request_the_canary_saw_fails_the_task_as_a_violation_and_is_audited`, `::test_a_write_that_succeeded_inside_the_sandbox_fails_the_task`, `::test_runtime_records_without_the_canary_never_make_a_check_succeed`, `integration/test_probes_live.py::test_the_probes_catch_a_policy_that_lets_more_through` (*live*) |
| S3 | A broken sandbox is mistaken for a restrictive one | Positive controls must succeed. A failed control makes the run inconclusive, never verified | `security/test_enforcement_check.py::test_a_failed_positive_control_never_verifies_a_check`, `unit/test_probes.py::test_a_failed_control_makes_the_run_inconclusive_never_verified` |
| S4 | A disabled, misconfigured or unavailable runtime lets work run outside a sandbox | Without a runtime the task fails with `sandbox_unavailable`. Every other refusal fails it with its own code, having run nothing. Nothing ever falls back to running outside a sandbox | Section 5, and `e2e/test_phase3_workflow.py::test_a_worker_without_a_runtime_refuses_checks_and_still_runs_other_tasks` |
| S5 | A check's results go unrecorded | A sandbox whose creation cannot be audited is deleted before use. All checks are written in one transaction after the run. A failed write fails the task with `handler_error` | `security/test_enforcement_check.py::test_what_cannot_be_audited_never_succeeds` |
| S6 | Another task kind creates sandboxes through the handler context | The worker grants the capability to `enforcement_check` tasks only; any other handler gets `sandbox_unavailable` | `security/test_enforcement_check.py::test_only_an_enforcement_check_task_can_create_a_sandbox` |
| S7 | The configured runtime changes security decisions | Policy cannot import the runtime or configuration. Decisions for the same task are identical with no runtime, a disabled one and OpenShell | `security/test_enforcement_check.py::test_decisions_are_identical_whichever_runtime_is_configured`, `unit/test_policy.py::test_decisions_do_not_depend_on_the_environment`, `unit/test_layering.py` |
| S8 | Someone without `task:create` starts checks | Submission requires `task:create`: operators and administrators, not auditors. The quota of 10 active tasks applies | `security/test_enforcement_check.py::test_an_auditor_cannot_start_an_enforcement_check` |
| S9 | A sandbox outlives its task, or a running task loses its sandbox | The gate always deletes it, and a stopped run deletes it too. The worker sweeps orphans once a minute, and lists sandboxes before reading which jobs are live | `integration/test_enforcement_check_tasks.py::test_cancelling_a_check_stops_the_probes_and_deletes_the_sandbox`, `::test_the_worker_sweeps_orphaned_sandboxes_between_tasks`, `unit/test_sandbox_gate.py::test_live_jobs_are_read_only_after_the_sandboxes_are_listed` |

## 5. Failure behaviour

Every path below fails closed: no probe runs unless the row says so, and nothing runs outside a sandbox.

| Failure | Behaviour | Verified by |
|---|---|---|
| No runtime configured (`AEGIS_SANDBOX_RUNTIME=none`) | `failed` (`sandbox_unavailable`); other kinds still run | `security/test_enforcement_check.py::test_without_a_runtime_an_enforcement_check_fails_closed_and_runs_nothing`, `e2e/test_phase3_workflow.py::test_a_worker_without_a_runtime_refuses_checks_and_still_runs_other_tasks` |
| Runtime disabled by the factory | `failed` (`disabled`) | `security/test_enforcement_check.py::test_a_disabled_runtime_refuses_before_anything_is_created`, `security/test_runtime_boundary.py::test_a_disabled_runtime_executes_nothing` |
| CLI or prover missing | `failed` (`cli_missing`) | `security/test_enforcement_check.py::test_a_missing_cli_fails_the_task_and_starts_nothing` |
| No probe image configured | `failed` (`image_missing`) before the runtime is used | `security/test_enforcement_check.py::test_a_missing_probe_image_fails_the_task_before_the_runtime_is_used`, `e2e/test_phase3_workflow.py::test_a_worker_configured_for_openshell_without_an_image_refuses_checks` |
| Wrong CLI, prover or gateway version; missing workspace; a global policy | `failed` with that code (`version_mismatch`, `workspace_missing`, `global_policy_active`) | `security/test_enforcement_check.py::test_a_runtime_refused_before_use_fails_the_task_with_its_code_and_runs_no_probe` |
| Gateway unreachable or not connected | Retried with backoff, then `failed` (`attempts_exhausted`). Nothing is created | `security/test_enforcement_check.py::test_an_unavailable_runtime_is_retried_and_never_executes_anything`, `integration/test_enforcement_check_tasks.py::test_attempts_are_bounded_when_the_runtime_never_recovers` |
| Submitted policy not `within_boundary`, or coverage incomplete | `failed` (`policy_refused`). No sandbox is created | `security/test_enforcement_check.py::test_a_runtime_refused_before_use_fails_the_task_with_its_code_and_runs_no_probe` |
| Sandbox rejected, or never ready (including Landlock under `hard_requirement`) | `failed` (`sandbox_rejected`, `sandbox_not_ready`). Nothing is left behind | `security/test_enforcement_check.py::test_a_runtime_refused_before_use_fails_the_task_with_its_code_and_runs_no_probe` |
| Effective policy refused, or the image unrecognised | Sandbox deleted unused and audited; `failed` (`effective_policy_refused`, `image_unrecognised`) | `security/test_enforcement_check.py::test_a_sandbox_refused_after_creation_is_deleted_unused_and_audited` |
| The runtime stalls during the probes | The sandbox is deleted, the attempt retried, then `failed` (`attempts_exhausted`) | `security/test_enforcement_check.py::test_a_runtime_that_stalls_during_the_probes_is_retried_and_deleted_each_time` |
| A restriction violated | `failed` (`enforcement_violation`), logged at `ERROR`, audited, never retried. Every probe ran | `security/test_enforcement_check.py::test_a_request_the_canary_saw_fails_the_task_as_a_violation_and_is_audited` |
| A positive control fails, or a result is unclear | `failed` (`enforcement_inconclusive`). Every probe ran | `security/test_enforcement_check.py::test_a_failed_positive_control_never_verifies_a_check`, `::test_runtime_records_without_the_canary_never_make_a_check_succeed` |
| Cancellation or shutdown during a run | Probes stop before the next one; unrun checks are `inconclusive`; the sandbox is deleted | `integration/test_enforcement_check_tasks.py::test_cancelling_a_check_stops_the_probes_and_deletes_the_sandbox` |
| Audit write fails | `failed` (`handler_error`); nothing is reported as verified | `security/test_enforcement_check.py::test_what_cannot_be_audited_never_succeeds` |
| The sandbox cannot be deleted | `sandbox.deleted` with outcome `failure`. The verdict stands, because it was reached first, and the next sweep removes the sandbox | `security/test_enforcement_check.py::test_a_sandbox_that_cannot_be_deleted_is_audited_and_swept_later` |

## 6. Residual risks

- **The gateway identity is not scoped.** On a local gateway the CLI identity is a Platform Admin. AEGIS restricts itself in code; the workspace is a scope, not an access boundary (ADR-0016).
- **The check proves the configured runtime, not a workload.** It says what OpenShell enforced for the probe policy at that moment. Agent workloads arrive in Phase 4 and must be gated the same way.
- **The fingerprint is recorded, not enforced at run time.** A test pins it, so a change fails CI, and each run audits the fingerprint it used. A person who can change `deploy/openshell/` on the worker's host can change what is submitted, and the audit will show it. The probes then still judge what is actually enforced.
- **The release marker identifies the probe image; it does not authenticate it.** An image built with the same marker would be admitted. Its image ID is audited.
- **The canary is host-specific and single-run.** It needs `docker0` at `172.17.0.1` and free ports 18901 and 18902; otherwise checks are retried and then fail. While it runs, any container on that bridge can reach it. It serves a fixed reply and records only ports and paths (ADR-0018).
- **The probes cover OpenShell's default enforcement surface,** not providers, middleware, other protocols or GPUs (ADR-0018).
- **Live evidence is local.** CI uses fakes, which show how AEGIS judges results, not that a kernel enforces anything. The live evidence is recorded per pull request and applies to the host and OpenShell version it ran on.
- **A shutdown can leave a sandbox behind** until the next sweep, at most a minute while a worker runs.
- **Docker is root-equivalent on the host.** AEGIS never touches the Docker socket; only the gateway does.
- **OpenShell releases often.** An upgrade is refused until it has been re-verified and the pin changed (ADR-0016).

## 7. Running the tests

```bash
make up
make migrate
make test-security      # includes every fail-closed path above, against a fake CLI
make test-integration   # includes the fake-runtime tasks and two real-process failure workflows

# Optional: real OpenShell. Stop any running worker first: its orphan sweep would delete the
# tests' sandboxes.
make openshell-init
make test-openshell     # includes the Phase 3 workflow through real API and worker processes
```

CI runs the fake-runtime tests and the security suite on every pull request. CI never uses a real OpenShell, so the live run is local, and its evidence is recorded in the pull request that closes Phase 3.

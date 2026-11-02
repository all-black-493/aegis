# Phase 2 threat model

- **Status:** Accepted for Phase 2
- **Date:** 2026-11-02
- **Covers:** the code as built at the end of Phase 2.
- **Extends:** the [Phase 1 threat model](phase-1-threat-model.md). Everything there still holds unless this document says otherwise.

## 1. Scope

**What Phase 2 adds.**

- **A third task kind, `generate`:** it sends one prompt to the configured model and stores the text that comes back (ADR-0015).
- **Two model providers behind one contract (ADR-0013):**
  - the deterministic, offline mock, which is the default and is used in CI;
  - an adapter for a local Ollama server on `127.0.0.1` (ADR-0014), which runs in AEGIS's own optional `local-ai` container.

**Still out of scope:**

- agents, tools and multi-step execution (Phases 4 and 9);
- OpenShell and every form of runtime isolation (Phase 3);
- provenance (Phase 5), approvals and cost limits (Phase 6) and evidence verification (Phase 7).

The model never executes code, calls tools or triggers actions.

## 2. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Prompts | `tasks.input` and the saved decision's inputs | They may hold whatever a client chose to send |
| Model output | `tasks.result` | Untrusted text; it could carry injected instructions or forged log lines |
| Model identity | Every `generate` result and its `model.generated` event | Research records depend on knowing exactly which model answered |
| Model choice and sampling | Configuration (`AEGIS_MODEL_*`, `AEGIS_OLLAMA_*`) and policy constants | Whoever controls them controls what answers |

## 3. Trust boundaries

| Boundary | Between | Controls |
|---|---|---|
| B5, revised | The worker and its handlers | The closed registry now holds `noop`, `wait` and `generate`. The handler context adds `generate(request)`, bound to the task's halt signal, and still offers no database, settings or credentials |
| B7 | The worker and the model server | Only on `127.0.0.1` at the configured port, with the host fixed in code. No tools, system prompt or response format are sent. Remote-backed models are refused. Every response is size-limited and parsed strictly |

## 4. Threats and mitigations

| ID | Threat | Mitigations | Verified by |
|---|---|---|---|
| M1 | A task chooses its own model, sampling, tools or instructions | The input is exactly `prompt` and `max_output_tokens`, and any other key is refused. The model comes from configuration. Temperature and seed are policy constants | `security/test_model_boundary.py::test_a_task_cannot_choose_the_model_sampling_or_tools`, `unit/test_policy.py::test_submission_rules`, `e2e/test_phase2_workflow.py::test_a_generate_task_completes_the_same_workflow_on_each_provider` |
| M2 | An oversized or empty prompt reaches the model | The policy refuses it at submission and the handler checks it again, so it is never sent | `integration/test_generate_tasks.py::test_a_refused_prompt_is_denied_and_never_sent`, `unit/test_jobs.py::test_generate_refuses_input_the_policy_would_refuse` |
| M3 | Model output (for example a prompt injection) triggers an action | Output is stored as the task's result and nothing parses, executes or acts on it. A tool call from the model ends the task with `tool_call`, and nothing it streamed is kept | `security/test_model_boundary.py::test_model_output_is_stored_as_inert_text`, `security/test_model_server.py::test_a_tool_call_from_the_model_fails_the_task_and_stores_nothing` |
| M4 | Prompts or output leak into logs or the audit store | The worker and the adapter never log them. `model.generated` carries only the identity and counts. Audit details are size-limited, and model identity fields are bounded | `e2e/test_phase2_workflow.py::test_a_generate_task_completes_the_same_workflow_on_each_provider`, `integration/test_generate_tasks.py::test_a_generate_task_runs_end_to_end_and_records_the_model`, `unit/test_model_providers.py::test_identities_and_statuses_are_validated` |
| M5 | The choice of provider changes security decisions | Policy cannot import configuration. Decisions are identical with the mock and with Ollama | `unit/test_policy.py::test_decisions_do_not_depend_on_the_environment`, `unit/test_layering.py`, `e2e/test_phase2_workflow.py::test_a_generate_task_completes_the_same_workflow_on_each_provider` |
| M6 | A generation keeps running after cancellation, a disabled initiator or shutdown | The halt signal reaches the provider, which stops between steps or streamed lines and closes its connection | `integration/test_generate_tasks.py::test_cancelling_a_generation_stops_the_model`, `integration/test_local_ai.py::test_a_stop_request_ends_generation_promptly` |
| M7 | A misbehaving model server exhausts the worker or corrupts records | Limits on lines, streams and output. Malformed versions, digests, text and counts are protocol errors. Output the database cannot hold fails the task with `invalid_result` | `security/test_model_server.py::test_an_endless_stream_is_cut_to_the_output_limit`, `security/test_model_boundary.py::test_output_the_database_cannot_hold_fails_the_task`, `integration/test_ollama_adapter.py` |
| M8 | A missing, swapped or remote model silently produces results | A missing, remote, non-generative or wrongly pinned model fails the task with its code before the prompt is sent. Every success records the digest and runtime version | `security/test_model_server.py::test_a_remote_swapped_or_unusable_model_never_receives_the_prompt`, `integration/test_generate_tasks.py::test_a_refused_model_fails_the_task_with_its_code_and_no_retry` |
| M9 | Prompts or secrets leave the host through the model server | No setting names the model host: it is `127.0.0.1` in code, unknown `AEGIS_*` variables are refused, and `OLLAMA_HOST` is ignored. Requests carry only the prompt and fixed options. The worker holds no secret but its database password, which never reaches a handler | `security/test_model_server.py::test_the_model_server_cannot_be_moved_off_this_host`, `::test_only_the_prompt_and_fixed_options_reach_the_model_server` |

## 5. Failure behaviour

| Failure | Behaviour | Verified by |
|---|---|---|
| Model server unreachable at worker startup | The worker logs `model provider unavailable` and still starts; other kinds run | `integration/test_generate_tasks.py::test_an_unreachable_model_fails_generation_but_not_other_tasks` |
| Model server unreachable during a task | Retried with backoff, then `failed` (`attempts_exhausted`) | `integration/test_generate_tasks.py::test_an_unavailable_model_is_retried_then_the_task_fails` |
| Stream ends before it finishes | Retried like an unreachable server; a partial answer is never stored | `security/test_model_server.py::test_a_stream_that_ends_early_stores_no_partial_answer` |
| Model refused (missing, remote, not generative, wrong digest, tool call, protocol error) | `failed` with that code; no retry | `integration/test_generate_tasks.py::test_a_refused_model_fails_the_task_with_its_code_and_no_retry`, `security/test_model_server.py::test_a_remote_swapped_or_unusable_model_never_receives_the_prompt` |
| No provider configured for the handler | `failed` (`model_unavailable`) | `integration/test_generate_tasks.py::test_a_refused_model_fails_the_task_with_its_code_and_no_retry` |
| Audit write fails when a generation completes | The completion rolls back, and the task is retried after its lease, as in Phase 1 | `security/test_failure_injection.py::test_an_audit_failure_at_completion_commits_nothing_and_the_task_is_retried` |

## 6. Residual risks

- **Prompts are stored** with the task and its decision. Anyone who may read the task can read them; clients must not send secrets.
- **Output is untrusted** but readable by the task's readers. Anything that later uses it must treat it as `untrusted` (Phase 5).
- **No egress control for Ollama.** The container can reach the internet, which pulls need. Restricting it is OpenShell's job (Phase 3).
- **No authentication in Ollama.** Any process on the host can use it. It is published on loopback only.
- **No cost limits** beyond the caps and the active-task quota (Phase 6).
- **Repeatability** is exact only for the mock (ADR-0014).
- **The model can change between checks.** A model replaced between the identity check and the chat call is recorded with the earlier digest (ADR-0014).

## 7. Running the tests

```bash
make up
make migrate
make test-security      # includes the model boundary and the model server boundary
make test-integration   # includes the Phase 2 workflow with the mock provider

# Optional: the same workflow on the local model
make up-local-ai
make model-pull         # once; downloads AEGIS_OLLAMA_MODEL
make test-local-ai
```

CI runs the mock workflow and the security suite on every pull request. CI never runs a real model, so the Ollama run is local, and its evidence is recorded in the pull request that closes Phase 2.

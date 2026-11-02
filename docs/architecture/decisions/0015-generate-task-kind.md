# ADR-0015: The `generate` task kind

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

The provider contract (ADR-0013) and the Ollama adapter (ADR-0014) can produce text, but nothing in AEGIS asks for it yet. Phase 2 needs one task kind that sends a prompt to the configured model through the existing workflow: the API admits it under policy, the worker runs it under a fenced lease, and the result, history and audit chain record what happened. The model's output is untrusted. It must not be able to trigger actions, choose its own settings, or reach the logs or the audit store.

## Decisions

| Area | Decision | Rationale |
|---|---|---|
| Kind and input | `generate` takes exactly `{"prompt": text, "max_output_tokens": n}`. The prompt has 1 to 8,000 characters and is not only whitespace; `n` is an integer from 1 to 512. Any other key is refused with `input_invalid`. Policy `2026.11.02-1` adds the kind and these limits. Migration 0007 adds `generate` to the `CHECK` on `tasks.kind`. | A task cannot choose the model, sampling, tools, a system prompt or a response format. The limits sit well inside the provider ceilings (ADR-0013). |
| Sampling | Temperature 0 and seed 0 are policy constants (`GENERATE_TEMPERATURE`, `GENERATE_SEED`), sent with every request and recorded in every result. | Runs are as repeatable as the model allows, and research records say exactly how they were made. |
| Approval | None (decision U6). The output is inert text, the quota of 10 active tasks applies, and both input and output are bounded. | Approval rules belong to the risk engine (Phase 6). |
| Which model | Configuration, not task input: `AEGIS_MODEL_PROVIDER` and the Ollama settings (ADR-0013). The worker builds one provider at startup and shares it with every task. It checks the provider once; if it is unhealthy, the worker logs `model provider unavailable` and still starts. | Operators choose the model. Other kinds keep running, and each `generate` task retries or fails on its own. |
| Handler capability | `HandlerContext.generate(request)` is bound to the task's halt signal. The handler gets neither the provider object nor its settings, nor any database or credentials. Without a configured provider it fails with `model_unavailable`. | H6: the model is reachable only to generate, and only while the task may still run. A method exposes less than the `context.model` object the Phase 2 plan sketched. |
| Handler | Re-checks its input as the policy does, builds the request from the policy constants, and returns `text`, `finish_reason`, `provider`, `model`, `model_digest`, `runtime_version`, `prompt_tokens`, `output_tokens`, `duration_ms`, `temperature` and `seed`. | The result names the exact model and runtime that answered. |
| Untrusted output | The text is stored as the task's result and returned to callers who may read the task. It is never parsed, executed, logged, audited or used in a decision. | A prompt injection can change only the text that comes back. |
| Failures | `ProviderUnavailableError` (`unavailable`, `unreachable`) becomes `RetryableError`, so backoff and the attempt limit apply (ADR-0009). Any other provider error ends the task `failed` with that error's code: `model_missing`, `not_generative`, `digest_mismatch`, `remote_model`, `tool_call` or `protocol_error`. A new `HandlerFailure(code)` carries the code, and anything that is not a short lowercase code becomes `handler_error`. | Only transient failures are retried, and a failed task says exactly why it failed. |
| Stopping | Cancellation, a disabled initiator and shutdown set the halt signal as in Phase 1. The mock stops within 10 ms; Ollama between streamed lines, closing the connection. The task then ends as any Phase 1 task does. | A halt stops generation, not just the result. |
| Result size | Results are measured as UTF-8 JSON (ADR-0009 previously measured escaped ASCII). Text that cannot be encoded, contains NUL, or escapes to more than 8 KiB ends the task with `invalid_result`. | The size limit matches what PostgreSQL stores. Output the database cannot hold fails closed. |
| Audit | `model.generated` (outcome `success`, reason `completed`) is written in the transaction that completes the task. Its details are `provider`, `model`, `model_digest`, `runtime_version`, `prompt_tokens`, `output_tokens`, `duration_ms` and `finish_reason`, and never the prompt or the text. A failed generation writes no model event; its job events carry the code. | Every successful generation is accountable without copying task data into the audit store. |
| Identity bounds | A `ModelIdentity` has provider and model names of at most 128 characters and a runtime version matching `[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}`. The Ollama adapter treats any other `/api/version` answer as `protocol_error`. Streamed content that is not valid text (a lone surrogate) is a protocol error too. | A model server cannot put long or forged text into audit details, or make the worker's completion fail. |
| Shared instances | One provider per worker process; one `TaskService` per API application, held by `ApiContext` (previously one per request). | Process-wide objects are built once at the entry point and injected. |
| Downgrade | Migration 0007's downgrade (development only, ADR-0003) is refused while any `generate` task is unfinished. Finished ones are kept: terminal tasks never change, and the restored `CHECK` is `NOT VALID`, so it refuses every new `generate` row. | Downgrading neither loses history nor leaves work that the older code cannot finish. |

## Handler contract (ADR-0009), revised

- **H1:** handlers have no outside effects. The only exception is `generate`, whose single input and output is the configured local model server.
- **H2:** the mock is deterministic. Ollama runs with temperature 0 and seed 0, both recorded, but exact repeatability is not guaranteed.
- **H5:** the registry holds exactly `noop`, `wait` and `generate`, the same set as the policy's `TASK_KINDS`.
- **H6:** the handler context offers `stop_requested()`, `wait(seconds)` and `generate(request)`. It still offers no database, settings or credentials.

## Consequences and limitations

- **Prompts are stored.** A prompt is task input, so it is kept in `tasks.input` and in the saved decision's inputs (decision U7), and anyone who may read the task may read it and its output. Clients must not put secrets in prompts.
- **Output is untrusted data.** Nothing in AEGIS consumes it yet. Anything that later feeds model output into a decision or a tool must treat it as `untrusted` (Phase 5).
- **At-least-once delivery.** A `generate` task may run again after a crash or a lost lease. It has no outside effects, but it spends model time twice.
- **Repeatability is not guaranteed** for Ollama (ADR-0014). The mock is exactly repeatable.
- **Pathological output can fail a task.** Up to 4 KiB of text is accepted, but text made mostly of characters JSON must escape can exceed the 8 KiB result limit and end the task with `invalid_result`.
- **No token budget beyond the caps.** There is no per-identity cost limit or approval threshold; those belong to the risk engine (Phase 6).
- **No runtime enforcement.** The model server is reached only on `127.0.0.1`. AEGIS does not restrict what Ollama itself can reach (ADR-0014), and nothing runs under OpenShell until Phase 3.

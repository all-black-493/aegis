# ADR-0014: Ollama integration

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

The Ollama provider (ADR-0013) must run text generation on a model served by a local Ollama, and record exactly which model answered. It must not let prompts leave the host, let a model trigger actions, or let a misbehaving server exhaust the worker.

Ollama's documentation describes its main branch. AGENTS.md requires integrations to be verified against the version actually installed.

## Version verified

The pinned version is the `ollama/ollama` image `sha256:da6e0dc5651df159e45686fd663c4dbe1624a52c44d7280eeac1551d8f865532`, already present locally. With networking disabled it reports client version 0.34.2; its server reports 0.34.2 on `/api/version`. It ran from AEGIS's own volume `aegis_ollama-models` on `127.0.0.1:11436`, with `qwen3:0.6b` pulled (digest `7df6b6e09427a769808717c0a93cadc4ae99ed4eb8bf5ca557c90846becea435`, 522,653,767 bytes, `Q4_K_M`, Apache-2.0 according to both the upstream model card and `/api/show`).

Behaviour observed on 2026-11-02:

| Request | Observed |
|---|---|
| `GET /api/version` | `{"version": "0.34.2"}` |
| `POST /api/show` | Keys `capabilities`, `details`, `license`, `model_info`, `modelfile`, `modified_at`, `parameters`, `template`. `qwen3:0.6b` reports `completion`, `tools` and `thinking`. There is no `remote_host` or `remote_model` for a local model |
| `GET /api/tags` | Entries carry `name`, `model`, `digest` (64 hex characters, no `sha256:` prefix), `size`, `details`, `capabilities`, `modified_at` |
| An unknown model | HTTP 404 with `{"error": "model '…' not found"}`, from both `/api/show` and `/api/chat` |
| `POST /api/chat`, streamed, `think: false` | Chunked line-by-line JSON. Chunks carry `message.content`; the final line has `done: true`, `done_reason`, `prompt_eval_count`, `eval_count` and durations. There is no `thinking` text and no `<think>` tags. Lines are under 400 bytes |
| `num_predict` reached | `done_reason: "length"`; otherwise `"stop"` |
| `think: true` | Reasoning arrives in a separate `message.thinking` field, not in `content` |
| Temperature 0, seed 0, repeated | Identical text across repeated calls, on CPU |
| First call | About 2 s, including loading the model |

## Decisions

| Area | Decision | Rationale |
|---|---|---|
| Transport | `http.client` from the standard library, to `127.0.0.1` (fixed, ADR-0013) on `AEGIS_OLLAMA_PORT`. Metadata calls use a timeout of at most 10 s; generation uses `AEGIS_MODEL_TIMEOUT_SECONDS` as the longest wait for the next bytes. | No new dependency, and nothing can point the adapter at another host. |
| Checks before every generation | `/api/version`, `/api/show` and `/api/tags` are read on every call. The model must report the `completion` capability, be listed locally, carry no `remote_host` or `remote_model`, have a well-formed digest, and match `AEGIS_OLLAMA_MODEL_DIGEST` when pinned. | The recorded identity, and the locality and digest checks, always describe the model that actually answered, at the cost of three loopback requests per task. |
| Request | One user message containing the prompt; `stream: true`; `options` with `temperature`, `seed` and `num_predict`; and `think: false` only when the model reports `thinking`. No tools, response format, system prompt, `keep_alive`, template or raw mode. | Models get no tools to call and no instructions beyond the prompt. Thinking stays off for reasoning models, and the flag is never sent to models that might reject it. |
| Stream | Read line by line. Each line is at most 64 KiB, the whole stream at most 4 MiB, and output at most 4 KiB, after which the adapter stops reading and returns `limit`. A stop request is checked between lines, and closing the connection ends generation early. `thinking` text is discarded. | A misbehaving server cannot exhaust memory or keep a stopped task running. |
| Refusals | A tool call ends generation with a protocol error (`tool_call`). A remote-backed model is refused (`remote_model`). An `error` object mid-stream, a stream that ends without `done`, a timeout, a reset or a 5xx response is retryable (`unavailable`). Malformed JSON, oversized lines, an unexpected `done_reason`, bad token counts, or another 4xx response is a protocol error. A 404 means `model_missing`. | Only transient failures are retried; anything a model or server should never do fails the attempt. |
| Health | `check()` returns `ok` with the identity, or one detail code: `unreachable`, `unavailable`, `model_missing`, `remote_model`, `not_generative`, `digest_mismatch` or `protocol_error`. | The doctor (Increment 3) reports exactly why the configured model can't be used. |
| Logging | The adapter logs nothing, and its error messages never include the prompt or the output. | Prompts and model output are task data, not log data (AGENTS.md §5.4). |
| Tests | Unit tests cover the request body, the stream handling and name matching, without sockets. Integration tests drive the adapter against a fake Ollama: a threaded HTTP server on `127.0.0.1` that streams chunked line-by-line JSON and records requests. CI runs no real Ollama. | The contract is exercised on every pull request without downloading a model. |

## Local AI service (Increment 3)

| Area | Decision | Rationale |
|---|---|---|
| Compose service | `ollama` under the `local-ai` profile. Image pinned by the digest above. Published as `127.0.0.1:${AEGIS_OLLAMA_PORT:-11436}:11434`. Models live on the named volume `ollama-models` (`aegis_ollama-models`). | Optional and local only. Port 11436 avoids an Ollama on its standard port. |
| Hardening | `read_only: true` with a private `tmpfs` at `/tmp`, `cap_drop: [ALL]` and `no-new-privileges`. Verified on 0.34.2: generation and pulls still work, the volume is writable, and the root filesystem is not. | The container keeps only what it needs. |
| Healthcheck | `ollama list` inside the container, every 5 s. | Readiness means the server answers, not just that the process exists. |
| Make targets | `make up-local-ai` starts PostgreSQL and Ollama and waits for both. `make model-pull` runs `aegis model pull`. `make test-local-ai` runs the tests marked `local_ai`. `make down` stops every profile (`--profile '*'`), because plain `docker compose down` leaves profiled services running. | Starting, pulling and testing are explicit, and nothing is left running by accident. |
| Pulling | `aegis model pull` validates `AEGIS_OLLAMA_MODEL`, streams `POST /api/pull` on 127.0.0.1, prints each new status (control characters removed), then runs `check()` and prints the digest to pin. On 0.34.2 a failed pull is an `error` line inside an HTTP 200 stream, which the command reports as `pull_failed`. Pulling is an administration action only: the `ModelProvider` contract has no pull, and the worker never pulls. | The download is deliberate, and the operator sees exactly which model arrived. |
| Doctor | A `Model provider` check. With the mock it is optional and passes. With `AEGIS_MODEL_PROVIDER=ollama` it is required and runs `check()` through the doctor's `System` boundary: `PASS` with the model, digest and version; `WARN` if the server is not the verified 0.34.2; `FAIL` with a hint for each detail code. | `make doctor` says exactly why the configured model can't be used, and stays optional when no model is configured. |
| Live tests | Tests marked `local_ai` run the adapter and the doctor check against the real model: the verified runtime, finishing on stop and length, repeatability at temperature 0 with seed 0, stopping, and digest pinning. They are deselected by `make test-integration` and in CI, and fail with a hint when `AEGIS_OLLAMA_MODEL` is unset. | The verification above can be repeated by anyone with the model, without CI downloading it. |

## Consequences and limitations

- **Upgrades need re-verification.** These observations hold for 0.34.2. Newer releases may change field names or behaviour, so an upgrade means changing the Compose digest, `VERIFIED_VERSION`, re-running `make test-local-ai`, and updating this ADR.
- **Repeated pulls go to the registry.** Re-pulling a model already present still contacts it (`pulling manifest`), so `make model-pull` needs internet access.
- **Determinism is not guaranteed.** It held for repeated CPU runs, but GPUs, other quantizations or other versions may differ.
- **The model can change between checks.** The three metadata requests add a few milliseconds per generation, and a model replaced between the check and the chat call would be recorded with the earlier digest.
- **Stopping can lag during loading.** A stop is noticed between streamed lines, so while a large model is still loading it waits until the first line arrives or the timeout expires.
- **No egress control.** Ollama itself can reach the internet (it needs to, for pulls). AEGIS refuses remote-backed models but does not restrict Ollama's network access; that belongs to OpenShell (Phase 3).

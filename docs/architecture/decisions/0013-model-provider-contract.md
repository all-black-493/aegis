# ADR-0013: Model provider contract, mock provider and model configuration

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

Phase 2 must let the same application workflow run with a deterministic mock and with a local Ollama model (README §11). AGENTS.md §6.1 asks for a provider abstraction with a mock that needs no model download, and forbids hard-coding assumptions about model availability.

Everything in AEGIS that might use a model must be shielded from the details of any one model server. Security decisions must not depend on which model is configured, and nothing a model returns may become authority (AGENTS.md §3.4).

## Decisions

| Area | Decision | Rationale |
|---|---|---|
| Contract | `aegis.model_providers.contract` defines `ModelIdentity` (provider, model, digest, runtime version), `GenerationRequest` (prompt, `max_output_tokens`, temperature, seed), `Generation` (text, finish reason, token counts, duration, identity) and `ProviderStatus` (healthy, a short detail code, identity). The `ModelProvider` protocol has two methods: `check()` and `generate(request, stop_requested)`. | Callers depend on a small, typed interface rather than on a model server. |
| Errors | `ProviderUnavailableError` is the only retryable error. `ModelUnavailableError`, `ProviderProtocolError` and `GenerationStoppedError` are not retryable. Each class carries a `retryable` flag. | The worker can map retries without knowing which provider is in use. |
| Ceilings | Requests and generations validate themselves when created: a prompt of 1 byte to 16 KiB of UTF-8, 1–2048 output tokens, temperature 0–2, seed 0 to 2³¹−1. Output is at most 4 KiB of UTF-8, and `bounded_text()` cuts at a character boundary. A cut-off output reports `limit`. | These are the provider layer's technical ceilings. Task policy (Increment 4) sets tighter limits inside them. |
| Mock | `MockProvider` is deterministic and offline. Its text is a pure function of the prompt (a fixed template with the prompt's SHA-256 prefix and word count), cut to `max_output_tokens`. Its identity is fixed: `mock` / `mock-1` with a constant digest. Scripted failures, delays that honour stop requests, and oversized output exist for tests and are reachable only through its constructor. | Tests and CI need no model, no network and no download. |
| Configuration | `AEGIS_MODEL_PROVIDER` (`mock` by default, or `ollama`). `AEGIS_OLLAMA_PORT` (default 11436). `AEGIS_OLLAMA_MODEL`: required for `ollama`, with no default; a local name or `namespace/name`, with an optional tag. `AEGIS_OLLAMA_MODEL_DIGEST`: an optional 64-hex-character pin. `AEGIS_MODEL_TIMEOUT_SECONDS` (5–600, default 120). None of these is in `.env.example`, and the doctor validates them. | Operational settings that are validated and never change a decision. |
| Locality | The model server's host is fixed to `127.0.0.1` in code. No host or URL setting exists, and an `AEGIS_*` name such as `AEGIS_OLLAMA_HOST` is refused as unknown. Model names cannot contain a registry host. | Prompts cannot be sent off the machine by configuration, and pulls cannot be redirected to another registry. |
| Factory | `build_provider(settings)` returns the mock. It refuses `ollama` with `ModelUnavailableError` until the adapter exists (Increment 2). | A setting for a provider that doesn't exist yet fails closed rather than silently using something else. |
| Layering | `aegis.model_providers` and `aegis.integrations` may not import the database, audit, identity, authorization, policy, tasks or jobs code, nor SQLAlchemy, psycopg or Alembic. `aegis.policy` and `aegis.authorization` may not import either package. `tests/unit/test_layering.py` enforces both rules. | Providers know nothing of AEGIS's state, and decisions cannot depend on the model. |

## Consequences and limitations

- **Nothing calls a provider yet.** The Ollama adapter arrives in Increment 2, and the `generate` task kind in Increment 4.
- **Approximate counts.** The mock's token counts are word counts, not real tokenization.
- **No external providers.** None is shipped: the configuration accepts only `mock` and `ollama`. Adding one would need its own ADR, including how credentials are handled and how the local-only rule changes.
- **Fixed host, configurable port.** A fixed `127.0.0.1` means an Ollama in a container must publish its port on the host's loopback (Increment 3).

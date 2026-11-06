# ADR-0002: Layering, configuration and logging

- **Status:** Accepted
- **Date:** 2026-11-01

## Context

Phase 1 adds several components (database, identity, authorization, policy, tasks, jobs, API, worker). Before any of them exists, the project needs:

- a package layout;
- import rules that keep security decisions independent of configuration;
- an operational configuration foundation;
- structured logging that does not leak secrets;
- a safe way to add new variables to existing `.env` files.

## Decisions

| Area | Decision | Rationale |
|---|---|---|
| Layout | Components sit directly under `src/aegis/<component>/`. Entry points live in `src/aegis/apps/{api,worker,cli}/`. There is no `packages/` grouping level. | The extra level adds nothing to import paths. AGENTS.md §7 and README §10 show the target tree. |
| Import rules | `tests/unit/test_layering.py` enforces them. Since Phase 4, only `aegis.apps.api` may import FastAPI or Starlette, because the worker and the CLI share every other package (ADR-0004). (1) `aegis.authorization` and `aegis.policy` may not import `aegis.config` or read environment variables. (2) No module outside `aegis.apps` imports `aegis.apps`. (3) Only entry points use `aegis.doctor`. (4) `aegis.config` imports no other `aegis` package. | Configuration must not be able to influence security decisions. Entry points stay leaves. Rules are added as components arrive. |
| Configuration versus policy | Environment variables carry operational configuration only. Security thresholds belong to versioned policy code, and configuration may only tighten limits that policy allows. | Prevents a deployment setting from silently weakening a security decision. |
| Variable registry | `aegis.config.variables` lists every `AEGIS_*` variable: its purpose, and whether it is secret, required or part of `.env.example`. Unknown `AEGIS_*` names are rejected. | One source of truth for the template, the doctor, redaction and settings. Typos fail loudly. |
| Settings | Frozen standard-library dataclasses and an explicit loader. Every problem is reported at once, naming variables but never echoing values. `AEGIS_ENV` defaults to `production`, which refuses `DEBUG` logging. | No dependency is needed for a handful of typed fields. Pydantic arrives with FastAPI in Increment 6. Unset configuration gets the strictest behaviour. |
| Logging | Standard-library logging with one JSON object per line. Values are redacted in two ways: secrets registered at startup, and patterns for bearer tokens, `aegis_pat_` tokens, URL credentials and `password=`-style pairs. Only entry points configure logging. | Structured, injection-safe output (newlines are escaped) with no new dependency. |
| `make setup` | Creates `.env` only if it does not exist, using an exclusive create with mode 600 that never follows a symlink. Every `__GENERATED_BY_MAKE_SETUP__` placeholder is replaced with 32 random bytes in hex from the `secrets` module. | Each checkout gets its own credentials. |
| `make env-upgrade` | Appends variables present in `.env.example` and missing from `.env`, generating secrets for placeholders. It never changes, reorders or removes existing lines, and prints names only. It refuses, without writing, if `.env` is missing, unparsable, a symlink, or accessible to other users. It is safe to rerun. | Existing checkouts can take on new variables without losing their values or exposing new secrets. |
| Template rules | In `.env.example`, secret variables must use the placeholder, non-secret variables must not, and every variable must be in the registry. | A real secret can never be committed in the template. |

## Consequences and limitations

- Redaction is best-effort. Patterns can miss unusual formats, and secrets shorter than 8 characters cannot be registered for redaction (the doctor requires secrets of at least 16).
- The layering test is static. It does not see dynamic imports such as `importlib.import_module`.
- `.env` supports only a subset of dotenv syntax: `KEY=VALUE`, comments and fully quoted values.
- No process loads settings or configures logging yet. The API, worker and CLI adopt them in their increments, and add their own settings, including secret-bearing ones, at that point.

# ADR-0001: Phase 0 development foundation

- **Status:** Accepted
- **Date:** 2026-11-01

## Context

Phase 0 sets up a reproducible local development environment that runs without the original developer's machine or paid credentials (AGENTS.md §3.6, README §11).

The specifications left several tooling and layout choices open. The project owner approved the decisions below after a repository assessment.

## Decisions

| Area | Decision | Rationale | Alternatives considered |
|---|---|---|---|
| Dependency management | uv with a committed `uv.lock`. Make targets that run Python use `uv sync --locked` or `uv run --locked`. | Hash-pinned lockfile. A stale lock fails the build. uv manages the Python version, which isolates the project from whatever interpreter or virtualenv is active in the shell. | Poetry, pip-tools |
| Python | 3.13 (`requires-python = ">=3.13,<3.14"`, `.python-version`) | Broad wheel support for upcoming SDKs. Re-evaluate once OpenShell's requirements are known. | 3.14 |
| Layout | A single installable `aegis` distribution in `src/` layout, built with `uv_build` | Modular monolith; no per-package overhead. | uv workspace with multiple distributions; top-level `apps/`, `packages/` and `integrations/` packages |
| Doctor | `src/aegis/doctor/`, standard library only, host access behind a `System` protocol | Runs before any application code exists. Can later be exposed as `aegis doctor` without duplication. Every failure path is unit-testable. | `scripts/doctor.py` |
| Database | PostgreSQL 17, pinned by tag and digest, host port 5433 on `127.0.0.1` | Port 5433 avoids clashing with locally installed PostgreSQL servers. Loopback-only binding. | PostgreSQL 18 |
| Database driver | psycopg 3, development dependency only | Used only by integration tests. Supports both sync and async, so it does not presume the Phase 1 API framework. | asyncpg; a container-side `psql` check |
| Compose | One root `docker-compose.yml`. Core services have no profile. Optional services get profiles in the phases that implement them. | A plain `docker compose up` starts the core. A literal `core` profile would make it start nothing. | Separate compose files per concern |
| Credentials | `make setup` generates a per-checkout password into a mode-600 `.env`. It never overwrites an existing `.env`. Compose rejects missing or empty values. | No shared, well-known development passwords. | A fixed default password in `.env.example` |
| Quality | Ruff (format and lint, including the `S` security rules), mypy `--strict`, pytest | One fast linter and formatter; the most established strict type checker. | pyright |
| Tests | Unit tests are hermetic (network and subprocess access fail the test). Integration tests use real services and fail rather than skip. | Unit tests cannot silently depend on infrastructure. Missing infrastructure cannot produce a false green. | Marker-based selection |
| Platform | Ubuntu / Linux x86_64 with Docker Engine and Compose v2 | Matches the development machine and CI runners. | macOS, WSL2, Podman |
| CI | GitHub Actions. Read-only token, no secrets, `pull_request` (never `pull_request_target`), actions pinned to commit SHAs, caching disabled. | Pull-request code runs only with GitHub's read-only token and no secrets, and there is no shared cache state. | — |

## Consequences

- Contributors must install uv themselves. The Makefile reports a missing uv clearly.
- Upgrading the PostgreSQL image, the action SHAs or the uv version is a manual change until supply-chain automation arrives in Phase 11.
- The application configuration framework, migrations, API framework and worker queue are Phase 1 decisions. Phase 0 code reads only the four PostgreSQL variables.

## Outstanding decisions

- License, `SECURITY.md` and `CONTRIBUTING.md`.
- Whether the target tree's `packages/` level is kept inside `src/aegis/` (Phase 1).
- API framework, configuration framework, migrations and worker queue (Phase 1).
- Branch protection for `main`.

# Getting started

AEGIS has completed **Phase 0** and is building **Phase 1**. The repository provides:

- a PostgreSQL service with least-privilege database roles and migrations;
- an append-only audit store;
- identities, role assignments and API credentials, administered through the `aegis` CLI;
- an HTTP API on `127.0.0.1` with health checks, `GET /v1/me`, and routes to submit, view, list and cancel tasks;
- the authorization rules and the shared security-decision contract;
- task, decision and history storage whose integrity rules the database enforces;
- the versioned, fingerprinted policy and the decision service that saves every decision with its inputs;
- an environment doctor;
- the configuration and logging foundation;
- the test and quality tooling.

There is no worker yet, so submitted tasks are queued but never run. There is no agent execution, model provider, OpenShell integration, or other security control yet. Nothing executes untrusted workloads.

## Supported platform

| Component | Supported | Tested with |
|---|---|---|
| Operating system | Ubuntu / Linux x86_64 | Ubuntu 26.04 LTS; GitHub-hosted `ubuntu-24.04` in CI |
| Containers | Docker Engine with the Compose v2 plugin | Docker 28.3.2, Compose 2.38.2 |
| Python | 3.13, installed and managed by uv | 3.13.14 |
| uv | 0.13.1 or later | 0.13.1 |

macOS, Windows/WSL2, Docker Desktop and Podman are untested and unsupported.

## Prerequisites

- `git`, GNU `make`, `bash` and coreutils (standard on Ubuntu).
- Docker Engine with the Compose v2 plugin. Your user must be able to run `docker` without `sudo` (the `docker` group or rootless Docker).
- [uv](https://docs.astral.sh/uv/getting-started/installation/) 0.13.1 or later on `PATH`. `make setup` does not install uv for you.
- At least 2 GiB of free disk space and 2 GiB of RAM. Measured footprint: PostgreSQL image ~450 MB, Python 3.13 ~110 MB, `.venv` ~115 MB, empty database ~50 MB, PostgreSQL idle memory ~20 MiB.
- Network access during the first setup, to PyPI, the uv Python downloads and Docker Hub. No model downloads or API credentials are needed.

## Quick start

```bash
git clone <repository-url> aegis
cd aegis
make setup
make up
make migrate
make doctor
make test
make test-integration
make down
```

## Commands

| Command | What it does |
|---|---|
| `make help` | Lists the available targets. |
| `make setup` | Installs the locked dependencies (`uv sync --locked`). Creates `.env` from `.env.example`, generating every secret, only if `.env` does not exist. Safe to rerun. |
| `make env-upgrade` | Appends variables that `.env.example` has and `.env` lacks, generating secrets where needed. Never changes, reorders or removes existing lines. Prints variable names, never values. Safe to rerun. |
| `make doctor` | Diagnoses the local environment (see below). |
| `make up` | Starts PostgreSQL and waits until its healthcheck passes. |
| `make migrate` | Creates or updates the database roles and schema (`aegis db bootstrap`), then applies pending migrations (`aegis db migrate`). Safe to rerun. |
| `make api` | Runs the API in the foreground on `127.0.0.1`, port `AEGIS_API_PORT` (default 8000). Stop it with Ctrl-C. Requires `make up` and `make migrate`. |
| `make down` | Stops and removes the containers. The database volume is kept. |
| `make test` | Runs the unit tests. Needs no Docker, database, model, network or credentials. |
| `make test-integration` | Runs the integration tests against the running PostgreSQL. Requires `make up`. |
| `make lint` | Checks formatting and lint rules with Ruff. |
| `make format` | Sorts imports and formats the code with Ruff. |
| `make typecheck` | Type-checks `src/` and `tests/` with mypy in strict mode. |
| `make check` | Runs `lint` and `typecheck`. |

Every target exits non-zero on failure.

## Configuration

`make setup` creates `.env` with file mode 600. The file is git-ignored and must never be committed.

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_ENV` | `development` in `.env.example`; **`production` when unset** | `development`, `test` or `production`. Production refuses `DEBUG` logging. |
| `AEGIS_LOG_LEVEL` | `INFO` (not in `.env.example`) | `DEBUG`, `INFO`, `WARNING` or `ERROR` |
| `AEGIS_API_PORT` | `8000` (not in `.env.example`) | Port the API listens on. The API always binds to `127.0.0.1`. |
| `AEGIS_POSTGRES_USER` | `aegis` | PostgreSQL bootstrap superuser, used only to create roles and databases |
| `AEGIS_POSTGRES_DB` | `aegis` | PostgreSQL database |
| `AEGIS_POSTGRES_PASSWORD` | generated | Bootstrap superuser password. Older 48-character values remain valid. |
| `AEGIS_POSTGRES_PORT` | `5433` | Host port, published on `127.0.0.1` only |
| `AEGIS_DB_OWNER_PASSWORD` | generated | Password of `aegis_owner`, which runs migrations and administration |
| `AEGIS_DB_APP_PASSWORD` | generated | Password of `aegis_app`, which the API uses (and the worker will) |
| `AEGIS_TOKEN_PEPPER` | generated | Server-side key for hashing API tokens; at least 32 characters. Changing it invalidates every issued token. |

Generated secrets are 64 hex characters from a cryptographic random generator, unique per checkout.

Docker Compose refuses to start if any PostgreSQL variable is missing or empty.

Every `AEGIS_*` variable is listed in `src/aegis/config/variables.py`. An `AEGIS_*` name that isn't listed there is rejected as a probable typo.

These variables are operational configuration only. Security policy lives in code and cannot be changed through the environment.

PostgreSQL reads `AEGIS_POSTGRES_USER`, `AEGIS_POSTGRES_DB` and `AEGIS_POSTGRES_PASSWORD` only when it initializes an empty volume; changing them later requires a data reset (see Troubleshooting). The two role passwords can change at any time: `make migrate` applies them.

To change the port, edit `.env` and run `make down` followed by `make up`.

## Database

All AEGIS objects live in the `aegis` schema of the `AEGIS_POSTGRES_DB` database. Three roles are involved:

| Role | Attributes | Used by |
|---|---|---|
| `AEGIS_POSTGRES_USER` (default `aegis`) | Superuser, created by the PostgreSQL image | `aegis db bootstrap` only |
| `aegis_owner` | Login; not a superuser; cannot create roles or databases | Migrations (`aegis db migrate`) and identity administration (`aegis identity`, `aegis credential`, `aegis role`) |
| `aegis_app` | Login; no ownership; only the privileges each migration grants | The API (`make api`) and, from Increment 10, the worker |

`aegis db bootstrap` is safe to rerun. Each run:

- creates the two roles, or resets their attributes and passwords;
- sends each password to PostgreSQL only as a SCRAM-SHA-256 verifier computed on the client;
- revokes `PUBLIC` access to the database and to the `public` schema;
- creates the `aegis` schema owned by `aegis_owner`, and pins both roles' `search_path` to it.

`aegis db migrate` runs as `aegis_owner` with only the owner's credentials. All pending migrations run in one transaction, behind an advisory lock. Migrations never run when a process starts.

The doctor and the readiness helper compare the database's revision with the latest migration in the package.

### Audit events

Security-relevant events are stored in `aegis.audit_events`:

- `aegis_app` can only insert. It cannot read, change, delete or truncate events, and cannot choose an event's sequence number or timestamp.
- Triggers reject changes and deletions from every role, including `aegis_owner`, and stamp each event with the database's transaction time.
- `AuditRecorder` writes an event only inside the caller's transaction, so the event and the change it describes commit or roll back together.
- Detail fields are limited to an allowlist per event type, and secrets are redacted before storage.

The audit table is **not** tamper-proof against the owner or the superuser. See ADR-0010 for exactly what is and isn't guaranteed.

### Tasks and decisions

Tasks, the security decisions that justify their state changes, and their history are stored in `aegis.tasks`, `aegis.security_decisions` and `aegis.task_state_transitions`. The legal transitions are listed in `aegis.task_transition_rules` and in `aegis.tasks.states`, and a test keeps the two identical. The database itself refuses, even for direct SQL as `aegis_app`:

- an illegal transition, a version that doesn't rise by exactly 1, or a state change without its history row;
- a history row without a state change, or a task committed in state `created`;
- queuing or running a task without an allow decision for that task, from the right stage, made in the same transaction and used only once;
- a decision whose subject isn't the task's initiator;
- any change to a task's fixed columns or to a finished task, and any change to decisions, history or the transition rules.

These rules prove internal consistency, not legitimacy. See ADR-0008.

Decisions come from `DecisionService` (ADR-0007). It checks authorization first, then the policy rules for submission and execution, where any deny wins and anything unmatched or failing is denied. Each decision records the policy version and fingerprint and is saved with its inputs, so it can be replayed. The policy reads no configuration.

### Identities and credentials

Identities, role assignments and API credentials are managed with the `aegis` CLI, which connects as `aegis_owner`. Run it through uv with the project's `.env`:

```bash
uv run --locked --env-file .env aegis identity create alice --kind human --role admin
uv run --locked --env-file .env aegis credential issue alice --days 30 --description laptop
uv run --locked --env-file .env aegis role grant alice auditor
uv run --locked --env-file .env aegis role revoke alice auditor
uv run --locked --env-file .env aegis identity create ci-runner --kind service --role operator
uv run --locked --env-file .env aegis credential issue ci-runner
uv run --locked --env-file .env aegis credential list ci-runner
uv run --locked --env-file .env aegis credential revoke <credential-id>
uv run --locked --env-file .env aegis identity disable ci-runner
uv run --locked --env-file .env aegis identity enable ci-runner
```

Every command also accepts `--database <name>` to target another database.

- Identities are `human` or `service`. Names are 1–63 characters of `a-z`, `0-9`, `.`, `_`, `:` and `-`. Identities are never deleted; disable them instead.
- Roles are `admin`, `operator` and `auditor` (ADR-0006). The `worker` role belongs only to the seeded `system:worker` identity. `system:worker` and `system:cli` cannot be changed or given credentials.
- `credential issue` prints the token once, alone on stdout, and the credential ID and expiry on stderr. Only a peppered hash is stored, so a lost token cannot be recovered: revoke it and issue another.
- Tokens expire after 30 days by default. `--days` accepts 1 to 90; there are no tokens without an expiry.
- The last active admin cannot be disabled or lose the `admin` role.
- Every command runs in one transaction with its audit events, recorded with actor `system:cli`. Commands refuse to run until `make migrate` has brought the schema up to date.

See ADR-0005 for the design and its limitations.

## The API

`make api` serves the API on `127.0.0.1` only. It connects as `aegis_app` and holds the token pepper; it never has owner or superuser credentials.

| Route | Authentication | Result |
|---|---|---|
| `GET /health/live` | none | `200 {"status": "alive"}` while the process runs |
| `GET /health/ready` | none | `200 {"status": "ready"}` when the database answers and its schema is current; otherwise `503` |
| `GET /v1/me` | bearer token | The caller's identity ID, name, kind, roles and credential ID |
| `POST /v1/tasks` | bearer token and `Idempotency-Key` | Submits a task: `201` when created, `200` when the same request is repeated |
| `GET /v1/tasks` | bearer token | The caller's tasks, newest first; `scope=all` lists everyone's (admins and auditors) |
| `GET /v1/tasks/{id}` | bearer token | One task, if the caller may see it; otherwise `404` |
| `POST /v1/tasks/{id}/cancel` | bearer token | Cancels a task (`200`), or asks a running one to stop (`202`) |

```bash
TOKEN=$(uv run --locked --env-file .env aegis credential issue alice)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/v1/me
curl -s -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: first-task-0001" \
  -H "Content-Type: application/json" -d '{"kind": "wait", "input": {"seconds": 5}}' \
  http://127.0.0.1:8000/v1/tasks
```

- Every `/v1` route requires a token. Every authentication failure gets the same `401`, whatever the reason. Failures involving an existing credential (wrong secret, revoked, expired, disabled identity) are audited as `auth.failed`.
- There are no administration routes; use the CLI.
- Errors are problem details (`application/problem+json`) with a stable `code`. They never echo what was sent.
- Request bodies are limited to 64 KiB and must be `application/json`.
- Every response carries an `X-Request-ID`, which also appears in the logs and audit events.
- `/docs` and `/openapi.json` exist only when `AEGIS_ENV=development`.

Tasks:

- The only kinds are `noop` (input `{}`) and `wait` (input `{"seconds": n}`, 0 to 300). A `wait` over 30 seconds is created in `awaiting_approval`; approvals arrive in Phase 6. Each identity may have at most 10 unfinished tasks.
- `Idempotency-Key` is required: 8 to 128 characters from `A-Z a-z 0-9 _ . : -`, unique per identity. Repeating a request with the same key and body returns the original task with `Idempotent-Replayed: true`; the same key with a different body gets `409`. A refused submission does not use up its key.
- A refused request gets `403` with code `denied` and the policy's reason codes. Tasks the caller may not see get the same `404` as tasks that do not exist.
- Every submission, cancellation and refusal is saved as a security decision with its audit events, in the same transaction as the change. Reading another identity's tasks is audited as `task.read_privileged`.
- `GET /v1/tasks` takes `limit` (1 to 100, default 50) and the `next_cursor` from the previous page as `cursor`.

See ADR-0004 and ADR-0011 for the design and its limitations.

## The doctor

`make doctor` prints one line per check. Each check is **required** or **optional**, with a status of `PASS`, `WARN`, `FAIL` or `SKIP`.

- **Required:** Python 3.13, uv, Docker Engine, Docker Compose v2, `.env` configuration, disk space, memory, the PostgreSQL host port, the PostgreSQL service (Compose healthcheck plus a TCP connection from the host), and database migrations (the schema is at the latest revision).
- **Optional:** whether the doctor runs inside the project `.venv`, whether `.env` grants any permission to other users or groups, and whether `.env` defines every variable in `.env.example`.
- **Not checked:** the model provider (Phase 2), NVIDIA OpenShell (Phase 3) and Langfuse/OpenTelemetry (Phase 8). These are listed separately and never reported as passing.

The `.env` configuration check also validates `AEGIS_ENV` and `AEGIS_LOG_LEVEL`, requires every secret (the token pepper must be at least 32 characters), and rejects unknown `AEGIS_*` names.

The doctor exits non-zero if any required check fails or could not run. Optional checks never change the exit code. Secrets are redacted from all output.

The doctor does not authenticate as the AEGIS roles. `make test-integration` does.

## Tests

- **Unit tests** (`tests/unit`) are hermetic. A guard in `tests/unit/conftest.py` fails any test that opens a network or database connection or starts a subprocess. API unit tests use an in-process test client. `tests/unit/test_layering.py` enforces the import rules recorded in ADR-0002.
- **Integration tests** (`tests/integration`) use the real Docker CLI, `git`, `make` and PostgreSQL. They:
  - connect from the host and run `SELECT 1`;
  - check that PostgreSQL 17 is running and that a wrong password is rejected;
  - inspect the resolved Compose configuration;
  - exercise the real `make setup` and `make env-upgrade` targets;
  - verify `.gitignore`;
  - recreate, bootstrap and migrate a separate `<AEGIS_POSTGRES_DB>_test` database, then verify role privileges, migrations and the CLI against it;
  - verify the audit table's privileges, triggers and constraints, transactional recording and redaction;
  - verify the identity tables' privileges, triggers and constraints, token authentication, the administration rules and the `aegis` CLI, including that tokens and secrets never appear in storage or output;
  - verify the task integrity rules both through `apply_transition()` and through direct SQL as `aegis_app`, including concurrent transitions, and that the Python and SQL transition tables are identical;
  - verify the decision service: saved decisions and their inputs, the quota, the execution rules E1–E4, evaluator errors saved as denials, approval never queuing a task, and replay;
  - verify the API against the test database: CLI-issued tokens, identical 401s, `auth.failed` auditing, readiness when the database is down or behind, and that a real API process listens on `127.0.0.1` only;
  - verify the task API: idempotent submission (including concurrent requests), the quota, refusals saved as decisions, hidden tasks, audited privileged reads, cancellation in every state, saved decisions satisfying C1–C9, and that a failed audit write leaves no task, decision or event.

  They fail, never skip, when PostgreSQL or the settings are missing. Only databases whose names end in `_test` can be recreated; the development database is never touched by the tests.

## Validating an environment

| Step | Expected result |
|---|---|
| `make setup` | Exit 0. `.env` exists with mode 600. Running it again prints `.env already exists; leaving it unchanged.` |
| `make up` | The `postgres` container reports `Healthy`. |
| `make migrate` | Exit 0. Running it again reports `already at revision`. |
| `make doctor` | Every required check reports `PASS`, and the result line reads `Result: OK`. |
| `make check` | Exit 0. |
| `make test` | All unit tests pass. |
| `make test-integration` | All integration tests pass. |
| `make api`, then `curl http://127.0.0.1:8000/health/ready` | `{"status":"ready"}` |
| `make down`, then `make up` | Previously stored data is still present. |

### Continuous integration

CI (`.github/workflows/ci.yml`) runs the same Make targets on every push to `main` and on every pull request, in three jobs:

1. **Static checks:** `make lint` and `make typecheck`.
2. **Unit tests:** `make test`.
3. **Integration tests:** `make setup`, `make up`, `make migrate`, `make doctor` and `make test-integration`, with freshly generated secrets.

The workflow has read-only repository permissions and uses no secrets. Every action is pinned to a commit SHA, and caching is disabled.

## Data reset

To delete the local database, run `docker compose down --volumes`, then `make up` and `make migrate`. This is irreversible and no Make target deletes data.

## Troubleshooting

- **`make doctor` reports missing variables, or `make migrate` says a password is required.** New variables were added since your `.env` was created. Run `make env-upgrade`, then `make migrate`.
- **`make doctor` reports that database migrations are not applied or are behind.** Run `make migrate`.
- **`make env-upgrade` refuses because `.env` is accessible to other users.** Run `chmod 600 .env` and try again. Secrets are never appended to a file others can read.
- **`uv` not found.** Make sure the directory the uv installer used (usually `~/.local/bin`) is on `PATH`.
- **`VIRTUAL_ENV ... does not match the project environment` warning from uv.** Another virtualenv is active in your shell. uv ignores it and uses `.venv`. Run `deactivate` to silence the warning.
- **Docker `permission denied`.** Add your user to the `docker` group and log in again, or use rootless Docker.
- **Host port already in use.** Set a free `AEGIS_POSTGRES_PORT` in `.env`, then run `make down` and `make up`.
- **Second checkout on the same machine.** Checkouts share the Compose project name `aegis`, and therefore the container and database volume. Give the second checkout its own `COMPOSE_PROJECT_NAME=<name>` and a different `AEGIS_POSTGRES_PORT` in its `.env`.
- **The bootstrap password is a placeholder or too short, or `.env` was lost.** Run these steps in order:
  1. If `.env` exists, run `docker compose down --volumes`.
  2. Delete `.env`.
  3. Run `make setup`.
  4. Run `make up`.
  5. Run `make migrate`.

  This deletes the local database.
- **Integration tests fail with `password authentication failed` for the bootstrap user.** The volume was initialized with a different `AEGIS_POSTGRES_PASSWORD` than the one in `.env`. Run `docker compose down --volumes`, `make up`, then `make migrate`. This deletes the local database.

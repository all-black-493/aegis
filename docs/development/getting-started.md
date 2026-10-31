# Getting started

AEGIS has completed **Phase 0** and is building **Phase 1**. The repository provides a PostgreSQL service, an environment doctor, the configuration and logging foundation, and the test and quality tooling.

There is no API, worker, agent execution, model provider, OpenShell integration, audit store, or other security control yet. Nothing executes untrusted workloads.

## Supported platform

| Component | Supported | Tested with |
|---|---|---|
| Operating system | Ubuntu / Linux x86_64 | Ubuntu 26.04 LTS. CI targets GitHub-hosted `ubuntu-24.04` but has not run yet. |
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
| `AEGIS_POSTGRES_USER` | `aegis` | PostgreSQL user |
| `AEGIS_POSTGRES_DB` | `aegis` | PostgreSQL database |
| `AEGIS_POSTGRES_PASSWORD` | generated | 64 hex characters from a cryptographic random generator, unique per checkout. Older 48-character values remain valid. |
| `AEGIS_POSTGRES_PORT` | `5433` | Host port, published on `127.0.0.1` only |

Docker Compose refuses to start if any PostgreSQL variable is missing or empty.

Every `AEGIS_*` variable is listed in `src/aegis/config/variables.py`. An `AEGIS_*` name that isn't listed there is rejected as a probable typo.

These variables are operational configuration only. Security policy lives in code and cannot be changed through the environment.

PostgreSQL reads the user, database and password only when it initializes an empty volume. Changing them later requires a data reset (see Troubleshooting).

To change the port, edit `.env` and run `make down` followed by `make up`.

## The doctor

`make doctor` prints one line per check. Each check is **required** or **optional**, with a status of `PASS`, `WARN`, `FAIL` or `SKIP`.

- **Required:** Python 3.13, uv, Docker Engine, Docker Compose v2, `.env` configuration, disk space, memory, the PostgreSQL host port, and the PostgreSQL service (Compose healthcheck plus a TCP connection from the host).
- **Optional:** whether the doctor runs inside the project `.venv`, whether `.env` grants any permission to other users or groups, and whether `.env` defines every variable in `.env.example`.

The `.env` configuration check also validates `AEGIS_ENV` and `AEGIS_LOG_LEVEL`, and rejects unknown `AEGIS_*` names.
- **Not checked:** database migrations (Phase 1), the model provider (Phase 2), NVIDIA OpenShell (Phase 3) and Langfuse/OpenTelemetry (Phase 8). These are listed separately and never reported as passing.

The doctor exits non-zero if any required check fails or could not run. Optional checks never change the exit code. The PostgreSQL password is redacted from all output.

The doctor does not authenticate to PostgreSQL. `make test-integration` does.

## Tests

- **Unit tests** (`tests/unit`) are hermetic. A guard in `tests/unit/conftest.py` fails any test that opens a network connection or starts a subprocess. `tests/unit/test_layering.py` enforces the import rules recorded in ADR-0002.
- **Integration tests** (`tests/integration`) use the real Docker CLI, `git`, `make` and PostgreSQL. They:
  - connect from the host and run `SELECT 1`;
  - check that PostgreSQL 17 is running and that a wrong password is rejected;
  - inspect the resolved Compose configuration;
  - exercise the real `make setup` and `make env-upgrade` targets;
  - verify `.gitignore`.

  They fail, never skip, when PostgreSQL or the settings are missing.

## Validating an environment

| Step | Expected result |
|---|---|
| `make setup` | Exit 0. `.env` exists with mode 600. Running it again prints `.env already exists; leaving it unchanged.` |
| `make up` | The `postgres` container reports `Healthy`. |
| `make doctor` | Every required check reports `PASS`, and the result line reads `Result: OK`. |
| `make check` | Exit 0. |
| `make test` | All unit tests pass. |
| `make test-integration` | All integration tests pass. |
| `make down`, then `make up` | Previously stored data is still present. |

### Continuous integration

CI (`.github/workflows/ci.yml`) runs the same Make targets on every push to `main` and on every pull request, in three jobs:

1. **Static checks:** `make lint` and `make typecheck`.
2. **Unit tests:** `make test`.
3. **Integration tests:** `make setup`, `make up`, `make doctor` and `make test-integration`, with a freshly generated password.

The workflow has read-only repository permissions and uses no secrets. Every action is pinned to a commit SHA, and caching is disabled.

The workflow has not run on GitHub yet, because no remote is configured.

## Data reset

To delete the local database, run `docker compose down --volumes`. This is irreversible and no Make target does it.

## Troubleshooting

- **`make doctor` warns that `.env` is missing variables.** New variables were added since your `.env` was created. Run `make env-upgrade`.
- **`make env-upgrade` refuses because `.env` is accessible to other users.** Run `chmod 600 .env` and try again. Secrets are never appended to a file others can read.
- **`uv` not found.** Make sure the directory the uv installer used (usually `~/.local/bin`) is on `PATH`.
- **`VIRTUAL_ENV ... does not match the project environment` warning from uv.** Another virtualenv is active in your shell. uv ignores it and uses `.venv`. Run `deactivate` to silence the warning.
- **Docker `permission denied`.** Add your user to the `docker` group and log in again, or use rootless Docker.
- **Host port already in use.** Set a free `AEGIS_POSTGRES_PORT` in `.env`, then run `make down` and `make up`.
- **Second checkout on the same machine.** Checkouts share the Compose project name `aegis`, and therefore the container and database volume. Give the second checkout its own `COMPOSE_PROJECT_NAME=<name>` and a different `AEGIS_POSTGRES_PORT` in its `.env`.
- **The password is a placeholder or too short, or `.env` was lost.** Run these steps in order:
  1. If `.env` exists, run `docker compose down --volumes`.
  2. Delete `.env`.
  3. Run `make setup`.
  4. Run `make up`.

  This deletes the local database.
- **Integration tests fail with `password authentication failed`.** The volume was initialized with a different password than the one in `.env`. Run `docker compose down --volumes`, then `make up`. This deletes the local database.

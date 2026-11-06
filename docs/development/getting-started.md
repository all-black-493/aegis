# Getting started

AEGIS has implemented **Phase 0** (the local development foundation), **Phase 1** (API, worker, database and configuration), **Phase 2** (model provider abstraction) and **Phase 3** (NVIDIA OpenShell integration). The repository provides:

- a PostgreSQL service with least-privilege database roles and migrations;
- an append-only audit store;
- identities, role assignments and API credentials, administered through the `aegis` CLI;
- an HTTP API on `127.0.0.1` with health checks, `GET /v1/me`, and routes to submit, view, list and cancel tasks;
- a worker that runs the four built-in task kinds, `noop`, `wait`, `generate` and `enforcement_check`, with leases, retries and recovery;
- the authorization rules and the shared security-decision contract;
- task, decision and history storage whose integrity rules the database enforces;
- the versioned, fingerprinted policy and the decision service that saves every decision with its inputs;
- the model provider contract, a deterministic, offline mock provider and an adapter for a local Ollama server, used by `generate` tasks;
- the sandbox runtime contract, a version-pinned NVIDIA OpenShell adapter, AEGIS's sandbox policies and probe image, the prover gate that admits a sandbox only after its policy is proven within the boundary, and enforcement probes that verify the sandbox's filesystem, process and network restrictions independently, run by `enforcement_check` tasks;
- an environment doctor;
- the configuration and logging foundation;
- the test and quality tooling, including a security suite and an end-to-end test;
- the threat models for Phases 1 to 3, in `docs/security/`.

The worker runs only `noop`, `wait`, `generate` and `enforcement_check`. The first two have no effects outside AEGIS; `generate` sends one prompt to the configured model (the mock by default, or a local Ollama on `127.0.0.1`) and stores the text it returns. `enforcement_check` runs AEGIS's own fixed probes in an OpenShell sandbox and reports whether every restriction held (see NVIDIA OpenShell). It is the only kind that uses a sandbox: the other three run in the worker process, and AEGIS claims no filesystem, network or process isolation for them. There is no agent execution, and nothing executes untrusted workloads. The API and worker run as processes on the host; containers for them are planned, not built.

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
make test-security
make up-local-ai
make model-pull
make test-local-ai
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
| `make up-local-ai` | Starts PostgreSQL and the local Ollama server (optional; see Local AI below) and waits until both are healthy. |
| `make model-pull` | Downloads `AEGIS_OLLAMA_MODEL` into the local Ollama server and prints its digest. Requires `make up-local-ai`. |
| `make migrate` | Creates or updates the database roles and schema (`aegis db bootstrap`), then applies pending migrations (`aegis db migrate`). Safe to rerun. |
| `make api` | Runs the API in the foreground on `127.0.0.1`, port `AEGIS_API_PORT` (default 8000). Stop it with Ctrl-C. Requires `make up` and `make migrate`. |
| `make worker` | Runs the task worker in the foreground. Ctrl-C or SIGTERM stops it gracefully. Requires `make up` and `make migrate`; run as many as you like. |
| `make down` | Stops and removes all containers, including the local Ollama server. Volumes, including downloaded models, are kept. |
| `make test` | Runs the unit tests. Needs no Docker, database, model, network or credentials. |
| `make test-integration` | Runs the integration tests and the end-to-end test against the running PostgreSQL. Requires `make up`. |
| `make test-security` | Runs the security suite (`tests/security`) against the running PostgreSQL. Requires `make up`. |
| `make test-local-ai` | Runs the tests marked `local_ai` against the real local model. Requires `make up-local-ai`, `make model-pull` and `AEGIS_OLLAMA_MODEL`. Not part of CI. |
| `make openshell-init` | Creates AEGIS's OpenShell workspace if it does not exist, then checks the runtime. Requires OpenShell 0.1.6. |
| `make openshell-image` | Builds the probe image offline from the local `ubuntu:24.04` (pinned by digest, never pulled) and prints the `AEGIS_OPENSHELL_IMAGE=sha256:…` line to add to `.env`. |
| `make test-openshell` | Runs the tests marked `openshell` against the real OpenShell gateway. Requires `make openshell-init` and the local `ubuntu:24.04` image; stop any running worker first. Not part of CI. |
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
| `AEGIS_WORKER_POLL_SECONDS` | `1` (not in `.env.example`) | How often an idle worker looks for work, 1–60 |
| `AEGIS_WORKER_LEASE_SECONDS` | `30` (not in `.env.example`) | How long a claimed task stays leased without a heartbeat, 10–600 |
| `AEGIS_WORKER_HEARTBEAT_SECONDS` | `5` (not in `.env.example`) | How often a worker renews its lease; at most a third of the lease |
| `AEGIS_WORKER_SHUTDOWN_GRACE_SECONDS` | `10` (not in `.env.example`) | How long a running task may finish after a stop is requested, 0–300 |
| `AEGIS_WORKER_MAX_ATTEMPTS` | `3` (not in `.env.example`) | Attempts per task, 1 to the policy's maximum of 10 |
| `AEGIS_MODEL_PROVIDER` | `mock` (not in `.env.example`) | `mock` (deterministic and offline) or `ollama` (the local Ollama server; see Local AI below) |
| `AEGIS_OLLAMA_PORT` | `11436` (not in `.env.example`) | Port of the local Ollama server. The host is always `127.0.0.1`; there is no host setting. |
| `AEGIS_OLLAMA_MODEL` | none (not in `.env.example`) | Local Ollama model, such as `qwen3:0.6b`; required when the provider is `ollama`. Registry hosts are refused. |
| `AEGIS_OLLAMA_MODEL_DIGEST` | none (not in `.env.example`) | Optional pin: the model's 64-character digest |
| `AEGIS_MODEL_TIMEOUT_SECONDS` | `120` (not in `.env.example`) | How long a model call may wait for output, 5–600 |
| `AEGIS_SANDBOX_RUNTIME` | `none` (not in `.env.example`) | `none` (every sandbox operation is refused) or `openshell` (see NVIDIA OpenShell below) |
| `AEGIS_OPENSHELL_GATEWAY` | `openshell` (not in `.env.example`) | The registered OpenShell gateway AEGIS uses |
| `AEGIS_OPENSHELL_WORKSPACE` | `aegis` (not in `.env.example`) | The OpenShell workspace that holds AEGIS's sandboxes; `default` is refused |
| `AEGIS_OPENSHELL_IMAGE` | unset (not in `.env.example`) | The probe image's ID (`sha256:…`) from `make openshell-image`; sandboxes are created from exactly this image |
| `AEGIS_POSTGRES_USER` | `aegis` | PostgreSQL bootstrap superuser, used only to create roles and databases |
| `AEGIS_POSTGRES_DB` | `aegis` | PostgreSQL database |
| `AEGIS_POSTGRES_PASSWORD` | generated | Bootstrap superuser password. Older 48-character values remain valid. |
| `AEGIS_POSTGRES_PORT` | `5433` | Host port, published on `127.0.0.1` only |
| `AEGIS_DB_OWNER_PASSWORD` | generated | Password of `aegis_owner`, which runs migrations and administration |
| `AEGIS_DB_APP_PASSWORD` | generated | Password of `aegis_app`, which the API and worker use |
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
| `aegis_app` | Login; no ownership; only the privileges each migration grants | The API (`make api`) and the worker (`make worker`) |

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

Jobs in `aegis.jobs` carry admitted tasks to the worker. The database also refuses an attempt number that doesn't rise by exactly 1 at each claim, a renewed lease that had expired, and history from a worker that isn't the job's current attempt or whose lease has expired (rule D8, ADR-0009).

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

`make api` serves the API on `127.0.0.1` only. It connects as `aegis_app` and holds the token pepper; it never has owner or superuser credentials, and it removes every secret variable from its environment once its settings are loaded.

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

- The only kinds are `noop` (input `{}`), `wait` (input `{"seconds": n}`, 0 to 300), `generate` (input `{"prompt": text, "max_output_tokens": n}`, 1 to 8,000 characters and 1 to 512 tokens; see The worker) and `enforcement_check` (input `{}`; see NVIDIA OpenShell). A `wait` over 30 seconds is created in `awaiting_approval`; approvals arrive in Phase 6. Each identity may have at most 10 unfinished tasks.
- `Idempotency-Key` is required: 8 to 128 characters from `A-Z a-z 0-9 _ . : -`, unique per identity. Repeating a request with the same key and body returns the original task with `Idempotent-Replayed: true`; the same key with a different body gets `409`. A refused submission does not use up its key.
- A refused request gets `403` with code `denied` and the policy's reason codes. Tasks the caller may not see get the same `404` as tasks that do not exist.
- Every submission, cancellation and refusal is saved as a security decision with its audit events, in the same transaction as the change. Reading another identity's tasks is audited as `task.read_privileged`.
- `GET /v1/tasks` takes `limit` (1 to 100, default 50) and the `next_cursor` from the previous page as `cursor`.

See ADR-0004 and ADR-0011 for the design and its limitations.

## The worker

`make worker` runs a worker that claims queued tasks and runs them. It connects as `aegis_app`, loads no other secret, and removes every secret variable from its own environment before running anything. (`/proc/self/environ` still holds the initial copy; see the threat model.)

- **Delegated execution.** The worker acts as `system:worker`, never as the person who submitted the task. Before each task runs, it decides `task.execute` again with the current policy: the worker must hold the `worker` role, and the submitter must still be active, still hold `task:create`, and still have an unrevoked submitting credential. If not, the task fails with that reason and nothing runs. A newer policy can also hold the task for approval.
- **Leases.** A claimed task is leased for `AEGIS_WORKER_LEASE_SECONDS`, renewed at every heartbeat by the database clock. Every write by the worker is fenced on the job's attempt and lease, so a worker that has lost its lease cannot record anything more.
- **Cancellation.** A cancellation request reaches a running task at the next heartbeat. A heartbeat also stops the task if its submitter has been disabled.
- **Recovery.** If a worker dies, any worker notices the expired lease and moves the task to `interrupted`, then back to `queued` after a backoff, or to `failed` once its attempts are used up.
- **Shutdown.** Ctrl-C or SIGTERM stops the worker claiming. A running task gets `AEGIS_WORKER_SHUTDOWN_GRACE_SECONDS` to finish; otherwise it is released and queued again.
- **Delivery.** Delivery is at least once: a task may run again after a crash. `noop` and `wait` have no outside effects, `generate` only asks the model again, and `enforcement_check` runs its probes again in a new sandbox.
- **Models.** The worker builds the provider named by `AEGIS_MODEL_PROVIDER` once, at startup, and checks it. If it is unavailable, the worker logs `model provider unavailable` and still runs other kinds. A `generate` task is retried while the model server cannot be reached and fails with the provider's code (for example `model_missing` or `digest_mismatch`) otherwise.
- **`generate` results.** The result holds the `text`, why it stopped (`finish_reason`), the model's identity (`provider`, `model`, `model_digest`, `runtime_version`), token counts, the duration, and the fixed `temperature` 0 and `seed` 0. Each success adds a `model.generated` audit event with the identity and counts, never the prompt or the text. Neither appears in the logs.
- **Prompts are stored.** A prompt is task input, kept with the task and its decision. Never put secrets in a prompt. The output is untrusted text: AEGIS stores it and never acts on it.

```bash
make worker
curl -s -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: first-generate-0001" \
  -H "Content-Type: application/json" \
  -d '{"kind": "generate", "input": {"prompt": "Name three primary colours.", "max_output_tokens": 64}}' \
  http://127.0.0.1:8000/v1/tasks
```

See ADR-0009 for the design and its limitations.

## Local AI (optional)

The worker can use a local model through Ollama instead of the deterministic mock. Nothing else needs it: CI and the default setup use the mock.

1. Add to `.env`:
   ```bash
   AEGIS_MODEL_PROVIDER=ollama
   AEGIS_OLLAMA_MODEL=qwen3:0.6b
   ```
2. Run `make up-local-ai`. It starts AEGIS's own Ollama container, published on `127.0.0.1` only, at port `AEGIS_OLLAMA_PORT` (default 11436). An Ollama already running on the standard port 11434 is not affected.
3. Run `make model-pull`. It downloads the model, about 523 MB for `qwen3:0.6b`, into the Docker volume `aegis_ollama-models`, and prints its digest. To pin that exact model, add `AEGIS_OLLAMA_MODEL_DIGEST=<digest>` to `.env`.
4. Run `make doctor` (the model provider check is now required) and `make test-local-ai`.

Notes:

- **Image:** the container runs the Ollama image pinned by digest (0.34.2, the version the adapter was verified against; ADR-0014). Its root filesystem is read-only, it has no Linux capabilities, and privilege escalation is disabled.
- **Hardware:** no GPU is assumed; small models run on a CPU.
- **Remote models:** AEGIS refuses remote-backed models and never sends tools or system prompts.
- **Network:** the Ollama container itself can reach the internet, which pulls need; restricting it is OpenShell's job (Phase 3).
- **Using it:** restart `make worker` after changing the model settings; the worker reads them once, at startup. `generate` tasks then run on the local model, and their results name its digest and Ollama version.

## NVIDIA OpenShell (optional)

OpenShell is the runtime enforcement boundary for AEGIS workloads from Phase 3 on. So far AEGIS has the adapter, its sandbox policies, the probe image, the prover gate, the enforcement probes and the `enforcement_check` task kind that runs them (ADR-0016 to ADR-0019). No other task runs in a sandbox yet. CI never uses a real OpenShell.

1. Install NVIDIA OpenShell **0.1.6** (AEGIS refuses every other version) and start its gateway, for example the Debian package's `openshell-gateway.service` user unit. `openshell status` must report `connected`.
2. Run `make openshell-init`. It creates the `aegis` workspace on the gateway (`AEGIS_OPENSHELL_WORKSPACE`) if it is missing, and checks the CLI, prover and gateway versions and that no global policy is active.
3. Run `make openshell-image`. It builds the probe image offline and prints a line such as `AEGIS_OPENSHELL_IMAGE=sha256:…`.
4. Add `AEGIS_SANDBOX_RUNTIME=openshell` and that `AEGIS_OPENSHELL_IMAGE` line to `.env`, then run `make doctor` (the OpenShell check is now required) and `make test-openshell`.
5. Restart the worker and submit an `enforcement_check` task as an operator:

```bash
curl -s -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: first-check-0001" \
  -H "Content-Type: application/json" -d '{"kind": "enforcement_check", "input": {}}' \
  http://127.0.0.1:8000/v1/tasks
```

The task succeeds only if every check held. Its result is `{"verdict": "verified", "checks": {...}}`, and each check is audited as `enforcement.checked` with what was expected, what was observed and the outcome. A violated check fails the task with `enforcement_violation` and is logged at `ERROR`; anything unclear fails it with `enforcement_inconclusive`. An unreachable gateway or a busy canary is retried. A refused policy, image or OpenShell version fails the task with its code, and without a runtime it fails with `sandbox_unavailable` (ADR-0019).

Notes:

- **What AEGIS may do on the gateway:** only the commands listed in ADR-0016, only in its own workspace, and only to sandboxes named `aegis-*` and labelled `aegis.managed=true`. It never sets a global policy, attaches providers or changes a running sandbox's policy.
- **Shared gateway:** on a local gateway without OIDC roles, the CLI identity is a Platform Admin. AEGIS restricts itself in code; the workspace is a scope, not an access boundary.
- **Policies and the gate:** AEGIS's sandbox policies are in `deploy/openshell/` and fingerprinted. Before a sandbox is used, the prover must show its submitted and its effective policy within `boundary.yaml`, and the image must carry AEGIS's release marker. The sandbox is always deleted afterwards, and both events are audited (`sandbox.created`, `sandbox.deleted`).
- **Enforcement probes:** a run starts a canary on the default Docker bridge, `172.17.0.1`, ports 18901 and 18902. The ports must be free and `docker0` must have that address. It opens a gated sandbox and runs 16 fixed probes, one exec each: filesystem, process and network restrictions, plus positive controls. AEGIS judges each one from the command's result and what the canary received, and reports `verified`, `violated` or `inconclusive`. OpenShell's own denial records are reported beside AEGIS's evidence as corroboration (ADR-0018).
- **Orphans:** a worker deletes AEGIS's sandboxes whose job is no longer running, at its first step and then once a minute. A worker running during `make test-openshell` would also delete the tests' sandboxes, so stop it first.
- **No downloads:** the image is built from the local `ubuntu:24.04`, and the tests fail with a hint if it is missing.
- **Upgrades:** a new OpenShell release must be re-verified before AEGIS accepts it (ADR-0016). Consider `sudo apt-mark hold openshell`.

## The doctor

`make doctor` prints one line per check. Each check is **required** or **optional**, with a status of `PASS`, `WARN`, `FAIL` or `SKIP`.

- **Required:** Python 3.13, uv, Docker Engine, Docker Compose v2, `.env` configuration, disk space, memory, the PostgreSQL host port, the PostgreSQL service (Compose healthcheck plus a TCP connection from the host), and database migrations (the schema is at the latest revision).
- **Optional:** whether the doctor runs inside the project `.venv`, whether `.env` grants any permission to other users or groups, and whether `.env` defines every variable in `.env.example`.
- **Model provider:** optional and passing with the mock. Required when `AEGIS_MODEL_PROVIDER=ollama`: the local server must be reachable, the configured model present, local and matching any pinned digest. A server version other than the verified 0.34.2 is a warning.
- **NVIDIA OpenShell:** optional and skipped while `AEGIS_SANDBOX_RUNTIME=none`, which refuses every sandbox operation. Required when it is `openshell`: Landlock ABI 3 or later, the CLI, prover and gateway at the verified 0.1.6, the gateway connected, AEGIS's workspace present, no global policy active, and the probe image configured and present.
- **Not checked:** Langfuse/OpenTelemetry (Phase 8). It is listed separately and never reported as passing.

The `.env` configuration check also validates `AEGIS_ENV` and `AEGIS_LOG_LEVEL`, requires every secret (the token pepper must be at least 32 characters), and rejects unknown `AEGIS_*` names.

The doctor exits non-zero if any required check fails or could not run. Optional checks never change the exit code. Secrets are redacted from all output.

The doctor does not authenticate as the AEGIS roles. `make test-integration` and `make test-security` do.

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
  - verify the task API: idempotent submission (including concurrent requests), the quota, refusals saved as decisions, hidden tasks, audited privileged reads, cancellation in every state, saved decisions satisfying C1–C9, and that a failed audit write leaves no task, decision or event;
  - verify the Compose configuration of the optional Ollama service (profile, digest pin, loopback-only port, hardening);
  - verify the Ollama adapter against a fake Ollama server on `127.0.0.1`: model checks, streaming, limits, refusals of tool calls and remote models, timeouts, stopping, and that prompts and output never reach logs or errors;
  - verify the OpenShell adapter against a fake `openshell` and `openshell-prover`: health and its failure codes, the exact arguments of `create` and `exec`, no sandbox left behind when creation is refused or not ready, exec timeouts and bounded output, confirmed deletion, paging and filtering of AEGIS's sandboxes, and prover verdicts;
  - verify sandbox auditing against the test database: a gated sandbox's `sandbox.created` and `sandbox.deleted` events, and orphan cleanup that keeps a running job's sandbox and deletes only AEGIS's dead ones;
  - verify the worker: a task from submission to `succeeded` with its full audit chain, one claim among racing workers, stale workers refused by the service and the database, the attempt rule, the execution checks E1–E6 with the handler never running, cancellation, retries, recovery after `kill -9`, graceful shutdown, and the real `make worker` process;
  - verify `generate` tasks with the mock: from the API to `succeeded` with `model.generated`, refused prompts never sent, cancellation stopping the model, retries while the model is unavailable, failure codes for refused models, and a worker process with an unreachable model still running other kinds;
  - verify `enforcement_check` tasks against a fake `openshell` CLI: from the API to `succeeded` with the full audit chain (sandbox creation and deletion, one `enforcement.checked` per check), sandbox names and labels, retries of an unreachable gateway with a new sandbox per attempt, refusals that run no probe, cancellation that stops the probes and deletes the sandbox, and the worker's orphan sweep.

- **The end-to-end tests** (`tests/e2e`) use only real processes: the `aegis` CLI creates identities and issues tokens, then the API and worker processes run tasks over HTTP on loopback. Neither process output may contain a credential.
  - **Phase 1 workflow** (run by `make test-integration`): a worker is killed with SIGKILL during a task, and a second worker finishes it. The audit chain is checked.
  - **Phase 3 workflow:** with real OpenShell (`make test-openshell`), an `enforcement_check` runs from the API through the worker to `succeeded`. A submission with input is refused. The test checks the verdict, the audit chain (runtime version, image, policy version and fingerprint, prover result, and all 16 checks with every network result corroborated), the decisions and policy version, that no sandbox is left behind, and that no secret appears in any process output. Without OpenShell (`make test-integration`, as in CI), a worker with no runtime fails the check with `sandbox_unavailable` and still runs other tasks, and a worker configured for OpenShell with no image fails it with `image_missing`.
  - **Phase 2 workflow, once per provider:** a `generate` task runs from submission to `succeeded`. A submission that tries to choose the model is refused. The test checks the result's model identity, the history, the audit chain ending in `model.generated`, the decisions and policy version, and that neither the prompt nor the output appears in any process output. `make test-integration` runs it with the mock (as CI does), and `make test-local-ai` runs it with the local Ollama model.
- **Local AI tests** (marked `local_ai`, run only by `make test-local-ai`) check the real local model: the verified runtime version, the doctor's model check, finishing on stop and length, repeatability at temperature 0 with a fixed seed, stopping, digest pinning, and the Phase 2 end-to-end workflow. `make test-integration` and CI deselect them, and they fail rather than skip when `AEGIS_OLLAMA_MODEL` is not set.
- **The security suite** (`tests/security`, run by `make test-security`) holds the cross-cutting checks that the threat models (`docs/security/phase-1-threat-model.md`, `phase-2-threat-model.md` and `phase-3-threat-model.md`) rely on:
  - the exact privileges of `aegis_app`;
  - attacks made with stolen `aegis_app` credentials: approval bypass, forged tasks, unregistered kinds;
  - spoofed request IDs;
  - a sweep of every table, log and response for credentials;
  - failure injection: database down, database lost during a run, audit writes failing in the worker, evaluator errors, and a worker started on an outdated schema;
  - the model boundary: model output stored as inert text, tasks unable to choose the model, sampling or tools, and output the database cannot hold failing the task;
  - the model server boundary, against a fake Ollama server on loopback and driven through the real worker:
    - only the prompt and fixed options reach the server, with no secret in any request;
    - remote, swapped, missing or misreporting models never receive the prompt;
    - a tool call or a stream that ends early stores nothing;
    - an endless stream is cut to the output limit.
  - the enforcement probes, through the gate and the adapter against a fake `openshell` CLI: a sandbox that claims a refusal the canary saw through is a violation, a write that succeeded is a violation, OpenShell's records alone never verify a run, and a refused or failing run runs no probe or still deletes its sandbox and stops the canary;
  - the sandbox gate, against a fake `openshell` CLI: a submitted policy that is not proven (exceeding, unsupported, inconclusive, an error or partial coverage) creates nothing; an effective policy widened by a provider is proven as enforced, refused and deleted; a global policy stops the gate; an unrecognised image is deleted unused; orphan cleanup never touches other sandboxes;
  - the `enforcement_check` boundary, against a fake `openshell` CLI and driven through the real worker: every fail-closed path in the Phase 3 threat model, one by one (no runtime, a disabled or unavailable one, a missing CLI or image, wrong versions, a missing workspace, a global policy, a refused policy, a rejected or unready sandbox, a sandbox refused after creation, a runtime that stalls mid-run, and a sandbox that cannot be deleted). A request the canary saw or a write that succeeded fails the task as `enforcement_violation`, logged and audited; a failed control is never verified; runtime records alone never verify a check; what cannot be audited never succeeds; only `enforcement_check` tasks can create a sandbox; decisions are identical whichever runtime is configured; the registry matches the policy; auditors cannot start checks;
  - the sandbox runtime boundary, against a fake `openshell` CLI: no AEGIS secret or `OPENSHELL_*` override reaches the CLI, only allow-listed commands run in AEGIS's workspace, other sandboxes are never listed or deleted, an unverified or unreachable runtime creates nothing, and a disabled runtime starts no process.
- **OpenShell tests** (marked `openshell`, run only by `make test-openshell`) check the real gateway: the verified version, a sandbox's lifecycle and user, exec timeouts, the effective policy against its boundary through the prover, and the prover's refusals. They also build the probe image with `make openshell-image`, open the gate with AEGIS's real policies (UID and GID 2000, audited creation and deletion), and show that the real prover stops `best_effort` Landlock, a root user or a widened path before any sandbox is created. They then run the enforcement probes, which must report `verified` with every network refusal corroborated by OpenShell, and run them under a deliberately widened policy, which must report the two gaps as `violated`. An `enforcement_check` task then runs through the worker and must succeed with every check held and corroborated, and again through real API and worker processes (the Phase 3 workflow). A sandbox's environment and filesystem must show none of the host's AEGIS secrets, `.env` or gateway keys. Stop any running worker first: its orphan sweep would delete the tests' sandboxes. `make test-integration` and CI deselect them.
- **Shared test code** (`tests/fixtures`): the shared callers, audit recorder and worker settings (`services`); record queries (`records`); the fake Ollama server; the fake `openshell` and `openshell-prover`; an in-process fake runtime; probe answers, including a fake CLI scripted to enforce everything; the enforcement check and worker built for tests (`enforcement`); test-only OpenShell policies; and the helpers that start processes and find free ports. `tests/conftest.py` provides the database fixtures, `operator`, and the live OpenShell runtime and probe image.

Integration, end-to-end and security tests fail, never skip, when PostgreSQL or the settings are missing. They share the `<AEGIS_POSTGRES_DB>_test` database, recreated for each run; one security test also recreates `<AEGIS_POSTGRES_DB>_outdated_test`. Only databases whose names end in `_test` can be recreated; the development database is never touched by the tests.

## Validating an environment

| Step | Expected result |
|---|---|
| `make setup` | Exit 0. `.env` exists with mode 600. Running it again prints `.env already exists; leaving it unchanged.` |
| `make up` | The `postgres` container reports `Healthy`. |
| `make migrate` | Exit 0. Running it again reports `already at revision`. |
| `make doctor` | Every required check reports `PASS`, and the result line reads `Result: OK`. |
| `make check` | Exit 0. |
| `make test` | All unit tests pass. |
| `make test-integration` | All integration and end-to-end tests pass. |
| `make test-security` | All security tests pass. |
| `make up-local-ai`, `make model-pull`, `make test-local-ai` (optional) | Both containers report `Healthy`; the pull prints `is ready: digest …`; all local AI tests pass. |
| `make openshell-init`, `make openshell-image`, `make test-openshell` (optional) | `OpenShell 0.1.6 is ready`; the image ID is printed; all OpenShell tests pass. |
| `make api`, then `curl http://127.0.0.1:8000/health/ready` | `{"status":"ready"}` |
| `make down`, then `make up` | Previously stored data is still present. |

### Continuous integration

CI (`.github/workflows/ci.yml`) runs the same Make targets on every push to `main` and on every pull request, in three jobs:

1. **Static checks:** `make lint` and `make typecheck`.
2. **Unit tests:** `make test`.
3. **Integration tests:** `make setup`, `make up`, `make migrate`, `make doctor`, `make test-integration` and `make test-security`, with freshly generated secrets.

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

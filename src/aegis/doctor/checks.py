import json
import stat
from dataclasses import dataclass
from pathlib import Path

from aegis.config.envfile import PLACEHOLDER, EnvFileError, parse_env_file
from aegis.config.settings import (
    ModelProviderKind,
    SandboxRuntimeKind,
    SettingsError,
    load_api_settings,
    load_common_settings,
    load_model_settings,
    load_runtime_settings,
    load_token_pepper,
    load_worker_settings,
)
from aegis.config.variables import REQUIRED_NAMES, SECRET_NAMES
from aegis.db.migrate import head_revision
from aegis.doctor.model import CheckResult, Diagnosis, Requirement, Status
from aegis.doctor.system import System
from aegis.integrations.ollama.provider import VERIFIED_VERSION
from aegis.integrations.openshell.cli import VERIFIED_VERSION as VERIFIED_OPENSHELL

REQUIRED_PYTHON = (3, 13)
POSTGRES_HOST = "127.0.0.1"
POSTGRES_SERVICE = "postgres"
SCHEMA_VERSION_QUERY = "SELECT version_num FROM aegis.alembic_version"
MIN_SECRET_LENGTH = 16
GIB = 1024**3
MIN_FREE_DISK_BYTES = 2 * GIB
MIN_TOTAL_MEMORY_BYTES = 2 * GIB
LOW_AVAILABLE_MEMORY_BYTES = 1 * GIB
MIN_LANDLOCK_ABI = 3

REQUIRED = Requirement.REQUIRED
OPTIONAL = Requirement.OPTIONAL
PASS, WARN, FAIL, SKIP = Status.PASS, Status.WARN, Status.FAIL, Status.SKIP


@dataclass(frozen=True)
class _Docker:
    executable: str | None
    root_dir: Path | None


@dataclass(frozen=True)
class _Container:
    state: str
    health: str


@dataclass(frozen=True)
class _PostgresState:
    blockers: tuple[str, ...]
    container: _Container | None = None
    error: str | None = None

    @property
    def known(self) -> bool:
        return not self.blockers and self.error is None


_MODEL_HINTS = {
    "unreachable": "start it with `make up-local-ai`",
    "model_missing": "pull it with `make model-pull`",
    "digest_mismatch": "the model differs from AEGIS_OLLAMA_MODEL_DIGEST",
    "remote_model": "remote-backed models are refused",
    "not_generative": "the model cannot generate text",
}


_RUNTIME_HINTS = {
    "cli_missing": f"install the OpenShell {VERIFIED_OPENSHELL} package",
    "version_mismatch": f"AEGIS is verified with OpenShell {VERIFIED_OPENSHELL} only (ADR-0016)",
    "unreachable": "start it with `systemctl --user start openshell-gateway`",
    "not_connected": "register and select the gateway named by AEGIS_OPENSHELL_GATEWAY",
    "workspace_missing": "create it with `make openshell-init`",
    "global_policy_active": "a global policy would replace AEGIS's sandbox policies",
}


def run_checks(system: System, root: Path) -> Diagnosis:
    env_values, env_result = check_env_file(root)
    engine_result, docker = check_docker_engine(system, root)
    compose_result = check_docker_compose(system, root, docker)
    port = _port(env_values) if env_result.status is PASS else None
    blockers = tuple(
        result.name
        for result in (engine_result, compose_result, env_result)
        if result.status is not PASS
    )
    postgres = _probe_postgres(system, root, docker, blockers)
    service_result = check_postgres_service(system, port, postgres)

    results = (
        check_python(system),
        check_project_environment(system, root),
        check_uv(system, root),
        engine_result,
        compose_result,
        env_result,
        check_env_permissions(root),
        check_env_template(root, env_values),
        check_disk(system, root, docker.root_dir),
        check_memory(system),
        check_postgres_port(system, port, postgres),
        service_result,
        check_migrations(system, root, docker, env_values, service_result),
        check_model_provider(system, env_values if env_result.status is PASS else None),
        check_sandbox_runtime(system, env_values if env_result.status is PASS else None),
    )
    secrets = frozenset(
        value for key, value in (env_values or {}).items() if key in SECRET_NAMES and value
    )
    return Diagnosis(results, secrets)


def check_python(system: System) -> CheckResult:
    version = system.python_version()
    text = ".".join(str(part) for part in version)
    if version[:2] == REQUIRED_PYTHON:
        return CheckResult("Python 3.13", REQUIRED, PASS, text)
    return CheckResult(
        "Python 3.13",
        REQUIRED,
        FAIL,
        f"found {text}; run `make doctor` so uv selects 3.13",
    )


def check_project_environment(system: System, root: Path) -> CheckResult:
    name = "Project environment"
    prefix = system.python_prefix()
    expected = root / ".venv"
    if prefix.resolve() == expected.resolve():
        return CheckResult(name, OPTIONAL, PASS, str(expected))
    return CheckResult(
        name,
        OPTIONAL,
        WARN,
        f"running from {prefix}, not {expected}; use `make doctor`",
    )


def check_uv(system: System, root: Path) -> CheckResult:
    uv = system.which("uv")
    if uv is None:
        return CheckResult("uv", REQUIRED, FAIL, "not found on PATH")
    result = system.run([uv, "--version"], root)
    if result.returncode != 0:
        return CheckResult("uv", REQUIRED, FAIL, _first_line(result.stderr))
    return CheckResult("uv", REQUIRED, PASS, result.stdout.strip())


def check_docker_engine(system: System, root: Path) -> tuple[CheckResult, _Docker]:
    name = "Docker Engine"
    docker = system.which("docker")
    if docker is None:
        return CheckResult(name, REQUIRED, FAIL, "docker CLI not found on PATH"), _Docker(
            None, None
        )
    result = system.run([docker, "info", "--format", "{{json .}}"], root)
    info = _json_object(result.stdout)
    version = str(info.get("ServerVersion") or "")
    if result.returncode != 0 or not version:
        detail = f"daemon not reachable: {_first_line(result.stderr)}"
        if "permission denied" in result.stderr.lower():
            detail += " (add your user to the docker group, or use rootless Docker)"
        return CheckResult(name, REQUIRED, FAIL, detail), _Docker(docker, None)
    root_dir = info.get("DockerRootDir")
    docker_root = Path(root_dir) if isinstance(root_dir, str) and root_dir else None
    return CheckResult(name, REQUIRED, PASS, version), _Docker(docker, docker_root)


def check_docker_compose(system: System, root: Path, docker: _Docker) -> CheckResult:
    name = "Docker Compose v2"
    if docker.executable is None:
        return CheckResult(name, REQUIRED, SKIP, "blocked by: docker CLI not found")
    result = system.run([docker.executable, "compose", "version", "--short"], root)
    version = result.stdout.strip().removeprefix("v")
    major = version.split(".")[0]
    if result.returncode != 0 or not major.isdigit():
        return CheckResult(name, REQUIRED, FAIL, "the `docker compose` plugin is not available")
    if int(major) < 2:
        return CheckResult(name, REQUIRED, FAIL, f"found {version}; version 2 or later is required")
    return CheckResult(name, REQUIRED, PASS, version)


def check_env_file(root: Path) -> tuple[dict[str, str] | None, CheckResult]:
    name = ".env configuration"
    path = root / ".env"
    if not path.is_file():
        return None, CheckResult(name, REQUIRED, FAIL, "not found; run `make setup`")
    try:
        values = parse_env_file(path)
    except EnvFileError as error:
        return None, CheckResult(name, REQUIRED, FAIL, f"invalid: {error}")
    except (OSError, UnicodeDecodeError):
        return None, CheckResult(name, REQUIRED, FAIL, "could not be read as UTF-8 text")
    problem = _env_problem(values)
    if problem is not None:
        return values, CheckResult(name, REQUIRED, FAIL, problem)
    return values, CheckResult(name, REQUIRED, PASS, "PostgreSQL settings are present")


def check_env_permissions(root: Path) -> CheckResult:
    name = ".env permissions"
    path = root / ".env"
    if not path.is_file():
        return CheckResult(name, OPTIONAL, SKIP, ".env not found")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        return CheckResult(
            name,
            OPTIONAL,
            WARN,
            f"mode {mode:o} lets other users access it; run `chmod 600 .env`",
        )
    return CheckResult(name, OPTIONAL, PASS, f"mode {mode:o}")


def check_env_template(root: Path, env_values: dict[str, str] | None) -> CheckResult:
    name = ".env up to date"
    if env_values is None:
        return CheckResult(name, OPTIONAL, SKIP, "blocked by: .env configuration")
    try:
        template = parse_env_file(root / ".env.example")
    except (OSError, UnicodeDecodeError, EnvFileError):
        return CheckResult(name, OPTIONAL, SKIP, ".env.example could not be read")
    missing = [key for key in template if key not in env_values]
    if missing:
        return CheckResult(
            name, OPTIONAL, WARN, f"missing {', '.join(missing)}; run `make env-upgrade`"
        )
    return CheckResult(name, OPTIONAL, PASS, "defines every variable in .env.example")


def check_disk(system: System, root: Path, docker_root: Path | None) -> CheckResult:
    name = "Disk space"
    notes: list[str] = []
    too_low = unknown = False
    for label, path in (("project", root), ("Docker data", docker_root)):
        if path is None:
            continue
        free = system.disk_free_bytes(path)
        if free is None:
            notes.append(f"{label}: unknown")
            unknown = True
            continue
        notes.append(f"{label} {free / GIB:.1f} GiB free")
        too_low = too_low or free < MIN_FREE_DISK_BYTES
    detail = ", ".join(notes)
    if too_low:
        return CheckResult(
            name,
            REQUIRED,
            FAIL,
            f"{detail}; at least {MIN_FREE_DISK_BYTES // GIB} GiB needed",
        )
    return CheckResult(name, REQUIRED, WARN if unknown else PASS, detail)


def check_memory(system: System) -> CheckResult:
    name = "Memory"
    memory = system.memory()
    if memory is None:
        return CheckResult(name, REQUIRED, FAIL, "cannot read /proc/meminfo; Linux is required")
    detail = (
        f"{memory.total_bytes / GIB:.1f} GiB total, "
        f"{memory.available_bytes / GIB:.1f} GiB available"
    )
    if memory.total_bytes < MIN_TOTAL_MEMORY_BYTES:
        return CheckResult(
            name,
            REQUIRED,
            FAIL,
            f"{detail}; at least {MIN_TOTAL_MEMORY_BYTES // GIB} GiB needed",
        )
    if memory.available_bytes < LOW_AVAILABLE_MEMORY_BYTES:
        return CheckResult(name, REQUIRED, WARN, f"{detail}; low available memory")
    return CheckResult(name, REQUIRED, PASS, detail)


def check_postgres_port(system: System, port: int | None, postgres: _PostgresState) -> CheckResult:
    name = "PostgreSQL host port"
    if port is None:
        return CheckResult(name, REQUIRED, SKIP, "blocked by: .env configuration")
    address = f"{POSTGRES_HOST}:{port}"
    if postgres.container is not None and postgres.container.state == "running":
        return CheckResult(name, REQUIRED, PASS, f"{address} is used by the aegis postgres service")
    if system.can_bind(POSTGRES_HOST, port):
        return CheckResult(name, REQUIRED, PASS, f"{address} is available")
    if not postgres.known:
        return CheckResult(
            name,
            REQUIRED,
            FAIL,
            f"{address} is in use; Docker checks failed, so the owner is unknown",
        )
    return CheckResult(
        name,
        REQUIRED,
        FAIL,
        f"{address} is in use by another process; set a free AEGIS_POSTGRES_PORT in .env",
    )


def check_postgres_service(
    system: System, port: int | None, postgres: _PostgresState
) -> CheckResult:
    name = "PostgreSQL service"
    if postgres.blockers:
        return CheckResult(name, REQUIRED, SKIP, f"blocked by: {', '.join(postgres.blockers)}")
    if postgres.error is not None:
        return CheckResult(
            name, REQUIRED, FAIL, f"could not query Docker Compose: {postgres.error}"
        )
    container = postgres.container
    if container is None:
        return CheckResult(name, REQUIRED, FAIL, "not created; run `make up`")
    if container.state != "running":
        return CheckResult(name, REQUIRED, FAIL, f"container is {container.state}; run `make up`")
    if container.health != "healthy":
        return CheckResult(
            name,
            REQUIRED,
            FAIL,
            f"health is {container.health or 'unknown'}; see `docker compose logs postgres`",
        )
    if port is None or not system.can_connect(POSTGRES_HOST, port):
        return CheckResult(
            name,
            REQUIRED,
            FAIL,
            f"not accepting connections on {POSTGRES_HOST}:{port}; run `make down` then `make up`",
        )
    return CheckResult(
        name,
        REQUIRED,
        PASS,
        f"healthy, accepting connections on {POSTGRES_HOST}:{port}",
    )


def _probe_postgres(
    system: System, root: Path, docker: _Docker, blockers: tuple[str, ...]
) -> _PostgresState:
    if blockers or docker.executable is None:
        return _PostgresState(blockers)
    result = system.run(
        [
            docker.executable,
            "compose",
            "ps",
            "--all",
            "--format",
            "json",
            POSTGRES_SERVICE,
        ],
        root,
    )
    if result.returncode != 0:
        return _PostgresState((), error=_first_line(result.stderr))
    try:
        entries = _parse_compose_ps(result.stdout)
    except ValueError:
        return _PostgresState((), error="unexpected `docker compose ps` output")
    for entry in entries:
        if entry.get("Service") == POSTGRES_SERVICE:
            container = _Container(str(entry.get("State", "")), str(entry.get("Health", "")))
            return _PostgresState((), container)
    return _PostgresState(())


def _env_problem(values: dict[str, str]) -> str | None:
    missing = [key for key in REQUIRED_NAMES if not values.get(key)]
    if missing:
        return f"missing or empty: {', '.join(missing)}; run `make env-upgrade`"
    for key in sorted(SECRET_NAMES & values.keys()):
        if values[key] == PLACEHOLDER:
            return f"{key} is still the placeholder; see getting-started troubleshooting"
        if len(values[key]) < MIN_SECRET_LENGTH:
            return f"{key} is shorter than {MIN_SECRET_LENGTH} characters"
    if _port(values) is None:
        return "AEGIS_POSTGRES_PORT must be an integer from 1024 to 65535"
    try:
        load_common_settings(values)
        load_api_settings(values)
        load_worker_settings(values)
        load_model_settings(values)
        load_runtime_settings(values)
        load_token_pepper(values)
    except SettingsError as error:
        return "; ".join(error.problems)
    return None


def _port(values: dict[str, str] | None) -> int | None:
    raw = (values or {}).get("AEGIS_POSTGRES_PORT", "")
    if not (raw.isascii() and raw.isdigit()):
        return None
    port = int(raw)
    return port if 1024 <= port <= 65535 else None


def _parse_compose_ps(output: str) -> list[dict[str, object]]:
    text = output.strip()
    if not text:
        return []
    # Compose emits a JSON array before v2.21 and one object per line afterwards.
    if text.startswith("["):
        entries = json.loads(text)
    else:
        entries = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [entry for entry in entries if isinstance(entry, dict)]


def _json_object(text: str) -> dict[str, object]:
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def check_migrations(
    system: System,
    root: Path,
    docker: _Docker,
    env_values: dict[str, str] | None,
    service: CheckResult,
) -> CheckResult:
    name = "Database migrations"
    if service.status is not PASS or docker.executable is None or env_values is None:
        return CheckResult(name, REQUIRED, SKIP, "blocked by: PostgreSQL service")
    result = system.run(
        [
            docker.executable,
            "compose",
            "exec",
            "-T",
            POSTGRES_SERVICE,
            "psql",
            "-U",
            env_values["AEGIS_POSTGRES_USER"],
            "-d",
            env_values["AEGIS_POSTGRES_DB"],
            "-XAtq",
            "-c",
            SCHEMA_VERSION_QUERY,
        ],
        root,
    )
    head = head_revision()
    if result.returncode != 0 and "does not exist" not in result.stderr:
        return CheckResult(
            name, REQUIRED, FAIL, f"could not read the schema version: {_first_line(result.stderr)}"
        )
    current = result.stdout.strip() if result.returncode == 0 else ""
    if not current:
        return CheckResult(name, REQUIRED, FAIL, "not applied; run `make migrate`")
    if current != head:
        return CheckResult(
            name, REQUIRED, FAIL, f"at revision {current}, latest is {head}; run `make migrate`"
        )
    return CheckResult(name, REQUIRED, PASS, f"at latest revision {head}")


def check_model_provider(system: System, env_values: dict[str, str] | None) -> CheckResult:
    name = "Model provider"
    if env_values is None:
        return CheckResult(name, OPTIONAL, SKIP, "blocked by: .env configuration")
    settings = load_model_settings(env_values)
    if settings.provider is ModelProviderKind.MOCK or settings.ollama is None:
        return CheckResult(name, OPTIONAL, PASS, "mock provider (deterministic, offline)")
    ollama = settings.ollama
    status = system.model_status(settings)
    if not status.healthy or status.identity is None:
        hint = _MODEL_HINTS.get(status.detail, "see ADR-0014")
        return CheckResult(name, REQUIRED, FAIL, f"{ollama.model}: {status.detail}; {hint}")
    identity = status.identity
    digest = (identity.digest or "")[:12]
    detail = f"{ollama.model} ({digest}) on Ollama {identity.runtime_version}"
    if identity.runtime_version != VERIFIED_VERSION:
        return CheckResult(
            name, REQUIRED, WARN, f"{detail}; the adapter was verified with {VERIFIED_VERSION}"
        )
    return CheckResult(name, REQUIRED, PASS, detail)


def check_sandbox_runtime(system: System, env_values: dict[str, str] | None) -> CheckResult:
    name = "NVIDIA OpenShell"
    if env_values is None:
        return CheckResult(name, OPTIONAL, SKIP, "blocked by: .env configuration")
    settings = load_runtime_settings(env_values)
    if settings.runtime is SandboxRuntimeKind.NONE:
        return CheckResult(
            name, OPTIONAL, SKIP, "disabled (AEGIS_SANDBOX_RUNTIME=none); sandbox tasks are refused"
        )
    abi = system.landlock_abi()
    if abi is None or abi < MIN_LANDLOCK_ABI:
        detail = f"Landlock ABI {abi or 'unavailable'}; OpenShell needs ABI {MIN_LANDLOCK_ABI}"
        return CheckResult(name, REQUIRED, FAIL, detail)
    status = system.runtime_status(settings)
    if not status.healthy:
        hint = _RUNTIME_HINTS.get(status.detail, "see ADR-0016")
        return CheckResult(name, REQUIRED, FAIL, f"{status.detail}; {hint}")
    openshell = settings.openshell
    detail = (
        f"{status.version} via gateway {openshell.gateway}, workspace {openshell.workspace},"
        f" Landlock ABI {abi}"
    )
    return CheckResult(name, REQUIRED, PASS, detail)


def _first_line(text: str) -> str:
    return next((line.strip() for line in text.splitlines() if line.strip()), "no output")

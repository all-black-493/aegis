import json
from dataclasses import dataclass
from pathlib import Path

from aegis.db.migrate import head_revision
from aegis.doctor.model import FAIL, PASS, REQUIRED, SKIP, CheckResult
from aegis.doctor.system import System
from aegis.doctor.toolchain import Docker, first_line

POSTGRES_HOST = "127.0.0.1"
POSTGRES_SERVICE = "postgres"
SCHEMA_VERSION_QUERY = "SELECT version_num FROM aegis.alembic_version"


@dataclass(frozen=True)
class _Container:
    state: str
    health: str


@dataclass(frozen=True)
class PostgresState:
    blockers: tuple[str, ...]
    container: _Container | None = None
    error: str | None = None

    @property
    def known(self) -> bool:
        return not self.blockers and self.error is None


def check_postgres_port(system: System, port: int | None, postgres: PostgresState) -> CheckResult:
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
    system: System, port: int | None, postgres: PostgresState
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


def check_migrations(
    system: System,
    root: Path,
    docker: Docker,
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
            name, REQUIRED, FAIL, f"could not read the schema version: {first_line(result.stderr)}"
        )
    current = result.stdout.strip() if result.returncode == 0 else ""
    if not current:
        return CheckResult(name, REQUIRED, FAIL, "not applied; run `make migrate`")
    if current != head:
        return CheckResult(
            name, REQUIRED, FAIL, f"at revision {current}, latest is {head}; run `make migrate`"
        )
    return CheckResult(name, REQUIRED, PASS, f"at latest revision {head}")


def probe_postgres(
    system: System, root: Path, docker: Docker, blockers: tuple[str, ...]
) -> PostgresState:
    if blockers or docker.executable is None:
        return PostgresState(blockers)
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
        return PostgresState((), error=first_line(result.stderr))
    try:
        entries = _parse_compose_ps(result.stdout)
    except ValueError:
        return PostgresState((), error="unexpected `docker compose ps` output")
    for entry in entries:
        if entry.get("Service") == POSTGRES_SERVICE:
            container = _Container(str(entry.get("State", "")), str(entry.get("Health", "")))
            return PostgresState((), container)
    return PostgresState(())


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

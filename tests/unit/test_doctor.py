import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from aegis.config.settings import (
    ModelProviderKind,
    ModelSettings,
    RuntimeSettings,
    SandboxRuntimeKind,
)
from aegis.config.variables import TEMPLATE_NAMES
from aegis.db.migrate import head_revision
from aegis.doctor.__main__ import main
from aegis.doctor.checks import GIB, run_checks
from aegis.doctor.model import CheckResult, Diagnosis, Requirement, Status
from aegis.doctor.report import REDACTED, render
from aegis.doctor.system import CommandResult, Memory
from aegis.model_providers.contract import ModelIdentity, ProviderStatus
from aegis.runtime.contract import RuntimeStatus

PASSWORD = "0123456789abcdef0123456789abcdef"
MODEL_DIGEST = "7df6b6e09427a769808717c0a93cadc4ae99ed4eb8bf5ca557c90846becea435"
HEALTHY_MODEL = ProviderStatus(
    healthy=True,
    detail="ok",
    identity=ModelIdentity("ollama", "qwen3:0.6b", MODEL_DIGEST, "0.34.2"),
)
OLLAMA = {"AEGIS_MODEL_PROVIDER": "ollama", "AEGIS_OLLAMA_MODEL": "qwen3:0.6b"}
UV_VERSION = ("uv", "--version")
DOCKER_INFO = ("docker", "info", "--format", "{{json .}}")
COMPOSE_VERSION = ("docker", "compose", "version", "--short")
COMPOSE_PS = ("docker", "compose", "ps", "--all", "--format", "json", "postgres")
SCHEMA_VERSION = (
    "docker",
    "compose",
    "exec",
    "-T",
    "postgres",
    "psql",
    "-U",
    "aegis",
    "-d",
    "aegis",
    "-XAtq",
    "-c",
    "SELECT version_num FROM aegis.alembic_version",
)


def _ok(stdout: str) -> CommandResult:
    return CommandResult(0, stdout, "")


def _ps(state: str = "running", health: str = "healthy") -> CommandResult:
    return _ok(json.dumps({"Service": "postgres", "State": state, "Health": health}) + "\n")


def _default_commands() -> dict[tuple[str, ...], CommandResult]:
    return {
        UV_VERSION: _ok("uv 0.13.1\n"),
        DOCKER_INFO: _ok(
            json.dumps({"ServerVersion": "28.3.2", "DockerRootDir": "/var/lib/docker"})
        ),
        COMPOSE_VERSION: _ok("2.38.2\n"),
        COMPOSE_PS: _ps(),
        SCHEMA_VERSION: _ok(f"{head_revision()}\n"),
    }


@dataclass
class FakeSystem:
    prefix: Path
    version: tuple[int, int, int] = (3, 13, 14)
    programs: dict[str, str] = field(
        default_factory=lambda: {"uv": "/usr/bin/uv", "docker": "/usr/bin/docker"}
    )
    commands: dict[tuple[str, ...], CommandResult] = field(default_factory=_default_commands)
    free_bytes: int | None = 100 * GIB
    mem: Memory | None = field(default_factory=lambda: Memory(16 * GIB, 8 * GIB))
    port_free: bool = False
    accepts_connections: bool = True
    model: ProviderStatus = field(default_factory=lambda: HEALTHY_MODEL)
    model_settings: list[ModelSettings] = field(default_factory=list)
    runtime: RuntimeStatus = field(default_factory=lambda: RuntimeStatus(True, "ok", "0.1.6"))
    runtime_settings: list[RuntimeSettings] = field(default_factory=list)
    abi: int | None = 8

    def python_version(self) -> tuple[int, int, int]:
        return self.version

    def python_prefix(self) -> Path:
        return self.prefix

    def which(self, program: str) -> str | None:
        return self.programs.get(program)

    def run(self, argv: Sequence[str], cwd: Path) -> CommandResult:
        return self.commands[(Path(argv[0]).name, *argv[1:])]

    def disk_free_bytes(self, path: Path) -> int | None:
        return self.free_bytes

    def memory(self) -> Memory | None:
        return self.mem

    def can_bind(self, host: str, port: int) -> bool:
        return self.port_free

    def can_connect(self, host: str, port: int) -> bool:
        return self.accepts_connections

    def model_status(self, settings: ModelSettings) -> ProviderStatus:
        self.model_settings.append(settings)
        return self.model

    def runtime_status(self, settings: RuntimeSettings) -> RuntimeStatus:
        self.runtime_settings.append(settings)
        return self.runtime

    def landlock_abi(self) -> int | None:
        return self.abi


def write_env(root: Path, **overrides: str | None) -> None:
    values: dict[str, str | None] = {
        "AEGIS_ENV": "development",
        "AEGIS_POSTGRES_USER": "aegis",
        "AEGIS_POSTGRES_DB": "aegis",
        "AEGIS_POSTGRES_PASSWORD": PASSWORD,
        "AEGIS_POSTGRES_PORT": "5433",
        "AEGIS_DB_OWNER_PASSWORD": "owner-password-0123456789abcdef",
        "AEGIS_DB_APP_PASSWORD": "app-password-0123456789abcdef",
        "AEGIS_TOKEN_PEPPER": "token-pepper-0123456789abcdef0123456789",
        **overrides,
    }
    path = root / ".env"
    path.write_text("".join(f"{k}={v}\n" for k, v in values.items() if v is not None))
    path.chmod(0o600)


def result(diagnosis: Diagnosis, name: str) -> CheckResult:
    return next(r for r in diagnosis.results if r.name == name)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "docker-compose.yml").touch()
    (tmp_path / ".env.example").write_text("".join(f"{name}=x\n" for name in TEMPLATE_NAMES))
    write_env(tmp_path)
    return tmp_path


@pytest.fixture
def system(root: Path) -> FakeSystem:
    return FakeSystem(prefix=root / ".venv")


def test_healthy_environment_passes(system: FakeSystem, root: Path) -> None:
    diagnosis = run_checks(system, root)

    statuses = {r.name: r.status for r in diagnosis.results}
    # The sandbox runtime is disabled by default, which skips its check rather than passing it.
    assert statuses.pop("NVIDIA OpenShell") is Status.SKIP
    assert set(statuses.values()) == {Status.PASS}
    assert diagnosis.exit_code == 0
    assert "Result: OK" in render(diagnosis)


def test_missing_docker_cli_fails_and_blocks_dependent_checks(
    system: FakeSystem, root: Path
) -> None:
    del system.programs["docker"]

    diagnosis = run_checks(system, root)

    assert result(diagnosis, "Docker Engine").status is Status.FAIL
    assert result(diagnosis, "Docker Compose v2").status is Status.SKIP
    service = result(diagnosis, "PostgreSQL service")
    assert service.status is Status.SKIP
    assert "Docker Engine" in service.detail
    assert diagnosis.exit_code == 1
    assert "Result: FAILED" in render(diagnosis)


@pytest.mark.parametrize(
    ("stderr", "hint"),
    [
        (
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock.",
            "not reachable",
        ),
        (
            "permission denied while trying to connect to the Docker daemon socket",
            "docker group",
        ),
    ],
)
def test_unreachable_docker_daemon_fails(
    system: FakeSystem, root: Path, stderr: str, hint: str
) -> None:
    system.commands[DOCKER_INFO] = CommandResult(1, json.dumps({"ServerVersion": ""}), stderr)

    diagnosis = run_checks(system, root)

    engine = result(diagnosis, "Docker Engine")
    assert engine.status is Status.FAIL
    assert hint in engine.detail
    assert result(diagnosis, "PostgreSQL service").status is Status.SKIP
    assert diagnosis.exit_code == 1


def test_compose_v1_fails(system: FakeSystem, root: Path) -> None:
    system.commands[COMPOSE_VERSION] = _ok("1.29.2\n")

    diagnosis = run_checks(system, root)

    assert result(diagnosis, "Docker Compose v2").status is Status.FAIL
    assert diagnosis.exit_code == 1


def test_missing_compose_plugin_fails(system: FakeSystem, root: Path) -> None:
    system.commands[COMPOSE_VERSION] = CommandResult(1, "", "'compose' is not a docker command.")

    diagnosis = run_checks(system, root)

    assert result(diagnosis, "Docker Compose v2").status is Status.FAIL
    assert diagnosis.exit_code == 1


def test_missing_uv_fails(system: FakeSystem, root: Path) -> None:
    del system.programs["uv"]

    diagnosis = run_checks(system, root)

    assert result(diagnosis, "uv").status is Status.FAIL
    assert diagnosis.exit_code == 1


def test_wrong_python_version_fails(system: FakeSystem, root: Path) -> None:
    system.version = (3, 12, 8)

    diagnosis = run_checks(system, root)

    assert result(diagnosis, "Python 3.13").status is Status.FAIL
    assert diagnosis.exit_code == 1


def test_foreign_interpreter_warns_without_failing(system: FakeSystem, root: Path) -> None:
    system.prefix = Path("/home/someone/.virtualenvs/unrelated")

    diagnosis = run_checks(system, root)

    environment = result(diagnosis, "Project environment")
    assert environment.requirement is Requirement.OPTIONAL
    assert environment.status is Status.WARN
    assert diagnosis.exit_code == 0


def test_missing_env_file_fails_and_blocks_postgres_checks(system: FakeSystem, root: Path) -> None:
    (root / ".env").unlink()

    diagnosis = run_checks(system, root)

    env = result(diagnosis, ".env configuration")
    assert env.status is Status.FAIL
    assert "make setup" in env.detail
    assert result(diagnosis, "PostgreSQL host port").status is Status.SKIP
    assert result(diagnosis, "PostgreSQL service").status is Status.SKIP
    assert diagnosis.exit_code == 1


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"AEGIS_POSTGRES_USER": None}, "missing or empty: AEGIS_POSTGRES_USER"),
        ({"AEGIS_POSTGRES_PASSWORD": ""}, "missing or empty: AEGIS_POSTGRES_PASSWORD"),
        ({"AEGIS_POSTGRES_PASSWORD": "__GENERATED_BY_MAKE_SETUP__"}, "placeholder"),
        ({"AEGIS_POSTGRES_PASSWORD": "short"}, "shorter than 16"),
        ({"AEGIS_POSTGRES_PORT": "abc"}, "from 1024 to 65535"),
        ({"AEGIS_POSTGRES_PORT": "80"}, "from 1024 to 65535"),
        ({"AEGIS_POSTGRES_PORT": "70000"}, "from 1024 to 65535"),
        ({"AEGIS_POSTGRES_PORT": "²"}, "from 1024 to 65535"),
        ({"AEGIS_ENV": "staging"}, "AEGIS_ENV must be one of"),
        ({"AEGIS_ENV": "production", "AEGIS_LOG_LEVEL": "DEBUG"}, "not allowed in production"),
        ({"AEGIS_TYPO": "1"}, "AEGIS_TYPO is not a known AEGIS variable"),
        ({"AEGIS_TOKEN_PEPPER": None}, "missing or empty: AEGIS_TOKEN_PEPPER"),
        ({"AEGIS_TOKEN_PEPPER": "pepper-0123456789abcdef"}, "at least 32 characters"),
        ({"AEGIS_API_PORT": "80"}, "AEGIS_API_PORT must be an integer"),
        ({"AEGIS_WORKER_LEASE_SECONDS": "5"}, "AEGIS_WORKER_LEASE_SECONDS must be an integer"),
        ({"AEGIS_WORKER_MAX_ATTEMPTS": "11"}, "AEGIS_WORKER_MAX_ATTEMPTS must be an integer"),
        ({"AEGIS_MODEL_PROVIDER": "ollama"}, "AEGIS_OLLAMA_MODEL is required"),
        ({"AEGIS_OLLAMA_MODEL": "hf.co/user/model"}, "must be a local model name"),
        ({"AEGIS_OLLAMA_HOST": "10.0.0.5"}, "AEGIS_OLLAMA_HOST is not a known AEGIS variable"),
        (
            {"AEGIS_WORKER_LEASE_SECONDS": "30", "AEGIS_WORKER_HEARTBEAT_SECONDS": "20"},
            "at most a third of the lease",
        ),
    ],
)
def test_invalid_env_configuration_fails(
    system: FakeSystem, root: Path, overrides: dict[str, str | None], message: str
) -> None:
    write_env(root, **overrides)

    diagnosis = run_checks(system, root)

    env = result(diagnosis, ".env configuration")
    assert env.status is Status.FAIL
    assert message in env.detail
    assert diagnosis.exit_code == 1


def test_unparseable_env_file_does_not_leak_its_contents(system: FakeSystem, root: Path) -> None:
    (root / ".env").write_text("AEGIS_POSTGRES_PASSWORD=leaky secret value\n")

    diagnosis = run_checks(system, root)

    assert result(diagnosis, ".env configuration").status is Status.FAIL
    assert "leaky secret value" not in render(diagnosis)


def test_env_missing_template_variables_warns_without_failing(
    system: FakeSystem, root: Path
) -> None:
    write_env(root, AEGIS_ENV=None)

    diagnosis = run_checks(system, root)

    assert result(diagnosis, ".env configuration").status is Status.PASS
    up_to_date = result(diagnosis, ".env up to date")
    assert up_to_date.requirement is Requirement.OPTIONAL
    assert up_to_date.status is Status.WARN
    assert "AEGIS_ENV" in up_to_date.detail
    assert "make env-upgrade" in up_to_date.detail
    assert diagnosis.exit_code == 0


def test_env_template_check_is_skipped_without_a_template(system: FakeSystem, root: Path) -> None:
    (root / ".env.example").unlink()

    diagnosis = run_checks(system, root)

    assert result(diagnosis, ".env up to date").status is Status.SKIP
    assert diagnosis.exit_code == 0


def test_world_readable_env_warns_without_failing(system: FakeSystem, root: Path) -> None:
    (root / ".env").chmod(0o644)

    diagnosis = run_checks(system, root)

    permissions = result(diagnosis, ".env permissions")
    assert permissions.requirement is Requirement.OPTIONAL
    assert permissions.status is Status.WARN
    assert diagnosis.exit_code == 0


def test_port_used_by_another_process_fails(system: FakeSystem, root: Path) -> None:
    system.commands[COMPOSE_PS] = _ok("")
    system.port_free = False

    diagnosis = run_checks(system, root)

    port = result(diagnosis, "PostgreSQL host port")
    assert port.status is Status.FAIL
    assert "another process" in port.detail
    assert diagnosis.exit_code == 1


def test_postgres_not_started_fails_with_hint(system: FakeSystem, root: Path) -> None:
    system.commands[COMPOSE_PS] = _ok("")
    system.port_free = True

    diagnosis = run_checks(system, root)

    assert result(diagnosis, "PostgreSQL host port").status is Status.PASS
    service = result(diagnosis, "PostgreSQL service")
    assert service.status is Status.FAIL
    assert "make up" in service.detail
    assert diagnosis.exit_code == 1


@pytest.mark.parametrize(
    ("state", "health", "message"),
    [
        ("exited", "", "container is exited"),
        ("running", "starting", "health is starting"),
        ("running", "unhealthy", "health is unhealthy"),
    ],
)
def test_unhealthy_postgres_fails(
    system: FakeSystem, root: Path, state: str, health: str, message: str
) -> None:
    system.commands[COMPOSE_PS] = _ps(state, health)

    diagnosis = run_checks(system, root)

    service = result(diagnosis, "PostgreSQL service")
    assert service.status is Status.FAIL
    assert message in service.detail
    assert diagnosis.exit_code == 1


def test_postgres_not_accepting_connections_fails(system: FakeSystem, root: Path) -> None:
    system.accepts_connections = False

    diagnosis = run_checks(system, root)

    assert result(diagnosis, "PostgreSQL service").status is Status.FAIL
    assert diagnosis.exit_code == 1


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (CommandResult(1, "", 'ERROR:  schema "aegis" does not exist'), "run `make migrate`"),
        (CommandResult(1, "", 'ERROR:  relation "x" does not exist'), "run `make migrate`"),
        (_ok(""), "not applied"),
        (_ok("0000\n"), f"at revision 0000, latest is {head_revision()}"),
        (CommandResult(2, "", "psql: error: connection refused"), "could not read"),
    ],
)
def test_pending_or_unreadable_migrations_fail(
    system: FakeSystem, root: Path, response: CommandResult, message: str
) -> None:
    system.commands[SCHEMA_VERSION] = response

    diagnosis = run_checks(system, root)

    migrations = result(diagnosis, "Database migrations")
    assert migrations.status is Status.FAIL
    assert message in migrations.detail
    assert diagnosis.exit_code == 1


def test_migration_check_is_blocked_when_postgres_is_unhealthy(
    system: FakeSystem, root: Path
) -> None:
    system.commands[COMPOSE_PS] = _ps("running", "starting")

    diagnosis = run_checks(system, root)

    assert result(diagnosis, "Database migrations").status is Status.SKIP
    assert diagnosis.exit_code == 1


def test_compose_query_failure_fails_postgres_service(system: FakeSystem, root: Path) -> None:
    system.commands[COMPOSE_PS] = CommandResult(1, "", "compose exploded")

    diagnosis = run_checks(system, root)

    service = result(diagnosis, "PostgreSQL service")
    assert service.status is Status.FAIL
    assert "compose exploded" in service.detail


def test_legacy_compose_ps_array_output_is_supported(system: FakeSystem, root: Path) -> None:
    system.commands[COMPOSE_PS] = _ok(
        json.dumps([{"Service": "postgres", "State": "running", "Health": "healthy"}])
    )

    diagnosis = run_checks(system, root)

    assert result(diagnosis, "PostgreSQL service").status is Status.PASS


def test_low_disk_space_fails(system: FakeSystem, root: Path) -> None:
    system.free_bytes = 1 * GIB

    diagnosis = run_checks(system, root)

    assert result(diagnosis, "Disk space").status is Status.FAIL
    assert diagnosis.exit_code == 1


def test_unknown_disk_space_warns(system: FakeSystem, root: Path) -> None:
    system.free_bytes = None

    assert result(run_checks(system, root), "Disk space").status is Status.WARN


@pytest.mark.parametrize(
    ("memory", "status"),
    [
        (Memory(16 * GIB, GIB // 2), Status.WARN),
        (Memory(1 * GIB, GIB // 2), Status.FAIL),
        (None, Status.FAIL),
    ],
)
def test_memory_thresholds(
    system: FakeSystem, root: Path, memory: Memory | None, status: Status
) -> None:
    system.mem = memory

    assert result(run_checks(system, root), "Memory").status is status


def test_secrets_are_redacted_from_report(system: FakeSystem, root: Path) -> None:
    system.commands[COMPOSE_PS] = CommandResult(1, "", f"auth failed for password {PASSWORD}")

    output = render(run_checks(system, root))

    assert PASSWORD not in output
    assert REDACTED in output


def test_unimplemented_integrations_are_listed_but_not_checked(
    system: FakeSystem, root: Path
) -> None:
    diagnosis = run_checks(system, root)
    output = render(diagnosis)

    assert "Langfuse and OpenTelemetry  Phase 8" in output
    assert "[----] NVIDIA OpenShell" not in output
    for name in ("Ollama", "Langfuse"):
        assert not any(name.lower() in r.name.lower() for r in diagnosis.results)
    assert diagnosis.exit_code == 0


@pytest.mark.parametrize(
    ("requirement", "status", "exit_code"),
    [
        (Requirement.REQUIRED, Status.FAIL, 1),
        (Requirement.REQUIRED, Status.SKIP, 1),
        (Requirement.REQUIRED, Status.WARN, 0),
        (Requirement.OPTIONAL, Status.FAIL, 0),
        (Requirement.OPTIONAL, Status.SKIP, 0),
    ],
)
def test_exit_code_reflects_required_checks_only(
    requirement: Requirement, status: Status, exit_code: int
) -> None:
    diagnosis = Diagnosis((CheckResult("check", requirement, status, ""),), frozenset())

    assert diagnosis.exit_code == exit_code


def test_main_refuses_to_run_outside_repository_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)

    assert main() == 2
    assert "repository root" in capsys.readouterr().err


def test_the_mock_provider_needs_no_model_server(system: FakeSystem, root: Path) -> None:
    check = result(run_checks(system, root), "Model provider")

    assert (check.requirement, check.status) == (Requirement.OPTIONAL, Status.PASS)
    assert "mock" in check.detail
    assert system.model_settings == []


def test_a_configured_ollama_model_is_required_and_identified(
    system: FakeSystem, root: Path
) -> None:
    write_env(root, **OLLAMA)

    diagnosis = run_checks(system, root)

    check = result(diagnosis, "Model provider")
    assert (check.requirement, check.status) == (Requirement.REQUIRED, Status.PASS)
    assert check.detail == "qwen3:0.6b (7df6b6e09427) on Ollama 0.34.2"
    [settings] = system.model_settings
    assert settings.provider is ModelProviderKind.OLLAMA
    assert diagnosis.exit_code == 0


@pytest.mark.parametrize(
    ("detail", "hint"),
    [
        ("unreachable", "make up-local-ai"),
        ("model_missing", "make model-pull"),
        ("digest_mismatch", "AEGIS_OLLAMA_MODEL_DIGEST"),
        ("remote_model", "remote-backed models are refused"),
        ("not_generative", "cannot generate text"),
        ("protocol_error", "ADR-0014"),
    ],
)
def test_an_unusable_ollama_model_fails_with_a_hint(
    system: FakeSystem, root: Path, detail: str, hint: str
) -> None:
    write_env(root, **OLLAMA)
    system.model = ProviderStatus(healthy=False, detail=detail)

    diagnosis = run_checks(system, root)

    check = result(diagnosis, "Model provider")
    assert (check.status, diagnosis.exit_code) == (Status.FAIL, 1)
    assert detail in check.detail
    assert hint in check.detail


def test_an_unverified_ollama_version_warns(system: FakeSystem, root: Path) -> None:
    write_env(root, **OLLAMA)
    system.model = ProviderStatus(
        healthy=True,
        detail="ok",
        identity=ModelIdentity("ollama", "qwen3:0.6b", MODEL_DIGEST, "0.40.0"),
    )

    check = result(run_checks(system, root), "Model provider")

    assert check.status is Status.WARN
    assert "verified with 0.34.2" in check.detail


def test_the_model_check_waits_for_a_valid_env_file(system: FakeSystem, root: Path) -> None:
    write_env(root, AEGIS_MODEL_PROVIDER="ollama")

    check = result(run_checks(system, root), "Model provider")

    assert (check.status, check.detail) == (Status.SKIP, "blocked by: .env configuration")
    assert system.model_settings == []


OPENSHELL = {"AEGIS_SANDBOX_RUNTIME": "openshell"}


def test_a_disabled_runtime_is_skipped_and_refuses_sandbox_tasks(
    system: FakeSystem, root: Path
) -> None:
    check = result(run_checks(system, root), "NVIDIA OpenShell")

    assert (check.requirement, check.status) == (Requirement.OPTIONAL, Status.SKIP)
    assert "sandbox tasks are refused" in check.detail
    assert system.runtime_settings == []


def test_a_configured_openshell_is_required_and_identified(system: FakeSystem, root: Path) -> None:
    write_env(root, **OPENSHELL)

    diagnosis = run_checks(system, root)

    check = result(diagnosis, "NVIDIA OpenShell")
    assert (check.requirement, check.status) == (Requirement.REQUIRED, Status.PASS)
    assert check.detail == "0.1.6 via gateway openshell, workspace aegis, Landlock ABI 8"
    [settings] = system.runtime_settings
    assert settings.runtime is SandboxRuntimeKind.OPENSHELL
    assert diagnosis.exit_code == 0


@pytest.mark.parametrize(
    ("detail", "hint"),
    [
        ("cli_missing", "install the OpenShell 0.1.6 package"),
        ("version_mismatch", "ADR-0016"),
        ("unreachable", "systemctl --user start openshell-gateway"),
        ("not_connected", "AEGIS_OPENSHELL_GATEWAY"),
        ("workspace_missing", "make openshell-init"),
        ("global_policy_active", "replace AEGIS's sandbox policies"),
        ("protocol_error", "ADR-0016"),
    ],
)
def test_an_unusable_openshell_fails_with_a_hint(
    system: FakeSystem, root: Path, detail: str, hint: str
) -> None:
    write_env(root, **OPENSHELL)
    system.runtime = RuntimeStatus(False, detail)

    diagnosis = run_checks(system, root)

    check = result(diagnosis, "NVIDIA OpenShell")
    assert (check.status, diagnosis.exit_code) == (Status.FAIL, 1)
    assert detail in check.detail
    assert hint in check.detail


@pytest.mark.parametrize("abi", [None, 2])
def test_openshell_needs_landlock_abi_3(system: FakeSystem, root: Path, abi: int | None) -> None:
    write_env(root, **OPENSHELL)
    system.abi = abi

    check = result(run_checks(system, root), "NVIDIA OpenShell")

    assert (check.requirement, check.status) == (Requirement.REQUIRED, Status.FAIL)
    assert "needs ABI 3" in check.detail
    assert system.runtime_settings == []


def test_an_invalid_runtime_setting_fails_the_env_check(system: FakeSystem, root: Path) -> None:
    write_env(root, AEGIS_SANDBOX_RUNTIME="docker")

    diagnosis = run_checks(system, root)

    assert result(diagnosis, ".env configuration").status is Status.FAIL
    assert result(diagnosis, "NVIDIA OpenShell").status is Status.SKIP

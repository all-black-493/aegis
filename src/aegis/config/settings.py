import re
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from enum import StrEnum

from aegis.config.envfile import PLACEHOLDER
from aegis.config.variables import BY_NAME, PREFIX, SECRET_NAMES

OWNER_ROLE = "aegis_owner"
APP_ROLE = "aegis_app"
DATABASE_HOST = "127.0.0.1"
API_HOST = "127.0.0.1"
DEFAULT_API_PORT = 8000
# The model server is always local; no setting can point AEGIS at another host.
MODEL_HOST = "127.0.0.1"
DEFAULT_OLLAMA_PORT = 11436
DEFAULT_MODEL_TIMEOUT_SECONDS = 120
# Mirrors aegis.policy.rules.MAX_JOB_ATTEMPTS, which configuration may not import; a test keeps
# them equal, and the worker re-checks at startup.
MAX_WORKER_ATTEMPTS = 10
MIN_SECRET_LENGTH = 16
MIN_PEPPER_LENGTH = 32
# A local name or namespace/name with an optional tag; no registry host, so a pull cannot be
# redirected to another registry through this setting.
_OLLAMA_MODEL = re.compile(
    r"(?:[A-Za-z0-9][A-Za-z0-9_-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*(?::[A-Za-z0-9][A-Za-z0-9._-]*)?"
)
_DIGEST = re.compile(r"[0-9a-f]{64}")


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class SettingsError(ValueError):
    def __init__(self, problems: list[str]) -> None:
        self.problems = tuple(problems)
        super().__init__("invalid configuration: " + "; ".join(self.problems))


class DatabaseRole(StrEnum):
    ADMIN = "admin"
    OWNER = "owner"
    APP = "app"


@dataclass(frozen=True, repr=False)
class Secret:
    _value: str

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret('[REDACTED]')"

    __str__ = __repr__


@dataclass(frozen=True)
class CommonSettings:
    environment: Environment
    log_level: LogLevel


@dataclass(frozen=True)
class DatabaseSettings:
    host: str
    port: int
    name: str
    user: str
    password: Secret


@dataclass(frozen=True)
class ApiSettings:
    port: int


class ModelProviderKind(StrEnum):
    MOCK = "mock"
    OLLAMA = "ollama"


@dataclass(frozen=True)
class OllamaSettings:
    port: int
    model: str
    digest: str | None


@dataclass(frozen=True)
class ModelSettings:
    provider: ModelProviderKind = ModelProviderKind.MOCK
    timeout_seconds: float = DEFAULT_MODEL_TIMEOUT_SECONDS
    ollama: OllamaSettings | None = None


@dataclass(frozen=True)
class WorkerSettings:
    poll_seconds: float = 1
    lease_seconds: float = 30
    heartbeat_seconds: float = 5
    shutdown_grace_seconds: float = 10
    max_attempts: int = 3


def load_database_settings(environ: Mapping[str, str], role: DatabaseRole) -> DatabaseSettings:
    problems = unknown_variables(environ)
    name = _required(environ, "AEGIS_POSTGRES_DB", problems)
    port = _port(environ, "AEGIS_POSTGRES_PORT", problems)
    match role:
        case DatabaseRole.ADMIN:
            user = _required(environ, "AEGIS_POSTGRES_USER", problems)
            password = _secret(environ, "AEGIS_POSTGRES_PASSWORD", problems)
        case DatabaseRole.OWNER:
            user = OWNER_ROLE
            password = _secret(environ, "AEGIS_DB_OWNER_PASSWORD", problems)
        case DatabaseRole.APP:
            user = APP_ROLE
            password = _secret(environ, "AEGIS_DB_APP_PASSWORD", problems)
    if problems:
        raise SettingsError(problems)
    return DatabaseSettings(DATABASE_HOST, port, name, user, Secret(password))


def load_common_settings(environ: Mapping[str, str]) -> CommonSettings:
    problems = unknown_variables(environ)
    environment = _choice(environ, "AEGIS_ENV", Environment, Environment.PRODUCTION, problems)
    log_level = _choice(environ, "AEGIS_LOG_LEVEL", LogLevel, LogLevel.INFO, problems)
    if environment is Environment.PRODUCTION and log_level is LogLevel.DEBUG:
        problems.append("AEGIS_LOG_LEVEL=DEBUG is not allowed in production")
    if problems:
        raise SettingsError(problems)
    return CommonSettings(environment=environment, log_level=log_level)


def load_api_settings(environ: Mapping[str, str]) -> ApiSettings:
    problems = unknown_variables(environ)
    port = DEFAULT_API_PORT
    if environ.get("AEGIS_API_PORT", "").strip():
        port = _port(environ, "AEGIS_API_PORT", problems)
    if problems:
        raise SettingsError(problems)
    return ApiSettings(port)


def load_worker_settings(environ: Mapping[str, str]) -> WorkerSettings:
    problems = unknown_variables(environ)
    defaults = WorkerSettings()
    poll = _bounded(environ, "AEGIS_WORKER_POLL_SECONDS", 1, 60, defaults.poll_seconds, problems)
    lease = _bounded(
        environ, "AEGIS_WORKER_LEASE_SECONDS", 10, 600, defaults.lease_seconds, problems
    )
    heartbeat = _bounded(
        environ, "AEGIS_WORKER_HEARTBEAT_SECONDS", 1, 200, defaults.heartbeat_seconds, problems
    )
    grace = _bounded(
        environ,
        "AEGIS_WORKER_SHUTDOWN_GRACE_SECONDS",
        0,
        300,
        defaults.shutdown_grace_seconds,
        problems,
    )
    attempts = _bounded(
        environ,
        "AEGIS_WORKER_MAX_ATTEMPTS",
        1,
        MAX_WORKER_ATTEMPTS,
        defaults.max_attempts,
        problems,
    )
    if heartbeat * 3 > lease:
        problems.append("AEGIS_WORKER_HEARTBEAT_SECONDS must be at most a third of the lease")
    if problems:
        raise SettingsError(problems)
    return WorkerSettings(poll, lease, heartbeat, grace, int(attempts))


def load_model_settings(environ: Mapping[str, str]) -> ModelSettings:
    problems = unknown_variables(environ)
    provider = _choice(
        environ, "AEGIS_MODEL_PROVIDER", ModelProviderKind, ModelProviderKind.MOCK, problems
    )
    timeout = _bounded(
        environ, "AEGIS_MODEL_TIMEOUT_SECONDS", 5, 600, DEFAULT_MODEL_TIMEOUT_SECONDS, problems
    )
    port = DEFAULT_OLLAMA_PORT
    if environ.get("AEGIS_OLLAMA_PORT", "").strip():
        port = _port(environ, "AEGIS_OLLAMA_PORT", problems)
    model = environ.get("AEGIS_OLLAMA_MODEL", "").strip()
    if model and (len(model) > 128 or not _OLLAMA_MODEL.fullmatch(model)):
        problems.append("AEGIS_OLLAMA_MODEL must be a local model name such as qwen3:0.6b")
    digest = environ.get("AEGIS_OLLAMA_MODEL_DIGEST", "").strip() or None
    if digest is not None and not _DIGEST.fullmatch(digest):
        problems.append("AEGIS_OLLAMA_MODEL_DIGEST must be 64 lowercase hex characters")
    if provider is ModelProviderKind.OLLAMA and not model:
        problems.append("AEGIS_OLLAMA_MODEL is required when AEGIS_MODEL_PROVIDER is ollama")
    if problems:
        raise SettingsError(problems)
    ollama = None
    if provider is ModelProviderKind.OLLAMA:
        ollama = OllamaSettings(port, model, digest)
    return ModelSettings(provider, timeout, ollama)


def load_token_pepper(environ: Mapping[str, str]) -> Secret:
    problems = unknown_variables(environ)
    pepper = _secret(environ, "AEGIS_TOKEN_PEPPER", problems, MIN_PEPPER_LENGTH)
    if problems:
        raise SettingsError(problems)
    return Secret(pepper)


def forget_secrets(environ: MutableMapping[str, str]) -> None:
    # Entry points call this once their settings are loaded, so later lookups and child processes
    # find no credential. /proc/self/environ still holds the process's initial environment.
    for name in SECRET_NAMES:
        environ.pop(name, None)


def unknown_variables(environ: Mapping[str, str]) -> list[str]:
    return [
        f"{name} is not a known AEGIS variable"
        for name in sorted(environ)
        if name.startswith(PREFIX) and name not in BY_NAME
    ]


def _required(environ: Mapping[str, str], name: str, problems: list[str]) -> str:
    value = environ.get(name, "").strip()
    if not value:
        problems.append(f"{name} is required")
    return value


def _port(environ: Mapping[str, str], name: str, problems: list[str]) -> int:
    raw = environ.get(name, "").strip()
    if raw.isascii() and raw.isdigit() and 1024 <= int(raw) <= 65535:
        return int(raw)
    problems.append(f"{name} must be an integer from 1024 to 65535")
    return 0


def _bounded(
    environ: Mapping[str, str],
    name: str,
    low: int,
    high: int,
    default: float,
    problems: list[str],
) -> float:
    raw = environ.get(name, "").strip()
    if not raw:
        return default
    if raw.isascii() and raw.isdigit() and low <= int(raw) <= high:
        return int(raw)
    problems.append(f"{name} must be an integer from {low} to {high}")
    return default


def _secret(
    environ: Mapping[str, str],
    name: str,
    problems: list[str],
    min_length: int = MIN_SECRET_LENGTH,
) -> str:
    value = environ.get(name, "")
    if not value:
        problems.append(f"{name} is required; run `make env-upgrade`")
    elif value == PLACEHOLDER:
        problems.append(f"{name} is still the placeholder")
    elif len(value) < min_length:
        problems.append(f"{name} must be at least {min_length} characters")
    return value


def _choice[E: StrEnum](
    environ: Mapping[str, str], name: str, kind: type[E], default: E, problems: list[str]
) -> E:
    raw = environ.get(name)
    if raw is None:
        return default
    for member in kind:
        if raw.strip().casefold() == member.value.casefold():
            return member
    allowed = ", ".join(member.value for member in kind)
    problems.append(f"{name} must be one of: {allowed}")
    return default

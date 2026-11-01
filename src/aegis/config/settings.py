from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from aegis.config.envfile import PLACEHOLDER
from aegis.config.variables import BY_NAME, PREFIX

OWNER_ROLE = "aegis_owner"
APP_ROLE = "aegis_app"
DATABASE_HOST = "127.0.0.1"
MIN_SECRET_LENGTH = 16


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


def _secret(environ: Mapping[str, str], name: str, problems: list[str]) -> str:
    value = environ.get(name, "")
    if not value:
        problems.append(f"{name} is required; run `make env-upgrade`")
    elif value == PLACEHOLDER:
        problems.append(f"{name} is still the placeholder")
    elif len(value) < MIN_SECRET_LENGTH:
        problems.append(f"{name} must be at least {MIN_SECRET_LENGTH} characters")
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

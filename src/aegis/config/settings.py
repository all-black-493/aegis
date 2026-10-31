from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from aegis.config.variables import BY_NAME, PREFIX


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


@dataclass(frozen=True)
class CommonSettings:
    environment: Environment
    log_level: LogLevel


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

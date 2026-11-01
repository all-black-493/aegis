import dataclasses

import pytest

from aegis.config.envfile import PLACEHOLDER
from aegis.config.settings import (
    CommonSettings,
    DatabaseRole,
    Environment,
    LogLevel,
    SettingsError,
    load_common_settings,
    load_database_settings,
    unknown_variables,
)
from aegis.config.variables import VARIABLES

CANARY = "canary-value-0123456789abcdef"


def test_unset_variables_give_secure_defaults() -> None:
    assert load_common_settings({}) == CommonSettings(Environment.PRODUCTION, LogLevel.INFO)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("development", Environment.DEVELOPMENT),
        ("TEST", Environment.TEST),
        (" production ", Environment.PRODUCTION),
    ],
)
def test_environment_is_parsed(raw: str, expected: Environment) -> None:
    assert load_common_settings({"AEGIS_ENV": raw}).environment is expected


def test_log_level_is_case_insensitive() -> None:
    assert load_common_settings({"AEGIS_LOG_LEVEL": "warning"}).log_level is LogLevel.WARNING


@pytest.mark.parametrize("name", ["AEGIS_ENV", "AEGIS_LOG_LEVEL"])
@pytest.mark.parametrize("value", [CANARY, ""])
def test_invalid_values_are_rejected_without_echoing_them(name: str, value: str) -> None:
    with pytest.raises(SettingsError) as excinfo:
        load_common_settings({name: value})

    assert name in str(excinfo.value)
    if value:
        assert value not in str(excinfo.value)


def test_debug_logging_is_refused_in_production() -> None:
    with pytest.raises(SettingsError, match="DEBUG is not allowed in production"):
        load_common_settings({"AEGIS_LOG_LEVEL": "DEBUG"})


def test_debug_logging_is_allowed_in_development() -> None:
    settings = load_common_settings({"AEGIS_ENV": "development", "AEGIS_LOG_LEVEL": "DEBUG"})

    assert settings.log_level is LogLevel.DEBUG


def test_unknown_aegis_variables_are_rejected_by_name_only() -> None:
    with pytest.raises(SettingsError) as excinfo:
        load_common_settings({"AEGIS_ENVV": CANARY})

    assert "AEGIS_ENVV" in str(excinfo.value)
    assert CANARY not in str(excinfo.value)


def test_every_problem_is_reported_at_once() -> None:
    with pytest.raises(SettingsError) as excinfo:
        load_common_settings({"AEGIS_ENV": "x", "AEGIS_LOG_LEVEL": "y", "AEGIS_TYPO": "z"})

    assert len(excinfo.value.problems) == 3


def test_variables_without_the_aegis_prefix_are_ignored() -> None:
    assert load_common_settings({"PATH": "/usr/bin", "COMPOSE_PROJECT_NAME": "x"}).environment


def test_every_registered_variable_is_known() -> None:
    assert unknown_variables({variable.name: "" for variable in VARIABLES}) == []


def test_settings_are_immutable() -> None:
    settings = load_common_settings({})

    with pytest.raises(dataclasses.FrozenInstanceError):
        settings.environment = Environment.DEVELOPMENT  # type: ignore[misc]


DATABASE_ENV = {
    "AEGIS_POSTGRES_DB": "aegis",
    "AEGIS_POSTGRES_PORT": "5433",
    "AEGIS_POSTGRES_USER": "aegis",
    "AEGIS_POSTGRES_PASSWORD": "a" * 24,
    "AEGIS_DB_OWNER_PASSWORD": "b" * 24,
    "AEGIS_DB_APP_PASSWORD": "c" * 24,
}


@pytest.mark.parametrize(
    ("role", "user", "password"),
    [
        (DatabaseRole.ADMIN, "aegis", "a" * 24),
        (DatabaseRole.OWNER, "aegis_owner", "b" * 24),
        (DatabaseRole.APP, "aegis_app", "c" * 24),
    ],
)
def test_each_database_role_loads_its_own_credentials(
    role: DatabaseRole, user: str, password: str
) -> None:
    settings = load_database_settings(DATABASE_ENV, role)

    assert (settings.host, settings.port, settings.name) == ("127.0.0.1", 5433, "aegis")
    assert settings.user == user
    assert settings.password.reveal() == password


@pytest.mark.parametrize(
    ("role", "password_name"),
    [(DatabaseRole.APP, "AEGIS_DB_APP_PASSWORD"), (DatabaseRole.OWNER, "AEGIS_DB_OWNER_PASSWORD")],
)
def test_runtime_roles_need_no_other_credentials(role: DatabaseRole, password_name: str) -> None:
    environ = {
        "AEGIS_POSTGRES_DB": "aegis",
        "AEGIS_POSTGRES_PORT": "5433",
        password_name: DATABASE_ENV[password_name],
    }

    assert load_database_settings(environ, role).password.reveal() == DATABASE_ENV[password_name]


@pytest.mark.parametrize(
    ("value", "message"),
    [(None, "is required"), ("", "is required"), (PLACEHOLDER, "placeholder"), ("short", "16")],
)
def test_invalid_role_passwords_are_rejected_without_echoing_them(
    value: str | None, message: str
) -> None:
    environ = dict(DATABASE_ENV)
    environ.pop("AEGIS_DB_APP_PASSWORD")
    if value is not None:
        environ["AEGIS_DB_APP_PASSWORD"] = value

    with pytest.raises(SettingsError, match=message) as excinfo:
        load_database_settings(environ, DatabaseRole.APP)

    assert "AEGIS_DB_APP_PASSWORD" in str(excinfo.value)
    if value:
        assert value not in str(excinfo.value).replace("AEGIS_DB_APP_PASSWORD", "")


@pytest.mark.parametrize("port", ["", "80", "70000", "²"])
def test_invalid_database_port_is_rejected(port: str) -> None:
    with pytest.raises(SettingsError, match="AEGIS_POSTGRES_PORT"):
        load_database_settings({**DATABASE_ENV, "AEGIS_POSTGRES_PORT": port}, DatabaseRole.APP)


def test_secrets_never_appear_in_representations() -> None:
    settings = load_database_settings(DATABASE_ENV, DatabaseRole.APP)
    password = "c" * 24

    for text in (repr(settings), str(settings), repr(settings.password), f"{settings.password}"):
        assert password not in text
    assert "[REDACTED]" in repr(settings)

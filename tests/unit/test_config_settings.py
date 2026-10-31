import dataclasses

import pytest

from aegis.config.settings import (
    CommonSettings,
    Environment,
    LogLevel,
    SettingsError,
    load_common_settings,
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

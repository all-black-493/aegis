import os
from collections.abc import Iterator
from dataclasses import replace

import pytest
from sqlalchemy import Engine

from aegis.config.settings import (
    DatabaseRole,
    DatabaseSettings,
    SettingsError,
    load_database_settings,
)
from aegis.db.admin import bootstrap, recreate_test_database
from aegis.db.engine import create_database_engine
from aegis.db.migrate import upgrade


def _settings(role: DatabaseRole) -> DatabaseSettings:
    try:
        return load_database_settings(os.environ, role)
    except SettingsError as error:
        pytest.fail(f"{error}; run integration tests with `make test-integration`")


@pytest.fixture(scope="session")
def test_database() -> str:
    admin = _settings(DatabaseRole.ADMIN)
    name = f"{admin.name}_test"
    recreate_test_database(admin, name)
    owner, app = _settings(DatabaseRole.OWNER), _settings(DatabaseRole.APP)
    bootstrap(admin, name, owner.password, app.password)
    engine = create_database_engine(replace(owner, name=name), application_name="aegis-tests")
    try:
        upgrade(engine)
    finally:
        engine.dispose()
    return name


@pytest.fixture(scope="session")
def admin_settings(test_database: str) -> DatabaseSettings:
    return replace(_settings(DatabaseRole.ADMIN), name=test_database)


@pytest.fixture(scope="session")
def owner_settings(test_database: str) -> DatabaseSettings:
    return replace(_settings(DatabaseRole.OWNER), name=test_database)


@pytest.fixture(scope="session")
def app_settings(test_database: str) -> DatabaseSettings:
    return replace(_settings(DatabaseRole.APP), name=test_database)


@pytest.fixture
def owner_engine(owner_settings: DatabaseSettings) -> Iterator[Engine]:
    engine = create_database_engine(owner_settings, application_name="aegis-tests")
    yield engine
    engine.dispose()


@pytest.fixture
def app_engine(app_settings: DatabaseSettings) -> Iterator[Engine]:
    engine = create_database_engine(app_settings, application_name="aegis-tests")
    yield engine
    engine.dispose()

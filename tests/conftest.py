import os
import subprocess
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import Engine, text

from aegis.config.settings import (
    DatabaseRole,
    DatabaseSettings,
    SettingsError,
    load_database_settings,
    load_runtime_settings,
)
from aegis.db.admin import bootstrap, recreate_test_database
from aegis.db.engine import create_database_engine
from aegis.db.migrate import upgrade
from aegis.integrations.openshell.cli import VERIFIED_VERSION
from aegis.integrations.openshell.runtime import OpenShellRuntime

if TYPE_CHECKING:
    from tests.fixtures.services import Caller

ROOT = Path(__file__).resolve().parents[1]


def _settings(role: DatabaseRole) -> DatabaseSettings:
    try:
        return load_database_settings(os.environ, role)
    except SettingsError as error:
        hint = "run database tests with `make test-integration` or `make test-security`"
        pytest.fail(f"{error}; {hint}")


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


@pytest.fixture
def isolated_jobs(owner_engine: Engine) -> None:
    # One test database serves the whole session; jobs left open by earlier tests would otherwise
    # be claimed or recovered by the workers a test starts.
    with owner_engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE aegis.jobs SET state = 'finished', lease_owner = NULL,"
                " lease_expires_at = NULL, last_error_code = 'test_isolation'"
                " WHERE state IN ('pending', 'running')"
            )
        )


@pytest.fixture
def operator(owner_engine: Engine) -> "Caller":
    # Imported here so unit tests, which run without .env, never read the pepper.
    from aegis.authorization.catalog import Role
    from tests.fixtures.services import make_caller

    return make_caller(owner_engine, Role.OPERATOR, prefix="operator")


@pytest.fixture(scope="session")
def openshell_runtime() -> OpenShellRuntime:
    runtime = OpenShellRuntime(load_runtime_settings(os.environ).openshell)
    status = runtime.check()
    if not status.healthy:
        pytest.fail(
            f"OpenShell is not usable ({status.detail}): install OpenShell {VERIFIED_VERSION}"
            " and run `make openshell-init`; see the getting-started guide"
        )
    return runtime


@pytest.fixture(scope="session")
def probe_image() -> str:
    # Built by the same `make openshell-image` an operator runs, offline and without pulling.
    built = subprocess.run(
        ["make", "--no-print-directory", "openshell-image"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    line = built.stdout.strip().splitlines()[-1] if built.stdout.strip() else ""
    if built.returncode != 0 or not line.startswith("AEGIS_OPENSHELL_IMAGE=sha256:"):
        pytest.fail(f"the probe image did not build: {built.stderr.strip()[-300:]}")
    return line.split("=", 1)[1]

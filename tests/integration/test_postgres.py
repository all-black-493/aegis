import os

import psycopg
import pytest
from psycopg.rows import TupleRow

EXPECTED_MAJOR_VERSION = 17


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.fail(f"{name} is not set; run integration tests with `make test-integration`")
    return value


def _connect(password: str | None = None) -> psycopg.Connection[TupleRow]:
    return psycopg.connect(
        host="127.0.0.1",
        port=int(_env("AEGIS_POSTGRES_PORT")),
        user=_env("AEGIS_POSTGRES_USER"),
        password=password if password is not None else _env("AEGIS_POSTGRES_PASSWORD"),
        dbname=_env("AEGIS_POSTGRES_DB"),
        connect_timeout=5,
    )


def test_select_1() -> None:
    with _connect() as connection:
        assert connection.execute("SELECT 1").fetchone() == (1,)


def test_server_runs_pinned_major_version() -> None:
    with _connect() as connection:
        assert connection.info.server_version // 10000 == EXPECTED_MAJOR_VERSION


def test_wrong_password_is_rejected() -> None:
    with pytest.raises(psycopg.OperationalError, match="password authentication failed"):
        _connect(password="definitely-not-the-password")

import psycopg
from psycopg.rows import TupleRow
from sqlalchemy import URL, Engine, create_engine

from aegis.config.settings import DatabaseSettings

CONNECT_TIMEOUT_SECONDS = 5


def create_database_engine(settings: DatabaseSettings, *, application_name: str) -> Engine:
    url = URL.create(
        "postgresql+psycopg",
        username=settings.user,
        password=settings.password.reveal(),
        host=settings.host,
        port=settings.port,
        database=settings.name,
    )
    return create_engine(
        url,
        pool_pre_ping=True,
        hide_parameters=True,
        connect_args={
            "connect_timeout": CONNECT_TIMEOUT_SECONDS,
            "application_name": application_name,
        },
    )


def connect(
    settings: DatabaseSettings,
    *,
    application_name: str,
    database: str | None = None,
    autocommit: bool = False,
) -> psycopg.Connection[TupleRow]:
    return psycopg.connect(
        host=settings.host,
        port=settings.port,
        user=settings.user,
        password=settings.password.reveal(),
        dbname=database or settings.name,
        connect_timeout=CONNECT_TIMEOUT_SECONDS,
        application_name=application_name,
        autocommit=autocommit,
    )

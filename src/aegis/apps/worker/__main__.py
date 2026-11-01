import logging
import os
import signal
import sys
import threading
from types import FrameType

from sqlalchemy.exc import SQLAlchemyError

from aegis.audit.recorder import AuditRecorder
from aegis.config.logs import Redactor, configure_logging
from aegis.config.settings import (
    DatabaseRole,
    SettingsError,
    load_common_settings,
    load_database_settings,
    load_worker_settings,
)
from aegis.config.variables import SECRET_NAMES
from aegis.db.engine import create_database_engine
from aegis.db.migrate import schema_status
from aegis.jobs.worker import Worker
from aegis.policy.rules import MAX_JOB_ATTEMPTS

logger = logging.getLogger("aegis.worker")


def main() -> int:
    environ = dict(os.environ)
    try:
        common = load_common_settings(environ)
        settings = load_worker_settings(environ)
        database = load_database_settings(environ, DatabaseRole.APP)
    except SettingsError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    if settings.max_attempts > MAX_JOB_ATTEMPTS:
        print(
            f"error: AEGIS_WORKER_MAX_ATTEMPTS exceeds the policy's {MAX_JOB_ATTEMPTS}",
            file=sys.stderr,
        )
        return 1
    # Handlers run in this process; they get no credentials, including through the environment.
    for name in SECRET_NAMES:
        os.environ.pop(name, None)
    secret = database.password.reveal()
    configure_logging(common, secrets=[secret])
    engine = create_database_engine(database, application_name="aegis-worker")
    try:
        try:
            with engine.connect() as connection:
                ready = schema_status(connection).ready
        except SQLAlchemyError as error:
            logger.error("database unavailable: %s", type(error).__name__)
            return 1
        if not ready:
            logger.error("the database schema is not current; run `make migrate`")
            return 1
        stop = threading.Event()

        def request_stop(signum: int, _frame: FrameType | None) -> None:
            logger.info("stopping", extra={"signal": signal.Signals(signum).name})
            stop.set()

        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        Worker(engine, AuditRecorder(Redactor([secret])), settings).run(stop)
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())

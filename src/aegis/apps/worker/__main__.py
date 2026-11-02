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
    forget_secrets,
    load_common_settings,
    load_database_settings,
    load_model_settings,
    load_runtime_settings,
    load_worker_settings,
)
from aegis.db.engine import create_database_engine
from aegis.db.migrate import schema_status
from aegis.jobs.sandboxes import clean_orphaned_sandboxes
from aegis.jobs.worker import Worker
from aegis.model_providers.factory import build_provider
from aegis.policy.rules import MAX_JOB_ATTEMPTS
from aegis.runtime.contract import SandboxRuntimeError
from aegis.runtime.factory import build_runtime

logger = logging.getLogger("aegis.worker")


def main() -> int:
    environ = dict(os.environ)
    try:
        common = load_common_settings(environ)
        settings = load_worker_settings(environ)
        database = load_database_settings(environ, DatabaseRole.APP)
        model = load_model_settings(environ)
        sandboxes = load_runtime_settings(environ)
    except SettingsError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    if settings.max_attempts > MAX_JOB_ATTEMPTS:
        print(
            f"error: AEGIS_WORKER_MAX_ATTEMPTS exceeds the policy's {MAX_JOB_ATTEMPTS}",
            file=sys.stderr,
        )
        return 1
    forget_secrets(os.environ)
    secret = database.password.reveal()
    configure_logging(common, secrets=[secret])
    provider = build_provider(model)
    status = provider.check()
    if not status.healthy:
        # Not fatal: other task kinds still run, and each generate task retries or fails on its own.
        logger.warning(
            "model provider unavailable",
            extra={"provider": model.provider.value, "detail": status.detail},
        )
    runtime = build_runtime(sandboxes)
    recorder = AuditRecorder(Redactor([secret]))
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
        try:
            clean_orphaned_sandboxes(engine, recorder, runtime)
        except SandboxRuntimeError as error:
            # No sandbox can be created while the runtime is unusable, so cleanup can wait.
            logger.warning("sandbox cleanup skipped", extra={"detail": error.code})
        Worker(engine, recorder, settings, provider=provider).run(stop)
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())

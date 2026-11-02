import logging
import threading
import time
from collections.abc import Mapping
from typing import Any

from sqlalchemy import Engine, select
from sqlalchemy.exc import SQLAlchemyError

from aegis.config.settings import WorkerSettings
from aegis.identity.schema import identities
from aegis.jobs import repository as jobs
from aegis.jobs.handlers import Handler, HandlerContext
from aegis.jobs.settlement import Claim, HandlerRun, Stop, claim_ids
from aegis.tasks.schema import tasks

SUPERVISION_TICK_SECONDS = 0.25

logger = logging.getLogger("aegis.worker")


def call(
    handler: Handler, task_input: Mapping[str, Any], context: HandlerContext, run: HandlerRun
) -> None:
    try:
        run.result = handler(task_input, context)
    except Exception as error:
        run.error = error


class Supervisor:
    # Keeps the lease alive while a handler runs, and says why it must stop if it must.
    def __init__(self, engine: Engine, settings: WorkerSettings) -> None:
        self._engine = engine
        self._settings = settings

    def watch(self, claim: Claim, thread: threading.Thread, stop: threading.Event) -> Stop | None:
        settings = self._settings
        tick = min(settings.heartbeat_seconds, SUPERVISION_TICK_SECONDS)
        lease_deadline = time.monotonic() + settings.lease_seconds
        next_beat = time.monotonic() + settings.heartbeat_seconds
        shutdown_at: float | None = None
        while True:
            thread.join(tick)
            if not thread.is_alive():
                return None
            now = time.monotonic()
            if stop.is_set() and shutdown_at is None:
                shutdown_at = now + settings.shutdown_grace_seconds
            if shutdown_at is not None and now >= shutdown_at:
                return Stop.SHUTDOWN
            if now < next_beat:
                continue
            next_beat = now + settings.heartbeat_seconds
            try:
                stopped = self._heartbeat(claim)
            except SQLAlchemyError as error:
                logger.warning("heartbeat failed: %s", type(error).__name__, extra=claim_ids(claim))
                if now >= lease_deadline:
                    return Stop.FENCE_LOST
                continue
            if stopped is not None:
                return stopped
            lease_deadline = now + settings.lease_seconds

    def _heartbeat(self, claim: Claim) -> Stop | None:
        with self._engine.begin() as connection:
            if jobs.renew(connection, claim.job, self._settings.lease_seconds) is None:
                return Stop.FENCE_LOST
            row = connection.execute(
                select(tasks.c.cancel_requested_by, identities.c.status)
                .join(identities, identities.c.id == tasks.c.initiator_id)
                .where(tasks.c.id == claim.task.task_id)
            ).one()
        if row.cancel_requested_by is not None:
            return Stop.CANCEL_REQUESTED
        if row.status != "active":
            return Stop.INITIATOR_DISABLED
        return None

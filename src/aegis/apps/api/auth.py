import logging

from fastapi import Request
from sqlalchemy.exc import SQLAlchemyError

from aegis.apps.api.context import ApiContext, api_context, request_id
from aegis.apps.api.problems import ApiError
from aegis.audit.events import AuditEvent, AuditEventType, Outcome, Source
from aegis.authorization.access import ActorContext
from aegis.identity.authentication import (
    AuthenticationError,
    FailureReason,
    presented_token,
    verify,
)

UNAUTHENTICATED_HEADERS = {"WWW-Authenticate": "Bearer"}

logger = logging.getLogger("aegis.api.auth")


def require_actor(request: Request) -> ActorContext:
    context = api_context(request)
    try:
        token = presented_token(_bearer_token(request.headers.getlist("authorization")))
        with context.engine.connect() as connection:
            return verify(connection, token, context.pepper)
    except AuthenticationError as error:
        _record_failure(context, error, request_id(request))
        raise ApiError(401, "unauthenticated", UNAUTHENTICATED_HEADERS) from None


def _bearer_token(headers: list[str]) -> str | None:
    if not headers:
        return None
    scheme, _, token = headers[0].strip().partition(" ")
    if len(headers) > 1 or scheme.lower() != "bearer":
        raise AuthenticationError(FailureReason.MALFORMED)
    return token.strip()


def _record_failure(context: ApiContext, error: AuthenticationError, request: str) -> None:
    logger.warning(
        "authentication failed",
        extra={"request_id": request, "reason": error.reason.value},
    )
    if error.credential_id is None:
        return
    event = AuditEvent(
        event_type=AuditEventType.AUTH_FAILED,
        source=Source.API,
        outcome=Outcome.DENIED,
        target_type="credential",
        target_id=str(error.credential_id),
        request_id=request,
        reason_code=error.reason.value,
    )
    try:
        with context.engine.begin() as connection:
            context.recorder.record(connection, event)
    except SQLAlchemyError:
        logger.critical(
            "could not record auth.failed; the request was still refused",
            extra={"request_id": request, "event_id": str(event.event_id)},
        )

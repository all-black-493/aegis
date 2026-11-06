import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.exc import SQLAlchemyError

from aegis.apps.api.context import api_context, request_id
from aegis.apps.api.problems import problem
from aegis.apps.api.schemas.health import Status
from aegis.db.migrate import schema_status

logger = logging.getLogger("aegis.api")

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
def live() -> Status:
    return Status(status="alive")


@router.get("/ready", response_model=Status, responses={503: {"description": "Not ready"}})
def ready(request: Request) -> Response:
    try:
        with api_context(request).engine.connect() as connection:
            schema = schema_status(connection)
    except SQLAlchemyError as error:
        logger.warning(
            "not ready: database unavailable: %s",
            type(error).__name__,
            extra={"request_id": request_id(request)},
        )
        return problem(503, "not_ready")
    if not schema.ready:
        logger.warning(
            "not ready: schema at %s, expected %s",
            schema.current,
            schema.head,
            extra={"request_id": request_id(request)},
        )
        return problem(503, "not_ready")
    return JSONResponse(Status(status="ready").model_dump())

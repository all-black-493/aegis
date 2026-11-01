import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from aegis.apps.api.auth import require_actor
from aegis.apps.api.context import api_context, request_id
from aegis.apps.api.problems import problem
from aegis.authorization.access import ActorContext
from aegis.db.migrate import schema_status
from aegis.identity.schema import identities

logger = logging.getLogger("aegis.api")

health = APIRouter(prefix="/health", tags=["health"])
v1 = APIRouter(prefix="/v1", dependencies=[Depends(require_actor)])


class Status(BaseModel):
    status: str


class Me(BaseModel):
    identity_id: UUID
    name: str
    kind: str
    roles: list[str]
    credential_id: UUID | None


@health.get("/live")
def live() -> Status:
    return Status(status="alive")


@health.get("/ready", response_model=Status, responses={503: {"description": "Not ready"}})
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


@v1.get("/me")
def me(request: Request, actor: Annotated[ActorContext, Depends(require_actor)]) -> Me:
    with api_context(request).engine.connect() as connection:
        name = connection.execute(
            select(identities.c.name).where(identities.c.id == actor.identity_id)
        ).scalar_one()
    return Me(
        identity_id=actor.identity_id,
        name=name,
        kind=actor.kind.value,
        roles=sorted(role.value for role in actor.roles),
        credential_id=actor.credential_id,
    )

import logging
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from aegis.apps.api.auth import require_actor
from aegis.apps.api.context import api_context, request_id
from aegis.apps.api.problems import ApiError, problem
from aegis.apps.api.tasks import (
    DEFAULT_PAGE_SIZE,
    SUBMIT_OPENAPI,
    TaskPage,
    TaskSubmission,
    TaskView,
    decode_cursor,
    encode_cursor,
    idempotency_key,
    submission_body,
    task_service,
    view,
)
from aegis.authorization.access import ActorContext
from aegis.db.migrate import schema_status
from aegis.identity.schema import identities
from aegis.tasks.repository import TaskRecord
from aegis.tasks.service import (
    MAX_PAGE_SIZE,
    AccessDeniedError,
    IdempotencyConflictError,
    Submission,
    TaskFinishedError,
)
from aegis.tasks.transitions import TaskNotFoundError

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


Actor = Annotated[ActorContext, Depends(require_actor)]


@v1.post(
    "/tasks",
    status_code=201,
    response_model=TaskView,
    responses={200: {"model": TaskView, "description": "Replayed"}},
    openapi_extra=SUBMIT_OPENAPI,
)
def submit_task(
    request: Request,
    actor: Actor,
    key: Annotated[str, Depends(idempotency_key)],
    body: Annotated[TaskSubmission, Depends(submission_body)],
) -> Response:
    submission = Submission(body.kind, body.input, key)
    try:
        submitted = task_service(request).submit(actor, submission, request_id(request))
    except IdempotencyConflictError:
        raise ApiError(409, "idempotency_key_conflict") from None
    except AccessDeniedError as denied:
        return _denied(denied)
    task = submitted.task
    if submitted.replayed:
        return _task(task, 200, {"Idempotent-Replayed": "true"})
    return _task(task, 201, {"Location": f"/v1/tasks/{task.task_id}"})


@v1.get("/tasks", response_model=TaskPage)
def list_tasks(
    request: Request,
    actor: Actor,
    scope: Literal["own", "all"] = "own",
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    cursor: Annotated[str | None, Query(max_length=128)] = None,
) -> Response:
    after = None if cursor is None else decode_cursor(cursor)
    try:
        page = task_service(request).page(
            actor, everyone=scope == "all", limit=limit, after=after, request_id=request_id(request)
        )
    except AccessDeniedError as denied:
        return _denied(denied)
    body = TaskPage(
        items=[view(task) for task in page.tasks],
        next_cursor=None if page.next is None else encode_cursor(page.next),
    )
    return JSONResponse(body.model_dump(mode="json"))


@v1.get("/tasks/{task_id}", response_model=TaskView)
def get_task(request: Request, actor: Actor, task_id: UUID) -> Response:
    try:
        task = task_service(request).get(actor, task_id, request_id(request))
    except (TaskNotFoundError, AccessDeniedError):
        return problem(404)
    return _task(task, 200)


@v1.post("/tasks/{task_id}/cancel", response_model=TaskView)
def cancel_task(request: Request, actor: Actor, task_id: UUID) -> Response:
    try:
        cancelled = task_service(request).cancel(actor, task_id, request_id(request))
    except TaskNotFoundError:
        return problem(404)
    except AccessDeniedError as denied:
        return _denied(denied) if denied.visible else problem(404)
    except TaskFinishedError:
        return problem(409, "task_finished")
    return _task(cancelled.task, 202 if cancelled.pending else 200)


def _task(task: TaskRecord, status: int, headers: dict[str, str] | None = None) -> Response:
    return JSONResponse(view(task).model_dump(mode="json"), status_code=status, headers=headers)


def _denied(denied: AccessDeniedError) -> Response:
    return problem(403, "denied", reasons=list(denied.decision.reason_codes))

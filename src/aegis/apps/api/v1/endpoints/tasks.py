from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, Response

from aegis.agents.records import read_runs, read_steps
from aegis.apps.api.context import api_context, request_id
from aegis.apps.api.deps import Actor, idempotency_key, submission_body, task_service
from aegis.apps.api.pagination import DEFAULT_PAGE_SIZE, decode_cursor, encode_cursor
from aegis.apps.api.problems import ApiError, problem
from aegis.apps.api.schemas.agents import StepPage, run_view, step_view
from aegis.apps.api.schemas.tasks import (
    SUBMIT_OPENAPI,
    TaskPage,
    TaskSubmission,
    TaskView,
    view,
)
from aegis.tasks.repository import TaskRecord
from aegis.tasks.service import (
    MAX_PAGE_SIZE,
    AccessDeniedError,
    IdempotencyConflictError,
    Submission,
    TaskFinishedError,
)
from aegis.tasks.transitions import TaskNotFoundError

router = APIRouter(prefix="/tasks")


@router.post(
    "",
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


@router.get("", response_model=TaskPage)
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


@router.get("/{task_id}", response_model=TaskView)
def get_task(request: Request, actor: Actor, task_id: UUID) -> Response:
    try:
        task = task_service(request).get(actor, task_id, request_id(request))
    except (TaskNotFoundError, AccessDeniedError):
        return problem(404)
    return _task(task, 200)


@router.post("/{task_id}/cancel", response_model=TaskView)
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


@router.get("/{task_id}/steps", response_model=StepPage)
def task_steps(
    request: Request,
    actor: Actor,
    task_id: UUID,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    after: Annotated[int, Query(ge=0)] = 0,
) -> Response:
    # Whoever may read the task may read its steps, and a privileged read is audited as one.
    try:
        task_service(request).get(actor, task_id, request_id(request))
    except (TaskNotFoundError, AccessDeniedError):
        return problem(404)
    with api_context(request).engine.connect() as connection:
        runs = read_runs(connection, task_id)
        steps = read_steps(connection, task_id, after=after, limit=limit)
    body = StepPage(
        runs=[run_view(run) for run in runs],
        steps=[step_view(step) for step in steps],
        next_after=steps[-1].step_id if len(steps) == limit else None,
    )
    return JSONResponse(body.model_dump(mode="json"))


def _task(task: TaskRecord, status: int, headers: dict[str, str] | None = None) -> Response:
    return JSONResponse(view(task).model_dump(mode="json"), status_code=status, headers=headers)


def _denied(denied: AccessDeniedError) -> Response:
    return problem(403, "denied", reasons=list(denied.decision.reason_codes))

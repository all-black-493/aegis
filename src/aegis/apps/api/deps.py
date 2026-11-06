from typing import Annotated

from fastapi import Depends, Request
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError

from aegis.apps.api.auth import require_actor
from aegis.apps.api.context import api_context
from aegis.apps.api.problems import ApiError
from aegis.apps.api.schemas.tasks import IDEMPOTENCY_KEY, TaskSubmission
from aegis.authorization.access import ActorContext
from aegis.tasks.service import TaskService

Actor = Annotated[ActorContext, Depends(require_actor)]


def task_service(request: Request) -> TaskService:
    return api_context(request).tasks


def idempotency_key(request: Request) -> str:
    values = request.headers.getlist("idempotency-key")
    if not values:
        raise ApiError(400, "idempotency_key_required")
    if len(values) > 1 or not IDEMPOTENCY_KEY.fullmatch(values[0]):
        raise ApiError(400, "idempotency_key_invalid")
    return values[0]


async def submission_body(request: Request) -> TaskSubmission:
    # Parsed here rather than as a body parameter so that authentication and the
    # Idempotency-Key check run first (ADR-0011).
    raw = await request.body()
    try:
        return TaskSubmission.model_validate_json(raw)
    except ValidationError as error:
        errors = error.errors(include_url=False, include_context=False, include_input=False)
        raise RequestValidationError(
            [{**item, "loc": ("body", *item["loc"])} for item in errors]
        ) from None

import base64
import math
import re
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from pydantic import AfterValidator, BaseModel, ConfigDict, StringConstraints, ValidationError
from pydantic_core import PydanticCustomError

from aegis.apps.api.context import api_context
from aegis.apps.api.problems import ApiError
from aegis.tasks.repository import Position, TaskRecord
from aegis.tasks.service import TaskService

IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9_.:-]{8,128}")
DEFAULT_PAGE_SIZE = 50
_CURSOR = re.compile(r"[A-Za-z0-9_-]{1,128}")


def _storable(value: Any) -> Any:
    # jsonb rejects NaN, infinities and NUL, and prints numbers without exponents: 1e308 would
    # grow to 309 digits and could push a saved decision's inputs past their size limit.
    if isinstance(value, float) and (not math.isfinite(value) or "e" in repr(value)):
        raise PydanticCustomError("json_unsupported", "unsupported JSON value")
    if isinstance(value, str) and "\x00" in value:
        raise PydanticCustomError("json_unsupported", "unsupported JSON value")
    if isinstance(value, dict):
        for key, item in value.items():
            _storable(key)
            _storable(item)
    elif isinstance(value, list):
        for item in value:
            _storable(item)
    return value


class TaskSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    input: Annotated[dict[str, Any], AfterValidator(_storable)]


class TaskView(BaseModel):
    id: UUID
    kind: str
    state: str
    version: int
    owner_id: UUID
    input: dict[str, Any]
    result: dict[str, Any] | None
    failure_code: str | None
    cancel_requested_at: datetime | None
    created_at: datetime
    updated_at: datetime
    finished_at: datetime | None


class TaskPage(BaseModel):
    items: list[TaskView]
    next_cursor: str | None


SUBMIT_OPENAPI = {
    "parameters": [
        {
            "name": "Idempotency-Key",
            "in": "header",
            "required": True,
            "schema": {"type": "string", "pattern": f"^{IDEMPOTENCY_KEY.pattern}$"},
        }
    ],
    "requestBody": {
        "required": True,
        "content": {"application/json": {"schema": TaskSubmission.model_json_schema()}},
    },
}


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


def view(task: TaskRecord) -> TaskView:
    return TaskView(
        id=task.task_id,
        kind=task.kind.value,
        state=task.state.value,
        version=task.version,
        owner_id=task.owner_id,
        input=dict(task.input),
        result=None if task.result is None else dict(task.result),
        failure_code=task.failure_code,
        cancel_requested_at=task.cancel_requested_at,
        created_at=task.created_at,
        updated_at=task.updated_at,
        finished_at=task.finished_at,
    )


def encode_cursor(position: Position) -> str:
    raw = f"{position.created_at.isoformat()}|{position.task_id}".encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_cursor(cursor: str) -> Position:
    try:
        if not _CURSOR.fullmatch(cursor):
            raise ValueError("malformed cursor")
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("ascii")
        created_at, _, task_id = raw.partition("|")
        position = Position(datetime.fromisoformat(created_at), UUID(task_id))
    except ValueError:
        raise ApiError(400, "invalid_cursor") from None
    if position.created_at.tzinfo is None:
        raise ApiError(400, "invalid_cursor")
    return position

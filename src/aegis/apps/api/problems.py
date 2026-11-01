import logging
from collections.abc import Mapping
from http import HTTPStatus
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException

PROBLEM_MEDIA_TYPE = "application/problem+json"
_CODES = {
    400: "bad_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    413: "content_too_large",
    415: "unsupported_media_type",
    422: "validation_failed",
    500: "internal_error",
    503: "service_unavailable",
}

logger = logging.getLogger(__name__)


class ApiError(HTTPException):
    def __init__(self, status: int, code: str, headers: Mapping[str, str] | None = None) -> None:
        super().__init__(status, headers=headers)
        self.code = code


def problem(
    status: int, code: str | None = None, headers: Mapping[str, str] | None = None, **extra: Any
) -> JSONResponse:
    body = {
        "type": "about:blank",
        "title": HTTPStatus(status).phrase,
        "status": status,
        "code": code or _CODES.get(status, f"http_{status}"),
        **extra,
    }
    return JSONResponse(body, status_code=status, headers=headers, media_type=PROBLEM_MEDIA_TYPE)


def http_problem(_request: Request, error: Exception) -> JSONResponse:
    if not isinstance(error, HTTPException):
        raise error
    return problem(error.status_code, getattr(error, "code", None), error.headers)


def validation_problem(_request: Request, error: Exception) -> JSONResponse:
    if not isinstance(error, RequestValidationError):
        raise error
    # Only the error type and the declared location are returned: never input, messages or context.
    errors = [{"type": item["type"], "loc": _location(item)} for item in error.errors()]
    return problem(422, errors=errors)


def unavailable_problem(request: Request, error: Exception) -> JSONResponse:
    if not isinstance(error, SQLAlchemyError):
        raise error
    logger.error(
        "database unavailable: %s",
        type(error).__name__,
        extra={"request_id": getattr(request.state, "request_id", None)},
    )
    return problem(503)


def _location(item: Mapping[str, Any]) -> list[str | int]:
    location = list(item.get("loc", ()))
    if item.get("type") == "extra_forbidden":
        location = location[:-1]
    return [part for part in location if isinstance(part, str | int)]

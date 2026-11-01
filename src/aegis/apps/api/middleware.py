import logging
import time
from uuid import uuid4

from starlette.datastructures import Headers, MutableHeaders
from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from aegis.apps.api.problems import ApiError, problem

MAX_BODY_BYTES = 64 * 1024
RESPONSE_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}

logger = logging.getLogger("aegis.api")


class RequestMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        started = time.monotonic()
        status = 500
        response_started = False

        async def send_with_headers(message: Message) -> None:
            nonlocal status, response_started
            if message["type"] == "http.response.start":
                response_started = True
                status = message["status"]
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = request_id
                headers.update(RESPONSE_HEADERS)
            await send(message)

        try:
            rejection = _check_body(Headers(scope=scope))
            if rejection is not None:
                await rejection(scope, receive, send_with_headers)
            else:
                await self.app(scope, _limited(receive), send_with_headers)
        except HTTPException as error:
            if response_started:
                raise
            await problem(error.status_code, getattr(error, "code", None))(
                scope, receive, send_with_headers
            )
        except Exception:
            logger.exception("unhandled error", extra={"request_id": request_id})
            if response_started:
                raise
            await problem(500)(scope, receive, send_with_headers)
        finally:
            logger.info(
                "request",
                extra={
                    "request_id": request_id,
                    "method": scope["method"],
                    "path": scope["path"],
                    "status": status,
                    "duration_ms": round((time.monotonic() - started) * 1000, 1),
                },
            )


def _check_body(headers: Headers) -> Response | None:
    lengths = headers.getlist("content-length")
    if len(lengths) > 1 or (lengths and not (lengths[0].isascii() and lengths[0].isdigit())):
        return problem(400, "invalid_content_length")
    if lengths and int(lengths[0]) > MAX_BODY_BYTES:
        return problem(413)
    has_body = bool(lengths and int(lengths[0]) > 0) or "transfer-encoding" in headers
    if has_body and not _is_json(headers.getlist("content-type")):
        return problem(415)
    return None


def _is_json(content_types: list[str]) -> bool:
    if len(content_types) != 1:
        return False
    media_type, *parameters = (part.strip() for part in content_types[0].lower().split(";"))
    return media_type == "application/json" and parameters in ([], ["charset=utf-8"])


def _limited(receive: Receive) -> Receive:
    received = 0

    async def receive_within_limit() -> Message:
        nonlocal received
        message = await receive()
        if message["type"] == "http.request":
            received += len(message.get("body", b""))
            if received > MAX_BODY_BYTES:
                raise ApiError(413, "content_too_large")
        return message

    return receive_within_limit

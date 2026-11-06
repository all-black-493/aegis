import io
import logging
from collections.abc import Iterator
from typing import NoReturn

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.routing import APIRoute, iter_route_contexts
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict
from sqlalchemy import create_engine

from aegis.apps.api import auth
from aegis.apps.api.app import create_app
from aegis.apps.api.auth import require_actor
from aegis.apps.api.context import ApiContext
from aegis.apps.api.health import router as health
from aegis.apps.api.middleware import MAX_BODY_BYTES
from aegis.apps.api.v1.router import router as v1
from aegis.audit.recorder import AuditRecorder
from aegis.config.logs import Redactor, configure_logging
from aegis.config.settings import (
    CommonSettings,
    Environment,
    LogLevel,
    Secret,
    SettingsError,
    load_api_settings,
)
from aegis.identity.authentication import AuthenticationError, FailureReason

PEPPER = Secret("unit-test-pepper-0123456789abcdef0123")
FAKE_SECRET = "fake-secret-value-0123456789abcdef"
TOKEN = "aegis_pat_" + "a" * 26 + "_" + "b" * 52
PRODUCTION_ROUTES = {
    ("GET", "/health/live"),
    ("GET", "/health/ready"),
    ("GET", "/v1/me"),
    ("POST", "/v1/tasks"),
    ("GET", "/v1/tasks"),
    ("GET", "/v1/tasks/{task_id}"),
    ("POST", "/v1/tasks/{task_id}/cancel"),
}


class Probe(BaseModel):
    model_config = ConfigDict(extra="forbid")
    count: int


probe = APIRouter(prefix="/probe")


@probe.post("/echo")
def echo(body: Probe) -> Probe:
    return body


@probe.get("/crash")
def crash() -> None:
    raise RuntimeError(f"boom {FAKE_SECRET}")


def _app(environment: Environment = Environment.PRODUCTION) -> FastAPI:
    # The engine is never connected: these tests stop before any database access.
    engine = create_engine("postgresql+psycopg://unit:unit@127.0.0.1:9/unit")
    context = ApiContext(engine, PEPPER, AuditRecorder(Redactor()))
    return create_app(context, environment)


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = _app()
    app.include_router(probe)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


@pytest.fixture
def log_output() -> Iterator[io.StringIO]:
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    stream = io.StringIO()
    configure_logging(CommonSettings(Environment.TEST, LogLevel.INFO), stream=stream)
    yield stream
    root.handlers[:] = handlers
    root.setLevel(level)


def _routes(*routers: APIRouter) -> set[tuple[str, str]]:
    return {
        (method, str(context.path))
        for router in routers
        for context in iter_route_contexts(router.routes)
        for method in context.methods or ()
    }


def test_the_api_exposes_only_health_me_and_tasks() -> None:
    assert _routes(health, v1) == PRODUCTION_ROUTES


def test_every_v1_route_requires_authentication(client: TestClient) -> None:
    contexts = list(iter_route_contexts(v1.routes))
    assert {context.path for context in contexts} == {
        path for _, path in PRODUCTION_ROUTES if path.startswith("/v1/")
    }
    for context in contexts:
        route = context.route
        assert isinstance(route, APIRoute)
        assert any(d.call is require_actor for d in route.dependant.dependencies), context.path
        for method in context.methods or ():
            assert client.request(method, str(context.path)).status_code == 401, context.path


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": ""},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer not-a-token"},
        {"Authorization": f"Basic {TOKEN}"},
        {"Authorization": TOKEN},
        {"Authorization": f"Bearer {TOKEN}x"},
    ],
)
def test_unauthenticated_requests_get_one_identical_401(
    client: TestClient, headers: dict[str, str]
) -> None:
    reference = client.get("/v1/me")

    response = client.get("/v1/me", headers=headers)

    assert response.status_code == 401
    assert response.content == reference.content
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "about:blank",
        "title": "Unauthorized",
        "status": 401,
        "code": "unauthenticated",
    }


def test_repeated_authorization_headers_are_refused(client: TestClient) -> None:
    response = client.get(
        "/v1/me", headers=[("Authorization", f"Bearer {TOKEN}"), ("Authorization", "Bearer x")]
    )

    assert response.status_code == 401


def test_validation_errors_do_not_echo_input(client: TestClient) -> None:
    response = client.post(
        "/probe/echo", json={"count": FAKE_SECRET, FAKE_SECRET: FAKE_SECRET, "nested": [1]}
    )

    assert response.status_code == 422
    assert FAKE_SECRET not in response.text
    assert response.json()["errors"] == [
        {"type": "int_parsing", "loc": ["body", "count"]},
        {"type": "extra_forbidden", "loc": ["body"]},
        {"type": "extra_forbidden", "loc": ["body"]},
    ]


def test_invalid_json_is_rejected_without_echoing_it(client: TestClient) -> None:
    response = client.post(
        "/probe/echo",
        content=f'{{"count": "{FAKE_SECRET}"',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert FAKE_SECRET not in response.text
    assert response.json()["errors"][0]["type"] == "json_invalid"


def test_unexpected_errors_get_a_generic_500(client: TestClient, log_output: io.StringIO) -> None:
    response = client.get("/probe/crash")

    assert response.status_code == 500
    assert response.json() == {
        "type": "about:blank",
        "title": "Internal Server Error",
        "status": 500,
        "code": "internal_error",
    }
    assert "boom" not in response.text
    assert response.headers["x-request-id"] in log_output.getvalue()


def test_bodies_over_64_kib_are_refused_by_declared_length(client: TestClient) -> None:
    body = b'{"count": 1}' + b" " * MAX_BODY_BYTES

    response = client.post(
        "/probe/echo", content=body, headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 413
    assert response.json()["code"] == "content_too_large"


def test_streamed_bodies_over_64_kib_are_refused(client: TestClient) -> None:
    def chunks() -> Iterator[bytes]:
        yield b'{"count": 1'
        for _ in range(MAX_BODY_BYTES // 1024 + 1):
            yield b" " * 1024
        yield b"}"

    response = client.post(
        "/probe/echo", content=chunks(), headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 413


def test_bodies_up_to_the_limit_are_accepted(client: TestClient) -> None:
    body = b'{"count": 1}'
    body += b" " * (MAX_BODY_BYTES - len(body))

    response = client.post(
        "/probe/echo", content=body, headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 200


@pytest.mark.parametrize(
    "content_type",
    [None, "text/plain", "application/x-www-form-urlencoded", "application/json; charset=latin-1"],
)
def test_bodies_must_be_json(client: TestClient, content_type: str | None) -> None:
    headers = {} if content_type is None else {"Content-Type": content_type}

    response = client.post("/probe/echo", content=b'{"count": 1}', headers=headers)

    assert response.status_code == 415
    assert response.json()["code"] == "unsupported_media_type"


@pytest.mark.parametrize("content_type", ["application/json", "Application/JSON; Charset=UTF-8"])
def test_json_bodies_are_accepted(client: TestClient, content_type: str) -> None:
    response = client.post(
        "/probe/echo", content=b'{"count": 1}', headers={"Content-Type": content_type}
    )

    assert response.status_code == 200


def test_body_checks_apply_before_authentication(client: TestClient) -> None:
    response = client.post("/v1/me", content=b"x", headers={"Content-Type": "text/plain"})

    assert response.status_code == 415


def test_invalid_content_length_is_refused(client: TestClient) -> None:
    response = client.post(
        "/probe/echo",
        content=b'{"count": 1}',
        headers={"Content-Type": "application/json", "Content-Length": "1x"},
    )

    assert response.status_code == 400


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [("GET", "/health/live", 200), ("GET", "/nowhere", 404), ("DELETE", "/v1/me", 405)],
)
def test_every_response_has_a_request_id_and_safe_headers(
    client: TestClient, method: str, path: str, status: int
) -> None:
    first = client.request(method, path)
    second = client.request(method, path)

    assert first.status_code == status
    assert len(first.headers["x-request-id"]) == 32
    assert first.headers["x-request-id"] != second.headers["x-request-id"]
    assert first.headers["cache-control"] == "no-store"
    assert first.headers["x-content-type-options"] == "nosniff"
    assert "server" not in first.headers
    if status >= 400:
        assert first.headers["content-type"] == "application/problem+json"


@pytest.mark.parametrize("environment", [Environment.PRODUCTION, Environment.TEST])
def test_docs_are_disabled_outside_development(environment: Environment) -> None:
    with TestClient(_app(environment)) as client:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path).status_code == 404


def test_docs_are_served_in_development() -> None:
    with TestClient(_app(Environment.DEVELOPMENT)) as client:
        assert client.get("/docs").status_code == 200
        paths = set(client.get("/openapi.json").json()["paths"])

    assert paths == {path for _, path in PRODUCTION_ROUTES}


def test_tokens_never_reach_the_logs(client: TestClient, log_output: io.StringIO) -> None:
    client.get("/v1/me", headers={"Authorization": f"Bearer {TOKEN}x"})
    client.get(f"/v1/me?access_token={TOKEN}", headers={"Authorization": TOKEN})

    output = log_output.getvalue()
    assert '"message": "authentication failed"' in output
    assert '"reason": "malformed"' in output
    assert TOKEN not in output
    assert TOKEN[10:36] not in output


def test_the_api_port_defaults_to_8000_and_is_validated() -> None:
    assert load_api_settings({}).port == 8000
    assert load_api_settings({"AEGIS_API_PORT": "8080"}).port == 8080
    with pytest.raises(SettingsError, match="AEGIS_API_PORT"):
        load_api_settings({"AEGIS_API_PORT": "80"})


@pytest.mark.parametrize("reason", list(FailureReason))
def test_every_failure_reason_gets_the_same_401(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, reason: FailureReason
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> NoReturn:
        raise AuthenticationError(reason)

    monkeypatch.setattr(auth, "presented_token", refuse)
    reference = client.get("/v1/me").content

    response = client.get("/v1/me", headers={"Authorization": f"Bearer {TOKEN}"})

    assert response.status_code == 401
    assert response.content == reference

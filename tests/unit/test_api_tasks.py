from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from aegis.apps.api.app import create_app
from aegis.apps.api.auth import require_actor
from aegis.apps.api.context import ApiContext
from aegis.apps.api.deps import task_service
from aegis.apps.api.pagination import decode_cursor, encode_cursor
from aegis.apps.api.problems import ApiError
from aegis.apps.api.schemas.tasks import TaskSubmission, view
from aegis.audit.recorder import AuditRecorder
from aegis.authorization.access import ActorContext
from aegis.authorization.catalog import IdentityKind, Role
from aegis.config.logs import Redactor
from aegis.config.settings import Environment, Secret
from aegis.tasks.repository import Position, TaskRecord
from aegis.tasks.service import request_fingerprint
from aegis.tasks.states import TaskKind, TaskState

FAKE_SECRET = "fake-secret-value-0123456789abcdef"
KEY = {"Idempotency-Key": "key-0123456789"}
ACTOR = ActorContext(uuid4(), IdentityKind.HUMAN, frozenset({Role.OPERATOR}), uuid4())


def _client(*, authenticated: bool) -> TestClient:
    # The engine is never connected: these tests stop before any database access.
    engine = create_engine("postgresql+psycopg://unit:unit@127.0.0.1:9/unit")
    context = ApiContext(
        engine, Secret("unit-test-pepper-0123456789abcdef0123"), AuditRecorder(Redactor())
    )
    app = create_app(context, Environment.PRODUCTION)
    if authenticated:
        app.dependency_overrides[require_actor] = lambda: ACTOR
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def client() -> Iterator[TestClient]:
    with _client(authenticated=True) as client:
        yield client


def _post(client: TestClient, body: bytes | str, headers: dict[str, str] | None = None) -> Any:
    return client.post(
        "/v1/tasks",
        content=body,
        headers={"Content-Type": "application/json", **(headers or {})},
    )


def test_authentication_runs_before_the_key_and_body_checks() -> None:
    with _client(authenticated=False) as anonymous:
        response = _post(anonymous, f'{{"kind": "{FAKE_SECRET}"')

    assert response.status_code == 401
    assert FAKE_SECRET not in response.text


def test_the_key_is_checked_before_the_body(client: TestClient) -> None:
    response = _post(client, "{not json")

    assert (response.status_code, response.json()["code"]) == (400, "idempotency_key_required")


@pytest.mark.parametrize(
    "headers",
    [
        [("Idempotency-Key", "short")],
        [("Idempotency-Key", "x" * 129)],
        [("Idempotency-Key", "has spaces in it")],
        [("Idempotency-Key", "key/with/slash")],
        [("Idempotency-Key", "key-0123456789"), ("Idempotency-Key", "key-9876543210")],
    ],
)
def test_malformed_idempotency_keys_are_refused(
    client: TestClient, headers: list[tuple[str, str]]
) -> None:
    response = client.post(
        "/v1/tasks",
        content=b'{"kind": "noop", "input": {}}',
        headers=[("Content-Type", "application/json"), *headers],
    )

    assert (response.status_code, response.json()["code"]) == (400, "idempotency_key_invalid")


@pytest.mark.parametrize("field", ["owner_id", "initiator_id"])
def test_ownership_cannot_be_set_in_the_body(client: TestClient, field: str) -> None:
    body = f'{{"kind": "noop", "input": {{}}, "{field}": "{uuid4()}"}}'

    response = _post(client, body, KEY)

    assert response.status_code == 422
    assert response.json()["errors"] == [{"type": "extra_forbidden", "loc": ["body"]}]
    assert field not in response.text


@pytest.mark.parametrize(
    ("body", "error"),
    [
        ("", {"type": "json_invalid", "loc": ["body"]}),
        (f'{{"kind": "noop", "input": "{FAKE_SECRET}"', {"type": "json_invalid", "loc": ["body"]}),
        ('{"input": {}}', {"type": "missing", "loc": ["body", "kind"]}),
        ('{"kind": "noop"}', {"type": "missing", "loc": ["body", "input"]}),
        ('{"kind": "noop", "input": []}', {"type": "dict_type", "loc": ["body", "input"]}),
        (
            f'{{"kind": "{FAKE_SECRET.upper()}", "input": {{}}}}',
            {"type": "string_pattern_mismatch", "loc": ["body", "kind"]},
        ),
        (
            '{"kind": "noop", "input": {"a": NaN}}',
            {"type": "json_unsupported", "loc": ["body", "input"]},
        ),
        (
            '{"kind": "noop", "input": {"a": [1e400]}}',
            {"type": "json_unsupported", "loc": ["body", "input"]},
        ),
        (
            '{"kind": "noop", "input": {"a": {"b": "x\\u0000"}}}',
            {"type": "json_unsupported", "loc": ["body", "input"]},
        ),
        (
            '{"kind": "noop", "input": {"\\u0000": 1}}',
            {"type": "json_unsupported", "loc": ["body", "input"]},
        ),
        *(
            (
                f'{{"kind": "noop", "input": {{"a": [{number}]}}}}',
                {"type": "json_unsupported", "loc": ["body", "input"]},
            )
            for number in ("1e308", "-1e16", "1e-5", "2.5E-300")
        ),
    ],
)
def test_invalid_bodies_get_422_without_echo(
    client: TestClient, body: str, error: dict[str, Any]
) -> None:
    response = _post(client, body, KEY)

    assert response.status_code == 422
    assert response.json()["errors"] == [error]
    assert FAKE_SECRET not in response.text
    assert FAKE_SECRET.upper() not in response.text


def test_numbers_postgresql_stores_as_written_are_accepted() -> None:
    raw = '{"kind": "noop", "input": {"a": [0, 0.5, -0.0001, 1E2, 1e15, 12345678901234567890]}}'

    submission = TaskSubmission.model_validate_json(raw)

    assert submission.input == {"a": [0, 0.5, -0.0001, 100.0, 1e15, 12345678901234567890]}


@pytest.mark.parametrize(
    ("query", "status"),
    [
        ("scope=mine", 422),
        ("limit=0", 422),
        ("limit=101", 422),
        ("cursor=" + "a" * 129, 422),
        ("cursor=not+a+cursor", 400),
        ("cursor=bm90IGEgY3Vyc29y", 400),
    ],
)
def test_list_parameters_are_validated(client: TestClient, query: str, status: int) -> None:
    response = client.get(f"/v1/tasks?{query}")

    assert response.status_code == status


def test_invalid_task_ids_are_refused(client: TestClient) -> None:
    assert client.get("/v1/tasks/not-a-uuid").status_code == 422
    assert client.post("/v1/tasks/not-a-uuid/cancel").status_code == 422


def test_cursors_round_trip_and_reject_tampering() -> None:
    position = Position(datetime(2026, 11, 1, 12, 0, 0, 123456, tzinfo=UTC), uuid4())
    naive = encode_cursor(Position(datetime(2026, 11, 1, 12), uuid4()))

    assert decode_cursor(encode_cursor(position)) == position
    for cursor in (naive, encode_cursor(position)[:-4], "", "=" * 8):
        with pytest.raises(ApiError) as refused:
            decode_cursor(cursor)
        assert (refused.value.status_code, refused.value.code) == (400, "invalid_cursor")


def test_the_fingerprint_is_canonical_and_covers_kind_and_input() -> None:
    reference = request_fingerprint("wait", {"seconds": 5, "a": [1, {"b": 2}]})

    assert request_fingerprint("wait", {"a": [1, {"b": 2}], "seconds": 5}) == reference
    assert len(reference) == 64
    assert request_fingerprint("noop", {"seconds": 5, "a": [1, {"b": 2}]}) != reference
    assert request_fingerprint("wait", {"seconds": 6, "a": [1, {"b": 2}]}) != reference
    assert request_fingerprint("wait", {"seconds": 5.0, "a": [1, {"b": 2}]}) != reference
    with pytest.raises(ValueError, match="JSON compliant"):
        request_fingerprint("wait", {"seconds": float("nan")})


def test_the_task_view_exposes_only_public_fields() -> None:
    now = datetime(2026, 11, 1, tzinfo=timezone(timedelta(hours=1)))
    owner = UUID(int=7)
    task = TaskRecord(
        task_id=uuid4(),
        initiator_id=owner,
        owner_id=owner,
        submitted_credential_id=uuid4(),
        kind=TaskKind.WAIT,
        input={"seconds": 1},
        state=TaskState.QUEUED,
        version=1,
        idempotency_key="key-0123456789",
        request_fingerprint="f" * 64,
        cancel_requested_at=None,
        cancel_requested_by=uuid4(),
        result=None,
        failure_code=None,
        created_at=now,
        updated_at=now,
        finished_at=None,
    )

    body = view(task).model_dump(mode="json")

    assert set(body) == {
        "id",
        "kind",
        "state",
        "version",
        "owner_id",
        "input",
        "result",
        "failure_code",
        "cancel_requested_at",
        "created_at",
        "updated_at",
        "finished_at",
    }
    assert (body["kind"], body["state"], body["owner_id"]) == ("wait", "queued", str(owner))


def test_the_development_openapi_document_describes_task_submission() -> None:
    engine = create_engine("postgresql+psycopg://unit:unit@127.0.0.1:9/unit")
    context = ApiContext(engine, Secret("p" * 32), AuditRecorder(Redactor()))

    with TestClient(create_app(context, Environment.DEVELOPMENT)) as client:
        document = client.get("/openapi.json").json()

    submit = document["paths"]["/v1/tasks"]["post"]
    assert submit["parameters"][0]["name"] == "Idempotency-Key"
    body = submit["requestBody"]["content"]["application/json"]["schema"]
    assert body["required"] == ["kind", "input"]
    assert body["additionalProperties"] is False
    assert set(document["paths"]) == {
        "/health/live",
        "/health/ready",
        "/v1/me",
        "/v1/tasks",
        "/v1/tasks/{task_id}",
        "/v1/tasks/{task_id}/cancel",
    }


def test_every_request_shares_the_application_task_service() -> None:
    engine = create_engine("postgresql+psycopg://unit:unit@127.0.0.1:9/unit")
    context = ApiContext(engine, Secret("p" * 32), AuditRecorder(Redactor()))
    app = create_app(context, Environment.TEST)
    requests = [Request({"type": "http", "app": app}) for _ in range(2)]

    assert task_service(requests[0]) is task_service(requests[1]) is context.tasks

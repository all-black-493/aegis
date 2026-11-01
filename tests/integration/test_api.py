import io
import logging
import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import httpx2
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import OperationalError

from aegis.apps.api.app import create_app
from aegis.apps.api.context import ApiContext
from aegis.audit.events import AuditEvent
from aegis.audit.recorder import AuditRecorder
from aegis.authorization.catalog import IdentityKind, Role
from aegis.config.logs import Redactor, configure_logging
from aegis.config.settings import (
    CommonSettings,
    DatabaseSettings,
    Environment,
    LogLevel,
    load_token_pepper,
)
from aegis.db.engine import create_database_engine
from aegis.db.migrate import downgrade, upgrade
from aegis.identity.admin import IdentityAdministration, IssuedCredential

PEPPER = load_token_pepper(os.environ)


class FailingRecorder(AuditRecorder):
    def record(self, connection: Connection, event: AuditEvent) -> None:
        raise OperationalError("INSERT INTO aegis.audit_events", {}, Exception("audit store down"))


def _context(engine: Engine, recorder: AuditRecorder | None = None) -> ApiContext:
    return ApiContext(engine, PEPPER, recorder or AuditRecorder(Redactor([PEPPER.reveal()])))


@pytest.fixture
def client(app_engine: Engine) -> Iterator[TestClient]:
    app = create_app(_context(app_engine), Environment.TEST)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


@pytest.fixture
def log_output() -> Iterator[io.StringIO]:
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    stream = io.StringIO()
    configure_logging(
        CommonSettings(Environment.TEST, LogLevel.INFO), secrets=[PEPPER.reveal()], stream=stream
    )
    yield stream
    root.handlers[:] = handlers
    root.setLevel(level)


def _issue(owner_engine: Engine, *roles: Role) -> IssuedCredential:
    name = f"api-{uuid4().hex[:12]}"
    with owner_engine.begin() as connection:
        administration = IdentityAdministration(connection, AuditRecorder(Redactor()))
        administration.create_identity(name, IdentityKind.HUMAN, roles)
        return administration.issue_credential(name, PEPPER)


def _change(owner_engine: Engine, action: str, issued: IssuedCredential) -> None:
    with owner_engine.begin() as connection:
        administration = IdentityAdministration(connection, AuditRecorder(Redactor()))
        if action == "revoke":
            administration.revoke_credential(issued.credential_id)
        else:
            administration.disable_identity(issued.identity_name)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _auth_failures(owner_engine: Engine, request_id: str) -> list[tuple[object, ...]]:
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT source, outcome, actor_id, target_type, target_id, reason_code"
                " FROM aegis.audit_events WHERE event_type = 'auth.failed'"
                " AND request_id = :request_id"
            ),
            {"request_id": request_id},
        )
        return [tuple(row) for row in rows]


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


def test_a_cli_issued_token_is_accepted_by_v1_me(test_database: str, client: TestClient) -> None:
    name = f"cli-{uuid4().hex[:12]}"

    def cli(*args: str) -> str:
        result = subprocess.run(
            [sys.executable, "-m", "aegis.apps.cli", *args, "--database", test_database],
            env=dict(os.environ),
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout

    cli("identity", "create", name, "--kind", "human", "--role", "operator", "--role", "auditor")
    token = cli("credential", "issue", name).strip()

    response = client.get("/v1/me", headers=_bearer(token))

    assert response.status_code == 200
    body = response.json()
    assert (body["name"], body["kind"], body["roles"]) == (name, "human", ["auditor", "operator"])
    assert body["credential_id"] in cli("credential", "list", name)
    assert token not in response.text


def test_every_authentication_failure_gets_the_identical_401(
    owner_engine: Engine, client: TestClient
) -> None:
    revoked, disabled, valid = (_issue(owner_engine, Role.OPERATOR) for _ in range(3))
    _change(owner_engine, "revoke", revoked)
    _change(owner_engine, "disable", disabled)
    good = valid.token.reveal()
    attempts = {
        "missing": {},
        "malformed": {"Authorization": "Bearer nonsense"},
        "unknown": _bearer("aegis_pat_" + "a" * 26 + "_" + "b" * 52),
        "wrong secret": _bearer(good[:-1] + ("a" if good[-1] != "a" else "b")),
        "revoked": _bearer(revoked.token.reveal()),
        "disabled": _bearer(disabled.token.reveal()),
    }

    responses = {reason: client.get("/v1/me", headers=h) for reason, h in attempts.items()}

    assert client.get("/v1/me", headers=_bearer(good)).status_code == 200
    reference = responses["missing"]
    for reason, response in responses.items():
        assert response.status_code == 401, reason
        assert response.content == reference.content, reason
        assert response.headers["www-authenticate"] == "Bearer", reason


def test_only_failures_of_known_credentials_are_audited(
    owner_engine: Engine, client: TestClient
) -> None:
    issued = _issue(owner_engine, Role.AUDITOR)
    _change(owner_engine, "revoke", issued)

    known = client.get("/v1/me", headers=_bearer(issued.token.reveal()))
    unknown = client.get("/v1/me", headers=_bearer("aegis_pat_" + "c" * 26 + "_" + "d" * 52))
    malformed = client.get("/v1/me", headers={"Authorization": "Bearer nonsense"})

    assert _auth_failures(owner_engine, known.headers["x-request-id"]) == [
        ("api", "denied", None, "credential", str(issued.credential_id), "revoked")
    ]
    for response in (unknown, malformed):
        assert _auth_failures(owner_engine, response.headers["x-request-id"]) == []


def test_a_failed_audit_write_still_refuses_the_request(
    owner_engine: Engine, app_engine: Engine, log_output: io.StringIO
) -> None:
    issued = _issue(owner_engine)
    _change(owner_engine, "revoke", issued)
    app = create_app(_context(app_engine, FailingRecorder(Redactor())), Environment.TEST)

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/v1/me", headers=_bearer(issued.token.reveal()))

    assert response.status_code == 401
    assert '"level": "CRITICAL"' in log_output.getvalue()
    assert "could not record auth.failed" in log_output.getvalue()


def test_tokens_never_reach_the_logs(
    owner_engine: Engine, client: TestClient, log_output: io.StringIO
) -> None:
    valid, revoked = _issue(owner_engine), _issue(owner_engine)
    _change(owner_engine, "revoke", revoked)

    for issued in (valid, revoked):
        token = issued.token.reveal()
        client.get(f"/v1/me?token={token}", headers=_bearer(token))

    output = log_output.getvalue()
    assert '"reason": "revoked"' in output
    for issued in (valid, revoked):
        assert issued.token.reveal().rsplit("_", 1)[1] not in output


def test_readiness_reports_a_migrated_database(client: TestClient) -> None:
    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_readiness_fails_when_the_database_is_down(app_settings: DatabaseSettings) -> None:
    engine = create_database_engine(
        replace(app_settings, port=_free_port()), application_name="aegis-tests"
    )
    app = create_app(_context(engine), Environment.TEST)
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            ready = client.get("/health/ready")
            me = client.get("/v1/me", headers=_bearer("aegis_pat_" + "a" * 26 + "_" + "b" * 52))
            malformed = client.get("/v1/me", headers={"Authorization": "Bearer nonsense"})
    finally:
        engine.dispose()

    assert (ready.status_code, ready.json()["code"]) == (503, "not_ready")
    assert (me.status_code, me.json()["code"]) == (503, "service_unavailable")
    assert malformed.status_code == 401


def test_readiness_fails_when_migrations_are_behind(
    owner_engine: Engine, client: TestClient
) -> None:
    downgrade(owner_engine, "0002")
    try:
        response = client.get("/health/ready")
    finally:
        upgrade(owner_engine)

    assert (response.status_code, response.json()["code"]) == (503, "not_ready")


def test_the_api_process_listens_on_loopback_only(
    test_database: str, owner_engine: Engine, app_settings: DatabaseSettings
) -> None:
    port = _free_port()
    token = _issue(owner_engine).token.reveal()
    environ = {
        **os.environ,
        "AEGIS_ENV": "production",
        "AEGIS_API_PORT": str(port),
        "AEGIS_POSTGRES_DB": test_database,
    }
    process = subprocess.Popen(
        [sys.executable, "-m", "aegis.apps.api"],
        env=environ,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        base = f"http://127.0.0.1:{port}"
        live = _wait_until_live(base)
        listeners = _listeners(port)
        with httpx2.Client(base_url=base) as http:
            ready = http.get("/health/ready")
            docs = http.get("/docs")
            me = http.get("/v1/me", headers=_bearer(token))
    finally:
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=15)

    assert live.status_code == 200
    assert "server" not in live.headers
    assert listeners == {"127.0.0.1"}
    assert (ready.status_code, docs.status_code, me.status_code) == (200, 404, 200)
    assert process.returncode == 0
    output = stdout + stderr
    assert '"path": "/v1/me"' in output
    for secret in (token, PEPPER.reveal(), app_settings.password.reveal()):
        assert secret not in output


def _wait_until_live(base: str) -> httpx2.Response:
    deadline = time.monotonic() + 15
    while True:
        try:
            return httpx2.get(f"{base}/health/live")
        except httpx2.TransportError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.1)


def _listeners(port: int) -> set[str]:
    found = set()
    for table, family in (("/proc/net/tcp", "ipv4"), ("/proc/net/tcp6", "ipv6")):
        path = Path(table)
        if not path.exists():
            continue
        for line in path.read_text().splitlines()[1:]:
            local, state = line.split()[1], line.split()[3]
            address, _, hex_port = local.partition(":")
            if state == "0A" and int(hex_port, 16) == port:
                found.add("127.0.0.1" if address == "0100007F" else f"{family}:{address}")
    return found

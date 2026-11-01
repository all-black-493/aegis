from dataclasses import dataclass

from fastapi import Request
from sqlalchemy import Engine

from aegis.audit.recorder import AuditRecorder
from aegis.config.settings import Secret


@dataclass(frozen=True)
class ApiContext:
    engine: Engine
    pepper: Secret
    recorder: AuditRecorder


def api_context(request: Request) -> ApiContext:
    context: ApiContext = request.app.state.context
    return context


def request_id(request: Request) -> str:
    value: str = request.state.request_id
    return value

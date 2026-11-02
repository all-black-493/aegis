from dataclasses import dataclass, field

from fastapi import Request
from sqlalchemy import Engine

from aegis.audit.recorder import AuditRecorder
from aegis.config.settings import Secret
from aegis.tasks.service import TaskService


@dataclass(frozen=True)
class ApiContext:
    engine: Engine
    pepper: Secret
    recorder: AuditRecorder
    tasks: TaskService = field(init=False)

    def __post_init__(self) -> None:
        # One task service per application, shared by every request.
        object.__setattr__(self, "tasks", TaskService(self.engine, self.recorder))


def api_context(request: Request) -> ApiContext:
    context: ApiContext = request.app.state.context
    return context


def request_id(request: Request) -> str:
    value: str = request.state.request_id
    return value

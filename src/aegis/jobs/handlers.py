import threading
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any

from aegis.tasks.states import TaskKind

MAX_WAIT_SECONDS = 300


class RetryableError(Exception):
    pass


class HandlerContext:
    # The whole interface a handler gets: no database, settings or credentials (H6).
    def __init__(self, halt: threading.Event) -> None:
        self._halt = halt

    def stop_requested(self) -> bool:
        return self._halt.is_set()

    def wait(self, seconds: float) -> bool:
        return not self._halt.wait(seconds)


type Handler = Callable[[Mapping[str, Any], HandlerContext], Mapping[str, Any]]


def noop(task_input: Mapping[str, Any], context: HandlerContext) -> Mapping[str, Any]:
    if task_input:
        raise ValueError("noop takes no input")
    return {}


def wait(task_input: Mapping[str, Any], context: HandlerContext) -> Mapping[str, Any]:
    seconds = task_input.get("seconds")
    if (
        set(task_input) != {"seconds"}
        or not isinstance(seconds, int)
        or isinstance(seconds, bool)
        or not 0 <= seconds <= MAX_WAIT_SECONDS
    ):
        raise ValueError("wait takes {'seconds': n} with n from 0 to 300")
    context.wait(seconds)
    return {"waited_seconds": seconds}


REGISTRY: Mapping[TaskKind, Handler] = MappingProxyType({TaskKind.NOOP: noop, TaskKind.WAIT: wait})

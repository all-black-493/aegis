import re
from collections.abc import Mapping
from typing import Any

from aegis.tool_registry.model import ArgumentError

MAX_PATH_BYTES = 256
MAX_PATH_SEGMENTS = 8
_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")


def check_arguments(schema: Mapping[str, Any], arguments: Mapping[str, Any]) -> None:
    # The subset of JSON Schema the catalog uses, so no dependency decides what may run. Unknown
    # keys are always refused, and `maxLength` counts UTF-8 bytes, which is stricter.
    properties: Mapping[str, Mapping[str, Any]] = schema["properties"]
    if set(arguments) - set(properties) or set(schema["required"]) - set(arguments):
        raise ArgumentError("invalid_arguments")
    for key, value in arguments.items():
        limit = properties[key].get("maxLength")
        if (
            not isinstance(value, str)
            or "\x00" in value
            or (limit is not None and len(value.encode()) > limit)
        ):
            raise ArgumentError("invalid_arguments")


def workspace_path(raw: str) -> str:
    # Relative and already normal, so what is refused here never reaches the sandbox: the local
    # model proposes `/a.txt` for `a.txt` (ADR-0020). Symlinks are checked inside the sandbox.
    segments = raw.split("/")
    if (
        len(raw.encode()) > MAX_PATH_BYTES
        or len(segments) > MAX_PATH_SEGMENTS
        or any(s in (".", "..") or not _SEGMENT.fullmatch(s) for s in segments)
    ):
        raise ArgumentError("path_not_allowed")
    return raw

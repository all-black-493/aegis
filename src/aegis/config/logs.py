import json
import logging
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import IO

from aegis.config.settings import CommonSettings

REDACTED = "[REDACTED]"
MIN_SECRET_LENGTH = 8

_PATTERNS = (
    (re.compile(r"aegis_pat_[A-Za-z0-9_\-]+"), f"aegis_pat_{REDACTED}"),
    (
        re.compile(
            r"(?i)(\bauthorization\b[\"']?\s*[:=]\s*[\"']?)(?:(?:bearer|basic|token)\s+)?[^\s,;\"']+"
        ),
        rf"\1{REDACTED}",
    ),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+:)[^\s@/]+@"), rf"\1{REDACTED}@"),
    (
        re.compile(
            r"(?i)\b([a-z_]*(?:password|passwd|secret|token|pepper|api_?key)[a-z_]*[\"']?)"
            r"(\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
        ),
        rf"\1\2{REDACTED}",
    ),
)

_RECORD_ATTRIBUTES = frozenset(vars(logging.makeLogRecord({}))) | {
    "message",
    "asctime",
    "color_message",
}


class Redactor:
    def __init__(self, secrets: Iterable[str] = ()) -> None:
        values = set(secrets)
        if any(len(value) < MIN_SECRET_LENGTH for value in values):
            raise ValueError(
                f"secrets shorter than {MIN_SECRET_LENGTH} characters cannot be redacted"
            )
        self._secrets = tuple(sorted(values, key=len, reverse=True))

    def redact(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, REDACTED)
        for pattern, replacement in _PATTERNS:
            text = pattern.sub(replacement, text)
        return text


class JsonFormatter(logging.Formatter):
    def __init__(self, redactor: Redactor) -> None:
        super().__init__()
        self._redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _RECORD_ATTRIBUTES and not key.startswith("_"):
                entry[key] = value
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            entry["stack"] = self.formatStack(record.stack_info)
        return json.dumps(self._clean(entry))

    def _clean(self, value: object) -> object:
        if isinstance(value, str):
            return self._redactor.redact(value)
        if isinstance(value, bool | int | float) or value is None:
            return value
        if isinstance(value, dict):
            return {str(key): self._clean(item) for key, item in value.items()}
        if isinstance(value, list | tuple | set | frozenset):
            return [self._clean(item) for item in value]
        return self._redactor.redact(str(value))


def configure_logging(
    settings: CommonSettings, *, secrets: Iterable[str] = (), stream: IO[str] | None = None
) -> None:
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter(Redactor(secrets)))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(settings.log_level.value)

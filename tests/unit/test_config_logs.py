import io
import json
import logging
from collections.abc import Iterator

import pytest

from aegis.config.logs import REDACTED, JsonFormatter, Redactor, configure_logging
from aegis.config.settings import CommonSettings, Environment, LogLevel

SECRET = "registered-secret-value-1234567890"


class Leaky:
    def __str__(self) -> str:
        return f"object holding {SECRET}"


@pytest.fixture
def capture() -> Iterator[tuple[logging.Logger, io.StringIO]]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter(Redactor([SECRET])))
    logger = logging.getLogger("aegis.test.logs")
    logger.handlers[:] = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    yield logger, stream
    logger.handlers.clear()


@pytest.fixture
def restore_root_logger() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


def entries(stream: io.StringIO) -> list[dict[str, object]]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def test_each_record_is_one_json_object(capture: tuple[logging.Logger, io.StringIO]) -> None:
    logger, stream = capture

    logger.info("hello %s", "world", extra={"task_id": "t-1", "attempt": 2})

    [entry] = entries(stream)
    assert entry["level"] == "INFO"
    assert entry["logger"] == "aegis.test.logs"
    assert entry["message"] == "hello world"
    assert entry["task_id"] == "t-1"
    assert entry["attempt"] == 2
    assert str(entry["timestamp"]).endswith("+00:00")


def test_terminal_colour_variants_are_dropped(capture: tuple[logging.Logger, io.StringIO]) -> None:
    logger, stream = capture

    logger.info("started", extra={"color_message": "\x1b[36mstarted\x1b[0m"})

    [entry] = entries(stream)
    assert "color_message" not in entry


def test_newlines_cannot_forge_extra_log_lines(capture: tuple[logging.Logger, io.StringIO]) -> None:
    logger, stream = capture

    logger.info('first\n{"level": "ERROR", "message": "forged"}')

    assert len(stream.getvalue().splitlines()) == 1


def test_registered_secrets_are_redacted_everywhere(
    capture: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = capture

    logger.info("message %s", SECRET, extra={"detail": SECRET, "nested": {"list": [SECRET]}})
    logger.info("object", extra={"value": Leaky()})
    try:
        raise RuntimeError(f"failure {SECRET}")
    except RuntimeError:
        logger.exception("caught")

    output = stream.getvalue()
    assert SECRET not in output
    assert output.count(REDACTED) >= 5


@pytest.mark.parametrize(
    ("text", "sensitive"),
    [
        ("Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
        ("authorization=token123456", "token123456"),
        ("using aegis_pat_ABCDEF_0123456789abcdef", "ABCDEF_0123456789abcdef"),
        ("postgresql://aegis:hunter2secret@127.0.0.1:5433/aegis", "hunter2secret"),
        ("AEGIS_POSTGRES_PASSWORD=hunter2secret", "hunter2secret"),
        ('password: "hunter2 secret"', "hunter2 secret"),
        ("api_key=hunter2secret", "hunter2secret"),
    ],
)
def test_credential_patterns_are_redacted(
    capture: tuple[logging.Logger, io.StringIO], text: str, sensitive: str
) -> None:
    logger, stream = capture

    logger.warning(text)

    assert sensitive not in stream.getvalue()
    assert REDACTED in stream.getvalue()


def test_secrets_too_short_to_redact_are_refused() -> None:
    with pytest.raises(ValueError, match="cannot be redacted"):
        Redactor(["short"])


@pytest.mark.usefixtures("restore_root_logger")
def test_configure_logging_installs_one_redacting_json_handler() -> None:
    stream = io.StringIO()
    settings = CommonSettings(Environment.DEVELOPMENT, LogLevel.INFO)

    configure_logging(settings, secrets=[SECRET], stream=stream)
    configure_logging(settings, secrets=[SECRET], stream=stream)
    logging.getLogger("aegis.example").debug("hidden")
    logging.getLogger("aegis.example").info("shown %s", SECRET)

    assert len(logging.getLogger().handlers) == 1
    [entry] = entries(stream)
    assert entry["message"] == f"shown {REDACTED}"

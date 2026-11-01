from uuid import uuid4

import pytest

from aegis.audit.events import (
    ALLOWED_DETAILS,
    EVENT_TYPE_PATTERN,
    MAX_DETAIL_TEXT,
    ActorKind,
    AuditEvent,
    AuditEventError,
    AuditEventType,
    Outcome,
    Source,
)
from aegis.audit.recorder import AuditRecorder
from aegis.config.logs import REDACTED, Redactor

SECRET = "registered-secret-value-1234567890"


def event(**overrides: object) -> AuditEvent:
    values: dict[str, object] = {
        "event_type": AuditEventType.TASK_CREATED,
        "source": Source.API,
        "outcome": Outcome.SUCCESS,
        "details": {"kind": "noop"},
    }
    values.update(overrides)
    return AuditEvent(**values)  # type: ignore[arg-type]


def test_every_event_type_has_a_detail_allowlist() -> None:
    assert set(ALLOWED_DETAILS) == set(AuditEventType)


def test_event_type_names_match_the_database_constraint() -> None:
    for event_type in AuditEventType:
        assert EVENT_TYPE_PATTERN.fullmatch(event_type.value)
        assert len(event_type.value) <= 64


def test_details_are_copied_and_immutable() -> None:
    details: dict[str, str | int | bool | None] = {"kind": "noop"}
    recorded = event(details=details)
    details["kind"] = "changed"

    assert recorded.details["kind"] == "noop"
    with pytest.raises(TypeError):
        recorded.details["kind"] = "other"  # type: ignore[index]


def test_each_event_gets_its_own_id() -> None:
    assert event().event_id != event().event_id


def test_unknown_detail_keys_are_rejected_by_name_only() -> None:
    with pytest.raises(AuditEventError, match="does not allow details: password") as excinfo:
        event(details={"kind": "noop", "password": SECRET})

    assert SECRET not in str(excinfo.value)


@pytest.mark.parametrize("value", [{"nested": 1}, ["list"], 1.5, b"bytes"])
def test_detail_values_must_be_scalars(value: object) -> None:
    with pytest.raises(AuditEventError, match="must be a string, integer, boolean or null"):
        event(details={"kind": value})


def test_oversized_detail_is_rejected_without_echoing_it() -> None:
    oversized = SECRET * 10
    assert len(oversized) > MAX_DETAIL_TEXT

    with pytest.raises(AuditEventError, match="exceeds") as excinfo:
        event(details={"kind": oversized})

    assert SECRET not in str(excinfo.value)


@pytest.mark.parametrize(
    "overrides",
    [
        {"actor_id": uuid4()},
        {"actor_kind": ActorKind.HUMAN},
        {"target_type": "task"},
        {"target_id": "x"},
    ],
)
def test_paired_fields_must_be_given_together(overrides: dict[str, object]) -> None:
    with pytest.raises(AuditEventError, match="must be given together"):
        event(**overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {"reason_code": "Bad Code"},
        {"request_id": "has space"},
        {"target_type": "Task!", "target_id": "x"},
        {"target_type": "task", "target_id": ""},
        {"policy_version": "x" * 65},
    ],
)
def test_malformed_fields_are_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(AuditEventError):
        event(**overrides)


def test_recorder_redacts_secrets_and_credentials_before_storage() -> None:
    recorder = AuditRecorder(Redactor([SECRET]))

    row = recorder.row(
        event(
            event_type=AuditEventType.IDENTITY_CREATED,
            details={"kind": "human", "name": f"named {SECRET}"},
            target_type="identity",
            target_id="token=abc123def456",
        )
    )

    assert SECRET not in str(row)
    assert "abc123def456" not in str(row)
    assert row["details"] == {"kind": "human", "name": f"named {REDACTED}"}


def test_recorder_stores_enum_values() -> None:
    actor = uuid4()
    row = AuditRecorder(Redactor()).row(
        event(actor_id=actor, actor_kind=ActorKind.SERVICE, outcome=Outcome.DENIED)
    )

    assert (row["event_type"], row["source"], row["outcome"]) == ("task.created", "api", "denied")
    assert (row["actor_id"], row["actor_kind"]) == (actor, "service")

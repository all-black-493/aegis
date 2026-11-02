import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID, uuid4

MAX_DETAIL_TEXT = 256
EVENT_TYPE_PATTERN = re.compile(r"[a-z]+(_[a-z]+)*\.[a-z]+(_[a-z]+)*")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_TARGET_TYPE = re.compile(r"[a-z][a-z_]{0,63}")
_REQUEST_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")

type DetailValue = str | int | bool | None


class AuditEventType(StrEnum):
    AUTH_FAILED = "auth.failed"
    CREDENTIAL_ISSUED = "credential.issued"
    CREDENTIAL_REVOKED = "credential.revoked"
    CREDENTIAL_LISTED = "credential.listed"
    IDENTITY_CREATED = "identity.created"
    IDENTITY_DISABLED = "identity.disabled"
    IDENTITY_ENABLED = "identity.enabled"
    ROLE_GRANTED = "role.granted"
    ROLE_REVOKED = "role.revoked"
    AUTHZ_DENIED = "authz.denied"
    SECURITY_DECISION = "security.decision"
    TASK_CREATED = "task.created"
    TASK_TRANSITIONED = "task.transitioned"
    TASK_CANCEL_REQUESTED = "task.cancel_requested"
    TASK_READ_PRIVILEGED = "task.read_privileged"
    JOB_FAILED = "job.failed"
    JOB_INTERRUPTED = "job.interrupted"
    JOB_RETRIED = "job.retried"
    JOB_FENCE_LOST = "job.fence_lost"
    MODEL_GENERATED = "model.generated"
    SANDBOX_CREATED = "sandbox.created"
    SANDBOX_DELETED = "sandbox.deleted"


class Source(StrEnum):
    API = "api"
    WORKER = "worker"
    CLI = "cli"
    SYSTEM = "system"


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class ActorKind(StrEnum):
    HUMAN = "human"
    SERVICE = "service"
    SYSTEM = "system"


ALLOWED_DETAILS: Mapping[AuditEventType, frozenset[str]] = MappingProxyType(
    {
        AuditEventType.AUTH_FAILED: frozenset(),
        AuditEventType.CREDENTIAL_ISSUED: frozenset({"expires_at"}),
        AuditEventType.CREDENTIAL_REVOKED: frozenset(),
        AuditEventType.CREDENTIAL_LISTED: frozenset(),
        AuditEventType.IDENTITY_CREATED: frozenset({"kind", "name"}),
        AuditEventType.IDENTITY_DISABLED: frozenset(),
        AuditEventType.IDENTITY_ENABLED: frozenset(),
        AuditEventType.ROLE_GRANTED: frozenset({"role"}),
        AuditEventType.ROLE_REVOKED: frozenset({"role"}),
        AuditEventType.AUTHZ_DENIED: frozenset({"action"}),
        AuditEventType.SECURITY_DECISION: frozenset({"action", "effect", "stage"}),
        AuditEventType.TASK_CREATED: frozenset({"kind"}),
        AuditEventType.TASK_TRANSITIONED: frozenset({"from_state", "to_state"}),
        AuditEventType.TASK_CANCEL_REQUESTED: frozenset(),
        AuditEventType.TASK_READ_PRIVILEGED: frozenset({"scope"}),
        AuditEventType.JOB_FAILED: frozenset({"attempt", "error_code"}),
        AuditEventType.JOB_INTERRUPTED: frozenset({"attempt"}),
        AuditEventType.JOB_RETRIED: frozenset({"attempt", "run_after"}),
        AuditEventType.JOB_FENCE_LOST: frozenset({"attempt"}),
        AuditEventType.MODEL_GENERATED: frozenset(
            {
                "provider",
                "model",
                "model_digest",
                "runtime_version",
                "prompt_tokens",
                "output_tokens",
                "duration_ms",
                "finish_reason",
            }
        ),
        AuditEventType.SANDBOX_CREATED: frozenset(
            {
                "sandbox_id",
                "runtime_version",
                "image",
                "policy_version",
                "policy_fingerprint",
                "policy_hash",
                "prover_result",
            }
        ),
        AuditEventType.SANDBOX_DELETED: frozenset({"task", "job"}),
    }
)


class AuditEventError(ValueError):
    pass


@dataclass(frozen=True)
class AuditEvent:
    event_type: AuditEventType
    source: Source
    outcome: Outcome
    actor_id: UUID | None = None
    actor_kind: ActorKind | None = None
    target_type: str | None = None
    target_id: str | None = None
    task_id: UUID | None = None
    job_id: UUID | None = None
    decision_id: UUID | None = None
    request_id: str | None = None
    reason_code: str | None = None
    policy_version: str | None = None
    details: Mapping[str, DetailValue] = field(default_factory=dict)
    event_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        unknown = sorted(set(self.details) - ALLOWED_DETAILS[self.event_type])
        if unknown:
            raise AuditEventError(f"{self.event_type} does not allow details: {', '.join(unknown)}")
        for key, value in self.details.items():
            if isinstance(value, str):
                if len(value) > MAX_DETAIL_TEXT:
                    raise AuditEventError(f"detail {key} exceeds {MAX_DETAIL_TEXT} characters")
            elif not isinstance(value, int) and value is not None:
                raise AuditEventError(f"detail {key} must be a string, integer, boolean or null")
        if (self.actor_id is None) != (self.actor_kind is None):
            raise AuditEventError("actor_id and actor_kind must be given together")
        if (self.target_type is None) != (self.target_id is None):
            raise AuditEventError("target_type and target_id must be given together")
        _check("target_type", self.target_type, _TARGET_TYPE)
        _check("reason_code", self.reason_code, _CODE)
        _check("request_id", self.request_id, _REQUEST_ID)
        if self.target_id is not None and not 1 <= len(self.target_id) <= 128:
            raise AuditEventError("target_id must be 1 to 128 characters")
        if self.policy_version is not None and not 1 <= len(self.policy_version) <= 64:
            raise AuditEventError("policy_version must be 1 to 64 characters")
        object.__setattr__(self, "details", MappingProxyType(dict(self.details)))


def _check(name: str, value: str | None, pattern: re.Pattern[str]) -> None:
    if value is not None and not pattern.fullmatch(value):
        raise AuditEventError(f"{name} has an invalid format")

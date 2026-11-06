import hashlib
import tempfile
from collections.abc import Callable, Collection, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType

from aegis.runtime.contract import (
    ProverVerdict,
    RuntimeRefusedError,
    RuntimeUnavailableError,
    Sandbox,
    SandboxRuntime,
    SandboxRuntimeError,
    SandboxSpec,
)

# Bump with any change to the files below; the fingerprint test fails until both change together.
SANDBOX_POLICY_VERSION = "2026.11.07-1"
POLICY_DIR = Path(__file__).resolve().parents[3] / "deploy" / "openshell"
POLICY_FILES = (
    "boundary.yaml",
    "probe.yaml",
    "agent-boundary.yaml",
    "agent.yaml",
    "probe/Dockerfile",
)
# Written into the image by deploy/openshell/probe/Dockerfile.
RELEASE_FILE = "/etc/aegis-probe-release"
RELEASE = "aegis-openshell-probe 3"

type DetailValue = str | int | None


class SandboxEventKind(StrEnum):
    CREATED = "created"
    DELETED = "deleted"


@dataclass(frozen=True)
class SandboxEvent:
    kind: SandboxEventKind
    name: str
    succeeded: bool
    reason: str
    details: Mapping[str, DetailValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", MappingProxyType(dict(self.details)))


type EventSink = Callable[[SandboxEvent], None]


@dataclass(frozen=True)
class SandboxProfile:
    name: str
    policy: str
    boundary: str


PROBE_PROFILE = SandboxProfile("probe", "probe.yaml", "boundary.yaml")
AGENT_PROFILE = SandboxProfile("agent", "agent.yaml", "agent-boundary.yaml")


@dataclass(frozen=True)
class AdmittedSandbox:
    # What the gate hands over once a sandbox is proven, for the length of its block.
    sandbox: Sandbox
    profile: SandboxProfile


@dataclass(frozen=True)
class SandboxPolicies:
    directory: Path
    version: str
    fingerprint: str


def load_policies(directory: Path = POLICY_DIR) -> SandboxPolicies:
    digest = hashlib.sha256(SANDBOX_POLICY_VERSION.encode())
    for name in POLICY_FILES:
        try:
            content = (directory / name).read_bytes()
        except OSError:
            raise RuntimeRefusedError(f"{name} is missing", code="policy_missing") from None
        digest.update(b"\0" + name.encode() + b"\0" + content)
    return SandboxPolicies(directory, SANDBOX_POLICY_VERSION, digest.hexdigest())


class SandboxGate:
    # A sandbox is admitted only after the runtime is healthy, the submitted policy is proven
    # within the boundary, the sandbox's effective policy is proven again, and the image is
    # recognised. It is deleted when the block ends, whatever happened (ADR-0017).
    def __init__(
        self,
        runtime: SandboxRuntime,
        policies: SandboxPolicies,
        image: str | None,
        on_event: EventSink,
        profile: SandboxProfile = PROBE_PROFILE,
    ) -> None:
        self._runtime = runtime
        self._policies = policies
        self._image = image
        self._on_event = on_event
        self._profile = profile

    @contextmanager
    def open(self, name: str, labels: Mapping[str, str]) -> Iterator[AdmittedSandbox]:
        if self._image is None:
            raise RuntimeRefusedError("no probe image is configured", code="image_missing")
        status = self._runtime.check()
        if not status.healthy:
            error = RuntimeUnavailableError if status.retryable else RuntimeRefusedError
            raise error("the runtime is not usable", code=status.detail)
        policy = self._policies.directory / self._profile.policy
        self._prove(policy, "policy_refused")
        sandbox = self._runtime.create(SandboxSpec(name, self._image, policy, labels))
        reason = "refused"
        try:
            verdict = self._prove_effective(name)
            self._check_release(name)
            self._on_event(
                SandboxEvent(
                    SandboxEventKind.CREATED,
                    name,
                    True,
                    "verified",
                    {
                        "sandbox_id": sandbox.sandbox_id,
                        "runtime_version": status.version,
                        "profile": self._profile.name,
                        "image": self._image,
                        "policy_version": self._policies.version,
                        "policy_fingerprint": self._policies.fingerprint,
                        "policy_hash": sandbox.policy_hash,
                        "prover_result": verdict.result.value,
                    },
                )
            )
            reason = "aborted"
            yield AdmittedSandbox(sandbox, self._profile)
            reason = "completed"
        finally:
            self._delete(name, reason)

    def _prove(self, candidate: Path, code: str) -> ProverVerdict:
        boundary = self._policies.directory / self._profile.boundary
        verdict = self._runtime.check_policy(candidate, boundary)
        if not verdict.passed:
            raise RuntimeRefusedError(
                f"the policy is not proven within the boundary: {verdict.result.value}", code=code
            )
        return verdict

    def _prove_effective(self, name: str) -> ProverVerdict:
        # Providers, baseline paths or a global policy can change what a sandbox enforces, so
        # the policy it actually runs under is proven, not the file that was submitted.
        with tempfile.TemporaryDirectory(prefix="aegis-policy-") as directory:
            effective = Path(directory) / "effective.yaml"
            effective.write_text(self._runtime.effective_policy(name))
            return self._prove(effective, "effective_policy_refused")

    def _check_release(self, name: str) -> None:
        result = self._runtime.exec(name, ["/usr/bin/cat", RELEASE_FILE], 10)
        if result.exit_code != 0 or result.stdout.strip() != RELEASE:
            raise RuntimeRefusedError("the image is not AEGIS's probe", code="image_unrecognised")

    def _delete(self, name: str, reason: str) -> None:
        try:
            self._runtime.delete(name)
        except SandboxRuntimeError as error:
            # The sandbox outlives the attempt; orphan cleanup will remove it (ADR-0017).
            self._on_event(SandboxEvent(SandboxEventKind.DELETED, name, False, error.code))
            return
        self._on_event(SandboxEvent(SandboxEventKind.DELETED, name, True, reason))


def clean_orphans(
    runtime: SandboxRuntime, live_jobs: Callable[[], Collection[str]], on_event: EventSink
) -> int:
    sandboxes = runtime.managed()
    # Read after listing: a job is running before its sandbox exists, so the job of every listed
    # sandbox that is still in use is found, however the two calls interleave with a claim.
    live = live_jobs()
    deleted = 0
    for sandbox in sandboxes:
        if sandbox.labels.get("aegis.job") in live:
            continue
        details = {key: sandbox.labels.get(f"aegis.{key}") for key in ("task", "job")}
        try:
            runtime.delete(sandbox.name)
        except SandboxRuntimeError as error:
            on_event(
                SandboxEvent(SandboxEventKind.DELETED, sandbox.name, False, error.code, details)
            )
            continue
        on_event(SandboxEvent(SandboxEventKind.DELETED, sandbox.name, True, "orphaned", details))
        deleted += 1
    return deleted

import re
import shutil
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

import pytest

from aegis.runtime.contract import (
    REQUIRED_PROVER_DOMAINS,
    ExecResult,
    ProverResult,
    ProverVerdict,
    RuntimeRefusedError,
    RuntimeStatus,
    RuntimeUnavailableError,
    Sandbox,
    SandboxSpec,
)
from aegis.runtime.gate import (
    POLICY_DIR,
    RELEASE,
    SandboxEvent,
    SandboxEventKind,
    SandboxGate,
    clean_orphans,
    load_policies,
)

PINNED_VERSION = "2026.11.02-1"
PINNED_FINGERPRINT = "4a1b151f93f5322f94f7531ac66e3ea5f59d196a32cea278c377a1eeb89b4f66"
IMAGE = "sha256:" + "a" * 64
PASS = ProverVerdict(ProverResult.WITHIN_BOUNDARY, frozenset(REQUIRED_PROVER_DOMAINS))


@dataclass
class FakeRuntime:
    # An in-process runtime: every call is recorded, and each answer can be scripted.
    status: RuntimeStatus = field(default_factory=lambda: RuntimeStatus(True, "ok", "0.1.6"))
    verdicts: list[ProverVerdict] = field(default_factory=lambda: [PASS, PASS])
    effective: str = "version: 1\n"
    release: str = RELEASE + "\n"
    delete_error: Exception | None = None
    calls: list[str] = field(default_factory=list)
    specs: list[SandboxSpec] = field(default_factory=list)
    live: dict[str, Sandbox] = field(default_factory=dict)
    checked: list[str] = field(default_factory=list)

    def check(self) -> RuntimeStatus:
        self.calls.append("check")
        return self.status

    def create(self, spec: SandboxSpec) -> Sandbox:
        self.calls.append("create")
        self.specs.append(spec)
        labels = MappingProxyType({**spec.labels, "aegis.managed": "true"})
        self.live[spec.name] = Sandbox(spec.name, "id-1", "Ready", "ab" * 32, labels)
        return self.live[spec.name]

    def get(self, name: str) -> Sandbox | None:
        return self.live.get(name)

    def exec(self, name: str, argv: Sequence[str], timeout_seconds: int) -> ExecResult:
        self.calls.append("exec " + " ".join(argv))
        return ExecResult(0, self.release, "")

    def effective_policy(self, name: str) -> str:
        self.calls.append("effective_policy")
        return self.effective

    def delete(self, name: str) -> None:
        self.calls.append("delete")
        if self.delete_error is not None:
            raise self.delete_error
        self.live.pop(name, None)

    def managed(self) -> tuple[Sandbox, ...]:
        return tuple(self.live.values())

    def check_policy(self, candidate: Path, boundary: Path) -> ProverVerdict:
        self.calls.append("check_policy")
        self.checked.append(candidate.read_text())
        return self.verdicts.pop(0)


@pytest.fixture
def runtime() -> FakeRuntime:
    return FakeRuntime()


def _gate(
    runtime: FakeRuntime, events: list[SandboxEvent], image: str | None = IMAGE
) -> SandboxGate:
    return SandboxGate(runtime, load_policies(), image, events.append)


def test_the_sandbox_policies_are_pinned() -> None:
    policies = load_policies()

    assert (policies.version, policies.fingerprint) == (PINNED_VERSION, PINNED_FINGERPRINT)


@pytest.mark.parametrize("name", ["boundary.yaml", "probe.yaml"])
def test_the_policies_require_landlock_a_non_root_user_and_no_network(name: str) -> None:
    text = (POLICY_DIR / name).read_text()

    assert "compatibility: hard_requirement" in text
    assert 'run_as_user: "2000"' in text
    assert 'run_as_group: "2000"' in text
    assert "network_policies" not in text
    assert "include_workdir: false" in text


def test_the_probe_image_is_built_offline_from_a_pinned_base_as_a_non_root_user() -> None:
    dockerfile = (POLICY_DIR / "probe" / "Dockerfile").read_text()

    assert re.search(r"^FROM ubuntu@sha256:[0-9a-f]{64}$", dockerfile, re.MULTILINE)
    assert re.search(r"^USER 2000:2000$", dockerfile, re.MULTILINE)
    for fetch in ("apt", "curl", "wget", "ADD http"):
        assert fetch not in dockerfile


def test_missing_policy_files_are_refused(tmp_path: Path) -> None:
    shutil.copy(POLICY_DIR / "boundary.yaml", tmp_path / "boundary.yaml")

    with pytest.raises(RuntimeRefusedError) as refused:
        load_policies(tmp_path)

    assert refused.value.code == "policy_missing"


def test_an_admitted_sandbox_is_proven_twice_recognised_audited_and_deleted(
    runtime: FakeRuntime,
) -> None:
    events: list[SandboxEvent] = []

    with _gate(runtime, events).open("aegis-probe-1", {"aegis.task": "t1"}) as sandbox:
        assert sandbox.name == "aegis-probe-1"
        assert [event.kind for event in events] == [SandboxEventKind.CREATED]

    assert runtime.calls == [
        "check",
        "check_policy",
        "create",
        "effective_policy",
        "check_policy",
        "exec /usr/bin/cat /etc/aegis-probe-release",
        "delete",
    ]
    [spec] = runtime.specs
    assert (spec.image, spec.policy, dict(spec.labels)) == (
        IMAGE,
        POLICY_DIR / "probe.yaml",
        {"aegis.task": "t1"},
    )
    assert runtime.checked[1] == runtime.effective
    created, deleted = events
    assert (created.succeeded, created.reason) == (True, "verified")
    assert dict(created.details) == {
        "sandbox_id": "id-1",
        "runtime_version": "0.1.6",
        "image": IMAGE,
        "policy_version": PINNED_VERSION,
        "policy_fingerprint": PINNED_FINGERPRINT,
        "policy_hash": "ab" * 32,
        "prover_result": "within_boundary",
    }
    assert (deleted.kind, deleted.succeeded, deleted.reason) == (
        SandboxEventKind.DELETED,
        True,
        "completed",
    )
    assert runtime.live == {}


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"status": RuntimeStatus(False, "global_policy_active")}, "global_policy_active"),
        (
            {"verdicts": [ProverVerdict(ProverResult.EXCEEDS_BOUNDARY, frozenset())]},
            "policy_refused",
        ),
        ({"verdicts": [ProverVerdict(ProverResult.UNSUPPORTED, frozenset())]}, "policy_refused"),
        ({"verdicts": [ProverVerdict(ProverResult.INCONCLUSIVE, frozenset())]}, "policy_refused"),
        ({"verdicts": [ProverVerdict(ProverResult.ERROR, frozenset())]}, "policy_refused"),
    ],
)
def test_nothing_is_created_unless_the_runtime_and_the_submitted_policy_pass(
    change: dict[str, object], code: str
) -> None:
    runtime = FakeRuntime(**change)  # type: ignore[arg-type]
    events: list[SandboxEvent] = []

    with pytest.raises(RuntimeRefusedError) as refused, _gate(runtime, events).open("aegis-p", {}):
        pytest.fail("the block must not run")

    assert refused.value.code == code
    assert "create" not in runtime.calls
    assert events == []


def test_no_image_means_no_sandbox(runtime: FakeRuntime) -> None:
    events: list[SandboxEvent] = []

    with (
        pytest.raises(RuntimeRefusedError) as refused,
        _gate(runtime, events, None).open("aegis-p", {}),
    ):
        pytest.fail("the block must not run")

    assert refused.value.code == "image_missing"
    assert runtime.calls == []


@pytest.mark.parametrize(
    ("change", "code"),
    [
        (
            {"verdicts": [PASS, ProverVerdict(ProverResult.EXCEEDS_BOUNDARY, frozenset())]},
            "effective_policy_refused",
        ),
        (
            {"verdicts": [PASS, ProverVerdict(ProverResult.WITHIN_BOUNDARY, frozenset())]},
            "effective_policy_refused",
        ),
        ({"release": "something else\n"}, "image_unrecognised"),
    ],
)
def test_a_sandbox_that_fails_after_creation_is_deleted_unused(
    change: dict[str, object], code: str
) -> None:
    runtime = FakeRuntime(**change)  # type: ignore[arg-type]
    events: list[SandboxEvent] = []

    with pytest.raises(RuntimeRefusedError) as refused, _gate(runtime, events).open("aegis-p", {}):
        pytest.fail("the block must not run")

    assert refused.value.code == code
    assert runtime.live == {}
    [deleted] = events
    assert (deleted.kind, deleted.succeeded, deleted.reason) == (
        SandboxEventKind.DELETED,
        True,
        "refused",
    )


def test_a_failure_inside_the_block_still_deletes_the_sandbox(runtime: FakeRuntime) -> None:
    events: list[SandboxEvent] = []

    with (
        pytest.raises(ValueError, match="probe failed"),
        _gate(runtime, events).open("aegis-p", {}),
    ):
        raise ValueError("probe failed")

    assert runtime.live == {}
    assert events[-1].reason == "aborted"


def test_a_creation_that_cannot_be_audited_is_deleted(runtime: FakeRuntime) -> None:
    def refuse(event: SandboxEvent) -> None:
        if event.kind is SandboxEventKind.CREATED:
            raise OSError("the audit store is down")

    gate = SandboxGate(runtime, load_policies(), IMAGE, refuse)

    with pytest.raises(OSError, match="audit store is down"), gate.open("aegis-p", {}):
        pytest.fail("the block must not run")

    assert runtime.live == {}


def test_a_failed_deletion_is_reported_not_raised() -> None:
    runtime = FakeRuntime(delete_error=RuntimeUnavailableError(code="delete_pending"))
    events: list[SandboxEvent] = []

    with _gate(runtime, events).open("aegis-p", {}):
        pass

    assert (events[-1].succeeded, events[-1].reason) == (False, "delete_pending")


def test_orphans_are_deleted_unless_in_use(runtime: FakeRuntime) -> None:
    for name, job in (("aegis-live", "j-live"), ("aegis-dead", "j-dead"), ("aegis-bare", None)):
        labels = {"aegis.managed": "true", **({"aegis.job": job} if job else {})}
        runtime.live[name] = Sandbox(name, name, "Ready", None, labels)
    events: list[SandboxEvent] = []

    deleted = clean_orphans(runtime, lambda s: s.labels.get("aegis.job") == "j-live", events.append)

    assert deleted == 2
    assert set(runtime.live) == {"aegis-live"}
    assert {(e.name, e.reason, e.details["job"]) for e in events} == {
        ("aegis-dead", "orphaned", "j-dead"),
        ("aegis-bare", "orphaned", None),
    }

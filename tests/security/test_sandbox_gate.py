from pathlib import Path
from typing import Any

import pytest

from aegis.runtime.contract import REQUIRED_PROVER_DOMAINS, RuntimeRefusedError, Sandbox
from aegis.runtime.gate import (
    RELEASE,
    SandboxEvent,
    SandboxEventKind,
    SandboxGate,
    clean_orphans,
    load_policies,
)
from tests.fixtures.fake_openshell import FakeOpenShell

IMAGE = "sha256:" + "d" * 64
PASSING = {
    "result": "within_boundary",
    "exit_code": 0,
    "coverage": {"domains": sorted(REQUIRED_PROVER_DOMAINS)},
    "counterexample": None,
    "reason_code": None,
}
WIDENED = """version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr, /lib, /etc, /proc, /dev/urandom]
  read_write: [/tmp, /dev/null]
landlock:
  compatibility: hard_requirement
process:
  run_as_user: "2000"
  run_as_group: "2000"
network_policies:
  github:
    endpoints: [{host: api.github.com, port: 443}]
    binaries: [{path: /usr/bin/curl}]
"""


@pytest.fixture
def fake(tmp_path: Path) -> FakeOpenShell:
    fake = FakeOpenShell(tmp_path / "bin")
    fake.update(exec={"/usr/bin/cat /etc/aegis-probe-release": {"stdout": RELEASE + "\n"}})
    return fake


def _open(fake: FakeOpenShell, events: list[SandboxEvent]) -> None:
    gate = SandboxGate(fake.runtime(), load_policies(), IMAGE, events.append)
    with gate.open("aegis-probe-1", {}):
        pytest.fail("a refused sandbox must never be used")


@pytest.mark.parametrize(
    "verdict",
    [
        {"result": "exceeds_boundary", "exit_code": 1, "counterexample": {"domain": "landlock"}},
        {"result": "unsupported", "exit_code": 3, "reason_code": "unresolved_filesystem_path"},
        {"result": "inconclusive", "exit_code": 3, "reason_code": "solver_timeout"},
        {"result": "error", "exit_code": 2, "reason_code": "invalid_policy"},
        {"coverage": {"domains": ["filesystem", "process"]}},
    ],
)
def test_a_submitted_policy_that_is_not_proven_never_creates_a_sandbox(
    fake: FakeOpenShell, verdict: dict[str, Any]
) -> None:
    fake.update(verdict={**PASSING, **verdict})
    events: list[SandboxEvent] = []

    with pytest.raises(RuntimeRefusedError) as refused:
        _open(fake, events)

    assert refused.value.code == "policy_refused"
    assert ("openshell", "sandbox", "create") not in fake.commands()
    assert fake.state["sandboxes"] == {}
    assert events == []


def test_an_effective_policy_widened_by_a_provider_is_refused_and_deleted(
    fake: FakeOpenShell,
) -> None:
    exceeds = {**PASSING, "result": "exceeds_boundary", "exit_code": 1}
    fake.update(effective_policy=WIDENED, verdict_sequence=[PASSING, exceeds])
    events: list[SandboxEvent] = []

    with pytest.raises(RuntimeRefusedError) as refused:
        _open(fake, events)

    assert refused.value.code == "effective_policy_refused"
    submitted, effective = fake.state["proven"]
    assert "network_policies" not in submitted
    assert effective == WIDENED + "\n"
    assert fake.state["sandboxes"] == {}
    assert [(e.kind, e.reason) for e in events] == [(SandboxEventKind.DELETED, "refused")]


def test_a_global_policy_stops_the_gate_before_anything_is_created(fake: FakeOpenShell) -> None:
    fake.update(global_policy=True)
    events: list[SandboxEvent] = []

    with pytest.raises(RuntimeRefusedError) as refused:
        _open(fake, events)

    assert refused.value.code == "global_policy_active"
    assert ("openshell", "sandbox", "create") not in fake.commands()


def test_an_unrecognised_image_is_deleted_unused(fake: FakeOpenShell) -> None:
    fake.update(exec={"/usr/bin/cat /etc/aegis-probe-release": {"stdout": "ubuntu\n"}})
    events: list[SandboxEvent] = []

    with pytest.raises(RuntimeRefusedError) as refused:
        _open(fake, events)

    assert refused.value.code == "image_unrecognised"
    assert fake.state["sandboxes"] == {}


def test_orphan_cleanup_never_touches_sandboxes_that_are_not_aegis(fake: FakeOpenShell) -> None:
    managed = {"aegis.managed": "true"}
    fake.add_sandbox("aegis-dead", **managed)
    fake.add_sandbox("aegis-unlabelled")
    fake.add_sandbox("research-agent", **managed)
    fake.add_sandbox("aegis-other-team", workspace="default", **managed)
    fake.update(ignore_selector=True)
    events: list[SandboxEvent] = []

    def never_in_use(sandbox: Sandbox) -> bool:
        return False

    deleted = clean_orphans(fake.runtime(), never_in_use, events.append)

    assert deleted == 1
    assert set(fake.state["sandboxes"]) == {
        "aegis-unlabelled",
        "research-agent",
        "aegis-other-team",
    }
    assert [event.name for event in events] == ["aegis-dead"]

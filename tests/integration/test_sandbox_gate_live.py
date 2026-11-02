import shutil
from pathlib import Path
from uuid import uuid4

import pytest

from aegis.integrations.openshell.cli import VERIFIED_VERSION
from aegis.integrations.openshell.runtime import OpenShellRuntime
from aegis.runtime.contract import RuntimeRefusedError
from aegis.runtime.gate import (
    POLICY_DIR,
    SandboxEvent,
    SandboxEventKind,
    SandboxGate,
    load_policies,
)

pytestmark = pytest.mark.openshell


def test_the_gate_admits_the_probe_sandbox_and_deletes_it(
    openshell_runtime: OpenShellRuntime, probe_image: str
) -> None:
    events: list[SandboxEvent] = []
    name = f"aegis-gate-{uuid4().hex[:8]}"
    gate = SandboxGate(openshell_runtime, load_policies(), probe_image, events.append)

    with gate.open(name, {"aegis.purpose": "test"}):
        user = openshell_runtime.exec(name, ["/usr/bin/id", "-u"], 30)
        groups = openshell_runtime.exec(name, ["/usr/bin/id", "-G"], 30)

    assert (user.stdout.strip(), groups.stdout.strip()) == ("2000", "2000")
    created, deleted = events
    assert (created.kind, created.reason) == (SandboxEventKind.CREATED, "verified")
    assert created.details["runtime_version"] == VERIFIED_VERSION
    assert created.details["image"] == probe_image
    assert created.details["prover_result"] == "within_boundary"
    assert (deleted.kind, deleted.succeeded, deleted.reason) == (
        SandboxEventKind.DELETED,
        True,
        "completed",
    )
    assert openshell_runtime.get(name) is None


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("compatibility: hard_requirement", "compatibility: best_effort"),
        ('run_as_user: "2000"', 'run_as_user: "0"'),
        ("read_write: [/tmp, /dev/null]", "read_write: [/tmp, /dev/null, /home]"),
    ],
)
def test_the_real_prover_stops_a_weakened_probe_policy_before_creation(
    openshell_runtime: OpenShellRuntime, probe_image: str, tmp_path: Path, old: str, new: str
) -> None:
    policies = tmp_path / "openshell"
    shutil.copytree(POLICY_DIR, policies)
    probe = policies / "probe.yaml"
    probe.write_text(probe.read_text().replace(old, new))
    before = {sandbox.name for sandbox in openshell_runtime.managed()}
    gate = SandboxGate(openshell_runtime, load_policies(policies), probe_image, lambda event: None)

    with pytest.raises(RuntimeRefusedError) as refused, gate.open("aegis-weakened", {}):
        pytest.fail("a weakened policy must never be admitted")

    assert refused.value.code == "policy_refused"
    assert {sandbox.name for sandbox in openshell_runtime.managed()} == before

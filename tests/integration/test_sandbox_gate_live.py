import os
import shutil
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest

from aegis.config.settings import load_runtime_settings
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


@pytest.fixture(scope="module")
def runtime() -> OpenShellRuntime:
    runtime = OpenShellRuntime(load_runtime_settings(os.environ).openshell)
    status = runtime.check()
    if not status.healthy:
        pytest.fail(f"OpenShell is not usable ({status.detail}); run `make openshell-init`")
    return runtime


@pytest.fixture(scope="module")
def image() -> str:
    # The same offline build as `make openshell-image`; it never pulls.
    build = subprocess.run(
        [
            "docker",
            "build",
            "--pull=false",
            "--network",
            "none",
            "--quiet",
            "--tag",
            "aegis-openshell-probe:1",
            str(POLICY_DIR / "probe"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if build.returncode != 0:
        pytest.fail(f"the probe image did not build offline: {build.stderr.strip()[-300:]}")
    return build.stdout.strip()


def test_the_gate_admits_the_probe_sandbox_and_deletes_it(
    runtime: OpenShellRuntime, image: str
) -> None:
    events: list[SandboxEvent] = []
    name = f"aegis-gate-{uuid4().hex[:8]}"
    gate = SandboxGate(runtime, load_policies(), image, events.append)

    with gate.open(name, {"aegis.purpose": "test"}):
        user = runtime.exec(name, ["/usr/bin/id", "-u"], 30)
        groups = runtime.exec(name, ["/usr/bin/id", "-G"], 30)

    assert (user.stdout.strip(), groups.stdout.strip()) == ("2000", "2000")
    created, deleted = events
    assert (created.kind, created.reason) == (SandboxEventKind.CREATED, "verified")
    assert created.details["runtime_version"] == VERIFIED_VERSION
    assert created.details["image"] == image
    assert created.details["prover_result"] == "within_boundary"
    assert (deleted.kind, deleted.succeeded, deleted.reason) == (
        SandboxEventKind.DELETED,
        True,
        "completed",
    )
    assert runtime.get(name) is None


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("compatibility: hard_requirement", "compatibility: best_effort"),
        ('run_as_user: "2000"', 'run_as_user: "0"'),
        ("read_write: [/tmp, /dev/null]", "read_write: [/tmp, /dev/null, /home]"),
    ],
)
def test_the_real_prover_stops_a_weakened_probe_policy_before_creation(
    runtime: OpenShellRuntime, image: str, tmp_path: Path, old: str, new: str
) -> None:
    policies = tmp_path / "openshell"
    shutil.copytree(POLICY_DIR, policies)
    probe = policies / "probe.yaml"
    probe.write_text(probe.read_text().replace(old, new))
    before = {sandbox.name for sandbox in runtime.managed()}
    gate = SandboxGate(runtime, load_policies(policies), image, lambda event: None)

    with pytest.raises(RuntimeRefusedError) as refused, gate.open("aegis-weakened", {}):
        pytest.fail("a weakened policy must never be admitted")

    assert refused.value.code == "policy_refused"
    assert {sandbox.name for sandbox in runtime.managed()} == before

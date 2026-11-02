import os
import re
import subprocess
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest

from aegis.config.settings import load_runtime_settings
from aegis.integrations.openshell.cli import VERIFIED_VERSION
from aegis.integrations.openshell.runtime import OpenShellRuntime
from aegis.runtime.contract import ProverResult, SandboxSpec

pytestmark = pytest.mark.openshell
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "openshell"
# Already present on a machine that ran Docker before; the tests never pull an image.
IMAGE = "ubuntu:24.04"


@pytest.fixture(scope="module")
def runtime() -> OpenShellRuntime:
    runtime = OpenShellRuntime(load_runtime_settings(os.environ).openshell)
    status = runtime.check()
    if not status.healthy:
        pytest.fail(
            f"OpenShell is not usable ({status.detail}): install OpenShell {VERIFIED_VERSION}"
            " and run `make openshell-init`; see the getting-started guide"
        )
    present = subprocess.run(
        ["docker", "image", "inspect", IMAGE], capture_output=True, check=False
    )
    if present.returncode != 0:
        pytest.fail(f"{IMAGE} is not present locally, and these tests never pull images")
    return runtime


@pytest.fixture
def sandbox(runtime: OpenShellRuntime) -> Iterator[str]:
    name = f"aegis-test-{uuid4().hex[:8]}"
    runtime.create(SandboxSpec(name, IMAGE, FIXTURES / "policy.yaml", {"aegis.purpose": "test"}))
    try:
        yield name
    finally:
        runtime.delete(name)


def test_the_gateway_is_the_verified_runtime(runtime: OpenShellRuntime) -> None:
    status = runtime.check()

    assert (status.healthy, status.detail, status.version) == (True, "ok", VERIFIED_VERSION)


def test_a_sandbox_runs_commands_as_its_policy_user(
    runtime: OpenShellRuntime, sandbox: str
) -> None:
    found = runtime.get(sandbox)
    result = runtime.exec(sandbox, ["/usr/bin/id", "-u"], 30)

    assert found is not None
    assert found.ready
    assert re.fullmatch(r"[0-9a-f]{64}", found.policy_hash or "")
    assert (result.exit_code, result.stdout.strip(), result.timed_out) == (0, "1000", False)
    assert sandbox in {managed.name for managed in runtime.managed()}


def test_an_exec_timeout_is_reported(runtime: OpenShellRuntime, sandbox: str) -> None:
    result = runtime.exec(sandbox, ["/usr/bin/sleep", "30"], 2)

    assert (result.exit_code, result.timed_out) == (124, True)


def test_the_effective_policy_stays_within_the_boundary(
    runtime: OpenShellRuntime, sandbox: str, tmp_path: Path
) -> None:
    effective = tmp_path / "effective.yaml"
    effective.write_text(runtime.effective_policy(sandbox))

    verdict = runtime.check_policy(effective, FIXTURES / "boundary.yaml")

    assert "hard_requirement" in effective.read_text()
    assert (verdict.result, verdict.passed) == (ProverResult.WITHIN_BOUNDARY, True)


@pytest.mark.parametrize(
    ("old", "new", "result", "evidence"),
    [
        ("hard_requirement", "best_effort", ProverResult.EXCEEDS_BOUNDARY, '"landlock"'),
        ("    - /tmp\n", "    - /tmp/cache\n", ProverResult.UNSUPPORTED, None),
        ('run_as_user: "1000"', 'run_as_user: "1001"', ProverResult.UNSUPPORTED, None),
    ],
)
def test_the_prover_refuses_wider_or_uncheckable_policies(
    runtime: OpenShellRuntime,
    tmp_path: Path,
    old: str,
    new: str,
    result: ProverResult,
    evidence: str | None,
) -> None:
    candidate = tmp_path / "candidate.yaml"
    candidate.write_text((FIXTURES / "policy.yaml").read_text().replace(old, new))

    verdict = runtime.check_policy(candidate, FIXTURES / "boundary.yaml")

    assert (verdict.result, verdict.passed) == (result, False)
    if evidence is not None:
        assert evidence in (verdict.counterexample or "")


def test_a_deleted_sandbox_is_gone(runtime: OpenShellRuntime) -> None:
    name = f"aegis-test-{uuid4().hex[:8]}"
    runtime.create(SandboxSpec(name, IMAGE, FIXTURES / "policy.yaml"))

    runtime.delete(name)

    assert runtime.get(name) is None
    assert name not in {managed.name for managed in runtime.managed()}

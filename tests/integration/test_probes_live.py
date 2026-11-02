import shutil
from pathlib import Path
from uuid import uuid4

import pytest

from aegis.integrations.openshell.runtime import OpenShellRuntime
from aegis.runtime.gate import POLICY_DIR, SandboxGate, load_policies
from aegis.runtime.probes.model import Kind, Outcome, Verdict
from aegis.runtime.probes.suite import verify_enforcement

pytestmark = pytest.mark.openshell


def _verify(
    runtime: OpenShellRuntime, image: str, policies: Path = POLICY_DIR
) -> dict[str, Outcome]:
    gate = SandboxGate(runtime, load_policies(policies), image, lambda event: None)
    report = verify_enforcement(gate, runtime, f"aegis-probe-{uuid4().hex[:7]}", {})
    outcomes = {result.check_id: result.outcome for result in report.results}
    outcomes["verdict"] = Outcome.HELD if report.verdict is Verdict.VERIFIED else Outcome.VIOLATED
    return outcomes | {
        f"corroborated:{r.check_id}": Outcome.HELD if r.corroborated else Outcome.INCONCLUSIVE
        for r in report.results
        if r.kind is Kind.NETWORK
    }


def test_every_restriction_holds_under_openshell_and_is_corroborated(
    openshell_runtime: OpenShellRuntime, probe_image: str
) -> None:
    outcomes = _verify(openshell_runtime, probe_image)

    assert {
        check: outcome for check, outcome in outcomes.items() if outcome is not Outcome.HELD
    } == {}
    assert openshell_runtime.managed() == ()


def test_the_probes_catch_a_policy_that_lets_more_through(
    openshell_runtime: OpenShellRuntime, probe_image: str, tmp_path: Path
) -> None:
    # Widen the boundary and the probe policy together, so the gate admits the sandbox: perl may
    # reach the canary, and bash may send any GET. The probes must see both gaps for themselves.
    policies = tmp_path / "openshell"
    shutil.copytree(POLICY_DIR, policies)
    for name in ("boundary.yaml", "probe.yaml"):
        path = policies / name
        path.write_text(
            path.read_text()
            .replace("path: /probe/**", "path: /**")
            .replace(
                "      - path: /usr/bin/bash\n",
                "      - path: /usr/bin/bash\n      - path: /usr/bin/perl\n",
            )
        )

    outcomes = _verify(openshell_runtime, probe_image, policies)

    assert outcomes["network.other_binary"] is Outcome.VIOLATED
    assert outcomes["network.request_path"] is Outcome.VIOLATED
    assert outcomes["network.request_method"] is Outcome.HELD
    assert outcomes["filesystem.unlisted_read"] is Outcome.HELD
    assert outcomes["verdict"] is Outcome.VIOLATED

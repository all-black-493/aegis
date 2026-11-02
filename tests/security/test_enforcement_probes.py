from pathlib import Path

import pytest

from aegis.runtime.contract import RuntimeRefusedError
from aegis.runtime.gate import SandboxEvent, SandboxEventKind, SandboxGate, load_policies
from aegis.runtime.probes.catalog import PROBES
from aegis.runtime.probes.model import Outcome, Verdict
from aegis.runtime.probes.suite import run_probes, verify_enforcement
from tests.fixtures.fake_openshell import FakeOpenShell
from tests.fixtures.probe_answers import (
    FakeCanary,
    argv,
    control_hits,
    enforce_everything,
    fill,
)

RUN = "5eed"
IMAGE = "sha256:" + "e" * 64
NAME = "aegis-probe-1"


@pytest.fixture
def fake(tmp_path: Path) -> FakeOpenShell:
    return enforce_everything(FakeOpenShell(tmp_path / "bin"), RUN)


def _probe(fake: FakeOpenShell, canary: FakeCanary) -> tuple[Verdict, dict[str, Outcome]]:
    runtime = fake.runtime()
    gate = SandboxGate(runtime, load_policies(), IMAGE, lambda event: None)
    with gate.open(NAME, {}):
        report = run_probes(runtime, NAME, canary, RUN, sleep=lambda _: None)
    return report.verdict, {result.check_id: result.outcome for result in report.results}


def test_a_sandbox_that_enforces_everything_is_verified(fake: FakeOpenShell) -> None:
    verdict, outcomes = _probe(fake, FakeCanary(control_hits(RUN)))

    assert verdict is Verdict.VERIFIED
    assert set(outcomes.values()) == {Outcome.HELD}
    assert fake.state["sandboxes"] == {}


@pytest.mark.parametrize("check_id", ["network.other_binary", "network.request_method"])
def test_a_sandbox_claiming_a_refusal_the_canary_saw_through_is_a_violation(
    fake: FakeOpenShell, check_id: str
) -> None:
    probe = next(probe for probe in PROBES if probe.check_id == check_id)
    assert probe.canary is not None
    hits = control_hits(RUN) | {(probe.canary[0], fill(probe.canary[1], RUN))}

    verdict, outcomes = _probe(fake, FakeCanary(hits))

    assert outcomes[check_id] is Outcome.VIOLATED
    assert verdict is Verdict.VIOLATED


def test_runtime_records_alone_never_verify_a_run(fake: FakeOpenShell) -> None:
    # Every OpenShell record is present, but no control reached the canary.
    verdict, outcomes = _probe(fake, FakeCanary(set()))

    assert outcomes["network.canary_get"] is Outcome.INCONCLUSIVE
    assert verdict is Verdict.INCONCLUSIVE


def test_a_write_that_succeeded_inside_the_sandbox_is_a_violation(fake: FakeOpenShell) -> None:
    probe = next(p for p in PROBES if p.check_id == "filesystem.readonly_truncate")
    answers = fake.state["exec"]
    answers[" ".join(argv(probe, RUN))] = {"exit": 0, "stdout": "", "stderr": ""}
    fake.update(exec=answers)

    verdict, outcomes = _probe(fake, FakeCanary(control_hits(RUN)))

    assert outcomes["filesystem.readonly_truncate"] is Outcome.VIOLATED
    assert verdict is Verdict.VIOLATED


def test_a_refused_sandbox_runs_no_probe_and_stops_the_canary(fake: FakeOpenShell) -> None:
    fake.update(verdict={**fake.state["verdict"], "result": "exceeds_boundary", "exit_code": 1})
    canary = FakeCanary(set())
    gate = SandboxGate(fake.runtime(), load_policies(), IMAGE, lambda event: None)

    with pytest.raises(RuntimeRefusedError):
        verify_enforcement(gate, fake.runtime(), NAME, {}, canary=lambda: canary)

    assert not [c for c in fake.calls() if "exec" in c["argv"]]
    assert canary.closed


def test_a_failure_during_the_probes_still_deletes_the_sandbox_and_stops_the_canary(
    fake: FakeOpenShell,
) -> None:
    class Broken(FakeCanary):
        def hits(self) -> frozenset[tuple[int, str]]:
            raise OSError("the canary failed")

    canary = Broken(set())
    events: list[SandboxEvent] = []
    gate = SandboxGate(fake.runtime(), load_policies(), IMAGE, events.append)

    with pytest.raises(OSError, match="the canary failed"):
        verify_enforcement(gate, fake.runtime(), NAME, {}, canary=lambda: canary)

    assert fake.state["sandboxes"] == {}
    assert canary.closed
    assert (events[-1].kind, events[-1].reason) == (SandboxEventKind.DELETED, "aborted")

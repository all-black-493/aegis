from dataclasses import replace

import pytest

from aegis.integrations.openshell.parsing import parse_records
from aegis.runtime.contract import EnforcementRecord, ExecResult
from aegis.runtime.gate import POLICY_DIR, RELEASE
from aegis.runtime.probes.catalog import (
    PROBES,
    READONLY_CONTENT,
    READONLY_MARKER,
    UNLISTED_FILE,
)
from aegis.runtime.probes.model import (
    NONCE,
    Observation,
    Outcome,
    ProbeResult,
    Role,
    Signature,
    Verdict,
)
from aegis.runtime.probes.suite import RECORD_ATTEMPTS, run_probes
from aegis.runtime.probes.verdicts import judge, matches, summarize
from tests.fixtures.fake_runtime import FakeRuntime
from tests.fixtures.probe_answers import (
    FakeCanary,
    control_hits,
    enforcing_answers,
    enforcing_records,
    fill,
)

RUN = "c0ffee"
BY_ID = {probe.check_id: probe for probe in PROBES}


def _fill(text: str) -> str:
    return fill(text, RUN)


def _enforcing_runtime() -> tuple[FakeRuntime, set[tuple[int, str]]]:
    runtime = FakeRuntime(results=enforcing_answers(RUN), enforcement=enforcing_records(RUN))
    return runtime, control_hits(RUN)


def _run(runtime: FakeRuntime, hits: set[tuple[int, str]]) -> dict[str, ProbeResult]:
    report = run_probes(runtime, "aegis-probe", FakeCanary(hits), RUN, sleep=lambda _: None)
    return {result.check_id: result for result in report.results}


def test_the_catalog_covers_filesystem_process_and_network_with_controls() -> None:
    kinds = {(probe.kind.value, probe.role.value) for probe in PROBES}

    assert len(BY_ID) == len(PROBES)
    assert kinds == {
        ("filesystem", "control"),
        ("filesystem", "restriction"),
        ("process", "restriction"),
        ("network", "control"),
        ("network", "restriction"),
    }
    for probe in PROBES:
        assert probe.argv[0].startswith("/usr/bin/")
        if probe.role is Role.RESTRICTION:
            assert probe.breached is not None, probe.check_id
        if probe.kind.value == "network":
            assert probe.record is not None, probe.check_id


def test_the_probe_image_provides_what_the_catalog_expects() -> None:
    dockerfile = (POLICY_DIR / "probe" / "Dockerfile").read_text()

    assert f"printf '{READONLY_CONTENT}\\n' > {READONLY_MARKER}" in dockerfile
    assert f"> {UNLISTED_FILE}" in dockerfile
    assert f"printf '{RELEASE}\\n'" in dockerfile
    assert "chown -R 2000:2000 /srv/aegis" in dockerfile
    assert "/srv/aegis/workspace" in dockerfile


@pytest.mark.parametrize(
    ("signature", "observation", "expected"),
    [
        (Signature(exit_zero=True), Observation(0, "", ""), True),
        (Signature(exit_zero=True), Observation(1, "", ""), False),
        (
            Signature(exit_zero=False, stderr_has=("Permission denied",)),
            Observation(1, "", "x: Permission denied"),
            True,
        ),
        (
            Signature(exit_zero=False, stderr_has=("Permission denied",)),
            Observation(1, "", "No such file"),
            False,
        ),
        (Signature(stdout_is=NONCE), Observation(0, f"{RUN}\n", ""), True),
        (Signature(stdout_is=NONCE), Observation(0, f"{RUN} extra", ""), False),
        (Signature(stdout_has=("a", "b")), Observation(0, "b a", ""), True),
    ],
)
def test_signatures_match_every_field_that_is_set(
    signature: Signature, observation: Observation, expected: bool
) -> None:
    assert matches(signature, observation, RUN) is expected


def test_an_enforcing_runtime_is_verified_with_every_record_corroborated() -> None:
    runtime, hits = _enforcing_runtime()

    report = run_probes(runtime, "aegis-probe", FakeCanary(hits), RUN, sleep=lambda _: None)

    assert report.verdict is Verdict.VERIFIED
    assert {result.outcome for result in report.results} == {Outcome.HELD}
    assert all(r.corroborated is not False for r in report.results)
    assert not any(NONCE in call for call in runtime.calls)


@pytest.mark.parametrize(
    "check_id",
    ["network.request_method", "network.other_port", "network.other_binary"],
)
def test_a_request_the_canary_received_is_a_violation_whatever_the_sandbox_says(
    check_id: str,
) -> None:
    runtime, hits = _enforcing_runtime()
    probe = BY_ID[check_id]
    assert probe.canary is not None
    hits.add((probe.canary[0], _fill(probe.canary[1])))

    results = _run(runtime, hits)

    assert results[check_id].outcome is Outcome.VIOLATED


@pytest.mark.parametrize(
    ("check_id", "result"),
    [
        ("filesystem.unlisted_read", ExecResult(0, "aegis unlisted file", "")),
        ("filesystem.readonly_truncate", ExecResult(0, "", "")),
        ("filesystem.readonly_intact", ExecResult(0, "", "")),
        ("process.hardening", ExecResult(0, "NoNewPrivs:\t0\nCapEff:\t00000000a80425fb\n", "")),
        ("network.request_path", ExecResult(0, "HTTP/1.0 200 OK\r\n\r\naegis-canary /admin/x", "")),
        ("network.unrouted_host", ExecResult(0, "HTTP/1.1 200 OK", "")),
    ],
)
def test_an_action_that_succeeded_is_a_violation(check_id: str, result: ExecResult) -> None:
    runtime, hits = _enforcing_runtime()
    runtime.results[tuple(_fill(arg) for arg in BY_ID[check_id].argv)] = result

    results = _run(runtime, hits)

    assert results[check_id].outcome is Outcome.VIOLATED


@pytest.mark.parametrize(
    ("check_id", "result"),
    [
        ("filesystem.scratch_write", ExecResult(1, "", "Read-only file system")),
        ("filesystem.listed_read", ExecResult(1, "", "Permission denied")),
        ("network.canary_get", ExecResult(9, "", "connect: Permission denied")),
    ],
)
def test_a_failed_control_makes_the_run_inconclusive_never_verified(
    check_id: str, result: ExecResult
) -> None:
    runtime, hits = _enforcing_runtime()
    runtime.results[tuple(_fill(arg) for arg in BY_ID[check_id].argv)] = result

    report = run_probes(runtime, "aegis-probe", FakeCanary(hits), RUN, sleep=lambda _: None)

    assert {r.check_id: r.outcome for r in report.results}[check_id] is Outcome.INCONCLUSIVE
    assert report.verdict is Verdict.INCONCLUSIVE


def test_a_control_the_canary_did_not_see_is_inconclusive() -> None:
    runtime, _ = _enforcing_runtime()

    report = run_probes(runtime, "aegis-probe", FakeCanary(set()), RUN, sleep=lambda _: None)

    assert report.verdict is Verdict.INCONCLUSIVE


def test_an_unexplained_failure_or_a_timeout_is_inconclusive() -> None:
    runtime, hits = _enforcing_runtime()
    runtime.results[tuple(_fill(arg) for arg in BY_ID["filesystem.private_read"].argv)] = (
        ExecResult(127, "", "ls: not found")
    )
    runtime.results[tuple(_fill(arg) for arg in BY_ID["network.metadata"].argv)] = ExecResult(
        124, "", "", timed_out=True
    )

    results = _run(runtime, hits)

    assert results["filesystem.private_read"].outcome is Outcome.INCONCLUSIVE
    assert results["network.metadata"].outcome is Outcome.INCONCLUSIVE
    assert results["network.metadata"].exit_code is None


def test_a_violation_outranks_an_inconclusive_check() -> None:
    held = ProbeResult(
        "a", BY_ID["filesystem.unlisted_read"].kind, Role.RESTRICTION, Outcome.HELD, 1, None
    )

    assert (
        summarize(
            (replace(held, outcome=Outcome.INCONCLUSIVE), replace(held, outcome=Outcome.VIOLATED))
        ).verdict
        is Verdict.VIOLATED
    )
    assert (
        summarize((held, replace(held, outcome=Outcome.INCONCLUSIVE))).verdict
        is Verdict.INCONCLUSIVE
    )
    assert summarize(()).verdict is Verdict.INCONCLUSIVE


def test_records_are_polled_until_they_arrive_and_never_decide_the_outcome() -> None:
    runtime, hits = _enforcing_runtime()
    complete = list(runtime.enforcement)
    batches = [complete[:2], complete[:4], complete]

    class Lagging(FakeRuntime):
        def records(self, name: str) -> tuple[EnforcementRecord, ...]:
            return tuple(batches.pop(0) if batches else complete)

    lagging = Lagging(results=runtime.results)
    waits: list[float] = []

    report = run_probes(lagging, "aegis-probe", FakeCanary(hits), RUN, sleep=waits.append)

    assert len(waits) == 2
    assert all(r.corroborated is not False for r in report.results)

    silent = FakeRuntime(results=runtime.results)
    report = run_probes(silent, "aegis-probe", FakeCanary(hits), RUN, sleep=waits.append)

    assert report.verdict is Verdict.VERIFIED
    assert silent.calls.count("records") == RECORD_ATTEMPTS
    assert {r.corroborated for r in report.results if r.kind.value == "network"} == {False}


def test_a_probe_without_an_observation_is_inconclusive() -> None:
    result = judge(BY_ID["filesystem.unlisted_read"], None, frozenset(), (), RUN)

    assert (result.outcome, result.exit_code) == (Outcome.INCONCLUSIVE, None)


def test_openshell_shorthand_records_are_parsed() -> None:
    log = "\n".join(
        [
            "[1793585667.008] [sandbox] [WARN ] [openshell_supervisor_network::proxy] Denied ...",
            "[1793585667.008] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED /usr/bin/bash(0)"
            " -> 192.0.2.1:443 [reason:transparent_tcp_policy_denied]",
            "[1793585667.1] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED"
            " POST http://172.17.0.1:18901/probe/x [policy:canary engine:l7]",
            "[1793585667.2] [sandbox] [OCSF ] [ocsf] SSH:OPEN [INFO] ALLOWED",
            "[1793585667.3] [sandbox] [OCSF ] [ocsf] CONFIG:LOADED [INFO] Acknowledged revision",
            "x" * 5000,
        ]
    )

    records = parse_records(log)

    assert [(r.category, r.action) for r in records] == [
        ("NET:OPEN", "DENIED"),
        ("HTTP:POST", "DENIED"),
    ]
    assert records[0].detail.startswith("/usr/bin/bash(0) -> 192.0.2.1:443")


def test_long_record_details_are_truncated() -> None:
    line = "[ocsf] NET:OPEN [MED] DENIED " + "z" * 2000

    [record] = parse_records(line)

    assert len(record.detail) == 512


def test_a_stopped_run_runs_no_more_probes_and_is_never_verified() -> None:
    runtime, hits = _enforcing_runtime()
    asked: list[None] = []

    def stop() -> bool:
        asked.append(None)
        return len(asked) > 2

    report = run_probes(
        runtime, "aegis-probe", FakeCanary(hits), RUN, sleep=lambda _: None, stop=stop
    )

    assert len([call for call in runtime.calls if call.startswith("exec ")]) == 2
    assert "records" not in runtime.calls
    assert report.verdict is Verdict.INCONCLUSIVE
    assert {r.outcome for r in report.results[2:]} == {Outcome.INCONCLUSIVE}

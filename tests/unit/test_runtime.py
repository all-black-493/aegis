from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from aegis.config.settings import (
    OpenShellSettings,
    RuntimeSettings,
    SandboxRuntimeKind,
    SettingsError,
    load_runtime_settings,
)
from aegis.integrations.openshell.cli import (
    ALLOWED_COMMANDS,
    CommandNotAllowedError,
    OpenShellCli,
    environment,
)
from aegis.integrations.openshell.runtime import (
    OpenShellRuntime,
    is_managed,
    parse_sandbox,
    parse_verdict,
)
from aegis.runtime.contract import (
    MAX_EXEC_SECONDS,
    REQUIRED_PROVER_DOMAINS,
    InvalidSandboxError,
    ProverResult,
    ProverVerdict,
    RuntimeProtocolError,
    RuntimeRefusedError,
    RuntimeStatus,
    Sandbox,
    SandboxSpec,
    check_exec,
)
from aegis.runtime.disabled import DisabledRuntime
from aegis.runtime.factory import build_runtime

POLICY = Path("/policies/probe.yaml")


def test_the_runtime_is_disabled_unless_configured() -> None:
    assert load_runtime_settings({}) == RuntimeSettings(
        SandboxRuntimeKind.NONE, OpenShellSettings("openshell", "aegis")
    )


def test_openshell_settings_are_parsed() -> None:
    settings = load_runtime_settings(
        {
            "AEGIS_SANDBOX_RUNTIME": "openshell",
            "AEGIS_OPENSHELL_GATEWAY": "lab-gateway",
            "AEGIS_OPENSHELL_WORKSPACE": "aegis-ci",
            "AEGIS_OPENSHELL_IMAGE": "sha256:" + "b" * 64,
        }
    )

    assert settings == RuntimeSettings(
        SandboxRuntimeKind.OPENSHELL,
        OpenShellSettings("lab-gateway", "aegis-ci", "sha256:" + "b" * 64),
    )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("AEGIS_SANDBOX_RUNTIME", "docker"),
        ("AEGIS_OPENSHELL_GATEWAY", "https://10.0.0.1:17670"),
        ("AEGIS_OPENSHELL_GATEWAY", "Gateway"),
        ("AEGIS_OPENSHELL_WORKSPACE", "default"),
        ("AEGIS_OPENSHELL_WORKSPACE", "a-workspace-name-too-long"),
        ("AEGIS_OPENSHELL_WORKSPACE", "-aegis"),
        ("AEGIS_OPENSHELL_ENDPOINT", "https://10.0.0.1:17670"),
        ("AEGIS_OPENSHELL_IMAGE", "aegis-openshell-probe:1"),
        ("AEGIS_OPENSHELL_IMAGE", "ubuntu@sha256:" + "b" * 64),
        ("AEGIS_OPENSHELL_IMAGE", "sha256:" + "B" * 64),
    ],
)
def test_invalid_runtime_settings_are_refused(name: str, value: str) -> None:
    with pytest.raises(SettingsError) as refused:
        load_runtime_settings({name: value})

    assert name in str(refused.value)


@pytest.mark.parametrize(
    "change",
    [
        {"name": "sandbox-1"},
        {"name": "aegis-UPPER"},
        {"name": "aegis-" + "x" * 41},
        {"name": "aegis-trailing-"},
        {"image": "--policy=/tmp/open.yaml"},
        {"image": "ubuntu:24.04 --gpu"},
        {"policy": Path("relative.yaml")},
        {"cpu": "all"},
        {"memory": "1T"},
        {"labels": {"aegis.managed": "true"}},
        {"labels": {"Key": "value"}},
        {"labels": {"key": "two words"}},
    ],
)
def test_sandbox_specs_are_validated(change: dict[str, Any]) -> None:
    fields: dict[str, Any] = {"name": "aegis-probe-1", "image": "ubuntu:24.04", "policy": POLICY}

    with pytest.raises(InvalidSandboxError):
        SandboxSpec(**{**fields, **change})


def test_a_valid_spec_keeps_its_labels_read_only() -> None:
    spec = SandboxSpec("aegis-probe-1", "ubuntu@sha256:" + "a" * 64, POLICY, {"aegis.task": "t1"})

    with pytest.raises(TypeError):
        spec.labels["aegis.managed"] = "true"  # type: ignore[index]


@pytest.mark.parametrize(
    ("argv", "timeout"),
    [
        ([], 5),
        (["id"], 5),
        (["/usr/bin/id", "a\x00b"], 5),
        (["/usr/bin/echo", *["x"] * 64], 5),
        (["/usr/bin/echo", "x" * 5000], 5),
        (["/usr/bin/id"], 0),
        (["/usr/bin/id"], MAX_EXEC_SECONDS + 1),
        (["/usr/bin/id"], True),
    ],
)
def test_exec_requests_are_validated(argv: list[str], timeout: int) -> None:
    with pytest.raises(InvalidSandboxError):
        check_exec(argv, timeout)


def test_only_a_within_boundary_verdict_with_full_coverage_passes() -> None:
    full = frozenset(REQUIRED_PROVER_DOMAINS)

    assert ProverVerdict(ProverResult.WITHIN_BOUNDARY, full).passed
    assert not ProverVerdict(ProverResult.WITHIN_BOUNDARY, full - {"landlock"}).passed
    for result in set(ProverResult) - {ProverResult.WITHIN_BOUNDARY}:
        assert not ProverVerdict(result, full).passed


def test_status_details_are_short_codes() -> None:
    with pytest.raises(InvalidSandboxError):
        RuntimeStatus(False, "Gateway at https://127.0.0.1 refused")


def test_the_disabled_runtime_refuses_everything() -> None:
    runtime = DisabledRuntime()
    spec = SandboxSpec("aegis-probe-1", "ubuntu:24.04", POLICY)
    calls: list[Callable[[], object]] = [
        lambda: runtime.create(spec),
        lambda: runtime.get("aegis-probe-1"),
        lambda: runtime.exec("aegis-probe-1", ["/usr/bin/id"], 5),
        lambda: runtime.effective_policy("aegis-probe-1"),
        lambda: runtime.delete("aegis-probe-1"),
        lambda: runtime.check_policy(POLICY, POLICY),
    ]

    assert runtime.check() == RuntimeStatus(False, "disabled")
    assert runtime.managed() == ()
    for call in calls:
        with pytest.raises(RuntimeRefusedError) as refused:
            call()
        assert refused.value.code == "sandbox_unavailable"


def test_the_factory_builds_the_configured_runtime() -> None:
    assert isinstance(build_runtime(RuntimeSettings()), DisabledRuntime)
    assert isinstance(
        build_runtime(RuntimeSettings(SandboxRuntimeKind.OPENSHELL)), OpenShellRuntime
    )


def test_the_cli_gets_no_secrets_and_no_openshell_overrides() -> None:
    source = {
        "AEGIS_DB_APP_PASSWORD": "secret-value",
        "OPENSHELL_GATEWAY_INSECURE": "1",
        "OPENSHELL_GATEWAY_ENDPOINT": "https://203.0.113.9",
        "PATH": "/home/attacker/bin:/usr/bin",
        "HOME": "/home/aegis",
        "XDG_CONFIG_HOME": "relative/config",
    }

    assert environment(source) == {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "NO_COLOR": "1",
        "HOME": "/home/aegis",
    }


def test_commands_outside_the_allow_list_are_refused_before_anything_runs() -> None:
    cli = OpenShellCli("openshell", "aegis", environ={})
    refused = [
        ("policy", "set"),
        ("policy", "update"),
        ("policy", "delete"),
        ("provider", "create"),
        ("forward", "start"),
        ("sandbox", "connect"),
        ("gateway", "add"),
        ("settings", "set"),
    ]

    for command in refused:
        assert command not in ALLOWED_COMMANDS
        with pytest.raises(CommandNotAllowedError):
            cli.run(command, [], timeout=1, limit=1)


def _record(**change: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": "7e256482",
        "name": "aegis-probe-1",
        "phase": "Ready",
        "labels": {"aegis.managed": "true"},
        "configuration_admission": {"state": "accepted", "policy_hash": "5b90" * 16},
    }
    return {**record, **change}


def test_sandbox_records_are_parsed() -> None:
    sandbox = parse_sandbox(_record())

    assert (sandbox.name, sandbox.sandbox_id, sandbox.ready) == ("aegis-probe-1", "7e256482", True)
    assert sandbox.policy_hash == "5b90" * 16
    assert is_managed(sandbox)


@pytest.mark.parametrize(
    "record",
    [[], _record(name=None), _record(phase=""), _record(labels=["aegis.managed"])],
)
def test_malformed_sandbox_records_are_protocol_errors(record: Any) -> None:
    with pytest.raises(RuntimeProtocolError):
        parse_sandbox(record)


@pytest.mark.parametrize(
    "sandbox",
    [
        Sandbox("aegis-probe-1", "1", "Ready", None, {}),
        Sandbox("aegis-probe-1", "1", "Ready", None, {"aegis.managed": "false"}),
        Sandbox("probe-1", "1", "Ready", None, {"aegis.managed": "true"}),
    ],
)
def test_only_named_and_labelled_sandboxes_are_managed(sandbox: Sandbox) -> None:
    assert not is_managed(sandbox)


def _verdict(**change: Any) -> dict[str, Any]:
    verdict: dict[str, Any] = {
        "schema_version": 1,
        "prover_version": "0.1.6",
        "result": "exceeds_boundary",
        "exit_code": 1,
        "coverage": {"domains": sorted(REQUIRED_PROVER_DOMAINS)},
        "counterexample": {"domain": "filesystem", "path": "/sandbox/" + "x" * 2000},
        "reason_code": None,
    }
    return {**verdict, **change}


def test_prover_reports_are_parsed_and_counterexamples_bounded() -> None:
    verdict = parse_verdict(_verdict(), 1)

    assert (verdict.result, verdict.passed) == (ProverResult.EXCEEDS_BOUNDARY, False)
    assert verdict.counterexample is not None
    assert len(verdict.counterexample) <= 1024


@pytest.mark.parametrize(
    ("report", "exit_code", "error"),
    [
        (_verdict(schema_version=2), 1, RuntimeRefusedError),
        (_verdict(prover_version="0.1.7"), 1, RuntimeRefusedError),
        (_verdict(result="maybe"), 1, RuntimeProtocolError),
        (_verdict(), 0, RuntimeProtocolError),
        (_verdict(coverage={"domains": "filesystem"}), 1, RuntimeProtocolError),
    ],
)
def test_untrustworthy_prover_reports_are_refused(
    report: dict[str, Any], exit_code: int, error: type[Exception]
) -> None:
    with pytest.raises(error):
        parse_verdict(report, exit_code)

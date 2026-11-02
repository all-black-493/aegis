import contextlib
import json
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any

from aegis.config.settings import OpenShellSettings
from aegis.integrations.openshell.cli import VERIFIED_VERSION, Completed, OpenShellCli
from aegis.runtime.contract import (
    MANAGED_LABEL,
    MAX_EXEC_OUTPUT_BYTES,
    ExecResult,
    ProverResult,
    ProverVerdict,
    RuntimeProtocolError,
    RuntimeRefusedError,
    RuntimeStatus,
    RuntimeUnavailableError,
    Sandbox,
    SandboxRuntimeError,
    SandboxSpec,
    check_exec,
    check_sandbox_name,
)

CALL_TIMEOUT_SECONDS = 30
CREATE_TIMEOUT_SECONDS = 300
EXEC_GRACE_SECONDS = 30
DELETE_WAIT_SECONDS = 60
PROVER_TIMEOUT_SECONDS = 10
MAX_JSON_BYTES = 1024 * 1024
MAX_POLICY_BYTES = 256 * 1024
MAX_COUNTEREXAMPLE_CHARS = 1024
# The sandbox's canonical main process only keeps it alive; AEGIS runs its work through exec.
IDLE_COMMAND = ("/usr/bin/sleep", "infinity")
# sandbox exec reports its own --timeout with this exit status (ADR-0016).
EXEC_TIMEOUT_EXIT = 124


class OpenShellRuntime:
    def __init__(
        self,
        settings: OpenShellSettings,
        *,
        cli: OpenShellCli | None = None,
        delete_wait_seconds: float = DELETE_WAIT_SECONDS,
    ) -> None:
        self._settings = settings
        self._cli = cli or OpenShellCli(settings.gateway, settings.workspace)
        self._delete_wait = delete_wait_seconds

    def check(self) -> RuntimeStatus:
        try:
            self._verify()
            workspace = self._run(("workspace", "get"), [self._settings.workspace])
            if workspace.exit_code != 0:
                return RuntimeStatus(False, "workspace_missing", VERIFIED_VERSION)
            if self._global_policy_active():
                return RuntimeStatus(False, "global_policy_active", VERIFIED_VERSION)
        except SandboxRuntimeError as error:
            return RuntimeStatus(False, error.code)
        return RuntimeStatus(True, "ok", VERIFIED_VERSION)

    def ensure_workspace(self) -> bool:
        self._verify()
        if self._run(("workspace", "get"), [self._settings.workspace]).exit_code == 0:
            return False
        created = self._run(
            ("workspace", "create"), ["--name", self._settings.workspace, "--label", "owner=aegis"]
        )
        if created.exit_code != 0:
            raise RuntimeRefusedError(
                "the workspace could not be created", code="workspace_refused"
            )
        return True

    def create(self, spec: SandboxSpec) -> Sandbox:
        # Re-verified for every sandbox: an upgrade between tasks must not go unnoticed.
        self._verify()
        labels = {**spec.labels, MANAGED_LABEL: "true"}
        args = [
            "--name",
            spec.name,
            "--from",
            spec.image,
            "--policy",
            str(spec.policy),
            "--cpu",
            spec.cpu,
            "--memory",
            spec.memory,
            *(item for key, value in labels.items() for item in ("--label", f"{key}={value}")),
            "--no-tty",
            "--detach",
            "--no-auto-providers",
            "--output",
            "json",
            "--",
            *IDLE_COMMAND,
        ]
        completed = self._run(("sandbox", "create"), args, timeout=CREATE_TIMEOUT_SECONDS)
        if completed.exit_code != 0:
            self._discard(spec.name)
            raise RuntimeRefusedError("OpenShell refused the sandbox", code="sandbox_rejected")
        sandbox = parse_sandbox(_json(completed))
        if not sandbox.ready or _admission(completed) != "accepted":
            self._discard(spec.name)
            raise RuntimeRefusedError("the sandbox did not become ready", code="sandbox_not_ready")
        return sandbox

    def get(self, name: str) -> Sandbox | None:
        completed = self._run(("sandbox", "get"), [check_sandbox_name(name), "--output", "json"])
        if completed.exit_code != 0:
            if _not_found(completed):
                return None
            raise RuntimeUnavailableError("the sandbox could not be read")
        return parse_sandbox(_json(completed))

    def exec(self, name: str, argv: Sequence[str], timeout_seconds: int) -> ExecResult:
        check_exec(argv, timeout_seconds)
        sandbox = self.get(name)
        if sandbox is None or not sandbox.ready:
            # A missing sandbox would also exit 1, which must not be mistaken for the command's.
            raise RuntimeUnavailableError("the sandbox is not ready", code="sandbox_not_ready")
        args = [
            "--name",
            name,
            "--no-tty",
            "--no-login-shell",
            "--timeout",
            str(timeout_seconds),
            "--",
            *argv,
        ]
        completed = self._cli.run(
            ("sandbox", "exec"),
            args,
            timeout=timeout_seconds + EXEC_GRACE_SECONDS,
            limit=MAX_EXEC_OUTPUT_BYTES,
        )
        if completed.timed_out:
            raise RuntimeUnavailableError("the exec call did not return", code="exec_stalled")
        return ExecResult(
            exit_code=completed.exit_code,
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=completed.exit_code == EXEC_TIMEOUT_EXIT
            and completed.seconds >= timeout_seconds,
            truncated=completed.truncated,
        )

    def effective_policy(self, name: str) -> str:
        completed = self._cli.run(
            ("sandbox", "get"),
            [check_sandbox_name(name), "--policy-only"],
            timeout=CALL_TIMEOUT_SECONDS,
            limit=MAX_POLICY_BYTES,
        )
        if completed.exit_code != 0 or completed.truncated or completed.timed_out:
            raise RuntimeUnavailableError("the effective policy could not be read")
        return completed.stdout

    def delete(self, name: str) -> None:
        check_sandbox_name(name)
        if self._run(("sandbox", "delete"), [name]).exit_code != 0:
            raise RuntimeUnavailableError("the sandbox could not be deleted", code="delete_failed")
        deadline = time.monotonic() + self._delete_wait
        while self.get(name) is not None:
            if time.monotonic() >= deadline:
                raise RuntimeUnavailableError("deletion is still pending", code="delete_pending")
            time.sleep(0.5)

    def managed(self) -> tuple[Sandbox, ...]:
        found: list[Sandbox] = []
        token = ""
        while True:
            args = ["--selector", f"{MANAGED_LABEL}=true", "--output", "json"]
            completed = self._run(("sandbox", "list"), [*args, "--page-token", token])
            if completed.exit_code != 0:
                raise RuntimeUnavailableError("sandboxes could not be listed")
            page = _json(completed)
            entries = page.get("sandboxes")
            if not isinstance(entries, list):
                raise RuntimeProtocolError("the sandbox list is malformed")
            # The selector is the gateway's filter; the name and label are checked here too.
            found.extend(sandbox for sandbox in map(parse_sandbox, entries) if is_managed(sandbox))
            token = page.get("next_page_token") or ""
            if not isinstance(token, str):
                raise RuntimeProtocolError("the sandbox list is malformed")
            if not token:
                return tuple(found)

    def check_policy(self, candidate: Path, boundary: Path) -> ProverVerdict:
        if self._cli.prover_version() != f"openshell-prover {VERIFIED_VERSION}":
            raise RuntimeRefusedError(
                "the prover is not the verified version", code="version_mismatch"
            )
        completed = self._cli.prove(candidate, boundary, timeout_seconds=PROVER_TIMEOUT_SECONDS)
        if completed.timed_out:
            raise RuntimeUnavailableError("the prover did not finish", code="prover_stalled")
        return parse_verdict(_json(completed), completed.exit_code)

    def _verify(self) -> None:
        if self._cli.version() != f"openshell {VERIFIED_VERSION}":
            raise RuntimeRefusedError(
                "the CLI is not the verified version", code="version_mismatch"
            )
        if self._cli.prover_version() != f"openshell-prover {VERIFIED_VERSION}":
            raise RuntimeRefusedError(
                "the prover is not the verified version", code="version_mismatch"
            )
        completed = self._run(("status",), ["--output", "json"])
        if completed.exit_code != 0:
            raise RuntimeUnavailableError("the gateway could not be reached", code="unreachable")
        status = _json(completed)
        # An unknown gateway name also exits 0, reporting not_configured (ADR-0016).
        if status.get("status") != "connected":
            raise RuntimeUnavailableError("the gateway is not connected", code="not_connected")
        if status.get("version") != VERIFIED_VERSION:
            raise RuntimeRefusedError(
                "the gateway is not the verified version", code="version_mismatch"
            )

    def _global_policy_active(self) -> bool:
        # A global policy replaces every sandbox's own policy, so AEGIS refuses to run under one.
        completed = self._run(("policy", "get"), ["--global"])
        if completed.exit_code == 0:
            return True
        if "no global policy revision found" in _message(completed):
            return False
        raise RuntimeUnavailableError("the global policy could not be read")

    def _discard(self, name: str) -> None:
        with contextlib.suppress(SandboxRuntimeError):
            self.delete(name)

    def _run(
        self,
        command: tuple[str, ...],
        args: Sequence[str],
        *,
        timeout: float = CALL_TIMEOUT_SECONDS,
    ) -> Completed:
        completed = self._cli.run(command, args, timeout=timeout, limit=MAX_JSON_BYTES)
        if completed.timed_out:
            raise RuntimeUnavailableError("the gateway did not answer in time", code="unreachable")
        return completed


def is_managed(sandbox: Sandbox) -> bool:
    try:
        check_sandbox_name(sandbox.name)
    except ValueError:
        return False
    return sandbox.labels.get(MANAGED_LABEL) == "true"


def parse_sandbox(value: object) -> Sandbox:
    if not isinstance(value, Mapping):
        raise RuntimeProtocolError("a sandbox record is malformed")
    name, sandbox_id, phase = value.get("name"), value.get("id"), value.get("phase")
    labels = value.get("labels") or {}
    admission = value.get("configuration_admission") or {}
    if not all(isinstance(item, str) and item for item in (name, sandbox_id, phase)):
        raise RuntimeProtocolError("a sandbox record is malformed")
    if not isinstance(labels, Mapping) or not isinstance(admission, Mapping):
        raise RuntimeProtocolError("a sandbox record is malformed")
    policy_hash = admission.get("policy_hash")
    return Sandbox(
        name=str(name),
        sandbox_id=str(sandbox_id),
        phase=str(phase),
        policy_hash=policy_hash if isinstance(policy_hash, str) and policy_hash else None,
        labels=MappingProxyType({str(k): str(v) for k, v in labels.items()}),
    )


def parse_verdict(value: Mapping[str, Any], exit_code: int) -> ProverVerdict:
    if value.get("schema_version") != 1 or value.get("prover_version") != VERIFIED_VERSION:
        raise RuntimeRefusedError(
            "the prover output is not the verified schema", code="version_mismatch"
        )
    try:
        result = ProverResult(str(value.get("result")))
    except ValueError:
        raise RuntimeProtocolError("the prover reported an unknown result") from None
    if value.get("exit_code") != exit_code:
        raise RuntimeProtocolError("the prover's result and exit status disagree")
    coverage = value.get("coverage")
    domains = coverage.get("domains") if isinstance(coverage, Mapping) else None
    if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains):
        raise RuntimeProtocolError("the prover coverage is malformed")
    reason_code = value.get("reason_code")
    counterexample = value.get("counterexample")
    return ProverVerdict(
        result=result,
        domains=frozenset(domains),
        reason_code=reason_code if isinstance(reason_code, str) else None,
        counterexample=(
            json.dumps(counterexample, sort_keys=True)[:MAX_COUNTEREXAMPLE_CHARS]
            if counterexample is not None
            else None
        ),
    )


def _json(completed: Completed) -> dict[str, Any]:
    if completed.truncated:
        raise RuntimeProtocolError("OpenShell's output exceeded its size limit")
    try:
        value = json.loads(completed.stdout)
    except ValueError:
        raise RuntimeProtocolError("OpenShell's output is not JSON") from None
    if not isinstance(value, dict):
        raise RuntimeProtocolError("OpenShell's output is not a JSON object")
    return value


def _admission(completed: Completed) -> object:
    admission = _json(completed).get("configuration_admission")
    return admission.get("state") if isinstance(admission, Mapping) else None


def _not_found(completed: Completed) -> bool:
    return "not found" in _message(completed)


def _message(completed: Completed) -> str:
    # The CLI wraps errors at 80 columns inside a box border (ADR-0016).
    return " ".join(completed.stderr.replace("\u2502", " ").split())

import contextlib
import time
from collections.abc import Sequence
from pathlib import Path

from aegis.config.settings import OpenShellSettings
from aegis.integrations.openshell.cli import VERIFIED_VERSION, Completed, OpenShellCli
from aegis.integrations.openshell.parsing import (
    admission_state,
    error_message,
    json_object,
    not_found,
    parse_records,
    parse_sandbox,
    parse_verdict,
)
from aegis.runtime.contract import (
    MANAGED_LABEL,
    MAX_EXEC_OUTPUT_BYTES,
    EnforcementRecord,
    ExecResult,
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
LOG_LINES = 2000
MAX_JSON_BYTES = 1024 * 1024
MAX_POLICY_BYTES = 256 * 1024
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
            return RuntimeStatus(False, error.code, retryable=error.retryable)
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
        sandbox = parse_sandbox(json_object(completed))
        if not sandbox.ready or admission_state(completed) != "accepted":
            self._discard(spec.name)
            raise RuntimeRefusedError("the sandbox did not become ready", code="sandbox_not_ready")
        return sandbox

    def get(self, name: str) -> Sandbox | None:
        completed = self._run(("sandbox", "get"), [check_sandbox_name(name), "--output", "json"])
        if completed.exit_code != 0:
            if not_found(completed):
                return None
            raise RuntimeUnavailableError("the sandbox could not be read")
        return parse_sandbox(json_object(completed))

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
            page = json_object(completed)
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

    def records(self, name: str) -> tuple[EnforcementRecord, ...]:
        # All levels: filtering with --level warn would hide policy events (ADR-0018).
        args = [check_sandbox_name(name), "--source", "sandbox", "-n", str(LOG_LINES)]
        completed = self._run(("logs",), args)
        if completed.exit_code != 0:
            raise RuntimeUnavailableError("the sandbox log could not be read")
        return parse_records(completed.stdout)

    def check_policy(self, candidate: Path, boundary: Path) -> ProverVerdict:
        if self._cli.prover_version() != f"openshell-prover {VERIFIED_VERSION}":
            raise RuntimeRefusedError(
                "the prover is not the verified version", code="version_mismatch"
            )
        completed = self._cli.prove(candidate, boundary, timeout_seconds=PROVER_TIMEOUT_SECONDS)
        if completed.timed_out:
            raise RuntimeUnavailableError("the prover did not finish", code="prover_stalled")
        return parse_verdict(json_object(completed), completed.exit_code)

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
        status = json_object(completed)
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
        if "no global policy revision found" in error_message(completed):
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

import os
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from aegis.runtime.contract import RuntimeRefusedError

# Installed by NVIDIA's Debian package (ADR-0016). No setting can point AEGIS at another binary.
OPENSHELL = Path("/usr/bin/openshell")
PROVER = Path("/usr/bin/openshell-prover")
VERIFIED_VERSION = "0.1.7"
# The only commands AEGIS runs. Global policies, providers, services, forwards and policy
# changes on live sandboxes are deliberately absent.
ALLOWED_COMMANDS = frozenset(
    {
        ("status",),
        ("workspace", "get"),
        ("workspace", "create"),
        ("sandbox", "create"),
        ("sandbox", "get"),
        ("sandbox", "list"),
        ("sandbox", "exec"),
        ("sandbox", "delete"),
        ("policy", "get"),
        ("logs",),
    }
)
KILL_GRACE_SECONDS = 5
_CHUNK = 64 * 1024


class CommandNotAllowedError(ValueError):
    pass


@dataclass(frozen=True)
class Completed:
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool
    timed_out: bool
    seconds: float


def environment(source: Mapping[str, str]) -> dict[str, str]:
    # The CLI finds its gateway registration and mTLS files under the home directory. Nothing
    # else is passed: no AEGIS secrets, and no OPENSHELL_* override that could weaken TLS.
    scrubbed = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "NO_COLOR": "1"}
    for name in ("HOME", "XDG_CONFIG_HOME"):
        if source.get(name, "").startswith("/"):
            scrubbed[name] = source[name]
    return scrubbed


class OpenShellCli:
    def __init__(
        self,
        gateway: str,
        workspace: str,
        *,
        executable: Path = OPENSHELL,
        prover: Path = PROVER,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._gateway = gateway
        self._workspace = workspace
        self._executable = executable
        self._prover = prover
        self._env = environment(os.environ if environ is None else environ)

    def run(
        self, command: tuple[str, ...], args: Sequence[str], *, timeout: float, limit: int
    ) -> Completed:
        if command not in ALLOWED_COMMANDS:
            raise CommandNotAllowedError(f"openshell {' '.join(command)} is not allowed")
        scope = ["--gateway", self._gateway, "--workspace", self._workspace, "--color", "never"]
        return self._spawn([str(self._executable), *scope, *command, *args], timeout, limit)

    def version(self) -> str:
        return self._spawn([str(self._executable), "--version"], 10, 1024).stdout.strip()

    def prover_version(self) -> str:
        return self._spawn([str(self._prover), "--version"], 10, 1024).stdout.strip()

    def prove(self, candidate: Path, boundary: Path, *, timeout_seconds: int) -> Completed:
        argv = [
            str(self._prover),
            "check",
            str(candidate),
            "--boundary",
            str(boundary),
            "--output",
            "json",
            "--timeout",
            f"{timeout_seconds}s",
        ]
        return self._spawn(argv, timeout_seconds + 10, 256 * 1024)

    def _spawn(self, argv: list[str], timeout: float, limit: int) -> Completed:
        started = time.monotonic()
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed binary, allow-listed command
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._env,
                cwd="/",
                start_new_session=True,
            )
        except OSError:
            raise RuntimeRefusedError(
                f"{Path(argv[0]).name} could not be started", code="cli_missing"
            ) from None
        if process.stdout is None or process.stderr is None:
            raise RuntimeRefusedError("the CLI's output could not be captured")
        out, err = _Reader(process.stdout, limit), _Reader(process.stderr, limit)
        timed_out = False
        try:
            process.wait(timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            # The CLI runs in its own session, so this also stops anything it started.
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(KILL_GRACE_SECONDS)
        out.join()
        err.join()
        return Completed(
            exit_code=process.returncode,
            stdout=out.text(),
            stderr=err.text(),
            truncated=out.truncated or err.truncated,
            timed_out=timed_out,
            seconds=time.monotonic() - started,
        )


class _Reader:
    # Keeps at most `limit` bytes and discards the rest, so a flood of output can neither
    # exhaust memory nor block the process on a full pipe.
    def __init__(self, stream: IO[bytes], limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self._kept = bytearray()
        self.truncated = False
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()

    def _read(self) -> None:
        with self._stream:
            while chunk := self._stream.read(_CHUNK):
                room = self._limit - len(self._kept)
                if len(chunk) > room:
                    self.truncated = True
                self._kept += chunk[: max(room, 0)]

    def join(self) -> None:
        self._thread.join(KILL_GRACE_SECONDS)

    def text(self) -> str:
        return self._kept.decode(errors="replace")

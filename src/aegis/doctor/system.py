import shutil
import socket
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

COMMAND_TIMEOUT_SECONDS = 15.0
CONNECT_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class Memory:
    total_bytes: int
    available_bytes: int


class System(Protocol):
    def python_version(self) -> tuple[int, int, int]: ...
    def python_prefix(self) -> Path: ...
    def which(self, program: str) -> str | None: ...
    def run(self, argv: Sequence[str], cwd: Path) -> CommandResult: ...
    def disk_free_bytes(self, path: Path) -> int | None: ...
    def memory(self) -> Memory | None: ...
    def can_bind(self, host: str, port: int) -> bool: ...
    def can_connect(self, host: str, port: int) -> bool: ...


class HostSystem:
    def python_version(self) -> tuple[int, int, int]:
        return sys.version_info.major, sys.version_info.minor, sys.version_info.micro

    def python_prefix(self) -> Path:
        return Path(sys.prefix)

    def which(self, program: str) -> str | None:
        return shutil.which(program)

    def run(self, argv: Sequence[str], cwd: Path) -> CommandResult:
        try:
            completed = subprocess.run(  # noqa: S603 - argv[0] comes from which()
                list(argv),
                cwd=cwd,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=COMMAND_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(-1, "", f"timed out after {COMMAND_TIMEOUT_SECONDS:.0f}s")
        except OSError as error:
            return CommandResult(-1, "", str(error))
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)

    def disk_free_bytes(self, path: Path) -> int | None:
        try:
            return shutil.disk_usage(path).free
        except OSError:
            return None

    def memory(self) -> Memory | None:
        try:
            lines = Path("/proc/meminfo").read_text(encoding="ascii").splitlines()
        except OSError:
            return None
        fields: dict[str, int] = {}
        for line in lines:
            key, _, rest = line.partition(":")
            parts = rest.split()
            if parts and parts[0].isdigit():
                fields[key] = int(parts[0]) * 1024
        if "MemTotal" not in fields or "MemAvailable" not in fields:
            return None
        return Memory(fields["MemTotal"], fields["MemAvailable"])

    def can_bind(self, host: str, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((host, port))
            except OSError:
                return False
        return True

    def can_connect(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_SECONDS):
                return True
        except OSError:
            return False

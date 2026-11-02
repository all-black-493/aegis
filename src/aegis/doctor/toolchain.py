import json
from dataclasses import dataclass
from pathlib import Path

from aegis.doctor.model import FAIL, OPTIONAL, PASS, REQUIRED, SKIP, WARN, CheckResult
from aegis.doctor.system import System

REQUIRED_PYTHON = (3, 13)


@dataclass(frozen=True)
class Docker:
    executable: str | None
    root_dir: Path | None


def check_python(system: System) -> CheckResult:
    version = system.python_version()
    text = ".".join(str(part) for part in version)
    if version[:2] == REQUIRED_PYTHON:
        return CheckResult("Python 3.13", REQUIRED, PASS, text)
    return CheckResult(
        "Python 3.13",
        REQUIRED,
        FAIL,
        f"found {text}; run `make doctor` so uv selects 3.13",
    )


def check_project_environment(system: System, root: Path) -> CheckResult:
    name = "Project environment"
    prefix = system.python_prefix()
    expected = root / ".venv"
    if prefix.resolve() == expected.resolve():
        return CheckResult(name, OPTIONAL, PASS, str(expected))
    return CheckResult(
        name,
        OPTIONAL,
        WARN,
        f"running from {prefix}, not {expected}; use `make doctor`",
    )


def check_uv(system: System, root: Path) -> CheckResult:
    uv = system.which("uv")
    if uv is None:
        return CheckResult("uv", REQUIRED, FAIL, "not found on PATH")
    result = system.run([uv, "--version"], root)
    if result.returncode != 0:
        return CheckResult("uv", REQUIRED, FAIL, first_line(result.stderr))
    return CheckResult("uv", REQUIRED, PASS, result.stdout.strip())


def check_docker_engine(system: System, root: Path) -> tuple[CheckResult, Docker]:
    name = "Docker Engine"
    docker = system.which("docker")
    if docker is None:
        return CheckResult(name, REQUIRED, FAIL, "docker CLI not found on PATH"), Docker(None, None)
    result = system.run([docker, "info", "--format", "{{json .}}"], root)
    info = json_object(result.stdout)
    version = str(info.get("ServerVersion") or "")
    if result.returncode != 0 or not version:
        detail = f"daemon not reachable: {first_line(result.stderr)}"
        if "permission denied" in result.stderr.lower():
            detail += " (add your user to the docker group, or use rootless Docker)"
        return CheckResult(name, REQUIRED, FAIL, detail), Docker(docker, None)
    root_dir = info.get("DockerRootDir")
    docker_root = Path(root_dir) if isinstance(root_dir, str) and root_dir else None
    return CheckResult(name, REQUIRED, PASS, version), Docker(docker, docker_root)


def check_docker_compose(system: System, root: Path, docker: Docker) -> CheckResult:
    name = "Docker Compose v2"
    if docker.executable is None:
        return CheckResult(name, REQUIRED, SKIP, "blocked by: docker CLI not found")
    result = system.run([docker.executable, "compose", "version", "--short"], root)
    version = result.stdout.strip().removeprefix("v")
    major = version.split(".")[0]
    if result.returncode != 0 or not major.isdigit():
        return CheckResult(name, REQUIRED, FAIL, "the `docker compose` plugin is not available")
    if int(major) < 2:
        return CheckResult(name, REQUIRED, FAIL, f"found {version}; version 2 or later is required")
    return CheckResult(name, REQUIRED, PASS, version)


def json_object(text: str) -> dict[str, object]:
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def first_line(text: str) -> str:
    return next((line.strip() for line in text.splitlines() if line.strip()), "no output")

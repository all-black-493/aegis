from pathlib import Path

from aegis.config.settings import (
    ModelProviderKind,
    SandboxRuntimeKind,
    load_model_settings,
    load_runtime_settings,
)
from aegis.doctor.model import FAIL, OPTIONAL, PASS, REQUIRED, SKIP, WARN, CheckResult
from aegis.doctor.system import System
from aegis.integrations.ollama.provider import VERIFIED_VERSION
from aegis.integrations.openshell.cli import VERIFIED_VERSION as VERIFIED_OPENSHELL

MIN_LANDLOCK_ABI = 3


_MODEL_HINTS = {
    "unreachable": "start it with `make up-local-ai`",
    "model_missing": "pull it with `make model-pull`",
    "digest_mismatch": "the model differs from AEGIS_OLLAMA_MODEL_DIGEST",
    "remote_model": "remote-backed models are refused",
    "not_generative": "the model cannot generate text",
}


_RUNTIME_HINTS = {
    "cli_missing": f"install the OpenShell {VERIFIED_OPENSHELL} package",
    "version_mismatch": f"AEGIS is verified with OpenShell {VERIFIED_OPENSHELL} only (ADR-0016)",
    "unreachable": "start it with `systemctl --user start openshell-gateway`",
    "not_connected": "register and select the gateway named by AEGIS_OPENSHELL_GATEWAY",
    "workspace_missing": "create it with `make openshell-init`",
    "global_policy_active": "a global policy would replace AEGIS's sandbox policies",
}


def check_model_provider(system: System, env_values: dict[str, str] | None) -> CheckResult:
    name = "Model provider"
    if env_values is None:
        return CheckResult(name, OPTIONAL, SKIP, "blocked by: .env configuration")
    settings = load_model_settings(env_values)
    if settings.provider is ModelProviderKind.MOCK or settings.ollama is None:
        return CheckResult(name, OPTIONAL, PASS, "mock provider (deterministic, offline)")
    ollama = settings.ollama
    status = system.model_status(settings)
    if not status.healthy or status.identity is None:
        hint = _MODEL_HINTS.get(status.detail, "see ADR-0014")
        return CheckResult(name, REQUIRED, FAIL, f"{ollama.model}: {status.detail}; {hint}")
    identity = status.identity
    digest = (identity.digest or "")[:12]
    detail = f"{ollama.model} ({digest}) on Ollama {identity.runtime_version}"
    if identity.runtime_version != VERIFIED_VERSION:
        return CheckResult(
            name, REQUIRED, WARN, f"{detail}; the adapter was verified with {VERIFIED_VERSION}"
        )
    return CheckResult(name, REQUIRED, PASS, detail)


def check_sandbox_runtime(system: System, env_values: dict[str, str] | None) -> CheckResult:
    name = "NVIDIA OpenShell"
    if env_values is None:
        return CheckResult(name, OPTIONAL, SKIP, "blocked by: .env configuration")
    settings = load_runtime_settings(env_values)
    if settings.runtime is SandboxRuntimeKind.NONE:
        return CheckResult(
            name, OPTIONAL, SKIP, "disabled (AEGIS_SANDBOX_RUNTIME=none); sandbox tasks are refused"
        )
    abi = system.landlock_abi()
    if abi is None or abi < MIN_LANDLOCK_ABI:
        detail = f"Landlock ABI {abi or 'unavailable'}; OpenShell needs ABI {MIN_LANDLOCK_ABI}"
        return CheckResult(name, REQUIRED, FAIL, detail)
    status = system.runtime_status(settings)
    if not status.healthy:
        hint = _RUNTIME_HINTS.get(status.detail, "see ADR-0016")
        return CheckResult(name, REQUIRED, FAIL, f"{status.detail}; {hint}")
    openshell = settings.openshell
    image_problem = _probe_image_problem(system, openshell.image)
    if image_problem is not None:
        return CheckResult(name, REQUIRED, FAIL, image_problem)
    detail = (
        f"{status.version} via gateway {openshell.gateway}, workspace {openshell.workspace},"
        f" Landlock ABI {abi}, probe image {(openshell.image or '')[7:19]}"
    )
    return CheckResult(name, REQUIRED, PASS, detail)


def _probe_image_problem(system: System, image: str | None) -> str | None:
    if image is None:
        return "AEGIS_OPENSHELL_IMAGE is not set; run `make openshell-image` and add its output"
    docker = system.which("docker")
    if docker is None:
        return "the Docker CLI is needed to find the probe image"
    found = system.run([docker, "image", "inspect", "--format", "{{.Id}}", image], Path.cwd())
    if found.returncode != 0 or found.stdout.strip() != image:
        return "the probe image is not present; run `make openshell-image`"
    return None

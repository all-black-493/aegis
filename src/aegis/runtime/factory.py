from aegis.config.settings import RuntimeSettings, SandboxRuntimeKind
from aegis.integrations.openshell.runtime import OpenShellRuntime
from aegis.runtime.contract import SandboxRuntime
from aegis.runtime.disabled import DisabledRuntime


def build_runtime(settings: RuntimeSettings) -> SandboxRuntime:
    if settings.runtime is SandboxRuntimeKind.OPENSHELL:
        return OpenShellRuntime(settings.openshell)
    return DisabledRuntime()

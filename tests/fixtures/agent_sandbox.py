from aegis.runtime.contract import Sandbox
from aegis.runtime.gate import AGENT_PROFILE, AdmittedSandbox, SandboxProfile

AGENT_SANDBOX = "aegis-agent-1"


def admitted(profile: SandboxProfile = AGENT_PROFILE) -> AdmittedSandbox:
    return AdmittedSandbox(Sandbox(AGENT_SANDBOX, "id-1", "Ready", None, {}), profile)

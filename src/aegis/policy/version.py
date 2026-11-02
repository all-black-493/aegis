import hashlib
from pathlib import Path
from types import ModuleType

from aegis.policy import facts, rules
from aegis.policy.rules import EXECUTION_RULES, SUBMISSION_RULES, Policy

# Bump on every change to aegis.policy.facts or aegis.policy.rules; the fingerprint test will fail
# until the version and the pinned fingerprint are updated together.
POLICY_VERSION = "2026.11.02-2"


def fingerprint(version: str, modules: tuple[ModuleType, ...] = (facts, rules)) -> str:
    digest = hashlib.sha256(version.encode())
    for module in modules:
        if module.__file__ is None:
            raise RuntimeError(f"{module.__name__} has no source file to fingerprint")
        digest.update(b"\0" + Path(module.__file__).read_bytes())
    return digest.hexdigest()


CURRENT_POLICY = Policy(
    version=POLICY_VERSION,
    digest=fingerprint(POLICY_VERSION),
    submission_rules=SUBMISSION_RULES,
    execution_rules=EXECUTION_RULES,
)

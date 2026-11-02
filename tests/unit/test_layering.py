import ast
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"
SECURITY_PACKAGES = ("aegis.authorization", "aegis.policy")
AUDIT_INDEPENDENT_OF = (
    "aegis.identity",
    "aegis.authorization",
    "aegis.policy",
    "aegis.tasks",
    "aegis.jobs",
)
AUTHORIZATION_INDEPENDENT_OF = (
    "aegis.db",
    "aegis.audit",
    "aegis.identity",
    "aegis.tasks",
    "aegis.jobs",
    "sqlalchemy",
    "psycopg",
    "alembic",
)
EVALUATION_FRAMEWORKS = ("deepeval", "deepteam")
MODEL_PACKAGES = ("aegis.model_providers", "aegis.integrations")
MODEL_PACKAGES_INDEPENDENT_OF = (
    "aegis.db",
    "aegis.audit",
    "aegis.identity",
    "aegis.authorization",
    "aegis.policy",
    "aegis.tasks",
    "aegis.jobs",
    "sqlalchemy",
    "psycopg",
    "alembic",
)
# The sandbox runtime enforces nothing AEGIS decides and depends on none of AEGIS's state.
RUNTIME_PACKAGES = ("aegis.runtime", "aegis.integrations.openshell")
ENVIRONMENT_ACCESS = frozenset({"environ", "environb", "getenv", "putenv", "unsetenv"})


@dataclass(frozen=True)
class Rule:
    source: str
    forbidden: str
    reason: str
    allowed: tuple[str, ...] = ()


RULES = (
    *(
        Rule(package, "aegis.config", "configuration must not influence security decisions")
        for package in SECURITY_PACKAGES
    ),
    *(
        Rule("aegis.audit", package, "audit depends only on configuration and the database")
        for package in AUDIT_INDEPENDENT_OF
    ),
    *(
        Rule("aegis.authorization", package, "authorization is pure: no storage or I/O")
        for package in AUTHORIZATION_INDEPENDENT_OF
    ),
    *(
        Rule("aegis", framework, "evaluation frameworks stay outside the application (ADR-0012)")
        for framework in EVALUATION_FRAMEWORKS
    ),
    *(
        Rule(source, forbidden, "model providers know nothing of AEGIS's state or decisions")
        for source in MODEL_PACKAGES
        for forbidden in MODEL_PACKAGES_INDEPENDENT_OF
    ),
    *(
        Rule(package, model, "decisions cannot depend on the model")
        for package in SECURITY_PACKAGES
        for model in MODEL_PACKAGES
    ),
    *(
        Rule(source, forbidden, "the sandbox runtime knows nothing of AEGIS's state or decisions")
        for source in RUNTIME_PACKAGES
        for forbidden in MODEL_PACKAGES_INDEPENDENT_OF
    ),
    *(
        Rule(package, runtime, "decisions cannot depend on the sandbox runtime")
        for package in SECURITY_PACKAGES
        for runtime in RUNTIME_PACKAGES
    ),
    Rule("aegis", "aegis.apps", "entry points are leaves", allowed=("aegis.apps",)),
    Rule(
        "aegis",
        "aegis.doctor",
        "only entry points may use the doctor",
        allowed=("aegis.doctor", "aegis.apps"),
    ),
)


def _under(module: str, package: str) -> bool:
    return module == package or module.startswith(package + ".")


def _module_name(path: Path, src: Path) -> str:
    parts = list(path.relative_to(src).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _imports(tree: ast.AST, module: str, is_package: bool) -> Iterator[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = module.split(".") if is_package else module.split(".")[:-1]
                base = base[: len(base) - (node.level - 1)]
                target = ".".join([*base, node.module] if node.module else base)
            else:
                target = node.module or ""
            yield target
            yield from (f"{target}.{alias.name}" for alias in node.names)


def _reads_environment(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and node.attr in ENVIRONMENT_ACCESS
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
        ):
            return True
        if (
            isinstance(node, ast.ImportFrom)
            and node.module == "os"
            and any(alias.name in ENVIRONMENT_ACCESS for alias in node.names)
        ):
            return True
    return False


def violations(src: Path) -> list[str]:
    found: set[str] = set()
    for path in sorted(src.rglob("*.py")):
        module = _module_name(path, src)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = set(_imports(tree, module, path.name == "__init__.py"))
        for rule in RULES:
            if not _under(module, rule.source) or any(_under(module, a) for a in rule.allowed):
                continue
            found.update(
                f"{module} imports {target}: {rule.reason}"
                for target in imports
                if _under(target, rule.forbidden)
            )
        if _under(module, "aegis.config"):
            found.update(
                f"{module} imports {target}: configuration is the bottom layer"
                for target in imports
                if _under(target, "aegis") and not _under(target, "aegis.config")
            )
        if any(_under(module, package) for package in SECURITY_PACKAGES) and _reads_environment(
            tree
        ):
            found.add(f"{module} reads the environment: security decisions must not depend on it")
    return sorted(found)


def _write(root: Path, relative: str, source: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)


def test_source_tree_respects_the_layering_rules() -> None:
    assert violations(SRC) == []


@pytest.mark.parametrize(
    ("relative", "source", "reason"),
    [
        ("aegis/policy/rules.py", "from aegis.config.settings import X\n", "must not influence"),
        (
            "aegis/authorization/catalog.py",
            "from ..config import variables\n",
            "must not influence",
        ),
        ("aegis/authorization/catalog.py", "import os\nX = os.environ.get('A')\n", "environment"),
        ("aegis/policy/rules.py", "from os import getenv\n", "environment"),
        ("aegis/tasks/service.py", "import aegis.apps.api\n", "entry points are leaves"),
        ("aegis/tasks/service.py", "from aegis.doctor import checks\n", "only entry points"),
        ("aegis/config/settings.py", "from aegis.audit import recorder\n", "bottom layer"),
        ("aegis/audit/recorder.py", "from aegis.identity import service\n", "audit depends only"),
        ("aegis/audit/recorder.py", "from ..tasks.service import x\n", "audit depends only"),
        ("aegis/authorization/access.py", "import sqlalchemy\n", "authorization is pure"),
        ("aegis/authorization/access.py", "from aegis.db import engine\n", "authorization is pure"),
        ("aegis/jobs/worker.py", "import deepeval\n", "outside the application"),
        ("aegis/policy/rules.py", "from deepteam import red_team\n", "outside the application"),
        ("aegis/apps/worker/__main__.py", "from deepeval.metrics import X\n", "outside the"),
        ("aegis/model_providers/mock.py", "from aegis.db import engine\n", "know nothing"),
        ("aegis/model_providers/contract.py", "import sqlalchemy\n", "know nothing"),
        (
            "aegis/integrations/ollama/client.py",
            "from aegis.tasks import service\n",
            "know nothing",
        ),
        ("aegis/policy/rules.py", "from aegis.model_providers import contract\n", "the model"),
        ("aegis/authorization/access.py", "import aegis.integrations.ollama\n", "the model"),
        (
            "aegis/runtime/contract.py",
            "from aegis.audit import recorder\n",
            "sandbox runtime knows",
        ),
        ("aegis/runtime/factory.py", "from aegis.policy import rules\n", "sandbox runtime knows"),
        ("aegis/policy/rules.py", "from aegis.runtime import contract\n", "depend on the sandbox"),
        (
            "aegis/authorization/access.py",
            "import aegis.runtime.contract\n",
            "depend on the sandbox",
        ),
    ],
)
def test_forbidden_dependencies_are_detected(
    tmp_path: Path, relative: str, source: str, reason: str
) -> None:
    _write(tmp_path, relative, source)

    found = violations(tmp_path)

    assert found
    assert all(reason in finding for finding in found)


def test_permitted_dependencies_are_not_reported(tmp_path: Path) -> None:
    _write(tmp_path, "aegis/apps/cli/main.py", "import aegis.doctor\nimport aegis.config\n")
    _write(tmp_path, "aegis/tasks/service.py", "from aegis.config.settings import X\n")
    _write(tmp_path, "aegis/policy/rules.py", "from aegis.authorization import catalog\n")
    _write(tmp_path, "aegis/config/logs.py", "from aegis.config.settings import X\nimport os\n")
    _write(tmp_path, "aegis/model_providers/factory.py", "from aegis.config.settings import X\n")
    _write(tmp_path, "aegis/jobs/worker.py", "from aegis.model_providers import contract\n")

    assert violations(tmp_path) == []

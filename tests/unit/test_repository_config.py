import re
from pathlib import Path

from aegis.config.envfile import PLACEHOLDER, parse_env_file
from aegis.config.settings import DEFAULT_OLLAMA_PORT
from aegis.config.variables import BY_NAME, REQUIRED_NAMES, SECRET_NAMES, TEMPLATE_NAMES

ROOT = Path(__file__).resolve().parents[2]


def test_env_template_lists_exactly_the_template_variables() -> None:
    template = parse_env_file(ROOT / ".env.example")

    assert list(template) == list(TEMPLATE_NAMES)


def test_env_template_contains_no_real_secret() -> None:
    template = parse_env_file(ROOT / ".env.example")

    assert {name for name, value in template.items() if value == PLACEHOLDER} == SECRET_NAMES


def test_compose_uses_registered_variables_safely() -> None:
    compose = (ROOT / "docker-compose.yml").read_text()
    uses = re.findall(r"\$\{(AEGIS_[A-Z_]+)(:[?-])([^}]*)\}", compose)

    assert uses
    assert {name for name, _, _ in uses} <= BY_NAME.keys()
    for name, operator, default in uses:
        if name in REQUIRED_NAMES:
            assert operator == ":?", f"{name} must fail when unset"
        else:
            # Optional variables fall back to exactly the default the application uses.
            assert (name, operator, default) == (
                "AEGIS_OLLAMA_PORT",
                ":-",
                str(DEFAULT_OLLAMA_PORT),
            )


def test_documented_make_targets_match_makefile() -> None:
    makefile = (ROOT / "Makefile").read_text()
    guide = (ROOT / "docs/development/getting-started.md").read_text()
    targets = set(re.findall(r"^([a-z-]+):.*## ", makefile, re.MULTILINE))
    documented = set(re.findall(r"`make ([a-z-]+)`", guide))

    assert documented == targets

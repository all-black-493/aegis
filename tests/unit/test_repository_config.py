import re
from pathlib import Path

from aegis.doctor.checks import ENV_KEYS, PASSWORD_PLACEHOLDER
from aegis.doctor.envfile import parse_env_file

ROOT = Path(__file__).resolve().parents[2]


def test_env_template_matches_doctor_and_compose() -> None:
    template = parse_env_file(ROOT / ".env.example")
    compose = (ROOT / "docker-compose.yml").read_text()
    compose_keys = set(re.findall(r"\$\{(AEGIS_[A-Z_]+)", compose))

    assert set(template) == set(ENV_KEYS) == compose_keys


def test_env_template_contains_no_real_password() -> None:
    template = parse_env_file(ROOT / ".env.example")

    assert template["AEGIS_POSTGRES_PASSWORD"] == PASSWORD_PLACEHOLDER


def test_documented_make_targets_match_makefile() -> None:
    makefile = (ROOT / "Makefile").read_text()
    guide = (ROOT / "docs/development/getting-started.md").read_text()
    targets = set(re.findall(r"^([a-z-]+):.*## ", makefile, re.MULTILINE))
    documented = set(re.findall(r"`make ([a-z-]+)`", guide))

    assert documented == targets

import stat
from pathlib import Path

from aegis.config.envfile import PLACEHOLDER, EnvFileError, parse_env_file
from aegis.config.settings import (
    MIN_SECRET_LENGTH,
    SettingsError,
    load_api_settings,
    load_common_settings,
    load_model_settings,
    load_runtime_settings,
    load_token_pepper,
    load_worker_settings,
)
from aegis.config.variables import REQUIRED_NAMES, SECRET_NAMES
from aegis.doctor.model import FAIL, OPTIONAL, PASS, REQUIRED, SKIP, WARN, CheckResult


def check_env_file(root: Path) -> tuple[dict[str, str] | None, CheckResult]:
    name = ".env configuration"
    path = root / ".env"
    if not path.is_file():
        return None, CheckResult(name, REQUIRED, FAIL, "not found; run `make setup`")
    try:
        values = parse_env_file(path)
    except EnvFileError as error:
        return None, CheckResult(name, REQUIRED, FAIL, f"invalid: {error}")
    except (OSError, UnicodeDecodeError):
        return None, CheckResult(name, REQUIRED, FAIL, "could not be read as UTF-8 text")
    problem = _env_problem(values)
    if problem is not None:
        return values, CheckResult(name, REQUIRED, FAIL, problem)
    return values, CheckResult(name, REQUIRED, PASS, "PostgreSQL settings are present")


def check_env_permissions(root: Path) -> CheckResult:
    name = ".env permissions"
    path = root / ".env"
    if not path.is_file():
        return CheckResult(name, OPTIONAL, SKIP, ".env not found")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        return CheckResult(
            name,
            OPTIONAL,
            WARN,
            f"mode {mode:o} lets other users access it; run `chmod 600 .env`",
        )
    return CheckResult(name, OPTIONAL, PASS, f"mode {mode:o}")


def check_env_template(root: Path, env_values: dict[str, str] | None) -> CheckResult:
    name = ".env up to date"
    if env_values is None:
        return CheckResult(name, OPTIONAL, SKIP, "blocked by: .env configuration")
    try:
        template = parse_env_file(root / ".env.example")
    except (OSError, UnicodeDecodeError, EnvFileError):
        return CheckResult(name, OPTIONAL, SKIP, ".env.example could not be read")
    missing = [key for key in template if key not in env_values]
    if missing:
        return CheckResult(
            name, OPTIONAL, WARN, f"missing {', '.join(missing)}; run `make env-upgrade`"
        )
    return CheckResult(name, OPTIONAL, PASS, "defines every variable in .env.example")


def _env_problem(values: dict[str, str]) -> str | None:
    missing = [key for key in REQUIRED_NAMES if not values.get(key)]
    if missing:
        return f"missing or empty: {', '.join(missing)}; run `make env-upgrade`"
    for key in sorted(SECRET_NAMES & values.keys()):
        if values[key] == PLACEHOLDER:
            return f"{key} is still the placeholder; see getting-started troubleshooting"
        if len(values[key]) < MIN_SECRET_LENGTH:
            return f"{key} is shorter than {MIN_SECRET_LENGTH} characters"
    if postgres_port(values) is None:
        return "AEGIS_POSTGRES_PORT must be an integer from 1024 to 65535"
    try:
        load_common_settings(values)
        load_api_settings(values)
        load_worker_settings(values)
        load_model_settings(values)
        load_runtime_settings(values)
        load_token_pepper(values)
    except SettingsError as error:
        return "; ".join(error.problems)
    return None


def postgres_port(values: dict[str, str] | None) -> int | None:
    raw = (values or {}).get("AEGIS_POSTGRES_PORT", "")
    if not (raw.isascii() and raw.isdigit()):
        return None
    port = int(raw)
    return port if 1024 <= port <= 65535 else None

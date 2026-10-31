import re
from pathlib import Path

_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class EnvFileError(ValueError):
    pass


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not _KEY.fullmatch(key):
            raise EnvFileError(f"line {number}: expected KEY=VALUE")
        if key in values:
            raise EnvFileError(f"line {number}: duplicate key {key}")
        values[key] = _unquote(value.strip(), number)
    return values


def _unquote(value: str, number: int) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    if value.startswith(("'", '"')) or any(character.isspace() for character in value):
        raise EnvFileError(f"line {number}: value must be fully quoted or contain no whitespace")
    return value

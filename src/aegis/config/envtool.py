import argparse
import os
import secrets
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from aegis.config.envfile import PLACEHOLDER, EnvFileError, parse_env_text
from aegis.config.variables import BY_NAME, PREFIX, SECRET_NAMES

SECRET_BYTES = 32


class EnvToolError(Exception):
    pass


@dataclass(frozen=True)
class CreateResult:
    created: bool
    generated: tuple[str, ...]


@dataclass(frozen=True)
class UpgradeResult:
    added: tuple[str, ...]
    generated: tuple[str, ...]
    unknown: tuple[str, ...]


def generate_secret() -> str:
    return secrets.token_hex(SECRET_BYTES)


def create_env_file(template: Path, target: Path) -> CreateResult:
    text = _read_template(template)
    generated: list[str] = []
    lines = []
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        key, separator, value = stripped.partition("=")
        if separator and not stripped.startswith("#") and value.strip() == PLACEHOLDER:
            generated.append(key.strip())
            line = f"{key.strip()}={generate_secret()}\n"
        lines.append(line)
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        return CreateResult(created=False, generated=())
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write("".join(lines))
    return CreateResult(created=True, generated=tuple(generated))


def upgrade_env_file(template: Path, target: Path) -> UpgradeResult:
    template_values = parse_env_text(_read_template(template))
    try:
        descriptor = os.open(target, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW)
    except FileNotFoundError:
        raise EnvToolError(f"{target} not found; run `make setup` first") from None
    except OSError:
        raise EnvToolError(f"{target} must be a regular file, not a symlink") from None
    try:
        mode = os.fstat(descriptor).st_mode
        if not stat.S_ISREG(mode):
            raise EnvToolError(f"{target} must be a regular file")
        if stat.S_IMODE(mode) & 0o077:
            raise EnvToolError(f"{target} is accessible to other users; run `chmod 600 {target}`")
        text = _read_all(descriptor, target)
        try:
            current = parse_env_text(text)
        except EnvFileError as error:
            raise EnvToolError(f"{target} is invalid: {error}") from None
        missing = [name for name in template_values if name not in current]
        unknown = tuple(name for name in current if name.startswith(PREFIX) and name not in BY_NAME)
        if not missing:
            return UpgradeResult(added=(), generated=(), unknown=unknown)
        addition = "" if not text or text.endswith("\n") else "\n"
        generated = []
        for name in missing:
            value = template_values[name]
            if value == PLACEHOLDER:
                value = generate_secret()
                generated.append(name)
            addition += f"{name}={value}\n"
        _write_all(descriptor, addition.encode("utf-8"))
        os.fsync(descriptor)
        return UpgradeResult(added=tuple(missing), generated=tuple(generated), unknown=unknown)
    finally:
        os.close(descriptor)


def _read_template(template: Path) -> str:
    try:
        text = template.read_text(encoding="utf-8")
        values = parse_env_text(text)
    except (OSError, UnicodeDecodeError, EnvFileError) as error:
        raise EnvToolError(f"{template} cannot be used: {error}") from None
    problems = []
    for name, value in values.items():
        if name not in BY_NAME:
            problems.append(f"{name} is not a known AEGIS variable")
        elif name in SECRET_NAMES and value != PLACEHOLDER:
            problems.append(f"{name} is secret and must use the placeholder")
        elif name not in SECRET_NAMES and value == PLACEHOLDER:
            problems.append(f"{name} is not secret and must not use the placeholder")
    if problems:
        raise EnvToolError(f"{template} is invalid: " + "; ".join(problems))
    return text


def _read_all(descriptor: int, target: Path) -> str:
    chunks = []
    while chunk := os.read(descriptor, 65536):
        chunks.append(chunk)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError:
        raise EnvToolError(f"{target} is not valid UTF-8") from None


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(descriptor, view) :]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aegis.config.envtool")
    parser.add_argument("command", choices=("create", "upgrade"))
    parser.add_argument("--template", type=Path, default=Path(".env.example"))
    parser.add_argument("--target", type=Path, default=Path(".env"))
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            created = create_env_file(args.template, args.target)
            if created.created:
                count = len(created.generated)
                print(f"Created {args.target} with {count} generated secret(s) (file mode 600).")
            else:
                print(f"{args.target} already exists; leaving it unchanged.")
        else:
            upgraded = upgrade_env_file(args.template, args.target)
            if upgraded.added:
                print(f"Added to {args.target}: {', '.join(upgraded.added)}")
                if upgraded.generated:
                    print(f"Generated secrets for: {', '.join(upgraded.generated)}")
            else:
                print(f"No changes: {args.target} already defines every variable in the template.")
            if upgraded.unknown:
                print(f"Not known to AEGIS (left unchanged): {', '.join(upgraded.unknown)}")
    except (EnvToolError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta

from aegis.config.settings import Secret

TOKEN_PREFIX = "aegis_pat_"  # noqa: S105
HASH_SCHEME = "hmac-sha256-v1"
DEFAULT_LIFETIME = timedelta(days=30)
MAX_LIFETIME = timedelta(days=90)
LOOKUP_BYTES = 16
SECRET_BYTES = 32
MAX_TOKEN_LENGTH = 128
_TOKEN = re.compile(rf"{TOKEN_PREFIX}([a-z2-7]{{26}})_([a-z2-7]{{52}})")


@dataclass(frozen=True, repr=False)
class Token:
    lookup_id: str
    _secret: str

    def reveal(self) -> str:
        return f"{TOKEN_PREFIX}{self.lookup_id}_{self._secret}"

    def digest(self, pepper: Secret) -> bytes:
        message = f"{self.lookup_id}:{self._secret}".encode()
        return hmac.new(pepper.reveal().encode(), message, hashlib.sha256).digest()

    def matches(self, pepper: Secret, expected: bytes) -> bool:
        return hmac.compare_digest(self.digest(pepper), expected)

    def __repr__(self) -> str:
        return f"Token(lookup_id={self.lookup_id!r}, secret='[REDACTED]')"

    __str__ = __repr__


def generate_token() -> Token:
    return Token(_random_base32(LOOKUP_BYTES), _random_base32(SECRET_BYTES))


def parse_token(raw: str) -> Token | None:
    if len(raw) > MAX_TOKEN_LENGTH:
        return None
    match = _TOKEN.fullmatch(raw)
    return Token(match[1], match[2]) if match else None


def lifetime(days: int | None) -> timedelta:
    if days is None:
        return DEFAULT_LIFETIME
    if not 1 <= days <= MAX_LIFETIME.days:
        raise ValueError(f"credential lifetime must be 1 to {MAX_LIFETIME.days} days")
    return timedelta(days=days)


def _random_base32(size: int) -> str:
    return base64.b32encode(secrets.token_bytes(size)).decode().rstrip("=").lower()

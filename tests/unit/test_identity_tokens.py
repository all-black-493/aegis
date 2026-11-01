from datetime import timedelta

import pytest

from aegis.config.settings import Secret
from aegis.identity.tokens import (
    TOKEN_PREFIX,
    Token,
    generate_token,
    lifetime,
    parse_token,
)

PEPPER = Secret("unit-test-pepper-0123456789abcdef0123")


def test_generated_tokens_round_trip_through_the_parser() -> None:
    token = generate_token()
    raw = token.reveal()

    assert raw.startswith(TOKEN_PREFIX)
    assert len(raw) == len(TOKEN_PREFIX) + 26 + 1 + 52
    assert parse_token(raw) == token


def test_generated_tokens_are_unique() -> None:
    assert len({generate_token().reveal() for _ in range(1000)}) == 1000


def test_token_representations_hide_the_secret() -> None:
    token = generate_token()
    secret = token.reveal().rsplit("_", 1)[1]

    for text in (repr(token), str(token), f"{token}", repr([token])):
        assert secret not in text
        assert token.lookup_id in text


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "aegis_pat_",
        TOKEN_PREFIX + "a" * 26 + "_" + "a" * 51,
        TOKEN_PREFIX + "a" * 26 + "_" + "a" * 53,
        TOKEN_PREFIX + "a" * 26 + "-" + "a" * 52,
        TOKEN_PREFIX + "a" * 26 + "_" + "A" * 52,
        TOKEN_PREFIX + "a" * 26 + "_" + "1" * 52,
        "Bearer " + TOKEN_PREFIX + "a" * 26 + "_" + "a" * 52,
        TOKEN_PREFIX + "a" * 26 + "_" + "a" * 52 + "\n",
        "x" * 10_000,
    ],
)
def test_malformed_tokens_are_not_parsed(raw: str) -> None:
    assert parse_token(raw) is None


def test_digests_depend_on_the_pepper_and_the_whole_token() -> None:
    token = generate_token()
    other_secret = Token(token.lookup_id, "b" * 52)
    other_lookup = Token("b" * 26, token.reveal().rsplit("_", 1)[1])

    digest = token.digest(PEPPER)

    assert len(digest) == 32
    assert token.matches(PEPPER, digest)
    assert not token.matches(Secret("other-pepper-0123456789abcdef0123456"), digest)
    assert not other_secret.matches(PEPPER, digest)
    assert not other_lookup.matches(PEPPER, digest)


@pytest.mark.parametrize(
    ("days", "expected"),
    [(None, timedelta(days=30)), (1, timedelta(days=1)), (90, timedelta(days=90))],
)
def test_lifetimes_default_to_30_days_and_stop_at_90(days: int | None, expected: timedelta) -> None:
    assert lifetime(days) == expected


@pytest.mark.parametrize("days", [0, -1, 91, 10_000])
def test_lifetimes_outside_the_limits_are_refused(days: int) -> None:
    with pytest.raises(ValueError, match="1 to 90 days"):
        lifetime(days)

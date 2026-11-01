import pytest

from aegis.config.settings import DatabaseSettings, Secret
from aegis.db.admin import recreate_test_database

ADMIN = DatabaseSettings("127.0.0.1", 5433, "aegis", "aegis", Secret("x" * 24))


@pytest.mark.parametrize(
    "name",
    ["aegis", "postgres", "template1", "aegis_testing", "Aegis_test", "_test", "a_test; DROP x"],
)
def test_only_databases_named_test_can_be_recreated(name: str) -> None:
    with pytest.raises(ValueError, match="only databases named"):
        recreate_test_database(ADMIN, name)


def test_the_configured_database_is_never_recreated() -> None:
    admin = DatabaseSettings("127.0.0.1", 5433, "aegis_test", "aegis", Secret("x" * 24))

    with pytest.raises(ValueError, match="only databases named"):
        recreate_test_database(admin, "aegis_test")

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SETTINGS = {
    "AEGIS_POSTGRES_USER": "compose_test",
    "AEGIS_POSTGRES_DB": "compose_test",
    "AEGIS_POSTGRES_PASSWORD": "compose-config-test-password",
    "AEGIS_POSTGRES_PORT": "15433",
}


def _compose_config(tmp_path: Path, settings: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env_file = tmp_path / "compose.env"
    env_file.write_text("".join(f"{key}={value}\n" for key, value in settings.items()))
    environment = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_")}
    return subprocess.run(
        [
            "docker",
            "compose",
            "--file",
            str(ROOT / "docker-compose.yml"),
            "--env-file",
            str(env_file),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def postgres(tmp_path: Path) -> dict[str, Any]:
    result = _compose_config(tmp_path, SETTINGS)
    assert result.returncode == 0, result.stderr
    services: dict[str, Any] = json.loads(result.stdout)["services"]
    assert list(services) == ["postgres"]
    postgres: dict[str, Any] = services["postgres"]
    return postgres


def test_postgres_is_a_core_service_without_profile(postgres: dict[str, Any]) -> None:
    assert "profiles" not in postgres


def test_image_is_pinned_to_postgres_17_by_digest(postgres: dict[str, Any]) -> None:
    image: str = postgres["image"]
    assert image.startswith("postgres:17.")
    assert "@sha256:" in image


def test_port_is_published_on_loopback_only(postgres: dict[str, Any]) -> None:
    [port] = postgres["ports"]
    assert port["host_ip"] == "127.0.0.1"
    assert port["published"] == SETTINGS["AEGIS_POSTGRES_PORT"]
    assert port["target"] == 5432


def test_healthcheck_probes_over_tcp(postgres: dict[str, Any]) -> None:
    kind, command = postgres["healthcheck"]["test"]
    assert kind == "CMD-SHELL"
    assert "pg_isready -h 127.0.0.1" in command


def test_data_is_stored_on_a_named_volume(postgres: dict[str, Any]) -> None:
    [volume] = postgres["volumes"]
    assert (volume["type"], volume["source"], volume["target"]) == (
        "volume",
        "postgres-data",
        "/var/lib/postgresql/data",
    )


@pytest.mark.parametrize("key", sorted(SETTINGS))
@pytest.mark.parametrize("value", [None, ""])
def test_missing_or_empty_setting_is_rejected(tmp_path: Path, key: str, value: str | None) -> None:
    settings = {k: v for k, v in SETTINGS.items() if k != key}
    if value is not None:
        settings[key] = value

    result = _compose_config(tmp_path, settings)

    assert result.returncode != 0
    assert key in result.stderr

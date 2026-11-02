import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from aegis.config.settings import DEFAULT_OLLAMA_PORT

ROOT = Path(__file__).resolve().parents[2]
OLLAMA_IMAGE_DIGEST = "da6e0dc5651df159e45686fd663c4dbe1624a52c44d7280eeac1551d8f865532"
SETTINGS = {
    "AEGIS_POSTGRES_USER": "compose_test",
    "AEGIS_POSTGRES_DB": "compose_test",
    "AEGIS_POSTGRES_PASSWORD": "compose-config-test-password",
    "AEGIS_POSTGRES_PORT": "15433",
}


def _compose_config(
    tmp_path: Path, settings: dict[str, str], *profiles: str
) -> subprocess.CompletedProcess[str]:
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
            *(arg for profile in profiles for arg in ("--profile", profile)),
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


def _ollama(tmp_path: Path, settings: dict[str, str]) -> dict[str, Any]:
    result = _compose_config(tmp_path, settings, "local-ai")
    assert result.returncode == 0, result.stderr
    services: dict[str, Any] = json.loads(result.stdout)["services"]
    assert sorted(services) == ["ollama", "postgres"]
    ollama: dict[str, Any] = services["ollama"]
    return ollama


def test_ollama_runs_only_with_the_local_ai_profile(tmp_path: Path) -> None:
    ollama = _ollama(tmp_path, SETTINGS)

    assert ollama["profiles"] == ["local-ai"]


def test_ollama_is_pinned_to_the_verified_image(tmp_path: Path) -> None:
    ollama = _ollama(tmp_path, SETTINGS)

    assert ollama["image"] == f"ollama/ollama@sha256:{OLLAMA_IMAGE_DIGEST}"


@pytest.mark.parametrize(
    ("configured", "published"), [(None, str(DEFAULT_OLLAMA_PORT)), ("11500", "11500")]
)
def test_ollama_is_published_on_loopback_only(
    tmp_path: Path, configured: str | None, published: str
) -> None:
    settings = SETTINGS if configured is None else {**SETTINGS, "AEGIS_OLLAMA_PORT": configured}

    [port] = _ollama(tmp_path, settings)["ports"]

    assert (port["host_ip"], port["published"], port["target"]) == ("127.0.0.1", published, 11434)


def test_ollama_runs_hardened_with_models_on_its_own_volume(tmp_path: Path) -> None:
    ollama = _ollama(tmp_path, SETTINGS)

    [volume] = ollama["volumes"]
    assert (volume["type"], volume["source"], volume["target"]) == (
        "volume",
        "ollama-models",
        "/root/.ollama",
    )
    assert ollama["read_only"] is True
    assert ollama["cap_drop"] == ["ALL"]
    assert ollama["security_opt"] == ["no-new-privileges:true"]
    assert ollama["tmpfs"] == ["/tmp"]  # noqa: S108 (the container's private tmpfs)
    assert ollama["healthcheck"]["test"] == ["CMD", "ollama", "list"]

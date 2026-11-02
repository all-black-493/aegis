import os
import re
import time
from dataclasses import replace

import pytest

from aegis.config.settings import OllamaSettings, load_model_settings
from aegis.doctor.integrations import check_model_provider
from aegis.doctor.model import Requirement, Status
from aegis.doctor.system import HostSystem
from aegis.integrations.ollama.provider import VERIFIED_VERSION, OllamaProvider
from aegis.model_providers.contract import (
    FinishReason,
    GenerationRequest,
    GenerationStoppedError,
)

pytestmark = pytest.mark.local_ai
PROMPT = "Name three primary colours."


def _never() -> bool:
    return False


@pytest.fixture(scope="module")
def ollama() -> OllamaSettings:
    settings = load_model_settings(os.environ).ollama
    if settings is None:
        pytest.fail(
            "set AEGIS_OLLAMA_MODEL, then run `make up-local-ai` and `make model-pull`;"
            " see the getting-started guide"
        )
    return settings


@pytest.fixture(scope="module")
def provider(ollama: OllamaSettings) -> OllamaProvider:
    return OllamaProvider(ollama, timeout_seconds=120)


def test_the_local_model_runs_on_the_verified_runtime(
    ollama: OllamaSettings, provider: OllamaProvider
) -> None:
    status = provider.check()

    assert (status.healthy, status.detail) == (True, "ok")
    assert status.identity is not None
    assert status.identity.runtime_version == VERIFIED_VERSION
    assert re.fullmatch(r"[0-9a-f]{64}", status.identity.digest or "")
    if ollama.digest is not None:
        assert status.identity.digest == ollama.digest


def test_the_doctor_requires_and_identifies_the_local_model(ollama: OllamaSettings) -> None:
    values = {
        "AEGIS_MODEL_PROVIDER": "ollama",
        "AEGIS_OLLAMA_MODEL": ollama.model,
        "AEGIS_OLLAMA_PORT": str(ollama.port),
    }

    check = check_model_provider(HostSystem(), values)

    assert (check.requirement, check.status) == (Requirement.REQUIRED, Status.PASS)
    assert f"on Ollama {VERIFIED_VERSION}" in check.detail


def test_generation_finishes_and_records_the_model(provider: OllamaProvider) -> None:
    complete = provider.generate(GenerationRequest(PROMPT, 128), _never)
    cut = provider.generate(GenerationRequest("Write a long story about the sea.", 3), _never)

    assert complete.finish_reason in (FinishReason.STOP, FinishReason.LENGTH)
    assert complete.text.strip()
    assert complete.prompt_tokens > 0
    assert complete.output_tokens > 0
    assert (cut.finish_reason, cut.output_tokens) == (FinishReason.LENGTH, 3)
    status = provider.check()
    assert status.identity == complete.identity == cut.identity


def test_temperature_zero_with_a_fixed_seed_repeats(provider: OllamaProvider) -> None:
    request = GenerationRequest(PROMPT, 64, temperature=0.0, seed=0)

    first = provider.generate(request, _never)
    second = provider.generate(request, _never)

    assert first.text == second.text


def test_a_stop_request_ends_generation_promptly(provider: OllamaProvider) -> None:
    checks = 0

    def stop_soon() -> bool:
        nonlocal checks
        checks += 1
        return checks > 3

    started = time.monotonic()
    with pytest.raises(GenerationStoppedError):
        provider.generate(
            GenerationRequest("Count slowly from one to five hundred.", 512), stop_soon
        )

    assert time.monotonic() - started < 5


def test_a_wrong_digest_pin_is_refused(ollama: OllamaSettings) -> None:
    status = OllamaProvider(replace(ollama, digest="0" * 64), 120).check()

    assert (status.healthy, status.detail) == (False, "digest_mismatch")

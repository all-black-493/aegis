from aegis.config.settings import ModelProviderKind, ModelSettings
from aegis.model_providers.contract import ModelProvider, ModelUnavailableError
from aegis.model_providers.mock import MockProvider


def build_provider(settings: ModelSettings) -> ModelProvider:
    if settings.provider is ModelProviderKind.MOCK:
        return MockProvider()
    # Refused rather than ignored until the Ollama adapter exists (Phase 2, Increment 2).
    raise ModelUnavailableError(f"the {settings.provider} provider is not available yet")

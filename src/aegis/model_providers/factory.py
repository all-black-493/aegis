from aegis.config.settings import ModelProviderKind, ModelSettings
from aegis.integrations.ollama.provider import OllamaProvider
from aegis.model_providers.contract import ModelProvider, ModelUnavailableError
from aegis.model_providers.mock import MockProvider


def build_provider(settings: ModelSettings) -> ModelProvider:
    if settings.provider is ModelProviderKind.MOCK:
        return MockProvider()
    if settings.ollama is None:
        raise ModelUnavailableError("the Ollama provider is not configured")
    return OllamaProvider(settings.ollama, settings.timeout_seconds)

from aegis.config.settings import ModelProviderKind, ModelSettings
from aegis.integrations.ollama.provider import OllamaProvider
from aegis.model_providers.contract import ModelUnavailableError
from aegis.model_providers.mock import MockProvider
from aegis.model_providers.steps import StepProvider


def build_provider(settings: ModelSettings) -> StepProvider:
    if settings.provider is ModelProviderKind.MOCK:
        return MockProvider()
    if settings.ollama is None:
        raise ModelUnavailableError("the Ollama provider is not configured")
    return OllamaProvider(settings.ollama, settings.timeout_seconds)

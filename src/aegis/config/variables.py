from dataclasses import dataclass
from types import MappingProxyType

PREFIX = "AEGIS_"


@dataclass(frozen=True)
class Variable:
    name: str
    description: str
    secret: bool = False
    in_template: bool = True
    required: bool = False


VARIABLES = (
    Variable("AEGIS_ENV", "development, test or production; unset means production"),
    Variable("AEGIS_LOG_LEVEL", "DEBUG, INFO, WARNING or ERROR; default INFO", in_template=False),
    Variable("AEGIS_POSTGRES_USER", "PostgreSQL bootstrap user", required=True),
    Variable("AEGIS_POSTGRES_DB", "PostgreSQL database", required=True),
    Variable(
        "AEGIS_POSTGRES_PASSWORD", "PostgreSQL bootstrap password", secret=True, required=True
    ),
    Variable("AEGIS_POSTGRES_PORT", "PostgreSQL host port on 127.0.0.1", required=True),
    Variable(
        "AEGIS_DB_OWNER_PASSWORD",
        "password of the aegis_owner role (migrations, administration)",
        secret=True,
        required=True,
    ),
    Variable(
        "AEGIS_DB_APP_PASSWORD",
        "password of the aegis_app role (API, worker)",
        secret=True,
        required=True,
    ),
    Variable("AEGIS_API_PORT", "API port on 127.0.0.1; default 8000", in_template=False),
    Variable(
        "AEGIS_WORKER_POLL_SECONDS", "worker idle poll interval, 1-60; default 1", in_template=False
    ),
    Variable("AEGIS_WORKER_LEASE_SECONDS", "job lease, 10-600; default 30", in_template=False),
    Variable(
        "AEGIS_WORKER_HEARTBEAT_SECONDS",
        "lease renewal interval, at most a third of the lease; default 5",
        in_template=False,
    ),
    Variable(
        "AEGIS_WORKER_SHUTDOWN_GRACE_SECONDS",
        "time a running task gets to finish at shutdown, 0-300; default 10",
        in_template=False,
    ),
    Variable(
        "AEGIS_WORKER_MAX_ATTEMPTS",
        "attempts per task, 1 to the policy's 10; default 3",
        in_template=False,
    ),
    Variable(
        "AEGIS_MODEL_PROVIDER",
        "model provider for the worker: mock or ollama; default mock",
        in_template=False,
    ),
    Variable(
        "AEGIS_OLLAMA_PORT",
        "port of the local Ollama server on 127.0.0.1; default 11436",
        in_template=False,
    ),
    Variable(
        "AEGIS_OLLAMA_MODEL",
        "local Ollama model, required when the provider is ollama",
        in_template=False,
    ),
    Variable(
        "AEGIS_OLLAMA_MODEL_DIGEST",
        "optional pin: the model's 64-character digest from Ollama",
        in_template=False,
    ),
    Variable(
        "AEGIS_MODEL_TIMEOUT_SECONDS",
        "how long a model call may wait for output, 5-600; default 120",
        in_template=False,
    ),
    Variable(
        "AEGIS_SANDBOX_RUNTIME",
        "sandbox runtime: none or openshell; default none, which refuses sandbox tasks",
        in_template=False,
    ),
    Variable(
        "AEGIS_OPENSHELL_GATEWAY",
        "registered OpenShell gateway to use; default openshell",
        in_template=False,
    ),
    Variable(
        "AEGIS_OPENSHELL_WORKSPACE",
        "OpenShell workspace that holds AEGIS's sandboxes; default aegis",
        in_template=False,
    ),
    Variable(
        "AEGIS_OPENSHELL_IMAGE",
        "image ID of the probe image, printed by `make openshell-image`",
        in_template=False,
    ),
    Variable(
        "AEGIS_TOKEN_PEPPER",
        "server-side key for hashing API tokens (API, administration)",
        secret=True,
        required=True,
    ),
)

BY_NAME = MappingProxyType({variable.name: variable for variable in VARIABLES})
SECRET_NAMES = frozenset(variable.name for variable in VARIABLES if variable.secret)
REQUIRED_NAMES = tuple(variable.name for variable in VARIABLES if variable.required)
TEMPLATE_NAMES = tuple(variable.name for variable in VARIABLES if variable.in_template)

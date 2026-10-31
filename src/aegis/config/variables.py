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
)

BY_NAME = MappingProxyType({variable.name: variable for variable in VARIABLES})
SECRET_NAMES = frozenset(variable.name for variable in VARIABLES if variable.secret)
REQUIRED_NAMES = tuple(variable.name for variable in VARIABLES if variable.required)
TEMPLATE_NAMES = tuple(variable.name for variable in VARIABLES if variable.in_template)

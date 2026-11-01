import os
import sys

import uvicorn

from aegis.apps.api.app import create_app
from aegis.apps.api.context import ApiContext
from aegis.audit.recorder import AuditRecorder
from aegis.config.logs import Redactor, configure_logging
from aegis.config.settings import (
    API_HOST,
    DatabaseRole,
    SettingsError,
    load_api_settings,
    load_common_settings,
    load_database_settings,
    load_token_pepper,
)
from aegis.db.engine import create_database_engine


def main() -> int:
    environ = dict(os.environ)
    try:
        common = load_common_settings(environ)
        api = load_api_settings(environ)
        database = load_database_settings(environ, DatabaseRole.APP)
        pepper = load_token_pepper(environ)
    except SettingsError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    secrets = [database.password.reveal(), pepper.reveal()]
    configure_logging(common, secrets=secrets)
    engine = create_database_engine(database, application_name="aegis-api")
    context = ApiContext(engine, pepper, AuditRecorder(Redactor(secrets)))
    try:
        uvicorn.run(
            create_app(context, common.environment),
            host=API_HOST,
            port=api.port,
            log_config=None,
            access_log=False,
            server_header=False,
            proxy_headers=False,
        )
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())

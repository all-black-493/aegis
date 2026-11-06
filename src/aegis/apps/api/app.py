from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException

from aegis.apps.api import health
from aegis.apps.api.context import ApiContext
from aegis.apps.api.middleware import RequestMiddleware
from aegis.apps.api.problems import http_problem, unavailable_problem, validation_problem
from aegis.apps.api.v1.router import router as v1
from aegis.config.settings import Environment


def create_app(context: ApiContext, environment: Environment) -> FastAPI:
    docs = environment is Environment.DEVELOPMENT
    app = FastAPI(
        title="AEGIS",
        openapi_url="/openapi.json" if docs else None,
        docs_url="/docs" if docs else None,
        redoc_url=None,
    )
    app.state.context = context
    app.add_middleware(RequestMiddleware)
    app.add_exception_handler(HTTPException, http_problem)
    app.add_exception_handler(RequestValidationError, validation_problem)
    app.add_exception_handler(SQLAlchemyError, unavailable_problem)
    app.include_router(health.router)
    app.include_router(v1)
    return app

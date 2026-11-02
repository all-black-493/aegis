from pathlib import Path

from aegis.config.variables import SECRET_NAMES
from aegis.doctor.configuration import (
    check_env_file,
    check_env_permissions,
    check_env_template,
    postgres_port,
)
from aegis.doctor.database import (
    check_migrations,
    check_postgres_port,
    check_postgres_service,
    probe_postgres,
)
from aegis.doctor.host import check_disk, check_memory
from aegis.doctor.integrations import check_model_provider, check_sandbox_runtime
from aegis.doctor.model import PASS, Diagnosis
from aegis.doctor.system import System
from aegis.doctor.toolchain import (
    check_docker_compose,
    check_docker_engine,
    check_project_environment,
    check_python,
    check_uv,
)


def run_checks(system: System, root: Path) -> Diagnosis:
    env_values, env_result = check_env_file(root)
    engine_result, docker = check_docker_engine(system, root)
    compose_result = check_docker_compose(system, root, docker)
    port = postgres_port(env_values) if env_result.status is PASS else None
    blockers = tuple(
        result.name
        for result in (engine_result, compose_result, env_result)
        if result.status is not PASS
    )
    postgres = probe_postgres(system, root, docker, blockers)
    service_result = check_postgres_service(system, port, postgres)

    results = (
        check_python(system),
        check_project_environment(system, root),
        check_uv(system, root),
        engine_result,
        compose_result,
        env_result,
        check_env_permissions(root),
        check_env_template(root, env_values),
        check_disk(system, root, docker.root_dir),
        check_memory(system),
        check_postgres_port(system, port, postgres),
        service_result,
        check_migrations(system, root, docker, env_values, service_result),
        check_model_provider(system, env_values if env_result.status is PASS else None),
        check_sandbox_runtime(system, env_values if env_result.status is PASS else None),
    )
    secrets = frozenset(
        value for key, value in (env_values or {}).items() if key in SECRET_NAMES and value
    )
    return Diagnosis(results, secrets)

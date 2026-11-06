import threading

import pytest
from sqlalchemy import Engine

from aegis.integrations.openshell.runtime import OpenShellRuntime
from aegis.jobs.enforcement import EnforcementCheck
from aegis.runtime.probes.catalog import PROBES
from aegis.tasks.states import TaskState
from tests.fixtures import records
from tests.fixtures.enforcement import checked, submit, worker
from tests.fixtures.services import RECORDER, Caller

pytestmark = [pytest.mark.openshell, pytest.mark.usefixtures("isolated_jobs")]


def test_an_enforcement_check_task_is_verified_under_openshell(
    app_engine: Engine,
    owner_engine: Engine,
    operator: Caller,
    openshell_runtime: OpenShellRuntime,
    probe_image: str,
) -> None:
    task = submit(app_engine, operator.actor)
    enforcement = EnforcementCheck(app_engine, RECORDER, openshell_runtime, probe_image)

    assert worker(app_engine, enforcement).step(threading.Event())

    found = records.task(app_engine, task.task_id)
    assert (found.state, found.failure_code) == (TaskState.SUCCEEDED, None)
    checks = checked(owner_engine, task.task_id)
    assert {check: row["reason_code"] for check, row in checks.items()} == {
        probe.check_id: "held" for probe in PROBES
    }
    assert {
        check: row["details"]["corroborated"]
        for check, row in checks.items()
        if row["details"]["kind"] == "network"
    } == {probe.check_id: True for probe in PROBES if probe.kind.value == "network"}
    events = records.task_events(owner_engine, task.task_id)
    assert (events.count("sandbox.created"), events.count("sandbox.deleted")) == (1, 1)
    assert openshell_runtime.managed() == ()

import os
import subprocess
from pathlib import Path

import pytest

from aegis.config.settings import load_runtime_settings
from aegis.integrations.openshell.cli import VERIFIED_VERSION
from aegis.integrations.openshell.runtime import OpenShellRuntime

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def openshell_runtime() -> OpenShellRuntime:
    runtime = OpenShellRuntime(load_runtime_settings(os.environ).openshell)
    status = runtime.check()
    if not status.healthy:
        pytest.fail(
            f"OpenShell is not usable ({status.detail}): install OpenShell {VERIFIED_VERSION}"
            " and run `make openshell-init`; see the getting-started guide"
        )
    return runtime


@pytest.fixture(scope="session")
def probe_image() -> str:
    # Built by the same `make openshell-image` an operator runs, offline and without pulling.
    built = subprocess.run(
        ["make", "--no-print-directory", "openshell-image"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    line = built.stdout.strip().splitlines()[-1] if built.stdout.strip() else ""
    if built.returncode != 0 or not line.startswith("AEGIS_OPENSHELL_IMAGE=sha256:"):
        pytest.fail(f"the probe image did not build: {built.stderr.strip()[-300:]}")
    return line.split("=", 1)[1]

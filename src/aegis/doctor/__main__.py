import sys
from pathlib import Path

from aegis.doctor.checks import run_checks
from aegis.doctor.report import render
from aegis.doctor.system import HostSystem


def main() -> int:
    root = Path.cwd()
    if not (root / "docker-compose.yml").is_file():
        print(
            "error: run the doctor from the repository root (`make doctor`)",
            file=sys.stderr,
        )
        return 2
    diagnosis = run_checks(HostSystem(), root)
    print(render(diagnosis))
    return diagnosis.exit_code


if __name__ == "__main__":
    sys.exit(main())

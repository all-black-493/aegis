from pathlib import Path

from aegis.doctor.model import FAIL, PASS, REQUIRED, WARN, CheckResult
from aegis.doctor.system import System

GIB = 1024**3
MIN_FREE_DISK_BYTES = 2 * GIB
MIN_TOTAL_MEMORY_BYTES = 2 * GIB
LOW_AVAILABLE_MEMORY_BYTES = 1 * GIB


def check_disk(system: System, root: Path, docker_root: Path | None) -> CheckResult:
    name = "Disk space"
    notes: list[str] = []
    too_low = unknown = False
    for label, path in (("project", root), ("Docker data", docker_root)):
        if path is None:
            continue
        free = system.disk_free_bytes(path)
        if free is None:
            notes.append(f"{label}: unknown")
            unknown = True
            continue
        notes.append(f"{label} {free / GIB:.1f} GiB free")
        too_low = too_low or free < MIN_FREE_DISK_BYTES
    detail = ", ".join(notes)
    if too_low:
        return CheckResult(
            name,
            REQUIRED,
            FAIL,
            f"{detail}; at least {MIN_FREE_DISK_BYTES // GIB} GiB needed",
        )
    return CheckResult(name, REQUIRED, WARN if unknown else PASS, detail)


def check_memory(system: System) -> CheckResult:
    name = "Memory"
    memory = system.memory()
    if memory is None:
        return CheckResult(name, REQUIRED, FAIL, "cannot read /proc/meminfo; Linux is required")
    detail = (
        f"{memory.total_bytes / GIB:.1f} GiB total, "
        f"{memory.available_bytes / GIB:.1f} GiB available"
    )
    if memory.total_bytes < MIN_TOTAL_MEMORY_BYTES:
        return CheckResult(
            name,
            REQUIRED,
            FAIL,
            f"{detail}; at least {MIN_TOTAL_MEMORY_BYTES // GIB} GiB needed",
        )
    if memory.available_bytes < LOW_AVAILABLE_MEMORY_BYTES:
        return CheckResult(name, REQUIRED, WARN, f"{detail}; low available memory")
    return CheckResult(name, REQUIRED, PASS, detail)

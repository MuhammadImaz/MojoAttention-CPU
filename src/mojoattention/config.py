from __future__ import annotations

from dataclasses import dataclass, fields

CACHE_BUDGET_BYTES = 5_000_000_000
GIB = 1024**3


@dataclass(frozen=True, slots=True)
class ProjectPolicy:
    cache_budget_bytes: int = CACHE_BUDGET_BYTES
    cache_warning_percent: int = 70
    cache_stop_percent: int = 80
    minimum_total_memory_bytes: int = 8 * GIB
    minimum_available_memory_bytes: int = 4 * GIB
    minimum_free_disk_bytes: int = 15 * GIB
    minimum_logical_cpus: int = 4
    minimum_glibc: tuple[int, int] = (2, 34)


def policy_errors(policy: ProjectPolicy) -> tuple[str, ...]:
    expected = ProjectPolicy()
    errors: list[str] = []
    for field in fields(expected):
        field_name = field.name
        value = getattr(policy, field_name)
        required = getattr(expected, field_name)
        if type(value) is not type(required) or value != required:
            errors.append(f"{field_name}: detected={value!r}, required={required!r}")
    return tuple(errors)

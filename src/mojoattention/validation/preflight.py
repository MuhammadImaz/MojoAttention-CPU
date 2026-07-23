from __future__ import annotations

import json
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from typing import Literal

from mojoattention.config import ProjectPolicy, policy_errors

EXIT_PASS = 0
EXIT_INFRASTRUCTURE_INVALID = 2
EXIT_CONTRACT_INVALID = 3

X86_64_V3_FLAGS = frozenset(
    {
        "avx",
        "avx2",
        "bmi1",
        "bmi2",
        "cx16",
        "f16c",
        "fma",
        "lahf_lm",
        "lzcnt",
        "movbe",
        "popcnt",
        "sse3",
        "ssse3",
        "sse4_1",
        "sse4_2",
        "xsave",
    }
)


class RunState(StrEnum):
    IDLE = "idle"
    ACTIVE = "active"
    STAGING = "staging"
    UNSEALED = "unsealed"


@dataclass(frozen=True, slots=True)
class HostSnapshot:
    os_name: str
    distribution: str
    distribution_version: str
    architecture: str
    glibc_version: tuple[int, int]
    cpu_flags: frozenset[str]
    v3_probe: str
    v3_effective: bool
    os_avx_enabled: bool
    logical_cpus: int
    total_memory_bytes: int
    available_memory_bytes: int
    free_disk_bytes: int
    cache_bytes: int
    cache_path: str
    disk_path: str
    gpu_present: bool
    run_state: RunState


Status = Literal["pass", "warning", "fail"]
FailureKind = Literal["infrastructure-invalid", "contract-invalid"]


@dataclass(frozen=True, slots=True)
class Check:
    id: str
    status: Status
    message: str
    detected: object
    required: object
    unit: str | None
    remediation: str | None
    path: str | None = None
    reproduction_command: str | None = None
    failure_kind: FailureKind | None = None


@dataclass(frozen=True, slots=True)
class PreflightResult:
    mode: Literal["baseline", "broad"]
    verdict: Literal["pass", "infrastructure-invalid", "contract-invalid"]
    checks: tuple[Check, ...]
    summary: str

    @property
    def exit_code(self) -> int:
        return {
            "pass": EXIT_PASS,
            "infrastructure-invalid": EXIT_INFRASTRUCTURE_INVALID,
            "contract-invalid": EXIT_CONTRACT_INVALID,
        }[self.verdict]


def _check(
    id: str,
    ok: bool,
    message: str,
    detected: object,
    required: object,
    unit: str | None,
    remediation: str,
    *,
    path: str | None = None,
    failure_kind: FailureKind = "infrastructure-invalid",
) -> Check:
    return Check(
        id=id,
        status="pass" if ok else "fail",
        message=message,
        detected=detected,
        required=required,
        unit=unit,
        remediation=None if ok else remediation,
        path=path,
        failure_kind=None if ok else failure_kind,
    )


def evaluate(snapshot: HostSnapshot, policy: ProjectPolicy, mode: Literal["baseline", "broad"]) -> PreflightResult:
    if mode not in ("baseline", "broad"):
        raise ValueError(f"unsupported preflight mode: {mode}")
    checks: list[Check] = []
    errors = policy_errors(policy)
    effective = policy if not errors else ProjectPolicy()
    checks.append(
        _check(
            "PF-000",
            not errors,
            "exact resource policy",
            list(errors),
            [],
            None,
            "Restore the checked-in typed resource policy.",
            failure_kind="contract-invalid",
        )
    )
    checks.extend(
        [
            _check(
                "PF-001",
                snapshot.os_name == "linux",
                "Linux host",
                snapshot.os_name,
                "linux",
                None,
                "Run on a supported 64-bit Linux host.",
            ),
            _check(
                "PF-002",
                snapshot.architecture in {"x86_64", "amd64"},
                "x86-64 architecture",
                snapshot.architecture,
                "x86_64",
                None,
                "Use an x86-64 host supported by pinned Mojo/MAX.",
            ),
        ]
    )
    proven = snapshot.distribution.lower() == "ubuntu" and snapshot.distribution_version == "26.04"
    checks.append(
        Check(
            id="PF-003",
            status="pass" if proven else "warning",
            message="proven Linux distribution",
            detected=f"{snapshot.distribution} {snapshot.distribution_version}".strip(),
            required="Ubuntu 26.04 LTS",
            unit=None,
            remediation=None if proven else "Reproduce on the proven Ubuntu host before publishing claims.",
        )
    )
    checks.append(
        _check(
            "PF-004",
            snapshot.glibc_version >= effective.minimum_glibc,
            "glibc version",
            ".".join(map(str, snapshot.glibc_version)),
            ".".join(map(str, effective.minimum_glibc)),
            None,
            "Upgrade to a Linux distribution with glibc 2.34 or newer.",
        )
    )
    missing = sorted(X86_64_V3_FLAGS - snapshot.cpu_flags)
    checks.append(
        _check(
            "PF-005",
            not missing and snapshot.v3_effective,
            "effective x86-64-v3 capabilities",
            {
                "probe": snapshot.v3_probe,
                "effective": snapshot.v3_effective,
                "required_flags": sorted(X86_64_V3_FLAGS),
                "missing_flags": missing,
            },
            {"level": "x86-64-v3", "effective": True, "missing_flags": []},
            None,
            "Use a CPU and OS providing the complete effective x86-64-v3 psABI feature level.",
        )
    )
    checks.extend(
        [
            _check(
                "PF-006",
                snapshot.os_avx_enabled,
                "OS-enabled AVX state",
                snapshot.os_avx_enabled,
                True,
                None,
                "Enable OS XSAVE/AVX state support or use a compatible kernel/host.",
            ),
            _check(
                "PF-007",
                snapshot.total_memory_bytes >= effective.minimum_total_memory_bytes,
                "total memory",
                snapshot.total_memory_bytes,
                effective.minimum_total_memory_bytes,
                "bytes",
                "Use a host with at least 8 GiB total RAM.",
            ),
            _check(
                "PF-008",
                snapshot.logical_cpus >= effective.minimum_logical_cpus,
                "logical CPU count",
                snapshot.logical_cpus,
                effective.minimum_logical_cpus,
                "cpus",
                "Provide at least four logical CPUs.",
            ),
        ]
    )

    if mode == "broad":
        percent = snapshot.cache_bytes * 100 // effective.cache_budget_bytes
        cache_status: Status = (
            "fail"
            if percent >= effective.cache_stop_percent
            else ("warning" if percent >= effective.cache_warning_percent else "pass")
        )
        checks.append(
            Check(
                id="PF-302",
                status=cache_status,
                message="project Modular cache budget",
                detected={"bytes": snapshot.cache_bytes, "percentage": percent, "path": snapshot.cache_path},
                required={
                    "budget_bytes": effective.cache_budget_bytes,
                    "warning_percent": effective.cache_warning_percent,
                    "stop_percent": effective.cache_stop_percent,
                },
                unit="bytes",
                remediation=None
                if cache_status == "pass"
                else (
                    "Stop broad work and inspect active runs before documented safe cleanup."
                    if cache_status == "fail"
                    else "Plan documented safe cleanup before the stop threshold."
                ),
                path=snapshot.cache_path,
                failure_kind="infrastructure-invalid" if cache_status == "fail" else None,
            )
        )
        checks.extend(
            [
                _check(
                    "PF-303",
                    snapshot.available_memory_bytes >= effective.minimum_available_memory_bytes,
                    "available memory",
                    snapshot.available_memory_bytes,
                    effective.minimum_available_memory_bytes,
                    "bytes",
                    "Close memory-intensive work before broad compilation.",
                ),
                _check(
                    "PF-304",
                    snapshot.free_disk_bytes >= effective.minimum_free_disk_bytes,
                    "free filesystem space",
                    snapshot.free_disk_bytes,
                    effective.minimum_free_disk_bytes,
                    "bytes",
                    "Free space safely on the project filesystem.",
                    path=snapshot.disk_path,
                ),
                _check(
                    "PF-305",
                    snapshot.run_state is RunState.IDLE,
                    "active or unsealed run state",
                    snapshot.run_state.value,
                    RunState.IDLE.value,
                    None,
                    "Wait for active work or seal/preserve staged evidence; preflight never deletes it.",
                    path=f"{snapshot.disk_path}/reports/runs",
                ),
            ]
        )

    reproduction = f"scripts/run.sh mojoattention preflight --mode {mode} --json -"
    checks = [
        replace(check, reproduction_command=reproduction) if check.status != "pass" else check for check in checks
    ]
    failures = [check for check in checks if check.status == "fail"]
    verdict: Literal["pass", "infrastructure-invalid", "contract-invalid"]
    if any(check.failure_kind == "contract-invalid" for check in failures):
        verdict = "contract-invalid"
    elif failures:
        verdict = "infrastructure-invalid"
    else:
        verdict = "pass"
    warnings = sum(check.status == "warning" for check in checks)
    summary = f"{verdict}: {len(checks) - len(failures)}/{len(checks)} checks non-failing; {warnings} warning(s)"
    return PreflightResult(mode, verdict, tuple(sorted(checks, key=lambda check: check.id)), summary)


def render_json(result: PreflightResult) -> str:
    def check_dict(check: Check) -> dict[str, object]:
        value = asdict(check)
        value.pop("failure_kind")
        return value

    payload = {
        "checks": [check_dict(check) for check in result.checks],
        "mode": result.mode,
        "schema_version": "1.0.0",
        "summary": result.summary,
        "verdict": result.verdict,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"

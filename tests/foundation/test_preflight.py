from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from mojoattention.cli.main import main
from mojoattention.config import CACHE_BUDGET_BYTES, ProjectPolicy
from mojoattention.validation.identity import EXPECTED, evaluate_identity
from mojoattention.validation.preflight import (
    EXIT_CONTRACT_INVALID,
    EXIT_INFRASTRUCTURE_INVALID,
    EXIT_PASS,
    HostSnapshot,
    RunState,
    evaluate,
    render_json,
)

V3 = frozenset(
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


def host(**overrides: object) -> HostSnapshot:
    values: dict[str, object] = {
        "os_name": "linux",
        "distribution": "Ubuntu",
        "distribution_version": "26.04",
        "architecture": "x86_64",
        "glibc_version": (2, 43),
        "cpu_flags": V3,
        "v3_probe": "glibc-hwcaps:x86-64-v3",
        "v3_effective": True,
        "os_avx_enabled": True,
        "logical_cpus": 4,
        "total_memory_bytes": 8 * 1024**3,
        "available_memory_bytes": 4 * 1024**3,
        "free_disk_bytes": 15 * 1024**3,
        "cache_bytes": 0,
        "cache_path": "/project/.cache/modular",
        "disk_path": "/project",
        "gpu_present": False,
        "run_state": RunState.IDLE,
    }
    values.update(overrides)
    return HostSnapshot(**values)  # type: ignore[arg-type]


class PreflightTests(unittest.TestCase):
    def test_environment_identity_reports_every_mismatch(self) -> None:
        exact = evaluate_identity(dict(EXPECTED))
        drifted = evaluate_identity({**EXPECTED, "ruff": "0.0.0"})
        self.assertTrue(all(check.matches for check in exact))
        self.assertEqual(["ruff"], [check.name for check in drifted if not check.matches])

    def test_baseline_passes_at_exact_thresholds_and_gpu_is_allowed(self) -> None:
        result = evaluate(host(gpu_present=True), ProjectPolicy(), mode="baseline")
        self.assertEqual("pass", result.verdict)
        self.assertEqual(EXIT_PASS, result.exit_code)

    def test_non_ubuntu_is_warning_but_non_linux_fails(self) -> None:
        warning = evaluate(host(distribution="Fedora", distribution_version="42"), ProjectPolicy(), "baseline")
        self.assertEqual("pass", warning.verdict)
        self.assertIn("PF-003", [c.id for c in warning.checks if c.status == "warning"])
        failed = evaluate(host(os_name="darwin"), ProjectPolicy(), "baseline")
        self.assertEqual("infrastructure-invalid", failed.verdict)
        self.assertEqual(EXIT_INFRASTRUCTURE_INVALID, failed.exit_code)

    def test_full_v3_and_os_vector_state_are_required(self) -> None:
        missing = evaluate(host(cpu_flags=V3 - {"ssse3"}), ProjectPolicy(), "baseline")
        ineffective = evaluate(host(v3_effective=False), ProjectPolicy(), "baseline")
        disabled = evaluate(host(os_avx_enabled=False), ProjectPolicy(), "baseline")
        self.assertEqual("infrastructure-invalid", missing.verdict)
        self.assertEqual("infrastructure-invalid", ineffective.verdict)
        self.assertEqual("infrastructure-invalid", disabled.verdict)

    def test_baseline_rejects_arch_glibc_memory_and_cpu_boundaries(self) -> None:
        cases = (
            {"architecture": "aarch64"},
            {"glibc_version": (2, 33)},
            {"total_memory_bytes": 8 * 1024**3 - 1},
            {"logical_cpus": 3},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                result = evaluate(host(**overrides), ProjectPolicy(), "baseline")
                self.assertEqual(EXIT_INFRASTRUCTURE_INVALID, result.exit_code)

    def test_broad_resource_boundaries(self) -> None:
        self.assertEqual("pass", evaluate(host(), ProjectPolicy(), "broad").verdict)
        low_ram = evaluate(host(available_memory_bytes=4 * 1024**3 - 1), ProjectPolicy(), "broad")
        low_disk = evaluate(host(free_disk_bytes=15 * 1024**3 - 1), ProjectPolicy(), "broad")
        self.assertEqual(EXIT_INFRASTRUCTURE_INVALID, low_ram.exit_code)
        self.assertEqual(EXIT_INFRASTRUCTURE_INVALID, low_disk.exit_code)

    def test_cache_budget_boundaries_and_invalid_policy(self) -> None:
        warning = evaluate(host(cache_bytes=CACHE_BUDGET_BYTES * 70 // 100), ProjectPolicy(), "broad")
        stopped = evaluate(host(cache_bytes=CACHE_BUDGET_BYTES * 80 // 100), ProjectPolicy(), "broad")
        invalid = evaluate(host(), ProjectPolicy(cache_budget_bytes=0), "broad")
        self.assertEqual("warning", next(c.status for c in warning.checks if c.id == "PF-302"))
        self.assertEqual(EXIT_INFRASTRUCTURE_INVALID, stopped.exit_code)
        self.assertEqual(EXIT_CONTRACT_INVALID, invalid.exit_code)

    def test_policy_drift_and_malformed_values_fail_in_every_mode(self) -> None:
        policies = (
            ProjectPolicy(cache_budget_bytes=1),
            ProjectPolicy(cache_warning_percent=1),
            ProjectPolicy(minimum_logical_cpus=-1),
            ProjectPolicy(cache_budget_bytes="bad"),  # type: ignore[arg-type]
        )
        for policy in policies:
            for mode in ("baseline", "broad"):
                with self.subTest(policy=policy, mode=mode):
                    self.assertEqual(EXIT_CONTRACT_INVALID, evaluate(host(), policy, mode).exit_code)

    def test_active_or_unsealed_runs_are_never_mutated(self) -> None:
        for state in (RunState.ACTIVE, RunState.STAGING, RunState.UNSEALED):
            result = evaluate(host(run_state=state), ProjectPolicy(), "broad")
            self.assertEqual(EXIT_INFRASTRUCTURE_INVALID, result.exit_code)

    def test_json_is_canonical_and_has_required_shape(self) -> None:
        result = evaluate(host(), ProjectPolicy(), "baseline")
        payload = render_json(result)
        self.assertTrue(payload.endswith("\n"))
        parsed = json.loads(payload)
        self.assertEqual(["checks", "mode", "schema_version", "summary", "verdict"], sorted(parsed))
        self.assertEqual(sorted(parsed["checks"], key=lambda item: item["id"]), parsed["checks"])

    def test_cli_stdout_and_stderr_are_separate_and_deterministic(self) -> None:
        stdout, stderr = StringIO(), StringIO()
        with (
            mock.patch("mojoattention.cli.main.probe", return_value=host()),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            exit_code = main(["preflight", "--mode", "baseline", "--json", "-"])
        self.assertEqual(EXIT_PASS, exit_code)
        self.assertEqual("pass: 9/9 checks non-failing; 0 warning(s)\n", stderr.getvalue())
        self.assertEqual("pass", json.loads(stdout.getvalue())["verdict"])

    def test_cli_usage_exit_is_distinct_and_json_file_is_atomic(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            main(["preflight", "--mode", "wrong"])
        self.assertEqual(64, raised.exception.code)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "nested" / "result.json"
            with mock.patch("mojoattention.cli.main.probe", return_value=host()):
                self.assertEqual(EXIT_PASS, main(["preflight", "--json", str(destination)]))
            self.assertEqual("pass", json.loads(destination.read_text(encoding="utf-8"))["verdict"])
            self.assertEqual([], list(destination.parent.glob("tmp*")))

    def test_failure_diagnostics_include_path_percentage_and_reproduction(self) -> None:
        result = evaluate(host(cache_bytes=CACHE_BUDGET_BYTES * 80 // 100), ProjectPolicy(), "broad")
        cache = next(check for check in result.checks if check.id == "PF-302")
        self.assertEqual(80, cache.detected["percentage"])  # type: ignore[index]
        self.assertEqual("/project/.cache/modular", cache.path)
        self.assertIn("preflight --mode broad", cache.reproduction_command or "")


if __name__ == "__main__":
    unittest.main()

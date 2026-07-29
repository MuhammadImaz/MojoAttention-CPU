from __future__ import annotations

import json
import os
import subprocess
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

from mojoattention.validation.fast import (
    AdapterResult,
    Observation,
    evaluate_observations,
    execute_checks,
    load_manifest,
    run_bounded_argv,
)

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "contracts" / "validation-suites" / "fast.json"
SCHEMA = ROOT / "schemas" / "validation-suite.schema.json"


class FastRunnerTests(unittest.TestCase):
    def manifest(self):
        return load_manifest(MANIFEST.read_bytes(), SCHEMA.read_bytes())

    def observations(self):
        manifest = self.manifest()
        return tuple(
            Observation(
                validation_id=check.validation_id,
                case_id=check.case_id,
                seed=check.seed,
                selected=1,
                collected=1,
                completed=1,
                skipped=0,
                xfailed=0,
                deselected=0,
                collection_errors=0,
                shard_index=0,
                shard_total=1,
                status="pass",
            )
            for check in manifest.checks
        )

    def test_manifest_is_immutable_and_digest_bound(self) -> None:
        manifest = self.manifest()
        self.assertEqual("fast", manifest.suite_id)
        self.assertEqual(13, len(manifest.checks))
        with self.assertRaises(FrozenInstanceError):
            manifest.checks[0].case_id = "changed"  # type: ignore[misc]

        tampered = json.loads(MANIFEST.read_bytes())
        tampered["runner_config"]["timeout_seconds"] -= 1
        with self.assertRaises(ValueError):
            load_manifest(json.dumps(tampered).encode(), SCHEMA.read_bytes())

    def test_exact_complete_observation_inventory_passes(self) -> None:
        verdict, errors = evaluate_observations(self.manifest(), self.observations())
        self.assertEqual("pass", verdict)
        self.assertEqual((), errors)

    def test_inventory_and_execution_drift_fail_closed(self) -> None:
        canonical = self.observations()
        mutations = (
            canonical[:-1],
            canonical + (canonical[0],),
            tuple(reversed(canonical)),
            (replace(canonical[0], seed=9), *canonical[1:]),
            (replace(canonical[0], skipped=1, completed=0), *canonical[1:]),
            (replace(canonical[0], xfailed=1), *canonical[1:]),
            (replace(canonical[0], deselected=1), *canonical[1:]),
            (replace(canonical[0], collection_errors=1), *canonical[1:]),
            (replace(canonical[0], shard_total=2), *canonical[1:]),
        )
        for observations in mutations:
            with self.subTest(observations=observations):
                verdict, errors = evaluate_observations(self.manifest(), observations)
                self.assertEqual("contract-invalid", verdict)
                self.assertTrue(errors)

    def test_completed_check_failure_maps_to_product_verdict(self) -> None:
        failed = list(self.observations())
        failed[2] = replace(failed[2], status="fail")
        verdict, errors = evaluate_observations(self.manifest(), tuple(failed))
        self.assertEqual("product-fail", verdict)
        self.assertTrue(errors)

    def test_failure_priority_is_contract_then_infrastructure_then_product(self) -> None:
        canonical = list(self.observations())
        canonical[0] = replace(canonical[0], status="fail", failure_class="product-fail")
        canonical[1] = replace(canonical[1], status="fail", failure_class="infrastructure-invalid")
        verdict, _ = evaluate_observations(self.manifest(), tuple(canonical))
        self.assertEqual("infrastructure-invalid", verdict)
        canonical[2] = replace(canonical[2], status="fail", failure_class="contract-invalid")
        verdict, _ = evaluate_observations(self.manifest(), tuple(canonical))
        self.assertEqual("contract-invalid", verdict)

    def test_bounded_subprocess_uses_explicit_cwd_minimal_environment_and_no_shell(self) -> None:
        manifest = self.manifest()
        completed = subprocess.CompletedProcess(["tool"], 0, stdout=b"ok", stderr=b"")
        ambient = {"PATH": "/tools", "SECRET": "must-not-leak", "LC_ALL": "ambient"}
        with patch.dict(os.environ, ambient, clear=True), patch("subprocess.run", return_value=completed) as run:
            result = run_bounded_argv(("tool", "--machine"), ROOT, manifest.runner_config)
        self.assertEqual(0, result.returncode)
        kwargs = run.call_args.kwargs
        self.assertEqual(ROOT, kwargs["cwd"])
        self.assertEqual({"PATH": "/tools", "LC_ALL": "C"}, kwargs["env"])
        self.assertFalse(kwargs["shell"])
        self.assertEqual(manifest.runner_config.timeout_seconds, kwargs["timeout"])
        self.assertTrue(kwargs["capture_output"])

    def test_bounded_subprocess_maps_timeout_and_missing_tool_without_log_parsing(self) -> None:
        manifest = self.manifest()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["tool"], 1)):
            timed_out = run_bounded_argv(("tool",), ROOT, manifest.runner_config)
        self.assertEqual("infrastructure-invalid", timed_out.failure_class)
        self.assertEqual("FAST-EXEC-002", timed_out.error.code)
        with patch("subprocess.run", side_effect=FileNotFoundError):
            missing = run_bounded_argv(("tool",), ROOT, manifest.runner_config)
        self.assertEqual("infrastructure-invalid", missing.failure_class)
        self.assertEqual("FAST-EXEC-001", missing.error.code)

    def test_bounded_subprocess_caps_output_and_rejects_recursive_or_unbounded_commands(self) -> None:
        config = replace(self.manifest().runner_config, max_output_bytes=4)
        completed = subprocess.CompletedProcess(["tool"], 0, stdout=b"123456", stderr=b"abcdef")
        with patch("subprocess.run", return_value=completed):
            result = run_bounded_argv(("tool",), ROOT, config)
        self.assertEqual(b"1234", result.stdout)
        self.assertEqual(b"abcd", result.stderr)
        self.assertTrue(result.output_truncated)
        for argv in (
            ("scripts/quality.sh",),
            ("pytest", "tests"),
            ("uv", "run", "pytest", "tests/"),
            ("mojoattention", "validate", "--suite", "fast"),
        ):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                run_bounded_argv(argv, ROOT, config)

    def test_execute_checks_preserves_manifest_order_and_records_monotonic_elapsed_time(self) -> None:
        manifest = self.manifest()
        calls: list[str] = []

        def adapter(check):
            calls.append(check.validation_id)
            return AdapterResult.passed(check)

        ticks = iter((100, 175))
        result = execute_checks(
            manifest,
            {check.validation_id: adapter for check in manifest.checks},
            clock=lambda: next(ticks),
        )
        self.assertEqual(tuple(check.validation_id for check in manifest.checks), tuple(calls))
        self.assertEqual(75, result.elapsed_ns)
        self.assertEqual("nanoseconds", result.elapsed_unit)
        self.assertEqual("pass", result.verdict)
        self.assertEqual((), result.errors)

    def test_execute_checks_fails_closed_for_missing_adapter_and_adapter_crash(self) -> None:
        manifest = self.manifest()
        adapters = {check.validation_id: AdapterResult.passed for check in manifest.checks}
        adapters.pop(manifest.checks[0].validation_id)
        missing = execute_checks(manifest, adapters, clock=lambda: 1)
        self.assertEqual("contract-invalid", missing.verdict)
        self.assertEqual("FAST-ADAPTER-001", missing.errors[0].code)

        def crash(_check):
            raise RuntimeError("private diagnostic")

        adapters[manifest.checks[0].validation_id] = crash
        crashed = execute_checks(manifest, adapters, clock=lambda: 1)
        self.assertEqual("infrastructure-invalid", crashed.verdict)
        self.assertEqual("FAST-ADAPTER-002", crashed.errors[0].code)
        self.assertNotIn("private diagnostic", crashed.errors[0].message)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

from mojoattention.validation.fast import Observation, evaluate_observations, load_manifest

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


if __name__ == "__main__":
    unittest.main()

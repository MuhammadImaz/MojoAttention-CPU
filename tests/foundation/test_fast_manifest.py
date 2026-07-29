from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from mojoattention.validation.evidence import canonical_bytes
from mojoattention.validation.protected_assets import validate_policy

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "validation-suite.schema.json"
MANIFEST = ROOT / "contracts" / "validation-suites" / "fast.json"
PROTECTED_SCHEMA = ROOT / "schemas" / "protected-assets.schema.json"
PROTECTED_POLICY = ROOT / "contracts" / "protected-assets.json"


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


class FastManifestContractTests(unittest.TestCase):
    def test_canonical_schema_manifest_and_digests_are_strict(self) -> None:
        schema = json.loads(SCHEMA.read_bytes())
        manifest = json.loads(MANIFEST.read_bytes())
        Draft202012Validator.check_schema(schema)
        self.assertEqual((), tuple(Draft202012Validator(schema).iter_errors(manifest)))

        unsigned = dict(manifest)
        manifest_digest = unsigned.pop("manifest_digest")
        self.assertEqual(manifest_digest, digest(unsigned))
        self.assertEqual(manifest["config_digest"], digest(manifest["runner_config"]))

    def test_fast_inventory_is_ordered_unique_single_case_and_single_shard(self) -> None:
        manifest = json.loads(MANIFEST.read_bytes())
        checks = manifest["checks"]
        expected_ids = [f"FAST-{index:03d}" for index in range(1, 14)]
        self.assertEqual(expected_ids, [check["validation_id"] for check in checks])
        self.assertEqual(len(checks), manifest["required_total"])
        self.assertEqual({"shard_index": 0, "shard_total": 1}, manifest["runner_config"]["shard"])
        self.assertTrue(all(check["required_count"] == 1 for check in checks))
        self.assertEqual(len(checks), len({check["case_id"] for check in checks}))
        self.assertTrue(all(check["reproduction_argv"][0] == "mojoattention" for check in checks))

    def test_schema_rejects_unknown_fields_inventory_drift_and_unbounded_argv(self) -> None:
        schema = json.loads(SCHEMA.read_bytes())
        canonical = json.loads(MANIFEST.read_bytes())
        mutations = []

        unknown = deepcopy(canonical)
        unknown["unexpected"] = True
        mutations.append(unknown)

        duplicate = deepcopy(canonical)
        duplicate["checks"][1]["validation_id"] = duplicate["checks"][0]["validation_id"]
        mutations.append(duplicate)

        wrong_count = deepcopy(canonical)
        wrong_count["checks"][0]["required_count"] = 2
        mutations.append(wrong_count)

        case_drift = deepcopy(canonical)
        case_drift["checks"][0]["case_id"] = "different-case"
        mutations.append(case_drift)

        empty_argv = deepcopy(canonical)
        empty_argv["checks"][0]["reproduction_argv"] = []
        mutations.append(empty_argv)

        incomplete_shard = deepcopy(canonical)
        incomplete_shard["runner_config"]["shard"]["shard_total"] = 2
        mutations.append(incomplete_shard)

        validator = Draft202012Validator(schema)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertTrue(tuple(validator.iter_errors(mutation)))

    def test_fast_authority_is_protected(self) -> None:
        policy = json.loads(PROTECTED_POLICY.read_bytes())
        self.assertEqual((), validate_policy(policy, PROTECTED_SCHEMA))
        scopes = {scope["category"]: tuple(scope["paths"]) for scope in policy["protected_scopes"]}
        self.assertIn("contracts/validation-suites", scopes["required-check-policy"])
        self.assertIn("schemas", scopes)


if __name__ == "__main__":
    unittest.main()

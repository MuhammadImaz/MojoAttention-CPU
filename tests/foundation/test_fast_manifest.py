from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from mojoattention.validation.acceptance import ContractContext, compute_contract_digest, validate_contract
from mojoattention.validation.evidence import canonical_bytes
from mojoattention.validation.fast import FAST_PROTOCOL_DIGEST
from mojoattention.validation.protected_assets import validate_policy

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "validation-suite.schema.json"
MANIFEST = ROOT / "contracts" / "validation-suites" / "fast.json"
PROTECTED_SCHEMA = ROOT / "schemas" / "protected-assets.schema.json"
PROTECTED_POLICY = ROOT / "contracts" / "protected-assets.json"
AGENT_LOOP_CONTRACT = ROOT / "contracts" / "acceptance" / "1-7-agent-loop.example.json"


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
        expected_ids = [f"FAST-{index:03d}" for index in range(1, 15)]
        self.assertEqual(expected_ids, [check["validation_id"] for check in checks])
        self.assertEqual(len(checks), manifest["required_total"])
        self.assertEqual({"shard_index": 0, "shard_total": 1}, manifest["runner_config"]["shard"])
        self.assertTrue(all(check["required_count"] == 1 for check in checks))
        self.assertEqual(len(checks), len({check["case_id"] for check in checks}))
        self.assertTrue(all(check["reproduction_argv"][0] == "mojoattention" for check in checks))
        loop = checks[-1]
        self.assertEqual("agent-loop-policy-canary", loop["case_id"])
        self.assertEqual("canary", loop["kind"])
        self.assertEqual("contract-invalid", loop["expected_verdict"])

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
        evaluator = scopes["protected-evaluator"]
        for path in (
            "src/mojoattention/cli/main.py",
            "src/mojoattention/validation/agent_loop.py",
            "src/mojoattention/validation/fast.py",
            "src/mojoattention/validation/fast_canaries.py",
        ):
            self.assertIn(path, evaluator)
        self.assertIn("scripts/quality.sh", scopes["required-check-policy"])
        self.assertIn(".gitignore", scopes["generated-outputs"])
        self.assertIn("reports/README.md", scopes["generated-outputs"])

    def test_provider_neutral_authority_protects_fast_gate_without_granting_approval(self) -> None:
        authority = json.loads((ROOT / "contracts" / "agent-authority.json").read_bytes())
        for path in (
            "contracts/validation-suites",
            "schemas/validation-suite.schema.json",
            "schemas/agent-loop-state.schema.json",
            "src/mojoattention/cli/main.py",
            "src/mojoattention/validation/agent_loop.py",
            "src/mojoattention/validation/fast.py",
            "src/mojoattention/validation/fast_canaries.py",
            "tests/foundation/test_agent_loop.py",
            "tests/foundation/test_agent_loop_cli.py",
            "tests/foundation/test_agent_loop_controls.py",
            "tests/foundation/test_agent_loop_journal.py",
            ".gitignore",
            "reports/README.md",
            "scripts/quality.sh",
            ".github/workflows/foundation-quality.yml",
        ):
            self.assertIn(path, authority["protected_paths"])
        self.assertTrue(all(not role["can_approve_protected_changes"] for role in authority["roles"]))
        self.assertTrue(all(not role["can_approve_final_merge"] for role in authority["roles"]))

    def test_agent_loop_has_one_indirect_journal_producer(self) -> None:
        authority = json.loads((ROOT / "contracts" / "agent-authority.json").read_bytes())
        producers = [
            role["id"] for role in authority["roles"] if "reports/agent-loops" in role["indirect_output_paths"]
        ]
        self.assertEqual(["agent-loop-producer"], producers)
        producer = next(role for role in authority["roles"] if role["id"] == producers[0])
        self.assertEqual([], producer["write_paths"])
        self.assertFalse(producer["can_approve_protected_changes"])
        self.assertFalse(producer["can_approve_final_merge"])

    def test_fast_014_reproduction_contract_exists_and_binds_exact_authority(self) -> None:
        manifest = json.loads(MANIFEST.read_bytes())
        check = manifest["checks"][-1]
        contract_path = ROOT / check["reproduction_argv"][5]
        self.assertEqual(AGENT_LOOP_CONTRACT, contract_path)
        self.assertTrue(contract_path.is_file())

        contract = json.loads(contract_path.read_bytes())
        self.assertEqual("2.0.0", contract["schema_version"])
        self.assertEqual(compute_contract_digest(contract), contract["contract_digest"])
        self.assertEqual(manifest["manifest_digest"], contract["suite_manifest_digest"])
        self.assertEqual(manifest["config_digest"], contract["config_digest"])
        self.assertEqual(FAST_PROTOCOL_DIGEST, contract["protocol_digest"])
        self.assertEqual(FAST_PROTOCOL_DIGEST, contract["referenced_digests"]["protocol"])
        self.assertEqual(14, contract["required_suites"][0]["required_total"])
        self.assertEqual(
            [item["validation_id"] for item in manifest["checks"]],
            [item["validation_id"] for item in contract["required_suites"][0]["validations"]],
        )
        errors = validate_contract(
            contract,
            ROOT,
            ContractContext(
                contract["source_revision"],
                contract["trusted_base_revision"],
                contract["prior_validation_identity"],
            ),
        )
        self.assertEqual(("ACPT-008",), tuple(error.code for error in errors))


if __name__ == "__main__":
    unittest.main()

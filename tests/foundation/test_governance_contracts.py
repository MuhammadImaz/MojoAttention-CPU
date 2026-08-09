from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]


def load(relative: str) -> dict[str, object]:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def errors(instance: object, schema_name: str) -> list[object]:
    schema = load(f"schemas/{schema_name}")
    Draft202012Validator.check_schema(schema)
    return list(Draft202012Validator(schema).iter_errors(instance))


class RequiredCheckContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load("contracts/required-checks.json")

    def test_canonical_contract_has_all_stable_ordered_identities(self) -> None:
        self.assertEqual([], errors(self.contract, "required-checks.schema.json"))
        tiers = self.contract["tiers"]
        assert isinstance(tiers, list)
        self.assertEqual(
            [
                ("fast", "foundation-quality", "active"),
                ("correctness", "correctness", "reserved"),
                ("model", "model", "reserved"),
                ("training-smoke", "training-smoke", "reserved"),
                ("benchmark-smoke", "benchmark-smoke", "reserved"),
                ("nightly", "nightly", "reserved"),
                ("stable-benchmark", "stable-benchmark", "reserved"),
                ("release", "release", "reserved"),
            ],
            [(tier["tier_id"], tier["check_name"], tier["activation"]) for tier in tiers],
        )
        self.assertEqual(len(tiers), len({tier["check_name"] for tier in tiers}))

    def test_missing_duplicate_reordered_unknown_and_invalid_retention_fail(self) -> None:
        mutations: list[dict[str, object]] = []
        for transform in ("missing", "duplicate", "reordered", "unknown", "retention"):
            candidate = deepcopy(self.contract)
            tiers = candidate["tiers"]
            assert isinstance(tiers, list)
            if transform == "missing":
                tiers.pop()
            elif transform == "duplicate":
                tiers[1] = deepcopy(tiers[0])
            elif transform == "reordered":
                tiers[0], tiers[1] = tiers[1], tiers[0]
            elif transform == "unknown":
                tiers[0]["unexpected"] = True
            else:
                tiers[0]["artifact"]["retention_days"] = 0
            mutations.append(candidate)
        for candidate in mutations:
            self.assertTrue(errors(candidate, "required-checks.schema.json"))


class RepositoryGovernanceContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.intent = load("contracts/repository-governance.json")

    def test_canonical_intent_is_strict_and_requires_human_activation(self) -> None:
        self.assertEqual([], errors(self.intent, "repository-governance.schema.json"))
        self.assertEqual("configured-intent", self.intent["state_kind"])
        self.assertTrue(self.intent["activation"]["human_admin_required"])
        self.assertFalse(self.intent["activation"]["repository_files_prove_activation"])

    def test_unknown_missing_source_and_contradictory_activation_fail(self) -> None:
        unknown = deepcopy(self.intent)
        unknown["unexpected"] = True
        missing_source = deepcopy(self.intent)
        del missing_source["required_checks"]["expected_source"]
        contradiction = deepcopy(self.intent)
        contradiction["activation"]["human_admin_required"] = False
        for candidate in (unknown, missing_source, contradiction):
            self.assertTrue(errors(candidate, "repository-governance.schema.json"))

    def test_authenticated_observation_requires_complete_provenance(self) -> None:
        observation = {
            "schema_version": "1.0.0",
            "state_kind": "observed-hosted-state",
            "repository": "MuhammadImaz/MojoAttention-CPU",
            "default_branch": "main",
            "head_sha": "1" * 40,
            "base_sha": "2" * 40,
            "observed_at": "2026-08-05T12:00:00Z",
            "api_version": "2026-03-10",
            "status": "available",
            "controls": {
                "rulesets": [],
                "classic_branch_protection": None,
                "actions_full_sha_required": True,
                "actions_default_permissions": "read",
                "dependency_automation_active": True,
            },
            "provenance": {
                "source": "github-rest-api",
                "authenticated": True,
                "actor": "human-admin",
                "permissions": ["administration:read", "metadata:read"],
                "payload_sha256": "sha256:" + "3" * 64,
            },
        }
        self.assertEqual([], errors(observation, "governance-observation.schema.json"))
        for key in ("actor", "permissions", "payload_sha256"):
            candidate = deepcopy(observation)
            del candidate["provenance"][key]
            self.assertTrue(errors(candidate, "governance-observation.schema.json"), key)


class GovernanceProtectionTests(unittest.TestCase):
    def test_governance_assets_are_protected_by_both_policies(self) -> None:
        protected = load("contracts/protected-assets.json")
        scopes = {path for scope in protected["protected_scopes"] for path in scope["paths"]}
        authority = load("contracts/agent-authority.json")
        authority_paths = set(authority["protected_paths"])
        expected = {
            "contracts/required-checks.json",
            "contracts/ci-tier-policy.json",
            "contracts/repository-governance.json",
            "schemas/required-checks.schema.json",
            "schemas/ci-tier-policy.schema.json",
            "schemas/repository-governance.schema.json",
            "schemas/governance-observation.schema.json",
            "src/mojoattention/validation/governance.py",
            "src/mojoattention/validation/ci_evidence.py",
            "src/mojoattention/validation/ci_planner.py",
            "scripts/run_ci_plan.py",
            "scripts/validate_governance_contracts.py",
            ".github/CODEOWNERS",
            ".github/dependabot.yml",
            ".github/workflows/foundation-quality.yml",
        }

        def is_scoped(path: str) -> bool:
            return any(path == scope or path.startswith(scope + "/") for scope in scopes)

        self.assertEqual(set(), {path for path in expected if not is_scoped(path)})
        self.assertLessEqual(expected, authority_paths)

    def test_codeowners_and_dependency_automation_intent_are_explicit(self) -> None:
        codeowners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")
        dependabot = (ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")
        for scope in ("/.github/", "/contracts/", "/schemas/", "/scripts/", "/tests/"):
            self.assertIn(f"{scope} @MuhammadImaz", codeowners)
        self.assertIn("package-ecosystem: github-actions", dependabot)
        self.assertIn("- MuhammadImaz", dependabot)

    def test_governance_operations_never_claim_repository_intent_is_activation(self) -> None:
        operations = " ".join((ROOT / "docs/governance.md").read_text(encoding="utf-8").split())
        self.assertIn("do not prove that GitHub enforces it", operations)
        self.assertIn("AI review is advisory", operations)
        self.assertIn("Epic 2 must still prove clean CPU tensor round-trip", operations)


if __name__ == "__main__":
    unittest.main()

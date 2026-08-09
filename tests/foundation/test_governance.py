from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mojoattention.validation.governance import evaluate_governance

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 5, 12, tzinfo=UTC)


def load(relative: str) -> dict[str, object]:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def protection(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": "repository-main",
        "source": "repository-ruleset",
        "enforcement": "active",
        "applies_to": "main",
        "required_checks": {
            "strict": True,
            "checks": [{"name": "foundation-quality", "source": "github-actions"}],
        },
        "reviews": {
            "minimum_approvals": 1,
            "codeowners_required": True,
            "dismiss_stale_reviews": True,
            "require_last_push_approval": True,
        },
        "bypass": {"administrators_enforced": True, "allowed_actors": []},
    }
    value.update(overrides)
    return value


def observation(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "state_kind": "observed-hosted-state",
        "repository": "MuhammadImaz/MojoAttention-CPU",
        "default_branch": "main",
        "head_sha": "1" * 40,
        "base_sha": "2" * 40,
        "observed_at": NOW.isoformat().replace("+00:00", "Z"),
        "api_version": "2026-03-10",
        "status": "available",
        "controls": {
            "rulesets": [protection()],
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
    value.update(overrides)
    return value


def evaluate(snapshot: object, *, now: datetime = NOW, registry: object | None = None):
    if isinstance(snapshot, dict) and isinstance(snapshot.get("provenance"), dict):
        unsigned = deepcopy(snapshot)
        unsigned["provenance"].pop("payload_sha256", None)
        snapshot["provenance"]["payload_sha256"] = (
            "sha256:" + hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        )
    return evaluate_governance(
        load("contracts/repository-governance.json"),
        snapshot,
        required_checks_record=registry or load("contracts/required-checks.json"),
        intent_schema=ROOT / "schemas/repository-governance.schema.json",
        observation_schema=ROOT / "schemas/governance-observation.schema.json",
        required_checks_schema=ROOT / "schemas/required-checks.schema.json",
        repository="MuhammadImaz/MojoAttention-CPU",
        default_branch="main",
        head_sha="1" * 40,
        base_sha="2" * 40,
        api_version="2026-03-10",
        observed_at=now,
        maximum_age=timedelta(hours=1),
    )


class GovernanceEvaluatorTests(unittest.TestCase):
    def test_complete_authenticated_matching_observation_passes(self) -> None:
        result = evaluate(observation())
        self.assertEqual("pass", result.verdict)
        self.assertTrue(result.audit_valid)
        self.assertTrue(result.operationally_compliant)
        self.assertEqual((), result.findings)
        self.assertEqual(("repository-main",), result.applicable_sources)

    def test_drift_and_missing_activation_are_product_fail(self) -> None:
        snapshot = observation()
        snapshot["controls"]["actions_full_sha_required"] = False
        snapshot["controls"]["dependency_automation_active"] = False
        snapshot["controls"]["rulesets"] = []
        result = evaluate(snapshot)
        self.assertEqual("product-fail", result.verdict)
        self.assertTrue(result.audit_valid)
        self.assertFalse(result.operationally_compliant)
        self.assertEqual(
            ["GOV-101", "GOV-102", "GOV-103"],
            [finding.code for finding in result.findings],
        )
        self.assertTrue(result.human_actions)

    def test_unavailable_partial_and_stale_observations_are_infrastructure_invalid(self) -> None:
        unavailable = observation(status="rate-limited")
        stale = observation(observed_at="2026-08-05T10:00:00Z")
        for snapshot in (unavailable, stale):
            result = evaluate(snapshot)
            self.assertEqual("infrastructure-invalid", result.verdict)
            self.assertFalse(result.audit_valid)
            self.assertFalse(result.operationally_compliant)

    def test_malformed_wrong_identity_and_unauthenticated_are_contract_invalid(self) -> None:
        wrong = observation(repository="other/repository")
        unauthenticated = observation()
        unauthenticated["provenance"]["authenticated"] = False
        malformed = observation()
        del malformed["base_sha"]
        for snapshot in (wrong, unauthenticated, malformed):
            result = evaluate(snapshot)
            self.assertEqual("contract-invalid", result.verdict)
            self.assertFalse(result.audit_valid)

    def test_effective_rules_compose_overlapping_sources(self) -> None:
        weak = protection(
            id="organization-main",
            source="organization-ruleset",
            required_checks={"strict": False, "checks": []},
            reviews={
                "minimum_approvals": 0,
                "codeowners_required": False,
                "dismiss_stale_reviews": False,
                "require_last_push_approval": False,
            },
        )
        snapshot = observation()
        snapshot["controls"]["rulesets"].append(weak)
        result = evaluate(snapshot)
        self.assertEqual("pass", result.verdict)
        self.assertEqual(("organization-main", "repository-main"), result.applicable_sources)
        codes = {finding.code for finding in result.findings}
        self.assertEqual({"GOV-110"}, codes)
        self.assertTrue(any(finding.context.get("precedence") for finding in result.findings))

    def test_findings_are_canonical_regardless_of_ruleset_order(self) -> None:
        first = protection(id="z-rule")
        second = deepcopy(first)
        second["id"] = "a-rule"
        snapshot = observation()
        snapshot["controls"]["rulesets"] = [first, second]
        reversed_snapshot = deepcopy(snapshot)
        reversed_snapshot["controls"]["rulesets"].reverse()
        result = evaluate(snapshot)
        self.assertEqual(result, evaluate(reversed_snapshot))
        self.assertEqual("pass", result.verdict)
        self.assertEqual(["GOV-110"], [finding.code for finding in result.findings])

    def test_inactive_and_nonapplicable_sources_do_not_claim_protection(self) -> None:
        snapshot = observation()
        snapshot["controls"]["rulesets"] = [
            protection(enforcement="disabled"),
            protection(id="other-branch", applies_to="develop"),
        ]
        result = evaluate(snapshot)
        self.assertEqual("product-fail", result.verdict)
        self.assertEqual((), result.applicable_sources)

    def test_semantically_incomplete_or_unknown_protection_is_contract_invalid(self) -> None:
        for mutation in ("missing", "unknown", "bad-type"):
            snapshot = observation()
            item = snapshot["controls"]["rulesets"][0]
            if mutation == "missing":
                del item["reviews"]
            elif mutation == "unknown":
                item["claimed_active"] = True
            else:
                item["reviews"]["minimum_approvals"] = "one"
            self.assertEqual("contract-invalid", evaluate(snapshot).verdict, mutation)

    def test_required_check_claims_come_from_validated_registry(self) -> None:
        registry = load("contracts/required-checks.json")
        registry["tiers"][0]["check_name"] = "caller-selected-pass"
        self.assertEqual("contract-invalid", evaluate(observation(), registry=registry).verdict)


if __name__ == "__main__":
    unittest.main()

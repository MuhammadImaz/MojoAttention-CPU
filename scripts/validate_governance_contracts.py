#!/usr/bin/env python3
"""Deterministically validate committed governance intent without claiming activation."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from mojoattention.validation.ci_evidence import load_foundation_manifest


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    for contract_name, schema_name in (
        ("ci-tier-policy.json", "ci-tier-policy.schema.json"),
        ("repository-governance.json", "repository-governance.schema.json"),
        ("required-checks.json", "required-checks.schema.json"),
    ):
        contract = json.loads((root / "contracts" / contract_name).read_bytes())
        schema = json.loads((root / "schemas" / schema_name).read_bytes())
        Draft202012Validator.check_schema(schema)
        errors = tuple(Draft202012Validator(schema).iter_errors(contract))
        if errors:
            raise ValueError(f"{contract_name} is invalid: {errors[0].message}")
    product_schema = json.loads((root / "schemas/product-validation-suite.schema.json").read_bytes())
    Draft202012Validator.check_schema(product_schema)
    tiers = json.loads((root / "contracts/required-checks.json").read_bytes())["tiers"]
    if len({item["tier_id"] for item in tiers}) != 8 or len({item["check_name"] for item in tiers}) != 8:
        raise ValueError("required-check tier and check identities must contain eight unique entries")
    if [item["activation"] for item in tiers].count("active") != 1:
        raise ValueError("exactly one required-check tier must be active")
    load_foundation_manifest(
        root / "contracts/validation-suites/foundation.json",
        root / "schemas/foundation-validation-suite.schema.json",
    )
    observation_schema = json.loads((root / "schemas/governance-observation.schema.json").read_bytes())
    Draft202012Validator.check_schema(observation_schema)
    codeowners = (root / ".github/CODEOWNERS").read_text(encoding="utf-8")
    required_scopes = ("/.github/", "/contracts/", "/schemas/", "/scripts/", "/tests/")
    if any(scope not in codeowners for scope in required_scopes) or "@MuhammadImaz" not in codeowners:
        raise ValueError("CODEOWNERS does not cover the protected governance inventory")
    dependabot = (root / ".github/dependabot.yml").read_text(encoding="utf-8")
    required_fragments = (
        "version: 2",
        "package-ecosystem: github-actions",
        "interval: weekly",
        "- MuhammadImaz",
    )
    if any(fragment not in dependabot for fragment in required_fragments):
        raise ValueError("Dependabot intent does not bind immutable Action maintenance ownership")
    print("governance-intent: valid (activation not inferred)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

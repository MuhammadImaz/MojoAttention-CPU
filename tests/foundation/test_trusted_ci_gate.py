from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_gate():
    spec = importlib.util.spec_from_file_location("trusted_ci_gate", ROOT / "scripts/trusted_ci_gate.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_dependency_free_validator_accepts_both_protected_controls() -> None:
    gate = load_gate()
    for record_path, schema_path in (
        ("contracts/protected-assets.json", "schemas/protected-assets.schema.json"),
        ("contracts/required-checks.json", "schemas/required-checks.schema.json"),
        ("contracts/ci-tier-policy.json", "schemas/ci-tier-policy.schema.json"),
    ):
        record = json.loads((ROOT / record_path).read_text(encoding="utf-8"))
        schema = json.loads((ROOT / schema_path).read_text(encoding="utf-8"))
        assert gate.Draft202012Validator(schema).iter_errors(record) == ()


def test_dependency_free_validator_rejects_unknown_duplicate_and_wrong_tier() -> None:
    gate = load_gate()
    schema = json.loads((ROOT / "schemas/required-checks.schema.json").read_text(encoding="utf-8"))
    record = json.loads((ROOT / "contracts/required-checks.json").read_text(encoding="utf-8"))
    record["unknown"] = True
    record["tiers"][1] = record["tiers"][0]
    issues = gate.Draft202012Validator(schema).iter_errors(record)
    assert issues
    assert any(
        "additional" in issue.message or "unique" in issue.message or "const" in issue.message for issue in issues
    )


def test_trusted_gate_is_protected_by_both_inventories() -> None:
    policy = json.loads((ROOT / "contracts/protected-assets.json").read_text(encoding="utf-8"))
    authority = json.loads((ROOT / "contracts/agent-authority.json").read_text(encoding="utf-8"))
    scopes = [path for scope in policy["protected_scopes"] for path in scope["paths"]]
    assert "scripts/trusted_ci_gate.py" in scopes
    assert "scripts/trusted_ci_gate.py" in authority["protected_paths"]


def test_workflow_contains_no_fake_jsonschema_module() -> None:
    workflow = (ROOT / ".github/workflows/foundation-quality.yml").read_text(encoding="utf-8")
    assert 'types.ModuleType("jsonschema")' not in workflow
    assert "Draft202012Validator" not in workflow


def test_missing_external_authorization_does_not_preempt_trusted_validation() -> None:
    gate = (ROOT / "scripts/trusted_ci_gate.py").read_text(encoding="utf-8")
    assert 'item.code != "PROT-003"' in gate
    assert '"PROT-004"' not in gate
    assert '"protected_change_review"' in gate
    assert "_validate_applicable_tiers" in gate
    assert "applicable tier remains reserved" in gate

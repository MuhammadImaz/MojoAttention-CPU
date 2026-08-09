from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from mojoattention.validation.ci_evidence import (
    CiRunIdentity,
    artifact_name,
    load_foundation_manifest,
    load_foundation_receipt,
    verify_ci_evidence,
)
from mojoattention.validation.evidence import EvidenceWriter, canonical_bytes, digest_bytes
from tests.foundation.test_evidence import DIGEST, SCHEMA, context

ROOT = Path(__file__).resolve().parents[2]
FOUNDATION_MANIFEST = ROOT / "contracts" / "validation-suites" / "foundation.json"
FOUNDATION_SCHEMA = ROOT / "schemas" / "foundation-validation-suite.schema.json"
CURRENT_REVISION = subprocess.run(
    ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True
).stdout.strip()


def identity(**updates: object) -> CiRunIdentity:
    values: dict[str, object] = {
        "github_run_id": 123456789,
        "github_run_attempt": 2,
        "workflow_identity": ".github/workflows/foundation-quality.yml",
        "workflow_revision": "1" * 40,
        "job_name": "foundation-quality",
        "check_name": "foundation-quality",
        "head_sha": "1" * 40,
        "base_sha": "2" * 40,
        "trusted_validator_revision": "2" * 40,
    }
    values.update(updates)
    return CiRunIdentity(**values)  # type: ignore[arg-type]


def governance_binding() -> dict[str, object]:
    return {
        "intent_digest": DIGEST,
        "observation_digest": "sha256:" + "b" * 64,
        "observation_source": "authenticated-export",
        "observed_at": "2026-08-05T12:00:00Z",
        "api_version": "2026-03-10",
        "audit_verdict": "product-fail",
        "audit_valid": True,
        "operationally_compliant": False,
        "human_actions": ["Activate dependency automation."],
    }


def validation(validation_id: str, case_id: str, attachment: str) -> dict[str, object]:
    return {
        "validation_id": validation_id,
        "case_id": case_id,
        "status": "pass",
        "reproduction_argv": ["scripts/quality.sh", "--ci"],
        "metrics": [],
        "errors": [],
        "attachments": [attachment],
    }


class CiEvidenceContractTests(unittest.TestCase):
    def test_foundation_receipt_must_bind_actual_inventory_and_run_identity(self) -> None:
        manifest = load_foundation_manifest(FOUNDATION_MANIFEST, FOUNDATION_SCHEMA)
        receipt = {
            "schema_version": "1.0.0",
            "verdict": "pass",
            "head_sha": "1" * 40,
            "base_sha": "2" * 40,
            "plan_digest": DIGEST,
            "dispatcher_digest": "sha256:" + "c" * 64,
            "command": ["scripts/quality.sh", "--ci"],
            "validations": [
                {"validation_id": item["validation_id"], "case_id": item["case_id"], "status": "pass"}
                for item in manifest["validations"]
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            path.write_bytes(canonical_bytes(receipt, newline=True))
            self.assertEqual(
                receipt,
                load_foundation_receipt(path, manifest, "1" * 40, "2" * 40, DIGEST, "sha256:" + "c" * 64),
            )
            receipt["validations"].pop()
            path.write_bytes(canonical_bytes(receipt, newline=True))
            with self.assertRaises(ValueError):
                load_foundation_receipt(path, manifest, "1" * 40, "2" * 40, DIGEST, "sha256:" + "c" * 64)

    def test_foundation_evidence_inventory_is_strict_ordered_and_self_digesting(self) -> None:
        manifest = load_foundation_manifest(FOUNDATION_MANIFEST, FOUNDATION_SCHEMA)
        self.assertEqual("foundation", manifest["suite_id"])
        self.assertEqual(
            ["FOUND-001", "FOUND-002", "FOUND-003", "FOUND-004", "FOUND-005"],
            [item["validation_id"] for item in manifest["validations"]],
        )
        unsigned = dict(manifest)
        claimed = unsigned.pop("manifest_digest")
        self.assertEqual(claimed, digest_bytes(canonical_bytes(unsigned)))
        schema = json.loads(FOUNDATION_SCHEMA.read_bytes())
        Draft202012Validator.check_schema(schema)
        mutated = deepcopy(manifest)
        mutated["validations"][1] = deepcopy(mutated["validations"][0])
        self.assertTrue(tuple(Draft202012Validator(schema).iter_errors(mutated)))

    def test_artifact_name_binds_run_attempt_and_full_source_without_caller_freedom(self) -> None:
        self.assertEqual(
            "foundation-evidence-run-123456789-attempt-2-source-" + "1" * 40,
            artifact_name("foundation-evidence", identity()),
        )
        for base in ("", "../loose", "Foundation Evidence", "foundation-evidence-run-1"):
            with self.subTest(base=base), self.assertRaises(ValueError):
                artifact_name(base, identity())
        with self.assertRaises(ValueError):
            identity(head_sha="main")

    def test_v3_writer_and_independent_ci_verifier_bind_governance_and_run_identity(self) -> None:
        manifest = load_foundation_manifest(FOUNDATION_MANIFEST, FOUNDATION_SCHEMA)
        ids = [item["validation_id"] for item in manifest["validations"]]
        cases = [item["case_id"] for item in manifest["validations"]]
        ci = identity(
            workflow_revision=CURRENT_REVISION,
            head_sha=CURRENT_REVISION,
            base_sha=CURRENT_REVISION,
            trusted_validator_revision=CURRENT_REVISION,
        )
        trusted = context(
            suite_id="foundation",
            suite_manifest_digest=manifest["manifest_digest"],
            declared_validation_ids=ids,
            declared_case_ids=cases,
            governance=governance_binding(),
            ci=ci.as_evidence(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            writer = EvidenceWriter._for_test(root / "runs", trusted, "c" * 32)
            leaves = []
            validations = []
            for item in manifest["validations"]:
                attachment = f"diagnostics/{item['validation_id'].lower()}.json"
                leaves.append(writer.snapshot_bytes(b"{}\n", attachment, "application/json"))
                validations.append(validation(item["validation_id"], item["case_id"], attachment))
            complete = writer.finalize(
                verdict="pass",
                validations=validations,
                attachments=leaves,
                schema_path=SCHEMA,
            )
            verified = verify_ci_evidence(
                complete,
                SCHEMA,
                expected_identity=ci,
                expected_validation_ids=tuple(ids),
            )
            self.assertEqual((), verified.errors)
            assert verified.manifest is not None
            self.assertEqual("3.0.0", verified.manifest["schema_version"])
            report = (complete / "report.md").read_text(encoding="utf-8")
            for expected in (
                "GitHub run: `123456789` (attempt `2`)",
                "Governance audit: `product-fail`",
                "Activate dependency automation.",
            ):
                self.assertIn(expected, report)

    def test_ci_verifier_rejects_mixed_identity_rehash_and_duplicate_inventory(self) -> None:
        manifest = load_foundation_manifest(FOUNDATION_MANIFEST, FOUNDATION_SCHEMA)
        ci = identity(
            workflow_revision=CURRENT_REVISION,
            head_sha=CURRENT_REVISION,
            base_sha=CURRENT_REVISION,
            trusted_validator_revision=CURRENT_REVISION,
        )
        ids = tuple(item["validation_id"] for item in manifest["validations"])
        cases = [item["case_id"] for item in manifest["validations"]]
        trusted = context(
            suite_id="foundation",
            suite_manifest_digest=manifest["manifest_digest"],
            declared_validation_ids=list(ids),
            declared_case_ids=cases,
            governance=governance_binding(),
            ci=ci.as_evidence(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            writer = EvidenceWriter._for_test(root / "runs", trusted, "d" * 32)
            leaves = []
            validations = []
            for item in manifest["validations"]:
                attachment = f"diagnostics/{item['validation_id'].lower()}.json"
                leaves.append(writer.snapshot_bytes(b"{}\n", attachment, "application/json"))
                validations.append(validation(item["validation_id"], item["case_id"], attachment))
            complete = writer.finalize(verdict="pass", validations=validations, attachments=leaves, schema_path=SCHEMA)
            raw_path = complete / "evidence.json"
            raw = json.loads(raw_path.read_bytes())
            raw["ci"]["head_sha"] = "3" * 40
            unsigned = dict(raw)
            unsigned.pop("evidence_digest")
            raw["evidence_digest"] = digest_bytes(canonical_bytes(unsigned))
            raw_path.write_bytes(canonical_bytes(raw, newline=True))
            result = verify_ci_evidence(
                complete,
                SCHEMA,
                expected_identity=ci,
                expected_validation_ids=ids,
            )
            self.assertTrue(result.errors)


if __name__ == "__main__":
    unittest.main()

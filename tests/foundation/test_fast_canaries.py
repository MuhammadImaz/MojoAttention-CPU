from __future__ import annotations

import hashlib
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from mojoattention.validation.fast import Observation, load_manifest
from mojoattention.validation.fast_canaries import (
    AgentLoopFixture,
    AssertionFixture,
    ContractFixture,
    EvidenceFixture,
    ReportFixture,
    WorkflowFixture,
    agent_loop_canary,
    assertion_canary,
    contract_canary,
    evidence_canary,
    execute_false_green_canary,
    protected_change_canary,
    report_canary,
    workflow_canary,
)
from mojoattention.validation.protected_assets import TrustedPolicyInput, git_blob_oid

ROOT = Path(__file__).resolve().parents[2]


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=Fast Canary", "-c", "user.email=fast@example.invalid", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1"},
    ).stdout.strip()


class FastFalseGreenCanaryTests(unittest.TestCase):
    def assert_mutation_then_clean(self, mutated, clean, validation_id: str, verdict: str) -> None:
        rejected = mutated()
        self.assertEqual(validation_id, rejected.validation_id)
        self.assertEqual(verdict, rejected.verdict)
        self.assertFalse(rejected.passed)
        self.assertIsNotNone(rejected.reason_code)
        accepted = clean()
        self.assertEqual(validation_id, accepted.validation_id)
        self.assertEqual("pass", accepted.verdict)
        self.assertTrue(accepted.passed)

    def test_assertion_removal_is_product_failure_with_clean_control(self) -> None:
        self.assert_mutation_then_clean(
            lambda: assertion_canary(AssertionFixture(assertions_executed=0, behavior_detected=False)),
            lambda: assertion_canary(AssertionFixture(assertions_executed=1, behavior_detected=True)),
            "FAST-008",
            "product-fail",
        )

    def test_workflow_omission_tricks_are_contract_invalid_with_clean_controls(self) -> None:
        clean = WorkflowFixture()
        mutations = (
            replace(clean, enabled=False),
            replace(clean, condition_result=False),
            replace(clean, continue_on_error=True),
            replace(clean, propagates_exit=False),
            replace(clean, selected=0, collected=0, completed=0),
            replace(clean, deselected=1),
            replace(clean, skipped=1, completed=0),
            replace(clean, xfailed=1),
            replace(clean, placeholder=True),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_mutation_then_clean(
                    lambda mutation=mutation: workflow_canary(mutation),
                    lambda: workflow_canary(clean),
                    "FAST-009",
                    "contract-invalid",
                )

    def test_forged_and_altered_report_bytes_are_contract_invalid_with_clean_controls(self) -> None:
        payload = b'{"status":"pass"}\n'
        clean = ReportFixture(payload, _digest(payload), payload)
        mutations = (
            replace(clean, observed_bytes=b'{"status":"fail"}\n'),
            replace(clean, declared_digest="sha256:" + "0" * 64),
            replace(clean, rendered_bytes=b"forged report\n"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_mutation_then_clean(
                    lambda mutation=mutation: report_canary(mutation),
                    lambda: report_canary(clean),
                    "FAST-010",
                    "contract-invalid",
                )

    def test_incomplete_records_attachments_and_shards_are_contract_invalid_with_clean_controls(self) -> None:
        record = Observation("FAST-X", "case", 1601, 1, 1, 1, 0, 0, 0, 0, 0, 1, "pass")
        attachment = b"bounded attachment"
        clean = EvidenceFixture(
            expected_ids=("FAST-X",),
            records=(record,),
            attachment=attachment,
            attachment_digest=_digest(attachment),
            shard_complete=True,
            subprocess_succeeded=True,
        )
        mutations = (
            replace(clean, records=()),
            replace(clean, attachment=attachment[:-1]),
            replace(clean, attachment_digest="sha256:" + "0" * 64),
            replace(clean, shard_complete=False),
            replace(clean, records=(replace(record, completed=0),)),
            replace(clean, records=(replace(record, skipped=1, completed=0),)),
            replace(clean, records=(replace(record, xfailed=1),)),
            replace(clean, records=(replace(record, deselected=1),)),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_mutation_then_clean(
                    lambda mutation=mutation: evidence_canary(mutation),
                    lambda: evidence_canary(clean),
                    "FAST-011",
                    "contract-invalid",
                )

    def test_invalid_contract_schema_inventory_and_matrix_are_rejected_with_clean_controls(self) -> None:
        clean = ContractFixture(
            schema_valid=True,
            expected_ids=("FAST-A", "FAST-B"),
            observed_ids=("FAST-A", "FAST-B"),
            expected_counts=(1, 1),
            observed_counts=(1, 1),
        )
        mutations = (
            replace(clean, schema_valid=False),
            replace(clean, observed_ids=("FAST-A",)),
            replace(clean, observed_ids=("FAST-A", "FAST-UNKNOWN")),
            replace(clean, observed_ids=("FAST-A", "FAST-A")),
            replace(clean, observed_counts=(1, 2)),
            replace(clean, observed_counts=(0, 0)),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_mutation_then_clean(
                    lambda mutation=mutation: contract_canary(mutation),
                    lambda: contract_canary(clean),
                    "FAST-012",
                    "contract-invalid",
                )

    def test_unauthorized_protected_change_uses_disposable_git_repository(self) -> None:
        policy_bytes = (ROOT / "contracts" / "protected-assets.json").read_bytes()
        schema_bytes = (ROOT / "schemas" / "protected-assets.schema.json").read_bytes()
        trusted = TrustedPolicyInput(
            policy_bytes,
            schema_bytes,
            git_blob_oid(policy_bytes),
            _digest(policy_bytes),
            _digest(schema_bytes),
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            _git(repo, "init", "-q")
            (repo / "tests").mkdir()
            (repo / "tests" / "canary.py").write_text("assert True\n", encoding="utf-8")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-qm", "base")
            base = _git(repo, "rev-parse", "HEAD")
            (repo / "tests" / "canary.py").write_text("pass\n", encoding="utf-8")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-qm", "candidate")
            candidate = _git(repo, "rev-parse", "HEAD")

            self.assert_mutation_then_clean(
                lambda: protected_change_canary(repo, base, candidate, trusted),
                lambda: protected_change_canary(repo, base, base, trusted),
                "FAST-013",
                "contract-invalid",
            )
            self.assertEqual("", _git(repo, "status", "--porcelain"))

    def test_agent_loop_semantic_and_retry_budget_mutations_have_clean_controls(self) -> None:
        clean = AgentLoopFixture(semantic_failure="causality", retries_consumed=1, retry_budget=1)
        mutations = (
            replace(clean, semantic_failure=None),
            replace(clean, retries_consumed=0),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_mutation_then_clean(
                    lambda mutation=mutation: agent_loop_canary(mutation, ROOT),
                    lambda: agent_loop_canary(clean, ROOT),
                    "FAST-014",
                    "contract-invalid",
                )

    def test_canaries_do_not_accept_fixture_authored_ids_or_expected_verdicts(self) -> None:
        fields = set(AssertionFixture.__dataclass_fields__)
        self.assertNotIn("validation_id", fields)
        self.assertNotIn("expected_verdict", fields)
        self.assertEqual("FAST-008", assertion_canary(AssertionFixture(0, False)).validation_id)

    def test_manifest_canary_adapters_execute_mutation_and_clean_control(self) -> None:
        manifest = load_manifest(
            (ROOT / "contracts" / "validation-suites" / "fast.json").read_bytes(),
            (ROOT / "schemas" / "validation-suite.schema.json").read_bytes(),
        )
        policy_bytes = (ROOT / "contracts" / "protected-assets.json").read_bytes()
        schema_bytes = (ROOT / "schemas" / "protected-assets.schema.json").read_bytes()
        trusted = TrustedPolicyInput(
            policy_bytes,
            schema_bytes,
            git_blob_oid(policy_bytes),
            _digest(policy_bytes),
            _digest(schema_bytes),
        )
        with tempfile.TemporaryDirectory() as directory:
            canary_root = Path(directory)
            for check in manifest.checks:
                if check.kind != "canary":
                    continue
                with self.subTest(validation_id=check.validation_id):
                    result = execute_false_green_canary(check, canary_root, trusted)
                    self.assertEqual("pass", result.observation.status)
                    self.assertEqual((), result.errors)
                    self.assertEqual("mojoattention", check.reproduction_argv[0])
                    self.assertEqual("fast", check.reproduction_argv[3])
            self.assertEqual((), tuple(canary_root.iterdir()))

    def test_adapter_requires_the_expected_structured_mutation_reason(self) -> None:
        manifest = load_manifest(
            (ROOT / "contracts" / "validation-suites" / "fast.json").read_bytes(),
            (ROOT / "schemas" / "validation-suite.schema.json").read_bytes(),
        )
        check = next(item for item in manifest.checks if item.validation_id == "FAST-008")
        policy_bytes = (ROOT / "contracts" / "protected-assets.json").read_bytes()
        schema_bytes = (ROOT / "schemas" / "protected-assets.schema.json").read_bytes()
        trusted = TrustedPolicyInput(
            policy_bytes,
            schema_bytes,
            git_blob_oid(policy_bytes),
            _digest(policy_bytes),
            _digest(schema_bytes),
        )
        rejected = type(assertion_canary(AssertionFixture(0, False)))("FAST-008", "product-fail", False, "WRONG-REASON")
        accepted = assertion_canary(AssertionFixture(1, True))
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "mojoattention.validation.fast_canaries._canary_pair",
                return_value=(rejected, accepted),
            ),
        ):
            result = execute_false_green_canary(check, Path(directory), trusted)
        self.assertEqual("fail", result.observation.status)
        self.assertEqual("FAST-CANARY-CONTROL", result.errors[0].code)


if __name__ == "__main__":
    unittest.main()

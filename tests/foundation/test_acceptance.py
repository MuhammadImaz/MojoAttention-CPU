from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from mojoattention.validation.acceptance import (
    ContractContext,
    compute_contract_digest,
    issue_contract,
    validate_contract,
)

ROOT = Path(__file__).resolve().parents[2]
SOURCE = "1" * 40
BASE = "2" * 40
ANCHOR = "3" * 40


def unsigned_contract() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "contract_id": "story-1-3",
        "contract_version": 1,
        "source_revision": SOURCE,
        "trusted_base_revision": BASE,
        "contract_digest": "sha256:" + ("0" * 64),
        "requirement_ids": ["FR2", "NFR3", "NFR11"],
        "capability_ids": ["CAP-2"],
        "exclusions": ["reference-backend", "mojo-kernel"],
        "allowed_paths": ["src/mojoattention/validation", "tests/foundation"],
        "protected_paths": [],
        "generated_outputs": [],
        "required_suites": [
            {
                "suite_id": "foundation",
                "validations": [
                    {"validation_id": "ACPT-001", "required_count": 1},
                    {"validation_id": "ACPT-003", "required_count": 1},
                ],
                "required_total": 2,
            }
        ],
        "referenced_digests": {
            "tolerance": None,
            "baseline": None,
            "workload": None,
            "protocol": None,
        },
        "retry_budget": 5,
        "prior_validation_identity": None,
        "stop_conditions": [
            "scope-expansion",
            "validation-weakening",
            "protected-conflict",
            "non-improving-retry",
            "nondeterminism",
        ],
        "authorization_id": None,
    }


def valid_contract() -> dict[str, object]:
    return issue_contract(unsigned_contract())


def valid_authorization(contract: dict[str, object]) -> dict[str, object]:
    authorization = {
        "schema_version": "2.0.0",
        "authorization_id": "human-story-1-3",
        "contract_digest": contract["contract_digest"],
        "source_revision": SOURCE,
        "trusted_base_revision": BASE,
        "trusted_base_tree": "5" * 40,
        "candidate_revision": "6" * 40,
        "candidate_tree": "7" * 40,
        "trusted_policy_oid": "8" * 40,
        "trusted_policy_digest": "sha256:" + ("9" * 64),
        "change_set_digest": "sha256:" + ("a" * 64),
        "authorized_protected_paths": contract["protected_paths"],
        "approval_anchor_revision": ANCHOR,
        "approver_kind": "human",
        "provenance_digest": "sha256:" + ("4" * 64),
    }
    payload = dict(authorization)
    payload.pop("provenance_digest")
    authorization["provenance_digest"] = (
        "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    )
    return authorization


class AcceptanceContractTests(unittest.TestCase):
    def context(
        self,
        *,
        authorization: dict[str, object] | None = None,
        prior_validation_identity: str | None = None,
    ) -> ContractContext:
        return ContractContext(
            source_revision=SOURCE,
            trusted_base_revision=BASE,
            prior_validation_identity=prior_validation_identity,
            approval_anchor_revision=ANCHOR if authorization else None,
            authorization=authorization,
        )

    def codes(self, contract: object, context: ContractContext | None = None) -> set[str]:
        return {error.code for error in validate_contract(contract, ROOT, context or self.context())}

    def test_complete_contract_and_schema_pass(self) -> None:
        contract = valid_contract()
        self.assertEqual((), validate_contract(contract, ROOT, self.context()))
        example = json.loads((ROOT / "contracts" / "acceptance" / "1-3.example.json").read_text(encoding="utf-8"))
        self.assertEqual((), validate_contract(example, ROOT, self.context()))

        version_two = unsigned_contract()
        version_two["schema_version"] = "2.0.0"
        version_two["suite_manifest_digest"] = "sha256:" + ("a" * 64)
        version_two = issue_contract(version_two)
        self.assertEqual((), validate_contract(version_two, ROOT, self.context()))

    def test_unknown_missing_and_malformed_fields_fail_stably(self) -> None:
        for mutation in ("unknown", "missing", "version", "revision", "digest"):
            contract = valid_contract()
            if mutation == "unknown":
                contract["surprise"] = True
            elif mutation == "missing":
                del contract["exclusions"]
            elif mutation == "version":
                contract["schema_version"] = "2.0.0"
            elif mutation == "revision":
                contract["source_revision"] = "HEAD"
            else:
                contract["contract_digest"] = "bad"
            self.assertIn("ACPT-001", self.codes(contract), mutation)
        nested = valid_contract()
        suites = deepcopy(nested["required_suites"])
        suites[0]["validations"][0]["unknown"] = True
        nested["required_suites"] = suites
        self.assertIn("ACPT-001", self.codes(nested))

    def test_digest_is_deterministic_and_every_bound_mutation_fails(self) -> None:
        contract = valid_contract()
        reordered = dict(reversed(list(contract.items())))
        self.assertEqual(compute_contract_digest(contract), compute_contract_digest(reordered))
        for field, value in (
            ("requirement_ids", ["FR2"]),
            ("allowed_paths", ["src"]),
            ("retry_budget", 4),
            ("stop_conditions", ["scope-expansion"]),
        ):
            changed = deepcopy(contract)
            changed[field] = value
            self.assertIn("ACPT-003", self.codes(changed), field)
            self.assertNotEqual(contract["contract_digest"], issue_contract(changed)["contract_digest"])

    def test_every_top_level_bound_category_changes_the_digest(self) -> None:
        contract = valid_contract()
        suites = deepcopy(contract["required_suites"])
        suites[0]["validations"][0]["required_count"] = 2
        suites[0]["required_total"] = 3
        references = deepcopy(contract["referenced_digests"])
        references["baseline"] = "sha256:" + ("7" * 64)
        mutations: tuple[tuple[str, object], ...] = (
            ("schema_version", "1.0.1"),
            ("contract_id", "story-1-3-reissued"),
            ("contract_version", 2),
            ("source_revision", "5" * 40),
            ("trusted_base_revision", "6" * 40),
            ("requirement_ids", ["FR2"]),
            ("capability_ids", ["CAP-2", "CAP-3"]),
            ("exclusions", ["reference-backend"]),
            ("allowed_paths", ["src"]),
            ("protected_paths", ["src/mojoattention/validation/acceptance.py"]),
            ("generated_outputs", ["src/mojoattention/validation/output.json"]),
            ("required_suites", suites),
            ("referenced_digests", references),
            ("retry_budget", 4),
            ("prior_validation_identity", "run-1"),
            ("stop_conditions", list(reversed(contract["stop_conditions"]))),  # type: ignore[arg-type]
            ("authorization_id", "human-story-1-3"),
        )
        for field, value in mutations:
            changed = deepcopy(contract)
            changed[field] = value
            self.assertNotEqual(contract["contract_digest"], compute_contract_digest(changed), field)
            self.assertTrue(self.codes(changed), field)

    def test_validator_never_mutates_or_repairs_input(self) -> None:
        contract = valid_contract()
        contract["contract_digest"] = "sha256:" + ("f" * 64)
        before = deepcopy(contract)
        self.assertIn("ACPT-003", self.codes(contract))
        self.assertEqual(before, contract)

    def test_explicit_context_detects_stale_identity(self) -> None:
        contract = valid_contract()
        stale = validate_contract(
            contract,
            ROOT,
            ContractContext(
                source_revision="a" * 40,
                trusted_base_revision=BASE,
                prior_validation_identity=None,
            ),
        )
        self.assertIn("ACPT-002", {error.code for error in stale})
        source_error = next(error for error in stale if error.message == "source revision is stale")
        self.assertEqual(SOURCE, source_error.context["actual"])
        self.assertEqual("a" * 40, source_error.context["expected"])
        contract["prior_validation_identity"] = "run-7"
        contract = issue_contract(contract)
        self.assertIn("ACPT-002", self.codes(contract))
        self.assertEqual((), validate_contract(contract, ROOT, self.context(prior_validation_identity="run-7")))

    def test_path_alias_symlink_overlap_and_scope_expansion_fail(self) -> None:
        for paths in (
            ["../src"],
            ["/src"],
            ["src\\mojoattention"],
            ["src/./mojoattention"],
            ["src/"],
            ["src", "src/mojoattention"],
        ):
            contract = valid_contract()
            contract["allowed_paths"] = paths
            contract = issue_contract(contract)
            self.assertIn("ACPT-004", self.codes(contract), paths)
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            link = Path(directory) / "escape"
            link.symlink_to("/tmp")
            contract = valid_contract()
            contract["allowed_paths"] = [str(link.relative_to(ROOT))]
            contract = issue_contract(contract)
            self.assertIn("ACPT-004", self.codes(contract))
        contract = valid_contract()
        contract["generated_outputs"] = ["reports/result.json"]
        contract = issue_contract(contract)
        self.assertIn("ACPT-004", self.codes(contract))
        contract = valid_contract()
        contract["protected_paths"] = ["contracts/agent-authority.json"]
        contract["authorization_id"] = "human-story-1-3"
        contract = issue_contract(contract)
        self.assertIn("ACPT-004", self.codes(contract))

    def test_inventory_intent_digest_and_retry_semantics(self) -> None:
        mutations: tuple[tuple[str, object, str], ...] = (
            ("requirement_ids", ["FR2", "FR2"], "ACPT-001"),
            ("exclusions", ["FR2"], "ACPT-001"),
            (
                "required_suites",
                [{"suite_id": "foundation", "validations": [], "required_total": 0}],
                "ACPT-001",
            ),
            (
                "required_suites",
                [
                    {
                        "suite_id": "foundation",
                        "validations": [{"validation_id": "ACPT-001", "required_count": 1}],
                        "required_total": 2,
                    }
                ],
                "ACPT-005",
            ),
            ("retry_budget", 6, "ACPT-001"),
            ("stop_conditions", ["scope-expansion"], "ACPT-007"),
        )
        for field, value, code in mutations:
            contract = valid_contract()
            contract[field] = value
            contract = issue_contract(contract)
            self.assertIn(code, self.codes(contract), field)
        contract = valid_contract()
        references = dict(contract["referenced_digests"])  # type: ignore[arg-type]
        references["baseline"] = "sha256:BAD"
        contract["referenced_digests"] = references
        self.assertIn("ACPT-001", self.codes(contract))

    def test_duplicate_validation_ids_across_suites_fail(self) -> None:
        contract = valid_contract()
        contract["required_suites"] = [
            {
                "suite_id": "one",
                "validations": [{"validation_id": "ACPT-001", "required_count": 1}],
                "required_total": 1,
            },
            {
                "suite_id": "two",
                "validations": [{"validation_id": "ACPT-001", "required_count": 2}],
                "required_total": 2,
            },
        ]
        contract = issue_contract(contract)
        self.assertIn("ACPT-005", self.codes(contract))

    def test_suite_total_is_optional_but_checked_when_present(self) -> None:
        contract = valid_contract()
        suites = deepcopy(contract["required_suites"])
        del suites[0]["required_total"]
        contract["required_suites"] = suites
        contract = issue_contract(contract)
        self.assertEqual((), validate_contract(contract, ROOT, self.context()))

    def test_requirement_and_capability_ids_must_be_disjoint(self) -> None:
        contract = valid_contract()
        contract["requirement_ids"] = ["FR2", "CAP-2"]
        contract = issue_contract(contract)
        self.assertIn("ACPT-001", self.codes(contract))

    def test_invalid_repository_schema_returns_stable_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "schemas").mkdir()
            (root / "schemas" / "acceptance-contract.schema.json").write_text(
                '{"$schema":"https://json-schema.org/draft/2020-12/schema","type":7}',
                encoding="utf-8",
            )
            self.assertEqual({"ACPT-001"}, {error.code for error in validate_contract({}, root, self.context())})

    def test_protected_paths_require_exact_external_human_authorization(self) -> None:
        contract = valid_contract()
        contract["allowed_paths"] = ["src/mojoattention/validation/acceptance.py"]
        contract["protected_paths"] = ["src/mojoattention/validation/acceptance.py"]
        contract["authorization_id"] = "human-story-1-3"
        contract = issue_contract(contract)
        self.assertIn("ACPT-008", self.codes(contract))
        authorization = valid_authorization(contract)
        self.assertEqual((), validate_contract(contract, ROOT, self.context(authorization=authorization)))
        for key, value in (
            ("contract_digest", "sha256:" + ("9" * 64)),
            ("approval_anchor_revision", "8" * 40),
            ("approver_kind", "automation"),
            ("authorized_protected_paths", []),
        ):
            invalid = deepcopy(authorization)
            invalid[key] = value
            self.assertIn("ACPT-008", self.codes(contract, self.context(authorization=invalid)), key)

    def test_generated_protected_output_needs_exact_authorization(self) -> None:
        contract = valid_contract()
        contract["allowed_paths"] = ["reports"]
        contract["protected_paths"] = ["reports/result.json"]
        contract["generated_outputs"] = ["reports/result.json"]
        contract["authorization_id"] = "human-story-1-3"
        contract = issue_contract(contract)
        self.assertIn("ACPT-008", self.codes(contract))
        authorization = valid_authorization(contract)
        self.assertEqual((), validate_contract(contract, ROOT, self.context(authorization=authorization)))

    def test_authorized_protected_paths_use_set_semantics(self) -> None:
        contract = valid_contract()
        contract["allowed_paths"] = [
            "schemas/acceptance-contract.schema.json",
            "schemas/protected-change-authorization.schema.json",
        ]
        contract["protected_paths"] = [
            "schemas/acceptance-contract.schema.json",
            "schemas/protected-change-authorization.schema.json",
        ]
        contract["authorization_id"] = "human-story-1-3"
        contract = issue_contract(contract)
        authorization = valid_authorization(contract)
        authorization["authorized_protected_paths"] = list(reversed(authorization["authorized_protected_paths"]))
        payload = dict(authorization)
        payload.pop("provenance_digest")
        authorization["provenance_digest"] = (
            "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        )
        self.assertEqual((), validate_contract(contract, ROOT, self.context(authorization=authorization)))

    def test_approval_anchor_cannot_self_reference_source_revision(self) -> None:
        contract = valid_contract()
        contract["allowed_paths"] = ["src/mojoattention/validation/acceptance.py"]
        contract["protected_paths"] = ["src/mojoattention/validation/acceptance.py"]
        contract["authorization_id"] = "human-story-1-3"
        contract = issue_contract(contract)
        authorization = valid_authorization(contract)
        authorization["approval_anchor_revision"] = SOURCE
        context = ContractContext(
            source_revision=SOURCE,
            trusted_base_revision=BASE,
            prior_validation_identity=None,
            approval_anchor_revision=SOURCE,
            authorization=authorization,
        )
        self.assertIn("ACPT-008", self.codes(contract, context))

    def test_cli_validates_contract_and_reports_input_failures(self) -> None:
        command = [
            sys.executable,
            "-m",
            "mojoattention.cli.main",
            "contract",
            "validate",
            "--contract",
            "contracts/acceptance/1-3.example.json",
            "--source-revision",
            SOURCE,
            "--trusted-base-revision",
            BASE,
            "--json",
            "-",
        ]
        passed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(0, passed.returncode, passed.stderr)
        self.assertEqual("pass", json.loads(passed.stdout)["verdict"])
        missing = command.copy()
        missing[missing.index("contracts/acceptance/1-3.example.json")] = "missing.json"
        failed = subprocess.run(missing, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(3, failed.returncode)
        self.assertEqual("ACPT-009", json.loads(failed.stdout)["errors"][0]["code"])
        outside = subprocess.run(command, cwd="/tmp", text=True, capture_output=True, check=False)
        self.assertEqual(0, outside.returncode, outside.stderr)
        usage = subprocess.run(
            [sys.executable, "-m", "mojoattention.cli.main", "contract", "validate"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(64, usage.returncode)

    def test_cli_rejects_proposal_local_authorization_and_output_failure(self) -> None:
        command = [
            sys.executable,
            "-m",
            "mojoattention.cli.main",
            "contract",
            "validate",
            "--contract",
            "contracts/acceptance/1-3.example.json",
            "--source-revision",
            SOURCE,
            "--trusted-base-revision",
            BASE,
            "--authorization",
            "contracts/acceptance/1-3.authorization.example.json",
            "--approval-anchor-revision",
            ANCHOR,
            "--json",
            "-",
        ]
        local = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(3, local.returncode)
        self.assertEqual("ACPT-008", json.loads(local.stdout)["errors"][0]["code"])
        no_output = command[:]
        del no_output[no_output.index("--authorization") : no_output.index("--json")]
        no_output[-1] = "."
        failed = subprocess.run(no_output, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(3, failed.returncode)

    def test_cli_requires_independent_anchor_and_classifies_input_boundaries(self) -> None:
        contract = valid_contract()
        contract["allowed_paths"] = ["src/mojoattention/validation/acceptance.py"]
        contract["protected_paths"] = ["src/mojoattention/validation/acceptance.py"]
        contract["authorization_id"] = "human-story-1-3"
        contract = issue_contract(contract)
        authorization = valid_authorization(contract)
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            contract_path = temporary / "contract.json"
            authorization_path = temporary / "authorization.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            authorization_path.write_text(json.dumps(authorization), encoding="utf-8")
            base = [
                sys.executable,
                "-m",
                "mojoattention.cli.main",
                "contract",
                "validate",
                "--contract",
                str(contract_path),
                "--source-revision",
                SOURCE,
                "--trusted-base-revision",
                BASE,
                "--authorization",
                str(authorization_path),
                "--json",
                "-",
            ]
            missing_anchor = subprocess.run(base, cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(3, missing_anchor.returncode)
            self.assertEqual("ACPT-008", json.loads(missing_anchor.stdout)["errors"][0]["code"])
            with_anchor = base[:-2] + ["--approval-anchor-revision", ANCHOR, "--json", "-"]
            passed = subprocess.run(with_anchor, cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(0, passed.returncode, passed.stderr)
            authorization_path.write_text("{", encoding="utf-8")
            malformed = subprocess.run(with_anchor, cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual("ACPT-008", json.loads(malformed.stdout)["errors"][0]["code"])
            missing_contract = with_anchor[:]
            missing_contract[missing_contract.index(str(contract_path))] = str(temporary / "missing-authorization.json")
            failed = subprocess.run(missing_contract, cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual("ACPT-009", json.loads(failed.stdout)["errors"][0]["code"])

    def test_cli_classifies_symlink_resolution_loops(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            left = temporary / "left"
            right = temporary / "right"
            left.symlink_to(right)
            right.symlink_to(left)
            command = [
                sys.executable,
                "-m",
                "mojoattention.cli.main",
                "contract",
                "validate",
                "--contract",
                "contracts/acceptance/1-3.example.json",
                "--source-revision",
                SOURCE,
                "--trusted-base-revision",
                BASE,
                "--authorization",
                str(left),
                "--approval-anchor-revision",
                ANCHOR,
                "--json",
                "-",
            ]
            authorization = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(3, authorization.returncode)
            self.assertEqual("ACPT-008", json.loads(authorization.stdout)["errors"][0]["code"])
            environment = dict(os.environ)
            environment["MOJOATTENTION_PROJECT_ROOT"] = str(left)
            project_root = subprocess.run(
                command[: command.index("--authorization")] + ["--json", "-"],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(3, project_root.returncode)
            self.assertEqual("ACPT-009", json.loads(project_root.stdout)["errors"][0]["code"])


if __name__ == "__main__":
    unittest.main()

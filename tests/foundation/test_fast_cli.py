from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from mojoattention.cli.main import (
    _attribute_protected_errors,
    _fast_contract_inventory,
    _foundation_adapters,
    build_parser,
    main,
)
from mojoattention.validation.fast import (
    FastError,
    FastRunResult,
    Observation,
    ProcessResult,
    evidence_validations,
    verify_fast_evidence,
)
from mojoattention.validation.protected_assets import ProtectedError

TRUST_ARGS = [
    "--trusted-base",
    "/tmp/trusted-base.json",
    "--trusted-policy",
    "/tmp/protected-assets.json",
    "--trusted-policy-schema",
    "/tmp/protected-assets.schema.json",
    "--authorization",
    "/tmp/authorization.json",
    "--trusted-authorization-schema",
    "/tmp/protected-change-authorization.schema.json",
    "--approval-anchor-revision",
    "a" * 40,
]


class FastCliTests(unittest.TestCase):
    def test_parser_exposes_only_the_canonical_fast_surface(self) -> None:
        parsed = build_parser().parse_args(
            [
                "validate",
                "--suite",
                "fast",
                *TRUST_ARGS,
                "--contract",
                "/tmp/issued-contract.json",
                "--output",
                "reports/runs",
            ]
        )
        self.assertEqual("validate", parsed.command)
        self.assertEqual("fast", parsed.suite)
        self.assertEqual("reports/runs", parsed.output)

    def test_noncanonical_output_is_contract_invalid_without_orchestration(self) -> None:
        with patch("mojoattention.cli.main.run_fast_validation") as run:
            self.assertEqual(
                3,
                main(
                    [
                        "validate",
                        "--suite",
                        "fast",
                        *TRUST_ARGS,
                        "--contract",
                        "/tmp/issued-contract.json",
                        "--output",
                        "/tmp/chosen-run",
                    ]
                ),
            )
        run.assert_not_called()

    def test_cli_emits_canonical_payload_and_public_verdict_exit(self) -> None:
        with (
            patch(
                "mojoattention.cli.main.run_fast_validation",
                return_value=("product-fail", Path("/repo/reports/runs/a.complete"), ()),
            ),
            patch("mojoattention.cli.main._root", return_value=Path("/repo")),
        ):
            self.assertEqual(
                1,
                main(
                    [
                        "validate",
                        "--suite",
                        "fast",
                        *TRUST_ARGS,
                        "--contract",
                        "/tmp/issued-contract.json",
                        "--output",
                        "reports/runs",
                    ]
                ),
            )

    def test_publication_failure_is_non_evidence_infrastructure_invalid(self) -> None:
        stdout = StringIO()
        stderr = StringIO()
        with (
            patch("mojoattention.cli.main.run_fast_validation", side_effect=OSError("private")),
            patch("mojoattention.cli.main._root", return_value=Path("/repo")),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            exit_code = main(
                [
                    "validate",
                    "--suite",
                    "fast",
                    *TRUST_ARGS,
                    "--contract",
                    "/tmp/issued-contract.json",
                    "--output",
                    "reports/runs",
                ]
            )
        self.assertEqual(2, exit_code)
        self.assertEqual(
            {
                "errors": [
                    {
                        "code": "FAST-CLI-003",
                        "context": {"phase": "orchestrate"},
                        "message": "Fast execution or publication failed",
                    }
                ],
                "non_evidence": True,
                "verdict": "infrastructure-invalid",
            },
            json.loads(stdout.getvalue()),
        )
        self.assertNotIn("private", stderr.getvalue())

    def test_validate_usage_exit_is_64_and_diagnostic_only_uses_stderr(self) -> None:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            main(["validate", "--suite", "fast"])
        self.assertEqual(64, raised.exception.code)
        self.assertEqual("", stdout.getvalue())
        self.assertIn("usage:", stderr.getvalue())

    def test_all_public_verdicts_have_exact_exits_and_canonical_stdout(self) -> None:
        expected = {"pass": 0, "product-fail": 1, "infrastructure-invalid": 2, "contract-invalid": 3}
        for verdict, expected_exit in expected.items():
            stdout = StringIO()
            stderr = StringIO()
            with (
                self.subTest(verdict=verdict),
                patch(
                    "mojoattention.cli.main.run_fast_validation",
                    return_value=(verdict, Path("/repo/reports/runs/generated.complete"), ()),
                ),
                patch("mojoattention.cli.main._root", return_value=Path("/repo")),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                exit_code = main(
                    [
                        "validate",
                        "--suite",
                        "fast",
                        *TRUST_ARGS,
                        "--contract",
                        "/tmp/issued-contract.json",
                        "--output",
                        "reports/runs",
                    ]
                )
            self.assertEqual(expected_exit, exit_code)
            self.assertEqual(verdict, json.loads(stdout.getvalue())["verdict"])
            self.assertEqual("", stderr.getvalue())
            self.assertTrue(stdout.getvalue().endswith("\n"))


class FastContractIntersectionTests(unittest.TestCase):
    def setUp(self) -> None:
        from mojoattention.validation.fast import load_manifest

        root = Path(__file__).resolve().parents[2]
        self.manifest = load_manifest(
            (root / "contracts/validation-suites/fast.json").read_bytes(),
            (root / "schemas/validation-suite.schema.json").read_bytes(),
        )
        self.contract = {
            "schema_version": "2.0.0",
            "suite_manifest_digest": self.manifest.manifest_digest,
            "config_digest": self.manifest.config_digest,
            "required_suites": [
                {
                    "suite_id": "fast",
                    "validations": [
                        {"validation_id": item.validation_id, "required_count": item.required_count}
                        for item in self.manifest.checks
                    ],
                    "required_total": self.manifest.required_total,
                }
            ],
        }

    def test_exact_contract_manifest_intersection_passes(self) -> None:
        _fast_contract_inventory(self.contract, self.manifest)
        self.assertEqual(self.manifest.manifest_digest, self.contract["suite_manifest_digest"])
        self.assertEqual(self.manifest.config_digest, self.contract["config_digest"])
        suite = self.contract["required_suites"][0]
        self.assertEqual(14, suite["required_total"])
        self.assertEqual("FAST-014", suite["validations"][-1]["validation_id"])

    def test_tracked_story_1_7_v2_contract_drives_exact_evidence_inventory(self) -> None:
        root = Path(__file__).resolve().parents[2]
        contract = json.loads((root / "contracts/acceptance/1-7-agent-loop.example.json").read_bytes())
        _fast_contract_inventory(contract, self.manifest)
        observations = tuple(
            Observation(
                check.validation_id,
                check.case_id,
                check.seed,
                1,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                1,
                "pass",
            )
            for check in self.manifest.checks
        )
        validations = evidence_validations(
            FastRunResult("pass", observations, (), 1),
            {check.validation_id: check.reproduction_argv for check in self.manifest.checks},
            reference_target_ns=self.manifest.reference_target_ns,
        )
        self.assertEqual(
            [item["validation_id"] for item in contract["required_suites"][0]["validations"]],
            [item["validation_id"] for item in validations],
        )

    def test_any_contract_manifest_drift_is_rejected(self) -> None:
        mutations = []
        missing = deepcopy(self.contract)
        missing["required_suites"][0]["validations"].pop()
        mutations.append(missing)
        extra = deepcopy(self.contract)
        extra["required_suites"][0]["validations"].append({"validation_id": "FAST-999", "required_count": 1})
        mutations.append(extra)
        reordered = deepcopy(self.contract)
        reordered["required_suites"][0]["validations"].reverse()
        mutations.append(reordered)
        count = deepcopy(self.contract)
        count["required_suites"][0]["validations"][0]["required_count"] = 2
        mutations.append(count)
        total = deepcopy(self.contract)
        total["required_suites"][0]["required_total"] = 0
        mutations.append(total)
        suite_digest = deepcopy(self.contract)
        suite_digest["suite_manifest_digest"] = "sha256:" + "0" * 64
        mutations.append(suite_digest)
        config_digest = deepcopy(self.contract)
        config_digest["config_digest"] = "sha256:" + "0" * 64
        mutations.append(config_digest)
        wrong_version = deepcopy(self.contract)
        wrong_version["schema_version"] = "1.0.0"
        mutations.append(wrong_version)
        for contract in mutations:
            with self.subTest(contract=contract), self.assertRaises(ValueError):
                _fast_contract_inventory(contract, self.manifest)

    def test_foundation_adapters_execute_static_import_and_path_checks(self) -> None:
        adapters = _foundation_adapters(Path("/repo"), self.manifest, authority_valid=True)
        checks = {item.validation_id: item for item in self.manifest.checks}
        with (
            patch(
                "mojoattention.cli.main.run_bounded_argv",
                return_value=ProcessResult(0, b"", b"", False),
            ) as bounded,
            patch(
                "mojoattention.cli.main.subprocess.check_output",
                return_value=b"src/mojoattention/__init__.py\0",
            ),
        ):
            self.assertEqual("pass", adapters["FAST-003"](checks["FAST-003"]).observation.status)
            self.assertEqual("pass", adapters["FAST-004"](checks["FAST-004"]).observation.status)
            self.assertEqual("pass", adapters["FAST-006"](checks["FAST-006"]).observation.status)
        self.assertEqual(
            ("ruff", "check", "./src/mojoattention/__init__.py"),
            bounded.call_args_list[0].args[0],
        )
        self.assertEqual("-c", bounded.call_args_list[1].args[0][1])

    def test_static_adapter_ignores_untracked_python_and_uses_only_head_tree_paths(self) -> None:
        adapters = _foundation_adapters(Path("/repo"), self.manifest, authority_valid=True)
        check = next(item for item in self.manifest.checks if item.validation_id == "FAST-003")
        with (
            patch(
                "mojoattention.cli.main.subprocess.check_output",
                return_value=b"src/mojoattention/good.py\0tests/foundation/test_good.py\0",
            ),
            patch(
                "mojoattention.cli.main.run_bounded_argv",
                return_value=ProcessResult(0, b"", b"", False),
            ) as bounded,
        ):
            result = adapters["FAST-003"](check)
        self.assertEqual("pass", result.observation.status)
        argv = bounded.call_args.args[0]
        self.assertEqual(
            (
                "ruff",
                "check",
                "./src/mojoattention/good.py",
                "./tests/foundation/test_good.py",
            ),
            argv,
        )
        self.assertNotIn(".", argv)
        self.assertNotIn("./untracked_bad.py", argv)

    def test_foundation_adapter_failures_are_typed_and_private_paths_are_not_reported(self) -> None:
        adapters = _foundation_adapters(Path("/repo"), self.manifest, authority_valid=True)
        checks = {item.validation_id: item for item in self.manifest.checks}
        failed = ProcessResult(
            9,
            b"human success text",
            b"human failure text",
            False,
            "product-fail",
            FastError("FAST-EXEC-004", "bounded subprocess returned a nonzero exit", {}),
        )
        with (
            patch("mojoattention.cli.main.run_bounded_argv", return_value=failed),
            patch(
                "mojoattention.cli.main.subprocess.check_output",
                return_value=b"src/mojoattention/good.py\0",
            ),
        ):
            static = adapters["FAST-003"](checks["FAST-003"])
        self.assertEqual("product-fail", static.observation.failure_class)
        with patch(
            "mojoattention.cli.main.subprocess.check_output",
            return_value=b".agents/private-state.json\0.codex/session.json\0",
        ):
            path = adapters["FAST-006"](checks["FAST-006"])
        self.assertEqual("contract-invalid", path.observation.failure_class)
        self.assertEqual({"count": 2}, path.errors[0].context)

    def test_protected_findings_are_attributed_only_to_fast_013(self) -> None:
        observations = tuple(
            Observation(
                item.validation_id,
                item.case_id,
                item.seed,
                1,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                1,
                "pass",
            )
            for item in self.manifest.checks
        )
        result = _attribute_protected_errors(
            FastRunResult("pass", observations, (), 1),
            (ProtectedError("PROT-003", "unauthorized", {"path": "protected"}),),
        )
        failed = [item for item in result.observations if item.status == "fail"]
        self.assertEqual(["FAST-013"], [item.validation_id for item in failed])
        self.assertEqual("FAST-013", result.errors[0].context["validation_id"])


class FastEvidenceTranslationTests(unittest.TestCase):
    def test_every_observation_becomes_one_schema_shaped_validation(self) -> None:
        observation = Observation(
            "FAST-001",
            "acceptance-contract",
            1601,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            1,
            "fail",
            "infrastructure-invalid",
        )
        result = FastRunResult(
            "infrastructure-invalid",
            (observation,),
            (FastError("FAST-ADAPTER-002", "adapter failed", {}),),
            9,
        )
        validations = evidence_validations(
            result,
            {"FAST-001": ("mojoattention", "validate", "--suite", "fast")},
        )
        self.assertEqual(1, len(validations))
        self.assertEqual("fail", validations[0]["status"])
        self.assertEqual("FAST-ADAPTER-002", validations[0]["errors"][0]["code"])
        self.assertEqual([], validations[0]["attachments"])
        metrics = {item["name"]: (item["value"], item["unit"]) for item in validations[0]["metrics"]}
        self.assertEqual((9, "nanoseconds"), metrics["run-elapsed"])
        self.assertEqual((1601, "seed"), metrics["seed"])
        self.assertEqual((1, "count"), metrics["selected"])
        self.assertEqual((1, "count"), metrics["collected"])
        self.assertEqual((1, "count"), metrics["completed"])
        self.assertEqual((0, "count"), metrics["skipped"])
        self.assertEqual((0, "count"), metrics["xfailed"])
        self.assertEqual((0, "count"), metrics["deselected"])
        self.assertEqual((0, "count"), metrics["collection-errors"])
        self.assertEqual((0, "index"), metrics["shard-index"])
        self.assertEqual((1, "count"), metrics["shard-total"])

    def test_verified_fast_evidence_requires_exact_authenticated_completion(self) -> None:
        from mojoattention.validation.fast import load_manifest

        root = Path(__file__).resolve().parents[2]
        manifest = load_manifest(
            (root / "contracts/validation-suites/fast.json").read_bytes(),
            (root / "schemas/validation-suite.schema.json").read_bytes(),
        )
        observations = tuple(
            Observation(
                check.validation_id,
                check.case_id,
                check.seed,
                1,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                1,
                "pass",
            )
            for check in manifest.checks
        )
        result = FastRunResult("pass", observations, (), 17)
        validations = evidence_validations(
            result,
            {check.validation_id: check.reproduction_argv for check in manifest.checks},
            reference_target_ns=manifest.reference_target_ns,
        )
        evidence = {
            "verdict": "pass",
            "seed": manifest.seed,
            "declared_validation_ids": [check.validation_id for check in manifest.checks],
            "declared_case_ids": [check.case_id for check in manifest.checks],
            "validations": validations,
        }
        self.assertEqual((), verify_fast_evidence(manifest, result, evidence))
        metrics = {item["name"]: item for item in validations[0]["metrics"]}
        self.assertEqual(manifest.reference_target_ns, metrics["reference-target"]["value"])
        self.assertEqual("nanoseconds", metrics["reference-target"]["unit"])

        tampered = dict(evidence)
        tampered_validations = [dict(item) for item in validations]
        tampered_metrics = [dict(item) for item in tampered_validations[0]["metrics"]]
        next(item for item in tampered_metrics if item["name"] == "seed")["value"] = 9
        tampered_validations[0]["metrics"] = tampered_metrics
        tampered["validations"] = tampered_validations
        errors = verify_fast_evidence(manifest, result, tampered)
        self.assertEqual("FAST-EVID-001", errors[0].code)


if __name__ == "__main__":
    unittest.main()

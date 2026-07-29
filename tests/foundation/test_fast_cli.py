from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from mojoattention.cli.main import build_parser, main
from mojoattention.validation.fast import (
    FastError,
    FastRunResult,
    Observation,
    evidence_validations,
    verify_fast_evidence,
)


class FastCliTests(unittest.TestCase):
    def test_parser_exposes_only_the_canonical_fast_surface(self) -> None:
        parsed = build_parser().parse_args(
            [
                "validate",
                "--suite",
                "fast",
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

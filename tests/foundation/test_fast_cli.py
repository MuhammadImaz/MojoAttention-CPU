from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from mojoattention.cli.main import build_parser, main
from mojoattention.validation.fast import (
    FastError,
    FastRunResult,
    Observation,
    evidence_validations,
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


if __name__ == "__main__":
    unittest.main()

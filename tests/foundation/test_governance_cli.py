from __future__ import annotations

import json
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from mojoattention.cli.main import build_parser, main
from mojoattention.validation.governance import GovernanceError, GovernanceResult

ARGS = [
    "governance",
    "audit",
    "--intent",
    "/tmp/repository-governance.json",
    "--intent-schema",
    "/tmp/repository-governance.schema.json",
    "--observation",
    "/tmp/governance-observation.json",
    "--observation-schema",
    "/tmp/governance-observation.schema.json",
    "--required-checks",
    "/tmp/required-checks.json",
    "--required-checks-schema",
    "/tmp/required-checks.schema.json",
    "--repository",
    "owner/repository",
    "--default-branch",
    "main",
    "--head-sha",
    "1" * 40,
    "--base-sha",
    "2" * 40,
    "--evaluation-time",
    "2026-08-05T12:00:00Z",
    "--maximum-age-seconds",
    "3600",
    "--api-version",
    "2026-03-10",
]


def result(verdict: str) -> GovernanceResult:
    finding = GovernanceError("GOV-101", "mismatch", {"token": "[REDACTED]"})
    return GovernanceResult(
        verdict,  # type: ignore[arg-type]
        verdict in {"pass", "product-fail"},
        verdict == "pass",
        () if verdict == "pass" else (finding,),
        ("Activate protection.",) if verdict == "product-fail" else (),
        ("repository-main",),
    )


def records() -> list[object]:
    return [
        {"state_kind": "configured-intent"},
        {"state_kind": "observed-hosted-state"},
        {"registry_id": "mojoattention-required-checks"},
    ]


def test_parser_exposes_only_read_only_audit_with_explicit_inputs() -> None:
    parsed = build_parser().parse_args(ARGS)
    assert parsed.command == "governance"
    assert parsed.governance_command == "audit"
    with pytest.raises(SystemExit) as raised:
        build_parser().parse_args(["governance", "activate"])
    assert raised.value.code == 64


def test_usage_failure_is_64_on_stderr_only() -> None:
    stdout, stderr = StringIO(), StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr), pytest.raises(SystemExit) as raised:
        main(["governance", "audit"])
    assert raised.value.code == 64
    assert stdout.getvalue() == ""
    assert "usage:" in stderr.getvalue()


@pytest.mark.parametrize(
    ("verdict", "exit_code"),
    [("pass", 0), ("product-fail", 1), ("infrastructure-invalid", 2), ("contract-invalid", 3)],
)
def test_typed_exits_and_canonical_separated_payload(verdict: str, exit_code: int) -> None:
    stdout, stderr = StringIO(), StringIO()
    with (
        patch("mojoattention.cli.main._read_json", side_effect=records()),
        patch("mojoattention.cli.main.evaluate_governance", return_value=result(verdict)) as evaluate,
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        assert main(ARGS) == exit_code
    payload = json.loads(stdout.getvalue())
    assert list(payload) == sorted(payload)
    assert payload["verdict"] == verdict
    assert payload["declared_intent"] == {"state_kind": "configured-intent"}
    assert payload["observed_state"] == {"state_kind": "observed-hosted-state"}
    assert isinstance(payload["mismatches"], list)
    assert isinstance(payload["unavailable"], list)
    assert isinstance(payload["human_actions"], list)
    assert payload["reproduction_argv"] == ["mojoattention", *ARGS]
    assert stdout.getvalue().endswith("\n")
    evaluate.assert_called_once()
    assert "[REDACTED]" in stderr.getvalue() or stderr.getvalue() == ""


def test_input_errors_are_bounded_redacted_contract_invalid() -> None:
    stdout, stderr = StringIO(), StringIO()
    secret_args = [value.replace("repository-governance.json", "token=private.json") for value in ARGS]
    with (
        patch("mojoattention.cli.main._read_json", side_effect=OSError("token=private")),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        assert main(secret_args) == 3
    combined = stdout.getvalue() + stderr.getvalue()
    assert "private" not in combined
    assert json.loads(stdout.getvalue())["verdict"] == "contract-invalid"


def test_cli_passes_explicit_time_and_identity_without_environment_defaults() -> None:
    with (
        patch("mojoattention.cli.main._read_json", side_effect=records()),
        patch("mojoattention.cli.main.evaluate_governance", return_value=result("pass")) as evaluate,
        redirect_stdout(StringIO()),
    ):
        assert main(ARGS) == 0
    kwargs = evaluate.call_args.kwargs
    assert kwargs["repository"] == "owner/repository"
    assert kwargs["api_version"] == "2026-03-10"
    assert kwargs["observed_at"] == datetime(2026, 8, 5, 12, tzinfo=UTC)
    assert kwargs["intent_schema"] == Path("/tmp/repository-governance.schema.json")

from __future__ import annotations

import json
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from mojoattention.cli.main import build_parser, main, run_agent_loop_evaluate
from mojoattention.validation.agent_loop import AuthenticatedLoopControls, EvidenceBinding, LoopHeader, LoopState

TRUST_ARGS = [
    "--contract",
    "/tmp/issued-contract.json",
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
    "--trusted-loop-schema",
    "/tmp/agent-loop-state.schema.json",
    "--role",
    "implementation-agent",
]


def state(status: str = "awaiting-validation", terminal: bool = False) -> LoopState:
    header = LoopHeader(
        "1.0.0",
        "1" * 32,
        "sha256:" + "a" * 64,
        "a" * 40,
        "b" * 40,
        "c" * 40,
        "d" * 40,
        "implementation-agent",
        2,
        ("src",),
        ("schemas",),
        "2026-07-29T12:00:00Z",
        "sha256:" + "e" * 64,
    )
    return LoopState(header, (), status, 1, 0, None, None, terminal)  # type: ignore[arg-type]


def test_parser_exposes_canonical_start_evaluate_and_inspect_surfaces() -> None:
    start = build_parser().parse_args(["agent-loop", "start", *TRUST_ARGS, "--timestamp", "2026-07-29T12:00:00Z"])
    assert start.agent_loop_command == "start"
    evaluate = build_parser().parse_args(
        [
            "agent-loop",
            "evaluate",
            *TRUST_ARGS,
            "--loop-id",
            "1" * 32,
            "--event",
            "/tmp/event.json",
            "--evidence",
            "/tmp/run.complete",
        ]
    )
    assert evaluate.agent_loop_command == "evaluate"
    inspect = build_parser().parse_args(
        [
            "agent-loop",
            "inspect",
            "--loop-id",
            "1" * 32,
            "--trusted-loop-schema",
            "/tmp/agent-loop-state.schema.json",
        ]
    )
    assert inspect.agent_loop_command == "inspect"


def test_usage_errors_exit_64_on_stderr_only() -> None:
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr), pytest.raises(SystemExit) as raised:
        main(["agent-loop", "start"])
    assert raised.value.code == 64
    assert stdout.getvalue() == ""
    assert "usage:" in stderr.getvalue()


def test_start_returns_generated_identity_and_exact_next_action() -> None:
    stdout = StringIO()
    stderr = StringIO()
    with (
        patch("mojoattention.cli.main.run_agent_loop_start", return_value=state()),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        result = main(["agent-loop", "start", *TRUST_ARGS, "--timestamp", "2026-07-29T12:00:00Z"])
    assert result == 0
    assert json.loads(stdout.getvalue()) == {
        "attempt": 1,
        "errors": [],
        "loop_id": "1" * 32,
        "next_action": "record-validation",
        "retries_consumed": 0,
        "status": "awaiting-validation",
        "terminal": False,
        "verdict": "pass",
    }
    assert stdout.getvalue().endswith("\n")
    assert stderr.getvalue() == ""


def test_inspect_is_read_only_and_pass_means_awaiting_human_review() -> None:
    stdout = StringIO()
    awaiting_review = state("awaiting-human-review", True)
    with (
        patch("mojoattention.cli.main.run_agent_loop_inspect", return_value=awaiting_review) as inspect,
        redirect_stdout(stdout),
    ):
        result = main(
            [
                "agent-loop",
                "inspect",
                "--loop-id",
                "1" * 32,
                "--trusted-loop-schema",
                "/tmp/agent-loop-state.schema.json",
            ]
        )
    assert result == 0
    assert json.loads(stdout.getvalue())["next_action"] == "human-review"
    assert json.loads(stdout.getvalue())["status"] == "awaiting-human-review"
    inspect.assert_called_once()


@pytest.mark.parametrize(
    ("verdict", "exit_code"),
    [
        ("pass", 0),
        ("product-fail", 1),
        ("infrastructure-invalid", 2),
        ("contract-invalid", 3),
    ],
)
def test_evaluate_preserves_typed_verdict_exits(verdict: str, exit_code: int) -> None:
    stdout = StringIO()
    with (
        patch("mojoattention.cli.main.run_agent_loop_evaluate", return_value=(state(), verdict)),
        redirect_stdout(stdout),
    ):
        result = main(
            [
                "agent-loop",
                "evaluate",
                *TRUST_ARGS,
                "--loop-id",
                "1" * 32,
                "--event",
                "/tmp/event.json",
                "--evidence",
                "/tmp/run.complete",
            ]
        )
    assert result == exit_code
    assert json.loads(stdout.getvalue())["verdict"] == verdict


def test_structured_errors_do_not_leak_private_exception_text() -> None:
    stdout = StringIO()
    stderr = StringIO()
    with (
        patch("mojoattention.cli.main.run_agent_loop_start", side_effect=ValueError("private secret")),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        result = main(["agent-loop", "start", *TRUST_ARGS, "--timestamp", "2026-07-29T12:00:00Z"])
    assert result == 3
    payload = json.loads(stdout.getvalue())
    assert payload["errors"][0]["code"] == "LOOP-CLI-001"
    assert "private secret" not in stdout.getvalue() + stderr.getvalue()


def authenticated_controls() -> AuthenticatedLoopControls:
    return AuthenticatedLoopControls(
        "sha256:" + "a" * 64,
        "a" * 40,
        "b" * 40,
        "c" * 40,
        "d" * 40,
        "implementation-agent",
        ("src",),
        ("schemas",),
        2,
        "fast",
        "sha256:" + "e" * 64,
        "sha256:" + "f" * 64,
        ("FAST-014",),
        b"{}",
    )


def test_evaluate_authenticates_and_admits_evidence_before_durable_pass_append() -> None:
    args = build_parser().parse_args(
        [
            "agent-loop",
            "evaluate",
            *TRUST_ARGS,
            "--loop-id",
            "1" * 32,
            "--event",
            "/tmp/event.json",
            "--evidence",
            "/tmp/run.complete",
        ]
    )
    awaiting_review = state("awaiting-human-review", True)
    binding = EvidenceBinding(
        "2" * 32,
        "sha256:" + "9" * 64,
        "a" * 40,
        "b" * 40,
        "sha256:" + "a" * 64,
        "complete",
        True,
        "pass",
        ("FAST-014",),
    )
    event = {
        "record_type": "event",
        "schema_version": "1.0.0",
        "attempt": 1,
        "validation_binding": {"validation_id": "FAST-014", "status": "pass", "errors": []},
        "diagnosis": None,
        "improvement_proof": None,
        "stop_reason": None,
        "actor_kind": "validator",
        "timestamp": "2026-07-29T12:00:01Z",
    }
    with (
        patch("mojoattention.cli.main.AgentLoopJournal") as journal_class,
        patch(
            "mojoattention.cli.main._load_agent_loop_controls",
            return_value=(authenticated_controls(), b"{}", {}),
        ),
        patch("mojoattention.cli.main._read_protected_caller_bytes", return_value=json.dumps(event).encode()),
        patch(
            "mojoattention.cli.main.verify_evidence",
            return_value=type(
                "Verification",
                (),
                {
                    "errors": (),
                    "manifest": {
                        "verdict": "pass",
                        "config_digest": "sha256:" + "e" * 64,
                        "validations": [
                            {
                                "validation_id": "FAST-014",
                                "case_id": "fast-014",
                                "status": "pass",
                                "metrics": [],
                                "errors": [],
                            }
                        ],
                    },
                },
            )(),
        ),
        patch("mojoattention.cli.main.admit_completed_evidence", return_value=binding) as admit,
    ):
        journal_class.return_value.inspect.return_value = state()
        journal_class.return_value.append.return_value = awaiting_review
        result, verdict = run_agent_loop_evaluate(Path("/repo"), args)
    assert result.status == "awaiting-human-review"
    assert verdict == "pass"
    admit.assert_called_once()
    appended = journal_class.return_value.append.call_args.args[1]
    assert appended["transition"] == "awaiting-human-review"
    assert appended["status"] == "awaiting-human-review"
    assert "approval" not in appended
    assert "merge" not in appended

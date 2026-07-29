from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from mojoattention.validation.acceptance import ContractContext, issue_contract, validate_contract
from mojoattention.validation.agent_loop import (
    ControlBinding,
    Diagnosis,
    EvidenceBinding,
    Improvement,
    LoopEvent,
    LoopHeader,
    LoopState,
    RepairRequest,
    ValidationObservation,
    evaluate_retry,
)
from mojoattention.validation.evidence import EvidenceWriter, verify_evidence
from mojoattention.validation.fast import (
    AdapterResult,
    FastCheck,
    FastError,
    Observation,
    RunnerConfig,
    Verdict,
    evaluate_observations,
    load_manifest,
    run_bounded_argv,
)
from mojoattention.validation.protected_assets import (
    TrustedPolicyInput,
    evaluate_and_compose_trusted_context,
    evaluate_protected_changes,
    inspect_repository_changes,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
_EXPECTED_REASONS = {
    "FAST-008": "FAST-CANARY-ASSERTION",
    "FAST-009": "FAST-CANARY-WORKFLOW",
    "FAST-010": "FAST-CANARY-REPORT",
    "FAST-011": "FAST-CANARY-EVIDENCE",
    "FAST-012": "FAST-CANARY-CONTRACT",
    "FAST-013": "FAST-CANARY-PROTECTED",
    "FAST-014": "FAST-CANARY-AGENT-LOOP",
}


@dataclass(frozen=True, slots=True)
class CanaryOutcome:
    validation_id: str
    verdict: Verdict
    passed: bool
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class AssertionFixture:
    assertions_executed: int
    behavior_detected: bool


@dataclass(frozen=True, slots=True)
class WorkflowFixture:
    enabled: bool = True
    condition_result: bool = True
    continue_on_error: bool = False
    propagates_exit: bool = True
    selected: int = 1
    collected: int = 1
    completed: int = 1
    skipped: int = 0
    xfailed: int = 0
    deselected: int = 0
    placeholder: bool = False


@dataclass(frozen=True, slots=True)
class ReportFixture:
    authority_bytes: bytes
    declared_digest: str
    observed_bytes: bytes
    rendered_bytes: bytes | None = None


@dataclass(frozen=True, slots=True)
class EvidenceFixture:
    expected_ids: tuple[str, ...]
    records: tuple[Observation, ...]
    attachment: bytes
    attachment_digest: str
    shard_complete: bool
    subprocess_succeeded: bool


@dataclass(frozen=True, slots=True)
class ContractFixture:
    schema_valid: bool
    expected_ids: tuple[str, ...]
    observed_ids: tuple[str, ...]
    expected_counts: tuple[int, ...]
    observed_counts: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class AgentLoopFixture:
    semantic_failure: str | None
    retries_consumed: int
    retry_budget: int


def _outcome(
    validation_id: str,
    valid: bool,
    failure_verdict: Literal["product-fail", "contract-invalid"],
    reason_code: str,
) -> CanaryOutcome:
    if valid:
        return CanaryOutcome(validation_id, "pass", True)
    return CanaryOutcome(validation_id, failure_verdict, False, reason_code)


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def assertion_canary(fixture: AssertionFixture) -> CanaryOutcome:
    """Detect a removed assertion by requiring execution and observable behavior."""

    valid = fixture.assertions_executed == 1 and fixture.behavior_detected
    return _outcome("FAST-008", valid, "product-fail", "FAST-CANARY-ASSERTION")


def workflow_canary(fixture: WorkflowFixture) -> CanaryOutcome:
    """Reject workflow/check omission and shell-success laundering."""

    valid = (
        fixture.enabled
        and fixture.condition_result
        and not fixture.continue_on_error
        and fixture.propagates_exit
        and not fixture.placeholder
        and (
            fixture.selected,
            fixture.collected,
            fixture.completed,
            fixture.skipped,
            fixture.xfailed,
            fixture.deselected,
        )
        == (1, 1, 1, 0, 0, 0)
    )
    return _outcome("FAST-009", valid, "contract-invalid", "FAST-CANARY-WORKFLOW")


def report_canary(fixture: ReportFixture) -> CanaryOutcome:
    """Bind both stored and rendered report bytes to protected authority bytes."""

    rendered = fixture.authority_bytes if fixture.rendered_bytes is None else fixture.rendered_bytes
    valid = (
        fixture.declared_digest == _digest(fixture.authority_bytes)
        and fixture.observed_bytes == fixture.authority_bytes
        and rendered == fixture.authority_bytes
    )
    return _outcome("FAST-010", valid, "contract-invalid", "FAST-CANARY-REPORT")


def evidence_canary(fixture: EvidenceFixture) -> CanaryOutcome:
    """Require complete structured records and attachment/shard closure."""

    observed_ids = tuple(record.validation_id for record in fixture.records)
    records_complete = all(
        (
            record.selected,
            record.collected,
            record.completed,
            record.skipped,
            record.xfailed,
            record.deselected,
            record.collection_errors,
            record.shard_index,
            record.shard_total,
            record.status,
        )
        == (1, 1, 1, 0, 0, 0, 0, 0, 1, "pass")
        for record in fixture.records
    )
    valid = (
        fixture.subprocess_succeeded
        and fixture.shard_complete
        and observed_ids == fixture.expected_ids
        and len(observed_ids) == len(set(observed_ids))
        and records_complete
        and bool(fixture.attachment)
        and fixture.attachment_digest == _digest(fixture.attachment)
    )
    return _outcome("FAST-011", valid, "contract-invalid", "FAST-CANARY-EVIDENCE")


def contract_canary(fixture: ContractFixture) -> CanaryOutcome:
    """Reject schema, ID, matrix, count, and zero-inventory drift."""

    valid = (
        fixture.schema_valid
        and fixture.observed_ids == fixture.expected_ids
        and len(fixture.observed_ids) == len(set(fixture.observed_ids))
        and fixture.observed_counts == fixture.expected_counts
        and len(fixture.observed_counts) == len(fixture.observed_ids)
        and all(count == 1 for count in fixture.observed_counts)
    )
    return _outcome("FAST-012", valid, "contract-invalid", "FAST-CANARY-CONTRACT")


def agent_loop_canary(fixture: AgentLoopFixture, root: Path) -> CanaryOutcome:
    """Exercise production retry policy for semantic and retry-budget stops."""

    digest = "sha256:" + "1" * 64
    evidence = EvidenceBinding(
        "run-fast-014",
        digest,
        "1" * 40,
        "2" * 40,
        digest,
        "complete",
        True,
        "product-fail",
        ("FAST-014",),
    )
    controls = ControlBinding(
        digest,
        "1" * 40,
        "2" * 40,
        "3" * 40,
        "4" * 40,
        "implementer",
        ("src/mojoattention/validation",),
        ("schemas", "contracts"),
    )
    header = LoopHeader(
        "1.0.0",
        "loop-fast-014",
        digest,
        "1" * 40,
        "2" * 40,
        "3" * 40,
        "4" * 40,
        "implementer",
        fixture.retry_budget,
        controls.allowed_paths,
        controls.protected_paths,
        "2026-07-29T00:00:00Z",
        digest,
    )
    event = LoopEvent(
        "1.0.0",
        header.loop_id,
        2,
        digest,
        digest,
        1,
        "validation-recorded",
        "validation-failed",
        controls,
        "FAST-014",
        (evidence,),
        None,
        None,
        None,
        "validator",
        "2026-07-29T00:00:01Z",
    )
    state = LoopState(
        header,
        (event,),
        "validation-failed",
        1,
        fixture.retries_consumed,
        "FAST-014",
        evidence.run_id,
        False,
    )
    observation_before = ValidationObservation(
        "FAST-014", "agent-loop-policy-canary", digest, "fail", "failures", "decrease", 2
    )
    observation_after = ValidationObservation(
        "FAST-014", "agent-loop-policy-canary", digest, "fail", "failures", "decrease", 1
    )
    request = RepairRequest(
        Diagnosis(
            "FAST-014",
            "product-fail",
            "FAST-014",
            digest,
            evidence.evidence_digest,
            ("src/mojoattention/validation/agent_loop.py",),
            ("python", "-m", "pytest", "-q", "tests/foundation/test_agent_loop.py"),
        ),
        Improvement("FAST-014", "agent-loop-policy-canary", digest, "failures", "decrease", 2, 1),
        ("src/mojoattention/validation/agent_loop.py",),
        (observation_before,),
        (observation_after,),
        "modify",
        "agent",
        False,
        None,
        None,
        None,
        None,
        failure_kind=fixture.semantic_failure,
    )
    authority = {
        "protected_paths": ["schemas", "contracts"],
        "roles": [
            {
                "id": "implementer",
                "read_paths": ["src"],
                "write_paths": ["src/mojoattention/validation"],
                "indirect_output_paths": [],
                "can_approve_protected_changes": False,
                "can_approve_final_merge": False,
            }
        ],
    }
    semantic = evaluate_retry(replace(state, retries_consumed=0), request, authority, root)
    exhausted = evaluate_retry(state, replace(request, failure_kind=None), authority, root)
    valid = (
        semantic.allowed is False
        and semantic.stop_reason == "causality"
        and exhausted.allowed is False
        and exhausted.stop_reason == "retry-budget-exhausted"
    )
    return _outcome("FAST-014", valid, "contract-invalid", "FAST-CANARY-AGENT-LOOP")


def protected_change_canary(
    root: Path,
    trusted_base_revision: str,
    candidate_revision: str,
    trusted_policy: TrustedPolicyInput,
) -> CanaryOutcome:
    """Evaluate real Git effects without accepting fixture-authored policy outcomes."""

    inspection, acquisition_errors = inspect_repository_changes(
        root,
        trusted_base_revision,
        candidate_revision,
        trusted_policy,
    )
    if acquisition_errors or inspection is None:
        return CanaryOutcome("FAST-013", "contract-invalid", False, "FAST-CANARY-PROTECTED-ACQUIRE")
    errors = evaluate_protected_changes(
        inspection.policy,
        inspection.effects,
        inspection.identity,
        inspection.change_set_digest,
        "sha256:" + "1" * 64,
        None,
    )
    return _outcome("FAST-013", not errors, "contract-invalid", "FAST-CANARY-PROTECTED")


def _run_git(root: Path, *args: str) -> str:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    completed = subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "user.name=Fast Canary",
            "-c",
            "user.email=fast@example.invalid",
            *args,
        ],
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        raise OSError("isolated Git canary failed")
    return completed.stdout.strip()


def _protected_pair(root: Path, trusted_policy: TrustedPolicyInput) -> tuple[CanaryOutcome, CanaryOutcome]:
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fast-protected-", dir=root) as directory:
        repo = Path(directory)
        _run_git(repo, "init", "-q")
        protected = repo / "tests" / "canary.py"
        protected.parent.mkdir()
        protected.write_text("assert True\n", encoding="utf-8")
        _run_git(repo, "add", "-A")
        _run_git(repo, "commit", "-qm", "clean control")
        base = _run_git(repo, "rev-parse", "HEAD")
        protected.write_text("pass\n", encoding="utf-8")
        _run_git(repo, "add", "-A")
        _run_git(repo, "commit", "-qm", "unauthorized mutation")
        candidate = _run_git(repo, "rev-parse", "HEAD")
        return (
            protected_change_canary(repo, base, candidate, trusted_policy),
            protected_change_canary(repo, base, base, trusted_policy),
        )


def _bounded_python(source: Path) -> int | None:
    config = RunnerConfig(20, 64 * 1024, "C", ("PATH",), 0, 1)
    return run_bounded_argv((sys.executable, str(source)), source.parent, config).returncode


def _assertion_pair(root: Path) -> tuple[CanaryOutcome, CanaryOutcome]:
    with tempfile.TemporaryDirectory(prefix="fast-assertion-", dir=root) as directory:
        isolated = Path(directory)
        mutation = isolated / "mutation.py"
        control = isolated / "control.py"
        mutation.write_text("value = 1\n", encoding="utf-8")
        control.write_text("value = 1\nassert value == 2\n", encoding="utf-8")
        removed_assertion_escaped = _bounded_python(mutation) == 0
        assertion_executed = _bounded_python(control) not in (None, 0)
    return (
        _outcome("FAST-008", not removed_assertion_escaped, "product-fail", "FAST-CANARY-ASSERTION"),
        _outcome("FAST-008", assertion_executed, "product-fail", "FAST-CANARY-ASSERTION"),
    )


def _workflow_pair(root: Path) -> tuple[CanaryOutcome, CanaryOutcome]:
    with tempfile.TemporaryDirectory(prefix="fast-workflow-", dir=root) as directory:
        isolated = Path(directory)
        workflow = isolated / "quality.yml"
        clean = "permissions:\n  contents: read\nsteps:\n  - run: exit 7\n"
        mutation = clean.replace("run: exit 7", "run: exit 7 || true")

        def inspect(text: str) -> CanaryOutcome:
            workflow.write_text(text, encoding="utf-8")
            command = next(line.split("run:", 1)[1].strip() for line in text.splitlines() if "run:" in line)
            result = run_bounded_argv(
                ("/bin/bash", "-c", command),
                isolated,
                RunnerConfig(20, 64 * 1024, "C", ("PATH",), 0, 1),
            )
            valid = (
                "contents: read" in workflow.read_text(encoding="utf-8")
                and "continue-on-error" not in text
                and "|| true" not in command
                and result.returncode == 7
            )
            return _outcome("FAST-009", valid, "contract-invalid", "FAST-CANARY-WORKFLOW")

        return inspect(mutation), inspect(clean)


def _report_pair(root: Path, trusted_policy: TrustedPolicyInput) -> tuple[CanaryOutcome, CanaryOutcome]:
    revision = _run_git(PROJECT_ROOT, "rev-parse", "HEAD")
    digest = "sha256:" + "a" * 64
    bounded_context = {
        "suite_id": "fast",
        "contract_digest": digest,
        "config_digest": digest,
        "protocol_digest": digest,
        "declared_case_ids": ["report-projection"],
        "declared_validation_ids": ["FAST-010"],
        "seed": 1601,
        "producer": {"name": "mojoattention", "version": "1.0.0"},
        "environment": {"os": "linux", "architecture": "x86-64", "python_version": "3.14.4"},
    }
    context, errors = evaluate_and_compose_trusted_context(
        PROJECT_ROOT,
        revision,
        revision,
        trusted_policy,
        digest,
        bounded_context,
        None,
    )
    if context is None or errors:
        raise OSError("report canary could not acquire trusted evidence context")
    validation = {
        "validation_id": "FAST-010",
        "case_id": "report-projection",
        "status": "pass",
        "reproduction_argv": ["mojoattention", "validate", "--suite", "fast"],
        "metrics": [{"name": "cases", "value": 1, "value_type": "integer", "unit": "count"}],
        "errors": [],
        "attachments": [],
    }
    schema = (PROJECT_ROOT / "schemas" / "validation-evidence.schema.json").read_bytes()

    def produce() -> Path:
        writer = EvidenceWriter(root, context)
        return writer.finalize(verdict="pass", validations=[validation], attachments=[], schema_path=schema)

    clean = produce()
    mutated = produce()
    (mutated / "report.md").write_bytes((mutated / "report.md").read_bytes() + b"forged\n")

    def verify(path: Path) -> CanaryOutcome:
        valid = not verify_evidence(path, schema).errors
        return _outcome("FAST-010", valid, "contract-invalid", "FAST-CANARY-REPORT")

    outcomes = verify(mutated), verify(clean)
    for directory in (mutated, clean):
        for child in directory.iterdir():
            child.unlink()
        directory.rmdir()
    return outcomes


def _evidence_pair(root: Path) -> tuple[CanaryOutcome, CanaryOutcome]:
    del root
    manifest = load_manifest(
        (PROJECT_ROOT / "contracts" / "validation-suites" / "fast.json").read_bytes(),
        (PROJECT_ROOT / "schemas" / "validation-suite.schema.json").read_bytes(),
    )
    records = tuple(
        Observation(
            check.validation_id,
            check.case_id,
            check.seed,
            check.required_count,
            check.required_count,
            check.required_count,
            0,
            0,
            0,
            0,
            manifest.runner_config.shard_index,
            manifest.runner_config.shard_total,
            "pass",
        )
        for check in manifest.checks
    )

    def close(observations: tuple[Observation, ...]) -> CanaryOutcome:
        verdict, errors = evaluate_observations(manifest, observations)
        valid = verdict == "pass" and not errors
        return _outcome("FAST-011", valid, "contract-invalid", "FAST-CANARY-EVIDENCE")

    return close(records[:-1]), close(records)


def _contract_pair(root: Path) -> tuple[CanaryOutcome, CanaryOutcome]:
    del root
    contract = json.loads((PROJECT_ROOT / "contracts" / "acceptance" / "1-3.example.json").read_bytes())
    context = ContractContext(
        str(contract["source_revision"]),
        str(contract["trusted_base_revision"]),
        contract["prior_validation_identity"],
    )
    mutation = deepcopy(contract)
    validations = mutation["required_suites"][0]["validations"]
    validations[1]["validation_id"] = validations[0]["validation_id"]
    mutation = issue_contract(mutation)

    def validate(value: object) -> CanaryOutcome:
        errors = validate_contract(value, PROJECT_ROOT, context)
        valid = not errors
        return _outcome("FAST-012", valid, "contract-invalid", "FAST-CANARY-CONTRACT")

    return validate(mutation), validate(contract)


def _canary_pair(
    check: FastCheck,
    root: Path,
    trusted_policy: TrustedPolicyInput,
) -> tuple[CanaryOutcome, CanaryOutcome]:
    pairs = {
        "FAST-008": _assertion_pair,
        "FAST-009": _workflow_pair,
        "FAST-011": _evidence_pair,
        "FAST-012": _contract_pair,
    }
    if check.validation_id == "FAST-014":
        clean = AgentLoopFixture("causality", 1, 1)
        mutation = AgentLoopFixture(None, 0, 1)
        return agent_loop_canary(mutation, PROJECT_ROOT), agent_loop_canary(clean, PROJECT_ROOT)
    if check.validation_id == "FAST-013":
        return _protected_pair(root, trusted_policy)
    if check.validation_id == "FAST-010":
        return _report_pair(root, trusted_policy)
    try:
        return pairs[check.validation_id](root)
    except KeyError as error:
        raise ValueError("unknown false-green canary") from error


def execute_false_green_canary(
    check: FastCheck,
    temporary_root: Path,
    trusted_policy: TrustedPolicyInput,
) -> AdapterResult:
    """Execute a trusted mutation and its unchanged control as one Fast adapter."""

    try:
        mutation, control = _canary_pair(check, temporary_root, trusted_policy)
    except OSError, subprocess.SubprocessError, ValueError:
        return AdapterResult.failed(
            check,
            "infrastructure-invalid",
            FastError(
                "FAST-CANARY-EXEC",
                "false-green canary could not execute in isolation",
                {"validation_id": check.validation_id},
            ),
        )
    mutation_matches = (
        mutation.validation_id == check.validation_id
        and mutation.verdict == check.expected_verdict
        and not mutation.passed
        and mutation.reason_code == _EXPECTED_REASONS.get(check.validation_id)
    )
    control_matches = control.validation_id == check.validation_id and control.verdict == "pass" and control.passed
    if not mutation_matches or not control_matches:
        return AdapterResult.failed(
            check,
            "contract-invalid",
            FastError(
                "FAST-CANARY-CONTROL",
                "false-green mutation or clean control produced an unexpected structured outcome",
                {"validation_id": check.validation_id},
            ),
        )
    return AdapterResult.passed(check)

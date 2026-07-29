from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from mojoattention.validation.fast import AdapterResult, FastCheck, FastError, Observation, Verdict
from mojoattention.validation.protected_assets import (
    TrustedPolicyInput,
    evaluate_protected_changes,
    inspect_repository_changes,
)


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


def _canary_pair(
    check: FastCheck,
    root: Path,
    trusted_policy: TrustedPolicyInput,
) -> tuple[CanaryOutcome, CanaryOutcome]:
    payload = b'{"status":"pass"}\n'
    record = Observation("FAST-X", "case", check.seed, 1, 1, 1, 0, 0, 0, 0, 0, 1, "pass")
    attachment = b"bounded attachment"
    pairs: dict[str, tuple[CanaryOutcome, CanaryOutcome]] = {
        "FAST-008": (
            assertion_canary(AssertionFixture(0, False)),
            assertion_canary(AssertionFixture(1, True)),
        ),
        "FAST-009": (
            workflow_canary(WorkflowFixture(continue_on_error=True, propagates_exit=False)),
            workflow_canary(WorkflowFixture()),
        ),
        "FAST-010": (
            report_canary(ReportFixture(payload, _digest(payload), b'{"status":"fail"}\n')),
            report_canary(ReportFixture(payload, _digest(payload), payload)),
        ),
        "FAST-011": (
            evidence_canary(EvidenceFixture(("FAST-X",), (), attachment, _digest(attachment), False, True)),
            evidence_canary(EvidenceFixture(("FAST-X",), (record,), attachment, _digest(attachment), True, True)),
        ),
        "FAST-012": (
            contract_canary(ContractFixture(True, ("FAST-A",), ("FAST-UNKNOWN",), (1,), (1,))),
            contract_canary(ContractFixture(True, ("FAST-A",), ("FAST-A",), (1,), (1,))),
        ),
    }
    if check.validation_id == "FAST-013":
        return _protected_pair(root, trusted_policy)
    try:
        return pairs[check.validation_id]
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

from __future__ import annotations

import copy
import json
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from mojoattention.validation.agent_loop import (
    HUMAN_ESCALATION_FAILURES,
    SEMANTIC_STOP_FAILURES,
    AgentLoopContractError,
    AgentLoopError,
    Diagnosis,
    Improvement,
    LoopEvent,
    LoopHeader,
    LoopState,
    RepairRequest,
    ValidationObservation,
    classify_stop_reason,
    derive_journal_state,
    digest_record,
    evaluate_retry,
    replay_journal,
    seal_event,
    seal_header,
    validate_agent_loop_record,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "agent-loop-state.schema.json"
DIGEST = "sha256:" + ("a" * 64)
REVISION = "a" * 40


def header() -> dict[str, Any]:
    return seal_header(
        {
            "record_type": "header",
            "schema_version": "1.0.0",
            "loop_id": "1" * 32,
            "contract_digest": DIGEST,
            "source_revision": REVISION,
            "source_tree": "b" * 40,
            "trusted_base_revision": "c" * 40,
            "trusted_base_tree": "d" * 40,
            "assigned_role": "implementation-agent",
            "retry_budget": 5,
            "allowed_paths": ["src/mojoattention/validation/agent_loop.py"],
            "protected_paths": ["schemas/agent-loop-state.schema.json"],
            "created_at": "2026-07-29T12:00:00Z",
        }
    )


def event(
    immutable: dict[str, Any],
    *,
    sequence: int,
    attempt: int,
    transition: str,
    status: str,
    prior: str,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "record_type": "event",
        "schema_version": "1.0.0",
        "loop_id": immutable["loop_id"],
        "sequence": sequence,
        "prior_event_digest": prior,
        "attempt": attempt,
        "control_binding": {
            "contract_digest": immutable["contract_digest"],
            "source_revision": immutable["source_revision"],
            "source_tree": immutable["source_tree"],
            "trusted_base_revision": immutable["trusted_base_revision"],
            "trusted_base_tree": immutable["trusted_base_tree"],
            "assigned_role": immutable["assigned_role"],
            "allowed_paths": immutable["allowed_paths"],
            "protected_paths": immutable["protected_paths"],
        },
        "transition": transition,
        "status": status,
        "validation_binding": None,
        "evidence_bindings": [],
        "diagnosis": None,
        "improvement_proof": None,
        "stop_reason": None,
        "actor_kind": "system",
        "timestamp": f"2026-07-29T12:00:0{sequence}Z",
    }
    if transition in {"validation-recorded", "awaiting-human-review"}:
        validation_status = "pass" if transition == "awaiting-human-review" else "fail"
        record["validation_binding"] = {
            "validation_id": "FAST-014",
            "status": validation_status,
            "errors": [] if validation_status == "pass" else [{"code": "LOOP-101", "message": "failed", "context": {}}],
        }
        record["evidence_bindings"] = [
            {
                "run_id": "2" * 32,
                "evidence_digest": "sha256:" + f"{sequence:064x}",
                "source_revision": immutable["source_revision"],
                "source_tree": immutable["source_tree"],
                "contract_digest": immutable["contract_digest"],
                "lifecycle": "complete",
                "independently_verified": True,
                "verdict": "pass" if validation_status == "pass" else "product-fail",
                "validation_ids": ["FAST-014"],
            }
        ]
    return seal_event(record)


def test_schema_is_strict_draft_2020_12_and_accepts_sealed_records() -> None:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    immutable = header()
    genesis = event(
        immutable,
        sequence=1,
        attempt=1,
        transition="initialized",
        status="awaiting-validation",
        prior=immutable["header_digest"],
    )
    assert validate_agent_loop_record(immutable, SCHEMA) == ()
    assert validate_agent_loop_record(genesis, SCHEMA) == ()
    for record in (immutable, genesis):
        tampered = copy.deepcopy(record)
        tampered["unknown"] = True
        assert validate_agent_loop_record(tampered, SCHEMA)[0].code == "LOOP-001"


def test_digest_excludes_only_own_digest_and_is_canonical() -> None:
    immutable = header()
    assert immutable["header_digest"] == digest_record(immutable, "header_digest")
    reordered = dict(reversed(list(immutable.items())))
    assert digest_record(reordered, "header_digest") == immutable["header_digest"]
    changed = copy.deepcopy(immutable)
    changed["retry_budget"] = 4
    assert digest_record(changed, "header_digest") != immutable["header_digest"]


def test_full_ordered_replay_derives_state_and_retry_consumption() -> None:
    immutable = header()
    first = event(
        immutable,
        sequence=1,
        attempt=1,
        transition="initialized",
        status="awaiting-validation",
        prior=immutable["header_digest"],
    )
    validation = event(
        immutable,
        sequence=2,
        attempt=1,
        transition="validation-recorded",
        status="validation-failed",
        prior=first["event_digest"],
    )
    retry = event(
        immutable,
        sequence=3,
        attempt=2,
        transition="retry-authorized",
        status="retry-authorized",
        prior=validation["event_digest"],
    )
    state = derive_journal_state(immutable, [first, validation, retry], SCHEMA)
    assert state == {
        "status": "retry-authorized",
        "attempt": 2,
        "retries_consumed": 1,
        "last_validation": validation,
    }


@pytest.mark.parametrize("retry_budget", range(6))
def test_retry_budget_is_bounded_zero_through_five(retry_budget: int) -> None:
    immutable = header()
    immutable["retry_budget"] = retry_budget
    immutable = seal_header({key: value for key, value in immutable.items() if key != "header_digest"})
    assert validate_agent_loop_record(immutable, SCHEMA) == ()


def test_replay_rejects_attempt_six_and_broken_order_or_chain() -> None:
    immutable = header()
    first = event(
        immutable,
        sequence=1,
        attempt=1,
        transition="initialized",
        status="awaiting-validation",
        prior=immutable["header_digest"],
    )
    sixth = event(
        immutable,
        sequence=2,
        attempt=6,
        transition="retry-authorized",
        status="awaiting-validation",
        prior=first["event_digest"],
    )
    with pytest.raises(AgentLoopContractError, match="LOOP-001"):
        derive_journal_state(immutable, [first, sixth], SCHEMA)
    reordered = copy.deepcopy(first)
    reordered["sequence"] = 2
    reordered = seal_event({key: value for key, value in reordered.items() if key != "event_digest"})
    with pytest.raises(AgentLoopContractError, match="LOOP-004"):
        derive_journal_state(immutable, [reordered], SCHEMA)
    broken = copy.deepcopy(first)
    broken["prior_event_digest"] = DIGEST
    broken = seal_event({key: value for key, value in broken.items() if key != "event_digest"})
    with pytest.raises(AgentLoopContractError, match="LOOP-005"):
        derive_journal_state(immutable, [broken], SCHEMA)


def test_replay_rejects_tampered_event_digest_and_cross_loop_event() -> None:
    immutable = header()
    first = event(
        immutable,
        sequence=1,
        attempt=1,
        transition="initialized",
        status="awaiting-validation",
        prior=immutable["header_digest"],
    )
    tampered = copy.deepcopy(first)
    tampered["actor_kind"] = "agent"
    with pytest.raises(AgentLoopContractError, match="LOOP-003"):
        derive_journal_state(immutable, [tampered], SCHEMA)
    foreign = copy.deepcopy(first)
    foreign["loop_id"] = "2" * 32
    foreign = seal_event({key: value for key, value in foreign.items() if key != "event_digest"})
    with pytest.raises(AgentLoopContractError, match="LOOP-006"):
        derive_journal_state(immutable, [foreign], SCHEMA)


def test_nested_error_metric_and_path_objects_reject_unknown_fields() -> None:
    immutable = header()
    first = event(
        immutable,
        sequence=1,
        attempt=1,
        transition="validation-recorded",
        status="validation-failed",
        prior=immutable["header_digest"],
    )
    first["validation_binding"] = {
        "validation_id": "FAST-014",
        "status": "fail",
        "errors": [{"code": "LOOP-101", "message": "failed", "context": {}}],
    }
    first["diagnosis"] = {
        "validation_id": "FAST-014",
        "verdict": "product-fail",
        "error_code": "LOOP-101",
        "failure_signature": DIGEST,
        "evidence_digest": DIGEST,
        "affected_paths": ["src/mojoattention/validation/agent_loop.py"],
        "reproduction_argv": ["python", "-m", "pytest"],
    }
    first["improvement_proof"] = {
        "validation_id": "FAST-014",
        "case_id": "loop-chain",
        "config_digest": DIGEST,
        "metric": {"name": "failures", "direction": "decrease", "before": 2, "after": 1},
    }
    first = seal_event({key: value for key, value in first.items() if key != "event_digest"})
    assert validate_agent_loop_record(first, SCHEMA) == ()
    for path in ("validation_binding", "diagnosis", "improvement_proof"):
        invalid = copy.deepcopy(first)
        invalid[path]["unknown"] = 1
        invalid = seal_event({key: value for key, value in invalid.items() if key != "event_digest"})
        assert validate_agent_loop_record(invalid, SCHEMA)[0].code == "LOOP-001"


def test_public_loop_types_are_frozen_and_replay_is_typed() -> None:
    immutable = header()
    first = event(
        immutable,
        sequence=1,
        attempt=1,
        transition="initialized",
        status="awaiting-validation",
        prior=immutable["header_digest"],
    )
    validation = event(
        immutable,
        sequence=2,
        attempt=1,
        transition="validation-recorded",
        status="validation-failed",
        prior=first["event_digest"],
    )
    validation["diagnosis"] = {
        "validation_id": "FAST-014",
        "verdict": "product-fail",
        "error_code": "LOOP-101",
        "failure_signature": DIGEST,
        "evidence_digest": validation["evidence_bindings"][0]["evidence_digest"],
        "affected_paths": ["src/mojoattention/validation/agent_loop.py"],
        "reproduction_argv": ["python", "-m", "pytest"],
    }
    validation["improvement_proof"] = {
        "validation_id": "FAST-014",
        "case_id": "loop-chain",
        "config_digest": DIGEST,
        "metric": {"name": "failures", "direction": "decrease", "before": 2, "after": 1},
    }
    validation = seal_event({key: value for key, value in validation.items() if key != "event_digest"})
    state = replay_journal(immutable, [first, validation], SCHEMA)
    assert isinstance(state, LoopState)
    assert isinstance(state.header, LoopHeader)
    assert isinstance(state.events[0], LoopEvent)
    assert isinstance(state.events[1].diagnosis, Diagnosis)
    assert isinstance(state.events[1].improvement, Improvement)
    assert isinstance(state.errors, tuple)
    with pytest.raises(FrozenInstanceError):
        state.attempt = 2  # type: ignore[misc]


def test_closed_transition_table_rejects_illegal_and_post_terminal_events() -> None:
    immutable = header()
    first = event(
        immutable,
        sequence=1,
        attempt=1,
        transition="initialized",
        status="awaiting-validation",
        prior=immutable["header_digest"],
    )
    illegal = event(
        immutable,
        sequence=2,
        attempt=1,
        transition="retry-authorized",
        status="retry-authorized",
        prior=first["event_digest"],
    )
    with pytest.raises(AgentLoopContractError, match="LOOP-010"):
        replay_journal(immutable, [first, illegal], SCHEMA)
    terminal = event(
        immutable,
        sequence=2,
        attempt=1,
        transition="awaiting-human-review",
        status="awaiting-human-review",
        prior=first["event_digest"],
    )
    after = event(
        immutable,
        sequence=3,
        attempt=1,
        transition="stopped",
        status="stopped",
        prior=terminal["event_digest"],
    )
    with pytest.raises(AgentLoopContractError, match="LOOP-011"):
        replay_journal(immutable, [first, terminal, after], SCHEMA)


def test_every_event_must_bind_immutable_controls_exactly() -> None:
    immutable = header()
    first = event(
        immutable,
        sequence=1,
        attempt=1,
        transition="initialized",
        status="awaiting-validation",
        prior=immutable["header_digest"],
    )
    for field, replacement in (
        ("contract_digest", "sha256:" + "b" * 64),
        ("source_tree", "e" * 40),
        ("trusted_base_tree", "f" * 40),
        ("assigned_role", "other-agent"),
        ("allowed_paths", ["other"]),
        ("protected_paths", []),
    ):
        mismatched = copy.deepcopy(first)
        mismatched["control_binding"][field] = replacement
        mismatched = seal_event({key: value for key, value in mismatched.items() if key != "event_digest"})
        with pytest.raises(AgentLoopContractError, match="LOOP-012"):
            replay_journal(immutable, [mismatched], SCHEMA)


def test_validation_evidence_must_be_complete_verified_unique_and_consistent() -> None:
    immutable = header()
    first = event(
        immutable,
        sequence=1,
        attempt=1,
        transition="initialized",
        status="awaiting-validation",
        prior=immutable["header_digest"],
    )
    validation = event(
        immutable,
        sequence=2,
        attempt=1,
        transition="validation-recorded",
        status="validation-failed",
        prior=first["event_digest"],
    )
    binding = {
        "run_id": "2" * 32,
        "evidence_digest": DIGEST,
        "source_revision": immutable["source_revision"],
        "source_tree": immutable["source_tree"],
        "contract_digest": immutable["contract_digest"],
        "lifecycle": "complete",
        "independently_verified": True,
        "verdict": "product-fail",
        "validation_ids": ["FAST-014"],
    }
    validation["evidence_bindings"] = [binding]
    validation["validation_binding"] = {
        "validation_id": "FAST-014",
        "status": "fail",
        "errors": [{"code": "LOOP-101", "message": "failed", "context": {}}],
    }
    validation = seal_event({key: value for key, value in validation.items() if key != "event_digest"})
    assert replay_journal(immutable, [first, validation], SCHEMA).last_validation == validation["event_digest"]
    for field, value in (
        ("lifecycle", "staging"),
        ("independently_verified", False),
        ("source_tree", "e" * 40),
        ("contract_digest", "sha256:" + "b" * 64),
    ):
        bad = copy.deepcopy(validation)
        bad["evidence_bindings"][0][field] = value
        bad = seal_event({key: value for key, value in bad.items() if key != "event_digest"})
        with pytest.raises(AgentLoopContractError, match="LOOP-001|LOOP-013"):
            replay_journal(immutable, [first, bad], SCHEMA)
    duplicate = copy.deepcopy(validation)
    duplicate["evidence_bindings"].append(copy.deepcopy(binding))
    duplicate = seal_event({key: value for key, value in duplicate.items() if key != "event_digest"})
    with pytest.raises(AgentLoopContractError, match="LOOP-001|LOOP-013"):
        replay_journal(immutable, [first, duplicate], SCHEMA)


@pytest.mark.parametrize("failure, expected", tuple(SEMANTIC_STOP_FAILURES.items()))
def test_semantic_stops_are_lossless_exact_mappings(failure: str, expected: str) -> None:
    assert classify_stop_reason(failure) == expected


@pytest.mark.parametrize("failure", HUMAN_ESCALATION_FAILURES)
def test_human_escalation_failures_are_exact_mappings(failure: str) -> None:
    assert classify_stop_reason(failure) == "human-escalation"


def test_stop_classification_never_uses_free_text_or_substrings() -> None:
    assert classify_stop_reason("causality happened") is None
    assert classify_stop_reason("prefix-validation-weakening") is None
    assert classify_stop_reason("unknown") is None
    assert AgentLoopError("LOOP-999", "x", {}).code == "LOOP-999"


def test_typed_stop_requires_exact_reason_and_is_terminal() -> None:
    immutable = header()
    first = event(
        immutable,
        sequence=1,
        attempt=1,
        transition="initialized",
        status="awaiting-validation",
        prior=immutable["header_digest"],
    )
    stopped = event(
        immutable,
        sequence=2,
        attempt=1,
        transition="stopped",
        status="stopped",
        prior=first["event_digest"],
    )
    stopped["stop_reason"] = "protected-conflict"
    stopped = seal_event({key: value for key, value in stopped.items() if key != "event_digest"})
    state = replay_journal(immutable, [first, stopped], SCHEMA)
    assert state.terminal is True
    assert state.events[-1].stop_reason == "protected-conflict"


def retry_state(verdict: str = "product-fail") -> LoopState:
    immutable = header()
    first = event(
        immutable,
        sequence=1,
        attempt=1,
        transition="initialized",
        status="awaiting-validation",
        prior=immutable["header_digest"],
    )
    failed = event(
        immutable,
        sequence=2,
        attempt=1,
        transition="validation-recorded",
        status="validation-failed",
        prior=first["event_digest"],
    )
    if verdict != "product-fail":
        failed["evidence_bindings"][0]["verdict"] = verdict
        failed["validation_binding"]["status"] = "invalid"
        failed = seal_event({key: value for key, value in failed.items() if key != "event_digest"})
    return replay_journal(immutable, [first, failed], SCHEMA)


def repair_request(**changes: object) -> RepairRequest:
    state = retry_state()
    evidence = state.events[-1].evidence_bindings[0]
    values: dict[str, object] = {
        "diagnosis": Diagnosis(
            "FAST-014",
            "product-fail",
            "LOOP-101",
            DIGEST,
            evidence.evidence_digest,
            ("src/mojoattention/validation/agent_loop.py",),
            ("python", "-m", "pytest", "-q", "tests/foundation/test_agent_loop.py"),
        ),
        "improvement": Improvement(
            "FAST-014",
            "loop-chain",
            DIGEST,
            "failures",
            "decrease",
            2,
            1,
        ),
        "repair_paths": ("src/mojoattention/validation/agent_loop.py",),
        "previous_observations": (
            ValidationObservation("FAST-014", "loop-chain", DIGEST, "fail", "failures", "decrease", 2),
        ),
        "current_observations": (
            ValidationObservation("FAST-014", "loop-chain", DIGEST, "fail", "failures", "decrease", 1),
        ),
        "operation": "modify",
        "actor_kind": "agent",
        "requests_approval": False,
        "infrastructure_identity_before": None,
        "infrastructure_identity_after": None,
        "semantic_state_before": None,
        "semantic_state_after": None,
    }
    values.update(changes)
    return RepairRequest(**values)  # type: ignore[arg-type]


def authority_manifest() -> dict[str, Any]:
    return {
        "protected_paths": ["schemas", "contracts", ".github", "uv.lock"],
        "roles": [
            {
                "id": "implementation-agent",
                "read_paths": [""],
                "write_paths": ["src/mojoattention/validation"],
                "indirect_output_paths": ["reports"],
                "can_approve_protected_changes": False,
                "can_approve_final_merge": False,
            }
        ],
    }


def test_retry_is_allowed_only_for_same_identity_strict_metric_improvement(tmp_path: Path) -> None:
    decision = evaluate_retry(retry_state(), repair_request(), authority_manifest(), tmp_path)
    assert decision.allowed is True
    assert decision.stop_reason is None


@pytest.mark.parametrize(
    "request_change",
    [
        {"repair_paths": ("other/file.py",)},
        {"repair_paths": ("schemas/agent-loop-state.schema.json",)},
        {"repair_paths": ("reports/generated.json",)},
        {"requests_approval": True},
    ],
)
def test_scope_authority_protected_indirect_and_self_approval_stop(
    tmp_path: Path, request_change: dict[str, object]
) -> None:
    decision = evaluate_retry(retry_state(), repair_request(**request_change), authority_manifest(), tmp_path)
    assert decision.allowed is False
    assert decision.stop_reason in {"scope-expansion", "protected-conflict"}


@pytest.mark.parametrize(
    "improvement",
    [
        Improvement("OTHER-014", "loop-chain", DIGEST, "failures", "decrease", 2, 1),
        Improvement("FAST-014", "other-case", DIGEST, "failures", "decrease", 2, 1),
        Improvement("FAST-014", "loop-chain", "sha256:" + "b" * 64, "failures", "decrease", 2, 1),
        Improvement("FAST-014", "loop-chain", DIGEST, "failures", "decrease", 2, 2),
        Improvement("FAST-014", "loop-chain", DIGEST, "failures", "decrease", 2, 3),
    ],
)
def test_incomparable_equal_or_worse_metric_is_non_improving(improvement: Improvement, tmp_path: Path) -> None:
    decision = evaluate_retry(retry_state(), repair_request(improvement=improvement), authority_manifest(), tmp_path)
    assert decision.allowed is False
    assert decision.stop_reason == "non-improving-retry"


def test_new_required_failure_and_repeated_signature_are_non_improving(tmp_path: Path) -> None:
    regressed = repair_request(
        current_observations=(
            ValidationObservation("FAST-014", "loop-chain", DIGEST, "fail", "failures", "decrease", 1),
            ValidationObservation("FAST-015", "control", DIGEST, "fail", None, None, None),
        )
    )
    assert evaluate_retry(retry_state(), regressed, authority_manifest(), tmp_path).stop_reason == "non-improving-retry"
    state = retry_state()
    previous = state.events[-1]
    assert previous.validation_id == "FAST-014"
    repeated = repair_request(previous_failure_signatures=(DIGEST,))
    assert evaluate_retry(state, repeated, authority_manifest(), tmp_path).stop_reason == "non-improving-retry"


def test_infrastructure_retry_requires_changed_identity_and_unchanged_semantics(tmp_path: Path) -> None:
    diagnosis = repair_request().diagnosis
    infrastructure = Diagnosis(
        diagnosis.validation_id,
        "infrastructure-invalid",
        diagnosis.error_code,
        diagnosis.failure_signature,
        diagnosis.evidence_digest,
        diagnosis.affected_paths,
        diagnosis.reproduction_argv,
    )
    allowed = repair_request(
        diagnosis=infrastructure,
        infrastructure_identity_before=DIGEST,
        infrastructure_identity_after="sha256:" + "b" * 64,
        semantic_state_before="sha256:" + "c" * 64,
        semantic_state_after="sha256:" + "c" * 64,
    )
    allowed_decision = evaluate_retry(retry_state("infrastructure-invalid"), allowed, authority_manifest(), tmp_path)
    assert allowed_decision.allowed is True
    unchanged = repair_request(
        diagnosis=infrastructure,
        infrastructure_identity_before=DIGEST,
        infrastructure_identity_after=DIGEST,
        semantic_state_before="sha256:" + "c" * 64,
        semantic_state_after="sha256:" + "c" * 64,
    )
    assert (
        evaluate_retry(retry_state("infrastructure-invalid"), unchanged, authority_manifest(), tmp_path).stop_reason
        == "human-escalation"
    )


def test_contract_invalid_terminal_and_exhausted_states_refuse_before_append(tmp_path: Path) -> None:
    contract_invalid = repair_request(
        diagnosis=Diagnosis(
            "FAST-014",
            "contract-invalid",
            "LOOP-101",
            DIGEST,
            retry_state().events[-1].evidence_bindings[0].evidence_digest,
            ("src/mojoattention/validation/agent_loop.py",),
            ("python", "-m", "pytest"),
        )
    )
    contract_decision = evaluate_retry(retry_state(), contract_invalid, authority_manifest(), tmp_path)
    assert contract_decision.stop_reason == "human-escalation"
    exhausted = retry_state()
    exhausted = LoopState(
        exhausted.header,
        exhausted.events,
        exhausted.status,
        exhausted.attempt,
        exhausted.header.retry_budget,
        exhausted.last_validation,
        exhausted.evidence_run_id,
        exhausted.terminal,
        exhausted.errors,
    )
    exhausted_decision = evaluate_retry(exhausted, repair_request(), authority_manifest(), tmp_path)
    assert exhausted_decision.stop_reason == "retry-budget-exhausted"


def test_required_failure_to_pass_is_improvement_only_without_regression(tmp_path: Path) -> None:
    resolved = repair_request(
        improvement=Improvement("FAST-014", "loop-chain", DIGEST, "unused", "decrease", 0, 0),
        current_observations=(ValidationObservation("FAST-014", "loop-chain", DIGEST, "pass", None, None, None),),
    )
    assert evaluate_retry(retry_state(), resolved, authority_manifest(), tmp_path).allowed is True
    regressed = repair_request(
        improvement=Improvement("FAST-014", "loop-chain", DIGEST, "unused", "decrease", 0, 0),
        previous_observations=(
            ValidationObservation("FAST-014", "loop-chain", DIGEST, "fail", None, None, None),
            ValidationObservation("FAST-015", "control", DIGEST, "pass", None, None, None),
        ),
        current_observations=(
            ValidationObservation("FAST-014", "loop-chain", DIGEST, "pass", None, None, None),
            ValidationObservation("FAST-015", "control", DIGEST, "fail", None, None, None),
        ),
    )
    assert evaluate_retry(retry_state(), regressed, authority_manifest(), tmp_path).stop_reason == "non-improving-retry"


@pytest.mark.parametrize(
    "failure",
    [
        "causality",
        "nonfinite",
        "unsupported-input",
        "unexpected-fallback",
        "missing-routing",
        "nondeterminism",
        "scope-expansion",
        "protected-conflict",
        "validation-weakening",
    ],
)
def test_mandatory_semantic_failure_refuses_retry_before_authorization(failure: str, tmp_path: Path) -> None:
    decision = evaluate_retry(
        retry_state(),
        repair_request(failure_kind=failure),
        authority_manifest(),
        tmp_path,
    )
    assert decision.allowed is False
    assert decision.stop_reason == failure


def test_symlink_alias_and_generate_indirect_output_are_never_repair_authority(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "mojoattention").mkdir()
    (tmp_path / "src" / "mojoattention" / "validation").symlink_to(tmp_path / "outside")
    alias = repair_request(
        diagnosis=Diagnosis(
            "FAST-014",
            "product-fail",
            "LOOP-101",
            DIGEST,
            retry_state().events[-1].evidence_bindings[0].evidence_digest,
            ("src/mojoattention/validation/agent_loop.py",),
            ("python", "-m", "pytest"),
        )
    )
    assert evaluate_retry(retry_state(), alias, authority_manifest(), tmp_path).stop_reason == "scope-expansion"
    generated = repair_request(
        diagnosis=Diagnosis(
            "FAST-014",
            "product-fail",
            "LOOP-101",
            DIGEST,
            retry_state().events[-1].evidence_bindings[0].evidence_digest,
            ("reports/output.json",),
            ("python", "-m", "pytest"),
        ),
        repair_paths=("reports/output.json",),
        operation="generate",
    )
    assert evaluate_retry(retry_state(), generated, authority_manifest(), tmp_path).stop_reason == "scope-expansion"

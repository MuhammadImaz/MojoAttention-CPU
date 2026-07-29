from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

import mojoattention.validation.agent_loop as agent_loop
from mojoattention.validation.agent_loop import (
    AgentLoopContractError,
    AuthenticatedLoopControls,
    ControlAcquisitionRequest,
    LoopHeader,
    LoopState,
    admit_completed_evidence,
    authenticate_loop_controls,
)
from mojoattention.validation.evidence import EvidenceError, Verification
from mojoattention.validation.identity import require_clean_candidate

DIGEST = "sha256:" + "a" * 64


class TrustedContext:
    def evidence_context(self) -> dict[str, Any]:
        return {
            "candidate_revision": "a" * 40,
            "candidate_tree": "b" * 40,
            "trusted_base_revision": "c" * 40,
            "trusted_base_tree": "d" * 40,
            "contract_digest": DIGEST,
        }


def request() -> ControlAcquisitionRequest:
    return ControlAcquisitionRequest(
        contract={
            "contract_digest": DIGEST,
            "source_revision": "a" * 40,
            "trusted_base_revision": "c" * 40,
            "prior_validation_identity": None,
            "allowed_paths": ["src"],
            "protected_paths": ["schemas"],
            "retry_budget": 2,
            "config_digest": "sha256:" + "e" * 64,
            "protocol_digest": "sha256:" + "f" * 64,
            "required_suites": [{"suite_id": "fast", "validations": [{"validation_id": "FAST-014"}]}],
        },
        contract_schema=b"{}",
        contract_context=object(),
        authority_manifest={"roles": [{"id": "implementation-agent"}]},
        authority_schema=b"{}",
        evidence_schema=b"{}",
        assigned_role="implementation-agent",
        trusted_base_revision="c" * 40,
        candidate_revision="a" * 40,
        trusted_policy=object(),
        authorization=object(),
        bounded_context={},
        control_source_kind="protected-caller",
    )


def patch_valid_controls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    checks: list[str] = []

    def clean(_root: Path, revision: str) -> dict[str, str]:
        checks.append(revision)
        return {"candidate_revision": revision, "candidate_tree": "b" * 40}

    monkeypatch.setattr(agent_loop, "require_clean_candidate", clean)
    monkeypatch.setattr(agent_loop, "validate_contract", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(agent_loop, "validate_manifest", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(
        agent_loop,
        "evaluate_and_compose_trusted_context",
        lambda *_args, **_kwargs: (TrustedContext(), ()),
    )
    return checks


def test_authenticated_controls_compose_existing_validators_and_recheck_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checks = patch_valid_controls(monkeypatch)
    controls = authenticate_loop_controls(tmp_path, request())
    assert checks == ["a" * 40, "a" * 40]
    assert controls.assigned_role == "implementation-agent"
    assert controls.source_tree == "b" * 40
    assert controls.expected_validation_ids == ("FAST-014",)


@pytest.mark.parametrize("source_kind", ["candidate-worktree", "private-agent-state", "prose"])
def test_candidate_local_or_private_state_cannot_establish_trust(
    source_kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_valid_controls(monkeypatch)
    invalid = request()
    invalid = ControlAcquisitionRequest(
        **{**invalid.__dict__, "control_source_kind": source_kind}  # type: ignore[arg-type]
    )
    with pytest.raises(AgentLoopContractError, match="LOOP-401"):
        authenticate_loop_controls(tmp_path, invalid)


def test_contract_authority_or_protected_evaluation_failure_denies_controls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_valid_controls(monkeypatch)
    monkeypatch.setattr(agent_loop, "validate_contract", lambda *_args, **_kwargs: (object(),))
    with pytest.raises(AgentLoopContractError, match="LOOP-402"):
        authenticate_loop_controls(tmp_path, request())
    patch_valid_controls(monkeypatch)
    monkeypatch.setattr(agent_loop, "validate_manifest", lambda *_args, **_kwargs: (object(),))
    with pytest.raises(AgentLoopContractError, match="LOOP-403"):
        authenticate_loop_controls(tmp_path, request())
    patch_valid_controls(monkeypatch)
    monkeypatch.setattr(
        agent_loop,
        "evaluate_and_compose_trusted_context",
        lambda *_args, **_kwargs: (None, (object(),)),
    )
    with pytest.raises(AgentLoopContractError, match="LOOP-404"):
        authenticate_loop_controls(tmp_path, request())


def controls() -> AuthenticatedLoopControls:
    return AuthenticatedLoopControls(
        contract_digest=DIGEST,
        source_revision="a" * 40,
        source_tree="b" * 40,
        trusted_base_revision="c" * 40,
        trusted_base_tree="d" * 40,
        assigned_role="implementation-agent",
        allowed_paths=("src",),
        protected_paths=("schemas",),
        retry_budget=2,
        suite_id="fast",
        config_digest="sha256:" + "e" * 64,
        protocol_digest="sha256:" + "f" * 64,
        expected_validation_ids=("FAST-014",),
        evidence_schema=b"{}",
    )


def state() -> LoopState:
    control = controls()
    header = LoopHeader(
        "1.0.0",
        "1" * 32,
        control.contract_digest,
        control.source_revision,
        control.source_tree,
        control.trusted_base_revision,
        control.trusted_base_tree,
        control.assigned_role,
        control.retry_budget,
        control.allowed_paths,
        control.protected_paths,
        "2026-07-29T12:00:00Z",
        DIGEST,
    )
    return LoopState(header, (), "awaiting-validation", 1, 0, None, None, False)


def evidence_manifest(**changes: object) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "run_id": "2" * 32,
        "evidence_digest": DIGEST,
        "lifecycle": "complete",
        "source_revision": "a" * 40,
        "source_tree": "b" * 40,
        "candidate_revision": "a" * 40,
        "candidate_tree": "b" * 40,
        "trusted_base_revision": "c" * 40,
        "trusted_base_tree": "d" * 40,
        "contract_digest": DIGEST,
        "suite_id": "fast",
        "config_digest": "sha256:" + "e" * 64,
        "protocol_digest": "sha256:" + "f" * 64,
        "verdict": "pass",
        "declared_validation_ids": ["FAST-014"],
    }
    manifest.update(changes)
    return manifest


def patch_clean_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        agent_loop,
        "require_clean_candidate",
        lambda *_args: {"candidate_revision": "a" * 40, "candidate_tree": "b" * 40},
    )


def test_only_independently_verified_complete_same_identity_evidence_is_admitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_clean_candidate(monkeypatch)
    monkeypatch.setattr(
        agent_loop,
        "verify_evidence",
        lambda *_args, **_kwargs: Verification(evidence_manifest(), ()),
    )
    binding = admit_completed_evidence(tmp_path, state(), controls(), tmp_path / ("2" * 32 + ".complete"))
    assert binding.run_id == "2" * 32
    assert binding.independently_verified is True
    assert binding.validation_ids == ("FAST-014",)


@pytest.mark.parametrize(
    "changes",
    [
        {"source_tree": "9" * 40},
        {"contract_digest": "sha256:" + "9" * 64},
        {"suite_id": "other"},
        {"config_digest": "sha256:" + "9" * 64},
        {"protocol_digest": "sha256:" + "9" * 64},
        {"declared_validation_ids": ["FAST-999"]},
    ],
)
def test_stale_mixed_or_drifted_evidence_is_rejected(
    changes: dict[str, object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_clean_candidate(monkeypatch)
    monkeypatch.setattr(
        agent_loop,
        "verify_evidence",
        lambda *_args, **_kwargs: Verification(evidence_manifest(**changes), ()),
    )
    with pytest.raises(AgentLoopContractError, match="LOOP-406"):
        admit_completed_evidence(tmp_path, state(), controls(), tmp_path / ("2" * 32 + ".complete"))


def test_staging_invalid_and_unverified_external_observations_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_clean_candidate(monkeypatch)
    monkeypatch.setattr(
        agent_loop,
        "verify_evidence",
        lambda *_args, **_kwargs: Verification(None, (EvidenceError("EVID-002", "not complete", {}),)),
    )
    with pytest.raises(AgentLoopContractError, match="LOOP-405"):
        admit_completed_evidence(tmp_path, state(), controls(), tmp_path / ("2" * 32 + ".staging"))


def test_public_clean_candidate_check_rejects_tracked_dirt_and_ignores_untracked(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("sealed\n")
    subprocess.run(["git", "add", "tracked.txt"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "sealed"], cwd=tmp_path, check=True)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, check=True, capture_output=True, text=True
    ).stdout.strip()
    (tmp_path / "untracked.txt").write_text("private\n")
    assert require_clean_candidate(tmp_path, revision)["candidate_revision"] == revision
    tracked.write_text("dirty\n")
    with pytest.raises(ValueError, match="tracked cleanliness"):
        require_clean_candidate(tmp_path, revision)

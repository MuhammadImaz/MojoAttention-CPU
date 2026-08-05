from __future__ import annotations

import argparse
import json
import platform
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]

from mojoattention.validation.evidence import (
    EvidenceError,
    EvidenceWriter,
    Verification,
    canonical_bytes,
    digest_bytes,
    verify_evidence,
)
from mojoattention.validation.protected_assets import (
    AuthorizationContext,
    TrustedPolicyInput,
    evaluate_and_compose_trusted_context,
    git_blob_oid,
    load_trusted_authorization,
)

SHA = re.compile(r"^[0-9a-f]{40}$")
ID = re.compile(r"^[a-z0-9]+(?:[-.][a-z0-9]+)*$")
WORKFLOW = re.compile(r"^\.github/workflows/[a-z0-9][a-z0-9-]*\.ya?ml$")


@dataclass(frozen=True, slots=True)
class CiRunIdentity:
    github_run_id: int
    github_run_attempt: int
    workflow_identity: str
    workflow_revision: str
    job_name: str
    check_name: str
    head_sha: str
    base_sha: str
    trusted_validator_revision: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.github_run_id, bool)
            or self.github_run_id < 1
            or isinstance(self.github_run_attempt, bool)
            or self.github_run_attempt < 1
            or not WORKFLOW.fullmatch(self.workflow_identity)
            or not ID.fullmatch(self.job_name)
            or not ID.fullmatch(self.check_name)
            or any(
                not SHA.fullmatch(value)
                for value in (
                    self.workflow_revision,
                    self.head_sha,
                    self.base_sha,
                    self.trusted_validator_revision,
                )
            )
        ):
            raise ValueError("CI run identity is invalid or ambiguous")

    def as_evidence(self) -> dict[str, object]:
        return {
            "github_run_id": self.github_run_id,
            "github_run_attempt": self.github_run_attempt,
            "workflow_identity": self.workflow_identity,
            "workflow_revision": self.workflow_revision,
            "job_name": self.job_name,
            "check_name": self.check_name,
            "head_sha": self.head_sha,
            "base_sha": self.base_sha,
            "trusted_validator_revision": self.trusted_validator_revision,
        }


def artifact_name(base_name: str, identity: CiRunIdentity) -> str:
    if (
        not ID.fullmatch(base_name)
        or len(base_name) > 80
        or "-run-" in base_name
        or "-attempt-" in base_name
        or "-source-" in base_name
    ):
        raise ValueError("artifact base name is invalid or already identity-qualified")
    return f"{base_name}-run-{identity.github_run_id}-attempt-{identity.github_run_attempt}-source-{identity.head_sha}"


def load_foundation_manifest(manifest_path: Path, schema_path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(manifest_path.read_bytes())
        schema = json.loads(schema_path.read_bytes())
        if not isinstance(manifest, dict) or not isinstance(schema, dict):
            raise ValueError("Foundation manifest and schema must be objects")
        Draft202012Validator.check_schema(schema)
        errors = tuple(Draft202012Validator(schema).iter_errors(manifest))
        if errors:
            raise ValueError(f"Foundation manifest is schema-invalid: {errors[0].message}")
        unsigned = dict(manifest)
        claimed = unsigned.pop("manifest_digest")
        if claimed != digest_bytes(canonical_bytes(unsigned)):
            raise ValueError("Foundation manifest digest is invalid")
        ids = [item["validation_id"] for item in manifest["validations"]]
        cases = [item["case_id"] for item in manifest["validations"]]
        if len(ids) != len(set(ids)) or len(cases) != len(set(cases)):
            raise ValueError("Foundation validation identity inventory is not unique")
        return manifest
    except (OSError, TypeError, KeyError, json.JSONDecodeError, SchemaError) as error:
        raise ValueError("Foundation evidence inventory is unavailable or invalid") from error


def verify_ci_evidence(
    path: Path,
    schema_path: Path | bytes,
    *,
    expected_identity: CiRunIdentity,
    expected_validation_ids: tuple[str, ...],
) -> Verification:
    verified = verify_evidence(path, schema_path)
    if verified.errors or verified.manifest is None:
        return verified
    manifest = verified.manifest
    try:
        if manifest.get("schema_version") != "3.0.0":
            raise ValueError("CI publication requires evidence schema v3")
        if manifest.get("ci") != expected_identity.as_evidence():
            raise ValueError("CI run identity differs from publication boundary")
        if manifest.get("candidate_revision") != expected_identity.head_sha:
            raise ValueError("candidate and CI head identities are mixed")
        if manifest.get("trusted_base_revision") != expected_identity.base_sha:
            raise ValueError("trusted base and CI base identities are mixed")
        actual_ids = tuple(item["validation_id"] for item in manifest["validations"])
        declared_ids = tuple(manifest["declared_validation_ids"])
        if actual_ids != expected_validation_ids or declared_ids != expected_validation_ids:
            raise ValueError("CI evidence validation inventory differs from protected Foundation intent")
        governance = manifest["governance"]
        if governance["human_actions"] != sorted(set(governance["human_actions"])):
            raise ValueError("governance human actions are not canonical")
    except KeyError, TypeError, ValueError:
        return Verification(
            None,
            (EvidenceError("EVID-003", "CI evidence identity or inventory verification failed", {"phase": "ci"}),),
        )
    return verified


def _read_object(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return raw, value


def publish_foundation_evidence(
    *,
    root: Path,
    output: Path,
    trusted_base: str,
    candidate_head: str,
    trusted_policy_path: Path,
    trusted_policy_schema_path: Path,
    authorization_path: Path | None,
    authorization_schema_path: Path,
    governance_result_path: Path,
    identity: CiRunIdentity,
) -> tuple[Path, str, int]:
    """Publish one verified Foundation run from explicit, commit-bound CI inputs."""

    policy_bytes = trusted_policy_path.read_bytes()
    policy_schema_bytes = trusted_policy_schema_path.read_bytes()
    trusted_policy = TrustedPolicyInput(
        policy_bytes=policy_bytes,
        schema_bytes=policy_schema_bytes,
        identity=git_blob_oid(policy_bytes),
        policy_digest=digest_bytes(policy_bytes),
        schema_digest=digest_bytes(policy_schema_bytes),
    )
    authorization: AuthorizationContext | None = None
    contract_digest = digest_bytes(b"foundation-governance-bootstrap")
    if authorization_path is not None:
        payload, authorization_errors = load_trusted_authorization(
            authorization_path.read_bytes(), authorization_schema_path.read_bytes()
        )
        if authorization_errors or payload is None:
            raise ValueError("external protected-change authorization is invalid")
        contract_digest = str(payload["contract_digest"])
        authorization = AuthorizationContext(
            payload,
            str(payload["approval_anchor_revision"]),
            contract_digest,
        )

    manifest = load_foundation_manifest(
        root / "contracts/validation-suites/foundation.json",
        root / "schemas/foundation-validation-suite.schema.json",
    )
    governance_raw, governance_result = _read_object(governance_result_path)
    if governance_result.get("verdict") != "pass":
        raise ValueError("only a passing, independently evaluated governance audit can publish passing CI evidence")
    observation = governance_result.get("observed_state")
    declared_intent = governance_result.get("declared_intent")
    if not isinstance(observation, dict) or not isinstance(declared_intent, dict):
        raise ValueError("governance audit lacks bound intent or observation")
    provenance = observation.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("governance observation lacks authenticated provenance")
    human_actions = governance_result.get("human_actions")
    if not isinstance(human_actions, list) or not all(isinstance(item, str) for item in human_actions):
        raise ValueError("governance human actions are invalid")
    governance = {
        "intent_digest": digest_bytes(canonical_bytes(declared_intent)),
        "observation_digest": digest_bytes(canonical_bytes(observation)),
        "observation_source": provenance["source"],
        "observed_at": observation["observed_at"],
        "api_version": observation["api_version"],
        "audit_verdict": governance_result["verdict"],
        "audit_valid": governance_result["audit_valid"],
        "operationally_compliant": governance_result["operationally_compliant"],
        "human_actions": sorted(set(human_actions)),
    }
    validation_ids = [str(item["validation_id"]) for item in manifest["validations"]]
    case_ids = [str(item["case_id"]) for item in manifest["validations"]]
    bounded_context = {
        "suite_id": "foundation",
        "contract_digest": contract_digest,
        "suite_manifest_digest": manifest["manifest_digest"],
        "config_digest": digest_bytes((root / "contracts/required-checks.json").read_bytes()),
        "protocol_digest": digest_bytes((root / ".github/workflows/foundation-quality.yml").read_bytes()),
        "declared_case_ids": case_ids,
        "declared_validation_ids": validation_ids,
        "seed": 0,
        "producer": {"name": "mojoattention", "version": "1.0.0"},
        "environment": {
            "os": sys.platform.replace("_", "-"),
            "architecture": platform.machine().replace("_", "-"),
            "python_version": platform.python_version(),
            "reference_host": "unverified",
        },
        "governance": governance,
        "ci": identity.as_evidence(),
    }
    context, protected_errors = evaluate_and_compose_trusted_context(
        root,
        trusted_base,
        candidate_head,
        trusted_policy,
        contract_digest,
        bounded_context,
        authorization,
    )
    if context is None or any(error.code not in {"PROT-003", "PROT-004"} for error in protected_errors):
        raise ValueError("trusted protected-change evaluation rejected Foundation evidence authority")

    writer = EvidenceWriter(output, context)
    try:
        leaves = []
        validations = []
        for item in manifest["validations"]:
            attachment_path = f"diagnostics/{str(item['validation_id']).lower()}.json"
            attachment_payload = (
                governance_raw
                if item["validation_id"] == "FOUND-004"
                else canonical_bytes({"case_id": item["case_id"], "status": "pass"}, newline=True)
            )
            leaves.append(writer.snapshot_bytes(attachment_payload, attachment_path, "application/json"))
            validations.append(
                {
                    "validation_id": item["validation_id"],
                    "case_id": item["case_id"],
                    "status": "pass",
                    "reproduction_argv": ["scripts/quality.sh", "--ci"],
                    "metrics": [],
                    "errors": [],
                    "attachments": [attachment_path],
                }
            )
        complete = writer.finalize(
            verdict="pass",
            validations=validations,
            attachments=leaves,
            schema_path=root / "schemas/validation-evidence.schema.json",
        )
    finally:
        writer.abort()
    verified = verify_ci_evidence(
        complete,
        root / "schemas/validation-evidence.schema.json",
        expected_identity=identity,
        expected_validation_ids=tuple(validation_ids),
    )
    if verified.errors or verified.manifest is None:
        raise ValueError("published Foundation evidence failed independent verification")
    tier = next(
        item
        for item in json.loads((root / "contracts/required-checks.json").read_bytes())["tiers"]
        if item["tier_id"] == "fast"
    )
    return complete, str(verified.manifest["evidence_digest"]), int(tier["artifact"]["retention_days"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m mojoattention.validation.ci_evidence")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trusted-base", required=True)
    parser.add_argument("--candidate-head", required=True)
    parser.add_argument("--trusted-policy", type=Path, required=True)
    parser.add_argument("--trusted-policy-schema", type=Path, required=True)
    parser.add_argument("--authorization", type=Path)
    parser.add_argument("--authorization-schema", type=Path, required=True)
    parser.add_argument("--governance-result", type=Path, required=True)
    parser.add_argument("--github-run-id", type=int, required=True)
    parser.add_argument("--github-run-attempt", type=int, required=True)
    parser.add_argument("--workflow-revision", required=True)
    parser.add_argument("--job-name", required=True)
    parser.add_argument("--check-name", required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    values = parser.parse_args(argv)
    try:
        identity = CiRunIdentity(
            values.github_run_id,
            values.github_run_attempt,
            ".github/workflows/foundation-quality.yml",
            values.workflow_revision,
            values.job_name,
            values.check_name,
            values.candidate_head,
            values.trusted_base,
            values.trusted_base,
        )
        complete, evidence_digest, retention_days = publish_foundation_evidence(
            root=values.root,
            output=values.output,
            trusted_base=values.trusted_base,
            candidate_head=values.candidate_head,
            trusted_policy_path=values.trusted_policy,
            trusted_policy_schema_path=values.trusted_policy_schema,
            authorization_path=values.authorization,
            authorization_schema_path=values.authorization_schema,
            governance_result_path=values.governance_result,
            identity=identity,
        )
        artifact = artifact_name("foundation-evidence", identity)
        values.github_output.write_text(
            f"complete_path={complete}\ncomplete_root={complete.parent}\nevidence_digest={evidence_digest}\n"
            f"retention_days={retention_days}\nartifact_name={artifact}\n",
            encoding="utf-8",
        )
        print(json.dumps({"artifact_name": artifact, "evidence_digest": evidence_digest}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"contract-invalid: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

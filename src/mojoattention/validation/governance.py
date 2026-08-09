from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]

GovernanceVerdict = Literal["pass", "product-fail", "infrastructure-invalid", "contract-invalid"]
SchemaSource = Path | bytes


@dataclass(frozen=True)
class GovernanceError:
    code: str
    message: str
    context: dict[str, object]


@dataclass(frozen=True)
class GovernanceIntent:
    repository: str
    default_branch: str
    api_version: str
    expected_source: str
    strict_checks: bool
    minimum_approvals: int
    codeowners_required: bool
    dismiss_stale_reviews: bool
    require_last_push_approval: bool
    administrators_enforced: bool
    allowed_bypass_actors: tuple[str, ...]
    full_sha_pins_required: bool
    dependency_automation_required: bool


@dataclass(frozen=True)
class ProtectionObservation:
    identifier: str
    source: str
    enforcement: str
    applies_to: str
    strict_checks: bool
    checks: tuple[tuple[str, str], ...]
    minimum_approvals: int
    codeowners_required: bool
    dismiss_stale_reviews: bool
    require_last_push_approval: bool
    administrators_enforced: bool
    allowed_bypass_actors: tuple[str, ...]


@dataclass(frozen=True)
class GovernanceObservation:
    repository: str
    default_branch: str
    head_sha: str
    base_sha: str
    observed_at: datetime
    api_version: str
    status: str
    protections: tuple[ProtectionObservation, ...]
    actions_full_sha_required: bool
    actions_default_permissions: str
    dependency_automation_active: bool
    provenance_source: str
    provenance_actor: str
    provenance_permissions: tuple[str, ...]
    payload_sha256: str


@dataclass(frozen=True)
class GovernanceResult:
    verdict: GovernanceVerdict
    audit_valid: bool
    operationally_compliant: bool
    findings: tuple[GovernanceError, ...]
    human_actions: tuple[str, ...]
    applicable_sources: tuple[str, ...]


def _canonical_findings(findings: list[GovernanceError]) -> tuple[GovernanceError, ...]:
    return tuple(
        sorted(
            findings,
            key=lambda item: (
                item.code,
                item.message,
                json.dumps(item.context, sort_keys=True, separators=(",", ":")),
            ),
        )
    )


def _result(
    verdict: GovernanceVerdict,
    findings: list[GovernanceError],
    *,
    applicable_sources: tuple[str, ...] = (),
    human_actions: tuple[str, ...] = (),
) -> GovernanceResult:
    return GovernanceResult(
        verdict=verdict,
        audit_valid=verdict in ("pass", "product-fail"),
        operationally_compliant=verdict == "pass",
        findings=_canonical_findings(findings),
        human_actions=tuple(sorted(set(human_actions))),
        applicable_sources=tuple(sorted(applicable_sources)),
    )


def _schema_errors(instance: object, source: SchemaSource, kind: str) -> list[GovernanceError]:
    try:
        raw = source if isinstance(source, bytes) else source.read_bytes()
        schema = json.loads(raw)
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
    except (OSError, TypeError, json.JSONDecodeError, SchemaError) as error:
        return [GovernanceError("GOV-001", f"{kind} schema is unavailable or invalid", {"error": str(error)})]
    return [
        GovernanceError(
            "GOV-002",
            f"{kind} does not satisfy its schema",
            {"path": "/".join(str(part) for part in error.absolute_path), "validator": str(error.validator)},
        )
        for error in sorted(validator.iter_errors(instance), key=lambda item: tuple(map(str, item.absolute_path)))
    ]


def _parse_intent(raw: dict[str, Any]) -> GovernanceIntent:
    reviews = raw["pull_request_reviews"]
    return GovernanceIntent(
        repository=raw["repository"],
        default_branch=raw["default_branch"],
        api_version=raw["api_version"],
        expected_source=raw["required_checks"]["expected_source"],
        strict_checks=raw["required_checks"]["strict"],
        minimum_approvals=reviews["minimum_approvals"],
        codeowners_required=reviews["codeowners_required"],
        dismiss_stale_reviews=reviews["dismiss_stale_reviews"],
        require_last_push_approval=reviews["require_last_push_approval"],
        administrators_enforced=raw["bypass"]["administrators_enforced"],
        allowed_bypass_actors=tuple(raw["bypass"]["allowed_actors"]),
        full_sha_pins_required=raw["actions"]["full_commit_sha_pins_required"],
        dependency_automation_required=raw["dependency_automation"]["required_active"],
    )


def _parse_protection(raw: object, fallback_id: str) -> ProtectionObservation:
    if not isinstance(raw, dict):
        raise ValueError("protection source must be an object")
    required = {"source", "enforcement", "applies_to", "required_checks", "reviews", "bypass"}
    if not required <= raw.keys():
        raise ValueError("protection source is incomplete")
    if not set(raw) <= required | {"id"}:
        raise ValueError("protection source contains unknown fields")
    checks = raw["required_checks"]
    reviews = raw["reviews"]
    bypass = raw["bypass"]
    if not all(isinstance(value, dict) for value in (checks, reviews, bypass)):
        raise ValueError("protection controls must be objects")
    check_entries = checks.get("checks")
    if not isinstance(check_entries, list):
        raise ValueError("required check inventory must be an array")
    if set(checks) != {"strict", "checks"} or not isinstance(checks["strict"], bool):
        raise ValueError("required check controls are malformed")
    parsed_checks: list[tuple[str, str]] = []
    for check in check_entries:
        if not isinstance(check, dict) or set(check) != {"name", "source"}:
            raise ValueError("required check entry is malformed")
        parsed_checks.append((str(check["name"]), str(check["source"])))
    expected_review_keys = {
        "minimum_approvals",
        "codeowners_required",
        "dismiss_stale_reviews",
        "require_last_push_approval",
    }
    if set(reviews) != expected_review_keys or set(bypass) != {"administrators_enforced", "allowed_actors"}:
        raise ValueError("review or bypass observation is incomplete")
    if (
        not isinstance(reviews["minimum_approvals"], int)
        or isinstance(reviews["minimum_approvals"], bool)
        or reviews["minimum_approvals"] < 0
        or any(not isinstance(reviews[key], bool) for key in expected_review_keys - {"minimum_approvals"})
        or not isinstance(bypass["administrators_enforced"], bool)
    ):
        raise ValueError("review or bypass observation has invalid types")
    allowed = bypass["allowed_actors"]
    if not isinstance(allowed, list):
        raise ValueError("allowed bypass actors must be an array")
    return ProtectionObservation(
        identifier=str(raw.get("id", fallback_id)),
        source=str(raw["source"]),
        enforcement=str(raw["enforcement"]),
        applies_to=str(raw["applies_to"]),
        strict_checks=checks.get("strict") is True,
        checks=tuple(sorted(parsed_checks)),
        minimum_approvals=int(reviews["minimum_approvals"]),
        codeowners_required=reviews["codeowners_required"] is True,
        dismiss_stale_reviews=reviews["dismiss_stale_reviews"] is True,
        require_last_push_approval=reviews["require_last_push_approval"] is True,
        administrators_enforced=bypass["administrators_enforced"] is True,
        allowed_bypass_actors=tuple(sorted(str(actor) for actor in allowed)),
    )


def _parse_observation(raw: dict[str, Any]) -> GovernanceObservation:
    controls = raw["controls"]
    protections = [_parse_protection(item, f"ruleset-{index}") for index, item in enumerate(controls["rulesets"])]
    classic = controls["classic_branch_protection"]
    if classic is not None:
        protections.append(_parse_protection(classic, "classic-branch-protection"))
    provenance = raw["provenance"]
    timestamp = datetime.fromisoformat(raw["observed_at"].replace("Z", "+00:00"))
    return GovernanceObservation(
        repository=raw["repository"],
        default_branch=raw["default_branch"],
        head_sha=raw["head_sha"],
        base_sha=raw["base_sha"],
        observed_at=timestamp,
        api_version=raw["api_version"],
        status=raw["status"],
        protections=tuple(sorted(protections, key=lambda item: item.identifier)),
        actions_full_sha_required=controls["actions_full_sha_required"],
        actions_default_permissions=controls["actions_default_permissions"],
        dependency_automation_active=controls["dependency_automation_active"],
        provenance_source=provenance["source"],
        provenance_actor=provenance["actor"],
        provenance_permissions=tuple(sorted(provenance["permissions"])),
        payload_sha256=provenance["payload_sha256"],
    )


def evaluate_governance(
    intent_record: object,
    observation_record: object,
    *,
    required_checks_record: object,
    intent_schema: SchemaSource,
    observation_schema: SchemaSource,
    required_checks_schema: SchemaSource,
    repository: str,
    default_branch: str,
    head_sha: str,
    base_sha: str,
    api_version: str,
    observed_at: datetime,
    maximum_age: timedelta,
) -> GovernanceResult:
    """Compare protected intent with an explicit authenticated snapshot without I/O."""
    unavailable = {"unavailable", "unauthorized", "rate-limited", "network-failure", "incomplete"}
    if isinstance(observation_record, dict) and observation_record.get("status") in unavailable:
        return _result(
            "infrastructure-invalid",
            [
                GovernanceError(
                    "GOV-010",
                    "hosted governance observation is unavailable",
                    {"status": observation_record["status"]},
                )
            ],
        )
    findings = _schema_errors(intent_record, intent_schema, "governance intent")
    findings.extend(_schema_errors(observation_record, observation_schema, "governance observation"))
    findings.extend(_schema_errors(required_checks_record, required_checks_schema, "required check registry"))
    if (
        findings
        or not isinstance(intent_record, dict)
        or not isinstance(observation_record, dict)
        or not isinstance(required_checks_record, dict)
    ):
        return _result("contract-invalid", findings)
    try:
        intent = _parse_intent(intent_record)
        observation = _parse_observation(observation_record)
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return _result(
            "contract-invalid",
            [GovernanceError("GOV-003", "governance controls are malformed or incomplete", {"error": str(error)})],
        )
    identities = {
        "repository": (repository, intent.repository, observation.repository),
        "default_branch": (default_branch, intent.default_branch, observation.default_branch),
        "head_sha": (head_sha, head_sha, observation.head_sha),
        "base_sha": (base_sha, base_sha, observation.base_sha),
        "api_version": (api_version, intent.api_version, observation.api_version),
    }
    identity_findings = [
        GovernanceError("GOV-004", "governance identity does not match trusted inputs", {"field": field})
        for field, values in identities.items()
        if len(set(values)) != 1
    ]
    if identity_findings:
        return _result("contract-invalid", identity_findings)
    unsigned_observation = json.loads(json.dumps(observation_record))
    claimed_payload_digest = unsigned_observation["provenance"].pop("payload_sha256")
    actual_payload_digest = (
        "sha256:"
        + hashlib.sha256(json.dumps(unsigned_observation, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    )
    if (
        claimed_payload_digest != actual_payload_digest
        or "administration:read" not in observation.provenance_permissions
    ):
        return _result(
            "contract-invalid",
            [GovernanceError("GOV-006", "governance provenance is not bound to an authorized payload", {})],
        )
    now = observed_at.astimezone(UTC)
    timestamp = observation.observed_at.astimezone(UTC)
    if observation.status != "available":
        return _result(
            "infrastructure-invalid",
            [
                GovernanceError(
                    "GOV-010",
                    "hosted governance observation is unavailable",
                    {"status": observation.status},
                )
            ],
        )
    if timestamp > now or now - timestamp > maximum_age:
        return _result(
            "infrastructure-invalid",
            [GovernanceError("GOV-011", "hosted governance observation is stale or future-dated", {})],
        )
    applicable = tuple(
        protection
        for protection in observation.protections
        if protection.enforcement == "active" and protection.applies_to == default_branch
    )
    source_ids = tuple(item.identifier for item in applicable)
    human_actions: list[str] = []
    if not applicable:
        findings.append(GovernanceError("GOV-101", "no active protection applies to the default branch", {}))
        human_actions.append("Activate branch protection or an applicable ruleset.")
    if not observation.actions_full_sha_required:
        findings.append(GovernanceError("GOV-102", "repository Actions policy does not require full SHA pins", {}))
        human_actions.append("Require full-length commit SHA pins for Actions.")
    if observation.actions_default_permissions != "read":
        findings.append(GovernanceError("GOV-104", "default Actions permissions are not read-only", {}))
        human_actions.append("Set default workflow permissions to read-only.")
    if intent.dependency_automation_required and not observation.dependency_automation_active:
        findings.append(GovernanceError("GOV-103", "dependency automation is not observed active", {}))
        human_actions.append("Activate dependency automation.")
    try:
        active_tiers = tuple(tier for tier in required_checks_record["tiers"] if tier["activation"] == "active")
        registry_source = required_checks_record["expected_source"]
        if registry_source != intent.expected_source or not active_tiers:
            raise ValueError("required check registry conflicts with governance intent")
        expected_checks = {(tier["check_name"], registry_source) for tier in active_tiers}
    except (KeyError, TypeError, ValueError) as error:
        return _result(
            "contract-invalid",
            [GovernanceError("GOV-005", "required check intent is incomplete or conflicting", {"error": str(error)})],
        )
    if applicable:
        bypass = set(applicable[0].allowed_bypass_actors)
        for protection in applicable[1:]:
            bypass.intersection_update(protection.allowed_bypass_actors)
        weak: list[str] = []
        if intent.strict_checks and not any(item.strict_checks for item in applicable):
            weak.append("strict-required-checks")
        effective_checks = {check for item in applicable for check in item.checks}
        if not expected_checks <= effective_checks:
            weak.append("required-check-inventory-or-source")
        if max(item.minimum_approvals for item in applicable) < intent.minimum_approvals:
            weak.append("minimum-approvals")
        for field in (
            "codeowners_required",
            "dismiss_stale_reviews",
            "require_last_push_approval",
            "administrators_enforced",
        ):
            if getattr(intent, field) and not any(getattr(item, field) for item in applicable):
                weak.append(field)
        if bypass != set(intent.allowed_bypass_actors):
            weak.append("bypass-actors")
        if weak:
            findings.append(
                GovernanceError(
                    "GOV-111",
                    "effective applicable protection provides weaker coverage than intent",
                    {"sources": sorted(source_ids), "controls": sorted(weak)},
                )
            )
            human_actions.append("Strengthen effective protection for the default branch.")
    if len(applicable) > 1:
        precedence = [item.identifier for item in sorted(applicable, key=lambda item: (item.source, item.identifier))]
        context: dict[str, object] = {"sources": sorted(source_ids), "precedence": precedence}
        message = "multiple protection sources overlap on the default branch"
        findings.append(GovernanceError("GOV-110", message, context))
    if any(finding.code != "GOV-110" for finding in findings):
        return _result(
            "product-fail",
            findings,
            applicable_sources=source_ids,
            human_actions=tuple(human_actions),
        )
    return _result("pass", findings, applicable_sources=source_ids)

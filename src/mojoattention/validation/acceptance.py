from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]

from mojoattention.validation.paths import contains, has_overlap, is_canonical_repo_path

REQUIRED_STOPS = frozenset(
    {
        "scope-expansion",
        "validation-weakening",
        "protected-conflict",
        "non-improving-retry",
        "nondeterminism",
    }
)


@dataclass(frozen=True)
class ContractError:
    code: str
    message: str
    context: dict[str, object]


@dataclass(frozen=True)
class ContractContext:
    source_revision: str
    trusted_base_revision: str
    prior_validation_identity: str | None
    approval_anchor_revision: str | None = None
    authorization: dict[str, object] | None = None


def _canonical_payload(contract: dict[str, object]) -> bytes:
    bound = deepcopy(contract)
    bound.pop("contract_digest", None)
    return json.dumps(bound, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def compute_contract_digest(contract: dict[str, object]) -> str:
    return f"sha256:{hashlib.sha256(_canonical_payload(contract)).hexdigest()}"


def issue_contract(contract: dict[str, object]) -> dict[str, object]:
    issued = deepcopy(contract)
    issued["contract_digest"] = compute_contract_digest(issued)
    return issued


def _schema_errors(instance: object, schema_path: Path, code: str) -> list[ContractError]:
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except (OSError, json.JSONDecodeError, TypeError, SchemaError) as error:
        return [ContractError(code, "schema cannot be loaded or is invalid", {"error": str(error)})]
    errors = sorted(
        Draft202012Validator(schema).iter_errors(instance),
        key=lambda item: (tuple(str(part) for part in item.path), item.message),
    )
    return [
        ContractError(
            code,
            error.message,
            {"path": "/".join(str(part) for part in error.absolute_path)},
        )
        for error in errors
    ]


def _path_errors(contract: dict[str, Any], root: Path) -> list[ContractError]:
    errors: list[ContractError] = []
    groups = {
        "allowed_paths": contract["allowed_paths"],
        "protected_paths": contract["protected_paths"],
        "generated_outputs": contract["generated_outputs"],
    }
    for name, paths in groups.items():
        for path in paths:
            if not is_canonical_repo_path(path, root, require_exists=False):
                errors.append(
                    ContractError("ACPT-004", "path is noncanonical or unsafe", {"field": name, "path": path})
                )
        if has_overlap(paths):
            errors.append(
                ContractError("ACPT-004", "path class contains duplicate or overlapping scopes", {"field": name})
            )
    for output in contract["generated_outputs"]:
        matches = [scope for scope in contract["allowed_paths"] if contains(scope, output)]
        if len(matches) != 1:
            errors.append(
                ContractError(
                    "ACPT-004",
                    "generated output must be covered by exactly one allowed scope",
                    {"path": output, "matches": len(matches)},
                )
            )
    for protected_path in contract["protected_paths"]:
        matches = [scope for scope in contract["allowed_paths"] if contains(scope, protected_path)]
        if len(matches) != 1:
            errors.append(
                ContractError(
                    "ACPT-004",
                    "protected path must be covered by exactly one allowed scope",
                    {"path": protected_path, "matches": len(matches)},
                )
            )
    return errors


def _inventory_errors(contract: dict[str, Any]) -> list[ContractError]:
    errors: list[ContractError] = []
    suite_ids: set[str] = set()
    all_validation_ids: set[str] = set()
    for suite in contract["required_suites"]:
        suite_id = suite["suite_id"]
        if suite_id in suite_ids:
            errors.append(ContractError("ACPT-005", "duplicate suite id", {"suite_id": suite_id}))
        suite_ids.add(suite_id)
        validation_ids = [item["validation_id"] for item in suite["validations"]]
        if len(validation_ids) != len(set(validation_ids)):
            errors.append(ContractError("ACPT-005", "duplicate validation id within suite", {"suite_id": suite_id}))
        for validation_id in validation_ids:
            if validation_id in all_validation_ids:
                errors.append(
                    ContractError(
                        "ACPT-005",
                        "validation id appears in multiple suites",
                        {"validation_id": validation_id},
                    )
                )
            all_validation_ids.add(validation_id)
        expected = sum(item["required_count"] for item in suite["validations"])
        declared_total = suite.get("required_total")
        if declared_total is not None and declared_total != expected:
            errors.append(
                ContractError(
                    "ACPT-005",
                    "suite total does not equal validation cardinality",
                    {"suite_id": suite_id, "declared": declared_total, "expected": expected},
                )
            )
    return errors


def _authorization_errors(
    contract: dict[str, Any],
    root: Path,
    context: ContractContext,
) -> list[ContractError]:
    protected = contract["protected_paths"]
    authorization = context.authorization
    if not protected:
        if contract["authorization_id"] is not None or authorization is not None:
            return [
                ContractError(
                    "ACPT-008",
                    "authorization is forbidden when no protected path is declared",
                    {},
                )
            ]
        return []
    if contract["authorization_id"] is None or authorization is None:
        return [ContractError("ACPT-008", "protected paths require external human authorization", {})]
    schema_errors = _schema_errors(
        authorization,
        root / "schemas" / "protected-change-authorization.schema.json",
        "ACPT-008",
    )
    if schema_errors:
        return schema_errors
    if context.approval_anchor_revision == contract["source_revision"]:
        return [
            ContractError(
                "ACPT-008",
                "approval anchor cannot self-reference the proposal source revision",
                {"approval_anchor_revision": context.approval_anchor_revision},
            )
        ]
    expected: dict[str, object] = {
        "authorization_id": contract["authorization_id"],
        "contract_digest": contract["contract_digest"],
        "source_revision": contract["source_revision"],
        "trusted_base_revision": contract["trusted_base_revision"],
        "authorized_protected_paths": protected,
        "approval_anchor_revision": context.approval_anchor_revision,
        "approver_kind": "human",
    }
    errors: list[ContractError] = []
    for field, value in expected.items():
        actual = authorization.get(field)
        matches = (
            set(actual) == set(value)
            if field == "authorized_protected_paths" and isinstance(actual, list) and isinstance(value, list)
            else actual == value
        )
        if not matches:
            errors.append(
                ContractError(
                    "ACPT-008",
                    "authorization binding does not match trusted context",
                    {"field": field, "expected": value, "actual": actual},
                )
            )
    return errors


def validate_contract(
    contract: object,
    root: Path,
    context: ContractContext,
) -> tuple[ContractError, ...]:
    schema_errors = _schema_errors(contract, root / "schemas" / "acceptance-contract.schema.json", "ACPT-001")
    if schema_errors:
        return tuple(schema_errors)
    assert isinstance(contract, dict)
    typed: dict[str, Any] = contract
    errors: list[ContractError] = []
    if typed["source_revision"] != context.source_revision:
        errors.append(
            ContractError(
                "ACPT-002",
                "source revision is stale",
                {"expected": context.source_revision, "actual": typed["source_revision"]},
            )
        )
    if typed["trusted_base_revision"] != context.trusted_base_revision:
        errors.append(
            ContractError(
                "ACPT-002",
                "trusted-base revision is stale",
                {"expected": context.trusted_base_revision, "actual": typed["trusted_base_revision"]},
            )
        )
    if typed["prior_validation_identity"] != context.prior_validation_identity:
        errors.append(
            ContractError(
                "ACPT-002",
                "prior validation identity is stale",
                {"expected": context.prior_validation_identity, "actual": typed["prior_validation_identity"]},
            )
        )
    try:
        expected_digest = compute_contract_digest(typed)
    except (TypeError, ValueError) as error:
        errors.append(ContractError("ACPT-003", "contract cannot be canonically serialized", {"error": str(error)}))
    else:
        if typed["contract_digest"] != expected_digest:
            errors.append(
                ContractError(
                    "ACPT-003",
                    "contract digest does not match bound fields",
                    {"expected": expected_digest, "actual": typed["contract_digest"]},
                )
            )
    requirements = set(typed["requirement_ids"])
    capabilities = set(typed["capability_ids"])
    ambiguous = requirements & capabilities
    if ambiguous:
        errors.append(
            ContractError(
                "ACPT-001",
                "ids cannot be both requirements and capabilities",
                {"ids": sorted(ambiguous)},
            )
        )
    included = requirements | capabilities
    overlap = included & set(typed["exclusions"])
    if overlap:
        errors.append(ContractError("ACPT-001", "included ids conflict with exclusions", {"ids": sorted(overlap)}))
    errors.extend(_path_errors(typed, root))
    errors.extend(_inventory_errors(typed))
    if not REQUIRED_STOPS.issubset(typed["stop_conditions"]):
        errors.append(
            ContractError(
                "ACPT-007",
                "required semantic stop conditions are incomplete",
                {"missing": sorted(REQUIRED_STOPS - set(typed["stop_conditions"]))},
            )
        )
    errors.extend(_authorization_errors(typed, root, context))
    return tuple(errors)

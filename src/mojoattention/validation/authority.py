from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

REQUIRED_ROLES = frozenset(
    {
        "orchestrator",
        "explorer",
        "acceptance-auditor",
        "implementer",
        "test-builder",
        "validation-triage",
        "performance-analyst",
        "documentation-agent",
    }
)
READ_ONLY_ROLES = frozenset({"explorer", "acceptance-auditor", "validation-triage"})
OPERATIONS = frozenset({"create", "modify", "delete", "rename", "copy", "generate"})


@dataclass(frozen=True)
class AuthorityError:
    code: str
    message: str
    path: str | None = None


def _canonical_scope(scope: str, root: Path) -> bool:
    pure = PurePosixPath(scope)
    if not scope or scope.startswith("/") or "\\" in scope or ".." in pure.parts or scope.endswith("/"):
        return False
    candidate = root / scope
    try:
        current = root
        for part in pure.parts:
            current /= part
            if current.is_symlink():
                return False
        return candidate.exists() and candidate.resolve().is_relative_to(root.resolve())
    except OSError:
        return False


def _canonical_target(path: str, root: Path) -> bool:
    pure = PurePosixPath(path)
    if not path or path.startswith("/") or "\\" in path or any(part in {"", ".", ".."} for part in pure.parts):
        return False
    current = root
    try:
        for part in pure.parts:
            current /= part
            if current.is_symlink():
                return False
            if not current.exists():
                break
        return current.resolve(strict=False).is_relative_to(root.resolve())
    except OSError:
        return False


def _contains(scope: str, path: str) -> bool:
    scope_path, candidate = PurePosixPath(scope), PurePosixPath(path)
    return candidate == scope_path or scope_path in candidate.parents


def validate_manifest(manifest: Any, root: Path) -> tuple[AuthorityError, ...]:
    schema = json.loads((root / "schemas" / "agent-authority.schema.json").read_text(encoding="utf-8"))
    schema_errors = sorted(Draft202012Validator(schema).iter_errors(manifest), key=lambda item: list(item.path))
    if schema_errors:
        classified: list[AuthorityError] = []
        for error in schema_errors:
            path = list(error.path)
            code = "AUTH-001"
            if error.validator == "minItems" and path == ["roles"]:
                code = "AUTH-002"
            elif path and path[-1] in {"can_approve_protected_changes", "can_approve_final_merge"}:
                code = "AUTH-006"
            classified.append(AuthorityError(code, error.message))
        return tuple(classified)
    roles = manifest["roles"]
    ids = [role["id"] for role in roles]
    errors: list[AuthorityError] = []
    if len(ids) != len(set(ids)) or set(ids) != REQUIRED_ROLES:
        errors.append(AuthorityError("AUTH-002", "role inventory must be complete and unique"))
    for role in roles:
        write_scopes = [*role["write_paths"], *role["indirect_output_paths"]]
        for scope in [*manifest["protected_paths"], *role["read_paths"], *write_scopes]:
            if not _canonical_scope(scope, root):
                errors.append(AuthorityError("AUTH-003", "scope is noncanonical, unresolved, or unsafe", scope))
        if role["id"] in READ_ONLY_ROLES and write_scopes:
            errors.append(AuthorityError("AUTH-004", "read-only role declares write authority", role["id"]))
        if role["can_approve_protected_changes"] or role["can_approve_final_merge"]:
            errors.append(
                AuthorityError("AUTH-006", "automated roles cannot approve protected changes or merge", role["id"])
            )
    writers = [
        (role["id"], scope) for role in roles for scope in [*role["write_paths"], *role["indirect_output_paths"]]
    ]
    for index, (left_role, left_scope) in enumerate(writers):
        for right_role, right_scope in writers[index + 1 :]:
            if left_role != right_role and (_contains(left_scope, right_scope) or _contains(right_scope, left_scope)):
                errors.append(
                    AuthorityError("AUTH-005", f"writer scopes overlap: {left_role} and {right_role}", left_scope)
                )
    return tuple(errors)


def authorize_write(
    manifest: dict[str, Any],
    role_id: str,
    operation: str,
    path: str,
    contracted_paths: tuple[str, ...],
    *,
    root: Path,
    destination: str | None = None,
    stop: str | None = None,
) -> AuthorityError | None:
    if stop is not None:
        return AuthorityError("AUTH-009", "mandatory stop requires human escalation", stop)
    if operation not in OPERATIONS:
        return AuthorityError("AUTH-010", "unsupported operation", operation)
    if operation in {"rename", "copy"} and destination is None:
        return AuthorityError("AUTH-010", "rename and copy require a destination", operation)
    if operation not in {"rename", "copy"} and destination is not None:
        return AuthorityError("AUTH-010", "operation does not accept a destination", operation)
    role = next((item for item in manifest["roles"] if item["id"] == role_id), None)
    if role is None:
        return AuthorityError("AUTH-002", "unknown role", role_id)
    targets = [path, *([destination] if destination is not None else [])]
    role_scopes = role["indirect_output_paths"] if operation == "generate" else role["write_paths"]
    for target in targets:
        if not _canonical_target(target, root):
            return AuthorityError("AUTH-003", "operation path is noncanonical or unsafe", target)
        if any(_contains(scope, target) for scope in manifest["protected_paths"]):
            return AuthorityError("AUTH-009", "protected policy change requires human authorization", target)
        if not any(_contains(scope, target) for scope in role_scopes):
            return AuthorityError("AUTH-007", "path is outside role authority", target)
        if not any(_contains(scope, target) for scope in contracted_paths):
            return AuthorityError("AUTH-008", "path is outside contracted authority", target)
    return None


def authorize_read(manifest: dict[str, Any], role_id: str, path: str, *, root: Path) -> AuthorityError | None:
    role = next((item for item in manifest["roles"] if item["id"] == role_id), None)
    if role is None:
        return AuthorityError("AUTH-002", "unknown role", role_id)
    if not _canonical_target(path, root):
        return AuthorityError("AUTH-003", "read path is noncanonical or unsafe", path)
    if not any(_contains(scope, path) for scope in role["read_paths"]):
        return AuthorityError("AUTH-011", "path is outside role read authority", path)
    return None

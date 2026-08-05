from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]

from mojoattention.validation.paths import contains, has_overlap

OID = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MODE = re.compile(r"^(?:000000|040000|100644|100755|120000|160000)$")
REQUIRED_CATEGORIES = frozenset(
    {
        "tests",
        "schemas",
        "tolerances",
        "baselines",
        "workflows",
        "dependency-locks",
        "agent-policy",
        "codeowners",
        "golden-data",
        "required-check-policy",
        "generated-outputs",
        "reference-oracles",
        "acceptance-contracts",
        "ownership-metadata",
        "protected-policy",
        "authorization-controls",
        "protected-evaluator",
    }
)


@dataclass(frozen=True)
class ProtectedError:
    code: str
    message: str
    context: dict[str, object]


@dataclass(frozen=True)
class ChangeEffect:
    kind: str
    path: str
    old_mode: str
    new_mode: str
    old_oid: str
    new_oid: str
    source_path: str | None = None
    score: int | None = None
    inferred_by: str | None = None


@dataclass(frozen=True)
class Inspection:
    identity: dict[str, str]
    effects: tuple[ChangeEffect, ...]
    change_set_digest: str
    policy: dict[str, object]


@dataclass(frozen=True)
class AuthorizationContext:
    envelope: dict[str, object]
    approval_anchor_revision: str
    contract_digest: str


_TRUSTED_CONTEXT_TOKEN = object()


@dataclass(frozen=True)
class TrustedEvaluationContext:
    """Non-serializable writer authority constructed after trusted evaluation."""

    _canonical_payload: bytes
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _TRUSTED_CONTEXT_TOKEN:
            raise ValueError("trusted evaluation context must come from protected evaluation")

    def evidence_context(self) -> dict[str, Any]:
        value = json.loads(self._canonical_payload)
        if not isinstance(value, dict):
            raise ValueError("trusted evaluation context is invalid")
        return value


def _compose_trusted_evaluation_context(
    inspection: Inspection,
    trusted_policy: TrustedPolicyInput,
    protected_errors: tuple[ProtectedError, ...],
    bounded_context: dict[str, Any],
    authorization: AuthorizationContext | None,
) -> TrustedEvaluationContext:
    """Bind suite inputs to identities already resolved by the protected evaluator."""

    required = {
        "suite_id",
        "contract_digest",
        "config_digest",
        "protocol_digest",
        "declared_case_ids",
        "declared_validation_ids",
        "seed",
        "producer",
        "environment",
    }
    allowed = (
        required,
        required | {"suite_manifest_digest"},
        required | {"suite_manifest_digest", "governance", "ci"},
    )
    if set(bounded_context) not in allowed:
        raise ValueError("bounded evidence context fields are incomplete or unknown")
    payload = dict(bounded_context)
    payload.update(inspection.identity)
    payload.update(
        {
            "source_revision": inspection.identity["candidate_revision"],
            "source_tree": inspection.identity["candidate_tree"],
            "trusted_schema_oid": git_blob_oid(trusted_policy.schema_bytes),
            "trusted_schema_digest": trusted_policy.schema_digest,
            "change_set_digest": inspection.change_set_digest,
            "authorization_id": (authorization.envelope["authorization_id"] if authorization is not None else None),
            "provenance_digest": (authorization.envelope["provenance_digest"] if authorization is not None else None),
        }
    )
    # A trusted policy rejection is evidence-capable; acquisition/identity failures
    # never produce an Inspection and therefore cannot reach this composition point.
    if any(error.code not in {"PROT-003", "PROT-004"} for error in protected_errors):
        raise ValueError("untrusted acquisition errors cannot form evidence context")
    return TrustedEvaluationContext(_canonical_bytes(payload), _TRUSTED_CONTEXT_TOKEN)


def evaluate_and_compose_trusted_context(
    root: Path,
    trusted_base_revision: str,
    candidate_revision: str,
    trusted_policy: TrustedPolicyInput,
    contract_digest: str,
    bounded_context: dict[str, Any],
    authorization: AuthorizationContext | None,
) -> tuple[TrustedEvaluationContext | None, tuple[ProtectedError, ...]]:
    """Perform trusted acquisition and policy evaluation before issuing writer authority."""

    inspection, acquisition_errors = inspect_repository_changes(
        root,
        trusted_base_revision,
        candidate_revision,
        trusted_policy,
    )
    if acquisition_errors or inspection is None:
        return None, acquisition_errors
    protected_errors = evaluate_protected_changes(
        inspection.policy,
        inspection.effects,
        inspection.identity,
        inspection.change_set_digest,
        contract_digest,
        authorization,
    )
    return (
        _compose_trusted_evaluation_context(
            inspection,
            trusted_policy,
            protected_errors,
            bounded_context,
            authorization,
        ),
        protected_errors,
    )


@dataclass(frozen=True)
class TrustedPolicyInput:
    policy_bytes: bytes
    schema_bytes: bytes
    identity: str
    policy_digest: str
    schema_digest: str


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def git_blob_oid(payload: bytes) -> str:
    header = f"blob {len(payload)}\0".encode()
    return hashlib.sha1(header + payload).hexdigest()  # noqa: S324 - Git SHA-1 object identity, not security hashing


def _safe_tree_path(path: str) -> bool:
    return bool(
        path
        and not path.startswith("/")
        and "\\" not in path
        and "//" not in path
        and not path.endswith("/")
        and all(part not in {"", ".", ".."} for part in PurePosixPath(path).parts)
    )


def validate_policy(policy: object, schema_path: Path) -> tuple[ProtectedError, ...]:
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        schema_errors = sorted(
            Draft202012Validator(schema).iter_errors(policy),
            key=lambda item: (tuple(str(part) for part in item.path), item.message),
        )
    except (OSError, ValueError, json.JSONDecodeError, TypeError, SchemaError) as error:
        return (ProtectedError("PROT-001", "trusted policy schema is unavailable or invalid", {"error": str(error)}),)
    errors = [
        ProtectedError(
            "PROT-001",
            "trusted policy is schema-invalid",
            {"schema_path": "/".join(str(part) for part in item.absolute_path), "error": item.message},
        )
        for item in schema_errors
    ]
    if errors or not isinstance(policy, dict):
        return tuple(errors)
    categories = policy.get("protected_categories")
    scopes = policy.get("protected_scopes")
    rules = policy.get("generated_rules")
    if not isinstance(categories, list) or set(categories) != REQUIRED_CATEGORIES:
        errors.append(
            ProtectedError(
                "PROT-001",
                "protected category inventory is incomplete",
                {"missing": sorted(REQUIRED_CATEGORIES - set(categories or []))},
            )
        )
    if isinstance(scopes, list):
        scope_categories: list[str] = []
        all_paths: list[str] = []
        for index, scope in enumerate(scopes):
            if not isinstance(scope, dict):
                continue
            category = scope.get("category")
            paths = scope.get("paths")
            if isinstance(category, str):
                scope_categories.append(category)
            if isinstance(paths, list):
                all_paths.extend(path for path in paths if isinstance(path, str))
                if any(not isinstance(path, str) or not _safe_tree_path(path) for path in paths):
                    errors.append(
                        ProtectedError("PROT-001", "protected scope path is noncanonical", {"scope_index": index})
                    )
                if has_overlap([path for path in paths if isinstance(path, str)]):
                    errors.append(ProtectedError("PROT-001", "protected scope paths overlap", {"scope_index": index}))
        if set(scope_categories) != REQUIRED_CATEGORIES:
            errors.append(
                ProtectedError(
                    "PROT-001",
                    "protected scope categories are incomplete",
                    {"categories": sorted(set(scope_categories))},
                )
            )
        if len(scope_categories) != len(set(scope_categories)):
            errors.append(ProtectedError("PROT-001", "protected scope category is duplicated", {}))
        if has_overlap(all_paths):
            errors.append(ProtectedError("PROT-001", "protected scopes overlap across categories", {}))
    if isinstance(rules, list):
        graph: dict[str, set[str]] = {}
        seen_ids: set[str] = set()
        all_triggers: list[str] = []
        all_outputs: list[str] = []
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            rule_id = rule.get("id")
            triggers = rule.get("trigger_paths", [])
            outputs = rule.get("output_paths", [])
            if isinstance(rule_id, str):
                if rule_id in seen_ids:
                    errors.append(ProtectedError("PROT-005", "generated rule id is duplicated", {"rule_id": rule_id}))
                seen_ids.add(rule_id)
            typed_triggers = [path for path in triggers if isinstance(path, str)]
            typed_outputs = [path for path in outputs if isinstance(path, str)]
            all_triggers.extend(typed_triggers)
            all_outputs.extend(typed_outputs)
            if any(not _safe_tree_path(path) for path in [*typed_triggers, *typed_outputs]):
                errors.append(ProtectedError("PROT-005", "generated rule path is noncanonical", {"rule_index": index}))
            if has_overlap(typed_triggers) or has_overlap(typed_outputs):
                errors.append(ProtectedError("PROT-005", "generated rule paths overlap", {"rule_index": index}))
            graph.setdefault(str(rule_id), set())
        if has_overlap(all_triggers):
            errors.append(ProtectedError("PROT-005", "generated trigger scopes overlap across rules", {}))
        if has_overlap(all_outputs):
            errors.append(ProtectedError("PROT-005", "generated output scopes overlap across rules", {}))
        for left in rules:
            if not isinstance(left, dict):
                continue
            for right in rules:
                if not isinstance(right, dict):
                    continue
                if any(
                    contains(output, trigger) or contains(trigger, output)
                    for output in left.get("output_paths", [])
                    for trigger in right.get("trigger_paths", [])
                ):
                    graph[str(left.get("id"))].add(str(right.get("id")))
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str) -> bool:
            if node in visiting:
                return True
            if node in visited:
                return False
            visiting.add(node)
            cyclic = any(visit(child) for child in graph.get(node, set()))
            visiting.remove(node)
            visited.add(node)
            return cyclic

        if any(visit(node) for node in sorted(graph)):
            errors.append(ProtectedError("PROT-005", "generated rules contain a cycle", {}))
    return tuple(errors)


def _effect_payload(effect: ChangeEffect) -> dict[str, object]:
    return {
        "kind": effect.kind,
        "path": effect.path,
        "source_path": effect.source_path,
        "old_mode": effect.old_mode,
        "new_mode": effect.new_mode,
        "old_oid": effect.old_oid,
        "new_oid": effect.new_oid,
        "score": effect.score,
        "inferred_by": effect.inferred_by,
    }


def compute_change_digest(
    trusted_base_revision: str,
    trusted_base_tree: str,
    candidate_revision: str,
    candidate_tree: str,
    trusted_policy_oid: str,
    trusted_policy_digest: str,
    effects: tuple[ChangeEffect, ...],
) -> str:
    ordered = sorted((_effect_payload(effect) for effect in effects), key=lambda item: _canonical_bytes(item))
    payload = {
        "trusted_base_revision": trusted_base_revision,
        "trusted_base_tree": trusted_base_tree,
        "candidate_revision": candidate_revision,
        "candidate_tree": candidate_tree,
        "trusted_policy_oid": trusted_policy_oid,
        "trusted_policy_digest": trusted_policy_digest,
        "effects": ordered,
    }
    return f"sha256:{hashlib.sha256(_canonical_bytes(payload)).hexdigest()}"


def compute_provenance_digest(envelope: dict[str, object]) -> str:
    payload = dict(envelope)
    payload.pop("provenance_digest", None)
    return f"sha256:{hashlib.sha256(_canonical_bytes(payload)).hexdigest()}"


def load_trusted_authorization(
    payload_bytes: bytes,
    schema_bytes: bytes,
) -> tuple[dict[str, object] | None, tuple[ProtectedError, ...]]:
    try:
        payload = json.loads(payload_bytes)
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError) as error:
        return None, (
            ProtectedError(
                "PROT-004",
                "protected caller authorization is invalid",
                {"error": str(error)},
            ),
        )
    if not isinstance(payload, dict):
        return None, (
            ProtectedError(
                "PROT-004",
                "protected caller authorization is not an object",
                {},
            ),
        )
    typed: dict[str, object] = payload
    try:
        schema = json.loads(schema_bytes)
        Draft202012Validator.check_schema(schema)
        schema_errors = sorted(
            Draft202012Validator(schema).iter_errors(typed),
            key=lambda item: (tuple(str(part) for part in item.path), item.message),
        )
    except (json.JSONDecodeError, TypeError, SchemaError) as error:
        return None, (ProtectedError("PROT-004", "trusted authorization schema is invalid", {"error": str(error)}),)
    if schema_errors:
        return None, tuple(
            ProtectedError(
                "PROT-004",
                "protected caller authorization is schema-invalid",
                {"schema_path": "/".join(str(part) for part in error.absolute_path), "error": error.message},
            )
            for error in schema_errors
        )
    if typed.get("provenance_digest") != compute_provenance_digest(typed):
        return None, (
            ProtectedError(
                "PROT-004",
                "protected caller authorization provenance digest is invalid",
                {},
            ),
        )
    return typed, ()


def _git(root: Path, *args: str) -> bytes:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_EXTERNAL_DIFF": "",
        "GIT_PAGER": "cat",
        "LC_ALL": "C",
    }
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.quotePath=false",
            "-c",
            "diff.external=",
            "-c",
            "diff.renameLimit=0",
            "-c",
            "core.attributesFile=",
            "-c",
            "core.hooksPath=",
            "-c",
            "protocol.file.allow=never",
            *args,
        ],
        cwd=root,
        capture_output=True,
        check=False,
        env=environment,
    )
    if result.returncode != 0:
        raise ValueError(result.stderr.decode(errors="replace").strip() or "git command failed")
    return result.stdout


def _resolve_commit(root: Path, revision: str, code: str) -> tuple[str, str]:
    if not OID.fullmatch(revision):
        raise ValueError(f"{code}: revision must be a full lowercase object id")
    object_type = _git(root, "cat-file", "-t", revision).decode().strip()
    if object_type != "commit":
        raise ValueError(f"{code}: object is not a commit")
    resolved = _git(root, "rev-parse", f"{revision}^{{commit}}").decode().strip()
    if resolved != revision:
        raise ValueError(f"{code}: revision resolution changed identity")
    tree = _git(root, "rev-parse", f"{revision}^{{tree}}").decode().strip()
    if not OID.fullmatch(tree):
        raise ValueError(f"{code}: commit tree identity is invalid")
    return revision, tree


def _parse_raw_diff(raw: bytes) -> tuple[ChangeEffect, ...]:
    if not raw:
        return ()
    fields = raw.split(b"\0")
    if fields[-1] == b"":
        fields.pop()
    effects: list[ChangeEffect] = []
    index = 0
    while index < len(fields):
        header = fields[index]
        index += 1
        if not header.startswith(b":"):
            raise ValueError(f"record {index - 1}: missing raw header")
        try:
            metadata, first_path_bytes = header.split(b"\t", 1) if b"\t" in header else (header, fields[index])
            if b"\t" not in header:
                index += 1
            old_mode, new_mode, old_oid, new_oid, status_value = metadata[1:].decode("ascii").split()
            first_path = first_path_bytes.decode("utf-8")
        except (IndexError, UnicodeDecodeError, ValueError) as error:
            raise ValueError(f"record {index - 1}: malformed raw diff") from error
        status = status_value[0]
        score_text = status_value[1:]
        if not MODE.fullmatch(old_mode) or not MODE.fullmatch(new_mode):
            raise ValueError(f"record {index - 1}: invalid file mode")
        if not OID.fullmatch(old_oid) or not OID.fullmatch(new_oid):
            raise ValueError(f"record {index - 1}: invalid object id")
        if status not in {"A", "M", "D", "R", "C", "T"}:
            raise ValueError(f"record {index - 1}: unsupported status {status}")
        if status in {"R", "C"}:
            if not score_text or not score_text.isdigit() or not 0 <= int(score_text) <= 100:
                raise ValueError(f"record {index - 1}: rename/copy score is invalid")
            score = int(score_text)
        else:
            if score_text:
                raise ValueError(f"record {index - 1}: score is forbidden for status {status}")
            score = None
        source_path: str | None = None
        path = first_path
        if status in {"R", "C"}:
            if index >= len(fields):
                raise ValueError(f"record {index - 1}: missing rename/copy destination")
            source_path = first_path
            try:
                path = fields[index].decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError(f"record {index}: path is not UTF-8") from error
            index += 1
        if not _safe_tree_path(path) or (source_path is not None and not _safe_tree_path(source_path)):
            raise ValueError(f"record {index - 1}: noncanonical tree path")
        kind = {"A": "add", "M": "modify", "D": "delete", "R": "rename", "C": "copy", "T": "type-change"}[status]
        effects.append(ChangeEffect(kind, path, old_mode, new_mode, old_oid, new_oid, source_path, score))
    return tuple(sorted(effects, key=lambda effect: _canonical_bytes(_effect_payload(effect))))


def inspect_repository_changes(
    root: Path,
    trusted_base_revision: str,
    candidate_revision: str,
    trusted_policy: TrustedPolicyInput,
) -> tuple[Inspection | None, tuple[ProtectedError, ...]]:
    errors: list[ProtectedError] = []
    try:
        base, base_tree = _resolve_commit(root, trusted_base_revision, "trusted-base")
    except (OSError, ValueError) as error:
        errors.append(
            ProtectedError(
                "PROT-001",
                "trusted base is unavailable or invalid",
                {"object_id": trusted_base_revision, "error": str(error)},
            )
        )
        base = base_tree = ""
    try:
        candidate, candidate_tree = _resolve_commit(root, candidate_revision, "candidate")
    except (OSError, ValueError) as error:
        errors.append(
            ProtectedError(
                "PROT-002",
                "candidate is unavailable or invalid",
                {"object_id": candidate_revision, "error": str(error)},
            )
        )
        candidate = candidate_tree = ""
    if errors:
        return None, tuple(errors)
    try:
        if trusted_policy.identity != git_blob_oid(trusted_policy.policy_bytes):
            raise ValueError("protected caller policy Git blob identity does not match bytes")
        policy_digest = f"sha256:{hashlib.sha256(trusted_policy.policy_bytes).hexdigest()}"
        if trusted_policy.policy_digest != policy_digest:
            raise ValueError("protected caller policy digest does not match bytes")
        schema_digest = f"sha256:{hashlib.sha256(trusted_policy.schema_bytes).hexdigest()}"
        if trusted_policy.schema_digest != schema_digest:
            raise ValueError("protected caller policy schema digest does not match bytes")
        policy_bytes = trusted_policy.policy_bytes
        schema_bytes = trusted_policy.schema_bytes
        policy_oid = trusted_policy.identity
        policy = json.loads(policy_bytes)
        schema = json.loads(schema_bytes)
        Draft202012Validator.check_schema(schema)
        schema_errors = sorted(Draft202012Validator(schema).iter_errors(policy), key=lambda item: item.message)
        if schema_errors:
            raise ValueError(schema_errors[0].message)
        with tempfile.TemporaryDirectory() as directory:
            schema_path = Path(directory) / "protected-assets.schema.json"
            schema_path.write_bytes(schema_bytes)
            semantic_errors = validate_policy(policy, schema_path)
        if semantic_errors:
            return None, semantic_errors
        raw = _git(
            root,
            "diff-tree",
            "--no-commit-id",
            "-r",
            "--raw",
            "-z",
            "-M50%",
            "-C50%",
            "--find-copies-harder",
            base,
            candidate,
            "--",
        )
    except (OSError, ValueError, json.JSONDecodeError, TypeError, SchemaError) as error:
        return None, (
            ProtectedError(
                "PROT-001",
                "trusted policy or change analysis failed",
                {"trusted_base_revision": base, "error": str(error)},
            ),
        )
    try:
        direct_effects = _parse_raw_diff(raw)
        effects = _inferred_effects(policy, direct_effects)
    except ValueError as error:
        return None, (
            ProtectedError(
                "PROT-002",
                "candidate changed-path record is invalid",
                {"candidate_revision": candidate, "error": str(error)},
            ),
        )
    identity = {
        "trusted_base_revision": base,
        "trusted_base_tree": base_tree,
        "candidate_revision": candidate,
        "candidate_tree": candidate_tree,
        "trusted_policy_oid": policy_oid,
        "trusted_policy_digest": policy_digest,
    }
    digest = compute_change_digest(base, base_tree, candidate, candidate_tree, policy_oid, policy_digest, effects)
    return Inspection(identity, effects, digest, policy), ()


def _inferred_effects(policy: dict[str, Any], direct: tuple[ChangeEffect, ...]) -> tuple[ChangeEffect, ...]:
    effects = list(direct)
    active_paths = {effect.path for effect in direct} | {effect.source_path for effect in direct if effect.source_path}
    activated = {effect.inferred_by for effect in direct if effect.inferred_by is not None}
    changed = True
    while changed:
        changed = False
        for rule in policy.get("generated_rules", []):
            rule_id = rule["id"]
            if rule_id in activated:
                continue
            if any(
                any(contains(trigger, path) or contains(path, trigger) for trigger in rule["trigger_paths"])
                for path in active_paths
            ):
                activated.add(rule_id)
                for output in rule["output_paths"]:
                    effects.append(
                        ChangeEffect("generated", output, "000000", "000000", "0" * 40, "0" * 40, inferred_by=rule_id)
                    )
                    active_paths.add(output)
                changed = True
    return tuple(sorted(effects, key=lambda effect: _canonical_bytes(_effect_payload(effect))))


def _protected_paths(policy: dict[str, Any], effects: tuple[ChangeEffect, ...]) -> tuple[tuple[str, ChangeEffect], ...]:
    scopes = [path for scope in policy["protected_scopes"] for path in scope["paths"]]
    matches: list[tuple[str, ChangeEffect]] = []
    for effect in effects:
        for endpoint in [effect.source_path, effect.path]:
            if endpoint is not None and any(contains(scope, endpoint) for scope in scopes):
                matches.append((endpoint, effect))
    return tuple(sorted(matches, key=lambda item: (item[0], _canonical_bytes(_effect_payload(item[1])))))


def evaluate_protected_changes(
    policy: dict[str, Any],
    effects: tuple[ChangeEffect, ...],
    identity: dict[str, str],
    change_set_digest: str,
    contract_digest: str,
    authorization: AuthorizationContext | None,
) -> tuple[ProtectedError, ...]:
    if not DIGEST.fullmatch(contract_digest):
        return (ProtectedError("PROT-004", "contract digest is invalid", {}),)
    protected = _protected_paths(policy, effects)
    if not protected:
        return ()
    protected_paths = sorted({path for path, _effect in protected})
    remediation = str(policy["remediation"])
    if authorization is None:
        return tuple(
            ProtectedError(
                "PROT-003",
                "protected asset change lacks trusted human authorization",
                {
                    "path": path,
                    "change_kind": effect.kind,
                    "trusted_base_revision": identity["trusted_base_revision"],
                    "remediation": remediation,
                },
            )
            for path, effect in protected
        )
    envelope = authorization.envelope
    required_fields = {
        "schema_version",
        "authorization_id",
        "contract_digest",
        "source_revision",
        "trusted_base_revision",
        "trusted_base_tree",
        "candidate_revision",
        "candidate_tree",
        "trusted_policy_oid",
        "trusted_policy_digest",
        "change_set_digest",
        "authorized_protected_paths",
        "approval_anchor_revision",
        "approver_kind",
        "provenance_digest",
    }
    if set(envelope) != required_fields:
        return (
            ProtectedError(
                "PROT-004",
                "trusted authorization envelope fields are invalid",
                {
                    "missing": sorted(required_fields - set(envelope)),
                    "unknown": sorted(set(envelope) - required_fields),
                },
            ),
        )
    expected: dict[str, object] = {
        "schema_version": "2.0.0",
        "contract_digest": contract_digest,
        "source_revision": identity["trusted_base_revision"],
        **identity,
        "change_set_digest": change_set_digest,
        "authorized_protected_paths": protected_paths,
        "approval_anchor_revision": authorization.approval_anchor_revision,
        "approver_kind": "human",
        "provenance_digest": compute_provenance_digest(envelope),
    }
    mismatches = [field for field, value in expected.items() if envelope.get(field) != value]
    if authorization.approval_anchor_revision in {identity["trusted_base_revision"], identity["candidate_revision"]}:
        mismatches.append("approval_anchor_revision")
    if mismatches:
        return (
            ProtectedError(
                "PROT-004",
                "trusted authorization does not bind the exact protected change",
                {
                    "fields": sorted(set(mismatches)),
                    "trusted_base_revision": identity["trusted_base_revision"],
                    "remediation": remediation,
                },
            ),
        )
    return ()

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError, ValidationError  # type: ignore[import-untyped]

SHA = re.compile(r"^[0-9a-f]{40}$")
SAFE_PATH = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.?/)(?!.*\\)(?!.*//)[A-Za-z0-9._/-]+$")
EVENTS = frozenset({"pull-request", "push-branch", "push-main", "schedule", "workflow-dispatch", "release"})
Verdict = Literal["pass", "contract-invalid"]


@dataclass(frozen=True, slots=True)
class Change:
    kind: str
    path: str
    source_path: str | None = None


@dataclass(frozen=True, slots=True)
class PlannerFinding:
    code: str
    message: str
    context: dict[str, object]


@dataclass(frozen=True, slots=True)
class TierExecution:
    tier_id: str
    command: tuple[str, ...]
    runner_class: str
    minimum_memory_gib: int
    minimum_logical_cpus: int


@dataclass(frozen=True, slots=True)
class CiPlan:
    verdict: Verdict
    base_revision: str
    head_revision: str
    event_class: str
    changed_paths: tuple[str, ...]
    required_tiers: tuple[str, ...]
    not_applicable_tiers: tuple[str, ...]
    commands: tuple[tuple[str, ...], ...]
    executions: tuple[TierExecution, ...]
    findings: tuple[PlannerFinding, ...]

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": "1.0.0",
            "verdict": self.verdict,
            "base_revision": self.base_revision,
            "head_revision": self.head_revision,
            "event_class": self.event_class,
            "changed_paths": list(self.changed_paths),
            "required_tiers": list(self.required_tiers),
            "not_applicable_tiers": list(self.not_applicable_tiers),
            "commands": [list(item) for item in self.commands],
            "executions": [
                {
                    "tier_id": item.tier_id,
                    "command": list(item.command),
                    "runner_class": item.runner_class,
                    "minimum_memory_gib": item.minimum_memory_gib,
                    "minimum_logical_cpus": item.minimum_logical_cpus,
                }
                for item in self.executions
            ],
            "findings": [
                {"code": item.code, "message": item.message, "context": dict(sorted(item.context.items()))}
                for item in self.findings
            ],
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        payload["plan_digest"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
        return payload


def _schema_errors(instance: object, schema: dict[str, Any], kind: str) -> None:
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(instance),
        key=lambda item: (tuple(str(part) for part in item.absolute_path), item.message),
    )
    if errors:
        path = "/".join(str(part) for part in errors[0].absolute_path)
        raise ValueError(f"{kind} is schema-invalid at {path}: {errors[0].message}")


def load_ci_controls(
    policy_path: Path,
    policy_schema_path: Path,
    registry_path: Path,
    registry_schema_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        policy = json.loads(policy_path.read_bytes())
        policy_schema = json.loads(policy_schema_path.read_bytes())
        registry = json.loads(registry_path.read_bytes())
        registry_schema = json.loads(registry_schema_path.read_bytes())
        if not all(isinstance(item, dict) for item in (policy, policy_schema, registry, registry_schema)):
            raise ValueError("CI controls and schemas must be objects")
        _schema_errors(policy, policy_schema, "CI tier policy")
        _schema_errors(registry, registry_schema, "required-check registry")
        _validate_semantics(policy, registry)
        return policy, registry
    except (OSError, TypeError, json.JSONDecodeError, SchemaError) as error:
        raise ValueError("CI planning controls are unavailable or invalid") from error


def _validate_semantics(policy: dict[str, Any], registry: dict[str, Any]) -> None:
    tiers = policy["tiers"]
    tier_ids = [item["tier_id"] for item in tiers]
    registry_ids = [item["tier_id"] for item in registry["tiers"]]
    if tier_ids != registry_ids or len(tier_ids) != len(set(tier_ids)):
        raise ValueError("CI policy tier inventory differs from required-check registry")
    known = set(tier_ids)
    for item in tiers:
        if item["tier_id"] in item["prerequisites"] or not set(item["prerequisites"]) <= known:
            raise ValueError("CI tier prerequisite is unknown or self-referential")
    visiting: set[str] = set()
    visited: set[str] = set()
    graph = {item["tier_id"]: tuple(item["prerequisites"]) for item in tiers}

    def visit(tier_id: str) -> None:
        if tier_id in visiting:
            raise ValueError("CI tier prerequisites contain a cycle")
        if tier_id in visited:
            return
        visiting.add(tier_id)
        for prerequisite in graph[tier_id]:
            visit(prerequisite)
        visiting.remove(tier_id)
        visited.add(tier_id)

    for tier_id in tier_ids:
        visit(tier_id)


def plan_ci(
    policy: dict[str, Any],
    registry: dict[str, Any],
    changes: tuple[Change, ...],
    available_paths: frozenset[str],
    suite_inventories: dict[str, tuple[str, ...]] | None = None,
    *,
    event_class: str,
    base_revision: str,
    head_revision: str,
) -> CiPlan:
    _validate_semantics(policy, registry)
    if event_class not in EVENTS or not SHA.fullmatch(base_revision) or not SHA.fullmatch(head_revision):
        raise ValueError("CI plan identity or event class is invalid")
    paths = sorted(
        {
            path
            for change in changes
            for path in (change.path, change.source_path)
            if path is not None and SAFE_PATH.fullmatch(path)
        }
    )
    if any(
        not SAFE_PATH.fullmatch(path)
        for change in changes
        for path in (change.path, change.source_path)
        if path is not None
    ):
        raise ValueError("changed path is unsafe or noncanonical")
    tiers = policy["tiers"]
    by_id = {item["tier_id"]: item for item in tiers}
    required: set[str] = set()
    for item in tiers:
        event_matches = event_class in item["event_classes"]
        path_matches = any(
            path == prefix or path.startswith(prefix + "/") for prefix in item["path_prefixes"] for path in paths
        )
        artifact_matches = any(path in item["required_artifacts"] for path in paths)
        if artifact_matches or (event_matches and (path_matches or not item["path_prefixes"])):
            required.add(item["tier_id"])

    def add_prerequisites(tier_id: str) -> None:
        for prerequisite in by_id[tier_id]["prerequisites"]:
            if prerequisite not in required:
                required.add(prerequisite)
                add_prerequisites(prerequisite)

    for tier_id in tuple(required):
        add_prerequisites(tier_id)

    registry_by_id = {item["tier_id"]: item for item in registry["tiers"]}
    findings: list[PlannerFinding] = []
    commands: list[tuple[str, ...]] = []
    executions: list[TierExecution] = []
    ordered_required = tuple(item["tier_id"] for item in tiers if item["tier_id"] in required)
    for tier_id in ordered_required:
        item = by_id[tier_id]
        missing = sorted(set(item["required_artifacts"]) - available_paths)
        if missing:
            findings.append(
                PlannerFinding(
                    "CI-PLAN-002",
                    "applicable tier is missing its canonical manifest or runner",
                    {"tier_id": tier_id, "missing_paths": missing},
                )
            )
        if registry_by_id[tier_id]["activation"] != "active":
            findings.append(
                PlannerFinding(
                    "CI-PLAN-003",
                    "applicable tier remains reserved in the required-check registry",
                    {"tier_id": tier_id},
                )
            )
        inventory = (suite_inventories or {}).get(tier_id, ())
        if tier_id != "fast" and not inventory:
            findings.append(
                PlannerFinding(
                    "CI-PLAN-004",
                    "applicable product suite manifest has an empty or invalid validation inventory",
                    {"tier_id": tier_id},
                )
            )
        if not missing and registry_by_id[tier_id]["activation"] == "active" and (tier_id == "fast" or bool(inventory)):
            command = tuple(item["command"])
            runner = registry_by_id[tier_id]["runner"]
            commands.append(command)
            executions.append(
                TierExecution(
                    tier_id,
                    command,
                    runner["class"],
                    runner["minimum_memory_gib"],
                    runner["minimum_logical_cpus"],
                )
            )
    findings.sort(key=lambda item: (item.code, str(item.context.get("tier_id", ""))))
    all_ids = tuple(item["tier_id"] for item in tiers)
    return CiPlan(
        "contract-invalid" if findings else "pass",
        base_revision,
        head_revision,
        event_class,
        tuple(paths),
        ordered_required,
        tuple(tier_id for tier_id in all_ids if tier_id not in required),
        tuple(commands),
        tuple(executions),
        tuple(findings),
    )


def git_changes(root: Path, base_revision: str, head_revision: str) -> tuple[Change, ...]:
    if not SHA.fullmatch(base_revision) or not SHA.fullmatch(head_revision):
        raise ValueError("Git change identity is invalid")
    result = subprocess.run(
        ["git", "diff", "--name-status", "-z", "-M", "-C", "--find-copies-harder", base_revision, head_revision, "--"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    fields = result.stdout.split(b"\0")
    changes: list[Change] = []
    index = 0
    while index < len(fields) and fields[index]:
        status = fields[index].decode("ascii")
        index += 1
        if status.startswith(("R", "C")):
            source = fields[index].decode("utf-8")
            destination = fields[index + 1].decode("utf-8")
            index += 2
            changes.append(Change(status[0], destination, source))
        else:
            path = fields[index].decode("utf-8")
            index += 1
            changes.append(Change(status[0], path))
    return tuple(changes)


def git_paths(root: Path, revision: str) -> frozenset[str]:
    if not SHA.fullmatch(revision):
        raise ValueError("Git tree identity is invalid")
    result = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--name-only", revision],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return frozenset(item.decode("utf-8") for item in result.stdout.split(b"\0") if item)


def git_suite_inventories(root: Path, revision: str, policy: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    inventories: dict[str, tuple[str, ...]] = {}
    suite_schema_path = root / policy["suite_manifest_schema"]
    suite_schema = json.loads(suite_schema_path.read_bytes())
    suite_validator = Draft202012Validator(suite_schema)
    for item in policy["tiers"]:
        tier_id = item["tier_id"]
        if tier_id == "fast":
            continue
        manifest_path = item["required_artifacts"][0]
        result = subprocess.run(
            ["git", "show", f"{revision}:{manifest_path}"],
            cwd=root,
            check=False,
            capture_output=True,
        )
        if result.returncode:
            continue
        try:
            manifest = json.loads(result.stdout)
            suite_validator.validate(manifest)
            validations = manifest["validations"]
            ids = tuple(value["validation_id"] for value in validations)
            if (
                manifest.get("suite_id") == tier_id
                and ids
                and len(ids) == len(set(ids))
                and all(isinstance(value, str) and re.fullmatch(r"^[A-Z][A-Z0-9]*-[0-9]{3}$", value) for value in ids)
            ):
                inventories[tier_id] = ids
        except TypeError, KeyError, json.JSONDecodeError:
            continue
    return inventories


def worktree_snapshot(
    root: Path, base_revision: str, policy: dict[str, Any]
) -> tuple[tuple[Change, ...], frozenset[str], dict[str, tuple[str, ...]], str]:
    """Bind tracked, staged, and untracked local state without mutating the index."""
    changes = list(git_changes(root, base_revision, base_revision))
    result = subprocess.run(
        ["git", "diff", "--name-status", "-z", "-M", "-C", "--find-copies-harder", base_revision, "--"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    fields = result.stdout.split(b"\0")
    index = 0
    while index < len(fields) and fields[index]:
        status = fields[index].decode("ascii")
        index += 1
        if status.startswith(("R", "C")):
            source = fields[index].decode("utf-8")
            destination = fields[index + 1].decode("utf-8")
            index += 2
            changes.append(Change(status[0], destination, source))
        else:
            changes.append(Change(status[0], fields[index].decode("utf-8")))
            index += 1
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    known = {(item.path, item.source_path) for item in changes}
    for raw in untracked:
        if raw:
            change = Change("A", raw.decode("utf-8"))
            if (change.path, None) not in known:
                changes.append(change)
    listed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    paths = frozenset(raw.decode("utf-8") for raw in listed if raw and (root / raw.decode("utf-8")).exists())
    digest = hashlib.sha256()
    for change in sorted(changes, key=lambda item: (item.path, item.source_path or "", item.kind)):
        digest.update(json.dumps([change.kind, change.source_path, change.path], separators=(",", ":")).encode())
        candidate = root / change.path
        if candidate.is_file():
            digest.update(candidate.read_bytes())
        elif candidate.is_symlink():
            digest.update(candidate.readlink().as_posix().encode())
    inventories: dict[str, tuple[str, ...]] = {}
    suite_schema = json.loads((root / policy["suite_manifest_schema"]).read_bytes())
    suite_validator = Draft202012Validator(suite_schema)
    for item in policy["tiers"]:
        tier_id = item["tier_id"]
        if tier_id == "fast":
            continue
        manifest_path = root / item["required_artifacts"][0]
        if not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_bytes())
            suite_validator.validate(manifest)
            ids = tuple(value["validation_id"] for value in manifest["validations"])
            unsigned = dict(manifest)
            unsigned.pop("manifest_digest", None)
            manifest_digest = (
                "sha256:"
                + hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            )
            if (
                manifest.get("suite_id") == tier_id
                and manifest.get("manifest_digest") == manifest_digest
                and manifest.get("required_total") == sum(value["required_count"] for value in manifest["validations"])
                and ids
                and len(ids) == len(set(ids))
            ):
                inventories[tier_id] = ids
        except TypeError, KeyError, json.JSONDecodeError, OSError, ValidationError:
            continue
    return tuple(changes), paths, inventories, digest.hexdigest()[:40]

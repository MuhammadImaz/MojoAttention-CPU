#!/usr/bin/env python3
"""Execute an already validated CI argv plan without a shell boundary."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

SAFE_RELATIVE = __import__("re").compile(r"^(?!/)(?!.*(?:^|/)\.\.?/)(?!.*\\)(?!.*//)[A-Za-z0-9._/-]+$")


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_digest(value: dict[str, object], excluded: str) -> str:
    unsigned = dict(value)
    unsigned.pop(excluded, None)
    return _sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode())


def _untracked_state(root: Path) -> tuple[tuple[str, str], ...]:
    result = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    paths = [item.decode() for item in result.stdout.split(b"\0") if item]
    ignored = subprocess.run(
        ["git", "ls-files", "--others", "--ignored", "--exclude-standard", "-z", ".venv", ".tools"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    paths.extend(
        item.decode()
        for item in ignored.stdout.split(b"\0")
        if item and b"/__pycache__/" not in item and not item.endswith(b".pyc")
    )
    paths.sort()
    return tuple((path, _sha256((root / path).read_bytes())) for path in paths if (root / path).is_file())


def _assert_candidate_unchanged(root: Path, initial_untracked: tuple[tuple[str, str], ...]) -> None:
    if subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=root, check=False).returncode:
        raise ValueError("candidate tracked bytes changed after plan authentication")
    if _untracked_state(root) != initial_untracked:
        raise ValueError("candidate untracked bytes changed after plan authentication")


def _verify_product_result(execution: dict[str, object], stdout: bytes, root: Path) -> None:
    manifest = execution.get("manifest")
    if not isinstance(manifest, dict):
        raise ValueError("product execution lacks its sealed manifest")
    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise ValueError("product command did not emit one canonical JSON result") from error
    if not isinstance(result, dict) or result.get("schema_version") != "1.0.0":
        raise ValueError("product result is not a canonical object")
    if set(result) != {
        "schema_version",
        "suite_id",
        "manifest_digest",
        "verdict",
        "required_total",
        "observed_total",
        "skipped_total",
        "xfailed_total",
        "validations",
        "evidence",
    }:
        raise ValueError("product result contains missing or undeclared fields")
    manifest_digest = _canonical_digest(manifest, "manifest_digest")
    if manifest.get("manifest_digest") != manifest_digest:
        raise ValueError("sealed product manifest digest is invalid")
    declared = manifest.get("validations")
    observed = result.get("validations")
    if not isinstance(declared, list) or not isinstance(observed, list) or not declared:
        raise ValueError("product validation inventory is empty")
    expected = {item["validation_id"]: item["required_count"] for item in declared if isinstance(item, dict)}
    actual: dict[str, int] = {}
    for item in observed:
        if not isinstance(item, dict) or set(item) != {"validation_id", "observed_count", "status"}:
            raise ValueError("product observation is malformed")
        validation_id = item.get("validation_id")
        count = item.get("observed_count")
        if not isinstance(validation_id, str) or validation_id in actual:
            raise ValueError("product observations are duplicate or unidentified")
        if item.get("status") != "pass" or not isinstance(count, int) or isinstance(count, bool):
            raise ValueError("product observation is skipped, xfailed, failed, or uncounted")
        actual[validation_id] = count
    if actual != expected:
        raise ValueError("product observation inventory is missing, reduced, or forged")
    required_total = sum(expected.values())
    if (
        manifest.get("required_total") != required_total
        or result.get("required_total") != required_total
        or result.get("observed_total") != sum(actual.values())
        or result.get("suite_id") != execution.get("tier_id")
        or result.get("manifest_digest") != manifest_digest
        or result.get("verdict") != "pass"
        or result.get("skipped_total") != 0
        or result.get("xfailed_total") != 0
    ):
        raise ValueError("product aggregate counts, identity, or verdict do not close")
    evidence = result.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != {"entries", "evidence_digest"}:
        raise ValueError("product evidence closure is missing")
    entries = evidence.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("product evidence is empty")
    seen: set[str] = set()
    evidenced: dict[str, int] = {}
    resolved_root = root.resolve()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"validation_id", "observed_count", "path", "sha256"}:
            raise ValueError("product evidence entry is malformed")
        validation_id, evidence_count = entry.get("validation_id"), entry.get("observed_count")
        path, claimed = entry.get("path"), entry.get("sha256")
        if not isinstance(path, str) or SAFE_RELATIVE.fullmatch(path) is None or path in seen:
            raise ValueError("product evidence path is unsafe or duplicate")
        if (
            not isinstance(validation_id, str)
            or validation_id in evidenced
            or not isinstance(evidence_count, int)
            or isinstance(evidence_count, bool)
        ):
            raise ValueError("product evidence inventory is malformed or duplicate")
        seen.add(path)
        artifact = (root / path).resolve()
        if (
            not artifact.is_relative_to(resolved_root)
            or not artifact.is_file()
            or claimed != _sha256(artifact.read_bytes())
        ):
            raise ValueError("product evidence artifact is missing or digest-invalid")
        evidenced[validation_id] = evidence_count
    if evidenced != expected:
        raise ValueError("product evidence is not complete for the declared validation inventory")
    if evidence.get("evidence_digest") != _canonical_digest(evidence, "evidence_digest"):
        raise ValueError("product evidence digest does not close")


def _worktree_identity(root: Path, base: str) -> str:
    changes: list[tuple[str, str | None, str]] = []
    fields = subprocess.run(
        ["git", "diff", "--name-status", "-z", "-M", "-C", "--find-copies-harder", base, "--"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    index = 0
    while index < len(fields) and fields[index]:
        status = fields[index].decode("ascii")
        index += 1
        if status.startswith(("R", "C")):
            source, target = fields[index].decode(), fields[index + 1].decode()
            index += 2
            changes.append((status[0], source, target))
        else:
            changes.append((status[0], None, fields[index].decode()))
            index += 1
    known = {(target, source) for _kind, source, target in changes}
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=root, check=True, capture_output=True
    ).stdout.split(b"\0")
    for raw in untracked:
        if raw and (raw.decode(), None) not in known:
            changes.append(("A", None, raw.decode()))
    digest = hashlib.sha256()
    for kind, source, target in sorted(changes, key=lambda item: (item[2], item[1] or "", item[0])):
        digest.update(json.dumps([kind, source, target], separators=(",", ":")).encode())
        candidate = root / target
        if candidate.is_file():
            digest.update(candidate.read_bytes())
        elif candidate.is_symlink():
            digest.update(candidate.readlink().as_posix().encode())
    return digest.hexdigest()[:40]


def main(argv: list[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else argv
    skip_foundation = "--foundation-already-ran" in values[4:]
    receipt_path: Path | None = None
    if "--receipt" in values[4:]:
        receipt_index = values.index("--receipt", 4)
        if receipt_index + 1 >= len(values):
            return 64
        receipt_path = Path(values[receipt_index + 1])
    allowed_tail = (["--foundation-already-ran"] if skip_foundation else []) + (
        ["--receipt", str(receipt_path)] if receipt_path is not None else []
    )
    if len(values) < 4 or sorted(values[4:]) != sorted(allowed_tail):
        print(
            "usage: scripts/run_ci_plan.py PLAN EXPECTED_DIGEST PROJECT_ROOT CONTROL_ROOT "
            "[--foundation-already-ran] [--receipt PATH]",
            file=sys.stderr,
        )
        return 64
    plan_path, expected_digest, root, control_root = Path(values[0]), values[1], Path(values[2]), Path(values[3])
    try:
        plan = json.loads(plan_path.read_bytes())
        embedded_digest = plan.pop("plan_digest", None)
        canonical = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
        actual_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
        if embedded_digest != expected_digest or actual_digest != expected_digest:
            raise ValueError("trusted CI plan digest differs from authenticated decision")
        if plan.get("schema_version") != "1.0.0" or plan.get("verdict") != "pass":
            raise ValueError("only a passing canonical CI plan is executable")
        head = (
            _worktree_identity(root, str(plan.get("base_revision")))
            if plan.get("identity_kind") == "worktree"
            else subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
            ).stdout.strip()
        )
        if head != plan.get("head_revision"):
            raise ValueError("candidate checkout identity differs from the sealed plan")
        controls = plan.get("trusted_control_digests")
        if not isinstance(controls, dict) or not controls:
            raise ValueError("sealed plan lacks trusted control identities")
        for relative, claimed in controls.items():
            if not isinstance(relative, str) or SAFE_RELATIVE.fullmatch(relative) is None:
                raise ValueError("trusted control path is invalid")
            path = control_root / relative
            if not path.is_file() or claimed != _sha256(path.read_bytes()):
                raise ValueError("trusted control identity changed before dispatch")
        executions = plan.get("executions")
        if not isinstance(executions, list) or not executions:
            raise ValueError("passing CI plan must contain at least Foundation")
        memory_kib = int(
            next(
                line.split()[1]
                for line in Path("/proc/meminfo").read_text().splitlines()
                if line.startswith("MemTotal:")
            )
        )
        memory_gib = memory_kib / 1024 / 1024
        cpus = os.cpu_count() or 0
        initial_untracked = _untracked_state(root)
        completed_commands: list[list[str]] = []
        for execution in executions:
            if not isinstance(execution, dict):
                raise ValueError("CI plan execution is invalid")
            command = execution.get("command")
            if (
                not isinstance(command, list)
                or len(command) < 2
                or not all(isinstance(item, str) and item and "\0" not in item for item in command)
            ):
                raise ValueError("CI plan command is invalid")
            if memory_gib < execution.get("minimum_memory_gib", 0) or cpus < execution.get("minimum_logical_cpus", 0):
                print(
                    f"infrastructure-invalid: runner capacity is below {execution.get('tier_id')} prerequisites",
                    file=sys.stderr,
                )
                return 2
            if execution.get("tier_id") == "fast" and skip_foundation:
                continue
            if plan.get("identity_kind") != "worktree":
                _assert_candidate_unchanged(root, initial_untracked)
            if execution.get("tier_id") == "fast":
                subprocess.run(command, cwd=root, check=True)
            else:
                completed = subprocess.run(command, cwd=root, check=True, capture_output=True)
                _verify_product_result(execution, completed.stdout, root)
            if plan.get("identity_kind") != "worktree":
                _assert_candidate_unchanged(root, initial_untracked)
            completed_commands.append(command)
        if receipt_path is not None:
            foundation = json.loads((root / "contracts/validation-suites/foundation.json").read_bytes())
            receipt = {
                "schema_version": "1.0.0",
                "verdict": "pass",
                "head_sha": plan["head_revision"],
                "base_sha": plan["base_revision"],
                "plan_digest": expected_digest,
                "dispatcher_digest": _sha256(Path(__file__).read_bytes()),
                "command": ["scripts/quality.sh", "--ci"],
                "validations": [
                    {"validation_id": item["validation_id"], "case_id": item["case_id"], "status": "pass"}
                    for item in foundation["validations"]
                ],
            }
            if ["scripts/quality.sh", "--ci"] not in completed_commands:
                raise ValueError("Foundation command was not observed by the trusted dispatcher")
            receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    except subprocess.CalledProcessError as error:
        print(f"CI product execution failed: {error}", file=sys.stderr)
        return error.returncode if error.returncode in {1, 2, 3, 64} else 1
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"CI plan execution failed: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

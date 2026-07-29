from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from contextlib import suppress
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

from mojoattention.config import ProjectPolicy
from mojoattention.validation.acceptance import ContractContext, ContractError, validate_contract
from mojoattention.validation.authority import authorize_read, validate_manifest
from mojoattention.validation.evidence import EXIT_CODES as EVIDENCE_EXIT_CODES
from mojoattention.validation.evidence import (
    Attachment,
    EvidenceWriter,
    canonical_bytes,
    read_approved_attachment,
    verify_evidence,
)
from mojoattention.validation.fast import (
    FAST_PROTOCOL_DIGEST,
    AdapterResult,
    CheckAdapter,
    FastCheck,
    FastError,
    FastRunResult,
    evidence_validations,
    execute_checks,
    load_manifest,
    run_bounded_argv,
    verify_fast_evidence,
)
from mojoattention.validation.fast_canaries import execute_false_green_canary
from mojoattention.validation.host import probe
from mojoattention.validation.identity import detect_identity, evaluate_identity, require_clean_candidate
from mojoattention.validation.paths import contains
from mojoattention.validation.preflight import evaluate, render_json
from mojoattention.validation.privacy import find_forbidden_tracked_paths, tracked_paths
from mojoattention.validation.protected_assets import (
    AuthorizationContext,
    ProtectedError,
    TrustedPolicyInput,
    evaluate_and_compose_trusted_context,
    evaluate_protected_changes,
    inspect_repository_changes,
    load_trusted_authorization,
)


class ProjectArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(64, f"{self.prog}: error: {message}\n")


def _is_project_root(path: Path) -> bool:
    config = path / "pyproject.toml"
    try:
        return config.is_file() and 'name = "mojoattention-cpu"' in config.read_text(encoding="utf-8")
    except OSError:
        return False


def _root() -> Path:
    configured = os.environ.get("MOJOATTENTION_PROJECT_ROOT")
    if configured:
        try:
            resolved = Path(configured).resolve()
        except (OSError, RuntimeError) as error:
            raise RuntimeError("configured project root cannot be resolved") from error
        if _is_project_root(resolved):
            return resolved
        raise RuntimeError("configured project root is not a valid checkout")
    candidates = [Path.cwd(), *Path.cwd().parents, *Path(__file__).resolve().parents]
    for candidate in candidates:
        resolved = candidate.resolve()
        if _is_project_root(resolved):
            return resolved
    raise RuntimeError("project root not found; use scripts/run.sh from a valid checkout")


def _write_payload(payload: str, destination: str) -> bool:
    if destination == "-":
        sys.stdout.write(payload)
        return True
    target = Path(destination)
    temporary_name: str | None = None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=target.parent, delete=False) as temporary:
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, target)
        return True
    except OSError as error:
        if temporary_name is not None:
            with suppress(OSError):
                Path(temporary_name).unlink(missing_ok=True)
        print(f"CLI-JSON contract-invalid: cannot write {target}: {error}", file=sys.stderr)
        return False


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_protected_caller_bytes(root: Path, path_value: str) -> bytes:
    candidate_path = Path(path_value)
    lexical_path = candidate_path if candidate_path.is_absolute() else Path.cwd() / candidate_path
    resolved_root = root.resolve()
    if lexical_path.absolute().is_relative_to(resolved_root):
        raise OSError("trusted input must be outside the candidate checkout")
    path = candidate_path.absolute()
    if path.resolve(strict=True).is_relative_to(resolved_root):
        raise OSError("trusted input must be outside the candidate checkout")
    descriptors: list[int] = []
    try:
        current = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(current)
        for component in path.parts[1:-1]:
            current = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            descriptors.append(current)
        parent_before = [
            (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_nlink,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )
            for value in (os.fstat(item) for item in descriptors)
        ]
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current)
        try:
            before = os.fstat(descriptor)
            if not os.path.isfile(f"/proc/self/fd/{descriptor}") or before.st_nlink != 1:
                raise OSError("trusted input must be a single-link regular file")
            chunks: list[bytes] = []
            while block := os.read(descriptor, 1024 * 1024):
                chunks.append(block)
            after = os.fstat(descriptor)
            identity = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(before, name) != getattr(after, name) for name in identity):
                raise OSError("trusted input changed while being read")
            parent_after = [
                (
                    value.st_dev,
                    value.st_ino,
                    value.st_mode,
                    value.st_nlink,
                    value.st_size,
                    value.st_mtime_ns,
                    value.st_ctime_ns,
                )
                for value in (os.fstat(item) for item in descriptors)
            ]
            if parent_before != parent_after:
                raise OSError("trusted input parent changed while being read")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _candidate_blob(root: Path, revision: str, path: str) -> bytes:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_PAGER": "cat",
        "LC_ALL": "C",
    }
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=", "-c", "protocol.file.allow=never", "show", f"{revision}:{path}"],
        cwd=root,
        capture_output=True,
        check=False,
        env=environment,
    )
    if result.returncode != 0:
        raise ValueError("candidate control blob is unavailable")
    return result.stdout


def _trusted_blob(root: Path, revision: str, path: str) -> bytes:
    return _candidate_blob(root, revision, path)


def _fast_contract_inventory(contract: dict[str, Any], manifest: Any) -> None:
    if contract.get("schema_version") != "2.0.0":
        raise ValueError("Fast requires Acceptance Contract v2")
    expected = [
        {"validation_id": check.validation_id, "required_count": check.required_count} for check in manifest.checks
    ]
    suites = contract.get("required_suites")
    if suites != [{"suite_id": "fast", "validations": expected, "required_total": manifest.required_total}]:
        raise ValueError("Acceptance Contract Fast inventory differs from the trusted manifest")
    bindings = {
        "suite_manifest_digest": manifest.manifest_digest,
        "config_digest": manifest.config_digest,
    }
    for field, expected_value in bindings.items():
        if contract.get(field) != expected_value:
            raise ValueError(f"Acceptance Contract {field} differs from the trusted manifest")


def _foundation_adapters(
    root: Path,
    manifest: Any,
    *,
    authority_valid: bool,
    diagnostics: dict[str, bytes] | None = None,
) -> dict[str, CheckAdapter]:
    """Bind foundation IDs to work already validated or to bounded executors."""

    adapters: dict[str, CheckAdapter] = {}
    for check in manifest.checks:
        if check.kind != "foundation":
            continue
        if check.validation_id == "FAST-003":

            def static_adapter(item: FastCheck) -> AdapterResult:
                committed = subprocess.check_output(
                    ["git", "ls-tree", "-r", "-z", "--name-only", "HEAD"],
                    cwd=root,
                    env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1"},
                )
                python_paths = tuple(
                    f"./{path}"
                    for raw in committed.split(b"\0")
                    if raw
                    for path in (raw.decode("utf-8", errors="strict"),)
                    if path.endswith(".py")
                    and not path.startswith("/")
                    and "\\" not in path
                    and all(part not in {"", ".", ".."} for part in PurePosixPath(path).parts)
                )
                if not python_paths:
                    return AdapterResult.failed(
                        item,
                        "contract-invalid",
                        FastError("FAST-STATIC-001", "candidate commit contains no bounded Python inputs", {}),
                    )
                chunks: list[tuple[str, ...]] = []
                current: list[str] = []
                current_bytes = 0
                for path in python_paths:
                    encoded_size = len(path.encode("utf-8")) + 1
                    if current and (len(current) >= 256 or current_bytes + encoded_size > 60_000):
                        chunks.append(tuple(current))
                        current = []
                        current_bytes = 0
                    current.append(path)
                    current_bytes += encoded_size
                chunks.append(tuple(current))
                processes = [
                    run_bounded_argv(
                        ("ruff", "check", *chunk),
                        root,
                        manifest.runner_config,
                    )
                    for chunk in chunks
                ]
                if diagnostics is not None:
                    diagnostics[item.validation_id] = canonical_bytes(
                        {
                            "chunks": [
                                {
                                    "returncode": process.returncode,
                                    "output_truncated": process.output_truncated,
                                    "stdout": process.stdout.decode("utf-8", errors="replace"),
                                    "stderr": process.stderr.decode("utf-8", errors="replace"),
                                }
                                for process in processes
                            ],
                        },
                        newline=True,
                    )
                if failed := next((process for process in processes if process.error is not None), None):
                    assert failed.error is not None
                    return AdapterResult.failed(item, failed.failure_class or "product-fail", failed.error)
                return AdapterResult.passed(item)

            adapters[check.validation_id] = static_adapter
        elif check.validation_id == "FAST-004":

            def import_adapter(item: FastCheck) -> AdapterResult:
                process = run_bounded_argv(
                    (sys.executable, "-c", "import mojoattention"),
                    root,
                    manifest.runner_config,
                )
                if diagnostics is not None:
                    diagnostics[item.validation_id] = canonical_bytes(
                        {
                            "returncode": process.returncode,
                            "output_truncated": process.output_truncated,
                            "stdout": process.stdout.decode("utf-8", errors="replace"),
                            "stderr": process.stderr.decode("utf-8", errors="replace"),
                        },
                        newline=True,
                    )
                if process.error is not None:
                    return AdapterResult.failed(item, process.failure_class or "product-fail", process.error)
                return AdapterResult.passed(item)

            adapters[check.validation_id] = import_adapter
        elif check.validation_id == "FAST-005" and not authority_valid:
            adapters[check.validation_id] = lambda item: AdapterResult.failed(
                item,
                "contract-invalid",
                FastError("FAST-AUTH-001", "candidate authority controls are invalid", {}),
            )
        elif check.validation_id == "FAST-006":

            def path_adapter(item: FastCheck) -> AdapterResult:
                committed_paths = subprocess.check_output(
                    ["git", "ls-tree", "-r", "-z", "--name-only", "HEAD"],
                    cwd=root,
                    env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1"},
                )
                forbidden = find_forbidden_tracked_paths(committed_paths)
                if forbidden:
                    return AdapterResult.failed(
                        item,
                        "contract-invalid",
                        FastError(
                            "FAST-PATH-001",
                            "tracked paths violate public privacy policy",
                            {"count": len(forbidden)},
                        ),
                    )
                return AdapterResult.passed(item)

            adapters[check.validation_id] = path_adapter
        else:
            # FAST-001/002 were validated from immutable contract/schema bytes
            # before this map is created. FAST-007 is closed only after the
            # shared renderer and independent evidence verifier succeed below.
            adapters[check.validation_id] = AdapterResult.passed
    return adapters


def _attribute_protected_errors(
    result: FastRunResult,
    protected_errors: tuple[ProtectedError, ...],
) -> FastRunResult:
    if not protected_errors:
        return result
    index = next(
        index for index, observation in enumerate(result.observations) if observation.validation_id == "FAST-013"
    )
    observation = result.observations[index]
    rejected = type(observation)(
        observation.validation_id,
        observation.case_id,
        observation.seed,
        observation.selected,
        observation.collected,
        observation.completed,
        observation.skipped,
        observation.xfailed,
        observation.deselected,
        observation.collection_errors,
        observation.shard_index,
        observation.shard_total,
        "fail",
        "contract-invalid",
    )
    errors = tuple(
        FastError(item.code, item.message, {**item.context, "validation_id": "FAST-013"}) for item in protected_errors
    )
    return FastRunResult(
        "contract-invalid",
        (*result.observations[:index], rejected, *result.observations[index + 1 :]),
        errors,
        result.elapsed_ns,
    )


def run_fast_validation(
    root: Path,
    contract_path: str,
    output: Path,
    *,
    trusted_base_path: str,
    trusted_policy_path: str,
    trusted_policy_schema_path: str,
    authorization_path: str,
    authorization_schema_path: str,
    approval_anchor_revision: str,
) -> tuple[str, Path, tuple[FastError, ...]]:
    """Run the authenticated Fast orchestration and publish one verified closure."""

    writer: EvidenceWriter | None = None
    contract_bytes = _read_protected_caller_bytes(root, contract_path)
    contract = json.loads(contract_bytes)
    if not isinstance(contract, dict):
        raise ValueError("Acceptance Contract must be an object")
    candidate_revision = str(contract.get("source_revision", ""))
    trusted_base_revision = str(contract.get("trusted_base_revision", ""))
    _require_candidate_checkout(root, candidate_revision)

    trusted_base = json.loads(_read_protected_caller_bytes(root, trusted_base_path))
    if not isinstance(trusted_base, dict) or set(trusted_base) != {
        "trusted_base_revision",
        "trusted_base_tree",
        "trusted_policy_identity",
        "trusted_policy_digest",
        "trusted_policy_schema_digest",
    }:
        raise ValueError("trusted-base anchor is invalid")
    if trusted_base["trusted_base_revision"] != trusted_base_revision:
        raise ValueError("contract trusted base differs from authenticated anchor")
    base_tree = subprocess.run(
        ["git", "rev-parse", f"{trusted_base_revision}^{{tree}}"],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
        env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1"},
    )
    if base_tree.returncode != 0 or base_tree.stdout.strip() != trusted_base["trusted_base_tree"]:
        raise ValueError("authenticated trusted-base tree differs from Git")
    policy_bytes = _read_protected_caller_bytes(root, trusted_policy_path)
    policy_schema = _read_protected_caller_bytes(root, trusted_policy_schema_path)
    trusted_policy = TrustedPolicyInput(
        policy_bytes,
        policy_schema,
        str(trusted_base["trusted_policy_identity"]),
        str(trusted_base["trusted_policy_digest"]),
        str(trusted_base["trusted_policy_schema_digest"]),
    )
    authorization_bytes = _read_protected_caller_bytes(root, authorization_path)
    authorization_schema = _read_protected_caller_bytes(root, authorization_schema_path)
    authorization_envelope, authorization_errors = load_trusted_authorization(
        authorization_bytes,
        authorization_schema,
    )
    if authorization_errors or authorization_envelope is None:
        raise ValueError("protected-change authorization is invalid")
    authorization = AuthorizationContext(
        envelope=authorization_envelope,
        approval_anchor_revision=approval_anchor_revision,
        contract_digest=str(contract.get("contract_digest", "")),
    )

    manifest_bytes = _trusted_blob(root, trusted_base_revision, "contracts/validation-suites/fast.json")
    manifest_schema = _trusted_blob(root, trusted_base_revision, "schemas/validation-suite.schema.json")
    # Candidate-owned authority and evidence interfaces are acquired once from
    # the bound commit, never from mutable worktree bytes after execution.
    authority_bytes = _candidate_blob(root, candidate_revision, "contracts/agent-authority.json")
    authority_schema = _candidate_blob(root, candidate_revision, "schemas/agent-authority.schema.json")
    acceptance_schema = _candidate_blob(root, candidate_revision, "schemas/acceptance-contract.schema.json")
    evidence_schema = _candidate_blob(root, candidate_revision, "schemas/validation-evidence.schema.json")
    authority_manifest = json.loads(authority_bytes)
    authority_errors = validate_manifest(authority_manifest, root, schema_bytes=authority_schema)
    if authority_errors:
        raise ValueError("candidate authority controls are invalid")
    json.loads(evidence_schema)

    manifest = load_manifest(manifest_bytes, manifest_schema)
    _fast_contract_inventory(contract, manifest)
    if contract.get("protocol_digest") != FAST_PROTOCOL_DIGEST:
        raise ValueError("Acceptance Contract protocol_digest differs from the runner protocol")
    contract_errors = validate_contract(
        contract,
        root,
        ContractContext(
            source_revision=candidate_revision,
            trusted_base_revision=trusted_base_revision,
            prior_validation_identity=None,
        ),
        schema_bytes=acceptance_schema,
    )
    if contract_errors:
        raise ValueError("Acceptance Contract is invalid")

    bounded_context = {
        "suite_id": manifest.suite_id,
        "contract_digest": contract["contract_digest"],
        "suite_manifest_digest": manifest.manifest_digest,
        "config_digest": manifest.config_digest,
        "protocol_digest": FAST_PROTOCOL_DIGEST,
        "declared_case_ids": [item.case_id for item in manifest.checks],
        "declared_validation_ids": [item.validation_id for item in manifest.checks],
        "seed": manifest.seed,
        "producer": {"name": "mojoattention", "version": "1.0.0"},
        "environment": {
            "os": sys.platform.replace("_", "-"),
            "architecture": os.uname().machine.replace("_", "-"),
            "python_version": ".".join(str(item) for item in sys.version_info[:3]),
            "reference_host": "unverified",
        },
    }
    trusted_context, protected_errors = evaluate_and_compose_trusted_context(
        root,
        trusted_base_revision,
        candidate_revision,
        trusted_policy,
        contract["contract_digest"],
        bounded_context,
        authorization,
    )
    if trusted_context is None:
        raise ValueError("trusted Fast controls could not be acquired")

    diagnostics: dict[str, bytes] = {}
    adapters = _foundation_adapters(
        root,
        manifest,
        authority_valid=not authority_errors,
        diagnostics=diagnostics,
    )
    with tempfile.TemporaryDirectory(prefix="mojoattention-fast-canaries-") as canary_directory:

        def canary_adapter(check: FastCheck) -> AdapterResult:
            return execute_false_green_canary(check, Path(canary_directory), trusted_policy)

        for item in manifest.checks:
            if item.kind == "canary":
                adapters[item.validation_id] = canary_adapter
        result = execute_checks(manifest, adapters)
    if protected_errors:
        result = _attribute_protected_errors(result, protected_errors)
    _require_candidate_checkout(root, candidate_revision)
    try:
        writer = EvidenceWriter(output, trusted_context)
        attachment_paths = {
            validation_id: (f"diagnostics/{validation_id.lower()}.json",) for validation_id in diagnostics
        }
        leaves = [
            writer.snapshot_bytes(
                payload,
                attachment_paths[validation_id][0],
                "application/json",
            )
            for validation_id, payload in sorted(diagnostics.items())
        ]
        validations = evidence_validations(
            result,
            {item.validation_id: item.reproduction_argv for item in manifest.checks},
            reference_target_ns=manifest.reference_target_ns,
            attachment_paths=attachment_paths,
        )
        complete = writer.finalize(
            verdict=result.verdict,
            validations=validations,
            attachments=leaves,
            schema_path=evidence_schema,
        )
        verified = verify_evidence(complete, evidence_schema)
        if verified.errors or verified.manifest is None:
            raise OSError("published Fast evidence failed independent verification")
        if closure_errors := verify_fast_evidence(
            manifest,
            result,
            verified.manifest,
            attachment_paths=attachment_paths,
        ):
            raise OSError(closure_errors[0].message)
        _require_candidate_checkout(root, candidate_revision)
        return result.verdict, complete, result.errors
    finally:
        if writer is not None:
            with suppress(OSError):
                writer.abort()


def _require_candidate_checkout(root: Path, revision: str) -> None:
    require_clean_candidate(root, revision)


def build_parser() -> argparse.ArgumentParser:
    parser = ProjectArgumentParser(prog="mojoattention")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=ProjectArgumentParser)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--mode", choices=("baseline", "broad"), default="baseline")
    preflight.add_argument("--json", dest="json_path", default="-", metavar="PATH")
    environment = commands.add_parser("environment")
    environment.add_argument("--json", dest="json_path", default="-", metavar="PATH")
    privacy = commands.add_parser("privacy")
    privacy.add_argument("--json", dest="json_path", default="-", metavar="PATH")
    authority = commands.add_parser("authority")
    authority.add_argument("--json", dest="json_path", default="-", metavar="PATH")
    contract = commands.add_parser("contract")
    contract_commands = contract.add_subparsers(
        dest="contract_command",
        required=True,
        parser_class=ProjectArgumentParser,
    )
    contract_validate = contract_commands.add_parser("validate")
    contract_validate.add_argument("--contract", dest="contract_path", required=True, metavar="PATH")
    contract_validate.add_argument("--source-revision", required=True, metavar="SHA")
    contract_validate.add_argument("--trusted-base-revision", required=True, metavar="SHA")
    contract_validate.add_argument("--prior-validation-identity", default=None, metavar="ID")
    contract_validate.add_argument("--authorization", dest="authorization_path", metavar="PATH")
    contract_validate.add_argument("--approval-anchor-revision", metavar="SHA")
    contract_validate.add_argument("--json", dest="json_path", default="-", metavar="PATH")
    protected = commands.add_parser("protected")
    protected_commands = protected.add_subparsers(
        dest="protected_command", required=True, parser_class=ProjectArgumentParser
    )
    protected_validate = protected_commands.add_parser("validate")
    protected_validate.add_argument("--trusted-base-revision", required=True, metavar="SHA")
    protected_validate.add_argument("--candidate-revision", required=True, metavar="SHA")
    protected_validate.add_argument("--contract-digest", required=True, metavar="DIGEST")
    protected_validate.add_argument("--trusted-policy", required=True, metavar="PATH")
    protected_validate.add_argument("--trusted-policy-schema", required=True, metavar="PATH")
    protected_validate.add_argument("--trusted-policy-identity", required=True, metavar="OID")
    protected_validate.add_argument("--trusted-policy-digest", required=True, metavar="DIGEST")
    protected_validate.add_argument("--trusted-policy-schema-digest", required=True, metavar="DIGEST")
    protected_validate.add_argument("--authorization", metavar="PATH")
    protected_validate.add_argument("--trusted-authorization-schema", metavar="PATH")
    protected_validate.add_argument("--approval-anchor-revision", metavar="SHA")
    protected_validate.add_argument("--json", dest="json_path", default="-", metavar="PATH")
    evidence = commands.add_parser("evidence")
    evidence_commands = evidence.add_subparsers(
        dest="evidence_command", required=True, parser_class=ProjectArgumentParser
    )
    for name in ("verify", "inspect"):
        evidence_read = evidence_commands.add_parser(name)
        evidence_read.add_argument("--run", required=True, metavar="PATH")
        evidence_read.add_argument("--json", dest="json_path", default="-", metavar="PATH")
    evidence_produce = evidence_commands.add_parser("produce")
    evidence_produce.add_argument("--trusted-request", required=True, metavar="PATH")
    evidence_produce.add_argument("--trusted-policy", required=True, metavar="PATH")
    evidence_produce.add_argument("--trusted-policy-schema", required=True, metavar="PATH")
    evidence_produce.add_argument("--trusted-policy-identity", required=True, metavar="OID")
    evidence_produce.add_argument("--trusted-policy-digest", required=True, metavar="DIGEST")
    evidence_produce.add_argument("--trusted-policy-schema-digest", required=True, metavar="DIGEST")
    evidence_produce.add_argument("--authorization", metavar="PATH")
    evidence_produce.add_argument("--trusted-authorization-schema", metavar="PATH")
    evidence_produce.add_argument("--approval-anchor-revision", metavar="SHA")
    evidence_produce.add_argument("--output", default="reports/runs", metavar="PATH")
    evidence_produce.add_argument("--json", dest="json_path", default="-", metavar="PATH")
    validate = commands.add_parser("validate")
    validate.add_argument("--suite", choices=("fast",), required=True)
    validate.add_argument("--contract", dest="contract_path", required=True, metavar="PATH")
    validate.add_argument("--trusted-base", required=True, metavar="PATH")
    validate.add_argument("--trusted-policy", required=True, metavar="PATH")
    validate.add_argument("--trusted-policy-schema", required=True, metavar="PATH")
    validate.add_argument("--authorization", required=True, metavar="PATH")
    validate.add_argument("--trusted-authorization-schema", required=True, metavar="PATH")
    validate.add_argument("--approval-anchor-revision", required=True, metavar="SHA")
    validate.add_argument("--output", default="reports/runs", metavar="PATH")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "validate":
        fast_payload: dict[str, Any]
        if args.output != "reports/runs":
            fast_payload = {
                "errors": [
                    {
                        "code": "FAST-CLI-001",
                        "message": "output must be the approved reports/runs root",
                        "context": {"output": args.output},
                    }
                ],
                "non_evidence": True,
                "verdict": "contract-invalid",
            }
            print("FAST-CLI-001 contract-invalid: output root rejected", file=sys.stderr)
            exit_code = EVIDENCE_EXIT_CODES["contract-invalid"]
        else:
            try:
                root = _root()
                verdict, complete, fast_errors = run_fast_validation(
                    root,
                    args.contract_path,
                    root / "reports" / "runs",
                    trusted_base_path=args.trusted_base,
                    trusted_policy_path=args.trusted_policy,
                    trusted_policy_schema_path=args.trusted_policy_schema,
                    authorization_path=args.authorization,
                    authorization_schema_path=args.trusted_authorization_schema,
                    approval_anchor_revision=args.approval_anchor_revision,
                )
                fast_payload = {
                    "errors": [
                        {"code": item.code, "message": item.message, "context": dict(item.context)}
                        for item in fast_errors
                    ],
                    "run": str(complete.relative_to(root)),
                    "verdict": verdict,
                }
                exit_code = EVIDENCE_EXIT_CODES[verdict]
            except KeyError, TypeError, json.JSONDecodeError, ValueError:
                fast_payload = {
                    "errors": [
                        {
                            "code": "FAST-CLI-002",
                            "message": "Fast contract or trusted controls are invalid",
                            "context": {"phase": "orchestrate"},
                        }
                    ],
                    "non_evidence": True,
                    "verdict": "contract-invalid",
                }
                print("FAST-CLI-002 contract-invalid: Fast orchestration rejected", file=sys.stderr)
                exit_code = EVIDENCE_EXIT_CODES["contract-invalid"]
            except OSError, RuntimeError:
                fast_payload = {
                    "errors": [
                        {
                            "code": "FAST-CLI-003",
                            "message": "Fast execution or publication failed",
                            "context": {"phase": "orchestrate"},
                        }
                    ],
                    "non_evidence": True,
                    "verdict": "infrastructure-invalid",
                }
                print("FAST-CLI-003 infrastructure-invalid: Fast orchestration failed", file=sys.stderr)
                exit_code = EVIDENCE_EXIT_CODES["infrastructure-invalid"]
        if not _write_payload(canonical_bytes(fast_payload, newline=True).decode(), "-"):
            return EVIDENCE_EXIT_CODES["infrastructure-invalid"]
        return exit_code
    if args.command == "evidence":
        if args.evidence_command == "produce":
            writer: EvidenceWriter | None = None
            try:
                root = _root()
                if args.output != "reports/runs":
                    raise ValueError("output must be the approved reports/runs root")
                output = root / "reports" / "runs"
                if output.is_symlink() or output.parent.is_symlink():
                    raise ValueError("output root cannot contain symlinks")
                request_bytes = _read_protected_caller_bytes(root, args.trusted_request)
                request = json.loads(request_bytes)
                if not isinstance(request, dict):
                    raise ValueError("trusted request must be an object")
                trusted_policy = TrustedPolicyInput(
                    policy_bytes=_read_protected_caller_bytes(root, args.trusted_policy),
                    schema_bytes=_read_protected_caller_bytes(root, args.trusted_policy_schema),
                    identity=args.trusted_policy_identity,
                    policy_digest=args.trusted_policy_digest,
                    schema_digest=args.trusted_policy_schema_digest,
                )
                production_authorization: AuthorizationContext | None = None
                authorization_inputs = (
                    args.authorization,
                    args.trusted_authorization_schema,
                    args.approval_anchor_revision,
                )
                if any(value is None for value in authorization_inputs) and any(
                    value is not None for value in authorization_inputs
                ):
                    raise ValueError("authorization inputs must be supplied together")
                if args.authorization is not None:
                    authorization_bytes = _read_protected_caller_bytes(root, args.authorization)
                    authorization_schema_bytes = _read_protected_caller_bytes(root, args.trusted_authorization_schema)
                    envelope, authorization_errors = load_trusted_authorization(
                        authorization_bytes, authorization_schema_bytes
                    )
                    if authorization_errors or envelope is None:
                        raise ValueError("trusted authorization is invalid")
                    production_authorization = AuthorizationContext(
                        envelope=envelope,
                        approval_anchor_revision=args.approval_anchor_revision,
                        contract_digest=request["bounded_context"]["contract_digest"],
                    )
                trusted_context, protected_eval_errors = evaluate_and_compose_trusted_context(
                    root,
                    request["trusted_base_revision"],
                    request["candidate_revision"],
                    trusted_policy,
                    request["bounded_context"]["contract_digest"],
                    request["bounded_context"],
                    production_authorization,
                )
                if trusted_context is None:
                    raise ValueError("trusted evaluation inputs could not be acquired")
                resolved_context = trusted_context.evidence_context()
                candidate_revision = resolved_context["candidate_revision"]
                _require_candidate_checkout(root, candidate_revision)
                authority_manifest = json.loads(
                    _candidate_blob(root, candidate_revision, "contracts/agent-authority.json")
                )
                evidence_schema = _candidate_blob(
                    root,
                    candidate_revision,
                    "schemas/validation-evidence.schema.json",
                )
                if not isinstance(authority_manifest, dict):
                    raise ValueError("candidate authority manifest is invalid")
                acceptance_contract = request["acceptance_contract"]
                if acceptance_contract["contract_digest"] != request["bounded_context"]["contract_digest"]:
                    raise ValueError("acceptance contract digest is not evidence-bound")
                contract_errors = validate_contract(
                    acceptance_contract,
                    root,
                    ContractContext(
                        source_revision=resolved_context["source_revision"],
                        trusted_base_revision=resolved_context["trusted_base_revision"],
                        prior_validation_identity=None,
                        approval_anchor_revision=(
                            production_authorization.approval_anchor_revision
                            if production_authorization is not None
                            else None
                        ),
                        authorization=(
                            production_authorization.envelope if production_authorization is not None else None
                        ),
                    ),
                )
                if contract_errors:
                    raise ValueError("acceptance contract is invalid")
                if protected_eval_errors and request["verdict"] != "contract-invalid":
                    raise ValueError("protected rejection requires contract-invalid evidence")
                reported_errors = {
                    canonical_bytes(reported_error)
                    for validation in request["validations"]
                    for reported_error in validation["errors"]
                }
                trusted_errors = {canonical_bytes(asdict(finding)) for finding in protected_eval_errors}
                if not trusted_errors.issubset(reported_errors):
                    raise ValueError("trusted protected rejection is absent from validations")
                preflight_result = evaluate(probe(root), ProjectPolicy(), "broad")
                if preflight_result.exit_code != 0:
                    raise OSError("broad preflight rejected evidence production")
                contracted_roots = tuple(acceptance_contract["allowed_paths"])
                snapshots: list[tuple[bytes, str, str]] = []
                for descriptor in request["attachments"]:
                    allowed_roots = tuple(Path(value) for value in descriptor["allowed_roots"])
                    source_path = Path(descriptor["source"]).resolve(strict=True)
                    source_relative = source_path.relative_to(root.resolve()).as_posix()
                    if authorize_read(
                        authority_manifest,
                        "evidence-producer",
                        source_relative,
                        root=root,
                    ) is not None or not any(contains(contracted, source_relative) for contracted in contracted_roots):
                        raise ValueError("attachment source is outside role or contract authority")
                    for allowed_root in allowed_roots:
                        allowed_relative = allowed_root.resolve(strict=True).relative_to(root.resolve()).as_posix()
                        if not any(contains(contracted, allowed_relative) for contracted in contracted_roots):
                            raise ValueError("attachment root is outside contracted authority")
                    attachment_bytes = read_approved_attachment(Path(descriptor["source"]), allowed_roots)
                    if attachment_bytes != _candidate_blob(root, candidate_revision, source_relative):
                        raise ValueError("attachment bytes are not bound to the candidate revision")
                    snapshots.append((attachment_bytes, descriptor["path"], descriptor["media_type"]))
                _require_candidate_checkout(root, candidate_revision)
                writer = EvidenceWriter(output, trusted_context)
                leaves: list[Attachment] = [
                    writer.snapshot_bytes(data, archive_path, media_type)
                    for data, archive_path, media_type in snapshots
                ]
                complete = writer.finalize(
                    verdict=request["verdict"],
                    validations=request["validations"],
                    attachments=leaves,
                    schema_path=evidence_schema,
                )
                verified = verify_evidence(complete, evidence_schema)
                if verified.errors or verified.manifest is None:
                    raise OSError("published evidence failed verification")
                production_payload: dict[str, Any] = {
                    "errors": [],
                    "run": str(complete.relative_to(root)),
                    "verdict": verified.manifest["verdict"],
                }
                exit_code = EVIDENCE_EXIT_CODES[verified.manifest["verdict"]]
            except KeyError, TypeError, json.JSONDecodeError, ValueError:
                production_payload = {
                    "errors": [
                        {
                            "code": "EVID-001",
                            "message": "trusted production request is invalid",
                            "context": {"phase": "produce"},
                        }
                    ],
                    "non_evidence": True,
                    "verdict": "contract-invalid",
                }
                print(
                    "EVID-001 contract-invalid: production request rejected; "
                    "reproduction_argv=['mojoattention','evidence','produce',...]",
                    file=sys.stderr,
                )
                exit_code = EVIDENCE_EXIT_CODES["contract-invalid"]
            except OSError, RuntimeError:
                production_payload = {
                    "errors": [
                        {
                            "code": "EVID-004",
                            "message": "evidence publication failed",
                            "context": {"phase": "produce"},
                        }
                    ],
                    "non_evidence": True,
                    "verdict": "infrastructure-invalid",
                }
                print(
                    "EVID-004 infrastructure-invalid: publication failed; "
                    "reproduction_argv=['mojoattention','evidence','produce',...]",
                    file=sys.stderr,
                )
                exit_code = EVIDENCE_EXIT_CODES["infrastructure-invalid"]
            finally:
                if writer is not None:
                    try:
                        writer.abort()
                    except OSError:
                        print(
                            "EVID-004 infrastructure-invalid: staging cleanup failed; "
                            "reproduction_argv=['mojoattention','evidence','produce',...]",
                            file=sys.stderr,
                        )
            if not _write_payload(canonical_bytes(production_payload, newline=True).decode(), args.json_path):
                return EVIDENCE_EXIT_CODES["infrastructure-invalid"]
            return exit_code
        try:
            root = _root()
            run_path = Path(args.run)
            if not run_path.is_absolute():
                run_path = root / run_path
            evidence_result = verify_evidence(run_path, root / "schemas" / "validation-evidence.schema.json")
        except OSError, RuntimeError, ValueError:
            evidence_payload: dict[str, Any] = {
                "errors": [
                    {
                        "code": "EVID-001",
                        "message": "evidence input is unavailable",
                        "context": {"phase": "verify"},
                    }
                ],
                "non_evidence": True,
                "verdict": "contract-invalid",
            }
            exit_code = EVIDENCE_EXIT_CODES["contract-invalid"]
            print(
                "EVID-001 contract-invalid: evidence input is unavailable; "
                "reproduction_argv=['mojoattention','evidence','verify','--run',RUN]",
                file=sys.stderr,
            )
        else:
            if evidence_result.errors:
                evidence_payload = {
                    "errors": [asdict(finding) for finding in evidence_result.errors],
                    "non_evidence": True,
                    "verdict": "contract-invalid",
                }
                exit_code = EVIDENCE_EXIT_CODES["contract-invalid"]
                for finding in evidence_result.errors:
                    print(
                        f"{finding.code} contract-invalid: {finding.message}; "
                        f"context={finding.context}; "
                        "reproduction_argv=['mojoattention','evidence','verify','--run',RUN]",
                        file=sys.stderr,
                    )
            else:
                assert evidence_result.manifest is not None
                evidence_payload = {
                    "evidence": evidence_result.manifest,
                    "errors": [],
                    "verdict": evidence_result.manifest["verdict"],
                }
                exit_code = EVIDENCE_EXIT_CODES[evidence_result.manifest["verdict"]]
        if not _write_payload(canonical_bytes(evidence_payload, newline=True).decode(), args.json_path):
            return EVIDENCE_EXIT_CODES["infrastructure-invalid"]
        return exit_code
    if args.command == "protected":
        protected_errors: tuple[ProtectedError, ...]
        try:
            root = _root()
        except (OSError, RuntimeError) as input_error:
            protected_errors = (ProtectedError("PROT-001", "project root is unavailable", {"error": str(input_error)}),)
        else:
            try:
                trusted_policy = TrustedPolicyInput(
                    policy_bytes=_read_protected_caller_bytes(root, args.trusted_policy),
                    schema_bytes=_read_protected_caller_bytes(root, args.trusted_policy_schema),
                    identity=args.trusted_policy_identity,
                    policy_digest=args.trusted_policy_digest,
                    schema_digest=args.trusted_policy_schema_digest,
                )
            except OSError as input_error:
                inspection = None
                protected_errors = (
                    ProtectedError(
                        "PROT-001", "protected caller policy input is unavailable", {"error": str(input_error)}
                    ),
                )
            else:
                inspection, protected_errors = inspect_repository_changes(
                    root, args.trusted_base_revision, args.candidate_revision, trusted_policy
                )
            if not protected_errors and inspection is not None:
                authorization_context: AuthorizationContext | None = None
                authorization_inputs = (
                    args.authorization,
                    args.trusted_authorization_schema,
                    args.approval_anchor_revision,
                )
                if any(value is None for value in authorization_inputs) and any(
                    value is not None for value in authorization_inputs
                ):
                    protected_errors = (
                        ProtectedError(
                            "PROT-004",
                            "authorization, its trusted schema, and approval anchor must be supplied together",
                            {},
                        ),
                    )
                elif args.authorization is not None:
                    assert args.trusted_authorization_schema is not None
                    try:
                        authorization_bytes = _read_protected_caller_bytes(root, args.authorization)
                        authorization_schema_bytes = _read_protected_caller_bytes(
                            root, args.trusted_authorization_schema
                        )
                    except OSError as input_error:
                        envelope = None
                        protected_errors = (
                            ProtectedError(
                                "PROT-004",
                                "protected caller authorization input is unavailable",
                                {"error": str(input_error)},
                            ),
                        )
                    else:
                        envelope, protected_errors = load_trusted_authorization(
                            authorization_bytes, authorization_schema_bytes
                        )
                    if not protected_errors and envelope is not None:
                        authorization_context = AuthorizationContext(
                            envelope=envelope,
                            approval_anchor_revision=args.approval_anchor_revision,
                            contract_digest=args.contract_digest,
                        )
                if not protected_errors:
                    protected_errors = evaluate_protected_changes(
                        inspection.policy,
                        inspection.effects,
                        inspection.identity,
                        inspection.change_set_digest,
                        args.contract_digest,
                        authorization_context,
                    )
        payload = (
            json.dumps(
                {
                    "errors": [asdict(error) for error in protected_errors],
                    "verdict": "contract-invalid" if protected_errors else "pass",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        if not _write_payload(payload, args.json_path):
            return 3
        for protected_error in protected_errors:
            diagnostic = (
                f"{protected_error.code} contract-invalid: {protected_error.message}; context={protected_error.context}"
            )
            print(
                diagnostic,
                file=sys.stderr,
            )
        return 3 if protected_errors else 0
    if args.command == "contract":
        errors: tuple[ContractError, ...]
        try:
            root = _root()
        except (OSError, RuntimeError) as input_error:
            errors = (ContractError("ACPT-009", "project root is unavailable", {"error": str(input_error)}),)
        else:
            try:
                contract_path = Path(args.contract_path)
                if not contract_path.is_absolute():
                    contract_path = root / contract_path
                contract = _read_json(contract_path)
            except (OSError, json.JSONDecodeError, TypeError) as input_error:
                errors = (ContractError("ACPT-009", "contract input cannot be read", {"error": str(input_error)}),)
            else:
                authorization: Any = None
                authorization_error: ContractError | None = None
                if args.authorization_path is None and args.approval_anchor_revision is not None:
                    authorization_error = ContractError(
                        "ACPT-008",
                        "approval anchor requires an authorization envelope",
                        {},
                    )
                elif args.authorization_path is not None and args.approval_anchor_revision is None:
                    authorization_error = ContractError(
                        "ACPT-008",
                        "authorization requires an independently supplied approval anchor",
                        {},
                    )
                elif args.authorization_path is not None:
                    try:
                        authorization_path = Path(args.authorization_path).resolve()
                    except (OSError, RuntimeError) as input_error:
                        authorization_error = ContractError(
                            "ACPT-008",
                            "authorization path cannot be resolved",
                            {"error": str(input_error)},
                        )
                    else:
                        if authorization_path.is_relative_to(root.resolve()):
                            authorization_error = ContractError(
                                "ACPT-008",
                                "authorization must be anchored outside the proposed repository",
                                {"path": str(authorization_path)},
                            )
                        else:
                            try:
                                authorization = _read_json(authorization_path)
                            except (OSError, json.JSONDecodeError, TypeError) as input_error:
                                authorization_error = ContractError(
                                    "ACPT-008",
                                    "authorization input cannot be read",
                                    {"error": str(input_error)},
                                )
                if authorization_error is not None:
                    errors = (authorization_error,)
                else:
                    context = ContractContext(
                        source_revision=args.source_revision,
                        trusted_base_revision=args.trusted_base_revision,
                        prior_validation_identity=args.prior_validation_identity,
                        approval_anchor_revision=args.approval_anchor_revision,
                        authorization=authorization,
                    )
                    errors = validate_contract(contract, root, context)
        payload = (
            json.dumps(
                {"errors": [asdict(error) for error in errors], "verdict": "contract-invalid" if errors else "pass"},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        if not _write_payload(payload, args.json_path):
            return 3
        for contract_error in errors:
            print(
                f"{contract_error.code} contract-invalid: {contract_error.message}; context={contract_error.context}",
                file=sys.stderr,
            )
        return 3 if errors else 0
    if args.command in {"privacy", "authority"}:
        try:
            root = _root()
        except RuntimeError as error:
            print(f"CLI-ROOT contract-invalid: {error}", file=sys.stderr)
            return 3
        try:
            if args.command == "privacy":
                failures = find_forbidden_tracked_paths(tracked_paths(str(root)))
                policy_checks = [{"id": "PRIV-001", "path": path, "status": "contract-invalid"} for path in failures]
            else:
                manifest = json.loads((root / "contracts" / "agent-authority.json").read_text(encoding="utf-8"))
                authority_failures = validate_manifest(manifest, root)
                policy_checks = [asdict(error) | {"status": "contract-invalid"} for error in authority_failures]
        except (OSError, json.JSONDecodeError, subprocess.SubprocessError) as error:
            policy_checks = [
                {
                    "id": "PRIV-002" if args.command == "privacy" else "AUTH-000",
                    "message": str(error),
                    "status": "contract-invalid",
                }
            ]
        verdict = "pass" if not policy_checks else "contract-invalid"
        payload = (
            json.dumps({"checks": policy_checks, "verdict": verdict}, sort_keys=True, separators=(",", ":")) + "\n"
        )
        if not _write_payload(payload, args.json_path):
            return 3
        for policy_check in policy_checks:
            print(
                f"{policy_check.get('id', policy_check.get('code'))} contract-invalid: {policy_check}", file=sys.stderr
            )
        return 0 if verdict == "pass" else 3
    if args.command == "environment":
        checks = evaluate_identity(detect_identity())
        verdict = "pass" if all(check.matches for check in checks) else "contract-invalid"
        payload = (
            json.dumps(
                {"checks": [asdict(check) for check in checks], "verdict": verdict},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        if not _write_payload(payload, args.json_path):
            return 3
        for identity_check in checks:
            if not identity_check.matches:
                print(
                    f"ENV-{identity_check.name} contract-invalid: detected={identity_check.detected!r}; "
                    f"required={identity_check.expected!r}; "
                    "reproduction='scripts/run.sh mojoattention environment --json -'; "
                    "remediation='synchronize the exact lock'",
                    file=sys.stderr,
                )
        return 0 if verdict == "pass" else 3

    try:
        root = _root()
    except RuntimeError as error:
        print(f"CLI-ROOT contract-invalid: {error}", file=sys.stderr)
        return 3
    result = evaluate(probe(root), ProjectPolicy(), args.mode)
    if not _write_payload(render_json(result), args.json_path):
        return 3
    print(result.summary, file=sys.stderr)
    for preflight_check in result.checks:
        if preflight_check.status != "pass":
            print(
                f"{preflight_check.id} {preflight_check.status}: {preflight_check.message}; "
                f"detected={preflight_check.detected!r}; required={preflight_check.required!r}; "
                f"unit={preflight_check.unit!r}; path={preflight_check.path!r}; "
                f"reproduction={preflight_check.reproduction_command!r}; remediation={preflight_check.remediation!r}",
                file=sys.stderr,
            )
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())

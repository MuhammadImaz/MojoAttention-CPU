from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from contextlib import suppress
from dataclasses import asdict
from pathlib import Path
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
from mojoattention.validation.host import probe
from mojoattention.validation.identity import detect_identity, evaluate_identity
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


def _require_candidate_checkout(root: Path, revision: str) -> None:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
    }
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
        env=environment,
    )
    dirty = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=no"],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
        env=environment,
    )
    if head.returncode != 0 or head.stdout.strip() != revision or dirty.returncode != 0 or dirty.stdout:
        raise ValueError("candidate checkout identity or tracked cleanliness is invalid")


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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

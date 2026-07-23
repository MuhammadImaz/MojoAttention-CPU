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
from mojoattention.validation.authority import validate_manifest
from mojoattention.validation.host import probe
from mojoattention.validation.identity import detect_identity, evaluate_identity
from mojoattention.validation.preflight import evaluate, render_json
from mojoattention.validation.privacy import find_forbidden_tracked_paths, tracked_paths


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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

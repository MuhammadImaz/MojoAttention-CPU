from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from contextlib import suppress
from dataclasses import asdict
from pathlib import Path
from typing import NoReturn

from mojoattention.config import ProjectPolicy
from mojoattention.validation.host import probe
from mojoattention.validation.identity import detect_identity, evaluate_identity
from mojoattention.validation.preflight import evaluate, render_json


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
    candidates = [Path(configured)] if configured else []
    candidates.extend([Path.cwd(), *Path.cwd().parents, *Path(__file__).resolve().parents])
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


def build_parser() -> argparse.ArgumentParser:
    parser = ProjectArgumentParser(prog="mojoattention")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=ProjectArgumentParser)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--mode", choices=("baseline", "broad"), default="baseline")
    preflight.add_argument("--json", dest="json_path", default="-", metavar="PATH")
    environment = commands.add_parser("environment")
    environment.add_argument("--json", dest="json_path", default="-", metavar="PATH")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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
    for check in result.checks:
        if check.status != "pass":
            print(
                f"{check.id} {check.status}: {check.message}; detected={check.detected!r}; "
                f"required={check.required!r}; unit={check.unit!r}; path={check.path!r}; "
                f"reproduction={check.reproduction_command!r}; remediation={check.remediation!r}",
                file=sys.stderr,
            )
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())

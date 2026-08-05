from __future__ import annotations

import importlib.metadata
import os
import platform
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

EXPECTED = {
    "python": "3.14.4",
    "uv": "0.11.29",
    "modular": "26.4.0",
    "max": "26.4.0",
    "max-cli": "26.4.0",
    "mojo": "1.0.0b2",
    "mojo-cli": "1.0.0b2",
    "torch": "2.13.0+cpu",
    "numpy": "2.5.1",
    "pytest": "9.1.1",
    "ruff": "0.15.22",
    "mypy": "2.3.0",
    "jsonschema": "4.25.1",
    "gcc": "15.2",
    "g++": "15.2",
}


@dataclass(frozen=True, slots=True)
class IdentityCheck:
    name: str
    detected: str
    expected: str
    matches: bool


def evaluate_identity(detected: dict[str, str]) -> tuple[IdentityCheck, ...]:
    return tuple(
        IdentityCheck(name, detected.get(name, "missing"), expected, detected.get(name) == expected)
        for name, expected in EXPECTED.items()
    )


def _command_version(command: list[str], pattern: str) -> str:
    try:
        completed = subprocess.run(command, check=False, text=True, capture_output=True, timeout=30)
    except OSError, subprocess.TimeoutExpired:
        return "missing"
    if completed.returncode != 0:
        return "missing"
    match = re.search(pattern, completed.stdout)
    return match.group(1) if match else "missing"


def detect_identity() -> dict[str, str]:
    packages = ("modular", "max", "mojo", "torch", "numpy", "pytest", "ruff", "mypy", "jsonschema")
    detected = {name: _package_version(name) for name in packages}
    uv_bin = os.environ.get("MOJOATTENTION_UV_BIN", "uv")
    detected.update(
        {
            "python": platform.python_version(),
            "uv": _command_version([uv_bin, "--version"], r"uv\s+(\S+)"),
            "max-cli": _command_version(["max", "--version"], r"MAX\s+(\S+)"),
            "mojo-cli": _command_version(["mojo", "--version"], r"Mojo\s+(\S+)"),
            "gcc": _command_version(["gcc", "-dumpfullversion"], r"(\d+\.\d+)"),
            "g++": _command_version(["g++", "-dumpfullversion"], r"(\d+\.\d+)"),
        }
    )
    return detected


def require_clean_candidate(root: Path, revision: str) -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
    }

    def git(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=root,
            capture_output=True,
            check=False,
            text=True,
            env=environment,
        )

    head = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    dirty = git("status", "--porcelain=v1", "--untracked-files=no")
    if (
        head.returncode != 0
        or head.stdout.strip() != revision
        or tree.returncode != 0
        or not re.fullmatch(r"[0-9a-f]{40}", tree.stdout.strip())
        or dirty.returncode != 0
        or dirty.stdout
    ):
        raise ValueError("candidate checkout identity or tracked cleanliness is invalid")
    return {"candidate_revision": revision, "candidate_tree": tree.stdout.strip()}


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "missing"

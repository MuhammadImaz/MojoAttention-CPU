from __future__ import annotations

import subprocess
from pathlib import PurePosixPath

FORBIDDEN_SEGMENTS = frozenset(
    {
        ".agents",
        ".codex",
        ".claude",
        ".cursor",
        ".continue",
        ".windsurf",
        ".gemini",
        ".roo",
        ".opencode",
        "_bmad",
        "_bmad-output",
    }
)
FORBIDDEN_NAMES = frozenset({"agents.md", "claude.md", "gemini.md", ".roomodes", "copilot-instructions.md"})


def _forbidden(path: str) -> bool:
    normalized = path.replace("\\", "/")
    parts = tuple(part.casefold() for part in PurePosixPath(normalized).parts)
    if not parts or normalized.startswith("/") or ".." in parts or "" in parts:
        return True
    if any(part in FORBIDDEN_SEGMENTS for part in parts):
        return True
    if len(parts) >= 3 and parts[0] == ".github" and parts[1] in {"instructions", "prompts"}:
        return parts[-1].endswith((".instructions.md", ".prompt.md"))
    name = parts[-1]
    return name in FORBIDDEN_NAMES or name.startswith((".aider", ".cline"))


def find_forbidden_tracked_paths(payload: bytes) -> tuple[str, ...]:
    paths = [item.decode("utf-8", errors="surrogateescape") for item in payload.split(b"\0") if item]
    return tuple(sorted(path for path in paths if _forbidden(path)))


def tracked_paths(root: str) -> bytes:
    return subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root)

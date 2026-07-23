from __future__ import annotations

from pathlib import Path, PurePosixPath


def contains(scope: str, path: str) -> bool:
    scope_path = PurePosixPath(scope)
    candidate = PurePosixPath(path)
    return candidate == scope_path or scope_path in candidate.parents


def is_canonical_repo_path(path: str, root: Path, *, require_exists: bool) -> bool:
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or "//" in path
        or path.endswith("/")
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        return False
    current = root
    try:
        for part in path.split("/"):
            current /= part
            if current.is_symlink():
                return False
            if not current.exists():
                if require_exists:
                    return False
                break
        return current.resolve(strict=False).is_relative_to(root.resolve())
    except OSError:
        return False


def has_overlap(paths: list[str]) -> bool:
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            if contains(left, right) or contains(right, left):
                return True
    return False

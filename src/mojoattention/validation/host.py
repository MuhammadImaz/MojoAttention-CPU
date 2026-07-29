from __future__ import annotations

import os
import platform
import re
import shutil
import stat
import subprocess
from collections import OrderedDict
from pathlib import Path

from mojoattention.validation.evidence import digest_bytes, verify_evidence
from mojoattention.validation.preflight import HostSnapshot, RunState

_RUN_VERIFICATION_CACHE_LIMIT = 64
_RUN_VERIFICATION_CACHE: OrderedDict[tuple[str, tuple[tuple[str, int, int, int, int], ...], str], bool] = OrderedDict()


def _memory(path: Path = Path("/proc/meminfo")) -> tuple[int, int]:
    try:
        values: dict[str, int] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            name, raw = line.split(":", 1)
            values[name] = int(raw.strip().split()[0]) * 1024
        return values["MemTotal"], values["MemAvailable"]
    except OSError, KeyError, ValueError, IndexError:
        return 0, 0


def _normalize_flags(flags: set[str]) -> frozenset[str]:
    if "pni" in flags:
        flags.add("sse3")
    if "abm" in flags:
        flags.add("lzcnt")
    return frozenset(flags)


def _cpu_flags(path: Path = Path("/proc/cpuinfo")) -> frozenset[str]:
    try:
        records = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith(("flags", "Features")) and ":" in line:
                records.append(set(line.partition(":")[2].split()))
        if not records:
            return frozenset()
        common = set.intersection(*records)
        return _normalize_flags(common)
    except OSError:
        return frozenset()


def _distribution(path: Path = Path("/etc/os-release")) -> tuple[str, str]:
    values: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    except OSError:
        pass
    return values.get("NAME", "unknown"), values.get("VERSION_ID", "unknown")


def _tree_size(path: Path, root: Path) -> int:
    try:
        if not path.exists():
            return 0
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            return 2**63 - 1
        total = 0
        for entry in path.rglob("*"):
            if entry.is_symlink():
                return 2**63 - 1
            if entry.is_file():
                total += entry.stat().st_size
        return total
    except OSError:
        return 2**63 - 1


def _marker_state(name: str) -> RunState | None:
    tokens = set(filter(None, re.split(r"[._-]+", name.lower())))
    if "active" in tokens:
        return RunState.ACTIVE
    if "staging" in tokens:
        return RunState.STAGING
    if "unsealed" in tokens:
        return RunState.UNSEALED
    return None


def _run_signature(path: Path) -> tuple[tuple[str, int, int, int, int], ...]:
    entries: list[tuple[str, int, int, int, int]] = []
    for item in sorted(path.rglob("*")):
        value = item.stat(follow_symlinks=False)
        entries.append(
            (
                item.relative_to(path).as_posix(),
                value.st_mode,
                value.st_ino,
                value.st_size,
                value.st_ctime_ns,
            )
        )
    return tuple(entries)


def _schema_snapshot(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise OSError("evidence schema must be a single-link regular file")
        chunks: list[bytes] = []
        while block := os.read(descriptor, 1024 * 1024):
            chunks.append(block)
        after = os.fstat(descriptor)
        identity = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, name) != getattr(after, name) for name in identity):
            raise OSError("evidence schema changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _verify_complete_cached(entry: Path, schema_path: Path) -> bool:
    before = _run_signature(entry)
    schema = _schema_snapshot(schema_path)
    key = (
        str(entry.resolve(strict=True)),
        before,
        digest_bytes(schema),
    )
    cached = _RUN_VERIFICATION_CACHE.get(key)
    if cached is not None:
        if _run_signature(entry) != before:
            return False
        _RUN_VERIFICATION_CACHE.move_to_end(key)
        return cached
    valid = not verify_evidence(entry, schema).errors
    if _run_signature(entry) != before:
        return False
    _RUN_VERIFICATION_CACHE[key] = valid
    while len(_RUN_VERIFICATION_CACHE) > _RUN_VERIFICATION_CACHE_LIMIT:
        _RUN_VERIFICATION_CACHE.popitem(last=False)
    return valid


def _run_state(root: Path) -> RunState:
    runs = root / "reports" / "runs"
    try:
        if not runs.exists():
            return RunState.IDLE
        if not runs.is_dir() or runs.is_symlink():
            return RunState.UNSEALED
        for entry in runs.iterdir():
            state = _marker_state(entry.name)
            if state is not None:
                return state
            if entry.is_symlink() or not entry.is_dir():
                return RunState.UNSEALED
            match = re.fullmatch(r"([0-9a-f]{32})\.complete", entry.name)
            if match is None:
                return RunState.UNSEALED
            if not _verify_complete_cached(entry, root / "schemas" / "validation-evidence.schema.json"):
                return RunState.UNSEALED
        return RunState.IDLE
    except OSError:
        return RunState.UNSEALED


def _effective_v3() -> tuple[str, bool]:
    candidates = (
        Path("/lib64/ld-linux-x86-64.so.2"),
        Path("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
    )
    loader = next((candidate for candidate in candidates if candidate.is_file()), None)
    if loader is None:
        return "glibc-hwcaps-v1:x86-64-v3", False
    try:
        completed = subprocess.run(
            [loader, "--help"],
            check=False,
            text=True,
            capture_output=True,
            timeout=10,
            env={**os.environ, "LC_ALL": "C"},
        )
    except OSError, subprocess.TimeoutExpired:
        return "glibc-hwcaps-v1:x86-64-v3", False
    supported = completed.returncode == 0 and "x86-64-v3 (supported, searched)" in completed.stdout
    return "glibc-hwcaps-v1:x86-64-v3", supported


def probe(root: Path) -> HostSnapshot:
    system = platform.system().lower()
    libc_name, libc_version = platform.libc_ver()
    try:
        parts = [int(part) for part in libc_version.split(".")[:2]] if libc_name == "glibc" else []
    except ValueError:
        parts = []
    glibc_version = (parts[0], parts[1]) if len(parts) == 2 else (0, 0)
    total, available = _memory() if system == "linux" else (0, 0)
    flags = _cpu_flags() if system == "linux" else frozenset()
    v3_probe, v3_effective = _effective_v3() if system == "linux" else ("unsupported-os", False)
    distribution, distribution_version = _distribution() if system == "linux" else (platform.system(), "unknown")
    try:
        free_disk = shutil.disk_usage(root).free
    except OSError:
        free_disk = 0
    cache_path = root / ".cache" / "modular"
    return HostSnapshot(
        os_name=system,
        distribution=distribution,
        distribution_version=distribution_version,
        architecture=platform.machine().lower(),
        glibc_version=glibc_version,
        cpu_flags=flags,
        v3_probe=v3_probe,
        v3_effective=v3_effective,
        os_avx_enabled="avx" in flags and "xsave" in flags,
        logical_cpus=os.cpu_count() or 0,
        total_memory_bytes=total,
        available_memory_bytes=available,
        free_disk_bytes=free_disk,
        cache_bytes=_tree_size(cache_path, root),
        cache_path=str(cache_path),
        disk_path=str(root),
        gpu_present=Path("/dev/nvidia0").exists() or Path("/dev/dri").exists(),
        run_state=_run_state(root),
    )

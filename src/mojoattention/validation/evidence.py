from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from mojoattention.validation.protected_assets import TrustedEvaluationContext

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[0-9a-f]{32}$")
EXIT_CODES = {"pass": 0, "product-fail": 1, "infrastructure-invalid": 2, "contract-invalid": 3}
Verdict = Literal["pass", "product-fail", "infrastructure-invalid", "contract-invalid"]


@dataclass(frozen=True)
class EvidenceError:
    code: str
    message: str
    context: dict[str, object]


@dataclass(frozen=True)
class Attachment:
    path: str
    sha256: str
    size_bytes: int
    media_type: str


@dataclass(frozen=True)
class Verification:
    manifest: dict[str, Any] | None
    errors: tuple[EvidenceError, ...]


def canonical_bytes(value: object, *, newline: bool = False) -> bytes:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    return data + (b"\n" if newline else b"")


def digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _safe_relative(path: str) -> bool:
    return bool(
        path
        and not path.startswith("/")
        and "\\" not in path
        and "\0" not in path
        and "//" not in path
        and not path.endswith("/")
        and all(part not in {"", ".", ".."} for part in PurePosixPath(path).parts)
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_noreplace(source: Path, target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as error:
        raise OSError("atomic no-replace publication is unsupported") from error
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(-100, os.fsencode(source), -100, os.fsencode(target), 1)
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), str(target))


def _read_regular(path: Path) -> bytes:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("attachment must be a single-link regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        data = b""
        while block := os.read(descriptor, 1024 * 1024):
            data += block
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, name) != getattr(after, name) for name in identity):
        raise ValueError("attachment changed while being read")
    return data


def _read_relative_regular(root_fd: int, relative: str, *, max_bytes: int = 256 * 1024 * 1024) -> bytes:
    if not _safe_relative(relative):
        raise ValueError("relative read path is unsafe")
    descriptors: list[int] = []
    try:
        current_fd = os.dup(root_fd)
        descriptors.append(current_fd)
        parts = PurePosixPath(relative).parts
        for component in parts[:-1]:
            current_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current_fd,
            )
            descriptors.append(current_fd)
        leaf_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current_fd)
        descriptors.append(leaf_fd)
        before = os.fstat(leaf_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("evidence leaf must be a single-link regular file")
        chunks: list[bytes] = []
        total = 0
        while block := os.read(leaf_fd, 1024 * 1024):
            total += len(block)
            if total > max_bytes:
                raise ValueError("evidence leaf exceeds size limit")
            chunks.append(block)
        after = os.fstat(leaf_fd)
        identity = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, name) != getattr(after, name) for name in identity):
            raise ValueError("evidence leaf changed while being read")
        return b"".join(chunks)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read_approved_source(source: Path, allowed_roots: tuple[Path, ...]) -> bytes:
    if not source.is_absolute():
        raise ValueError("attachment source must be absolute")
    for root in allowed_roots:
        if not root.is_absolute():
            continue
        current = Path(root.anchor)
        root_has_symlink = False
        for component in root.parts[1:]:
            current /= component
            if current.is_symlink():
                root_has_symlink = True
                break
        if root_has_symlink:
            continue
        try:
            relative = source.relative_to(root)
        except ValueError:
            continue
        if not relative.parts:
            continue
        descriptors: list[int] = []
        try:
            current_fd = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptors.append(current_fd)
            for component in root.parts[1:]:
                current_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=current_fd,
                )
                descriptors.append(current_fd)
            for component in relative.parts[:-1]:
                current_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=current_fd,
                )
                descriptors.append(current_fd)
            leaf_fd = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current_fd)
            descriptors.append(leaf_fd)
            before = os.fstat(leaf_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError("attachment must be a single-link regular file")
            chunks: list[bytes] = []
            total = 0
            while block := os.read(leaf_fd, 1024 * 1024):
                total += len(block)
                if total > 256 * 1024 * 1024:
                    raise ValueError("attachment exceeds the 256-mebibyte limit")
                chunks.append(block)
            after = os.fstat(leaf_fd)
            identity = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if any(getattr(before, name) != getattr(after, name) for name in identity):
                raise ValueError("attachment changed while being read")
            return b"".join(chunks)
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
    raise ValueError("attachment source is outside approved roots")


def render_markdown(manifest: dict[str, Any], non_report: list[dict[str, object]]) -> str:
    lines = [
        f"# Validation Evidence: {manifest['run_id']}",
        "",
        f"- Suite: `{manifest['suite_id']}`",
        f"- Verdict: `{manifest['verdict']}`",
        f"- Source: `{manifest['source_revision']}`",
        f"- Trusted base: `{manifest['trusted_base_revision']}`",
        "",
        "## Validations",
        "",
    ]
    for result in sorted(manifest["validations"], key=lambda item: item["validation_id"]):
        reproduction = json.dumps(result["reproduction_argv"], ensure_ascii=False)
        lines.extend(
            [
                f"- `{result['validation_id']}`: **{result['status']}**",
                f"  - Reproduce: {_markdown_code(reproduction)}",
            ]
        )
    lines.extend(["", "## Attachments", ""])
    for item in sorted(non_report, key=lambda value: str(value["path"])):
        lines.append(
            f"- {_markdown_code(str(item['path']))} — `{item['sha256']}`; "
            f"{item['size_bytes']} bytes; `{item['media_type']}`"
        )
    return "\n".join(lines) + "\n"


def _markdown_code(value: str) -> str:
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * (longest + 1)
    padding = " " if value.startswith("`") or value.endswith("`") else ""
    return f"{fence}{padding}{value}{padding}{fence}"


class EvidenceWriter:
    def __init__(
        self,
        runs_root: Path,
        context: TrustedEvaluationContext,
        *,
        run_id: str | None = None,
    ) -> None:
        self.runs_root = runs_root.resolve()
        self.run_id = run_id or secrets.token_hex(16)
        if not RUN_ID.fullmatch(self.run_id):
            raise ValueError("run id is invalid")
        self.context = context.evidence_context()
        self.staging = self.runs_root / f"{self.run_id}.staging"
        self.complete = self.runs_root / f"{self.run_id}.complete"
        self.runs_root.mkdir(parents=True, exist_ok=True)
        self.staging.mkdir(exist_ok=False)
        self._sealed = False
        staging = {"schema_version": "1.0.0", "run_id": self.run_id, "lifecycle": "staging"}
        self._write("staging.json", canonical_bytes(staging, newline=True))
        _fsync_directory(self.staging)

    def _write(self, relative: str, data: bytes) -> Path:
        if not _safe_relative(relative):
            raise ValueError("archive path is unsafe")
        parts = PurePosixPath(relative).parts
        directories: list[int] = []
        try:
            current_fd = os.open(self.staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            directories.append(current_fd)
            for component in parts[:-1]:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_fd)
                    os.fsync(current_fd)
                except FileExistsError:
                    pass
                current_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=current_fd,
                )
                directories.append(current_fd)
            file_fd = os.open(
                parts[-1],
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=current_fd,
            )
            try:
                view = memoryview(data)
                while view:
                    written = os.write(file_fd, view)
                    view = view[written:]
                os.fsync(file_fd)
            finally:
                os.close(file_fd)
            os.fsync(current_fd)
        finally:
            for descriptor in reversed(directories):
                os.close(descriptor)
        return self.staging / relative

    def snapshot(self, source: Path, archive_path: str, media_type: str, allowed_roots: tuple[Path, ...]) -> Attachment:
        if self._sealed:
            raise RuntimeError("writer is sealed")
        try:
            data = _read_approved_source(source, allowed_roots)
        except OSError as error:
            raise ValueError("attachment source cannot be opened safely") from error
        self._write(archive_path, data)
        return Attachment(archive_path, digest_bytes(data), len(data), media_type)

    def finalize(
        self,
        *,
        verdict: Verdict,
        validations: list[dict[str, Any]],
        attachments: list[Attachment],
        schema_path: Path,
    ) -> Path:
        if self._sealed:
            raise RuntimeError("writer is sealed")
        self._sealed = True
        validation_ids = [item.get("validation_id") for item in validations]
        attachment_paths = [item.path for item in attachments]
        if not validations or len(validation_ids) != len(set(validation_ids)):
            raise ValueError("validation inventory must be nonempty and unique")
        if len(attachment_paths) != len(set(attachment_paths)) or "report.md" in attachment_paths:
            raise ValueError("attachment inventory must be unique and cannot supply report.md")
        statuses = [item.get("status") for item in validations]
        if sorted(str(item["validation_id"]) for item in validations) != sorted(
            self.context.get("declared_validation_ids", [])
        ):
            raise ValueError("actual validation inventory differs from declared inventory")
        if sorted({str(item["case_id"]) for item in validations}) != sorted(self.context.get("declared_case_ids", [])):
            raise ValueError("actual case inventory differs from declared inventory")
        referenced_paths = {str(path) for item in validations for path in item.get("attachments", [])}
        if referenced_paths != set(attachment_paths):
            raise ValueError("validation attachment inventory differs from supplied leaves")
        if verdict == "pass" and any(status != "pass" for status in statuses):
            raise ValueError("pass verdict requires every validation to pass")
        if verdict != "pass" and all(status == "pass" for status in statuses):
            raise ValueError("non-pass verdict requires a failed validation")
        if any(item.get("status") == "fail" and not item.get("errors") for item in validations):
            raise ValueError("failed validations require typed errors")
        manifest = dict(self.context)
        manifest.update(
            {
                "schema_version": "1.0.0",
                "run_id": self.run_id,
                "lifecycle": "complete",
                "verdict": verdict,
                "validations": sorted(validations, key=lambda item: item["validation_id"]),
            }
        )
        leaves = [item.__dict__ for item in sorted(attachments, key=lambda item: item.path)]
        report = render_markdown(manifest, leaves).encode()
        self._write("report.md", report)
        leaves.append(Attachment("report.md", digest_bytes(report), len(report), "text/markdown").__dict__)
        leaves.sort(key=lambda item: item["path"])
        manifest["attachments"] = leaves
        manifest["attachment_closure_digest"] = digest_bytes(canonical_bytes(leaves))
        manifest["evidence_digest"] = digest_bytes(canonical_bytes(manifest))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        errors = tuple(Draft202012Validator(schema).iter_errors(manifest))
        if errors:
            raise ValueError(f"evidence is schema-invalid: {errors[0].message}")
        (self.staging / "staging.json").unlink()
        self._write("evidence.json", canonical_bytes(manifest, newline=True))
        _fsync_directory(self.staging)
        staged = verify_evidence(self.staging, schema_path, expected_suffix=".staging")
        if staged.errors:
            raise ValueError(f"staged closure verification failed: {staged.errors[0].code}")
        _rename_noreplace(self.staging, self.complete)
        _fsync_directory(self.runs_root)
        return self.complete


def verify_evidence(path: Path, schema_path: Path, *, expected_suffix: str = ".complete") -> Verification:
    errors: list[EvidenceError] = []
    match = re.fullmatch(rf"([0-9a-f]{{32}}){re.escape(expected_suffix)}", path.name)
    if match is None or path.is_symlink() or not path.is_dir():
        return Verification(
            None,
            (EvidenceError("EVID-002", "evidence is not a complete run", {"phase": "location"}),),
        )
    root_fd = -1
    manifest: dict[str, Any] | None = None
    try:
        root_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        bound_path = Path(f"/proc/self/fd/{root_fd}")
        raw = _read_relative_regular(root_fd, "evidence.json", max_bytes=16 * 1024 * 1024)
        manifest = json.loads(raw)
        if not isinstance(manifest, dict):
            raise ValueError("root JSON must be an object")
        if raw != canonical_bytes(manifest, newline=True):
            raise ValueError("root JSON is noncanonical")
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        schema_errors = tuple(Draft202012Validator(schema).iter_errors(manifest))
        if schema_errors:
            raise ValueError(schema_errors[0].message)
        if manifest["run_id"] != match.group(1) or manifest["lifecycle"] != "complete":
            raise ValueError("directory identity or lifecycle mismatch")
        expected_root = dict(manifest)
        root_digest = expected_root.pop("evidence_digest")
        if root_digest != digest_bytes(canonical_bytes(expected_root)):
            raise ValueError("root digest mismatch")
        leaves = manifest["attachments"]
        if sum(int(item["size_bytes"]) for item in leaves) > 1024 * 1024 * 1024:
            raise ValueError("attachment closure exceeds cumulative size limit")
        if manifest["attachment_closure_digest"] != digest_bytes(canonical_bytes(leaves)):
            raise ValueError("attachment closure mismatch")
        expected_files = {"evidence.json", *(item["path"] for item in leaves)}
        expected_directories = {
            str(parent)
            for filename in expected_files
            for parent in PurePosixPath(filename).parents
            if str(parent) != "."
        }
        actual_files: set[str] = set()
        actual_directories: set[str] = set()
        for item in bound_path.rglob("*"):
            relative = str(item.relative_to(bound_path))
            mode = item.lstat().st_mode
            if stat.S_ISREG(mode):
                actual_files.add(relative)
            elif stat.S_ISDIR(mode) and not item.is_symlink():
                actual_directories.add(relative)
            else:
                raise ValueError("unexpected non-regular filesystem object")
        if expected_files != actual_files or expected_directories != actual_directories:
            raise ValueError("attachment inventory mismatch")
        for item in leaves:
            data = _read_relative_regular(root_fd, item["path"])
            if len(data) != item["size_bytes"] or digest_bytes(data) != item["sha256"]:
                raise ValueError(f"attachment mismatch: {item['path']}")
        non_report = [item for item in leaves if item["path"] != "report.md"]
        report = _read_relative_regular(root_fd, "report.md", max_bytes=16 * 1024 * 1024).decode("utf-8")
        if report != render_markdown(manifest, non_report):
            raise ValueError("Markdown projection mismatch")
    except OSError, ValueError, json.JSONDecodeError, TypeError, KeyError:
        errors.append(EvidenceError("EVID-001", "evidence verification failed", {"phase": "verify"}))
        return Verification(None, tuple(errors))
    finally:
        if root_fd >= 0:
            os.close(root_fd)
    return Verification(manifest, ())

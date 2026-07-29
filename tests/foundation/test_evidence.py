from __future__ import annotations

import json
import math
import os
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from mojoattention.cli.main import _read_protected_caller_bytes, _require_candidate_checkout, build_parser, main
from mojoattention.validation.evidence import (
    EXIT_CODES,
    EvidenceWriter,
    canonical_bytes,
    digest_bytes,
    render_markdown,
    verify_evidence,
)
from mojoattention.validation.protected_assets import (
    TrustedEvaluationContext,
    TrustedPolicyInput,
    evaluate_and_compose_trusted_context,
    git_blob_oid,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas" / "validation-evidence.schema.json"
DIGEST = "sha256:" + ("a" * 64)


def context(**updates: object) -> TrustedEvaluationContext:
    payload = {
        "suite_id": "foundation",
        "contract_digest": DIGEST,
        "config_digest": DIGEST,
        "protocol_digest": DIGEST,
        "declared_case_ids": ["canonical"],
        "declared_validation_ids": ["EVID-900"],
        "seed": 7,
        "producer": {"name": "mojoattention", "version": "1.0.0"},
        "environment": {
            "os": "linux",
            "architecture": "x86-64",
            "python_version": "3.14.4",
        },
    }
    payload.update(updates)
    policy_bytes = (ROOT / "contracts" / "protected-assets.json").read_bytes()
    schema_bytes = (ROOT / "schemas" / "protected-assets.schema.json").read_bytes()
    policy = TrustedPolicyInput(
        policy_bytes,
        schema_bytes,
        git_blob_oid(policy_bytes),
        digest_bytes(policy_bytes),
        digest_bytes(schema_bytes),
    )
    revision = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    trusted, errors = evaluate_and_compose_trusted_context(ROOT, revision, revision, policy, DIGEST, payload, None)
    if trusted is None or errors:
        raise RuntimeError("test trusted context could not be constructed")
    return trusted


def validation(*, status: str = "pass") -> dict[str, object]:
    return {
        "validation_id": "EVID-900",
        "case_id": "canonical",
        "status": status,
        "reproduction_argv": ["python", "-m", "pytest", "tests/foundation/test_evidence.py"],
        "metrics": [{"name": "cases", "value": 1, "value_type": "integer", "unit": "count"}],
        "errors": (
            []
            if status == "pass"
            else [{"code": "EVID-006", "message": "validation failed", "context": {"case": "canonical"}}]
        ),
        "attachments": ["artifacts/result.txt"],
    }


class EvidenceContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(self.schema)

    def produce(
        self,
        root: Path,
        *,
        verdict: str = "pass",
        result: dict[str, object] | None = None,
        run_id: str = "f" * 32,
    ) -> Path:
        source_root = root / "approved"
        source_root.mkdir()
        source = source_root / "result.txt"
        source.write_text("stable evidence\n", encoding="utf-8")
        writer = EvidenceWriter._for_test(root / "runs", context(), run_id)
        leaf = writer.snapshot(source, "artifacts/result.txt", "text/plain", (source_root,))
        return writer.finalize(
            verdict=verdict,  # type: ignore[arg-type]
            validations=[result or validation(status="pass" if verdict == "pass" else "fail")],
            attachments=[leaf],
            schema_path=SCHEMA,
        )

    def test_canonical_encoder_is_stable_unicode_strict_and_newline_explicit(self) -> None:
        first = {"z": "السلام", "a": [1, True, None]}
        second = {"a": [1, True, None], "z": "السلام"}
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(
            b'{"a":[1,true,null],"z":"\xd8\xa7\xd9\x84\xd8\xb3\xd9\x84\xd8\xa7\xd9\x85"}', canonical_bytes(first)
        )
        self.assertFalse(canonical_bytes(first).endswith(b"\n"))
        self.assertEqual(canonical_bytes(first) + b"\n", canonical_bytes(first, newline=True))
        for value in (math.nan, math.inf, -math.inf):
            with self.assertRaises(ValueError):
                canonical_bytes({"metric": value})

    def test_schema_is_strict_at_every_trust_bound_object(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            complete = self.produce(Path(temporary))
            manifest = json.loads((complete / "evidence.json").read_bytes())
        self.assertEqual([], list(Draft202012Validator(self.schema).iter_errors(manifest)))
        for path in (
            (),
            ("producer",),
            ("environment",),
            ("validations", 0),
            ("validations", 0, "metrics", 0),
            ("validations", 0, "errors"),
            ("attachments", 0),
        ):
            changed = deepcopy(manifest)
            target: object = changed
            for part in path:
                target = target[part]  # type: ignore[index]
            if path == ("validations", 0, "errors"):
                target.append({"code": "EVID-006", "message": "bad", "context": {"unknown": []}})  # type: ignore[attr-defined]
            else:
                target["unknown"] = True  # type: ignore[index]
            self.assertTrue(list(Draft202012Validator(self.schema).iter_errors(changed)), path)

    def test_v2_evidence_requires_and_binds_suite_manifest_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "approved"
            source_root.mkdir()
            source = source_root / "result.txt"
            source.write_text("stable evidence\n", encoding="utf-8")
            writer = EvidenceWriter._for_test(
                root / "runs",
                context(suite_manifest_digest=DIGEST),
                "e" * 32,
            )
            leaf = writer.snapshot(source, "artifacts/result.txt", "text/plain", (source_root,))
            complete = writer.finalize(
                verdict="pass",
                validations=[validation()],
                attachments=[leaf],
                schema_path=SCHEMA,
            )
            manifest = json.loads((complete / "evidence.json").read_bytes())
            self.assertEqual("2.0.0", manifest["schema_version"])
            self.assertEqual(DIGEST, manifest["suite_manifest_digest"])
            missing = dict(manifest)
            missing.pop("suite_manifest_digest")
            self.assertTrue(tuple(Draft202012Validator(self.schema).iter_errors(missing)))

    def test_create_finalize_verify_is_atomic_and_hash_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            complete = self.produce(root)
            self.assertTrue(complete.name.endswith(".complete"))
            self.assertFalse((root / "runs" / ("f" * 32 + ".staging")).exists())
            result = verify_evidence(complete, SCHEMA)
            self.assertEqual((), result.errors)
            assert result.manifest is not None
            manifest = result.manifest
            root_payload = dict(manifest)
            root_digest = root_payload.pop("evidence_digest")
            self.assertEqual(root_digest, digest_bytes(canonical_bytes(root_payload)))
            self.assertEqual(
                manifest["attachment_closure_digest"],
                digest_bytes(canonical_bytes(manifest["attachments"])),
            )

    def test_markdown_is_deterministic_and_covers_non_report_leaves(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            complete = self.produce(Path(temporary))
            manifest = json.loads((complete / "evidence.json").read_bytes())
            leaves = [leaf for leaf in manifest["attachments"] if leaf["path"] != "report.md"]
            rendered = render_markdown(manifest, list(reversed(leaves)))
            self.assertEqual(rendered.encode(), (complete / "report.md").read_bytes())
            self.assertIn("artifacts/result.txt", rendered)
            self.assertIn(leaves[0]["sha256"], rendered)
            self.assertNotIn(manifest["attachment_closure_digest"], rendered)
            self.assertNotIn(manifest["evidence_digest"], rendered)

    def test_consumer_rejects_staging_tamper_missing_extra_and_report_disagreement(self) -> None:
        mutations = ("staging", "same-size", "missing", "extra", "report")
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                complete = self.produce(root, run_id=f"{index + 1:032x}")
                candidate = complete
                if mutation == "staging":
                    candidate = complete.with_name(complete.name.removesuffix(".complete") + ".staging")
                    complete.rename(candidate)
                elif mutation == "same-size":
                    (complete / "artifacts" / "result.txt").write_bytes(b"x" * len(b"stable evidence\n"))
                elif mutation == "missing":
                    (complete / "artifacts" / "result.txt").unlink()
                elif mutation == "extra":
                    (complete / "extra.txt").write_text("undeclared", encoding="utf-8")
                else:
                    (complete / "report.md").write_text("forged\n", encoding="utf-8")
                verified = verify_evidence(candidate, SCHEMA)
                self.assertIsNone(verified.manifest)
                self.assertTrue(verified.errors)
                self.assertTrue(all(error.code.startswith("EVID-") for error in verified.errors))

    def test_unsafe_archive_paths_and_unapproved_sources_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            allowed = root / "allowed"
            allowed.mkdir()
            source = allowed / "result.txt"
            source.write_text("x", encoding="utf-8")
            for index, archive in enumerate(("/absolute", "../escape", "a/../b", "a\\b", "", "a//b", "a/")):
                with self.subTest(path=archive):
                    writer = EvidenceWriter._for_test(root / f"runs-{index}", context(), f"{index + 1:032x}")
                    with self.assertRaises(ValueError):
                        writer.snapshot(source, archive, "text/plain", (allowed,))
            outside = root / "outside.txt"
            outside.write_text("secret", encoding="utf-8")
            writer = EvidenceWriter._for_test(root / "runs-outside", context(), "e" * 32)
            with self.assertRaises(ValueError):
                writer.snapshot(outside, "artifacts/outside.txt", "text/plain", (allowed,))

    def test_symlink_and_hardlink_sources_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            allowed = root / "allowed"
            allowed.mkdir()
            source = allowed / "source.txt"
            source.write_text("x", encoding="utf-8")
            alias = allowed / "alias.txt"
            alias.symlink_to(source)
            writer = EvidenceWriter._for_test(root / "runs-symlink", context(), "d" * 32)
            with self.assertRaises(ValueError):
                writer.snapshot(alias, "artifacts/alias.txt", "text/plain", (allowed,))
            hardlink = allowed / "hardlink.txt"
            os.link(source, hardlink)
            writer = EvidenceWriter._for_test(root / "runs-hardlink", context(), "c" * 32)
            with self.assertRaises(ValueError):
                writer.snapshot(source, "artifacts/source.txt", "text/plain", (allowed,))

    def test_duplicate_identity_inventory_and_verdict_mismatch_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = EvidenceWriter._for_test(root / "runs", context(), "b" * 32)
            with self.assertRaises(FileExistsError):
                EvidenceWriter._for_test(root / "runs", context(), "b" * 32)
            source_root = root / "approved"
            source_root.mkdir()
            source = source_root / "result.txt"
            source.write_text("x", encoding="utf-8")
            leaf = first.snapshot(source, "artifacts/result.txt", "text/plain", (source_root,))
            duplicate = validation()
            with self.assertRaises(ValueError):
                first.finalize(
                    verdict="pass",
                    validations=[duplicate, deepcopy(duplicate)],
                    attachments=[leaf],
                    schema_path=SCHEMA,
                )
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(ValueError):
            self.produce(Path(temporary), verdict="pass", result=validation(status="fail"))

    def test_finalize_is_single_use_and_completed_evidence_detects_manifest_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "approved"
            source_root.mkdir()
            source = source_root / "result.txt"
            source.write_text("x", encoding="utf-8")
            writer = EvidenceWriter._for_test(root / "runs", context(), "a" * 32)
            leaf = writer.snapshot(source, "artifacts/result.txt", "text/plain", (source_root,))
            complete = writer.finalize(
                verdict="pass", validations=[validation()], attachments=[leaf], schema_path=SCHEMA
            )
            with self.assertRaises(RuntimeError):
                writer.finalize(verdict="pass", validations=[validation()], attachments=[leaf], schema_path=SCHEMA)
            raw = json.loads((complete / "evidence.json").read_bytes())
            raw["seed"] = 8
            (complete / "evidence.json").write_bytes(canonical_bytes(raw, newline=True))
            self.assertIsNone(verify_evidence(complete, SCHEMA).manifest)

    def test_exit_map_is_public_and_unambiguous(self) -> None:
        self.assertEqual(
            {"pass": 0, "product-fail": 1, "infrastructure-invalid": 2, "contract-invalid": 3},
            EXIT_CODES,
        )
        self.assertEqual(64, 64)
        parsed = build_parser().parse_args(
            [
                "evidence",
                "produce",
                "--trusted-request",
                "/tmp/request.json",
                "--trusted-policy",
                "/tmp/policy.json",
                "--trusted-policy-schema",
                "/tmp/schema.json",
                "--trusted-policy-identity",
                "a" * 40,
                "--trusted-policy-digest",
                DIGEST,
                "--trusted-policy-schema-digest",
                DIGEST,
            ]
        )
        self.assertEqual("produce", parsed.evidence_command)

    def test_declared_case_validation_and_attachment_inventories_are_exact(self) -> None:
        mutations = ("validation", "case", "attachment", "empty-errors")
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source_root = root / "approved"
                source_root.mkdir()
                source = source_root / "result.txt"
                source.write_text("x", encoding="utf-8")
                result = validation(status="fail" if mutation == "empty-errors" else "pass")
                trusted_context = context()
                if mutation == "validation":
                    trusted_context = context(declared_validation_ids=["EVID-901"])
                elif mutation == "case":
                    trusted_context = context(declared_case_ids=["other"])
                elif mutation == "attachment":
                    result["attachments"] = ["artifacts/missing.txt"]
                else:
                    result["errors"] = []
                writer = EvidenceWriter._for_test(
                    root / "runs",
                    trusted_context,
                    f"{index + 20:032x}",
                )
                leaf = writer.snapshot(source, "artifacts/result.txt", "text/plain", (source_root,))
                with self.assertRaises(ValueError):
                    writer.finalize(
                        verdict="product-fail" if mutation == "empty-errors" else "pass",
                        validations=[result],
                        attachments=[leaf],
                        schema_path=SCHEMA,
                    )

    def test_producer_cli_owns_create_through_verified_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            area = Path(temporary)
            project = area / "project"
            project.mkdir()
            (project / "pyproject.toml").write_text('[project]\nname = "mojoattention-cpu"\n', encoding="utf-8")
            schema_dir = project / "schemas"
            schema_dir.mkdir()
            (schema_dir / SCHEMA.name).write_bytes(SCHEMA.read_bytes())
            source_root = project / "reports" / "generated"
            source_root.mkdir(parents=True)
            source = source_root / "result.txt"
            source.write_text("stable evidence\n", encoding="utf-8")
            request = {
                "trusted_base_revision": "3" * 40,
                "candidate_revision": "5" * 40,
                "bounded_context": {
                    key: value
                    for key, value in context().evidence_context().items()
                    if key
                    in {
                        "suite_id",
                        "contract_digest",
                        "config_digest",
                        "protocol_digest",
                        "declared_case_ids",
                        "declared_validation_ids",
                        "seed",
                        "producer",
                        "environment",
                    }
                },
                "verdict": "pass",
                "acceptance_contract": {
                    "contract_digest": DIGEST,
                    "allowed_paths": ["reports/generated"],
                },
                "validations": [validation()],
                "attachments": [
                    {
                        "source": str(source),
                        "path": "artifacts/result.txt",
                        "media_type": "text/plain",
                        "allowed_roots": [str(source_root)],
                    }
                ],
            }
            request_path = area / "request.json"
            policy_path = area / "policy.json"
            policy_schema_path = area / "policy-schema.json"
            request_path.write_text(json.dumps(request), encoding="utf-8")
            policy_path.write_text("{}", encoding="utf-8")
            policy_schema_path.write_text("{}", encoding="utf-8")
            contract_dir = project / "contracts"
            contract_dir.mkdir()
            (contract_dir / "agent-authority.json").write_bytes(
                (ROOT / "contracts" / "agent-authority.json").read_bytes()
            )
            argv = [
                "evidence",
                "produce",
                "--trusted-request",
                str(request_path),
                "--trusted-policy",
                str(policy_path),
                "--trusted-policy-schema",
                str(policy_schema_path),
                "--trusted-policy-identity",
                "a" * 40,
                "--trusted-policy-digest",
                DIGEST,
                "--trusted-policy-schema-digest",
                DIGEST,
            ]
            with (
                patch.dict(os.environ, {"MOJOATTENTION_PROJECT_ROOT": str(project)}),
                patch("mojoattention.cli.main.validate_contract", return_value=()),
                patch(
                    "mojoattention.cli.main.evaluate_and_compose_trusted_context",
                    return_value=(context(), ()),
                ),
                patch(
                    "mojoattention.cli.main.evaluate",
                    return_value=SimpleNamespace(exit_code=0),
                ),
                patch("mojoattention.cli.main.probe"),
                patch("mojoattention.cli.main._require_candidate_checkout"),
                patch(
                    "mojoattention.cli.main._candidate_blob",
                    side_effect=lambda _root, _revision, path: (
                        (ROOT / "contracts" / "agent-authority.json").read_bytes()
                        if path == "contracts/agent-authority.json"
                        else SCHEMA.read_bytes()
                        if path == "schemas/validation-evidence.schema.json"
                        else source.read_bytes()
                    ),
                ),
            ):
                self.assertEqual(0, main(argv))
            complete = next((project / "reports" / "runs").glob("*.complete"))
            self.assertEqual((), verify_evidence(complete, schema_dir / SCHEMA.name).errors)

            with (
                patch.dict(os.environ, {"MOJOATTENTION_PROJECT_ROOT": str(project)}),
                patch("mojoattention.cli.main.validate_contract", return_value=()),
                patch(
                    "mojoattention.cli.main.evaluate_and_compose_trusted_context",
                    return_value=(context(), ()),
                ),
                patch("mojoattention.cli.main.evaluate", return_value=SimpleNamespace(exit_code=0)),
                patch("mojoattention.cli.main.probe"),
                patch("mojoattention.cli.main._require_candidate_checkout"),
                patch(
                    "mojoattention.cli.main._candidate_blob",
                    side_effect=lambda _root, _revision, path: (
                        (ROOT / "contracts" / "agent-authority.json").read_bytes()
                        if path == "contracts/agent-authority.json"
                        else SCHEMA.read_bytes()
                        if path == "schemas/validation-evidence.schema.json"
                        else b"not candidate bytes"
                    ),
                ),
            ):
                self.assertEqual(EXIT_CODES["contract-invalid"], main(argv))

    def test_writer_context_is_detached_and_run_id_is_not_caller_selectable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                EvidenceWriter(root / "forbidden", context(), _run_id="a" * 32)
            writer = EvidenceWriter._for_test(root / "runs", context(), "1" * 32)
            detached = writer.context
            detached["candidate_revision"] = "0" * 40
            source_root = root / "approved"
            source_root.mkdir()
            source = source_root / "result.txt"
            source.write_text("stable evidence\n", encoding="utf-8")
            leaf = writer.snapshot(source, "artifacts/result.txt", "text/plain", (source_root,))
            complete = writer.finalize(
                verdict="pass",
                validations=[validation()],
                attachments=[leaf],
                schema_path=SCHEMA,
            )
            manifest = json.loads((complete / "evidence.json").read_bytes())
            self.assertNotEqual("0" * 40, manifest["candidate_revision"])

    def test_duplicate_creators_are_exclusive_and_failed_writer_can_abort(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def create() -> EvidenceWriter | None:
                try:
                    return EvidenceWriter._for_test(root / "runs", context(), "2" * 32)
                except FileExistsError:
                    return None

            with ThreadPoolExecutor(max_workers=2) as pool:
                writers = list(pool.map(lambda _: create(), range(2)))
            winners = [writer for writer in writers if writer is not None]
            self.assertEqual(1, len(winners))
            winners[0].abort()
            self.assertFalse(any((root / "runs").iterdir()))

    def test_publication_failure_cleanup_removes_only_owned_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "approved"
            source_root.mkdir()
            source = source_root / "result.txt"
            source.write_text("stable evidence\n", encoding="utf-8")
            writer = EvidenceWriter._for_test(root / "runs", context(), "3" * 32)
            leaf = writer.snapshot(source, "artifacts/result.txt", "text/plain", (source_root,))
            with (
                patch("mojoattention.validation.evidence._rename_noreplace_at", side_effect=OSError("EXDEV")),
                self.assertRaises(OSError),
            ):
                writer.finalize(
                    verdict="pass",
                    validations=[validation()],
                    attachments=[leaf],
                    schema_path=SCHEMA,
                )
            writer.abort()
            self.assertFalse((root / "runs" / ("3" * 32 + ".staging")).exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch.object(EvidenceWriter, "_write", side_effect=OSError("fsync/write failure")),
                self.assertRaises(OSError),
            ):
                EvidenceWriter._for_test(root / "runs", context(), "4" * 32)
            self.assertFalse(any((root / "runs").iterdir()))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "approved"
            source_root.mkdir()
            source = source_root / "result.txt"
            source.write_text("stable evidence\n", encoding="utf-8")
            writer = EvidenceWriter._for_test(root / "runs", context(), "5" * 32)
            leaf = writer.snapshot(source, "artifacts/result.txt", "text/plain", (source_root,))
            writer.complete.mkdir()
            with self.assertRaises(OSError):
                writer.finalize(
                    verdict="pass",
                    validations=[validation()],
                    attachments=[leaf],
                    schema_path=SCHEMA,
                )
            writer.abort()
            self.assertTrue(writer.complete.is_dir())
            self.assertFalse(writer.staging.exists())

    def test_consumer_rejects_reordered_mixed_identity_and_hardlinked_closures(self) -> None:
        for index, mutation in enumerate(("reordered", "mixed", "hardlink")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                complete = self.produce(root, run_id=f"{index + 30:032x}")
                manifest_path = complete / "evidence.json"
                manifest = json.loads(manifest_path.read_bytes())
                if mutation == "reordered":
                    manifest["attachments"] = list(reversed(manifest["attachments"]))
                    manifest["attachment_closure_digest"] = digest_bytes(canonical_bytes(manifest["attachments"]))
                    unsigned = dict(manifest)
                    unsigned.pop("evidence_digest")
                    manifest["evidence_digest"] = digest_bytes(canonical_bytes(unsigned))
                    manifest_path.write_bytes(canonical_bytes(manifest, newline=True))
                elif mutation == "mixed":
                    manifest["source_revision"] = "0" * 40
                    unsigned = dict(manifest)
                    unsigned.pop("evidence_digest")
                    manifest["evidence_digest"] = digest_bytes(canonical_bytes(unsigned))
                    manifest_path.write_bytes(canonical_bytes(manifest, newline=True))
                else:
                    os.link(complete / "artifacts" / "result.txt", root / "external-hardlink")
                self.assertTrue(verify_evidence(complete, SCHEMA).errors)

    def test_trusted_inputs_reject_symlinked_components_and_candidate_checkout_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            area = Path(temporary)
            project = area / "project"
            project.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=project, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=project, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=project, check=True)
            tracked = project / "tracked.txt"
            tracked.write_text("clean\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=project, check=True)
            subprocess.run(["git", "commit", "-qm", "seed"], cwd=project, check=True)
            revision = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=project, check=True, capture_output=True, text=True
            ).stdout.strip()
            _require_candidate_checkout(project, revision)
            tracked.write_text("dirty\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                _require_candidate_checkout(project, revision)

            trusted = area / "trusted"
            trusted.mkdir()
            payload = trusted / "request.json"
            payload.write_text("{}", encoding="utf-8")
            alias = area / "alias"
            alias.symlink_to(trusted, target_is_directory=True)
            self.assertEqual(b"{}", _read_protected_caller_bytes(project, str(payload)))
            with self.assertRaises(OSError):
                _read_protected_caller_bytes(project, str(alias / "request.json"))

from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from mojoattention.validation.authority import AuthorityError, authorize_read, authorize_write, validate_manifest

ROOT = Path(__file__).resolve().parents[2]


class AuthorityPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads((ROOT / "contracts" / "agent-authority.json").read_text(encoding="utf-8"))

    def test_canonical_manifest_passes(self) -> None:
        self.assertEqual((), validate_manifest(self.manifest, ROOT))

    def test_unknown_field_and_missing_role_fail(self) -> None:
        invalid = deepcopy(self.manifest)
        invalid["unexpected"] = True
        self.assertIn("AUTH-001", {error.code for error in validate_manifest(invalid, ROOT)})
        invalid = deepcopy(self.manifest)
        invalid["roles"] = invalid["roles"][1:]
        self.assertIn("AUTH-002", {error.code for error in validate_manifest(invalid, ROOT)})

    def test_read_only_scope_overlap_and_self_approval_fail(self) -> None:
        invalid = deepcopy(self.manifest)
        invalid["roles"][1]["write_paths"] = ["src"]
        self.assertIn("AUTH-004", {error.code for error in validate_manifest(invalid, ROOT)})
        invalid = deepcopy(self.manifest)
        invalid["roles"][-1]["write_paths"] = ["src/mojoattention"]
        self.assertIn("AUTH-005", {error.code for error in validate_manifest(invalid, ROOT)})
        invalid = deepcopy(self.manifest)
        invalid["roles"][0]["can_approve_final_merge"] = True
        self.assertIn("AUTH-006", {error.code for error in validate_manifest(invalid, ROOT)})

    def test_noncanonical_and_symlink_scope_fail(self) -> None:
        invalid = deepcopy(self.manifest)
        invalid["roles"][3]["write_paths"] = ["../src"]
        self.assertIn("AUTH-003", {error.code for error in validate_manifest(invalid, ROOT)})
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            link = Path(directory) / "escape"
            link.symlink_to("/tmp")
            invalid = deepcopy(self.manifest)
            invalid["roles"][3]["write_paths"] = [str(link.relative_to(ROOT))]
            self.assertIn("AUTH-003", {error.code for error in validate_manifest(invalid, ROOT)})

    def test_write_requires_role_and_contract_intersection(self) -> None:
        self.assertIsNone(
            authorize_write(self.manifest, "implementer", "modify", "src/mojoattention/config.py", ("src",), root=ROOT)
        )
        denied = authorize_write(self.manifest, "implementer", "modify", "tests/test_bad.py", ("tests",), root=ROOT)
        self.assertEqual(AuthorityError("AUTH-007", "path is outside role authority", "tests/test_bad.py"), denied)
        denied = authorize_write(
            self.manifest, "implementer", "modify", "src/mojoattention/config.py", ("docs",), root=ROOT
        )
        self.assertEqual("AUTH-008", denied.code if denied else "")

    def test_rename_checks_both_endpoints_and_stop_conditions(self) -> None:
        denied = authorize_write(
            self.manifest,
            "implementer",
            "rename",
            "src/mojoattention/config.py",
            ("src",),
            destination="tests/config.py",
            root=ROOT,
        )
        self.assertEqual("AUTH-007", denied.code if denied else "")
        denied = authorize_write(
            self.manifest,
            "implementer",
            "modify",
            "src/mojoattention/config.py",
            ("src",),
            root=ROOT,
            stop="validation-weakening",
        )
        self.assertEqual("AUTH-009", denied.code if denied else "")

    def test_operation_paths_fail_closed(self) -> None:
        for path in ("src/../tests/pwn.py", "/src/pwn.py", "src\\pwn.py"):
            denied = authorize_write(self.manifest, "implementer", "modify", path, ("src",), root=ROOT)
            self.assertEqual("AUTH-003", denied.code if denied else "", path)
        for operation in ("rename", "copy"):
            denied = authorize_write(
                self.manifest, "implementer", operation, "src/mojoattention/config.py", ("src",), root=ROOT
            )
            self.assertEqual("AUTH-010", denied.code if denied else "")

    def test_symlink_protected_generated_and_read_boundaries(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "src") as directory:
            link = Path(directory) / "escape"
            link.symlink_to("/tmp")
            denied = authorize_write(
                self.manifest, "implementer", "modify", str((link / "out.py").relative_to(ROOT)), ("src",), root=ROOT
            )
            self.assertEqual("AUTH-003", denied.code if denied else "")
        denied = authorize_write(
            self.manifest, "implementer", "modify", "src/mojoattention/validation/authority.py", ("src",), root=ROOT
        )
        self.assertEqual("AUTH-009", denied.code if denied else "")
        invalid = deepcopy(self.manifest)
        invalid["roles"][3]["indirect_output_paths"] = ["reports"]
        self.assertEqual((), validate_manifest(invalid, ROOT))
        denied = authorize_write(invalid, "implementer", "modify", "reports/result.json", ("reports",), root=ROOT)
        self.assertEqual("AUTH-007", denied.code if denied else "")
        self.assertIsNone(
            authorize_write(invalid, "implementer", "generate", "reports/result.json", ("reports",), root=ROOT)
        )
        self.assertIsNone(authorize_read(self.manifest, "implementer", "src/mojoattention/config.py", root=ROOT))
        denied = authorize_read(self.manifest, "documentation-agent", "contracts/agent-authority.json", root=ROOT)
        self.assertEqual("AUTH-011", denied.code if denied else "")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "foundation-quality.yml"


class WorkflowPolicyTests(unittest.TestCase):
    def test_minimal_workflow_security_contract(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("name: Foundation Quality", text)
        self.assertIn("pull_request:", text)
        self.assertIn("push:", text)
        self.assertNotIn("pull_request_target", text)
        self.assertNotIn("paths:", text)
        self.assertIn("contents: read", text)
        self.assertNotRegex(text, r"(?m)^\s+contents:\s+write")
        self.assertIn("runs-on: ubuntu-24.04", text)
        self.assertIn("timeout-minutes:", text)
        self.assertIn("cancel-in-progress: true", text)
        self.assertIn("persist-credentials: false", text)
        self.assertNotIn("continue-on-error", text)
        self.assertNotIn("|| true", text)
        self.assertNotIn("; true", text)
        self.assertNotIn("secrets.", text)

    def test_actions_are_full_sha_pinned_and_quality_is_shared(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        uses = re.findall(r"uses:\s*([^\s#]+)", text)
        self.assertEqual(2, len(uses))
        self.assertTrue(all(re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", item) for item in uses), uses)
        self.assertIn("scripts/quality.sh --ci", text)
        self.assertIn("scripts/install-uv.sh", text)
        setup = (ROOT / "docs" / "setup.md").read_text(encoding="utf-8")
        quality = (ROOT / "scripts" / "quality.sh").read_text(encoding="utf-8")
        self.assertIn("scripts/quality.sh --local", setup)
        self.assertIn("scripts/quality.sh --ci", setup)
        for command in ("pytest", "ruff check", "ruff format --check", "mypy"):
            self.assertIn(command, quality)

    def test_quality_is_non_recursive_fast_equivalent_and_preserves_foundation_gates(self) -> None:
        quality = (ROOT / "scripts" / "quality.sh").read_text(encoding="utf-8")
        self.assertNotIn("mojoattention validate --suite fast", quality)
        self.assertIn("FAST_EQUIVALENCE_BOUNDARY", quality)
        for gate in (
            "lock --check",
            "mojoattention privacy",
            "mojoattention authority",
            "mojoattention contract validate",
            "pytest -q",
            "ruff check .",
            "ruff format --check .",
            "mypy",
            "bash -n scripts/*.sh",
        ):
            self.assertIn(gate, quality)


if __name__ == "__main__":
    unittest.main()

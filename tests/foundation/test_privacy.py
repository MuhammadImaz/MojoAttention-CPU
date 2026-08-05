from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from mojoattention.validation.privacy import find_forbidden_tracked_paths

ROOT = Path(__file__).resolve().parents[2]


class PrivacyPolicyTests(unittest.TestCase):
    def test_clean_public_tree_passes_without_reading_ignored_files(self) -> None:
        tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        self.assertEqual((), find_forbidden_tracked_paths(tracked))

    def test_forbidden_aliases_fail_deterministically(self) -> None:
        tracked = (
            b"src/ok.py\0.codex/config.toml\0docs/AGENTS.md\0"
            b".github/copilot-instructions.md\0.github/prompts/private.prompt.md\0"
        )
        self.assertEqual(
            (
                ".codex/config.toml",
                ".github/copilot-instructions.md",
                ".github/prompts/private.prompt.md",
                "docs/AGENTS.md",
            ),
            find_forbidden_tracked_paths(tracked),
        )

    def test_case_alias_and_malformed_path_fail_closed(self) -> None:
        tracked = b".GeMiNi/private.toml\0../AGENTS.md\0"
        self.assertEqual(("../AGENTS.md", ".GeMiNi/private.toml"), find_forbidden_tracked_paths(tracked))

    def test_publish_candidates_include_untracked_nonignored_paths(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            forbidden = Path(directory) / ".GeMiNi" / "settings.json"
            forbidden.parent.mkdir(parents=True)
            forbidden.write_text("synthetic", encoding="utf-8")
            candidates = subprocess.check_output(
                ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
            )
            self.assertIn(str(forbidden.relative_to(ROOT)), find_forbidden_tracked_paths(candidates))

    def test_git_ignore_effective_patterns(self) -> None:
        candidates = (
            b".agents/private.md\0.codex/config.toml\0_bmad-output/story.md\0AGENTS.md\0.gemini/settings.json\0"
            b"reports/agent-loops/example/header.json\0"
        )
        completed = subprocess.run(
            ["git", "check-ignore", "--stdin", "-z"], cwd=ROOT, input=candidates, capture_output=True, check=False
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(set(candidates.rstrip(b"\0").split(b"\0")), set(completed.stdout.rstrip(b"\0").split(b"\0")))


if __name__ == "__main__":
    unittest.main()

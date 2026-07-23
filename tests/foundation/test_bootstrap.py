from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


class BootstrapTests(unittest.TestCase):
    def _seed_temporary_project(self, root: Path) -> Path:
        script_dir = root / "scripts"
        script_dir.mkdir()
        script = script_dir / "bootstrap.sh"
        shutil.copy2(ROOT / "scripts" / "bootstrap.sh", script)
        required = (
            "pyproject.toml",
            "uv.toml",
            "uv.lock",
            ".python-version",
            "README.md",
            "docs/setup.md",
            "src/mojoattention/config.py",
            "src/mojoattention/validation/preflight.py",
            "contracts/README.md",
            "schemas/README.md",
            "fixtures/README.md",
            "reports/README.md",
        )
        for relative in required:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("seed\n", encoding="utf-8")
        uv = root / ".tools" / "uv" / "uv"
        uv.parent.mkdir(parents=True)
        uv.write_text("#!/bin/sh\necho 'uv 0.11.29 (test)'\n", encoding="utf-8")
        uv.chmod(0o755)
        mojoattention = root / ".venv" / "bin" / "mojoattention"
        mojoattention.parent.mkdir(parents=True)
        mojoattention.write_text('#!/bin/sh\necho \'{"verdict":"pass"}\'\n', encoding="utf-8")
        mojoattention.chmod(0o755)
        python = root / ".venv" / "bin" / "python"
        python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        python.chmod(0o755)
        (root / ".cache" / "modular").mkdir(parents=True)
        return script

    @pytest.mark.host_integration
    def test_check_mode_is_idempotent_and_external_cwd_safe(self) -> None:
        script = ROOT / "scripts" / "bootstrap.sh"
        with tempfile.TemporaryDirectory() as outside:
            env = os.environ.copy()
            first = subprocess.run([script, "--check"], cwd=outside, env=env, text=True, capture_output=True)
            second = subprocess.run([script, "--check"], cwd=outside, env=env, text=True, capture_output=True)
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(first.stdout, second.stdout)

    @pytest.mark.host_integration
    def test_external_project_environment_is_neutralized(self) -> None:
        env = os.environ.copy()
        env["UV_PROJECT_ENVIRONMENT"] = "/tmp/shared-environment"
        completed = subprocess.run(
            [ROOT / "scripts" / "bootstrap.sh", "--check"], env=env, text=True, capture_output=True
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("environment=.venv", completed.stdout)

    def test_runner_is_external_cwd_safe_and_exports_project_state(self) -> None:
        code = (
            "import os,pathlib; "
            "print(pathlib.Path.cwd()); "
            "print(os.environ['MODULAR_CACHE_DIR']); "
            "print(os.environ['XDG_DATA_HOME'])"
        )
        with tempfile.TemporaryDirectory() as outside:
            completed = subprocess.run(
                [ROOT / "scripts" / "run.sh", "python", "-c", code],
                cwd=outside,
                text=True,
                capture_output=True,
            )
        self.assertEqual(0, completed.returncode, completed.stderr)
        lines = completed.stdout.splitlines()
        self.assertEqual(str(ROOT), lines[0])
        self.assertEqual(str(ROOT / ".cache" / "modular"), lines[1])
        self.assertEqual(str(ROOT / ".cache" / "xdg-data"), lines[2])

    def test_clean_seed_check_is_idempotent_and_preserves_private_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            script = self._seed_temporary_project(root)
            private = root / "_bmad-output" / "keep.txt"
            private.parent.mkdir()
            private.write_text("keep", encoding="utf-8")
            first = subprocess.run([script, "--check"], cwd=outside, text=True, capture_output=True)
            second = subprocess.run([script, "--check"], cwd=outside, text=True, capture_output=True)
            self.assertEqual(0, first.returncode, first.stderr)
            self.assertEqual(first.stdout, second.stdout)
            self.assertEqual("keep", private.read_text(encoding="utf-8"))

    def test_missing_structure_and_symlinked_environment_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = self._seed_temporary_project(root)
            (root / "schemas" / "README.md").unlink()
            missing = subprocess.run([script, "--check"], text=True, capture_output=True)
            self.assertEqual(3, missing.returncode)
            self.assertIn("required project path is missing", missing.stderr)
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external:
            root = Path(directory)
            script = self._seed_temporary_project(root)
            shutil.rmtree(root / ".venv")
            (root / ".venv").symlink_to(external, target_is_directory=True)
            escaped = subprocess.run([script, "--check"], text=True, capture_output=True)
            self.assertEqual(3, escaped.returncode)
            self.assertIn("refusing symlinked project path", escaped.stderr)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ProjectConfigTests(unittest.TestCase):
    def test_declared_indexes_and_exact_direct_versions(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        uv_config = tomllib.loads((ROOT / "uv.toml").read_text(encoding="utf-8"))
        self.assertEqual("==0.11.29", uv_config["required-version"])
        indexes = {item["name"]: item for item in project["tool"]["uv"]["index"]}
        self.assertEqual("https://pypi.org/simple", indexes["pypi"]["url"])
        self.assertTrue(indexes["modular-stable"]["explicit"])
        self.assertTrue(indexes["pytorch-cpu"]["explicit"])
        dependencies = project["project"]["dependencies"]
        for requirement in ("modular==26.4.0", "numpy==2.5.1", "torch==2.13.0+cpu"):
            self.assertIn(requirement, dependencies)

    def test_lock_is_hashed_and_bound_to_approved_indexes(self) -> None:
        lock_text = (ROOT / "uv.lock").read_text(encoding="utf-8")
        lock = tomllib.loads(lock_text)
        self.assertEqual("==3.14.4", lock["requires-python"])
        self.assertIn('hash = "sha256:', lock_text)
        registries = {package["source"]["registry"] for package in lock["package"] if "registry" in package["source"]}
        self.assertEqual(
            {
                "https://pypi.org/simple",
                "https://modular.gateway.scarf.sh/simple/",
                "https://download.pytorch.org/whl/cpu",
            },
            registries,
        )
        for package in lock["package"]:
            if "registry" not in package["source"]:
                continue
            artifacts = ([package["sdist"]] if "sdist" in package else []) + package.get("wheels", [])
            self.assertTrue(artifacts, package["name"])
            self.assertTrue(all(item.get("hash", "").startswith("sha256:") for item in artifacts), package["name"])

    def test_private_agent_assets_remain_absent_while_minimal_ci_exists(self) -> None:
        self.assertFalse((ROOT / "AGENTS.md").exists())
        self.assertFalse((ROOT / ".codex" / "config.toml").exists())
        self.assertTrue((ROOT / ".github" / "workflows" / "foundation-quality.yml").is_file())

    def test_private_ai_workspace_and_generated_preflight_are_ignored(self) -> None:
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for pattern in (".agents/", ".codex/", "_bmad/", "_bmad-output/", "AGENTS.md", "reports/preflight*.json"):
            self.assertIn(pattern, ignore)

    def test_bootstrap_trust_anchor_and_gate_order_are_explicit(self) -> None:
        installer = (ROOT / "scripts" / "install-uv.sh").read_text(encoding="utf-8")
        bootstrap = (ROOT / "scripts" / "bootstrap.sh").read_text(encoding="utf-8")
        self.assertIn("eec03a8b63d55915694db3af4e91324b39ced49e2aeac7af37851c7eb3f470ea", installer)
        self.assertIn("sha256sum --check", installer)
        self.assertLess(bootstrap.index("preflight --mode broad"), bootstrap.index("sync --locked"))
        self.assertIn('--config-file "${project_root}/uv.toml"', bootstrap)


if __name__ == "__main__":
    unittest.main()

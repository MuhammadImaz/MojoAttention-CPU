from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "foundation-quality.yml"


class WorkflowPolicyTests(unittest.TestCase):
    def test_trusted_base_decision_precedes_every_candidate_execution_boundary(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        ordered = [
            "name: Resolve immutable event identity",
            "name: Check out authenticated trusted base",
            "name: Finalize immutable trusted base identity",
            "name: Acquire trusted validator and controls",
            "name: Validate trusted policy and candidate authorization",
            "name: Check out exact candidate",
            "name: Install checksum-pinned uv",
            "name: Synchronize exact candidate lock",
            "name: Run Foundation Quality",
        ]
        positions = [text.index(item) for item in ordered]
        self.assertEqual(sorted(positions), positions)
        trusted_gate = text[: text.index("name: Check out exact candidate")]
        for forbidden in ("scripts/quality.sh", "scripts/install-uv.sh", "uv sync", "import mojoattention"):
            self.assertNotIn(forbidden, trusted_gate)

    def test_explicit_base_head_binding_and_isolated_trusted_checkout(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.base.sha", text)
        self.assertIn("github.event.pull_request.head.sha", text)
        self.assertIn("github.event.before", text)
        self.assertIn("github.sha", text)
        self.assertIn("fetch-depth: 0", text)
        self.assertNotIn("fetch-depth: 1", text)
        self.assertIn("path: .trusted/base", text)
        self.assertIn("path: candidate", text)
        self.assertIn('GIT_CONFIG_NOSYSTEM: "1"', text)
        self.assertIn("GIT_CONFIG_GLOBAL: /dev/null", text)
        self.assertIn('GIT_NO_REPLACE_OBJECTS: "1"', text)
        self.assertIn('rev-parse "${TRUSTED_BASE}^{commit}"', text)
        self.assertIn('rev-parse "${CANDIDATE_HEAD}^{commit}"', text)
        for binding in (
            "scripts/trusted_ci_gate.py",
            "foundation-trusted-controls/trusted_ci_gate.py",
            "PROTECTED_CHANGE_AUTHORIZATION",
        ):
            self.assertIn(binding, text)
        self.assertIn("id: trusted_controls", text)
        self.assertIn("dispatcher_sha256", text)
        self.assertIn("sha256sum", text)
        run_step = text[text.index("name: Run Foundation Quality") : text.index("name: Evaluate authenticated")]
        self.assertIn("steps.trusted_controls.outputs.dispatcher_sha256", run_step)
        self.assertIn("trusted dispatcher changed after authentication", run_step)
        self.assertIn("foundation-receipt.json", run_step)
        self.assertIn('--receipt "${RUNNER_TEMP}/foundation-receipt.json"', run_step)
        self.assertNotIn('"status":"pass"', run_step)

    def test_trusted_control_inventory_and_capacity_fail_closed_are_explicit(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for path in (
            "contracts/protected-assets.json",
            "schemas/protected-assets.schema.json",
            "contracts/required-checks.json",
            "contracts/ci-tier-policy.json",
            "schemas/required-checks.schema.json",
            "schemas/ci-tier-policy.schema.json",
            "src/mojoattention/validation/protected_assets.py",
            "scripts/trusted_ci_gate.py",
        ):
            self.assertIn(path, text)
        self.assertIn("story-1-8-bootstrap", text)
        self.assertIn("candidate-required-checks.json", text)
        self.assertIn("infrastructure-invalid", text)
        self.assertIn("minimum_memory_gib", text)
        self.assertIn("minimum_logical_cpus", text)
        self.assertNotRegex(text, r"pytest[^\n]*(?:-k|--ignore|--deselect)")
        self.assertNotIn("skip", text.lower())

    def test_embedded_trusted_evaluator_and_capacity_programs_compile(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        programs = re.findall(r"<<'PY'\n(.*?)\n\s*PY", text, flags=re.DOTALL)
        self.assertEqual(1, len(programs))
        for index, program in enumerate(programs):
            normalized = "\n".join(
                line[10:] if line.startswith("          ") else line for line in program.splitlines()
            )
            compile(normalized, f"workflow-program-{index}", "exec")

    def test_minimal_workflow_security_contract(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("name: Foundation Quality", text)
        self.assertIn("pull_request:", text)
        self.assertIn("push:", text)
        self.assertNotIn("branches: [main]", text)
        self.assertIn("github.event.repository.default_branch", text)
        self.assertIn("steps.event_identity.outputs.trusted_ref", text)
        self.assertIn("Finalize immutable trusted base identity", text)
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
        self.assertEqual(4, len(uses))
        self.assertTrue(all(re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", item) for item in uses), uses)
        self.assertIn("scripts/run_ci_plan.py", text)
        tier_policy = (ROOT / "contracts/ci-tier-policy.json").read_text(encoding="utf-8")
        self.assertIn('"command":["scripts/quality.sh","--ci"]', tier_policy)
        self.assertIn("scripts/install-uv.sh", text)
        self.assertIn("UV_DEFAULT_INDEX: https://pypi.org/simple", text)
        self.assertNotIn("UV_INDEX:", text)
        self.assertIn("sync --locked --all-groups", text)
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("https://modular.gateway.scarf.sh/simple/", project)
        self.assertIn("https://download.pytorch.org/whl/cpu", project)
        setup = (ROOT / "docs" / "setup.md").read_text(encoding="utf-8")
        quality = (ROOT / "scripts" / "quality.sh").read_text(encoding="utf-8")
        self.assertIn("scripts/quality.sh --local", setup)
        self.assertIn("scripts/quality.sh --ci", setup)
        for command in ("pytest", "ruff check", "ruff format --check", "mypy"):
            self.assertIn(command, quality)

    def test_complete_evidence_is_verified_before_non_overwriting_upload(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        ordered = [
            "name: Run Foundation Quality",
            "name: Produce and independently verify canonical evidence",
            "name: Verify canonical evidence from authenticated trusted base",
            "name: Upload verified complete evidence",
        ]
        positions = [text.index(item) for item in ordered]
        self.assertEqual(sorted(positions), positions)
        publication = text[text.index(ordered[1]) :]
        self.assertIn('--foundation-receipt "${RUNNER_TEMP}/foundation-receipt.json"', publication)
        self.assertIn("*.complete", publication)
        trusted_verify = text[text.index(ordered[2]) : text.index(ordered[3])]
        self.assertIn(".trusted/base/src", trusted_verify)
        self.assertIn("verify_ci_evidence", trusted_verify)
        self.assertIn("steps.evidence.outputs.complete_path", trusted_verify)
        self.assertIn("evidence_digest", publication)
        self.assertIn("GITHUB_STEP_SUMMARY", publication)
        self.assertIn("github.run_id", publication)
        self.assertIn("github.run_attempt", publication)
        self.assertIn("steps.identity.outputs.candidate_head", publication)
        self.assertIn("retention-days: ${{ steps.evidence.outputs.retention_days }}", publication)
        self.assertIn("overwrite: false", publication)
        self.assertIn("if-no-files-found: error", publication)
        self.assertNotIn("if: always()", publication)

    def test_hosted_governance_and_evidence_are_required(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        quality_start = text.index("name: Run Foundation Quality")
        governance_start = text.index("name: Evaluate authenticated hosted governance")
        quality_step = text[quality_start:governance_start]
        self.assertNotIn("if:", quality_step)
        self.assertNotIn("if: ${{ vars.GOVERNANCE_OBSERVATION != '' }}", text)
        self.assertIn("date -u +%Y-%m-%dT%H:%M:%SZ", text)
        self.assertNotIn('--evaluation-time "${observed_at}"', text)

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

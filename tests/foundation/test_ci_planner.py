from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from mojoattention.cli.main import main
from mojoattention.validation.ci_planner import Change, git_changes, load_ci_controls, plan_ci

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "contracts/ci-tier-policy.json"
POLICY_SCHEMA = ROOT / "schemas/ci-tier-policy.schema.json"
REGISTRY = ROOT / "contracts/required-checks.json"
REGISTRY_SCHEMA = ROOT / "schemas/required-checks.schema.json"
BASE = "1" * 40
HEAD = "2" * 40


def load_plan_runner():
    spec = importlib.util.spec_from_file_location("run_ci_plan", ROOT / "scripts/run_ci_plan.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def controls() -> tuple[dict[str, object], dict[str, object]]:
    return load_ci_controls(POLICY, POLICY_SCHEMA, REGISTRY, REGISTRY_SCHEMA)


def candidate_paths(policy: dict[str, object], *tiers: str) -> frozenset[str]:
    selected = set(tiers) | {"fast"}
    return frozenset(
        path
        for item in policy["tiers"]  # type: ignore[union-attr]
        if item["tier_id"] in selected
        for path in item["required_artifacts"]
    )


def activate(registry: dict[str, object], *tiers: str) -> dict[str, object]:
    result = deepcopy(registry)
    for item in result["tiers"]:  # type: ignore[union-attr]
        if item["tier_id"] in tiers:
            item["activation"] = "active"
    return result


def inventories(*tiers: str) -> dict[str, tuple[str, ...]]:
    return {tier: (f"{tier.upper().replace('-', '')}-001",) for tier in tiers}


class CiPlannerTests(unittest.TestCase):
    def test_policy_and_registry_have_the_same_complete_ordered_tier_inventory(self) -> None:
        policy, registry = controls()
        expected = [
            "fast",
            "correctness",
            "model",
            "training-smoke",
            "benchmark-smoke",
            "nightly",
            "stable-benchmark",
            "release",
        ]
        self.assertEqual(expected, [item["tier_id"] for item in policy["tiers"]])  # type: ignore[index]
        self.assertEqual(expected, [item["tier_id"] for item in registry["tiers"]])  # type: ignore[index]

    def test_foundation_only_change_has_no_fake_product_success(self) -> None:
        policy, registry = controls()
        plan = plan_ci(
            policy,
            registry,
            (Change("M", "docs/governance.md"),),
            candidate_paths(policy),
            event_class="pull-request",
            base_revision=BASE,
            head_revision=HEAD,
        )
        self.assertEqual("pass", plan.verdict)
        self.assertEqual(("fast",), plan.required_tiers)
        self.assertEqual(("scripts/quality.sh", "--ci"), plan.commands[0])
        self.assertIn("correctness", plan.not_applicable_tiers)

    def test_kernel_change_requires_real_activated_correctness_suite(self) -> None:
        policy, registry = controls()
        change = (Change("A", "src/mojoattention/backends/mojo/scalar.py"),)
        missing = plan_ci(
            policy,
            registry,
            change,
            candidate_paths(policy),
            event_class="pull-request",
            base_revision=BASE,
            head_revision=HEAD,
        )
        self.assertEqual("contract-invalid", missing.verdict)
        self.assertEqual(("fast", "correctness"), missing.required_tiers)
        self.assertEqual({"CI-PLAN-002", "CI-PLAN-003", "CI-PLAN-004"}, {item.code for item in missing.findings})
        complete = plan_ci(
            policy,
            activate(registry, "correctness"),
            change,
            candidate_paths(policy, "correctness"),
            inventories("correctness"),
            event_class="pull-request",
            base_revision=BASE,
            head_revision=HEAD,
        )
        self.assertEqual("pass", complete.verdict)
        self.assertEqual(2, len(complete.commands))

    def test_reserved_correctness_allows_declared_contract_precursors_but_applies_after_activation(self) -> None:
        policy, registry = controls()
        change = (Change("M", "contracts/kernel/kernel-contract.json"),)
        precursor = plan_ci(
            policy,
            registry,
            change,
            candidate_paths(policy),
            event_class="pull-request",
            base_revision=BASE,
            head_revision=HEAD,
        )
        self.assertEqual("pass", precursor.verdict)
        self.assertEqual(("fast",), precursor.required_tiers)
        active = plan_ci(
            policy,
            activate(registry, "correctness"),
            change,
            candidate_paths(policy, "correctness"),
            inventories("correctness"),
            event_class="pull-request",
            base_revision=BASE,
            head_revision=HEAD,
        )
        self.assertEqual("pass", active.verdict)
        self.assertEqual(("fast", "correctness"), active.required_tiers)

    def test_model_training_and_benchmark_changes_close_prerequisite_union(self) -> None:
        policy, registry = controls()
        changes = (
            Change("A", "src/mojoattention/model/training/loop.py"),
            Change("A", "src/mojoattention/benchmark/runner.py"),
        )
        required = ("correctness", "model", "training-smoke", "benchmark-smoke")
        plan = plan_ci(
            policy,
            activate(registry, *required),
            changes,
            candidate_paths(policy, *required),
            inventories(*required),
            event_class="pull-request",
            base_revision=BASE,
            head_revision=HEAD,
        )
        self.assertEqual("pass", plan.verdict)
        self.assertEqual(("fast", *required), plan.required_tiers)

    def test_rename_uses_source_and_destination_and_cannot_hide_cross_area_impact(self) -> None:
        policy, registry = controls()
        plan = plan_ci(
            policy,
            registry,
            (Change("R", "docs/old-kernel.py", "src/mojoattention/backends/mojo/scalar.py"),),
            candidate_paths(policy),
            event_class="pull-request",
            base_revision=BASE,
            head_revision=HEAD,
        )
        self.assertIn("correctness", plan.required_tiers)
        self.assertEqual(
            ("docs/old-kernel.py", "src/mojoattention/backends/mojo/scalar.py"),
            plan.changed_paths,
        )

    def test_git_copy_detection_includes_an_unchanged_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "ci@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "CI"], cwd=root, check=True)
            source = root / "src/mojoattention/backends/reference.py"
            source.parent.mkdir(parents=True)
            source.write_text("canonical unchanged source\n" * 20, encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            destination = root / "docs/copied-reference.py"
            destination.parent.mkdir()
            destination.write_bytes(source.read_bytes())
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "copy"], cwd=root, check=True)
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            changes = git_changes(root, base, head)
            self.assertIn(
                Change("C", "docs/copied-reference.py", "src/mojoattention/backends/reference.py"),
                changes,
            )

    def test_schedule_and_release_require_full_declared_prerequisite_graph(self) -> None:
        policy, registry = controls()
        nightly = ("correctness", "model", "training-smoke", "nightly")
        scheduled = plan_ci(
            policy,
            activate(registry, *nightly),
            (),
            candidate_paths(policy, *nightly),
            inventories(*nightly),
            event_class="schedule",
            base_revision=BASE,
            head_revision=HEAD,
        )
        self.assertEqual(("fast", "correctness", "model", "training-smoke", "nightly"), scheduled.required_tiers)
        release = ("correctness", "model", "training-smoke", "benchmark-smoke", "release")
        released = plan_ci(
            policy,
            activate(registry, *release),
            (),
            candidate_paths(policy, *release),
            inventories(*release),
            event_class="release",
            base_revision=BASE,
            head_revision=HEAD,
        )
        self.assertEqual(("fast", *release), released.required_tiers)

    def test_unsafe_rename_source_is_rejected_instead_of_silently_dropped(self) -> None:
        policy, registry = controls()
        with self.assertRaisesRegex(ValueError, "unsafe"):
            plan_ci(
                policy,
                registry,
                (Change("R", "docs/safe.md", "../src/mojoattention/backends/mojo.py"),),
                candidate_paths(policy),
                event_class="pull-request",
                base_revision=BASE,
                head_revision=HEAD,
            )

    def test_schema_and_semantics_reject_unknown_fields_reordering_and_cycles(self) -> None:
        policy = json.loads(POLICY.read_bytes())
        for mutation in ("unknown", "reorder", "cycle"):
            candidate = deepcopy(policy)
            if mutation == "unknown":
                candidate["unknown"] = True
            elif mutation == "reorder":
                candidate["tiers"][0], candidate["tiers"][1] = candidate["tiers"][1], candidate["tiers"][0]
            else:
                candidate["tiers"][1]["prerequisites"] = ["model"]
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "policy.json"
                path.write_text(json.dumps(candidate), encoding="utf-8")
                with self.assertRaises(ValueError, msg=mutation):
                    load_ci_controls(path, POLICY_SCHEMA, REGISTRY, REGISTRY_SCHEMA)

    def test_cli_emits_canonical_foundation_plan_for_unchanged_commit(self) -> None:
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "plan.json"
            self.assertEqual(
                0,
                main(
                    [
                        "ci",
                        "plan",
                        "--base",
                        revision,
                        "--head",
                        revision,
                        "--event",
                        "push-branch",
                        "--json",
                        str(output),
                    ]
                ),
            )
            plan = json.loads(output.read_bytes())
            self.assertEqual("pass", plan["verdict"])
            self.assertEqual(["fast"], plan["required_tiers"])

    def test_plan_runner_executes_argv_without_shell_and_rejects_empty_plan(self) -> None:
        runner = load_plan_runner()
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = Path(temporary) / "plan.json"
            revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            valid = {
                "schema_version": "1.0.0",
                "verdict": "pass",
                "base_revision": revision,
                "identity_kind": "worktree",
                "head_revision": runner._worktree_identity(ROOT, revision),
                "trusted_control_digests": {
                    "contracts/ci-tier-policy.json": "sha256:" + hashlib.sha256(POLICY.read_bytes()).hexdigest()
                },
                "executions": [
                    {
                        "tier_id": "fast",
                        "command": ["bash", "-n", "scripts/quality.sh"],
                        "minimum_memory_gib": 0,
                        "minimum_logical_cpus": 0,
                    }
                ],
            }

            def seal(payload: dict[str, object]) -> str:
                payload.pop("plan_digest", None)
                value = (
                    "sha256:"
                    + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                )
                payload["plan_digest"] = value
                return value

            digest = seal(valid)
            plan_path.write_text(json.dumps(valid), encoding="utf-8")
            args = [str(plan_path), digest, str(ROOT), str(ROOT)]
            self.assertEqual(0, runner.main(args))
            wrong_head = deepcopy(valid)
            wrong_head["head_revision"] = "0" * 40
            wrong_digest = seal(wrong_head)
            plan_path.write_text(json.dumps(wrong_head), encoding="utf-8")
            self.assertEqual(3, runner.main([str(plan_path), wrong_digest, str(ROOT), str(ROOT)]))
            forged_control = deepcopy(valid)
            forged_control["trusted_control_digests"] = {"contracts/ci-tier-policy.json": "sha256:" + "0" * 64}
            forged_digest = seal(forged_control)
            plan_path.write_text(json.dumps(forged_control), encoding="utf-8")
            self.assertEqual(3, runner.main([str(plan_path), forged_digest, str(ROOT), str(ROOT)]))
            plan_path.write_text(json.dumps(valid), encoding="utf-8")
            valid["executions"][0]["command"] = ["bash", "-c", "exit 0"]
            plan_path.write_text(json.dumps(valid), encoding="utf-8")
            self.assertEqual(3, runner.main(args))
            valid["executions"][0]["command"] = ["bash", "-n", "scripts/quality.sh"]
            valid["executions"] = []
            digest = seal(valid)
            plan_path.write_text(json.dumps(valid), encoding="utf-8")
            args[1] = digest
            self.assertEqual(3, runner.main(args))
            valid["executions"] = [
                {
                    "tier_id": "correctness",
                    "command": ["bash", "-n", "scripts/quality.sh"],
                    "minimum_memory_gib": 1_000_000,
                    "minimum_logical_cpus": 1_000_000,
                }
            ]
            digest = seal(valid)
            plan_path.write_text(json.dumps(valid), encoding="utf-8")
            args[1] = digest
            self.assertEqual(2, runner.main(args))

    def test_product_result_requires_exact_inventory_counts_verdict_and_evidence_closure(self) -> None:
        runner = load_plan_runner()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "evidence" / "result.txt"
            artifact.parent.mkdir()
            artifact.write_text("proved\n", encoding="utf-8")
            manifest = {
                "schema_version": "1.0.0",
                "suite_id": "correctness",
                "required_total": 3,
                "validations": [
                    {"validation_id": "CORRECTNESS-001", "required_count": 2},
                    {"validation_id": "CORRECTNESS-002", "required_count": 1},
                ],
                "verdict_rules": {
                    name: "contract-invalid" for name in ("skip", "xfail", "empty", "missing", "duplicate", "reduced")
                },
                "evidence": {"require_complete": True, "require_sha256_closure": True},
            }
            manifest["manifest_digest"] = runner._canonical_digest(manifest, "manifest_digest")
            execution = {"tier_id": "correctness", "manifest": manifest}
            second_artifact = root / "evidence" / "result-2.txt"
            second_artifact.write_text("proved too\n", encoding="utf-8")
            evidence = {
                "entries": [
                    {
                        "validation_id": "CORRECTNESS-001",
                        "observed_count": 2,
                        "path": "evidence/result.txt",
                        "sha256": runner._sha256(artifact.read_bytes()),
                    },
                    {
                        "validation_id": "CORRECTNESS-002",
                        "observed_count": 1,
                        "path": "evidence/result-2.txt",
                        "sha256": runner._sha256(second_artifact.read_bytes()),
                    },
                ]
            }
            evidence["evidence_digest"] = runner._canonical_digest(evidence, "evidence_digest")
            valid = {
                "schema_version": "1.0.0",
                "suite_id": "correctness",
                "manifest_digest": manifest["manifest_digest"],
                "verdict": "pass",
                "required_total": 3,
                "observed_total": 3,
                "skipped_total": 0,
                "xfailed_total": 0,
                "validations": [
                    {"validation_id": "CORRECTNESS-001", "observed_count": 2, "status": "pass"},
                    {"validation_id": "CORRECTNESS-002", "observed_count": 1, "status": "pass"},
                ],
                "evidence": evidence,
            }
            runner._verify_product_result(execution, json.dumps(valid).encode(), root)
            incomplete_evidence = deepcopy(valid)
            incomplete_evidence["evidence"]["entries"] = incomplete_evidence["evidence"]["entries"][:1]
            incomplete_evidence["evidence"]["evidence_digest"] = runner._canonical_digest(
                incomplete_evidence["evidence"], "evidence_digest"
            )
            with self.assertRaises(ValueError):
                runner._verify_product_result(execution, json.dumps(incomplete_evidence).encode(), root)
            mutations = []
            for label in ("missing", "partial", "reduced", "skipped", "xfailed", "forged", "no-evidence"):
                candidate = deepcopy(valid)
                if label in {"missing", "partial"}:
                    candidate["validations"] = candidate["validations"][:1]
                elif label == "reduced":
                    candidate["validations"][0]["observed_count"] = 1
                elif label == "skipped":
                    candidate["skipped_total"] = 1
                elif label == "xfailed":
                    candidate["xfailed_total"] = 1
                elif label == "forged":
                    candidate["manifest_digest"] = "sha256:" + "0" * 64
                else:
                    candidate["evidence"] = {"entries": [], "evidence_digest": "sha256:" + "0" * 64}
                mutations.append((label, candidate))
            mutations.append(("no-op", b""))
            for label, candidate in mutations:
                payload = candidate if isinstance(candidate, bytes) else json.dumps(candidate).encode()
                with self.assertRaises(ValueError, msg=label):
                    runner._verify_product_result(execution, payload, root)

    def test_each_suite_manifest_and_runner_path_triggers_its_own_tier(self) -> None:
        policy, registry = controls()
        for tier in [item for item in policy["tiers"] if item["tier_id"] != "fast"]:
            tier_id = tier["tier_id"]
            for path in tier["required_artifacts"]:
                plan = plan_ci(
                    policy,
                    registry,
                    (Change("M", path),),
                    candidate_paths(policy),
                    event_class="pull-request",
                    base_revision=BASE,
                    head_revision=HEAD,
                )
                self.assertIn(tier_id, plan.required_tiers, path)


if __name__ == "__main__":
    unittest.main()

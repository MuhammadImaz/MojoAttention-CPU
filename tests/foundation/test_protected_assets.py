from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

from mojoattention.validation.protected_assets import (
    AuthorizationContext,
    ChangeEffect,
    TrustedPolicyInput,
    _parse_raw_diff,
    compute_change_digest,
    compute_provenance_digest,
    evaluate_protected_changes,
    git_blob_oid,
    inspect_repository_changes,
    load_trusted_authorization,
    validate_policy,
)

ROOT = Path(__file__).resolve().parents[2]


def run_git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "core.quotePath=false", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def commit(root: Path, message: str) -> str:
    run_git(root, "add", "-A")
    run_git(root, "commit", "-m", message)
    return run_git(root, "rev-parse", "HEAD")


def policy() -> dict[str, object]:
    return json.loads((ROOT / "contracts" / "protected-assets.json").read_text(encoding="utf-8"))


def trusted_policy() -> TrustedPolicyInput:
    policy_bytes = (ROOT / "contracts" / "protected-assets.json").read_bytes()
    schema_bytes = (ROOT / "schemas" / "protected-assets.schema.json").read_bytes()
    return TrustedPolicyInput(
        policy_bytes=policy_bytes,
        schema_bytes=schema_bytes,
        identity=git_blob_oid(policy_bytes),
        policy_digest="sha256:" + hashlib.sha256(policy_bytes).hexdigest(),
        schema_digest="sha256:" + hashlib.sha256(schema_bytes).hexdigest(),
    )


class ProtectedPolicyTests(unittest.TestCase):
    def test_canonical_policy_and_schema_pass(self) -> None:
        self.assertEqual((), validate_policy(policy(), ROOT / "schemas" / "protected-assets.schema.json"))

    def test_policy_rejects_missing_category_unsafe_path_overlap_and_cycle(self) -> None:
        for mutation in ("category", "unsafe", "overlap", "cycle", "cross-overlap", "self-cycle"):
            candidate = deepcopy(policy())
            if mutation == "category":
                candidate["protected_categories"].pop()  # type: ignore[union-attr]
            elif mutation == "unsafe":
                candidate["protected_scopes"][0]["paths"] = ["../tests"]  # type: ignore[index]
            elif mutation == "overlap":
                candidate["protected_scopes"][0]["paths"] = ["tests", "tests/foundation"]  # type: ignore[index]
            elif mutation == "cycle":
                candidate["generated_rules"] = [  # type: ignore[index]
                    {"id": "a", "trigger_paths": ["src"], "output_paths": ["reports"]},
                    {"id": "b", "trigger_paths": ["reports"], "output_paths": ["src"]},
                ]
            elif mutation == "cross-overlap":
                candidate["generated_rules"] = [  # type: ignore[index]
                    {"id": "a", "trigger_paths": ["src"], "output_paths": ["reports/a"]},
                    {"id": "b", "trigger_paths": ["src/generated"], "output_paths": ["reports/b"]},
                ]
            else:
                candidate["generated_rules"] = [  # type: ignore[index]
                    {"id": "a", "trigger_paths": ["reports"], "output_paths": ["reports/generated"]},
                ]
            self.assertTrue(validate_policy(candidate, ROOT / "schemas" / "protected-assets.schema.json"), mutation)

    def test_authorization_loader_applies_the_trusted_v2_schema(self) -> None:
        malformed = {
            "provenance_digest": "sha256:" + "0" * 64,
            "approval_anchor_revision": "not-a-revision",
        }
        malformed["provenance_digest"] = compute_provenance_digest(malformed)
        loaded, errors = load_trusted_authorization(
            json.dumps(malformed).encode(),
            (ROOT / "schemas" / "protected-change-authorization.schema.json").read_bytes(),
        )
        self.assertIsNone(loaded)
        self.assertEqual({"PROT-004"}, {error.code for error in errors})

    def test_change_digest_is_order_independent_and_identity_bound(self) -> None:
        effects = (
            ChangeEffect("modify", "tests/a.py", "100644", "100644", "1" * 40, "2" * 40),
            ChangeEffect("delete", "schemas/a.json", "100644", "000000", "3" * 40, "0" * 40),
        )
        first = compute_change_digest("a" * 40, "b" * 40, "c" * 40, "d" * 40, "e" * 40, "sha256:" + "1" * 64, effects)
        second = compute_change_digest(
            "a" * 40,
            "b" * 40,
            "c" * 40,
            "d" * 40,
            "e" * 40,
            "sha256:" + "1" * 64,
            tuple(reversed(effects)),
        )
        self.assertEqual(first, second)
        self.assertNotEqual(
            first,
            compute_change_digest("a" * 40, "f" * 40, "c" * 40, "d" * 40, "e" * 40, "sha256:" + "1" * 64, effects),
        )
        self.assertNotEqual(
            first,
            compute_change_digest("a" * 40, "b" * 40, "c" * 40, "d" * 40, "e" * 40, "sha256:" + "2" * 64, effects),
        )

    def test_every_canonical_category_is_enforced(self) -> None:
        candidate = policy()
        scopes = candidate["protected_scopes"]
        assert isinstance(scopes, list)
        effects = tuple(
            ChangeEffect("modify", scope["paths"][0], "100644", "100644", "1" * 40, "2" * 40) for scope in scopes
        )
        identity = {
            "trusted_base_revision": "a" * 40,
            "trusted_base_tree": "b" * 40,
            "candidate_revision": "c" * 40,
            "candidate_tree": "d" * 40,
            "trusted_policy_oid": "e" * 40,
            "trusted_policy_digest": "sha256:" + "f" * 64,
        }
        digest = compute_change_digest("a" * 40, "b" * 40, "c" * 40, "d" * 40, "e" * 40, "sha256:" + "f" * 64, effects)
        errors = evaluate_protected_changes(candidate, effects, identity, digest, "sha256:" + "1" * 64, None)
        self.assertEqual(len(scopes), len(errors))
        self.assertEqual({"PROT-003"}, {error.code for error in errors})

    def test_contract_digest_is_validated_even_without_protected_effects(self) -> None:
        errors = evaluate_protected_changes(
            policy(),
            (ChangeEffect("modify", "README.md", "100644", "100644", "1" * 40, "2" * 40),),
            {"trusted_base_revision": "a" * 40},
            "sha256:" + "3" * 64,
            "invalid",
            None,
        )
        self.assertEqual({"PROT-004"}, {error.code for error in errors})

    def test_raw_parser_covers_change_kinds_typed_entries_and_unusual_paths(self) -> None:
        zero = b"0" * 40
        one = b"1" * 40
        records = [
            b":000000 100644 " + zero + b" " + one + b" A\0added\0",
            b":100644 100755 " + one + b" " + one + b" M\0mode-change\0",
            b":100644 000000 " + one + b" " + zero + b" D\0deleted\0",
            b":100644 100644 " + one + b" " + one + b" R100\0old name\0new\nname\0",
            b":100644 100644 " + one + b" " + one + b" C075\0copy-from\0copy-to\0",
            b":100644 120000 " + one + b" " + one + b" T\0link\0",
            b":100644 160000 " + one + b" " + one + b" T\0submodule\0",
        ]
        effects = _parse_raw_diff(b"".join(records))
        self.assertEqual(
            {"add", "modify", "delete", "rename", "copy", "type-change"},
            {effect.kind for effect in effects},
        )
        self.assertTrue(any(effect.new_mode == "120000" for effect in effects))
        self.assertTrue(any(effect.new_mode == "160000" for effect in effects))
        self.assertTrue(any(effect.source_path == "old name" and effect.path == "new\nname" for effect in effects))

    def test_raw_parser_rejects_malformed_modes_oids_statuses_and_scores(self) -> None:
        zero = b"0" * 40
        one = b"1" * 40
        records = (
            b":100600 100644 " + one + b" " + one + b" M\0path\0",
            b":100644 100644 bad " + one + b" M\0path\0",
            b":100644 100644 " + one + b" " + one + b" X\0path\0",
            b":100644 100644 " + one + b" " + one + b" R101\0old\0new\0",
            b":000000 100644 " + zero + b" " + one + b" A12\0path\0",
        )
        for record in records:
            with self.subTest(record=record), self.assertRaises(ValueError):
                _parse_raw_diff(record)

    def test_unauthorized_and_exact_authorized_effects(self) -> None:
        effects = (ChangeEffect("modify", "tests/foundation/test_x.py", "100644", "100644", "1" * 40, "2" * 40),)
        identity = {
            "trusted_base_revision": "a" * 40,
            "trusted_base_tree": "b" * 40,
            "candidate_revision": "c" * 40,
            "candidate_tree": "d" * 40,
            "trusted_policy_oid": "e" * 40,
            "trusted_policy_digest": "sha256:" + "f" * 64,
        }
        digest = compute_change_digest(
            *(
                identity[key]
                for key in (
                    "trusted_base_revision",
                    "trusted_base_tree",
                    "candidate_revision",
                    "candidate_tree",
                    "trusted_policy_oid",
                )
            ),
            identity["trusted_policy_digest"],
            effects,
        )  # type: ignore[arg-type]
        errors = evaluate_protected_changes(policy(), effects, identity, digest, "sha256:" + "1" * 64, None)
        self.assertEqual({"PROT-003"}, {error.code for error in errors})
        authorization = {
            "schema_version": "2.0.0",
            "authorization_id": "human-story-1-4",
            "contract_digest": "sha256:" + "1" * 64,
            "source_revision": identity["trusted_base_revision"],
            **identity,
            "change_set_digest": digest,
            "authorized_protected_paths": ["tests/foundation/test_x.py"],
            "approval_anchor_revision": "9" * 40,
            "approver_kind": "human",
            "provenance_digest": "sha256:" + "0" * 64,
        }
        authorization["provenance_digest"] = compute_provenance_digest(authorization)
        context = AuthorizationContext(
            envelope=authorization,
            approval_anchor_revision="9" * 40,
            contract_digest="sha256:" + "1" * 64,
        )
        self.assertEqual(
            (), evaluate_protected_changes(policy(), effects, identity, digest, "sha256:" + "1" * 64, context)
        )
        authorization["candidate_revision"] = "8" * 40
        authorization["provenance_digest"] = compute_provenance_digest(authorization)
        self.assertEqual(
            {"PROT-004"},
            {
                e.code
                for e in evaluate_protected_changes(policy(), effects, identity, digest, "sha256:" + "1" * 64, context)
            },
        )

    def test_generator_effects_are_inferred_transitively(self) -> None:
        candidate = deepcopy(policy())
        candidate["generated_rules"] = [  # type: ignore[index]
            {"id": "build", "trigger_paths": ["src"], "output_paths": ["reports/generated"]},
            {"id": "publish", "trigger_paths": ["reports/generated"], "output_paths": ["fixtures/golden"]},
        ]
        effects = (ChangeEffect("modify", "src/a.py", "100644", "100644", "1" * 40, "2" * 40),)
        identity = {
            "trusted_base_revision": "a" * 40,
            "trusted_base_tree": "b" * 40,
            "candidate_revision": "c" * 40,
            "candidate_tree": "d" * 40,
            "trusted_policy_oid": "e" * 40,
            "trusted_policy_digest": "sha256:" + "f" * 64,
        }
        inferred = (
            *effects,
            ChangeEffect(
                "generated",
                "reports/generated",
                "000000",
                "000000",
                "0" * 40,
                "0" * 40,
                inferred_by="build",
            ),
            ChangeEffect(
                "generated",
                "fixtures/golden",
                "000000",
                "000000",
                "0" * 40,
                "0" * 40,
                inferred_by="publish",
            ),
        )
        digest = compute_change_digest("a" * 40, "b" * 40, "c" * 40, "d" * 40, "e" * 40, "sha256:" + "f" * 64, inferred)
        errors = evaluate_protected_changes(candidate, inferred, identity, digest, "sha256:" + "1" * 64, None)
        paths = {str(error.context.get("path")) for error in errors}
        self.assertIn("fixtures/golden", paths)


class ProtectedGitTests(unittest.TestCase):
    def test_git_inspection_reads_trusted_policy_and_detects_modify_delete_rename_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            run_git(repo, "init", "-q")
            run_git(repo, "config", "user.name", "Test")
            run_git(repo, "config", "user.email", "test@example.invalid")
            (repo / "contracts").mkdir()
            (repo / "schemas").mkdir()
            (repo / "tests").mkdir()
            (repo / "pyproject.toml").write_text(
                '[project]\nname = "mojoattention-cpu"\nversion = "0.0.0"\n', encoding="utf-8"
            )
            (repo / "contracts" / "protected-assets.json").write_text(json.dumps(policy()), encoding="utf-8")
            (repo / "schemas" / "protected-assets.schema.json").write_text(
                (ROOT / "schemas" / "protected-assets.schema.json").read_text(encoding="utf-8"), encoding="utf-8"
            )
            (repo / "tests" / "modify.py").write_text("assert True\n", encoding="utf-8")
            (repo / "tests" / "delete.py").write_text("assert True\n", encoding="utf-8")
            (repo / "tests" / "rename.py").write_text("assert True\n", encoding="utf-8")
            base = commit(repo, "base")
            supplied_policy = trusted_policy()
            identical, identical_errors = inspect_repository_changes(repo, base, base, supplied_policy)
            self.assertEqual((), identical_errors)
            assert identical is not None
            self.assertEqual((), identical.effects)
            (repo / "tests" / "modify.py").write_text("assert False\n", encoding="utf-8")
            (repo / "tests" / "delete.py").unlink()
            (repo / "tests" / "rename.py").rename(repo / "tests" / "renamed.py")
            (repo / "tests" / "link.py").symlink_to("modify.py")
            candidate = commit(repo, "candidate")
            result, errors = inspect_repository_changes(repo, base, candidate, supplied_policy)
            self.assertEqual((), errors)
            assert result is not None
            kinds = {effect.kind for effect in result.effects}
            self.assertTrue({"modify", "delete", "rename", "add"}.issubset(kinds))
            self.assertTrue(any(effect.new_mode == "120000" for effect in result.effects))
            self.assertEqual(base, result.identity["trusted_base_revision"])
            self.assertEqual(candidate, result.identity["candidate_revision"])
            cli = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "mojoattention.cli.main",
                    "protected",
                    "validate",
                    "--trusted-base-revision",
                    base,
                    "--candidate-revision",
                    candidate,
                    "--contract-digest",
                    "sha256:" + "1" * 64,
                    "--trusted-policy",
                    str(ROOT / "contracts" / "protected-assets.json"),
                    "--trusted-policy-schema",
                    str(ROOT / "schemas" / "protected-assets.schema.json"),
                    "--trusted-policy-identity",
                    supplied_policy.identity,
                    "--trusted-policy-digest",
                    supplied_policy.policy_digest,
                    "--trusted-policy-schema-digest",
                    supplied_policy.schema_digest,
                    "--json",
                    "-",
                ],
                cwd=repo,
                env={**os.environ, "MOJOATTENTION_PROJECT_ROOT": str(repo)},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(3, cli.returncode)
            cli_payload = json.loads(cli.stdout)
            self.assertEqual("contract-invalid", cli_payload["verdict"])
            self.assertEqual("PROT-003", cli_payload["errors"][0]["code"])

            authorization = {
                "schema_version": "2.0.0",
                "authorization_id": "human-story-1-4",
                "contract_digest": "sha256:" + "1" * 64,
                "source_revision": result.identity["trusted_base_revision"],
                **result.identity,
                "change_set_digest": result.change_set_digest,
                "authorized_protected_paths": sorted(
                    {
                        str(error.context["path"])
                        for error in evaluate_protected_changes(
                            result.policy,
                            result.effects,
                            result.identity,
                            result.change_set_digest,
                            "sha256:" + "1" * 64,
                            None,
                        )
                    }
                ),
                "approval_anchor_revision": "9" * 40,
                "approver_kind": "human",
                "provenance_digest": "sha256:" + "0" * 64,
            }
            authorization["provenance_digest"] = compute_provenance_digest(authorization)
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as authorization_file:
                json.dump(authorization, authorization_file)
                authorization_file.flush()
                authorized_cli = subprocess.run(
                    [
                        *cli.args,
                        "--authorization",
                        authorization_file.name,
                        "--trusted-authorization-schema",
                        str(ROOT / "schemas" / "protected-change-authorization.schema.json"),
                        "--approval-anchor-revision",
                        "9" * 40,
                    ],
                    cwd=repo,
                    env={**os.environ, "MOJOATTENTION_PROJECT_ROOT": str(repo)},
                    text=True,
                    capture_output=True,
                    check=False,
                )
            self.assertEqual(0, authorized_cli.returncode, authorized_cli.stderr)
            self.assertEqual("pass", json.loads(authorized_cli.stdout)["verdict"])

            local_input_cli = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "mojoattention.cli.main",
                    "protected",
                    "validate",
                    "--trusted-base-revision",
                    base,
                    "--candidate-revision",
                    candidate,
                    "--contract-digest",
                    "sha256:" + "1" * 64,
                    "--trusted-policy",
                    str(repo / "contracts" / "protected-assets.json"),
                    "--trusted-policy-schema",
                    str(repo / "schemas" / "protected-assets.schema.json"),
                    "--trusted-policy-identity",
                    supplied_policy.identity,
                    "--trusted-policy-digest",
                    supplied_policy.policy_digest,
                    "--trusted-policy-schema-digest",
                    supplied_policy.schema_digest,
                    "--json",
                    "-",
                ],
                cwd=repo,
                env={**os.environ, "MOJOATTENTION_PROJECT_ROOT": str(repo)},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(3, local_input_cli.returncode)
            self.assertEqual("PROT-001", json.loads(local_input_cli.stdout)["errors"][0]["code"])

    def test_symbolic_abbreviated_missing_and_identical_revisions_fail_or_pass_deterministically(self) -> None:
        _, errors = inspect_repository_changes(ROOT, "HEAD", "HEAD", trusted_policy())
        self.assertEqual({"PROT-001", "PROT-002"}, {error.code for error in errors})

    def test_policy_oid_digest_and_schema_digest_must_match_supplied_bytes(self) -> None:
        revision = run_git(ROOT, "rev-parse", "HEAD")
        supplied = trusted_policy()
        for mutation in (
            replace(supplied, identity="e" * 40),
            replace(supplied, policy_digest="sha256:" + "e" * 64),
            replace(supplied, schema_digest="sha256:" + "e" * 64),
        ):
            with self.subTest(mutation=mutation):
                result, errors = inspect_repository_changes(ROOT, revision, revision, mutation)
                self.assertIsNone(result)
                self.assertEqual({"PROT-001"}, {error.code for error in errors})


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mojoattention.validation.host import (
    _RUN_VERIFICATION_CACHE,
    _cpu_flags,
    _memory,
    _run_state,
    _tree_size,
    _verify_complete_cached,
)
from mojoattention.validation.preflight import RunState


class HostAdapterTests(unittest.TestCase):
    def tearDown(self) -> None:
        _RUN_VERIFICATION_CACHE.clear()

    def test_cpu_flags_are_intersected_across_all_processors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cpuinfo = Path(directory) / "cpuinfo"
            cpuinfo.write_text("processor: 0\nflags: avx avx2 pni abm\nprocessor: 1\nflags: avx pni abm\n")
            flags = _cpu_flags(cpuinfo)
        self.assertIn("sse3", flags)
        self.assertIn("lzcnt", flags)
        self.assertNotIn("avx2", flags)

    def test_missing_or_malformed_memory_probe_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            malformed = Path(directory) / "meminfo"
            malformed.write_text("MemTotal: nope kB\n", encoding="utf-8")
            self.assertEqual((0, 0), _memory(missing))
            self.assertEqual((0, 0), _memory(malformed))

    def test_run_markers_and_corruption_fail_closed_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runs = root / "reports" / "runs"
            runs.mkdir(parents=True)
            marker = runs / ".active.json"
            marker.write_text("keep", encoding="utf-8")
            self.assertEqual(RunState.ACTIVE, _run_state(root))
            self.assertEqual("keep", marker.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runs = root / "reports" / "runs"
            runs.parent.mkdir(parents=True)
            runs.write_text("corrupt", encoding="utf-8")
            self.assertEqual(RunState.UNSEALED, _run_state(root))

    def test_cache_symlink_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external:
            root = Path(directory)
            cache = root / ".cache" / "modular"
            cache.parent.mkdir()
            cache.symlink_to(external, target_is_directory=True)
            self.assertEqual(2**63 - 1, _tree_size(cache, root))

    def test_complete_run_verification_cache_is_invalidated_by_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / ("a" * 32 + ".complete")
            run.mkdir()
            leaf = run / "evidence.json"
            leaf.write_text("first", encoding="utf-8")
            schema = root / "schema.json"
            schema.write_text("{}", encoding="utf-8")
            with patch("mojoattention.validation.host.verify_evidence") as verify:
                verify.return_value.errors = ()
                self.assertTrue(_verify_complete_cached(run, schema))
                self.assertTrue(_verify_complete_cached(run, schema))
                self.assertEqual(1, verify.call_count)
                leaf.write_text("changed-size", encoding="utf-8")
                self.assertTrue(_verify_complete_cached(run, schema))
                self.assertEqual(2, verify.call_count)

    def test_complete_run_verification_cache_rejects_mutation_during_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / ("a" * 32 + ".complete")
            run.mkdir()
            leaf = run / "evidence.json"
            leaf.write_text("first", encoding="utf-8")
            schema = root / "schema.json"
            schema.write_text("{}", encoding="utf-8")

            def mutate(*_args: object, **_kwargs: object) -> object:
                leaf.write_text("changed-size", encoding="utf-8")
                result = unittest.mock.Mock()
                result.errors = ()
                return result

            with patch("mojoattention.validation.host.verify_evidence", side_effect=mutate) as verify:
                self.assertFalse(_verify_complete_cached(run, schema))
                self.assertEqual(1, verify.call_count)
                self.assertFalse(_RUN_VERIFICATION_CACHE)

    def test_complete_run_verification_cache_rejects_mutation_during_cache_hit(self) -> None:
        signature_a = (("evidence.json", 1, 2, 3, 4),)
        signature_b = (("evidence.json", 1, 2, 5, 6),)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / ("a" * 32 + ".complete")
            run.mkdir()
            schema = root / "schema.json"
            schema.write_text("{}", encoding="utf-8")
            with (
                patch("mojoattention.validation.host._run_signature", side_effect=(signature_a, signature_a)),
                patch("mojoattention.validation.host.verify_evidence") as verify,
            ):
                verify.return_value.errors = ()
                self.assertTrue(_verify_complete_cached(run, schema))
            with (
                patch("mojoattention.validation.host._run_signature", side_effect=(signature_a, signature_b)),
                patch("mojoattention.validation.host.verify_evidence") as verify,
            ):
                self.assertFalse(_verify_complete_cached(run, schema))
                verify.assert_not_called()

    def test_complete_run_verification_cache_binds_schema_bytes_and_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / ("a" * 32 + ".complete")
            run.mkdir()
            (run / "evidence.json").write_text("first", encoding="utf-8")
            schema = root / "schema.json"
            schema.write_text("{}", encoding="utf-8")
            with patch("mojoattention.validation.host.verify_evidence") as verify:
                verify.return_value.errors = ()
                self.assertTrue(_verify_complete_cached(run, schema))
                schema.write_text('{"type":"object"}', encoding="utf-8")
                self.assertTrue(_verify_complete_cached(run, schema))
                self.assertEqual(2, verify.call_count)

            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            schema.unlink()
            schema.symlink_to(target)
            with self.assertRaises(OSError):
                _verify_complete_cached(run, schema)


if __name__ == "__main__":
    unittest.main()

# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for parallel unit-test sharding and diff-scoped neuter-matrix execution."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from scripts import neuter_matrix as nm  # noqa: E402
from scripts import run_unit_tests as rut  # noqa: E402


class ParallelUnitTestRunnerTests(unittest.TestCase):
    def test_discovers_exact_same_modules_as_unittest_discover(self):
        std_suite = unittest.defaultTestLoader.discover(str(_REF_ROOT), pattern="test*.py")
        expected_mods: set[str] = set()

        def _walk(s):
            for item in s:
                if isinstance(item, unittest.TestSuite):
                    _walk(item)
                else:
                    expected_mods.add(item.__class__.__module__)

        _walk(std_suite)
        discovered = rut.discover_test_modules(_REF_ROOT, pattern="test*.py")
        actual_mods = {m.module_name for m in discovered}
        self.assertEqual(actual_mods, expected_mods)
        # Heavy suites must be scheduled at the front of the LPT queue.
        top_10 = [m.module_name for m in discovered[:10]]
        self.assertIn("tests.test_security_regression", top_10)

    def test_parallel_runner_executes_passes_and_catches_failures_under_safepath(self):
        with tempfile.TemporaryDirectory(prefix="mantis_rut_") as tmp:
            root = Path(tmp)
            tests_dir = root / "tests"
            tests_dir.mkdir()
            (tests_dir / "__init__.py").write_text("", encoding="utf-8")
            (tests_dir / "test_alpha.py").write_text(
                "import unittest\n"
                "class AlphaTest(unittest.TestCase):\n"
                "    def test_ok(self):\n"
                "        self.assertEqual(1 + 1, 2)\n",
                encoding="utf-8",
            )
            (tests_dir / "test_beta.py").write_text(
                "import unittest\n"
                "class BetaTest(unittest.TestCase):\n"
                "    def test_two(self):\n"
                "        self.assertTrue(True)\n"
                "    def test_three(self):\n"
                "        self.assertEqual('a'.upper(), 'A')\n",
                encoding="utf-8",
            )
            import contextlib
            import io

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc_ok = rut.run_suite(ref_root=root, jobs=2)
            self.assertEqual(rc_ok, 0)

            (tests_dir / "test_gamma.py").write_text(
                "import unittest\n"
                "class GammaTest(unittest.TestCase):\n"
                "    def test_boom(self):\n"
                "        self.assertEqual(1, 2)\n",
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc_fail = rut.run_suite(ref_root=root, jobs=2)
            self.assertEqual(rc_fail, 1)


class DiffScopedNeuterMatrixTests(unittest.TestCase):
    def test_unrelated_changes_select_zero_scenarios_and_exit_cleanly(self):
        scoped, reason = nm.scenarios_for_changed_files(["README.md", "reference/core/depth.py"])
        self.assertEqual(scoped, [], reason)
        self.assertTrue(nm.run_matrix([], jobs=1))

    def test_targeted_source_change_selects_matching_scenarios_only(self):
        scoped, _ = nm.scenarios_for_changed_files(["reference/core/paths.py"])
        self.assertIsNotNone(scoped)
        assert scoped is not None
        self.assertGreaterEqual(len(scoped), 2)
        self.assertIn("revert_midpath_walk", scoped)
        self.assertLess(len(scoped), len(nm.SCENARIOS))

    def test_modifying_neuter_matrix_or_pinned_test_escalates_to_full_matrix(self):
        scoped_nm, _ = nm.scenarios_for_changed_files(["reference/scripts/neuter_matrix.py"])
        self.assertIsNone(scoped_nm)
        scoped_pin, _ = nm.scenarios_for_changed_files(["reference/tests/test_symbol_grounding.py"])
        self.assertIsNone(scoped_pin)

    def test_cli_empty_changed_from_and_unrelated_changed_files(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-P",
                str(_REF_ROOT / "scripts" / "neuter_matrix.py"),
                "--changed-files",
                "README.md",
            ],
            cwd=str(_REF_ROOT),
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONSAFEPATH": "1"},
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("0 scenarios target", proc.stdout)


if __name__ == "__main__":
    unittest.main()

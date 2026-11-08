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

"""Operator exclusions (core.exclusions): what a scan leaves alone.

Covers the matcher, and the three places a pattern changes what a run does:
file discovery (file-by-file and auto), the surveyor's groups
(cross-functional), and the agent's listing (whole). Reading an excluded
file stays allowed; that is asserted too, since it is the deliberate half
of the design.
"""
from __future__ import annotations

import asyncio
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from core.exclusions import filter_excluded, is_excluded, normalize_exclude_patterns  # noqa: E402


class TestMatcher(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(normalize_exclude_patterns(None), ())
        self.assertEqual(normalize_exclude_patterns(""), ())
        self.assertEqual(normalize_exclude_patterns("vendor/, ./third_party/*,,a\nb"),
                         ("vendor", "third_party/*", "a", "b"))
        self.assertEqual(normalize_exclude_patterns(["vendor", "vendor/", "x,y"]), ("vendor", "x", "y"))
        self.assertEqual(normalize_exclude_patterns(["a\\b\\"]), ("a/b",))
        self.assertEqual(normalize_exclude_patterns([3, None, "ok"]), ("ok",))

    def test_bare_name_matches_any_depth_and_whole_components_only(self):
        pats = ("vendor",)
        self.assertTrue(is_excluded("vendor/a.go", pats))
        self.assertTrue(is_excluded("src/vendor/a/b.go", pats))
        self.assertTrue(is_excluded("src/vendor", pats))
        self.assertFalse(is_excluded("src/vendored.go", pats))
        self.assertFalse(is_excluded("src/myvendor/a.go", pats))

    def test_slashed_pattern_is_anchored_to_the_target(self):
        pats = ("third_party/*",)
        self.assertTrue(is_excluded("third_party/zlib/inflate.c", pats))
        self.assertFalse(is_excluded("src/third_party/zlib/inflate.c", pats))
        self.assertTrue(is_excluded("src/gen/a.pb.go", ("src/gen/*.pb.go",)))
        self.assertFalse(is_excluded("src/gen/a.go", ("src/gen/*.pb.go",)))

    def test_file_globs_and_case(self):
        self.assertTrue(is_excluded("a/b/c.min.js", ("*.min.js",)))
        self.assertFalse(is_excluded("a/b/c.js", ("*.min.js",)))
        self.assertFalse(is_excluded("Vendor/a.go", ("vendor",)), "case-sensitive, like paths")

    def test_edge_inputs(self):
        self.assertFalse(is_excluded("", ("vendor",)))
        self.assertFalse(is_excluded("vendor/a.go", ()))
        self.assertTrue(is_excluded("/vendor/a.go", ("vendor",)))
        self.assertTrue(is_excluded("vendor\\a.go", ("vendor",)))
        self.assertEqual(filter_excluded(["a.py", "vendor/b.py", "c.py"], ("vendor",)), ["a.py", "c.py"])
        self.assertEqual(filter_excluded(["a.py", "vendor/b.py"], ()), ["a.py", "vendor/b.py"])


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def make_tree(tmp: str, git: bool = True) -> Path:
    repo = Path(tmp) / "repo"
    for rel, body in {
        "src/app.py": "def main():\n    return 1\n",
        "src/util.py": "def helper(x):\n    return x\n",
        "src/testdata/fixture.py": "x = 1\n",
        "vendor/lib/thing.py": "def vendored():\n    return 2\n",
        "tests/test_app.py": "from src.app import main\n",
        "docs/readme.txt": "hi\n",
    }.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    if git:
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "add", "-A")
    return repo


class TestDiscovery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_excl_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def rel(self, repo, files):
        return sorted(os.path.relpath(f, repo) for f in files)

    def test_discover_files_honours_exclusions_on_both_paths(self):
        import main as main_mod

        for git in (True, False):
            repo = make_tree(tempfile.mkdtemp(dir=self.tmp), git=git)
            everything = self.rel(repo, main_mod.discover_files(repo))
            self.assertIn("vendor/lib/thing.py", everything)
            self.assertIn("src/testdata/fixture.py", everything)
            kept = self.rel(repo, main_mod.discover_files(repo, exclude=("vendor", "testdata", "docs/*")))
            self.assertEqual(kept, ["src/app.py", "src/util.py", "tests/test_app.py"], (git, kept))
            # No patterns: byte-identical to before.
            self.assertEqual(self.rel(repo, main_mod.discover_files(repo, exclude=())), everything)

    def test_surveyor_leaves_excluded_files_out_of_every_group(self):
        from core.surveyor import survey

        repo = make_tree(self.tmp)
        full = survey(repo, include_churn=False)
        trimmed = survey(repo, include_churn=False, exclude=("vendor", "testdata"))

        def roots(astm):
            return {r for s in astm["slices"] for r in s["root_paths"]}

        self.assertEqual(full["provenance"]["vetted_file_count"], 6)
        self.assertEqual(trimmed["provenance"]["vetted_file_count"], 4)
        self.assertTrue(any(r.startswith("vendor") for r in roots(full)),
                        f"fixture must survey vendor unfiltered: {roots(full)}")
        self.assertFalse(any(r.startswith("vendor") or "testdata" in r for r in roots(trimmed)),
                         roots(trimmed))
        # The snapshot is computed over what remains, so it differs.
        self.assertNotEqual(full["snapshot_id"], trimmed["snapshot_id"])
        # No patterns: identical to the unfiltered call.
        self.assertEqual(survey(repo, include_churn=False, exclude=())["snapshot_id"],
                         full["snapshot_id"])

    def test_listing_hides_excluded_paths_but_reading_still_works(self):
        from core.context import RunContext, current_run_context
        from tools.research_tools import list_files, read_file

        repo = make_tree(self.tmp, git=False)
        ctx = RunContext(jail_dir=str(repo), db_path="", exclude=("vendor", "testdata"))
        token = current_run_context.set(ctx)
        try:
            listing = asyncio.run(list_files(""))
            self.assertIn("src/app.py", listing)
            self.assertNotIn("vendor", listing)
            self.assertNotIn("testdata", listing)
            sub = asyncio.run(list_files("src"))
            self.assertIn("src/util.py", sub)
            self.assertNotIn("fixture.py", sub)
            body = asyncio.run(read_file("vendor/lib/thing.py"))
            self.assertIn("def vendored", body)
        finally:
            current_run_context.reset(token)
        # No exclusions: the listing is what it always was.
        token = current_run_context.set(RunContext(jail_dir=str(repo), db_path=""))
        try:
            self.assertIn("vendor/lib/thing.py", asyncio.run(list_files("")))
        finally:
            current_run_context.reset(token)

    def test_discover_files_rejects_symlink_dirs_hardlinks_env_and_bad_git_jail(self):
        import main as main_mod

        repo = make_tree(self.tmp, git=True)
        outside_dir = Path(self.tmp) / "outside_host_dir"
        outside_dir.mkdir()
        outside_file = outside_dir / "secret_target.py"
        outside_file.write_text("SECRET = 1\n", encoding="utf-8")

        # 1. Stage a file in git under `escape/secret_target.py`, then replace `escape` with a symlink
        #    pointing outside the repository so `git ls-files` emits `escape/secret_target.py` while
        #    `(repo / "escape/secret_target.py").is_symlink()` is False!
        escape_dir = repo / "escape"
        escape_dir.mkdir()
        (escape_dir / "secret_target.py").write_text("x = 1\n", encoding="utf-8")
        (repo / ".env").write_text("API_KEY=supersecret\n", encoding="utf-8")
        _git(repo, "add", "-f", "escape/secret_target.py", ".env")
        shutil.rmtree(escape_dir)
        escape_dir.symlink_to(outside_dir)

        # 2. Hardlink inside checkout aliasing `outside_file`
        hardlink_path = repo / "src" / "hardlinked.py"
        os.link(outside_file, hardlink_path)

        rels = self.rel(repo, main_mod.discover_files(repo))
        self.assertIn("src/app.py", rels)
        self.assertNotIn("escape/secret_target.py", rels)
        self.assertNotIn(".env", rels)
        self.assertNotIn("src/hardlinked.py", rels)

        # 3. Unvetted git config causes `_validate_git_jail` to fail; `discover_files` skips git
        #    without executing git filters and still rejects symlinked dirs and hardlinks on fallback walk.
        marker = Path(self.tmp) / "git_filter_ran"
        (repo / ".gitattributes").write_text("* filter=evil\n", encoding="utf-8")
        with open(repo / ".git" / "config", "a", encoding="utf-8") as fh:
            fh.write(f'\n[filter "evil"]\n\tclean = touch {marker}\n')

        rels_fallback = self.rel(repo, main_mod.discover_files(repo))
        self.assertFalse(marker.exists())
        self.assertIn("src/app.py", rels_fallback)
        self.assertNotIn("escape/secret_target.py", rels_fallback)
        self.assertNotIn("src/hardlinked.py", rels_fallback)
        self.assertNotIn(".env", rels_fallback)


class TestCli(unittest.TestCase):
    def test_exclude_flag_is_repeatable_and_comma_separated(self):
        from scripts.launch import build_parser

        args = build_parser().parse_args(["x", "--exclude", "vendor,testdata", "--exclude", "docs/*"])
        self.assertEqual(args.exclude, ["vendor,testdata", "docs/*"])
        self.assertEqual(normalize_exclude_patterns(args.exclude), ("vendor", "testdata", "docs/*"))

    def test_workflow_config_accepts_exclude(self):
        from core.graph_loader import GlobalConfig

        self.assertEqual(GlobalConfig(exclude=["vendor"]).exclude, ["vendor"])
        self.assertEqual(GlobalConfig(exclude="vendor,docs").exclude, "vendor,docs")
        self.assertIsNone(GlobalConfig().exclude)


if __name__ == "__main__":
    unittest.main()

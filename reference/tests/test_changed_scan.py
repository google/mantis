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

"""Coverage knows what content it covered; `--scan-mode changed` scans the rest.

A file a completed campaign covered used to stay covered whatever happened
to it afterwards: edit it, run again, and every mode that consults the
ledger skipped it. The ledger now records each covered file's content
(core.cost.coverage_files); a covered file that differs now is uncovered
again, and the `changed` mode scans exactly those plus never-covered
files, in one campaign over the whole target. Issue #15.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from core.cost import (  # noqa: E402
    changed_files, content_changed, file_identity, record_coverage_files, record_spend,
    scope_identities, uncovered_files,
)
from core.database import init_db, record_run  # noqa: E402

RUN = "11111111-2222-3333-4444-555555555555"


def _touch_later(path: str) -> None:
    """Makes the next write land on a different mtime even on coarse clocks."""
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))


class _Repo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_changed_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = os.path.realpath(os.path.join(self.tmp, "repo"))
        os.makedirs(os.path.join(self.repo, "pkg"))
        self.files = {}
        for name in ("a", "b", "pkg/c"):
            p = os.path.join(self.repo, f"{name}.py")
            Path(p).write_text(f"def {name.split('/')[-1]}():\n    return 1\n")
            self.files[name] = p
        self.db = os.path.join(self.tmp, "k.db")
        init_db(self.db)

    def cover(self, *names, run=RUN, target=None, model=""):
        """A completed campaign over `target` (default: the repo) that
        examined `names`, content and all."""
        if model:
            record_run(self.db, run, model)
        record_spend(self.db, run, target or self.repo, "whole", tokens=10, metadata={"failed": False})
        record_coverage_files(self.db, run, target or self.repo,
                              scope_identities([self.files[n] for n in names]))

    def edit(self, name, text="def x():\n    return 2\n"):
        _touch_later(self.files[name])
        Path(self.files[name]).write_text(text)


class ContentIdentityTest(_Repo):
    def test_identity_is_content_size_and_mtime(self):
        h, size, mtime = file_identity(self.files["a"])
        self.assertEqual(len(h), 16)
        self.assertEqual(size, os.path.getsize(self.files["a"]))
        self.assertEqual(mtime, os.stat(self.files["a"]).st_mtime_ns)
        self.assertIsNone(file_identity(self.repo), "a directory has no content identity")
        self.assertIsNone(file_identity(os.path.join(self.repo, "missing.py")))

    def test_unchanged_touched_and_edited(self):
        ident = file_identity(self.files["a"])
        ids = [ident]
        self.assertFalse(content_changed(self.files["a"], ids))
        # Touched: mtime moved, bytes did not -- the hash decides, not the clock.
        _touch_later(self.files["a"])
        self.assertFalse(content_changed(self.files["a"], ids))
        # Edited: different bytes.
        self.edit("a")
        self.assertTrue(content_changed(self.files["a"], ids))
        # Edited back to a version the ledger knows: unchanged against that version.
        self.assertFalse(content_changed(self.files["a"], ids + [file_identity(self.files["a"])]))
        self.assertFalse(content_changed(self.files["a"], []), "no record, no change")

    def test_size_and_mtime_short_circuit_without_reading(self):
        h, size, mtime = file_identity(self.files["a"])
        # A lie in the hash is not noticed when size+mtime still match: that
        # is the git-index rule, and it is what keeps a large tree cheap.
        self.assertFalse(content_changed(self.files["a"], [("0000000000000000", size, mtime)]))
        # Without size/mtime (an imported row) the file is hashed.
        self.assertTrue(content_changed(self.files["a"], [("0000000000000000", None, None)]))
        self.assertFalse(content_changed(self.files["a"], [(h, None, None)]))


class LedgerTest(_Repo):
    def test_a_covered_file_edited_since_is_uncovered_again(self):
        files = list(self.files.values())
        self.cover("a", "b", "pkg/c")
        self.assertEqual(uncovered_files(self.db, files), [])
        self.assertEqual(changed_files(self.db, files), {"files": []})
        self.edit("b")
        self.assertEqual(uncovered_files(self.db, files), [self.files["b"]])
        self.assertEqual(changed_files(self.db, files), {"files": [self.files["b"]]})
        self.assertEqual(uncovered_files(self.db, files, rescan_changed_files=False), [],
                         "the old answer is still available on request")

    def test_a_file_covered_before_content_was_recorded_stays_covered(self):
        """INV-6: turning the content ledger on must not re-sweep an existing
        knowledge base. A spend row with no content row covers for every
        version of the file."""
        files = list(self.files.values())
        record_spend(self.db, RUN, self.repo, "whole", tokens=10, metadata={"failed": False})
        self.edit("a")
        self.assertEqual(uncovered_files(self.db, files), [])
        self.assertEqual(changed_files(self.db, files), {"files": []})

    def test_a_new_file_and_an_edited_file_are_both_uncovered(self):
        self.cover("a", "b", "pkg/c")
        new = os.path.join(self.repo, "pkg", "d.py")
        Path(new).write_text("def d():\n    return 4\n")
        self.edit("pkg/c")
        files = list(self.files.values()) + [new]
        self.assertEqual(sorted(uncovered_files(self.db, files)), sorted([self.files["pkg/c"], new]))
        self.assertEqual(changed_files(self.db, files), {"files": [self.files["pkg/c"]]},
                         "a new file is uncovered, not changed")

    def test_a_file_added_under_an_old_whole_tree_row_is_still_covered(self):
        """INV-6 again: a whole-tree campaign that recorded no content cannot
        say which files existed then, so a file under it is covered -- the
        ancestor rule as it always was. Only once EVERY covering campaign
        recorded content can "not recorded" mean "not there"."""
        record_spend(self.db, RUN, self.repo, "whole", tokens=10, metadata={"failed": False})
        new = os.path.join(self.repo, "pkg", "d.py")
        Path(new).write_text("def d():\n    return 4\n")
        files = list(self.files.values()) + [new]
        self.assertEqual(uncovered_files(self.db, files), [])
        # A later change-scoped campaign over the root that recorded content
        # for ONE file must not make the others read as new.
        record_spend(self.db, "22222222-2222-3333-4444-555555555555", self.repo, "changed", tokens=10,
                     metadata={"failed": False})
        record_coverage_files(self.db, "22222222-2222-3333-4444-555555555555", self.repo,
                              scope_identities([self.files["a"]]))
        self.assertEqual(uncovered_files(self.db, files), [])

    def test_content_recorded_for_tells_an_old_ledger_from_an_unchanged_tree(self):
        from core.cost import content_recorded_for

        files = list(self.files.values())
        record_spend(self.db, RUN, self.repo, "whole", tokens=10, metadata={"failed": False})
        self.assertEqual(content_recorded_for(self.db, files), 0)
        self.cover("a", "b", run="22222222-2222-3333-4444-555555555555")
        self.assertEqual(content_recorded_for(self.db, files), 2)

    def test_content_coverage_is_per_model_like_the_rest(self):
        files = list(self.files.values())
        self.cover("a", "b", "pkg/c", model="vertex_ai/gemini-3.8-flash")
        self.assertEqual(uncovered_files(self.db, files, model="vertex_ai/gemini-3.8-flash"), [])
        self.assertEqual(len(uncovered_files(self.db, files, model="other/model")), 3,
                         "another model has covered nothing here")
        self.edit("a")
        self.assertEqual(uncovered_files(self.db, files, model="vertex_ai/gemini-3.8-flash"), [self.files["a"]])

    def test_a_second_campaign_records_the_new_content(self):
        files = list(self.files.values())
        self.cover("a", "b", "pkg/c")
        self.edit("a")
        self.cover("a", run="22222222-2222-3333-4444-555555555555")
        self.assertEqual(uncovered_files(self.db, files), [], "covered as it is now")

    def test_changed_files_can_be_asked_per_run(self):
        self.cover("a", "b")
        self.cover("pkg/c", run="33333333-2222-3333-4444-555555555555")
        self.edit("a")
        self.edit("pkg/c")
        files = list(self.files.values())
        self.assertEqual(changed_files(self.db, files, run_id=RUN), {"files": [self.files["a"]]})
        self.assertEqual(changed_files(self.db, files), {"files": [self.files["a"], self.files["pkg/c"]]})

    def test_ledger_writes_are_bookkeeping(self):
        self.assertEqual(record_coverage_files("", RUN, self.repo, [(self.files["a"], "ab", 1, 1)]), 0)
        self.assertEqual(record_coverage_files(self.db, RUN, self.repo, []), 0)
        bad = os.path.join(self.tmp, "nope", "k.db")
        self.assertEqual(record_coverage_files(bad, RUN, self.repo, [(self.files["a"], "ab", 1, 1)]), 0)
        self.assertIsNone(changed_files("", []), "no ledger: unknowable")
        self.assertEqual(changed_files(bad, list(self.files.values())), {"files": []}, "no file: nothing recorded")


class ResolveTest(_Repo):
    def _resolve(self, mode, **cfg):
        import main

        scope: dict = {}
        config = {"scan_mode": mode, "surveyor": {"min_source_files": 1000}, **cfg}
        targets, astm, resolved = main.resolve_scan_targets(
            Path(self.repo), config, list(self.files.values()), db_path=self.db, scope_out=scope)
        return targets, resolved, scope

    def test_changed_is_a_scan_mode_with_its_aliases(self):
        import main

        self.assertIn("changed", main._SCAN_MODES)
        self.assertEqual(main.normalize_scan_mode("incremental"), "changed")
        self.assertEqual(main.normalize_scan_mode("changed-files"), "changed")

    def test_nothing_changed_means_nothing_to_scan(self):
        self.cover("a", "b", "pkg/c")
        targets, resolved, scope = self._resolve("changed")
        self.assertEqual((targets, resolved), ([], "changed"))
        self.assertTrue(scope["nothing_changed"])

    def test_changed_files_become_one_root_campaign_scoped_to_them(self):
        self.cover("a", "b", "pkg/c")
        self.edit("b")
        targets, resolved, scope = self._resolve("changed")
        self.assertEqual(targets, [self.repo], "the campaign is over the target, not the file")
        self.assertEqual(resolved, "changed")
        self.assertEqual(scope["focus_files"], [self.files["b"]])
        self.assertEqual(scope["focus_groups"], [{"dir": self.repo, "files": [self.files["b"]]}])
        self.assertFalse(scope["nothing_changed"])

    def test_a_first_run_in_changed_mode_scans_everything_as_new(self):
        targets, resolved, scope = self._resolve("changed")
        # Three files in two directories. pkg/ has one changed file: too
        # small to stand alone by preference, but it cannot climb into the
        # root (a root campaign would span every other), so it stays; the two
        # root files are then one single-file campaign each.
        self.assertEqual(targets, [self.files["a"], self.files["b"], os.path.join(self.repo, "pkg")])
        self.assertEqual(sorted(scope["focus_files"]), sorted(self.files.values()))
        self.assertEqual([(g["dir"], g["files"]) for g in scope["focus_groups"]], [
            (self.files["a"], [self.files["a"]]),
            (self.files["b"], [self.files["b"]]),
            (os.path.join(self.repo, "pkg"), [self.files["pkg/c"]]),
        ])

    def test_changed_files_are_grouped_by_directory(self):
        import main

        root = self.repo
        def p(*parts):
            return os.path.join(root, *parts)
        # cmd/api: 4 files (a campaign); cmd/api/internal: 1 file (merges up
        # into cmd/api); pkg/util: 3 files (its own campaign); tools/x: 1
        # file (climbs to tools, then stops short of the root); main.go at
        # the root: its own single-file campaign, since others exist.
        files = [p("cmd", "api", f"{i}.go") for i in range(4)] + [p("cmd", "api", "internal", "z.go")] \
            + [p("pkg", "util", f"{i}.go") for i in range(3)] + [p("main.go"), p("tools", "x", "t.go")]
        groups = main.group_changed_files(files, root)
        by_dir = {g["dir"]: g["files"] for g in groups}
        self.assertEqual(sorted(by_dir), sorted([p("main.go"), p("cmd", "api"), p("pkg", "util"), p("tools")]))
        self.assertEqual(len(by_dir[p("cmd", "api")]), 5)
        self.assertEqual(len(by_dir[p("pkg", "util")]), 3)
        self.assertEqual(by_dir[p("tools")], [p("tools", "x", "t.go")])
        self.assertEqual(by_dir[p("main.go")], [p("main.go")])
        self.assertEqual(sum(len(f) for f in by_dir.values()), len(files), "every file is in exactly one campaign")
        self._assert_disjoint(by_dir)

    def _assert_disjoint(self, by_dir: dict) -> None:
        """No campaign's identity path contains another's: the path is the
        scope of its stamps and of get_findings."""
        for d in by_dir:
            for e in by_dir:
                self.assertFalse(d != e and e.startswith(d + os.sep), f"{e} is inside {d}")

    def test_a_nested_directory_always_joins_its_ancestor(self):
        import main

        root = self.repo
        big = [os.path.join(root, "big", f"{i}.go") for i in range(main.CHANGED_CAMPAIGN_MAX_FILES)]
        nested = [os.path.join(root, "big", "sub", "n.go")]
        groups = main.group_changed_files(big + nested, root)
        by_dir = {g["dir"]: g["files"] for g in groups}
        self.assertEqual(sorted(by_dir), [os.path.join(root, "big")])
        self.assertEqual(len(by_dir[os.path.join(root, "big")]), main.CHANGED_CAMPAIGN_MAX_FILES + 1,
                         "the max is a preference; disjoint scopes are not")
        self._assert_disjoint(by_dir)
        self.assertEqual(main.group_changed_files([], root), [])
        self.assertEqual(main.group_changed_files(["/elsewhere/x.go"], root), [], "outside the target: dropped")

    def test_root_files_alone_are_the_one_root_campaign(self):
        import main

        root = self.repo
        only_root = [os.path.join(root, "a.py"), os.path.join(root, "b.py")]
        self.assertEqual(main.group_changed_files(only_root, root), [{"dir": root, "files": only_root}])
        with_other = main.group_changed_files(only_root + [os.path.join(root, "pkg", "c.py")], root)
        self.assertEqual([g["dir"] for g in with_other],
                         [os.path.join(root, "a.py"), os.path.join(root, "b.py"), os.path.join(root, "pkg")])
        self._assert_disjoint({g["dir"]: g["files"] for g in with_other})

    def test_an_old_ledger_without_content_is_scanned_whole_once(self):
        import contextlib
        import io

        record_spend(self.db, RUN, self.repo, "whole", tokens=10, metadata={"failed": False})
        self.edit("a")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            targets, resolved, scope = self._resolve("changed")
        self.assertEqual((targets, resolved), ([self.repo], "whole"), "cannot tell what changed: scan it all, once")
        self.assertIn("recorded no file content", err.getvalue())
        self.assertNotIn("focus_files", scope)

    def test_auto_on_a_small_tree_still_scans_whole_and_says_what_changed(self):
        import contextlib
        import io

        self.cover("a", "b", "pkg/c")
        self.edit("a")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            targets, resolved, _scope = self._resolve("auto")
        self.assertEqual((targets, resolved), ([self.repo], "whole"), "non-breaking: auto still rescans whole")
        self.assertIn("1 of 3 source file(s) changed", err.getvalue())
        self.assertIn("--scan-mode changed", err.getvalue())

    def test_the_focus_directive_fences_the_file_list(self):
        import main

        text = main._render_change_focus([self.files["b"], self.files["pkg/c"]], self.repo)
        self.assertIn("CHANGE-SCOPED RUN", text)
        self.assertIn("b.py", text)
        self.assertIn("pkg/c.py", text)
        self.assertIn("UNTRUSTED", text, "file names are repository bytes")
        self.assertNotIn(self.repo, text, "paths are shown relative to the target")

    def test_scope_files_of_a_campaign(self):
        import main

        files = list(self.files.values())
        self.assertEqual(main._campaign_scope_files({"targets": [self.repo]}, self.repo, files), files)
        self.assertEqual(main._campaign_scope_files({"targets": [self.files["a"]]}, self.files["a"], files),
                         [self.files["a"]])
        self.assertEqual(main._campaign_scope_files({"targets": [os.path.join(self.repo, "pkg")]},
                                                    os.path.join(self.repo, "pkg"), files),
                         [self.files["pkg/c"]])
        self.assertEqual(main._campaign_scope_files({}, self.repo, []), [])


class ChangedFilesOverrideTest(_Repo):
    """--changed-files: the caller names the changed files (the PR driver,
    one file per run) instead of the ledger."""

    def _resolve(self, listed, **cfg):
        import main

        scope: dict = {}
        config = {"scan_mode": "changed", "surveyor": {"min_source_files": 1000}, **cfg}
        targets, _astm, resolved = main.resolve_scan_targets(
            Path(self.repo), config, list(self.files.values()), db_path=self.db, scope_out=scope,
            changed_files_override=listed)
        return targets, resolved, scope

    def test_listed_paths_resolve_against_the_target(self):
        import main

        outside_file = os.path.join(self.tmp, "outside.py")
        Path(outside_file).write_text("x = 1\n")
        os.symlink(outside_file, os.path.join(self.repo, "link.py"))
        files, outside, not_source = main._listed_changed_files(
            Path(self.repo),
            ["pkg/c.py", self.files["a"], "./pkg/c.py", "../outside.py", "link.py", "missing.py", ""],
            list(self.files.values()))
        self.assertEqual(files, [self.files["pkg/c"], self.files["a"]], "discovered spelling, list order, no repeats")
        self.assertEqual(outside, ["../outside.py", "link.py"], "a symlink is judged by where it lands")
        self.assertEqual(not_source, ["missing.py"])

    def test_the_list_replaces_the_ledger(self):
        self.cover("a", "b", "pkg/c")  # the ledger says nothing changed
        targets, resolved, scope = self._resolve([self.files["pkg/c"]])
        self.assertEqual((targets, resolved), ([os.path.join(self.repo, "pkg")], "changed"))
        self.assertEqual(scope["focus_files"], [self.files["pkg/c"]])
        self.assertEqual(scope["changed_files"], [], "covered as it is: not changed for the prior-PoC rule")
        self.edit("pkg/c")
        _targets, _resolved, scope = self._resolve([self.files["pkg/c"]])
        self.assertEqual(scope["changed_files"], [self.files["pkg/c"]])

    def test_a_listed_file_keeps_its_own_directory(self):
        import main

        deep = os.path.join(self.repo, "cmd", "x", "y.py")
        os.makedirs(os.path.dirname(deep))
        Path(deep).write_text("def y():\n    return 1\n")
        self.files["cmd/x/y"] = deep
        self.assertEqual([g["dir"] for g in main.group_changed_files([deep], self.repo)],
                         [os.path.join(self.repo, "cmd")], "the ledger's grouping climbs a small directory")
        targets, _resolved, scope = self._resolve([deep])
        self.assertEqual(targets, [os.path.join(self.repo, "cmd", "x")], "a listed file does not climb")
        self.assertEqual(scope["focus_groups"], [{"dir": os.path.join(self.repo, "cmd", "x"), "files": [deep]}])
        # Two listed directories, one inside the other, still never nest.
        groups = main.group_changed_files([deep, self.files["pkg/c"], os.path.join(self.repo, "cmd", "z.py")],
                                          self.repo, climb=False)
        self.assertEqual([g["dir"] for g in groups], [os.path.join(self.repo, "cmd"), os.path.join(self.repo, "pkg")])

    def test_a_root_file_alone_is_the_root_campaign(self):
        targets, _resolved, _scope = self._resolve([self.files["a"]])
        self.assertEqual(targets, [self.repo])

    def test_an_empty_list_is_nothing_to_scan(self):
        targets, resolved, scope = self._resolve([])
        self.assertEqual((targets, resolved), ([], "changed"))
        self.assertTrue(scope["nothing_changed"])

    def test_no_prior_poc_is_rerun_in_a_static_sandbox(self):
        import asyncio

        import main
        from core.context import RunContext
        from core.database import read_findings, read_regression_checks, record_artifact, write_findings
        from core.sandbox import build_sandbox

        write_findings(self.db, self.repo, [{"title": "t", "severity": "HIGH", "status": "dynamic_confirmed",
                                             "description": "d", "line_numbers": [1], "filepath": "pkg/c.py"}],
                       run_id=RUN)
        prior = read_findings(self.db, run_id=RUN)
        record_artifact(self.db, RUN, "poc", f"workspace/repro_{prior[0]['id']}.py", "print('x')\n")
        ctx = RunContext(jail_dir=self.repo, db_path=self.db, target_file=self.repo, run_id="r2",
                         sandbox=build_sandbox({"type": "static-only"}, self.repo))
        note = asyncio.run(main._rerun_prior_pocs(ctx, self.db, "r2", prior, changed_paths={"pkg/c.py"}))
        self.assertEqual(note, "")
        self.assertEqual(read_regression_checks(self.db, run_id="r2"), [])


class EndToEndTest(_Repo):
    """The pipeline against a dummy endpoint: the plan it prints is the evidence."""

    def setUp(self):
        super().setUp()
        self.env = {k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}
        self.env.update({"OPENAI_API_KEY": "dummy", "LLM_TIMEOUT": "3", "MANTIS_LLM_MAX_PATIENCE_SECONDS": "3"})

    def run_main(self, *extra):
        proc = subprocess.run(
            [sys.executable, str(_REF_ROOT / "main.py"), self.repo, "--yes",
             "--sandbox", "static-only", "--model", "openai/nonexistent", "--api-base", "http://127.0.0.1:9",
             "--max-llm-calls", "1", "--db", self.db, *extra],
            capture_output=True, text=True, timeout=300, env=self.env, cwd=str(_REF_ROOT))
        return proc.returncode, proc.stdout + proc.stderr

    def test_changed_mode_end_to_end(self):
        self.cover("a", "b", "pkg/c")
        code, out = self.run_main("--scan-mode", "changed")
        self.assertEqual(code, 0, out)
        self.assertIn("every one of 3 source file(s) is covered in its present content; nothing to scan", out)
        self.assertNotIn("Work plan", out)
        self.edit("b")
        _code, out = self.run_main("--scan-mode", "changed")
        self.assertIn("Scan mode changed: 1 of 3 source file(s) to examine (1 changed since last covered, 0 never covered)", out)
        self.assertIn("1 campaign(s) over the target, one per directory with changed files", out)
        self.assertIn("Work plan — changed: 1 campaign(s)", out)
        self.assertIn("Triggered via: " + self.repo, out, "one campaign over the target")

    def test_changed_files_in_two_directories_are_two_campaigns(self):
        self.cover("a", "b", "pkg/c")
        for name in ("pkg/d", "pkg/e"):
            p = os.path.join(self.repo, f"{name}.py")
            Path(p).write_text("def f():\n    return 3\n")
            self.files[name] = p
        self.edit("pkg/c")
        self.edit("b")
        _code, out = self.run_main("--scan-mode", "changed")
        self.assertIn("4 of 5 source file(s) to examine (2 changed since last covered, 2 never covered)", out)
        self.assertIn("2 campaign(s) over the target", out)
        self.assertIn("Work plan — changed: 2 campaign(s)", out)
        # b.py at the root is its own single-file campaign (a root campaign
        # would span pkg's); it sorts first, and the dummy endpoint pauses
        # the run inside it. The banner counts both.
        self.assertIn("Triggered via: " + self.files["b"] + "\n", out, "the campaign for b.py alone")
        self.assertNotIn("Triggered via: " + self.repo + "\n", out, "no root campaign beside another")
        self.assertIn("of 2 changed target(s)", out)

    def test_resume_notices_drift_and_points_at_changed(self):
        record_spend(self.db, RUN, self.files["a"], "file-by-file", tokens=10, metadata={"failed": False})
        record_coverage_files(self.db, RUN, self.files["a"], scope_identities([self.files["a"]]))
        self.edit("a")
        _code, out = self.run_main("--resume", RUN, "--scan-mode", "file-by-file")
        self.assertIn("[RESUME] 1 file(s) this run covered changed on disk since", out)
        self.assertIn("--scan-mode changed", out)
        self.assertNotIn("Triggered via: " + self.files["a"], out, "a resumed run does not rescan it")

    def test_listed_changed_files_end_to_end(self):
        # A fresh database: the ledger would call every file new.
        _code, out = self.run_main("--scan-mode", "changed", "--changed-files", "pkg/c.py")
        self.assertIn("Scan mode changed: 1 listed file(s) to examine; 1 campaign(s) over the target", out)
        self.assertIn("Work plan — changed: 1 campaign(s)", out)
        self.assertIn("Triggered via: " + os.path.join(self.repo, "pkg") + "\n", out, "the file's directory, over the repo")

    def test_listed_changed_files_misuse_exits_1(self):
        code, out = self.run_main("--changed-files", "pkg/c.py")
        self.assertEqual(code, 1, out)
        self.assertIn("--changed-files needs a directory target and --scan-mode changed", out)
        code, out = self.run_main("--scan-mode", "changed", "--changed-files", "../outside.py")
        self.assertEqual(code, 1, out)
        self.assertIn("1 path(s) outside the target", out)
        code, out = self.run_main("--scan-mode", "changed", "--changed-files", "missing.py")
        self.assertEqual(code, 1, out)
        self.assertIn("none of the listed paths is a source file", out)
        proc = subprocess.run(
            [sys.executable, str(_REF_ROOT / "main.py"), self.files["a"], "--yes", "--sandbox", "static-only",
             "--model", "openai/nonexistent", "--api-base", "http://127.0.0.1:9", "--db", self.db,
             "--scan-mode", "changed", "--changed-files", "a.py"],
            capture_output=True, text=True, timeout=300, env=self.env, cwd=str(_REF_ROOT))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("target is a file", proc.stdout + proc.stderr)

    def test_sequential_listed_runs_leave_an_earlier_finding_alone(self):
        """The PR driver scans one file per run. Two files in one directory,
        in sequence: the second run neither re-decides nor restamps the
        first run's finding -- not when it lists the sibling file, and not
        when it lists the finding's own file."""
        from core.database import read_findings, read_regression_checks, write_findings

        d = os.path.join(self.repo, "pkg", "d.py")
        Path(d).write_text("def d():\n    return 4\n")
        write_findings(self.db, self.repo, [{"title": "ssrf in c", "severity": "HIGH", "status": "static_confirmed",
                                             "description": "d", "line_numbers": [1], "filepath": "pkg/c.py"}],
                       run_id=RUN)
        before = read_findings(self.db, run_id=RUN)
        self.assertEqual(len(before), 1)
        outs = [self.run_main("--scan-mode", "changed", "--changed-files", rel)[1] for rel in ("pkg/d.py", "pkg/c.py")]
        after = read_findings(self.db, run_id=RUN)
        self.assertEqual([(f["id"], f["status"]) for f in after], [(f["id"], f["status"]) for f in before])
        self.assertEqual(read_regression_checks(self.db), [], "no later run decided about it")
        for out in outs:
            self.assertNotIn("earlier finding(s) sit in the changed files", out)
            self.assertIn("Triggered via: " + os.path.join(self.repo, "pkg") + "\n", out)


class DirectiveReachesEveryNodeTest(unittest.IsolatedAsyncioTestCase):
    """Nodes run with include_contents="none", so only the first node sees
    the seed message. The change-scoped directive therefore rides on
    RunContext.campaign_directive and is appended to every node's
    instructions; a three-node graph with a recording model shows it."""

    async def test_every_node_sees_the_campaign_directive(self):
        from google.adk.agents.llm_agent import LlmAgent
        from google.adk.apps.app import App
        from google.adk.models.base_llm import BaseLlm
        from google.adk.models.llm_response import LlmResponse
        from google.adk.runners import Runner
        from google.adk.sessions.in_memory_session_service import InMemorySessionService
        from google.adk.workflow import START, Edge, Workflow
        from google.genai import types

        from core.context import RunContext, current_run_context
        from core.graph_loader import (
            CAMPAIGN_DIRECTIVE_MARKER, _make_campaign_directive_before_model_callback,
        )

        seen: list = []

        class Recorder(BaseLlm):
            model: str = "dummy"

            async def generate_content_async(self, req, stream=False):
                sys_inst = str(getattr(req.config, "system_instruction", "") or "")
                user_texts = [p.text for c in (req.contents or []) for p in (c.parts or []) if getattr(p, "text", None)]
                seen.append((sys_inst, user_texts))
                yield LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text="ok")]))

        def node(name):
            return LlmAgent(name=name, model=Recorder(), instruction=f"You are {name}.", include_contents="none",
                            before_model_callback=[_make_campaign_directive_before_model_callback(name)])

        a, b, c = node("first"), node("second"), node("third")
        wf = Workflow(name="wf", edges=[Edge(from_node=START, to_node=a), Edge(from_node=a, to_node=b),
                                        Edge(from_node=b, to_node=c)])
        ss = InMemorySessionService()
        runner = Runner(app=App(name="probe", root_agent=wf), session_service=ss)
        await ss.create_session(app_name="probe", user_id="u", session_id="s")
        ctx = RunContext(jail_dir="/tmp", db_path="", campaign_directive="\nCHANGE-SCOPED RUN: b.py")
        token = current_run_context.set(ctx)
        try:
            msg = types.Content(role="user", parts=[types.Part.from_text(text="Evaluate X SEED-ONLY")])
            async for _ in runner.run_async(user_id="u", session_id="s", new_message=msg):
                pass
        finally:
            current_run_context.reset(token)
        self.assertEqual(len(seen), 3)
        # The seed reaches the first node only -- the fact this channel exists for.
        self.assertTrue(any("SEED-ONLY" in t for t in seen[0][1]))
        self.assertFalse(any("SEED-ONLY" in t for t in seen[1][1] + seen[2][1]))
        # The directive reaches all three, once each.
        for sys_inst, _ in seen:
            self.assertEqual(sys_inst.count(CAMPAIGN_DIRECTIVE_MARKER), 1, sys_inst[-200:])
            self.assertIn("CHANGE-SCOPED RUN: b.py", sys_inst)

    async def test_no_directive_appends_nothing(self):
        from core.context import RunContext, current_run_context
        from core.graph_loader import _make_campaign_directive_before_model_callback

        class Req:
            class config:
                system_instruction = "base"

            def __init__(self):
                self.appended = []

            def append_instructions(self, items):
                self.appended.extend(items)

        cb = _make_campaign_directive_before_model_callback("x")
        req = Req()
        token = current_run_context.set(RunContext(jail_dir="/tmp", db_path=""))
        try:
            cb(None, req)
        finally:
            current_run_context.reset(token)
        self.assertEqual(req.appended, [])
        cb(None, None)  # no request: no error

    def _req(self, sys_inst="base"):
        class Req:
            def __init__(self, s):
                self.config = type("C", (), {"system_instruction": s})()
                self.appended = []

            def append_instructions(self, items):
                self.appended.extend(items)
                self.config.system_instruction += "".join(items)
        return Req(sys_inst)

    def _run_cb(self, node, ctx):
        from core.context import current_run_context
        from core.graph_loader import _make_campaign_directive_before_model_callback

        req = self._req()
        token = current_run_context.set(ctx)
        try:
            _make_campaign_directive_before_model_callback(node)(None, req)
        finally:
            current_run_context.reset(token)
        return req

    async def test_context_reaches_the_deciding_stages_and_not_the_reporter(self):
        """What earlier runs found here used to ride only in the seed, which
        the history node alone reads. It now reaches the stages that choose
        where to look; the reporter and the stages after reproduction work
        from this run's findings and must not have earlier runs' findings in
        their instructions."""
        from core.context import RunContext
        from core.graph_loader import CAMPAIGN_CONTEXT_MARKER, CAMPAIGN_DIRECTIVE_MARKER

        ctx = RunContext(jail_dir="/tmp", db_path="", campaign_context="\n<memory>prior finding X</memory>",
                         campaign_directive="\nCHANGE-SCOPED RUN: b.py")
        for node in ("architect", "threat_modeler", "planner", "researcher", "researcher_2", "reviewer", "critic"):
            req = self._run_cb(node, ctx)
            joined = "".join(req.appended)
            self.assertIn(CAMPAIGN_CONTEXT_MARKER, joined, node)
            self.assertIn("prior finding X", joined, node)
            self.assertIn(CAMPAIGN_DIRECTIVE_MARKER, joined, node)
            self.assertLess(joined.index(CAMPAIGN_CONTEXT_MARKER), joined.index(CAMPAIGN_DIRECTIVE_MARKER),
                            "data before instruction")
        for node in ("history", "reproducer", "patcher", "calibrator", "reflector", "reporter"):
            req = self._run_cb(node, ctx)
            joined = "".join(req.appended)
            self.assertNotIn(CAMPAIGN_CONTEXT_MARKER, joined, node)
            self.assertIn(CAMPAIGN_DIRECTIVE_MARKER, joined, node)

    async def test_context_is_bounded_and_a_cut_fence_is_closed(self):
        from core.context import RunContext
        from core.graph_loader import MAX_CAMPAIGN_CONTEXT_CHARS
        from core.llm_gateway import UNTRUSTED_DATA_END, wrap_untrusted_content

        big = wrap_untrusted_content("x" * (MAX_CAMPAIGN_CONTEXT_CHARS * 2), filename="memory")
        ctx = RunContext(jail_dir="/tmp", db_path="", campaign_context="\n" + big, campaign_directive="\nD")
        req = self._run_cb("planner", ctx)
        context_block, directive_block = req.appended
        self.assertLess(len(context_block), MAX_CAMPAIGN_CONTEXT_CHARS + 200)
        self.assertIn("[campaign context truncated]", context_block)
        self.assertTrue(context_block.rstrip().endswith("[campaign context truncated]"))
        self.assertIn(UNTRUSTED_DATA_END, context_block, "the fence a cut opened is closed before the directive")
        self.assertLess(context_block.index(UNTRUSTED_DATA_END), context_block.index("[campaign context truncated]"))

    async def test_appending_is_idempotent_per_request(self):
        from core.context import RunContext, current_run_context
        from core.graph_loader import _make_campaign_directive_before_model_callback

        ctx = RunContext(jail_dir="/tmp", db_path="", campaign_context="\nC", campaign_directive="\nD")
        req = self._req()
        token = current_run_context.set(ctx)
        try:
            cb = _make_campaign_directive_before_model_callback("planner")
            cb(None, req)
            cb(None, req)
        finally:
            current_run_context.reset(token)
        self.assertEqual(len(req.appended), 2)

    def test_execute_sub_task_sets_the_context_on_both_paths(self):
        import inspect

        import main

        src = inspect.getsource(main.execute_sub_task)
        self.assertIn("campaign_context = ", src)
        self.assertLess(src.index("campaign_context = "), src.index("if resumed_invocation_id:"),
                        "a resumed invocation sends no seed; the context must be set before the branch")


class ExportImportTest(_Repo):
    def test_content_hashes_round_trip_through_a_knowledge_export(self):
        from core import knowledge as K

        self.cover("a", "b", "pkg/c")
        out = os.path.join(self.tmp, "export")
        K.export_knowledge(self.db, out, repo_root=self.repo)
        cov = json.loads(Path(out, K.COVERAGE).read_text())
        self.assertEqual(sorted(e["path"] for e in cov["files"]), ["a.py", "b.py", "pkg/c.py"])
        self.assertTrue(all(len(e["content_hash"]) == 16 for e in cov["files"]))
        self.assertNotIn("mtime_ns", cov["files"][0], "another machine's clock is not exported")

        # A fresh checkout at another path, same content: everything covered.
        other = os.path.realpath(os.path.join(self.tmp, "clone"))
        shutil.copytree(self.repo, other)
        fresh = os.path.join(self.tmp, "fresh.db")
        init_db(fresh)
        K.import_knowledge(fresh, out, run_id="run-new", repo_root=other)
        files = [os.path.join(other, "a.py"), os.path.join(other, "b.py"), os.path.join(other, "pkg", "c.py")]
        self.assertEqual(uncovered_files(fresh, files), [])
        # Edit one there: uncovered again, from the imported hash alone.
        Path(files[1]).write_text("def b():\n    return 99\n")
        self.assertEqual(uncovered_files(fresh, files), [files[1]])
        # Importing twice adds nothing.
        before = sqlite3.connect(fresh).execute("SELECT COUNT(*) FROM coverage_files").fetchone()[0]
        K.import_knowledge(fresh, out, run_id="run-new", repo_root=other)
        after = sqlite3.connect(fresh).execute("SELECT COUNT(*) FROM coverage_files").fetchone()[0]
        self.assertEqual(before, after)

    def test_an_export_without_files_still_imports(self):
        from core import knowledge as K

        self.cover("a")
        out = os.path.join(self.tmp, "export")
        K.export_knowledge(self.db, out, repo_root=self.repo)
        cov = json.loads(Path(out, K.COVERAGE).read_text())
        cov.pop("files")
        Path(out, K.COVERAGE).write_text(json.dumps(cov))
        fresh = os.path.join(self.tmp, "fresh.db")
        init_db(fresh)
        counts = K.import_knowledge(fresh, out, run_id="run-new", repo_root=self.repo)
        self.assertGreaterEqual(counts["coverage_paths"], 1)


if __name__ == "__main__":
    unittest.main()

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

"""A database from before the content ledger can be filled in after the
fact, so `--scan-mode changed` does not need one more whole scan to learn
what the files looked like when they were covered."""

from __future__ import annotations

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

from core.cost import (  # noqa: E402
    backfill_coverage, changed_files, git_blob_identities, record_spend, run_snapshot_ids, uncovered_files,
)
from core.database import init_db, record_artifact, record_run  # noqa: E402

RUN = "22222222-3333-4444-5555-666666666666"


def _git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True, text=True,
                          env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}).stdout.strip()


class BackfillTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_backfill_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = os.path.realpath(os.path.join(self.tmp, "repo"))
        os.makedirs(os.path.join(self.repo, "pkg"))
        self.files = {}
        for name in ("a", "b", "pkg/c"):
            p = os.path.join(self.repo, f"{name}.py")
            Path(p).write_text(f"def {name.split('/')[-1]}():\n    return 1\n")
            self.files[name] = p
        _git(self.repo, "init", "-q")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-q", "-m", "scanned state")
        self.commit = _git(self.repo, "rev-parse", "HEAD")
        self.db = os.path.join(self.tmp, "k.db")
        init_db(self.db)
        record_run(self.db, RUN, "vertex_ai/gemini-3.8-flash")
        # An old file-by-file run: spend rows, no content rows.
        for name in ("a", "b"):
            record_spend(self.db, RUN, self.files[name], "file-by-file", tokens=10, metadata={"failed": False})
        record_spend(self.db, RUN, os.path.join(self.repo, "pkg"), "cross-functional", tokens=10, metadata={"failed": False})
        record_spend(self.db, RUN, self.files["pkg/c"], "file-by-file", tokens=0, metadata={"failed": True})

    def _edit(self, name, text="def x():\n    return 2\n"):
        p = self.files[name]
        st = os.stat(p)
        Path(p).write_text(text)
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))

    def test_git_identities_match_the_ledgers_hash_rule(self):
        from core.cost import file_identity

        ids = git_blob_identities(self.repo, self.commit, ["a.py", "pkg/c.py", "nope.py"])
        self.assertEqual(set(ids), {"a.py", "pkg/c.py"}, "a file absent at the commit is left out")
        h, size, mtime = ids["a.py"]
        self.assertEqual(h, file_identity(self.files["a"])[0], "the same hash the tree would get")
        self.assertEqual(size, os.path.getsize(self.files["a"]))
        self.assertIsNone(mtime)
        self.assertEqual(git_blob_identities(self.repo, "0" * 40, ["a.py"]), {}, "unknown commit: nothing")
        self.assertEqual(git_blob_identities(self.tmp, self.commit, ["a.py"]), {}, "not a repo: nothing")

    def test_git_blob_identities_refuses_unvetted_repo_config_and_flag_commits(self):
        marker = os.path.join(self.tmp, "fsmonitor_ran")
        self.assertEqual(git_blob_identities(self.repo, "--all", ["a.py"]), {})
        with open(os.path.join(self.repo, ".git", "config"), "a", encoding="utf-8") as fh:
            fh.write(
                f'\n[core]\n\tfsmonitor = touch {marker}\n'
                '[extensions]\n\tpartialClone = origin\n'
                '[remote "origin"]\n\tpromisor = true\n'
            )
        self.assertEqual(git_blob_identities(self.repo, self.commit, ["a.py"]), {})
        self.assertFalse(os.path.exists(marker))

    def test_the_runs_recorded_commit_is_found_on_its_artifacts(self):
        self.assertEqual(run_snapshot_ids(self.db), {})
        record_artifact(self.db, RUN, "summary", "workspace/kb/summary.md", "x",
                        metadata={"resource": self.files["a"], "snapshot_id": self.commit})
        record_artifact(self.db, RUN, "plan", "workspace/plan", "x", metadata={"snapshot_id": "not a commit"})
        self.assertEqual(run_snapshot_ids(self.db), {RUN: self.commit})

    def test_backfill_from_the_recorded_commit_sees_a_later_edit(self):
        record_artifact(self.db, RUN, "summary", "workspace/kb/summary.md", "x",
                        metadata={"resource": self.files["a"], "snapshot_id": self.commit})
        files = list(self.files.values())
        self._edit("b")  # edited AFTER the scan: must come out as changed
        summary = backfill_coverage(self.db, self.repo, files)
        done = {(os.path.relpath(t, self.repo), n, src) for _r, t, n, src in summary["backfilled"]}
        self.assertEqual(done, {("a.py", 1, f"commit {self.commit[:12]}"), ("b.py", 1, f"commit {self.commit[:12]}"),
                                ("pkg", 1, f"commit {self.commit[:12]}")})
        self.assertEqual(summary["rows"], 3)
        self.assertEqual([s for s in summary["skipped"]], [], "the failed campaign is simply not a campaign")
        self.assertEqual(changed_files(self.db, files)["files"], [self.files["b"]],
                         "hashed at the commit: the edit since is a change, the untouched files are not")
        self.assertEqual(uncovered_files(self.db, files), [self.files["b"]])
        # Idempotent: a second pass finds the rows and leaves them.
        again = backfill_coverage(self.db, self.repo, files)
        self.assertEqual(again["backfilled"], [])
        self.assertEqual({s[2] for s in again["skipped"]}, {"already has content rows"})

    def test_without_a_commit_the_operator_must_say_so(self):
        files = list(self.files.values())
        summary = backfill_coverage(self.db, self.repo, files)
        self.assertEqual(summary["backfilled"], [])
        self.assertTrue(all("--at <commit> or --assume-unchanged" in s[2] for s in summary["skipped"]))
        self.assertEqual(summary["rows"], 0)
        # --at names the commit.
        summary = backfill_coverage(self.db, self.repo, files, at=self.commit, dry_run=True)
        self.assertEqual(len(summary["backfilled"]), 3)
        self.assertEqual(summary["rows"], 0, "dry run writes nothing")
        self.assertEqual(changed_files(self.db, files), {"files": []})
        # --assume-unchanged records the tree as it is now.
        self._edit("a")
        summary = backfill_coverage(self.db, self.repo, files, assume_unchanged=True)
        self.assertEqual(len(summary["backfilled"]), 3)
        self.assertEqual(changed_files(self.db, files)["files"], [], "asserted unchanged: today's content is the covered content")

    def test_the_cli_reports_and_exits_by_outcome(self):
        env = {k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}
        proc = subprocess.run(
            [sys.executable, str(_REF_ROOT / "scripts" / "knowledge.py"), "backfill-coverage",
             "--db", self.db, "--repo", self.repo, "--at", self.commit],
            capture_output=True, text=True, timeout=120, env=env, cwd=str(_REF_ROOT))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Recorded content for 3 campaign(s), 3 file row(s)", proc.stdout)
        self.assertIn("--scan-mode changed run now examines only what differs", proc.stdout)
        proc = subprocess.run(
            [sys.executable, str(_REF_ROOT / "scripts" / "knowledge.py"), "backfill-coverage",
             "--db", self.db, "--repo", self.repo],
            capture_output=True, text=True, timeout=120, env=env, cwd=str(_REF_ROOT))
        self.assertEqual(proc.returncode, 0, "nothing left to do is not a failure")
        self.assertIn("already has content rows", proc.stdout)


if __name__ == "__main__":
    unittest.main()

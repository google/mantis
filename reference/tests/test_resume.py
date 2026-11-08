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

"""--resume scans what a run has not finished.

The spend ledger says which campaigns completed and which failed. A resumed
run skips the completed ones and scans the rest under the same run id;
`--resume` with no id picks the most recent run recorded for the target; a
failed campaign never counts as coverage.
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REF_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REF_ROOT))

from core.cost import (  # noqa: E402
    latest_run_id,
    record_run_scan_mode,
    record_spend,
    run_ledger,
    run_scan_mode,
    uncovered_files,
)


class LedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_resume_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = os.path.realpath(os.path.join(self.tmp, "repo"))
        os.makedirs(self.root)
        self.db = os.path.join(self.tmp, "m.db")
        self.a = os.path.join(self.root, "a.py")
        self.b = os.path.join(self.root, "b.py")
        self.c = os.path.join(self.root, "c.py")

    def test_a_failed_campaign_covers_nothing(self):
        record_spend(self.db, "r1", self.a, "file-by-file", tokens=10, metadata={"failed": False})
        record_spend(self.db, "r1", self.b, "file-by-file", tokens=10, metadata={"failed": True})
        self.assertEqual(uncovered_files(self.db, [self.a, self.b, self.c]), [self.b, self.c])
        # A later success covers it; the failure row stays for cost estimation.
        record_spend(self.db, "r2", self.b, "file-by-file", tokens=10, metadata={"failed": False})
        self.assertEqual(uncovered_files(self.db, [self.a, self.b, self.c]), [self.c])
        # A failed whole-directory campaign covers none of its files either.
        record_spend(self.db, "r3", self.root, "whole", tokens=10, metadata={"failed": True})
        self.assertEqual(uncovered_files(self.db, [self.a, self.b, self.c]), [self.c])

    def test_run_ledger_reports_the_latest_row_per_target(self):
        self.assertIsNone(run_ledger("", "r1"))
        self.assertIsNone(run_ledger(self.db, ""))
        self.assertEqual(run_ledger(self.db, "r1"), {}, "no database yet: nothing recorded")
        record_spend(self.db, "r1", self.a, "file-by-file", tokens=10, metadata={"failed": True})
        record_spend(self.db, "r1", self.b, "file-by-file", tokens=10, metadata={"failed": False})
        record_spend(self.db, "r2", self.c, "file-by-file", tokens=10, metadata={"failed": False})
        # Rows written without a harness fingerprint read back as None: the
        # stamp is unknown, never invented.
        self.assertEqual(run_ledger(self.db, "r1"), {
            self.a: {"failed": True, "harness_fingerprint": None},
            self.b: {"failed": False, "harness_fingerprint": None},
        })
        self.assertEqual(run_ledger(self.db, "r3"), {})
        # A retry that succeeds supersedes the failure, stamp included.
        record_spend(self.db, "r1", self.a, "file-by-file", tokens=10, metadata={"failed": False},
                     harness_fingerprint="abcdef0123456789")
        self.assertEqual(run_ledger(self.db, "r1")[self.a],
                         {"failed": False, "harness_fingerprint": "abcdef0123456789"})
        corrupt = os.path.join(self.tmp, "corrupt.db")
        Path(corrupt).write_bytes(b"not a database")
        self.assertIsNone(run_ledger(corrupt, "r1"))

    def test_run_scan_mode_is_what_the_ledger_recorded(self):
        from core.database import init_db, record_run

        self.assertEqual(run_scan_mode(self.db, "r1"), "", "no database")
        record_spend(self.db, "r1", self.a, "file-by-file", tokens=10)
        record_spend(self.db, "r2", self.root, "whole", tokens=10)
        self.assertEqual(run_scan_mode(self.db, "r1"), "file-by-file")
        self.assertEqual(run_scan_mode(self.db, "r2"), "whole")
        self.assertEqual(run_scan_mode(self.db, "r3"), "", "no rows")
        self.assertEqual(run_scan_mode("", "r1"), "")
        self.assertEqual(run_scan_mode(self.db, ""), "")
        # Fallback for a run that paused inside its first campaign before any
        # campaign_spend row was written.
        init_db(self.db)
        record_run(self.db, "r-paused-early", "vertex_ai/gemini-3.8-flash")
        self.assertTrue(record_run_scan_mode(self.db, "r-paused-early", "file-by-file"))
        self.assertEqual(run_scan_mode(self.db, "r-paused-early"), "file-by-file")

    def test_latest_run_id_is_scoped_to_the_target(self):
        self.assertEqual(latest_run_id(self.db, self.root), "")
        other = os.path.realpath(os.path.join(self.tmp, "other"))
        os.makedirs(other)
        conn = sqlite3.connect(self.db)
        conn.execute(
            "CREATE TABLE campaign_spend (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, "
            "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, target TEXT, scan_mode TEXT, tokens INTEGER, "
            "llm_calls INTEGER, graph_steps INTEGER, elapsed_seconds REAL, metadata_json TEXT)"
        )
        rows = [
            ("old-here", "2026-01-01 00:00:00", self.a),
            ("new-elsewhere", "2026-01-03 00:00:00", os.path.join(other, "x.py")),
            ("new-here", "2026-01-02 00:00:00", self.b),
        ]
        conn.executemany(
            "INSERT INTO campaign_spend (run_id, timestamp, target, scan_mode, tokens, metadata_json) "
            "VALUES (?, ?, ?, 'file-by-file', 1, '{}')",
            rows,
        )
        conn.commit()
        conn.close()
        self.assertEqual(latest_run_id(self.db, self.root), "new-here")
        self.assertEqual(latest_run_id(self.db, other), "new-elsewhere")
        self.assertEqual(latest_run_id(self.db), "new-elsewhere", "no target: the newest run anywhere")
        self.assertEqual(latest_run_id(self.db, os.path.join(self.tmp, "nowhere")), "new-elsewhere",
                         "nothing under the target: fall back to the newest run anywhere")

    def test_latest_run_id_falls_back_to_findings(self):
        from core.database import init_db, write_findings

        init_db(self.db)
        self.assertEqual(latest_run_id(self.db, self.root), "", "tables but no run")
        write_findings(self.db, "a.py", [{
            "title": "x", "severity": "LOW", "status": "candidate", "description": "d",
            "line_numbers": [1], "cwe": "CWE-1", "filepath": "a.py",
        }], run_id="only-findings")
        self.assertEqual(latest_run_id(self.db, self.root), "only-findings")
        record_spend(self.db, "ledger-run", self.a, "file-by-file", tokens=10)
        self.assertEqual(latest_run_id(self.db, self.root), "ledger-run")


class CliTest(unittest.TestCase):
    def parse(self, *argv):
        from scripts.launch import build_parser

        with contextlib.redirect_stderr(io.StringIO()):
            return build_parser().parse_args(list(argv))

    def test_resume_takes_an_optional_run_id(self):
        self.assertEqual(self.parse("x").resume, "")
        self.assertEqual(self.parse("x", "--resume", "abc").resume, "abc")
        self.assertEqual(self.parse("x", "--resume").resume, "latest")
        self.assertEqual(self.parse("--resume", "abc", "x").resume, "abc")


class ResumeRunTest(unittest.TestCase):
    """End to end against a dummy endpoint: the campaign list is the evidence."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_resume_e2e_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = os.path.realpath(os.path.join(self.tmp, "repo"))
        os.makedirs(self.repo)
        self.files = {}
        for name in ("a", "b", "c", "d"):
            p = os.path.join(self.repo, f"{name}.py")
            Path(p).write_text(f"def {name}():\n    return 1\n")
            self.files[name] = p
        self.db = os.path.join(self.tmp, "m.db")
        self.env = {k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}
        self.env.update({"OPENAI_API_KEY": "dummy", "LLM_TIMEOUT": "3", "MANTIS_LLM_MAX_PATIENCE_SECONDS": "3"})

    def run_main(self, *extra, scan_mode="file-by-file"):
        mode = ["--scan-mode", scan_mode] if scan_mode else []
        proc = subprocess.run(
            [sys.executable, str(_REF_ROOT / "main.py"), self.repo, *mode, "--yes",
             "--sandbox", "static-only", "--model", "openai/nonexistent", "--api-base", "http://127.0.0.1:9",
             "--max-llm-calls", "1", "--db", self.db, *extra],
            capture_output=True, text=True, timeout=300, env=self.env, cwd=str(_REF_ROOT))
        return proc.returncode, proc.stdout + proc.stderr

    def test_resume_scans_only_what_the_run_has_not_finished(self):
        run = "11111111-2222-3333-4444-555555555555"
        record_spend(self.db, run, self.files["a"], "file-by-file", tokens=10, metadata={"failed": False})
        record_spend(self.db, run, self.files["b"], "file-by-file", tokens=10, metadata={"failed": False})
        record_spend(self.db, run, self.files["c"], "file-by-file", tokens=10, metadata={"failed": True})
        # d.py has no row: the run never reached it.

        _code, out = self.run_main("--resume", run)
        self.assertIn(f"Resuming run {run}: 2 of 4 campaign(s) completed; 1 failed and 1 never started: 2 to scan.", out)
        self.assertIn("file-by-file: 2 campaign(s)", out)
        self.assertIn(f"Run ID: {run}", out, "the same run id, not a new one")
        self.assertIn("Triggered via: " + self.files["c"], out, "the failed campaign is the first one rerun")
        self.assertNotIn("Triggered via: " + self.files["a"], out)
        self.assertNotIn("Triggered via: " + self.files["b"], out)
        # The dummy endpoint pauses the run at its one allowed LLM call, and a
        # paused campaign records nothing, so the ledger is as seeded.
        self.assertEqual(run_ledger(self.db, run), {
            self.files["a"]: {"failed": False, "harness_fingerprint": None},
            self.files["b"]: {"failed": False, "harness_fingerprint": None},
            self.files["c"]: {"failed": True, "harness_fingerprint": None},
        })

        # Everything now has a successful row: nothing to do, and no id needed.
        record_spend(self.db, run, self.files["c"], "file-by-file", tokens=10, metadata={"failed": False})
        record_spend(self.db, run, self.files["d"], "file-by-file", tokens=10, metadata={"failed": False})
        code, out = self.run_main("--resume")
        self.assertEqual(code, 0, out)
        self.assertIn(f"Resuming the most recent run: {run}", out)
        self.assertIn("4 of 4 campaign(s) completed", out)
        self.assertIn("Nothing left to scan for this run", out)

    def test_a_resumed_run_keeps_its_scan_mode(self):
        """The bug report's command: a file-by-file sweep of a small directory,
        three campaigns failed, resumed with `--resume` and nothing else. Four
        files is under the sweep threshold, so `auto` would plan one whole-
        directory campaign; the run must plan the way it was recorded."""
        run = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        record_spend(self.db, run, self.files["a"], "file-by-file", tokens=10, metadata={"failed": True})
        record_spend(self.db, run, self.files["b"], "file-by-file", tokens=10, metadata={"failed": False})
        record_spend(self.db, run, self.files["c"], "file-by-file", tokens=10, metadata={"failed": True})
        record_spend(self.db, run, self.files["d"], "file-by-file", tokens=10, metadata={"failed": True})
        _code, out = self.run_main("--resume", scan_mode=None)
        self.assertIn(f"Resuming the most recent run: {run}", out)
        self.assertIn("[RESUME] Scan mode file-by-file, as recorded for this run.", out)
        self.assertIn("1 of 4 campaign(s) completed; 3 failed and 0 never started: 3 to scan.", out)
        self.assertIn("file-by-file: 3 campaign(s)", out)
        self.assertNotIn("whole: 1 campaign(s)", out)
        # Repeating the SAME recorded scan mode is accepted.
        _code, out = self.run_main("--resume", run, scan_mode="file-by-file")
        self.assertIn("file-by-file: 3 campaign(s)", out)
        # Switching to a different scan mode on --resume is rejected as a usage error (64).
        for other_mode in ("changed", "whole", "cross-functional"):
            code, out = self.run_main("--resume", run, scan_mode=other_mode)
            self.assertEqual(code, 64, out)
            self.assertIn("cannot switch --scan-mode from 'file-by-file'", out)
            self.assertIn(f"to '{other_mode}'", out)
            self.assertNotIn("Work plan", out)

    def test_resume_without_a_run_to_resume_is_an_error(self):
        code, out = self.run_main("--resume")
        self.assertEqual(code, 1, out)
        self.assertIn("no earlier run recorded", out)
        self.assertNotIn("Work plan", out)

    def test_resume_auto_uncovered_sweep_keeps_initial_uncovered_plan(self):
        """When auto mode chooses file-by-file over ONLY uncovered files,
        resuming that run must keep the saved uncovered subset instead of
        re-planning every discovered file in the repository."""
        import asyncio
        from unittest.mock import patch

        import main as mantis_main
        from core.budget import BudgetExceededError

        import json

        wf_data = json.loads((_REF_ROOT / "workflow.json").read_text(encoding="utf-8"))
        wf_data.setdefault("config", {})["surveyor"] = {"min_source_files": 4}
        wf_path = os.path.join(self.tmp, "wf_auto.json")
        Path(wf_path).write_text(json.dumps(wf_data), encoding="utf-8")

        # Add 2 more files (6 total > min_source_files=4). Cover a..d in 'r0',
        # leaving exactly 2 uncovered files: e.py and f.py.
        e_file = os.path.join(self.repo, "e.py")
        f_file = os.path.join(self.repo, "f.py")
        Path(e_file).write_text("def e():\n    return 5\n")
        Path(f_file).write_text("def f():\n    return 6\n")
        for p in self.files.values():
            record_spend(self.db, "r0", p, "file-by-file", tokens=500, metadata={"failed": False})

        seen_first: list[str] = []

        async def _first_exec(_runner, _ss, filepath, _rid, **kw):
            seen_first.append(filepath)
            if len(seen_first) == 1:
                kw["budget_controller"].audit_code_reads += 1
                return False
            raise BudgetExceededError("max_tokens", 1000, 1000, _rid)

        out1, err1 = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, self.env, clear=True), \
             patch.object(mantis_main, "execute_sub_task", side_effect=_first_exec), \
             contextlib.redirect_stdout(out1), \
             contextlib.redirect_stderr(err1):
            rc1 = asyncio.run(
                mantis_main.pipeline(
                    scan_target=self.repo,
                    workflow_path=wf_path,
                    load_local=False,
                    db_override=self.db,
                    model_override="openai/nonexistent",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    auto_configure=False,
                    scan_mode_override="auto",
                    assume_yes=True,
                )
            )
        self.assertEqual(rc1, 2, out1.getvalue() + err1.getvalue())
        self.assertEqual(seen_first, [e_file, f_file])

        seen_resume: list[str] = []

        async def _resume_exec(_runner, _ss, filepath, _rid, **kw):
            seen_resume.append(filepath)
            kw["budget_controller"].audit_code_reads += 1
            return False

        out2, err2 = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, self.env, clear=True), \
             patch.object(mantis_main, "execute_sub_task", side_effect=_resume_exec), \
             contextlib.redirect_stdout(out2), \
             contextlib.redirect_stderr(err2):
            rc2 = asyncio.run(
                mantis_main.pipeline(
                    scan_target=self.repo,
                    workflow_path=wf_path,
                    load_local=False,
                    db_override=self.db,
                    model_override="openai/nonexistent",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    auto_configure=False,
                    resume_run_id="latest",
                    assume_yes=True,
                )
            )
        combined2 = out2.getvalue() + err2.getvalue()
        self.assertEqual(rc2, 0, combined2)
        self.assertIn(
            "1 of 2 campaign(s) completed; 0 failed and 1 never started: 1 to scan.",
            combined2,
        )
        self.assertEqual(seen_resume, [f_file])

    def test_resume_cross_functional_reuses_saved_plan_without_rerunning_propose_campaigns(self):
        """A cross-functional run that saved a campaign plan reloads its
        planned targets and groups on --resume without calling propose_campaigns."""
        import asyncio
        from unittest.mock import patch

        import main as mantis_main
        from core.cost import record_run_plan
        from core.database import init_db, record_run
        import core.planner as planner_mod

        sub_a = os.path.join(self.repo, "svc_a")
        sub_b = os.path.join(self.repo, "svc_b")
        os.makedirs(sub_a)
        os.makedirs(sub_b)
        Path(os.path.join(sub_a, "x.py")).write_text("x = 1\n")
        Path(os.path.join(sub_b, "y.py")).write_text("y = 2\n")

        run = "22222222-3333-4444-5555-666666666666"
        init_db(self.db)
        record_run(self.db, run, "openai/nonexistent")
        record_spend(self.db, run, sub_a, "cross-functional", tokens=500, metadata={"failed": False})
        saved = record_run_plan(
            self.db,
            run,
            targets=[sub_a, sub_b],
            target_root=self.repo,
            plan_groups=[
                {"targets": [sub_a], "hypothesis": "check a", "chain": None},
                {"targets": [sub_b], "hypothesis": "check b", "chain": None},
            ],
            campaign_plan={
                "available": True,
                "hypotheses": {sub_b: {"hypothesis": "check b", "priority": 1}},
            },
        )
        self.assertTrue(saved)

        confirmed_counts: list[int] = []

        def _capture_confirm(*, scan_mode, campaigns, budget, assume_yes, estimate=None):
            confirmed_counts.append(campaigns)
            return False  # stop cleanly right after planning & confirmation

        with patch.dict(os.environ, self.env, clear=True), \
             patch.object(planner_mod, "propose_campaigns", side_effect=AssertionError("propose_campaigns must not run on resume")), \
             patch.object(mantis_main, "_confirm_work_plan", side_effect=_capture_confirm), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            rc = asyncio.run(
                mantis_main.pipeline(
                    scan_target=self.repo,
                    db_override=self.db,
                    model_override="openai/nonexistent",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    auto_configure=False,
                    resume_run_id=run,
                )
            )
        self.assertEqual(rc, 0)
        self.assertEqual(confirmed_counts, [1])


if __name__ == "__main__":
    unittest.main()

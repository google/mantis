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

"""Phase-2 CL 5 regression suite: MCP diff gate & concurrency, off-Vertex PR scan,
POSIX launcher/installer wrappers, and stage-eval callback & dedup equivalence parity."""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
os.environ.setdefault("LITELLM_MODE", "PRODUCTION")

import evals.run_eval as run_eval  # noqa: E402
import evals.stage_agents as stage_agents  # noqa: E402
import main as pipeline_main  # noqa: E402
import scripts.mcp_server as mcp_server  # noqa: E402
import scripts.pr_scan as pr_scan  # noqa: E402
from core.cost import record_spend  # noqa: E402
from core.database import init_db, record_artifact, record_run, write_findings  # noqa: E402


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        capture_output=True,
        text=False,
        env=env,
    )


class TestP2McpCiEvals(unittest.TestCase):
    """Covers every finding assigned to Phase-2 CL 5 (`p2-cl5`)."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="mantis_p2_cl5_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    # ------------------------------------------------------------------
    # 1. mcp-advise-1: translate_line_through_hunks & line-drift gating
    # ------------------------------------------------------------------
    def test_mcp_advise_1_translate_line_through_hunks_prevents_false_shift_miss_and_false_regression(self) -> None:
        self.assertTrue(
            hasattr(mcp_server, "translate_line_through_hunks"),
            "mcp_server must expose translate_line_through_hunks",
        )
        repo = Path(self.tmp) / "repo_shift"
        repo.mkdir()
        # Build a 130-line file with helper() at top and vuln() at lines 120..123.
        lines = ["def helper(x):", "    return x + 1", ""]
        while len(lines) < 119:
            lines.append(f"# filler {len(lines) + 1}")
        lines.extend([
            "def vuln(cmd):",       # old line 120
            "    os.system(cmd)",   # old line 121 (pre-existing HIGH finding)
            "    return cmd",       # old line 122
            "    # end vuln",       # old line 123
        ])
        (repo / "app.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "init")

        state = mcp_server.MantisState(str(repo), home=str(Path(self.tmp) / "state_shift"))
        mcp_server.reindex(state)
        record_spend(state.db_path, "run-1", str(repo), "whole", tokens=100)
        write_findings(
            state.db_path,
            str(repo / "app.py"),
            [{
                "title": "Command injection in vuln",
                "description": "os.system sink",
                "severity": "HIGH",
                "filepath": "app.py",
                "line_numbers": [121],
            }],
            run_id="run-1",
            status="static_confirmed",
        )

        # Case A: Prepend 20 comment lines at top AND edit line 123 inside vuln() (now 140..143).
        prepended = [f"# header {i}" for i in range(20)] + lines[:-1] + ["    return str(cmd)"]
        (repo / "app.py").write_text("\n".join(prepended) + "\n", encoding="utf-8")
        diff_a = _git(repo, "diff", "--unified=0").stdout.decode("utf-8")

        # Must BLOCK both before reindex() and after reindex().
        out_before = mcp_server.check_change(state, diff=diff_a)
        self.assertEqual(out_before["verdict"], "BLOCK", out_before)
        self.assertEqual(out_before["findings"][0]["relationship"], "direct")

        mcp_server.reindex(state)
        out_after = mcp_server.check_change(state, diff=diff_a)
        self.assertEqual(out_after["verdict"], "BLOCK", out_after)
        self.assertEqual(out_after["findings"][0]["relationship"], "direct")

        # Case B: Untouched pre-existing finding at old line 6 (outside helper 1..2),
        # shifted down to new line 10 when 4 lines are inserted at lines 2..5.
        # Old line 6 was within +/-3 of new changed line 5 BEFORE translation,
        # but at new line 10 (|10 - 5| = 5 > 3) it is untouched file debt (REVIEW, not BLOCK).
        repo_b = Path(self.tmp) / "repo_shift_b"
        repo_b.mkdir()
        base_b = (
            "def helper(x):\n"
            "    return x\n"
            "\n"
            "\n"
            "def untouched_sink(q):\n"
            "    return eval(q)\n"
        )
        (repo_b / "mod.py").write_text(base_b, encoding="utf-8")
        _git(repo_b, "init", "-q", "-b", "main")
        _git(repo_b, "add", "-A")
        _git(repo_b, "commit", "-q", "-m", "base")

        state_b = mcp_server.MantisState(str(repo_b), home=str(Path(self.tmp) / "state_shift_b"))
        mcp_server.reindex(state_b)
        record_spend(state_b.db_path, "run-b1", str(repo_b), "whole", tokens=100)
        write_findings(
            state_b.db_path,
            str(repo_b / "mod.py"),
            [{
                "title": "Eval sink in untouched_sink",
                "description": "pre-existing",
                "severity": "HIGH",
                "filepath": "mod.py",
                "line_numbers": [6],
            }],
            run_id="run-b1",
            status="static_confirmed",
        )

        edited_b = (
            "def helper(x):\n"
            "    a = 1\n"
            "    b = 2\n"
            "    c = 3\n"
            "    d = 4\n"
            "    return x + a + b + c + d\n"
            "\n"
            "\n"
            "def untouched_sink(q):\n"
            "    return eval(q)\n"
        )
        (repo_b / "mod.py").write_text(edited_b, encoding="utf-8")
        mcp_server.reindex(state_b)
        diff_b = _git(repo_b, "diff", "--unified=0").stdout.decode("utf-8")
        out_b = mcp_server.check_change(state_b, diff=diff_b)
        self.assertEqual(out_b["verdict"], "REVIEW", out_b)
        self.assertEqual(out_b["findings"][0]["relationship"], "unrelated_in_file")

    # ------------------------------------------------------------------
    # 2. mcp-advise-2: parse_diff_moves for git mv and git rm
    # ------------------------------------------------------------------
    def test_mcp_advise_2_parse_diff_moves_handles_git_mv_and_git_rm(self) -> None:
        self.assertTrue(
            hasattr(mcp_server, "parse_diff_moves"),
            "mcp_server must expose parse_diff_moves",
        )
        repo = Path(self.tmp) / "repo_moves"
        repo.mkdir()
        (repo / "login.py").write_text("def auth(u):\n    return eval(u)\n", encoding="utf-8")
        (repo / "clean.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "init")

        state = mcp_server.MantisState(str(repo), home=str(Path(self.tmp) / "state_moves"))
        mcp_server.reindex(state)
        record_spend(state.db_path, "run-m1", str(repo), "whole", tokens=50)
        write_findings(
            state.db_path,
            str(repo / "login.py"),
            [{
                "title": "Code injection in auth",
                "description": "eval on user",
                "severity": "HIGH",
                "filepath": "login.py",
                "line_numbers": [2],
            }],
            run_id="run-m1",
            status="static_confirmed",
        )

        # (a) Pure git mv (100% similarity, zero hunks) + git mv with edit: both must BLOCK.
        (repo / "auth").mkdir()
        _git(repo, "mv", "login.py", "auth/login.py")
        pure_mv_diff = _git(repo, "diff", "--cached", "-M").stdout.decode("utf-8")
        moves = mcp_server.parse_diff_moves(pure_mv_diff)
        self.assertEqual(moves["renamed"], {"login.py": "auth/login.py"})
        out_mv = mcp_server.check_change(state, diff=pure_mv_diff)
        self.assertEqual(out_mv["verdict"], "BLOCK", out_mv)
        self.assertEqual(out_mv["findings"][0]["renamed_from"], "login.py")

        # Reset and test git rm login.py + clean edit on clean.py -> must REVIEW (not PASS).
        _git(repo, "reset", "--hard", "HEAD")
        _git(repo, "rm", "-q", "login.py")
        (repo / "clean.py").write_text("def ok():\n    return 2\n", encoding="utf-8")
        _git(repo, "add", "clean.py")
        rm_diff = _git(repo, "diff", "--cached", "-M").stdout.decode("utf-8")
        moves_rm = mcp_server.parse_diff_moves(rm_diff)
        self.assertIn("login.py", moves_rm["deleted"])
        out_rm = mcp_server.check_change(state, diff=rm_diff)
        self.assertEqual(out_rm["verdict"], "REVIEW", out_rm)
        self.assertTrue(any("login.py" in r and "deletes" in r for r in out_rm["reasons"]), out_rm["reasons"])

    # ------------------------------------------------------------------
    # 3. mcp-advise-3: uncapped caller_file_paths for blast radius
    # ------------------------------------------------------------------
    def test_mcp_advise_3_blast_radius_caller_files_uncapped_past_ten_callers(self) -> None:
        repo = Path(self.tmp) / "repo_callers"
        repo.mkdir()
        (repo / "core_lib.py").write_text("def sink_fn(v):\n    return v + 1\n", encoding="utf-8")
        for idx in range(12):
            (repo / f"c{idx:02d}.py").write_text(
                f"from core_lib import sink_fn\n\ndef call_{idx:02d}(x):\n    return sink_fn(x)\n",
                encoding="utf-8",
            )
        state = mcp_server.MantisState(str(repo), home=str(Path(self.tmp) / "state_callers"))
        mcp_server.reindex(state)
        record_spend(state.db_path, "run-c1", str(repo), "whole", tokens=50)
        write_findings(
            state.db_path,
            str(repo / "c11.py"),
            [{
                "title": "Auth bypass in 12th caller",
                "description": "reaches sink_fn",
                "severity": "HIGH",
                "filepath": "c11.py",
                "line_numbers": [4],
            }],
            run_id="run-c1",
            status="static_confirmed",
        )
        diff = (
            "--- a/core_lib.py\n"
            "+++ b/core_lib.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def sink_fn(v):\n"
            "-    return v + 1\n"
            "+    return v + 2\n"
        )
        out = mcp_server.check_change(state, diff=diff)
        self.assertEqual(out["verdict"], "REVIEW", out)
        self.assertTrue(
            any(f["filepath"] == "c11.py" and f["relationship"] == "caller_radius" for f in out["findings"]),
            out["findings"],
        )

    # ------------------------------------------------------------------
    # 4. mcp-advise-4a: _mcp_repo_scan_cmd delegates to _scan_cmd
    # ------------------------------------------------------------------
    def test_mcp_advise_4_repo_scan_cmd_delegates_to_scan_cmd_and_preserves_mocks(self) -> None:
        self.assertTrue(
            hasattr(mcp_server, "_mcp_repo_scan_cmd"),
            "mcp_server must expose _mcp_repo_scan_cmd delegating to _scan_cmd",
        )
        repo = Path(self.tmp) / "repo_cmd"
        repo.mkdir()
        (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
        (repo / "b.py").write_text("y = 2\n", encoding="utf-8")
        state = mcp_server.MantisState(str(repo), home=str(Path(self.tmp) / "state_cmd"))

        cmd = mcp_server._mcp_repo_scan_cmd(state, ["a.py", "b.py"], 120, "test-model")
        base = mcp_server._scan_cmd(state, str(repo), 120, "test-model")
        self.assertEqual(cmd[:len(base)], base)
        self.assertIn("--scan-mode", cmd)
        self.assertEqual(cmd[cmd.index("--scan-mode") + 1], "changed")
        self.assertIn("--changed-files=a.py", cmd)
        self.assertIn("--changed-files=b.py", cmd)
        self.assertIn("--sandbox", cmd)
        self.assertEqual(cmd[cmd.index("--sandbox") + 1], "static-only")

        seen_calls = []

        def fake_scan_cmd(st, target, max_llm_calls, model):
            seen_calls.append((target, max_llm_calls, model))
            return [sys.executable, "-c", "pass"]

        with mock.patch.object(mcp_server, "_scan_cmd", fake_scan_cmd):
            out = mcp_server.scan_change(state, ["a.py", "b.py"], max_llm_calls=120, model="m")
            status = mcp_server.scan_status(state, out["scan_id"], wait_seconds=10)
        self.assertEqual(status.get("status"), "done", status)
        self.assertEqual(len(seen_calls), 1, "one repo-rooted pipeline invocation per scan_change")
        self.assertEqual(seen_calls[0][1], 120)

    # ------------------------------------------------------------------
    # 5. mcp-advise-4b: finding_resolutions survive subsequent rescans
    # ------------------------------------------------------------------
    def test_mcp_advise_4_finding_resolutions_persist_across_rescan(self) -> None:
        repo = Path(self.tmp) / "repo_res"
        repo.mkdir()
        (repo / "app.py").write_text("def f(x):\n    return eval(x)\n\ndef g(y):\n    return exec(y)\n", encoding="utf-8")
        state = mcp_server.MantisState(str(repo), home=str(Path(self.tmp) / "state_res"))
        mcp_server.reindex(state)
        record_spend(state.db_path, "run-1", str(repo), "whole", tokens=50)
        write_findings(
            state.db_path,
            str(repo / "app.py"),
            [
                {
                    "title": "Eval injection in f",
                    "description": "eval sink",
                    "severity": "HIGH",
                    "filepath": "app.py",
                    "line_numbers": [2],
                    "cwe": "CWE-94",
                },
                {
                    "title": "Exec injection in g",
                    "description": "exec sink",
                    "severity": "HIGH",
                    "filepath": "app.py",
                    "line_numbers": [5],
                    "cwe": "CWE-94",
                },
            ],
            run_id="run-1",
            status="static_confirmed",
        )
        rows = mcp_server.get_findings(state)["findings"]
        by_title = {r["title"]: r["id"] for r in rows}

        # Resolve first as false_positive and second as accepted_risk.
        r1 = mcp_server.resolve_finding(state, by_title["Eval injection in f"], "false_positive", "guarded upstream")
        self.assertTrue(r1.get("applied"), r1)
        r2 = mcp_server.resolve_finding(state, by_title["Exec injection in g"], "accepted_risk", "internal admin tool")
        self.assertTrue(r2.get("applied"), r2)
        self.assertEqual(r2.get("new_status"), "accepted_risk")

        # accepted_risk must be suppressed in database/SARIF and protected as monotonic terminal.
        from core.database import is_suppressed, read_findings, update_finding_status_by_id, update_status
        from core.sarif import build_sarif

        self.assertTrue(is_suppressed("accepted_risk"))
        sarif_doc, _sarif_skipped = build_sarif(read_findings(state.db_path), scan_root=str(repo))
        self.assertEqual(sarif_doc["runs"][0]["results"], [], "accepted_risk leaked into active SARIF")
        update_status(state.db_path, "app.py", "run-1", "static_confirmed")
        after_stamp = {r["id"]: r["status"] for r in read_findings(state.db_path)}
        self.assertEqual(after_stamp[by_title["Exec injection in g"]], "accepted_risk")

        # Next MCP scan (run-2) re-reports both static findings with new row IDs.
        write_findings(
            state.db_path,
            str(repo / "app.py"),
            [
                {
                    "title": "Eval injection in f",
                    "description": "eval sink re-reported",
                    "severity": "HIGH",
                    "filepath": "app.py",
                    "line_numbers": [2],
                    "cwe": "CWE-94",
                },
                {
                    "title": "Exec injection in g",
                    "description": "exec sink re-reported",
                    "severity": "HIGH",
                    "filepath": "app.py",
                    "line_numbers": [5],
                    "cwe": "CWE-94",
                },
            ],
            run_id="run-2",
            status="static_confirmed",
        )
        gate = mcp_server.check_change(state, files=["app.py"])
        self.assertEqual(gate["verdict"], "PASS", gate)

        # Machine-verified dynamic evidence MUST still override false_positive (INV-1).
        write_findings(
            state.db_path,
            str(repo / "app.py"),
            [{
                "title": "Eval injection in f",
                "description": "sandbox exploited",
                "severity": "HIGH",
                "filepath": "app.py",
                "line_numbers": [2],
                "cwe": "CWE-94",
            }],
            run_id="run-3",
            status="dynamic_confirmed",
            verified_evidence=True,
        )
        gate_dyn = mcp_server.check_change(state, files=["app.py"])
        self.assertEqual(gate_dyn["verdict"], "BLOCK", gate_dyn)

        # Resolving a dynamic_confirmed finding as accepted_risk must NOT overwrite
        # machine-verified 'dynamic_confirmed' status on the DB row (neither via
        # resolve_finding nor direct update_finding_status_by_id), while recording
        # accepted_risk in finding_resolutions for the MCP gate.
        dyn_rows = [
            r for r in read_findings(state.db_path)
            if r["run_id"] == "run-3" and r["status"] == "dynamic_confirmed"
        ]
        self.assertEqual(len(dyn_rows), 1)
        dyn_id = dyn_rows[0]["id"]
        update_finding_status_by_id(state.db_path, dyn_id, "run-3", "accepted_risk")
        self.assertEqual(
            next(r["status"] for r in read_findings(state.db_path) if r["id"] == dyn_id),
            "dynamic_confirmed",
        )
        r_acc_dyn = mcp_server.resolve_finding(state, dyn_id, "accepted_risk", "accepted in lab")
        self.assertTrue(r_acc_dyn.get("applied"), r_acc_dyn)
        self.assertEqual(r_acc_dyn.get("new_status"), "dynamic_confirmed")
        self.assertEqual(
            next(r["status"] for r in read_findings(state.db_path) if r["id"] == dyn_id),
            "dynamic_confirmed",
        )
        self.assertEqual(mcp_server.check_change(state, files=["app.py"])["verdict"], "PASS")

    # ------------------------------------------------------------------
    # 6. mcp-advise-7, 8: atomic scan slot lock & process-group killpg
    # ------------------------------------------------------------------
    def test_mcp_advise_7_8_scan_lock_toctou_and_process_group_cleanup(self) -> None:
        repo = Path(self.tmp) / "repo_conc"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
        state = mcp_server.MantisState(str(repo), home=str(Path(self.tmp) / "state_conc"))
        state.ensure_home()

        # (a) Concurrent worker-thread race: slow ensure_home to widen any lock gap.
        barrier = threading.Barrier(6)
        orig_ensure = state.ensure_home

        def slow_ensure():
            time.sleep(0.05)
            return orig_ensure()

        results = []
        res_lock = threading.Lock()

        def worker():
            barrier.wait()
            r = mcp_server.scan_change(state, ["app.py"])
            with res_lock:
                results.append(r)

        with mock.patch.object(state, "ensure_home", slow_ensure), mock.patch.object(
            mcp_server,
            "_scan_cmd",
            lambda *a, **k: [sys.executable, "-c", "import time; time.sleep(0.4)"],
        ):
            threads = [threading.Thread(target=worker) for _ in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        ok = [r for r in results if "scan_id" in r]
        refused = [r for r in results if "error" in r]
        self.assertEqual(len(ok), mcp_server.MAX_CONCURRENT_SCANS, results)
        self.assertEqual(len(refused), 6 - mcp_server.MAX_CONCURRENT_SCANS)
        for item in ok:
            mcp_server.scan_status(state, item["scan_id"], wait_seconds=10)

        # (b) Timed-out subprocess tree (child + grandchild) is killed via start_new_session + killpg.
        pid_file = Path(self.tmp) / "grandchild.pid"
        fork_tree_py = (
            "import subprocess, sys, time\n"
            f"p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            f"open({str(pid_file)!r}, 'w').write(str(p.pid))\n"
            "time.sleep(60)\n"
        )
        with mock.patch.object(
            mcp_server, "_scan_cmd", lambda *a, **k: [sys.executable, "-c", fork_tree_py]
        ):
            out = mcp_server.scan_change(state, ["app.py"], timeout_seconds=0.5)
            st = mcp_server.scan_status(state, out["scan_id"], wait_seconds=10)
        self.assertEqual(st.get("status"), "timed_out", st)
        self.assertTrue(pid_file.exists(), "child never wrote grandchild PID")
        grandchild_pid = int(pid_file.read_text().strip())

        def _pid_running(pid: int) -> bool:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return False
            except PermissionError:
                return True
            stat_path = Path(f"/proc/{pid}/stat")
            if stat_path.exists():
                try:
                    raw_stat = stat_path.read_text(encoding="utf-8", errors="replace")
                    after_comm = raw_stat.rsplit(")", 1)[-1].strip()
                    if after_comm.startswith("Z"):
                        return False
                except OSError:
                    pass
            return True

        # Give OS a brief moment to reap killed process group, then verify PID is gone.
        deadline = time.time() + 3.0
        alive = True
        while time.time() < deadline:
            if not _pid_running(grandchild_pid):
                alive = False
                break
            time.sleep(0.05)
        if alive:
            with contextlib.suppress(ProcessLookupError):
                os.kill(grandchild_pid, signal.SIGKILL)
        self.assertFalse(alive, f"grandchild PID {grandchild_pid} leaked after scan timeout")

    # ------------------------------------------------------------------
    # 7. mcp-advise-9: advise.py resolves relative --file against repo
    # ------------------------------------------------------------------
    def test_mcp_advise_9_advise_resolves_relative_file_against_target_root(self) -> None:
        db_path = str(Path(self.tmp) / "shared_knowledge.db")
        init_db(db_path)
        repo_a = Path(self.tmp) / "repoA"
        repo_b = Path(self.tmp) / "repoB"
        for r, label in ((repo_a, "REPO_A"), (repo_b, "REPO_B")):
            (r / "src").mkdir(parents=True)
            (r / "src" / "auth.py").write_text("def login():\n    pass\n", encoding="utf-8")
            _git(r, "init", "-q", "-b", "main")
            run_id = f"run_{label}"
            record_run(db_path, run_id, "test-model", metadata={"target_root": str(r.resolve())})
            record_artifact(
                db_path,
                run_id,
                "threat_model",
                "workspace/kb/THREAT_MODEL.md",
                f"## System Overview\nTHREAT_MODEL_UNIQUE_{label}\n",
                metadata={"resource": str(r.resolve())},
            )
            write_findings(
                db_path,
                str((r / "src" / "auth.py").resolve()),
                [{
                    "title": f"FINDING_UNIQUE_{label}",
                    "description": f"bug in {label}",
                    "severity": "HIGH",
                    "filepath": "src/auth.py",
                    "line_numbers": [1],
                }],
                run_id=run_id,
                status="static_confirmed",
            )

        advise_py = str(_REF_ROOT / "scripts" / "advise.py")
        # From repoA root with relative --file src/auth.py
        p1 = subprocess.run(
            [sys.executable, advise_py, "--db", db_path, "--file", "src/auth.py", "--json"],
            cwd=str(repo_a),
            capture_output=True,
            text=True,
        )
        self.assertEqual(p1.returncode, 0, p1.stderr)
        self.assertIn("THREAT_MODEL_UNIQUE_REPO_A", p1.stdout)
        self.assertIn("FINDING_UNIQUE_REPO_A", p1.stdout)
        self.assertNotIn("REPO_B", p1.stdout)

        # From repoA/src subdirectory with relative --file auth.py
        p2 = subprocess.run(
            [sys.executable, advise_py, "--db", db_path, "--file", "auth.py", "--json"],
            cwd=str(repo_a / "src"),
            capture_output=True,
            text=True,
        )
        self.assertEqual(p2.returncode, 0, p2.stderr)
        self.assertIn("FINDING_UNIQUE_REPO_A", p2.stdout)
        self.assertNotIn("REPO_B", p2.stdout)

    # ------------------------------------------------------------------
    # 8. gap-degraded-structural-index-8: legitimately empty AST repos
    # ------------------------------------------------------------------
    def test_gap_degraded_structural_index_8_legitimately_empty_repo(self) -> None:
        repo = Path(self.tmp) / "tf_repo"
        repo.mkdir()
        (repo / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")
        state = mcp_server.MantisState(str(repo), home=str(Path(self.tmp) / "state_tf"))
        res = mcp_server.reindex(state)
        self.assertEqual(res["status"], "empty")
        self.assertEqual(res["total_files"], 0)

        idx = state.index()
        self.assertTrue(hasattr(idx, "is_legitimately_empty"))
        self.assertTrue(idx.is_legitimately_empty())
        self.assertTrue(pr_scan.index_is_repo_rooted(state))

        record_spend(state.db_path, "run-tf", str(repo), "whole", tokens=20)
        gate = mcp_server.check_change(state, files=["main.tf"])
        self.assertEqual(gate["verdict"], "PASS", gate)
        self.assertEqual(gate["coverage_gaps"], [])

    # ------------------------------------------------------------------
    # 9. ci-pr-scan-2: --max-run-seconds & SIGTERM summary/report flush
    # ------------------------------------------------------------------
    def test_ci_pr_scan_2_max_run_seconds_and_sigterm_summary_flush(self) -> None:
        repo = Path(self.tmp) / "pr_deadline"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
        (repo / "b.py").write_text("y = 1\n", encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "base")
        base = _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
        (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
        (repo / "b.py").write_text("y = 2\n", encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "head")

        # (a) --max-run-seconds caps the whole run and skips launching b.py.
        out_json = Path(self.tmp) / "deadline_report.json"
        summary_md = Path(self.tmp) / "deadline_summary.md"
        gh_out = Path(self.tmp) / "deadline_gh_out"
        sleeper = lambda *a, **k: [sys.executable, "-c", "import time; time.sleep(5)"]
        with mock.patch.object(pr_scan, "_scan_cmd", sleeper), contextlib.redirect_stdout(io.StringIO()):
            rc = pr_scan.main(
                [
                    "--repo", str(repo),
                    "--base", base,
                    "--daily-token-budget", "0",
                    "--per-file-timeout", "30",
                    "--max-run-seconds", "0.4",
                    "--output-json", str(out_json),
                    "--summary", str(summary_md),
                    "--github-output", str(gh_out),
                    "--state-dir", str(Path(self.tmp) / "st_dl"),
                ],
                env={**os.environ, "GEMINI_API_KEY": "test-key", "MODEL": "gemini-3.8-flash"},
            )
        self.assertEqual(rc, pr_scan.EXIT_OK)
        rep = json.loads(out_json.read_text(encoding="utf-8"))
        by_file = {r["file"]: r["status"] for r in rep["scan"]["results"]}
        self.assertEqual(by_file["a.py"], "timed_out")
        self.assertEqual(by_file["b.py"], "deadline_exceeded")
        self.assertEqual(rep["verdict"], "REVIEW")

        # (b) SIGTERM mid-scan flushes summary, github-output, and output-json instead of abrupt death.
        sig_json = Path(self.tmp) / "sigterm_report.json"
        sig_sum = Path(self.tmp) / "sigterm_summary.md"
        sig_gh = Path(self.tmp) / "sigterm_gh_out"
        started_marker = Path(self.tmp) / "scan_started.marker"
        child_snippet = (
            f"import pathlib, time; "
            f"pathlib.Path({str(started_marker)!r}).write_text('1'); "
            f"time.sleep(30)"
        )
        driver_code = (
            f"import sys; sys.path.insert(0, {str(_REF_ROOT)!r})\n"
            "from unittest import mock\n"
            "import scripts.pr_scan as pr_scan\n"
            f"child = [sys.executable, '-c', {child_snippet!r}]\n"
            "with mock.patch.object(pr_scan, '_scan_cmd', lambda *a, **k: list(child)):\n"
            f"    sys.exit(pr_scan.main(['--repo', {str(repo)!r}, '--base', {base!r}, '--model', 'gemini-3.8-flash', "
            f"'--daily-token-budget', '0', '--output-json', {str(sig_json)!r}, '--summary', {str(sig_sum)!r}, "
            f"'--github-output', {str(sig_gh)!r}, '--state-dir', {str(Path(self.tmp) / 'st_sig')!r}], "
            "env={'PATH': '/usr/bin:/bin', 'GEMINI_API_KEY': 'test-key', "
            "'LITELLM_LOCAL_MODEL_COST_MAP': 'True', 'LITELLM_MODE': 'PRODUCTION'}))\n"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", driver_code],
            env={
                **os.environ,
                "LITELLM_LOCAL_MODEL_COST_MAP": "True",
                "LITELLM_MODE": "PRODUCTION",
            },
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.time() + 30.0
            while not started_marker.exists() and time.time() < deadline:
                time.sleep(0.05)
            self.assertTrue(started_marker.exists(), "child scan never started")
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=15)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        self.assertTrue(sig_json.exists(), "SIGTERM failed to flush --output-json")
        self.assertTrue(sig_sum.exists(), "SIGTERM failed to flush --summary")
        self.assertIn("verdict=", sig_gh.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    # 10. ci-pr-scan-4: non-UTF-8 git diff bytes & top-level _not_run
    # ------------------------------------------------------------------
    def test_ci_pr_scan_4_non_utf8_diff_bytes_and_unexpected_driver_exception(self) -> None:
        repo = Path(self.tmp) / "pr_latin1"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        (repo / "latin.py").write_bytes(b"label = 'cafe'\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "base")
        base = _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
        (repo / "latin.py").write_bytes(b"label = 'caf\xe9'\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "latin1")

        changed, diff_text, _moves = pr_scan.pr_changes(repo, base)
        self.assertEqual(changed["latin.py"], [1])
        self.assertIn("\ufffd", diff_text)

        # Top-level unexpected exception must route through _not_run (exit 0 / 3, never exit 1).
        summary_md = Path(self.tmp) / "crash_summary.md"
        gh_out = Path(self.tmp) / "crash_gh_out"
        with mock.patch.object(pr_scan, "pr_changes", side_effect=RuntimeError("unexpected boom")), \
                contextlib.redirect_stdout(io.StringIO()):
            rc_open = pr_scan.main(
                [
                    "--repo", str(repo), "--base", base, "--model", "gemini-3.8-flash",
                    "--daily-token-budget", "0", "--summary", str(summary_md),
                    "--github-output", str(gh_out),
                ],
                env={"PATH": os.environ.get("PATH", ""), "GEMINI_API_KEY": "k"},
            )
            rc_closed = pr_scan.main(
                [
                    "--repo", str(repo), "--base", base, "--model", "gemini-3.8-flash",
                    "--daily-token-budget", "0", "--fail-closed",
                    "--summary", str(summary_md), "--github-output", str(gh_out),
                ],
                env={"PATH": os.environ.get("PATH", ""), "GEMINI_API_KEY": "k"},
            )
        self.assertEqual(rc_open, pr_scan.EXIT_OK)
        self.assertEqual(rc_closed, pr_scan.EXIT_INFRA)
        self.assertIn("verdict=NOT_RUN", gh_out.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    # 11. ci-pr-scan-8: Cloud Monitoring gated on Vertex models only
    # ------------------------------------------------------------------
    def test_ci_pr_scan_8_daily_token_meter_gated_to_vertex_models_only(self) -> None:
        repo = Path(self.tmp) / "pr_off_vertex"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "base")
        base = _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
        (repo / "app.py").write_text("x = 2\n", encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "head")

        noop_scan = lambda state, target, max_llm_calls, model: [
            sys.executable,
            "-c",
            (
                f"import sys; sys.path.insert(0, {str(_REF_ROOT)!r}); "
                "from core.cost import record_spend; "
                f"record_spend({state.db_path!r}, 'r', {target!r}, 'changed', tokens=10)"
            ),
        ]

        def forbid_gcp_meter(*_a, **_kw):
            raise AssertionError("Cloud Monitoring meter must not run for non-Vertex models")

        cases = [
            (["--model", "anthropic/claude-opus-5"], {"ANTHROPIC_API_KEY": "sk-ant-test"}),
            (["--model", "gemini-3.8-flash"], {"GEMINI_API_KEY": "ai-studio-key"}),
            (["--model", "openai/gpt-5", "--api-base", "http://127.0.0.1:9/v1"], {"OPENAI_API_KEY": "sk-test"}),
        ]
        for idx, (extra_args, extra_env) in enumerate(cases):
            out_json = Path(self.tmp) / f"off_vertex_{idx}.json"
            gh_out = Path(self.tmp) / f"off_vertex_gh_{idx}"
            clean_env = {"PATH": os.environ.get("PATH", ""), **extra_env}
            with mock.patch.object(pr_scan, "tokens_served_today", forbid_gcp_meter), \
                    mock.patch.object(pr_scan, "_scan_cmd", noop_scan), \
                    contextlib.redirect_stdout(io.StringIO()):
                # Default --daily-token-budget (100M) is intentionally NOT overridden to 0!
                rc = pr_scan.main(
                    [
                        "--repo", str(repo),
                        "--base", base,
                        "--fail-closed",
                        "--output-json", str(out_json),
                        "--github-output", str(gh_out),
                        "--state-dir", str(Path(self.tmp) / f"st_ov_{idx}"),
                        *extra_args,
                    ],
                    env=clean_env,
                )
            self.assertEqual(rc, pr_scan.EXIT_OK, f"case {extra_args} failed: {gh_out.read_text()}")
            self.assertEqual(json.loads(out_json.read_text())["verdict"], "PASS")

    # ------------------------------------------------------------------
    # 12. ci-pr-scan-10: --scan-mode uncovered
    # ------------------------------------------------------------------
    def test_ci_pr_scan_10_scan_mode_uncovered_skips_covered_small_repo_files(self) -> None:
        from scripts.launch import build_parser

        parsed = build_parser().parse_args(["--scan-mode", "uncovered", "."])
        self.assertEqual(parsed.scan_mode, "uncovered")

        repo = Path(self.tmp) / "small_repo"
        repo.mkdir()
        a_py = str((repo / "a.py").resolve())
        b_py = str((repo / "b.py").resolve())
        Path(a_py).write_text("x = 1\n", encoding="utf-8")
        Path(b_py).write_text("y = 2\n", encoding="utf-8")
        db_path = str(Path(self.tmp) / "uncovered.db")
        init_db(db_path)
        record_run(db_path, "r1", "vertex_ai/gemini-3.8-flash")
        record_spend(db_path, "r1", a_py, "file-by-file", tokens=100)

        targets, _astm, mode = pipeline_main.resolve_scan_targets(
            repo,
            {"scan_mode": "uncovered", "default_model": "vertex_ai/gemini-3.8-flash"},
            [a_py, b_py],
            db_path=db_path,
        )
        self.assertEqual(targets, [b_py])
        self.assertEqual(mode, "file-by-file")

        # Once b.py is also covered, --scan-mode uncovered returns 0 targets cleanly.
        record_spend(db_path, "r1", b_py, "file-by-file", tokens=100)
        targets_done, _astm2, mode_done = pipeline_main.resolve_scan_targets(
            repo,
            {"scan_mode": "uncovered", "default_model": "vertex_ai/gemini-3.8-flash"},
            [a_py, b_py],
            db_path=db_path,
        )
        self.assertEqual(targets_done, [])
        self.assertEqual(mode_done, "uncovered")

    # ------------------------------------------------------------------
    # 13. operator-surface-4, 10 & run-lifecycle-5: dash, CWD, SIGTERM
    # ------------------------------------------------------------------
    def test_operator_surface_4_10_and_run_lifecycle_5_posix_shells_and_sigterm(self) -> None:
        run_sh = _REF_ROOT / "run.sh"
        install_sh = _REF_ROOT / "install.sh"
        for script_path in (run_sh, install_sh):
            p = subprocess.run(["sh", "-n", str(script_path)], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            if Path("/bin/dash").exists():
                dp = subprocess.run(["/bin/dash", "-n", str(script_path)], capture_output=True, text=True)
                self.assertEqual(dp.returncode, 0, dp.stderr)
            non_comment = "\n".join(
                ln for ln in script_path.read_text(encoding="utf-8").splitlines()
                if not ln.lstrip().startswith("#")
            )
            self.assertNotRegex(non_comment, r"(?m)^\s*source\s+", f"{script_path.name} uses bashism 'source'")

        # install.sh must honour PYTHON env var and enforce 3.12 <= version < 3.15.
        fake_py315 = Path(self.tmp) / "fake_py315.sh"
        fake_py315.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = \"--version\" ]; then echo 'Python 3.15.0'; exit 0; fi\n"
            "exit 1\n",
            encoding="utf-8",
        )
        fake_py315.chmod(0o755)
        inst = subprocess.run(
            ["/bin/sh", str(install_sh)],
            env={**os.environ, "PYTHON": str(fake_py315)},
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(inst.returncode, 0)
        self.assertIn("Python 3.15.0", inst.stderr)

        # run.sh invoked as `sh run.sh --dry-run .` from caller_dir must anchor `.` to caller_dir!
        caller_dir = Path(self.tmp) / "caller_repo"
        caller_dir.mkdir()
        (caller_dir / "hello.py").write_text("x = 1\n", encoding="utf-8")
        dry = subprocess.run(
            ["/bin/sh", str(run_sh), "--no-auto-configure", "--sandbox", "static-only", "--dry-run", "."],
            cwd=str(caller_dir),
            env={**os.environ, "GEMINI_API_KEY": "dummy", "MANTIS_MODEL": "gemini/gemini-3.8-flash"},
            capture_output=True,
            text=True,
        )
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertIn(str(caller_dir.resolve()), dry.stdout)

        # SIGTERM sent to launch.py must flush --spend-report and exit 143.
        spend_out = Path(self.tmp) / "sigterm_spend.json"
        ready_file = Path(self.tmp) / "pipeline_ready"
        sig_script = (
            f"import asyncio, pathlib, sys; sys.path.insert(0, {str(_REF_ROOT)!r})\n"
            "from unittest import mock\n"
            "import scripts.launch as launch\n"
            "async def slow_pipeline(**kw):\n"
            f"    pathlib.Path({str(ready_file)!r}).write_text('1')\n"
            "    await asyncio.sleep(60)\n"
            "    return 0\n"
            f"sys.argv = ['launch.py', {str(caller_dir)!r}, '--no-auto-configure', '--sandbox', 'static-only', "
            f"'--model', 'gemini/gemini-3.8-flash', '--spend-report', {str(spend_out)!r}]\n"
            "with mock.patch.object(launch, 'pipeline', slow_pipeline), "
            "mock.patch.object(launch, 'run_preflight_checks', lambda *a, **k: (True, [])):\n"
            "    sys.exit(launch.main())\n"
        )
        p_sig = subprocess.Popen(
            [sys.executable, "-c", sig_script],
            env={
                **os.environ,
                "GEMINI_API_KEY": "dummy",
                "LITELLM_LOCAL_MODEL_COST_MAP": "True",
                "LITELLM_MODE": "PRODUCTION",
            },
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.time() + 30.0
            while not ready_file.exists() and time.time() < deadline:
                time.sleep(0.05)
            self.assertTrue(ready_file.exists(), "slow_pipeline never started")
            p_sig.send_signal(signal.SIGTERM)
            rc_sig = p_sig.wait(timeout=15)
        finally:
            if p_sig.poll() is None:
                p_sig.kill()
                p_sig.wait()
        self.assertEqual(rc_sig, 143)
        self.assertTrue(spend_out.exists())
        self.assertEqual(json.loads(spend_out.read_text())["exit_code"], 143)

    # ------------------------------------------------------------------
    # 14. evals-1: stage_agents wires production before_model_callback chain
    # ------------------------------------------------------------------
    def test_evals_1_stage_agent_wires_production_before_model_callbacks(self) -> None:
        import inspect
        from google.adk.models.llm_request import LlmRequest
        from google.genai import types

        jail = Path(self.tmp) / "eval_jail"
        jail.mkdir()
        (jail / "vuln.py").write_text("import os\ndef run(cmd):\n    os.system(cmd)\n", encoding="utf-8")
        db_path = str(Path(self.tmp) / "eval_cb.db")
        init_db(db_path)

        from core.graph_loader import GlobalConfig
        import core.graph_loader as graph_loader

        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("EVAL_REASONING_EFFORT", None)
            with mock.patch.object(stage_agents, "get_llm_kwargs", wraps=stage_agents.get_llm_kwargs) as spy, \
                    mock.patch.object(
                        graph_loader,
                        "_make_node_context_ceiling_before_model_callback",
                        wraps=graph_loader._make_node_context_ceiling_before_model_callback,
                    ) as ceil_spy:
                agent = stage_agents.build_stage_agent("researcher", model_id="openai/test-model")
            called_effort = spy.call_args.kwargs.get("reasoning_effort")
            self.assertEqual(
                ceil_spy.call_args.kwargs.get("max_continuations"),
                GlobalConfig().max_node_continuations,
            )
            with mock.patch.object(stage_agents, "_load_shipped_workflow_meta", return_value=({"max_node_continuations": 0}, {})), \
                    mock.patch.object(
                        graph_loader,
                        "_make_node_context_ceiling_before_model_callback",
                        wraps=graph_loader._make_node_context_ceiling_before_model_callback,
                    ) as ceil_zero_spy:
                stage_agents.build_stage_agent("researcher", model_id="openai/test-model")
            self.assertEqual(ceil_zero_spy.call_args.kwargs.get("max_continuations"), 0)
        self.assertEqual(called_effort, "medium", "researcher default effort should match workflow.json ('medium')")

        cbs = agent.before_model_callback
        self.assertIsInstance(cbs, list)
        self.assertGreaterEqual(len(cbs), 3, "production before_model_callback chain must be wired")

        # Execute callbacks under an eval RunContext and confirm deterministic audit checklist injection!
        ctx, tok = stage_agents.install_eval_run_context(str(jail), db_path, target_file=str(jail / "vuln.py"))
        try:
            req = LlmRequest(
                model="openai/test-model",
                contents=[types.Content(role="user", parts=[types.Part.from_text(text="Audit vuln.py")])],
            )
            for cb in cbs:
                if cb is not None:
                    maybe_coro = cb(callback_context=None, llm_request=req)
                    if inspect.isawaitable(maybe_coro):
                        asyncio.run(maybe_coro)
            sys_inst = str(getattr(req.config, "system_instruction", "") or "")
            user_texts = "\n".join(
                p.text for c in (req.contents or []) for p in (c.parts or []) if getattr(p, "text", None)
            )
            combined = sys_inst + "\n" + user_texts
            self.assertIn("os.system", combined, "campaign directive / AST sink checklist was not injected")
        finally:
            from core.context import current_run_context

            current_run_context.reset(tok)

    # ------------------------------------------------------------------
    # 15. evals-3: symmetric equivalence-class score_dedup_partition
    # ------------------------------------------------------------------
    def test_evals_3_score_dedup_partition_symmetric_equivalence_classes(self) -> None:
        syn_path = _REF_ROOT / "evals" / "synthetic_dataset.json"
        syn = json.loads(syn_path.read_text(encoding="utf-8"))
        id_to_title = {f["id"]: f["title"] for f in syn["findings"]}

        # (a) Valid merge keeping the SECOND twin (102, 202, 502) in every duplicate cluster -> 1.0!
        db_keep_second = []
        merged_map = {101: 102, 201: 202, 501: 502}
        for f in syn["findings"]:
            fid = f["id"]
            if fid in merged_map:
                prim = merged_map[fid]
                db_keep_second.append({
                    "id": fid,
                    "title": f["title"],
                    "status": "duplicate_merged",
                    "merged_into_id": prim,
                    "description": f"{f['description']}\n[MERGED: Duplicate of {id_to_title[prim]} - Reason: twin]",
                })
            else:
                db_keep_second.append({
                    "id": fid,
                    "title": f["title"],
                    "status": "reported",
                    "merged_into_id": None,
                    "description": f["description"],
                })
        res_sym = run_eval.score_dedup_partition(db_keep_second, syn)
        self.assertEqual(res_sym["tp"], 3, res_sym)
        self.assertEqual(res_sym["fn"], 0, res_sym)
        self.assertEqual(res_sym["fp"], 0, res_sym)
        self.assertEqual(res_sym["precision"], 1.0)
        self.assertEqual(res_sym["recall"], 1.0)
        self.assertEqual(res_sym["f1"], 1.0)

        # (b) Collapsing all 6 findings from 3 distinct bug clusters into 101 must penalize FP & FN!
        db_collapse = []
        for f in syn["findings"]:
            fid = f["id"]
            if fid in (102, 201, 202, 501, 502):
                db_collapse.append({
                    "id": fid,
                    "title": f["title"],
                    "status": "duplicate_merged",
                    "merged_into_id": 101,
                    "description": f"{f['description']}\n[MERGED: Duplicate of {id_to_title[101]} - Reason: overmerge]",
                })
            else:
                db_collapse.append({
                    "id": fid,
                    "title": f["title"],
                    "status": "reported",
                    "merged_into_id": None,
                    "description": f["description"],
                })
        res_collapse = run_eval.score_dedup_partition(db_collapse, syn)
        self.assertGreaterEqual(res_collapse["fp"], 2, res_collapse)
        self.assertGreaterEqual(res_collapse["fn"], 2, res_collapse)
        self.assertLess(res_collapse["precision"], 0.5)
        self.assertLess(res_collapse["recall"], 0.5)
        self.assertLess(res_collapse["safety"], 1.0)


if __name__ == "__main__":
    unittest.main()

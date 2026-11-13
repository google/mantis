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

"""Phase-1 CL 3 regression tests: deduplication safety, Tier-1 consolidation
location guard, grounded lineage boundaries, report_findings ID/status/identity
sanitization, tool-crash resilience, and resumable completion-stamp guard."""

from __future__ import annotations

import asyncio
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import types as pytypes
import unittest

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from google.genai import types  # noqa: E402

from core.budget import BudgetExceededError  # noqa: E402
from core.config import MantisAuthError  # noqa: E402
from core.consolidator import consolidate_run_findings, synthesize_aggregate_report  # noqa: E402
from core.context import RunContext, current_run_context  # noqa: E402
from core.database import (  # noqa: E402
    init_db,
    merge_findings,
    read_findings,
    record_run,
    update_finding_status_by_id,
    write_findings,
)
import core.graph_loader as gl  # noqa: E402
from core.structural_index import (  # noqa: E402
    _load_parser,
    build_structural_index,
    state_dir_for_db,
)
from tools.research_tools import (  # noqa: E402
    dedupe_findings,
    get_git_diff,
    get_git_log,
    get_plan,
    get_summary,
    get_threat_model,
    list_files,
    read_file,
    report_findings,
    write_file,
)
from tools.structural_tools import (  # noqa: E402
    find_callees,
    find_callers,
    find_symbol,
    get_function_boundary,
)


class TestDedupeLineageAndConsolidation(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_cl3_dedupe_")
        self.repo = Path(self.tmp) / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text(
            "def handle_request(req):\n"
            + "    q1 = 'SELECT * FROM users WHERE id=' + req.id\n"
            + ("    x = 1\n" * 180)
            + "    q2 = 'DELETE FROM audit_logs WHERE tag=' + req.tag\n"
            + "    return q1, q2\n",
            encoding="utf-8",
        )
        (self.repo / "auth.py").write_text("def login(u):\n    return u\n", encoding="utf-8")
        (self.repo / "profile.py").write_text("def bio(b):\n    return b\n", encoding="utf-8")
        self.db = str(Path(self.tmp) / "state" / "knowledge.db")
        Path(self.db).parent.mkdir(parents=True)
        init_db(self.db)
        self.rc = RunContext(
            jail_dir=str(self.repo),
            db_path=self.db,
            target_file=str(self.repo),
            run_id="r_cl3",
            active_node="deduplicator",
        )
        self._tok = current_run_context.set(self.rc)

    async def asyncTearDown(self):
        current_run_context.reset(self._tok)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_merge_findings_refuses_unresolved_or_closed_primary_and_ambiguous_titles(self):
        write_findings(
            self.db,
            str(self.repo),
            [
                {
                    "title": "SQLi in users",
                    "severity": "HIGH",
                    "description": "d1",
                    "filepath": "app.py",
                    "line_numbers": [2],
                },
                {
                    "title": "SQLi in audit_logs",
                    "severity": "HIGH",
                    "description": "d2",
                    "filepath": "app.py",
                    "line_numbers": [183],
                },
            ],
            run_id="r_cl3",
        )
        rows = read_findings(self.db, run_id="r_cl3")
        id1, id2 = int(rows[0]["id"]), int(rows[1]["id"])

        # 1. Paraphrased primary title with primary_id=None must NOT wipe both copies!
        msg_unres = dedupe_findings(
            primary_title="Paraphrased SQL Injection Title",
            primary_id=None,
            duplicate_ids=[id1, id2],
            reason="bad primary",
        )
        self.assertIn("ERROR", msg_unres.upper())
        statuses = [r["status"] for r in read_findings(self.db, run_id="r_cl3")]
        self.assertEqual(statuses, ["reported", "reported"])

        # 2. Closed primary must NOT be promoted to static_confirmed (Step 4 deleted).
        update_finding_status_by_id(self.db, id1, "r_cl3", "false_positive")
        n_closed = merge_findings(
            self.db,
            primary_title="SQLi in users",
            primary_id=id1,
            duplicate_ids=[id2],
            run_id="r_cl3",
        )
        self.assertEqual(n_closed, 0)
        by_id = {int(r["id"]): r["status"] for r in read_findings(self.db, run_id="r_cl3")}
        self.assertEqual(by_id[id1], "false_positive")
        self.assertEqual(by_id[id2], "reported")

        # 3. Ambiguous duplicate_titles matching >1 finding in scope is refused.
        write_findings(
            self.db,
            str(self.repo),
            [
                {
                    "title": "Ambiguous Finding",
                    "severity": "MEDIUM",
                    "description": "in auth",
                    "filepath": "auth.py",
                    "line_numbers": [1],
                },
                {
                    "title": "Ambiguous Finding",
                    "severity": "MEDIUM",
                    "description": "in profile",
                    "filepath": "profile.py",
                    "line_numbers": [1],
                },
            ],
            run_id="r_cl3",
        )
        msg_amb = dedupe_findings(
            primary_title="SQLi in audit_logs",
            primary_id=id2,
            duplicate_titles=["Ambiguous Finding"],
            reason="ambiguous",
        )
        self.assertIn("ERROR", msg_amb.upper())

    async def test_tier1_consolidation_preserves_distant_sinks_in_same_function(self):
        if _load_parser("python") is not None:
            build_structural_index(str(self.repo), state_dir_for_db(self.db))

        write_findings(
            self.db,
            str(self.repo),
            [
                {
                    "title": "SQL injection in user lookup",
                    "severity": "HIGH",
                    "description": "req.id concatenated into SELECT FROM users",
                    "filepath": "app.py",
                    "line_numbers": [2],
                    "cwe": "CWE-89",
                },
                {
                    "title": "SQL injection in audit log deletion",
                    "severity": "HIGH",
                    "description": "req.tag concatenated into DELETE FROM audit_logs",
                    "filepath": "app.py",
                    "line_numbers": [183],
                    "cwe": "CWE-89",
                },
            ],
            run_id="r_cl3",
        )
        stats = await consolidate_run_findings(self.db, "r_cl3")
        self.assertEqual(stats["tier1_merged"], 0)
        surviving = [
            r for r in read_findings(self.db, run_id="r_cl3") if r["status"] != "duplicate_merged"
        ]
        self.assertEqual(len(surviving), 2)

        # Also verify allow_llm=False skips Tier-2 LLM calls cleanly when paused.
        called = False

        async def _should_not_run(_p, _s):
            nonlocal called
            called = True
            raise AssertionError("LLM must not run when allow_llm=False")

        await consolidate_run_findings(
            self.db, "r_cl3", llm_callable=_should_not_run, allow_llm=False
        )
        self.assertFalse(called)
        ok = await synthesize_aggregate_report(
            self.db, "r_cl3", surviving, config={"default_model": "vertex_ai/gemini-3.8-flash"}, allow_llm=False
        )
        self.assertTrue(ok)

    def test_lineage_step2_requires_identifier_boundary_and_target_root(self):
        # Substring 'auth' inside 'authentication' must NOT collide with symbol `auth`.
        write_findings(
            self.db,
            str(self.repo),
            [
                {
                    "title": "Header SQLi in `parse_headers`",
                    "severity": "HIGH",
                    "description": "Reads authentication headers without quoting.",
                    "filepath": "app.py",
                    "line_numbers": [2],
                    "cwe": "CWE-89",
                }
            ],
            run_id="r_sub_1",
        )
        write_findings(
            self.db,
            str(self.repo),
            [
                {
                    "title": "SQL injection in `auth` lookup",
                    "severity": "HIGH",
                    "description": "Unsanitized lookup parameter.",
                    "filepath": "app.py",
                    "line_numbers": [183],
                    "cwe": "CWE-89",
                }
            ],
            run_id="r_sub_2",
        )
        r1 = read_findings(self.db, run_id="r_sub_1")[0]
        r2 = read_findings(self.db, run_id="r_sub_2")[0]
        self.assertNotEqual(r1["lineage_id"], r2["lineage_id"])

        # Cross-repo isolation in shared DB: Repo B must not inherit Repo A's lineage.
        repo_b = Path(self.tmp) / "repo_b"
        repo_b.mkdir()
        (repo_b / "app.py").write_text("def handle_request(r):\n    pass\n", encoding="utf-8")
        record_run(self.db, "r_sub_1", "m", metadata={"target_root": str(self.repo)})
        record_run(self.db, "r_repo_b", "m", metadata={"target_root": str(repo_b)})
        rc_b = RunContext(
            jail_dir=str(repo_b),
            db_path=self.db,
            target_file=str(repo_b),
            run_id="r_repo_b",
        )
        tok_b = current_run_context.set(rc_b)
        try:
            write_findings(
                self.db,
                str(repo_b),
                [
                    {
                        "title": "Header SQLi in `parse_headers`",
                        "severity": "HIGH",
                        "description": "Reads authentication headers without quoting.",
                        "filepath": "app.py",
                        "line_numbers": [2],
                        "cwe": "CWE-89",
                    }
                ],
                run_id="r_repo_b",
            )
        finally:
            current_run_context.reset(tok_b)
        rb = read_findings(self.db, run_id="r_repo_b")[0]
        self.assertNotEqual(rb["lineage_id"], r1["lineage_id"])

    def test_report_findings_blocks_id_overwrite_and_clamps_model_status_and_identity(self):
        self.rc.active_node = "researcher"
        res1 = report_findings(
            {
                "findings": [
                    {
                        "id": 1,
                        "title": "Critical Auth SQLi",
                        "severity": "CRITICAL",
                        "status": "VALID",
                        "signature": "forged_sig_123",
                        "lineage_id": "forged_lineage_123",
                        "filepath": "auth.py",
                        "line_numbers": [1],
                        "description": "Unsanitized user login query",
                    }
                ]
            }
        )
        self.assertIn("SUCCESS", res1)
        first_rows = read_findings(self.db, run_id="r_cl3")
        self.assertEqual(len(first_rows), 1)
        first_id = int(first_rows[0]["id"])
        self.assertEqual(first_rows[0]["status"], "reported")
        self.assertNotEqual(first_rows[0]["signature"], "forged_sig_123")
        self.assertNotEqual(first_rows[0]["lineage_id"], "forged_lineage_123")

        # Second researcher call passing colliding id=first_id on a different file
        # must NOT overwrite auth.py!
        res2 = report_findings(
            {
                "findings": [
                    {
                        "id": first_id,
                        "title": "Profile XSS",
                        "severity": "LOW",
                        "status": "NEEDS_RESEARCH",
                        "filepath": "profile.py",
                        "line_numbers": [1],
                        "description": "Bio rendered unescaped",
                    }
                ]
            }
        )
        self.assertIn("SUCCESS", res2)
        all_rows = read_findings(self.db, run_id="r_cl3")
        self.assertEqual(len(all_rows), 2)
        files = sorted(r["filepath"] for r in all_rows)
        self.assertEqual(files, ["auth.py", "profile.py"])
        self.assertTrue(all(r["status"] == "reported" for r in all_rows))


class TestToolCrashSafetyAndResumableStampGuard(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_cl3_tools_")
        self.repo = Path(self.tmp) / "repo"
        self.repo.mkdir()
        (self.repo / "a.py").write_text("x = 1\n", encoding="utf-8")
        self.db = str(Path(self.tmp) / "k.db")
        init_db(self.db)
        self.rc = RunContext(
            jail_dir=str(self.repo),
            db_path=self.db,
            target_file=str(self.repo),
            run_id="r_tools",
        )
        self._tok = current_run_context.set(self.rc)

    async def asyncTearDown(self):
        current_run_context.reset(self._tok)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_malformed_tool_args_and_corrupt_sqlite_return_errors_without_raising(self):
        # Dict content to workspace JSON serializes cleanly instead of AttributeError on .strip()
        w_dict = await write_file("workspace/notes.json", {"hello": "world"})  # type: ignore[arg-type]
        self.assertIn("SUCCESS", w_dict)

        for bad_coro in (
            write_file(None, "abc"),  # type: ignore[arg-type]
            write_file("workspace/x.txt", None),  # type: ignore[arg-type]
            read_file(None),  # type: ignore[arg-type]
            read_file("a.py", start_line="not_an_int"),  # type: ignore[arg-type]
            list_files(123),  # type: ignore[arg-type]
            get_git_diff(commit_hash=123),  # type: ignore[arg-type]
            get_git_log(max_commits="bad"),  # type: ignore[arg-type]
            get_function_boundary(None, "bad"),  # type: ignore[arg-type]
        ):
            out = await bad_coro
            self.assertIsInstance(out, str)

        for sync_out in (
            find_symbol(None),  # type: ignore[arg-type]
            find_callers(None),  # type: ignore[arg-type]
            find_callees(None),  # type: ignore[arg-type]
        ):
            self.assertIsInstance(sync_out, str)

        # Corrupt SQLite file: get_plan / get_threat_model / get_summary must not raise!
        corrupt_db = str(Path(self.tmp) / "corrupt.db")
        Path(corrupt_db).write_bytes(b"NOT A SQLITE FILE AT ALL")
        self.rc.db_path = corrupt_db
        for fn in (get_plan, get_threat_model, get_summary):
            res = fn()
            self.assertIsInstance(res, str)
            self.assertIn("ERROR", res.upper())

    async def test_agent_on_tool_error_callback_catches_runtime_errors_and_reraises_control_plane(self):
        wf_path = Path(_REF_ROOT) / "workflow.json"
        wf, _ = gl.load_workflow_from_json(str(wf_path), load_local=False)
        researcher = None
        for edge in wf.edges:
            for n in (edge.from_node, edge.to_node):
                ag = getattr(n, "agent", n)
                if getattr(ag, "name", None) == "researcher":
                    researcher = ag
                    break
        self.assertIsNotNone(researcher)
        cb = getattr(researcher, "on_tool_error_callback", None)
        self.assertIsNotNone(cb)

        dummy_tool = pytypes.SimpleNamespace(name="read_file")
        caught = cb(dummy_tool, {}, None, RuntimeError("unexpected boom"))
        self.assertIsInstance(caught, dict)
        self.assertIn("error", caught)

        with self.assertRaises(BudgetExceededError):
            cb(dummy_tool, {}, None, BudgetExceededError("tokens", 10, 1, "r"))
        with self.assertRaises(MantisAuthError):
            cb(dummy_tool, {}, None, MantisAuthError("auth"))

    def test_completion_stamp_skips_aborted_or_dangling_fc_invocation(self):
        write_findings(
            self.db,
            str(self.repo),
            [
                {
                    "title": "Candidate",
                    "severity": "HIGH",
                    "description": "d",
                    "filepath": "a.py",
                    "line_numbers": [1],
                }
            ],
            run_id="r_tools",
        )
        cb = gl._make_completion_stamp_callback("reproducer", "static_confirmed")

        # Simulate ADK ResumeAction.PAUSE / tool-crash session: trailing unanswered FC + error_code event
        fc_ev = pytypes.SimpleNamespace(
            invocation_id="inv_1",
            author="reproducer",
            branch="mantis_vulnerability_pipeline.reproducer",
            error_code=None,
            end_of_agent=False,
            content=types.Content(
                role="model",
                parts=[types.Part(function_call=types.FunctionCall(id="fc1", name="read_file", args={}))],
            ),
        )
        err_ev = pytypes.SimpleNamespace(
            invocation_id="inv_1",
            author="reproducer",
            branch="mantis_vulnerability_pipeline.reproducer",
            error_code="TOOL_ERROR",
            end_of_agent=False,
            content=None,
        )
        fake_inv = pytypes.SimpleNamespace(
            invocation_id="inv_1",
            branch="mantis_vulnerability_pipeline.reproducer",
            agent=pytypes.SimpleNamespace(name="reproducer"),
            session=pytypes.SimpleNamespace(events=[fc_ev, err_ev]),
        )
        fake_cb_ctx = pytypes.SimpleNamespace(_invocation_context=fake_inv)

        cb(callback_context=fake_cb_ctx)
        self.assertEqual(
            read_findings(self.db, run_id="r_tools")[0]["status"],
            "reported",
            "Aborted/dangling-FC invocation must NOT stamp static_confirmed.",
        )

        # ADK emits the end-of-agent marker on Event.actions; a marker that
        # follows an error event must not hide that error.
        eoa_ev = pytypes.SimpleNamespace(
            invocation_id="inv_3",
            author="reproducer",
            branch="mantis_vulnerability_pipeline.reproducer",
            error_code=None,
            actions=pytypes.SimpleNamespace(end_of_agent=True),
            content=None,
        )
        err_then_eoa_inv = pytypes.SimpleNamespace(
            invocation_id="inv_3",
            branch="mantis_vulnerability_pipeline.reproducer",
            agent=pytypes.SimpleNamespace(name="reproducer"),
            session=pytypes.SimpleNamespace(events=[
                pytypes.SimpleNamespace(**{**err_ev.__dict__, "invocation_id": "inv_3"}),
                eoa_ev,
            ]),
        )
        cb(callback_context=pytypes.SimpleNamespace(_invocation_context=err_then_eoa_inv))
        self.assertEqual(
            read_findings(self.db, run_id="r_tools")[0]["status"],
            "reported",
            "An end-of-agent marker after an error event must NOT stamp static_confirmed.",
        )

        # Clean invocation with answered FC stamps normally.
        fr_ev = pytypes.SimpleNamespace(
            invocation_id="inv_2",
            author="reproducer",
            branch="mantis_vulnerability_pipeline.reproducer",
            error_code=None,
            end_of_agent=False,
            content=types.Content(
                role="user",
                parts=[types.Part(function_response=types.FunctionResponse(id="fc1", name="read_file", response={"result": "ok"}))],
            ),
        )
        clean_inv = pytypes.SimpleNamespace(
            invocation_id="inv_2",
            branch="mantis_vulnerability_pipeline.reproducer",
            agent=pytypes.SimpleNamespace(name="reproducer"),
            session=pytypes.SimpleNamespace(events=[
                pytypes.SimpleNamespace(**{**fc_ev.__dict__, "invocation_id": "inv_2"}),
                fr_ev,
            ]),
        )
        cb(callback_context=pytypes.SimpleNamespace(_invocation_context=clean_inv))
        self.assertEqual(read_findings(self.db, run_id="r_tools")[0]["status"], "static_confirmed")


class TestPostRunBudgetWiringAndDuplicateItems(unittest.TestCase):
    def test_post_run_consolidation_and_aggregate_report_receive_budget_kwargs(self):
        import ast
        import main

        class _Ctrl:
            is_paused = False

        ctrl = _Ctrl()
        saved = dict(main._SPEND_REPORT)
        try:
            main._SPEND_REPORT["controller"] = ctrl
            self.assertEqual(
                main._post_run_llm_kwargs(None, paused=False),
                {"budget_controller": ctrl, "allow_llm": True},
            )
            self.assertFalse(main._post_run_llm_kwargs(None, paused=True)["allow_llm"])
            ctrl.is_paused = True
            self.assertFalse(main._post_run_llm_kwargs(None, paused=False)["allow_llm"])
            main._SPEND_REPORT["controller"] = None
            fallback = _Ctrl()
            self.assertIs(main._post_run_llm_kwargs(fallback, paused=False)["budget_controller"], fallback)
        finally:
            main._SPEND_REPORT.clear()
            main._SPEND_REPORT.update(saved)

        # Both post-run LLM call sites in the pipeline tail must forward the kwargs.
        tree = ast.parse(Path(main.__file__).read_text(encoding="utf-8"))
        seen = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) in (
                "consolidate_run_findings",
                "synthesize_aggregate_report",
            ):
                seen[node.func.id] = any(
                    kw.arg is None
                    and isinstance(kw.value, ast.Call)
                    and getattr(kw.value.func, "id", None) == "_post_run_llm_kwargs"
                    for kw in node.keywords
                )
        self.assertEqual(
            seen, {"consolidate_run_findings": True, "synthesize_aggregate_report": True}
        )

    def test_one_duplicate_item_does_not_discard_sibling_findings(self):
        tmp = tempfile.mkdtemp(prefix="mantis_cl3_dup_")
        self.addCleanup(shutil.rmtree, tmp, True)
        repo = Path(tmp) / "repo"
        repo.mkdir()
        (repo / "auth.py").write_text("def login(u):\n    return u\n", encoding="utf-8")
        db = str(Path(tmp) / "k.db")
        init_db(db)
        rc = RunContext(
            jail_dir=str(repo), db_path=db, target_file=str(repo), run_id="r_dup",
            active_node="researcher",
        )
        tok = current_run_context.set(rc)
        self.addCleanup(current_run_context.reset, tok)
        res = report_findings({
            "findings": [
                {"title": "Login SQLi", "severity": "HIGH", "description": "d",
                 "filepath": "auth.py", "line_numbers": [1]},
                {"title": "Stray dup", "severity": "LOW", "description": "x",
                 "filepath": "auth.py", "line_numbers": [2], "status": "DUPLICATE"},
            ]
        })
        self.assertIn("SUCCESS: Saved 1 finding", res)
        self.assertIn("DUPLICATE", res)
        self.assertEqual([r["title"] for r in read_findings(db, run_id="r_dup")], ["Login SQLi"])


if __name__ == "__main__":
    unittest.main()

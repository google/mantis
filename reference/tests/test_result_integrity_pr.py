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

"""Regression tests for default-path result-integrity fixes:

1. Same-named methods on distinct classes (`UserView.get` vs `OrderView.get`)
   and findings quoting the same parameter/sink in different functions keep
   independent signatures, lineages, and statuses.
2. Ungrounded findings do not steal an unrelated finding's lineage from a bare
   prose mention of a function name (`post`, `delete`, `search`).
3. Post-run Tier 1 consolidation never auto-merges line-less findings, distant
   templated findings, or adjacent findings in distinct functions without LLM
   adjudication.
4. ADK `end_of_agent` state events do not clear `pending_node_errors` after a
   stage ends on a model error (`MAX_TOKENS` / `SAFETY`).
5. Reviewer `Fallback:` verdicts increment `reviewer_verdict_fallbacks`;
   invalid-verdict re-asks keep tool calls open during mid-analysis narration;
   and critic bare verdicts do not wipe or promote multiple reviewer-confirmed
   findings when `finding_verdicts` is omitted.
6. Multi-file batch campaigns reject findings missing `filepath` instead of
   silently filing them against `group_targets[0]`.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from google.adk import Runner  # noqa: E402
from google.adk.agents import LlmAgent  # noqa: E402
from google.adk.apps.app import App, ResumabilityConfig  # noqa: E402
from google.adk.models.base_llm import BaseLlm  # noqa: E402
from google.adk.models.lite_llm import LiteLlm  # noqa: E402
from google.adk.models.llm_request import LlmRequest  # noqa: E402
from google.adk.models.llm_response import LlmResponse  # noqa: E402
from google.adk.sessions import InMemorySessionService  # noqa: E402
from google.genai import types  # noqa: E402

from core import config as cfg_mod  # noqa: E402
from core.consolidator import consolidate_run_findings  # noqa: E402
from core.context import RunContext, current_run_context  # noqa: E402
from core.database import init_db, read_findings, update_finding_status_by_id, write_findings  # noqa: E402
import core.graph_loader as gl  # noqa: E402
from core.structural_index import _load_parser, build_structural_index, state_dir_for_db  # noqa: E402
import main as mantis_main  # noqa: E402
from tools.research_tools import report_findings  # noqa: E402

_HAS_PYTHON_GRAMMAR = _load_parser("python") is not None


class _FakeClassifierCtx:
    def __init__(self):
        self.state = {}


class FindingIdentityAndConsolidationIntegrityTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_integrity_")
        self.base = Path(self._tmp.name)
        self.jail = self.base / "jail"
        self.jail.mkdir(parents=True, exist_ok=True)
        self.db = str(self.base / "state" / "knowledge.db")
        Path(self.db).parent.mkdir(parents=True, exist_ok=True)
        init_db(self.db)

    async def asyncTearDown(self):
        self._tmp.cleanup()

    @unittest.skipUnless(_HAS_PYTHON_GRAMMAR, "tree-sitter python grammar unavailable")
    async def test_class_methods_and_shared_backticked_params_keep_distinct_identity(self):
        views_py = self.jail / "app" / "views.py"
        views_py.parent.mkdir(parents=True, exist_ok=True)
        views_py.write_text(
            "class UserView:\n"
            "    def get(self, user_id):\n"
            "        return db.exec('SELECT * FROM users WHERE id=' + user_id)\n"
            "\n"
            "class OrderView:\n"
            "    def get(self, user_id):\n"
            "        return db.exec('SELECT * FROM orders WHERE owner=' + user_id)\n",
            encoding="utf-8",
        )
        manifest = build_structural_index(str(self.jail), state_dir_for_db(self.db))
        self.assertEqual(manifest.get("status"), "complete")

        # 1. UserView.get vs OrderView.get in same file: distinct signatures & lineages,
        # and dismissing UserView.get must NOT suppress OrderView.get on insert or merge!
        write_findings(
            self.db,
            str(self.jail),
            [{
                "title": "SQL injection via `user_id` parameter",
                "description": "Raw SQL query in UserView handler",
                "filepath": "app/views.py",
                "line_numbers": [3],
                "cwe": "CWE-89",
                "severity": "HIGH",
            }],
            run_id="r_cls",
        )
        r1 = read_findings(self.db, run_id="r_cls")[0]
        update_finding_status_by_id(self.db, int(r1["id"]), "r_cls", "false_positive")

        write_findings(
            self.db,
            str(self.jail),
            [{
                "title": "SQL injection via `user_id` parameter",
                "description": "Raw SQL query in OrderView handler",
                "filepath": "app/views.py",
                "line_numbers": [7],
                "cwe": "CWE-89",
                "severity": "HIGH",
            }],
            run_id="r_cls",
        )
        rows = sorted(read_findings(self.db, run_id="r_cls"), key=lambda r: r["id"])
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0]["signature"], rows[1]["signature"])
        self.assertNotEqual(rows[0]["lineage_id"], rows[1]["lineage_id"])
        self.assertEqual(rows[0]["status"], "false_positive")
        self.assertEqual(
            rows[1]["status"],
            "reported",
            "OrderView.get finding must not inherit false_positive from UserView.get!",
        )

        # Promote both in a fresh run and ensure Tier 1 consolidation does NOT merge them
        # even though they sit within 8 lines (lines 3 and 7) with identical templated wording!
        write_findings(
            self.db,
            str(self.jail),
            [
                {
                    "title": "SQL injection via `user_id` parameter",
                    "description": "Raw SQL query in handler",
                    "filepath": "app/views.py",
                    "line_numbers": [3],
                    "cwe": "CWE-89",
                    "status": "confirmed",
                },
                {
                    "title": "SQL injection via `user_id` parameter",
                    "description": "Raw SQL query in handler",
                    "filepath": "app/views.py",
                    "line_numbers": [7],
                    "cwe": "CWE-89",
                    "status": "confirmed",
                },
            ],
            run_id="r_cls_merge",
        )
        stats = await consolidate_run_findings(self.db, "r_cls_merge")
        self.assertEqual(stats["tier1_merged"], 0)
        active = [
            r for r in read_findings(self.db, run_id="r_cls_merge")
            if r["status"] != "duplicate_merged"
        ]
        self.assertEqual(len(active), 2)
        self.assertEqual(mantis_main._count_unique_active_findings(active), 2)

    async def test_prose_mention_does_not_hijack_lineage_and_tier1_refuses_lineless_or_distant_merges(self):
        # Finding 1 mentions `delete` in prose; ungrounded Finding 2 in `delete` must NOT steal its lineage.
        write_findings(
            self.db,
            str(self.jail),
            [{
                "title": "SQLi in `archive_records` before delete cleanup",
                "description": "archive_records interpolates filter string before delete step.",
                "filepath": "app/jobs.py",
                "line_numbers": [12],
                "cwe": "CWE-89",
            }],
            run_id="r_p1",
        )
        write_findings(
            self.db,
            str(self.jail),
            [{
                "title": "SQLi in `delete` endpoint",
                "description": "Unparameterized SQL statement in delete handler.",
                "filepath": "app/jobs.py",
                "line_numbers": [88],
                "cwe": "CWE-89",
            }],
            run_id="r_p2",
        )
        conn = sqlite3.connect(self.db)
        try:
            lins = [
                r[0]
                for r in conn.execute(
                    "SELECT lineage_id FROM findings WHERE filepath = 'app/jobs.py' ORDER BY id"
                ).fetchall()
            ]
        finally:
            conn.close()
        self.assertEqual(len(lins), 2)
        self.assertNotEqual(lins[0], lins[1])

        # Tier 1 must never auto-merge line-less findings or templated findings 60 lines apart.
        write_findings(
            self.db,
            str(self.jail),
            [
                {
                    "title": "SQL injection in search_users query builder",
                    "description": "Unsanitized filter parameter concatenated into SQL query in search_users",
                    "filepath": "app/search.py",
                    "line_numbers": [15],
                    "cwe": "CWE-89",
                    "code_paths": ["app/search.py:15:search_users"],
                },
                {
                    "title": "SQL injection in search_users query builder",
                    "description": "Unsanitized sort parameter concatenated into SQL query in search_users",
                    "filepath": "app/search.py",
                    "line_numbers": [75],
                    "cwe": "CWE-89",
                    "code_paths": ["app/search.py:75:search_users"],
                },
                {
                    "title": "SQL injection in search_users without line numbers",
                    "description": "Unsanitized parameter concatenated into SQL query in search_users",
                    "filepath": "app/search.py",
                    "line_numbers": [],
                    "cwe": "CWE-89",
                },
            ],
            run_id="r_tier1",
        )
        stats = await consolidate_run_findings(self.db, "r_tier1")
        self.assertEqual(stats["tier1_merged"], 0)

    async def test_batch_campaign_rejects_missing_filepath_instead_of_defaulting_to_first_file(self):
        f_a = self.jail / "a.py"
        f_b = self.jail / "b.py"
        f_a.write_text("x = 1\n", encoding="utf-8")
        f_b.write_text("y = 2\n", encoding="utf-8")

        batch_ctx = RunContext(
            jail_dir=str(self.jail),
            db_path=self.db,
            target_file=str(f_a),
            group_targets=(str(f_a), str(f_b)),
            scan_mode="cross-functional",
            run_id="r_batch",
            active_node="researcher",
        )
        tok = current_run_context.set(batch_ctx)
        try:
            res = report_findings({
                "findings": [{
                    "title": "Missing filepath in batch",
                    "description": "Should be rejected rather than filed against a.py",
                    "severity": "HIGH",
                    "cwe": "CWE-79",
                }]
            })
        finally:
            current_run_context.reset(tok)

        self.assertIn("Error", res)
        self.assertIn("filepath", res)
        self.assertEqual(read_findings(self.db, run_id="r_batch"), [])

    def test_lineage_step1_verifies_prose_signature_and_blocks_legacy_method_collision(self):
        """Regression test for r4-lineage-fallback:
        1. Dead guard `if prose_sig: return str(row[0])` used to return a row
           matched via `bare_sig` even when `row.qualified_symbol` conflicted
           AND `row.prose_signature` did not match!
        2. Even against a pre-migration legacy row with empty `qualified_symbol`,
           once `UserView.get` adopts that lineage, `OrderView.get` must NOT
           steal the same lineage through the legacy row!
        """
        from core.database import resolve_ancestor_lineage

        tmp = tempfile.mkdtemp(prefix="mantis_lin_fb_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        db = os.path.join(tmp, "lin.db")
        init_db(db)

        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO findings (run_id, filepath, title, description, severity, status,
                                     signature, prose_signature, lineage_id, target_symbol,
                                     symbol_source, qualified_symbol, line_numbers)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "r1", "views.py", "Missing auth in UserView.get", "desc", "HIGH", "confirmed",
                "bare_get_sig", "prose_user_get", "lin-user-get", "get",
                "", "UserView.get", "[12]",
            ),
        )
        conn.commit()
        lin_order = resolve_ancestor_lineage(
            cur,
            "views.py",
            signature="sig_order_get",
            cwe="CWE-862",
            symbol="get",
            db_path=db,
            bare_signature="bare_get_sig",
            prose_signature="prose_order_get",
            symbol_source="catalog",
            qualified_symbol="OrderView.get",
        )
        self.assertNotEqual(
            lin_order, "lin-user-get",
            "OrderView.get MUST NOT collide onto UserView.get via dead `if prose_sig:` guard!",
        )

        cur.execute(
            """INSERT INTO findings (run_id, filepath, title, description, severity, status,
                                     signature, prose_signature, lineage_id, target_symbol,
                                     symbol_source, qualified_symbol, line_numbers)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "r0", "legacy.py", "Missing auth in get", "desc", "HIGH", "confirmed",
                "legacy_bare_sig", "legacy_prose", "lin-legacy", "get",
                "", "", "[10]",
            ),
        )
        cur.execute(
            """INSERT INTO findings (run_id, filepath, title, description, severity, status,
                                     signature, prose_signature, lineage_id, target_symbol,
                                     symbol_source, qualified_symbol, line_numbers)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "r1", "legacy.py", "Missing auth in UserView.get", "desc", "HIGH", "confirmed",
                "sig_uv_get", "legacy_prose", "lin-legacy", "get",
                "catalog", "UserView.get", "[10]",
            ),
        )
        conn.commit()
        lin_ov = resolve_ancestor_lineage(
            cur,
            "legacy.py",
            signature="sig_ov_get",
            cwe="CWE-862",
            symbol="get",
            db_path=db,
            bare_signature="legacy_bare_sig",
            prose_signature="legacy_prose",
            symbol_source="catalog",
            qualified_symbol="OrderView.get",
        )
        self.assertNotEqual(
            lin_ov, "lin-legacy",
            "OrderView.get MUST NOT join a legacy lineage already claimed by UserView.get!",
        )
        conn.close()

    def test_tier1_consolidation_blocks_transitive_line_chaining(self):
        """Regression test for findings-lifecycle-2:
        Three findings at lines 10, 16, and 22 (each 6 lines from neighbor, but
        10 and 22 are 12 lines apart > 8-line window) MUST NOT transitively chain
        into a single merged bucket under Tier-1 deterministic consolidation.
        """
        from core.consolidator import _tier1_exact_groups

        findings = [
            {
                "id": 1,
                "filepath": "api.py",
                "cwe": "CWE-89",
                "title": "SQL injection in search query builder",
                "description": "Untrusted query parameter concatenated into SQL query in search_items",
                "line_numbers": [10],
                "status": "confirmed",
                "mantis_risk_score": 8.0,
                "qualified_symbol": "search_items",
                "code_paths": ["api.py:10"],
            },
            {
                "id": 2,
                "filepath": "api.py",
                "cwe": "CWE-89",
                "title": "SQL injection in search query builder",
                "description": "Untrusted query parameter concatenated into SQL query in search_items",
                "line_numbers": [16],
                "status": "confirmed",
                "mantis_risk_score": 7.0,
                "qualified_symbol": "search_items",
                "code_paths": ["api.py:16"],
            },
            {
                "id": 3,
                "filepath": "api.py",
                "cwe": "CWE-89",
                "title": "SQL injection in search query builder",
                "description": "Untrusted query parameter concatenated into SQL query in search_items",
                "line_numbers": [22],
                "status": "confirmed",
                "mantis_risk_score": 6.0,
                "qualified_symbol": "search_items",
                "code_paths": ["api.py:22"],
            },
        ]
        groups = _tier1_exact_groups(findings, idx=None)
        self.assertEqual(len(groups), 1)
        primary_id, dup_ids, _reason = groups[0]
        self.assertEqual(primary_id, 1)
        self.assertEqual(dup_ids, [2])
        self.assertNotIn(3, dup_ids, "Line 22 must NOT transitively chain onto line 10!")

        clique = [dict(f) for f in findings]
        clique[1]["line_numbers"] = [14]
        clique[2]["line_numbers"] = [17]
        c_groups = _tier1_exact_groups(clique, idx=None)
        self.assertEqual(len(c_groups), 1)
        self.assertEqual(c_groups[0][0], 1)
        self.assertEqual(sorted(c_groups[0][1]), [2, 3])


class StageAndVerdictIntegrityTest(unittest.IsolatedAsyncioTestCase):
    async def test_resumable_end_of_agent_does_not_clear_stage_model_error(self):
        class _ScriptedModel(BaseLlm):
            calls: int = 0
            fail_always: bool = True

            async def generate_content_async(self, llm_request, stream=False):
                self.calls += 1
                if self.fail_always or self.calls == 1:
                    yield LlmResponse(
                        error_code="MAX_TOKENS",
                        error_message="Output hit MAX_TOKENS",
                        finish_reason=types.FinishReason.MAX_TOKENS,
                    )
                    return
                yield LlmResponse(
                    content=types.Content(role="model", parts=[types.Part.from_text(text="Recovered clean output")]),
                    finish_reason=types.FinishReason.STOP,
                )

        # 1. Stage ending on MAX_TOKENS under ResumabilityConfig(is_resumable=True) MUST return task_failed=True.
        err_model = _ScriptedModel(model="fake-err", fail_always=True)
        err_agent = LlmAgent(name="researcher", model=err_model, instruction="Audit.")
        err_app = App(
            name=mantis_main.APP_NAME,
            root_agent=err_agent,
            resumability_config=ResumabilityConfig(is_resumable=True),
        )
        sess_svc = InMemorySessionService()
        runner = Runner(app=err_app, session_service=sess_svc)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            failed = await mantis_main.execute_sub_task(
                runner, sess_svc, "app.py", "run_eoa_err"
            )
        self.assertTrue(
            failed,
            "Resumable ADK end_of_agent event must NOT clear pending_node_errors after MAX_TOKENS!",
        )

        # 2. A stage that fails on attempt 1 and recovers on attempt 2 clears the pending error and returns False.
        class _RetryOnceModel(BaseLlm):
            calls: int = 0

            async def generate_content_async(self, llm_request, stream=False):
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("transient_first_attempt")
                yield LlmResponse(
                    content=types.Content(role="model", parts=[types.Part.from_text(text="Clean output")]),
                    finish_reason=types.FinishReason.STOP,
                )

        from google.adk.workflow import Edge
        from google.adk.workflow import RetryConfig
        from google.adk.workflow import START
        from google.adk.workflow import Workflow
        from google.adk.workflow import node

        rec_agent = LlmAgent(name="researcher", model=_RetryOnceModel(model="fake-retry"), instruction="Audit.")
        rec_node = node(
            rec_agent,
            name="researcher",
            retry_config=RetryConfig(max_attempts=2, initial_delay=0.01, max_delay=0.05),
        )
        wf = Workflow(
            name="mantis_test_wf",
            edges=[Edge(from_node=START, to_node=rec_node)],
        )
        rec_app = App(
            name=mantis_main.APP_NAME,
            root_agent=wf,
            resumability_config=ResumabilityConfig(is_resumable=True),
        )
        rec_sess = InMemorySessionService()
        rec_runner = Runner(app=rec_app, session_service=rec_sess)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rec_failed = await mantis_main.execute_sub_task(
                rec_runner, rec_sess, "app.py", "run_eoa_rec"
            )
        self.assertFalse(rec_failed, "Recovered stage on attempt 2 must clear pending_node_errors!")

    async def test_mid_analysis_reask_keeps_tools_open_and_critic_refuses_ambiguous_batch_wipeout(self):
        tmp = tempfile.mkdtemp(prefix="mantis_verdict_guard_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        db = os.path.join(tmp, "v.db")
        init_db(db)

        write_findings(
            db,
            tmp,
            [
                {"title": "Bug 1", "filepath": "a.py", "line_numbers": [10], "cwe": "CWE-89", "status": "confirmed"},
                {"title": "Bug 2", "filepath": "b.py", "line_numbers": [20], "cwe": "CWE-78", "status": "confirmed"},
            ],
            run_id="r_crit",
        )
        rows = sorted(read_findings(db, run_id="r_crit"), key=lambda r: r["id"])
        f1, f2 = int(rows[0]["id"]), int(rows[1]["id"])

        rc = RunContext(
            jail_dir=tmp,
            db_path=db,
            target_file=tmp,
            run_id="r_crit",
            promoted_finding_ids={f1, f2},
        )
        tok = current_run_context.set(rc)
        try:
            # 1. Reviewer fallback counter increments specifically for ReviewVerdict / ExtendedReviewVerdict.
            fake_resp = LlmResponse(
                content=types.Content(role="model", parts=[types.Part.from_text(text="Refused")]),
                finish_reason=types.FinishReason.SAFETY,
                error_code="SAFETY",
            )
            with contextlib.redirect_stderr(io.StringIO()):
                cfg_mod.ResilientLiteLlm._sanitize_structured_response(
                    fake_resp, cfg_mod.ExtendedReviewVerdict
                )
            self.assertEqual(rc.reviewer_verdict_fallbacks, 1)

            # 2. Narration turn on ExtendedReviewVerdict re-asks WITHOUT forbidding tool calls,
            #    allowing the model's follow-up tool call to pass through cleanly!
            seen_requests: list[LlmRequest] = []

            async def _fake_upstream(_self, req, stream=False):
                seen_requests.append(req)
                if len(seen_requests) == 1:
                    yield LlmResponse(
                        content=types.Content(
                            role="model",
                            parts=[types.Part.from_text(text="Let me inspect auth.py before deciding.")],
                        ),
                        finish_reason=types.FinishReason.STOP,
                    )
                else:
                    yield LlmResponse(
                        content=types.Content(
                            role="model",
                            parts=[types.Part(function_call=types.FunctionCall(name="read_file", args={"filepath": "a.py"}))],
                        ),
                        finish_reason=types.FinishReason.STOP,
                    )

            llm = cfg_mod.ResilientLiteLlm(model="openai/gpt-test")
            llm._output_schema_override = cfg_mod.ExtendedReviewVerdict
            req = LlmRequest(
                model="openai/gpt-test",
                contents=[types.Content(role="user", parts=[types.Part.from_text(text="Review findings")])],
            )
            with mock.patch.object(LiteLlm, "generate_content_async", _fake_upstream):
                out = [r async for r in llm.generate_content_async(req, stream=False)]

            self.assertEqual(len(seen_requests), 2)
            reask_text = seen_requests[1].contents[-1].parts[0].text
            self.assertNotIn("no tool calls", reask_text)
            self.assertIn("function-calling", reask_text)
            self.assertIsNotNone(out[0].content.parts[0].function_call)

            # 3. Critic bare `non_viable` with >1 reviewer-confirmed findings in scope
            #    must NOT wipe out f1 & f2 and must route to DEFAULT_ROUTE (calibrator).
            crit_cls = gl.create_classifier("critic_classifier", ["viable"])
            with contextlib.redirect_stderr(io.StringIO()):
                ev = await crit_cls._func(
                    _FakeClassifierCtx(),
                    {"route": "non_viable", "reason": "One sink looked guarded"},
                )
            self.assertEqual(ev.actions.route, gl.DEFAULT_ROUTE)
            after = {int(r["id"]): r["status"] for r in read_findings(db, run_id="r_crit")}
            self.assertEqual(after[f1], "confirmed")
            self.assertEqual(after[f2], "confirmed")
        finally:
            current_run_context.reset(tok)

    async def test_streamed_max_tokens_retries_and_keeps_tools_open(self):
        """Regression test for r4-max-tokens-reask:
        1. Streamed `partial=True` chunks followed by `partial=False` `MAX_TOKENS`
           (both bare string AND Python 3.12 `FinishReason` enum!) MUST fire the
           one-shot retry instead of being skipped by `not streamed_content`.
        2. Mid-JSON truncation (`{` + `"route"`) uses concise JSON prompt;
           narration/thinking truncation keeps tool calling open.
        3. Real ADK `Runner` (`StreamingMode.SSE`) drops ephemeral `partial=True`
           chunks and persists only the clean retried verdict.
        4. `FinishReason.SAFETY` enum MUST NOT trigger retry and still synthesizes
           fail-closed `Fallback:` JSON (`route == "false_positive"`).
        """
        from google.adk.agents.run_config import RunConfig, StreamingMode

        # Case A: Streamed mid-JSON truncation with real FinishReason.MAX_TOKENS enum
        seen_a: list[LlmRequest] = []
        streams_a: list[bool] = []

        async def _fake_stream_json(_self, req, stream=False):
            seen_a.append(req)
            streams_a.append(bool(stream))
            if len(seen_a) == 1:
                yield LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[types.Part.from_text(text='{"route": "confirmed", "reason": "verbose...')],
                    ),
                    partial=True,
                )
                yield LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[types.Part.from_text(text='{"route": "confirmed", "reason": "verbose...')],
                    ),
                    partial=False,
                    finish_reason=types.FinishReason.MAX_TOKENS,
                    error_code=types.FinishReason.MAX_TOKENS,
                )
            else:
                yield LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[types.Part.from_text(text='{"route": "confirmed", "reason": "Brief valid SQLi."}')],
                    ),
                    partial=False,
                    finish_reason=types.FinishReason.STOP,
                )

        llm_a = cfg_mod.ResilientLiteLlm(model="openai/gpt-test")
        llm_a._output_schema_override = cfg_mod.ExtendedReviewVerdict
        req_a = LlmRequest(
            model="openai/gpt-test",
            contents=[types.Content(role="user", parts=[types.Part.from_text(text="Review findings")])],
        )
        with mock.patch.object(LiteLlm, "generate_content_async", _fake_stream_json):
            out_a = [r async for r in llm_a.generate_content_async(req_a, stream=True)]

        self.assertEqual(len(seen_a), 2, "Streamed MAX_TOKENS must retry once!")
        self.assertEqual(streams_a, [True, False])
        reask_a = seen_a[1].contents[-1].parts[0].text
        self.assertIn("output token limit", reask_a)
        self.assertIn("Emit a concise ExtendedReviewVerdict JSON", reask_a)
        finals_a = [r for r in out_a if not getattr(r, "partial", False)]
        self.assertEqual(len(finals_a), 1)
        parsed_a = json.loads(finals_a[0].content.parts[0].text)
        self.assertEqual(parsed_a["route"], "confirmed")

        # Case B: Streamed narration truncation (no JSON started) keeps tool calls open
        seen_b: list[LlmRequest] = []

        async def _fake_stream_narration(_self, req, stream=False):
            seen_b.append(req)
            if len(seen_b) == 1:
                yield LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[types.Part.from_text(text="Let me trace every middleware file in detail...")],
                    ),
                    partial=True,
                )
                yield LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[types.Part.from_text(text="Let me trace every middleware file in detail...")],
                    ),
                    partial=False,
                    finish_reason=types.FinishReason.MAX_TOKENS,
                    error_code=None,
                )
            else:
                yield LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[
                            types.Part(
                                function_call=types.FunctionCall(
                                    name="read_file", args={"filepath": "auth.py"}
                                )
                            )
                        ],
                    ),
                    partial=False,
                    finish_reason=types.FinishReason.STOP,
                )

        llm_b = cfg_mod.ResilientLiteLlm(model="openai/gpt-test")
        llm_b._output_schema_override = cfg_mod.ExtendedReviewVerdict
        with mock.patch.object(LiteLlm, "generate_content_async", _fake_stream_narration):
            out_b = [r async for r in llm_b.generate_content_async(req_a, stream=True)]

        self.assertEqual(len(seen_b), 2)
        reask_b = seen_b[1].contents[-1].parts[0].text
        self.assertIn("function-calling interface", reask_b)
        finals_b = [r for r in out_b if not getattr(r, "partial", False)]
        self.assertEqual(len(finals_b), 1)
        self.assertEqual(finals_b[0].content.parts[0].function_call.name, "read_file")

        # Case C: Real ADK Runner with StreamingMode.SSE drops partial truncation and saves clean retry
        seen_c: list[int] = []

        async def _fake_runner_stream(_self, req, stream=False):
            seen_c.append(1)
            if len(seen_c) == 1:
                yield LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[types.Part.from_text(text='{"route": "conf')],
                    ),
                    partial=True,
                )
                yield LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[types.Part.from_text(text='{"route": "conf')],
                    ),
                    partial=False,
                    finish_reason=types.FinishReason.MAX_TOKENS,
                    error_code=types.FinishReason.MAX_TOKENS,
                )
            else:
                yield LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[types.Part.from_text(text='{"route": "confirmed", "reason": "Clean retry."}')],
                    ),
                    partial=False,
                    finish_reason=types.FinishReason.STOP,
                )

        llm_c = cfg_mod.ResilientLiteLlm(
            model="openai/gpt-test",
            output_schema_override=cfg_mod.ExtendedReviewVerdict,
        )
        rev_ag = LlmAgent(name="reviewer", model=llm_c, instruction="Review.")
        app_c = App(name="mantis_stream_test", root_agent=rev_ag)
        sess_svc = InMemorySessionService()
        await sess_svc.create_session(app_name="mantis_stream_test", user_id="u", session_id="s1")
        runner = Runner(app=app_c, session_service=sess_svc)
        with mock.patch.object(LiteLlm, "generate_content_async", _fake_runner_stream):
            async for _ev in runner.run_async(
                user_id="u",
                session_id="s1",
                new_message=types.Content(role="user", parts=[types.Part.from_text(text="Go")]),
                run_config=RunConfig(streaming_mode=StreamingMode.SSE),
            ):
                pass
        saved_sess = await sess_svc.get_session(app_name="mantis_stream_test", user_id="u", session_id="s1")
        model_events = [e for e in saved_sess.events if getattr(e, "author", "") == "reviewer" and not getattr(e, "partial", False)]
        self.assertEqual(len(model_events), 1)
        self.assertEqual(json.loads(model_events[0].content.parts[0].text)["route"], "confirmed")

        # Case D: FinishReason.SAFETY enum MUST NOT trigger retry
        seen_d: list[int] = []

        async def _fake_safety(_self, req, stream=False):
            seen_d.append(1)
            yield LlmResponse(
                content=types.Content(role="model", parts=[types.Part.from_text(text="Blocked")]),
                partial=False,
                finish_reason=types.FinishReason.SAFETY,
                error_code=types.FinishReason.SAFETY,
            )

        llm_d = cfg_mod.ResilientLiteLlm(model="openai/gpt-test")
        llm_d._output_schema_override = cfg_mod.ExtendedReviewVerdict
        with mock.patch.object(LiteLlm, "generate_content_async", _fake_safety), contextlib.redirect_stderr(io.StringIO()):
            out_d = [r async for r in llm_d.generate_content_async(req_a, stream=False)]
        self.assertEqual(len(seen_d), 1, "SAFETY enum must NOT trigger schema retry")
        parsed_d = json.loads(out_d[0].content.parts[0].text)
        self.assertEqual(parsed_d["route"], "false_positive")
        self.assertTrue(parsed_d["reason"].startswith("Fallback:"))

    def test_reviewer_fallback_persistence_and_attempt_isolation(self):
        """Regression test for r4-reviewer-fallback-not-persisted:
        - `_sanitize_structured_response` persists a durable `reviewer_fallback`
          artifact keyed by `(resource, pass_index, attempt)`.
        - `_rehydrate_campaign_resume_state` restores it into a fresh `RunContext`.
        - `_rehydrate_session_metrics` also recovers it from ADK session events
          even without the SQLite artifact, without double-counting when both exist.
        - Attempt 1's artifact does NOT bleed into Attempt 2 after Attempt 1 fails.
        - Parallel campaigns do NOT cross-contaminate each other's fallback counts.
        """
        from types import SimpleNamespace
        from core.cost import fallback_attempt_count, record_spend

        tmp = tempfile.mkdtemp(prefix="mantis_fb_persist_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        db = os.path.join(tmp, "fb.db")
        init_db(db)
        target_a = os.path.join(tmp, "a.py")
        target_b = os.path.join(tmp, "b.py")
        Path(target_a).write_text("x = 1\n", encoding="utf-8")
        Path(target_b).write_text("y = 2\n", encoding="utf-8")

        rc_a = RunContext(
            jail_dir=tmp,
            db_path=db,
            target_file=target_a,
            run_id="run_fb_iso",
            pass_index=1,
            fallback_attempt=1,
        )
        tok = current_run_context.set(rc_a)
        try:
            resp = LlmResponse(
                content=types.Content(role="model", parts=[types.Part.from_text(text="Blocked")]),
                finish_reason=types.FinishReason.SAFETY,
                error_code=types.FinishReason.SAFETY,
            )
            with contextlib.redirect_stderr(io.StringIO()):
                cfg_mod.ResilientLiteLlm._sanitize_structured_response(resp, cfg_mod.ExtendedReviewVerdict)
        finally:
            current_run_context.reset(tok)
        self.assertEqual(rc_a.reviewer_verdict_fallbacks, 1)

        # Fresh RunContext simulating process restart for campaign A, attempt 1
        fresh_a = RunContext(
            jail_dir=tmp,
            db_path=db,
            target_file=target_a,
            run_id="run_fb_iso",
            pass_index=1,
            fallback_attempt=1,
        )
        mantis_main._rehydrate_campaign_resume_state(fresh_a, db, "run_fb_iso", target_a, pass_idx=1)
        self.assertEqual(fresh_a.reviewer_verdict_fallbacks, 1)

        # Parallel sibling campaign B has zero fallbacks (no cross-contamination)
        fresh_b = RunContext(
            jail_dir=tmp,
            db_path=db,
            target_file=target_b,
            run_id="run_fb_iso",
            pass_index=1,
            fallback_attempt=1,
        )
        mantis_main._rehydrate_campaign_resume_state(fresh_b, db, "run_fb_iso", target_b, pass_idx=1)
        self.assertEqual(fresh_b.reviewer_verdict_fallbacks, 0)

        # Session event rehydration catches Fallback: reviewer event independently
        # and does NOT double-count when artifact already restored count=1.
        fake_events = [
            SimpleNamespace(
                author="reviewer_classifier",
                partial=False,
                node_info=None,
                usage_metadata=None,
                error_code=None,
                actions=SimpleNamespace(end_of_agent=False),
                content=types.Content(
                    role="model",
                    parts=[types.Part.from_text(text='{"route": "false_positive", "reason": "Fallback: ignored"}')],
                ),
            ),
            SimpleNamespace(
                author="reviewer",
                partial=False,
                node_info=None,
                usage_metadata=None,
                error_code=None,
                actions=SimpleNamespace(end_of_agent=False),
                content=types.Content(
                    role="model",
                    parts=[types.Part.from_text(text='{"route": "false_positive", "reason": "Fallback: SAFETY"}')],
                ),
            ),
        ]
        fake_sess = SimpleNamespace(events=fake_events, state={})
        fake_runner = SimpleNamespace(agent=SimpleNamespace(name="mantis_vulnerability_pipeline"))
        mantis_main._rehydrate_session_metrics(fake_sess, fake_runner, run_ctx=fresh_a)
        self.assertEqual(fresh_a.reviewer_verdict_fallbacks, 1, "Must not double-count artifact + session event")

        session_only_ctx = RunContext(jail_dir=tmp, db_path="", target_file=target_a, run_id="run_fb_iso")
        mantis_main._rehydrate_session_metrics(fake_sess, fake_runner, run_ctx=session_only_ctx)
        self.assertEqual(session_only_ctx.reviewer_verdict_fallbacks, 1)

        # After Attempt 1 records failure in campaign_spend, Attempt 2 starts clean (0 fallbacks)
        record_spend(
            db, "run_fb_iso", target_a, "whole", tokens=100,
            metadata={"failed": True, "reviewer_fallback": True, "fallback_attempts": 1},
        )
        self.assertEqual(fallback_attempt_count(db, "run_fb_iso", target_a), 1)
        attempt2_ctx = RunContext(
            jail_dir=tmp,
            db_path=db,
            target_file=target_a,
            run_id="run_fb_iso",
            pass_index=1,
            fallback_attempt=2,
        )
        mantis_main._rehydrate_campaign_resume_state(attempt2_ctx, db, "run_fb_iso", target_a, pass_idx=1)
        self.assertEqual(attempt2_ctx.reviewer_verdict_fallbacks, 0)

    def test_pipeline_pause_resume_reviewer_fallback_cap_and_sarif_properties(self):
        """End-to-end test in `main.pipeline` covering:
        1. Mid-campaign pause after reviewer fallback -> `--resume` rehydrates
           durable fallback signal, fails Attempt 1 (exit 1, zero coverage),
           labels summary `(unreviewed: reviewer fallback)`, and stamps accurate
           SARIF `runs[0].properties`.
        2. Recurring fallback on Attempt 2 (`--resume`) hits the retry cap (`2`),
           settles into terminal `review_incomplete` (`failed=False`,
           `unexamined=True`, `terminal_reviewer_fallback=True`), withholds
           coverage, keeps findings as `reported`, does NOT finalize run, and
           exits `1`.
        3. Subsequent `--resume` (Attempt 3) does NOT restart an infinite loop
           (0 `execute_sub_task` calls) and still exits `1`.
        4. Explicit `--resume --retry-unexamined` retries, succeeds when reviewer
           confirms the finding, clears `terminal_campaigns`, exports the finding
           to SARIF `results`, and exits `0`.
        """
        from core.budget import BudgetExceededError
        from core.cost import run_ledger, run_reviewer_fallback_summary
        from core.database import update_status

        tmp = tempfile.mkdtemp(prefix="mantis_fb_e2e_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        repo = os.path.realpath(os.path.join(tmp, "repo"))
        os.makedirs(repo)
        target_file = os.path.join(repo, "app.py")
        Path(target_file).write_text("def vuln(x):\n    return eval(x)\n", encoding="utf-8")
        db = os.path.join(tmp, "mantis.db")
        sarif_path = os.path.join(tmp, "out.sarif")
        wf_data = json.loads((_REF_ROOT / "workflow.json").read_text(encoding="utf-8"))
        wf_data.setdefault("config", {})["sarif_output"] = sarif_path
        wf_path = os.path.join(tmp, "wf.json")
        Path(wf_path).write_text(json.dumps(wf_data), encoding="utf-8")
        env = {
            "GOOGLE_CLOUD_PROJECT": "ci-offline-project",
            "LITELLM_LOCAL_MODEL_COST_MAP": "True",
            "LITELLM_MODE": "PRODUCTION",
            "OPENAI_API_KEY": "test-key",
            "MANTIS_MAX_REVIEWER_FALLBACK_ATTEMPTS": "2",
        }
        captured_run_id: list[str] = []

        def _trigger_reviewer_fallback():
            resp = LlmResponse(
                content=types.Content(role="model", parts=[types.Part.from_text(text="Safety refusal")]),
                finish_reason=types.FinishReason.SAFETY,
                error_code=types.FinishReason.SAFETY,
            )
            cfg_mod.ResilientLiteLlm._sanitize_structured_response(resp, cfg_mod.ExtendedReviewVerdict)

        # Slice 1a: writes candidate finding, reviewer emits fallback (persisted!), then budget pauses.
        async def _slice_pause(_runner, _ss, filepath, rid, **kw):
            captured_run_id.append(rid)
            write_findings(
                db,
                filepath,
                [
                    {
                        "title": "Code Injection via eval",
                        "filepath": "app.py",
                        "line_numbers": [2],
                        "cwe": "CWE-95",
                        "severity": "High",
                        "description": "eval executes user input",
                        "status": "reported",
                    }
                ],
                run_id=rid,
            )
            kw["budget_controller"].audit_code_reads += 1
            _trigger_reviewer_fallback()
            raise BudgetExceededError("max_tokens", 1000, 1000, rid)

        with mock.patch.dict(os.environ, env, clear=False), \
             mock.patch.object(mantis_main, "execute_sub_task", side_effect=_slice_pause), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            rc_pause = asyncio.run(
                mantis_main.pipeline(
                    scan_target=target_file,
                    workflow_path=wf_path,
                    load_local=False,
                    db_override=db,
                    model_override="openai/nonexistent",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    auto_configure=False,
                    scan_mode_override="whole",
                    assume_yes=True,
                )
            )
        self.assertEqual(rc_pause, 2, "Paused run must exit 2")
        run_id = captured_run_id[0]

        # Slice 1b (`--resume`): finishes cleanly WITHOUT emitting another fallback.
        # Durable artifact MUST restore reviewer_verdict_fallbacks=1 so Attempt 1 fails (exit 1)!
        async def _slice_finish_clean(_runner, _ss, filepath, rid, **kw):
            kw["budget_controller"].audit_code_reads += 1
            return False

        out1, err1 = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=False), \
             mock.patch.object(mantis_main, "execute_sub_task", side_effect=_slice_finish_clean), \
             contextlib.redirect_stdout(out1), \
             contextlib.redirect_stderr(err1):
            rc1 = asyncio.run(
                mantis_main.pipeline(
                    scan_target=target_file,
                    workflow_path=wf_path,
                    load_local=False,
                    db_override=db,
                    model_override="openai/nonexistent",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    auto_configure=False,
                    resume_run_id=run_id,
                    assume_yes=True,
                )
            )
        self.assertEqual(rc1, 1, f"Resumed post-fallback campaign MUST exit 1!\nstdout:\n{out1.getvalue()}\nstderr:\n{err1.getvalue()}")
        self.assertIn("(unreviewed: reviewer fallback)", out1.getvalue())
        self.assertNotIn("(suppressed at review)", out1.getvalue())
        self.assertIn("attempt 1/2", err1.getvalue())
        ledger1 = run_ledger(db, run_id)
        row1 = next(iter(ledger1.values()))
        self.assertTrue(row1.get("failed"))
        self.assertTrue(row1.get("reviewer_fallback"))
        self.assertEqual(row1.get("fallback_attempts"), 1)
        sarif1 = json.loads(Path(sarif_path).read_text(encoding="utf-8"))
        self.assertEqual(sarif1["runs"][0]["results"], [])
        props1 = sarif1["runs"][0]["properties"]
        self.assertEqual(props1["untriaged_omitted"], 1)
        self.assertEqual(props1["reviewer_fallback_count"], 1)
        self.assertEqual(props1["unreviewed_reviewer_fallback_findings"], 1)
        self.assertEqual(props1["review_incomplete_campaigns"], 0)

        # Verify zero coverage_files recorded on failure
        conn = sqlite3.connect(db)
        cov_tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        cov_count1 = conn.execute("SELECT COUNT(*) FROM coverage_files").fetchone()[0] if "coverage_files" in cov_tables else 0
        conn.close()
        self.assertEqual(cov_count1, 0)

        # Slice 2 (`--resume` Attempt 2): reviewer falls back AGAIN -> hits cap (2/2)!
        async def _slice_fallback_again(_runner, _ss, filepath, rid, **kw):
            kw["budget_controller"].audit_code_reads += 1
            _trigger_reviewer_fallback()
            return False

        out2, err2 = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=False), \
             mock.patch.object(mantis_main, "execute_sub_task", side_effect=_slice_fallback_again), \
             contextlib.redirect_stdout(out2), \
             contextlib.redirect_stderr(err2):
            rc2 = asyncio.run(
                mantis_main.pipeline(
                    scan_target=target_file,
                    workflow_path=wf_path,
                    load_local=False,
                    db_override=db,
                    model_override="openai/nonexistent",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    auto_configure=False,
                    resume_run_id=run_id,
                    assume_yes=True,
                )
            )
        self.assertEqual(rc2, 1, f"Terminal review-incomplete run must exit 1!\n{out2.getvalue()}\n{err2.getvalue()}")
        self.assertIn("retry cap reached", err2.getvalue())
        self.assertIn("(unreviewed: reviewer fallback)", out2.getvalue())
        ledger2 = run_ledger(db, run_id)
        row2 = next(iter(ledger2.values()))
        self.assertFalse(row2.get("failed"), "Terminal fallback settles as failed=False to stop infinite retry")
        self.assertTrue(row2.get("unexamined"), "Terminal fallback withholds coverage credit")
        self.assertTrue(row2.get("terminal_reviewer_fallback"))
        self.assertTrue(row2.get("review_incomplete"))
        self.assertEqual(row2.get("fallback_attempts"), 2)
        sarif2 = json.loads(Path(sarif_path).read_text(encoding="utf-8"))
        self.assertEqual(sarif2["runs"][0]["properties"]["review_incomplete_campaigns"], 1)
        self.assertEqual(sarif2["runs"][0]["properties"]["reviewer_fallback_count"], 2)
        # Finding stays "reported" (preserving DB/MCP/SARIF status vocabulary)
        f_rows = read_findings(db, run_id=run_id)
        self.assertEqual(len(f_rows), 1)
        self.assertEqual(f_rows[0]["status"], "reported")
        # Still zero coverage credit recorded and run is NOT finalized
        conn = sqlite3.connect(db)
        cov_count2 = conn.execute("SELECT COUNT(*) FROM coverage_files").fetchone()[0] if "coverage_files" in cov_tables else 0
        run_meta_row = conn.execute("SELECT metadata_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        conn.close()
        self.assertEqual(cov_count2, 0)
        if run_meta_row is not None and run_meta_row[0]:
            self.assertFalse(bool(json.loads(run_meta_row[0]).get("finalized")), "Incomplete review run must not be marked finalized")

        # Slice 3 (`--resume` Attempt 3): MUST NOT restart campaign; exits 1 with notice
        calls_3: list[str] = []

        async def _should_not_run(_runner, _ss, filepath, rid, **kw):
            calls_3.append(filepath)
            return False

        out3, err3 = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=False), \
             mock.patch.object(mantis_main, "execute_sub_task", side_effect=_should_not_run), \
             contextlib.redirect_stdout(out3), \
             contextlib.redirect_stderr(err3):
            rc3 = asyncio.run(
                mantis_main.pipeline(
                    scan_target=target_file,
                    workflow_path=wf_path,
                    load_local=False,
                    db_override=db,
                    model_override="openai/nonexistent",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    auto_configure=False,
                    resume_run_id=run_id,
                    assume_yes=True,
                )
            )
        self.assertEqual(calls_3, [], "Retry-capped campaign must NOT loop infinitely on --resume!")
        self.assertEqual(rc3, 1)
        self.assertIn("incomplete review", out3.getvalue())

        # Slice 4 (`--resume --retry-unexamined`): operator-forced retry succeeds!
        async def _slice_recover(_runner, _ss, filepath, rid, **kw):
            kw["budget_controller"].audit_code_reads += 1
            update_status(db, filepath, rid, "confirmed", campaign=filepath)
            return False

        out4, err4 = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=False), \
             mock.patch.object(mantis_main, "execute_sub_task", side_effect=_slice_recover), \
             contextlib.redirect_stdout(out4), \
             contextlib.redirect_stderr(err4):
            rc4 = asyncio.run(
                mantis_main.pipeline(
                    scan_target=target_file,
                    workflow_path=wf_path,
                    load_local=False,
                    db_override=db,
                    model_override="openai/nonexistent",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    auto_configure=False,
                    resume_run_id=run_id,
                    retry_unexamined=True,
                    assume_yes=True,
                )
            )
        self.assertEqual(rc4, 0, f"Recovered run must exit 0!\n{out4.getvalue()}\n{err4.getvalue()}")
        summary4 = run_reviewer_fallback_summary(db, run_id)
        self.assertEqual(summary4["terminal_campaigns"], 0)
        self.assertEqual(summary4["active_targets"], [])
        sarif4 = json.loads(Path(sarif_path).read_text(encoding="utf-8"))
        self.assertEqual(len(sarif4["runs"][0]["results"]), 1)
        self.assertEqual(sarif4["runs"][0]["properties"]["review_incomplete_campaigns"], 0)


if __name__ == "__main__":
    unittest.main()

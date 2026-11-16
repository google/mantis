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


if __name__ == "__main__":
    unittest.main()

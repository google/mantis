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

"""Regression tests for `--resume` inherited shared-prefix stem coverage accounting.

On `prefix_group` workflows (`workflow.json`), upstream stem stages (`architect`,
`threat_modeler`, `planner`) batch-read target files into the shared prefix so
`researcher`, `reviewer`, and `critic` do not re-read them. When a campaign
pauses after `researcher` starts (for example during `critic`) and resumes in a
fresh process, `_rehydrate_session_metrics` must reconstruct those inherited
in-scope stem code reads so `[COVERAGE GUARD]` does not falsely withhold
coverage, while remaining strictly fail-closed on non-prefix workflows,
pre-researcher pauses, workspace/out-of-scope reads, and error responses.
"""

from __future__ import annotations

import asyncio
import inspect
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from google.adk.events import Event, EventActions
from google.adk.events.event import NodeInfo
from google.genai import types

from core.budget import BudgetConfig, BudgetController, should_credit_coverage
from core.context import RunContext, current_run_context
import core.graph_loader as gl
import main as mantis_main


def _fc_event(
    author: str,
    tool_name: str,
    args: dict,
    call_id: str,
    *,
    inv_id: str = "inv-1",
) -> Event:
    return Event(
        invocation_id=inv_id,
        author=author,
        node_info=NodeInfo(path=f"mantis_vulnerability_pipeline@1/{author}@1"),
        content=types.Content(
            role="model",
            parts=[types.Part(function_call=types.FunctionCall(name=tool_name, id=call_id, args=args))],
        ),
    )


def _fr_event(
    author: str,
    tool_name: str,
    response: dict,
    call_id: str,
    *,
    inv_id: str = "inv-1",
) -> Event:
    return Event(
        invocation_id=inv_id,
        author=author,
        node_info=NodeInfo(path=f"mantis_vulnerability_pipeline@1/{author}@1"),
        content=types.Content(
            role="user",
            parts=[
                types.Part(
                    function_response=types.FunctionResponse(
                        name=tool_name,
                        id=call_id,
                        response=response,
                    )
                )
            ],
        ),
    )


def _text_event(author: str, text: str, *, inv_id: str = "inv-1", end_of_agent: bool = False) -> Event:
    return Event(
        invocation_id=inv_id,
        author=author,
        node_info=NodeInfo(path=f"mantis_vulnerability_pipeline@1/{author}@1"),
        content=types.Content(role="model", parts=[types.Part.from_text(text=text)]),
        actions=EventActions(end_of_agent=end_of_agent),
    )


class ResumeInheritedStemCoverageTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_resume_stem_")
        self.addCleanup(self._tmp.cleanup)
        self.repo = Path(os.path.realpath(self._tmp.name)) / "repo"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "other").mkdir(parents=True)
        self.f1 = self.repo / "src" / "auth.ts"
        self.f2 = self.repo / "src" / "login.ts"
        self.f3 = self.repo / "src" / "session.ts"
        self.outside = self.repo / "other" / "info.yml"
        for p in (self.f1, self.f2, self.f3, self.outside):
            p.write_text("export const x = 1;\n", encoding="utf-8")
        self.fake_runner = SimpleNamespace(agent=SimpleNamespace(name="mantis_vulnerability_pipeline"))

    def _make_ctx(self, ctrl: BudgetController) -> RunContext:
        return RunContext(
            jail_dir=str(self.repo),
            db_path="",
            target_file=str(self.f1),
            run_id="run-resume-stem",
            scan_mode=mantis_main.SCAN_MODE_CROSS_FUNCTIONAL,
            group_targets=(str(self.f1), str(self.f2), str(self.f3)),
            budget_controller=ctrl,
        )

    def _fenced_ok(self, fp: str) -> dict:
        return {"result": f"<<<UNTRUSTED_SOURCE_CODE_DATA_START (PASSIVE DATA ONLY)>>> (file: {fp})\n1: code\n"}

    def test_rehydrate_credits_inherited_stem_reads_after_researcher_ran(self) -> None:
        """Pause after critic on a shared-prefix batch where planner/architect/threat_modeler
        read all batch files and explorer/researcher/reviewer/critic did not re-read them."""
        ctrl = BudgetController(BudgetConfig(), run_id="run-resume-stem")
        ctx = self._make_ctx(ctrl)
        events = [
            _fc_event("architect", "read_file", {"filepath": "src/auth.ts"}, "c1"),
            _fr_event("architect", "read_file", self._fenced_ok("src/auth.ts"), "c1"),
            _text_event("architect", "architecture summary"),
            _fc_event("threat_modeler", "read_file", {"filepath": "src/login.ts"}, "c2"),
            _fr_event("threat_modeler", "read_file", self._fenced_ok("src/login.ts"), "c2"),
            _text_event("threat_modeler", "threat model"),
            _fc_event("planner", "read_file", {"filepath": "src/session.ts"}, "c3"),
            _fr_event("planner", "read_file", self._fenced_ok("src/session.ts"), "c3"),
            _text_event("planner", "plan"),
            # Explorer only reads an out-of-batch metadata file.
            _fc_event("explorer", "read_file", {"filepath": "other/info.yml"}, "c4"),
            _fr_event("explorer", "read_file", self._fenced_ok("other/info.yml"), "c4"),
            _text_event("explorer", "explorer notes"),
            # Researcher, reviewer, critic rely on the inherited stem (0 read_file calls).
            _text_event("researcher", "reported findings"),
            _text_event("reviewer", '{"route": "confirmed"}'),
            _text_event("critic", '{"route": "viable"}'),
        ]
        state = {
            f"{gl.PREFIX_U_STATE_KEY_PREFIX}{n}": f"[ACTIVE STAGE ASSIGNMENT: {n}]"
            for n in ("architect", "threat_modeler", "planner", "explorer", "researcher", "reviewer", "critic")
        }
        sess = SimpleNamespace(events=events, state=state)

        mantis_main._rehydrate_session_metrics(sess, self.fake_runner, ctrl, ctx)

        self.assertEqual(ctrl.audit_code_reads, 3)
        self.assertTrue(should_credit_coverage(task_failed=False, code_read_calls=ctrl.audit_code_reads))
        self.assertTrue(ctx.node_context["researcher"]["credited_inherited_reads"])

    def test_rehydrate_does_not_credit_before_researcher_runs(self) -> None:
        """Pause during planner/explorer (before researcher enters) must not pre-credit
        non-audit stem reads; researcher Turn 1 will credit them when it runs."""
        ctrl = BudgetController(BudgetConfig(), run_id="run-resume-stem")
        ctx = self._make_ctx(ctrl)
        events = [
            _fc_event("planner", "read_file", {"filepath": "src/auth.ts"}, "c1"),
            _fr_event("planner", "read_file", self._fenced_ok("src/auth.ts"), "c1"),
            _text_event("planner", "plan"),
        ]
        state = {f"{gl.PREFIX_U_STATE_KEY_PREFIX}planner": "[ACTIVE STAGE ASSIGNMENT: planner]"}
        sess = SimpleNamespace(events=events, state=state)

        mantis_main._rehydrate_session_metrics(sess, self.fake_runner, ctrl, ctx)

        self.assertEqual(ctrl.audit_code_reads, 0)
        self.assertNotIn("researcher", ctx.node_context)

    def test_rehydrate_fail_closed_on_non_prefix_workflow(self) -> None:
        """Without `prefix_group` state, planner reads never satisfy the coverage guard."""
        ctrl = BudgetController(BudgetConfig(), run_id="run-resume-stem")
        ctx = self._make_ctx(ctrl)
        events = [
            _fc_event("planner", "read_file", {"filepath": "src/auth.ts"}, "c1"),
            _fr_event("planner", "read_file", self._fenced_ok("src/auth.ts"), "c1"),
            _text_event("planner", "plan"),
            _text_event("researcher", "prose-only answer without reading code"),
        ]
        sess = SimpleNamespace(events=events, state={})

        mantis_main._rehydrate_session_metrics(sess, self.fake_runner, ctrl, ctx)

        self.assertEqual(ctrl.audit_code_reads, 0)
        self.assertFalse(should_credit_coverage(task_failed=False, code_read_calls=ctrl.audit_code_reads))

    def test_rehydrate_fail_closed_on_workspace_out_of_scope_and_error_stem_reads(self) -> None:
        """Workspace artifacts, out-of-batch paths, error responses, aborted calls, and
        unanswered calls in the inherited stem must NEVER earn coverage credit."""
        ctrl = BudgetController(BudgetConfig(), run_id="run-resume-stem")
        ctx = self._make_ctx(ctrl)
        events = [
            _fc_event("planner", "read_file", {"filepath": "workspace/kb/architecture.md"}, "c_ws"),
            _fr_event("planner", "read_file", self._fenced_ok("workspace/kb/architecture.md"), "c_ws"),
            _fc_event("planner", "read_file", {"filepath": "other/info.yml"}, "c_out"),
            _fr_event("planner", "read_file", self._fenced_ok("other/info.yml"), "c_out"),
            _fc_event("planner", "read_file", {"filepath": "src/auth.ts"}, "c_sberr"),
            _fr_event("planner", "read_file", {"result": "SANDBOX-ERROR: guest unavailable"}, "c_sberr"),
            _fc_event("planner", "read_file", {"filepath": "src/login.ts"}, "c_errdict"),
            _fr_event("planner", "read_file", {"error": "Invocation was aborted"}, "c_errdict"),
            _fc_event("planner", "read_file", {"filepath": "src/session.ts"}, "c_dangling"),
            _text_event("researcher", "no reads"),
        ]
        state = {
            f"{gl.PREFIX_U_STATE_KEY_PREFIX}planner": "[ACTIVE STAGE ASSIGNMENT: planner]",
            f"{gl.PREFIX_U_STATE_KEY_PREFIX}researcher": "[ACTIVE STAGE ASSIGNMENT: researcher]",
        }
        sess = SimpleNamespace(events=events, state=state)

        mantis_main._rehydrate_session_metrics(sess, self.fake_runner, ctrl, ctx)

        self.assertEqual(ctrl.audit_code_reads, 0)
        self.assertFalse(should_credit_coverage(task_failed=False, code_read_calls=ctrl.audit_code_reads))

    def test_rehydrate_no_double_count_with_explorer_or_fork_before_model(self) -> None:
        """Explorer's own in-scope reads (already counted via AUDIT_NODES) and a subsequent
        `fork_before_model` invocation for researcher must never double-count stem reads."""
        ctrl = BudgetController(BudgetConfig(), run_id="run-resume-stem")
        ctx = self._make_ctx(ctrl)
        events = [
            _fc_event("planner", "read_file", {"filepath": "src/auth.ts"}, "c1"),
            _fr_event("planner", "read_file", self._fenced_ok("src/auth.ts"), "c1"),
            _fc_event("planner", "read_file", {"filepath": "src/login.ts"}, "c2"),
            _fr_event("planner", "read_file", self._fenced_ok("src/login.ts"), "c2"),
            _text_event("planner", "plan"),
            _fc_event("explorer", "read_file", {"filepath": "src/session.ts"}, "c3"),
            _fr_event("explorer", "read_file", self._fenced_ok("src/session.ts"), "c3"),
            _text_event("explorer", "explored"),
            _text_event("researcher", "turn 1"),
        ]
        state = {
            f"{gl.PREFIX_U_STATE_KEY_PREFIX}{n}": f"[ACTIVE STAGE ASSIGNMENT: {n}]"
            for n in ("planner", "explorer", "researcher")
        }
        sess = SimpleNamespace(events=events, state=state)

        mantis_main._rehydrate_session_metrics(sess, self.fake_runner, ctrl, ctx)
        self.assertEqual(ctrl.audit_code_reads, 3)  # 2 from planner + 1 from explorer

        # Even if researcher's fork_before_model fires again on Turn 1, slot flag prevents double-counting.
        cb = gl._make_prefix_group_before_model_callback(
            "researcher",
            base_instruction="base",
            stage_role_prompt="researcher role",
            ancestor_chain=("planner", "explorer"),
            parent_id="explorer",
            prefix_group="audit_stem",
        )
        cb_ctx = SimpleNamespace(session=sess, state=dict(state))
        req = SimpleNamespace(
            contents=[types.Content(role="user", parts=[types.Part.from_text(text="opener")])],
            config=SimpleNamespace(system_instruction=""),
        )
        tok = current_run_context.set(ctx)
        try:
            res = cb(cb_ctx, req)
            if inspect.isawaitable(res):
                asyncio.run(res)
        finally:
            current_run_context.reset(tok)

        self.assertEqual(ctrl.audit_code_reads, 3)

    def test_rehydrate_ignores_stale_prefix_state_from_previous_completed_invocation(self) -> None:
        """Stale `_mantis_prefix_u:researcher` left in session.state from a completed earlier
        invocation must not credit reads in a new invocation that paused before researcher."""
        ctrl = BudgetController(BudgetConfig(), run_id="run-resume-stem")
        ctx = self._make_ctx(ctrl)
        events = [
            _text_event("researcher", "old invocation researcher", inv_id="inv-old"),
            Event(
                invocation_id="inv-old",
                author="mantis_vulnerability_pipeline",
                actions=EventActions(end_of_agent=True),
            ),
            # New invocation paused right after planner, before researcher ran.
            _fc_event("planner", "read_file", {"filepath": "src/auth.ts"}, "c_new", inv_id="inv-new"),
            _fr_event("planner", "read_file", self._fenced_ok("src/auth.ts"), "c_new", inv_id="inv-new"),
            _text_event("planner", "new plan", inv_id="inv-new"),
        ]
        state = {
            f"{gl.PREFIX_U_STATE_KEY_PREFIX}planner": "[ACTIVE STAGE ASSIGNMENT: planner]",
            f"{gl.PREFIX_U_STATE_KEY_PREFIX}researcher": "[ACTIVE STAGE ASSIGNMENT: researcher]",
        }
        sess = SimpleNamespace(events=events, state=state)

        mantis_main._rehydrate_session_metrics(sess, self.fake_runner, ctrl, ctx)

        self.assertEqual(ctrl.audit_code_reads, 0)

    def test_rehydrate_with_sqlite_session_service_persisted_state(self) -> None:
        """End-to-end check against real `_PatientSqliteSessionService` state persistence."""
        sdb = str(Path(self._tmp.name) / "sessions.db")
        ctrl = BudgetController(BudgetConfig(), run_id="run-sqlite")
        ctx = self._make_ctx(ctrl)

        async def _run() -> None:
            svc = mantis_main._PatientSqliteSessionService(db_path=sdb)
            sess = await svc.create_session(
                app_name=mantis_main.APP_NAME,
                user_id=mantis_main.USER_ID,
                session_id="sess-1",
                state={},
            )
            planner_opener = Event(
                invocation_id="inv-1",
                author="planner",
                node_info=NodeInfo(path="mantis_vulnerability_pipeline@1/planner@1"),
                content=types.Content(
                    role="model",
                    parts=[
                        types.Part(
                            function_call=types.FunctionCall(
                                name="read_file", id="c1", args={"filepath": "src/auth.ts"}
                            )
                        )
                    ],
                ),
                actions=EventActions(
                    state_delta={f"{gl.PREFIX_U_STATE_KEY_PREFIX}planner": "[ACTIVE STAGE ASSIGNMENT: planner]"}
                ),
            )
            planner_resp = _fr_event("planner", "read_file", self._fenced_ok("src/auth.ts"), "c1")
            researcher_ev = Event(
                invocation_id="inv-1",
                author="researcher",
                node_info=NodeInfo(path="mantis_vulnerability_pipeline@1/researcher@1"),
                content=types.Content(role="model", parts=[types.Part.from_text(text="found bug")]),
                actions=EventActions(
                    state_delta={
                        f"{gl.PREFIX_U_STATE_KEY_PREFIX}researcher": "[ACTIVE STAGE ASSIGNMENT: researcher]"
                    }
                ),
            )
            for ev in (planner_opener, planner_resp, researcher_ev):
                await svc.append_event(sess, ev)

            # Fresh process reloads session from SQLite and rehydrates metrics.
            reloaded = await svc.get_session(
                app_name=mantis_main.APP_NAME,
                user_id=mantis_main.USER_ID,
                session_id="sess-1",
            )
            mantis_main._rehydrate_session_metrics(reloaded, self.fake_runner, ctrl, ctx)

        asyncio.run(_run())
        self.assertEqual(ctrl.audit_code_reads, 1)
        self.assertTrue(should_credit_coverage(task_failed=False, code_read_calls=ctrl.audit_code_reads))


if __name__ == "__main__":
    unittest.main()

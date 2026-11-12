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

"""Regression tests for CL 4: resume ledger, multi-slice accounting, non-STOP
metering, multi-pass isolation, target-scoped memory/export, and DB anchoring."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any, AsyncGenerator
from unittest.mock import patch

_REF_ROOT = Path(__file__).resolve().parent.parent
import sys

if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from google.adk.agents import Agent  # noqa: E402
from google.adk.apps import App, ResumabilityConfig  # noqa: E402
from google.adk.events.event import Event, EventActions, NodeInfo  # noqa: E402
from google.adk.models.base_llm import BaseLlm  # noqa: E402
from google.adk.models.llm_request import LlmRequest  # noqa: E402
from google.adk.models.llm_response import LlmResponse  # noqa: E402
from google.adk.runners import Runner  # noqa: E402
from google.adk.workflow import START, Edge, RetryConfig, Workflow, node  # noqa: E402
from google.genai import types  # noqa: E402
from pydantic import PrivateAttr  # noqa: E402

import main as mantis_main  # noqa: E402
from core.budget import (  # noqa: E402
    BudgetConfig,
    BudgetController,
    BudgetExceededError,
    CampaignBudgetScope,
    should_credit_coverage,
)
from core.config import ResilientLiteLlm  # noqa: E402
from core.context import RunContext, current_run_context  # noqa: E402
from core.cost import (  # noqa: E402
    latest_run_id,
    load_run_plan,
    observed_campaign_cost,
    record_run_plan,
    record_spend,
    run_ledger,
    uncovered_files,
)
from core.database import (  # noqa: E402
    connect as db_connect,
    init_db,
    read_findings,
    record_learning,
    record_run,
    update_status,
    write_findings,
)
from core.graph_loader import (  # noqa: E402
    _make_stage_experience_before_model_callback,
    _persist_dismissal_verdict,
    apply_completion_stamp,
    campaign_has_findings_to_triage,
)
from core.knowledge import export_knowledge, import_knowledge  # noqa: E402
from core.memory import recall, recall_for_stage  # noqa: E402
from core.schemas import ReviewVerdict  # noqa: E402
from scripts.launch import build_parser  # noqa: E402
from tools.research_tools import get_findings  # noqa: E402
from tools.sandbox_tools import _record_finding_evidence  # noqa: E402


class _ScriptedLlm(BaseLlm):
    model: str = "scripted-cl4"
    _steps: list[Any] = PrivateAttr(default_factory=list)
    _idx: int = PrivateAttr(default=0)

    def __init__(self, steps: list[Any], model: str = "scripted-cl4") -> None:
        super().__init__(model=model)
        self._steps = list(steps)
        self._idx = 0

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        idx = self._idx
        self._idx += 1
        step = self._steps[idx]
        if isinstance(step, BaseException):
            raise step
        yield step


class TestResumeLedgerResolution(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="mantis_cl4_resume_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo_a = os.path.realpath(os.path.join(self.tmp, "repo_a"))
        self.repo_b = os.path.realpath(os.path.join(self.tmp, "repo_b"))
        os.makedirs(self.repo_a)
        os.makedirs(self.repo_b)
        Path(self.repo_a, "app.py").write_text("def handle():\n    return 1\n", encoding="utf-8")
        Path(self.repo_b, "srv.py").write_text("def serve():\n    return 2\n", encoding="utf-8")
        self.db = os.path.join(self.tmp, "knowledge.db")
        init_db(self.db)

    def test_latest_run_id_resolves_paused_first_campaign_run_and_isolates_repos(self) -> None:
        paused_id = "paused-first-campaign-0001"
        record_run(
            self.db,
            paused_id,
            "openai/gpt-test",
            metadata={"target_root": self.repo_a, "target": self.repo_a},
            started="2026-06-01 12:00:00",
        )
        # Fresh DB with zero campaign_spend and zero findings rows: must still resolve paused_id.
        self.assertEqual(latest_run_id(self.db, self.repo_a), paused_id)
        # Foreign repo with no runs in this DB must return "", never repo_a's run.
        self.assertEqual(latest_run_id(self.db, self.repo_b), "")

        # Seed an older completed run on repo_a with a campaign_spend row: paused_id is newer and must win.
        old_complete = "old-complete-0000"
        record_run(
            self.db,
            old_complete,
            "openai/gpt-test",
            metadata={"target_root": self.repo_a, "target": self.repo_a},
            started="2026-01-01 00:00:00",
        )
        record_spend(
            self.db,
            old_complete,
            self.repo_a,
            "cross-functional",
            tokens=50000,
            metadata={"failed": False},
        )
        conn = sqlite3.connect(self.db)
        try:
            conn.execute(
                "UPDATE campaign_spend SET timestamp = ? WHERE run_id = ?",
                ("2026-01-01 00:10:00", old_complete),
            )
            conn.commit()
        finally:
            conn.close()
        self.assertEqual(latest_run_id(self.db, self.repo_a), paused_id)

    def test_run_known_validates_existence_and_target_compatibility(self) -> None:
        from core.cost import run_known

        known, rec_root = run_known(self.db, "nonexistent-typo-id")
        self.assertFalse(known)
        self.assertEqual(rec_root, "")

        record_run(
            self.db,
            "run-a-only",
            "openai/gpt-test",
            metadata={"target_root": self.repo_a, "target": self.repo_a},
        )
        known_a, rec_a = run_known(self.db, "run-a-only")
        self.assertTrue(known_a)
        self.assertEqual(os.path.realpath(rec_a), self.repo_a)

        # Spend-only legacy seed remains recognized.
        record_spend(self.db, "legacy-spend-only", os.path.join(self.repo_b, "srv.py"), "file-by-file", tokens=100)
        known_b, rec_b = run_known(self.db, "legacy-spend-only")
        self.assertTrue(known_b)
        self.assertTrue(os.path.realpath(rec_b).startswith(self.repo_b))

        # Pipeline rejects unknown --resume ID and cross-repo --resume ID with EXIT_USAGE (64).
        err_buf = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err_buf):
            rc_missing = asyncio.run(
                mantis_main.pipeline(
                    scan_target=self.repo_a,
                    db_override=self.db,
                    model_override="openai/gpt-test",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    auto_configure=False,
                    assume_yes=True,
                    resume_run_id="nonexistent-typo-id",
                )
            )
            rc_foreign = asyncio.run(
                mantis_main.pipeline(
                    scan_target=self.repo_b,
                    db_override=self.db,
                    model_override="openai/gpt-test",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    auto_configure=False,
                    assume_yes=True,
                    resume_run_id="run-a-only",
                )
            )
        self.assertEqual(rc_missing, mantis_main.EXIT_USAGE)
        self.assertEqual(rc_foreign, mantis_main.EXIT_USAGE)


class TestMultiSliceResumeAccounting(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="mantis_cl4_slices_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = os.path.realpath(os.path.join(self.tmp, "repo"))
        os.makedirs(self.repo)
        self.app_py = os.path.join(self.repo, "app.py")
        Path(self.app_py).write_text("def query(u):\n    return u\n", encoding="utf-8")
        self.db = os.path.join(self.tmp, "knowledge.db")
        self.sess_db = os.path.join(self.tmp, "sessions.db")
        init_db(self.db)

    def test_multi_slice_resumed_campaign_rehydrates_code_reads_and_tokens(self) -> None:
        async def _run() -> None:
            svc = mantis_main._PatientSqliteSessionService(db_path=self.sess_db)
            run_id = "run-multislice"
            target_hash = hashlib.sha256(self.repo.encode("utf-8")).hexdigest()[:8]
            session_id = f"session_run_{run_id}_{target_hash}"
            sess = await svc.create_session(
                app_name=mantis_main.APP_NAME,
                user_id=mantis_main.USER_ID,
                session_id=session_id,
                state={"db_path": self.db, "run_id": run_id, "filepath": self.repo},
            )
            inv_id = "inv-slice-chain"
            # Seed pre-pause events across earlier slices: architect + researcher read_file("app.py")
            pre_events = [
                Event(
                    invocation_id=inv_id,
                    author="user",
                    content=types.Content(role="user", parts=[types.Part.from_text(text="Seed prompt")]),
                ),
                Event(
                    invocation_id=inv_id,
                    author="researcher",
                    node_info=NodeInfo(path="mantis_vulnerability_pipeline@1/researcher@1"),
                    content=types.Content(
                        role="model",
                        parts=[
                            types.Part(
                                function_call=types.FunctionCall(
                                    id="fc_read_1", name="read_file", args={"filepath": "app.py"}
                                )
                            )
                        ],
                    ),
                    usage_metadata=types.GenerateContentResponseUsageMetadata(
                        prompt_token_count=10000, candidates_token_count=2000, total_token_count=12000
                    ),
                ),
                Event(
                    invocation_id=inv_id,
                    author="researcher",
                    node_info=NodeInfo(path="mantis_vulnerability_pipeline@1/researcher@1"),
                    content=types.Content(
                        role="user",
                        parts=[
                            types.Part(
                                function_response=types.FunctionResponse(
                                    id="fc_read_1",
                                    name="read_file",
                                    response={"result": "<<<UNTRUSTED_SOURCE_CODE_DATA_START>>>\ndef query(u): pass"},
                                )
                            )
                        ],
                    ),
                ),
                Event(
                    invocation_id=inv_id,
                    author="researcher",
                    node_info=NodeInfo(path="mantis_vulnerability_pipeline@1/researcher@1"),
                    content=types.Content(role="model", parts=[types.Part.from_text(text="Audit complete")]),
                    output="Audit complete",
                    actions=EventActions(end_of_agent=True, state_delta={"res_out": "Audit complete"}),
                    usage_metadata=types.GenerateContentResponseUsageMetadata(
                        prompt_token_count=5000, candidates_token_count=1000, total_token_count=6000
                    ),
                ),
            ]
            for ev in pre_events:
                await svc.append_event(sess, ev)

            res_llm = _ScriptedLlm([])
            rep_llm = _ScriptedLlm(
                [
                    LlmResponse(
                        content=types.Content(role="model", parts=[types.Part.from_text(text="Final report")]),
                        finish_reason=types.FinishReason.STOP,
                        usage_metadata=types.GenerateContentResponseUsageMetadata(
                            prompt_token_count=2000, candidates_token_count=500, total_token_count=2500
                        ),
                    )
                ]
            )
            n_res = node(
                Agent(name="researcher", model=res_llm, include_contents="none", output_key="res_out"),
                name="researcher",
            )
            n_rep = node(
                Agent(name="reporter", model=rep_llm, include_contents="none", output_key="rep_out"),
                name="reporter",
            )
            wf = Workflow(
                name="mantis_vulnerability_pipeline",
                edges=[Edge(from_node=START, to_node=n_res), Edge(from_node=n_res, to_node=n_rep)],
            )
            app = App(
                name=mantis_main.APP_NAME,
                root_agent=wf,
                resumability_config=ResumabilityConfig(is_resumable=True),
            )
            runner = Runner(app=app, session_service=svc)

            parent_budget = BudgetController(config=BudgetConfig(max_tokens=50000), run_id=run_id)
            budget_ctrl = CampaignBudgetScope(parent_budget)
            budget_ctrl.begin_campaign()
            tokens_before = budget_ctrl.accumulated_tokens
            reads_before = budget_ctrl.audit_code_reads

            ctx = RunContext(jail_dir=self.repo, db_path=self.db, target_file=self.repo, run_id=run_id)
            tok = current_run_context.set(ctx)
            try:
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    task_failed = await mantis_main.execute_sub_task(
                        runner, svc, self.repo, run_id, db_path=self.db, budget_controller=budget_ctrl
                    )
            finally:
                current_run_context.reset(tok)
                await runner.close()

            self.assertFalse(task_failed)
            self.assertEqual(res_llm._idx, 0, "researcher fast-forwarded from prior slice")
            self.assertEqual(rep_llm._idx, 1, "reporter ran in final slice")
            code_reads = budget_ctrl.audit_code_reads - reads_before
            self.assertGreater(code_reads, 0, "prior-slice researcher read_file must be rehydrated")
            self.assertTrue(should_credit_coverage(task_failed, code_reads))
            self.assertEqual(ctx.pre_pause_tokens, 18000)
            # Fresh process budget only sees this process's 2,500 tokens:
            self.assertEqual(parent_budget.accumulated_tokens, 2500)
            # Adjusted tokens_before yields full 20,500-token campaign spend:
            tokens_before -= ctx.pre_pause_tokens
            self.assertEqual(budget_ctrl.accumulated_tokens - tokens_before, 20500)

        asyncio.run(_run())

    def test_rehydrate_finding_evidence_and_promoted_ids_and_filter_cost_rows(self) -> None:
        run_id = "run-rehydrate-ev"
        ctx = RunContext(jail_dir=self.repo, db_path=self.db, target_file=self.repo, run_id=run_id)
        tok = current_run_context.set(ctx)
        try:
            write_findings(
                self.db,
                self.repo,
                [
                    {
                        "title": "Confirmed SQLi",
                        "severity": "HIGH",
                        "status": "confirmed",
                        "description": "tainted query",
                        "line_numbers": [2],
                        "cwe": "CWE-89",
                        "filepath": "app.py",
                    },
                    {
                        "title": "Unreviewed note",
                        "severity": "LOW",
                        "status": "reported",
                        "description": "unreviewed",
                        "line_numbers": [1],
                        "cwe": "CWE-200",
                        "filepath": "app.py",
                    },
                ],
                run_id=run_id,
            )
            rows = read_findings(self.db, run_id=run_id)
            confirmed_id = next(r["id"] for r in rows if r["title"] == "Confirmed SQLi")
            _record_finding_evidence(ctx, confirmed_id, True, "sentinel matched", sink_symbol="query", ran=True)
        finally:
            current_run_context.reset(tok)

        resumed_ctx = RunContext(jail_dir=self.repo, db_path=self.db, target_file=self.repo, run_id=run_id)
        mantis_main._rehydrate_campaign_resume_state(resumed_ctx, self.db, run_id, self.repo, 1, "")
        self.assertTrue(resumed_ctx.sandbox_executed)
        self.assertTrue(resumed_ctx.finding_evidence[str(confirmed_id)]["reproduced"])
        self.assertEqual(resumed_ctx.promoted_finding_ids, {int(confirmed_id)})

        # Cost model excludes unexamined and resumed_tail rows while averaging real observations.
        record_spend(
            self.db, "r-cost", self.repo, "cross-functional", tokens=20000, metadata={"unexamined": True}
        )
        record_spend(
            self.db, "r-cost", self.repo, "cross-functional", tokens=25000, metadata={"resumed_tail": True}
        )
        self.assertEqual(observed_campaign_cost(self.db, "cross-functional"), (None, 0))
        record_spend(
            self.db, "r-cost", self.repo, "cross-functional", tokens=80000, metadata={"failed": False}
        )
        self.assertEqual(observed_campaign_cost(self.db, "cross-functional"), (80000, 1))


class TestCampaignDriveAndNonStopMetering(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="mantis_cl4_drive_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.tf = os.path.join(self.tmp, "app.py")
        Path(self.tf).write_text("x = 1\n", encoding="utf-8")
        self.db = os.path.join(self.tmp, "knowledge.db")
        self.sess_db = os.path.join(self.tmp, "sessions.db")

    def test_retried_node_success_clears_pending_error_while_unrecovered_fails(self) -> None:
        async def _run() -> None:
            svc = mantis_main._PatientSqliteSessionService(db_path=self.sess_db)
            llm_ok = _ScriptedLlm(
                [
                    RuntimeError("503 transient backend error"),
                    LlmResponse(
                        content=types.Content(role="model", parts=[types.Part.from_text(text="Recovered ok")]),
                        finish_reason=types.FinishReason.STOP,
                        usage_metadata=types.GenerateContentResponseUsageMetadata(
                            prompt_token_count=100, candidates_token_count=50, total_token_count=150
                        ),
                    ),
                ]
            )
            n1 = node(
                Agent(name="researcher", model=llm_ok, include_contents="none", output_key="res_out"),
                name="researcher",
                retry_config=RetryConfig(max_attempts=3, initial_delay=0.01),
            )
            wf = Workflow(name="mantis_vulnerability_pipeline", edges=[Edge(from_node=START, to_node=n1)])
            runner = Runner(app=App(name=mantis_main.APP_NAME, root_agent=wf), session_service=svc)
            bc = BudgetController(config=BudgetConfig(), run_id="r-retry-ok")
            bc.begin_campaign()
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                failed = await mantis_main.execute_sub_task(
                    runner, svc, self.tf, "r-retry-ok", db_path=self.db, budget_controller=bc
                )
            await runner.close()
            self.assertFalse(failed, "recovered node retry must not poison task_failed")
            self.assertEqual(bc.accumulated_tokens, 150)

        asyncio.run(_run())

    def test_non_stop_error_events_meter_tokens_and_enforce_budget(self) -> None:
        async def _run() -> None:
            svc = mantis_main._PatientSqliteSessionService(db_path=self.sess_db)
            llm = _ScriptedLlm(
                [
                    LlmResponse(
                        content=None,
                        error_code="MAX_TOKENS",
                        error_message="Hit output limit",
                        finish_reason=types.FinishReason.MAX_TOKENS,
                        usage_metadata=types.GenerateContentResponseUsageMetadata(
                            prompt_token_count=2000, candidates_token_count=2000, total_token_count=4000
                        ),
                    ),
                    LlmResponse(
                        content=None,
                        error_code="SAFETY",
                        error_message="Safety block",
                        finish_reason=types.FinishReason.SAFETY,
                        usage_metadata=types.GenerateContentResponseUsageMetadata(
                            prompt_token_count=1500, candidates_token_count=500, total_token_count=2000
                        ),
                    ),
                ]
            )
            n1 = node(
                Agent(name="researcher", model=llm, include_contents="none", output_key="res_out"),
                name="researcher",
            )
            n2 = node(
                Agent(name="reviewer", model=llm, include_contents="none", output_key="rev_out"),
                name="reviewer",
            )
            wf = Workflow(
                name="mantis_vulnerability_pipeline",
                edges=[Edge(from_node=START, to_node=n1), Edge(from_node=n1, to_node=n2)],
            )
            runner = Runner(app=App(name=mantis_main.APP_NAME, root_agent=wf), session_service=svc)
            bc = BudgetController(config=BudgetConfig(max_tokens=5000), run_id="r-nonstop")
            bc.begin_campaign()
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with self.assertRaises(BudgetExceededError) as ctx_exc:
                    await mantis_main.execute_sub_task(
                        runner, svc, self.tf, "r-nonstop", db_path=self.db, budget_controller=bc
                    )
            await runner.close()
            self.assertEqual(ctx_exc.exception.trigger, "token_budget")
            self.assertEqual(bc.accumulated_tokens, 6000)
            self.assertEqual(bc.llm_calls, 2)

        asyncio.run(_run())

    def test_streaming_truncation_and_schema_empty_giveup_meter_exactly_once(self) -> None:
        class _FakeSuperLlm(ResilientLiteLlm):
            _script: list[list[LlmResponse]] = PrivateAttr(default_factory=list)

            def __init__(self, script: list[list[LlmResponse]]) -> None:
                super().__init__(model="openai/gpt-test")
                self._script = list(script)

        async def _fake_super_gen(self_obj: Any, llm_request: Any, stream: bool = False):
            batch = self_obj._script.pop(0)
            for item in batch:
                yield item

        async def _run() -> None:
            bc = BudgetController(config=BudgetConfig(max_tokens=100000), run_id="r-trunc")
            bc.begin_campaign()
            ctx = RunContext(jail_dir=self.tmp, db_path=self.db, run_id="r-trunc", budget_controller=bc)
            tok = current_run_context.set(ctx)
            try:
                # 1) Truncated streaming turn (900 tokens) retries with stream=False (1100 tokens).
                trunc_resp = LlmResponse(
                    content=None,
                    error_code="MAX_TOKENS",
                    error_message="Tool call arguments were truncated while streaming",
                    finish_reason=types.FinishReason.MAX_TOKENS,
                    usage_metadata=types.GenerateContentResponseUsageMetadata(
                        prompt_token_count=500, candidates_token_count=400, total_token_count=900
                    ),
                )
                ok_resp = LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[types.Part.from_text(text='{"route": "confirmed", "reason": "verified"}')],
                    ),
                    finish_reason=types.FinishReason.STOP,
                    usage_metadata=types.GenerateContentResponseUsageMetadata(
                        prompt_token_count=800, candidates_token_count=300, total_token_count=1100
                    ),
                )
                llm = _FakeSuperLlm([[trunc_resp], [ok_resp]])
                req = LlmRequest(model="openai/gpt-test", config=types.GenerateContentConfig(response_schema=ReviewVerdict))
                with patch.object(BaseLlm, "generate_content_async", _fake_super_gen), redirect_stderr(io.StringIO()):
                    # Patch LiteLlm.generate_content_async on MRO parent directly:
                    with patch.object(ResilientLiteLlm.__bases__[0], "generate_content_async", _fake_super_gen):
                        out = [r async for r in llm.generate_content_async(req, stream=True)]
                self.assertEqual(len(out), 1)
                # Truncated turn metered 900 inside ResilientLiteLlm; final turn carries 1100 for _drive_campaign.
                self.assertEqual(bc.accumulated_tokens, 900)
                self.assertEqual(out[0].usage_metadata.total_token_count, 1100)

                # 2) Schema empty-turn give-up after max_empty_turns=1: billed once (300), yielded usage_metadata zeroed.
                empty_resp = LlmResponse(
                    content=types.Content(role="model", parts=[]),
                    finish_reason=types.FinishReason.STOP,
                    usage_metadata=types.GenerateContentResponseUsageMetadata(
                        prompt_token_count=300, candidates_token_count=0, total_token_count=300
                    ),
                )
                llm_empty = _FakeSuperLlm([[empty_resp]])
                with patch.dict(os.environ, {"MANTIS_LLM_EMPTY_TURN_MAX_ATTEMPTS": "1"}):
                    with patch.object(
                        ResilientLiteLlm.__bases__[0], "generate_content_async", _fake_super_gen
                    ), redirect_stderr(io.StringIO()):
                        out_empty = [r async for r in llm_empty.generate_content_async(req, stream=False)]
                self.assertEqual(len(out_empty), 1)
                self.assertEqual(bc.accumulated_tokens, 1200)
                self.assertEqual(out_empty[0].usage_metadata.total_token_count, 0)
            finally:
                current_run_context.reset(tok)

        asyncio.run(_run())


class TestMultiPassIsolationAndPassLedger(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="mantis_cl4_passes_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = os.path.realpath(os.path.join(self.tmp, "repo"))
        self.slice_dir = os.path.join(self.repo, "services", "auth")
        os.makedirs(self.slice_dir)
        Path(self.slice_dir, "login.py").write_text("def login(u):\n    return u\n", encoding="utf-8")
        self.db = os.path.join(self.tmp, "knowledge.db")
        init_db(self.db)

    def test_pass_index_isolates_findings_triage_dismissals_stamps_and_blind_snapshots(self) -> None:
        run_id = "run-multipass"
        finding_payload = {
            "title": "SQL Injection in login",
            "severity": "HIGH",
            "status": "reported",
            "description": "Unsanitized user parameter in SQL query",
            "line_numbers": [2],
            "cwe": "CWE-89",
            "filepath": "services/auth/login.py",
        }

        # Pass 1 reports and confirms the finding.
        ctx_p1 = RunContext(
            jail_dir=self.repo,
            db_path=self.db,
            target_file=self.slice_dir,
            run_id=run_id,
            pass_index=1,
            active_node="reproducer",
        )
        tok1 = current_run_context.set(ctx_p1)
        try:
            write_findings(self.db, self.slice_dir, [finding_payload], run_id=run_id)
            self.assertTrue(campaign_has_findings_to_triage(self.db, run_id, self.slice_dir))
            apply_completion_stamp(ctx_p1, "static_confirmed", "reproducer")
        finally:
            current_run_context.reset(tok1)

        p1_rows = read_findings(self.db, run_id=run_id, pass_index=1)
        self.assertEqual(len(p1_rows), 1)
        self.assertEqual(p1_rows[0]["status"], "static_confirmed")

        # Pass 2 starts clean: triage gate is False, researcher snapshot is blind, get_findings is empty.
        ctx_p2 = RunContext(
            jail_dir=self.repo,
            db_path=self.db,
            target_file=self.slice_dir,
            run_id=run_id,
            pass_index=2,
            active_node="planner",
            reported_in_pass=False,
        )
        tok2 = current_run_context.set(ctx_p2)
        try:
            self.assertFalse(campaign_has_findings_to_triage(self.db, run_id, self.slice_dir))
            req = LlmRequest(
                model="openai/gpt-test",
                config=types.GenerateContentConfig(system_instruction="Planner base instruction."),
            )
            ResilientLiteLlm._inject_active_findings_state(req)
            self.assertNotIn("SQL Injection in login", str(req.config.system_instruction))

            ctx_p2.active_node = "reviewer"
            self.assertIn("Zero findings recorded", get_findings())

            # Pass 2 independently rediscovers the exact same location/title and then dismisses it in Pass 2:
            write_findings(self.db, self.slice_dir, [finding_payload], run_id=run_id)
            self.assertTrue(campaign_has_findings_to_triage(self.db, run_id, self.slice_dir))
            _persist_dismissal_verdict(
                "critic_classifier", "non_viable", {"route": "non_viable", "reason": "Guarded upstream"}
            )
        finally:
            current_run_context.reset(tok2)

        # Pass 1's static_confirmed finding MUST survive Pass 2's dismissal!
        p1_after = read_findings(self.db, run_id=run_id, pass_index=1)
        p2_after = read_findings(self.db, run_id=run_id, pass_index=2)
        all_rows = read_findings(self.db, run_id=run_id)
        self.assertEqual(len(p1_after), 1)
        self.assertEqual(p1_after[0]["status"], "static_confirmed")
        self.assertEqual(len(p2_after), 1)
        self.assertEqual(p2_after[0]["status"], "non_viable")
        self.assertEqual(len(all_rows), 2)

        # _campaign_finding_counts resolves absolute slice paths accurately and scopes per pass when given.
        ctx_check = RunContext(jail_dir=self.repo, db_path=self.db, target_file=self.slice_dir, run_id=run_id)
        tok_c = current_run_context.set(ctx_check)
        try:
            self.assertEqual(
                mantis_main._campaign_finding_counts(self.db, run_id, self.slice_dir, pass_index=1),
                {"static_confirmed": 1},
            )
            self.assertEqual(
                mantis_main._campaign_finding_counts(self.db, run_id, self.slice_dir, pass_index=2),
                {"non_viable": 1},
            )
        finally:
            current_run_context.reset(tok_c)

    def test_run_pass_ledger_and_saved_plan_passes_preserve_run_ledger_contract(self) -> None:
        from core.cost import run_pass_ledger

        run_id = "run-pass-ledger"
        record_run(self.db, run_id, "openai/gpt-test", metadata={"target_root": self.repo})
        record_spend(
            self.db,
            run_id,
            self.slice_dir,
            "cross-functional",
            tokens=12000,
            metadata={"failed": False},
            harness_fingerprint="fp1234",
        )
        record_spend(
            self.db,
            run_id,
            self.slice_dir,
            "cross-functional",
            tokens=0,
            metadata={"failed": True, "guard": "graph_steps", "pass_index": 2},
            harness_fingerprint="fp1234",
        )
        # run_ledger() keeps its exact pinned dict shape!
        self.assertEqual(
            run_ledger(self.db, run_id),
            {self.slice_dir: {"failed": True, "harness_fingerprint": "fp1234"}},
        )
        # run_pass_ledger() distinguishes (target, 1) from (target, 2)!
        pass_ledger = run_pass_ledger(self.db, run_id)
        assert pass_ledger is not None
        self.assertFalse(pass_ledger[(self.slice_dir, 1)]["failed"])
        self.assertTrue(pass_ledger[(self.slice_dir, 2)]["failed"])

        # Saved run plan stores passes=2 without duplicating plan_groups.
        self.assertTrue(
            record_run_plan(
                self.db,
                run_id,
                [self.slice_dir],
                target_root=self.repo,
                plan_groups=[{"targets": [self.slice_dir], "hypothesis": "check auth", "chain": None}],
                passes=2,
                overwrite=True,
            )
        )
        loaded = load_run_plan(self.db, run_id, self.repo)
        assert loaded is not None
        self.assertEqual(loaded.get("passes"), 2)
        self.assertEqual(len(loaded["plan_groups"]), 1)


class TestMemoryKnowledgeIsolationAndDbAnchoring(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="mantis_cl4_mem_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo_a = os.path.realpath(os.path.join(self.tmp, "repo_a"))
        self.repo_b = os.path.realpath(os.path.join(self.tmp, "repo_b"))
        os.makedirs(self.repo_a)
        os.makedirs(self.repo_b)
        Path(self.repo_a, "alpha.py").write_text("a = 1\n", encoding="utf-8")
        Path(self.repo_b, "beta.py").write_text("b = 2\n", encoding="utf-8")
        self.db = os.path.join(self.tmp, "shared_knowledge.db")
        init_db(self.db)

    def test_shared_db_isolates_recall_and_export_and_preserves_timestamps_and_unexamined(self) -> None:
        # Seed Repo A run
        record_run(
            self.db,
            "run-repo-a",
            "openai/model-a",
            metadata={"target_root": self.repo_a, "target": self.repo_a},
            started="2026-02-01 08:00:00",
        )
        ctx_a = RunContext(jail_dir=self.repo_a, db_path=self.db, target_file=self.repo_a, run_id="run-repo-a")
        tok_a = current_run_context.set(ctx_a)
        try:
            write_findings(
                self.db,
                self.repo_a,
                [
                    {
                        "title": "Repo A Command Injection",
                        "severity": "CRITICAL",
                        "status": "dynamic_confirmed",
                        "description": "Repo A secret flaw",
                        "line_numbers": [1],
                        "cwe": "CWE-78",
                        "filepath": "alpha.py",
                    }
                ],
                run_id="run-repo-a",
            )
            record_learning(
                self.db,
                "run-repo-a",
                "experience:reviewer",
                "Repo A reviewer lesson",
                tags=["stage:reviewer", "confidence:high"],
            )
        finally:
            current_run_context.reset(tok_a)

        # Seed Repo B run with deterministic timestamps + an unexamined spend row on beta.py
        record_run(
            self.db,
            "run-repo-b",
            "openai/model-b",
            metadata={"target_root": self.repo_b, "target": self.repo_b},
            started="2026-03-15 10:20:30",
        )
        ctx_b = RunContext(jail_dir=self.repo_b, db_path=self.db, target_file=self.repo_b, run_id="run-repo-b")
        tok_b = current_run_context.set(ctx_b)
        try:
            write_findings(
                self.db,
                self.repo_b,
                [
                    {
                        "title": "Repo B Path Traversal",
                        "severity": "HIGH",
                        "status": "static_confirmed",
                        "description": "Repo B traversal",
                        "line_numbers": [1],
                        "cwe": "CWE-22",
                        "filepath": "beta.py",
                    }
                ],
                run_id="run-repo-b",
            )
            record_learning(
                self.db,
                "run-repo-b",
                "experience:reviewer",
                "Repo B reviewer lesson",
                tags=["stage:reviewer", "confidence:high"],
            )
        finally:
            current_run_context.reset(tok_b)

        conn = sqlite3.connect(self.db)
        try:
            conn.execute("UPDATE findings SET timestamp = '2026-03-15 10:21:00' WHERE run_id = 'run-repo-b'")
            conn.execute("UPDATE learnings SET timestamp = '2026-03-15 10:22:00' WHERE run_id = 'run-repo-b'")
            conn.commit()
        finally:
            conn.close()

        # Unexamined spend row must NOT count as coverage in uncovered_files or export_knowledge!
        beta_py = os.path.join(self.repo_b, "beta.py")
        record_spend(
            self.db,
            "run-repo-b",
            beta_py,
            "file-by-file",
            tokens=5000,
            metadata={"failed": False, "unexamined": True},
        )
        self.assertEqual(uncovered_files(self.db, [beta_py]), [beta_py])

        # Recall for Repo B sees ONLY Repo B's finding and learning.
        mem_b = recall(self.db, target=self.repo_b, active_root=self.repo_b)
        self.assertEqual([f["title"] for f in mem_b["confirmed"]], ["Repo B Path Traversal"])
        self.assertEqual([l["learning"] for l in mem_b["learnings"]], ["Repo B reviewer lesson"])
        stage_b = recall_for_stage(self.db, "reviewer", target=self.repo_b, active_root=self.repo_b)
        self.assertEqual([l["learning"] for l in stage_b], ["Repo B reviewer lesson"])

        # Export Repo B -> zero Repo A rows, zero unexamined scanned paths, and byte-identical round-trip!
        exp1 = os.path.join(self.repo_b, ".mantis", "knowledge")
        counts1 = export_knowledge(self.db, exp1, repo_root=self.repo_b, head="11111111")
        self.assertEqual(counts1["findings"], 1)
        self.assertEqual(counts1["learnings"], 1)
        self.assertEqual(counts1["runs"], 1)
        self.assertEqual(counts1["coverage_paths"], 0)
        manifest1 = json.loads(Path(exp1, "manifest.json").read_text(encoding="utf-8"))

        fresh_db = os.path.join(self.tmp, "reimported.db")
        import_knowledge(fresh_db, exp1, run_id="import-session", repo_root=self.repo_b, target=self.repo_b)
        exp2 = os.path.join(self.repo_b, ".mantis", "knowledge_rt")
        export_knowledge(fresh_db, exp2, repo_root=self.repo_b, head="11111111")
        manifest2 = json.loads(Path(exp2, "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest1["content_sha256"], manifest2["content_sha256"])

    def test_freeze_memory_by_default_and_no_memory_and_cli_flags(self) -> None:
        parser = build_parser()
        args_default = parser.parse_args(["target_dir"])
        self.assertFalse(args_default.no_memory)
        self.assertFalse(args_default.intra_run_learning)
        args_flags = parser.parse_args(["target_dir", "--no-memory", "--intra-run-learning"])
        self.assertTrue(args_flags.no_memory)
        self.assertTrue(args_flags.intra_run_learning)

        record_run(self.db, "prior-run", "openai/m", metadata={"target_root": self.repo_a})
        record_run(self.db, "current-run", "openai/m", metadata={"target_root": self.repo_a})
        ctx_seed = RunContext(jail_dir=self.repo_a, db_path=self.db, target_file=self.repo_a, run_id="prior-run")
        t0 = current_run_context.set(ctx_seed)
        try:
            record_learning(
                self.db, "prior-run", "experience:reviewer", "Prior run lesson", tags=["stage:reviewer"]
            )
            record_learning(
                self.db, "current-run", "experience:reviewer", "Same run lesson", tags=["stage:reviewer"]
            )
        finally:
            current_run_context.reset(t0)

        # Frozen to prior runs (pipeline default): excludes current-run.
        ctx_frozen = RunContext(
            jail_dir=self.repo_a,
            db_path=self.db,
            target_file=self.repo_a,
            run_id="current-run",
            freeze_memory_to_prior_runs=True,
        )
        tf = current_run_context.set(ctx_frozen)
        try:
            mem = recall(self.db, target=self.repo_a)
            self.assertEqual([l["learning"] for l in mem["learnings"]], ["Prior run lesson"])
        finally:
            current_run_context.reset(tf)

        # --no-memory disables both recall() and stage experience callback.
        ctx_nomem = RunContext(
            jail_dir=self.repo_a,
            db_path=self.db,
            target_file=self.repo_a,
            run_id="current-run",
            enable_memory=False,
        )
        tn = current_run_context.set(ctx_nomem)
        try:
            self.assertFalse(recall(self.db, target=self.repo_a)["available"])
            cb = _make_stage_experience_before_model_callback("reviewer")
            req = LlmRequest(
                model="openai/m", config=types.GenerateContentConfig(system_instruction="Base prompt")
            )
            cb(None, req)
            self.assertEqual(req.config.system_instruction, "Base prompt")
        finally:
            current_run_context.reset(tn)

    def test_database_connect_anchors_relative_path_away_from_hostile_cwd(self) -> None:
        hostile_cwd = Path(self.tmp) / "hostile_repo"
        hostile_cwd.mkdir()
        victim = Path(self.tmp) / "victim_file"
        (hostile_cwd / "knowledge.db").symlink_to(victim)
        safe_install = Path(self.tmp) / "safe_install"
        safe_install.mkdir()

        old_cwd = os.getcwd()
        os.chdir(hostile_cwd)
        try:
            with patch("core.paths.install_root", return_value=safe_install):
                conn = db_connect("knowledge.db")
                try:
                    conn.execute("CREATE TABLE IF NOT EXISTS probe (x INT)")
                finally:
                    conn.close()
            self.assertFalse(victim.exists(), "connect() must never follow CWD symlink")
            self.assertTrue((safe_install / "knowledge.db").exists())
        finally:
            os.chdir(old_cwd)


class ContextWindowExceededError(Exception):
    """Named like litellm's typed overflow so main._is_context_overflow matches."""


class TestRound1ReviewFixes(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="mantis_cl4_round1_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = os.path.realpath(os.path.join(self.tmp, "repo"))
        os.makedirs(self.repo)
        self.db = os.path.join(self.tmp, "knowledge.db")
        init_db(self.db)

    def test_no_memory_still_delivers_planner_hypothesis_and_group_context(self) -> None:
        from core.cost import record_run_scan_mode

        sub_a = os.path.join(self.repo, "svc_a")
        sub_b = os.path.join(self.repo, "svc_b")
        os.makedirs(sub_a)
        os.makedirs(sub_b)
        Path(sub_a, "x.py").write_text("x = 1\n", encoding="utf-8")
        Path(sub_b, "y.py").write_text("y = 2\n", encoding="utf-8")

        # Cross-run memory that --no-memory must withhold.
        record_run(self.db, "prior-run", "openai/nonexistent", metadata={"target_root": self.repo})
        write_findings(
            self.db,
            os.path.join(sub_a, "x.py"),
            [{"title": "PRIOR-RUN-MEMORY-MARKER", "severity": "HIGH", "status": "static_confirmed",
              "description": "earlier run", "line_numbers": [1], "cwe": "CWE-89"}],
            run_id="prior-run",
        )

        run = "33333333-4444-4555-8666-777777777777"
        record_run(self.db, run, "openai/nonexistent", metadata={"target_root": self.repo, "target": self.repo})
        record_run_scan_mode(self.db, run, "cross-functional")
        self.assertTrue(
            record_run_plan(
                self.db,
                run,
                targets=[sub_a, sub_b],
                target_root=self.repo,
                plan_groups=[
                    {"targets": [sub_a, sub_b], "hypothesis": "GROUP-HYPOTHESIS-MARKER",
                     "chain": "CHAIN-MARKER: upload feeds the parser"},
                ],
                campaign_plan={
                    "available": True,
                    "hypotheses": {sub_a: {"hypothesis": "PLANNER-HYPOTHESIS-MARKER", "priority": 1}},
                },
            )
        )

        seen: list[dict] = []

        async def _fake_execute_sub_task(*args: Any, **kwargs: Any) -> bool:
            seen.append({"target": args[2], "hypotheses": kwargs.get("hypotheses", ""),
                         "prior_memory": kwargs.get("prior_memory", "")})
            return False

        env = {k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}
        env.update({"OPENAI_API_KEY": "dummy", "LLM_TIMEOUT": "3", "MANTIS_LLM_MAX_PATIENCE_SECONDS": "3"})
        with patch.dict(os.environ, env, clear=True), \
             patch.object(mantis_main, "_confirm_work_plan", return_value=True), \
             patch.object(mantis_main, "execute_sub_task", side_effect=_fake_execute_sub_task), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            asyncio.run(
                mantis_main.pipeline(
                    scan_target=self.repo,
                    db_override=self.db,
                    model_override="openai/nonexistent",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    auto_configure=False,
                    resume_run_id=run,
                    no_memory=True,
                )
            )
        self.assertTrue(seen, "the planned campaign never ran")
        first = seen[0]
        self.assertEqual(first["target"], sub_a)
        self.assertEqual(first["prior_memory"], "")
        self.assertNotIn("PRIOR-RUN-MEMORY-MARKER", first["hypotheses"])
        self.assertIn("PLANNER-HYPOTHESIS-MARKER", first["hypotheses"])
        self.assertIn("CHAIN-MARKER", first["hypotheses"])
        self.assertIn(sub_b, first["hypotheses"])

    def test_imported_runs_never_take_over_bare_resume(self) -> None:
        from core.cost import run_known
        from core.knowledge import _import_runs

        real = "paused-real-run"
        record_run(self.db, real, "openai/m", metadata={"target_root": self.repo, "target": self.repo},
                   started="2026-01-01 00:00:00")
        export = Path(self.tmp, "export")
        export.mkdir()
        (export / "findings.jsonl").write_text(
            json.dumps({"run_id": "historic-run-2025", "title": "t", "filepath": "a.py"}) + "\n",
            encoding="utf-8",
        )
        (export / "runs.jsonl").write_text(
            json.dumps({"run_id": "historic-modeled", "model": "openai/old"}) + "\n", encoding="utf-8"
        )
        _import_runs(self.db, export / "runs.jsonl", export / "findings.jsonl", repo_root=self.repo)
        # The importer's other footprints, all stamped "now" under this repo:
        # a replayed coverage row, a finding under the sentinel id, and one
        # under the historic id.
        record_spend(self.db, "historic-run-2025", os.path.join(self.repo, "a.py"), "file-by-file",
                     tokens=0, metadata={"imported": True})
        record_spend(self.db, "historic-unflagged", os.path.join(self.repo, "b.py"), "file-by-file",
                     tokens=0, metadata={"imported": True})
        conn = sqlite3.connect(self.db)
        try:
            for rid in ("imported", "historic-run-2025"):
                conn.execute(
                    "INSERT INTO findings (run_id, filepath, title, severity, status) VALUES (?, ?, ?, 'LOW', 'new')",
                    (rid, os.path.join(self.repo, "a.py"), f"imp-{rid}"),
                )
            conn.commit()
        finally:
            conn.close()

        self.assertEqual(latest_run_id(self.db, self.repo), real)
        self.assertEqual(latest_run_id(self.db), real)
        for rid in ("historic-run-2025", "historic-modeled", "historic-unflagged", "imported"):
            self.assertEqual(run_known(self.db, rid), (False, ""), rid)
        self.assertEqual(run_known(self.db, real), (True, self.repo))

        # Importing must never flag a run that actually ran here.
        (export / "runs.jsonl").write_text(json.dumps({"run_id": real, "model": "openai/m"}) + "\n",
                                           encoding="utf-8")
        _import_runs(self.db, export / "runs.jsonl", repo_root=self.repo)
        self.assertEqual(latest_run_id(self.db, self.repo), real)
        self.assertTrue(run_known(self.db, real)[0])

    def test_latest_artifact_fallback_never_crosses_repo_root(self) -> None:
        from core.database import record_artifact
        from core.knowledge import _latest_artifact

        record_artifact(self.db, "rootless-run", "threat_model", "workspace/threat_model.json",
                        "FOREIGN", metadata={"resource": "/elsewhere/other_repo/svc"})
        record_artifact(self.db, "rootless-run", "threat_model", "workspace/threat_model.json",
                        "RELATIVE-ROOTLESS", metadata={"resource": "svc/rel"})
        conn = sqlite3.connect(self.db)
        try:
            self.assertIsNone(_latest_artifact(conn, artifact_type="threat_model", repo_root=self.repo))
        finally:
            conn.close()

        record_artifact(self.db, "rootless-run", "threat_model", "workspace/threat_model.json",
                        "OWN-PASS2", metadata={"resource": os.path.join(self.repo, "svc") + "#pass2"})
        conn = sqlite3.connect(self.db)
        try:
            self.assertEqual(_latest_artifact(conn, artifact_type="threat_model", repo_root=self.repo), "OWN-PASS2")
        finally:
            conn.close()

    def test_resumed_overflow_restart_survives_bad_rehydration_and_stays_flagged(self) -> None:
        class _Ev:
            def __init__(self) -> None:
                self.invocation_id = "inv-1"
                self.author = "researcher"
                self.actions = EventActions()

        class _Session:
            def __init__(self) -> None:
                self.events = [_Ev()]
                self.state: dict = {}

        class _Svc:
            async def get_session(self, **_kw: Any) -> Any:
                return _Session()

            async def delete_session(self, **_kw: Any) -> None:
                return None

            async def create_session(self, **_kw: Any) -> None:
                return None

        class _Runner:
            agent = None

        calls: list[Any] = []

        async def _drive(runner: Any, session_id: str, new_message: Any, resumed: Any, **_kw: Any) -> bool:
            calls.append(resumed)
            if resumed:
                raise ContextWindowExceededError("context window exceeded")
            return False

        # (resumed_mid_invocation, pre_pause_tokens) as rehydrated -> unchanged by the
        # restart. Neither case meets the spend row's resumed_tail predicate
        # (resumed and pre_pause_tokens == 0): the first records its full cost,
        # the second never resumed.
        for resumed_flag, pre_pause in ((True, 1234), (False, 0)):
            calls.clear()
            ctx = RunContext(jail_dir=self.repo, db_path="", target_file=self.repo, run_id="r")
            ctx.resumed_mid_invocation = resumed_flag
            ctx.pre_pause_tokens = pre_pause
            tok = current_run_context.set(ctx)
            try:
                with patch.object(mantis_main, "_rehydrate_session_metrics", side_effect=ValueError("malformed")), \
                     patch.object(mantis_main, "_drive_campaign", side_effect=_drive), \
                     patch.object(mantis_main, "_prepare_overflow_restart_handoff", return_value=""), \
                     redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
                    failed = asyncio.run(mantis_main.execute_sub_task(_Runner(), _Svc(), self.repo, "r", db_path=""))
            finally:
                current_run_context.reset(tok)
            self.assertFalse(failed)
            self.assertEqual(calls, ["inv-1", None])
            self.assertIn("RESUME METRICS WARNING", err.getvalue())
            self.assertEqual(ctx.resumed_mid_invocation, resumed_flag)
            self.assertEqual(ctx.pre_pause_tokens, pre_pause)
            self.assertFalse(ctx.resumed_mid_invocation and ctx.pre_pause_tokens == 0)


if __name__ == "__main__":
    unittest.main()

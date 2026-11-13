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

"""Phase-2 CL 4 regression suite: parallel prefix producer lock, calibrator
campaign scoping, finalized resume ledger & cumulative llm_calls, multi-pass
active lineage summary dedupe, synthesizer operator config & strict topology
gates, single-use state verdicts, SARIF/diversity result surfaces, GCE/remote/
microsandbox lifecycle guards, and delta-only workflow.local.json updates."""

from __future__ import annotations

import asyncio
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase, mock

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from google.adk.events.event import Event, EventActions, NodeInfo  # noqa: E402
from google.adk.models.llm_response import LlmResponse  # noqa: E402
from google.adk.workflow import DEFAULT_ROUTE  # noqa: E402
from google.genai import types  # noqa: E402

import core.diversity as diversity_mod  # noqa: E402
import core.environments.microsandbox_env as msb_mod  # noqa: E402
import core.graph_loader as gl  # noqa: E402
import core.sarif as sarif_mod  # noqa: E402
import main as mantis_main  # noqa: E402
import scripts.configure as configure_mod  # noqa: E402
import scripts.launch as launch_mod  # noqa: E402
import tools.research_tools as rt  # noqa: E402
from core.budget import BudgetConfig, BudgetController, CampaignBudgetScope  # noqa: E402
from core.context import RunContext, current_run_context  # noqa: E402
from core.cost import latest_run_id, record_spend  # noqa: E402
from core.database import (  # noqa: E402
    init_db,
    read_artifact,
    record_artifact,
    record_run,
    write_findings,
)
from core.environments.gce_env import GceEnvironment  # noqa: E402
from core.environments.microsandbox_env import MicrosandboxEnvironment  # noqa: E402
from core.environments.remote_env import RemoteTargetEnvironment  # noqa: E402
from core.synthesizer import ResearchGraphSynthesizer  # noqa: E402


class _DummyLlmRequest:
    def __init__(self, system_instruction: str = "Base stage prompt.") -> None:
        self.config = SimpleNamespace(system_instruction=system_instruction)
        self.appended: list[str] = []

    def append_instructions(self, blocks: list[str]) -> None:
        self.appended.extend(blocks)
        self.config.system_instruction += "".join(blocks)


class TestParallelPrefixAndCalibrator(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="mantis_p2_cl4_prefix_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = os.path.realpath(os.path.join(self.tmp, "repo"))
        for sub in ("services/auth", "services/billing", "services/orders"):
            d = Path(self.repo) / sub
            d.mkdir(parents=True, exist_ok=True)
            (d / "handler.py").write_text("def handle(x):\n    return x\n", encoding="utf-8")
        self.db = os.path.join(self.tmp, "knowledge.db")
        init_db(self.db)

    async def test_prefix_reuse_inflight_event_serializes_parallel_slices_and_pass_scoping(self) -> None:
        before, after = gl._make_prefix_reuse_callbacks("architect")
        shared_runs: dict = {}
        producer_calls = 0

        async def _run_slice(slice_rel: str, pass_index: int = 1) -> str:
            nonlocal producer_calls
            target = os.path.join(self.repo, slice_rel)
            ctx = RunContext(
                jail_dir=self.repo,
                db_path=self.db,
                target_file=target,
                artifact_resource=(f"{target}#pass{pass_index}" if pass_index > 1 else target),
                run_id="run-par-prefix",
                scan_mode="cross-functional",
                parallel_workers=3,
                shared_prefix_runs=shared_runs,
                pass_index=pass_index,
            )
            tok = current_run_context.set(ctx)
            try:
                res = before()
                if asyncio.iscoroutine(res) or asyncio.isfuture(res):
                    res = await res
                if res is not None:
                    return res.parts[0].text
                producer_calls += 1
                await asyncio.sleep(0.04)
                record_artifact(
                    self.db,
                    ctx.run_id,
                    "summary",
                    "workspace/.structured/summary.json",
                    json.dumps({"architecture": f"repo-wide-pass-{pass_index}"}),
                    metadata={"resource": ctx.artifact_resource or target},
                )
                after_res = after()
                if asyncio.iscoroutine(after_res):
                    await after_res
                return f"produced:{slice_rel}:pass{pass_index}"
            finally:
                current_run_context.reset(tok)

        outputs = await asyncio.gather(
            _run_slice("services/auth", 1),
            _run_slice("services/billing", 1),
            _run_slice("services/orders", 1),
        )
        self.assertEqual(producer_calls, 1, f"Expected 1 cold LLM producer across 3 slices, got {producer_calls}: {outputs}")
        reused = [o for o in outputs if "Reused the summary artifact" in o]
        self.assertEqual(len(reused), 2, outputs)
        for sub in ("services/auth", "services/billing", "services/orders"):
            art = read_artifact(
                self.db,
                artifact_type="summary",
                run_id="run-par-prefix",
                resource=os.path.join(self.repo, sub),
            )
            self.assertIn("repo-wide-pass-1", str(art))

        # Pass 2 under --passes 2 must produce a fresh prefix artifact rather than reusing Pass 1's.
        out_p2 = await _run_slice("services/auth", 2)
        self.assertEqual(producer_calls, 2)
        self.assertTrue(out_p2.startswith("produced:"))

        # Dead/empty producer recovery: if Slice 1 finishes with an empty "{}" artifact,
        # Slice 2 produces a valid summary and replaces the dead producer entry so Slice 3 reuses Slice 2!
        before_dead, after_dead = gl._make_prefix_reuse_callbacks("architect")
        dead_shared: dict = {}
        dead_calls = 0
        for idx_s, (sl_rel, body_txt) in enumerate(
            [
                ("services/auth", "{}"),
                ("services/billing", json.dumps({"architecture": "recovered-by-slice-2"})),
                ("services/orders", json.dumps({"architecture": "should-not-run"})),
            ],
            1,
        ):
            t_dir = os.path.join(self.repo, sl_rel)
            c_dead = RunContext(
                jail_dir=self.repo,
                db_path=self.db,
                target_file=t_dir,
                run_id="run-dead-producer",
                scan_mode="cross-functional",
                parallel_workers=1,
                shared_prefix_runs=dead_shared,
            )
            tk = current_run_context.set(c_dead)
            try:
                b_out = before_dead()
                if asyncio.iscoroutine(b_out):
                    b_out = await b_out
                if b_out is None:
                    dead_calls += 1
                    record_artifact(
                        self.db,
                        c_dead.run_id,
                        "summary",
                        "workspace/.structured/summary.json",
                        body_txt,
                        metadata={"resource": t_dir},
                    )
                    after_dead()
                else:
                    self.assertEqual(idx_s, 3)
                    self.assertIn("Reused the summary artifact", b_out.parts[0].text)
            finally:
                current_run_context.reset(tk)
        self.assertEqual(dead_calls, 2, "Slice 3 must reuse Slice 2 after Slice 1 recorded empty artifact")

        # Same-task node retry: the producing attempt failed (no after()), and
        # ADK retries the node in the SAME task. The retry must run the stage
        # again instead of awaiting its own in-flight claim forever.
        before_rt, _after_rt = gl._make_prefix_reuse_callbacks("architect")
        rt_ctx = RunContext(
            jail_dir=self.repo,
            db_path=self.db,
            target_file=os.path.join(self.repo, "services/auth"),
            run_id="run-retry-self",
            scan_mode="cross-functional",
            parallel_workers=1,
            shared_prefix_runs={},
        )
        tk_rt = current_run_context.set(rt_ctx)
        try:
            self.assertIsNone(before_rt(), "attempt 1 claims the in-flight slot and runs")
            retry_res = before_rt()
            self.assertFalse(asyncio.iscoroutine(retry_res), "retry must not await its own claim")
            self.assertIsNone(retry_res, "retry of the producer runs the stage again")
        finally:
            current_run_context.reset(tk_rt)

    async def test_shared_prefix_stages_withhold_slice_narrowing_directive_in_cross_functional_mode(self) -> None:
        slice_dir = os.path.join(self.repo, "services/auth")
        narrow_directive = (
            "Assigned Campaign Target Scope: 'services/auth/' "
            "(subsystem slice; read_file and list_files operate across the repository root, "
            "but focus your audit on this slice)."
        )
        ctx = RunContext(
            jail_dir=self.repo,
            db_path=self.db,
            target_file=slice_dir,
            run_id="run-prefix-dir",
            scan_mode="cross-functional",
            campaign_directive=narrow_directive,
        )
        tok = current_run_context.set(ctx)
        try:
            arch_req = _DummyLlmRequest()
            tm_req = _DummyLlmRequest()
            res_req = _DummyLlmRequest()
            gl._make_campaign_directive_before_model_callback("architect")(None, arch_req)
            gl._make_campaign_directive_before_model_callback("threat_modeler")(None, tm_req)
            gl._make_campaign_directive_before_model_callback("researcher")(None, res_req)

            ctx.active_node = "architect"
            arch_files = json.loads(await rt.list_files(""))
            ctx.active_node = "threat_modeler"
            tm_files = json.loads(await rt.list_files(""))
            ctx.active_node = "researcher"
            res_files = json.loads(await rt.list_files(""))
        finally:
            current_run_context.reset(tok)

        self.assertNotIn("Assigned Campaign Target Scope: 'services/auth/'", arch_req.config.system_instruction)
        self.assertNotIn("Assigned Campaign Target Scope: 'services/auth/'", tm_req.config.system_instruction)
        self.assertIn("list_files('.')", arch_req.config.system_instruction)
        self.assertIn("list_files('.')", tm_req.config.system_instruction)
        self.assertIn("Assigned Campaign Target Scope: 'services/auth/'", res_req.config.system_instruction)
        expected_all = [
            "services/auth/handler.py",
            "services/billing/handler.py",
            "services/orders/handler.py",
        ]
        self.assertEqual(arch_files, expected_all)
        self.assertEqual(tm_files, expected_all)
        self.assertEqual(res_files, ["services/auth/handler.py"])

    async def test_calibrator_threat_model_read_scoped_to_active_campaign(self) -> None:
        slice_a = os.path.join(self.repo, "services/auth")
        slice_b = os.path.join(self.repo, "services/billing")
        write_findings(
            self.db,
            slice_a,
            [
                {
                    "title": "Auth bypass in token parser",
                    "severity": "HIGH",
                    "status": "static_confirmed",
                    "description": "Unchecked signature flag",
                    "line_numbers": [10],
                    "cwe": "CWE-287",
                    "filepath": "services/auth/handler.py",
                }
            ],
            run_id="run-cal-scope",
        )
        record_artifact(
            self.db,
            "run-cal-scope",
            "threat_model",
            "workspace/.structured/threat_model.json",
            json.dumps({"threats": ["BILLING_SIBLING_ONLY_THREAT_LEAK"]}),
            metadata={"resource": slice_b},
        )

        captured_prompts: list[str] = []

        class _CaptureCalibLlm:
            async def generate_content_async(self, llm_req, stream: bool = False):
                txt = "\n".join(
                    str(getattr(p, "text", "") or "")
                    for c in (getattr(llm_req, "contents", None) or [])
                    for p in (getattr(c, "parts", None) or [])
                )
                captured_prompts.append(txt)
                payload = json.dumps(
                    {
                        "finding_id": 1,
                        "mantis_risk_score": 7.5,
                        "priority": "HIGH",
                        "impact_score": 4,
                        "likelihood_score": 4,
                        "inferred_exposure": "INTERNET_FACING",
                        "reasoning": "Verified auth flaw.",
                    }
                )
                yield LlmResponse(
                    content=types.Content(role="model", parts=[types.Part.from_text(text=payload)]),
                    finish_reason=types.FinishReason.STOP,
                )

        cal_node = gl.create_calibrator_node("calibrator", _CaptureCalibLlm(), "Calibrate findings.")
        fake_adk_ctx = SimpleNamespace(
            state={"db_path": self.db, "run_id": "run-cal-scope", "filepath": slice_a}
        )
        tok = current_run_context.set(None)
        try:
            with redirect_stdout(io.StringIO()):
                await cal_node._unwrapped_func(fake_adk_ctx, "input")
        finally:
            current_run_context.reset(tok)

        self.assertEqual(len(captured_prompts), 1)
        self.assertNotIn("BILLING_SIBLING_ONLY_THREAT_LEAK", captured_prompts[0])


class TestResumeFinalizedLlmCallsAndPassSummary(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="mantis_p2_cl4_resume_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = os.path.realpath(os.path.join(self.tmp, "repo"))
        os.makedirs(self.repo, exist_ok=True)
        Path(self.repo, "app.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
        self.db = os.path.join(self.tmp, "knowledge.db")
        init_db(self.db)

    def test_finalized_zero_finding_run_not_picked_by_bare_resume(self) -> None:
        from core.database import mark_run_finalized

        record_run(
            self.db,
            "run-paused-older",
            "openai/gpt-test",
            metadata={"target_root": self.repo, "target": self.repo, "finalized": False},
            started="2026-06-01 10:00:00",
        )
        record_run(
            self.db,
            "run-finished-clean",
            "openai/gpt-test",
            metadata={"target_root": self.repo, "target": self.repo},
            started="2026-06-01 11:00:00",
        )
        record_spend(
            self.db,
            "run-finished-clean",
            self.repo,
            "whole",
            tokens=1200,
            llm_calls=2,
            metadata={"failed": False},
        )
        mark_run_finalized(self.db, "run-finished-clean", finalized=True)

        # Bare --resume (latest_run_id) must skip the finalized zero-finding run and pick the paused run.
        self.assertEqual(latest_run_id(self.db, self.repo), "run-paused-older")

        # When ONLY finalized zero-finding runs exist, bare latest_run_id returns "" instead of a finished run.
        mark_run_finalized(self.db, "run-paused-older", finalized=True)
        self.assertEqual(latest_run_id(self.db, self.repo), "")

    def test_resume_rehydrates_prior_llm_calls_in_campaign_and_spend_report(self) -> None:
        from core.cost import prior_run_llm_calls

        run_id = "run-cum-calls"
        record_spend(
            self.db,
            run_id,
            os.path.join(self.repo, "a.py"),
            "file-by-file",
            tokens=5000,
            llm_calls=5,
            metadata={"failed": False},
        )
        self.assertEqual(prior_run_llm_calls(self.db, run_id), 5)

        # Mid-invocation session rehydration counts pre-pause model turns with usage_metadata.
        pre_events = [
            Event(
                invocation_id="inv-1",
                author="researcher",
                node_info=NodeInfo(path="mantis_vulnerability_pipeline@1/researcher@1"),
                content=types.Content(role="model", parts=[types.Part.from_text(text="turn 1")]),
                usage_metadata=types.GenerateContentResponseUsageMetadata(
                    prompt_token_count=1000, candidates_token_count=200, total_token_count=1200
                ),
            ),
            Event(
                invocation_id="inv-1",
                author="researcher",
                node_info=NodeInfo(path="mantis_vulnerability_pipeline@1/researcher@1"),
                content=types.Content(role="model", parts=[types.Part.from_text(text="turn 2")]),
                usage_metadata=types.GenerateContentResponseUsageMetadata(
                    prompt_token_count=1500, candidates_token_count=300, total_token_count=1800
                ),
            ),
        ]
        fake_session = SimpleNamespace(events=pre_events)
        fake_runner = SimpleNamespace(agent=SimpleNamespace(name="mantis_vulnerability_pipeline"))
        parent_ctrl = BudgetController(BudgetConfig(max_tokens=50000, max_llm_calls=4), run_id=run_id)
        scope_ctrl = CampaignBudgetScope(parent_ctrl)
        scope_ctrl.begin_campaign()
        ctx = RunContext(jail_dir=self.repo, db_path=self.db, target_file=self.repo, run_id=run_id)

        mantis_main._rehydrate_session_metrics(fake_session, fake_runner, scope_ctrl, ctx)
        self.assertEqual(ctx.pre_pause_llm_calls, 2)

        # Process makes 3 new LLM calls (under per-process max_llm_calls=4) and writes spend.json:
        # spend.json must report cumulative 5 (prior campaign) + 2 (pre-pause slice) + 3 (this process) = 10!
        for _ in range(3):
            scope_ctrl.record_tokens(500)
        spend_path = os.path.join(self.tmp, "spend.json")
        saved_report = dict(mantis_main._SPEND_REPORT)
        try:
            mantis_main._SPEND_REPORT["controller"] = parent_ctrl
            mantis_main._SPEND_REPORT["prior_llm_calls"] = prior_run_llm_calls(self.db, run_id) + ctx.pre_pause_llm_calls
            mantis_main._SPEND_REPORT["nodes"] = []
            mantis_main._SPEND_REPORT["campaigns"] = {}
            self.assertTrue(mantis_main.write_spend_report(spend_path, 0))
            written = json.loads(Path(spend_path).read_text(encoding="utf-8"))
        finally:
            mantis_main._SPEND_REPORT.clear()
            mantis_main._SPEND_REPORT.update(saved_report)

        self.assertEqual(parent_ctrl.llm_calls, 3)
        self.assertEqual(written["llm_calls"], 10)

    def test_end_of_run_active_finding_count_deduplicates_by_lineage_across_passes(self) -> None:
        active_rows = [
            {"id": 1, "lineage_id": "lin-sqli-auth", "signature": "sig1", "status": "static_confirmed", "pass_index": 1},
            {"id": 2, "lineage_id": "lin-sqli-auth", "signature": "sig1", "status": "dynamic_confirmed", "pass_index": 2},
            {"id": 3, "lineage_id": "lin-xss-view", "signature": "sig2", "status": "confirmed", "pass_index": 2},
        ]
        self.assertEqual(mantis_main._count_unique_active_findings(active_rows), 2)


class TestSynthesizerSarifAndDiversity(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="mantis_p2_cl4_synth_")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_objective_synthesis_merges_workflow_local_defaults_while_unit_default_stays_hermetic(self) -> None:
        wf_path = os.path.join(self.tmp, "workflow.json")
        local_path = os.path.join(self.tmp, "workflow.local.json")
        base_wf = {
            "name": "base_wf",
            "config": {
                "db_path": "knowledge.db",
                "default_model": "vertex_ai/gemini-3.8-flash",
                "sandbox": {"type": "static-only", "options": {}},
            },
            "nodes": [{"id": "researcher", "type": "agent", "skill": "mantis-researcher", "tools": ["read_file", "report_findings"]}],
            "edges": [{"from": "START", "to": "researcher"}],
        }
        local_wf = {
            "config": {
                "default_model": "openai/gpt-4o",
                "api_base": "https://llm-gateway.corp.example/v1",
                "db_path": os.path.join(self.tmp, "operator_kb.db"),
                "timeout": 240.0,
                "reasoning_effort": "high",
                "exclude": ["third_party/**"],
                "evidence_sources": [{"name": "advisories", "path": "docs/sec.md"}],
                "custom_tools": [{"name": "check_acl", "kind": "query", "sql": "SELECT 1"}],
                "sandbox": {
                    "type": "gce",
                    "options": {"project": "sec-audit-proj", "zone": "us-east1-b"},
                },
            }
        }
        Path(wf_path).write_text(json.dumps(base_wf), encoding="utf-8")
        Path(local_path).write_text(json.dumps(local_wf), encoding="utf-8")

        # Default unit-test construction (load_local=False) stays hermetic.
        hermetic_synth = ResearchGraphSynthesizer(workflow_path=wf_path)
        hermetic_spec = hermetic_synth.synthesize(objective="Audit web API endpoints")
        self.assertIsNone(hermetic_spec.config.api_base)
        self.assertNotEqual(hermetic_spec.config.default_model, "openai/gpt-4o")

        # Operator synthesis (load_local=True) inherits workflow.local.json settings,
        # while still stripping untrusted LLM-authored api_base.
        op_synth = ResearchGraphSynthesizer(workflow_path=wf_path, load_local=True)
        op_spec = op_synth.synthesize(objective="Audit auth logic")
        self.assertEqual(op_spec.config.default_model, "openai/gpt-4o")
        self.assertEqual(op_spec.config.api_base, "https://llm-gateway.corp.example/v1")
        self.assertEqual(op_spec.config.db_path, os.path.join(self.tmp, "operator_kb.db"))
        self.assertEqual(op_spec.config.timeout, 240.0)
        self.assertEqual(op_spec.config.reasoning_effort, "high")
        self.assertEqual(op_spec.config.exclude, ["third_party/**"])
        self.assertEqual(
            op_spec.config.model_dump().get("evidence_sources"),
            [{"name": "advisories", "path": "docs/sec.md"}],
        )
        self.assertEqual(
            op_spec.config.model_dump().get("custom_tools"),
            [{"name": "check_acl", "kind": "query", "sql": "SELECT 1"}],
        )
        self.assertEqual(op_spec.config.sandbox.type, "gce")
        self.assertEqual(op_spec.config.sandbox.options.get("project"), "sec-audit-proj")

        # LLM-authored api_base in raw spec must never override operator's api_base or inject SSRF URL.
        malicious_raw = {
            "name": "ssrf_attempt",
            "config": {"api_base": "https://evil.attacker.invalid/v1"},
            "nodes": [
                {"id": "analyzer", "type": "agent", "skill": "mantis-researcher", "tools": ["read_file", "report_findings"]},
                {"id": "reviewer", "type": "agent", "skill": "mantis-review", "tools": ["get_findings", "read_file"], "output_schema": "ReviewVerdict", "output_key": "verdict"},
                {"id": "review_decision", "type": "classifier", "routes": ["confirmed"], "max_visits": 1},
                {"id": "reporter", "type": "agent", "skill": "mantis-report", "tools": ["get_findings", "generate_report"]},
            ],
            "edges": [
                {"from": "START", "to": "analyzer"},
                {"from": "analyzer", "to": "reviewer"},
                {"from": "reviewer", "to": "review_decision"},
                {"from": "review_decision", "to": "reporter", "on": "confirmed"},
                {"from": "review_decision", "to": "analyzer", "on": "__DEFAULT__"},
            ],
        }
        sanitized_hermetic = hermetic_synth.sanitize_and_validate_spec(malicious_raw, objective="Audit API")
        self.assertIsNone(sanitized_hermetic.config.api_base)
        sanitized_op = op_synth.sanitize_and_validate_spec(malicious_raw, objective="Audit API")
        self.assertEqual(sanitized_op.config.api_base, "https://llm-gateway.corp.example/v1")

    def test_sanitize_and_validate_spec_rejects_multi_sink_and_default_route_in_list(self) -> None:
        synth = ResearchGraphSynthesizer()
        multi_sink_raw = {
            "name": "multi_sink_bad",
            "nodes": [
                {"id": "analyzer", "type": "agent", "skill": "mantis-researcher", "tools": ["read_file", "report_findings"]},
                {"id": "reviewer", "type": "agent", "skill": "mantis-review", "tools": ["get_findings"], "output_schema": "ReviewVerdict", "output_key": "verdict"},
                {"id": "decision", "type": "classifier", "routes": ["confirmed"], "max_visits": 1},
                {"id": "sink_one", "type": "agent", "skill": "mantis-report", "tools": ["get_findings", "generate_report"]},
                {"id": "sink_two", "type": "agent", "skill": "mantis-report", "tools": ["get_findings", "generate_report"]},
            ],
            "edges": [
                {"from": "START", "to": "analyzer"},
                {"from": "analyzer", "to": "reviewer"},
                {"from": "reviewer", "to": "decision"},
                {"from": "decision", "to": "sink_one", "on": "confirmed"},
                {"from": "decision", "to": "sink_two", "on": "__DEFAULT__"},
            ],
        }
        with self.assertRaises(ValueError) as ctx_ms:
            synth.sanitize_and_validate_spec(multi_sink_raw, objective="Audit sinks")
        self.assertIn("terminal sink", str(ctx_ms.exception).lower())

        default_in_list_raw = {
            "name": "default_list_bad",
            "nodes": [
                {"id": "analyzer", "type": "agent", "skill": "mantis-researcher", "tools": ["read_file", "report_findings"]},
                {"id": "reviewer", "type": "agent", "skill": "mantis-review", "tools": ["get_findings"], "output_schema": "ReviewVerdict", "output_key": "verdict"},
                {"id": "decision", "type": "classifier", "routes": ["confirmed"], "max_visits": 1},
                {"id": "reporter", "type": "agent", "skill": "mantis-report", "tools": ["get_findings", "generate_report"]},
            ],
            "edges": [
                {"from": "START", "to": "analyzer"},
                {"from": "analyzer", "to": "reviewer"},
                {"from": "reviewer", "to": "decision"},
                {"from": "decision", "to": "reporter", "on": ["confirmed", "__DEFAULT__"]},
            ],
        }
        with self.assertRaises(ValueError) as ctx_dl:
            synth.sanitize_and_validate_spec(default_in_list_raw, objective="Audit routes")
        self.assertIn("__DEFAULT__", str(ctx_dl.exception))

    async def test_classifier_consumes_session_state_verdict_single_use(self) -> None:
        c1 = gl.create_classifier("review_decision", ["confirmed"], max_visits=1)
        c2 = gl.create_classifier("downstream_decision", ["confirmed"], max_visits=1)

        shared_state: dict = {"verdict": {"route": "confirmed", "reason": "Confirmed by reviewer"}}
        ctx1 = SimpleNamespace(state=shared_state)
        ev1 = await c1._unwrapped_func(ctx1, "non-json prose output")
        self.assertEqual(ev1.actions.route if hasattr(ev1, "actions") and getattr(ev1.actions, "route", None) else getattr(ev1, "route", None), "confirmed")

        # Apply state delta as ADK session runner does between nodes.
        delta = getattr(getattr(ev1, "actions", None), "state_delta", None) or getattr(ev1, "state", None) or {}
        shared_state.update(delta)
        self.assertIsNone(shared_state.get("verdict"))

        ctx2 = SimpleNamespace(state=shared_state)
        ev2 = await c2._unwrapped_func(ctx2, "subsequent prose stage emitted no verdict")
        route2 = ev2.actions.route if hasattr(ev2, "actions") and getattr(ev2.actions, "route", None) else getattr(ev2, "route", None)
        self.assertEqual(route2, DEFAULT_ROUTE)

    def test_sarif_two_pass_max_rule_level_dynamic_confirmed_note_run_properties_and_atomic_write(self) -> None:
        findings = [
            {
                "title": "Minor SQL query issue",
                "description": "Low impact query construction",
                "filepath": "src/db.py",
                "line_numbers": [12],
                "severity": "LOW",
                "mantis_risk_score": 2.0,
                "cwe": "CWE-89",
                "status": "static_confirmed",
                "lineage_id": "lin-1",
            },
            {
                "title": "Critical RCE-adjacent SQL injection",
                "description": "Reached sink dynamically",
                "filepath": "src/admin_db.py",
                "line_numbers": [88],
                "severity": "CRITICAL",
                "mantis_risk_score": 9.6,
                "cwe": "CWE-89",
                "status": "dynamic_confirmed",
                "patch_status": "VERIFICATION_INCOMPLETE",
                "lineage_id": "lin-2",
            },
            {
                "title": "Unreviewed info leak",
                "description": "Raw candidate",
                "filepath": "src/info.py",
                "line_numbers": [5],
                "severity": "HIGH",
                "cwe": "CWE-200",
                "status": "reported",
                "lineage_id": "lin-3",
            },
        ]

        base_doc, skipped = sarif_mod.build_sarif(
            findings,
            scan_root=self.tmp,
            include_suppressed=False,
        )
        self.assertEqual(skipped, [])
        cwe89_base = next(r for r in base_doc["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "CWE-89")
        self.assertEqual(cwe89_base["defaultConfiguration"]["level"], "error")
        self.assertEqual(cwe89_base["properties"]["security-severity"], "9.6")

        doc, skipped = sarif_mod.build_sarif(
            findings,
            scan_root=self.tmp,
            include_suppressed=False,
            run_properties={"run_id": "r-sarif", "scan_mode": "whole", "sarif_scope": "run", "partial": False},
        )
        self.assertEqual(skipped, [])
        run0 = doc["runs"][0]
        self.assertEqual(run0["properties"]["run_id"], "r-sarif")
        self.assertEqual(run0["properties"]["scan_mode"], "whole")
        self.assertEqual(run0["properties"]["sarif_scope"], "run")
        self.assertEqual(run0["properties"]["partial"], False)
        self.assertEqual(run0["properties"]["untriaged_omitted"], 1)

        cwe89_rule = next(r for r in run0["tool"]["driver"]["rules"] if r["id"] == "CWE-89")
        self.assertEqual(cwe89_rule["defaultConfiguration"]["level"], "error")
        self.assertEqual(cwe89_rule["properties"]["security-severity"], "9.6")

        dyn_res = next(r for r in run0["results"] if "Critical RCE-adjacent" in r["message"]["text"])
        self.assertIn("reproduced: reached-sink evidence recorded", dyn_res["message"]["text"])

        # With include_suppressed=True, untriaged 'reported' finding gets level='note' AND its rule defaults to 'note'.
        doc_sup, _ = sarif_mod.build_sarif(findings, scan_root=self.tmp, include_suppressed=True)
        cwe200_rule = next(r for r in doc_sup["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "CWE-200")
        cwe200_res = next(r for r in doc_sup["runs"][0]["results"] if r["ruleId"] == "CWE-200")
        self.assertEqual(cwe200_res["level"], "note")
        self.assertEqual(cwe200_res["properties"].get("mantis/triage"), "untriaged")
        self.assertEqual(cwe200_rule["defaultConfiguration"]["level"], "note")

        # Atomic write_sarif: failure during json.dump must preserve existing destination file intact.
        out_sarif = os.path.join(self.tmp, "out.sarif")
        Path(out_sarif).write_text('{"sentinel": "intact"}\n', encoding="utf-8")
        with mock.patch("core.sarif.json.dump", side_effect=OSError("disk full mid-write")):
            with self.assertRaises(OSError):
                sarif_mod.write_sarif(out_sarif, findings[:1], scan_root=self.tmp)
        self.assertEqual(Path(out_sarif).read_text(encoding="utf-8"), '{"sentinel": "intact"}\n')
        leftover_tmps = [p for p in os.listdir(self.tmp) if p.endswith(".tmp")]
        self.assertEqual(leftover_tmps, [])

    def test_diversity_excludes_mitigated_and_archived_even_when_only_closed_rows_exist(self) -> None:
        only_closed = [
            {"filepath": "src/a.py", "status": "mitigated", "cwe": "CWE-89", "severity": "HIGH"},
            {"filepath": "src/b.py", "status": "archived", "cwe": "CWE-79", "severity": "MEDIUM"},
        ]
        self.assertEqual(diversity_mod.measure(only_closed), {"available": False})


class TestDynamicSandboxesAndOperatorConfig(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="mantis_p2_cl4_sb_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.local_repo = Path(self.tmp) / "local_repo"
        self.local_repo.mkdir(parents=True, exist_ok=True)
        (self.local_repo / "app.py").write_text("x = 1\n", encoding="utf-8")
        (self.local_repo / "other.py").write_text("y = 2\n", encoding="utf-8")
        deep_dir = self.local_repo / "a" / "b" / "c" / "d" / "e" / "f" / "g"
        deep_dir.mkdir(parents=True, exist_ok=True)
        (deep_dir / "Deep.java").write_text("class Deep {}\n", encoding="utf-8")

    async def test_gce_default_max_run_duration_2h_and_lazy_static_host_reads(self) -> None:
        gce = GceEnvironment(target_path=str(self.local_repo), project="unit-test-proj")
        self.assertEqual(gce.max_run_duration, "2h")

        with mock.patch.object(gce, "_run_gcloud", side_effect=AssertionError("gcloud must not run on lazy static read")):
            data = await gce.read_file("app.py")
            self.assertEqual(data, b"x = 1\n")
            listed = await gce.list_files("")
            self.assertIn("app.py", listed)
            self.assertIn("a/b/c/d/e/f/g/Deep.java", listed)
            self.assertFalse(gce._started)
            with self.assertRaises(FileNotFoundError):
                await gce.read_guest_file("app.py")

    async def test_remote_parallel_clamped_and_reset_runs_rebuild(self) -> None:
        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            clamped = mantis_main._resolve_effective_parallel(4, "remote")
            unchanged = mantis_main._resolve_effective_parallel(4, "microsandbox")
        self.assertEqual(clamped, 1)
        self.assertEqual(unchanged, 4)
        self.assertIn("remote", err_buf.getvalue().lower())

        remote_dir = Path(self.tmp) / "remote_reset_rebuild"
        remote_dir.mkdir(parents=True, exist_ok=True)
        (remote_dir / "svc.txt").write_text("clean_v1\n", encoding="utf-8")
        (remote_dir / "compiled.Artifact").write_text("clean_v1\n", encoding="utf-8")

        env = RemoteTargetEnvironment(
            target_path=str(self.local_repo),
            transport="exec",
            exec_argv=["/bin/sh", "-c"],
            workdir=str(remote_dir),
            reset_cmd="printf 'clean_v1\\n' > svc.txt",
            rebuild_cmd="cp svc.txt compiled.Artifact",
        )
        await env.initialize()
        await env.write_file("svc.txt", "patched_v2\n")
        await env.run_rebuild()
        self.assertEqual((remote_dir / "compiled.Artifact").read_text(encoding="utf-8"), "patched_v2\n")

        # Closing/resetting after target mutation must run reset_cmd AND rebuild_cmd so binary matches clean source!
        await env.close()
        self.assertEqual((remote_dir / "svc.txt").read_text(encoding="utf-8"), "clean_v1\n")
        self.assertEqual((remote_dir / "compiled.Artifact").read_text(encoding="utf-8"), "clean_v1\n")

    async def test_remote_write_file_stage_gate_transactional_rollback_and_read_your_writes_overlay(self) -> None:
        remote_dir = Path(self.tmp) / "remote_tx"
        remote_dir.mkdir(parents=True, exist_ok=True)
        (remote_dir / "app.py").write_text("x = 1\n", encoding="utf-8")
        (remote_dir / "other.py").write_text("y = 2\n", encoding="utf-8")

        env = RemoteTargetEnvironment(
            target_path=str(self.local_repo),
            transport="exec",
            exec_argv=["/bin/sh", "-c"],
            workdir=str(remote_dir),
            reset_cmd="printf 'x = 1\\n' > app.py",
            rebuild_cmd="python3 -m py_compile app.py && cp app.py .built_app.py",
        )
        db_p = os.path.join(self.tmp, "tx.db")
        init_db(db_p)

        # 1. Stage gate: researcher cannot mutate non-workspace target files.
        res_ctx = RunContext(
            jail_dir=str(self.local_repo),
            db_path=db_p,
            target_file=str(self.local_repo / "app.py"),
            run_id="r-tx",
            active_node="researcher",
            sandbox=env,
        )
        tok = current_run_context.set(res_ctx)
        try:
            denied = await rt.write_file("app.py", "x = 999\n")
            self.assertTrue(denied.startswith("Error:"), denied)
            self.assertEqual((remote_dir / "app.py").read_text(encoding="utf-8"), "x = 1\n")
        finally:
            current_run_context.reset(tok)

        # 2. Patcher writes valid code -> read-your-writes overlay serves mutated guest bytes while host stays untouched.
        patch_ctx = RunContext(
            jail_dir=str(self.local_repo),
            db_path=db_p,
            target_file=str(self.local_repo / "app.py"),
            run_id="r-tx",
            active_node="patcher",
            sandbox=env,
        )
        tok = current_run_context.set(patch_ctx)
        try:
            ok_write = await rt.write_file("app.py", "def safe():\n    return 42\n")
            self.assertIn("SUCCESS", ok_write)
            self.assertEqual((self.local_repo / "app.py").read_text(encoding="utf-8"), "x = 1\n")
            overlay_bytes = await env.read_file("app.py")
            self.assertEqual(overlay_bytes.decode("utf-8"), "def safe():\n    return 42\n")
            static_bytes = await env.read_file("other.py")
            self.assertEqual(static_bytes.decode("utf-8"), "y = 2\n")

            # 3. Broken edit failing rebuild_cmd rolls back remote app.py AND .built_app.py to prior working state!
            bad_write = await rt.write_file("app.py", "def broken(:\n")
            self.assertTrue(bad_write.startswith("Error:"), bad_write)
            self.assertEqual((remote_dir / "app.py").read_text(encoding="utf-8"), "def safe():\n    return 42\n")
            self.assertEqual((remote_dir / ".built_app.py").read_text(encoding="utf-8"), "def safe():\n    return 42\n")
            self.assertEqual((await env.read_file("app.py")).decode("utf-8"), "def safe():\n    return 42\n")
        finally:
            current_run_context.reset(tok)
            await env.close()

    async def test_microsandbox_ensure_lock_and_list_files_relative_paths_and_depth_25(self) -> None:
        create_calls = 0
        seen_cmds: list[str] = []
        many_deep_files = "\n".join(
            f"/workspace/sub/a/b/c/d/e/f/g/File{i:03d}.java" for i in range(450)
        )

        class _FakeSb:
            def __init__(self) -> None:
                self.fs = SimpleNamespace(
                    mkdir=mock.AsyncMock(),
                    copy_from_host=mock.AsyncMock(),
                    write=mock.AsyncMock(),
                )

            async def shell(self, cmd: str, cwd: str = "/workspace", timeout: float = 30.0):
                seen_cmds.append(cmd)
                return SimpleNamespace(stdout_text=many_deep_files + "\n", stderr_text="", exit_code=0)

            async def stop(self, timeout: int = 30) -> None:
                pass

            async def destroy(self, force: bool = True, timeout: int = 30) -> None:
                pass

        async def _fake_create(**kwargs):
            nonlocal create_calls
            create_calls += 1
            await asyncio.sleep(0.03)
            return _FakeSb()

        env = MicrosandboxEnvironment.__new__(MicrosandboxEnvironment)
        env.target_path = ""
        env.image = "mantis-sandbox:latest"
        env.timeout = 30.0
        env.memory = None
        env.cpus = None
        env._workdir = Path("/workspace")
        env._sb = None
        env._name = None
        env._stage_error = None
        env._lock = asyncio.Lock()

        with (
            mock.patch.object(msb_mod, "verify_network_none_policy"),
            mock.patch.object(msb_mod.MsbSandbox, "create", side_effect=_fake_create),
            mock.patch("core.poc_scaffold.mark_staged", new=mock.AsyncMock()),
        ):
            await asyncio.gather(env._ensure(), env._ensure(), env._ensure())
            self.assertEqual(create_calls, 1)

            listed = await env.list_files("sub")
            self.assertEqual(len(listed), 450)
            self.assertEqual(listed[0], "sub/a/b/c/d/e/f/g/File000.java")
            self.assertTrue(all(not p.startswith("..") and "TRUNCATION" not in p for p in listed))
            self.assertTrue(any("-maxdepth 25" in c for c in seen_cmds), seen_cmds)

    async def test_update_workflow_config_delta_only_and_skip_local_writes_on_no_auto_or_cli_sandbox(self) -> None:
        wf_path = os.path.join(self.tmp, "workflow.json")
        local_path = os.path.join(self.tmp, "workflow.local.json")
        base_wf = {
            "name": "base_wf",
            "config": {
                "db_path": "knowledge.db",
                "default_model": "vertex_ai/gemini-3.8-flash",
                "timeout": 180,
                "retry_attempts": 3,
                "sandbox": {"type": "static-only", "options": {}},
            },
            "nodes": [{"id": "researcher", "type": "agent", "skill": "mantis-researcher", "tools": ["read_file", "report_findings"]}],
            "edges": [{"from": "START", "to": "researcher"}],
        }
        Path(wf_path).write_text(json.dumps(base_wf), encoding="utf-8")

        # 1. Delta-only write: workflow.local.json stores ONLY updated keys, not frozen base keys.
        merged = configure_mod.update_workflow_config(
            wf_path, {"default_model": "openai/gpt-4o"}, save=True, save_tracked=False
        )
        self.assertEqual(merged["config"]["timeout"], 180)
        saved_local = json.loads(Path(local_path).read_text(encoding="utf-8"))
        self.assertEqual(saved_local, {"config": {"default_model": "openai/gpt-4o"}})

        os.unlink(local_path)

        # 2. Explicit CLI --sandbox override without --save-config must NEVER write workflow.local.json,
        # even when GCE project auto-resolution fills sandbox.options.project for this session.
        fake_caps = {
            "available_sandboxes": ["static-only", "gce"],
            "recommended_sandbox": "static-only",
            "gcp_project": "ephemeral-cli-proj",
            "vertex_project": "ephemeral-cli-proj",
            "microsandbox_image": "",
        }
        with (
            mock.patch.object(configure_mod, "detect_capabilities", return_value=fake_caps),
            mock.patch.object(configure_mod, "run_preflight_checks_async", new=mock.AsyncMock(return_value=(True, []))),
        ):
            cfg_cli_sb = await configure_mod.ensure_configured_async(
                workflow_path=wf_path,
                auto=True,
                overrides={"sandbox": {"type": "gce", "options": {}}},
                save=True,
                persist_overrides=False,
            )
            self.assertEqual(cfg_cli_sb["sandbox"]["type"], "gce")
            self.assertEqual(cfg_cli_sb["sandbox"]["options"]["project"], "ephemeral-cli-proj")
            self.assertFalse(os.path.exists(local_path), "CLI --sandbox without --save-config wrote workflow.local.json!")

            # 3. --no-auto-configure (auto=False) must NEVER write workflow.local.json either.
            await configure_mod.ensure_configured_async(
                workflow_path=wf_path,
                auto=False,
                overrides={"default_model": "openai/gpt-4o-mini"},
                save=True,
                persist_overrides=False,
            )
            self.assertFalse(os.path.exists(local_path), "--no-auto-configure wrote workflow.local.json!")


if __name__ == "__main__":
    unittest.main()

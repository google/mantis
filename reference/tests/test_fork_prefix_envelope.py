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

"""End-to-end envelope, INV-2 isolation, tool-permission, and verdict routing
tests for Shared-Prefix Stem + Independent Forked Judges workflows:
  - Option A: reference/workflow.fork_explorer.json
  - Option B: reference/workflow.fork_planner.json
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from google.adk.events import Event  # noqa: E402
from google.adk.models import LlmResponse  # noqa: E402
from google.adk.models.lite_llm import _get_completion_inputs  # noqa: E402
from google.adk.runners import InMemoryRunner  # noqa: E402
from google.genai import types  # noqa: E402

import core.graph_loader as gl  # noqa: E402
from core.budget import BudgetConfig, BudgetController  # noqa: E402
from core.config import (  # noqa: E402
    FINDINGS_SNAPSHOT_HEADER,
    ExtendedCriticVerdict,
    ExtendedReviewVerdict,
    ResilientLiteLlm,
)
from core.context import RunContext, current_run_context  # noqa: E402
from core.database import init_db, read_findings, record_learning  # noqa: E402
from core.environments.static_env import StaticOnlyEnvironment  # noqa: E402
from core.prompts import PREFIX_GROUP_BASE_INSTRUCTION  # noqa: E402
from tools import research_tools as rt  # noqa: E402


def _serialize_content(c: types.Content) -> dict[str, Any]:
    """Canonical byte-accurate serialization of a `types.Content` (roles, text,
    thought flags, thought_signatures, function_call ids/args, function_responses)."""
    parts_out = []
    for p in getattr(c, "parts", None) or []:
        sig = getattr(p, "thought_signature", None)
        if isinstance(sig, bytes):
            sig_repr: Any = sig.hex()
        else:
            sig_repr = sig
        fc = getattr(p, "function_call", None)
        fr = getattr(p, "function_response", None)
        parts_out.append({
            "text": getattr(p, "text", None),
            "thought": bool(getattr(p, "thought", False)),
            "thought_signature": sig_repr,
            "function_call": (
                {"id": fc.id, "name": fc.name, "args": dict(fc.args or {})}
                if fc is not None
                else None
            ),
            "function_response": (
                {"id": fr.id, "name": fr.name, "response": fr.response}
                if fr is not None
                else None
            ),
        })
    return {"role": getattr(c, "role", None), "parts": parts_out}


def _serialize_tools(llm_request: Any) -> str:
    """Canonical JSON serialization of `llm_request.config.tools`."""
    raw_tools = getattr(getattr(llm_request, "config", None), "tools", None) or []
    dumped = [t.model_dump(mode="json", exclude_none=True) for t in raw_tools]
    return json.dumps(dumped, sort_keys=True, separators=(",", ":"))


def _iter_workflow_agents(workflow: Any) -> dict[str, Any]:
    agents: dict[str, Any] = {}
    for edge in workflow.edges:
        for n in (getattr(edge, "from_node", None), getattr(edge, "to_node", None)):
            ag = getattr(n, "agent", n)
            name = getattr(ag, "name", None)
            if name and hasattr(ag, "before_model_callback"):
                agents[name] = ag
    return agents


class _ScriptedWireRecorder:
    """Captures exact wire-dispatched `LlmRequest` envelopes inside `ResilientLiteLlm`
    while driving a full multi-stage ADK Workflow campaign with real SQLite tools."""

    def __init__(self, target_dir: str):
        self.target_dir = target_dir
        self.requests_by_stage: dict[str, list[dict[str, Any]]] = {}
        self._call_seq = 0

    def _active_stage_of(self, llm_request: Any) -> str:
        for c in reversed(getattr(llm_request, "contents", None) or []):
            if getattr(c, "role", "") != "user":
                continue
            for p in getattr(c, "parts", None) or []:
                txt = getattr(p, "text", None) or ""
                if gl.ACTIVE_STAGE_HEADER_PREFIX in txt:
                    after = txt.split(gl.ACTIVE_STAGE_HEADER_PREFIX, 1)[1]
                    return after.split("]", 1)[0].strip()
        ctx = current_run_context.get()
        return str(getattr(ctx, "active_node", "") or "unknown")

    async def dispatch(self, llm_self: ResilientLiteLlm, llm_request: Any, stream: bool = False):
        if not llm_self._preserve_system_prefix:
            llm_self._inject_stage_turn_reminder(llm_request)
            llm_self._inject_active_findings_state(llm_request)

        # Also capture LiteLLM-converted wire messages & tools to prove provider-level byte equality.
        wire_msgs, wire_tools, wire_rf, _, _ = await _get_completion_inputs(
            llm_request, model="vertex_ai/gemini-3.8-flash"
        )
        raw_ctx_active_node = str(getattr(current_run_context.get(), "active_node", "") or "")
        stage = self._active_stage_of(llm_request)
        # Non-prefix stages (e.g. architect/threat_modeler/planner in Option A, deduplicator)
        # carry their stage identity in system_instruction.
        sys_inst = str(getattr(getattr(llm_request, "config", None), "system_instruction", "") or "")
        if stage == "unknown" or gl.ACTIVE_STAGE_HEADER_PREFIX not in json.dumps(
            [getattr(p, "text", "") for c in (llm_request.contents or []) for p in (c.parts or [])]
        ):
            if (
                "FindingCalibration" in str(llm_request.tools_dict.get("set_model_response", ""))
                or "mantis_risk_score" in str(llm_request.contents)
                or "Risk Calibrator" in sys_inst
                or "calibrate" in sys_inst.lower()
            ):
                stage = "calibrator"
            else:
                for cand_name, marker in (
                    ("architect", "System Architect stage"),
                    ("threat_modeler", "Threat Modeler stage"),
                    ("planner", "Security Planner stage"),
                    ("deduplicator", "Finding Deduplicator stage"),
                    ("reflector", "Engineering Reflector stage"),
                    ("reporter", "Security Reporter stage"),
                ):
                    if marker in sys_inst:
                        stage = cand_name
                        break

        snap = {
            "raw_ctx_active_node": raw_ctx_active_node,
            "system_instruction": sys_inst,
            "tools_json": _serialize_tools(llm_request),
            "tool_names": [
                fd.name
                for t in (getattr(llm_request.config, "tools", None) or [])
                for fd in (getattr(t, "function_declarations", None) or [])
            ],
            "contents": [_serialize_content(c) for c in (llm_request.contents or [])],
            "wire_messages_json": [json.dumps(m, sort_keys=True, default=str) for m in wire_msgs],
            "wire_tools_json": json.dumps(wire_tools, sort_keys=True, default=str),
            "wire_response_format": wire_rf,
        }
        self.requests_by_stage.setdefault(stage, []).append(snap)

        turn_num = len(self.requests_by_stage[stage])
        self._call_seq += 1
        cid = f"call_{stage}_{self._call_seq}"
        sig_bytes = f"sig_{stage}_{turn_num}".encode("utf-8")

        if stage == "architect":
            if turn_num == 1:
                yield LlmResponse(content=types.Content(role="model", parts=[
                    types.Part(text=f"architect thinking {turn_num}", thought=True),
                    types.Part(
                        function_call=types.FunctionCall(name="read_file", id=cid, args={"filepath": "routes/login.py"}),
                        thought_signature=sig_bytes,
                    ),
                ]))
                return
            if turn_num == 2:
                yield LlmResponse(content=types.Content(role="model", parts=[
                    types.Part(text="architect recording summary", thought=True),
                    types.Part(
                        function_call=types.FunctionCall(
                            name="record_summary",
                            id=cid,
                            args={"summary": {"overview": "Express/Python login & health service", "key_modules": ["routes/login.py"], "tech_stack": ["python"]}},
                        ),
                        thought_signature=sig_bytes,
                    ),
                ]))
                return
            yield LlmResponse(content=types.Content(role="model", parts=[
                types.Part(text="architect final thought", thought=True),
                types.Part(text="Architecture summary recorded."),
            ]))
            return

        if stage == "threat_modeler":
            if turn_num == 1:
                yield LlmResponse(content=types.Content(role="model", parts=[
                    types.Part(text="tm thinking", thought=True),
                    types.Part(
                        function_call=types.FunctionCall(
                            name="record_threat_model",
                            id=cid,
                            args={"threat_model": {"entry_points": ["POST /login"], "trust_boundaries": ["HTTP body -> SQLite"], "threats": ["SQLi in login"]}},
                        ),
                        thought_signature=sig_bytes,
                    ),
                ]))
                return
            yield LlmResponse(content=types.Content(role="model", parts=[
                types.Part(text="tm done thought", thought=True),
                types.Part(text="Threat model recorded."),
            ]))
            return

        if stage == "planner":
            if turn_num == 1:
                yield LlmResponse(content=types.Content(role="model", parts=[
                    types.Part(text="planner reading sink", thought=True),
                    types.Part(
                        function_call=types.FunctionCall(name="read_file", id=cid, args={"filepath": "routes/admin.py"}),
                        thought_signature=sig_bytes,
                    ),
                ]))
                return
            if turn_num == 2:
                yield LlmResponse(content=types.Content(role="model", parts=[
                    types.Part(text="planner saving plan", thought=True),
                    types.Part(
                        function_call=types.FunctionCall(
                            name="record_plan",
                            id=cid,
                            args={"plan": {"investigations": [{"title": "Audit SQLi & auth", "target_files": ["routes/login.py", "routes/admin.py"]}]}},
                        ),
                        thought_signature=sig_bytes,
                    ),
                ]))
                return
            yield LlmResponse(content=types.Content(role="model", parts=[
                types.Part(text="planner complete thought", thought=True),
                types.Part(text="Audit plan recorded for login and admin routes."),
            ]))
            return

        if stage == "explorer":
            if turn_num == 1:
                yield LlmResponse(content=types.Content(role="model", parts=[
                    types.Part(text="explorer reading login entrypoint", thought=True),
                    types.Part(
                        function_call=types.FunctionCall(name="read_file", id=cid, args={"filepath": "routes/login.py"}),
                        thought_signature=sig_bytes,
                    ),
                ]))
                return
            if turn_num == 2:
                yield LlmResponse(content=types.Content(role="model", parts=[
                    types.Part(text="explorer reading admin route", thought=True),
                    types.Part(
                        function_call=types.FunctionCall(name="read_file", id=cid, args={"filepath": "routes/admin.py"}),
                        thought_signature=sig_bytes,
                    ),
                ]))
                return
            yield LlmResponse(content=types.Content(role="model", parts=[
                types.Part(text="explorer neutral wrap-up", thought=True),
                types.Part(text="Neutral code-path summary: routes/login.py executes SQL; routes/admin.py checks role."),
            ]))
            return

        if stage == "researcher":
            if turn_num == 1:
                yield LlmResponse(content=types.Content(role="model", parts=[
                    types.Part(text="RESEARCHER_PRIVATE_THOUGHT_DO_NOT_LEAK", thought=True),
                    types.Part(
                        function_call=types.FunctionCall(
                            name="report_findings",
                            id=cid,
                            args={
                                "report": {
                                    "findings": [
                                        {
                                            "title": "SQL Injection in login_user",
                                            "severity": "CRITICAL",
                                            "description": "RESEARCHER_SECRET_PROSE_MARKER_SQLI unparameterized query in login_user",
                                            "filepath": "routes/login.py",
                                            "line_numbers": [5],
                                            "code_paths": ["routes/login.py:5:login_user"],
                                            "cwe": "CWE-89",
                                        },
                                        {
                                            "title": "Bogus claim in admin_panel",
                                            "severity": "MEDIUM",
                                            "description": "RESEARCHER_SECRET_PROSE_MARKER_FP false alarm on admin_panel",
                                            "filepath": "routes/admin.py",
                                            "line_numbers": [4],
                                            "code_paths": ["routes/admin.py:4:admin_panel"],
                                            "cwe": "CWE-285",
                                        },
                                        {
                                            "title": "Dead helper SQL query",
                                            "severity": "HIGH",
                                            "description": "RESEARCHER_SECRET_PROSE_MARKER_DEAD unreachable dead_query",
                                            "filepath": "routes/login.py",
                                            "line_numbers": [8],
                                            "code_paths": ["routes/login.py:8:dead_query"],
                                            "cwe": "CWE-89",
                                        },
                                    ]
                                }
                            },
                        ),
                        thought_signature=sig_bytes,
                    ),
                ]))
                return
            yield LlmResponse(content=types.Content(role="model", parts=[
                types.Part(text="RESEARCHER_FINAL_TRANSCRIPT_MARKER: reported 3 candidate findings."),
            ]))
            return

        if stage == "deduplicator":
            yield LlmResponse(content=types.Content(role="model", parts=[
                types.Part(text="DEDUPLICATOR_TRANSCRIPT_MARKER: no duplicate findings to merge."),
            ]))
            return

        if stage == "reviewer":
            if turn_num == 1:
                yield LlmResponse(content=types.Content(role="model", parts=[
                    types.Part(text="REVIEWER_PRIVATE_THOUGHT", thought=True),
                    types.Part(
                        function_call=types.FunctionCall(name="get_findings", id=cid, args={}),
                        thought_signature=sig_bytes,
                    ),
                ]))
                return
            ctx = current_run_context.get()
            rows = sorted(read_findings(ctx.db_path, run_id=ctx.run_id), key=lambda r: int(r["id"]))
            f_sqli = next(int(r["id"]) for r in rows if "login_user" in r["title"])
            f_fp = next(int(r["id"]) for r in rows if "admin_panel" in r["title"])
            f_dead = next(int(r["id"]) for r in rows if "Dead helper" in r["title"])
            # Deliberately wrap raw JSON in markdown fences to exercise ResilientLiteLlm salvage!
            verdict_json = json.dumps({
                "route": "confirmed",
                "reason": "REVIEWER_VERDICT_PROSE_MARKER: login_user and dead_query confirmed; admin_panel guarded.",
                "finding_verdicts": [
                    {"finding_id": f_sqli, "route": "confirmed", "reason": "Direct string interpolation in SQL."},
                    {"finding_id": f_fp, "route": "false_positive", "reason": "Strict role check blocks non-admins."},
                    {"finding_id": f_dead, "route": "confirmed", "reason": "Raw SQL sink present."},
                ],
            })
            yield LlmResponse(content=types.Content(role="model", parts=[
                types.Part(text=f"```json\n{verdict_json}\n```"),
            ]))
            return

        if stage == "critic":
            if turn_num == 1:
                yield LlmResponse(content=types.Content(role="model", parts=[
                    types.Part(text="CRITIC_PRIVATE_THOUGHT", thought=True),
                    types.Part(
                        function_call=types.FunctionCall(name="get_findings", id=cid, args={}),
                        thought_signature=sig_bytes,
                    ),
                ]))
                return
            ctx = current_run_context.get()
            rows = sorted(read_findings(ctx.db_path, run_id=ctx.run_id), key=lambda r: int(r["id"]))
            f_sqli = next(int(r["id"]) for r in rows if "login_user" in r["title"])
            f_dead = next(int(r["id"]) for r in rows if "Dead helper" in r["title"])
            verdict_json = json.dumps({
                "route": "viable",
                "reason": "login_user reachable via HTTP; dead_query has zero callers.",
                "finding_verdicts": [
                    {"finding_id": f_sqli, "route": "viable", "reason": "Reachable from POST /login."},
                    {"finding_id": f_dead, "route": "non_viable", "reason": "Dead helper never called."},
                ],
            })
            yield LlmResponse(content=types.Content(role="model", parts=[
                types.Part(text=verdict_json),
            ]))
            return

        # Calibrator / reflector / reporter
        if "FindingCalibration" in str(llm_request.tools_dict.get("set_model_response", "")) or "mantis_risk_score" in str(llm_request.contents):
            yield LlmResponse(content=types.Content(role="model", parts=[
                types.Part(text=json.dumps({
                    "finding_id": 1,
                    "mantis_risk_score": 9.2,
                    "priority": "CRITICAL",
                    "impact_score": 5,
                    "likelihood_score": 4,
                    "inferred_exposure": "EXPOSED",
                    "reasoning": "Unauthenticated SQL injection.",
                    "executive_summary": "Critical SQLi in login_user.",
                })),
            ]))
            return

        yield LlmResponse(content=types.Content(role="model", parts=[
            types.Part.from_text(text="NO_ENTRY" if stage == "reflector" else "Stage completed."),
        ]))


class TestForkPrefixEnvelope(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_fork_env_")
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(self.repo, "routes"), exist_ok=True)
        Path(self.repo, "routes", "login.py").write_text(
            "import sqlite3\n\n"
            "def login_user(conn, username, password):\n"
            "    q = f\"SELECT * FROM users WHERE name='{username}' AND pw='{password}'\"\n"
            "    return conn.execute(q).fetchall()\n\n"
            "def dead_query(conn, raw):\n"
            "    return conn.execute('SELECT ' + raw).fetchall()\n",
            encoding="utf-8",
        )
        Path(self.repo, "routes", "admin.py").write_text(
            "def admin_panel(user):\n"
            "    if getattr(user, 'role', None) != 'admin':\n"
            "        raise PermissionError('denied')\n"
            "    return {'ok': True}\n",
            encoding="utf-8",
        )

    async def asyncTearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _materialize_variant_path(self, variant_name: str) -> Path:
        base_raw = json.loads((_REF_ROOT / "workflow.json").read_text(encoding="utf-8"))
        if variant_name == "workflow.json":
            return _REF_ROOT / "workflow.json"
        if variant_name == "option_a_explorer":
            # Option A: isolated explorer-only stem (architect/threat_modeler/planner outside prefix_group)
            for nd in base_raw["nodes"]:
                if nd["id"] in ("architect", "threat_modeler", "planner"):
                    nd.pop("prefix_group", None)
                    nd.pop("fork_from", None)
                elif nd["id"] == "explorer":
                    nd.pop("fork_from", None)
                    nd["prefix_group"] = "audit_stem"
            out_p = Path(self.tmp) / "option_a_explorer.json"
            out_p.write_text(json.dumps(base_raw), encoding="utf-8")
            return out_p
        if variant_name == "option_b_planner":
            # Option B: architect -> threat_modeler -> planner stem without explorer node
            base_raw["nodes"] = [n for n in base_raw["nodes"] if n["id"] != "explorer"]
            for nd in base_raw["nodes"]:
                if nd.get("fork_from") == "explorer":
                    nd["fork_from"] = "planner"
            new_edges = []
            for e in base_raw["edges"]:
                if e["from"] == "planner" and e["to"] == "explorer":
                    new_edges.append({"from": "planner", "to": "researcher"})
                elif e["from"] == "explorer":
                    continue
                else:
                    new_edges.append(e)
            base_raw["edges"] = new_edges
            out_p = Path(self.tmp) / "option_b_planner.json"
            out_p.write_text(json.dumps(base_raw), encoding="utf-8")
            return out_p
        raise ValueError(f"Unknown variant: {variant_name}")

    async def _execute_variant(self, wf_filename: str):
        db_path = os.path.join(self.tmp, f"{wf_filename}.db")
        init_db(db_path)
        record_learning(
            db_path,
            category="injection",
            learning="[target_stage=reviewer] Verify string formatting in SQL queries.",
            run_id="prior_run",
        )

        wf_path = self._materialize_variant_path(wf_filename)
        with mock.patch.dict(
            os.environ,
            {"VERTEXAI_PROJECT": "dummy-test-proj", "VERTEXAI_LOCATION": "global"},
        ):
            workflow, cfg = gl.load_workflow_from_json(str(wf_path), load_local=False)

        recorder = _ScriptedWireRecorder(self.repo)
        ctrl = BudgetController(
            config=BudgetConfig(max_tokens=0, max_wall_clock_seconds=0),
            run_id="run_env",
        )
        rc = RunContext(
            jail_dir=self.repo,
            db_path=db_path,
            target_file=self.repo,
            run_id="run_env",
            sandbox=StaticOnlyEnvironment(target_path=self.repo),
            budget_controller=ctrl,
            campaign_directive="Audit routes/login.py and routes/admin.py thoroughly.",
            campaign_context="\nPrior note: focus on SQL sinks.",
            defer_reporter=True,
        )
        tok = current_run_context.set(rc)

        async def _patched_gen(llm_self, req, stream=False):
            async for item in recorder.dispatch(llm_self, req, stream=stream):
                yield item

        try:
            with mock.patch.object(ResilientLiteLlm, "generate_content_async", _patched_gen):
                runner = InMemoryRunner(agent=workflow, app_name="mantis_test")
                sess = await runner.session_service.create_session(
                    app_name="mantis_test",
                    user_id="u1",
                    state={"db_path": db_path, "run_id": "run_env", "filepath": self.repo},
                )
                seed = types.Content(
                    role="user",
                    parts=[types.Part.from_text(text=f"Initial Task Input: Evaluate {self.repo}")],
                )
                async for _ev in runner.run_async(user_id="u1", session_id=sess.id, new_message=seed):
                    pass
                final_sess = await runner.session_service.get_session(
                    app_name="mantis_test", user_id="u1", session_id=sess.id
                )
        finally:
            current_run_context.reset(tok)

        findings = read_findings(db_path, run_id="run_env")
        return workflow, cfg, recorder, findings, final_sess, ctrl

    def _assert_strict_alternation_and_signatures(self, contents: list[dict[str, Any]], label: str):
        self.assertGreaterEqual(len(contents), 1, label)
        self.assertEqual(contents[0]["role"], "user", f"{label}: must open with user role")
        self.assertEqual(contents[-1]["role"], "user", f"{label}: Turn-1/tool turn request must end on user role")
        for i in range(1, len(contents)):
            prev_role = contents[i - 1]["role"]
            cur_role = contents[i]["role"]
            self.assertNotEqual(
                prev_role,
                cur_role,
                f"{label}: adjacent identical roles at {i - 1}->{i} ({prev_role})",
            )

    async def test_option_a_explorer_byte_identical_prefix_inv2_and_verdicts(self):
        from core.budget import should_credit_coverage

        workflow, _cfg, rec, findings, final_sess, ctrl = await self._execute_variant(
            "option_a_explorer"
        )
        agents = _iter_workflow_agents(workflow)

        # Static-only skip: neither history nor reproducer made any LLM calls.
        # The reproducer's "failed_repro" verdict replaced critic's stale "viable",
        # so repro_classifier routed to the fallback (no chainer/patcher) and then
        # consumed the single-use state["verdict"].
        self.assertNotIn("history", rec.requests_by_stage)
        self.assertNotIn("reproducer", rec.requests_by_stage)
        self.assertNotIn("chainer", rec.requests_by_stage)
        self.assertNotIn("patcher", rec.requests_by_stage)
        self.assertIsNone(final_sess.state.get("verdict"))

        # Coverage credit: explorer read routes/login.py + routes/admin.py while researcher made 0 reads
        self.assertEqual(ctrl.audit_code_reads, 2)
        self.assertTrue(should_credit_coverage(False, ctrl.audit_code_reads))

        # Every stage's Turn-1 ctx.active_node (including non-prefix_group architect, deduplicator,
        # calibrator, reflector) equals its own node_id!
        for st_name, st_reqs in rec.requests_by_stage.items():
            self.assertEqual(
                st_reqs[0]["raw_ctx_active_node"],
                st_name,
                f"Turn-1 ctx.active_node stale on {st_name}: {st_reqs[0]['raw_ctx_active_node']}",
            )

        # All prefix_group agents have output_schema=None on ADK Agent (no set_model_response tool!)
        # AND identical reasoning_effort / LiteLLM _additional_args (preventing Gemini thinkingLevel KV-cache misses!)
        exp_add_args = dict(agents["explorer"].model._additional_args)
        self.assertEqual(exp_add_args.get("reasoning_effort"), "medium")
        for stage_id in ("explorer", "researcher", "reviewer", "critic", "reproducer"):
            ag = agents[stage_id]
            self.assertIsNone(ag.output_schema, f"{stage_id} must not inject ADK set_model_response")
            self.assertEqual(str(ag.instruction), PREFIX_GROUP_BASE_INSTRUCTION)
            self.assertEqual(
                dict(ag.model._additional_args),
                exp_add_args,
                f"{stage_id} model _additional_args (reasoning_effort/thinkingConfig) diverged from stem!",
            )

        exp_reqs = rec.requests_by_stage["explorer"]
        res_reqs = rec.requests_by_stage["researcher"]
        rev_reqs = rec.requests_by_stage["reviewer"]
        crit_reqs = rec.requests_by_stage["critic"]
        self.assertEqual(len(exp_reqs), 3)
        self.assertGreaterEqual(len(res_reqs), 2)
        self.assertGreaterEqual(len(rev_reqs), 2)
        self.assertGreaterEqual(len(crit_reqs), 2)

        # 1. Byte-for-byte equality of system_instruction, tools schemas, and contents[:len(stem)]
        # across explorer, researcher, reviewer, and critic (both LlmRequest AND LiteLLM wire level).
        base_sys = exp_reqs[0]["system_instruction"]
        base_tools = exp_reqs[0]["tools_json"]
        base_wire_tools = exp_reqs[0]["wire_tools_json"]
        self.assertEqual(base_sys, PREFIX_GROUP_BASE_INSTRUCTION)
        self.assertNotIn("set_model_response", exp_reqs[0]["tool_names"])

        # Stem contents after explorer finishes = explorer's last request contents + explorer's final model turn (4 turns)
        stem_prefix = res_reqs[0]["contents"][:-1]
        self.assertEqual(len(stem_prefix), len(exp_reqs[-1]["contents"]) + 1)
        self.assertEqual(
            stem_prefix[: len(exp_reqs[-1]["contents"])],
            exp_reqs[-1]["contents"],
            "explorer's own turns must match researcher's inherited stem byte-for-byte",
        )
        # Verify thought=True and thought_signature survived intact in stem_prefix!
        stem_sigs = [
            p["thought_signature"]
            for c in stem_prefix
            for p in c["parts"]
            if p["thought_signature"] is not None
        ]
        stem_thoughts = [
            p["text"] for c in stem_prefix for p in c["parts"] if p["thought"]
        ]
        self.assertGreaterEqual(len(stem_sigs), 2, "thought_signatures must remain intact")
        self.assertGreaterEqual(len(stem_thoughts), 3, "thought parts must remain intact")

        stem_wire_msg_count = len(exp_reqs[-1]["wire_messages_json"]) + 1  # + explorer final assistant msg
        ref_wire_prefix = res_reqs[0]["wire_messages_json"][:stem_wire_msg_count]

        for stage_name, stage_reqs in (
            ("explorer", exp_reqs),
            ("researcher", res_reqs),
            ("reviewer", rev_reqs),
            ("critic", crit_reqs),
        ):
            for idx, r in enumerate(stage_reqs):
                self.assertEqual(
                    r["system_instruction"],
                    base_sys,
                    f"{stage_name} turn {idx + 1} mutated system_instruction!",
                )
                self.assertEqual(
                    r["tools_json"],
                    base_tools,
                    f"{stage_name} turn {idx + 1} mutated tools schema!",
                )
                self.assertEqual(r["wire_tools_json"], base_wire_tools)
                self.assertIsNone(r["wire_response_format"])
                self._assert_strict_alternation_and_signatures(
                    r["contents"], f"{stage_name}[{idx}]"
                )
            if stage_name != "explorer":
                self.assertEqual(
                    stage_reqs[0]["contents"][: len(stem_prefix)],
                    stem_prefix,
                    f"{stage_name} Turn-1 stem contents diverged!",
                )
                self.assertEqual(
                    stage_reqs[0]["wire_messages_json"][:stem_wire_msg_count],
                    ref_wire_prefix,
                    f"{stage_name} Turn-1 LiteLLM wire prefix diverged!",
                )
                # Stage's own u_stage (contents[len(stem_prefix)]) is cached identically on Turn 2!
                self.assertEqual(
                    stage_reqs[0]["contents"][len(stem_prefix)],
                    stage_reqs[1]["contents"][len(stem_prefix)],
                    f"{stage_name} u_stage mutated between Turn 1 and Turn 2!",
                )

        # 2. Strict INV-2 isolation: reviewer & critic have ZERO researcher turns,
        # critic has ZERO reviewer turns, and [ACTIVE FINDINGS SNAPSHOT] lands in u_stage, NOT system_instruction!
        for judge_name, judge_reqs in (("reviewer", rev_reqs), ("critic", crit_reqs)):
            turn1_dump = json.dumps(judge_reqs[0]["contents"])
            self.assertNotIn("RESEARCHER_PRIVATE_THOUGHT_DO_NOT_LEAK", turn1_dump)
            self.assertNotIn("RESEARCHER_FINAL_TRANSCRIPT_MARKER", turn1_dump)
            self.assertNotIn("RESEARCHER_SECRET_PROSE_MARKER_SQLI", turn1_dump)
            self.assertNotIn("DEDUPLICATOR_TRANSCRIPT_MARKER", turn1_dump)
            u_judge_text = judge_reqs[0]["contents"][len(stem_prefix)]["parts"][0]["text"]
            self.assertIn(FINDINGS_SNAPSHOT_HEADER, u_judge_text)
            self.assertNotIn(FINDINGS_SNAPSHOT_HEADER, judge_reqs[0]["system_instruction"])

        critic_turn1_dump = json.dumps(crit_reqs[0]["contents"])
        self.assertNotIn("REVIEWER_PRIVATE_THOUGHT", critic_turn1_dump)
        self.assertNotIn("REVIEWER_VERDICT_PROSE_MARKER", critic_turn1_dump)

        # 3. Per-finding promotions/dismissals + static-only reproducer completion stamp!
        by_title = {r["title"]: r["status"] for r in findings}
        self.assertEqual(by_title["SQL Injection in login_user"], "static_confirmed")
        self.assertEqual(by_title["Bogus claim in admin_panel"], "false_positive")
        self.assertEqual(by_title["Dead helper SQL query"], "non_viable")

    async def test_option_b_chained_planner_stem_byte_identical_prefix_and_inv2(self):
        from core.budget import should_credit_coverage

        workflow, _cfg, rec, findings, final_sess, ctrl = await self._execute_variant(
            "option_b_planner"
        )
        agents = _iter_workflow_agents(workflow)

        self.assertNotIn("history", rec.requests_by_stage)
        self.assertNotIn("reproducer", rec.requests_by_stage)
        self.assertNotIn("chainer", rec.requests_by_stage)
        self.assertNotIn("patcher", rec.requests_by_stage)
        self.assertIsNone(final_sess.state.get("verdict"))

        # Coverage credit: architect + planner read routes/login.py + routes/admin.py in stem;
        # researcher made 0 reads of its own yet earns exact coverage credit (2)!
        self.assertEqual(ctrl.audit_code_reads, 2)
        self.assertTrue(should_credit_coverage(False, ctrl.audit_code_reads))

        # Every stage's Turn-1 ctx.active_node equals its own node_id!
        for st_name, st_reqs in rec.requests_by_stage.items():
            self.assertEqual(
                st_reqs[0]["raw_ctx_active_node"],
                st_name,
                f"Turn-1 ctx.active_node stale on {st_name}: {st_reqs[0]['raw_ctx_active_node']}",
            )

        arch_add_args = dict(agents["architect"].model._additional_args)
        self.assertEqual(arch_add_args.get("reasoning_effort"), "medium")
        for stage_id in (
            "architect",
            "threat_modeler",
            "planner",
            "researcher",
            "reviewer",
            "critic",
            "reproducer",
        ):
            ag = agents[stage_id]
            self.assertIsNone(ag.output_schema, f"{stage_id} must have output_schema=None")
            self.assertEqual(str(ag.instruction), PREFIX_GROUP_BASE_INSTRUCTION)
            self.assertEqual(
                dict(ag.model._additional_args),
                arch_add_args,
                f"{stage_id} model _additional_args (reasoning_effort/thinkingConfig) diverged from stem!",
            )

        arch_reqs = rec.requests_by_stage["architect"]
        tm_reqs = rec.requests_by_stage["threat_modeler"]
        plan_reqs = rec.requests_by_stage["planner"]
        res_reqs = rec.requests_by_stage["researcher"]
        rev_reqs = rec.requests_by_stage["reviewer"]
        crit_reqs = rec.requests_by_stage["critic"]

        base_sys = arch_reqs[0]["system_instruction"]
        base_tools = arch_reqs[0]["tools_json"]

        # Planner prompt includes the shared-prefix stem file-reading duty + exact record_plan schema in u_planner,
        # and forked stages carry SHARED-STEM REUSE & PARALLEL BATCHING to suppress redundant re-reads!
        u_planner_text = plan_reqs[0]["contents"][-1]["parts"][0]["text"]
        self.assertIn("SHARED-PREFIX STEM DUTY", u_planner_text)
        self.assertIn('record_plan(plan={"investigations":', u_planner_text)
        for fk_reqs in (res_reqs, rev_reqs, crit_reqs):
            self.assertIn(
                "SHARED-STEM REUSE & PARALLEL BATCHING",
                fk_reqs[0]["contents"][-1]["parts"][0]["text"],
            )

        # Transitive chain check:
        # threat_modeler Turn 1 inherits architect; planner Turn 1 inherits architect + threat_modeler;
        # researcher, reviewer, critic Turn 1 inherit architect + threat_modeler + planner!
        arch_stem_len = len(arch_reqs[-1]["contents"]) + 1
        self.assertEqual(len(tm_reqs[0]["contents"]) - 1, arch_stem_len)
        self.assertEqual(
            tm_reqs[0]["contents"][: len(arch_reqs[-1]["contents"])],
            arch_reqs[-1]["contents"],
        )

        tm_stem_len = len(tm_reqs[-1]["contents"]) + 1
        self.assertEqual(len(plan_reqs[0]["contents"]) - 1, tm_stem_len)
        self.assertEqual(
            plan_reqs[0]["contents"][: len(tm_reqs[-1]["contents"])],
            tm_reqs[-1]["contents"],
        )

        full_stem = res_reqs[0]["contents"][:-1]
        self.assertEqual(len(full_stem), len(plan_reqs[-1]["contents"]) + 1)
        self.assertEqual(
            full_stem[: len(plan_reqs[-1]["contents"])],
            plan_reqs[-1]["contents"],
        )

        full_wire_count = len(plan_reqs[-1]["wire_messages_json"]) + 1
        ref_wire_prefix = res_reqs[0]["wire_messages_json"][:full_wire_count]

        for stage_name, stage_reqs in (
            ("architect", arch_reqs),
            ("threat_modeler", tm_reqs),
            ("planner", plan_reqs),
            ("researcher", res_reqs),
            ("reviewer", rev_reqs),
            ("critic", crit_reqs),
        ):
            for idx, r in enumerate(stage_reqs):
                self.assertEqual(r["system_instruction"], base_sys, f"{stage_name}[{idx}]")
                self.assertEqual(r["tools_json"], base_tools, f"{stage_name}[{idx}]")
                self._assert_strict_alternation_and_signatures(
                    r["contents"], f"{stage_name}[{idx}]"
                )
            if stage_name in ("researcher", "reviewer", "critic"):
                self.assertEqual(stage_reqs[0]["contents"][: len(full_stem)], full_stem)
                self.assertEqual(
                    stage_reqs[0]["wire_messages_json"][:full_wire_count],
                    ref_wire_prefix,
                )

        # INV-2 isolation across Option B judges
        for judge_reqs in (rev_reqs, crit_reqs):
            dump = json.dumps(judge_reqs[0]["contents"])
            self.assertNotIn("RESEARCHER_PRIVATE_THOUGHT_DO_NOT_LEAK", dump)
            self.assertNotIn("RESEARCHER_FINAL_TRANSCRIPT_MARKER", dump)
            self.assertNotIn("DEDUPLICATOR_TRANSCRIPT_MARKER", dump)
        self.assertNotIn(
            "REVIEWER_VERDICT_PROSE_MARKER", json.dumps(crit_reqs[0]["contents"])
        )

        by_title = {r["title"]: r["status"] for r in findings}
        self.assertEqual(by_title["SQL Injection in login_user"], "static_confirmed")
        self.assertEqual(by_title["Bogus claim in admin_panel"], "false_positive")
        self.assertEqual(by_title["Dead helper SQL query"], "non_viable")

    def test_before_tool_callback_and_python_gate_block_unauthorized_report_findings(self):
        with mock.patch.dict(
            os.environ,
            {"VERTEXAI_PROJECT": "dummy-test-proj", "VERTEXAI_LOCATION": "global"},
        ):
            wf_a, _ = gl.load_workflow_from_json(
                str(_REF_ROOT / "workflow.json"), load_local=False
            )
        agents = _iter_workflow_agents(wf_a)
        fake_report_tool = SimpleNamespace(name="report_findings")
        fake_read_tool = SimpleNamespace(name="read_file")

        db_path = os.path.join(self.tmp, "perm.db")
        init_db(db_path)
        rc = RunContext(jail_dir=self.repo, db_path=db_path, target_file=self.repo, run_id="r_perm")
        tok = current_run_context.set(rc)
        try:
            for forbidden_stage in ("explorer", "reviewer", "critic"):
                cb = agents[forbidden_stage].before_tool_callback
                self.assertIsNotNone(cb, forbidden_stage)
                blocked = cb(tool=fake_report_tool, args={}, tool_context=None)
                self.assertIsInstance(blocked, dict)
                self.assertIn("not permitted in stage", blocked["error"])
                self.assertIn(forbidden_stage, blocked["error"])
                self.assertEqual(rc.active_node, forbidden_stage)

                # Allowed tool passes through (returns None)
                allowed = cb(tool=fake_read_tool, args={"filepath": "routes/login.py"}, tool_context=None)
                self.assertIsNone(allowed)

                # Direct Python call to report_findings ALSO refuses via ctx.active_node (INV-2)!
                direct = rt.report_findings({
                    "findings": [{
                        "title": "Should be blocked",
                        "severity": "HIGH",
                        "description": "d",
                        "filepath": "routes/login.py",
                        "line_numbers": [3],
                    }]
                })
                self.assertIn("not permitted in stage", direct)
                self.assertEqual(read_findings(db_path, run_id="r_perm"), [])

            # Researcher IS permitted to call report_findings
            res_cb = agents["researcher"].before_tool_callback
            self.assertIsNone(res_cb(tool=fake_report_tool, args={}, tool_context=None))
            self.assertEqual(rc.active_node, "researcher")
        finally:
            current_run_context.reset(tok)

    async def test_raw_json_verdict_state_and_invalid_json_retry_resilience(self):
        # 1. Verify create_classifier handles raw-JSON string in ctx.state["verdict"] (when node_input is None)
        # AND handles accumulated tool-turn prose ahead of the final JSON object.
        db_path = os.path.join(self.tmp, "cls_raw.db")
        init_db(db_path)
        rc = RunContext(jail_dir=self.repo, db_path=db_path, target_file=self.repo, run_id="r_raw")
        tok = current_run_context.set(rc)
        try:
            rt.report_findings({
                "findings": [
                    {"title": "Bug A", "severity": "HIGH", "description": "d", "filepath": "routes/login.py", "line_numbers": [5]},
                    {"title": "Bug B", "severity": "LOW", "description": "d", "filepath": "routes/admin.py", "line_numbers": [4]},
                ]
            })
            rows = sorted(read_findings(db_path, run_id="r_raw"), key=lambda r: int(r["id"]))
            id_a, id_b = int(rows[0]["id"]), int(rows[1]["id"])

            rev_cls = gl.create_classifier("reviewer_classifier", ["confirmed"])
            raw_verdict_str = (
                "Checking findings via get_findings...\n"
                + json.dumps({
                    "route": "confirmed",
                    "reason": "Bug A real, Bug B mitigated",
                    "finding_verdicts": [
                        {"finding_id": id_a, "route": "confirmed", "reason": "SQLi"},
                        {"finding_id": id_b, "route": "false_positive", "reason": "Guarded"},
                    ],
                })
            )
            fake_ctx = SimpleNamespace(state={"verdict": raw_verdict_str})
            ev = await rev_cls._func(fake_ctx, None)
            self.assertEqual(ev.actions.route, "confirmed")
            by_id = {int(r["id"]): r["status"] for r in read_findings(db_path, run_id="r_raw")}
            self.assertEqual(by_id[id_a], "confirmed")
            self.assertEqual(by_id[id_b], "false_positive")

            # 2. Verify ResilientLiteLlm with output_schema_override retries invalid non-JSON prose once
            # and emits clean schema-valid JSON on retry!
            llm = ResilientLiteLlm(
                model="openai/dummy",
                output_schema_override=ExtendedCriticVerdict,
                preserve_system_prefix=True,
            )
            seen_Turn_lengths: list[int] = []

            async def _fake_super_gen(_self, req, stream=False):
                seen_Turn_lengths.append(len(req.contents or []))
                if len(seen_Turn_lengths) == 1:
                    yield LlmResponse(content=types.Content(role="model", parts=[
                        types.Part.from_text(text="I think finding A is viable and reachable!"),
                    ]))
                else:
                    yield LlmResponse(content=types.Content(role="model", parts=[
                        types.Part.from_text(text=json.dumps({
                            "route": "viable",
                            "reason": "Reachable via HTTP",
                            "finding_verdicts": [{"finding_id": id_a, "route": "viable", "reason": "ok"}],
                        })),
                    ]))

            from google.adk.models.lite_llm import LiteLlm as BaseAdkLiteLlm
            from google.adk.models import LlmRequest

            req = LlmRequest(
                contents=[types.Content(role="user", parts=[types.Part.from_text(text="Judge now")])],
                config=types.GenerateContentConfig(system_instruction=PREFIX_GROUP_BASE_INSTRUCTION),
            )
            outputs = []
            with mock.patch.object(BaseAdkLiteLlm, "generate_content_async", _fake_super_gen):
                async for resp in llm.generate_content_async(req, stream=True):
                    outputs.append(resp)

            self.assertEqual(len(seen_Turn_lengths), 2, "Should retry invalid prose once")
            self.assertEqual(len(outputs), 1)
            parsed = ExtendedCriticVerdict.model_validate_json(outputs[0].content.parts[0].text)
            self.assertEqual(parsed.route, "viable")
            self.assertEqual(req.config.system_instruction, PREFIX_GROUP_BASE_INSTRUCTION)
        finally:
            current_run_context.reset(tok)

    def test_retry_attempt_slicing_keeps_only_final_ancestor_attempt(self):
        events = [
            Event(author="user", content=types.Content(role="user", parts=[types.Part.from_text(text="SEED")])),
            Event(author="explorer", content=types.Content(role="model", parts=[
                types.Part(text="stale attempt 1 thought", thought=True),
                types.Part.from_text(text="STALE_ATTEMPT_1_TEXT"),
            ])),
            Event(author="explorer", error_code="NodeContextExhausted", content=types.Content(role="model", parts=[])),
            Event(author="explorer", content=types.Content(role="model", parts=[
                types.Part(text="fresh attempt 2 thought", thought=True),
                types.Part(
                    function_call=types.FunctionCall(name="read_file", id="c2", args={"filepath": "a.py"}),
                    thought_signature=b"sig_attempt2",
                ),
            ])),
            Event(author="explorer", content=types.Content(role="user", parts=[
                types.Part(function_response=types.FunctionResponse(name="read_file", id="c2", response={"result": "code"})),
            ])),
            Event(author="explorer", content=types.Content(role="model", parts=[
                types.Part.from_text(text="FRESH_ATTEMPT_2_SUMMARY"),
            ])),
        ]
        # Both legacy forked_contents and signature-preserving forked_prefix_contents drop Attempt 1!
        legacy = gl.forked_contents(events, "explorer")
        legacy_dump = json.dumps([_serialize_content(c) for c in legacy])
        self.assertNotIn("STALE_ATTEMPT_1_TEXT", legacy_dump)
        self.assertIn("FRESH_ATTEMPT_2_SUMMARY", legacy_dump)

        prefix = gl.forked_prefix_contents(
            events,
            ("explorer",),
            state={f"{gl.PREFIX_U_STATE_KEY_PREFIX}explorer": "[ACTIVE STAGE ASSIGNMENT: explorer]\nRole"},
            preserve_signatures=True,
        )
        prefix_dump = json.dumps([_serialize_content(c) for c in prefix])
        self.assertNotIn("STALE_ATTEMPT_1_TEXT", prefix_dump)
        self.assertNotIn("stale attempt 1 thought", prefix_dump)
        self.assertIn("fresh attempt 2 thought", prefix_dump)
        self.assertIn("sig_attempt2".encode("utf-8").hex(), prefix_dump)
        self.assertEqual([c.role for c in prefix], ["user", "model", "user", "model"])

    def test_shipped_workflow_fingerprint_and_reasoning_effort_normalization(self):
        opt_a = self._materialize_variant_path("option_a_explorer")
        opt_b = self._materialize_variant_path("option_b_planner")
        with mock.patch.dict(
            os.environ,
            {"VERTEXAI_PROJECT": "dummy-test-proj", "VERTEXAI_LOCATION": "global"},
        ):
            _, base_cfg = gl.load_workflow_from_json(str(_REF_ROOT / "workflow.json"), load_local=False)
            _, base_cfg2 = gl.load_workflow_from_json(str(_REF_ROOT / "workflow.json"), load_local=False)
            _, exp_cfg = gl.load_workflow_from_json(str(opt_a), load_local=False)
            _, plan_cfg = gl.load_workflow_from_json(str(opt_b), load_local=False)
        self.assertTrue(base_cfg["harness_fingerprint"])
        self.assertEqual(base_cfg["harness_fingerprint"], base_cfg2["harness_fingerprint"])
        self.assertNotEqual(base_cfg["harness_fingerprint"], exp_cfg["harness_fingerprint"])
        self.assertNotEqual(base_cfg["harness_fingerprint"], plan_cfg["harness_fingerprint"])
        self.assertNotEqual(exp_cfg["harness_fingerprint"], plan_cfg["harness_fingerprint"])

        # Custom spec with mismatched reasoning_effort ("high" on critic vs "medium" on stem)
        # inside a prefix_group is deterministically normalized to the stem's reasoning_effort!
        raw_mismatch = json.loads((_REF_ROOT / "workflow.json").read_text(encoding="utf-8"))
        for nd in raw_mismatch["nodes"]:
            if nd["id"] == "critic":
                nd["reasoning_effort"] = "high"
        mismatch_path = os.path.join(self.tmp, "mismatch_effort.json")
        Path(mismatch_path).write_text(json.dumps(raw_mismatch), encoding="utf-8")
        with mock.patch.dict(
            os.environ,
            {"VERTEXAI_PROJECT": "dummy-test-proj", "VERTEXAI_LOCATION": "global"},
        ):
            wf_m, _ = gl.load_workflow_from_json(mismatch_path, load_local=False)
        m_agents = _iter_workflow_agents(wf_m)
        self.assertEqual(
            m_agents["critic"].model._additional_args.get("reasoning_effort"),
            "medium",
        )
        self.assertEqual(
            dict(m_agents["critic"].model._additional_args),
            dict(m_agents["explorer"].model._additional_args),
        )

    async def test_drive_campaign_shortcircuit_metering_and_scope_coverage(self):
        """Verifies main._drive_campaign does NOT inflate llm_calls on skip_when_static
        nodes, credits shipped hybrid workflow.json, Option A, and Option B, and fails closed
        when the stem only reads workspace/* artifacts."""
        import main as mantis_main
        from core.budget import should_credit_coverage

        for wf_name, expected_reads in (
            ("workflow.json", 4),
            ("option_a_explorer", 2),
            ("option_b_planner", 2),
        ):
            db_path = os.path.join(self.tmp, f"drive_{wf_name}.db")
            init_db(db_path)
            wf_p = self._materialize_variant_path(wf_name)
            with mock.patch.dict(
                os.environ,
                {"VERTEXAI_PROJECT": "dummy-test-proj", "VERTEXAI_LOCATION": "global"},
            ):
                workflow, cfg = gl.load_workflow_from_json(str(wf_p), load_local=False)

            rec = _ScriptedWireRecorder(self.repo)
            ctrl = BudgetController(
                config=BudgetConfig(max_tokens=0, max_wall_clock_seconds=0),
                run_id=f"drive_{wf_name}",
            )
            rc = RunContext(
                jail_dir=self.repo,
                db_path=db_path,
                target_file=self.repo,
                run_id=f"drive_{wf_name}",
                sandbox=StaticOnlyEnvironment(target_path=self.repo),
                budget_controller=ctrl,
                defer_reporter=True,
            )
            tok = current_run_context.set(rc)

            async def _patched_gen(llm_self, req, stream=False, _rec=rec):
                async for item in _rec.dispatch(llm_self, req, stream=stream):
                    item.usage_metadata = types.GenerateContentResponseUsageMetadata(
                        prompt_token_count=100,
                        candidates_token_count=20,
                        total_token_count=120,
                    )
                    yield item

            try:
                with mock.patch.object(ResilientLiteLlm, "generate_content_async", _patched_gen):
                    runner = InMemoryRunner(agent=workflow, app_name="mantis_drive")
                    sess = await runner.session_service.create_session(
                        app_name="mantis_drive",
                        user_id=mantis_main.USER_ID,
                        state={"db_path": db_path, "run_id": rc.run_id, "filepath": self.repo},
                    )
                    seed = types.Content(
                        role="user",
                        parts=[types.Part.from_text(text=f"Initial Task Input: Evaluate {self.repo}")],
                    )
                    failed = await mantis_main._drive_campaign(
                        runner,
                        sess.id,
                        seed,
                        None,
                        filepath=self.repo,
                        run_id=rc.run_id,
                        db_path=db_path,
                        status_map=cfg.get("on_enter_status"),
                        budget_controller=ctrl,
                        transcript=None,
                    )
                    final_sess = await runner.session_service.get_session(
                        app_name="mantis_drive", user_id=mantis_main.USER_ID, session_id=sess.id
                    )
            finally:
                current_run_context.reset(tok)

            self.assertFalse(failed, wf_name)
            total_real_calls = sum(len(v) for v in rec.requests_by_stage.values())
            # Zero fake llm_calls from skip_when_static on history + reproducer + deferred reporter!
            self.assertEqual(
                ctrl.llm_calls,
                total_real_calls,
                f"{wf_name}: metered llm_calls ({ctrl.llm_calls}) != real LLM calls ({total_real_calls})",
            )
            self.assertEqual(
                ctrl.accumulated_tokens,
                total_real_calls * 120,
                f"{wf_name}: skip_when_static added bogus estimated tokens!",
            )
            self.assertEqual(ctrl.audit_code_reads, expected_reads, wf_name)
            self.assertTrue(should_credit_coverage(failed, ctrl.audit_code_reads), wf_name)
            self.assertNotIn("chainer", rec.requests_by_stage, wf_name)
            self.assertNotIn("patcher", rec.requests_by_stage, wf_name)
            self.assertIsNone(final_sess.state.get("verdict"), wf_name)

        # Negative check: workspace-only reads in stem NEVER earn coverage credit (fail-closed)
        ws_events_contents = [
            types.Content(role="model", parts=[
                types.Part(function_call=types.FunctionCall(
                    name="read_file", id="ws1", args={"filepath": "workspace/kb/architecture.md"}
                )),
            ]),
            types.Content(role="user", parts=[
                types.Part(function_response=types.FunctionResponse(
                    name="read_file", id="ws1", response={"result": "<<<UNTRUSTED_SOURCE_CODE_DATA_START>>>\nkb"}
                )),
            ]),
        ]
        rc_neg = RunContext(jail_dir=self.repo, db_path="", target_file=self.repo, run_id="neg")
        self.assertEqual(gl._count_inherited_in_scope_code_reads(rc_neg, ws_events_contents), 0)


if __name__ == "__main__":
    unittest.main()

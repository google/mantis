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

"""Phase-2 CL 1 RED->GREEN regression tests:
1. Default hybrid shared-prefix stem in reference/workflow.json + removal of prototype JSONs.
2. Cross-functional Slice 2..N prefix-reuse compatibility with forked_prefix_contents.
3. Explicit Vertex CachedContent creation at stem exit, post-stem delta-only generateContent
   (stripping system_instruction/tools/toolConfig on wire), fail-safe fallback, and finally DELETE.
4. token-efficiency-2 static reproducer skip + INV-1 sandbox_executed gate on repro_classifier.
5. Sandbox-gated skips for history, single-file planner/bootstrap, <=1-finding deduplicator, and reporter.
6. Source-file count threshold & surveyor risk-ordered file-by-file sweeps.
7. Slim 9-field ReportedFindingInput wire schema & typed input schemas on domain tools.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import httpx

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from google.adk.models import LlmResponse
from google.adk.models.lite_llm import _get_completion_inputs
from google.adk.runners import InMemoryRunner
from google.genai import types

import core.config as cfg_mod
import core.graph_loader as gl
import core.schemas as schemas_mod
import main as mantis_main
import tools.research_tools as rt
from core.budget import BudgetConfig, BudgetController
from core.config import ResilientLiteLlm, anthropic_context_editing, client_context_editing
from core.context import RunContext, current_run_context
from core.database import init_db, read_artifact, read_findings, record_artifact, write_findings
from core.environments.static_env import StaticOnlyEnvironment


def _iter_agents(workflow) -> dict[str, object]:
    found: dict[str, object] = {}
    for edge in getattr(workflow, "edges", []) or []:
        for nd in (getattr(edge, "from_node", None), getattr(edge, "to_node", None)):
            ag = getattr(nd, "agent", nd)
            name = getattr(ag, "name", None)
            if name:
                found[str(name)] = ag
    return found


class TestP2Cl1ForkCacheEfficiency(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_p2_cl1_")
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(self.repo, "routes"), exist_ok=True)
        Path(self.repo, "routes", "login.py").write_text(
            "import sqlite3\n\n"
            "def login_user(conn, username):\n"
            "    return conn.execute(f\"SELECT * FROM users WHERE name='{username}'\").fetchall()\n",
            encoding="utf-8",
        )
        Path(self.repo, "routes", "admin.py").write_text(
            "def admin_panel(user):\n"
            "    if getattr(user, 'role', None) != 'admin':\n"
            "        raise PermissionError('denied')\n"
            "    return {'ok': True}\n",
            encoding="utf-8",
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_1_default_workflow_is_hybrid_shared_prefix_stem_and_temp_variants_removed(self):
        raw = json.loads((_REF_ROOT / "workflow.json").read_text(encoding="utf-8"))
        self.assertEqual(raw["config"].get("context_editing_trigger_tokens"), 180000)

        # Preserve config=None 50%/20% window defaults while clamping when config carries 180k!
        self.assertEqual(
            client_context_editing("vertex_ai/gemini-3.8-flash")["trigger_tokens"],
            524_288,
        )
        self.assertEqual(
            anthropic_context_editing("vertex_ai/claude-opus-5")["edits"][0]["trigger"]["value"],
            500_000,
        )
        self.assertEqual(
            client_context_editing("vertex_ai/gemini-3.8-flash", config=raw["config"])["trigger_tokens"],
            180_000,
        )
        self.assertEqual(
            anthropic_context_editing("vertex_ai/claude-opus-5", config=raw["config"])["edits"][0]["trigger"]["value"],
            180_000,
        )

        nodes_by_id = {n["id"]: n for n in raw["nodes"]}
        for nid in (
            "architect",
            "threat_modeler",
            "planner",
            "explorer",
            "researcher",
            "reviewer",
            "critic",
            "reproducer",
        ):
            self.assertIn(nid, nodes_by_id)
            self.assertEqual(nodes_by_id[nid].get("prefix_group"), "audit_stem")
            self.assertEqual(nodes_by_id[nid].get("reasoning_effort"), "medium")

        self.assertEqual(nodes_by_id["threat_modeler"].get("fork_from"), "architect")
        self.assertEqual(nodes_by_id["planner"].get("fork_from"), "threat_modeler")
        self.assertEqual(nodes_by_id["explorer"].get("fork_from"), "planner")
        for forked_leaf in ("researcher", "reviewer", "critic", "reproducer"):
            self.assertEqual(nodes_by_id[forked_leaf].get("fork_from"), "explorer")

        edge_pairs = {(e["from"], e["to"]) for e in raw["edges"]}
        self.assertIn(("history", "structural_index"), edge_pairs)
        self.assertIn(("structural_index", "architect"), edge_pairs)
        self.assertIn(("planner", "explorer"), edge_pairs)
        self.assertIn(("explorer", "researcher"), edge_pairs)

        stamps = {n["id"]: n["on_enter_status"] for n in raw["nodes"] if n.get("on_enter_status")}
        self.assertEqual(stamps, {"reproducer": "static_confirmed", "patcher": "dynamic_confirmed"})

    async def test_2_cross_functional_slice2_prefix_reuse_makes_planner_explorer_effective_stem(self):
        os.makedirs(os.path.join(self.repo, "billing"), exist_ok=True)
        Path(self.repo, "billing", "pay.py").write_text(
            "def charge(conn, amt):\n    return conn.execute(f'INSERT INTO tx VALUES ({amt})')\n",
            encoding="utf-8",
        )
        db_path = os.path.join(self.tmp, "xf.db")
        init_db(db_path)

        with mock.patch.dict(
            os.environ,
            {"VERTEXAI_PROJECT": "dummy-proj", "VERTEXAI_LOCATION": "global"},
        ):
            workflow, _ = gl.load_workflow_from_json(str(_REF_ROOT / "workflow.json"), load_local=False)

        shared_runs: dict = {}
        stage_calls_per_slice: list[dict[str, list[list[str]]]] = []

        for slice_dir in (os.path.join(self.repo, "routes"), os.path.join(self.repo, "billing")):
            calls_map: dict[str, list[list[str]]] = {}

            async def _fake_gen(_llm, req, stream=False, _cmap=calls_map, _sdir=slice_dir):
                ctx = current_run_context.get()
                st = str(getattr(ctx, "active_node", "") or "unknown")
                roles = [str(getattr(c, "role", "")) for c in (req.contents or [])]
                _cmap.setdefault(st, []).append(roles)
                turn = len(_cmap[st])
                cid = f"c_{st}_{turn}"
                if st == "architect":
                    if turn == 1:
                        yield LlmResponse(content=types.Content(role="model", parts=[
                            types.Part(
                                function_call=types.FunctionCall(
                                    name="record_summary",
                                    id=cid,
                                    args={"summary": {"overview": "Repo arch", "key_modules": ["routes", "billing"]}},
                                ),
                                thought_signature=b"sig_arch",
                            ),
                        ]))
                        return
                    yield LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text="Summary saved.")]))
                    return
                if st == "threat_modeler":
                    if turn == 1:
                        yield LlmResponse(content=types.Content(role="model", parts=[
                            types.Part(
                                function_call=types.FunctionCall(
                                    name="record_threat_model",
                                    id=cid,
                                    args={"threat_model": {"threats": ["SQLi"], "entry_points": ["/login"]}},
                                ),
                                thought_signature=b"sig_tm",
                            ),
                        ]))
                        return
                    yield LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text="TM saved.")]))
                    return
                if st == "planner":
                    if turn == 1:
                        yield LlmResponse(content=types.Content(role="model", parts=[
                            types.Part(
                                function_call=types.FunctionCall(
                                    name="record_plan",
                                    id=cid,
                                    args={"plan": {"investigations": [{"title": "Check SQL", "target_files": ["routes/login.py"]}]}},
                                ),
                                thought_signature=b"sig_plan",
                            ),
                        ]))
                        return
                    yield LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text="Plan saved.")]))
                    return
                if st == "explorer":
                    rel = "routes/login.py" if _sdir.endswith("routes") else "billing/pay.py"
                    if turn == 1:
                        yield LlmResponse(content=types.Content(role="model", parts=[
                            types.Part(
                                function_call=types.FunctionCall(name="read_file", id=cid, args={"filepath": rel}),
                                thought_signature=b"sig_exp",
                            ),
                        ]))
                        return
                    yield LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text="Explored slice.")]))
                    return
                yield LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text="Clean.")]))

            rc = RunContext(
                jail_dir=self.repo,
                db_path=db_path,
                target_file=slice_dir,
                path_root=self.repo,
                run_id="xf_run",
                scan_mode="cross-functional",
                sandbox=StaticOnlyEnvironment(target_path=self.repo),
                shared_prefix_runs=shared_runs,
                enable_context_cache=False,
                defer_reporter=True,
            )
            tok = current_run_context.set(rc)
            try:
                with mock.patch.object(ResilientLiteLlm, "generate_content_async", _fake_gen):
                    runner = InMemoryRunner(agent=workflow, app_name="xf_test")
                    sess = await runner.session_service.create_session(
                        app_name="xf_test", user_id="u", state={"db_path": db_path, "run_id": "xf_run"}
                    )
                    seed = types.Content(role="user", parts=[types.Part.from_text(text=f"Audit {slice_dir}")])
                    async for _ in runner.run_async(user_id="u", session_id=sess.id, new_message=seed):
                        pass
            finally:
                current_run_context.reset(tok)
            stage_calls_per_slice.append(calls_map)

        slice1, slice2 = stage_calls_per_slice
        self.assertIn("architect", slice1)
        self.assertIn("threat_modeler", slice1)
        # Slice 2 MUST short-circuit architect & threat_modeler via _make_prefix_reuse_callbacks!
        self.assertNotIn("architect", slice2)
        self.assertNotIn("threat_modeler", slice2)
        # Slice 2 planner starts fresh (["user"]), explorer inherits planner (["user","model","user","model","user"]),
        # and researcher inherits planner + explorer with strict user <-> model alternation!
        self.assertEqual(slice2["planner"][0], ["user"])
        self.assertEqual(slice2["explorer"][0], ["user", "model", "user", "model", "user"])
        self.assertEqual(
            slice2["researcher"][0],
            ["user", "model", "user", "model", "user", "model", "user", "model", "user"],
        )

    async def test_3_explicit_vertex_cached_content_create_delta_send_strip_tools_and_finally_delete(self):
        # Create a >20 KB source file so stem easily exceeds the 4,096-token explicit-cache floor
        big_code = "import sqlite3\n" + ("# padding comment for realistic stem size\n" * 600) + (
            "def login_user(conn, u):\n"
            "    return conn.execute(f\"SELECT * FROM users WHERE u='{u}'\").fetchall()\n"
        )
        Path(self.repo, "routes", "login.py").write_text(big_code, encoding="utf-8")

        db_path = os.path.join(self.tmp, "cache_e2e.db")
        init_db(db_path)

        http_log: list[dict] = []
        cache_handle = "projects/test-proj/locations/global/cachedContents/9988776655"
        gen_turn_counts: dict[str, int] = {}

        def _sse_or_json_response(parts_payload: list[dict], stream: bool, req_obj: httpx.Request) -> httpx.Response:
            body = {
                "candidates": [
                    {
                        "content": {"role": "model", "parts": parts_payload},
                        "finishReason": "STOP",
                    }
                ],
                "usageMetadata": {
                    "promptTokenCount": 5200,
                    "cachedContentTokenCount": 5000,
                    "candidatesTokenCount": 30,
                    "totalTokenCount": 5230,
                },
            }
            if stream:
                sse = f"data: {json.dumps(body)}\n\n".encode("utf-8")
                return httpx.Response(200, content=sse, headers={"content-type": "text/event-stream"}, request=req_obj)
            return httpx.Response(200, json=body, request=req_obj)

        async def _fake_send(_client_self, request: httpx.Request, **_kw):
            url = str(request.url)
            method = request.method.upper()
            raw_body = request.content.decode("utf-8") if request.content else ""
            parsed = json.loads(raw_body) if raw_body else {}
            http_log.append({"method": method, "url": url, "body": parsed, "headers": dict(request.headers)})

            if method == "POST" and url.endswith("/cachedContents"):
                return httpx.Response(200, json={"name": cache_handle, "expireTime": "2026-11-13T16:00:00Z"}, request=request)
            if method == "DELETE" and "cachedContents/" in url:
                return httpx.Response(200, json={}, request=request)

            is_stream = "streamGenerateContent" in url or "alt=sse" in url
            ctx = current_run_context.get()
            st = str(getattr(ctx, "active_node", "") or "unknown")
            gen_turn_counts[st] = gen_turn_counts.get(st, 0) + 1
            t = gen_turn_counts[st]

            if st == "architect":
                if t == 1:
                    return _sse_or_json_response(
                        [{"functionCall": {"name": "record_summary", "args": {"summary": {"overview": "App", "key_modules": ["routes/login.py"]}}}}],
                        is_stream,
                        request,
                    )
                return _sse_or_json_response([{"text": "Summary done."}], is_stream, request)
            if st == "threat_modeler":
                if t == 1:
                    return _sse_or_json_response(
                        [{"functionCall": {"name": "record_threat_model", "args": {"threat_model": {"threats": ["SQLi"]}}}}],
                        is_stream,
                        request,
                    )
                return _sse_or_json_response([{"text": "TM done."}], is_stream, request)
            if st == "planner":
                if t == 1:
                    return _sse_or_json_response(
                        [{"functionCall": {"name": "record_plan", "args": {"plan": {"investigations": [{"title": "SQLi", "target_files": ["routes/login.py"]}]}}}}],
                        is_stream,
                        request,
                    )
                return _sse_or_json_response([{"text": "Plan done."}], is_stream, request)
            if st == "explorer":
                if t == 1:
                    return _sse_or_json_response(
                        [{"functionCall": {"name": "read_file", "args": {"filepath": "routes/login.py"}}}],
                        is_stream,
                        request,
                    )
                return _sse_or_json_response([{"text": "Neutral map complete."}], is_stream, request)
            if st == "researcher":
                if t == 1:
                    line_no = len(big_code.splitlines())
                    return _sse_or_json_response(
                        [{
                            "functionCall": {
                                "name": "report_findings",
                                "args": {
                                    "report": {
                                        "findings": [{
                                            "title": "SQLi in login_user",
                                            "severity": "CRITICAL",
                                            "filepath": "routes/login.py",
                                            "line_numbers": [line_no],
                                            "description": "Unparameterized SQL query",
                                            "cwe": "CWE-89",
                                        }]
                                    }
                                },
                            }
                        }],
                        is_stream,
                        request,
                    )
                return _sse_or_json_response([{"text": "Reported 1 finding."}], is_stream, request)
            if st == "reviewer":
                if t == 1:
                    return _sse_or_json_response([{"functionCall": {"name": "get_findings", "args": {}}}], is_stream, request)
                rows = read_findings(db_path, run_id="r_cache")
                fid = int(rows[0]["id"])
                return _sse_or_json_response(
                    [{"text": json.dumps({"route": "confirmed", "reason": "ok", "finding_verdicts": [{"finding_id": fid, "route": "confirmed", "reason": "ok"}]})}],
                    is_stream,
                    request,
                )
            if st == "critic":
                if t == 1:
                    return _sse_or_json_response([{"functionCall": {"name": "get_findings", "args": {}}}], is_stream, request)
                rows = read_findings(db_path, run_id="r_cache")
                fid = int(rows[0]["id"])
                return _sse_or_json_response(
                    [{"text": json.dumps({"route": "viable", "reason": "ok", "finding_verdicts": [{"finding_id": fid, "route": "viable", "reason": "ok"}]})}],
                    is_stream,
                    request,
                )
            if st == "calibrator":
                return _sse_or_json_response(
                    [{"text": json.dumps({"finding_id": 1, "mantis_risk_score": 9.5, "priority": "CRITICAL", "impact_score": 5, "likelihood_score": 4, "reasoning": "SQLi"})}],
                    is_stream,
                    request,
                )
            return _sse_or_json_response([{"text": "NO_ENTRY"}], is_stream, request)

        env = {
            "VERTEXAI_PROJECT": "test-proj",
            "VERTEXAI_LOCATION": "global",
            "MANTIS_LLM_STREAM": "0",
        }
        with (
            mock.patch.dict(os.environ, env),
            mock.patch("litellm.llms.vertex_ai.gemini.vertex_and_google_ai_studio_gemini.VertexLLM._ensure_access_token_async", new=mock.AsyncMock(return_value=("fake-bearer-tok", "test-proj"))),
            mock.patch("litellm.llms.vertex_ai.context_caching.vertex_ai_context_caching.ContextCachingEndpoints._ensure_access_token_async", new=mock.AsyncMock(return_value=("fake-bearer-tok", "test-proj"))),
            mock.patch.object(httpx.AsyncClient, "send", _fake_send),
        ):
            workflow, cfg = gl.load_workflow_from_json(str(_REF_ROOT / "workflow.json"), load_local=False)
            ctrl = BudgetController(config=BudgetConfig(max_tokens=0, max_wall_clock_seconds=0), run_id="r_cache")
            rc = RunContext(
                jail_dir=self.repo,
                db_path=db_path,
                target_file=self.repo,
                run_id="r_cache",
                sandbox=StaticOnlyEnvironment(target_path=self.repo),
                budget_controller=ctrl,
                enable_context_cache=True,
                defer_reporter=True,
            )
            tok = current_run_context.set(rc)
            try:
                runner = InMemoryRunner(agent=workflow, app_name="cache_app")
                sess = await runner.session_service.create_session(
                    app_name="cache_app",
                    user_id=mantis_main.USER_ID,
                    state={"db_path": db_path, "run_id": "r_cache", "filepath": self.repo},
                )
                seed = types.Content(role="user", parts=[types.Part.from_text(text=f"Audit {self.repo}")])
                failed = await mantis_main._drive_campaign(
                    runner,
                    sess.id,
                    seed,
                    None,
                    filepath=self.repo,
                    run_id="r_cache",
                    db_path=db_path,
                    status_map=cfg.get("on_enter_status"),
                    budget_controller=ctrl,
                    transcript=None,
                )
            finally:
                current_run_context.reset(tok)

        self.assertFalse(failed)
        creates = [x for x in http_log if x["method"] == "POST" and x["url"].endswith("/cachedContents")]
        deletes = [x for x in http_log if x["method"] == "DELETE" and cache_handle in x["url"]]
        cached_gens = [x for x in http_log if x["method"] == "POST" and x["body"].get("cachedContent") == cache_handle]

        self.assertEqual(len(creates), 1, f"Expected 1 CachedContent POST, got {len(creates)}")
        create_body = creates[0]["body"]
        self.assertEqual(create_body.get("ttl"), "900s")
        self.assertIn("contents", create_body)
        self.assertEqual(create_body["contents"][-1]["role"], "model")
        self.assertTrue("systemInstruction" in create_body or "system_instruction" in create_body)
        self.assertIn("tools", create_body)
        # Gemini wire shape: every tool entry carries function declarations,
        # never OpenAI's `{"type": "function", "function": {...}}` (HTTP 400 live).
        self.assertTrue(create_body["tools"])
        for tool_entry in create_body["tools"]:
            self.assertTrue(
                set(tool_entry) <= {"function_declarations", "functionDeclarations"},
                f"cachedContents tool entry is not Gemini-shaped: {sorted(tool_entry)}",
            )
            decls = tool_entry.get("function_declarations") or tool_entry.get("functionDeclarations")
            self.assertTrue(decls)
            self.assertTrue(all("name" in d for d in decls))

        # researcher (2 turns) + reviewer (2 turns) + critic (2 turns) = 6 delta-only generateContent calls!
        self.assertEqual(len(cached_gens), 6)
        for cg in cached_gens:
            b = cg["body"]
            self.assertNotIn("system_instruction", b)
            self.assertNotIn("systemInstruction", b)
            self.assertNotIn("tools", b)
            self.assertNotIn("toolConfig", b)
            # Delta-only contents (1 turn on T1, 3 turns on T2) — never the 12-turn stem!
            self.assertLessEqual(len(b["contents"]), 3)

        # Guaranteed DELETE in _drive_campaign finally:!
        self.assertEqual(len(deletes), 1)
        rows = read_findings(db_path, run_id="r_cache")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "static_confirmed")

    async def test_4_explicit_cached_content_failsafe_fallback_on_create_error_and_expired_handle(self):
        big_code = "# padding comment for realistic stem size\n" * 600 + "def f(x):\n    return x\n"
        Path(self.repo, "routes", "login.py").write_text(big_code, encoding="utf-8")
        db_path = os.path.join(self.tmp, "fallback.db")
        init_db(db_path)

        # Case B: cachedContents POST succeeds, then generateContent with cachedContent returns 404 (expired TTL)
        # -> ResilientLiteLlm evicts handle and retries in-turn with full stem!
        seen_gen_bodies: list[dict] = []
        handle = "projects/test-proj/locations/global/cachedContents/expired123"

        async def _fake_send_expired(_client_self, request: httpx.Request, **_kw):
            url = str(request.url)
            method = request.method.upper()
            body = json.loads(request.content.decode("utf-8")) if request.content else {}
            if method == "POST" and url.endswith("/cachedContents"):
                return httpx.Response(200, json={"name": handle}, request=request)
            if method == "DELETE":
                return httpx.Response(200, json={}, request=request)
            seen_gen_bodies.append(body)
            if body.get("cachedContent") == handle:
                return httpx.Response(
                    404,
                    json={"error": {"code": 404, "message": "CachedContent not found or expired", "status": "NOT_FOUND"}},
                    request=request,
                )
            return httpx.Response(
                200,
                json={
                    "candidates": [{"content": {"role": "model", "parts": [{"text": "Done."}]}, "finishReason": "STOP"}],
                    "usageMetadata": {"promptTokenCount": 5000, "candidatesTokenCount": 5, "totalTokenCount": 5005},
                },
                request=request,
            )

        env = {"VERTEXAI_PROJECT": "test-proj", "VERTEXAI_LOCATION": "global", "MANTIS_LLM_STREAM": "0"}
        with (
            mock.patch.dict(os.environ, env),
            mock.patch("litellm.llms.vertex_ai.gemini.vertex_and_google_ai_studio_gemini.VertexLLM._ensure_access_token_async", new=mock.AsyncMock(return_value=("tok", "test-proj"))),
            mock.patch("litellm.llms.vertex_ai.context_caching.vertex_ai_context_caching.ContextCachingEndpoints._ensure_access_token_async", new=mock.AsyncMock(return_value=("tok", "test-proj"))),
            mock.patch.object(httpx.AsyncClient, "send", _fake_send_expired),
        ):
            mini_spec = {
                "name": "mini_cache_fallback",
                "config": {"default_model": "vertex_ai/gemini-3.8-flash", "reasoning_effort": "medium"},
                "nodes": [
                    {"id": "explorer", "type": "agent", "prefix_group": "audit_stem", "tools": ["read_file"]},
                    {"id": "researcher", "type": "agent", "fork_from": "explorer", "prefix_group": "audit_stem", "tools": ["read_file", "report_findings"]},
                ],
                "edges": [{"from": "START", "to": "explorer"}, {"from": "explorer", "to": "researcher"}],
            }
            spec_path = os.path.join(self.tmp, "mini_fb.json")
            Path(spec_path).write_text(json.dumps(mini_spec), encoding="utf-8")
            wf, _ = gl.load_workflow_from_json(spec_path, load_local=False)
            rc = RunContext(
                jail_dir=self.repo,
                db_path=db_path,
                target_file=self.repo,
                run_id="r_fb",
                sandbox=StaticOnlyEnvironment(target_path=self.repo),
                enable_context_cache=True,
            )
            tok = current_run_context.set(rc)
            try:
                runner = InMemoryRunner(agent=wf, app_name="fb_app")
                sess = await runner.session_service.create_session(app_name="fb_app", user_id="u", state={})
                # Seed a big prompt so stem >= 4096 tokens
                seed = types.Content(role="user", parts=[types.Part.from_text(text=big_code)])
                async for _ in runner.run_async(user_id="u", session_id=sess.id, new_message=seed):
                    pass
            finally:
                current_run_context.reset(tok)

        # explorer (1 call) + researcher attempt 1 with cachedContent (404) + researcher retry without cachedContent (200)
        cached_attempts = [b for b in seen_gen_bodies if b.get("cachedContent") == handle]
        fallback_attempts = [b for b in seen_gen_bodies if "cachedContent" not in b]
        self.assertEqual(len(cached_attempts), 1)
        self.assertGreaterEqual(len(fallback_attempts), 2)
        # Fallback retry sent full stem + system_instruction + tools!
        self.assertIn("system_instruction", fallback_attempts[-1])
        self.assertIn("tools", fallback_attempts[-1])
        self.assertGreaterEqual(len(fallback_attempts[-1]["contents"]), 3)

    async def test_5_token_efficiency_2_static_reproducer_skip_and_inv1_sandbox_executed_gate(self):
        db_path = os.path.join(self.tmp, "inv1.db")
        init_db(db_path)
        repro_cls = gl.create_classifier("repro_classifier", ["success"])

        # Without sandbox_executed=True on a sandboxed run, ReproVerdict("success") MUST downgrade to DEFAULT_ROUTE!
        rc_unexec = RunContext(
            jail_dir=self.repo,
            db_path=db_path,
            target_file=self.repo,
            run_id="r_inv1",
            sandbox=StaticOnlyEnvironment(target_path=self.repo),
            sandbox_executed=False,
        )
        tok = current_run_context.set(rc_unexec)
        try:
            ev_blocked = await repro_cls._func(
                SimpleNamespace(state={"verdict": json.dumps({"route": "success", "reason": "self-claimed"})}),
                None,
            )
            self.assertEqual(ev_blocked.actions.route, gl.DEFAULT_ROUTE)
        finally:
            current_run_context.reset(tok)

        # With sandbox_executed=True, ReproVerdict("success") routes "success" cleanly!
        rc_exec = RunContext(
            jail_dir=self.repo,
            db_path=db_path,
            target_file=self.repo,
            run_id="r_inv1_ok",
            sandbox=SimpleNamespace(working_dir="/workspace"),
            sandbox_executed=True,
            finding_evidence={"1": {"reproduced": True}},
        )
        tok2 = current_run_context.set(rc_exec)
        try:
            ev_ok = await repro_cls._func(
                SimpleNamespace(state={"verdict": json.dumps({"route": "success", "reason": "verified"})}),
                None,
            )
            self.assertEqual(ev_ok.actions.route, "success")
        finally:
            current_run_context.reset(tok2)

    def test_6_sandbox_gated_stage_skips_history_single_file_planner_dedup_and_reporter(self):
        db_path = os.path.join(self.tmp, "skips.db")
        init_db(db_path)
        single_file = os.path.join(self.repo, "routes", "login.py")

        with mock.patch.dict(
            os.environ,
            {"VERTEXAI_PROJECT": "dummy-proj", "VERTEXAI_LOCATION": "global"},
        ):
            wf, _ = gl.load_workflow_from_json(str(_REF_ROOT / "workflow.json"), load_local=False)
        agents = _iter_agents(wf)

        # Seed 1 finding on login.py and repo-root summary/threat_model artifacts
        write_findings(
            db_path,
            single_file,
            [{"title": "SQLi", "severity": "HIGH", "filepath": "routes/login.py", "description": "d", "line_numbers": [3]}],
            run_id="r_skips",
        )
        canon_root = os.path.realpath(self.repo)
        record_artifact(
            db_path, "r_skips", "summary", "workspace/.structured/summary.json",
            json.dumps({"overview": "Repo summary", "key_modules": ["routes/login.py"]}),
            metadata={"resource": canon_root},
        )
        record_artifact(
            db_path, "r_skips", "threat_model", "workspace/.structured/threat_model.json",
            json.dumps({"threats": ["SQLi"]}),
            metadata={"resource": canon_root},
        )

        # 1. With sandbox=None (test_suite.py mode): NONE of history, architect, planner, deduplicator, reporter skip!
        rc_none = RunContext(
            jail_dir=os.path.dirname(single_file),
            db_path=db_path,
            target_file=single_file,
            path_root=self.repo,
            run_id="r_skips",
            sandbox=None,
            defer_reporter=False,
        )
        tok = current_run_context.set(rc_none)
        try:
            for st in ("history", "architect", "threat_modeler", "planner", "deduplicator", "reporter"):
                cb = agents[st].before_agent_callback
                if cb is not None:
                    self.assertIsNone(cb(), f"{st} must NOT skip when ctx.sandbox is None")
        finally:
            current_run_context.reset(tok)

        # 2. With sandbox=StaticOnlyEnvironment: history, single-file architect/threat_modeler/planner,
        # <=1-finding deduplicator, static reproducer, and non-narrative reporter ALL skip!
        rc_sb = RunContext(
            jail_dir=os.path.dirname(single_file),
            db_path=db_path,
            target_file=single_file,
            path_root=self.repo,
            run_id="r_skips",
            sandbox=StaticOnlyEnvironment(target_path=single_file),
            defer_reporter=False,
        )
        tok2 = current_run_context.set(rc_sb)
        try:
            for st in ("history", "architect", "threat_modeler", "planner", "deduplicator", "reproducer", "reporter"):
                cb = agents[st].before_agent_callback
                self.assertIsNotNone(cb, f"{st} missing before_agent_callback")
                res = cb()
                self.assertIsNotNone(res, f"{st} should skip when ctx.sandbox is StaticOnlyEnvironment")
            # Deterministic single-file plan was persisted to DB!
            plan_raw = read_artifact(db_path, artifact_type="plan", run_id="r_skips", resource=single_file)
            self.assertIsNotNone(plan_raw)
            self.assertIn("login.py", plan_raw)
        finally:
            current_run_context.reset(tok2)

    def test_7_auto_mode_source_count_threshold_and_file_by_file_risk_ordering(self):
        # 10 .py files + 215 .md/.txt files = 225 total (> 200), but only 10 countable source files!
        doc_heavy = os.path.join(self.tmp, "doc_heavy")
        os.makedirs(os.path.join(doc_heavy, "src"), exist_ok=True)
        os.makedirs(os.path.join(doc_heavy, "docs"), exist_ok=True)
        discovered: list[str] = []
        for i in range(10):
            p = os.path.join(doc_heavy, "src", f"mod_{i}.py")
            Path(p).write_text("def f():\n    return 1\n", encoding="utf-8")
            discovered.append(p)
        for i in range(215):
            p = os.path.join(doc_heavy, "docs", f"note_{i}.md")
            Path(p).write_text("# doc\n", encoding="utf-8")
            discovered.append(p)

        targets, _astm, mode = mantis_main.resolve_scan_targets(
            Path(doc_heavy),
            {"scan_mode": "auto", "default_model": "vertex_ai/gemini-3.8-flash"},
            discovered,
            db_path=os.path.join(self.tmp, "doc_heavy.db"),
        )
        self.assertEqual(mode, mantis_main.SCAN_MODE_WHOLE)
        self.assertEqual(targets, [str(Path(doc_heavy).resolve())])

        # Risk-ordered per-file permutation puts high-risk code ahead of README/docs/lockfiles!
        mixed_files = [
            os.path.join(doc_heavy, "docs", "note_0.md"),
            os.path.join(doc_heavy, "src", "mod_0.py"),
        ]
        ordered = mantis_main._risk_order_file_sweep_targets(mixed_files, doc_heavy)
        self.assertEqual(ordered[0], os.path.join(doc_heavy, "src", "mod_0.py"))
        self.assertEqual(ordered[1], os.path.join(doc_heavy, "docs", "note_0.md"))

    async def test_8_slim_report_findings_wire_schema_and_typed_domain_tool_models(self):
        from google import adk
        from google.adk.models import LlmRequest

        # Measure report_findings + domain tools wire schema via ADK tool declaration pipeline
        ag = adk.Agent(
            name="schema_probe",
            model="openai/gpt-4o",
            instruction="probe",
            tools=[
                rt.report_findings,
                rt.record_plan,
                rt.generate_report,
                rt.record_exploit_chain,
                rt.record_learning,
            ],
        )
        req = LlmRequest()
        for t in await ag.canonical_tools():
            await t.process_llm_request(tool_context=None, llm_request=req)
        _, wire_tools, _, _, _ = await _get_completion_inputs(req, model="vertex_ai/gemini-3.8-flash")
        by_name = {wt["function"]["name"]: wt["function"] for wt in wire_tools}

        rf_bytes = len(json.dumps(by_name["report_findings"]))
        self.assertLess(rf_bytes, 3500, f"report_findings schema still bloated: {rf_bytes} bytes")
        rf_dump = json.dumps(by_name["report_findings"])
        self.assertNotIn("triage_checklist", rf_dump)
        self.assertNotIn("calibration_checklist", rf_dump)
        self.assertNotIn("reattack_variants", rf_dump)

        for typed_tool in ("record_plan", "generate_report", "record_exploit_chain", "record_learning"):
            params = by_name[typed_tool]["parameters"]
            arg_schema = next(iter(params["properties"].values()))
            # Must expose concrete properties (or $ref to concrete properties), NOT bare additionalProperties: True!
            has_props = bool(arg_schema.get("properties")) or "$ref" in arg_schema or "$defs" in params
            self.assertTrue(has_props, f"{typed_tool} still exposes untyped dict schema: {params}")

        # Runtime backward compatibility for dict calls + record_learning validation & reflector aliases!
        db_path = os.path.join(self.tmp, "slim.db")
        init_db(db_path)
        rc = RunContext(jail_dir=self.repo, db_path=db_path, target_file=self.repo, run_id="r_slim")
        tok = current_run_context.set(rc)
        try:
            ok_rf = rt.report_findings({
                "findings": [{
                    "title": "SQLi in login",
                    "severity": "CRITICAL",
                    "filepath": "routes/login.py",
                    "line_numbers": [4],
                    "code_paths": ["routes/login.py:4:login_user"],
                    "cwe": "CWE-89",
                    "description": "Unparameterized SQL",
                    "remediation": "Use ? placeholders",
                }]
            })
            self.assertIn("SUCCESS", ok_rf)

            ok_plan = rt.record_plan({
                "investigations": [{
                    "title": "Check login",
                    "target_files": ["routes/login.py"],
                    "line_range": [1, 10],
                    "priority": "high",
                }]
            })
            self.assertIn("SUCCESS", ok_plan)
            saved_plan = json.loads(read_artifact(db_path, artifact_type="plan", run_id="r_slim"))
            self.assertEqual(saved_plan["investigations"][0].get("line_range"), [1, 10])
            self.assertEqual(saved_plan["investigations"][0].get("priority"), "high")

            # Empty learning is refused!
            empty_learn = rt.record_learning({"category": "sql", "learning": "   "})
            self.assertIn("ERROR SAVING LEARNING", empty_learn)

            # Reflector vocabulary {cue, lesson, evidence, confidence, target_stage} succeeds!
            alias_learn = rt.record_learning({
                "cue": "auditing sqlite queries",
                "lesson": "check f-strings in conn.execute",
                "evidence": "routes/login.py:4",
                "confidence": "high",
                "target_stage": "researcher",
            })
            self.assertIn("SUCCESS", alias_learn)
        finally:
            current_run_context.reset(tok)


if __name__ == "__main__":
    unittest.main()

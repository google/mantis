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

"""Regression tests for Phase-2 CL 2 (LLM wire portability, CLI overrides, and SecretScrubber)."""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

import httpx  # noqa: E402
from google.adk.models import LlmRequest, LlmResponse  # noqa: E402
from google.adk.models.lite_llm import LiteLlm, _is_anthropic_model  # noqa: E402
from google.adk.tools.set_model_response_tool import SetModelResponseTool  # noqa: E402
from google.genai import types  # noqa: E402

import core.config as C  # noqa: E402
import core.graph_loader as GL  # noqa: E402
from core.budget import BudgetConfig, BudgetController  # noqa: E402
from core.context import RunContext, current_run_context  # noqa: E402
from core.llm_gateway import (  # noqa: E402
    UNTRUSTED_DATA_END,
    UNTRUSTED_DATA_START,
    SecretScrubber,
)


class P2LlmWireRegressionTest(unittest.TestCase):
    """Covers all findings owned by Phase-2 CL 2."""

    def test_01_secret_scrubber_preserves_code_and_redacts_quoted_literals(self):
        auth_code = (
            'def verify_login(request, user):\n'
            '    password = request.form.get("password", "")\n'
            '    token = request.args.get("token")\n'
            '    const_secret = process.env.JWT_SECRET\n'
            '    csrf_token = generate_csrf_token(user.id)\n'
            '    api_key = os.environ.get("API_KEY")\n'
            '    default_pw = "password"\n'
            '    tpl_secret = "${SERVICE_SECRET_KEY}"\n'
            '    return check_hash(password, token)\n'
        )
        self.assertEqual(SecretScrubber.scrub(auth_code), auth_code)

        fake_api_key = "_".join(("demo", "key", "9876543210", "abcdef1234"))
        fake_password = "".join(("Demo", "Pass", "Word", "98765!"))
        fake_client_secret = "-".join(("demo", "client", "val", "12345"))
        fake_auth_token = "_".join(("tok", "demo", "abcdef0123", "456789abcdef"))
        leaked_literals = (
            f'api_key = "{fake_api_key}"\n'
            f"password = '{fake_password}'\n"
            f'{{"client_secret": "{fake_client_secret}"}}\n'
            f'auth_token = "{fake_auth_token}"\n'
        )
        scrubbed = SecretScrubber.scrub(leaked_literals)
        self.assertNotIn(fake_api_key, scrubbed)
        self.assertNotIn(fake_password, scrubbed)
        self.assertNotIn(fake_client_secret, scrubbed)
        self.assertNotIn(fake_auth_token, scrubbed)
        self.assertIn("[REDACTED_CREDENTIAL]", scrubbed)
        self.assertIn("api_key =", scrubbed)

    def test_02_litellm_import_sets_offline_production_env_defaults(self):
        env = dict(os.environ)
        for key in (
            "LITELLM_LOCAL_MODEL_COST_MAP",
            "LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS",
            "LITELLM_MODE",
        ):
            env.pop(key, None)

        probe_code = (
            "import json, os, sys, urllib.request\n"
            f"sys.path.insert(0, {str(_REF_ROOT)!r})\n"
            "fetches = []\n"
            "_orig = urllib.request.urlopen\n"
            "def _blocked(url, *a, **kw):\n"
            "    fetches.append(str(getattr(url, 'full_url', url)))\n"
            "    raise OSError('network blocked in test')\n"
            "urllib.request.urlopen = _blocked\n"
            "import core.config\n"
            "print(json.dumps({\n"
            "    'cost_map': os.environ.get('LITELLM_LOCAL_MODEL_COST_MAP'),\n"
            "    'beta_headers': os.environ.get('LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS'),\n"
            "    'mode': os.environ.get('LITELLM_MODE'),\n"
            "    'fetches': fetches,\n"
            "}))\n"
        )
        proc = subprocess.run(
            [sys.executable, "-P", "-c", probe_code],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
            check=True,
        )
        payload = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(payload["cost_map"], "True")
        self.assertEqual(payload["beta_headers"], "True")
        self.assertEqual(payload["mode"], "PRODUCTION")
        self.assertEqual(payload["fetches"], [])

    def test_03_allowed_openai_params_forwards_reasoning_effort_without_matching_examples(self):
        clean_env = {
            "GEMINI_API_KEY": "test-gemini-key",
            "VERTEXAI_PROJECT": "test-project",
            "VERTEXAI_LOCATION": "global",
            "OPENAI_API_KEY": "test-openai-key",
        }
        with mock.patch.dict(os.environ, clean_env, clear=True):
            for model_id in (
                "gemini/gemini-3.8-flash-custom",
                "vertex_ai/gemini-3.8-pro-custom",
                "vertex_ai/gemini-2.5-pro",
                "vertex_ai/openai/zai-org/glm-5.2-maas",
                "deepseek/deepseek-r1",
                "openai/qwen3-32b",
                "openai/gpt-5-mini",
                "openai/o1",
                "openai/o3-mini",
                "openai/o4-mini",
            ):
                _, kw = C.get_llm_kwargs(model_id=model_id, reasoning_effort="low")
                self.assertEqual(
                    kw.get("allowed_openai_params"),
                    ["reasoning_effort"],
                    f"{model_id} should whitelist reasoning_effort against drop_params=True",
                )

            # Synthetic test-pinned example IDs MUST NOT match versioned reasoning families
            for synthetic in ("vertex_ai/gemini-example", "openai/gpt-example", "openai/gpt-4o"):
                _, syn_kw = C.get_llm_kwargs(model_id=synthetic, reasoning_effort="low")
                self.assertNotIn("allowed_openai_params", syn_kw, synthetic)
                if "example" in synthetic:
                    self.assertIsNone(syn_kw.get("timeout"), synthetic)

            # Wire-level proof through ResilientLiteLlm + httpx interception on an unlisted Gemini 3.x ID
            _, wire_kw = C.get_llm_kwargs(
                model_id="gemini/gemini-3.8-unlisted-preview",
                reasoning_effort="low",
            )
            captured_bodies: list[dict] = []

            async def _fake_send(client_self, request: httpx.Request, **kwargs):
                if request.content:
                    try:
                        captured_bodies.append(json.loads(request.content.decode("utf-8")))
                    except Exception:
                        pass
                resp_json = {
                    "candidates": [
                        {
                            "content": {"role": "model", "parts": [{"text": "wire ok"}]},
                            "finishReason": "STOP",
                            "index": 0,
                        }
                    ],
                    "usageMetadata": {
                        "promptTokenCount": 10,
                        "candidatesTokenCount": 2,
                        "totalTokenCount": 12,
                    },
                }
                return httpx.Response(200, json=resp_json, request=request)

            llm = C.ResilientLiteLlm(**wire_kw)
            req = LlmRequest(
                model=wire_kw["model"],
                contents=[types.Content(role="user", parts=[types.Part.from_text(text="ping")])],
            )
            with mock.patch.object(httpx.AsyncClient, "send", _fake_send):
                asyncio.run(self._drain_async_gen(llm.generate_content_async(req, stream=False)))

            self.assertTrue(captured_bodies, "expected outbound HTTP JSON payload")
            gen_cfg = captured_bodies[-1].get("generationConfig") or {}
            thinking_cfg = gen_cfg.get("thinkingConfig") or {}
            self.assertEqual(str(thinking_cfg.get("thinkingLevel", "")).lower(), "low")

    @staticmethod
    async def _drain_async_gen(agen):
        return [item async for item in agen]

    def test_04_workflow_cli_and_env_overrides_beat_per_node_defaults(self):
        wf_path = str(_REF_ROOT / "workflow.json")
        env = {
            "OPENAI_API_KEY": "dummy",
            "LLM_API_BASE": "http://env-loses.local/v1",
            "LLM_TIMEOUT": "60",
            "MANTIS_LLM_STREAM": "0",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            workflow, _cfg = GL.load_workflow_from_json(
                wf_path,
                model_override="openai/gpt-5",
                api_base_override="http://cli-wins.local/v1",
                timeout_override=900.0,
                reasoning_effort_override="low",
                load_local=False,
            )

        agent_models = self._collect_workflow_agent_models(workflow)
        self.assertIn("critic", agent_models)
        self.assertIn("researcher", agent_models)
        for name, model_inst in agent_models.items():
            args = getattr(model_inst, "_additional_args", {})
            self.assertEqual(args.get("reasoning_effort"), "low", name)
            self.assertEqual(args.get("api_base"), "http://cli-wins.local/v1", name)
            self.assertEqual(args.get("timeout"), 900.0, name)

        # Unstreamed default timeout on a high-effort node must not be crushed to
        # 180s. `patcher` is the shipped high-effort node outside the
        # `audit_stem` prefix_group (whose members share the stem's effort).
        with mock.patch.dict(
            os.environ,
            {"OPENAI_API_KEY": "dummy", "MANTIS_LLM_STREAM": "0"},
            clear=True,
        ):
            wf_default, _ = GL.load_workflow_from_json(
                wf_path,
                model_override="openai/gpt-5",
                load_local=False,
            )
        default_models = self._collect_workflow_agent_models(wf_default)
        patcher_args = getattr(default_models["patcher"], "_additional_args", {})
        self.assertEqual(patcher_args.get("reasoning_effort"), "high")
        self.assertEqual(patcher_args.get("timeout"), 900.0)
        # A global override applies uniformly across the prefix_group, so
        # every audit_stem member keeps byte-identical model args.
        stem_args = {
            n: dict(getattr(default_models[n], "_additional_args", {}))
            for n in ("architect", "planner", "explorer", "researcher", "reviewer", "critic")
        }
        self.assertEqual(len({json.dumps(a, sort_keys=True, default=str) for a in stem_args.values()}), 1)

    @staticmethod
    def _collect_workflow_agent_models(workflow) -> dict[str, object]:
        found: dict[str, object] = {}
        for edge in workflow.edges:
            for n in (getattr(edge, "from_node", None), getattr(edge, "to_node", None)):
                agent = getattr(n, "agent", n)
                model_inst = getattr(agent, "model", None)
                name = getattr(agent, "name", None)
                if name and model_inst is not None and hasattr(model_inst, "_additional_args"):
                    found[str(name)] = model_inst
        return found

    def test_05a_sandbox_override_preserves_matching_type_options(self):
        with tempfile.TemporaryDirectory() as tmp:
            wf_copy = Path(tmp) / "workflow.json"
            wf_copy.write_bytes((_REF_ROOT / "workflow.json").read_bytes())
            local_copy = Path(tmp) / "workflow.local.json"
            local_copy.write_text(
                json.dumps(
                    {
                        "config": {
                            "default_model": "openai/gpt-5",
                            "sandbox": {
                                "type": "gce",
                                "options": {"project": "my-sandbox-proj", "zone": "us-central1-a"},
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "dummy"}, clear=True):
                _, cfg_same = GL.load_workflow_from_json(
                    str(wf_copy),
                    sandbox_override="gce",
                    load_local=True,
                )
            self.assertEqual(cfg_same["sandbox"]["type"], "gce")
            self.assertEqual(
                cfg_same["sandbox"]["options"],
                {"project": "my-sandbox-proj", "zone": "us-central1-a"},
            )

    def test_05b_malformed_local_overlay_raises_config_validation_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            wf_copy = Path(tmp) / "workflow.json"
            wf_copy.write_bytes((_REF_ROOT / "workflow.json").read_bytes())
            local_copy = Path(tmp) / "workflow.local.json"
            local_copy.write_text('{\n  "config": {\n    bad_json\n', encoding="utf-8")
            with self.assertRaises(C.ConfigValidationError) as ctx_err:
                GL.load_workflow_from_json(str(wf_copy), load_local=True)
            self.assertIn("workflow.local.json", str(ctx_err.exception))

    def test_05c_invalid_numeric_env_raises_config_validation_error(self):
        with mock.patch.dict(
            os.environ,
            {"OPENAI_API_KEY": "dummy", "LLM_TIMEOUT": "not-a-number"},
            clear=True,
        ):
            with self.assertRaises(C.ConfigValidationError):
                C.get_llm_kwargs(model_id="openai/gpt-4o")

    def test_05d_output_ceiling_clamped_when_equal_to_context_window(self):
        with mock.patch("litellm.get_max_tokens", return_value=128000), mock.patch.object(
            C, "resolve_context_limit", return_value=128000
        ):
            clamped = C.resolve_output_ceiling("openai/equal-window-model")
            self.assertIsNotNone(clamped)
            self.assertLess(clamped, 128000)
            self.assertEqual(clamped, 32000)

    def test_05e_deterministic_4xx_errors_never_classified_retryable_or_rate_limit(self):
        import litellm

        bad_req = litellm.BadRequestError(
            message="Invalid parameter: quota project not set or request timeout invalid",
            model="openai/gpt-4o",
            llm_provider="openai",
        )
        self.assertFalse(C.is_rate_limit_error(bad_req))
        self.assertFalse(C.is_retryable_llm_error(bad_req))

    def test_06_run_llm_kwargs_and_flex_headers_wired_for_auxiliary_models(self):
        self.assertTrue(hasattr(C, "get_run_llm_kwargs"), "get_run_llm_kwargs missing")
        cfg = {
            "default_model": "vertex_ai/gemini-3.8-flash",
            "api_base": "http://gateway.local/v1",
            "timeout": 720.0,
            "reasoning_effort": "low",
        }
        with mock.patch.dict(
            os.environ,
            {
                "VERTEXAI_PROJECT": "demo-proj",
                "VERTEXAI_LOCATION": "global",
                "VERTEX_FLEX": "1",
            },
            clear=True,
        ):
            resolved, kw = C.get_run_llm_kwargs("vertex_ai/gemini-3.8-flash", cfg)
        self.assertEqual(resolved, "vertex_ai/gemini-3.8-flash")
        self.assertEqual(kw.get("api_base"), "http://gateway.local/v1")
        self.assertEqual(kw.get("timeout"), 720.0)
        self.assertEqual(kw.get("reasoning_effort"), "low")
        headers = kw.get("extra_headers") or {}
        self.assertEqual(headers.get("X-Vertex-AI-LLM-Request-Type"), "shared")
        self.assertEqual(headers.get("X-Vertex-AI-LLM-Shared-Request-Type"), "flex")

        main_src = (_REF_ROOT / "main.py").read_text(encoding="utf-8")
        self.assertGreaterEqual(main_src.count("get_run_llm_kwargs("), 3)

    def test_07a_bare_claude_normalizes_to_anthropic_prefix_for_adk_thinking_replay(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "dummy"}, clear=True):
            norm = C.normalize_model_id("claude-opus-5")
            self.assertEqual(norm, "anthropic/claude-opus-5")
            self.assertTrue(_is_anthropic_model(norm))

    def test_07b_vertex_claude_preserves_summarized_adaptive_thinking_display(self):
        from litellm.llms.vertex_ai.vertex_ai_partner_models.anthropic.transformation import (
            VertexAIAnthropicConfig,
        )

        mapped = VertexAIAnthropicConfig().map_openai_params(
            {"reasoning_effort": "high"}, {}, "claude-opus-5", True
        )
        self.assertEqual(
            mapped.get("thinking"),
            {"type": "adaptive", "display": "summarized"},
        )

    def test_07c_bedrock_claude_uses_client_editing_and_strips_prefix_bound_thoughts(self):
        bedrock_claude = "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0"
        self.assertTrue(C.supports_server_clear_tool_uses("anthropic/claude-opus-5"))
        self.assertTrue(C.supports_server_clear_tool_uses("vertex_ai/claude-opus-5"))
        self.assertFalse(C.supports_server_clear_tool_uses(bedrock_claude))

        with mock.patch.object(C, "resolve_context_limit", return_value=100_000):
            _, bedrock_kw = C.get_llm_kwargs(bedrock_claude)
            self.assertNotIn("context_management", bedrock_kw)
            client_edit = C.client_context_editing(bedrock_claude)
            self.assertIsNotNone(client_edit)

            ctrl = BudgetController(
                config=BudgetConfig(max_tokens=0, max_wall_clock_seconds=0), run_id="r"
            )
            tok = current_run_context.set(
                RunContext(
                    jail_dir="/tmp",
                    db_path="",
                    target_file="a.py",
                    run_id="r",
                    budget_controller=ctrl,
                    node_context={},
                )
            )
            try:
                cb = GL._make_client_context_editing_before_model_callback(
                    "researcher", model=bedrock_claude
                )
                req = LlmRequest()
                req.config.system_instruction = "audit"
                req.contents = [
                    types.Content(role="user", parts=[types.Part.from_text(text="start")])
                ]
                for i in range(10):
                    thought_part = types.Part(text=f"thinking {i}", thought=True)
                    thought_part.thought_signature = b"sig-" + str(i).encode("ascii")
                    fc_part = types.Part(
                        function_call=types.FunctionCall(
                            name="read_file", id=f"c{i}", args={"n": i}
                        )
                    )
                    fc_part.thought_signature = b"fcsig-" + str(i).encode("ascii")
                    req.contents.append(types.Content(role="model", parts=[thought_part, fc_part]))
                    req.contents.append(
                        types.Content(
                            role="user",
                            parts=[
                                types.Part(
                                    function_response=types.FunctionResponse(
                                        name="read_file",
                                        id=f"c{i}",
                                        response={"result": f"{i}:" + ("x" * 20_000)},
                                    )
                                )
                            ],
                        )
                    )
                asyncio.run(cb(callback_context=None, llm_request=req))
            finally:
                current_run_context.reset(tok)

        # Find last cleared FunctionResponse index
        last_cleared_idx = -1
        for idx, content in enumerate(req.contents):
            for p in content.parts or []:
                fr = getattr(p, "function_response", None)
                if fr is not None and fr.response == {"result": GL.CLEARED_TOOL_RESULT_TEXT}:
                    last_cleared_idx = idx
        self.assertGreater(last_cleared_idx, 0)

        # All model turns at or before last_cleared_idx must have thought & thought_signature stripped
        for idx, content in enumerate(req.contents):
            if content.role != "model":
                continue
            has_thought = any(getattr(p, "thought", False) for p in (content.parts or []))
            has_sig = any(
                getattr(p, "thought_signature", None) is not None for p in (content.parts or [])
            )
            if idx <= last_cleared_idx:
                self.assertFalse(has_thought, f"turn {idx} still has thought part")
                self.assertFalse(has_sig, f"turn {idx} still has thought_signature")
                self.assertTrue(
                    any(getattr(p, "function_call", None) is not None for p in (content.parts or [])),
                    f"turn {idx} lost its function_call pairing",
                )
            else:
                self.assertTrue(has_thought, f"kept turn {idx} should retain recent thought")

    def test_08_handoff_bypasses_structured_sanitizer_and_preserves_prefix(self):
        handoff_note = (
            "Reviewed findings 1-3; finding 2 is false positive; next inspect auth.py:88."
        )

        async def _fake_upstream(_self, llm_request, stream=False):
            yield LlmResponse(
                content=types.Content(
                    role="model",
                    parts=[types.Part.from_text(text=handoff_note)],
                ),
                finish_reason=types.FinishReason.STOP,
            )

        req = LlmRequest(
            model="openai/gpt-5",
            contents=[types.Content(role="user", parts=[types.Part.from_text(text="review")])],
            config=types.GenerateContentConfig(system_instruction="You are reviewer."),
        )
        req.append_tools([SetModelResponseTool(C.ExtendedReviewVerdict)])

        rc = RunContext(jail_dir="/tmp", db_path="", target_file="auth.py", run_id="r1")
        tok = current_run_context.set(rc)
        try:
            llm = C.ResilientLiteLlm(model="openai/gpt-5")
            with mock.patch.object(LiteLlm, "generate_content_async", _fake_upstream), contextlib.redirect_stderr(
                io.StringIO()
            ):
                out_text, _toks = asyncio.run(
                    GL._write_handoff("reviewer", llm, req, limit_tokens=100_000)
                )
            self.assertEqual(out_text, handoff_note)
            self.assertNotIn("Fallback:", out_text)
            self.assertEqual(rc.verdict_fallbacks, 0)

            self.assertTrue(hasattr(C, "_HandoffLiteLlm"))
            handoff_llm = C._HandoffLiteLlm(model="openai/gpt-5")
            with mock.patch.object(LiteLlm, "generate_content_async", _fake_upstream):
                direct_resps = asyncio.run(
                    self._drain_async_gen(handoff_llm.generate_content_async(req, stream=False))
                )
            self.assertEqual(direct_resps[0].content.parts[0].text, handoff_note)
        finally:
            current_run_context.reset(tok)

    def test_09_focus_and_seed_report_reach_hunting_stages_only_across_all_modes(self):
        import main as mantis_main

        self.assertTrue(hasattr(mantis_main, "_build_operator_steering_blocks"))
        op_focus, seed_block = mantis_main._build_operator_steering_blocks(
            "Focus on IDOR in /api/orders",
            "Bug #99: user_id parameter was not checked against session owner.",
        )
        self.assertIn("Focus on IDOR in /api/orders", op_focus)
        self.assertNotIn(UNTRUSTED_DATA_START, op_focus)
        self.assertIn(UNTRUSTED_DATA_START, seed_block)
        self.assertIn(UNTRUSTED_DATA_END, seed_block)
        self.assertIn("Bug #99", seed_block)

        for mode in ("whole", "file-by-file", "cross-functional"):
            huge_memory = "Prior findings:\n" + ("- line of prior memory\n" * 500)
            rc = RunContext(
                jail_dir="/tmp",
                db_path="",
                target_file="orders.py",
                run_id="r1",
                scan_mode=mode,
                campaign_context=huge_memory,
                operator_focus=op_focus,
                seed_report_block=seed_block,
            )
            tok = current_run_context.set(rc)
            try:
                for hunt_stage in ("architect", "threat_modeler", "planner", "researcher"):
                    cb = GL._make_campaign_directive_before_model_callback(hunt_stage)
                    req = LlmRequest(
                        model="openai/gpt-5",
                        contents=[
                            types.Content(role="user", parts=[types.Part.from_text(text="go")])
                        ],
                        config=types.GenerateContentConfig(system_instruction="Base prompt."),
                    )
                    cb(callback_context=None, llm_request=req)
                    inst = req.config.system_instruction
                    self.assertIn("Focus on IDOR in /api/orders", inst, f"{mode}/{hunt_stage}")
                    self.assertIn("Bug #99", inst, f"{mode}/{hunt_stage}")
                    # Operator focus must not be trapped inside an untrusted fence
                    focus_pos = inst.index("Focus on IDOR in /api/orders")
                    self.assertEqual(
                        inst[:focus_pos].count(UNTRUSTED_DATA_START.split(" ")[0]),
                        inst[:focus_pos].count(UNTRUSTED_DATA_END),
                        f"{mode}/{hunt_stage}: operator focus enclosed inside untrusted fence!",
                    )

                for judge_stage in ("reviewer", "critic", "reproducer"):
                    cb_judge = GL._make_campaign_directive_before_model_callback(judge_stage)
                    req_j = LlmRequest(
                        model="openai/gpt-5",
                        contents=[
                            types.Content(role="user", parts=[types.Part.from_text(text="go")])
                        ],
                        config=types.GenerateContentConfig(system_instruction="Judge prompt."),
                    )
                    cb_judge(callback_context=None, llm_request=req_j)
                    inst_j = req_j.config.system_instruction
                    self.assertNotIn("Focus on IDOR in /api/orders", inst_j, f"{mode}/{judge_stage}")
                    self.assertNotIn("Bug #99", inst_j, f"{mode}/{judge_stage}")
            finally:
                current_run_context.reset(tok)

    def test_10_vertex_claude_unmapped_adaptive_thinking_and_context_limit(self):
        import litellm
        from litellm.llms.anthropic.chat.transformation import AnthropicConfig
        from litellm.llms.vertex_ai.vertex_ai_partner_models.anthropic.transformation import (
            VertexAIAnthropicConfig,
        )

        cfg = VertexAIAnthropicConfig()
        # Newer Vertex Claude 5.x revisions absent from LiteLLM's local vertex_ai
        # map must still advertise thinking/reasoning_effort and map to adaptive
        # thinking + output_config.effort instead of silently dropping effort.
        orig_is_adaptive = AnthropicConfig._is_adaptive_thinking_model

        def _unmapped_vertex_adaptive(model_name: str, provider: str) -> bool:
            if model_name == "claude-opus-5-9" and provider == "vertex_ai":
                return False
            return orig_is_adaptive(model_name, provider)

        with mock.patch.object(
            AnthropicConfig, "_is_adaptive_thinking_model", side_effect=_unmapped_vertex_adaptive
        ):
            for bare in ("claude-opus-5-9", "claude-opus-5-5"):
                supported = cfg.get_supported_openai_params(model=bare)
                self.assertIn("thinking", supported, bare)
                self.assertIn("reasoning_effort", supported, bare)
                mapped = cfg.map_openai_params(
                    non_default_params={"reasoning_effort": "medium", "max_tokens": 128000},
                    optional_params={},
                    model=bare,
                    drop_params=False,
                )
                self.assertEqual(
                    mapped.get("thinking"),
                    {"type": "adaptive", "display": "summarized"},
                    bare,
                )
                self.assertEqual(mapped.get("output_config"), {"effort": "medium"}, bare)
                # `_apply_output_config` must also preserve `output_config.effort`
                # under `drop_params=True` for adaptive-thinking models even when
                # LiteLLM's fallback entry omits `supports_output_config`.
                wire_data = {"model": bare, "messages": [], **mapped}
                cfg._apply_output_config(data=wire_data, model=bare, optional_params=dict(mapped))
                self.assertEqual(wire_data.get("output_config"), {"effort": "medium"}, bare)

        # Older non-adaptive Claude models must not be promoted to adaptive thinking.
        legacy_mapped = cfg.map_openai_params(
            non_default_params={"max_tokens": 4096},
            optional_params={},
            model="claude-3-5-haiku@20241022",
            drop_params=False,
        )
        self.assertNotIn("thinking", legacy_mapped)

        # Unmapped minor revisions of 1M-window Claude families must resolve their
        # family context window (not the generic 200k fallback or None), keeping
        # context editing aligned with the configured 180k trigger cap. Also verify
        # the real unmocked capability fallback when `litellm.model_cost` has an
        # `anthropic`-only entry with `supports_adaptive_thinking=True` and omits
        # both `vertex_ai/` and `supports_output_config`.
        synthetic_cost = {
            "claude-opus-5": {"max_input_tokens": 1_000_000},
            "vertex_ai/claude-opus-5-5": {"max_input_tokens": 1_000_000},
            "vertex_ai/claude-haiku-4-5": {"max_input_tokens": 200_000},
            "claude-next-5-9": {
                "litellm_provider": "anthropic",
                "supports_adaptive_thinking": True,
                "max_input_tokens": 1_000_000,
            },
        }
        with mock.patch.object(litellm, "model_cost", synthetic_cost), mock.patch.object(
            litellm, "drop_params", True
        ):
            self.assertEqual(C.resolve_context_limit("vertex_ai/claude-opus-5-9"), 1_000_000)
            self.assertEqual(C.resolve_context_limit("vertex_ai/claude-opus-5"), 1_000_000)
            self.assertEqual(C.resolve_context_limit("vertex_ai/claude-opus-5-5"), 1_000_000)
            self.assertEqual(C.resolve_context_limit("vertex_ai/claude-haiku-4-5"), 200_000)
            self.assertEqual(C.resolve_context_limit("vertex_ai/claude-next-5-9"), 1_000_000)
            ce = C.anthropic_context_editing(
                "vertex_ai/claude-opus-5-9",
                config={"context_editing_trigger_tokens": 180_000},
            )
            self.assertIsNotNone(ce)
            self.assertEqual(ce["edits"][0]["trigger"]["value"], 180_000)

            next_supported = cfg.get_supported_openai_params(model="claude-next-5-9")
            self.assertIn("thinking", next_supported)
            self.assertIn("reasoning_effort", next_supported)
            next_mapped = cfg.map_openai_params(
                non_default_params={"reasoning_effort": "medium", "max_tokens": 128000},
                optional_params={},
                model="claude-next-5-9",
                drop_params=True,
            )
            self.assertEqual(
                next_mapped.get("thinking"),
                {"type": "adaptive", "display": "summarized"},
            )
            self.assertEqual(next_mapped.get("output_config"), {"effort": "medium"})
            next_wire = {"model": "claude-next-5-9", "messages": [], **next_mapped}
            cfg._apply_output_config(
                data=next_wire,
                model="claude-next-5-9",
                optional_params=dict(next_mapped),
            )
            self.assertEqual(next_wire.get("output_config"), {"effort": "medium"})

    def test_11_claude_forked_stem_boundary_cache_breakpoint(self):
        from types import SimpleNamespace

        # Forked Claude prefix_group stages must pin a 3rd cache_control breakpoint
        # right at the shared stem boundary (explorer's final assistant message) so
        # researcher/reviewer/critic cache 100% of the stem including explorer's final
        # response and continuously refresh the stem TTL across multi-turn stages.
        captured: list[dict] = []

        async def _fake_acompletion(model=None, messages=None, tools=None, **kwargs):
            captured.append({
                "model": model,
                "messages": list(messages or []),
                "cc_pts": list(kwargs.get("cache_control_injection_points") or []),
            })
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(role="assistant", content="ok", tool_calls=None),
                        finish_reason="stop",
                    )
                ],
                usage=SimpleNamespace(prompt_tokens=100, completion_tokens=5, total_tokens=105),
            )

        # Build a realistic shared stem containing parallel tool responses (which
        # expand 1 Content into 2 OpenAI `role="tool"` messages!) followed by the
        # forked stage's opening user turn + one local turn.
        stem_contents = [
            types.Content(role="user", parts=[types.Part.from_text(text="Stage: architect\nInspect repo.")]),
            types.Content(
                role="model",
                parts=[
                    types.Part(function_call=types.FunctionCall(name="read_file", id="c1", args={"filepath": "a.py"})),
                    types.Part(function_call=types.FunctionCall(name="read_file", id="c2", args={"filepath": "b.py"})),
                ],
            ),
            types.Content(
                role="user",
                parts=[
                    types.Part(function_response=types.FunctionResponse(name="read_file", id="c1", response={"result": "a"})),
                    types.Part(function_response=types.FunctionResponse(name="read_file", id="c2", response={"result": "b"})),
                ],
            ),
            types.Content(role="model", parts=[types.Part.from_text(text="Explorer map complete.")]),
        ]
        delta_contents = [
            types.Content(role="user", parts=[types.Part.from_text(text="Stage: researcher\nFind vulnerabilities.")]),
            types.Content(role="model", parts=[types.Part.from_text(text="Checking SQLi.")]),
            types.Content(role="user", parts=[types.Part.from_text(text="Continue.")]),
        ]

        # OpenAI message layout corresponding to [system] + stem_contents + delta_contents:
        # idx 0: system
        # idx 1: user (architect)
        # idx 2: assistant (2 tool_calls)
        # idx 3: tool (c1)
        # idx 4: tool (c2)
        # idx 5: assistant ("Explorer map complete.")  <-- EXACT stem end!
        # idx 6: user ("Stage: researcher...")
        # idx 7: assistant ("Checking SQLi.")
        # idx 8: user ("Continue.")
        openai_msgs = [
            {"role": "system", "content": "Shared base prompt"},
            {"role": "user", "content": "Stage: architect\nInspect repo."},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "c1"}, {"id": "c2"}]},
            {"role": "tool", "tool_call_id": "c1", "content": "a"},
            {"role": "tool", "tool_call_id": "c2", "content": "b"},
            {"role": "assistant", "content": "Explorer map complete."},
            {"role": "user", "content": "Stage: researcher\nFind vulnerabilities."},
            {"role": "assistant", "content": "Checking SQLi."},
            {"role": "user", "content": "Continue."},
        ]

        client = C.ResilientLiteLLMClient()
        stem_info = C._build_claude_stem_boundary_hint(stem_contents, delta_contents[0])
        self.assertIsNotNone(stem_info)
        tok = C._ACTIVE_CLAUDE_STEM_BOUNDARY.set(stem_info)
        try:
            with mock.patch("litellm.acompletion", side_effect=_fake_acompletion):
                asyncio.run(
                    client.acompletion(
                        model="vertex_ai/claude-opus-5-5",
                        messages=openai_msgs,
                        stream=False,
                        cache_control_injection_points=[
                            {"location": "message", "role": "system", "control": {"type": "ephemeral"}},
                            {"location": "message", "index": -1, "control": {"type": "ephemeral"}},
                        ],
                    )
                )
        finally:
            C._ACTIVE_CLAUDE_STEM_BOUNDARY.reset(tok)

        self.assertEqual(len(captured), 1)
        cc_pts = captured[0]["cc_pts"]
        self.assertEqual(len(cc_pts), 3)
        self.assertEqual(cc_pts[0]["role"], "system")
        self.assertEqual(cc_pts[1], {"location": "message", "index": 5, "control": {"type": "ephemeral"}})
        self.assertEqual(cc_pts[2]["index"], -1)

        # Must preserve TTL (e.g. 1h) from existing injection points and never exceed 4 breakpoints.
        captured.clear()
        tok = C._ACTIVE_CLAUDE_STEM_BOUNDARY.set(stem_info)
        try:
            with mock.patch("litellm.acompletion", side_effect=_fake_acompletion):
                asyncio.run(
                    client.acompletion(
                        model="vertex_ai/claude-opus-5-5",
                        messages=openai_msgs,
                        stream=False,
                        cache_control_injection_points=[
                            {"location": "message", "role": "system", "control": {"type": "ephemeral", "ttl": "1h"}},
                            {"location": "message", "index": -1, "control": {"type": "ephemeral", "ttl": "1h"}},
                        ],
                    )
                )
        finally:
            C._ACTIVE_CLAUDE_STEM_BOUNDARY.reset(tok)
        self.assertEqual(
            captured[0]["cc_pts"][1],
            {"location": "message", "index": 5, "control": {"type": "ephemeral", "ttl": "1h"}},
        )

        # Non-Claude models must never receive the Claude stem breakpoint.
        captured.clear()
        tok = C._ACTIVE_CLAUDE_STEM_BOUNDARY.set(stem_info)
        try:
            with mock.patch("litellm.acompletion", side_effect=_fake_acompletion):
                asyncio.run(
                    client.acompletion(
                        model="vertex_ai/gemini-3.8-flash",
                        messages=openai_msgs,
                        stream=False,
                        cache_control_injection_points=[],
                    )
                )
        finally:
            C._ACTIVE_CLAUDE_STEM_BOUNDARY.reset(tok)
        self.assertEqual(captured[0]["cc_pts"], [])


if __name__ == "__main__":
    unittest.main()

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

"""Anthropic context editing: the provider clears a stage's older tool
results before the model reads a request that has grown past the trigger,
so a long stage stays inside the window while the request we send stays
append-only. Sent to Claude models only; the client-side estimates (request
guard, node context ceiling) count the request the way the provider reads
it, so neither refuses or ends a stage the provider was about to serve."""

from __future__ import annotations

import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from core import config as C  # noqa: E402

CLAUDE = "vertex_ai/claude-example-1"
GEMINI = "vertex_ai/gemini-3.8-flash"


class ParameterTest(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop(C._CONTEXT_EDITING_ENV, None)
        os.environ.pop("MANTIS_MAX_INPUT_TOKENS", None)
        os.environ.pop("VERTEXAI_PROJECT", None)
        os.environ.pop("GOOGLE_CLOUD_PROJECT", None)

    def test_claude_models_get_a_clear_tool_uses_edit_sized_to_the_window(self):
        with patch.object(C, "resolve_context_limit", return_value=1_000_000):
            edit = C.anthropic_context_editing(CLAUDE)
        self.assertIsNotNone(edit)
        [e] = edit["edits"]
        self.assertEqual(e["type"], C.CONTEXT_EDITING_EDIT_TYPE)
        self.assertEqual(e["trigger"], {"type": "input_tokens", "value": 500_000})
        self.assertEqual(e["keep"], {"type": "tool_uses", "value": C.CONTEXT_EDITING_KEEP_TOOL_USES})
        self.assertEqual(e["clear_at_least"], {"type": "input_tokens", "value": 200_000})
        self.assertLess(C.CONTEXT_EDITING_TRIGGER_RATIO, 0.8, "the provider acts before the node context ceiling")

    def test_only_claude_models_and_only_when_on(self):
        with patch.object(C, "resolve_context_limit", return_value=1_000_000):
            for other in (GEMINI, "openai/gpt-5.3-codex", "gemini/gemini-3.6-flash", ""):
                self.assertIsNone(C.anthropic_context_editing(other), other)
            for route in ("anthropic/claude-x", "bedrock/anthropic.claude-x", "vertex_ai/claude-x"):
                self.assertIsNotNone(C.anthropic_context_editing(route), route)
            self.assertIsNone(C.anthropic_context_editing(CLAUDE, config={"context_editing": "off"}))
            self.assertIsNotNone(C.anthropic_context_editing(CLAUDE, config={"context_editing": "auto"}))
            os.environ[C._CONTEXT_EDITING_ENV] = "off"
            self.assertIsNone(C.anthropic_context_editing(CLAUDE))
            os.environ.pop(C._CONTEXT_EDITING_ENV)
        with patch.object(C, "resolve_context_limit", return_value=None):
            self.assertIsNone(C.anthropic_context_editing(CLAUDE), "no window to size against: not sent")
            os.environ["MANTIS_MAX_INPUT_TOKENS"] = "128000"
            capped = C.anthropic_context_editing(CLAUDE)
            self.assertIsNotNone(capped, "operator input cap sizes context editing when model window is unknown")
            self.assertEqual(capped["edits"][0]["trigger"]["value"], 64_000)
            self.assertEqual(capped["edits"][0]["clear_at_least"]["value"], 25_600)
            os.environ.pop("MANTIS_MAX_INPUT_TOKENS", None)

    def test_get_llm_kwargs_carries_it_for_claude_and_nothing_else(self):
        os.environ["VERTEXAI_PROJECT"] = "example-project"
        with patch.object(C, "resolve_context_limit", return_value=1_000_000):
            _, claude_kwargs = C.get_llm_kwargs(CLAUDE)
            _, gemini_kwargs = C.get_llm_kwargs(GEMINI)
        self.assertIn("context_management", claude_kwargs)
        self.assertEqual(C.context_editing_keeps(claude_kwargs["context_management"]), C.CONTEXT_EDITING_KEEP_TOOL_USES)
        self.assertNotIn("context_management", gemini_kwargs)

    def test_keeps_reads_the_edit_and_nothing_else(self):
        self.assertIsNone(C.context_editing_keeps(None))
        self.assertIsNone(C.context_editing_keeps({"edits": [{"type": "clear_thinking_20251015"}]}))
        self.assertEqual(C.context_editing_keeps({"edits": [{"type": "clear_tool_uses_20250919"}]}), 0)
        self.assertEqual(C.context_editing_keeps(
            {"edits": [{"type": "clear_tool_uses_20250919", "keep": {"type": "tool_uses", "value": 3}}]}), 3)


class EstimatesFollowTheProviderTest(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop("MANTIS_MAX_INPUT_TOKENS", None)

    def _messages(self, n_tools: int, chars: int):
        msgs = [{"role": "user", "content": "go"}]
        for i in range(n_tools):
            msgs.append({"role": "assistant", "content": None, "tool_calls": [{"id": f"c{i}", "type": "function",
                         "function": {"name": "read_file", "arguments": "{}"}}]})
            msgs.append({"role": "tool", "tool_call_id": f"c{i}", "content": "y" * chars})
        return msgs

    def test_the_request_guard_counts_cleared_results_as_cleared(self):
        # Ten 40k-char tool results: ~100k tokens at 4 chars/token, far over a
        # 50k-token window. With the edit keeping the newest 2, the provider
        # reads ~20k tokens -- and so does the guard.
        msgs = self._messages(10, 40_000)
        edit = {"edits": [{"type": "clear_tool_uses_20250919", "keep": {"type": "tool_uses", "value": 2}}]}
        with patch.object(C, "resolve_context_limit", return_value=50_000):
            with self.assertRaises(C.ContextBudgetExceededError):
                C.enforce_context_budget(CLAUDE, msgs)
            C.enforce_context_budget(CLAUDE, msgs, context_management=edit)  # fits as the provider reads it
            # The kept window alone still has to fit.
            with self.assertRaises(C.ContextBudgetExceededError):
                C.enforce_context_budget(CLAUDE, self._messages(3, 100_000), context_management=edit)

    def test_cleared_view_touches_only_older_tool_messages(self):
        msgs = self._messages(3, 10)
        seen = C._messages_as_the_provider_sees_them(msgs, keep=1)
        tools = [m for m in seen if m["role"] == "tool"]
        self.assertEqual([m["content"] for m in tools], [C._CLEARED_TOOL_RESULT, C._CLEARED_TOOL_RESULT, "y" * 10])
        self.assertEqual([m for m in seen if m["role"] != "tool"], [m for m in msgs if m["role"] != "tool"])
        self.assertEqual(msgs[2]["content"], "y" * 10, "the caller's messages are not mutated")
        self.assertIs(C._messages_as_the_provider_sees_them(msgs, keep=5), msgs, "nothing to clear: same list")

    def test_the_gateway_hands_the_request_edit_to_the_guard(self):
        import litellm

        from core.config import ResilientLiteLLMClient

        seen = {}

        def spy(model, messages, tools=None, context_management=None):
            seen["cm"] = context_management

        class _Resp:
            choices = [type("C", (), {"message": type("M", (), {"content": "ok"})()})()]

        edit = {"edits": [{"type": "clear_tool_uses_20250919", "keep": {"type": "tool_uses", "value": 2}}]}
        with patch.object(C, "enforce_context_budget", spy), \
             patch.object(litellm, "completion", lambda **kw: _Resp()):
            ResilientLiteLLMClient().completion(model="m", messages=[{"role": "user", "content": "hi"}],
                                                context_management=edit)
        self.assertEqual(seen.get("cm"), edit)

    def test_the_node_context_ceiling_measures_the_request_as_the_provider_reads_it(self):
        from google.adk.models import LlmRequest
        from google.genai import types

        import core.graph_loader as gl

        req = LlmRequest()
        req.config.system_instruction = "be careful"
        req.contents = [types.Content(role="user", parts=[types.Part.from_text(text="go")])]
        for i in range(6):
            req.contents.append(types.Content(role="model", parts=[types.Part(function_call=types.FunctionCall(name="read_file", args={"n": i}))]))
            req.contents.append(types.Content(role="user", parts=[types.Part(function_response=types.FunctionResponse(name="read_file", response={"result": "x" * 10_000}))]))
        full = gl._request_chars(req)
        kept2 = gl._request_chars(req, keep_tool_results=2)
        self.assertGreater(full, 60_000)
        self.assertLess(kept2, 21_000 + 1_000, "four of six results count as placeholders")
        self.assertGreater(kept2, 20_000)

        # The stage is told once, in the same words on every call.
        from core.context import RunContext, current_run_context
        token = current_run_context.set(RunContext(jail_dir="/tmp", db_path="", target_file="a.py", run_id="r"))
        self.addCleanup(current_run_context.reset, token)
        cb = gl._make_node_context_ceiling_before_model_callback("researcher", model="m", keep_tool_results=5)
        with patch("core.config.resolve_context_limit", return_value=1_000_000), \
             patch("core.config.resolve_input_token_cap", return_value=None):
            self.assertIsNone(asyncio.run(cb(callback_context=None, llm_request=req)))
            first = req.config.system_instruction
            self.assertIn("[CONTEXT EDITING]", first)
            self.assertIsNone(asyncio.run(cb(callback_context=None, llm_request=req)))
            self.assertEqual(req.config.system_instruction, first)
        plain = gl._make_node_context_ceiling_before_model_callback("researcher", model="m")
        req2 = LlmRequest()
        req2.config.system_instruction = "be careful"
        with patch("core.config.resolve_context_limit", return_value=1_000_000), \
             patch("core.config.resolve_input_token_cap", return_value=None):
            asyncio.run(plain(callback_context=None, llm_request=req2))
        self.assertNotIn("[CONTEXT EDITING]", req2.config.system_instruction, "no editing, no notice")


class ClientSideEditingTest(unittest.TestCase):
    """Models without prefix binding get the same editing from the harness:
    older tool results cleared before dispatch, deterministically, never
    the newest `keep`, re-applied on every rebuilt request."""

    def setUp(self):
        self.env = patch.dict(os.environ, {}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop(C._CONTEXT_EDITING_ENV, None)
        os.environ.pop("MANTIS_MAX_INPUT_TOKENS", None)
        from core.budget import BudgetConfig, BudgetController
        from core.context import RunContext, current_run_context
        self.ctrl = BudgetController(config=BudgetConfig(max_tokens=0, max_wall_clock_seconds=0), run_id="r")
        token = current_run_context.set(RunContext(jail_dir="/tmp", db_path="", target_file="a.py", run_id="r",
                                                   budget_controller=self.ctrl, node_context={}))
        self.addCleanup(current_run_context.reset, token)
        self.ctx = current_run_context.get()

    def test_the_parameter_mirrors_the_providers_and_is_for_other_models_only(self):
        with patch.object(C, "resolve_context_limit", return_value=1_000_000):
            self.assertIsNone(C.client_context_editing(CLAUDE), "the provider edits for Claude")
            for other in (GEMINI, "openai/gpt-5.3-codex", "gemini/gemini-3.6-flash"):
                edit = C.client_context_editing(other)
                self.assertEqual(edit, {"trigger_tokens": 500_000, "keep": C.CONTEXT_EDITING_KEEP_TOOL_USES,
                                        "clear_at_least_tokens": 200_000}, other)
            self.assertIsNone(C.client_context_editing(GEMINI, config={"context_editing": "off"}))
            os.environ[C._CONTEXT_EDITING_ENV] = "off"
            self.assertIsNone(C.client_context_editing(GEMINI))
            os.environ.pop(C._CONTEXT_EDITING_ENV)
        with patch.object(C, "resolve_context_limit", return_value=None):
            self.assertIsNone(C.client_context_editing(GEMINI))
            os.environ["MANTIS_MAX_INPUT_TOKENS"] = "128000"
            self.assertEqual(
                C.client_context_editing("openai/qwen-onprem"),
                {"trigger_tokens": 64_000, "keep": C.CONTEXT_EDITING_KEEP_TOOL_USES, "clear_at_least_tokens": 25_600},
            )
            self.assertIsNone(C.client_context_editing(""))
            os.environ.pop("MANTIS_MAX_INPUT_TOKENS", None)
        with patch.object(C, "resolve_context_limit", return_value=1_000_000):
            os.environ["MANTIS_MAX_INPUT_TOKENS"] = "128000"
            self.assertEqual(
                C.client_context_editing(GEMINI),
                {"trigger_tokens": 64_000, "keep": C.CONTEXT_EDITING_KEEP_TOOL_USES, "clear_at_least_tokens": 25_600},
                "tighter operator cap governs context editing trigger",
            )
            os.environ.pop("MANTIS_MAX_INPUT_TOKENS", None)
        self.assertIsNone(C.client_context_editing(""))

    @staticmethod
    def _request(n: int, chars: int = 10_000):
        from google.adk.models import LlmRequest
        from google.genai import types

        req = LlmRequest()
        req.config.system_instruction = "be careful"
        req.contents = [types.Content(role="user", parts=[types.Part.from_text(text="go")])]
        for i in range(n):
            req.contents.append(types.Content(role="model", parts=[
                types.Part(function_call=types.FunctionCall(name="read_file", id=f"c{i}", args={"n": i}))]))
            req.contents.append(types.Content(role="user", parts=[
                types.Part(function_response=types.FunctionResponse(name="read_file", id=f"c{i}",
                                                                    response={"result": f"{i}:" + "x" * chars}))]))
        return req

    @staticmethod
    def _results(req):
        import core.graph_loader as gl
        return [c.parts[i].function_response for c, i, _ in gl._function_response_parts(req)]

    def _callback(self, model=GEMINI, window=100_000):
        import core.graph_loader as gl
        patcher = patch.object(C, "resolve_context_limit", return_value=window)
        patcher.start()
        self.addCleanup(patcher.stop)
        return gl._make_client_context_editing_before_model_callback("researcher", model=model)

    def test_at_the_trigger_the_oldest_results_are_cleared_and_stay_cleared(self):
        import core.graph_loader as gl

        # 100k-token window: trigger 50k tokens, clear at least 20k tokens
        # (60k chars at 3 chars/token), keep 5. Twenty 10k-char results are
        # ~67k tokens: over the trigger; six results clear 60k chars.
        cb = self._callback()
        req = self._request(20)
        self.assertIsNone(asyncio.run(cb(callback_context=None, llm_request=req)))
        results = self._results(req)
        cleared = [r for r in results if r.response == {"result": gl.CLEARED_TOOL_RESULT_TEXT}]
        self.assertEqual(len(cleared), 6)
        self.assertEqual([r.id for r in cleared], [f"c{i}" for i in range(6)], "the oldest, in order; ids kept")
        self.assertTrue(all(r.name == "read_file" for r in cleared))
        self.assertTrue(results[6].response["result"].startswith("6:"), "the seventh is intact")
        self.assertEqual(self.ctx.node_context["researcher"][gl.NODE_CONTEXT_CLEARED_KEY], 6)
        self.assertIn("[CONTEXT EDITING]", req.config.system_instruction)
        snap = self.ctrl.spend_snapshot()
        self.assertEqual(snap["context"]["context_edits_applied"], 1)
        self.assertGreaterEqual(snap["context"]["context_edit_cleared_tokens"], 20_000)

        # ADK rebuilds the request from the session on the next call: the
        # same six are cleared again, nothing more (now under the trigger),
        # so the prefix the provider sees is the one it cached.
        again = self._request(20)
        asyncio.run(cb(callback_context=None, llm_request=again))
        results = self._results(again)
        self.assertEqual(sum(r.response == {"result": gl.CLEARED_TOOL_RESULT_TEXT} for r in results), 6)
        self.assertEqual(self.ctrl.spend_snapshot()["context"]["context_edits_applied"], 1)
        self.assertEqual(again.config.system_instruction.count("[CONTEXT EDITING]"), 1)

    def test_under_the_trigger_nothing_is_cleared(self):
        import core.graph_loader as gl
        cb = self._callback()
        req = self._request(4)
        asyncio.run(cb(callback_context=None, llm_request=req))
        self.assertTrue(all(r.response != {"result": gl.CLEARED_TOOL_RESULT_TEXT} for r in self._results(req)))
        self.assertEqual(self.ctx.node_context["researcher"].get(gl.NODE_CONTEXT_CLEARED_KEY, 0), 0)

    def test_the_newest_keep_are_never_cleared(self):
        import core.graph_loader as gl
        cb = self._callback()
        req = self._request(7, chars=100_000)  # far over the trigger; only two are clearable
        asyncio.run(cb(callback_context=None, llm_request=req))
        results = self._results(req)
        self.assertEqual([r.response == {"result": gl.CLEARED_TOOL_RESULT_TEXT} for r in results],
                         [True, True, False, False, False, False, False])

    def test_a_fresh_attempt_does_not_inherit_a_larger_count(self):
        import core.graph_loader as gl
        cb = self._callback()
        slot = gl._node_context_slot("researcher")
        slot[gl.NODE_CONTEXT_CLEARED_KEY] = 10
        req = self._request(3)
        asyncio.run(cb(callback_context=None, llm_request=req))
        self.assertTrue(all(r.response != {"result": gl.CLEARED_TOOL_RESULT_TEXT} for r in self._results(req)))
        self.assertEqual(slot[gl.NODE_CONTEXT_CLEARED_KEY], 0)

    def test_claude_is_left_to_its_provider(self):
        import core.graph_loader as gl
        cb = self._callback(model=CLAUDE)
        req = self._request(20)
        asyncio.run(cb(callback_context=None, llm_request=req))
        self.assertTrue(all(r.response != {"result": gl.CLEARED_TOOL_RESULT_TEXT} for r in self._results(req)))
        self.assertNotIn("[CONTEXT EDITING]", req.config.system_instruction)

    def test_the_ceiling_measures_the_request_as_cleared(self):
        import core.graph_loader as gl
        cb = self._callback()
        req = self._request(20)
        before = gl._request_chars(req)
        asyncio.run(cb(callback_context=None, llm_request=req))
        self.assertLess(gl._request_chars(req), before - 55_000)

    def test_every_agent_node_carries_the_callback_ahead_of_the_ceiling(self):
        from core.graph_loader import load_workflow_from_json

        workflow, _cfg = load_workflow_from_json(str(_REF_ROOT / "workflow.json"), load_local=False)
        seen = {}
        for edge in workflow.edges:
            for node in (getattr(edge, "from_node", None), getattr(edge, "to_node", None)):
                agent = getattr(node, "agent", node)
                if agent is not None and getattr(agent, "before_model_callback", None) and getattr(agent, "tools", None):
                    seen[getattr(agent, "name", id(agent))] = agent
        self.assertGreater(len(seen), 5)
        for name, agent in seen.items():
            names = [getattr(cb, "__qualname__", "") for cb in agent.before_model_callback]
            editing = next((i for i, n in enumerate(names) if "client_context_editing" in n), None)
            ceiling = next((i for i, n in enumerate(names) if "node_context_ceiling" in n), None)
            self.assertIsNotNone(editing, f"{name}: no client-side context editing callback")
            self.assertIsNotNone(ceiling, f"{name}: no ceiling callback")
            self.assertLess(editing, ceiling, f"{name}: the ceiling must measure the request as cleared")


if __name__ == "__main__":
    unittest.main()

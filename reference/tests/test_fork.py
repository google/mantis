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

"""A stage may fork its predecessor's conversation instead of starting
fresh (`fork_from`). What is inherited, what is not, where the callback
sits, and what the loader refuses."""

from __future__ import annotations

import asyncio
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from google.adk.events import Event  # noqa: E402
from google.adk.models import LlmRequest  # noqa: E402
from google.genai import types  # noqa: E402

import core.graph_loader as gl  # noqa: E402
from core.budget import BudgetConfig, BudgetController  # noqa: E402
from core.context import RunContext, current_run_context  # noqa: E402


def _ev(author, role, parts, **kw):
    return Event(author=author, content=types.Content(role=role, parts=parts), **kw)


def _planner_events():
    return [
        _ev("user", "user", [types.Part.from_text(text="Initial Task Input: Evaluate app")]),
        _ev("planner", "model", [
            types.Part(text="thinking hard", thought=True),
            types.Part(function_call=types.FunctionCall(name="read_file", id="c1", args={"filepath": "app.py"}),
                       thought_signature=b"sig"),
        ]),
        _ev("planner", "user", [types.Part(function_response=types.FunctionResponse(
            name="read_file", id="c1", response={"result": "def route(): ..."}))]),
        _ev("planner", "model", [types.Part.from_text(text="Plan: look at route() for injection.")]),
        _ev("other_stage", "model", [types.Part.from_text(text="not the planner's")]),
        _ev("planner", "model", [types.Part.from_text(text="partial")], partial=True),
        _ev("planner", "model", [types.Part.from_text(text="failed")], error_code="SOMETHING"),
    ]


class ForkedContentsTest(unittest.TestCase):
    def test_the_parents_transcript_minus_thinking_and_others(self):
        contents = gl.forked_contents(_planner_events(), "planner")
        self.assertEqual([c.role for c in contents], ["model", "user", "model"])
        first = contents[0].parts
        self.assertEqual(len(first), 1, "the thinking part is dropped")
        self.assertIsNotNone(first[0].function_call)
        self.assertEqual(first[0].function_call.id, "c1", "the call keeps its id to pair with its result")
        self.assertIsNone(first[0].thought_signature, "no signature travels into a different prefix")
        self.assertEqual(contents[1].parts[0].function_response.id, "c1")
        self.assertEqual(contents[2].parts[0].text, "Plan: look at route() for injection.")
        texts = json.dumps([p.text for c in contents for p in c.parts if p.text])
        self.assertNotIn("not the planner's", texts)
        self.assertNotIn("Initial Task Input", texts, "the seed is the user's, not the parent's")
        self.assertNotIn("partial", texts)
        self.assertNotIn("failed", texts)

    def test_nothing_to_inherit(self):
        self.assertEqual(gl.forked_contents([], "planner"), [])
        self.assertEqual(gl.forked_contents(None, "planner"), [])
        self.assertEqual(gl.forked_contents(_planner_events(), "nobody"), [])


class ForkCallbackTest(unittest.TestCase):
    def setUp(self):
        self.ctrl = BudgetController(config=BudgetConfig(max_tokens=0, max_wall_clock_seconds=0), run_id="r")
        self.token = current_run_context.set(RunContext(jail_dir="/tmp", db_path="", run_id="r",
                                                        budget_controller=self.ctrl, node_context={}))

    def tearDown(self):
        current_run_context.reset(self.token)

    def _request(self):
        req = LlmRequest()
        req.config.system_instruction = "You are the researcher."
        req.contents = [types.Content(role="user", parts=[types.Part.from_text(text="go")])]
        return req

    def test_the_transcript_is_prepended_on_every_call_and_the_note_once(self):
        cb = gl._make_fork_before_model_callback("researcher", "planner")
        ctx = SimpleNamespace(session=SimpleNamespace(events=_planner_events()))
        req = self._request()
        self.assertIsNone(asyncio.run(cb(callback_context=ctx, llm_request=req)))
        self.assertEqual(len(req.contents), 4, "three inherited, then the node's own")
        self.assertEqual(req.contents[-1].parts[0].text, "go")
        self.assertEqual(req.config.system_instruction.count(gl.FORK_NOTICE_MARKER), 1)
        self.assertIn("'planner' stage's work", req.config.system_instruction)
        # ADK rebuilds the request each call; the same transcript goes in front again.
        again = self._request()
        again.config.system_instruction = req.config.system_instruction
        asyncio.run(cb(callback_context=ctx, llm_request=again))
        self.assertEqual(len(again.contents), 4)
        self.assertEqual(again.config.system_instruction.count(gl.FORK_NOTICE_MARKER), 1)
        self.assertEqual(self.ctrl.spend_snapshot()["context"]["forked_requests"], 2)

    def test_no_parent_events_means_no_change(self):
        cb = gl._make_fork_before_model_callback("researcher", "planner")
        req = self._request()
        asyncio.run(cb(callback_context=SimpleNamespace(session=SimpleNamespace(events=[])), llm_request=req))
        self.assertEqual(len(req.contents), 1)
        self.assertNotIn(gl.FORK_NOTICE_MARKER, req.config.system_instruction)
        asyncio.run(cb(callback_context=None, llm_request=req))
        self.assertEqual(len(req.contents), 1)

    def test_the_parents_final_reply_is_not_doubled(self):
        """ADK opens the node's turn with its predecessor's final reply as a
        user message; the inherited transcript ends with the same text."""
        cb = gl._make_fork_before_model_callback("researcher", "planner")
        ctx = SimpleNamespace(session=SimpleNamespace(events=_planner_events()))
        req = LlmRequest()
        req.contents = [types.Content(role="user", parts=[types.Part.from_text(
            text="Plan: look at route() for injection.")])]
        asyncio.run(cb(callback_context=ctx, llm_request=req))
        texts = [p.text for c in req.contents for p in c.parts if p.text]
        self.assertEqual(texts.count("Plan: look at route() for injection."), 1)
        self.assertEqual(len(req.contents), 3, "call, result, then ADK's opener")

    def test_the_ceiling_sees_the_inherited_transcript(self):
        cb = gl._make_fork_before_model_callback("researcher", "planner")
        big = [_ev("planner", "user", [types.Part(function_response=types.FunctionResponse(
            name="read_file", id=f"c{i}", response={"result": "x" * 50_000}))]) for i in range(4)]
        ctx = SimpleNamespace(session=SimpleNamespace(events=big))
        req = self._request()
        before = gl._request_chars(req)
        asyncio.run(cb(callback_context=ctx, llm_request=req))
        self.assertGreater(gl._request_chars(req), before + 190_000)


class LoaderTest(unittest.TestCase):
    def _spec(self, fork_from):
        return {
            "name": "wf",
            "config": {"default_model": "openai/gpt-5.3-codex"},
            "nodes": [
                {"id": "planner", "type": "agent", "tools": ["read_file"], "system_prompt": "plan"},
                {"id": "researcher", "type": "agent", "tools": ["read_file"], "system_prompt": "research",
                 **({"fork_from": fork_from} if fork_from else {})},
            ],
            "edges": [{"from": "START", "to": "planner"}, {"from": "planner", "to": "researcher"}],
        }

    def _load(self, spec):
        import os
        import tempfile
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wf.json")
            Path(path).write_text(json.dumps(spec))
            with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "dummy"}):
                return gl.load_workflow_from_json(path, load_local=False)

    def _agent(self, workflow, name):
        for edge in workflow.edges:
            for node in (getattr(edge, "from_node", None), getattr(edge, "to_node", None)):
                agent = getattr(node, "agent", node)
                if getattr(agent, "name", None) == name:
                    return agent
        raise AssertionError(name)

    def test_a_fork_puts_the_callback_first_and_only_on_the_forked_node(self):
        workflow, _cfg = self._load(self._spec("planner"))
        names = [getattr(cb, "__qualname__", "") for cb in self._agent(workflow, "researcher").before_model_callback]
        self.assertIn("fork_before_model", names[0], names)
        self.assertLess(names.index(next(n for n in names if "fork_before_model" in n)),
                        names.index(next(n for n in names if "node_context_ceiling" in n)))
        planner_names = [getattr(cb, "__qualname__", "") for cb in self._agent(workflow, "planner").before_model_callback]
        self.assertFalse(any("fork_before_model" in n for n in planner_names))

    def test_a_fork_is_part_of_the_harness_fingerprint(self):
        _wf, cfg_plain = self._load(self._spec(None))
        _wf, cfg_fork = self._load(self._spec("planner"))
        self.assertNotEqual(cfg_plain.get("harness_fingerprint"), cfg_fork.get("harness_fingerprint"))
        nodes = [{"id": "a", "tools": [], "model": "m", "instruction": "i"}]
        self.assertEqual(gl.compute_harness_fingerprint(nodes),
                         gl.compute_harness_fingerprint([{**nodes[0], "fork_from": ""}]),
                         "no fork, same fingerprint as before the field existed")

    def test_the_loader_refuses_a_fork_from_nowhere_or_from_itself(self):
        with self.assertRaises(Exception) as cm:
            self._load(self._spec("nobody"))
        self.assertIn("fork_from", str(cm.exception))
        with self.assertRaises(Exception) as cm:
            self._load(self._spec("researcher"))
        self.assertIn("itself", str(cm.exception))


class PlannedEvalGraphTest(unittest.IsolatedAsyncioTestCase):
    """research_eval's planned arms: the planner runs first, the researcher
    follows with include_contents='none'; forked, its requests begin with
    the planner's transcript; fresh, they do not. A recording model stands
    in for the provider."""

    async def _run(self, fork: bool):
        from unittest import mock

        from google.adk.models.base_llm import BaseLlm
        from google.adk.models.llm_response import LlmResponse

        import evals.research_eval as re_mod
        import evals.stage_agents as sa

        seen: list = []

        def noop() -> str:
            """A tool the planner calls once, so its transcript has tool traffic."""
            return "ok"

        class Recorder(BaseLlm):
            model: str = "dummy"

            async def generate_content_async(self, req, stream=False):
                sys_inst = str(getattr(req.config, "system_instruction", "") or "")
                texts = [p.text for c in (req.contents or []) for p in (c.parts or []) if getattr(p, "text", None)]
                calls = sum(1 for c in (req.contents or []) for p in (c.parts or []) if getattr(p, "function_call", None))
                seen.append((sys_inst, texts, calls))
                planner_first_turn = sys_inst.startswith("You are planner") and not any(
                    getattr(p, "function_response", None) for c in (req.contents or []) for p in (c.parts or []))
                if planner_first_turn:
                    yield LlmResponse(content=types.Content(role="model", parts=[
                        types.Part(function_call=types.FunctionCall(name="noop", args={}))]))
                    return
                yield LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text="done")]))

        def build(stage_name, model_id=None, reasoning_effort=None, tools_override=None, **kw):
            from google.adk.agents import Agent

            from core.graph_loader import LiteralInstruction
            extra = {}
            if kw.get("include_contents") is not None:
                extra["include_contents"] = kw["include_contents"]
            if kw.get("before_model_callback"):
                extra["before_model_callback"] = list(kw["before_model_callback"])
            instruction = f"You are {stage_name}."
            if kw.get("instruction_suffix"):
                instruction += "\n\n" + kw["instruction_suffix"]
            tools = [noop] if stage_name == "planner" else []
            return Agent(name=stage_name, model=Recorder(), instruction=LiteralInstruction(instruction),
                         tools=tools, **extra)

        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp, "t")
            (target / "app").mkdir(parents=True)
            (target / "app" / "a.py").write_text("x = 1\n")
            (target / "ground_truth.json").write_text(json.dumps({
                "format_version": "1.0",
                "findings": [{"id": "gt1", "files": ["app/a.py"], "match_any": ["anything"]}],
            }))
            with mock.patch.object(sa, "build_stage_agent", build):
                result = await re_mod.eval_researcher(
                    "dummy", "low", target_dir=target, toolset="baseline",
                    predecessor="planner", fork=fork, arm_label="x",
                )
        return seen, result

    async def test_fresh_and_forked_planned_arms(self):
        seen, result = await self._run(fork=False)
        # planner (tool call), planner (final), researcher.
        self.assertEqual([s[0].split(".")[0] for s in seen], ["You are planner", "You are planner", "You are researcher"])
        self.assertTrue(any("Initial Task Input" in t for t in seen[0][1]), "the seed reaches the planner")
        researcher = seen[2]
        self.assertFalse(any("Initial Task Input" in t for t in researcher[1]), "and not the researcher")
        self.assertEqual(researcher[2], 0, "fresh: none of the planner's tool traffic")
        self.assertEqual(researcher[1], ["done"], "only the planner's final reply, as ADK opens every node's turn")
        self.assertIn("researcher stage", researcher[0], "the briefing rides in its instruction")
        self.assertNotIn(gl.FORK_NOTICE_MARKER, researcher[0])
        self.assertEqual((result["predecessor"], result["fork"], result["shape"]), ("planner", False, "planner"))

        seen, result = await self._run(fork=True)
        researcher = seen[2]
        self.assertEqual(researcher[2], 1, "forked: the planner's tool call is in front")
        self.assertEqual(researcher[1], ["done"], "the planner's final reply once, not twice")
        self.assertIn(gl.FORK_NOTICE_MARKER, researcher[0])
        self.assertEqual((result["fork"], result["shape"]), (True, "planner+fork"))
        self.assertIn("planner", result["tokens_by_stage"])


class OversizedForkStemCeilingTest(unittest.IsolatedAsyncioTestCase):
    """Regression tests for p2-context-fork-interplay-1:
    1. Oversized inherited stems of tool results are bounded deterministically to
       STEM_CONTEXT_CEILING_SHARE of the ceiling so sibling stages share identical
       bytes (preserving explicit/implicit caches) and have headroom to work.
    2. When an inherited stem STILL exceeds the ceiling on Turn 1 (zero own turns),
       continuations cannot shrink it, so the stage fails fast non-retryably
       instead of burning 6 handoff calls and returning canned ceiling text as a
       clean, coverage-credited campaign.
    """

    def setUp(self):
        self.ctrl = BudgetController(
            config=BudgetConfig(max_tokens=0, max_wall_clock_seconds=0), run_id="r_stem"
        )
        self.rc = RunContext(
            jail_dir="/tmp",
            db_path="",
            target_file="a.py",
            run_id="r_stem",
            budget_controller=self.ctrl,
            node_context={},
        )
        self.token = current_run_context.set(self.rc)

    def tearDown(self):
        current_run_context.reset(self.token)

    @staticmethod
    def _stem_tool_events(num_turns: int, result_chars: int, *, include_thoughts: bool = False):
        events = [
            _ev("user", "user", [types.Part.from_text(text="Initial Task Input: audit app")]),
        ]
        for i in range(num_turns):
            model_parts = []
            if include_thoughts:
                model_parts.append(types.Part(text=f"thinking {i}", thought=True))
            model_parts.append(
                types.Part(
                    function_call=types.FunctionCall(
                        name="read_file", id=f"stem_{i}", args={"filepath": f"f{i}.py"}
                    ),
                    thought_signature=(f"sig_{i}".encode() if include_thoughts else None),
                )
            )
            events.append(_ev("explorer", "model", model_parts))
            events.append(
                _ev(
                    "explorer",
                    "user",
                    [
                        types.Part(
                            function_response=types.FunctionResponse(
                                name="read_file",
                                id=f"stem_{i}",
                                response={"result": f"file{i}:" + ("x" * result_chars)},
                            )
                        )
                    ],
                )
            )
        events.append(_ev("explorer", "model", [types.Part.from_text(text="Explorer map ready.")]))
        return events

    async def test_oversized_stem_tool_results_are_bounded_identically_across_siblings(self):
        from unittest import mock

        # 100k window -> 80k ceiling -> 40k stem budget (120k chars at 3 chars/token).
        # 6 stem tool results x 40k chars = 240k chars (~80k tokens), right at ceiling.
        events = self._stem_tool_events(6, 40_000)
        cb_ctx = SimpleNamespace(
            session=SimpleNamespace(events=events),
            state={f"{gl.PREFIX_U_STATE_KEY_PREFIX}explorer": "[ACTIVE STAGE ASSIGNMENT: explorer]\nExplore."},
        )

        with mock.patch("core.config.resolve_context_limit", return_value=100_000), \
             mock.patch("core.config.resolve_input_token_cap", return_value=None):
            res_cb = gl._make_prefix_group_before_model_callback(
                "researcher",
                base_instruction="BASE",
                stage_role_prompt="Find bugs.",
                ancestor_chain=("explorer",),
                parent_id="explorer",
                preserve_signatures=True,
                prefix_group="audit_stem",
                enable_explicit_stem_cache=True,
                model="vertex_ai/gemini-3.8-flash",
            )
            rev_cb = gl._make_prefix_group_before_model_callback(
                "reviewer",
                base_instruction="BASE",
                stage_role_prompt="Review findings.",
                ancestor_chain=("explorer",),
                parent_id="explorer",
                preserve_signatures=True,
                prefix_group="audit_stem",
                enable_explicit_stem_cache=True,
                model="vertex_ai/gemini-3.8-flash",
            )
            ceil_cb = gl._make_node_context_ceiling_before_model_callback(
                "researcher",
                model="vertex_ai/gemini-3.8-flash",
                has_schema=False,
                preserve_system_prefix=True,
            )

            req_res = LlmRequest(contents=[types.Content(role="user", parts=[types.Part.from_text(text="go")])])
            req_rev = LlmRequest(contents=[types.Content(role="user", parts=[types.Part.from_text(text="go")])])
            await res_cb(callback_context=cb_ctx, llm_request=req_res)
            await rev_cb(callback_context=cb_ctx, llm_request=req_rev)

            # Researcher now fits well below the 80k ceiling and proceeds normally!
            self.assertIsNone(await ceil_cb(callback_context=cb_ctx, llm_request=req_res))

            # Verify oldest inherited tool results were cleared, newest kept, and
            # session.events was NOT mutated.
            res_frs = [c.parts[i].function_response for c, i, _ in gl._function_response_parts(req_res)]
            cleared_flags = [fr.response == {"result": gl.CLEARED_TOOL_RESULT_TEXT} for fr in res_frs]
            self.assertEqual(cleared_flags, [True, True, True, True, False, False])
            self.assertTrue(
                all(
                    p.function_response.response != {"result": gl.CLEARED_TOOL_RESULT_TEXT}
                    for ev in events
                    for p in (ev.content.parts or [])
                    if getattr(p, "function_response", None) is not None
                ),
                "session.events must remain untouched",
            )

            # Siblings share the EXACT byte-identical bounded stem & explicit cache slot key.
            res_cache = getattr(req_res, "_mantis_stem_cache", None)
            rev_cache = getattr(req_rev, "_mantis_stem_cache", None)
            self.assertIsNotNone(res_cache)
            self.assertEqual(res_cache, rev_cache)
            stem_len = res_cache["stem_len"]
            self.assertEqual(
                [c.model_dump() for c in req_res.contents[:stem_len]],
                [c.model_dump() for c in req_rev.contents[:stem_len]],
                "sibling forked stages must receive byte-identical bounded stems",
            )

    def test_claude_stem_bounding_strips_thoughts_only_up_to_last_cleared(self):
        events = self._stem_tool_events(4, 40_000, include_thoughts=True)
        inherited = gl.forked_prefix_contents(
            events,
            ("explorer",),
            state={f"{gl.PREFIX_U_STATE_KEY_PREFIX}explorer": "[ACTIVE STAGE ASSIGNMENT: explorer]"},
            preserve_signatures=True,
        )
        # 100k window -> 80k ceiling -> 40k stem budget (120k chars).
        # 4 x 40k = 160k chars -> oldest 2 cleared, newest 2 preserved.
        bounded, cleared = gl._bound_inherited_stem(
            inherited, limit_tokens=100_000, model="bedrock/anthropic.claude-sonnet-4-6"
        )
        self.assertEqual(cleared, 2)
        frs = [c.parts[i].function_response for c, i, _ in gl._function_response_parts_from_contents(bounded)]
        self.assertEqual([fr.response == {"result": gl.CLEARED_TOOL_RESULT_TEXT} for fr in frs], [True, True, False, False])
        model_turns = [c for c in bounded if c.role == "model" and any(p.function_call for p in c.parts)]
        self.assertEqual(len(model_turns), 4)
        # First 2 model turns (at or before cleared results) had thought + signature stripped.
        for mt in model_turns[:2]:
            self.assertFalse(any(getattr(p, "thought", False) for p in mt.parts))
            self.assertTrue(all(getattr(p, "thought_signature", None) is None for p in mt.parts))
        # Last 2 model turns (after cleared results) keep their thought + signature intact.
        for mt in model_turns[2:]:
            self.assertTrue(any(getattr(p, "thought", False) for p in mt.parts))
            self.assertTrue(any(getattr(p, "thought_signature", None) is not None for p in mt.parts))

    async def test_unrecoverable_oversized_fork_stem_fails_fast_without_continuations_or_clean_credit(self):
        """End-to-end through ADK Runner + RetryConfig: a schema-less forked stage
        whose inherited stem still exceeds the ceiling on Turn 1 must fail fast
        non-retryably with ZERO handoff LLM calls and NEVER return canned
        NODE_CONTEXT_CEILING_TEXT."""
        import contextlib
        import io
        from unittest import mock

        from google import adk
        from google.adk.apps.app import App
        from google.adk.models.base_llm import BaseLlm
        from google.adk.models.llm_response import LlmResponse
        from google.adk.runners import Runner
        from google.adk.sessions.in_memory_session_service import InMemorySessionService
        from google.adk.workflow import Edge, RetryConfig, START, Workflow, node

        stage_calls: list[str] = []
        handoff_calls: list = []

        class _StageLlm(BaseLlm):
            @classmethod
            def supported_models(cls):
                return [".*"]

            async def generate_content_async(self, llm_request, stream=False):
                stage_calls.append(self.model)
                yield LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text="unexpected")]))

        class _HandoffLlm(BaseLlm):
            @classmethod
            def supported_models(cls):
                return [".*"]

            async def generate_content_async(self, llm_request, stream=False):
                handoff_calls.append(llm_request)
                yield LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text="handoff")]))

        # Explorer produces non-tool-result prose (~1000 tokens = 3000 chars) that
        # cannot be cleared by tool-result bounding against a 1000-token window
        # (ceiling = 800 tokens = 2400 chars).
        class _ExplorerLlm(BaseLlm):
            @classmethod
            def supported_models(cls):
                return [".*"]

            async def generate_content_async(self, llm_request, stream=False):
                yield LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[types.Part.from_text(text="prose " * 600)],
                    )
                )

        retry = RetryConfig(max_attempts=2, initial_delay=0.01, max_delay=0.02, backoff_factor=1.0, jitter=0.0)
        explorer_ag = adk.Agent(
            name="explorer",
            model=_ExplorerLlm(model="stage"),
            instruction=gl.LiteralInstruction("BASE"),
        )
        researcher_ag = adk.Agent(
            name="researcher",
            model=_StageLlm(model="stage"),
            instruction=gl.LiteralInstruction("BASE"),
            before_model_callback=[
                gl._make_prefix_group_before_model_callback(
                    "researcher",
                    base_instruction="BASE",
                    stage_role_prompt="Find vulns.",
                    ancestor_chain=("explorer",),
                    parent_id="explorer",
                    preserve_signatures=True,
                    prefix_group="audit_stem",
                    model="stage",
                ),
                gl._make_node_context_ceiling_before_model_callback(
                    "researcher",
                    model="stage",
                    has_schema=False,
                    llm_factory=lambda: _HandoffLlm(model="handoff"),
                    preserve_system_prefix=True,
                ),
            ],
        )
        explorer_node = node(explorer_ag, name="explorer")
        wf = Workflow(
            name="wf_fork_ceil",
            edges=[
                Edge(from_node=START, to_node=explorer_node),
                Edge(
                    from_node=explorer_node,
                    to_node=node(researcher_ag, name="researcher", retry_config=retry),
                ),
            ],
        )
        ss = InMemorySessionService()
        runner = Runner(app=App(name="t_fork_ceil", root_agent=wf), session_service=ss)
        await ss.create_session(app_name="t_fork_ceil", user_id="u", session_id="s")

        texts: list[str] = []
        stderr = io.StringIO()
        with mock.patch("core.config.resolve_context_limit", return_value=1000), \
             mock.patch("core.config.resolve_input_token_cap", return_value=None), \
             contextlib.redirect_stderr(stderr), \
             self.assertRaises(Exception) as caught:
            async for ev in runner.run_async(
                user_id="u",
                session_id="s",
                new_message=types.Content(role="user", parts=[types.Part.from_text(text="go")]),
            ):
                for p in (getattr(getattr(ev, "content", None), "parts", None) or ()):
                    if p.text and ev.author == "researcher":
                        texts.append(p.text)

        self.assertIn("NodeContextExhausted", type(caught.exception).__name__ + str(caught.exception))
        self.assertEqual(stage_calls, [], "oversized Turn-1 forked stage must never call stage model")
        self.assertEqual(handoff_calls, [], "must skip _write_handoff when continuation cannot shrink stem")
        self.assertEqual(self.rc.node_context["researcher"]["continuations"], 0, "must not burn continuations")
        self.assertFalse(
            any(gl.NODE_CONTEXT_CEILING_TEXT in t for t in texts),
            "must never return canned ceiling text as a clean completion on Turn 1",
        )
        snap = self.ctrl.spend_snapshot()["context"]
        self.assertEqual(snap["ceiling_failures"], 1)
        self.assertEqual(snap["ceiling_ends"], 0)
        self.assertIn("continuations cannot shrink the inherited stem", stderr.getvalue())

    async def test_forked_stage_with_own_progress_still_continues_normally(self):
        """Once a forked stage has taken at least one own model/tool turn, hitting
        the ceiling triggers normal retryable continuation (not Turn-1 fail-fast)."""
        import contextlib
        import io
        from unittest import mock

        req = LlmRequest(
            contents=[
                types.Content(role="user", parts=[types.Part.from_text(text="explorer start")]),
                types.Content(role="model", parts=[types.Part.from_text(text="explorer done")]),
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text=f"{gl.ACTIVE_STAGE_HEADER_PREFIX}researcher]\nGo.")],
                ),
                # Own progress in this attempt:
                types.Content(
                    role="model",
                    parts=[types.Part(function_call=types.FunctionCall(name="read_file", id="own1", args={}))],
                ),
                types.Content(
                    role="user",
                    parts=[
                        types.Part(
                            function_response=types.FunctionResponse(
                                name="read_file", id="own1", response={"result": "z" * 260_000}
                            )
                        )
                    ],
                ),
            ]
        )
        setattr(req, "_mantis_inherited_len", 3)
        cb = gl._make_node_context_ceiling_before_model_callback(
            "researcher", model="m", has_schema=False, preserve_system_prefix=True
        )
        with mock.patch("core.config.resolve_context_limit", return_value=100_000), \
             mock.patch("core.config.resolve_input_token_cap", return_value=None), \
             contextlib.redirect_stderr(io.StringIO()), \
             self.assertRaises(gl.NodeContextExhausted) as caught:
            await cb(callback_context=None, llm_request=req)
        self.assertTrue(caught.exception.retryable, "forked stage with own turns must remain retryable")
        self.assertEqual(self.rc.node_context["researcher"]["continuations"], 1)

    async def test_standalone_fork_from_oversized_first_turn_also_fails_fast(self):
        import contextlib
        import io
        from unittest import mock

        fork_cb = gl._make_fork_before_model_callback("researcher", "planner")
        ceil_cb = gl._make_node_context_ceiling_before_model_callback("researcher", model="m", has_schema=False)
        events = [_ev("planner", "model", [types.Part.from_text(text="p" * 260_000)])]
        cb_ctx = SimpleNamespace(session=SimpleNamespace(events=events))
        req = LlmRequest(contents=[types.Content(role="user", parts=[types.Part.from_text(text="go")])])
        await fork_cb(callback_context=cb_ctx, llm_request=req)
        with mock.patch("core.config.resolve_context_limit", return_value=100_000), \
             mock.patch("core.config.resolve_input_token_cap", return_value=None), \
             contextlib.redirect_stderr(io.StringIO()), \
             self.assertRaises(gl.NodeContextExhausted) as caught:
            await ceil_cb(callback_context=cb_ctx, llm_request=req)
        self.assertFalse(caught.exception.retryable)
        self.assertEqual(self.rc.node_context["researcher"]["continuations"], 0)


if __name__ == "__main__":
    unittest.main()

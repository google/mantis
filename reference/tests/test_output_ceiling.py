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

"""The output-token ceiling a request asks for: the most the model allows,
from LiteLLM's registry; a default for a Claude model the registry does
not know (Anthropic requires the field, so "unset" means LiteLLM's guess);
the provider's own default for any other unknown model. A model that
allows less names its ceiling when it rejects the request, and the request
is retried once at that ceiling instead of failing the stage."""

from __future__ import annotations

import asyncio
import contextlib
import io
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from google.adk.models import LlmRequest, LlmResponse  # noqa: E402
from google.adk.models.lite_llm import LiteLlm  # noqa: E402
from google.genai import types  # noqa: E402

from core.config import (  # noqa: E402
    CLAUDE_DEFAULT_MAX_OUTPUT_TOKENS, ResilientLiteLlm, default_request_timeout, get_llm_kwargs, output_cap_from_error,
)

_FAST = {
    "MANTIS_LLM_MAX_PATIENCE_SECONDS": "5",
    "MANTIS_LLM_RETRY_INITIAL_DELAY": "0",
    "MANTIS_LLM_RETRY_MAX_DELAY": "0",
    "MANTIS_LLM_RETRY_MIN_OFFSET": "0",
}
VERTEX_MESSAGE = (
    'litellm.BadRequestError: Vertex_aiException BadRequestError - {"type":"error","error":'
    '{"type":"invalid_request_error","message":"max_tokens: 128000 > 32000, which is the maximum '
    'allowed number of output tokens for this model"}}'
)


class DefaultCeilingTest(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ, {"VERTEXAI_PROJECT": "p", "VERTEXAI_LOCATION": "global"}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for var in ("LLM_MAX_TOKENS", "MANTIS_MAX_TOKENS"):
            os.environ.pop(var, None)
        # The registry as LiteLLM ships it changes between versions; the
        # rule under test is how its answer is used, so it is scripted.
        registry = {"vertex_ai/gemini-known": 65536, "openai/gpt-known": 128000, "vertex_ai/claude-known": 32000}

        def get_max_tokens(model):
            if model in registry:
                return registry[model]
            raise Exception("unknown model")

        patcher = mock.patch("litellm.get_max_tokens", side_effect=get_max_tokens)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _ceiling(self, model, effort="max"):
        _, kw = get_llm_kwargs(model_id=model, reasoning_effort=effort)
        return kw.get("max_tokens")

    def test_a_known_model_gets_the_most_it_allows_at_every_effort(self):
        for effort in ("low", "medium", "high", "max"):
            self.assertEqual(self._ceiling("vertex_ai/gemini-known", effort), 65536, effort)
            self.assertEqual(self._ceiling("openai/gpt-known", effort), 128000, effort)
            self.assertEqual(self._ceiling("vertex_ai/claude-known", effort), 32000, effort)

    def test_an_unknown_claude_gets_the_default_because_unset_means_litellm_s_guess(self):
        for effort in ("low", "max"):
            self.assertEqual(self._ceiling("vertex_ai/claude-example", effort), CLAUDE_DEFAULT_MAX_OUTPUT_TOKENS)
        self.assertEqual(CLAUDE_DEFAULT_MAX_OUTPUT_TOKENS, 128000)

    def test_any_other_unknown_model_leaves_the_provider_s_default(self):
        for effort in ("low", "medium", "high", "max"):
            self.assertIsNone(self._ceiling("vertex_ai/gemini-example", effort), effort)
            self.assertIsNone(self._ceiling("openai/gpt-example", effort), effort)

    def test_the_operator_s_ceiling_wins(self):
        with mock.patch.dict(os.environ, {"MANTIS_MAX_TOKENS": "4096"}):
            self.assertEqual(self._ceiling("vertex_ai/gemini-known"), 4096)
            self.assertEqual(self._ceiling("vertex_ai/claude-example"), 4096)


class PromptCacheMarkersTest(unittest.TestCase):
    """ADK marks a cacheable prefix for every model when context caching is
    on. Claude needs the marks; for Gemini, LiteLLM turns them into Vertex
    explicit caching, which bills per prefix and refuses prefixes under the
    model's minimum (measured: a short deduplicator prompt failed its stage
    with a 400). Non-Claude models therefore name no injection points."""

    def setUp(self):
        env = mock.patch.dict(os.environ, {"VERTEXAI_PROJECT": "p", "VERTEXAI_LOCATION": "global"}, clear=False)
        env.start()
        self.addCleanup(env.stop)

    def test_claude_leaves_the_marks_to_adk_and_others_name_none(self):
        _, kw = get_llm_kwargs(model_id="vertex_ai/claude-example", reasoning_effort="low")
        self.assertNotIn("cache_control_injection_points", kw)
        for model in ("vertex_ai/gemini-example", "gemini/gemini-example", "openai/gpt-example"):
            _, kw = get_llm_kwargs(model_id=model, reasoning_effort="low")
            self.assertEqual(kw.get("cache_control_injection_points"), [], model)


class RequestTimeoutTest(unittest.TestCase):
    """Streamed (the default) and unstreamed defaults scale with effort so
    long-thinking models (including those that stay silent before emitting a
    chunk) get generous bounds (600s medium / 900s high / 1800s xhigh & max),
    while low-effort non-thinking models leave `timeout` unset in kwargs (and
    streamed calls still apply the harness's 600s per-chunk fallback). The
    operator's explicit timeout always wins."""

    def setUp(self):
        env = mock.patch.dict(os.environ, {"VERTEXAI_PROJECT": "p", "VERTEXAI_LOCATION": "global"}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for var in ("LLM_TIMEOUT", "MANTIS_TIMEOUT", "LLM_REQUEST_TIMEOUT", "MANTIS_LLM_STREAM"):
            os.environ.pop(var, None)

    def _timeout(self, model, effort):
        _, kw = get_llm_kwargs(model_id=model, reasoning_effort=effort)
        return kw.get("timeout")

    def test_streamed_turns_use_generous_effort_scaled_per_chunk_timeouts(self):
        self.assertEqual(default_request_timeout("vertex_ai/gemini-example", "medium"), 600.0)
        self.assertEqual(default_request_timeout("vertex_ai/gemini-example", "high"), 900.0)
        self.assertEqual(default_request_timeout("vertex_ai/gemini-example", "xhigh"), 1800.0)
        self.assertEqual(default_request_timeout("vertex_ai/gemini-example", "max"), 1800.0)
        self.assertEqual(self._timeout("vertex_ai/claude-example", "max"), 1800.0)
        self.assertEqual(self._timeout("vertex_ai/claude-example", "high"), 900.0)
        self.assertEqual(self._timeout("vertex_ai/claude-example", "low"), 600.0, "a thinking model at low effort too")
        self.assertIsNone(
            self._timeout("vertex_ai/gemini-example", "low"),
            "low-effort non-thinking models leave kwargs timeout unset (streamed calls still apply the harness fallback)",
        )

    def test_unstreamed_turns_scale_with_effort(self):
        with mock.patch.dict(os.environ, {"MANTIS_LLM_STREAM": "0"}):
            self.assertEqual(default_request_timeout("vertex_ai/claude-example", "max"), 1800.0)
            self.assertEqual(default_request_timeout("vertex_ai/claude-example", "xhigh"), 1800.0)
            self.assertEqual(default_request_timeout("vertex_ai/gemini-example", "high"), 900.0)
            self.assertEqual(default_request_timeout("vertex_ai/gemini-example", "medium"), 600.0)
            self.assertEqual(self._timeout("vertex_ai/claude-example", "max"), 1800.0)
            self.assertEqual(self._timeout("vertex_ai/claude-example", "low"), 600.0)
            self.assertEqual(self._timeout("openai/glm-example", "low"), 600.0)
            self.assertIsNone(self._timeout("vertex_ai/gemini-example", "low"))

    def test_the_operator_s_timeout_wins(self):
        with mock.patch.dict(os.environ, {"LLM_REQUEST_TIMEOUT": "42"}):
            self.assertEqual(self._timeout("vertex_ai/claude-example", "max"), 42.0)


class OutputCapFromErrorTest(unittest.TestCase):
    def test_reads_the_ceiling_the_provider_names(self):
        self.assertEqual(output_cap_from_error(Exception(VERTEX_MESSAGE)), 32000)
        gemini = ("Unable to submit request because it has a maxOutputTokens value of 1000000 but the "
                  "supported range is from 1 (inclusive) to 65537 (exclusive). Update the value and try again.")
        self.assertEqual(output_cap_from_error(Exception(gemini)), 65536)
        openai = "max_tokens is too large: 200000. This model supports at most 128000 completion tokens"
        self.assertEqual(output_cap_from_error(Exception(openai)), 128000)

    def test_anything_else_is_not_a_ceiling(self):
        self.assertIsNone(output_cap_from_error(Exception("429 Too Many Requests")))
        self.assertIsNone(output_cap_from_error(Exception("max_tokens: 1000 > 2000")), "not a rejection for asking more")
        self.assertIsNone(output_cap_from_error(Exception("max_tokens: 5 > 0")))


def _reply(text: str) -> LlmResponse:
    return LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text=text)]),
                       finish_reason=types.FinishReason.STOP)


class RetryAtTheNamedCeilingTest(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ, _FAST)
        env.start()
        self.addCleanup(env.stop)
        self.llm = ResilientLiteLlm(model="openai/fake", max_tokens=128000)
        self.request = LlmRequest(
            model="openai/fake",
            contents=[types.Content(role="user", parts=[types.Part.from_text(text="go")])],
        )

    def _run(self, script):
        seen = []

        async def upstream(_self, llm_request, stream=False):
            seen.append(dict(_self._additional_args))
            step = script.pop(0)
            if isinstance(step, Exception):
                raise step
            yield step

        async def go():
            return [r async for r in self.llm.generate_content_async(self.request, stream=False)]

        err = io.StringIO()
        with mock.patch.object(LiteLlm, "generate_content_async", upstream), contextlib.redirect_stderr(err):
            out = asyncio.run(go())
        return out, seen, err.getvalue()

    def test_a_rejected_ceiling_is_lowered_once_and_remembered(self):
        out, seen, err = self._run([Exception(VERTEX_MESSAGE), _reply("done")])
        self.assertEqual([r.content.parts[0].text for r in out], ["done"])
        self.assertEqual([s["max_tokens"] for s in seen], [128000, 32000])
        self.assertIn("allows at most 32000 output tokens", err)
        self.assertEqual(self.llm._additional_args["max_tokens"], 32000, "every later call uses the named ceiling")

    def test_a_ceiling_no_lower_than_the_request_is_not_retried(self):
        self.llm._additional_args["max_tokens"] = 32000
        with self.assertRaises(Exception) as cm:
            self._run([Exception(VERTEX_MESSAGE)])
        self.assertIn("max_tokens: 128000 > 32000", str(cm.exception))


if __name__ == "__main__":
    unittest.main()

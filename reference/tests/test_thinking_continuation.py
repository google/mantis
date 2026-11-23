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

"""A thinking turn the provider ends mid-thought with a continuation token
is continued: the same request again with the token, the segments joined
into one turn, usage summed, a bound on how many segments."""

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

import litellm  # noqa: E402
from litellm.types.utils import (  # noqa: E402
    Choices, Delta, Message, ModelResponse, ModelResponseStream, StreamingChoices, Usage,
)

from core import config as C  # noqa: E402
from core.config import (  # noqa: E402
    ResilientLiteLLMClient, continuation_token_of, merge_continued_response, with_continuation_token,
)

_FAST = {
    "MANTIS_LLM_RETRY_INITIAL_DELAY": "0", "MANTIS_LLM_MIN_OFFSET": "0",
    "MANTIS_LLM_RETRY_MAX_DELAY": "0", "MANTIS_LLM_MAX_PATIENCE_SECONDS": "30",
}


def _psf(token=None, raw=None):
    fields = {}
    if token:
        fields[C.CONTINUATION_TOKEN_FIELD] = token
    if raw:
        fields[C.CONTINUATION_RAW_FINISH_FIELD] = raw
    return fields


def whole(text="", finish="stop", token=None, raw=None, prompt=100, completion=10, reasoning=None):
    msg = Message(content=text or None, role="assistant")
    if reasoning:
        msg.reasoning_content = reasoning
    msg.provider_specific_fields = _psf(token, raw)
    return ModelResponse(choices=[Choices(finish_reason=finish, index=0, message=msg)],
                         usage=Usage(prompt_tokens=prompt, completion_tokens=completion, total_tokens=prompt + completion))


def chunk(text=None, finish=None, token=None, raw=None):
    delta = Delta(content=text, role="assistant" if text else None)
    delta.provider_specific_fields = _psf(token, raw)
    return ModelResponseStream(choices=[StreamingChoices(finish_reason=finish, index=0, delta=delta)])


def usage_chunk(prompt, completion, cached=0):
    from litellm.types.utils import PromptTokensDetailsWrapper
    usage = Usage(prompt_tokens=prompt, completion_tokens=completion, total_tokens=prompt + completion,
                  prompt_tokens_details=PromptTokensDetailsWrapper(cached_tokens=cached))
    return ModelResponseStream(choices=[], usage=usage)


class HelpersTest(unittest.TestCase):
    def test_only_a_continuation_stop_offers_a_token(self):
        self.assertEqual(continuation_token_of(whole(token="T", raw="CONTINUATION")), "T")
        self.assertIsNone(continuation_token_of(whole(token="T", raw="MAX_TOKENS")), "the request's ceiling is spent")
        self.assertIsNone(continuation_token_of(whole(finish="stop")))
        self.assertEqual(continuation_token_of(chunk(finish="length", token="T", raw="CONTINUATION")), "T")

    def test_the_token_rides_on_the_request_body_top_level(self):
        kw = with_continuation_token({"max_tokens": 5, "extra_body": {"x": 1}}, "T")
        self.assertEqual(kw["extra_body"], {"x": 1, "continuationToken": "T"})
        self.assertEqual(kw["max_tokens"], 5)

    def test_merge_joins_text_takes_the_later_finish_and_sums_usage(self):
        first = whole(text="", finish="length", token="T", raw="CONTINUATION", prompt=100, completion=50, reasoning="a")
        second = whole(text="answer", finish="stop", prompt=100, completion=20, reasoning="b")
        merged = merge_continued_response(first, second)
        self.assertEqual(merged.choices[0].message.content, "answer")
        self.assertEqual(merged.choices[0].message.reasoning_content, "ab")
        self.assertEqual(merged.choices[0].finish_reason, "stop")
        self.assertEqual((merged.usage.prompt_tokens, merged.usage.completion_tokens, merged.usage.total_tokens), (200, 70, 270))
        self.assertIsNone(continuation_token_of(merged), "the turn is over")

    def test_the_patch_surfaces_the_candidate_s_token_on_a_message(self):
        from litellm.llms.vertex_ai.gemini import vertex_and_google_ai_studio_gemini as vg
        self.assertTrue(getattr(vg.VertexGeminiConfig._process_candidates, "_mantis_continuation", False))
        resp = ModelResponse(choices=[])
        candidates = [{"content": {"role": "model", "parts": [{"text": "", "thought": True}]},
                       "finishReason": "CONTINUATION", "continuationToken": "QUJD", "index": 0}]
        vg.VertexGeminiConfig._process_candidates(candidates, resp, {})
        self.assertEqual(continuation_token_of(resp), "QUJD")
        self.assertEqual(resp.choices[0].finish_reason, "length", "CONTINUATION is mapped like a length stop")

        # Streaming chunk also surfaces CONTINUATION token and ignores MAX_TOKENS token
        # even when LiteLLM natively populates continuation_token on the delta.
        stream_cont = ModelResponseStream(choices=[])
        vg.VertexGeminiConfig._process_candidates(candidates, stream_cont, {})
        self.assertEqual(continuation_token_of(stream_cont), "QUJD")

        stream_max = ModelResponseStream(choices=[])
        max_candidates = [{"content": {"role": "model", "parts": [{"text": "", "thought": True}]},
                           "finishReason": "MAX_TOKENS", "continuationToken": "QUJD", "index": 0}]
        vg.VertexGeminiConfig._process_candidates(max_candidates, stream_max, {})
        self.assertIsNone(continuation_token_of(stream_max))

    def test_native_litellm_choice_native_finish_reason_is_recognized_and_cleared_on_merge(self):
        # LiteLLM 1.108+ populates continuation_token on Message and native_finish_reason on Choices.
        msg = Message(content=None, role="assistant")
        msg.provider_specific_fields = {C.CONTINUATION_TOKEN_FIELD: "NATIVE_TOK"}
        choice_cont = Choices(finish_reason="length", index=0, message=msg)
        choice_cont.provider_specific_fields = {"native_finish_reason": "CONTINUATION"}
        resp_cont = ModelResponse(choices=[choice_cont])
        self.assertEqual(continuation_token_of(resp_cont), "NATIVE_TOK")

        choice_max = Choices(finish_reason="length", index=0, message=msg)
        choice_max.provider_specific_fields = {"native_finish_reason": "MAX_TOKENS"}
        self.assertIsNone(continuation_token_of(ModelResponse(choices=[choice_max])))

        final = whole(text="done", finish="stop")
        final.choices[0].provider_specific_fields = {"native_finish_reason": "STOP"}
        merged = merge_continued_response(resp_cont, final)
        self.assertIsNone(continuation_token_of(merged))
        self.assertEqual(merged.choices[0].provider_specific_fields, {"native_finish_reason": "STOP"})


class WholeResponseTest(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, _FAST)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.client = ResilientLiteLLMClient()

    def _run(self, script, **kw):
        calls = []

        async def fake(**kwargs):
            calls.append(kwargs)
            return script.pop(0)

        err = io.StringIO()
        with mock.patch.object(litellm, "acompletion", side_effect=fake), contextlib.redirect_stderr(err):
            out = asyncio.run(self.client.acompletion("vertex_ai/gemini-example", [{"role": "user", "content": "q"}], None, **kw))
        return out, calls, err.getvalue()

    def test_a_turn_is_continued_until_it_finishes(self):
        script = [whole(finish="length", token="T1", raw="CONTINUATION", completion=30),
                  whole(finish="length", token="T2", raw="CONTINUATION", completion=30),
                  whole(text="done", finish="stop", completion=5)]
        out, calls, err = self._run(script, max_tokens=1000)
        self.assertEqual(out.choices[0].message.content, "done")
        self.assertEqual(out.choices[0].finish_reason, "stop")
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[1]["extra_body"]["continuationToken"], "T1")
        self.assertEqual(calls[2]["extra_body"]["continuationToken"], "T2")
        self.assertNotIn("_mantis_no_continue", calls[1], "the private flag never reaches LiteLLM")
        self.assertEqual(out.usage.completion_tokens, 65, "every segment's output counted")
        self.assertEqual(out.usage.prompt_tokens, 300, "every segment billed its prompt")
        self.assertEqual(err.count("[CONTINUATION]"), 2)

    def test_by_default_a_turn_is_continued_until_the_provider_ends_it(self):
        script = [whole(finish="length", token=f"T{i}", raw="CONTINUATION") for i in range(12)] + [whole(text="ok", finish="stop")]
        os.environ.pop("MANTIS_MAX_CONTINUATIONS", None)
        out, calls, _err = self._run(script)
        self.assertEqual(len(calls), 13, "no cap of this module's own: every segment's work is kept")
        self.assertEqual(out.choices[0].message.content, "ok")

    def test_an_operator_s_cap_ends_the_turn_as_the_provider_left_it(self):
        script = [whole(finish="length", token=f"T{i}", raw="CONTINUATION") for i in range(5)]
        with mock.patch.dict(os.environ, {"MANTIS_MAX_CONTINUATIONS": "2"}):
            out, calls, err = self._run(script)
        self.assertEqual(len(calls), 3, "the first segment and two continuations")
        self.assertEqual(out.choices[0].finish_reason, "length")
        self.assertIn("not continued: MANTIS_MAX_CONTINUATIONS=2 reached", err)

    def test_the_run_s_token_budget_stops_a_turn_it_cannot_afford(self):
        # The pipeline meters a turn when it ends; a turn of many segments
        # must consult the budget itself, with its own spend so far added.
        from core.budget import BudgetConfig, BudgetController
        from core.context import RunContext, current_run_context

        controller = BudgetController(BudgetConfig(max_tokens=1_000), run_id="r")
        controller.accumulated_tokens = 700
        token = current_run_context.set(RunContext(jail_dir="", db_path="", budget_controller=controller))
        self.addCleanup(current_run_context.reset, token)
        script = [whole(finish="length", token="T1", raw="CONTINUATION", prompt=100, completion=100),
                  whole(finish="length", token="T2", raw="CONTINUATION", prompt=100, completion=100),
                  whole(text="never", finish="stop")]
        out, calls, err = self._run(script)
        self.assertEqual(len(calls), 2, "segment two fits (700+200 < 1000); a third would not (700+400)")
        self.assertEqual(out.choices[0].finish_reason, "length")
        self.assertIn("token budget would be exceeded", err)

    def test_a_max_tokens_stop_is_not_continued(self):
        out, calls, _err = self._run([whole(finish="length", token="T", raw="MAX_TOKENS")])
        self.assertEqual(len(calls), 1)


class StreamedTurnTest(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, _FAST)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.client = ResilientLiteLLMClient()

    def _run(self, segments, **kw):
        calls = []

        async def fake(**kwargs):
            calls.append(kwargs)
            items = segments.pop(0)

            async def gen():
                for it in items:
                    yield it
            return gen()

        async def go():
            stream = await self.client.acompletion("vertex_ai/gemini-example", [{"role": "user", "content": "q"}], None, stream=True, **kw)
            return [c async for c in stream]

        err = io.StringIO()
        with mock.patch.object(litellm, "acompletion", side_effect=fake), contextlib.redirect_stderr(err):
            out = asyncio.run(go())
        return out, calls, err.getvalue()

    def test_segments_are_delivered_as_one_stream(self):
        segments = [
            [chunk(finish="length", token="T1", raw="CONTINUATION"), usage_chunk(100, 30, cached=0)],
            [chunk(text="ans"), chunk(text="wer", finish="stop"), usage_chunk(100, 5, cached=90)],
        ]
        out, calls, err = self._run(segments)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1]["extra_body"]["continuationToken"], "T1")
        finishes = [c.choices[0].finish_reason for c in out if c.choices]
        self.assertEqual(finishes, [None, "stop"], "the consumer sees one finish, the real one")
        self.assertEqual("".join(c.choices[0].delta.content or "" for c in out if c.choices), "answer")
        usage = [c.usage for c in out if not c.choices]
        self.assertEqual(len(usage), 1, "one usage chunk for the whole turn")
        self.assertEqual((usage[0].prompt_tokens, usage[0].completion_tokens), (200, 35))
        self.assertEqual(usage[0].prompt_tokens_details.cached_tokens, 90, "the resent prompt's cache hits are kept")
        self.assertIn("[CONTINUATION]", err)

    def test_a_single_segment_stream_passes_through_unchanged(self):
        segments = [[chunk(text="hi"), chunk(finish="stop"), usage_chunk(10, 2)]]
        out, calls, err = self._run(segments)
        self.assertEqual(len(calls), 1)
        self.assertEqual([c.choices[0].finish_reason for c in out if c.choices], [None, "stop"])
        self.assertEqual([c.usage.completion_tokens for c in out if not c.choices], [2])
        self.assertNotIn("[CONTINUATION]", err)

    def test_an_operator_s_cap_passes_the_provider_s_finish_through(self):
        segments = [[chunk(finish="length", token=f"T{i}", raw="CONTINUATION"), usage_chunk(100, 30)] for i in range(4)]
        with mock.patch.dict(os.environ, {"MANTIS_MAX_CONTINUATIONS": "1"}):
            out, calls, err = self._run(segments)
        self.assertEqual(len(calls), 2)
        self.assertEqual([c.choices[0].finish_reason for c in out if c.choices], ["length"])
        self.assertEqual([c.usage.completion_tokens for c in out if not c.choices], [60])
        self.assertIn("not continued: MANTIS_MAX_CONTINUATIONS=1 reached", err)

    def test_a_finish_on_its_own_chunk_after_the_token_is_withheld_too(self):
        """Measured: the token arrived on one chunk and the segment's finish
        reason on the next, and the finish leaked through to the consumer,
        where ADK would have ended the turn on it."""
        segments = [
            [chunk(token="T1", raw="CONTINUATION"), chunk(finish="length"), usage_chunk(100, 30)],
            [chunk(text="done", finish="stop"), usage_chunk(100, 5)],
        ]
        out, calls, _err = self._run(segments)
        self.assertEqual(len(calls), 2)
        self.assertEqual([c.choices[0].finish_reason for c in out if c.choices], [None, "stop"])

    def test_usage_on_a_content_chunk_is_summed_as_well(self):
        """Measured: the final usage arrived on the chunk that carried the
        finish, not on a usage-only chunk, and the turn reported only its
        last segment's usage."""
        from litellm.types.utils import PromptTokensDetailsWrapper

        def finish_with_usage(prompt, completion, cached, **kw):
            c = chunk(**kw)
            c.usage = Usage(prompt_tokens=prompt, completion_tokens=completion, total_tokens=prompt + completion,
                            prompt_tokens_details=PromptTokensDetailsWrapper(cached_tokens=cached))
            return c

        segments = [
            [finish_with_usage(100, 30, 0, finish="length", token="T1", raw="CONTINUATION")],
            [chunk(text="done"), finish_with_usage(130, 5, 120, finish="stop")],
        ]
        out, calls, _err = self._run(segments)
        self.assertEqual(len(calls), 2)
        with_usage = [c for c in out if getattr(c, "usage", None) is not None]
        self.assertEqual(len(with_usage), 1, "the intermediate segment's usage is not passed on")
        self.assertEqual((with_usage[0].usage.prompt_tokens, with_usage[0].usage.completion_tokens), (230, 35))
        self.assertEqual(with_usage[0].usage.prompt_tokens_details.cached_tokens, 120)
        self.assertEqual([c.choices[0].finish_reason for c in out if c.choices], [None, "stop"])


if __name__ == "__main__":
    unittest.main()

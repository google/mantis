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

"""Unit tests for ResilientLiteLLMClient streaming support (stream=True).

The resilience boundary under test:
- Every failure up to and including the FIRST chunk (connect errors, stream-open
  errors, first-chunk errors) re-enters the full-jitter backoff / auth-refresh
  loop, with the patience clock shared across restarts.
- A failure AFTER the first chunk raises MantisStreamInterruptedError
  (chunks_yielded, original_exception) instead of a transparent retry, because
  re-sampling a nondeterministic model would splice two different completions.
- The context budget guard runs eagerly at call time, not at first iteration.
- The sync completion() path mirrors the async path.
"""

import asyncio
import inspect
import os
import sys
import time
import types as pytypes
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

import litellm

import core.config as config_module
from core.config import (
    CONTINUATION_FINISH_REASON,
    CONTINUATION_RAW_FINISH_FIELD,
    CONTINUATION_TOKEN_FIELD,
    ContextBudgetExceededError,
    MantisAuthError,
    MantisStreamInterruptedError,
    REQUEST_TIMEOUT_STREAMED,
    ResilientLiteLlm,
    ResilientLiteLLMClient,
    _resolve_stream_chunk_timeout,
)

# Keep retries fast and deterministic-ish: ~1ms delays, generous patience so
# only the explicit patience test exercises exhaustion.
_FAST_RETRY_ENV = {
    "MANTIS_LLM_RETRY_INITIAL_DELAY": "0.001",
    "MANTIS_LLM_RETRY_MAX_DELAY": "0.002",
    "MANTIS_LLM_MIN_OFFSET": "0.0",
    "MANTIS_LLM_RETRY_BACKOFF": "1.0",
    "MANTIS_LLM_MAX_PATIENCE_SECONDS": "30.0",
}


class _Transient429(Exception):
    """Shaped like a retryable rate-limit error (status_code drives classification)."""

    status_code = 429


class _Auth401(Exception):
    """Shaped like an authentication failure."""

    status_code = 401


class _FakeAsyncStream:
    """Async-iterable stream that can fail before yielding its index-th chunk."""

    def __init__(self, chunks, fail_before_index=None, exc=None):
        self._chunks = list(chunks)
        self._index = 0
        self._fail_before_index = fail_before_index
        self._exc = exc

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._fail_before_index is not None and self._index == self._fail_before_index:
            raise self._exc
        if self._index >= len(self._chunks):
            raise StopAsyncIteration
        chunk = self._chunks[self._index]
        self._index += 1
        return chunk


class _FakeSyncStream:
    """Sync mirror of _FakeAsyncStream."""

    def __init__(self, chunks, fail_before_index=None, exc=None):
        self._chunks = list(chunks)
        self._index = 0
        self._fail_before_index = fail_before_index
        self._exc = exc

    def __iter__(self):
        return self

    def __next__(self):
        if self._fail_before_index is not None and self._index == self._fail_before_index:
            raise self._exc
        if self._index >= len(self._chunks):
            raise StopIteration
        chunk = self._chunks[self._index]
        self._index += 1
        return chunk


async def _collect(stream):
    return [chunk async for chunk in stream]


_MESSAGES = [{"role": "user", "content": "hi"}]


class TestResilientStreaming(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.client = ResilientLiteLLMClient()
        env_patch = patch.dict(os.environ, _FAST_RETRY_ENV)
        env_patch.start()
        self.addCleanup(env_patch.stop)

    # ------------------------------------------------------------------
    # Signature parity
    # ------------------------------------------------------------------

    def test_both_paths_expose_stream_parameter(self):
        for method in (ResilientLiteLLMClient.acompletion, ResilientLiteLLMClient.completion):
            params = inspect.signature(method).parameters
            self.assertIn("stream", params)
            self.assertIs(params["stream"].default, False)

    # ------------------------------------------------------------------
    # Async path
    # ------------------------------------------------------------------

    async def test_async_nonstream_path_unchanged(self):
        sentinel = object()
        seen = {}

        async def fake_acompletion(**kw):
            seen.update(kw)
            return sentinel

        with patch.object(litellm, "acompletion", fake_acompletion):
            result = await self.client.acompletion(model="m", messages=_MESSAGES)

        self.assertIs(result, sentinel)
        # The non-stream call must stay byte-identical to the pre-stream-support
        # request: no stream kwarg invented on behalf of the caller.
        self.assertNotIn("stream", seen)

    async def test_async_stream_happy_path(self):
        calls = []

        async def fake_acompletion(**kw):
            calls.append(kw)
            return _FakeAsyncStream(["c0", "c1", "c2"])

        with patch.object(litellm, "acompletion", fake_acompletion):
            stream = await self.client.acompletion(model="m", messages=_MESSAGES, stream=True)
            got = await _collect(stream)

        self.assertEqual(got, ["c0", "c1", "c2"])
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0]["stream"])

    async def test_async_stream_empty_stream_is_success(self):
        async def fake_acompletion(**kw):
            return _FakeAsyncStream([])

        with patch.object(litellm, "acompletion", fake_acompletion):
            stream = await self.client.acompletion(model="m", messages=_MESSAGES, stream=True)
            self.assertEqual(await _collect(stream), [])

    async def test_async_retryable_error_at_connect_is_retried(self):
        calls = {"n": 0}

        async def fake_acompletion(**kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise _Transient429("rate limited at connect")
            return _FakeAsyncStream(["a", "b"])

        with patch.object(litellm, "acompletion", fake_acompletion):
            stream = await self.client.acompletion(model="m", messages=_MESSAGES, stream=True)
            got = await _collect(stream)

        self.assertEqual(got, ["a", "b"])
        self.assertEqual(calls["n"], 2)

    async def test_async_error_before_first_chunk_is_retried(self):
        # The retry window must extend past "stream opened" to "first chunk
        # delivered": a 429 on the first __anext__ is still a zero-output failure.
        calls = {"n": 0}

        async def fake_acompletion(**kw):
            calls["n"] += 1
            if calls["n"] == 1:
                return _FakeAsyncStream(["a", "b"], fail_before_index=0, exc=_Transient429("quota"))
            return _FakeAsyncStream(["a", "b"])

        with patch.object(litellm, "acompletion", fake_acompletion):
            stream = await self.client.acompletion(model="m", messages=_MESSAGES, stream=True)
            got = await _collect(stream)

        self.assertEqual(got, ["a", "b"])
        self.assertEqual(calls["n"], 2)

    async def test_async_midstream_failure_raises_without_retry(self):
        # Even a retryable (429-shaped) error must NOT restart the stream once a
        # chunk has been delivered.
        inner = _Transient429("reset mid-stream")
        calls = {"n": 0}

        async def fake_acompletion(**kw):
            calls["n"] += 1
            return _FakeAsyncStream(["a", "b", "c"], fail_before_index=2, exc=inner)

        got = []
        with patch.object(litellm, "acompletion", fake_acompletion):
            stream = await self.client.acompletion(model="m", messages=_MESSAGES, stream=True)
            with self.assertRaises(MantisStreamInterruptedError) as cm:
                async for chunk in stream:
                    got.append(chunk)

        self.assertEqual(got, ["a", "b"])
        self.assertEqual(cm.exception.chunks_yielded, 2)
        self.assertIs(cm.exception.original_exception, inner)
        self.assertIs(cm.exception.__cause__, inner)
        self.assertEqual(calls["n"], 1)

    async def test_async_nonretryable_error_at_connect_raises_immediately(self):
        calls = {"n": 0}

        async def fake_acompletion(**kw):
            calls["n"] += 1
            raise ValueError("deterministic bad request")

        with patch.object(litellm, "acompletion", fake_acompletion):
            stream = await self.client.acompletion(model="m", messages=_MESSAGES, stream=True)
            with self.assertRaises(ValueError):
                await _collect(stream)

        self.assertEqual(calls["n"], 1)

    async def test_async_patience_exhaustion_reraises_original_error(self):
        calls = {"n": 0}

        async def fake_acompletion(**kw):
            calls["n"] += 1
            raise _Transient429("still rate limited")

        with patch.dict(os.environ, {"MANTIS_LLM_MAX_PATIENCE_SECONDS": "0.0"}):
            with patch.object(litellm, "acompletion", fake_acompletion):
                stream = await self.client.acompletion(model="m", messages=_MESSAGES, stream=True)
                with self.assertRaises(_Transient429):
                    await _collect(stream)

        self.assertEqual(calls["n"], 1)

    async def test_async_auth_refresh_covers_stream_open(self):
        calls = {"n": 0}

        async def fake_acompletion(**kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise _Auth401("token expired")
            return _FakeAsyncStream(["x"])

        with patch.object(litellm, "acompletion", fake_acompletion), \
                patch.object(config_module, "is_token_refreshable_auth_error", return_value=True), \
                patch.object(config_module, "try_refresh_auth", return_value=True):
            stream = await self.client.acompletion(model="m", messages=_MESSAGES, stream=True)
            got = await _collect(stream)

        self.assertEqual(got, ["x"])
        self.assertEqual(calls["n"], 2)

    async def test_async_unrefreshable_auth_error_wraps_as_mantis_auth_error(self):
        async def fake_acompletion(**kw):
            raise _Auth401("token expired, no refresh available")

        with patch.object(litellm, "acompletion", fake_acompletion), \
                patch.object(config_module, "try_refresh_auth", return_value=False):
            stream = await self.client.acompletion(model="m", messages=_MESSAGES, stream=True)
            with self.assertRaises(MantisAuthError):
                await _collect(stream)

    async def test_async_context_budget_enforced_eagerly_at_call_time(self):
        # The guard must fire at `await acompletion(...)` -- NOT lazily at first
        # iteration -- so an oversized payload is refused before any dispatch.
        async def fake_acompletion(**kw):  # pragma: no cover - must never run
            raise AssertionError("dispatch should have been refused by the budget guard")

        oversized = [{"role": "user", "content": "x" * 4000}]
        with patch.object(litellm, "acompletion", fake_acompletion), \
                patch.object(litellm, "get_max_input_tokens", return_value=10, create=True):
            with self.assertRaises(ContextBudgetExceededError):
                await self.client.acompletion(model="m", messages=oversized, stream=True)

    # ------------------------------------------------------------------
    # Sync path (mirror)
    # ------------------------------------------------------------------

    def test_sync_stream_happy_path(self):
        calls = []

        def fake_completion(**kw):
            calls.append(kw)
            return _FakeSyncStream(["s0", "s1"])

        with patch.object(litellm, "completion", fake_completion):
            got = list(self.client.completion(model="m", messages=_MESSAGES, stream=True))

        self.assertEqual(got, ["s0", "s1"])
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0]["stream"])

    def test_sync_error_before_first_chunk_is_retried(self):
        calls = {"n": 0}

        def fake_completion(**kw):
            calls["n"] += 1
            if calls["n"] == 1:
                return _FakeSyncStream(["a"], fail_before_index=0, exc=_Transient429("quota"))
            return _FakeSyncStream(["a"])

        with patch.object(litellm, "completion", fake_completion):
            got = list(self.client.completion(model="m", messages=_MESSAGES, stream=True))

        self.assertEqual(got, ["a"])
        self.assertEqual(calls["n"], 2)

    def test_sync_midstream_failure_raises_without_retry(self):
        inner = _Transient429("reset mid-stream")
        calls = {"n": 0}

        def fake_completion(**kw):
            calls["n"] += 1
            return _FakeSyncStream(["a", "b"], fail_before_index=1, exc=inner)

        got = []
        with patch.object(litellm, "completion", fake_completion):
            with self.assertRaises(MantisStreamInterruptedError) as cm:
                for chunk in self.client.completion(model="m", messages=_MESSAGES, stream=True):
                    got.append(chunk)

        self.assertEqual(got, ["a"])
        self.assertEqual(cm.exception.chunks_yielded, 1)
        self.assertIs(cm.exception.original_exception, inner)
        self.assertEqual(calls["n"], 1)

    def test_sync_nonstream_path_unchanged(self):
        sentinel = object()
        seen = {}

        def fake_completion(**kw):
            seen.update(kw)
            return sentinel

        with patch.object(litellm, "completion", fake_completion):
            result = self.client.completion(model="m", messages=_MESSAGES)

        self.assertIs(result, sentinel)
        # Sync non-stream has always passed stream explicitly; it must stay False.
        self.assertIs(seen.get("stream"), False)


class _SlowAsyncStream:
    """Async stream with configurable per-chunk delays and teardown tracking."""

    def __init__(self, chunks, delays=None, aclose_delay=0.0):
        self._chunks = list(chunks)
        self._delays = dict(delays or {})
        self._index = 0
        self._aclose_delay = aclose_delay
        self.aclose_calls = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        delay = self._delays.get(self._index, 0.0)
        if delay > 0:
            await asyncio.sleep(delay)
        if self._index >= len(self._chunks):
            raise StopAsyncIteration
        chunk = self._chunks[self._index]
        self._index += 1
        return chunk

    async def aclose(self):
        self.aclose_calls += 1
        if self._aclose_delay > 0:
            await asyncio.sleep(self._aclose_delay)


class _SeparateResponseWrapper:
    """Response object whose __aiter__() returns a distinct stream iterator."""

    def __init__(self, inner_iter):
        self._inner = inner_iter
        self.aclose_calls = 0

    def __aiter__(self):
        return self._inner

    async def aclose(self):
        self.aclose_calls += 1


def _litellm_stream_chunk(text="", finish_reason=None, provider_specific_fields=None):
    """Builds a minimal ModelResponseStream-compatible chunk for ADK/splicer tests."""
    from litellm.types.utils import Delta, ModelResponseStream, StreamingChoices

    delta_kwargs = {"role": "assistant", "content": text or None}
    if provider_specific_fields is not None:
        delta_kwargs["provider_specific_fields"] = provider_specific_fields
    return ModelResponseStream(
        id="chatcmpl-test",
        created=0,
        model="vertex_ai/gemini-3.8-flash",
        choices=[
            StreamingChoices(
                index=0,
                delta=Delta(**delta_kwargs),
                finish_reason=finish_reason,
            )
        ],
    )


class TestStreamedTimeout(unittest.IsolatedAsyncioTestCase):
    """Harness-enforced per-chunk timeouts on streamed turns (provider-independent)."""

    def setUp(self):
        self.client = ResilientLiteLLMClient()
        env_patch = patch.dict(os.environ, _FAST_RETRY_ENV)
        env_patch.start()
        self.addCleanup(env_patch.stop)

    def test_resolve_stream_chunk_timeout_precedence_and_validation(self):
        self.assertEqual(_resolve_stream_chunk_timeout({}), REQUEST_TIMEOUT_STREAMED)
        self.assertEqual(_resolve_stream_chunk_timeout({"timeout": None}), REQUEST_TIMEOUT_STREAMED)
        self.assertEqual(_resolve_stream_chunk_timeout({"timeout": 1200.0}), 1200.0)
        self.assertEqual(_resolve_stream_chunk_timeout({"timeout": 42}), 42.0)
        self.assertEqual(_resolve_stream_chunk_timeout({"timeout": "75.5"}), 75.5)
        self.assertEqual(
            _resolve_stream_chunk_timeout({"timeout": httpx.Timeout(30.0, read=123.0)}),
            123.0,
        )
        for bad in (0, -5.0, False, True, float("nan"), float("inf"), "not-a-number"):
            self.assertEqual(_resolve_stream_chunk_timeout({"timeout": bad}), REQUEST_TIMEOUT_STREAMED, repr(bad))

    async def test_stall_before_first_chunk_times_out_closes_stream_and_retries(self):
        stalled = _SlowAsyncStream(["never"], delays={0: 5.0})
        healthy = _SlowAsyncStream(["ok-1", "ok-2"])
        calls = {"n": 0}

        async def fake_acompletion(**kw):
            calls["n"] += 1
            return stalled if calls["n"] == 1 else healthy

        t0 = time.monotonic()
        with patch.object(litellm, "acompletion", fake_acompletion):
            stream = await self.client.acompletion(
                model="vertex_ai/gemini-3.8-flash",
                messages=_MESSAGES,
                stream=True,
                timeout=0.05,
            )
            got = await _collect(stream)
        elapsed = time.monotonic() - t0

        self.assertEqual(got, ["ok-1", "ok-2"])
        self.assertEqual(calls["n"], 2)
        self.assertEqual(stalled.aclose_calls, 1)
        self.assertLess(elapsed, 2.0)

    async def test_stall_during_stream_open_times_out_and_retries(self):
        calls = {"n": 0}

        async def fake_acompletion(**kw):
            calls["n"] += 1
            if calls["n"] == 1:
                await asyncio.sleep(5.0)
            return _SlowAsyncStream(["open-ok"])

        t0 = time.monotonic()
        with patch.object(litellm, "acompletion", fake_acompletion):
            stream = await self.client.acompletion(
                model="vertex_ai/gemini-3.8-flash",
                messages=_MESSAGES,
                stream=True,
                timeout=0.05,
            )
            got = await _collect(stream)
        elapsed = time.monotonic() - t0

        self.assertEqual(got, ["open-ok"])
        self.assertEqual(calls["n"], 2)
        self.assertLess(elapsed, 2.0)

    async def test_stall_between_chunks_closes_iter_and_response_and_raises_interrupted(self):
        inner_iter = _SlowAsyncStream(["c0", "c1"], delays={1: 5.0})
        wrapper = _SeparateResponseWrapper(inner_iter)
        calls = {"n": 0}

        async def fake_acompletion(**kw):
            calls["n"] += 1
            return wrapper

        got = []
        t0 = time.monotonic()
        with patch.object(litellm, "acompletion", fake_acompletion):
            stream = await self.client.acompletion(
                model="vertex_ai/gemini-3.8-flash",
                messages=_MESSAGES,
                stream=True,
                timeout=0.05,
            )
            with self.assertRaises(MantisStreamInterruptedError) as cm:
                async for chunk in stream:
                    got.append(chunk)
        elapsed = time.monotonic() - t0

        self.assertEqual(got, ["c0"])
        self.assertEqual(calls["n"], 1)
        self.assertEqual(cm.exception.chunks_yielded, 1)
        self.assertIsInstance(cm.exception.original_exception, TimeoutError)
        self.assertIn("waiting for the next chunk", str(cm.exception.original_exception))
        self.assertEqual(inner_iter.aclose_calls, 1)
        self.assertEqual(wrapper.aclose_calls, 1)
        self.assertLess(elapsed, 2.0)

    async def test_resilient_litellm_retries_whole_turn_on_midstream_chunk_timeout(self):
        from google.adk.models.llm_request import LlmRequest
        from google.genai import types as genai_types

        stalled = _SlowAsyncStream(
            [
                _litellm_stream_chunk(text="partial "),
                _litellm_stream_chunk(text="never arrives", finish_reason="stop"),
            ],
            delays={1: 5.0},
        )
        healthy = _SlowAsyncStream(
            [
                _litellm_stream_chunk(text="recovered "),
                _litellm_stream_chunk(text="after stall", finish_reason="stop"),
            ]
        )
        calls = {"n": 0}

        async def fake_acompletion(**kw):
            calls["n"] += 1
            return stalled if calls["n"] == 1 else healthy

        llm = ResilientLiteLlm(model="vertex_ai/gemini-3.8-flash", timeout=0.05)
        req = LlmRequest(
            model="vertex_ai/gemini-3.8-flash",
            contents=[genai_types.Content(role="user", parts=[genai_types.Part.from_text(text="hi")])],
        )

        responses = []
        with patch.object(litellm, "acompletion", fake_acompletion):
            async for resp in llm.generate_content_async(req, stream=True):
                responses.append(resp)

        self.assertEqual(calls["n"], 2)
        self.assertEqual(stalled.aclose_calls, 1)
        finals = [r for r in responses if not getattr(r, "partial", False)]
        self.assertTrue(finals)
        final_text = "".join(
            getattr(p, "text", "") or ""
            for p in (getattr(getattr(finals[-1], "content", None), "parts", None) or [])
        )
        self.assertEqual(final_text, "recovered after stall")

    async def test_per_chunk_timer_resets_each_chunk_for_long_streaming_turn(self):
        # Total stream duration (~0.15s) exceeds the per-chunk timeout (0.09s),
        # but every individual inter-chunk gap (0.03s) stays well under it.
        slow_but_alive = _SlowAsyncStream(
            ["t0", "t1", "t2", "t3", "t4"],
            delays={0: 0.03, 1: 0.03, 2: 0.03, 3: 0.03, 4: 0.03},
        )

        async def fake_acompletion(**kw):
            return slow_but_alive

        with patch.object(litellm, "acompletion", fake_acompletion):
            stream = await self.client.acompletion(
                model="vertex_ai/gemini-3.8-flash",
                messages=_MESSAGES,
                stream=True,
                timeout=0.09,
            )
            got = await _collect(stream)

        self.assertEqual(got, ["t0", "t1", "t2", "t3", "t4"])

    async def test_missing_timeout_enforces_harness_fallback_without_mutating_kwargs(self):
        # Low-effort non-thinking nodes omit `timeout` from kwargs; the harness
        # must still bound every streamed read via REQUEST_TIMEOUT_STREAMED.
        stalled = _SlowAsyncStream(["never"], delays={0: 5.0})
        seen_kwargs = []

        async def fake_acompletion(**kw):
            seen_kwargs.append(dict(kw))
            return stalled

        with patch.dict(os.environ, {"MANTIS_LLM_MAX_PATIENCE_SECONDS": "0.0"}), \
                patch.object(config_module, "REQUEST_TIMEOUT_STREAMED", 0.05), \
                patch.object(litellm, "acompletion", fake_acompletion):
            stream = await self.client.acompletion(
                model="vertex_ai/gemini-example",
                messages=_MESSAGES,
                stream=True,
            )
            with self.assertRaises(TimeoutError) as cm:
                await _collect(stream)

        self.assertIn("waiting for the first chunk", str(cm.exception))
        self.assertEqual(stalled.aclose_calls, 1)
        self.assertNotIn("timeout", seen_kwargs[0])

    async def test_upstream_timeout_error_message_preserved_when_harness_timer_not_expired(self):
        upstream = TimeoutError("provider gateway 504")

        async def fake_acompletion_first(**kw):
            return _FakeAsyncStream(["a"], fail_before_index=0, exc=upstream)

        with patch.dict(os.environ, {"MANTIS_LLM_MAX_PATIENCE_SECONDS": "0.0"}), \
                patch.object(litellm, "acompletion", fake_acompletion_first):
            stream = await self.client.acompletion(
                model="vertex_ai/gemini-3.8-flash",
                messages=_MESSAGES,
                stream=True,
                timeout=30.0,
            )
            with self.assertRaises(TimeoutError) as cm:
                await _collect(stream)
        self.assertIs(cm.exception, upstream)

        async def fake_acompletion_mid(**kw):
            return _FakeAsyncStream(["a", "b"], fail_before_index=1, exc=upstream)

        with patch.object(litellm, "acompletion", fake_acompletion_mid):
            stream = await self.client.acompletion(
                model="vertex_ai/gemini-3.8-flash",
                messages=_MESSAGES,
                stream=True,
                timeout=30.0,
            )
            with self.assertRaises(MantisStreamInterruptedError) as cm_mid:
                await _collect(stream)
        self.assertIs(cm_mid.exception.original_exception, upstream)

    async def test_continuation_segment_also_enforces_chunk_timeout(self):
        seg1_chunk = pytypes.SimpleNamespace(
            choices=[
                pytypes.SimpleNamespace(
                    delta=pytypes.SimpleNamespace(
                        content="part1",
                        provider_specific_fields={
                            CONTINUATION_TOKEN_FIELD: "tok-seg-2",
                            CONTINUATION_RAW_FINISH_FIELD: CONTINUATION_FINISH_REASON,
                        },
                    ),
                    finish_reason="length",
                )
            ],
            usage=None,
        )
        seg1 = _SlowAsyncStream([seg1_chunk])
        seg2 = _SlowAsyncStream(["part2a", "part2b"], delays={1: 5.0})
        calls = {"n": 0}

        async def fake_acompletion(**kw):
            calls["n"] += 1
            return seg1 if calls["n"] == 1 else seg2

        got = []
        with patch.object(litellm, "acompletion", fake_acompletion):
            stream = await self.client.acompletion(
                model="vertex_ai/gemini-3.8-flash",
                messages=_MESSAGES,
                stream=True,
                timeout=0.05,
            )
            with self.assertRaises(MantisStreamInterruptedError) as cm:
                async for chunk in stream:
                    got.append(chunk)

        self.assertEqual(calls["n"], 2)
        self.assertEqual(len(got), 2)
        self.assertIsInstance(cm.exception.original_exception, TimeoutError)
        self.assertEqual(seg2.aclose_calls, 1)

    async def test_stuck_aclose_is_bounded_and_does_not_stall_retry(self):
        stalled = _SlowAsyncStream(["never"], delays={0: 5.0}, aclose_delay=5.0)
        healthy = _SlowAsyncStream(["recovered"])
        calls = {"n": 0}

        async def fake_acompletion(**kw):
            calls["n"] += 1
            return stalled if calls["n"] == 1 else healthy

        t0 = time.monotonic()
        with patch.object(config_module, "_STREAM_CLOSE_TIMEOUT_SECONDS", 0.05), \
                patch.object(litellm, "acompletion", fake_acompletion):
            stream = await self.client.acompletion(
                model="vertex_ai/gemini-3.8-flash",
                messages=_MESSAGES,
                stream=True,
                timeout=0.05,
            )
            got = await _collect(stream)
        elapsed = time.monotonic() - t0

        self.assertEqual(got, ["recovered"])
        self.assertEqual(calls["n"], 2)
        self.assertEqual(stalled.aclose_calls, 1)
        self.assertLess(elapsed, 2.0)

    async def test_first_chunk_timeout_escalates_and_caps_retries_independently_of_429(self):
        """Regression test for r4-silent-thinking-timeout:
        - Default/effort timeouts escalate 1x -> 2x -> 4x (capped at 1800s).
        - First-chunk timeout retries stop after MAX_STREAM_TIMEOUT_RETRIES (default 2),
          not burning the full 3600s patience window on 18 identical retries.
        - HTTP 429 retries stay completely independent of the timeout retry counter.
        """
        # Pure escalation math checks
        self.assertEqual(config_module._compute_escalated_stream_timeout(600.0, 0), 600.0)
        self.assertEqual(config_module._compute_escalated_stream_timeout(600.0, 1), 1200.0)
        self.assertEqual(config_module._compute_escalated_stream_timeout(600.0, 2), 1800.0)
        self.assertEqual(config_module._compute_escalated_stream_timeout(900.0, 1), 1800.0)
        # Explicit operator timeout NEVER escalates
        self.assertEqual(
            config_module._compute_escalated_stream_timeout(180.0, 1, explicit_timeout=True), 180.0
        )
        # Respects remaining patience and wall-clock budget
        self.assertEqual(
            config_module._compute_escalated_stream_timeout(
                600.0, 1, remaining_patience=250.0, remaining_wall_seconds=120.0
            ),
            120.0,
        )

        # Live timeout retry cap: 1 initial attempt + 2 timeout retries = 3 total calls, then raises!
        # Even though a preceding 429 occurred, the 429 must NOT consume a timeout retry slot.
        calls = {"n": 0}
        seen_timeouts: list[float] = []
        orig_compute = config_module._compute_escalated_stream_timeout

        def _spy_compute(base, retries, **kw):
            val = orig_compute(base, retries, **kw)
            seen_timeouts.append(val)
            return val

        async def fake_acompletion(**kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise _Transient429("quota burst")
            return _SlowAsyncStream(["never"], delays={0: 5.0})

        with patch.object(config_module, "_compute_escalated_stream_timeout", side_effect=_spy_compute), \
                patch.dict(os.environ, {"MANTIS_STREAM_TIMEOUT_MAX_RETRIES": "2", "MANTIS_LLM_MAX_PATIENCE_SECONDS": "60.0"}), \
                patch.object(litellm, "acompletion", fake_acompletion):
            stream = await self.client.acompletion(
                model="vertex_ai/gemini-3.8-flash",
                messages=_MESSAGES,
                stream=True,
                timeout=0.04,
            )
            with self.assertRaises(TimeoutError) as cm:
                await _collect(stream)

        self.assertIn("waiting for the first chunk", str(cm.exception))
        # 1 (429) + 1 (initial timeout) + 2 (timeout retries) = 4 total calls!
        self.assertEqual(calls["n"], 4)
        self.assertEqual(seen_timeouts, [0.04, 0.04, 0.08, 0.16])

    async def test_explicit_operator_timeout_never_escalates_on_retry(self):
        client = ResilientLiteLLMClient()
        client.explicit_timeout = True
        observed: list[float] = []
        orig_compute = config_module._compute_escalated_stream_timeout

        def _spy_compute(base, retries, **kw):
            val = orig_compute(base, retries, **kw)
            observed.append(val)
            return val

        async def fake_acompletion(**kw):
            return _SlowAsyncStream(["never"], delays={0: 5.0})

        with patch.object(config_module, "_compute_escalated_stream_timeout", side_effect=_spy_compute), \
                patch.dict(os.environ, {"MANTIS_STREAM_TIMEOUT_MAX_RETRIES": "1", "MANTIS_LLM_MAX_PATIENCE_SECONDS": "60.0"}), \
                patch.object(litellm, "acompletion", fake_acompletion):
            stream = await client.acompletion(
                model="vertex_ai/gemini-3.8-flash",
                messages=_MESSAGES,
                stream=True,
                timeout=0.04,
            )
            with self.assertRaises(TimeoutError):
                await _collect(stream)

        self.assertEqual(observed, [0.04, 0.04])

    async def test_post_finish_eof_stall_preserves_completed_response(self):
        """Regression test for r4-finish-chunk-stall:
        A stream that has already yielded a clean terminal finish chunk (`stop`)
        and then hangs before EOF MUST flush and return the completed response
        instead of throwing `MantisStreamInterruptedError`."""
        from core.budget import BudgetConfig, BudgetController, render_spend_summary
        from core.context import RunContext, current_run_context

        class _HangAtEofStream:
            def __init__(self, chunks):
                self._chunks = list(chunks)
                self._idx = 0
                self.aclose_calls = 0

            def __aiter__(self):
                return self

            async def __anext__(self):
                if self._idx < len(self._chunks):
                    c = self._chunks[self._idx]
                    self._idx += 1
                    return c
                await asyncio.sleep(5.0)
                raise StopAsyncIteration

            async def aclose(self):
                self.aclose_calls += 1

        c0 = _litellm_stream_chunk(text="Complete ")
        c1 = _litellm_stream_chunk(text="answer!", finish_reason="stop")
        c1.usage = pytypes.SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        stalled_eof = _HangAtEofStream([c0, c1])

        ctrl = BudgetController(BudgetConfig(), run_id="r_eof")
        ctx = RunContext(jail_dir="/tmp", db_path="", budget_controller=ctrl, run_id="r_eof")
        tok = current_run_context.set(ctx)
        try:
            async def fake_acompletion(**kw):
                return stalled_eof

            with patch.dict(os.environ, {"MANTIS_STREAM_EOF_TIMEOUT_SECONDS": "0.05"}), \
                    patch.object(litellm, "acompletion", fake_acompletion):
                stream = await self.client.acompletion(
                    model="vertex_ai/gemini-3.8-flash",
                    messages=_MESSAGES,
                    stream=True,
                    timeout=5.0,  # Note: EOF timeout caps wait to 0.05s once finish+usage arrived!
                )
                t0 = time.monotonic()
                got = await _collect(stream)
                elapsed = time.monotonic() - t0
        finally:
            current_run_context.reset(tok)

        self.assertEqual(len(got), 2, "Must deliver both content and held terminal finish chunk")
        self.assertEqual(got[1].choices[0].finish_reason, "stop")
        self.assertEqual(stalled_eof.aclose_calls, 1)
        self.assertLess(elapsed, 2.0, "Post-finish+usage EOF stall must resolve via eof_timeout cap")
        snap = ctrl.spend_snapshot()
        self.assertEqual(snap["other"].get("stream_eof_stalls_preserved"), 1)
        self.assertGreaterEqual(snap["other"].get("stream_max_first_chunk_ms", 0), 0)
        summary_txt = "\n".join(render_spend_summary(snap))
        self.assertIn("post-finish EOF stall(s) preserved", summary_txt)

    async def test_stream_gap_timing_recorded_in_budget_snapshot(self):
        from core.budget import BudgetConfig, BudgetController, render_spend_summary
        from core.context import RunContext, current_run_context

        ctrl = BudgetController(BudgetConfig(), run_id="r_gap")
        ctx = RunContext(jail_dir="/tmp", db_path="", budget_controller=ctrl, run_id="r_gap")
        tok = current_run_context.set(ctx)
        try:
            slow = _SlowAsyncStream(["a", "b", "c"], delays={0: 0.02, 1: 0.06, 2: 0.01})

            async def fake_acompletion(**kw):
                return slow

            with patch.object(litellm, "acompletion", fake_acompletion):
                stream = await self.client.acompletion(
                    model="vertex_ai/gemini-3.8-flash",
                    messages=_MESSAGES,
                    stream=True,
                    timeout=5.0,
                )
                got = await _collect(stream)
        finally:
            current_run_context.reset(tok)

        self.assertEqual(got, ["a", "b", "c"])
        snap = ctrl.spend_snapshot()
        self.assertGreaterEqual(snap["other"].get("stream_max_first_chunk_ms", 0), 10)
        self.assertGreaterEqual(snap["other"].get("stream_max_chunk_gap_ms", 0), 40)
        summary_txt = "\n".join(render_spend_summary(snap))
        self.assertIn("Stream timing:", summary_txt)
        self.assertIn("max inter-chunk gap", summary_txt)

    def test_legacy_local_overlay_timeout_180_emits_warning(self):
        import contextlib
        import io
        import json
        import shutil
        import tempfile
        from core.graph_loader import load_workflow_from_json

        tmp = tempfile.mkdtemp(prefix="mantis_legacy_to_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        wf_src = Path(__file__).resolve().parent.parent / "workflow.json"
        wf_dst = Path(tmp) / "workflow.json"
        wf_dst.write_text(wf_src.read_text(encoding="utf-8"), encoding="utf-8")
        local_dst = Path(tmp) / "workflow.local.json"
        local_dst.write_text(json.dumps({"config": {"timeout": 180}}), encoding="utf-8")

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            load_workflow_from_json(str(wf_dst), load_local=True)
        self.assertIn("legacy `timeout: 180`", err.getvalue())
        self.assertIn("180s per-chunk timeout", err.getvalue())


if __name__ == "__main__":
    unittest.main()

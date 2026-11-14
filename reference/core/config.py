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

import asyncio
import contextvars
import hashlib
import json
import logging
import math
import os
import random
import re
import sys
import time
from collections.abc import Mapping, Sequence
from typing import Any, Optional, Tuple, Union

# Suppress ADK warning regarding Gemini via LiteLLM to maintain unified error handling and backoff
os.environ.setdefault("ADK_SUPPRESS_GEMINI_LITELLM_WARNINGS", "true")
# Keep LiteLLM 100% hermetic at import/call time (no live GitHub HTTP fetches or implicit CWD .env loads)
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
os.environ.setdefault("LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS", "True")
os.environ.setdefault("LITELLM_MODE", "PRODUCTION")

try:
    import litellm
    litellm.drop_params = True
    litellm.suppress_debug_info = True

    # Suppress interactive reauth popups (e.g. macOS Touch ID / WebAuthn prompts)
    # when ADC credentials require reauthentication.
    try:
        import google.oauth2.reauth
        google.oauth2.reauth.is_interactive = lambda: False
    except Exception:
        pass

    try:
        import google.oauth2.credentials
        _orig_creds_init = google.oauth2.credentials.Credentials.__init__

        def _non_interactive_creds_init(self, *args, **kwargs):
            kwargs["enable_reauth_refresh"] = False
            _orig_creds_init(self, *args, **kwargs)
            self._enable_reauth_refresh = False

        google.oauth2.credentials.Credentials.__init__ = _non_interactive_creds_init
    except Exception:
        pass

    # Patch VertexAIAnthropicConfig to properly support adaptive thinking models (Claude 4.6+)
    # when structured output (response_format) is used. LiteLLM temporarily swaps model to
    # claude-3-sonnet-20240229 to force tool-based response_format, but this mistakenly converts
    # reasoning_effort into legacy thinking={"type": "enabled"} and retains non-1.0 temperature.
    try:
        from litellm.llms.vertex_ai.vertex_ai_partner_models.anthropic.transformation import VertexAIAnthropicConfig
        from litellm.llms.anthropic.chat.transformation import (
            AnthropicConfig,
            REASONING_EFFORT_TO_OUTPUT_CONFIG_EFFORT,
        )
        from litellm.llms.anthropic.common_utils import AnthropicModelInfo

        # LiteLLM's local model map frequently adds newer Claude 4.6+/5.x
        # revisions (e.g. claude-opus-5-5) under the `anthropic` fallback
        # generalization before adding explicit `vertex_ai/` entries. When a
        # Vertex Claude model has no explicit `vertex_ai` capability entry
        # (`None`), fall back to `anthropic` without overriding explicit `False`
        # flags, and treat any adaptive-thinking model as supporting
        # `output_config.effort` so `_apply_output_config` does not silently
        # drop `output_config` under `drop_params=True`.
        _orig_get_provider_cap = AnthropicModelInfo._get_provider_resolved_capability

        @staticmethod
        def _safe_get_provider_cap(model: str, key: str, custom_llm_provider: str):
            val = _orig_get_provider_cap(model, key, custom_llm_provider)
            if val is None and str(custom_llm_provider or "").startswith("vertex_ai"):
                return _orig_get_provider_cap(model, key, "anthropic")
            return val

        AnthropicModelInfo._get_provider_resolved_capability = _safe_get_provider_cap

        _orig_model_supports_effort = AnthropicConfig._model_supports_effort_param

        @staticmethod
        def _safe_model_supports_effort(model: str, custom_llm_provider: str) -> bool:
            if _orig_model_supports_effort(model, custom_llm_provider):
                return True
            try:
                return bool(AnthropicConfig._is_adaptive_thinking_model(model, custom_llm_provider))
            except Exception:
                return False

        AnthropicConfig._model_supports_effort_param = _safe_model_supports_effort

        _orig_vertex_anthropic_map_openai_params = VertexAIAnthropicConfig.map_openai_params
        _orig_vertex_anthropic_supported_params = VertexAIAnthropicConfig.get_supported_openai_params

        def _is_vertex_claude_adaptive(model: str, provider: str) -> bool:
            for prov in (provider, "anthropic"):
                try:
                    if AnthropicConfig._is_adaptive_thinking_model(model, prov):
                        return True
                except Exception:
                    pass
            return False

        def _safe_vertex_anthropic_supported_params(self, model: str) -> list:
            params = list(_orig_vertex_anthropic_supported_params(self, model))
            provider = getattr(self, "_resolved_provider", "vertex_ai")
            if (
                "thinking" not in params or "reasoning_effort" not in params
            ) and _is_vertex_claude_adaptive(model, provider):
                for param_name in ("thinking", "reasoning_effort"):
                    if param_name not in params:
                        params.append(param_name)
            return params

        def _safe_vertex_anthropic_map_openai_params(
            self,
            non_default_params: dict,
            optional_params: dict,
            model: str,
            drop_params: bool,
        ) -> dict:
            original_model = model
            provider = getattr(self, "_resolved_provider", "vertex_ai")
            is_adaptive = _is_vertex_claude_adaptive(original_model, provider)

            res = _orig_vertex_anthropic_map_openai_params(
                self,
                non_default_params=non_default_params,
                optional_params=optional_params,
                model=model,
                drop_params=drop_params,
            )

            if is_adaptive:
                existing_display = (
                    res["thinking"].get("display")
                    if isinstance(res.get("thinking"), dict) and res["thinking"].get("display")
                    else "summarized"
                )
                raw_effort = non_default_params.get("reasoning_effort")
                if isinstance(raw_effort, dict):
                    raw_effort = raw_effort.get("effort")
                if raw_effort and raw_effort != "none":
                    mapped_effort = REASONING_EFFORT_TO_OUTPUT_CONFIG_EFFORT.get(raw_effort, raw_effort)
                    res["thinking"] = {"type": "adaptive", "display": existing_display}
                    res["output_config"] = {"effort": mapped_effort}
                elif "thinking" in res and isinstance(res["thinking"], dict) and res["thinking"].get("type") in ("enabled", "adaptive"):
                    res["thinking"] = {"type": "adaptive", "display": existing_display}

                # If thinking is enabled on an adaptive model, drop non-1.0 temperature and top_p
                if "thinking" in res:
                    temp = res.get("temperature")
                    if temp is not None and temp != 1:
                        res.pop("temperature", None)
                    res.pop("top_p", None)
            return res

        VertexAIAnthropicConfig.get_supported_openai_params = _safe_vertex_anthropic_supported_params
        VertexAIAnthropicConfig.map_openai_params = _safe_vertex_anthropic_map_openai_params
    except Exception:
        pass
except Exception:
    pass


# --- Gemini thinking continuation ----------------------------------------------------------
#
# Some Gemini models answer one request with at most a segment of thinking
# (measured: about 32k thinking tokens, seven minutes at the highest
# effort), then stop with finish reason CONTINUATION and a continuation
# token; the same request sent again with the token continues the turn,
# and the client's output ceiling counts across segments. The Google
# GenAI SDK does this re-sending itself. LiteLLM at the pinned version
# does not: it drops the token (it reads only finishReason and index from
# a candidate) and maps the unknown finish reason to "stop", so the turn
# ends with a thought and no answer. The fix needs the token surfaced and
# the request re-sent, and both are done here in the layer that already
# sees LiteLLM's responses raw. A LiteLLM that surfaces the token itself
# is left alone, and a response LiteLLM has already continued carries no
# token, so neither piece acts twice.

CONTINUATION_TOKEN_FIELD = "continuation_token"
CONTINUATION_RAW_FINISH_FIELD = "finish_reason_raw"
CONTINUATION_FINISH_REASON = "CONTINUATION"


def _install_gemini_continuation_patch() -> None:
    try:
        from litellm.litellm_core_utils import core_helpers
        from litellm.llms.vertex_ai.gemini import vertex_and_google_ai_studio_gemini as _vg
    except Exception:
        return
    try:
        fmap = getattr(core_helpers, "_FINISH_REASON_MAP", None)
        if isinstance(fmap, dict):
            fmap.setdefault(CONTINUATION_FINISH_REASON, "length")
    except Exception:
        pass
    config_cls = getattr(_vg, "VertexGeminiConfig", None)
    original = getattr(config_cls, "_process_candidates", None)
    if config_cls is None or original is None or getattr(original, "_mantis_continuation", False):
        return

    def _process_candidates(_candidates, model_response, standard_optional_params, cumulative_tool_call_index=0):
        out = original(_candidates, model_response, standard_optional_params, cumulative_tool_call_index)
        try:
            choices = list(getattr(model_response, "choices", None) or [])
            for idx, cand in enumerate(_candidates or []):
                if not isinstance(cand, dict):
                    continue
                token = cand.get("continuationToken") or cand.get(CONTINUATION_TOKEN_FIELD)
                raw = cand.get("finishReason")
                if not token and not raw:
                    continue
                choice = choices[idx] if idx < len(choices) else (choices[-1] if choices else None)
                holder = getattr(choice, "message", None) or getattr(choice, "delta", None)
                if holder is None:
                    continue
                fields = dict(getattr(holder, "provider_specific_fields", None) or {})
                if fields.get(CONTINUATION_TOKEN_FIELD):
                    continue  # LiteLLM surfaced it itself
                if token:
                    fields[CONTINUATION_TOKEN_FIELD] = token
                if raw:
                    fields[CONTINUATION_RAW_FINISH_FIELD] = str(raw)
                try:
                    holder.provider_specific_fields = fields
                except Exception:
                    setattr(holder, "provider_specific_fields", fields)
        except Exception:
            pass
        return out

    _process_candidates._mantis_continuation = True  # type: ignore[attr-defined]
    config_cls._process_candidates = staticmethod(_process_candidates)


_install_gemini_continuation_patch()

try:
    from google.adk.models.lite_llm import LiteLlm, LiteLLMClient, LlmCapabilities
    from pydantic import Field, PrivateAttr
except Exception:
    LiteLlm = object
    LiteLLMClient = object
    LlmCapabilities = None

    def Field(**kwargs: Any) -> Any:
        factory = kwargs.get("default_factory")
        if callable(factory):
            return factory()
        return kwargs.get("default", None)

    def PrivateAttr(**kwargs: Any) -> Any:
        return kwargs.get("default", None)


# ---------------------------------------------------------------------------
# P6: Per-finding review verdicts.
#
# A live run pushed 14 findings through ONE campaign-level ReviewVerdict: a
# single {route, reason} pair silently judged 14 independent vulnerabilities,
# so one review opinion either promoted or dismissed all of them at once.
# ExtendedReviewVerdict mirrors core.schemas.ReviewVerdict exactly (route,
# reason, extra="forbid") and adds an OPTIONAL finding_verdicts list carrying
# one verdict per finding id. It lives HERE rather than in core.schemas
# because the ADK runtime re-validates the agent's final response text against
# the bound output schema (google.adk.utils._schema_utils.validate_schema uses
# model_validate_json), and the canonical ReviewVerdict is extra="forbid":
# binding the strict schema while asking the reviewer for finding_verdicts
# would turn every extended response into an ADK validation error. The strict
# schema in core.schemas stays untouched as the wire-compatibility baseline
# (INV-6): when this class cannot be defined, graph_loader keeps the canonical
# schema and behavior is exactly pre-P6.
try:
    from typing import Literal as _Literal
    from pydantic import BaseModel as _PydanticBaseModel, ConfigDict as _PydanticConfigDict

    class FindingVerdict(_PydanticBaseModel):
        """One reviewer verdict for ONE finding (see ExtendedReviewVerdict)."""

        # extra="ignore" and route-as-plain-str are deliberate leniency: a
        # single malformed entry must never invalidate the 13 well-formed
        # sibling verdicts beside it in the same response. The classifier's
        # coercion layer lowercases routes, drops entries it cannot use, and
        # only ever persists the known dismissal vocabulary -- an unknown
        # route can therefore route conservatively but can never be learned.
        model_config = _PydanticConfigDict(extra="ignore")
        finding_id: int = Field(description="The numeric finding id exactly as returned by get_findings.")
        route: str = Field(
            description=(
                "'confirmed'/'false_positive' (reviewer) or 'viable'/'non_viable' (critic) "
                "for THIS finding only."
            )
        )
        reason: str = Field(default="", description="One sentence justifying this finding's verdict.")

    class ExtendedReviewVerdict(_PydanticBaseModel):
        """Structured reviewer verdict with optional per-finding verdicts (P6)."""

        model_config = _PydanticConfigDict(extra="forbid")
        route: _Literal["confirmed", "false_positive"]
        reason: str = Field(description="One sentence justifying the verdict.")
        # The empty-list default IS the fail-safe contract (INV-6): an absent
        # or empty list means campaign-level routing and persistence exactly
        # as before this field existed, so old prompts, old models, replayed
        # sessions, and synthesized refusal fallbacks lose nothing.
        finding_verdicts: list[FindingVerdict] = Field(
            default_factory=list,
            description=(
                "One verdict per finding id from get_findings. "
                "Empty list = the top-level verdict applies to the whole campaign."
            ),
        )

    class ExtendedCriticVerdict(_PydanticBaseModel):
        """Structured critic verdict with optional per-finding verdicts."""

        model_config = _PydanticConfigDict(extra="forbid")
        route: _Literal["viable", "non_viable"]
        reason: str = Field(description="One sentence justifying the verdict.")
        finding_verdicts: list[FindingVerdict] = Field(
            default_factory=list,
            description=(
                "One verdict per finding id from get_findings ('viable' or 'non_viable'). "
                "Empty list = the top-level verdict applies to the promoted campaign findings."
            ),
        )
except Exception:  # pragma: no cover - only when pydantic itself is absent
    FindingVerdict = None
    ExtendedReviewVerdict = None
    ExtendedCriticVerdict = None

DEFAULT_MODEL = "vertex_ai/gemini-3.8-flash"
DEFAULT_VERTEX_FAST_MODEL = "vertex_ai/gemini-3.5-flash-lite"
SUPPORTED_SANDBOXES = ("static-only", "static", "gvisor", "microsandbox", "gce", "remote")
RECOMMENDED_MODELS = (
    "gemini-3.8-flash",
    "gemini-3.5-flash-lite",
    "claude-opus-5",
    "vertex_ai/gemini-3.8-flash",
    "vertex_ai/gemini-3.5-flash-lite",
    "vertex_ai/claude-opus-5",
    "vertex_ai/zai_org/glm-5.2-maas",
)

PLACEHOLDER_STRINGS = {
    "YOUR_PROJECT_ID",
    "YOUR_PROJECT",
    "YOUR_GCP_PROJECT",
    "<YOUR_PROJECT_ID>",
    "<PROJECT_ID>",
    "YOUR_API_KEY",
    "<YOUR_API_KEY>",
    "TODO",
    "CHANGE_ME",
    "REPLACE_ME",
    "",
}


def is_placeholder(val: Any) -> bool:
    """Checks if a string or value represents an unconfigured placeholder."""
    if val is None:
        return True
    s = str(val).strip()
    if not s or s.upper() in PLACEHOLDER_STRINGS:
        return True
    if s.upper().startswith(("YOUR_", "<YOUR_", "CHANGE_ME", "REPLACE_ME")):
        return True
    # Token-level check for composite paths/models (e.g. openai/YOUR_API_KEY)
    for token in s.upper().split("/"):
        t = token.strip()
        if t in PLACEHOLDER_STRINGS or t.startswith(("YOUR_", "<YOUR_", "CHANGE_ME", "REPLACE_ME")):
            return True
    return False


class ConfigValidationError(ValueError):
    """Raised when local workflow overlay JSON or numeric LLM environment variables are invalid."""


def _parse_env_number(
    names: tuple[str, ...],
    *,
    as_int: bool = False,
    default: Optional[Union[int, float]] = None,
    min_val: Optional[float] = None,
) -> Optional[Union[int, float]]:
    """Parses the first set environment variable in `names` as an int/float,
    raising `ConfigValidationError` on non-numeric or out-of-range strings."""
    for name in names:
        raw = os.environ.get(name)
        if raw is None or not str(raw).strip():
            continue
        text = str(raw).strip()
        try:
            val: Union[int, float] = int(text) if as_int else float(text)
            if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
                raise ValueError("must be finite")
        except (TypeError, ValueError) as exc:
            kind = "integer" if as_int else "number"
            raise ConfigValidationError(
                f"Invalid {kind} in environment variable {name}={raw!r}."
            ) from exc
        if min_val is not None and val < min_val:
            raise ConfigValidationError(
                f"Environment variable {name}={raw!r} must be >= {min_val}."
            )
        return val
    return default


def validate_llm_env_vars() -> None:
    """Validates numeric LLM/retry environment variables upfront."""
    _parse_env_number(("LLM_TIMEOUT", "MANTIS_TIMEOUT", "LLM_REQUEST_TIMEOUT"), min_val=0.001)
    _parse_env_number(("LLM_MAX_TOKENS", "MANTIS_MAX_TOKENS"), as_int=True, min_val=1)
    _parse_env_number(("MANTIS_LLM_MAX_PATIENCE_SECONDS",), default=3600.0, min_val=0.0)
    _parse_env_number(("MANTIS_LLM_RETRY_INITIAL_DELAY",), default=5.0, min_val=0.0)
    _parse_env_number(("MANTIS_LLM_RETRY_MAX_DELAY",), default=60.0, min_val=0.0)
    _parse_env_number(("MANTIS_LLM_MIN_OFFSET", "MANTIS_LLM_RETRY_MIN_OFFSET"), default=5.0, min_val=0.0)
    _parse_env_number(("MANTIS_LLM_RETRY_BACKOFF",), default=2.0, min_val=0.0)
    _parse_env_number(("MANTIS_LLM_EMPTY_TURN_MAX_ATTEMPTS",), as_int=True, default=6, min_val=1)


def _llm_retry_params() -> tuple[float, float, float, float, float]:
    """Returns `(max_patience, initial_delay, max_delay, min_offset, backoff_factor)`."""
    max_patience = float(
        _parse_env_number(("MANTIS_LLM_MAX_PATIENCE_SECONDS",), default=3600.0, min_val=0.0) or 0.0
    )
    initial_delay = float(
        _parse_env_number(("MANTIS_LLM_RETRY_INITIAL_DELAY",), default=5.0, min_val=0.0) or 0.0
    )
    max_delay = float(
        _parse_env_number(("MANTIS_LLM_RETRY_MAX_DELAY",), default=60.0, min_val=0.0) or 0.0
    )
    min_offset = float(
        _parse_env_number(
            ("MANTIS_LLM_MIN_OFFSET", "MANTIS_LLM_RETRY_MIN_OFFSET"), default=5.0, min_val=0.0
        )
        or 0.0
    )
    backoff_factor = float(
        _parse_env_number(("MANTIS_LLM_RETRY_BACKOFF",), default=2.0, min_val=0.0) or 0.0
    )
    return max_patience, initial_delay, max_delay, min_offset, backoff_factor


_VERSIONED_REASONING_FAMILY_RE = re.compile(
    r"(?:^|[/:_-])(?:"
    r"gemini-(?:2\.5|3(?:\.\d+|[-_]|$))"
    r"|glm-5(?:\.\d+|[-_]|$)"
    r"|deepseek-r1(?:[-_.]|$)"
    r"|qwen3(?:[-_.]|$)"
    r"|gpt-5(?:\.\d+|[-_]|$)"
    r"|o1(?:[-_]|$)"
    r"|o3(?:[-_]|$)"
    r"|o4(?:[-_]|$)"
    r")",
    re.IGNORECASE,
)


def is_versioned_reasoning_model(model: Any) -> bool:
    """True for versioned reasoning model families whose `reasoning_effort`
    must pass through `litellm.drop_params = True` even when unlisted."""
    return bool(_VERSIONED_REASONING_FAMILY_RE.search(str(model or "").strip()))


def normalize_model_id(model_id: str) -> str:
    """Normalizes model names and routes bare gemini/claude models to vertex_ai or gemini/ based on credentials."""
    if not model_id:
        return DEFAULT_MODEL
    cleaned = model_id.strip()
    if cleaned.startswith("gemini-"):
        # If explicit Google AI Studio API key exists, route to gemini/ for LiteLLM
        if os.environ.get("GEMINI_API_KEY"):
            return f"gemini/{cleaned}"
        # If running in GCP / Vertex environment without explicit Google AI Studio API key, route to vertex_ai/
        if (
            os.environ.get("VERTEXAI_PROJECT")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
        ):
            return f"vertex_ai/{cleaned}"
    if cleaned.startswith("claude-"):
        # Route bare claude models to vertex_ai when GCP credentials exist and no direct Anthropic API key is set
        if not os.environ.get("ANTHROPIC_API_KEY") and (
            os.environ.get("VERTEXAI_PROJECT")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
        ):
            return f"vertex_ai/{cleaned}"
        return f"anthropic/{cleaned}"
    if cleaned in (
        "glm-5.2-maas",
        "zai-org/glm-5.2-maas",
        "vertex_ai/glm-5.2-maas",
        "vertex_ai/zai_org/glm-5.2-maas",
        "vertex_ai/zai-org/glm-5.2-maas",
        "vertex_ai/openai/zai-org/glm-5.2-maas",
    ):
        return "vertex_ai/openai/zai-org/glm-5.2-maas"
    return cleaned


def _http_status_of(e: Exception) -> Optional[int]:
    status = getattr(e, "status_code", None) or getattr(e, "code", None)
    if isinstance(status, int):
        return status
    resp = getattr(e, "response", None)
    resp_status = getattr(resp, "status_code", None) if resp is not None else None
    return resp_status if isinstance(resp_status, int) else None


def _is_deterministic_non_retryable_exc(e: Exception) -> bool:
    """True for deterministic client/request errors (4xx / schema / param errors)
    that must fail immediately rather than burning backoff patience."""
    status = _http_status_of(e)
    if status in (429, 503, 529):
        return False
    if status in (400, 401, 403, 404, 413, 422):
        return True
    non_retryable = set(globals().get("_NON_RETRYABLE_EXC_NAMES", ()))
    for cls in type(e).__mro__:
        if cls.__name__ in non_retryable:
            return status not in (408, 429, 500, 502, 503, 504, 529)
    return False


def is_rate_limit_error(e: Exception) -> bool:
    """Detects whether an exception represents a 429 / RateLimitError / RESOURCE_EXHAUSTED error."""
    try:
        import litellm
        if isinstance(e, (getattr(litellm, "RateLimitError", ()), getattr(litellm.exceptions, "RateLimitError", ()))):
            return True
    except Exception:
        pass
    status = _http_status_of(e)
    if status in (429, 503, 529):
        return True
    if _is_deterministic_non_retryable_exc(e) or (status is not None and status not in (429, 503, 529)):
        return False
    msg = str(e).lower()
    if any(k in msg for k in ("ratelimiterror", "resource_exhausted", "quota exceeded", "rate limit", "rate_limit", "overloaded", "too many requests")):
        return True
    if "429" in msg and any(k in msg for k in ("quota", "token", "limit", "exhausted", "aiplatform", "prediction")):
        return True
    return False


def is_retryable_llm_error(e: Exception) -> bool:
    """Detects whether an exception represents a retryable transient error (429, 408, 5xx, timeout, or network reset)."""
    if is_auth_error(e) or isinstance(e, (MantisAuthError, ConfigValidationError, PermissionError, FileNotFoundError)):
        return False
    if _is_deterministic_non_retryable_exc(e):
        return False
    if is_rate_limit_error(e):
        return True
    # An empty STOP turn is retried like a 429: same backoff, same patience.
    # Its cost is metered where it is raised (see MantisEmptyResponseError).
    if isinstance(e, MantisEmptyResponseError):
        return True
    # A stream cut after its first chunk (a read timeout on a silent
    # connection, a reset) is retried as a whole turn at the model layer:
    # the chunks already forwarded were partial events, which ADK does not
    # persist, so re-issuing the turn splices nothing. The client layer
    # that raised it refuses to retry for exactly the opposite reason: it
    # cannot know what its consumer did with the chunks.
    if isinstance(e, MantisStreamInterruptedError):
        return True
    if isinstance(e, json.decoder.JSONDecodeError):
        return True
    try:
        import litellm
        timeout_classes = (
            getattr(litellm, "Timeout", ()),
            getattr(getattr(litellm, "exceptions", None), "Timeout", ()),
            getattr(litellm, "InternalServerError", ()),
            getattr(getattr(litellm, "exceptions", None), "InternalServerError", ()),
            getattr(litellm, "ServiceUnavailableError", ()),
            getattr(getattr(litellm, "exceptions", None), "ServiceUnavailableError", ()),
            getattr(litellm, "BadGatewayError", ()),
            getattr(getattr(litellm, "exceptions", None), "BadGatewayError", ()),
        )
        valid_timeout_classes = tuple(c for c in timeout_classes if isinstance(c, type))
        if valid_timeout_classes and isinstance(e, valid_timeout_classes):
            return True
    except Exception:
        pass
    if isinstance(e, (asyncio.TimeoutError, TimeoutError, ConnectionResetError, BrokenPipeError)):
        return True
    status = _http_status_of(e)
    if status in (408, 429, 500, 502, 503, 504, 529):
        return True
    if status is not None:
        return False
    msg = str(e).lower()
    if any(
        k in msg
        for k in (
            "timeout",
            "timed out",
            "connection reset",
            "connection closed",
            "sockettimeout",
            "remotepathreset",
            "broken pipe",
            "internal server error",
            "service unavailable",
            "bad gateway",
            "gateway timeout",
        )
    ):
        return True
    return False


def extract_retry_after(e: Exception) -> Optional[float]:
    """Extracts suggested retry delay in seconds from response headers if present."""
    headers = getattr(e, "headers", None)
    if not headers:
        resp = getattr(e, "response", None)
        if resp:
            headers = getattr(resp, "headers", None)
    if headers and isinstance(headers, (dict, Mapping)):
        for k, v in headers.items():
            if k.lower() == "retry-after":
                try:
                    return float(v)
                except (ValueError, TypeError):
                    pass
    return None


# The output-token ceiling a Claude model gets when nothing else names one.
# Anthropic requires max_tokens on every request, so "unset" is never the
# provider's choice: LiteLLM fills it from its model registry and, for a
# model the registry does not know yet, with 4096 -- which at high effort
# a single turn of thinking exceeds. Current models allow 128k. A model
# that allows less says so when it rejects the request, and the request is
# retried at the ceiling it named (output_cap_from_error).
CLAUDE_DEFAULT_MAX_OUTPUT_TOKENS = 128000
# How providers word a rejected output ceiling. Anthropic: "max_tokens:
# 65536 > 32000, which is the maximum allowed...". Vertex Gemini: "...a
# maxOutputTokens value of 1000000 but the supported range is from 1
# (inclusive) to 65537 (exclusive)". OpenAI: "max_tokens is too large:
# 200000. This model supports at most 128000 completion tokens".
_OUTPUT_CAP_PATTERNS = (
    re.compile(r"max_tokens:\s*(?P<asked>\d+)\s*>\s*(?P<cap>\d+)"),
    re.compile(r"maxOutputTokens value of (?P<asked>\d+).*?to (?P<cap>\d+)\s*\((?P<bound>inclusive|exclusive)\)", re.S),
    re.compile(r"too large:\s*(?P<asked>\d+).*?supports at most (?P<cap>\d+)", re.S),
)


def output_cap_from_error(e: Exception) -> Optional[int]:
    """The output-token ceiling a provider names when it rejects a request
    for asking more; None for any other error, and None when the named
    ceiling is not below what was asked (nothing to retry at)."""
    text = str(e)
    for pattern in _OUTPUT_CAP_PATTERNS:
        m = pattern.search(text)
        if not m:
            continue
        asked, cap = int(m.group("asked")), int(m.group("cap"))
        if m.groupdict().get("bound") == "exclusive":
            cap -= 1
        return cap if 0 < cap < asked else None
    return None


# Whether model turns are streamed. Streamed, the request timeout applies
# between chunks rather than to the whole response, so a long thinking
# turn that keeps producing stays alive while a hung connection still
# trips it; thinking models stream their reasoning as it happens. Set from
# the workflow's `llm_streaming` (configure_llm_streaming); the
# environment's MANTIS_LLM_STREAM overrides either way.
_LLM_STREAMING: dict = {"enabled": True}


def configure_llm_streaming(enabled: Optional[bool]) -> None:
    """Records the workflow's choice; None leaves the default (on)."""
    if enabled is not None:
        _LLM_STREAMING["enabled"] = bool(enabled)


def llm_streaming_enabled() -> bool:
    """Whether to stream model turns: MANTIS_LLM_STREAM when set, else the
    workflow's `llm_streaming`, else on."""
    raw = os.environ.get("MANTIS_LLM_STREAM")
    if raw is not None and raw.strip():
        return raw.strip().lower() not in ("0", "false", "no", "off")
    return bool(_LLM_STREAMING["enabled"])


# How long one request may wait before it is abandoned and retried, when
# the operator sets no timeout (LLM_TIMEOUT / MANTIS_TIMEOUT /
# LLM_REQUEST_TIMEOUT). Streamed (the default), the timeout runs between
# chunks, and the providers keep a stream fed while the model thinks in
# silence (measured: turns of 650 and 905 seconds with no visible chunk
# completed under per-chunk timeouts of 10 to 60 seconds; a 641k-token
# prompt's first chunk arrived in 78 seconds), so a server that is
# working never meets the bound, however long the turn, and one value
# serves every effort: a dead connection is noticed in minutes.
# Unstreamed, the whole response -- thinking included -- must arrive
# inside it, and at the highest effort a single turn has been measured
# past five minutes; a timed-out turn is retried as the same long
# request, so the value scales with effort. Models that do not think get
# no timeout here and keep LiteLLM's.
REQUEST_TIMEOUT_STREAMED = 300.0
REQUEST_TIMEOUT_BY_EFFORT = {"max": 1800.0, "high": 900.0, "medium": 300.0}
REQUEST_TIMEOUT_THINKING_MODEL = 300.0


def default_request_timeout(model: str, effort: Optional[str]) -> Optional[float]:
    """The request timeout for `model` at `effort` when none is configured."""
    level = str(effort or "").lower().strip()
    name = str(model or "").lower()
    thinking = level in REQUEST_TIMEOUT_BY_EFFORT or "glm" in name or "claude" in name
    if not thinking:
        return None
    if llm_streaming_enabled():
        return REQUEST_TIMEOUT_STREAMED
    if level in REQUEST_TIMEOUT_BY_EFFORT:
        return REQUEST_TIMEOUT_BY_EFFORT[level]
    return REQUEST_TIMEOUT_THINKING_MODEL


def resolve_output_ceiling(model: str) -> Optional[int]:
    """The output-token ceiling to request for `model`: the most it allows.

    A ceiling costs nothing until it is used, and a turn that reaches it
    ends with MAX_TOKENS and fails its stage, so the right value is the
    model's maximum. LiteLLM's registry knows it for released models and
    is asked first. A Claude model it does not know gets
    CLAUDE_DEFAULT_MAX_OUTPUT_TOKENS, because for Anthropic "unset" means
    LiteLLM's own guess. Any other unknown model gets None: the request
    names no ceiling and the provider applies the model's own default.
    Whatever is sent, a model that allows less names its ceiling when it
    rejects the request, and ResilientLiteLlm retries at that ceiling.
    """
    name = str(model or "")
    try:
        import litellm
        known = litellm.get_max_tokens(name)
        if known:
            raw_ceiling = int(known)
            max_input = resolve_context_limit(name)
            if isinstance(max_input, int) and max_input > 0 and raw_ceiling >= max_input:
                quarter = max(4096, max_input // 4) if max_input > 8192 else max(1, max_input // 2)
                return min(raw_ceiling, quarter, 32768)
            return raw_ceiling
    except Exception:
        pass
    if "claude" in name.lower():
        return CLAUDE_DEFAULT_MAX_OUTPUT_TOKENS
    return None


def extract_rate_limit_detail(e: Exception) -> str:
    """Extracts a succinct summary of the rate limit reason from the exception."""
    msg = str(e)
    if "RESOURCE_EXHAUSTED" in msg:
        m = re.search(r"Quota exceeded for ([^.\s]+(?:\.[^.\s]+)*)", msg)
        if m:
            metric = m.group(1).split("/")[-1]
            return f"Quota exceeded: {metric}"
        return "RESOURCE_EXHAUSTED"
    if "tokens_per_minute" in msg:
        return "Tokens per minute limit exceeded"
    if "requests_per_minute" in msg:
        return "Requests per minute limit exceeded"
    return "Rate limit (429)"


def compute_full_jitter_delay(
    attempt: int,
    initial_delay: float = 5.0,
    max_delay: float = 60.0,
    min_offset: float = 5.0,
    backoff_factor: float = 2.0,
    retry_after: Optional[float] = None,
    max_remaining: Optional[float] = None,
) -> float:
    """Computes backoff delay using full jitter with a minimum offset."""
    upper_bound = min(max_delay, max(min_offset, initial_delay * (backoff_factor ** attempt)))
    if upper_bound <= min_offset:
        delay = min_offset
    else:
        delay = random.uniform(min_offset, upper_bound)

    if retry_after is not None and retry_after > 0:
        delay = min(max_delay, max(delay, retry_after))

    if max_remaining is not None:
        delay = min(delay, max(1.0, max_remaining))

    return delay


class MantisAuthError(RuntimeError):
    """Raised when an unrecoverable LLM authentication or token refresh failure occurs."""

    def __init__(self, message: str, original_exception: Optional[Exception] = None):
        super().__init__(message)
        self.original_exception = original_exception


# Process exit status for a MantisAuthError. Distinct from 1 (a scan that
# failed) and 2 (a budget pause) so a caller can recognize "the provider
# rejected the credentials" from the status alone. Log text is not a safe
# channel for that: the pipeline echoes file names and file contents that the
# code under audit controls, so any marker string can be forged there.
EXIT_AUTH = 4


class MantisStreamingTruncationError(RuntimeError):
    """Raised when streaming tool call arguments are truncated mid-stream by output limits or premature chunk completion."""
    pass


class MantisStreamInterruptedError(RuntimeError):
    """Raised when a resilient stream fails after at least one chunk was delivered.

    Everything before the first chunk is retried transparently: no output has been
    observed, so a fresh stream is equivalent to a slow first attempt. After that,
    a transparent retry would re-sample the model and splice two different
    completions together -- silently corrupting output the consumer has already
    processed. The wrapper therefore refuses to guess: it reports how far delivery
    got and leaves the continuation policy (re-prompt, discard, resume) to the
    caller.
    """

    def __init__(self, message: str, chunks_yielded: int = 0, original_exception: Optional[Exception] = None):
        super().__init__(message)
        self.chunks_yielded = chunks_yielded
        self.original_exception = original_exception


class MantisEmptyResponseError(RuntimeError):
    """A non-streaming turn finished with STOP and no parts: no text, no tool
    call, no error code. The model billed the prompt and said nothing.

    Left alone, ADK reports the turn as MODEL_RETURNED_NO_CONTENT, the node
    moves on with nothing, and the whole campaign is marked failed over one
    empty sample. Raised inside the model layer instead, so the turn goes
    back through the same backoff loop as a 429. The difference from a 429
    is that each attempt was a billed prompt, so the response's usage is
    metered against the run budget before this is raised: the token ceiling
    bounds the worst case, as it bounds everything else. From the second
    empty turn the request carries a nudge (EMPTY_TURN_NUDGE) instead of
    being re-sent byte for byte. Past the patience window -- or past
    ``MANTIS_LLM_EMPTY_TURN_MAX_ATTEMPTS`` empty turns on the one request,
    whichever comes first -- the stage ends: a verdict stage with its
    fail-closed verdict (see _sanitize_structured_response), any other with
    EMPTY_TURN_FINAL_TEXT as its final answer. Not an error event: the
    model's work up to that turn (findings saved, notes written) stands,
    the campaign completes, and --resume does not re-run it to draw the
    same silence again. Measured: a model that ended its turn silently
    after report_findings had its campaign marked failed and re-run on
    every resume, with the review packet already written.
    """

    def __init__(self, message: str, response: Any = None):
        super().__init__(message)
        self.response = response


# How many empty STOP turns one request may draw before the empty turn is
# passed on. The general patience window is for faults that pass (quota,
# 5xx); a request the model has answered with nothing six times in a row is
# being answered, and the answer is nothing. A calibrator with twenty
# findings and an hour of patience each would otherwise stall a run for a
# day on a prompt the model will never fill.
DEFAULT_EMPTY_TURN_MAX_ATTEMPTS = 6

#: Appended to the request (a new user message; the prefix is untouched)
#: from the second empty turn on: a model that has finished and omitted the
#: closing text answers this; one that is stuck does not, and the cap ends
#: the stage.
EMPTY_TURN_NUDGE = (
    "Your previous turn was empty. If this stage's work is complete, say so in one "
    "sentence (or give your verdict in the required form); otherwise continue with the "
    "next tool call."
)

#: The final answer of a schema-less stage whose model kept answering with
#: nothing: harness-authored, says what happened, claims nothing else.
EMPTY_TURN_FINAL_TEXT = (
    "The model ended this turn without content after repeated attempts; the stage ends "
    "here with its recorded work in place."
)


def empty_turn_final_response() -> Any:
    """The response a schema-less stage ends on at the empty-turn cap. Zero
    usage, not none: no model billed this text, and the event loop's
    estimate is for responses that carry no usage at all."""
    from google.adk.models import LlmResponse
    from google.genai import types

    return LlmResponse(
        content=types.Content(role="model", parts=[types.Part.from_text(text=EMPTY_TURN_FINAL_TEXT)]),
        finish_reason=types.FinishReason.STOP,
        usage_metadata=types.GenerateContentResponseUsageMetadata(
            prompt_token_count=0, candidates_token_count=0, total_token_count=0),
    )


def append_empty_turn_nudge(llm_request: Any) -> bool:
    """Adds EMPTY_TURN_NUDGE to the request as a new user message, once.
    Append-only, so a prefix-bound model accepts it. False if it could not."""
    try:
        from google.genai import types

        contents = getattr(llm_request, "contents", None)
        if contents is None:
            return False
        for content in contents:
            for part in getattr(content, "parts", None) or []:
                if getattr(part, "text", None) == EMPTY_TURN_NUDGE:
                    return False
        contents.append(types.Content(role="user", parts=[types.Part.from_text(text=EMPTY_TURN_NUDGE)]))
        return True
    except Exception:
        return False


def structured_llm_request(prompt: str, system_instruction: str, schema_cls: Any) -> Any:
    """A one-shot request whose answer is a ``set_model_response`` call.

    The tool is registered with ``LlmRequest.append_tools``, which fills both
    ``config.tools`` (a ``types.Tool`` carrying the declaration) and
    ``tools_dict``. Putting the ``SetModelResponseTool`` straight into
    ``GenerateContentConfig(tools=[...])`` looks the same and is not: ADK's
    LiteLlm adapter forwards only ``types.Tool`` instances and drops anything
    else without a word, so the model was being told to call a tool it had
    never been given. Some models then answer in prose that the caller can
    still parse; some answer with nothing, and an empty turn is retried.
    """
    from google.adk.models.llm_request import LlmRequest
    from google.adk.tools.set_model_response_tool import SetModelResponseTool
    from google.genai import types

    req = LlmRequest(
        contents=[types.Content(parts=[types.Part.from_text(text=prompt)], role="user")],
        config=types.GenerateContentConfig(system_instruction=system_instruction),
    )
    req.append_tools([SetModelResponseTool(schema_cls)])
    return req


def response_has_meaningful_content(response: Any) -> bool:
    """ADK's own rule for whether a response says anything: a function call
    or result, code, data, or text that is neither a thought nor whitespace.
    A turn of thought summaries with no answer after them has none. Falls
    back to "any part at all" if ADK's helper is unavailable."""
    try:
        from google.adk.flows.llm_flows.core._finalizer import has_meaningful_content
        return bool(has_meaningful_content(response))
    except Exception:
        content = getattr(response, "content", None)
        return bool(content and getattr(content, "parts", None))


def is_empty_stop_response(response: Any) -> bool:
    """The condition ADK flags as MODEL_RETURNED_NO_CONTENT, checked on the
    response before ADK sees it: a final STOP response with no meaningful
    content -- no parts, or only thought or whitespace parts, which is what
    a streamed turn of reasoning that never reaches an answer aggregates
    to. Partial chunks are never judged; a finish-only chunk after streamed
    content is the caller's business (see ResilientLiteLlm)."""
    if getattr(response, "partial", False) or getattr(response, "error_code", None):
        return False
    from google.genai import types as genai_types

    if getattr(response, "finish_reason", None) not in (genai_types.FinishReason.STOP, "STOP"):
        return False
    return not response_has_meaningful_content(response)


def meter_response_usage(response: Any) -> None:
    """Charges a response's usage to the run budget from inside the model
    layer. The pipeline meters from events, and a response the model layer
    swallows never becomes one; without this a retried empty turn would be
    free as far as the budget could tell. A budget ceiling crossed here
    raises BudgetExceededError, which is the point."""
    from core.context import current_run_context

    ctx = current_run_context.get()
    controller = getattr(ctx, "budget_controller", None) if ctx else None
    usage = getattr(response, "usage_metadata", None)
    total = int(getattr(usage, "total_token_count", 0) or 0) if usage else 0
    if controller is None or total <= 0:
        return
    cached = int(getattr(usage, "cached_content_token_count", 0) or 0)
    # The weight of a cached token is the run budget's to decide (a CI run
    # counts every token at full price); this layer only reports the counts.
    controller.record_tokens(
        total, cached_count=cached,
        prompt_count=int(getattr(usage, "prompt_token_count", 0) or 0),
        output_count=int(getattr(usage, "candidates_token_count", 0) or 0))


def _observe(name: str, n: int = 1) -> None:
    """Counts a request-level event on the run's spend report (core.budget)."""
    try:
        from core.budget import observe
        observe(name, n)
    except Exception:
        pass


def context_edits_applied(response: Any) -> tuple[int, int]:
    """(edits applied, input tokens cleared) that an Anthropic response
    reports under `context_management.applied_edits`, which LiteLLM keeps in
    the message's provider_specific_fields. (0, 0) when the response says
    nothing: no editing was requested, the trigger was not reached, or the
    provider does not report it."""
    edits = 0
    cleared = 0
    try:
        choices = getattr(response, "choices", None) or []
        message = getattr(choices[0], "message", None) if choices else None
        fields = getattr(message, "provider_specific_fields", None) or {}
        if not isinstance(fields, Mapping) or not fields:
            hidden = getattr(response, "_hidden_params", None) or {}
            fields = hidden.get("provider_specific_fields") or {} if isinstance(hidden, Mapping) else {}
        cm = fields.get("context_management") if isinstance(fields, Mapping) else None
        applied = cm.get("applied_edits") if isinstance(cm, Mapping) else None
        for edit in applied or []:
            if not isinstance(edit, Mapping):
                continue
            edits += 1
            cleared += int(edit.get("cleared_input_tokens") or 0)
    except Exception:
        return 0, 0
    return edits, cleared


def _observe_context_edits(response: Any) -> None:
    edits, cleared = context_edits_applied(response)
    if edits:
        _observe("context_edits_applied", edits)
    if cleared:
        _observe("context_edit_cleared_tokens", cleared)


class ContextBudgetExceededError(RuntimeError):
    """Raised before dispatch when a request cannot possibly fit the model's context window.

    Sending it anyway costs a full upload of the payload, a provider-side rejection, and --
    because the node retry layer cannot tell a deterministic overflow from a transient fault
    -- two more identical uploads of the same doomed request. The failure is deterministic in
    the request itself, so the only useful thing to do with it is refuse early and say which
    message was too big.
    """

    def __init__(self, message: str, estimated_tokens: int = 0, limit: int = 0):
        super().__init__(message)
        self.estimated_tokens = estimated_tokens
        self.limit = limit


# Exceptions whose outcome is fully determined by the request, so re-running the node with
# the identical request can only reproduce them. ADK's node retry cannot distinguish these
# from transient faults and will burn the full attempt budget on them.
#
# Matched by class name because several of these types live in third-party packages that may
# not be importable in every deployment, and a missing import must not silently disable the
# rule. Note this is intentionally NOT the same list as the log-suppression filter below:
# retrying an error and reporting it are separate decisions, and a context overflow must stay
# loudly visible precisely because the operator is the one who has to act on it.
_NON_RETRYABLE_EXC_NAMES = (
    "BudgetExceededError",
    "LlmCallsLimitExceededError",
    "MantisAuthError",
    "ContextBudgetExceededError",
    "ContextWindowExceededError",
    # litellm 4xx families whose outcome is fully determined by the request;
    # re-running the identical request can only reproduce the failure.
    "NotFoundError",
    "BadRequestError",
    "AuthenticationError",
    "PermissionDeniedError",
    "UnprocessableEntityError",
    "ContentPolicyViolationError",
    "UnsupportedParamsError",
)


# Characters per token. Deliberately a constant rather than a real tokenizer: tokenizing a
# multi-megabyte payload to discover that it is multi-megabyte is self-defeating, and the
# guard only needs to separate "plausibly fits" from "an order of magnitude over". Real code
# runs denser than 4 chars/token, so this UNDER-estimates and the guard errs toward letting
# a borderline request through to the provider -- the fail-open direction, which matters
# because this is a reliability control, not a security boundary.
_CHARS_PER_TOKEN = 4

# Fraction of the window a request may occupy before it is refused. Below 1.0 because the
# estimate is approximate and the response needs room too; a request at 95% of the window
# has no space left to answer in.
_CONTEXT_BUDGET_RATIO = 0.9


def _message_char_len(message: Any) -> int:
    """Total character length of one chat message, including structured content parts."""
    if isinstance(message, str):
        return len(message)
    if not isinstance(message, Mapping):
        return len(str(message))

    total = 0
    for key in ("role", "name", "tool_call_id"):
        value = message.get(key)
        if isinstance(value, str):
            total += len(value)

    content = message.get("content")
    if isinstance(content, str):
        total += len(content)
    elif isinstance(content, (list, tuple)):
        for part in content:
            if isinstance(part, Mapping):
                text = part.get("text")
                total += len(text) if isinstance(text, str) else len(str(part))
            else:
                total += len(str(part))
    elif content is not None:
        total += len(str(content))

    tool_calls = message.get("tool_calls")
    if isinstance(tool_calls, (list, tuple)):
        for call in tool_calls:
            total += len(str(call))

    return total


def estimate_prompt_tokens(messages: Any, tools: Any = None) -> int:
    """Cheap upper-bound-ish token estimate for a request, without tokenizing it."""
    total_chars = 0
    if isinstance(messages, (list, tuple)):
        for message in messages:
            total_chars += _message_char_len(message)
    elif messages is not None:
        total_chars += _message_char_len(messages)

    if tools:
        try:
            total_chars += len(json.dumps(tools, default=str))
        except (TypeError, ValueError):
            total_chars += len(str(tools))

    return total_chars // _CHARS_PER_TOKEN


def resolve_context_limit(model: Any) -> Optional[int]:
    """Returns the model's max input tokens, or None when it cannot be determined.

    Fails open on purpose. An unknown window means we cannot prove the request is doomed,
    and refusing a request that would have succeeded is a worse failure than the one this
    guard exists to prevent.
    """
    try:
        import litellm
    except Exception:
        return None

    model_name = str(model)
    # Only ever input limits. litellm's get_max_tokens()/"max_tokens" report the max OUTPUT
    # tokens -- often a couple of orders of magnitude smaller than the context window -- so
    # using either as an input budget would refuse ordinary requests.
    fn = getattr(litellm, "get_max_input_tokens", None)
    if fn is not None:
        try:
            value = fn(model_name)
        except Exception:
            value = None
        if isinstance(value, int) and value > 0:
            return value

    # Newer Vertex/provider-prefixed Claude revisions (e.g. vertex_ai/claude-opus-5-5)
    # may lag behind LiteLLM's local model_cost map, causing get_model_info() to either
    # raise or fall back to the generic 200k Claude default even though the bare or
    # family-major entry (e.g. claude-opus-5) is already registered at 1M tokens.
    model_cost = getattr(litellm, "model_cost", None)
    if is_claude_model(model_name) and isinstance(model_cost, Mapping) and model_name not in model_cost:
        bare = model_name.rsplit("/", 1)[-1].split("@", 1)[0].strip().lower()
        candidates = [bare]
        m_fam = re.match(r"^(claude-[a-z]+-\d+)(?:-\d+)+$", bare)
        if m_fam:
            candidates.append(m_fam.group(1))
        for cand in candidates:
            entry = model_cost.get(cand)
            if isinstance(entry, Mapping):
                val = entry.get("max_input_tokens")
                if isinstance(val, int) and val > 0:
                    return val

    try:
        info = litellm.get_model_info(model_name)
    except Exception:
        return None
    if isinstance(info, Mapping):
        value = info.get("max_input_tokens")
        if isinstance(value, int) and value > 0:
            return value
    return None


def _largest_message_summary(messages: Any) -> str:
    """Names the biggest contributor to an oversized request so the failure is actionable."""
    if not isinstance(messages, (list, tuple)) or not messages:
        return ""
    sizes = [(_message_char_len(m), i, m) for i, m in enumerate(messages)]
    chars, index, message = max(sizes, key=lambda item: item[0])
    role = message.get("role", "?") if isinstance(message, Mapping) else "?"
    return (
        f" Largest contributor: message {index} (role={role}) at {chars:,} characters "
        f"(~{chars // _CHARS_PER_TOKEN:,} tokens)."
    )


# Share of the model's input window that ONE tool response may occupy. The window-relative
# request guard below refuses a request that no longer fits; this is the control that keeps
# a single tool response from being the reason it does not. A quarter leaves room for the
# instruction, the conversation so far, a few more tool responses and the answer. Measured
# failure this exists for: a 1 MiB read_file (~262k tokens) and a 975k-char recorded summary
# each delivered whole into a 272k-token window, which refused the request on the spot.
TOOL_RESPONSE_WINDOW_FRACTION = 0.25

# No model-derived cap goes below this many characters (~10k tokens). The verdict stages
# read tool output looking for a bounds check; a cut tight enough to hide one reads as
# "the check is missing" (see tools/research_tools.MAX_READ_SIZE).
MIN_TOOL_RESPONSE_CHARS = 40_000

_TOOL_RESPONSE_CAP_ENV = "MANTIS_MAX_TOOL_RESPONSE_CHARS"


def resolve_tool_response_char_cap(model: Any) -> Optional[int]:
    """Characters one tool response may carry into `model`'s context, or None for no cap.

    Derived from the model's input window (``TOOL_RESPONSE_WINDOW_FRACTION`` of it, in
    characters at the guard's chars-per-token estimate) and from the operator's
    per-request input cap when that is tighter. ``MANTIS_MAX_TOOL_RESPONSE_CHARS`` is an
    absolute operator override that applies whether or not the model is known. An
    unknown model with no override means no cap -- the request guard still refuses what
    cannot fit, and the per-tool byte limits still apply -- which is the fail-open
    direction every control in this file takes.
    """
    raw = str(os.environ.get(_TOOL_RESPONSE_CAP_ENV, "") or "").strip()
    if raw:
        try:
            override = int(raw)
        except ValueError:
            override = 0
        if override > 0:
            return override

    limits = [l for l in (resolve_context_limit(model), resolve_input_token_cap()) if l]
    if not limits:
        return None
    tokens = int(min(limits) * TOOL_RESPONSE_WINDOW_FRACTION)
    return max(tokens * _CHARS_PER_TOKEN, MIN_TOOL_RESPONSE_CHARS)


# --- Anthropic context editing -----------------------------------------------
#
# Server-side clearing of a conversation's older tool results (Anthropic's
# `context_management`, edit `clear_tool_uses`). The provider applies it before
# the model reads the request, so a long stage stays inside the window while
# the request we send remains append-only -- the one form of history
# management that models binding their reasoning to its prefix accept. The
# cleared results are replaced by a placeholder the model can see, and the
# edit is reported back in the response. Measured on Vertex AI: a
# 210,105-token request was served at 529 tokens with the two tool results
# reported cleared. Claude models only: the parameter is Anthropic's, on any
# route (vertex_ai/, anthropic/, bedrock/).
#
# The trigger sits below the node context ceiling (0.8) so the provider acts
# first and the ceiling is the backstop; `clear_at_least` is sized so one edit
# buys a long stretch of further work (each edit invalidates the prompt cache
# from the edit point); `keep` leaves the newest results verbatim.
CONTEXT_EDITING_TRIGGER_RATIO = 0.5
CONTEXT_EDITING_KEEP_TOOL_USES = 5
CONTEXT_EDITING_CLEAR_RATIO = 0.2
CONTEXT_EDITING_EDIT_TYPE = "clear_tool_uses_20250919"
_CONTEXT_EDITING_ENV = "MANTIS_CONTEXT_EDITING"
_CONTEXT_EDITING_TRIGGER_CAP_ENV = "MANTIS_CONTEXT_EDITING_TRIGGER_TOKENS"
_OFF_WORDS = frozenset({"off", "false", "0", "no", "disabled"})


def is_claude_model(model: Any) -> bool:
    """A Claude model on any provider route."""
    return "claude" in str(model or "").lower()


def supports_server_clear_tool_uses(model: Any) -> bool:
    """True only on routes where the provider natively applies Anthropic's
    `clear_tool_uses_20250919` server-side edit (direct `anthropic/` and
    `vertex_ai/claude*`). Routes like `bedrock/` Converse or `openrouter/`
    drop or ignore `clear_tool_uses_20250919`, so they use client-side context
    editing instead."""
    raw = str(model or "").strip().lower()
    if not raw or not is_claude_model(raw):
        return False
    if raw.startswith("claude-"):
        return True
    if raw.startswith("anthropic/"):
        return True
    if raw.startswith("vertex_ai/") and "openai/" not in raw:
        return True
    return False


def _context_editing_trigger_cap(config: Optional[Mapping[str, Any]]) -> Optional[int]:
    env_raw = str(os.environ.get(_CONTEXT_EDITING_TRIGGER_CAP_ENV, "") or "").strip()
    if env_raw:
        try:
            env_cap = int(env_raw)
            if env_cap > 0:
                return env_cap
        except ValueError:
            pass
    if isinstance(config, Mapping):
        cfg_raw = config.get("context_editing_trigger_tokens")
        if cfg_raw is not None:
            try:
                cfg_cap = int(cfg_raw)
                if cfg_cap > 0:
                    return cfg_cap
            except (TypeError, ValueError):
                pass
    return None


def _context_editing_off(config: Optional[dict]) -> bool:
    if str(os.environ.get(_CONTEXT_EDITING_ENV, "") or "").strip().lower() in _OFF_WORDS:
        return True
    return isinstance(config, dict) and str(config.get("context_editing", "auto") or "").strip().lower() in _OFF_WORDS


def _effective_context_window(model: Any) -> Optional[int]:
    """Effective context window in tokens for `model`, or None when unknown.

    Uses the tighter of the model's known input limit and the operator's
    per-request cap (`MANTIS_MAX_INPUT_TOKENS`) so an unrecognized custom or
    on-prem endpoint with `MANTIS_MAX_INPUT_TOKENS` set still activates
    50%-window context editing, and a large-window model served behind a
    smaller server `--max-model-len` triggers editing before overflowing.
    """
    if not str(model or "").strip():
        return None
    limits = [l for l in (resolve_context_limit(model), resolve_input_token_cap()) if l]
    return min(limits) if limits else None


def anthropic_context_editing(model: Any, config: Optional[dict] = None) -> Optional[dict]:
    """The `context_management` parameter for `model`, or None when it must not
    be sent: not a Claude model, switched off (config `context_editing: off`
    or MANTIS_CONTEXT_EDITING=off), or a window we cannot size against."""
    if not is_claude_model(model):
        return None
    if _context_editing_off(config):
        return None
    limit = _effective_context_window(model)
    if not limit:
        return None
    trigger = int(limit * CONTEXT_EDITING_TRIGGER_RATIO)
    clear_at_least = int(limit * CONTEXT_EDITING_CLEAR_RATIO)
    cap = _context_editing_trigger_cap(config)
    if cap is not None and cap < trigger:
        trigger = cap
        clear_at_least = min(
            clear_at_least,
            max(1, int(cap * (CONTEXT_EDITING_CLEAR_RATIO / CONTEXT_EDITING_TRIGGER_RATIO))),
        )
    return {"edits": [{
        "type": CONTEXT_EDITING_EDIT_TYPE,
        "trigger": {"type": "input_tokens", "value": trigger},
        "keep": {"type": "tool_uses", "value": CONTEXT_EDITING_KEEP_TOOL_USES},
        "clear_at_least": {"type": "input_tokens", "value": clear_at_least},
    }]}


def client_context_editing(model: Any, config: Optional[dict] = None) -> Optional[dict]:
    """The harness-side counterpart of `anthropic_context_editing` for models
    whose route does not run server-side `clear_tool_uses_20250919`: the same
    trigger, keep and clear-at-least, applied by the harness to the request
    before dispatch (core.graph_loader). `{"trigger_tokens", "keep",
    "clear_at_least_tokens"}`, or None when the provider performs server-side
    clearing, when switched off, or when no window is known."""
    if supports_server_clear_tool_uses(model):
        return None
    if _context_editing_off(config):
        return None
    limit = _effective_context_window(model)
    if not limit:
        return None
    trigger = int(limit * CONTEXT_EDITING_TRIGGER_RATIO)
    clear_at_least = int(limit * CONTEXT_EDITING_CLEAR_RATIO)
    cap = _context_editing_trigger_cap(config)
    if cap is not None and cap < trigger:
        trigger = cap
        clear_at_least = min(
            clear_at_least,
            max(1, int(cap * (CONTEXT_EDITING_CLEAR_RATIO / CONTEXT_EDITING_TRIGGER_RATIO))),
        )
    return {
        "trigger_tokens": trigger,
        "keep": CONTEXT_EDITING_KEEP_TOOL_USES,
        "clear_at_least_tokens": clear_at_least,
    }


def context_editing_keeps(context_management: Any) -> Optional[int]:
    """How many newest tool results a `clear_tool_uses` edit keeps verbatim, or
    None when the parameter carries no such edit. What the client-side
    estimates (request guard, node context ceiling) treat as still present."""
    if not isinstance(context_management, Mapping):
        return None
    for edit in context_management.get("edits") or []:
        if isinstance(edit, Mapping) and str(edit.get("type", "")).startswith("clear_tool_uses"):
            keep = edit.get("keep") or {}
            if isinstance(keep, Mapping) and keep.get("type") == "tool_uses":
                try:
                    return max(0, int(keep.get("value", 0)))
                except (TypeError, ValueError):
                    return 0
            return 0
    return None


_CLEARED_TOOL_RESULT = "[cleared by context editing]"


def _messages_as_the_provider_sees_them(messages: Any, keep: int) -> Any:
    """The chat messages with every tool result but the newest `keep` replaced
    by the provider's placeholder -- the shape the model reads once a
    clear_tool_uses edit has fired. Tool calls themselves are untouched."""
    if not isinstance(messages, (list, tuple)):
        return messages
    tool_indexes = [i for i, m in enumerate(messages) if isinstance(m, Mapping) and m.get("role") == "tool"]
    cleared = set(tool_indexes[:-keep] if keep else tool_indexes)
    if not cleared:
        return messages
    return [
        ({**m, "content": _CLEARED_TOOL_RESULT} if i in cleared else m)
        for i, m in enumerate(messages)
    ]


def resolve_input_token_cap() -> Optional[int]:
    """An absolute per-request input ceiling from MANTIS_MAX_INPUT_TOKENS, or None.

    The window-relative guard below bounds a request by the MODEL's limit, which is
    whatever the model happens to have (a million tokens, say) and nothing at all for a
    model litellm does not know. This cap is the OPERATOR's limit: a number of tokens
    one request may carry regardless of model, so the cost of one call has a ceiling
    that does not move when the model changes and does not vanish behind a gateway.
    Unset, empty, zero, or unparsable means no cap, which is the previous behaviour.
    """
    raw = str(os.environ.get("MANTIS_MAX_INPUT_TOKENS", "") or "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def enforce_context_budget(model: Any, messages: Any, tools: Any = None,
                           context_management: Any = None) -> None:
    """Refuses a request that cannot fit the model's context window, or that exceeds the
    operator's per-request input cap, before dispatching it.

    `context_management` is the request's Anthropic context-editing parameter, when
    any: the provider clears older tool results before the model reads the request,
    so the estimate counts those as cleared too -- otherwise this would refuse a
    request the provider was about to make fit."""
    limit = resolve_context_limit(model)
    cap = resolve_input_token_cap()
    if not limit and not cap:
        return

    keep = context_editing_keeps(context_management)
    if keep is not None:
        messages = _messages_as_the_provider_sees_them(messages, keep)
    estimated = estimate_prompt_tokens(messages, tools)
    window_budget = int(limit * _CONTEXT_BUDGET_RATIO) if limit else None
    budget = min(b for b in (window_budget, cap) if b is not None)
    if estimated <= budget:
        return

    capped = cap is not None and (window_budget is None or cap <= window_budget)
    if capped:
        reason = (f"Request to '{model}' exceeds the per-request input cap: estimated "
                  f"~{estimated:,} input tokens against MANTIS_MAX_INPUT_TOKENS={cap:,}.")
    else:
        reason = (f"Request to '{model}' is too large for its context window: estimated "
                  f"~{estimated:,} input tokens against a {limit:,}-token window "
                  f"({estimated / limit:.1f}x the window, budget {budget:,}).")
    raise ContextBudgetExceededError(
        reason
        + f"{_largest_message_summary(messages)}"
        " Refused before dispatch; retrying the identical request cannot succeed. "
        "Narrow the tool output feeding this node (for example, pass a 'directory' to "
        "list_files or a smaller range to read_file).",
        estimated_tokens=estimated,
        limit=cap if capped else limit,
    )


def is_auth_error(e: Optional[Exception]) -> bool:
    """Detects whether an exception represents an authentication or token refresh failure."""
    if e is None:
        return False
    if isinstance(e, MantisAuthError):
        return True

    # Check known exception class names
    exc_cls_name = getattr(getattr(e, "__class__", None), "__name__", "")
    if exc_cls_name in (
        "RefreshError",
        "DefaultCredentialsError",
        "ReauthError",
        "ReauthFailError",
        "ReauthSamlChallengeFailError",
        "AuthenticationError",
    ):
        return True

    # Check known exception classes
    auth_classes = []
    try:
        import google.auth.exceptions
        for name in (
            "RefreshError",
            "DefaultCredentialsError",
            "ReauthFailError",
            "ReauthSamlChallengeFailError",
            "OAuthError",
            "UserAccessTokenError",
        ):
            cls = getattr(google.auth.exceptions, name, None)
            if cls is not None and isinstance(cls, type):
                auth_classes.append(cls)
    except Exception:
        pass

    try:
        import litellm
        for name in ("AuthenticationError",):
            cls = getattr(litellm, name, None) or getattr(getattr(litellm, "exceptions", None), name, None)
            if cls is not None and isinstance(cls, type):
                auth_classes.append(cls)
    except Exception:
        pass

    valid_classes = tuple(c for c in auth_classes if isinstance(c, type))
    if valid_classes and isinstance(e, valid_classes):
        return True

    status = getattr(e, "status_code", None) or getattr(e, "code", None)
    if status == 401:
        return True
    resp = getattr(e, "response", None)
    if resp and getattr(resp, "status_code", None) == 401:
        return True

    curr = e
    while curr is not None:
        msg = str(curr).lower()
        if any(
            phrase in msg
            for phrase in (
                "reauthentication is needed",
                "gcloud auth application-default login",
                "invalid_grant",
                "your default credentials were not found",
                "could not automatically determine credentials",
                "reauthentication required",
                "reauthentication challenge",
                "authenticationerror",
                "credentials are expired",
                "credentials expired",
                "failed to retrieve auth token",
                "invalid api key",
                "incorrect api key",
                "unauthenticated",
            )
        ):
            return True
        curr = getattr(curr, "__cause__", None) or getattr(curr, "__context__", None)

    return False


def format_auth_error_message(e: Exception, model: str = "") -> str:
    """Formats an informative, clean authentication error banner without tracebacks."""
    err_text = str(e).strip()
    if err_text.startswith("=" * 10) and "[AUTHENTICATION ERROR]" in err_text:
        return err_text
    cause_msg = ""
    curr = e
    while curr is not None:
        c_str = str(curr).strip()
        if c_str and not c_str.startswith("Traceback") and not c_str.startswith("PIPELINE"):
            cause_msg = c_str
        curr = getattr(curr, "__cause__", None) or getattr(curr, "__context__", None)

    cause_clean = cause_msg or err_text
    if "AuthenticationError:" in cause_clean:
        cause_clean = cause_clean.split("AuthenticationError:")[-1].strip()

    model_label = f" for '{model}'" if model else ""
    lines = [
        "=" * 80,
        f" ❌ [AUTHENTICATION ERROR] Cloud / LLM Authentication Failed{model_label}",
        "=" * 80,
        f"  • Cause: {cause_clean}",
    ]

    is_gcp = any(
        k in cause_clean.lower() or k in model.lower()
        for k in ("gcloud", "google", "vertex", "gemini", "adc", "application-default", "refresh_token", "rapt")
    ) or not model or model.startswith("vertex_ai/") or model.startswith("gemini/")

    is_anthropic = "anthropic" in model.lower() or "anthropic" in cause_clean.lower()
    is_openai = "openai" in model.lower() or "openai" in cause_clean.lower()

    if is_gcp:
        lines.extend([
            "  • If using Vertex AI with personal Application Default Credentials (ADC):",
            "      gcloud auth application-default login",
            "  • Or if using a Google Cloud service account key:",
            '      export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service_account_key.json"',
        ])
    if is_anthropic:
        lines.extend([
            "  • If using Anthropic API directly:",
            '      export ANTHROPIC_API_KEY="your-anthropic-api-key"',
        ])
    if is_openai:
        lines.extend([
            "  • If using OpenAI API directly:",
            '      export OPENAI_API_KEY="your-openai-api-key"',
        ])

    lines.append("=" * 80)
    return "\n".join(lines)


def clear_vertex_credential_caches() -> None:
    """Clears cached credentials across all LiteLLM Vertex AI handlers to force token reload."""
    try:
        import gc
        from litellm.llms.vertex_ai.vertex_llm_base import VertexBase

        for obj in gc.get_objects():
            if isinstance(obj, VertexBase):
                mapping = getattr(obj, "_credentials_project_mapping", None)
                if isinstance(mapping, dict):
                    mapping.clear()
    except Exception:
        pass


def is_token_refreshable_auth_error(e: Exception) -> bool:
    """Checks if an auth error is due to an expired access token that can be refreshed automatically."""
    curr = e
    while curr is not None:
        msg = str(curr).lower()
        if any(
            phrase in msg
            for phrase in (
                "reauthentication is needed",
                "gcloud auth application-default login",
                "invalid_grant",
                "your default credentials were not found",
                "could not automatically determine credentials",
                "invalid api key",
                "incorrect api key",
            )
        ):
            return False
        curr = getattr(curr, "__cause__", None) or getattr(curr, "__context__", None)

    status = getattr(e, "status_code", None) or getattr(e, "code", None)
    if status == 401:
        return True
    resp = getattr(e, "response", None)
    if resp and getattr(resp, "status_code", None) == 401:
        return True

    curr = e
    while curr is not None:
        msg = str(curr).lower()
        if any(
            phrase in msg
            for phrase in (
                "credentials are expired",
                "credentials expired",
                "unauthenticated",
                "401",
                "token has expired",
                "access token expired",
            )
        ):
            return True
        curr = getattr(curr, "__cause__", None) or getattr(curr, "__context__", None)

    return False


def try_refresh_auth() -> bool:
    """Attempts to refresh Application Default Credentials and clear LiteLLM token caches."""
    clear_vertex_credential_caches()
    try:
        import google.auth
        import google.auth.transport.requests

        creds, _ = google.auth.default()
        creds.refresh(google.auth.transport.requests.Request())
        return getattr(creds, "valid", False)
    except Exception:
        return False


class ExpectedErrorLoggingFilter(logging.Filter):
    """Filters out noisy, multi-frame tracebacks for expected operational conditions

    (such as MantisAuthError or BudgetExceededError), while strictly preserving full
    tracebacks for unexpected bugs or runtime exceptions.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if record.exc_info:
            exc_val = record.exc_info[1]
            if exc_val is not None:
                if is_auth_error(exc_val) or isinstance(exc_val, MantisAuthError):
                    return False
                exc_cls_name = getattr(getattr(exc_val, "__class__", None), "__name__", "")
                if exc_cls_name in (
                    "BudgetExceededError",
                    "LlmCallsLimitExceededError",
                    "MantisAuthError",
                ):
                    return False
                cause = getattr(exc_val, "__cause__", None) or getattr(exc_val, "__context__", None)
                if cause is not None and (
                    is_auth_error(cause)
                    or isinstance(cause, MantisAuthError)
                    or getattr(getattr(cause, "__class__", None), "__name__", "") in (
                        "BudgetExceededError",
                        "LlmCallsLimitExceededError",
                        "MantisAuthError",
                    )
                ):
                    return False

        # Also suppress messages directly matching authentication failure signatures
        msg = record.getMessage() if hasattr(record, "getMessage") else str(record.msg)
        if any(
            pattern in msg
            for pattern in (
                "Failed to load vertex credentials",
                "Reauthentication is needed",
                "gcloud auth application-default login",
            )
        ):
            return False

        return True


_expected_error_filter = ExpectedErrorLoggingFilter()

if getattr(logging, "lastResort", None):
    logging.lastResort.addFilter(_expected_error_filter)

_orig_logger_add_handler = logging.Logger.addHandler


def _filtered_add_handler(self: logging.Logger, h: logging.Handler) -> None:
    h.addFilter(_expected_error_filter)
    return _orig_logger_add_handler(self, h)


logging.Logger.addHandler = _filtered_add_handler


def apply_expected_error_filter() -> None:
    """Attaches _expected_error_filter to root, all existing loggers, and LiteLLM/ADK handlers."""
    root_lg = logging.getLogger()
    root_lg.addFilter(_expected_error_filter)
    for h in root_lg.handlers:
        h.addFilter(_expected_error_filter)

    known_loggers = [
        "",
        "LiteLLM",
        "litellm",
        "litellm._logging",
        "google_adk",
        "google_adk.google.adk.runners",
        "google.adk",
        "google.adk.runners",
        "google.adk.workflow._node_runner",
        "google_adk.google.adk.workflow._node_runner",
        "google.adk.workflow",
        "google_adk.google.adk.workflow",
        "google_adk.google.adk.flows.llm_flows.base_llm_flow",
        "google.adk.flows.llm_flows.base_llm_flow",
    ]
    for name in known_loggers:
        lg = logging.getLogger(name)
        lg.addFilter(_expected_error_filter)
        for h in lg.handlers:
            h.addFilter(_expected_error_filter)

    for lg in list(logging.Logger.manager.loggerDict.values()):
        if isinstance(lg, logging.Logger):
            lg.addFilter(_expected_error_filter)
            for h in lg.handlers:
                h.addFilter(_expected_error_filter)

    try:
        import litellm
        from litellm._logging import verbose_logger
        verbose_logger.addFilter(_expected_error_filter)
        for h in verbose_logger.handlers:
            h.addFilter(_expected_error_filter)
    except Exception:
        pass


apply_expected_error_filter()

# Disable ADK node retry on unrecoverable authentication errors or budget pauses
try:
    import google.adk.workflow.utils._retry_utils as _adk_retry_utils
    _orig_adk_should_retry_node = _adk_retry_utils._should_retry_node

    def _non_retryable_should_retry_node(
        exception: BaseException,
        retry_config: Any,
        node_state: Any,
    ) -> bool:
        if is_auth_error(exception) or isinstance(exception, MantisAuthError):
            return False
        exc_cls_name = getattr(getattr(exception, "__class__", None), "__name__", "")
        # A stage continuing in a fresh context (core.graph_loader
        # .NodeContextExhausted): retried for as long as the stage's own
        # continuation budget says so, whatever the node's attempt count --
        # the continuation IS the recovery, not a retry of a failure. The
        # exception carries the verdict so this module need not import the
        # graph loader.
        if exc_cls_name == "NodeContextExhausted":
            return retry_config is not None and bool(getattr(exception, "retryable", False))
        if exc_cls_name in _NON_RETRYABLE_EXC_NAMES:
            return False
        cause = getattr(exception, "__cause__", None) or getattr(exception, "__context__", None)
        if cause is not None and (
            is_auth_error(cause)
            or isinstance(cause, MantisAuthError)
            or getattr(getattr(cause, "__class__", None), "__name__", "") in _NON_RETRYABLE_EXC_NAMES
        ):
            return False
        return _orig_adk_should_retry_node(exception, retry_config, node_state)

    _adk_retry_utils._should_retry_node = _non_retryable_should_retry_node
except Exception:
    pass


# --- Continuation helpers (pure over LiteLLM response objects) -----------------------------

# A turn is continued until the provider ends it: with the answer, or with
# MAX_TOKENS when the request's own output ceiling -- cumulative across
# segments, set by the operator -- is spent. Ending it sooner throws every
# segment's work away with nothing to show, so there is no cap of this
# module's own by default. Two bounds remain. The run's budget (tokens,
# wall clock) is consulted before each segment, since a turn of many
# segments spends while the pipeline meters only whole turns; a run that
# could not afford the next segment ends the turn where it is and pauses on
# the usual path, resumable. And MANTIS_MAX_CONTINUATIONS lets an operator
# cap the segments of one turn anyway (0, the default, is no cap).
DEFAULT_MAX_CONTINUATIONS = 0


def max_continuations() -> int:
    """The operator's cap on continuations per turn; 0 for none."""
    try:
        return max(0, int(os.environ.get("MANTIS_MAX_CONTINUATIONS", str(DEFAULT_MAX_CONTINUATIONS))))
    except ValueError:
        return DEFAULT_MAX_CONTINUATIONS


def continuation_allowed(segments_so_far: int, turn_usage: Optional[dict]) -> "tuple[bool, str]":
    """Whether the turn may open another segment: (True, "") or (False, why).

    `segments_so_far` counts the segments already run; `turn_usage` is their
    summed usage (prompt/completion/total/cached). The run's budget is read
    from the current RunContext's controller, with the turn's own spend so
    far added to what the controller has already metered, since the
    pipeline meters a turn only when it ends."""
    cap = max_continuations()
    if cap and segments_so_far > cap:
        return False, f"MANTIS_MAX_CONTINUATIONS={cap} reached"
    try:
        from core.context import current_run_context

        ctx = current_run_context.get()
        controller = getattr(ctx, "budget_controller", None) if ctx is not None else None
        if controller is None:
            return True, ""
        cfg = getattr(controller, "config", None)
        max_tokens = int(getattr(cfg, "max_tokens", 0) or 0)
        if max_tokens > 0 and turn_usage:
            discount = float(getattr(cfg, "cache_discount", 0.1) or 0.0)
            total = int(turn_usage.get("total_tokens", 0) or 0)
            cached = int(turn_usage.get("cached_tokens", 0) or 0)
            turn_effective = total - cached + int(cached * discount)
            metered = int(getattr(controller, "accumulated_tokens", 0) or 0)
            if metered + turn_effective >= max_tokens:
                return False, (f"the run's token budget would be exceeded "
                               f"({metered + turn_effective:,} of {max_tokens:,} with this turn)")
        max_seconds = float(getattr(cfg, "max_wall_clock_seconds", 0) or 0)
        if max_seconds > 0:
            elapsed = float(getattr(controller, "elapsed_seconds", 0) or 0)
            if elapsed >= max_seconds:
                return False, f"the run's time budget is spent ({elapsed:.0f}s of {max_seconds:.0f}s)"
    except Exception:
        return True, ""
    return True, ""


def continuation_token_of(response_or_chunk: Any) -> Optional[str]:
    """The provider's continuation token on a response or stream chunk whose
    turn stopped mid-thought: present only when the raw finish reason was
    CONTINUATION (a server-side segment end). A MAX_TOKENS stop also carries
    a token, but means the request's own output ceiling is spent, and
    sending the token again would stop the same way at once."""
    try:
        choices = getattr(response_or_chunk, "choices", None) or []
        for choice in choices:
            holder = getattr(choice, "message", None) or getattr(choice, "delta", None)
            fields = getattr(holder, "provider_specific_fields", None) or {}
            if not isinstance(fields, dict):
                continue
            token = fields.get(CONTINUATION_TOKEN_FIELD)
            raw = str(fields.get(CONTINUATION_RAW_FINISH_FIELD) or "").upper()
            if token and raw == CONTINUATION_FINISH_REASON:
                return str(token)
    except Exception:
        return None
    return None


def with_continuation_token(kwargs: dict, token: str) -> dict:
    """The same request, with the token on the body's top level, where the
    provider reads it (LiteLLM merges `extra_body` there)."""
    out = dict(kwargs)
    extra = dict(out.get("extra_body") or {})
    extra["continuationToken"] = token
    out["extra_body"] = extra
    return out


def _add_usage(total: Optional[dict], usage: Any) -> Optional[dict]:
    """Sums the token fields of LiteLLM usage objects into one dict. The
    provider counts each segment's prompt again (and serves most of it from
    cache, the resend being byte-identical), so the cached count is summed
    with the rest and the turn's cache ratio stays true."""
    if usage is None:
        return total
    out = dict(total or {})
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        try:
            value = int(getattr(usage, key, None) or 0)
        except (TypeError, ValueError):
            value = 0
        out[key] = int(out.get(key, 0)) + value
    cached = _cached_tokens_of(usage)
    if cached or "cached_tokens" in out:
        out["cached_tokens"] = int(out.get("cached_tokens", 0)) + cached
    return out


def _cached_tokens_of(usage: Any) -> int:
    details = getattr(usage, "prompt_tokens_details", None)
    try:
        if isinstance(details, dict):
            return int(details.get("cached_tokens") or 0)
        return int(getattr(details, "cached_tokens", None) or 0)
    except (TypeError, ValueError):
        return 0


def _apply_usage(usage: Any, total: Optional[dict]) -> None:
    if usage is None or not total:
        return
    for key, value in total.items():
        if key == "cached_tokens":
            details = getattr(usage, "prompt_tokens_details", None)
            try:
                if isinstance(details, dict):
                    details["cached_tokens"] = value
                elif details is not None:
                    setattr(details, "cached_tokens", value)
                else:
                    from litellm.types.utils import PromptTokensDetailsWrapper
                    usage.prompt_tokens_details = PromptTokensDetailsWrapper(cached_tokens=value)
            except Exception:
                pass
            continue
        try:
            setattr(usage, key, value)
        except Exception:
            pass


def _is_usage_only_chunk(chunk: Any) -> bool:
    return not (getattr(chunk, "choices", None) or []) and getattr(chunk, "usage", None) is not None


def _usage_note(usage: Any) -> str:
    """'; segment used 33,101 prompt (32,900 cached), 32,765 output tokens' for
    the continuation notice; '' when the segment reported no usage."""
    if usage is None:
        return ""
    try:
        prompt = int(getattr(usage, "prompt_tokens", None) or 0)
        completion = int(getattr(usage, "completion_tokens", None) or 0)
    except (TypeError, ValueError):
        return ""
    return f"; segment used {prompt:,} prompt ({_cached_tokens_of(usage):,} cached), {completion:,} output tokens"


def _chunk_has_payload(chunk: Any) -> bool:
    """Whether a stream chunk carries anything besides a finish reason."""
    for choice in getattr(chunk, "choices", None) or []:
        delta = getattr(choice, "delta", None)
        if delta is None:
            continue
        if getattr(delta, "content", None) or getattr(delta, "tool_calls", None) or getattr(delta, "reasoning_content", None):
            return True
    return False


def _strip_finish(chunk: Any) -> Any:
    for choice in getattr(chunk, "choices", None) or []:
        try:
            choice.finish_reason = None
        except Exception:
            pass
    return chunk


def merge_continued_response(first: Any, continued: Any) -> Any:
    """Folds a continuation segment's response into the turn's: text and
    reasoning appended, tool calls and finish reason taken from the later
    segment (a turn ends in one place), usage summed, the token kept only
    while the latest segment still offers one."""
    try:
        f_choice = first.choices[0]
        c_choice = continued.choices[0]
        f_msg, c_msg = f_choice.message, c_choice.message
        if getattr(c_msg, "content", None):
            f_msg.content = (getattr(f_msg, "content", None) or "") + c_msg.content
        c_reasoning = getattr(c_msg, "reasoning_content", None)
        if c_reasoning:
            f_reasoning = getattr(f_msg, "reasoning_content", None) or ""
            try:
                f_msg.reasoning_content = f_reasoning + c_reasoning
            except Exception:
                pass
        if getattr(c_msg, "tool_calls", None):
            f_msg.tool_calls = c_msg.tool_calls
        f_msg.provider_specific_fields = dict(getattr(c_msg, "provider_specific_fields", None) or {})
        f_choice.finish_reason = c_choice.finish_reason
        total = _add_usage(_add_usage(None, getattr(first, "usage", None)), getattr(continued, "usage", None))
        if getattr(first, "usage", None) is not None:
            _apply_usage(first.usage, total)
        elif getattr(continued, "usage", None) is not None:
            first.usage = continued.usage
    except Exception:
        return first
    return first


class _ContinuationSplicer:
    """Delivers a streamed turn across continuation segments as one stream.

    Within a segment, chunks pass through. A segment's final chunk that
    carries a continuation token is withheld (its content, if any, is passed
    on without the finish), its usage chunk is summed and withheld, and the
    next segment is opened with the token through the same first-chunk retry
    as the first. The final segment's finish passes through, and its usage
    chunk carries the sum. A failure after delivery raises
    MantisStreamInterruptedError, as before.
    """

    def __init__(self, client: Any, model: Any, messages: Any, tools: Any, kwargs: dict):
        self.client = client
        self.model = model
        self.messages = messages
        self.tools = tools
        self.kwargs = kwargs
        self.chunks_yielded = 0
        self.usage_total: Optional[dict] = None
        self.segments = 1

    async def deliver(self, first_chunk: Any, stream_iter: Any):
        while True:
            # --- one segment. Chunks that end a turn -- a finish reason, usage
            # -- are held until the segment is over, because only then is it
            # known whether this segment ends the turn or a continuation
            # follows; LiteLLM may put the finish, the token and the usage on
            # different chunks, in any order, so none of them is judged alone.
            pending_token: Optional[str] = None
            held: list = []
            chunk = first_chunk
            first_chunk = None
            while True:
                if chunk is not None:
                    token = continuation_token_of(chunk)
                    if token:
                        pending_token = token
                    usage = getattr(chunk, "usage", None)
                    if usage is not None:
                        self.usage_total = _add_usage(self.usage_total, usage)
                    if usage is not None or _chunk_has_finish(chunk):
                        held.append(chunk)
                    else:
                        if held:
                            # Content after a finish-bearing chunk: the turn did
                            # not end there after all. Pass the held chunks on.
                            for h in held:
                                yield h
                                self.chunks_yielded += 1
                            held = []
                        yield chunk
                        self.chunks_yielded += 1
                try:
                    chunk = await stream_iter.__anext__()
                except StopAsyncIteration:
                    break
                except Exception as e:
                    raise MantisStreamInterruptedError(
                        f"Stream from '{self.model}' failed after {self.chunks_yielded} chunk(s) were already delivered "
                        f"({type(e).__name__}: {e}). A transparent retry would re-sample the model and splice "
                        "two different completions together; the consumer owns the continuation policy.",
                        chunks_yielded=self.chunks_yielded,
                        original_exception=e,
                    ) from e
            # --- segment over
            allowed, why = continuation_allowed(self.segments, self.usage_total) if pending_token else (False, "")
            if pending_token and not allowed:
                print(
                    f"\n[CONTINUATION] '{self.model}' stopped mid-thought after {self.segments} segment(s) and is "
                    f"not continued: {why}. The turn ends here.",
                    file=sys.stderr,
                    flush=True,
                )
            if pending_token and allowed:
                # A continuation follows: the held chunks' content goes on,
                # their finish and usage do not (the turn is not over).
                segment_usage = next((getattr(h, "usage", None) for h in reversed(held) if getattr(h, "usage", None) is not None), None)
                for h in held:
                    if _chunk_has_payload(h):
                        _strip_finish(h)
                        try:
                            h.usage = None
                        except Exception:
                            pass
                        yield h
                        self.chunks_yielded += 1
                self.segments += 1
                _observe("thinking_continuations")
                print(
                    f"\n[CONTINUATION] '{self.model}' stopped mid-thought; continuing the turn "
                    f"(segment {self.segments}){_usage_note(segment_usage)}...",
                    file=sys.stderr,
                    flush=True,
                )
                try:
                    first_chunk, stream_iter = await self.client._open_stream_with_retry(
                        self.model, self.messages, self.tools, with_continuation_token(self.kwargs, pending_token),
                    )
                except Exception as e:
                    raise MantisStreamInterruptedError(
                        f"Continuation of a turn from '{self.model}' could not be opened after "
                        f"{self.chunks_yielded} chunk(s) were delivered ({type(e).__name__}: {e}).",
                        chunks_yielded=self.chunks_yielded,
                        original_exception=e,
                    ) from e
                if first_chunk is None:
                    held = []
                    break  # an empty continuation: the turn ends here
                continue
            # This segment ends the turn: its held chunks go on as they came,
            # the usage carrying the whole turn's sum.
            for h in held:
                if getattr(h, "usage", None) is not None and self.segments > 1:
                    _apply_usage(h.usage, self.usage_total)
                yield h
                self.chunks_yielded += 1
            break


def _chunk_has_finish(chunk: Any) -> bool:
    return any(getattr(choice, "finish_reason", None) for choice in (getattr(chunk, "choices", None) or []))


def _strip_empty_injection_points(kwargs: dict[str, Any]) -> None:
    """Removes falsy `cache_control_injection_points` before LiteLLM wire dispatch.

    ADK's LiteLlm wrapper inspects `cache_control_injection_points: []` at agent
    construction time so it does not synthesize Anthropic `cache_control` blocks
    on non-Anthropic routes, then forwards the key into `LiteLLMClient`. Several
    OpenAI-compatible providers (including Vertex AI MaaS OpenAI endpoints and
    LiteLLM Proxy pass-through routes) forward unknown kwargs into the JSON body
    and reject empty `cache_control_injection_points` with HTTP 400.
    """
    if "cache_control_injection_points" in kwargs and not kwargs["cache_control_injection_points"]:
        kwargs.pop("cache_control_injection_points", None)


# Explicit Vertex/Gemini CachedContent stem pinning state passed from
# ResilientLiteLlm.generate_content_async down to ResilientLiteLLMClient.acompletion.
_ACTIVE_EXPLICIT_CACHE_HANDLE: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "_active_explicit_cache_handle", default=None
)
# Shared-stem boundary hint for forked Claude `prefix_group` stages so
# ResilientLiteLLMClient.acompletion can place a 3rd Anthropic `cache_control`
# breakpoint right at the end of the shared stem (explorer's final assistant
# message), caching 100% of the stem and refreshing its TTL on every turn.
_ACTIVE_CLAUDE_STEM_BOUNDARY: contextvars.ContextVar[Optional[dict[str, Any]]] = contextvars.ContextVar(
    "_active_claude_stem_boundary", default=None
)
EXPLICIT_CACHE_MIN_TOKENS_DEFAULT = 4096
EXPLICIT_CACHE_TTL_SECONDS_DEFAULT = 900


def _count_stem_openai_messages(stem_contents: Sequence[Any]) -> int:
    """Counts the OpenAI-format messages ADK produces for `stem_contents`."""
    count = 0
    for content in stem_contents or ():
        parts = getattr(content, "parts", None) or ()
        if not parts:
            continue
        fr_count = sum(1 for p in parts if getattr(p, "function_response", None) is not None)
        if fr_count > 0:
            count += fr_count
            has_other = any(
                getattr(p, "function_response", None) is None
                and (
                    getattr(p, "text", None)
                    or getattr(p, "function_call", None)
                    or getattr(p, "inline_data", None)
                )
                for p in parts
            )
            if has_other:
                count += 1
        else:
            count += 1
    return count


def _extract_content_text_prefix(content: Any, limit: int = 64) -> str:
    parts = getattr(content, "parts", None) or ()
    chunks = [
        str(getattr(p, "text", "") or "")
        for p in parts
        if not getattr(p, "thought", False) and getattr(p, "text", None)
    ]
    return "".join(chunks).strip()[:limit]


def _message_text_prefix(msg: Mapping[str, Any], limit: int = 64) -> str:
    content = msg.get("content")
    if isinstance(content, str):
        return content.strip()[:limit]
    if isinstance(content, list):
        chunks = [
            str(b.get("text") or "")
            for b in content
            if isinstance(b, Mapping) and b.get("type") == "text" and b.get("text")
        ]
        return "".join(chunks).strip()[:limit]
    return ""


def _message_has_cacheable_block(msg: Mapping[str, Any]) -> bool:
    content = msg.get("content")
    if isinstance(content, str):
        return bool(content.strip())
    if isinstance(content, list) and content:
        last = content[-1]
        if isinstance(last, Mapping):
            btype = str(last.get("type") or "").lower()
            if btype in ("thinking", "redacted_thinking"):
                return False
            if btype == "text":
                return bool(str(last.get("text") or "").strip())
            return True
    return False


def _build_claude_stem_boundary_hint(
    stem_contents: Sequence[Any],
    first_delta_content: Any = None,
) -> Optional[dict[str, Any]]:
    """Builds a boundary hint for pinning a Claude `cache_control` breakpoint at
    the end of `stem_contents`."""
    if not stem_contents or getattr(stem_contents[-1], "role", "") != "model":
        return None
    msg_count = _count_stem_openai_messages(stem_contents)
    if msg_count <= 0:
        return None
    delta_prefix = _extract_content_text_prefix(first_delta_content) if first_delta_content is not None else ""
    return {"stem_msg_count": msg_count, "delta_prefix": delta_prefix}


def _inject_claude_stem_breakpoint(
    model: Any,
    messages: Any,
    kwargs: dict[str, Any],
    boundary: Optional[Mapping[str, Any]] = None,
) -> None:
    """Inserts a 3rd Anthropic `cache_control` breakpoint at the shared stem
    boundary on forked Claude requests, preserving the existing TTL and staying
    strictly within Anthropic's 4-breakpoint cap."""
    if boundary is None:
        boundary = _ACTIVE_CLAUDE_STEM_BOUNDARY.get()
    if not boundary or not is_claude_model(model) or not isinstance(messages, list):
        return
    raw_points = kwargs.get("cache_control_injection_points")
    if not isinstance(raw_points, list) or not raw_points or len(raw_points) >= 4:
        return

    stem_msg_count = int(boundary.get("stem_msg_count") or 0)
    if stem_msg_count <= 0:
        return
    has_sys = 1 if (messages and isinstance(messages[0], Mapping) and messages[0].get("role") == "system") else 0
    target_idx = has_sys + stem_msg_count - 1
    if not (0 <= target_idx < len(messages) - 1):
        return

    stem_end_msg = messages[target_idx]
    delta_msg = messages[target_idx + 1]
    if not (isinstance(stem_end_msg, Mapping) and isinstance(delta_msg, Mapping)):
        return
    if stem_end_msg.get("role") != "assistant" or delta_msg.get("role") != "user":
        return
    if not _message_has_cacheable_block(stem_end_msg):
        return
    delta_prefix = str(boundary.get("delta_prefix") or "")
    if delta_prefix and not _message_text_prefix(delta_msg, len(delta_prefix)).startswith(delta_prefix):
        return

    for pt in raw_points:
        if isinstance(pt, Mapping) and pt.get("location") == "message" and pt.get("index") == target_idx:
            return

    control_template: dict[str, Any] = {"type": "ephemeral"}
    for pt in reversed(raw_points):
        if isinstance(pt, Mapping) and isinstance(pt.get("control"), Mapping):
            control_template = dict(pt["control"])
            break

    stem_point = {
        "location": "message",
        "index": target_idx,
        "control": control_template,
    }
    updated = list(raw_points)
    insert_at = len(updated)
    for idx, pt in enumerate(updated):
        if isinstance(pt, Mapping) and pt.get("location") == "message" and pt.get("index") == -1:
            insert_at = idx
            break
    updated.insert(insert_at, stem_point)
    kwargs["cache_control_injection_points"] = updated


def is_explicit_gemini_cache_eligible(model_id: Any, ctx: Any) -> bool:
    """True when `model_id` and `ctx` support explicit Gemini `cachedContents` stem pinning."""
    flag = os.environ.get("MANTIS_EXPLICIT_STEM_CACHE", "1").strip().lower()
    if flag in ("0", "false", "no", "off"):
        return False
    if ctx is None or getattr(ctx, "sandbox", None) is None:
        return False
    if not bool(getattr(ctx, "enable_context_cache", True)):
        return False
    norm = str(model_id or "").strip().lower()
    if not (norm.startswith("vertex_ai/gemini-") or norm.startswith("gemini/")):
        return False
    if "gemini-4" in norm:
        return False
    return True


def _estimate_stem_tokens(
    base_instruction: str,
    stem_contents: list[Any],
    tools_list: list[Any],
) -> int:
    chars = len(base_instruction or "")
    for content in stem_contents or ():
        for part in getattr(content, "parts", None) or ():
            txt = getattr(part, "text", None)
            if txt:
                chars += len(txt)
            fc = getattr(part, "function_call", None)
            if fc is not None:
                chars += len(json.dumps(getattr(fc, "args", None) or {}, default=str))
            fr = getattr(part, "function_response", None)
            if fr is not None:
                chars += len(json.dumps(getattr(fr, "response", None) or {}, default=str))
    for tool_obj in tools_list or ():
        try:
            chars += len(json.dumps(tool_obj.model_dump(mode="json", exclude_none=True), default=str))
        except Exception:
            chars += 500
    return chars // 4


def _is_cached_content_rejection(exc: BaseException) -> bool:
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    resp = getattr(exc, "response", None)
    if status is None and resp is not None:
        status = getattr(resp, "status_code", None)
    if status in (400, 404):
        return True
    msg = f"{type(exc).__name__} {exc}".lower()
    return any(
        tok in msg
        for tok in ("cachedcontent", "cached_content", "not_found", "not found", "expired", "404", "badrequest")
    )


async def ensure_explicit_stem_cache(
    *,
    ctx: Any,
    cache_slot_key: str,
    model_id: str,
    additional_args: dict[str, Any],
    base_instruction: str,
    tools_list: list[Any],
    stem_contents: list[Any],
) -> Optional[dict[str, Any]]:
    """Creates (or returns existing) explicit Gemini `CachedContent` handle for `stem_contents`."""
    if not is_explicit_gemini_cache_eligible(model_id, ctx):
        return None
    handles = getattr(ctx, "explicit_cache_handles", None)
    if not isinstance(handles, dict):
        return None
    existing = handles.get(cache_slot_key)
    if isinstance(existing, dict):
        if existing.get("failed") or existing.get("evicted"):
            return None
        if existing.get("name"):
            return existing

    try:
        min_tokens = max(
            1,
            int(os.environ.get("MANTIS_EXPLICIT_CACHE_MIN_TOKENS", str(EXPLICIT_CACHE_MIN_TOKENS_DEFAULT))),
        )
    except ValueError:
        min_tokens = EXPLICIT_CACHE_MIN_TOKENS_DEFAULT
    if _estimate_stem_tokens(base_instruction, stem_contents, tools_list) < min_tokens:
        return None

    if not stem_contents or getattr(stem_contents[-1], "role", "") != "model":
        return None

    try:
        import httpx
        from google.adk.models.lite_llm import _get_completion_inputs
        from google.adk.models.llm_request import LlmRequest
        from google.genai import types as genai_types
        from litellm.llms.vertex_ai.context_caching.vertex_ai_context_caching import (
            ContextCachingEndpoints,
        )
        from litellm.llms.vertex_ai.gemini.transformation import _transform_request_body

        norm_model = str(model_id).strip()
        if norm_model.startswith("gemini/"):
            provider = "gemini"
            bare_model = norm_model.split("/", 1)[1]
        else:
            provider = "vertex_ai"
            bare_model = norm_model.split("/", 1)[1] if "/" in norm_model else norm_model

        stem_req = LlmRequest(
            contents=list(stem_contents),
            config=genai_types.GenerateContentConfig(
                system_instruction=base_instruction,
                tools=list(tools_list) if tools_list else None,
            ),
        )
        messages, wire_tools, _rf, _gen_params, _ = await _get_completion_inputs(
            stem_req, model=norm_model
        )
        opt_params: dict[str, Any] = {}
        if wire_tools:
            # `_get_completion_inputs` yields OpenAI-format tools
            # (`{"type": "function", "function": {...}}`); `cachedContents`
            # needs Gemini `function_declarations`. litellm.completion maps
            # these via `map_openai_params` before `_transform_request_body`,
            # so do the same here or the POST is rejected with HTTP 400.
            if provider == "gemini":
                from litellm.llms.gemini.chat.transformation import (
                    GoogleAIStudioGeminiConfig as _GeminiParamCfg,
                )
            else:
                from litellm.llms.vertex_ai.gemini.vertex_and_google_ai_studio_gemini import (
                    VertexGeminiConfig as _GeminiParamCfg,
                )
            opt_params = _GeminiParamCfg().map_openai_params(
                non_default_params={"tools": wire_tools},
                optional_params={},
                model=bare_model,
                drop_params=False,
            )

        transformed = _transform_request_body(
            messages=messages,
            model=bare_model,
            optional_params=opt_params,
            custom_llm_provider=provider,  # type: ignore[arg-type]
            litellm_params={},
            cached_content=None,
        )

        endpoints = ContextCachingEndpoints()
        api_base = additional_args.get("api_base") or os.environ.get("LLM_API_BASE") or None
        if provider == "gemini":
            api_key = (
                additional_args.get("api_key")
                or os.environ.get("GEMINI_API_KEY")
                or os.environ.get("GOOGLE_API_KEY")
                or ""
            )
            if not api_key:
                handles[cache_slot_key] = {"failed": True}
                return None
            _auth_hdr, url = endpoints._get_token_and_url_context_caching(
                gemini_api_key=str(api_key),
                custom_llm_provider="gemini",
                api_base=api_base,
                vertex_project=None,
                vertex_location=None,
                vertex_auth_header=None,
                model=bare_model,
            )
            headers = {"x-goog-api-key": str(api_key), "Content-Type": "application/json"}
            model_resource = f"models/{bare_model}"
        else:
            vertex_project = (
                additional_args.get("vertex_project")
                or os.environ.get("VERTEXAI_PROJECT")
                or os.environ.get("GOOGLE_CLOUD_PROJECT")
            )
            vertex_location = (
                additional_args.get("vertex_location")
                or os.environ.get("VERTEXAI_LOCATION")
                or os.environ.get("GOOGLE_CLOUD_LOCATION")
                or "global"
            )
            vertex_credentials = additional_args.get("vertex_credentials")
            token, resolved_proj = await endpoints._ensure_access_token_async(
                credentials=vertex_credentials,
                project_id=vertex_project,
                custom_llm_provider="vertex_ai",
            )
            eff_proj = resolved_proj or vertex_project
            if not eff_proj:
                handles[cache_slot_key] = {"failed": True}
                return None
            auth_hdr, url = endpoints._get_token_and_url_context_caching(
                gemini_api_key=None,
                custom_llm_provider="vertex_ai",
                api_base=api_base,
                vertex_project=eff_proj,
                vertex_location=vertex_location,
                vertex_auth_header=token,
                model=bare_model,
            )
            headers = endpoints.set_headers(auth_header=auth_hdr, extra_headers=None)
            model_resource = (
                f"projects/{eff_proj}/locations/{vertex_location}/publishers/google/models/{bare_model}"
            )

        try:
            ttl_sec = max(
                60,
                int(os.environ.get("MANTIS_EXPLICIT_CACHE_TTL_SECONDS", str(EXPLICIT_CACHE_TTL_SECONDS_DEFAULT))),
            )
        except ValueError:
            ttl_sec = EXPLICIT_CACHE_TTL_SECONDS_DEFAULT

        payload: dict[str, Any] = {
            "model": model_resource,
            "ttl": f"{ttl_sec}s",
            "contents": transformed.get("contents") or [],
        }
        if "system_instruction" in transformed:
            payload["systemInstruction"] = transformed["system_instruction"]
        elif "systemInstruction" in transformed:
            payload["systemInstruction"] = transformed["systemInstruction"]
        if "tools" in transformed:
            payload["tools"] = transformed["tools"]
        if "toolConfig" in transformed:
            payload["toolConfig"] = transformed["toolConfig"]
        elif "tool_config" in transformed:
            payload["toolConfig"] = transformed["tool_config"]

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=headers, content=json.dumps(payload).encode("utf-8"))
        if resp.status_code >= 400:
            print(
                f"[CONTEXT CACHE] Explicit CachedContent creation returned HTTP {resp.status_code}; "
                "falling back to implicit prefix caching.",
                file=sys.stderr,
            )
            handles[cache_slot_key] = {"failed": True}
            return None
        resp_json = resp.json() if resp.content else {}
        handle_name = str(resp_json.get("name") or "").strip()
        if not handle_name:
            handles[cache_slot_key] = {"failed": True}
            return None

        if provider == "gemini":
            base_prefix = url.rsplit("/cachedContents", 1)[0]
            delete_url = f"{base_prefix}/{handle_name.lstrip('/')}"
        else:
            if "/projects/" in url and handle_name.startswith("projects/"):
                delete_url = f"{url.split('/projects/', 1)[0]}/{handle_name}"
            else:
                delete_url = f"{url.rstrip('/')}/{handle_name.rsplit('/', 1)[-1]}"

        entry = {
            "name": handle_name,
            "stem_len": len(stem_contents),
            "delete_url": delete_url,
            "headers": dict(headers),
            "provider": provider,
        }
        handles[cache_slot_key] = entry
        _observe("explicit_caches_created")
        return entry
    except Exception as exc:
        print(
            f"[CONTEXT CACHE] Explicit CachedContent unavailable ({type(exc).__name__}: {exc}); "
            "using implicit prefix caching.",
            file=sys.stderr,
        )
        handles[cache_slot_key] = {"failed": True}
        return None


async def cleanup_explicit_caches(ctx: Any) -> int:
    """Best-effort async DELETE of every active `CachedContent` handle stored on `ctx`."""
    if ctx is None:
        return 0
    handles = getattr(ctx, "explicit_cache_handles", None)
    if not isinstance(handles, dict) or not handles:
        return 0
    to_delete = [
        v
        for v in list(handles.values())
        if isinstance(v, dict) and v.get("name") and v.get("delete_url") and not v.get("deleted")
    ]
    handles.clear()
    if not to_delete:
        return 0
    deleted = 0
    try:
        import httpx

        async with httpx.AsyncClient(timeout=10.0) as client:
            for item in to_delete:
                try:
                    resp = await client.delete(item["delete_url"], headers=item.get("headers") or {})
                    if resp.status_code < 400 or resp.status_code == 404:
                        deleted += 1
                except Exception:
                    pass
    except Exception:
        pass
    return deleted


class ResilientLiteLLMClient(LiteLLMClient):
    """LiteLLMClient with full jitter exponential backoff (min offset 5s, 1h patience) on 429/quota exhaustion.

    Streaming (stream=True) is supported on both dispatch paths with a precise
    resilience boundary: every failure up to and including the first chunk re-enters
    the same backoff/auth-refresh loop as a non-streaming call, while a failure after
    the first chunk raises MantisStreamInterruptedError instead of retrying --
    sampling is nondeterministic, so a transparent restart would splice two different
    completions together. The consumer owns any continuation policy.
    """

    async def acompletion(
        self,
        model: Any,
        messages: Any,
        tools: Any = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Any:
        import litellm

        # A continuation segment's own request: it must not continue again
        # itself (its caller is the loop that does). Popped before LiteLLM
        # sees the kwargs.
        no_continue = bool(kwargs.pop("_mantis_no_continue", False))
        _strip_empty_injection_points(kwargs)
        _inject_claude_stem_breakpoint(model, messages, kwargs)

        # Before the retry loop, not inside it: an oversized request is deterministic, so
        # every pass through the loop would upload the same doomed payload again.
        enforce_context_budget(model, messages, tools, context_management=kwargs.get("context_management"))
        if kwargs.get("context_management"):
            _observe("context_edit_requests")

        explicit_cache_handle = kwargs.get("cached_content") or _ACTIVE_EXPLICIT_CACHE_HANDLE.get()
        if explicit_cache_handle:
            kwargs["cached_content"] = explicit_cache_handle
            tools = None
            kwargs.pop("tools", None)
            kwargs.pop("tool_choice", None)
            if isinstance(messages, list):
                messages = [
                    m
                    for m in messages
                    if not (isinstance(m, Mapping) and m.get("role") in ("system", "developer"))
                ]

        if stream:
            # Returned, not awaited into a response: callers receive the async
            # iterator directly (response = await client.acompletion(..., stream=True);
            # async for chunk in response). The context budget above still runs
            # eagerly, at call time, not at first iteration.
            return self._astream_with_retry(model, messages, tools, kwargs)

        max_patience, initial_delay, max_delay, min_offset, backoff_factor = _llm_retry_params()

        start_time = time.time()
        attempt = 0
        auth_refreshed = False
        while True:
            try:
                response = await litellm.acompletion(
                    model=model,
                    messages=messages,
                    tools=tools,
                    **kwargs,
                )
                _observe_context_edits(response)
                if no_continue:
                    return response
                return await self._continue_turn(response, model, messages, tools, kwargs)
            except Exception as e:
                if is_auth_error(e):
                    if not auth_refreshed and is_token_refreshable_auth_error(e) and try_refresh_auth():
                        auth_refreshed = True
                        _observe("auth_refreshes")
                        print(f"\n[AUTH REFRESH] Token refreshed for '{model}'; retrying request...", file=sys.stderr, flush=True)
                        continue
                    raise MantisAuthError(
                        format_auth_error_message(e, model=str(model)),
                        original_exception=e,
                    ) from None

                elapsed = time.time() - start_time
                if not is_retryable_llm_error(e) or elapsed >= max_patience:
                    raise

                remaining = max_patience - elapsed
                retry_after = extract_retry_after(e)
                delay = compute_full_jitter_delay(
                    attempt=attempt,
                    initial_delay=initial_delay,
                    max_delay=max_delay,
                    min_offset=min_offset,
                    backoff_factor=backoff_factor,
                    retry_after=retry_after,
                    max_remaining=remaining,
                )

                attempt += 1
                model_name = str(model)
                _observe("retries")
                if is_rate_limit_error(e):
                    _observe("rate_limit_retries")
                    err_detail = extract_rate_limit_detail(e)
                    prefix = f"[RATE LIMIT] 429 Quota Exceeded on '{model_name}'"
                else:
                    err_detail = f"{type(e).__name__}: {e}"
                    prefix = f"[LLM RETRY] Transient error on '{model_name}'"
                print(
                    f"\n{prefix}. "
                    f"Full jitter backoff: pausing {delay:.1f}s before retry (attempt {attempt}, elapsed {elapsed:.1f}s / {max_patience:.0f}s patience) [{err_detail}]...",
                    file=sys.stderr,
                    flush=True,
                )
                await asyncio.sleep(delay)

    async def _continue_turn(self, response: Any, model: Any, messages: Any, tools: Any, kwargs: dict) -> Any:
        """Continues a whole-response turn the provider ended mid-thought: the
        same request is sent again with the continuation token, each segment
        through the full retry loop, and the segments are folded into one
        response (merge_continued_response). Continues until the provider
        ends the turn, unless the run's budget or the operator's cap says
        otherwise (continuation_allowed); then the turn stands as the
        provider last left it."""
        segments = 1
        token = continuation_token_of(response)
        segment_usage = getattr(response, "usage", None)  # the latest segment's own usage, for the notice
        turn_usage = _add_usage(None, segment_usage)
        while token:
            allowed, why = continuation_allowed(segments, turn_usage)
            if not allowed:
                print(
                    f"\n[CONTINUATION] '{model}' stopped mid-thought after {segments} segment(s) and is "
                    f"not continued: {why}. The turn ends here.",
                    file=sys.stderr,
                    flush=True,
                )
                break
            segments += 1
            _observe("thinking_continuations")
            print(
                f"\n[CONTINUATION] '{model}' stopped mid-thought; continuing the turn "
                f"(segment {segments}){_usage_note(segment_usage)}...",
                file=sys.stderr,
                flush=True,
            )
            inner = with_continuation_token(kwargs, token)
            inner["_mantis_no_continue"] = True
            continued = await self.acompletion(model, messages, tools, stream=False, **inner)
            segment_usage = getattr(continued, "usage", None)
            turn_usage = _add_usage(turn_usage, segment_usage)
            response = merge_continued_response(response, continued)
            token = continuation_token_of(response)
        return response

    async def _astream_with_retry(
        self,
        model: Any,
        messages: Any,
        tools: Any,
        kwargs: dict,
    ) -> Any:
        """Streams a completion with retries confined to the pre-first-chunk window.
        Everything up to and including the first chunk re-enters the full jitter
        backoff / auth-refresh loop: no output has been delivered yet, so re-opening
        the stream is indistinguishable from a slow first attempt. The patience clock
        is shared across restarts (never reset per attempt). Once a chunk has been
        yielded, a failure raises MantisStreamInterruptedError instead of retrying:
        sampling is nondeterministic, so a transparent retry would splice two
        different completions together behind the consumer's back.

        A turn the provider ends with a continuation token is continued here
        (see _install_gemini_continuation_patch): the same request is sent again
        with the token and its chunks follow the first segment's as one stream,
        the finish and usage of the segments in between withheld, the usage of
        the whole turn summed on the final usage chunk.
        """
        first_chunk, stream_iter = await self._open_stream_with_retry(model, messages, tools, kwargs)
        if first_chunk is None:
            return
        splicer = _ContinuationSplicer(self, model, messages, tools, kwargs)
        async for chunk in splicer.deliver(first_chunk, stream_iter):
            yield chunk

    async def _open_stream_with_retry(
        self,
        model: Any,
        messages: Any,
        tools: Any,
        kwargs: dict,
    ) -> "tuple[Any, Any]":
        """Opens a stream and reads its first chunk, retrying everything up to that
        point. Returns (first_chunk, iterator); (None, None) for an empty stream."""
        import litellm

        max_patience, initial_delay, max_delay, min_offset, backoff_factor = _llm_retry_params()

        start_time = time.time()
        attempt = 0
        auth_refreshed = False
        while True:
            try:
                response = await litellm.acompletion(
                    model=model,
                    messages=messages,
                    tools=tools,
                    stream=True,
                    **kwargs,
                )
                stream_iter = response.__aiter__()
                try:
                    first_chunk = await stream_iter.__anext__()
                except StopAsyncIteration:
                    # An empty stream is a successfully completed (if silent) response.
                    return None, None
                return first_chunk, stream_iter
            except Exception as e:
                if is_auth_error(e):
                    if not auth_refreshed and is_token_refreshable_auth_error(e) and try_refresh_auth():
                        auth_refreshed = True
                        _observe("auth_refreshes")
                        print(f"\n[AUTH REFRESH] Token refreshed for '{model}'; retrying stream request...", file=sys.stderr, flush=True)
                        continue
                    raise MantisAuthError(
                        format_auth_error_message(e, model=str(model)),
                        original_exception=e,
                    ) from None
                elapsed = time.time() - start_time
                if not is_retryable_llm_error(e) or elapsed >= max_patience:
                    raise
                remaining = max_patience - elapsed
                retry_after = extract_retry_after(e)
                delay = compute_full_jitter_delay(
                    attempt=attempt,
                    initial_delay=initial_delay,
                    max_delay=max_delay,
                    min_offset=min_offset,
                    backoff_factor=backoff_factor,
                    retry_after=retry_after,
                    max_remaining=remaining,
                )
                attempt += 1
                model_name = str(model)
                _observe("retries")
                if is_rate_limit_error(e):
                    _observe("rate_limit_retries")
                    err_detail = extract_rate_limit_detail(e)
                    prefix = f"[RATE LIMIT] 429 Quota Exceeded on '{model_name}'"
                else:
                    err_detail = f"{type(e).__name__}: {e}"
                    prefix = f"[LLM RETRY] Transient error on '{model_name}'"
                print(
                    f"\n{prefix}. "
                    f"Full jitter backoff: pausing {delay:.1f}s before stream retry (attempt {attempt}, elapsed {elapsed:.1f}s / {max_patience:.0f}s patience) [{err_detail}]...",
                    file=sys.stderr,
                    flush=True,
                )
                await asyncio.sleep(delay)
                continue

    def completion(
        self,
        model: Any,
        messages: Any,
        tools: Any = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Any:
        import litellm

        _strip_empty_injection_points(kwargs)

        # Both dispatch paths are guarded: a control that only covers the async path is a
        # control that a single synchronous caller silently disables.
        enforce_context_budget(model, messages, tools, context_management=kwargs.get("context_management"))

        if stream:
            # Same boundary as the async path, for the same reason the context
            # budget guards both dispatch paths.
            return self._stream_with_retry(model, messages, tools, kwargs)

        max_patience, initial_delay, max_delay, min_offset, backoff_factor = _llm_retry_params()

        start_time = time.time()
        attempt = 0
        auth_refreshed = False
        while True:
            try:
                return litellm.completion(
                    model=model,
                    messages=messages,
                    tools=tools,
                    stream=stream,
                    **kwargs,
                )
            except Exception as e:
                if is_auth_error(e):
                    if not auth_refreshed and is_token_refreshable_auth_error(e) and try_refresh_auth():
                        auth_refreshed = True
                        print(f"\n[AUTH REFRESH] Token refreshed for '{model}'; retrying request...", file=sys.stderr, flush=True)
                        continue
                    raise MantisAuthError(
                        format_auth_error_message(e, model=str(model)),
                        original_exception=e,
                    ) from None

                elapsed = time.time() - start_time
                if not is_retryable_llm_error(e) or elapsed >= max_patience:
                    raise

                remaining = max_patience - elapsed
                retry_after = extract_retry_after(e)
                delay = compute_full_jitter_delay(
                    attempt=attempt,
                    initial_delay=initial_delay,
                    max_delay=max_delay,
                    min_offset=min_offset,
                    backoff_factor=backoff_factor,
                    retry_after=retry_after,
                    max_remaining=remaining,
                )

                attempt += 1
                model_name = str(model)
                _observe("retries")
                if is_rate_limit_error(e):
                    _observe("rate_limit_retries")
                    err_detail = extract_rate_limit_detail(e)
                    prefix = f"[RATE LIMIT] 429 Quota Exceeded on '{model_name}'"
                else:
                    err_detail = f"{type(e).__name__}: {e}"
                    prefix = f"[LLM RETRY] Transient error on '{model_name}'"
                print(
                    f"\n{prefix}. "
                    f"Full jitter backoff: pausing {delay:.1f}s before retry (attempt {attempt}, elapsed {elapsed:.1f}s / {max_patience:.0f}s patience) [{err_detail}]...",
                    file=sys.stderr,
                    flush=True,
                )
                time.sleep(delay)

    def _stream_with_retry(
        self,
        model: Any,
        messages: Any,
        tools: Any,
        kwargs: dict,
    ) -> Any:
        """Sync mirror of _astream_with_retry; see that method for the boundary rationale."""
        import litellm

        max_patience, initial_delay, max_delay, min_offset, backoff_factor = _llm_retry_params()

        start_time = time.time()
        attempt = 0
        auth_refreshed = False
        while True:
            try:
                response = litellm.completion(
                    model=model,
                    messages=messages,
                    tools=tools,
                    stream=True,
                    **kwargs,
                )
                stream_iter = iter(response)
                try:
                    first_chunk = next(stream_iter)
                except StopIteration:
                    return
            except Exception as e:
                if is_auth_error(e):
                    if not auth_refreshed and is_token_refreshable_auth_error(e) and try_refresh_auth():
                        auth_refreshed = True
                        _observe("auth_refreshes")
                        print(f"\n[AUTH REFRESH] Token refreshed for '{model}'; retrying stream request...", file=sys.stderr, flush=True)
                        continue
                    raise MantisAuthError(
                        format_auth_error_message(e, model=str(model)),
                        original_exception=e,
                    ) from None

                elapsed = time.time() - start_time
                if not is_retryable_llm_error(e) or elapsed >= max_patience:
                    raise

                remaining = max_patience - elapsed
                retry_after = extract_retry_after(e)
                delay = compute_full_jitter_delay(
                    attempt=attempt,
                    initial_delay=initial_delay,
                    max_delay=max_delay,
                    min_offset=min_offset,
                    backoff_factor=backoff_factor,
                    retry_after=retry_after,
                    max_remaining=remaining,
                )

                attempt += 1
                model_name = str(model)
                _observe("retries")
                if is_rate_limit_error(e):
                    _observe("rate_limit_retries")
                    err_detail = extract_rate_limit_detail(e)
                    prefix = f"[RATE LIMIT] 429 Quota Exceeded on '{model_name}'"
                else:
                    err_detail = f"{type(e).__name__}: {e}"
                    prefix = f"[LLM RETRY] Transient error on '{model_name}'"
                print(
                    f"\n{prefix}. "
                    f"Full jitter backoff: pausing {delay:.1f}s before stream retry (attempt {attempt}, elapsed {elapsed:.1f}s / {max_patience:.0f}s patience) [{err_detail}]...",
                    file=sys.stderr,
                    flush=True,
                )
                time.sleep(delay)
                continue

            break

        yield first_chunk
        chunks_yielded = 1
        while True:
            try:
                chunk = next(stream_iter)
            except StopIteration:
                return
            except Exception as e:
                raise MantisStreamInterruptedError(
                    f"Stream from '{model}' failed after {chunks_yielded} chunk(s) were already delivered "
                    f"({type(e).__name__}: {e}). A transparent retry would re-sample the model and splice "
                    "two different completions together; the consumer owns the continuation policy.",
                    chunks_yielded=chunks_yielded,
                    original_exception=e,
                ) from e
            yield chunk
            chunks_yielded += 1


#: Findings listed in a stage's snapshot before the list is cut.
FINDINGS_SNAPSHOT_MAX_LINES = 150
FINDINGS_SNAPSHOT_HEADER = "[STATE STORE: RECORDED FINDINGS (DO NOT RE-REPORT)]"


class ResilientLiteLlm(LiteLlm):
    """LiteLlm wrapper with resilient full jitter retry (min 5s offset, 1h patience) on quota and rate limits."""

    llm_client: LiteLLMClient = Field(default_factory=ResilientLiteLLMClient, exclude=True)
    _output_schema_override: Any = PrivateAttr(default=None)
    _preserve_system_prefix: bool = PrivateAttr(default=False)

    def __init__(self, model: str, **kwargs: Any) -> None:
        output_schema_override = kwargs.pop("output_schema_override", None)
        preserve_system_prefix = bool(kwargs.pop("preserve_system_prefix", False))
        if LiteLlm is not object:
            super().__init__(model=model, **kwargs)
        else:
            self.model = model
        self._output_schema_override = output_schema_override
        self._preserve_system_prefix = preserve_system_prefix
        if getattr(self, "llm_client", None) is None:
            self.llm_client = ResilientLiteLLMClient()
        if "gemini" in str(model).lower():
            try:
                import litellm
                if getattr(litellm, "vertex_ai_safety_settings", None) is None:
                    litellm.vertex_ai_safety_settings = [
                        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    ]
            except Exception:
                pass

    @property
    def capabilities(self) -> Any:
        """Explicitly declare output_schema_and_tools=False.

        When models have both tools and an output schema (e.g. reproducer, reviewer, critic),
        this instructs ADK's _OutputSchemaRequestProcessor to inject SetModelResponseTool.
        The agent can then conclude and submit its final structured verdict cleanly via a tool
        call (set_model_response) instead of attempting to push JSON via probe shell commands
        or becoming trapped in thinking-token loops.
        """
        if LlmCapabilities is not None:
            return LlmCapabilities(output_schema_and_tools=False)
        return getattr(super(), "capabilities", None)

    @staticmethod
    def build_stage_turn_reminder_entries(
        schema_cls: Any = None,
        *,
        has_set_model_response: bool = False,
        has_report_findings: bool = False,
    ) -> list[tuple[str, str]]:
        """Builds deterministic `(header, text)` stage reminder entries without mutating a request."""
        if schema_cls is None and not has_report_findings:
            return []

        reminder_entries: list[tuple[str, str]] = []

        if schema_cls is not None:
            schema_name = getattr(schema_cls, "__name__", str(schema_cls))
            if schema_name == "ReproVerdict":
                hint = '{"route": "success" | "failed_repro", "reason": "<explanation>"}'
            elif schema_name in ("ReviewVerdict", "ExtendedReviewVerdict"):
                # Per-finding verdicts (P6): the hint shows the optional
                # finding_verdicts list so the reviewer judges each finding id
                # individually instead of pushing every finding on the target
                # through one campaign-level route.
                hint = (
                    '{"route": "confirmed" | "false_positive", "reason": "<explanation>", '
                    '"finding_verdicts": [{"finding_id": <id from get_findings>, '
                    '"route": "confirmed" | "false_positive", "reason": "<one sentence>"}, ...]} '
                    '-- include one finding_verdicts entry PER finding id when multiple findings exist; '
                    'omit or leave the list empty only when there is a single finding or none'
                )
            elif schema_name in ("CriticVerdict", "ExtendedCriticVerdict"):
                hint = (
                    '{"route": "viable" | "non_viable", "reason": "<explanation>", '
                    '"finding_verdicts": [{"finding_id": <id from get_findings>, '
                    '"route": "viable" | "non_viable", "reason": "<one sentence>"}, ...]} '
                    '-- include one finding_verdicts entry PER finding id when multiple findings exist; '
                    'omit or leave the list empty only when there is a single finding or none'
                )
            else:
                hint = '{"route": "...", "reason": "..."}'

            reminder_header = f"[STAGE TURN REMINDER - {schema_name}]"
            if has_set_model_response:
                reminder = (
                    f"\n\n{reminder_header}: "
                    f"If your analysis or updates for this stage are complete, you MUST STOP calling other tools now. "
                    f"Do NOT invoke run_sandbox, write_file, or dummy shell commands to signal completion or test output. "
                    f"To conclude this stage and provide your result, submit your final verdict using the 'set_model_response' tool "
                    f"(e.g. set_model_response(route=..., reason=...)) or emit it directly as raw JSON response text conforming to {schema_name}: "
                    f"{hint}"
                )
            else:
                reminder = (
                    f"\n\n{reminder_header}: "
                    f"If your analysis or updates for this stage are complete, you MUST STOP calling tools now. "
                    f"Do NOT invoke any tools or shell commands to signal completion or test output. "
                    f"To conclude this stage and provide your result, emit your final verdict directly as raw JSON response text conforming to {schema_name}: "
                    f"{hint}"
                )
            reminder_entries.append((reminder_header, reminder))

        if has_report_findings:
            reporting_header = "[STAGE DIRECTIVE - RESEARCHER]"
            reporting_directive = (
                f"\n\n{reporting_header}: "
                f"When reporting security findings via 'report_findings', call 'report_findings' directly without "
                f"emitting intermediate conversational text, analysis essays, or markdown preambles prior to the tool call. "
                f"This ensures your entire output token budget is preserved for the full structured findings payload."
            )
            reminder_entries.append((reporting_header, reporting_directive))

        return reminder_entries

    @staticmethod
    def render_stage_turn_reminder(
        schema_cls: Any = None,
        *,
        has_set_model_response: bool = False,
        has_report_findings: bool = False,
    ) -> str:
        """Renders stage turn reminders as a single string for user-turn envelope injection."""
        entries = ResilientLiteLlm.build_stage_turn_reminder_entries(
            schema_cls,
            has_set_model_response=has_set_model_response,
            has_report_findings=has_report_findings,
        )
        return "".join(text for _header, text in entries)

    @staticmethod
    def _inject_stage_turn_reminder(llm_request: Any) -> None:
        """Injects a termination reminder or reporting directive on every turn."""
        schema_cls = getattr(getattr(llm_request, "config", None), "response_schema", None)
        has_set_model_response = False
        tools_dict = getattr(llm_request, "tools_dict", None)
        if schema_cls is None:
            if isinstance(tools_dict, dict) and "set_model_response" in tools_dict:
                has_set_model_response = True
                schema_cls = getattr(tools_dict["set_model_response"], "output_schema", None)
        else:
            if isinstance(tools_dict, dict) and "set_model_response" in tools_dict:
                has_set_model_response = True

        has_report_findings = isinstance(tools_dict, dict) and "report_findings" in tools_dict

        reminder_entries = ResilientLiteLlm.build_stage_turn_reminder_entries(
            schema_cls,
            has_set_model_response=has_set_model_response,
            has_report_findings=has_report_findings,
        )
        if not reminder_entries:
            return

        # Into the instruction, never into the messages. Both reminders are
        # the same text on every call of a stage, so they belong to the
        # stable head of the prompt. Appending them to the LAST message
        # instead -- as this once did -- changed that message between one
        # request and the next (the session keeps the original), which broke
        # the provider's prompt cache at the first tool result of every call
        # (measured: 18% of input served from cache over a run; the system
        # prompt was the only prefix that still matched) and, for models that
        # bind reasoning to its prefix, rewrites the prefix under every later
        # thinking block.
        for header, text in reminder_entries:
            ResilientLiteLlm._append_instruction_once(llm_request, header, text)

    @staticmethod
    def _append_instruction_once(llm_request: Any, header: str, text: str) -> None:
        """Appends `text` to the request's system instruction unless `header`
        is already in it. The instruction is rebuilt per request from the
        agent's, so this runs on every call and lands the same bytes each
        time -- the property the prompt cache and prefix binding need."""
        config = getattr(llm_request, "config", None)
        current = str(getattr(config, "system_instruction", "") or "") if config is not None else ""
        if header in current:
            return
        append = getattr(llm_request, "append_instructions", None)
        if callable(append):
            append([text])
        elif config is not None:
            config.system_instruction = current + text

    @staticmethod
    def get_or_render_findings_snapshot(cache_scope_key: str) -> str:
        """Computes and caches the campaign's active findings snapshot for `cache_scope_key`."""
        from core.context import current_run_context
        from core.database import read_findings

        ctx = current_run_context.get()
        if ctx is None or not ctx.db_path or not os.path.exists(ctx.db_path):
            return ""
        pass_idx = max(1, int(getattr(ctx, "pass_index", 1) or 1))
        active_node = str(getattr(ctx, "active_node", "") or "")
        if (
            pass_idx > 1
            and not bool(getattr(ctx, "reported_in_pass", False))
            and (
                active_node in ("architect", "threat_modeler", "planner", "explorer")
                or active_node == "researcher"
                or active_node.startswith("researcher_")
            )
        ):
            return ""
        store = getattr(ctx, "node_context", None)
        snapshots = store.setdefault("_findings_snapshot", {}) if isinstance(store, dict) else {}
        key = f"{pass_idx}:{cache_scope_key}"
        if key not in snapshots:
            try:
                findings = read_findings(
                    ctx.db_path, run_id=ctx.run_id,
                    scope_path=(getattr(ctx, "target_file", "") or None),
                    campaign=(getattr(ctx, "target_file", "") or None),
                    pass_index=pass_idx,
                )
            except Exception:
                return ""
            snapshots[key] = ResilientLiteLlm._render_findings_snapshot(findings)
        return str(snapshots.get(key) or "")

    @staticmethod
    def _inject_active_findings_state(llm_request: Any) -> None:
        """Tells a stage, once, which findings its campaign has already recorded.

        A snapshot taken at the stage's first call and held for the stage's
        lifetime, appended to the system instruction: the same bytes on every
        call, so the prompt cache holds and the prefix under retained
        reasoning never moves. Findings recorded during the stage reach the
        model through the tool results that recorded them and get_findings.

        The campaign's own findings only (the subtree of its target), fenced
        and bounded: titles are model-written text, and under --parallel the
        run's list is every sibling campaign's work. Keyed by the instruction
        it is appended to, so each stage of a campaign takes its own snapshot
        and a continued attempt takes a fresh one.
        """
        header = FINDINGS_SNAPSHOT_HEADER
        config = getattr(llm_request, "config", None)
        instruction = str(getattr(config, "system_instruction", "") or "") if config is not None else ""
        if header in instruction:
            return
        digest = hashlib.sha256(instruction.encode("utf-8", "replace")).hexdigest()
        block = ResilientLiteLlm.get_or_render_findings_snapshot(digest)
        if block:
            ResilientLiteLlm._append_instruction_once(llm_request, header, block)

    @staticmethod
    def _render_findings_snapshot(findings: list) -> str:
        if not findings:
            return ""
        from core.llm_gateway import SecretScrubber, wrap_untrusted_content

        lines = []
        for f in findings[: FINDINGS_SNAPSHOT_MAX_LINES]:
            f_id = f.get("id")
            f_sev = f.get("severity", "UNKNOWN")
            f_fp = f.get("filepath", "")
            f_lines = f.get("line_numbers") or []
            raw_title = str(f.get("title", "")).replace("\n", " ").strip()
            clean_title = SecretScrubber.scrub(raw_title)[:120]
            f_st = f.get("status", "reported")
            lines.append(f"  • Finding #{f_id} [{f_sev}] {f_fp}:{f_lines} - {clean_title} (status: {f_st})")
        omitted = len(findings) - len(lines)
        if omitted > 0:
            lines.append(f"  … and {omitted} more; get_findings lists them all.")
        return (
            f"\n\n{FINDINGS_SNAPSHOT_HEADER}\n"
            f"The following {len(findings)} vulnerability finding(s) were already recorded for this "
            "campaign when this stage began. Do NOT call report_findings for them; report only NEW, "
            "distinct findings. Findings recorded since appear in your tool results and in get_findings.\n"
            + wrap_untrusted_content("\n".join(lines), filename="recorded_findings_snapshot")
        )

    @staticmethod
    def _extract_valid_structured_json(text: str, schema_cls: Any) -> tuple[bool, Optional[str]]:
        """Validates raw or fenced/embedded JSON against `schema_cls`.

        Returns `(is_valid, salvaged_json)` where `salvaged_json` is `None` when
        `text.strip()` already validated verbatim, or the normalized JSON string
        when salvaged from fences/prose.
        """
        raw_stripped = (text or "").strip()
        if not raw_stripped or schema_cls is None:
            return False, None

        candidates: list[str] = [raw_stripped]
        clean_text = raw_stripped
        if clean_text.startswith("```json"):
            clean_text = clean_text[7:]
        elif clean_text.startswith("```"):
            clean_text = clean_text[3:]
        if clean_text.endswith("```"):
            clean_text = clean_text[:-3]
        clean_text = clean_text.strip()
        if clean_text and clean_text not in candidates:
            candidates.append(clean_text)

        for m in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL | re.IGNORECASE):
            cand_fenced = m.group(1).strip()
            if cand_fenced and cand_fenced not in candidates:
                candidates.append(cand_fenced)

        decoder = json.JSONDecoder()
        search_pos = 0
        while True:
            brace_idx = text.find("{", search_pos)
            if brace_idx == -1:
                break
            try:
                _obj, end_idx = decoder.raw_decode(text, brace_idx)
                if isinstance(_obj, dict):
                    cand_obj = text[brace_idx:end_idx].strip()
                    if cand_obj and cand_obj not in candidates:
                        candidates.append(cand_obj)
                search_pos = end_idx
            except Exception:
                search_pos = brace_idx + 1

        for cand in candidates:
            try:
                if hasattr(schema_cls, "model_validate_json"):
                    validated = schema_cls.model_validate_json(cand)
                    salvaged = (
                        validated.model_dump_json()
                        if cand != raw_stripped and hasattr(validated, "model_dump_json")
                        else (cand if cand != raw_stripped else None)
                    )
                    return True, salvaged
                elif hasattr(schema_cls, "validate_json"):
                    schema_cls.validate_json(cand)
                    return True, (cand if cand != raw_stripped else None)
            except Exception:
                continue
        return False, None

    @staticmethod
    def _sanitize_structured_response(
        response: Any,
        schema_cls: Any,
        *,
        allow_set_model_response_tool: bool = True,
    ) -> Any:
        """Sanitizes model responses when a structured schema is required to prevent Pydantic ValidationError on refusals."""
        if schema_cls is None or getattr(response, "partial", False):
            return response

        from google.genai import types

        # If the response contains function calls (e.g. set_model_response or tool calls), let ADK handle it
        # -- unless set_model_response is NOT registered (prefix_group raw-JSON mode), in which case a
        # hallucinated set_model_response call is converted directly into validated raw JSON text.
        parts = getattr(getattr(response, "content", None), "parts", None)
        if parts:
            fcs = [getattr(p, "function_call", None) for p in parts if getattr(p, "function_call", None) is not None]
            if fcs:
                if (
                    not allow_set_model_response_tool
                    and len(fcs) == 1
                    and getattr(fcs[0], "name", "") == "set_model_response"
                    and isinstance(getattr(fcs[0], "args", None), dict)
                ):
                    try:
                        cand_json = json.dumps(dict(fcs[0].args))
                        ok, salvaged = ResilientLiteLlm._extract_valid_structured_json(cand_json, schema_cls)
                        if ok:
                            final_json = salvaged if salvaged is not None else cand_json
                            thought_parts = [p for p in parts if getattr(p, "thought", False)]
                            sig = next(
                                (getattr(p, "thought_signature", None) for p in reversed(parts) if getattr(p, "thought_signature", None)),
                                None,
                            )
                            txt_part = types.Part(text=final_json, thought_signature=sig) if sig else types.Part.from_text(text=final_json)
                            response.content.parts = thought_parts + [txt_part]
                            return response
                    except Exception:
                        pass
                else:
                    return response

        # Extract text content from parts
        text = ""
        if parts:
            text = "".join(
                getattr(p, "text", "") or ""
                for p in parts
                if not getattr(p, "thought", False)
            )

        is_safety_block = getattr(response, "finish_reason", None) in (types.FinishReason.SAFETY, "SAFETY") or getattr(response, "error_code", None) == "SAFETY"

        # Check if the text (or fenced/embedded JSON inside it) validates against schema_cls.
        is_valid = False
        salvaged_json: Optional[str] = None
        if text.strip() and not is_safety_block and not getattr(response, "error_code", None):
            is_valid, salvaged_json = ResilientLiteLlm._extract_valid_structured_json(text, schema_cls)

        if is_safety_block:
            is_valid = False

        if is_valid and salvaged_json is not None:
            thought_parts = [p for p in (parts or []) if getattr(p, "thought", False)]
            sig = next(
                (
                    getattr(p, "thought_signature", None)
                    for p in reversed(parts or [])
                    if not getattr(p, "thought", False) and getattr(p, "thought_signature", None)
                ),
                None,
            )
            txt_part = types.Part(text=salvaged_json, thought_signature=sig) if sig else types.Part.from_text(text=salvaged_json)
            new_parts = thought_parts + [txt_part]
            if getattr(response, "content", None) is None:
                response.content = types.Content(role="model", parts=new_parts)
            else:
                response.content.parts = new_parts
            return response

        if not is_valid:
            schema_name = getattr(schema_cls, "__name__", str(schema_cls))
            model_fields = getattr(schema_cls, "model_fields", None) or {}
            if schema_name not in ("ReproVerdict", "ReviewVerdict", "ExtendedReviewVerdict", "CriticVerdict", "ExtendedCriticVerdict") and "route" not in model_fields:
                # Non-verdict schemas (FindingCalibration, AuditPlan) have dedicated
                # prose/JSON fallback parsers in their callers; replacing their text
                # with a ReproVerdict payload would clobber those fallbacks.
                if is_safety_block:
                    if getattr(response, "content", None) is None:
                        response.content = types.Content(role="model", parts=[types.Part.from_text(text="{}")])
                    else:
                        response.content.parts = [types.Part.from_text(text="{}")]
                    if getattr(response, "finish_reason", None) in (types.FinishReason.SAFETY, "SAFETY"):
                        response.finish_reason = types.FinishReason.STOP
                    if getattr(response, "error_code", None):
                        response.error_code = None
                        response.error_message = None
                return response
            clean_snippet = text.strip().replace("\n", " ")[:200] or "Model emitted non-JSON or refusal output"
            if schema_name == "ReproVerdict":
                fallback_payload = {
                    "route": "failed_repro",
                    "reason": f"Fallback: {clean_snippet}",
                }
            elif schema_name in ("ReviewVerdict", "ExtendedReviewVerdict"):
                # Fail CLOSED like the other two verdicts. The old value
                # ("confirmed") promoted a safety-blocked or garbage response
                # into a confirmed vulnerability and sent it down the
                # critic/repro chain. The "Fallback:" reason prefix is a
                # contract with the classifier: synthesized dismissals are
                # routed but never persisted as finding status. The explicit
                # empty finding_verdicts list is the same contract at the
                # per-finding level (INV-6): a synthesized verdict reviewed
                # nothing, so it must route campaign-level and can never
                # stamp any individual finding.
                fallback_payload = {
                    "route": "false_positive",
                    "reason": f"Fallback: {clean_snippet}",
                }
                if schema_name == "ExtendedReviewVerdict":
                    # Only the extended schema tolerates this key: the
                    # canonical ReviewVerdict is extra="forbid" and ADK
                    # re-validates this synthesized text against the bound
                    # schema, so adding the key there would turn the
                    # fail-safe itself into a validation error.
                    fallback_payload["finding_verdicts"] = []
            elif schema_name in ("CriticVerdict", "ExtendedCriticVerdict"):
                fallback_payload = {
                    "route": "non_viable",
                    "reason": f"Fallback: {clean_snippet}",
                }
                if schema_name == "ExtendedCriticVerdict":
                    fallback_payload["finding_verdicts"] = []
            else:
                fallback_payload = {
                    "route": "failed_repro",
                    "reason": f"Fallback: {clean_snippet}",
                }

            try:
                from core.context import current_run_context
                _rc = current_run_context.get()
                if _rc is not None:
                    _rc.verdict_fallbacks = int(getattr(_rc, "verdict_fallbacks", 0) or 0) + 1
            except Exception:
                pass

            fallback_json = json.dumps(fallback_payload)
            if getattr(response, "content", None) is None:
                response.content = types.Content(role="model", parts=[types.Part.from_text(text=fallback_json)])
            else:
                response.content.parts = [types.Part.from_text(text=fallback_json)]

            if getattr(response, "finish_reason", None) in (types.FinishReason.SAFETY, "SAFETY"):
                response.finish_reason = types.FinishReason.STOP
            if getattr(response, "error_code", None):
                response.error_code = None
                response.error_message = None

            print(
                f"\n[SCHEMA RESILIENCE] Intercepted non-schema/refusal output for {schema_name}; "
                f"synthesized fallback: {fallback_json}",
                file=sys.stderr,
                flush=True,
            )

        return response

    def _lower_output_cap(self, cap: int) -> bool:
        """Lowers this model's `max_tokens` to `cap` for every call from now
        on. False when the request already asked for no more than that, so
        a provider message the retry cannot act on is raised as it came."""
        additional = getattr(self, "_additional_args", None)
        if not isinstance(additional, dict):
            return False
        try:
            current = int(additional.get("max_tokens") or 0)
        except (TypeError, ValueError):
            current = 0
        if current and current <= int(cap):
            return False
        copied = dict(additional)
        copied["max_tokens"] = int(cap)
        self._additional_args = copied
        return True

    async def generate_content_async(
        self, llm_request: Any, stream: bool = False
    ) -> Any:
        if not self._preserve_system_prefix:
            self._inject_stage_turn_reminder(llm_request)
            self._inject_active_findings_state(llm_request)
        has_smr_tool = False
        if isinstance(getattr(llm_request, "tools_dict", None), dict) and "set_model_response" in llm_request.tools_dict:
            has_smr_tool = True
        if getattr(self, "_skip_structured_sanitizer", False) or _HANDOFF_PLAIN_TEXT_TURN.get():
            # Plain-text context-ceiling handoff turn: never coerce the summary
            # into a schema verdict (or a `Fallback:` dismissal).
            schema_cls = None
        else:
            schema_cls = getattr(getattr(llm_request, "config", None), "response_schema", None)
            if schema_cls is None and has_smr_tool:
                schema_cls = getattr(llm_request.tools_dict["set_model_response"], "output_schema", None)
            if schema_cls is None and self._output_schema_override is not None:
                schema_cls = self._output_schema_override

        max_patience, initial_delay, max_delay, min_offset, backoff_factor = _llm_retry_params()
        # An empty STOP turn is retried like a 429, but it is not a 429: a
        # request the model has answered with nothing this many times in a
        # row is being answered, and the answer is nothing. Past the cap the
        # empty turn is passed on (below) instead of burning the rest of the
        # patience window one identical request at a time.
        max_empty_turns = int(
            _parse_env_number(
                ("MANTIS_LLM_EMPTY_TURN_MAX_ATTEMPTS",),
                as_int=True,
                default=DEFAULT_EMPTY_TURN_MAX_ATTEMPTS,
                min_val=1,
            )
            or DEFAULT_EMPTY_TURN_MAX_ATTEMPTS
        )

        start_time = time.time()
        attempt = 0
        empty_turns = 0
        auth_refreshed = False
        schema_error_retried = False
        invalid_json_retried = False
        current_stream = stream
        active_request = llm_request
        stem_cache_meta = getattr(llm_request, "_mantis_stem_cache", None)
        while True:
            streamed_content = False  # per attempt: has this turn yielded an answer yet
            yielded_any = False       # per attempt: did upstream yield any LlmResponse at all
            pending_empty = None      # a final with no answer, held until the stream shows what follows
            retry_schema_turn = False
            used_cache_entry: Optional[dict[str, Any]] = None
            wire_request = active_request
            cache_tok = None
            claude_stem_tok = None
            try:
                from google.genai import types as genai_types
                if isinstance(stem_cache_meta, dict):
                    from core.context import current_run_context

                    rc_cache = current_run_context.get()
                    stem_len = int(stem_cache_meta.get("stem_len") or 0)
                    slot_key = str(stem_cache_meta.get("slot_key") or "")
                    full_contents = list(getattr(active_request, "contents", None) or [])
                    if (
                        rc_cache is not None
                        and slot_key
                        and stem_len > 0
                        and len(full_contents) > stem_len
                    ):
                        model_str = str(getattr(self, "model", "") or "")
                        if is_claude_model(model_str) and bool(getattr(rc_cache, "enable_context_cache", True)):
                            stem_hint = _build_claude_stem_boundary_hint(
                                full_contents[:stem_len], full_contents[stem_len]
                            )
                            if stem_hint is not None:
                                claude_stem_tok = _ACTIVE_CLAUDE_STEM_BOUNDARY.set(stem_hint)
                        entry = await ensure_explicit_stem_cache(
                            ctx=rc_cache,
                            cache_slot_key=slot_key,
                            model_id=model_str,
                            additional_args=dict(getattr(self, "_additional_args", None) or {}),
                            base_instruction=str(
                                getattr(getattr(active_request, "config", None), "system_instruction", "") or ""
                            ),
                            tools_list=list(getattr(getattr(active_request, "config", None), "tools", None) or []),
                            stem_contents=full_contents[:stem_len],
                        )
                        if entry and entry.get("name") and not entry.get("evicted"):
                            used_cache_entry = entry
                            wire_request = active_request.model_copy()
                            wire_request.contents = full_contents[stem_len:]
                            orig_cfg = getattr(active_request, "config", None)
                            if orig_cfg is not None:
                                cfg_copy = orig_cfg.model_copy()
                                cfg_copy.system_instruction = None
                                cfg_copy.tools = None
                                if hasattr(cfg_copy, "tool_config"):
                                    cfg_copy.tool_config = None
                                wire_request.config = cfg_copy
                            wire_request.tools_dict = {}
                            cache_tok = _ACTIVE_EXPLICIT_CACHE_HANDLE.set(str(entry["name"]))
                try:
                    async for response in super().generate_content_async(wire_request, stream=current_stream):
                        if (
                            current_stream
                            and (
                                getattr(response, "error_code", None) in (getattr(genai_types.FinishReason, "MAX_TOKENS", None), "MAX_TOKENS")
                                or getattr(response, "finish_reason", None) in (getattr(genai_types.FinishReason, "MAX_TOKENS", None), "MAX_TOKENS")
                            )
                            and "Tool call arguments were truncated" in str(getattr(response, "error_message", ""))
                        ):
                            meter_response_usage(response)
                            raise MantisStreamingTruncationError(str(getattr(response, "error_message", "")))
                        if pending_empty is not None:
                            # Something followed it, so it was not the end of the
                            # turn: pass it on as it came.
                            yielded_any = True
                            yield self._sanitize_structured_response(
                                pending_empty, schema_cls, allow_set_model_response_tool=has_smr_tool
                            )
                            pending_empty = None
                        if is_empty_stop_response(response) and not streamed_content:
                            pending_empty = response
                            continue
                        if (
                            schema_cls is not None
                            and not getattr(response, "partial", False)
                            and not schema_error_retried
                            and not streamed_content
                            and (
                                (
                                    getattr(response, "error_code", None)
                                    and str(getattr(response, "error_code", "")) not in ("SAFETY", "MAX_TOKENS")
                                )
                                or str(getattr(response, "finish_reason", "")).endswith("MALFORMED_FUNCTION_CALL")
                            )
                        ):
                            meter_response_usage(response)
                            schema_error_retried = True
                            retry_schema_turn = True
                            current_stream = False
                            break
                        if (
                            self._output_schema_override is not None
                            and schema_cls is not None
                            and not getattr(response, "partial", False)
                            and not invalid_json_retried
                            and not getattr(response, "error_code", None)
                            and getattr(response, "finish_reason", None) not in (genai_types.FinishReason.SAFETY, "SAFETY")
                        ):
                            resp_parts = getattr(getattr(response, "content", None), "parts", None) or []
                            resp_fcs = [getattr(p, "function_call", None) for p in resp_parts if getattr(p, "function_call", None) is not None]
                            if not resp_fcs:
                                resp_text = "".join(
                                    getattr(p, "text", "") or ""
                                    for p in resp_parts
                                    if not getattr(p, "thought", False)
                                )
                                is_ok, _ = self._extract_valid_structured_json(resp_text, schema_cls)
                                if not is_ok:
                                    meter_response_usage(response)
                                    invalid_json_retried = True
                                    retry_schema_turn = True
                                    current_stream = False
                                    schema_label = getattr(schema_cls, "__name__", "verdict")
                                    retry_req = active_request.model_copy()
                                    appended = list(getattr(active_request, "contents", None) or [])
                                    if getattr(response, "content", None) is not None and resp_parts:
                                        appended.append(response.content)
                                    appended.append(
                                        genai_types.Content(
                                            role="user",
                                            parts=[
                                                genai_types.Part.from_text(
                                                    text=(
                                                        f"Your response did not contain valid {schema_label} JSON. "
                                                        f"Emit ONLY a raw JSON object conforming to {schema_label} "
                                                        "(no markdown fences, no prose, and no tool calls)."
                                                    )
                                                )
                                            ],
                                        )
                                    )
                                    retry_req.contents = appended
                                    active_request = retry_req
                                    break
                        if response_has_meaningful_content(response):
                            streamed_content = True
                        yielded_any = True
                        yield self._sanitize_structured_response(
                            response, schema_cls, allow_set_model_response_tool=has_smr_tool
                        )
                finally:
                    if cache_tok is not None:
                        _ACTIVE_EXPLICIT_CACHE_HANDLE.reset(cache_tok)
                    if claude_stem_tok is not None:
                        _ACTIVE_CLAUDE_STEM_BOUNDARY.reset(claude_stem_tok)
                if retry_schema_turn:
                    continue
                if pending_empty is not None:
                    # The turn ended on it: an empty turn. Billed, so charged,
                    # before it is thrown away. A budget ceiling crossed here
                    # raises past the retry loop below, which does not retry
                    # that.
                    meter_response_usage(pending_empty)
                    raise MantisEmptyResponseError(
                        "The model returned no content (finish_reason=STOP with empty parts)",
                        response=pending_empty,
                    )
                if not yielded_any:
                    raise MantisEmptyResponseError(
                        "The model stream ended with zero chunks (empty response stream)"
                    )
                return
            except (json.decoder.JSONDecodeError, ValueError, MantisStreamingTruncationError) as e:
                if current_stream:
                    model_name = str(getattr(self, "model", getattr(llm_request, "model", "llm")))
                    print(
                        f"\n[STREAM RESILIENCE] Streaming tool call parsing failed on '{model_name}' ({type(e).__name__}: {e}). "
                        f"Retrying turn with stream=False...",
                        file=sys.stderr,
                        flush=True,
                    )
                    current_stream = False
                    continue
                if not is_retryable_llm_error(e):
                    raise
                elapsed = time.time() - start_time
                if elapsed >= max_patience:
                    raise
                remaining = max_patience - elapsed
                retry_after = extract_retry_after(e)
                delay = compute_full_jitter_delay(
                    attempt=attempt,
                    initial_delay=initial_delay,
                    max_delay=max_delay,
                    min_offset=min_offset,
                    backoff_factor=backoff_factor,
                    retry_after=retry_after,
                    max_remaining=remaining,
                )
                attempt += 1
                model_name = str(getattr(self, "model", getattr(llm_request, "model", "llm")))
                err_detail = f"{type(e).__name__}: {e}"
                print(
                    f"\n[LLM RETRY] Transient error on '{model_name}'. "
                    f"Full jitter backoff: pausing {delay:.1f}s before retry (attempt {attempt}, elapsed {elapsed:.1f}s / {max_patience:.0f}s patience) [{err_detail}]...",
                    file=sys.stderr,
                    flush=True,
                )
                await asyncio.sleep(delay)
            except Exception as e:
                if (
                    used_cache_entry is not None
                    and not yielded_any
                    and _is_cached_content_rejection(e)
                ):
                    used_cache_entry["evicted"] = True
                    print(
                        f"\n[CONTEXT CACHE] CachedContent '{used_cache_entry.get('name')}' rejected "
                        f"({type(e).__name__}); evicting handle and retrying with full stem...",
                        file=sys.stderr,
                        flush=True,
                    )
                    continue

                if current_stream and any(p in str(e).lower() for p in ("unterminated string", "jsondecodeerror", "truncated while streaming")):
                    model_name = str(getattr(self, "model", getattr(llm_request, "model", "llm")))
                    print(
                        f"\n[STREAM RESILIENCE] Streaming tool call parsing failed on '{model_name}' ({type(e).__name__}: {e}). "
                        f"Retrying turn with stream=False...",
                        file=sys.stderr,
                        flush=True,
                    )
                    current_stream = False
                    continue

                output_cap = output_cap_from_error(e)
                if output_cap and self._lower_output_cap(output_cap):
                    # The provider named a lower output ceiling than the
                    # request asked for. Same request, at that ceiling, once;
                    # the instance remembers it for every later call.
                    model_name = str(getattr(self, "model", getattr(llm_request, "model", "llm")))
                    print(
                        f"\n[LLM RETRY] '{model_name}' allows at most {output_cap} output tokens; "
                        "retrying at that ceiling...",
                        file=sys.stderr,
                        flush=True,
                    )
                    continue

                if is_auth_error(e):
                    if not auth_refreshed and is_token_refreshable_auth_error(e) and try_refresh_auth():
                        auth_refreshed = True
                        model_name = str(getattr(self, "model", getattr(llm_request, "model", "llm")))
                        print(f"\n[AUTH REFRESH] Token refreshed for '{model_name}'; retrying request...", file=sys.stderr, flush=True)
                        continue
                    raise MantisAuthError(
                        format_auth_error_message(
                            e,
                            model=str(getattr(self, "model", getattr(llm_request, "model", "llm"))),
                        ),
                        original_exception=e,
                    ) from None

                elapsed = time.time() - start_time
                if isinstance(e, MantisEmptyResponseError):
                    empty_turns += 1
                if isinstance(e, MantisEmptyResponseError) and (elapsed >= max_patience or empty_turns >= max_empty_turns):
                    # Out of patience, or out of empty turns: the stage ends
                    # here. A verdict stage gets its fail-closed verdict from
                    # the sanitizer, as before; any other gets a final answer
                    # that says what happened, so ADK sees a completed turn
                    # and not MODEL_RETURNED_NO_CONTENT -- the work the stage
                    # recorded stands, the campaign completes, and --resume
                    # has nothing to re-run (see MantisEmptyResponseError).
                    model_name = str(getattr(self, "model", getattr(llm_request, "model", "llm")))
                    reason = (f"{empty_turns} empty turn(s) in a row on this request (cap {max_empty_turns})"
                              if empty_turns >= max_empty_turns else f"{elapsed:.0f}s of retries")
                    print(
                        f"\n[LLM RETRY] '{model_name}' still returned no content after "
                        f"{reason}; ending the stage's turn with its recorded work in place.",
                        file=sys.stderr,
                        flush=True,
                    )
                    _observe("empty_turn_ends")
                    if schema_cls is not None:
                        from google.genai import types as _genai_types

                        giveup_resp = e.response if e.response is not None else empty_turn_final_response()
                        giveup_resp.usage_metadata = _genai_types.GenerateContentResponseUsageMetadata(
                            prompt_token_count=0,
                            candidates_token_count=0,
                            total_token_count=0,
                        )
                        yield self._sanitize_structured_response(
                            giveup_resp, schema_cls, allow_set_model_response_tool=has_smr_tool
                        )
                    else:
                        yield empty_turn_final_response()
                    return
                if isinstance(e, MantisEmptyResponseError) and empty_turns >= 2:
                    # The same bytes drew nothing twice; ask, once, whether
                    # the stage is done. Appended, never edited.
                    append_empty_turn_nudge(active_request)
                if not is_retryable_llm_error(e) or elapsed >= max_patience:
                    raise

                remaining = max_patience - elapsed
                retry_after = extract_retry_after(e)
                delay = compute_full_jitter_delay(
                    attempt=attempt,
                    initial_delay=initial_delay,
                    max_delay=max_delay,
                    min_offset=min_offset,
                    backoff_factor=backoff_factor,
                    retry_after=retry_after,
                    max_remaining=remaining,
                )

                attempt += 1
                model_name = str(getattr(self, "model", llm_request.model if hasattr(llm_request, "model") else "llm"))
                if is_rate_limit_error(e):
                    err_detail = extract_rate_limit_detail(e)
                    prefix = f"[RATE LIMIT] 429 Quota Exceeded on '{model_name}'"
                else:
                    err_detail = f"{type(e).__name__}: {e}"
                    prefix = f"[LLM RETRY] Transient error on '{model_name}'"
                print(
                    f"\n{prefix}. "
                    f"Full jitter backoff: pausing {delay:.1f}s before retry (attempt {attempt}, elapsed {elapsed:.1f}s / {max_patience:.0f}s patience) [{err_detail}]...",
                    file=sys.stderr,
                    flush=True,
                )
                await asyncio.sleep(delay)


_HANDOFF_PLAIN_TEXT_TURN: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "_handoff_plain_text_turn", default=False
)


class _HandoffLiteLlm(ResilientLiteLlm):
    """Plain-text handoff wrapper around `ResilientLiteLlm` for context-ceiling
    continuations on schema-bound nodes (`reviewer`, `critic`, `reproducer`).

    Preserves `_inject_stage_turn_reminder` and tool declarations byte-for-byte
    so provider prompt caches hit, while bypassing `_sanitize_structured_response`
    so mid-stage plain-text handoff summaries are never coerced into `Fallback:`
    dismissal verdicts.
    """

    _skip_structured_sanitizer: bool = PrivateAttr(default=True)


class DeferredEnvLiteLlm(ResilientLiteLlm):
    """ResilientLiteLlm that resolves cloud credentials at CALL time, not build time.

    get_llm_kwargs raises when a vertex_ai/ model has no resolvable project
    (VERTEXAI_PROJECT / GOOGLE_CLOUD_PROJECT / ADC), and graph_loader used to
    call it eagerly for every node while BUILDING the graph. That coupled two
    unrelated capabilities: constructing the workflow graph (pure local data
    flow) and holding cloud credentials (only needed to actually call the
    model). In hermetic environments -- unit tests, CI sandboxes, air-gapped
    graph review -- 9 tests failed at import/build time without ever intending
    to make an LLM call.

    This class carries a zero-argument resolver (a functools.partial closing
    over the exact same arguments graph_loader would have passed eagerly) and
    invokes it on the FIRST generate_content_async call. Resolution is
    fail-closed: if the environment still lacks credentials at call time, the
    resolver re-raises the same clear ValueError ("You must set
    VERTEXAI_PROJECT or GOOGLE_CLOUD_PROJECT...") with build-deferral context
    appended -- the call fails loudly, never silently downgrades to another
    provider. If the environment gained credentials between build and call
    (main.py setup, test fixtures, delayed ADC), resolution simply succeeds.
    """

    _env_resolver: Any = PrivateAttr(default=None)
    _env_resolved: bool = PrivateAttr(default=True)

    def __init__(self, model: str, env_resolver: Any = None, **kwargs: Any) -> None:
        super().__init__(model=model, **kwargs)
        self._env_resolver = env_resolver
        self._env_resolved = env_resolver is None

    def _resolve_deferred_env(self) -> None:
        if self._env_resolved:
            return
        try:
            resolved_model, llm_kwargs = self._env_resolver()
        except ValueError as e:
            # Same message the eager path produced, so operators and tests
            # that match on it keep working; the suffix explains why it
            # surfaced at call time instead of graph-build time.
            raise ValueError(
                f"{e} (credential resolution was deferred from graph build; "
                f"this LLM call for '{getattr(self, 'model', '?')}' cannot proceed without them)"
            ) from e
        merged = dict(llm_kwargs)
        merged.pop("model", None)
        try:
            # The construction-time model string was a display placeholder
            # (raw node/config id); swap in the fully resolved id now.
            self.model = resolved_model
        except Exception:
            pass
        additional = getattr(self, "_additional_args", None)
        if isinstance(additional, dict):
            additional.update(merged)
        self._env_resolver = None
        self._env_resolved = True

    async def generate_content_async(self, llm_request: Any, stream: bool = False) -> Any:
        self._resolve_deferred_env()
        async for item in super().generate_content_async(llm_request, stream=stream):
            yield item


def resolve_model_id(
    model_id: Optional[str] = None,
    default_model: str = DEFAULT_MODEL,
    global_model_override: Optional[str] = None,
) -> str:
    """The model a node will actually call, as its normalized id.

    Precedence: global_override > MANTIS_MODEL > node > MODEL_ID > default.
    Split out of get_llm_kwargs so a caller that only needs the identity --
    the harness fingerprint stamps it on every coverage row -- gets the same
    answer whether or not the credentials get_llm_kwargs goes on to require
    are present.
    """
    if global_model_override:
        raw_model = global_model_override
    elif os.environ.get("MANTIS_MODEL"):
        raw_model = os.environ.get("MANTIS_MODEL")
    else:
        raw_model = model_id or os.environ.get("MODEL_ID") or default_model
    return normalize_model_id(raw_model)


def get_llm_kwargs(
    model_id: Optional[str] = None,
    default_model: str = DEFAULT_MODEL,
    api_base: Optional[str] = None,
    default_api_base: Optional[str] = None,
    timeout: Optional[float] = None,
    default_timeout: Optional[float] = None,
    reasoning_effort: Optional[str] = None,
    default_reasoning_effort: Optional[str] = None,
    global_model_override: Optional[str] = None,
    config: Optional[dict] = None,
    *,
    explicit_reasoning_effort: bool = False,
) -> Tuple[str, dict]:
    """Resolves the LLM mapping details cleanly with precedence: global_override > MANTIS_MODEL > node > MODEL_ID > default."""
    validate_llm_env_vars()
    resolved_model = resolve_model_id(model_id, default_model, global_model_override)
    resolved_api_base = api_base or os.environ.get("LLM_API_BASE") or default_api_base
    env_timeout = _parse_env_number(
        ("LLM_TIMEOUT", "MANTIS_TIMEOUT", "LLM_REQUEST_TIMEOUT"), min_val=0.001
    )
    raw_timeout = timeout if timeout is not None else (
        env_timeout if env_timeout is not None else default_timeout
    )
    env_reasoning_effort = (os.environ.get("REASONING_EFFORT") or "").strip() or None
    effort = reasoning_effort or env_reasoning_effort or default_reasoning_effort
    if raw_timeout is None:
        raw_timeout = default_request_timeout(resolved_model, effort)

    llm_kwargs = {"model": resolved_model}
    if resolved_api_base:
        llm_kwargs["api_base"] = resolved_api_base
    if effort:
        clean_effort = str(effort).lower().strip()
        if not is_claude_model(resolved_model) and clean_effort in ("xhigh", "max"):
            # Non-Claude providers (e.g. Gemini) top out at "high"; clamp
            # "xhigh"/"max" so high-depth profiles degrade gracefully instead
            # of triggering UnsupportedParamsError.
            clean_effort = "high"
        llm_kwargs["reasoning_effort"] = clean_effort
        if not is_claude_model(resolved_model) and (
            is_versioned_reasoning_model(resolved_model)
            or explicit_reasoning_effort
            or bool(env_reasoning_effort)
        ):
            llm_kwargs["allowed_openai_params"] = ["reasoning_effort"]
    if raw_timeout is not None:
        try:
            timeout_val = float(raw_timeout)
            if timeout_val > 0:
                llm_kwargs["timeout"] = timeout_val
        except (ValueError, TypeError) as exc:
            raise ConfigValidationError(f"Invalid timeout value {raw_timeout!r}.") from exc

    env_max_tokens = _parse_env_number(("LLM_MAX_TOKENS", "MANTIS_MAX_TOKENS"), as_int=True, min_val=1)
    if env_max_tokens is not None:
        llm_kwargs["max_tokens"] = int(env_max_tokens)
    else:
        # The most the model allows (resolve_output_ceiling): thinking
        # shares the output budget, and a turn that reaches the ceiling
        # ends with MAX_TOKENS and fails its stage. None leaves the
        # provider's own default in place.
        ceiling = resolve_output_ceiling(resolved_model)
        if ceiling:
            llm_kwargs.setdefault("max_tokens", ceiling)

    if resolved_model.startswith("vertex_ai/"):
        project = os.environ.get("VERTEXAI_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
        if is_placeholder(project):
            project = None

        if not project and config and isinstance(config, dict):
            cfg_proj = config.get("project")
            if not cfg_proj or is_placeholder(cfg_proj):
                sb = config.get("sandbox")
                if isinstance(sb, dict):
                    sb_opts = sb.get("options")
                    if isinstance(sb_opts, dict):
                        cfg_proj = sb_opts.get("project")
            if cfg_proj and not is_placeholder(cfg_proj):
                project = str(cfg_proj)

        location = os.environ.get("VERTEXAI_LOCATION") or os.environ.get("GOOGLE_CLOUD_LOCATION") or "global"

        if not project:
            try:
                import google.auth
                _, project = google.auth.default()
                if is_placeholder(project):
                    project = None
            except Exception:
                pass

        if not project and not resolved_api_base:
            raise ValueError("ERROR: You must set VERTEXAI_PROJECT or GOOGLE_CLOUD_PROJECT env variables.")

        if project:
            llm_kwargs["vertex_project"] = project
            llm_kwargs["vertex_location"] = location

        if (
            os.environ.get("VERTEX_FLEX") in ("1", "true", "True")
            or os.environ.get("VERTEXAI_SERVICE_TIER", "").lower() == "flex"
            or (isinstance(config, Mapping) and bool(config.get("flex")))
        ):
            headers = dict(llm_kwargs.get("extra_headers") or {})
            headers["X-Vertex-AI-LLM-Request-Type"] = "shared"
            headers["X-Vertex-AI-LLM-Shared-Request-Type"] = "flex"
            llm_kwargs["extra_headers"] = headers
            if timeout is None and env_timeout is None and default_timeout is None:
                llm_kwargs["timeout"] = max(float(llm_kwargs.get("timeout") or 0.0), 600.0)

    # Relax the category filters for Gemini models, which sometimes trigger on
    # defensive security analysis and vulnerability remediation. Applied on
    # every route that reaches a Gemini model natively (vertex_ai/ and
    # gemini/), not only Vertex: the Gemini API route used to run with the
    # provider defaults, so the same prompt could be filtered through an API
    # key and pass through a project. Keyed on the provider prefix, not on
    # the substring "gemini": a Gemini model behind an OpenAI-compatible
    # gateway (openai/gemini-*) takes OpenAI parameters, and litellm rejects
    # this one there. The litellm global stays Vertex-scoped; it only exists
    # for callers that bypass these kwargs.
    # Prompt caching is per provider. Claude caches a prefix the request
    # marks, and ADK marks it when the app runs with context caching on.
    # ADK marks every model the same way, and for a Gemini model LiteLLM
    # turns the marks into Vertex explicit caching: a cachedContents entry
    # per distinct prefix, billed for its lifetime, and refused outright
    # when the prefix is under the model's minimum (measured: a 1,976-token
    # deduplicator prompt against a 4,096 minimum failed the stage with a
    # 400). Gemini caches prefixes implicitly without any of that, and
    # OpenAI caches automatically, so for both the request names no
    # injection points, which ADK honours as the caller's choice.
    if "claude" not in resolved_model:
        llm_kwargs.setdefault("cache_control_injection_points", [])

    if resolved_model.startswith(("gemini/", "vertex_ai/")) and "gemini" in resolved_model:
        safety_settings = [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
        ]
        llm_kwargs["safety_settings"] = safety_settings
        if resolved_model.startswith("vertex_ai/"):
            try:
                import litellm
                litellm.vertex_ai_safety_settings = safety_settings
            except Exception:
                pass

    # Anthropic server-side context editing, only on routes whose upstream
    # adapter forwards `clear_tool_uses_20250919` (`anthropic/`, `vertex_ai/claude*`).
    editing = (
        anthropic_context_editing(resolved_model, config=config)
        if supports_server_clear_tool_uses(resolved_model)
        else None
    )
    if editing:
        llm_kwargs["context_management"] = editing

    return resolved_model, llm_kwargs


def get_run_llm_kwargs(
    model_id: Optional[str] = None,
    config: Optional[Mapping[str, Any]] = None,
    *,
    api_base: Optional[str] = None,
    timeout: Optional[float] = None,
    reasoning_effort: Optional[str] = None,
    global_model_override: Optional[str] = None,
) -> Tuple[str, dict]:
    """Resolves `get_llm_kwargs` for auxiliary run-level LLM clients (planner,
    mid-run replanner, session compactor) so they inherit `--api-base`,
    `--timeout`, `--reasoning-effort`, and `--flex` headers identically to
    graph agent nodes."""
    cfg = dict(config) if isinstance(config, Mapping) else {}
    eff_api_base = api_base or cfg.get("_cli_api_base") or None
    eff_timeout = timeout if timeout is not None else cfg.get("_cli_timeout")
    eff_effort = (
        reasoning_effort
        or cfg.get("_cli_reasoning_effort")
        or cfg.get("_local_reasoning_effort")
        or None
    )
    return get_llm_kwargs(
        model_id=model_id,
        default_model=str(cfg.get("default_model") or DEFAULT_MODEL),
        api_base=eff_api_base,
        default_api_base=cfg.get("api_base"),
        timeout=eff_timeout,
        default_timeout=cfg.get("timeout"),
        reasoning_effort=eff_effort,
        default_reasoning_effort=cfg.get("reasoning_effort"),
        global_model_override=global_model_override or cfg.get("_cli_model_override"),
        config=cfg,
        explicit_reasoning_effort=bool(reasoning_effort or cfg.get("_cli_reasoning_effort")),
    )


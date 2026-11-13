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

"""Resource Budgeting, Step Counting, and Zero-Loss Resumption Engine.

Provides:
1. RUN-level ceilings: 12-hour wall-clock and 10M token budget. These are the
   real spend limits and accumulate across every campaign in the run.
   Setting either to 0 (accepted spellings: "0", "unlimited", "none", "off")
   disables that ceiling entirely -- for operators with dedicated hardware or
   budgets that make a token cap meaningless. The campaign-level runaway-loop
   guards below stay active even then, because a wedged loop produces zero
   findings at ANY budget; each of them also honours 0 = disabled individually.
2. CAMPAIGN-level runaway-loop guards: 500 graph steps, 50 visits per node,
   2,000 LLM calls, and 200 tool calls per node visit. These exist to stop a
   single campaign that has wedged itself in a loop, so they reset at each
   campaign boundary via begin_campaign(). Measured live: a campaign costs
   exactly 16 graph steps, so enforcing the 500-step guard cumulatively paused
   a multi-campaign run every ~31 campaigns -- a full juice-shop sweep
   (~1,168 campaigns) would have needed ~37 manual resumes for no protective
   benefit at all.
3. Cycle-safe classifier loop counters.
4. Graceful budget pause handling and state checkpointing.
5. One-line copy-pasteable --resume banner formatting.
"""

from __future__ import annotations

import dataclasses
import datetime
import logging
import re
import sys
import time
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional

# Suppress spurious OpenTelemetry context-detach tracebacks caused by contextvars
# isolation when an async generator pauses or cancels mid-stream (most visible on
# Python 3.14; the filter is harmless on older supported versions).
class _OTelContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return "Failed to detach context" not in record.getMessage()

logging.getLogger("opentelemetry.context").addFilter(_OTelContextFilter())

# Suppress noisy ADK preview/experimental feature notices
warnings.filterwarnings("ignore", message=r".*\[EXPERIMENTAL\].*")


def parse_duration_seconds(val: Any) -> float:
    """Parses duration strings like '1d', '12h', '30m', '3600s', '1.5h' or raw numbers into seconds."""
    if val is None:
        raise ValueError("Duration cannot be None")
    if isinstance(val, (int, float)):
        if val < 0:
            raise ValueError(f"Duration cannot be negative: {val}")
        return float(val)
    clean = str(val).strip().lower()
    if not clean:
        raise ValueError("Duration string cannot be empty")
    # 0 = ceiling disabled; these spellings exist so an operator can say what
    # they mean instead of knowing the sentinel convention.
    if clean in ("unlimited", "none", "off"):
        return 0.0
    m = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([dhms]|days?|hours?|mins?|minutes?|secs?|seconds?)?$", clean)
    if m:
        num = float(m.group(1))
        unit = (m.group(2) or "s").lower()
        if unit.startswith("d"):
            return num * 86400.0
        elif unit.startswith("h"):
            return num * 3600.0
        elif unit.startswith("m"):
            return num * 60.0
        elif unit.startswith("s"):
            return num
    try:
        num = float(clean)
        if num < 0:
            raise ValueError(f"Duration cannot be negative: {num}")
        return num
    except (ValueError, TypeError):
        raise ValueError(
            f"Invalid duration format: '{val}'. Expected format like '1d', '12h', '30m', '3600s' or raw seconds."
        ) from None


def parse_token_budget(val: Any) -> int:
    """Parses token strings like '1B', '10M', '500k', '10000000' or raw integers into tokens."""
    if val is None:
        raise ValueError("Token budget cannot be None")
    if isinstance(val, (int, float)):
        if val < 0:
            raise ValueError(f"Token budget cannot be negative: {val}")
        return int(val)
    clean = str(val).strip().lower()
    if not clean:
        raise ValueError("Token budget string cannot be empty")
    # 0 = ceiling disabled; same operator-facing spellings as durations.
    if clean in ("unlimited", "none", "off"):
        return 0
    m = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([bkmg]|billion|million|thousand)?$", clean)
    if m:
        num = float(m.group(1))
        unit = (m.group(2) or "").lower()
        if unit in ("b", "g", "billion"):
            return int(num * 1_000_000_000)
        elif unit in ("m", "million"):
            return int(num * 1_000_000)
        elif unit in ("k", "thousand"):
            return int(num * 1_000)
        elif not unit:
            return int(num)
    try:
        num = int(clean)
        if num < 0:
            raise ValueError(f"Token budget cannot be negative: {num}")
        return num
    except (ValueError, TypeError):
        raise ValueError(
            f"Invalid token budget format: '{val}'. Expected format like '1B', '10M', '500k' or raw integer."
        ) from None


@dataclasses.dataclass
class BudgetConfig:
    """Configurable execution budget limits."""
    max_wall_clock_seconds: float = 12.0 * 3600.0  # 12.0 hours
    max_tokens: int = 10_000_000                  # 10M token ceiling
    max_graph_steps: int = 500                    # 500 step loop ceiling
    max_node_visits: int = 50                     # Per-node runaway loop ceiling
    max_llm_calls: int = 2000                     # Global LLM call ceiling (2,000 default)
    max_node_tool_calls: int = 200                # Per-node visit runaway tool loop ceiling (200 default)
    # Weight of a cached input token against max_tokens. 0.1 matches the
    # discount providers give for a cache hit; 1.0 counts every token at
    # full price, which is what a run that must bound its worst-case bill
    # wants: a ceiling on effective tokens bounds raw tokens only when the
    # two are the same number.
    cache_discount: float = 0.1

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> BudgetConfig:
        raw_seconds = d.get("max_wall_clock_seconds")
        if raw_seconds is None:
            raw_seconds = d.get("max_time")
        raw_tokens = d.get("max_tokens")
        if raw_tokens is None:
            raw_tokens = d.get("token_budget")
        raw_steps = d.get("max_graph_steps")
        if raw_steps is None:
            raw_steps = d.get("max_steps")
        raw_node_visits = d.get("max_node_visits")
        raw_llm_calls = d.get("max_llm_calls")
        raw_node_tool_calls = d.get("max_node_tool_calls")
        if raw_node_tool_calls is None:
            raw_node_tool_calls = d.get("max_tool_calls")
        raw_discount = d.get("cache_discount")

        return cls(
            max_wall_clock_seconds=parse_duration_seconds(raw_seconds) if raw_seconds is not None else 12.0 * 3600.0,
            max_tokens=parse_token_budget(raw_tokens) if raw_tokens is not None else 10_000_000,
            max_graph_steps=int(raw_steps) if raw_steps is not None else 500,
            max_node_visits=int(raw_node_visits) if raw_node_visits is not None else 50,
            max_llm_calls=int(raw_llm_calls) if raw_llm_calls is not None else 2000,
            max_node_tool_calls=int(raw_node_tool_calls) if raw_node_tool_calls is not None else 200,
            cache_discount=clamp_cache_discount(raw_discount) if raw_discount is not None else 0.1,
        )


def clamp_cache_discount(val: Any) -> float:
    """A cache discount is a weight in [0, 1]; anything else is a configuration error."""
    try:
        f = float(val)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid cache_discount: {val!r}. Expected a number between 0 and 1.") from None
    if not (0.0 <= f <= 1.0):
        raise ValueError(f"Invalid cache_discount: {val!r}. Expected a number between 0 and 1.")
    return f


#: How the run kept within the model window, counted where it happened.
#: Every key appears in the spend report's "context" block, zero or not.
CONTEXT_OBSERVATIONS = (
    # A stage reached its context ceiling and went on in a fresh context from
    # a model-written handoff (core.graph_loader).
    "continuations",
    # A stage reached the ceiling with no continuation left and was ended
    # with its recorded work in place / failed because its output schema
    # could not be satisfied synthetically.
    "ceiling_ends",
    "ceiling_failures",
    # A tool result was cut to the stage's remaining headroom before it was
    # appended.
    "tool_result_cuts",
    # ADK compaction events seen (off by default; nonzero means it ran).
    "compactions",
    # A resumed campaign whose history no longer fit was started over.
    "overflow_restarts",
    # Requests sent with the provider's context editing (Anthropic
    # clear_tool_uses); edits the provider reports applying; the input
    # tokens those edits cleared.
    "context_edit_requests",
    "context_edits_applied",
    "context_edit_cleared_tokens",
    # Requests a forked stage sent with its parent's transcript in front
    # (core.graph_loader fork_from).
    "forked_requests",
)

#: Request-level events: how often a call had to be retried, and why, and
#: how often a stage ended on a model that kept answering with nothing.
REQUEST_OBSERVATIONS = (
    "retries",
    "rate_limit_retries",
    "auth_refreshes",
    "empty_turn_ends",
    "thinking_continuations",
)


def observe(name: str, n: int = 1) -> None:
    """Counts an event on the current run's controller, from anywhere in the
    process. No controller (a test, a tool run outside a campaign): nothing.
    Never raises."""
    try:
        from core.context import current_run_context

        ctx = current_run_context.get()
        controller = getattr(ctx, "budget_controller", None) if ctx is not None else None
        if controller is not None and hasattr(controller, "observe"):
            controller.observe(name, n)
    except Exception:
        pass


def render_spend_summary(snapshot: Dict[str, Any]) -> list:
    """The spend report as lines for the end-of-run console: tokens with the
    cache share, calls, and whichever context/request counters are nonzero.
    Counts only, no repository bytes."""
    lines: list = []
    try:
        prompt = int(snapshot.get("prompt_tokens") or 0)
        output = int(snapshot.get("output_tokens") or 0)
        cached = int(snapshot.get("cached_tokens") or 0)
        calls = int(snapshot.get("llm_calls") or 0)
        ratio = snapshot.get("cache_hit_ratio")
        if prompt > 0:
            share = f" ({ratio * 100:.0f}% read from the prompt cache)" if ratio is not None else ""
            lines.append(f"{prompt:,} input tokens{share}, {output:,} output tokens, {calls:,} LLM call(s)")
        else:
            total = int(snapshot.get("fresh_tokens") or 0) + cached
            lines.append(f"{total:,} tokens ({cached:,} cached), {calls:,} LLM call(s)")
        labels = {
            "continuations": "stage continuation(s)",
            "ceiling_ends": "stage(s) ended at the context ceiling",
            "ceiling_failures": "stage(s) failed at the context ceiling",
            "tool_result_cuts": "tool result(s) cut to fit",
            "compactions": "compaction(s)",
            "overflow_restarts": "resumed campaign(s) started over",
            "context_edit_requests": "request(s) with context editing",
            "context_edits_applied": "context edit(s) applied",
            "forked_requests": "request(s) on a forked transcript",
            "retries": "retried request(s)",
            "rate_limit_retries": "rate-limit retry(ies)",
            "auth_refreshes": "credential refresh(es)",
            "empty_turn_ends": "stage(s) ended on empty model turns",
            "thinking_continuations": "turn(s) continued past a thinking segment",
        }
        counters = dict(snapshot.get("context") or {})
        counters.update(snapshot.get("requests") or {})
        parts = [f"{int(v):,} {labels[k]}" for k, v in counters.items() if k in labels and int(v or 0) > 0]
        cleared = int(counters.get("context_edit_cleared_tokens") or 0)
        if cleared > 0:
            parts.append(f"{cleared:,} input tokens cleared by context editing")
        if parts:
            lines.append("Context: " + "; ".join(parts) + ".")
    except Exception:
        return lines
    return lines


class BudgetExceededError(Exception):
    """Raised when an execution exceeds its allocated wall-clock time, token, or step budget."""

    def __init__(
        self,
        trigger: str,
        current_value: Any,
        limit_value: Any,
        run_id: str,
        details: str = "",
    ):
        self.trigger = trigger
        self.current_value = current_value
        self.limit_value = limit_value
        self.run_id = run_id
        self.details = details
        msg = f"Budget limit exceeded [{trigger}]: {current_value} >= {limit_value} (Run ID: {run_id})"
        super().__init__(msg)


class BudgetController:
    """Tracks token consumption, step counts, and wall-clock execution limits."""

    def __init__(
        self,
        config: Optional[BudgetConfig] = None,
        run_id: str = "",
        initial_tokens: int = 0,
        initial_steps: int = 0,
        start_time: Optional[float] = None,
    ):
        self.config = config or BudgetConfig()
        self.run_id = run_id
        self.accumulated_tokens = initial_tokens
        # Usage-bearing LLM responses seen. Counted where tokens are counted, at
        # the same granularity, so the spend ledger's llm_calls column describes
        # the same events as its tokens column. Not a ceiling: max_llm_calls is
        # enforced by the ADK RunConfig, this merely observes.
        self.llm_calls = 0
        self.cached_tokens = 0
        self.fresh_tokens = initial_tokens
        # CUMULATIVE step count for the whole run. Never reset: main.py's spend
        # ledger computes each campaign's cost as the delta of this counter
        # either side of the campaign (steps_before / after), so resetting it
        # here would make those deltas go negative. The ceiling below is NOT
        # checked against this counter -- see campaign_graph_steps.
        self.graph_steps = initial_steps
        # CUMULATIVE count of code-reading tool calls made by AUDIT_NODES.
        # Never reset: like graph_steps above, the scan loop reads a
        # campaign's figure as the delta either side of the campaign, so
        # zeroing this in begin_campaign() would break that arithmetic. A
        # resumed run reconstructs the controller fresh and the count
        # restarts at zero, which is safe for the same reason the ledger
        # deltas are: every consumer snapshots its own before-value at a
        # campaign boundary.
        self.audit_code_reads = 0
        # Input and output split of the usage-bearing responses, so the spend
        # report can say what share of the input came from the provider's
        # prompt cache (cached_tokens / prompt_tokens). `fresh_tokens` cannot:
        # it holds the output too.
        self.prompt_tokens = 0
        self.output_tokens = 0
        # Context-management and request events, counted where they happen
        # (continuations, ceiling stops, tool-result cuts, compactions, context
        # edits, retries): the run's own account of how it kept within the
        # model window, readable from the spend report instead of the
        # sessions database. Keys are OBSERVATION_KEYS; unknown keys are kept
        # too, under "other".
        self.observations: Dict[str, int] = {}
        self.start_time = start_time or time.time()
        # ---- Per-CAMPAIGN runaway-loop guards ------------------------------
        # These counters answer "is THIS campaign stuck in a loop?", not "how
        # much has the run spent?" -- that is the wall-clock and token job
        # above. Enforcing them cumulatively turned every guard into a de facto
        # run ceiling: at a measured 16 graph steps per campaign, the 500-step
        # guard paused a sweep every ~31 campaigns, and a single campaign
        # measured at 160 LLM calls would trip a cumulative 2,000-call guard
        # after ~12. begin_campaign() zeroes them at each campaign boundary.
        #
        # INV-5/INV-6 (fail-safe resumption): a resumed run reconstructs this
        # controller fresh, so per-campaign counters start at zero -- which is
        # exactly right, because --resume always lands on a campaign boundary
        # and the scan loop calls begin_campaign() before any work. A
        # checkpoint written before these fields existed therefore loads and
        # behaves identically: missing per-campaign state IS zero.
        self.campaign_graph_steps = 0
        self.campaign_llm_calls = 0
        self.node_visit_counts: Dict[str, int] = {}
        self.node_tool_counts: Dict[str, int] = {}
        self.is_paused = False
        # Which ceiling paused the run, if one did ("token_budget",
        # "llm_calls_limit", "wall_clock", ...). Set by check_budget() for the
        # ceilings it owns and by the scan loop for the ones ADK raises.
        self.pause_trigger = ""

    def spend_snapshot(self) -> Dict[str, Any]:
        """The run's spend so far, in the terms the ceilings use.

        `tokens` is what max_tokens was checked against (cached input weighted
        by cache_discount); `fresh_tokens + cached_tokens` is the raw count a
        provider bills before any discount. A caller that must bound the bill
        wants the raw sum, or runs with cache_discount=1.0 so the two agree.
        `cache_hit_ratio` is cached_tokens / prompt_tokens (None before any
        input was metered); `context` and `requests` are the observation
        counters, every key present so a reader can rely on the shape.
        """
        return {
            "run_id": self.run_id,
            "tokens": int(self.accumulated_tokens),
            "fresh_tokens": int(self.fresh_tokens),
            "cached_tokens": int(self.cached_tokens),
            "prompt_tokens": int(self.prompt_tokens),
            "output_tokens": int(self.output_tokens),
            "cache_hit_ratio": (round(self.cached_tokens / self.prompt_tokens, 4)
                                if self.prompt_tokens > 0 else None),
            "cache_discount": float(self.config.cache_discount),
            "llm_calls": int(self.llm_calls),
            "graph_steps": int(self.graph_steps),
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "max_tokens": int(self.config.max_tokens),
            "max_llm_calls": int(self.config.max_llm_calls),
            "pause_trigger": self.pause_trigger,
            "context": {k: int(self.observations.get(k, 0)) for k in CONTEXT_OBSERVATIONS},
            "requests": {k: int(self.observations.get(k, 0)) for k in REQUEST_OBSERVATIONS},
            "other": {k: int(v) for k, v in sorted(self.observations.items())
                      if k not in CONTEXT_OBSERVATIONS and k not in REQUEST_OBSERVATIONS},
        }

    def observe(self, name: str, n: int = 1) -> None:
        """Counts one kind of event `n` more times. Never raises, never
        enforces: these are the run's notes to its operator."""
        try:
            key = str(name or "").strip()
            if not key:
                return
            self.observations[key] = int(self.observations.get(key, 0)) + int(n)
        except (TypeError, ValueError):
            pass

    def begin_campaign(self) -> None:
        """Resets the per-campaign runaway-loop counters at a campaign boundary.

        Called by the scan loop at the top of each campaign iteration, BEFORE
        the ledger's before-counters are captured. Deliberately does NOT touch
        the run-level state: accumulated_tokens, fresh/cached token splits,
        llm_calls, graph_steps and start_time keep accumulating, because the
        spend ledger derives per-campaign deltas from those cumulative values
        and the wall-clock/token ceilings are the genuine run budget.

        Fail-closed note: forgetting to call this makes the guards revert to
        the old cumulative behaviour -- a spurious pause, never a runaway.
        """
        self.campaign_graph_steps = 0
        self.campaign_llm_calls = 0
        # Node visit and per-visit tool counters are loop detectors scoped to a
        # single campaign's graph traversal. Clearing the visit counts also
        # resets the visit-index component of the node_tool_counts keys, so the
        # dict is cleared with it to keep the two in step.
        self.node_visit_counts = {}
        self.node_tool_counts = {}

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time

    @property
    def elapsed_formatted(self) -> str:
        seconds = int(self.elapsed_seconds)
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        if hours > 0:
            return f"{hours}h {minutes:02d}m {secs:02d}s"
        return f"{minutes}m {secs:02d}s"

    def record_tokens(self, count: int, cached_count: int = 0,
                      cache_discount: Optional[float] = None,
                      prompt_count: int = 0, output_count: int = 0) -> None:
        """Records token consumption from an LLM call or stage. Cached input
        tokens are weighted by `cache_discount` (the config's when omitted:
        0.1 by default, a 90% discount, matching a provider's cache-hit price).
        `prompt_count` / `output_count` split the same call's usage for the
        spend report; they do not change what the budget is charged."""
        self.llm_calls += 1
        # Per-campaign twin of the observer above, reset by begin_campaign().
        # Enforcement of max_llm_calls stays with the ADK RunConfig, which is
        # handed to each campaign's run_async separately and is therefore
        # already per-campaign scoped; this counter exists so the controller
        # can report how deep into ITS campaign allowance a campaign got.
        self.campaign_llm_calls += 1
        self.prompt_tokens += max(0, int(prompt_count or 0))
        self.output_tokens += max(0, int(output_count or 0))
        if count <= 0:
            return
        if cache_discount is None:
            cache_discount = self.config.cache_discount
        if cached_count > 0:
            uncached = max(0, count - cached_count)
            effective = int(uncached + cached_count * cache_discount)
            self.cached_tokens += cached_count
            self.fresh_tokens += uncached
            self.accumulated_tokens += effective
        else:
            self.fresh_tokens += count
            self.accumulated_tokens += count
        self.check_budget()

    def record_tool_call(
        self, node_name: str = "", tool_name: str = "", *, in_scope: bool = True
    ) -> None:
        """Records a tool call executed by an agent node and enforces the per-node tool ceiling."""
        clean_node = node_name.split("/")[-1].split("@")[0] if node_name else "unknown"
        if clean_node in AUDIT_NODES and tool_name in CODE_READ_TOOLS and in_scope:
            self.audit_code_reads += 1
        visit_idx = self.node_visit_counts.get(clean_node, 1)
        key = f"{clean_node}@{visit_idx}"
        self.node_tool_counts[key] = self.node_tool_counts.get(key, 0) + 1
        if (
            self.config.max_node_tool_calls > 0
            and self.node_tool_counts[key] > self.config.max_node_tool_calls
        ):
            self.is_paused = True
            raise BudgetExceededError(
                trigger="node_tool_calls_ceiling",
                current_value=self.node_tool_counts[key],
                limit_value=self.config.max_node_tool_calls,
                run_id=self.run_id,
                details=(
                    f"Node '{clean_node}' (visit {visit_idx}) exceeded max tool calls limit of "
                    f"{self.config.max_node_tool_calls} (latest call: {tool_name or 'unknown'})"
                ),
            )

    def record_step(self, node_name: str = "") -> None:
        """Records execution of a graph node step.

        Increments BOTH step counters: `graph_steps` (cumulative, feeds the
        spend ledger's per-campaign deltas in main.py) and
        `campaign_graph_steps` (per-campaign, the one the runaway-loop ceiling
        in check_budget() is enforced against).
        """
        self.graph_steps += 1
        self.campaign_graph_steps += 1
        if node_name:
            self.node_visit_counts[node_name] = self.node_visit_counts.get(node_name, 0) + 1
            if self.config.max_node_visits > 0 and self.node_visit_counts[node_name] > self.config.max_node_visits:
                raise BudgetExceededError(
                    trigger="node_visits_ceiling",
                    current_value=self.node_visit_counts[node_name],
                    limit_value=self.config.max_node_visits,
                    run_id=self.run_id,
                    details=f"Node '{node_name}' exceeded max visits limit of {self.config.max_node_visits}",
                )
        self.check_budget()

    def check_budget(self) -> None:
        """Evaluates all budget dimensions and raises BudgetExceededError if any threshold is hit.

        A ceiling of 0 means that dimension is DISABLED, not "pause instantly":
        without the > 0 guards below, `anything >= 0` is always true and a
        zeroed ceiling would trip on the very first check.
        """
        # 1. Wall-clock limit (RUN-level: this is a real budget, never reset)
        if self.config.max_wall_clock_seconds > 0 and self.elapsed_seconds >= self.config.max_wall_clock_seconds:
            self.is_paused = True
            raise BudgetExceededError(
                trigger="wall_clock",
                current_value=f"{self.elapsed_seconds:.1f}s",
                limit_value=f"{self.config.max_wall_clock_seconds:.1f}s",
                run_id=self.run_id,
                details=f"Elapsed time {self.elapsed_formatted} reached ceiling of {self.config.max_wall_clock_seconds / 3600:.1f}h",
            )

        # 2. Token ceiling (RUN-level: this is a real budget, never reset)
        if self.config.max_tokens > 0 and self.accumulated_tokens >= self.config.max_tokens:
            self.is_paused = True
            raise BudgetExceededError(
                trigger="token_budget",
                current_value=self.accumulated_tokens,
                limit_value=self.config.max_tokens,
                run_id=self.run_id,
                details=f"Accumulated tokens {self.accumulated_tokens:,} reached ceiling of {self.config.max_tokens:,}",
            )

        # 3. Graph step ceiling -- a CAMPAIGN-level runaway-loop guard, checked
        # against campaign_graph_steps rather than the cumulative graph_steps.
        # Checked cumulatively this stopped being a loop guard and became an
        # accidental run ceiling: measured live, every campaign costs exactly
        # 16 graph steps, so 500 cumulative steps paused a file-by-file sweep
        # every ~31 campaigns and a full juice-shop sweep (~1,168 campaigns)
        # would have needed ~37 manual resumes. A campaign that legitimately
        # loops still hits 500 within its own boundary and pauses, so the
        # protection is intact; only the false positives are gone. The trigger
        # name stays "graph_steps" so existing pause-handling and resume
        # tooling keyed on it keep working. A ceiling of 0 disables this guard
        # (checked here, above the comparison, so the comparison line itself
        # stays byte-identical for the neuter-matrix anchor that pins it).
        if self.config.max_graph_steps <= 0:
            return
        if self.campaign_graph_steps >= self.config.max_graph_steps:
            self.is_paused = True
            raise BudgetExceededError(
                trigger="graph_steps",
                current_value=self.campaign_graph_steps,
                limit_value=self.config.max_graph_steps,
                run_id=self.run_id,
                details=(
                    f"Campaign graph step count {self.campaign_graph_steps} reached ceiling of "
                    f"{self.config.max_graph_steps} ({self.graph_steps} steps total this run)"
                ),
            )

    def format_pause_banner(
        self,
        trigger: str,
        progress_summary: str = "",
        saved_recipe_path: str = "",
        target: str = "",
        workflow: str = "",
        resume_flags: "dict | None" = None,
    ) -> str:
        """Formats a clear, human-readable terminal pause banner with resume instructions."""
        token_limit = f"{self.config.max_tokens:,} limit" if self.config.max_tokens > 0 else "unlimited"
        if self.cached_tokens > 0:
            token_str = (
                f"{self.accumulated_tokens:,} effective / {token_limit} "
                f"({self.fresh_tokens:,} fresh + {self.cached_tokens:,} cached @ 0.1x)"
            )
        else:
            token_str = f"{self.accumulated_tokens:,} / {token_limit}"

        clean_trigger = " ".join(str(trigger).split())
        wall_limit = (
            f"{self.config.max_wall_clock_seconds / 3600:.1f}h limit"
            if self.config.max_wall_clock_seconds > 0
            else "unlimited"
        )
        step_limit = (
            f"{self.config.max_graph_steps} limit"
            if self.config.max_graph_steps > 0
            else "unlimited"
        )
        lines = [
            "=" * 80,
            " ⏸️  [BUDGET PAUSE] Mantis execution paused gracefully at budget ceiling",
            "=" * 80,
            f"  • Trigger:          {clean_trigger}",
            f"  • Run ID:           {self.run_id}",
            f"  • Wall-Clock Time:  {self.elapsed_formatted} / {wall_limit}",
            f"  • Token Usage:      {token_str}",
            # The step limit is per CAMPAIGN (a runaway-loop guard), so it is
            # rendered against the campaign counter; printing the run total
            # against a per-campaign limit would misstate how close the run is
            # to pausing by whatever the sweep has accumulated so far.
            f"  • Graph Steps:      {self.campaign_graph_steps} / {step_limit} "
            f"this campaign ({self.graph_steps} total this run)",
        ]
        if self.config.max_llm_calls > 0:
            lines.append(f"  • LLM Calls Limit:  {self.config.max_llm_calls}")
        if self.config.max_node_tool_calls > 0:
            lines.append(f"  • Node Tool Calls:  {self.config.max_node_tool_calls} limit / visit")
        if target:
            lines.append(f"  • Target:           {target}")
        if progress_summary:
            lines.append(f"  • Progress:         {progress_summary}")
        if saved_recipe_path:
            lines.append(f"  • Saved Recipe:     {saved_recipe_path}")

        import shlex

        from core.llm_gateway import strip_terminal_control
        from core.paths import install_root

        # SECURITY (INV-4): this banner is a copy-paste *executable* handed to an operator
        # or a coding agent. Probing $CWD for ./run.sh or scripts/launch.py is a code
        # execution primitive, because a campaign is normally launched from inside the
        # untrusted checkout and SKILL.md tells the reader to run whatever this prints.
        # Resolve the launcher from the installation only, and emit absolute, quoted paths
        # so no token in the command re-resolves against the attacker's directory later.
        launcher = install_root() / "run.sh"
        if launcher.is_file():
            base_launcher = shlex.quote(str(launcher))
        else:
            base_launcher = f"python3 {shlex.quote(str(install_root() / 'scripts' / 'launch.py'))}"

        parts = [base_launcher]
        if target:
            parts.append(shlex.quote(str(Path(target).resolve())))
        parts.append(f"--resume {shlex.quote(str(self.run_id))}")
        parts.append("--max-time 24h --token-budget 20M")
        if self.config.max_llm_calls > 0:
            parts.append(f"--max-llm-calls {self.config.max_llm_calls * 2}")
        if self.config.max_node_tool_calls > 0:
            parts.append(f"--max-node-tool-calls {self.config.max_node_tool_calls * 2}")
        # One-shot CLI overrides (--db, --model, ...) are deliberately NOT
        # persisted to workflow.local.json, so the resume command must carry
        # them itself: a paste that omits --db resumes against the configured
        # default database, not the one this run actually wrote to. Values
        # ride in from the operator's command line but pass through config
        # handling, so they are quoted like every other token.
        for flag, value in (resume_flags or {}).items():
            parts.append(f"{flag} {shlex.quote(str(value))}")
        if workflow:
            parts.append(f"--workflow {shlex.quote(str(Path(workflow).resolve()))}")
        resume_cmd = " ".join(parts)

        lines.extend([
            "",
            "💡 To resume execution right from this checkpoint with increased budget:",
            f"   {resume_cmd}",
            "=" * 80,
        ])
        # Findings text, target paths and recipe names reach this banner from untrusted
        # content; a terminal escape here repaints the command the operator is about to run.
        return strip_terminal_control("\n".join(lines))


class CampaignBudgetScope(BudgetController):
    """A per-campaign view over a shared run-level BudgetController.

    Exists for parallel campaign execution. The sequential loop shared ONE
    controller and derived each campaign's cost as before/after deltas of the
    cumulative counters. With N campaigns in flight that arithmetic charges one
    campaign with its siblings' spend, and each campaign's begin_campaign()
    zeroes the runaway-loop guards out from under every other one.

    The scope splits the two concerns the way the counters were always
    documented (see BudgetController.__init__):

    - RUN-level spend (accumulated/fresh/cached tokens, llm_calls, graph_steps)
      is mirrored into the shared parent on every record, so the genuine run
      budget -- wall clock and tokens -- is enforced against what ALL campaigns
      spent together. check_budget() delegates those two ceilings to the
      parent.
    - CAMPAIGN-level guards (campaign_graph_steps, campaign_llm_calls,
      node_visit_counts, node_tool_counts) live in this scope's own counters,
      inherited unchanged from BudgetController, so a guard sized for one
      campaign is charged with exactly one campaign.

    Because this scope's own cumulative counters start at zero, the scan
    loop's existing delta arithmetic (tokens_before etc.) is exact per
    campaign with no changes: siblings never move this scope's counters.

    INV-6 (fail-safe): with one worker this is behaviourally identical to the
    sequential controller -- same ceilings, same triggers, same banner -- and
    resume checkpoints keep reading the parent's run-level totals, which the
    mirroring keeps complete.

    `max_tokens`, when above 0, is this campaign's own token ceiling, checked
    against this scope's tokens in the run ceiling's unit (cached input
    weighted by cache_discount). It trips as "campaign_tokens", a campaign
    guard: in a run of several campaigns that one campaign stops and the
    others go on, so one campaign cannot spend the others' share. 0, the
    default, leaves only the run's ceilings.
    """

    def __init__(self, parent: BudgetController, max_tokens: int = 0):
        super().__init__(config=parent.config, run_id=parent.run_id)
        self._parent = parent
        self.campaign_max_tokens = max(0, int(max_tokens or 0))

    def record_tokens(self, count: int, cached_count: int = 0,
                      cache_discount: Optional[float] = None,
                      prompt_count: int = 0, output_count: int = 0) -> None:
        """Records tokens against this campaign AND the shared run ledger.

        Deliberately does not call parent.record_tokens(): that would also
        advance the PARENT's campaign-scoped counters, which nobody resets in
        parallel mode, turning the per-campaign runaway guards back into the
        accidental run ceilings begin_campaign() exists to prevent.
        """
        self.llm_calls += 1
        self.campaign_llm_calls += 1
        self._parent.llm_calls += 1
        prompt_count = max(0, int(prompt_count or 0))
        output_count = max(0, int(output_count or 0))
        self.prompt_tokens += prompt_count
        self.output_tokens += output_count
        self._parent.prompt_tokens += prompt_count
        self._parent.output_tokens += output_count
        if cache_discount is None:
            cache_discount = self.config.cache_discount
        if count > 0:
            if cached_count > 0:
                uncached = max(0, count - cached_count)
                effective = int(uncached + cached_count * cache_discount)
                self.cached_tokens += cached_count
                self.fresh_tokens += uncached
                self.accumulated_tokens += effective
                self._parent.cached_tokens += cached_count
                self._parent.fresh_tokens += uncached
                self._parent.accumulated_tokens += effective
            else:
                self.fresh_tokens += count
                self.accumulated_tokens += count
                self._parent.fresh_tokens += count
                self._parent.accumulated_tokens += count
        self.check_budget()

    def record_step(self, node_name: str = "") -> None:
        """Counts the step in the run's cumulative ledger, then in this campaign."""
        self._parent.graph_steps += 1
        super().record_step(node_name)

    def observe(self, name: str, n: int = 1) -> None:
        """An observation is the run's: mirrored to the parent like the totals."""
        super().observe(name, n)
        self._parent.observe(name, n)

    def check_budget(self) -> None:
        """Run-level ceilings against the SHARED totals, campaign guards against OWN.

        The parent check covers wall clock and tokens using the mirrored run
        totals (its campaign counters stay at zero in parallel mode, so its
        campaign-step comparison can never fire there). The inherited check
        then applies the campaign-scoped guards to this scope's own counters;
        its wall-clock and token comparisons see a subset of the parent's
        totals and therefore can never fire first -- they are redundant, not
        conflicting.
        """
        self._parent.check_budget()
        if self.campaign_max_tokens > 0 and self.accumulated_tokens >= self.campaign_max_tokens:
            self.is_paused = True
            raise BudgetExceededError(
                trigger="campaign_tokens",
                current_value=self.accumulated_tokens,
                limit_value=self.campaign_max_tokens,
                run_id=self.run_id,
                details=(f"Campaign tokens {self.accumulated_tokens:,} reached its ceiling of "
                         f"{self.campaign_max_tokens:,}"),
            )
        super().check_budget()

    def format_pause_banner(self, *args, **kwargs) -> str:
        """The pause banner reports the RUN, so it renders from the parent."""
        return self._parent.format_pause_banner(*args, **kwargs)


# ---------------------------------------------------------------------------
# Coverage-credit gate
# ---------------------------------------------------------------------------

# Tools whose invocation means the agent actually looked at target code. The
# scan loop refuses to credit a campaign to the coverage ledger unless at
# least one of these ran during it: a campaign that finished without a single
# code read examined nothing, whatever its exit status says.
CODE_READ_TOOLS = ("read_file", "get_function_boundary")

# Nodes whose code reads count as examination. The bookend stages (history,
# architect, threat_modeler, planner, reporter, ...) call read_file on
# workspace artifacts and orientation slices in EVERY campaign, so counting
# them would hand a researcher that aborted on a prose-only first turn a
# passing read delta every time. The names match workflow.json plus the two
# parallel researcher arms the synthesizer emits with parallel_researchers
# (researcher_structural / researcher_domain, which replace "researcher" in
# that topology); the stages listed after them only run once findings exist,
# so they can never create credit on their own. A custom workflow whose audit
# nodes are named differently fails CLOSED: reads count zero, credit is
# withheld with a visible warning, and the slice is rescanned -- never
# silently stamped.
AUDIT_NODES = (
    "explorer",
    "researcher",
    "researcher_structural",
    "researcher_domain",
    "reviewer",
    "critic",
    "reproducer",
    "patcher",
)


def should_credit_coverage(task_failed: bool, code_read_calls: int) -> bool:
    """Decides whether a finished campaign earns an examined-area credit.

    Pure so the gate is testable without a controller. A campaign is credited
    only when it ran to completion AND read code at least once: an agent that
    ends its run on a prose-only first turn comes back task_failed=False with
    zero reads, and crediting that would stamp an unread slice "examined" in
    the coverage ledger -- telling every later run that ground is covered
    when nobody looked.
    """
    return (not task_failed) and code_read_calls > 0

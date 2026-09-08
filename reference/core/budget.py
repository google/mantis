"""Resource Budgeting, Step Counting, and Zero-Loss Resumption Engine.

Provides:
1. 12-hour wall-clock, 10M token, and 500 graph step ceiling controls.
2. Cycle-safe classifier loop counters.
3. Graceful budget pause handling and state checkpointing.
4. One-line copy-pasteable --resume banner formatting.
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

# Suppress spurious OpenTelemetry context-detach tracebacks caused by Python 3.14
# contextvars strict isolation when an async generator pauses or cancels mid-stream.
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

        return cls(
            max_wall_clock_seconds=parse_duration_seconds(raw_seconds) if raw_seconds is not None else 12.0 * 3600.0,
            max_tokens=parse_token_budget(raw_tokens) if raw_tokens is not None else 10_000_000,
            max_graph_steps=int(raw_steps) if raw_steps is not None else 500,
            max_node_visits=int(raw_node_visits) if raw_node_visits is not None else 50,
            max_llm_calls=int(raw_llm_calls) if raw_llm_calls is not None else 2000,
            max_node_tool_calls=int(raw_node_tool_calls) if raw_node_tool_calls is not None else 200,
        )


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
        self.cached_tokens = 0
        self.fresh_tokens = initial_tokens
        self.graph_steps = initial_steps
        self.start_time = start_time or time.time()
        self.node_visit_counts: Dict[str, int] = {}
        self.node_tool_counts: Dict[str, int] = {}
        self.is_paused = False

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

    def record_tokens(self, count: int, cached_count: int = 0, cache_discount: float = 0.1) -> None:
        """Records token consumption from an LLM call or stage with cache discounting (0.1x / 90% discount)."""
        if count <= 0:
            return
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

    def record_tool_call(self, node_name: str = "", tool_name: str = "") -> None:
        """Records a tool call executed by an agent node and enforces the per-node tool ceiling."""
        clean_node = node_name.split("/")[-1].split("@")[0] if node_name else "unknown"
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
        """Records execution of a graph node step."""
        self.graph_steps += 1
        if node_name:
            self.node_visit_counts[node_name] = self.node_visit_counts.get(node_name, 0) + 1
            if self.node_visit_counts[node_name] > self.config.max_node_visits:
                raise BudgetExceededError(
                    trigger="node_visits_ceiling",
                    current_value=self.node_visit_counts[node_name],
                    limit_value=self.config.max_node_visits,
                    run_id=self.run_id,
                    details=f"Node '{node_name}' exceeded max visits limit of {self.config.max_node_visits}",
                )
        self.check_budget()

    def check_budget(self) -> None:
        """Evaluates all budget dimensions and raises BudgetExceededError if any threshold is hit."""
        # 1. Wall-clock limit
        if self.elapsed_seconds >= self.config.max_wall_clock_seconds:
            self.is_paused = True
            raise BudgetExceededError(
                trigger="wall_clock",
                current_value=f"{self.elapsed_seconds:.1f}s",
                limit_value=f"{self.config.max_wall_clock_seconds:.1f}s",
                run_id=self.run_id,
                details=f"Elapsed time {self.elapsed_formatted} reached ceiling of {self.config.max_wall_clock_seconds / 3600:.1f}h",
            )

        # 2. Token ceiling
        if self.accumulated_tokens >= self.config.max_tokens:
            self.is_paused = True
            raise BudgetExceededError(
                trigger="token_budget",
                current_value=self.accumulated_tokens,
                limit_value=self.config.max_tokens,
                run_id=self.run_id,
                details=f"Accumulated tokens {self.accumulated_tokens:,} reached ceiling of {self.config.max_tokens:,}",
            )

        # 3. Graph step ceiling
        if self.graph_steps >= self.config.max_graph_steps:
            self.is_paused = True
            raise BudgetExceededError(
                trigger="graph_steps",
                current_value=self.graph_steps,
                limit_value=self.config.max_graph_steps,
                run_id=self.run_id,
                details=f"Graph step count {self.graph_steps} reached ceiling of {self.config.max_graph_steps}",
            )

    def format_pause_banner(
        self,
        trigger: str,
        progress_summary: str = "",
        saved_recipe_path: str = "",
        target: str = "",
        workflow: str = "",
    ) -> str:
        """Formats a clear, human-readable terminal pause banner with resume instructions."""
        if self.cached_tokens > 0:
            token_str = (
                f"{self.accumulated_tokens:,} effective / {self.config.max_tokens:,} limit "
                f"({self.fresh_tokens:,} fresh + {self.cached_tokens:,} cached @ 0.1x)"
            )
        else:
            token_str = f"{self.accumulated_tokens:,} / {self.config.max_tokens:,} limit"

        clean_trigger = " ".join(str(trigger).split())
        lines = [
            "=" * 80,
            " ⏸️  [BUDGET PAUSE] Mantis execution paused gracefully at budget ceiling",
            "=" * 80,
            f"  • Trigger:          {clean_trigger}",
            f"  • Run ID:           {self.run_id}",
            f"  • Wall-Clock Time:  {self.elapsed_formatted} / {self.config.max_wall_clock_seconds / 3600:.1f}h limit",
            f"  • Token Usage:      {token_str}",
            f"  • Graph Steps:      {self.graph_steps} / {self.config.max_graph_steps} limit",
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

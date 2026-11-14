#!/usr/bin/env python3
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

"""Mantis Campaign Launcher.

Launches automated vulnerability review campaigns on target files or repositories.
Supports research graph synthesis, 12-hour budgeting controls, and zero-loss resumption.
"""

import argparse
import asyncio
import os
import re
import signal
import sys
from pathlib import Path
from typing import Any, Optional
import warnings

# Suppress noisy ADK preview/experimental feature notices
warnings.filterwarnings("ignore", message=r".*\[EXPERIMENTAL\].*")

# Ensure reference root is in sys.path when script is run directly
_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from core.budget import BudgetConfig, parse_duration_seconds, parse_token_budget
from core.config import EXIT_AUTH, MantisAuthError
from core.synthesizer import ResearchGraphSynthesizer, WorkflowSynthesizer
from main import EXIT_USAGE, _SCAN_MODES, pipeline, validate_resume_scan_mode
from scripts.configure import (
    detect_capabilities,
    ensure_configured,
    find_workflow_json,
    is_default_or_unconfigured,
    load_workflow_dict,
    run_preflight_checks,
    update_workflow_config,
)


class _SigtermInterrupt(BaseException):
    """Raised on SIGTERM so finally blocks flush --spend-report with exit 143."""


def _resolve_from_invocation_dir(val: str, inv_dir: str) -> str:
    """Joins a relative CLI path onto MANTIS_INVOCATION_DIR without resolving
    symlinks or collapsing '..' (preserving CP-3 traversal checks)."""
    if not inv_dir or not val:
        return val
    p = Path(val)
    if p.is_absolute():
        return val
    return str(Path(inv_dir) / p)


class _LauncherArgumentParser(argparse.ArgumentParser):
    """Exits 64 (EX_USAGE) on CLI usage errors instead of argparse's default 2.

    Exit code 2 is documented by Mantis as "paused at budget", so a CI
    wrapper could not otherwise distinguish a typo'd flag from a resumable
    pause. This is the only command-line parser: run.sh, scripts/launch.py
    and main.py all go through it.
    """

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(64, f"{self.prog}: error: {message}\n")


class _ExplicitPassesAction(argparse.Action):
    """Records `--passes N` while tracking whether the flag was explicitly given."""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        setattr(namespace, "_passes_explicit", True)


def build_parser() -> argparse.ArgumentParser:
    parser = _LauncherArgumentParser(
        description="Mantis Campaign Launcher: Automated Security Review Pipeline"
    )
    parser.add_argument("target", nargs="?", default=".", help="Target source file or repository directory to review")
    parser.add_argument("--workflow", "-w", type=str, default="", help="Path to workflow.json")
    parser.add_argument("--objective", type=str, default="", help="Natural language objective for research graph synthesis")
    parser.add_argument(
        "--sandbox",
        "-s",
        type=str,
        choices=["static-only", "static", "gvisor", "microsandbox", "gce", "remote"],
        help="Sandbox execution override",
    )
    parser.add_argument(
        "--model",
        "-m",
        type=str,
        help="Global LLM model override (e.g. gemini-3.8-flash, vertex_ai/claude-opus-5, openai/my-model)",
    )
    parser.add_argument("--api-base", type=str, help="Custom LLM API Base URL for OpenAI-compatible models")
    parser.add_argument(
        "--reasoning-effort",
        type=str,
        choices=["low", "medium", "high", "xhigh", "max"],
        help=(
            "Reasoning effort override for every node (low, medium, high; xhigh and max "
            "where the model offers them, as current Anthropic models do -- a model "
            "without them is sent the nearest level it has)."
        ),
    )
    parser.add_argument("--timeout", type=float, help="LLM request timeout in seconds")
    parser.add_argument("--db", "-d", type=str, help="Path to knowledge SQLite database")
    parser.add_argument(
        "--save-config",
        action="store_true",
        help=(
            "Persist CLI overrides (--model, --db, --sandbox, ...) into "
            "workflow.local.json. Without this flag overrides apply to this "
            "run only."
        ),
    )
    parser.add_argument(
        "--flex",
        action="store_true",
        help="Use Vertex AI Gemini Flex tier (routes requests via shared Flex capacity).",
    )

    # Budgeting & Resumption
    parser.add_argument(
        "--max-time",
        type=str,
        default=None,
        help="Wall-clock time ceiling override before graceful pause (e.g. 12h, 24h, 30m, or 'unlimited'; defaults to workflow budget)",
    )
    parser.add_argument(
        "--token-budget",
        "--max-tokens",
        dest="token_budget",
        type=str,
        default=None,
        help=(
            "Run token ceiling, e.g. 10M, 500k, or 'unlimited' (defaults to the "
            "workflow budget). Checked after each call against tokens weighted by "
            "--cache-discount; the run pauses with exit 2 when reached."
        ),
    )
    parser.add_argument(
        "--cache-discount",
        type=str,
        default=None,
        help=(
            "Weight of a cached input token against the token ceiling, 0 to 1 (defaults to "
            "the workflow budget, 0.1). Pass 1 to count every token at full price."
        ),
    )
    parser.add_argument(
        "--max-campaign-tokens",
        type=str,
        default=None,
        help=(
            "Token ceiling for each campaign, e.g. 4M or 500k, in the run ceiling's unit "
            "(see --cache-discount). A campaign that reaches it stops, its findings so far "
            "stored, and in a run of several campaigns the others go on; so one campaign "
            "cannot spend the others' share of --max-tokens. Default: none."
        ),
    )
    parser.add_argument(
        "--max-input-tokens",
        type=str,
        default=None,
        help=(
            "Per-request input token ceiling, e.g. 128k or 200000 (also MANTIS_MAX_INPUT_TOKENS). "
            "Sizes context editing, tool-response caps, node context ceilings, and the "
            "pre-dispatch guard -- recommended for custom/on-prem models whose window size "
            "is not in LiteLLM's registry."
        ),
    )
    parser.add_argument(
        "--spend-report",
        type=str,
        default="",
        help=(
            "Write the run's token and call totals as JSON to this path on exit, "
            "however the run ended (for a driver that allots this process a budget), "
            "with each campaign's outcome and spend; rewritten as each campaign ends."
        ),
    )
    parser.add_argument(
        "--transcript-out",
        type=str,
        default="",
        help=(
            "Append a JSONL transcript of every stage's prose, tool calls and tool "
            "responses to this path (the console echo clips tool output; this does not)."
        ),
    )
    parser.add_argument(
        "--no-budget",
        action="store_true",
        help=(
            "Disable the wall-clock and token spend ceilings entirely (for dedicated "
            "hardware or unmetered budgets). Runaway-loop guards stay active."
        ),
    )
    parser.add_argument(
        "--no-replan",
        action="store_true",
        help=(
            "Disable dynamic replanning: freezes the campaign plan at run "
            "start so a rerun holds the same plan (for reproducibility)."
        ),
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help=(
            "Number of campaigns to run concurrently (default: 1, the "
            "sequential behaviour). Run-level budget ceilings are shared "
            "across workers; per-campaign guards stay per campaign."
        ),
    )
    parser.add_argument(
        "--passes",
        type=int,
        default=1,
        action=_ExplicitPassesAction,
        help=(
            "Number of independent blind audit passes to run over each planned "
            "campaign slice (default: 1). With --passes N (N > 1), each pass "
            "runs in an isolated session without cross-pass coverage suppression "
            "and unions discovered findings into the consolidated run."
        ),
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=None,
        metavar="1-100",
        help=(
            "Continuous audit depth from 1 (fast shallow triage) to 100 "
            "(exhaustive full-stack + hardware/RTL coverage with multi-pass deep "
            "reasoning). Defaults to 30 when omitted. Explicit flags (--scan-mode, "
            "--passes, --reasoning-effort, --token-budget, --max-time) always take precedence."
        ),
    )
    parser.add_argument(
        "--parallel-ramp",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help=(
            "With --parallel N, start worker i after i*SECONDS instead of all at once, "
            "so N guests, N stagings and N first model calls do not land in the same "
            "second (default: 0, all at once)."
        ),
    )
    parser.add_argument(
        "--db-timeout",
        type=float,
        default=None,
        help=(
            "Seconds a knowledge-database write waits for the lock before "
            "failing with 'database is locked' (default: 60, or 15 x "
            "--parallel when that is larger; also MANTIS_DB_TIMEOUT)"
        ),
    )
    parser.add_argument(
        "--scan-mode",
        type=str,
        default=None,
        choices=list(_SCAN_MODES),
        help=(
            "Scan mode: 'whole' scans the target as one campaign; "
            "'file-by-file' runs one campaign per source file; "
            "'uncovered' runs one campaign per uncovered source file regardless of repo size; "
            "'cross-functional' hunts composite defects across ranked subsystems; "
            "'changed' scans only new/edited files since last covered and verifies "
            "prior findings touching them; 'auto' picks whole if small, else "
            "file-by-file over uncovered files, else cross-functional. "
            "Defaults to the workflow config, or auto."
        ),
    )
    parser.add_argument(
        "--changed-files",
        action="append",
        default=None,
        metavar="PATH",
        help=(
            "With --scan-mode changed over a directory: the files that changed, "
            "instead of the coverage ledger's answer; repeatable, one path per flag, "
            "relative to the target. Each directory holding them is one campaign over "
            "the whole target, so the agent can read across packages. A path outside "
            "the target is an error."
        ),
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip the work-plan confirmation prompt (for non-interactive use)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=None,
        metavar="PATTERN",
        help=(
            "Leave matching paths out of the scan; repeatable, or comma-separated. "
            "Patterns are relative to the target: a bare name (vendor, testdata) matches "
            "a directory or file of that name at any depth, a pattern with a slash "
            "(third_party/*, src/gen/*.pb.go) matches the relative path. Excluded files "
            "are not scanned or listed but stay readable for context. Adds to the "
            "workflow's `exclude` list."
        ),
    )
    parser.add_argument(
        "--path-root",
        type=str,
        default="",
        help=(
            "Directory to store finding filepaths relative to (e.g. the "
            "repository root when scanning a single file inside it); must "
            "be an ancestor of the target"
        ),
    )
    parser.add_argument(
        "--no-compaction",
        action="store_true",
        help=(
            "Force ADK event compaction off for this run even when the workflow "
            "config enables it (it is off by default: stages see only their own "
            "events, and in-stage compaction rewrote a stage's working context)."
        ),
    )
    parser.add_argument(
        "--no-context-cache",
        action="store_true",
        help="Disable ADK context caching",
    )
    parser.add_argument(
        "--no-memory",
        action="store_true",
        help=(
            "Disable cross-run memory recall and stage-experience injection for this run "
            "(order-independent clean-slate audit)."
        ),
    )
    parser.add_argument(
        "--intra-run-learning",
        action="store_true",
        help=(
            "Allow pass-1 campaigns to recall findings and lessons written by earlier "
            "campaigns of the same run (by default recall is frozen to prior runs)."
        ),
    )
    parser.add_argument(
        "--import-knowledge",
        type=str,
        default="",
        metavar="DIR",
        help=(
            "Read a knowledge export (scripts/knowledge.py export; by convention "
            ".mantis/knowledge in the repository) into the database before the run: prior "
            "findings and their status, learnings, coverage, and the threat model and "
            "architecture the run's tools then see. The files are treated as data."
        ),
    )
    parser.add_argument(
        "--focus",
        type=str,
        default="",
        help=(
            "Natural-language directive steering the campaign planner, e.g. "
            "'look for IDOR' or 'find memory corruption issues'"
        ),
    )
    parser.add_argument(
        "--seed-report",
        type=str,
        default="",
        help=(
            "Path to a bug report file; the planner hunts variants of the "
            "described bug, treating file content as untrusted evidence"
        ),
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=None,
        help="Maximum graph steps ceiling override (defaults to workflow budget)",
    )
    parser.add_argument(
        "--max-node-visits",
        type=int,
        default=None,
        help="Maximum visits per graph node ceiling override (defaults to workflow budget)",
    )
    parser.add_argument(
        "--max-llm-calls",
        type=int,
        default=None,
        help="LLM calls ceiling override before graceful pause (0 for unbounded; defaults to workflow budget)",
    )
    parser.add_argument(
        "--max-node-tool-calls",
        type=int,
        default=None,
        help="Per-node visit runaway tool loop ceiling override (defaults to workflow budget)",
    )
    parser.add_argument(
        "--resume",
        type=str,
        nargs="?",
        const="latest",
        default="",
        metavar="RUN_ID",
        help=(
            "Resume an interrupted or partially failed run: scan only the campaigns "
            "it has not completed (failed ones and ones it never reached), under the "
            "same run id and recorded scan mode, with a fresh budget. With no RUN_ID, "
            "picks the most recent run recorded for this target. Cannot be combined "
            "with a different --scan-mode; to verify fixes or scan edited code, omit "
            "--resume and start a new run with --scan-mode changed."
        ),
    )
    parser.add_argument(
        "--rescan-changed-harness",
        action="store_true",
        help=(
            "Treat ground covered by a different harness configuration (other tools, "
            "model, stage prompts or sandbox tier -- the coverage ledger stamps each "
            "campaign with a fingerprint of what ran it) as uncovered, so --resume and "
            "auto mode examine it again. By default such ground still counts as covered "
            "and the run reports how much of it there is."
        ),
    )
    parser.add_argument(
        "--retry-unexamined",
        action="store_true",
        help=(
            "With --resume: also re-run campaigns that previously exited without reading "
            "any target code ([COVERAGE GUARD])."
        ),
    )
    parser.add_argument(
        "--inspect",
        action="store_true",
        help="Preview synthesized workflow layout and prompt before execution",
    )
    parser.add_argument(
        "--synthesize-llm",
        action="store_true",
        default=True,
        help="Use LLM to synthesize tailored research graph for --objective (default: True)",
    )
    parser.add_argument(
        "--deterministic-only",
        action="store_false",
        dest="synthesize_llm",
        help="Force deterministic archetype synthesis instead of LLM research graph synthesis",
    )

    # Options
    parser.add_argument(
        "--probe",
        "--probe-llm",
        action="store_true",
        dest="probe_llm",
        help="Perform an active live reachability probe against the configured LLM endpoint during preflight",
    )
    parser.add_argument(
        "--no-auto-configure",
        action="store_true",
        help="Disable automatic environment detection and placeholder resolution",
    )
    parser.add_argument(
        "--preflight-only",
        "--test",
        "--preflight",
        action="store_true",
        help="Run preflight tests and exit without launching pipeline",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Launch interactive configuration wizard before review",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print review plan and target indexing without executing models",
    )

    return parser


def run_launch(
    target: str,
    workflow_path: str = "",
    objective: str = "",
    sandbox: Optional[str] = None,
    model: Optional[str] = None,
    api_base: Optional[str] = None,
    reasoning_effort: Optional[str] = None,
    timeout: Optional[float] = None,
    db_path: Optional[str] = None,
    flex: bool = False,
    auto_configure: bool = True,
    preflight_only: bool = False,
    interactive: bool = False,
    dry_run: bool = False,
    probe_llm: bool = False,
    max_time: Optional[str] = None,
    token_budget: Optional[str] = None,
    no_budget: bool = False,
    no_replan: bool = False,
    parallel: int = 1,
    passes: int = 1,
    passes_explicit: bool = False,
    depth: Optional[int] = None,
    parallel_ramp: float = 0.0,
    db_timeout: Optional[float] = None,
    focus: str = "",
    seed_report: str = "",
    max_steps: Optional[int] = None,
    max_node_visits: Optional[int] = None,
    max_llm_calls: Optional[int] = None,
    max_node_tool_calls: Optional[int] = None,
    resume_run_id: str = "",
    inspect: bool = False,
    synthesize_llm: bool = True,
    save_config: bool = False,
    scan_mode: Optional[str] = None,
    assume_yes: bool = False,
    exclude: Optional[list] = None,
    path_root: str = "",
    no_compaction: bool = False,
    no_context_cache: bool = False,
    cache_discount: Optional[float] = None,
    import_knowledge: str = "",
    rescan_changed_harness: bool = False,
    retry_unexamined: bool = False,
    transcript_out: str = "",
    changed_files: Optional[list] = None,
    max_campaign_tokens: int = 0,
    max_input_tokens: Optional[int] = None,
    no_memory: bool = False,
    intra_run_learning: bool = False,
) -> int:
    """Core launch workflow: auto-configures, preflights, and executes the Mantis pipeline."""
    if flex:
        os.environ["VERTEX_FLEX"] = "1"
    if max_input_tokens is not None and max_input_tokens > 0:
        os.environ["MANTIS_MAX_INPUT_TOKENS"] = str(int(max_input_tokens))

    if depth is not None:
        from core.depth import parse_depth
        try:
            depth = parse_depth(depth)
        except ValueError as exc:
            print(f"❌ Error: --depth: {exc}", file=sys.stderr)
            return EXIT_USAGE

    # SECURITY (INV-4): component-wise symlink validation. A leaf-only is_symlink()
    # check is bypassed by a hostile checkout shipping an intermediate symlink
    # (repo/link/sub with link -> ../../..), which .resolve() would silently follow.
    from core.paths import validate_scan_target

    target_path, target_err = validate_scan_target(target)
    if target_path is None:
        print(f"❌ Error: {target_err}", file=sys.stderr)
        return 1

    cli_budget_overrides: dict[str, Any] = {}
    try:
        if max_time is not None:
            cli_budget_overrides["max_wall_clock_seconds"] = parse_duration_seconds(max_time)
        if token_budget is not None:
            cli_budget_overrides["max_tokens"] = parse_token_budget(token_budget)
    except ValueError as ve:
        print(f"❌ Error: {ve}", file=sys.stderr)
        return EXIT_USAGE
    # --no-budget disables both RUN-level spend ceilings (0 = unbounded). Expressed
    # as CLI overrides so the normal effective-budget merge and the dry-run
    # display both see it; deliberately leaves the runaway-loop guards alone.
    if no_budget:
        cli_budget_overrides["max_wall_clock_seconds"] = 0.0
        cli_budget_overrides["max_tokens"] = 0
    if max_steps is not None:
        cli_budget_overrides["max_graph_steps"] = max_steps
    if max_node_visits is not None:
        cli_budget_overrides["max_node_visits"] = max_node_visits
    if max_llm_calls is not None:
        cli_budget_overrides["max_llm_calls"] = max_llm_calls
    if max_node_tool_calls is not None:
        cli_budget_overrides["max_node_tool_calls"] = max_node_tool_calls

    # Fast path: Preflight validation check without synthesis or execution
    if preflight_only:
        wf_file = find_workflow_json(workflow_path)
        wf_data = load_workflow_dict(wf_file)
        cfg = wf_data.get("config", {})
        overrides = {}
        if sandbox:
            overrides["sandbox"] = {"type": sandbox, "options": {}}
        if model:
            overrides["default_model"] = model
        if api_base:
            overrides["api_base"] = api_base
        if reasoning_effort:
            overrides["reasoning_effort"] = reasoning_effort
        if timeout is not None:
            overrides["timeout"] = timeout
        if db_path:
            overrides["db_path"] = db_path
        if auto_configure and overrides:
            cfg = ensure_configured(
                workflow_path=wf_file,
                auto=True,
                overrides=overrides,
                probe_llm=probe_llm,
                persist_overrides=save_config,
            )
        elif overrides:
            cfg = update_workflow_config(wf_file, overrides, save=False).get("config", cfg)
        ok, messages = run_preflight_checks(cfg, target_path=str(target_path), probe_llm=probe_llm)
        if not ok:
            print("\n❌ Preflight Verification Failed:", file=sys.stderr)
            for msg in messages:
                print(f"  {msg}", file=sys.stderr)
            return 1
        print("✅ Preflight validation succeeded.")
        for msg in messages:
            print(f"  {msg}")
        return 0

    # Research Graph Synthesis
    # Set here rather than inside the branch below: the pipeline call at the end of this
    # function reads it unconditionally, and a run without an objective never surveys.
    survey_astm = None
    if objective:
        base_budget = BudgetConfig()
        base_wf: dict = {}
        try:
            base_wf = load_workflow_dict(find_workflow_json(workflow_path), load_local=True)
            raw_b = base_wf.get("budget") or base_wf.get("config", {}).get("budget")
            if raw_b and isinstance(raw_b, dict):
                base_budget = BudgetConfig.from_dict(raw_b)
        except Exception:
            base_wf = {}

        synth_budget = BudgetConfig(
            max_wall_clock_seconds=cli_budget_overrides.get("max_wall_clock_seconds", base_budget.max_wall_clock_seconds),
            max_tokens=cli_budget_overrides.get("max_tokens", base_budget.max_tokens),
            max_graph_steps=cli_budget_overrides.get("max_graph_steps", base_budget.max_graph_steps),
            max_node_visits=cli_budget_overrides.get("max_node_visits", base_budget.max_node_visits),
            max_llm_calls=cli_budget_overrides.get("max_llm_calls", base_budget.max_llm_calls),
            max_node_tool_calls=cli_budget_overrides.get("max_node_tool_calls", base_budget.max_node_tool_calls),
        )

        mode_str = "LLM-driven research graph synthesis" if synthesize_llm else "deterministic archetype"
        print(f"✨ Synthesizing targeted research graph for objective: '{objective}' (mode: {mode_str})...")
        synthesizer = ResearchGraphSynthesizer(
            default_model=model,
            db_path=db_path,
            workflow_path=workflow_path or "",
            load_local=True,
            operator_config=base_wf.get("config") if isinstance(base_wf.get("config"), dict) else None,
        )
        effective_sandbox = sandbox
        if not effective_sandbox:
            try:
                effective_sandbox = (base_wf.get("config") or {}).get("sandbox", {}).get("type")
            except Exception:
                effective_sandbox = "static-only"
        effective_sandbox = effective_sandbox or "static-only"

        # Survey the repository before synthesizing, so the graph is shaped by what is
        # actually in the target rather than by the objective string alone. An objective
        # that names a domain still wins; this only supplies an answer where there was
        # previously none.
        #
        # Failure here is not fatal. Synthesis without a map is exactly the behaviour
        # that shipped before, so a surveyor problem costs specificity, not the run.
        try:
            from core.surveyor import survey
            survey_astm = survey(str(target_path))
            top = survey_astm.get("slices", [])
            if top:
                print(
                    f"🗺️  Surveyed {survey_astm.get('provenance', {}).get('groups_considered', 0)} "
                    f"candidate areas in {survey_astm.get('provenance', {}).get('elapsed_seconds', 0)}s."
                )
        except Exception as exc:
            print(f"  Surveyor unavailable ({exc}); synthesizing from the objective alone.", file=sys.stderr)
            survey_astm = None

        spec = synthesizer.synthesize(
            objective=objective,
            budget_config=synth_budget,
            target_root=str(target_path),
            sandbox_type=effective_sandbox,
            use_llm=synthesize_llm,
            model=model,
            timeout=timeout,
            astm=survey_astm,
        )
        meta = spec.evolution_metadata or {}
        if meta.get("archetype_source") == "repository":
            print(
                f"  Archetype '{meta.get('archetype')}' inferred from repository content "
                f"(the objective named no domain)."
            )
        if meta.get("sandbox_clamp"):
            clamp = meta["sandbox_clamp"]
            print(
                f"  🔒 Sandbox request '{clamp.get('requested')}' clamped to "
                f"'{clamp.get('effective')}': {clamp.get('reason')}"
            )
        mantis_home = os.environ.get("MANTIS_HOME")
        if mantis_home:
            workspace_dir = (Path(mantis_home) / "workspace").resolve()
        else:
            workspace_dir = (Path(__file__).resolve().parent.parent / "workspace").resolve()
        recipe_path = ResearchGraphSynthesizer.persist_recipe(spec, workspace_dir)
        workflow_path = str(recipe_path)
        print(f"✅ Synthesized recipe saved to: {recipe_path}")

        if inspect:
            print("\n" + "=" * 80)
            print("🔍 Synthesized Research Graph Preview:")
            print("=" * 80)
            print(f"  • Name:        {spec.name}")
            print(f"  • Nodes:       {[n.id for n in spec.nodes]}")
            print(f"  • Edges:       {len(spec.edges)} transitions")
            print(f"  • Archetype:   {spec.evolution_metadata.get('archetype') if spec.evolution_metadata else 'standard'}")
            print(f"  • Synthesis:   {spec.evolution_metadata.get('synthesis_mode') if spec.evolution_metadata else 'unknown'}")
            print("=" * 80)
            return 0

    wf_file = find_workflow_json(workflow_path)
    wf_data = load_workflow_dict(wf_file, load_local=False if objective else True)
    cfg = wf_data.get("config", {})
    initial_sb_type = (cfg.get("sandbox") or {}).get("type")

    # Resolve effective budget: CLI overrides > workflow budget > default BudgetConfig
    wf_budget_raw = wf_data.get("budget") or cfg.get("budget") or {}
    wf_budget = BudgetConfig.from_dict(wf_budget_raw) if wf_budget_raw else BudgetConfig()
    effective_budget = BudgetConfig(
        max_wall_clock_seconds=cli_budget_overrides.get("max_wall_clock_seconds", wf_budget.max_wall_clock_seconds),
        max_tokens=cli_budget_overrides.get("max_tokens", wf_budget.max_tokens),
        max_graph_steps=cli_budget_overrides.get("max_graph_steps", wf_budget.max_graph_steps),
        max_node_visits=cli_budget_overrides.get("max_node_visits", wf_budget.max_node_visits),
        max_llm_calls=cli_budget_overrides.get("max_llm_calls", wf_budget.max_llm_calls),
        max_node_tool_calls=cli_budget_overrides.get("max_node_tool_calls", wf_budget.max_node_tool_calls),
        cache_discount=cache_discount if cache_discount is not None else wf_budget.cache_discount,
    )

    # Build overrides dict
    overrides = {}
    if sandbox:
        overrides["sandbox"] = {"type": sandbox, "options": {}}
    if model:
        overrides["default_model"] = model
    if api_base:
        overrides["api_base"] = api_base
    if reasoning_effort:
        overrides["reasoning_effort"] = reasoning_effort
    if timeout is not None:
        overrides["timeout"] = timeout
    if db_path:
        overrides["db_path"] = db_path
    if depth is not None:
        overrides["depth"] = depth

    if resume_run_id and scan_mode:
        from core.paths import resolve_db_path

        resolved_db = resolve_db_path(
            db_path or cfg.get("db_path", "knowledge.db"),
            str(Path(wf_file).resolve().parent),
        )
        mode_err = validate_resume_scan_mode(
            resolved_db, str(target_path), resume_run_id, scan_mode
        )
        if mode_err:
            print(f"Error: {mode_err}", file=sys.stderr)
            return EXIT_USAGE

    # Check unconfigured placeholders and auto-configure
    is_unconf, issues = is_default_or_unconfigured(cfg)
    if is_unconf or interactive or (auto_configure and overrides):
        if interactive:
            from scripts.configure import run_interactive_wizard
            cfg = run_interactive_wizard(wf_file)
        elif auto_configure:
            print("⚙️ Auto-configuring Mantis environment...")
            cfg = ensure_configured(
                workflow_path=wf_file,
                auto=True,
                overrides=overrides if overrides else None,
                probe_llm=probe_llm,
                persist_overrides=save_config,
            )
    elif overrides:
        cfg = update_workflow_config(wf_file, overrides, save=False).get("config", cfg)

    # Preflight Check
    ok, messages = run_preflight_checks(cfg, target_path=str(target_path), probe_llm=probe_llm)
    if not ok and auto_configure and not is_unconf and not interactive:
        if os.environ.get("MANTIS_ALLOW_SANDBOX_DOWNGRADE") == "1":
            print("⚙️ Preflight check failed on existing configuration, attempting approved auto-configuration...")
            cfg = ensure_configured(
                workflow_path=wf_file,
                auto=True,
                overrides=overrides if overrides else None,
                probe_llm=probe_llm,
                persist_overrides=save_config,
            )
            ok, messages = run_preflight_checks(cfg, target_path=str(target_path), probe_llm=probe_llm)
        else:
            print(
                "❌ Preflight failed for the configured sandbox. Refusing to "
                "auto-downgrade isolation. Set MANTIS_ALLOW_SANDBOX_DOWNGRADE=1 "
                "to accept a degraded session.",
                file=sys.stderr,
            )

    if not ok:
        print("\n❌ Preflight Verification Failed:", file=sys.stderr)
        for msg in messages:
            print(f"  {msg}", file=sys.stderr)
        print("\nRun 'python3 reference/scripts/configure.py --interactive' or '--auto' to fix configuration.", file=sys.stderr)
        return 1


    if dry_run:
        from core.depth import DEFAULT_DEPTH, resolve_depth_profile
        _eff_depth = depth if depth is not None else (cfg.get("depth") or DEFAULT_DEPTH)
        _dprof = resolve_depth_profile(_eff_depth)
        print("\n📋 Dry-Run Execution Plan:")
        print(f"  • Target:        {target_path}")
        print(f"  • Workflow:      {wf_file}")
        print(f"  • Depth:         {_dprof.depth}/100 ({_dprof.tier}; effort={reasoning_effort or _dprof.reasoning_effort}, passes={passes if passes_explicit else _dprof.passes})")
        print(f"  • Sandbox:       {cfg.get('sandbox', {}).get('type', 'static-only')}")
        print(f"  • Model:         {model or cfg.get('default_model')}")
        print(f"  • Knowledge DB:  {db_path or cfg.get('db_path', 'knowledge.db')}")
        if effective_budget.max_wall_clock_seconds > 0:
            print(f"  • Max Time:      {effective_budget.max_wall_clock_seconds / 3600:.1f}h")
        else:
            print("  • Max Time:      unlimited")
        if effective_budget.max_tokens > 0:
            print(f"  • Token Budget:  {effective_budget.max_tokens:,}")
        else:
            print("  • Token Budget:  unlimited")
        print(f"  • Max Steps:     {effective_budget.max_graph_steps}")
        print(f"  • Max Visits:    {effective_budget.max_node_visits}")
        if effective_budget.max_llm_calls > 0:
            print(f"  • Max LLM Calls: {effective_budget.max_llm_calls}")
        if effective_budget.max_node_tool_calls > 0:
            print(f"  • Max Node Tool Calls: {effective_budget.max_node_tool_calls}")
        if resume_run_id:
            print(f"  • Resume Run ID: {'most recent run' if resume_run_id == 'latest' else resume_run_id}")
        return 0

    effective_sandbox_override: Optional[dict | str] = sandbox
    if (
        not effective_sandbox_override
        and os.environ.get("MANTIS_ALLOW_SANDBOX_DOWNGRADE") == "1"
        and initial_sb_type not in (None, "", "static-only", "static")
        and (cfg.get("sandbox") or {}).get("type") in ("static-only", "static")
    ):
        # Propagate the session-only downgrade into pipeline() in memory (as a
        # dict so banner_resume_flags does not turn it into sticky --sandbox).
        effective_sandbox_override = {"type": "static-only", "options": {}}

    async def _run_pipeline_with_sigterm() -> int:
        loop = asyncio.get_running_loop()
        task = asyncio.current_task()
        got_sigterm = False

        def _on_sigterm() -> None:
            nonlocal got_sigterm
            got_sigterm = True
            if task is not None and not task.done():
                task.cancel()

        installed = False
        try:
            loop.add_signal_handler(signal.SIGTERM, _on_sigterm)
            installed = True
        except (NotImplementedError, RuntimeError, ValueError):
            installed = False
        try:
            return await pipeline(
                scan_target=str(target_path),
                workflow_path=wf_file,
                model_override=model,
                api_base_override=api_base,
                sandbox_override=effective_sandbox_override,
                db_override=db_path,
                timeout_override=timeout,
                reasoning_effort_override=reasoning_effort,
                auto_configure=auto_configure and not bool(objective),
                load_local=False if objective else True,
                budget_config=effective_budget if bool(cli_budget_overrides) else None,
                resume_run_id=resume_run_id,
                objective=objective,
                max_llm_calls_override=cli_budget_overrides.get("max_llm_calls"),
                max_node_tool_calls_override=cli_budget_overrides.get("max_node_tool_calls"),
                enable_replan=False if no_replan else None,
                parallel=parallel,
                passes=passes,
                passes_explicit=passes_explicit,
                depth=depth,
                parallel_ramp_seconds=parallel_ramp,
                db_timeout=db_timeout,
                focus=focus,
                seed_report_path=seed_report,
                scan_mode_override=scan_mode,
                assume_yes=assume_yes,
                exclude_override=exclude,
                path_root=path_root,
                enable_compaction=False if no_compaction else None,
                enable_context_cache=False if no_context_cache else None,
                cache_discount_override=cache_discount,
                import_knowledge_dir=import_knowledge,
                rescan_changed_harness=rescan_changed_harness,
                retry_unexamined=retry_unexamined,
                transcript_out=transcript_out,
                changed_files_override=changed_files,
                max_campaign_tokens=max_campaign_tokens,
                max_input_tokens=max_input_tokens,
                no_memory=no_memory,
                intra_run_learning=intra_run_learning,
                # Already paid for above. Surveying chromium costs ~65s; the pipeline
                # would otherwise repeat it to answer the same question.
                precomputed_astm=survey_astm,
            )
        except asyncio.CancelledError:
            if got_sigterm:
                raise _SigtermInterrupt()
            raise
        finally:
            if installed:
                try:
                    loop.remove_signal_handler(signal.SIGTERM)
                except Exception:
                    pass

    # Launch Pipeline
    try:
        return asyncio.run(_run_pipeline_with_sigterm())
    except MantisAuthError as ae:
        print(f"\n{ae}", file=sys.stderr)
        return EXIT_AUTH


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    inv_dir = os.environ.get("MANTIS_INVOCATION_DIR", "").strip()
    if inv_dir:
        args.target = _resolve_from_invocation_dir(args.target or ".", inv_dir)
        args.workflow = _resolve_from_invocation_dir(args.workflow, inv_dir)
        args.spend_report = _resolve_from_invocation_dir(args.spend_report, inv_dir)
        args.transcript_out = _resolve_from_invocation_dir(args.transcript_out, inv_dir)
        args.seed_report = _resolve_from_invocation_dir(args.seed_report, inv_dir)
        args.import_knowledge = _resolve_from_invocation_dir(args.import_knowledge, inv_dir)
        args.path_root = _resolve_from_invocation_dir(args.path_root, inv_dir)

    # Parsed here so a bad value is a usage error (exit 64), not a stack
    # trace from inside the run and not exit 2, which means "paused at
    # budget" and is what a driver watches for.
    cache_discount = None
    if args.cache_discount is not None:
        try:
            from core.budget import clamp_cache_discount

            cache_discount = clamp_cache_discount(args.cache_discount)
        except ValueError as exc:
            parser.error(f"--cache-discount: {exc}")
    if args.token_budget is not None:
        try:
            parse_token_budget(args.token_budget)
        except ValueError as exc:
            parser.error(f"--token-budget/--max-tokens: {exc}")
    if args.max_time is not None:
        try:
            parse_duration_seconds(args.max_time)
        except ValueError as exc:
            parser.error(f"--max-time: {exc}")
    max_campaign_tokens = 0
    if args.max_campaign_tokens is not None:
        try:
            max_campaign_tokens = parse_token_budget(args.max_campaign_tokens)
        except ValueError as exc:
            parser.error(f"--max-campaign-tokens: {exc}")
    max_input_tokens: Optional[int] = None
    if args.max_input_tokens is not None:
        try:
            max_input_tokens = parse_token_budget(args.max_input_tokens)
            if max_input_tokens <= 0:
                raise ValueError("must be positive")
        except ValueError as exc:
            parser.error(f"--max-input-tokens: {exc}")
    if args.passes is not None and int(args.passes) < 1:
        parser.error("--passes: must be >= 1")
    if args.depth is not None:
        from core.depth import parse_depth
        try:
            args.depth = parse_depth(args.depth)
        except ValueError as exc:
            parser.error(f"--depth: {exc}")

    # The spend report is written however the run ended -- a driver that
    # allotted this process a budget needs the number even when the process
    # was interrupted. An exit code of None means "killed before it could say".
    # The path is also parked for the pipeline, which rewrites the report as
    # each campaign ends, so a process killed mid-run still names the
    # campaigns that finished.
    from main import _SPEND_REPORT, write_spend_report

    _SPEND_REPORT["path"] = args.spend_report or ""
    exit_code: Optional[int] = None
    prev_sigterm = None
    try:
        prev_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, lambda _signum, _frame: (_ for _ in ()).throw(_SigtermInterrupt()))
    except (ValueError, OSError):
        prev_sigterm = None
    try:
        exit_code = run_launch(
            target=args.target,
            workflow_path=args.workflow,
            objective=args.objective,
            sandbox=args.sandbox,
            model=args.model,
            api_base=args.api_base,
            reasoning_effort=args.reasoning_effort,
            timeout=args.timeout,
            db_path=args.db,
            flex=args.flex,
            auto_configure=not args.no_auto_configure,
            preflight_only=args.preflight_only,
            interactive=args.interactive,
            dry_run=args.dry_run,
            probe_llm=args.probe_llm,
            max_time=args.max_time,
            token_budget=args.token_budget,
            no_budget=args.no_budget,
            no_replan=args.no_replan,
            parallel=args.parallel,
            passes=args.passes,
            passes_explicit=bool(getattr(args, "_passes_explicit", False)),
            depth=args.depth,
            parallel_ramp=args.parallel_ramp,
            db_timeout=args.db_timeout,
            focus=args.focus,
            seed_report=args.seed_report,
            max_steps=args.max_steps,
            max_node_visits=args.max_node_visits,
            max_llm_calls=args.max_llm_calls,
            max_node_tool_calls=args.max_node_tool_calls,
            resume_run_id=args.resume,
            inspect=args.inspect,
            synthesize_llm=args.synthesize_llm,
            save_config=args.save_config,
            scan_mode=args.scan_mode,
            assume_yes=args.yes,
            exclude=args.exclude,
            path_root=args.path_root,
            no_compaction=args.no_compaction,
            no_context_cache=args.no_context_cache,
            cache_discount=cache_discount,
            import_knowledge=args.import_knowledge,
            rescan_changed_harness=args.rescan_changed_harness,
            retry_unexamined=args.retry_unexamined,
            transcript_out=args.transcript_out,
            changed_files=args.changed_files,
            max_campaign_tokens=max_campaign_tokens,
            max_input_tokens=max_input_tokens,
            no_memory=args.no_memory,
            intra_run_learning=args.intra_run_learning,
        )
    except MantisAuthError as ae:
        print(f"\n{ae}", file=sys.stderr)
        exit_code = EXIT_AUTH
    except _SigtermInterrupt:
        print("\nProcess terminated by SIGTERM.", file=sys.stderr)
        exit_code = 143
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\nProcess aborted by user.")
        exit_code = 130
    finally:
        if prev_sigterm is not None:
            try:
                signal.signal(signal.SIGTERM, prev_sigterm)
            except (ValueError, OSError):
                pass
        write_spend_report(args.spend_report, exit_code)
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except MantisAuthError as ae:
        print(f"\n{ae}", file=sys.stderr)
        sys.exit(EXIT_AUTH)
    except _SigtermInterrupt:
        sys.exit(143)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\nProcess aborted by user.")
        sys.exit(130)

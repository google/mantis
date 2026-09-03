#!/usr/bin/env python3
"""Mantis Campaign Launcher.

Launches automated vulnerability review campaigns on target files or repositories.
Automatically verifies configuration, auto-resolves defaults, and applies runtime overrides.
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

# Ensure reference root is in sys.path when script is run directly
_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from main import pipeline
from scripts.configure import (
    detect_capabilities,
    ensure_configured,
    find_workflow_json,
    is_default_or_unconfigured,
    load_workflow_dict,
    run_preflight_checks,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mantis Campaign Launcher: Automated Security Review Pipeline"
    )
    parser.add_argument("target", help="Target source file or repository directory to review")
    parser.add_argument("--workflow", "-w", type=str, default="", help="Path to workflow.json")
    parser.add_argument(
        "--sandbox",
        "-s",
        type=str,
        choices=["static-only", "static", "gvisor", "microsandbox", "gce"],
        help="Sandbox execution override",
    )
    parser.add_argument(
        "--model",
        "-m",
        type=str,
        help="Global LLM model override (e.g. gemini-3.7-flash, vertex_ai/claude-opus-5, openai/my-model)",
    )
    parser.add_argument("--api-base", type=str, help="Custom LLM API Base URL for OpenAI-compatible models")
    parser.add_argument(
        "--reasoning-effort",
        type=str,
        choices=["low", "medium", "high"],
        help="Reasoning effort override (low, medium, high)",
    )
    parser.add_argument("--timeout", type=float, help="LLM request timeout in seconds")
    parser.add_argument("--db", "-d", type=str, help="Path to knowledge SQLite database")
    parser.add_argument(
        "--flex",
        action="store_true",
        help="Use Vertex AI Gemini Flex tier (routes requests via shared Flex capacity).",
    )

    # Options
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
) -> int:
    """Core launch workflow: auto-configures, preflights, and executes the Mantis pipeline."""
    if flex:
        os.environ["VERTEX_FLEX"] = "1"

    target_path = Path(target).resolve()
    if not target_path.exists():
        print(f"❌ Error: Target '{target}' does not exist.", file=sys.stderr)
        return 1

    wf_file = find_workflow_json(workflow_path)
    wf_data = load_workflow_dict(wf_file)
    cfg = wf_data.get("config", {})

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
            )

    # Preflight Check
    ok, messages = run_preflight_checks(cfg, target_path=str(target_path))
    if not ok and auto_configure and not is_unconf and not interactive:
        if os.environ.get("MANTIS_ALLOW_SANDBOX_DOWNGRADE") == "1":
            print("⚙️ Preflight check failed on existing configuration, attempting approved auto-configuration...")
            cfg = ensure_configured(
                workflow_path=wf_file,
                auto=True,
                overrides=overrides if overrides else None,
            )
            ok, messages = run_preflight_checks(cfg, target_path=str(target_path))
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

    if preflight_only:
        print("✅ Preflight validation succeeded.")
        for msg in messages:
            print(f"  {msg}")
        return 0

    if dry_run:
        print("\n📋 Dry-Run Execution Plan:")
        print(f"  • Target:        {target_path}")
        print(f"  • Workflow:      {wf_file}")
        print(f"  • Sandbox:       {cfg.get('sandbox', {}).get('type', 'static-only')}")
        print(f"  • Model:         {model or cfg.get('default_model')}")
        print(f"  • Knowledge DB:  {db_path or cfg.get('db_path', 'knowledge.db')}")
        return 0

    # Launch Pipeline
    return asyncio.run(
        pipeline(
            scan_target=str(target_path),
            workflow_path=wf_file,
            model_override=model,
            api_base_override=api_base,
            sandbox_override=sandbox,
            db_override=db_path,
            timeout_override=timeout,
            reasoning_effort_override=reasoning_effort,
            auto_configure=auto_configure,
        )
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    return run_launch(
        target=args.target,
        workflow_path=args.workflow,
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
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\nProcess aborted by user.")
        sys.exit(130)

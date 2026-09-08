import asyncio
import json
import sys
import os
import uuid
import hashlib
import dataclasses
import subprocess
import warnings
from pathlib import Path
from typing import Optional

# Suppress noisy ADK preview/experimental feature notices
warnings.filterwarnings("ignore", message=r".*\[EXPERIMENTAL\].*")

from google.genai import types
from google.adk.runners import Runner, RunConfig
from google.adk.agents.run_config import StreamingMode
from google.adk.agents.invocation_context import LlmCallsLimitExceededError
from google.adk.sessions.sqlite_session_service import SqliteSessionService
from google.adk.sessions.base_session_service import BaseSessionService
from google.adk.apps.app import App, ResumabilityConfig
from google.adk.apps.compaction import EventsCompactionConfig
from google.adk.agents.context_cache_config import ContextCacheConfig

from core.budget import BudgetConfig, BudgetController, BudgetExceededError
from core.database import init_db, read_findings, read_risk_scores, update_status
from core.sandbox import build_sandbox
from core.graph_loader import load_workflow_from_json, DEFAULT_SEED_PROMPT
from core.context import RunContext, current_run_context
from core.paths import resolve_db_path
from core.config import MantisAuthError, is_auth_error, format_auth_error_message, ResilientLiteLlm
from core.compactor import MantisEventsSummarizer
from core.llm_gateway import strip_terminal_control

APP_NAME = "mantis_graph"
USER_ID = "user1"


def cprint(*args, **kwargs) -> None:
    """Console emitter for untrusted content (model text, tool responses, DB rows).

    SECURITY: strips terminal escape sequences and control characters so scanned
    repository content cannot repaint, reset or relocate the operator's terminal,
    or forge trusted-looking pipeline banners in the scroll-back.
    """
    cleaned = [strip_terminal_control(a) if isinstance(a, str) else a for a in args]
    print(*cleaned, **kwargs)


async def execute_sub_task(
    runner: Runner,
    session_service: BaseSessionService,
    filepath: str,
    run_id: str,
    db_path: str = "",
    status_map: dict[str, str] | None = None,
    seed_prompt_template: str = DEFAULT_SEED_PROMPT,
    budget_controller: Optional[BudgetController] = None,
) -> bool:
    """Executes the workflow graph for a single target file. Returns True if an error was encountered."""
    sanitized_filepath = str(filepath).replace("\n", "").replace("\r", "").strip()
    target_hash = hashlib.sha256(sanitized_filepath.encode("utf-8")).hexdigest()[:8]
    session_id = f"session_run_{run_id}_{target_hash}"
    existing_session = await session_service.get_session(app_name=APP_NAME, user_id=USER_ID, session_id=session_id)
    if existing_session is None:
        initial_state = {"db_path": db_path, "run_id": run_id, "filepath": sanitized_filepath}
        await session_service.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=session_id, state=initial_state)
    elif hasattr(existing_session, "state") and isinstance(existing_session.state, dict):
        existing_session.state.setdefault("db_path", db_path)
        existing_session.state.setdefault("run_id", run_id)
        existing_session.state.setdefault("filepath", sanitized_filepath)

    # Detect and record VCS metadata into SQLite knowledge base for reporting provenance
    if db_path and os.path.exists(os.path.dirname(os.path.abspath(db_path)) or "."):
        try:
            from tools.research_tools import detect_vcs_info
            from core.database import record_artifact
            vcs_meta = detect_vcs_info(sanitized_filepath)
            vcs_json = json.dumps(vcs_meta, indent=2)
            record_artifact(db_path, run_id, "vcs_info", "workspace/.structured/vcs_info.json", vcs_json)
        except Exception as e:
            print(f"[PROVENANCE WARNING] Failed to record VCS provenance: {e}", file=sys.stderr)

    resumed_invocation_id: Optional[str] = None
    if existing_session and existing_session.events:
        root_agent_name = getattr(getattr(runner, "agent", None), "name", None) or "mantis_vulnerability_pipeline"
        for ev in reversed(existing_session.events):
            inv_id = getattr(ev, "invocation_id", None)
            if inv_id:
                has_ended = any(
                    getattr(e, "invocation_id", None) == inv_id
                    and getattr(getattr(e, "actions", None), "end_of_agent", False)
                    and getattr(e, "author", None) in (root_agent_name, "mantis_vulnerability_pipeline")
                    for e in existing_session.events
                )
                if not has_ended:
                    resumed_invocation_id = inv_id
                break

    if resumed_invocation_id:
        new_message = None
    else:
        # SECURITY: literal substitution, not str.format(). A template containing a
        # format spec such as "{filepath:>9999999999}" would otherwise be evaluated
        # here, and conversion/attribute syntax would traverse object internals.
        query_text = (
            str(seed_prompt_template)
            .replace("{filepath}", str(sanitized_filepath))
            .replace("{run_id}", str(run_id))
        )
        new_message = types.Content(
            parts=[types.Part.from_text(text=query_text)],
            role="user"
        )
    
    print(f"\n[GRAPH EXECUTION] Triggered via: {filepath}")
    print("-" * 60)
    
    errored: set[str] = set()
    stamped_nodes: set[str] = set()
    last_banner: tuple[str | None, str | None] = (None, None)
    current_active_node: str | None = None
    streamed_partial_text: bool = False

    max_calls = 0
    if budget_controller and budget_controller.config.max_llm_calls > 0:
        max_calls = budget_controller.config.max_llm_calls
    run_cfg = RunConfig(
        max_llm_calls=max_calls,
        streaming_mode=StreamingMode.NONE,
    )

    try:
        async for event in runner.run_async(
            user_id=USER_ID,
            session_id=session_id,
            invocation_id=resumed_invocation_id,
            new_message=new_message,
            run_config=run_cfg,
        ):
            node_path = getattr(getattr(event, "node_info", None), "path", None)
            route = getattr(getattr(event, "actions", None), "route", None)

            if node_path:
                node_name = node_path.split("/")[-1].split("@")[0]
                if node_name != current_active_node:
                    current_active_node = node_name
                    streamed_partial_text = False
                    ctx = current_run_context.get()
                    if ctx:
                        ctx.active_node = node_name
                    if budget_controller:
                        budget_controller.record_step(node_name)

                if status_map and db_path and node_name in status_map and node_name not in stamped_nodes:
                    stamped_nodes.add(node_name)
                    new_status = status_map[node_name]
                    ctx = current_run_context.get()
                    if new_status in ("dynamic_confirmed", "patch_verified") and not (ctx and ctx.sandbox_executed):
                        pass
                    else:
                        update_status(db_path, filepath, run_id, new_status)

            banner = (node_path, route)
            if (node_path or route) and banner != last_banner:
                if node_path and route:
                    print(f"\n-- {node_path} -> {route}")
                elif node_path:
                    print(f"\n-- {node_path}")
                elif route:
                    print(f"\n-- {last_banner[0] or ''} -> {route}")
                last_banner = banner

            if getattr(event, "error_code", None):
                node_key = node_path or "unknown"
                errored.add(node_key)
                err_msg = getattr(event, "error_message", None) or f"ADK Event error: {event.error_code}"
                if event.error_code == "MantisAuthError" or is_auth_error(err_msg):
                    raise MantisAuthError(err_msg)
                if event.error_code in ("BudgetExceededError", "LlmCallsLimitExceededError"):
                    limit_val = budget_controller.config.max_llm_calls if budget_controller else 500
                    raise BudgetExceededError(
                        trigger="llm_calls_limit" if event.error_code == "LlmCallsLimitExceededError" else "budget_exceeded",
                        current_value="limit exceeded",
                        limit_value=limit_val,
                        run_id=run_id,
                        details=str(err_msg),
                    )
                print(f"\n[EVENT ERROR {event.error_code}] {err_msg}", file=sys.stderr)
            else:
                usage = getattr(event, "usage_metadata", None)
                if budget_controller and usage and getattr(usage, "total_token_count", None):
                    total_tokens = int(usage.total_token_count)
                    cached_tokens = int(getattr(usage, "cached_content_token_count", 0) or 0)
                    budget_controller.record_tokens(total_tokens, cached_count=cached_tokens, cache_discount=0.1)

                if hasattr(event, 'content') and event.content:
                    is_partial = getattr(event, "partial", False)
                    for part in getattr(event.content, "parts", []) or []:
                        if hasattr(part, 'text') and part.text:
                            # In streaming mode, print partial chunks incrementally.
                            # Skip final aggregated non-partial text only if partial text was already streamed.
                            if is_partial:
                                cprint(part.text, end="", flush=True)
                                streamed_partial_text = True
                            elif not streamed_partial_text or run_cfg.streaming_mode != StreamingMode.SSE:
                                cprint(part.text, end="", flush=True)
                            if not is_partial:
                                streamed_partial_text = False
                                if budget_controller and not (usage and getattr(usage, "total_token_count", None)):
                                    budget_controller.record_tokens(len(part.text) // 4)
                            if current_active_node == "reporter" and db_path and run_id:
                                try:
                                    from core.schemas import ExecutiveReport
                                    from core.database import record_artifact
                                    rpt_text = part.text.strip()
                                    if "```json" in rpt_text:
                                        rpt_text = rpt_text.split("```json", 1)[1].split("```", 1)[0].strip()
                                    elif "```" in rpt_text:
                                        rpt_text = rpt_text.split("```", 1)[1].split("```", 1)[0].strip()
                                    if rpt_text.startswith("{") and rpt_text.endswith("}"):
                                        rpt_data = json.loads(rpt_text)
                                        rpt_obj = ExecutiveReport.model_validate(rpt_data)
                                        record_artifact(db_path, run_id, "report", "workspace/.structured/report.json", rpt_obj.model_dump_json(indent=2))
                                except Exception:
                                    pass
                        elif hasattr(part, 'function_call') and part.function_call:
                            call = part.function_call
                            call_name = getattr(call, "name", "unknown_tool")
                            call_args = getattr(call, "args", {})
                            cprint(f"\n[TOOL CALL: {call_name}] args={call_args}", flush=True)
                            if budget_controller:
                                budget_controller.record_tool_call(current_active_node or "unknown", call_name)
                        elif hasattr(part, 'function_response') and part.function_response:
                            fn_resp = part.function_response
                            fn_name = getattr(fn_resp, "name", "unknown_tool")
                            raw_resp = getattr(fn_resp, "response", {})
                            if isinstance(raw_resp, dict):
                                resp_text = str(raw_resp.get("response") or raw_resp.get("result") or raw_resp.get("output") or raw_resp)
                            else:
                                resp_text = str(raw_resp)
                            
                            is_untrusted_data = resp_text.startswith("<<<UNTRUSTED_SOURCE_CODE_DATA_START")
                            is_sandbox_error = fn_name in ("run_sandbox", "run_sandbox_with_evidence") and (
                                "SANDBOX-ERROR:" in resp_text and not resp_text.startswith("exit=0")
                            )
                            is_fatal = not is_untrusted_data and (
                                resp_text.startswith("SANDBOX-ERROR")
                                or resp_text.startswith("ERROR SAVING DB")
                                or resp_text.startswith("FATAL ERROR")
                                or is_sandbox_error
                            )
                            is_validation_feedback = (
                                not is_untrusted_data
                                and not is_fatal
                                and (
                                    resp_text.startswith("Error")
                                    or resp_text.startswith("ERROR")
                                )
                                and "SANDBOX-UNAVAILABLE" not in resp_text
                            )

                            if is_fatal:
                                errored.add(f"tool:{fn_name}")
                                cprint(f"\n[TOOL FATAL ERROR: {fn_name}] {resp_text}", file=sys.stderr, flush=True)
                            elif is_validation_feedback:
                                cprint(f"\n[TOOL FEEDBACK: {fn_name}] {resp_text}", flush=True)
                            else:
                                cprint(f"\n[TOOL RESPONSE: {fn_name}] {resp_text[:500]}", flush=True)
    except LlmCallsLimitExceededError as le:
        limit_val = budget_controller.config.max_llm_calls if budget_controller else 500
        raise BudgetExceededError(
            trigger="llm_calls_limit",
            current_value="limit exceeded",
            limit_value=limit_val,
            run_id=run_id,
            details=f"ADK LLM calls limit of {limit_val} exceeded ({le})",
        ) from le
    except MantisAuthError:
        raise
    except Exception as e:
        if is_auth_error(e):
            raise MantisAuthError(format_auth_error_message(e)) from None
        raise
    finally:
        # Session trajectories are retained in session_service database for auditability and rehydration
        pass
            
    print("\n" + "-" * 60)
    return bool(errored)

def is_binary_file(path: Path, block_size: int = 1024) -> bool:
    """Returns True if the file contains null bytes in its initial block."""
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(block_size)
    except OSError:
        return True

def discover_files(target: Path, db_path: str = "") -> list[str]:
    """Source files under `target`. Uses git's own view when available —
    a repo already declares what isn't source. Excludes binary files."""
    if target.is_file():
        return [str(target)] if not is_binary_file(target) else []
    try:
        from tools.research_tools import _run_safe_git_command
        out, ok = _run_safe_git_command(
            ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            target,
            ceiling_dir="",
        )
        if ok and out:
            paths = [target / p for p in out.split("\0") if p]
            if paths:
                return [
                    str(p) for p in sorted(paths)
                    if p.is_file() and not p.is_symlink() and str(p) != db_path and not is_binary_file(p)
                ]
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass
    return [
        str(p) for p in sorted(target.rglob("*"))
        if p.is_file() and not p.is_symlink() and str(p) != db_path and not any(part.startswith(".") for part in p.parts) and not is_binary_file(p)
    ]

async def pipeline(
    scan_target: str,
    workflow_path: str = "",
    model_override: Optional[str] = None,
    api_base_override: Optional[str] = None,
    sandbox_override: Optional[dict | str] = None,
    db_override: Optional[str] = None,
    timeout_override: Optional[float] = None,
    reasoning_effort_override: Optional[str] = None,
    auto_configure: bool = True,
    load_local: bool = True,
    budget_config: Optional[BudgetConfig] = None,
    resume_run_id: str = "",
    objective: str = "",
    enable_compaction: Optional[bool] = None,
    enable_context_cache: Optional[bool] = None,
    max_llm_calls_override: Optional[int] = None,
    max_node_tool_calls_override: Optional[int] = None,
):
    """Main pipeline loop compiled declaratively from JSON specification."""
    if not workflow_path:
        pipeline_dir = os.path.realpath(os.path.dirname(__file__))
        workflow_path = os.path.join(pipeline_dir, "workflow.json")

    # Auto-resolve unconfigured placeholders if enabled
    if auto_configure:
        try:
            from scripts.configure import ensure_configured_async
            overrides = {}
            if model_override:
                overrides["default_model"] = model_override
            if api_base_override:
                overrides["api_base"] = api_base_override
            if sandbox_override:
                overrides["sandbox"] = sandbox_override
            if db_override:
                overrides["db_path"] = db_override
            if timeout_override is not None:
                overrides["timeout"] = timeout_override
            if reasoning_effort_override:
                overrides["reasoning_effort"] = reasoning_effort_override
            await ensure_configured_async(workflow_path, auto=True, overrides=overrides if overrides else None)
        except Exception as ce:
            print(f"[CONFIG WARNING] Auto-configuration check: {ce}", file=sys.stderr)

    try:
        effective_load_local = False if (objective or "workflows/recipes" in str(workflow_path)) else load_local
        workflow, config = load_workflow_from_json(
            workflow_path,
            model_override=model_override,
            api_base_override=api_base_override,
            sandbox_override=sandbox_override,
            db_override=db_override,
            timeout_override=timeout_override,
            reasoning_effort_override=reasoning_effort_override,
            load_local=effective_load_local,
        )
    except ValueError as e:
        print(f"Workflow Specification Error: {e}", file=sys.stderr)
        return 1

    try:
        from scripts.configure import run_preflight_checks_async
        ok, msgs = await run_preflight_checks_async(config)
        if not ok:
            for m in msgs:
                print(f"[PREFLIGHT WARNING] {m}", file=sys.stderr)
    except Exception:
        pass

    # SECURITY (INV-4): component-wise symlink validation (see core/paths.py).
    from core.paths import validate_scan_target

    target_path, target_err = validate_scan_target(scan_target)
    if target_path is None:
        print(f"Error: {target_err}", file=sys.stderr)
        return 1

    db_path = config.get("db_path", "knowledge.db")
    init_db(db_path)

    discovered_files = discover_files(target_path, db_path)
    if not discovered_files:
        print(f"Error: No source files found in target: {target_path}", file=sys.stderr)
        return 1

    run_id = resume_run_id if resume_run_id else str(uuid.uuid4())
    # Resolve budget configuration: explicit caller override > workflow.json budget > default BudgetConfig()
    resolved_budget = budget_config
    if resolved_budget is None:
        if "budget" in config and config["budget"]:
            resolved_budget = BudgetConfig.from_dict(config["budget"])
        else:
            resolved_budget = BudgetConfig()
    if max_llm_calls_override is not None:
        resolved_budget.max_llm_calls = max_llm_calls_override
    if max_node_tool_calls_override is not None:
        resolved_budget.max_node_tool_calls = max_node_tool_calls_override
    budget_ctrl = BudgetController(config=resolved_budget, run_id=run_id)

    # Target isolation: host target is treated as strictly read-only.
    # Mutations occur only in isolated guest sandboxes or under workspace/.
    snapshot_id = config.get("kb_snapshot_id") or ""
    if target_path.is_file():
        targets_to_scan = [str(target_path)]
        jail_dir = str(target_path.parent)
    else:
        # Repository scope: execute unified campaign across entire repository
        targets_to_scan = [str(target_path)]
        jail_dir = str(target_path)

    if resume_run_id:
        existing_findings = read_findings(db_path, run_id=run_id)
        if existing_findings and (not scan_target or scan_target == "."):
            stored_target = existing_findings[0].get("target_file") or existing_findings[0].get("filepath")
            if stored_target and os.path.exists(stored_target):
                target_path = Path(stored_target).resolve()
        print(f"\n🔄 Resuming Run ID: {run_id} ({len(existing_findings)} existing finding(s) checkpointed)")

    print(f"Compiling Graph Pipeline. Target: {target_path} ({len(discovered_files)} source file(s) indexed)")

    try:
        test_sandbox = build_sandbox(config.get("sandbox", {}), targets_to_scan[0])
        await test_sandbox.preflight()
        await test_sandbox.aclose()
    except (ValueError, TypeError, RuntimeError) as e:
        print(f"Sandbox Configuration Error: {e}", file=sys.stderr)
        return 2

    compaction_config = None
    use_compaction = config.get("enable_compaction", True) if enable_compaction is None else enable_compaction
    if use_compaction:
        comp_model_id = config.get("compaction_model") or config.get("default_model") or "vertex_ai/gemini-3.5-flash-lite"
        comp_llm = ResilientLiteLlm(model=comp_model_id)
        compaction_config = EventsCompactionConfig(
            token_threshold=int(config.get("compaction_token_threshold", 500000)),
            event_retention_size=int(config.get("compaction_event_retention", 50)),
            summarizer=MantisEventsSummarizer(llm=comp_llm),
        )

    context_cache_config = None
    use_context_cache = config.get("enable_context_cache", True) if enable_context_cache is None else enable_context_cache
    if use_context_cache:
        context_cache_config = ContextCacheConfig()

    run_app = App(
        name=APP_NAME,
        root_agent=workflow,
        events_compaction_config=compaction_config,
        context_cache_config=context_cache_config,
        resumability_config=ResumabilityConfig(is_resumable=True),
    )

    # SECURITY (INV-4): a relative session-db name is resolved by sqlite against $CWD,
    # which during a campaign is the untrusted checkout. Anchor and symlink-check it.
    sessions_db_path = resolve_db_path(
        config.get("sessions_db_path") or os.environ.get("MANTIS_SESSIONS_DB") or "",
        default_name="sessions.db",
    )
    session_service = SqliteSessionService(db_path=sessions_db_path)
    runner = Runner(
        app=run_app,
        session_service=session_service
    )

    base_ctx = RunContext(
        jail_dir=jail_dir,
        db_path=db_path,
        target_file="",
        run_id=run_id,
        snapshot_id=snapshot_id,
        budget_controller=budget_ctrl,
    )

    print(f"\n🚀 Engaging JSON Graph over target: {target_path} (Run ID: {run_id})...")

    failures = 0
    successes = 0
    paused = False
    try:
        for scan_item in targets_to_scan:
            sandbox = build_sandbox(config.get("sandbox", {}), scan_item)
            branch_ctx = dataclasses.replace(base_ctx, target_file=scan_item, sandbox=sandbox)
            current_run_context.set(branch_ctx)
            try:
                task_failed = await execute_sub_task(
                    runner,
                    session_service,
                    scan_item,
                    run_id,
                    db_path=db_path,
                    status_map=config.get("on_enter_status", {}),
                    seed_prompt_template=config.get("seed_prompt", DEFAULT_SEED_PROMPT),
                    budget_controller=budget_ctrl,
                )
                if task_failed:
                    failures += 1
                else:
                    successes += 1
            except BudgetExceededError as be:
                print("\n" + budget_ctrl.format_pause_banner(
                    trigger=be.details,
                    target=str(scan_target),
                    workflow=str(workflow_path),
                ))
                paused = True
                break
            except MantisAuthError as ae:
                print(f"\n{ae}", file=sys.stderr)
                return 1
            except Exception as e:
                if is_auth_error(e):
                    print(f"\n{format_auth_error_message(e)}", file=sys.stderr)
                    return 1
                print(f"PIPELINE CRITICAL ABORT IN TASK ({scan_item}): {e}", file=sys.stderr)
                failures += 1
            finally:
                await sandbox.aclose()
    finally:
        await runner.close()

    findings = read_findings(db_path, run_id=run_id)
    scores = read_risk_scores(db_path, run_id=run_id)
    suppressed_statuses = {"duplicate_merged", "false_positive", "non_viable", "sample_or_test", "reported"}
    active_findings = [f for f in findings if f.get("status") not in suppressed_statuses]
    print(f"\n📊 Summary: {len(active_findings)} active / {len(findings)} total vulnerability finding(s) recorded.")
    for f in findings:
        lines_str = f" (Lines: {f.get('line_numbers')})" if f.get('line_numbers') else ""
        st = f.get("status") or ""
        if st == "duplicate_merged":
            mark = " [duplicate_merged]"
        elif st == "reported":
            mark = " (suppressed at review)"
        elif st in ("false_positive", "non_viable", "sample_or_test"):
            mark = f" [{st}]"
        else:
            mark = f" [{st}]" if st else ""
        cprint(f"  - [{f.get('severity', 'Unknown')}] {f.get('filepath')}: {f.get('title')}{lines_str}{mark}")
    if scores:
        print("\n🎯 Risk Calibration Scores:")
        for s in scores:
            score_val = float(s.get('score', 0))
            cprint(f"  - {s.get('filepath')}: {score_val:.1f}/10.0 - {s.get('reasoning')}")

    if paused:
        return 2
    if failures > 0:
        print(f"\n⚠️ Pipeline completed with {failures} failure(s).")
        return 1
    elif len(findings) == 0:
        print(f"\nℹ️ Pipeline Execution Completed: No vulnerability findings recorded.")
        return 0
    elif len(active_findings) == 0:
        print(f"\nℹ️ Pipeline Execution Completed: No active vulnerability findings recorded ({len(findings)} suppressed/merged).")
        return 0
    else:
        print(f"\n🎉 Pipeline Execution Completed: Processed {len(active_findings)} active vulnerability finding(s).")
        return 0


def parse_cli_args():
    import argparse
    parser = argparse.ArgumentParser(description="Mantis Vulnerability Review Pipeline")
    parser.add_argument("target", help="Directory or file to scan")
    parser.add_argument("--workflow", "-w", type=str, default="", help="Path to workflow.json")
    parser.add_argument(
        "--sandbox",
        "-s",
        type=str,
        choices=["static-only", "static", "gvisor", "microsandbox", "gce"],
        help="Sandbox override",
    )
    parser.add_argument("--model", "-m", type=str, help="Global LLM model override")
    parser.add_argument("--api-base", type=str, help="Custom LLM API Base URL")
    parser.add_argument(
        "--reasoning-effort",
        type=str,
        choices=["low", "medium", "high"],
        help="Reasoning effort override",
    )
    parser.add_argument("--timeout", type=float, help="LLM timeout in seconds")
    parser.add_argument("--db", "-d", type=str, help="Knowledge SQLite DB path")
    parser.add_argument(
        "--no-auto-configure",
        action="store_true",
        help="Disable auto-configuration of unconfigured placeholders",
    )
    parser.add_argument(
        "--no-compaction",
        action="store_true",
        help="Disable ADK event compaction",
    )
    parser.add_argument(
        "--no-context-cache",
        action="store_true",
        help="Disable ADK context caching",
    )
    parser.add_argument(
        "--max-llm-calls",
        type=int,
        default=None,
        help="ADK LLM calls limit ceiling override (0 for unbounded, defaults to workflow budget)",
    )
    parser.add_argument(
        "--max-node-tool-calls",
        type=int,
        default=None,
        help="Per-node visit runaway tool loop ceiling override (defaults to workflow budget)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./run.sh <directory_or_file_to_scan> [flags...]")
        sys.exit(1)

    args = parse_cli_args()
    try:
        exit_code = asyncio.run(
            pipeline(
                scan_target=args.target,
                workflow_path=args.workflow,
                model_override=args.model,
                api_base_override=args.api_base,
                sandbox_override=args.sandbox,
                db_override=args.db,
                timeout_override=args.timeout,
                reasoning_effort_override=args.reasoning_effort,
                auto_configure=not args.no_auto_configure,
                enable_compaction=False if args.no_compaction else None,
                enable_context_cache=False if args.no_context_cache else None,
                max_llm_calls_override=args.max_llm_calls,
                max_node_tool_calls_override=args.max_node_tool_calls,
            )
        )
        sys.exit(exit_code)
    except MantisAuthError as ae:
        print(f"\n{ae}", file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\nProcess aborted by user.")
        sys.exit(130)

import asyncio
import sys
import os
import uuid
import dataclasses
import subprocess
from pathlib import Path

from google.genai import types
from google.adk.runners import Runner
from google.adk.sessions.sqlite_session_service import SqliteSessionService
from google.adk.sessions.base_session_service import BaseSessionService
from google.adk.apps.app import App

from core.database import init_db, read_findings, read_risk_scores, update_status
from core.sandbox import build_sandbox
from core.graph_loader import load_workflow_from_json, DEFAULT_SEED_PROMPT
from core.context import RunContext, current_run_context

APP_NAME = "mantis_graph"
USER_ID = "user1"

async def execute_sub_task(
    runner: Runner,
    session_service: BaseSessionService,
    filepath: str,
    run_id: str,
    db_path: str = "",
    status_map: dict[str, str] | None = None,
    seed_prompt_template: str = DEFAULT_SEED_PROMPT,
) -> bool:
    """Executes the workflow graph for a single target file. Returns True if an error was encountered."""
    session_id = f"session_run_{run_id}_{uuid.uuid4().hex[:8]}"
    await session_service.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=session_id)
    
    try:
        query_text = seed_prompt_template.format(filepath=filepath, run_id=run_id)
    except KeyError:
        query_text = seed_prompt_template.format(filepath=filepath)
    new_message = types.Content(
        parts=[types.Part.from_text(text=query_text)],
        role="user"
    )
    
    print(f"\n[GRAPH EXECUTION] Triggered via: {filepath}")
    print("-" * 60)
    
    errored: set[str] = set()
    stamped_nodes: set[str] = set()
    last_banner: tuple[str | None, str | None] = (None, None)

    try:
        async for event in runner.run_async(user_id=USER_ID, session_id=session_id, new_message=new_message):
            node_path = getattr(getattr(event, "node_info", None), "path", None)
            route = getattr(getattr(event, "actions", None), "route", None)

            if node_path:
                node_name = node_path.split("/")[-1].split("@")[0]
                if status_map and db_path and node_name in status_map and node_name not in stamped_nodes:
                    stamped_nodes.add(node_name)
                    new_status = status_map[node_name]
                    ctx = current_run_context.get()
                    if new_status == "dynamic_confirmed" and not (ctx and ctx.sandbox_executed):
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
                print(f"\n[EVENT ERROR {event.error_code}] {err_msg}", file=sys.stderr)
            else:
                if node_path and node_path in errored:
                    errored.discard(node_path)
                if hasattr(event, 'content') and event.content:
                    for part in getattr(event.content, "parts", []) or []:
                        if hasattr(part, 'text') and part.text:
                            print(part.text, end="", flush=True)
                        elif hasattr(part, 'function_call') and part.function_call:
                            call = part.function_call
                            call_name = getattr(call, "name", "unknown_tool")
                            call_args = getattr(call, "args", {})
                            print(f"\n[TOOL CALL: {call_name}] args={call_args}")
                        elif hasattr(part, 'function_response') and part.function_response:
                            fn_resp = part.function_response
                            fn_name = getattr(fn_resp, "name", "unknown_tool")
                            raw_resp = getattr(fn_resp, "response", {})
                            if isinstance(raw_resp, dict):
                                resp_text = str(raw_resp.get("response") or raw_resp.get("result") or raw_resp.get("output") or raw_resp)
                            else:
                                resp_text = str(raw_resp)
                            
                            is_fatal = (
                                resp_text.startswith("SANDBOX-ERROR")
                                or "ERROR SAVING DB" in resp_text
                                or "FATAL ERROR" in resp_text
                            )
                            is_validation_feedback = (
                                resp_text.startswith("Error")
                                or resp_text.startswith("ERROR")
                            ) and "SANDBOX-UNAVAILABLE" not in resp_text

                            if is_fatal:
                                errored.add(f"tool:{fn_name}")
                                print(f"\n[TOOL FATAL ERROR: {fn_name}] {resp_text}", file=sys.stderr)
                            elif is_validation_feedback:
                                print(f"\n[TOOL FEEDBACK: {fn_name}] {resp_text}")
                            else:
                                errored.discard(f"tool:{fn_name}")
                                print(f"\n[TOOL RESPONSE: {fn_name}] {resp_text[:500]}")
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
        out = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
             "-C", str(target), "ls-files", "-z",
             "--cached", "--others", "--exclude-standard"],
            capture_output=True, text=True, timeout=10, check=True
        ).stdout
        paths = [target / p for p in out.split("\0") if p]
        if paths:
            return [
                str(p) for p in sorted(paths)
                if p.is_file() and str(p) != db_path and not is_binary_file(p)
            ]
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass
    return [
        str(p) for p in sorted(target.rglob("*"))
        if p.is_file() and str(p) != db_path and not any(part.startswith(".") for part in p.parts) and not is_binary_file(p)
    ]

async def pipeline(scan_target: str, workflow_path: str = ""):
    """Main pipeline loop compiled declaratively from JSON specification."""
    if not workflow_path:
        pipeline_dir = os.path.realpath(os.path.dirname(__file__))
        workflow_path = os.path.join(pipeline_dir, "workflow.json")

    try:
        workflow, config = load_workflow_from_json(workflow_path)
    except ValueError as e:
        print(f"Workflow Specification Error: {e}", file=sys.stderr)
        return 1

    target_path = Path(scan_target).resolve()
    if not target_path.exists():
        print(f"Target '{scan_target}' does not exist.", file=sys.stderr)
        return 1

    db_path = config.get("db_path", "knowledge.db")
    init_db(db_path)

    discovered_files = discover_files(target_path, db_path)
    if not discovered_files:
        print(f"Error: No source files found in target: {target_path}", file=sys.stderr)
        return 1

    if target_path.is_file():
        targets_to_scan = [str(target_path)]
        jail_dir = str(target_path.parent)
    else:
        # Repository scope: execute the unified campaign across the entire repository
        targets_to_scan = [str(target_path)]
        jail_dir = str(target_path)

    print(f"Compiling Graph Pipeline. Target: {target_path} ({len(discovered_files)} source file(s) indexed)")
    
    try:
        test_sandbox = build_sandbox(config.get("sandbox", {}), targets_to_scan[0])
        await test_sandbox.preflight()
        await test_sandbox.aclose()
    except (ValueError, TypeError, RuntimeError) as e:
        print(f"Sandbox Configuration Error: {e}", file=sys.stderr)
        return 2

    run_app = App(
        name=APP_NAME,
        root_agent=workflow
    )
    
    sessions_db_path = config.get("sessions_db_path") or os.environ.get("MANTIS_SESSIONS_DB") or "sessions.db"
    session_service = SqliteSessionService(db_path=sessions_db_path)
    runner = Runner(
        app=run_app,
        session_service=session_service
    )

    run_id = str(uuid.uuid4())
    base_ctx = RunContext(
        jail_dir=jail_dir,
        db_path=db_path,
        target_file="",
        run_id=run_id
    )

    print(f"\n🚀 Engaging JSON Graph over target: {target_path} (Run ID: {run_id})...")
    
    failures = 0
    successes = 0
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
                    seed_prompt_template=config.get("seed_prompt", DEFAULT_SEED_PROMPT)
                )
                if task_failed:
                    failures += 1
                else:
                    successes += 1
            except Exception as e:
                print(f"PIPELINE CRITICAL ABORT IN TASK ({scan_item}): {e}", file=sys.stderr)
                failures += 1
            finally:
                await sandbox.aclose()
    finally:
        await runner.close()
        findings = read_findings(db_path, run_id=run_id)
        scores = read_risk_scores(db_path, run_id=run_id)
        print(f"\n📊 Summary: {len(findings)} vulnerability finding(s) recorded.")
        for f in findings:
            lines_str = f" (Lines: {f.get('line_numbers')})" if f.get('line_numbers') else ""
            mark = " (suppressed at review)" if f.get("status") == "reported" else ""
            print(f"  - [{f.get('severity', 'Unknown')}] {f.get('filepath')}: {f.get('title')}{lines_str}{mark}")
        if scores:
            print("\n🎯 Risk Calibration Scores:")
            for s in scores:
                score_val = float(s.get('score', 0))
                print(f"  - {s.get('filepath')}: {score_val:.1f}/10.0 - {s.get('reasoning')}")

        if failures > 0:
            print(f"\n⚠️ Pipeline completed with {failures} failure(s).")
            return 1
        elif len(findings) == 0:
            print(f"\nℹ️ Pipeline Execution Completed: No vulnerability findings recorded.")
            return 0
        else:
            print(f"\n🎉 Pipeline Execution Completed: Processed {len(findings)} vulnerability finding(s).")
            return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./run.sh <directory_or_file_to_scan>")
        sys.exit(1)
        
    target = sys.argv[1]
    try:
        exit_code = asyncio.run(pipeline(target))
        sys.exit(exit_code)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\nProcess aborted by user.")
        sys.exit(130)

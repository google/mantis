from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.context import current_run_context
from core.llm_gateway import SecretScrubber, wrap_untrusted_content
from google.adk.environment import ExecutionResult

MANTIS_SENTINEL_TOKEN = "MANTIS_REACHED_ENTRYPOINT"

_SANITIZER_SIGNALS = [
    re.compile(r"==\d+==ERROR:\s+(?:AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer|LeakSanitizer)", re.IGNORECASE),
    re.compile(r"SUMMARY:\s+(?:AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer):", re.IGNORECASE),
    re.compile(r"runtime error:\s+", re.IGNORECASE),
    re.compile(r"(?:Segmentation fault|SIGSEGV|SIGABRT|core dumped)", re.IGNORECASE),
    re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+([a-zA-Z0-9_:]+)", re.IGNORECASE),
]


def check_reached_sink_evidence(
    output: str,
    exit_code: int,
    sink_symbol: str = "",
    sentinel_content: str = "",
) -> Tuple[bool, str]:
    """Deterministically checks whether reached-sink evidence is present per INV-1 and INV-2 invariants.

    Returns:
        Tuple of (evidence_present: bool, reason: str)
    """
    # Fail-closed checks: command not found or missing file is EVIDENCE ABSENT
    if exit_code == 127:
        return False, "EVIDENCE_ABSENT: exit code 127 (command not found)"
    if "No such file or directory" in output and exit_code in (1, 2, 127):
        return False, "EVIDENCE_ABSENT: target or harness file not found"
    if "SANDBOX-UNAVAILABLE" in output:
        return False, "EVIDENCE_ABSENT: sandbox environment unavailable"

    # Channel A: Sidecar Sentinel File / explicit in-path flush token
    if sentinel_content and MANTIS_SENTINEL_TOKEN in sentinel_content:
        return True, "EVIDENCE_PRESENT: in-path sentinel marker MANTIS_REACHED_ENTRYPOINT verified"
    if MANTIS_SENTINEL_TOKEN in output:
        return True, "EVIDENCE_PRESENT: in-path sentinel marker emitted in execution trace"

    # Channel B: Target-produced Sanitizer / Crash backtrace naming sink
    has_sanitizer_or_crash = any(pat.search(output) for pat in _SANITIZER_SIGNALS)
    if has_sanitizer_or_crash:
        if sink_symbol:
            if sink_symbol in output:
                return True, f"EVIDENCE_PRESENT: crash backtrace explicitly confirms sink '{sink_symbol}'"
            return False, f"EVIDENCE_ABSENT: crash occurred but did not reach target sink '{sink_symbol}'"
        return True, "EVIDENCE_PRESENT: sanitizer/crash frame detected in execution output"

    return False, "EVIDENCE_ABSENT: no sentinel token or target-produced crash backtrace observed"


def _is_non_repro_node(ctx) -> bool:
    if ctx is None:
        return False
    active = getattr(ctx, "active_node", "")
    return bool(active and active not in ("reproducer", "patcher"))


async def run_sandbox(command: str) -> str:
    """Executes a command securely inside the configured sandbox. Use this to compile or run the reproduction script."""
    ctx = current_run_context.get()
    if ctx is None or ctx.sandbox is None:
        return "ERROR: No active sandbox environment (sandbox unavailable)."

    try:
        sandbox_type = type(ctx.sandbox).__name__
        is_static = sandbox_type in ("StaticOnlyEnvironment", "StaticOnlySandbox")

        if is_static:
            ctx.static_sandbox_attempts = getattr(ctx, "static_sandbox_attempts", 0) + 1
            if ctx.static_sandbox_attempts >= 3:
                if not _is_non_repro_node(ctx):
                    return (
                        f"ERROR: Sandbox execution permanently blocked in static-only mode (attempt {ctx.static_sandbox_attempts}). "
                        f"Dynamic execution is disabled. Do NOT call run_sandbox again. "
                        f"STOP calling tools immediately and submit your stage verdict using the 'set_model_response' tool "
                        f"(e.g. set_model_response(route='failed_repro', reason='Dynamic execution disabled in static-only mode')) "
                        f"or as structured JSON text (e.g. {{\"route\": \"failed_repro\", \"reason\": \"Dynamic execution disabled in static-only mode\"}}) "
                        f"in your model response to conclude this stage."
                    )
                return (
                    f"ERROR: Sandbox execution permanently blocked in static-only mode (attempt {ctx.static_sandbox_attempts}). "
                    f"Dynamic execution is disabled. Do NOT call run_sandbox again."
                )
            if not _is_non_repro_node(ctx):
                return (
                    "exit=127\n"
                    "SANDBOX-UNAVAILABLE: static-only sandbox; dynamic execution is disabled.\n"
                    "Do NOT retry running sandbox commands. In static-only mode, dynamic execution cannot be run. "
                    "Please update candidate findings in workspace/findings/ with repro_status='not_attempted', "
                    "STOP calling tools immediately, and submit your stage verdict using the 'set_model_response' tool "
                    "or as structured JSON text (e.g. {\"route\": \"failed_repro\", \"reason\": \"Dynamic execution disabled in static-only mode\"}) "
                    "in your model response."
                )
            return (
                "exit=127\n"
                "SANDBOX-UNAVAILABLE: static-only sandbox; dynamic execution is disabled.\n"
                "Do NOT retry running sandbox commands."
            )

        res = await ctx.sandbox.execute(command)
        if isinstance(res, ExecutionResult):
            raw_output = f"{res.stdout}{res.stderr}".strip()
            is_unavail = "SANDBOX-UNAVAILABLE" in raw_output or "SANDBOX-UNAVAILABLE" in res.stderr
            if is_unavail:
                ctx.static_sandbox_attempts = getattr(ctx, "static_sandbox_attempts", 0) + 1
                if ctx.static_sandbox_attempts >= 3:
                    if not _is_non_repro_node(ctx):
                        return (
                            f"ERROR: Sandbox execution permanently blocked (sandbox unavailable, attempt {ctx.static_sandbox_attempts}). "
                            f"Dynamic execution is disabled. Do NOT call run_sandbox again. "
                            f"STOP calling tools immediately and submit your stage verdict using the 'set_model_response' tool "
                            f"or as structured JSON text (e.g. {{\"route\": \"failed_repro\", \"reason\": \"Sandbox unavailable\"}}) "
                            f"in your model response to conclude this stage."
                        )
                    return (
                        f"ERROR: Sandbox execution permanently blocked (sandbox unavailable, attempt {ctx.static_sandbox_attempts}). "
                        f"Dynamic execution is disabled. Do NOT call run_sandbox again."
                    )
            elif res.exit_code != 127:
                ctx.sandbox_executed = True
            if not raw_output:
                return f"exit={res.exit_code}"
            scrubbed_output = SecretScrubber.scrub(raw_output)
            wrapped_output = wrap_untrusted_content(scrubbed_output, filename="sandbox_output")
            return f"exit={res.exit_code}\n{wrapped_output}"
        if isinstance(res, str):
            is_unavail = "SANDBOX-UNAVAILABLE" in res
            if is_unavail:
                ctx.static_sandbox_attempts = getattr(ctx, "static_sandbox_attempts", 0) + 1
                if ctx.static_sandbox_attempts >= 3:
                    if not _is_non_repro_node(ctx):
                        return (
                            f"ERROR: Sandbox execution permanently blocked (sandbox unavailable, attempt {ctx.static_sandbox_attempts}). "
                            f"Dynamic execution is disabled. Do NOT call run_sandbox again. "
                            f"STOP calling tools immediately and submit your stage verdict using the 'set_model_response' tool "
                            f"or as structured JSON text (e.g. {{\"route\": \"failed_repro\", \"reason\": \"Sandbox unavailable\"}}) "
                            f"in your model response to conclude this stage."
                        )
                    return (
                        f"ERROR: Sandbox execution permanently blocked (sandbox unavailable, attempt {ctx.static_sandbox_attempts}). "
                        f"Dynamic execution is disabled. Do NOT call run_sandbox again."
                    )
            elif res.startswith("exit=") and not res.startswith("exit=127"):
                ctx.sandbox_executed = True
            return SecretScrubber.scrub(res)
        return SecretScrubber.scrub(str(res))
    except Exception as e:
        return f"ERROR: Sandbox execution failed: {SecretScrubber.scrub(str(e))}"


async def run_sandbox_with_evidence(
    command: str,
    sentinel_path: Optional[str] = None,
    sink_symbol: str = "",
) -> Dict[str, Any]:
    """Executes a sandbox command and evaluates reached-sink evidence deterministically."""
    raw_res = await run_sandbox(command)
    exit_code = 0
    output = raw_res

    if raw_res.startswith("exit="):
        parts = raw_res.split("\n", 1)
        try:
            exit_code = int(parts[0].split("=")[1])
            output = parts[1] if len(parts) > 1 else ""
        except (ValueError, IndexError):
            pass

    sentinel_content = ""
    if sentinel_path:
        ctx = current_run_context.get()
        # SECURITY (INV-1/INV-4): the sentinel is read ONLY from inside the sandbox.
        # sentinel_path is model-controlled, so a host-filesystem fallback would be both
        # an arbitrary host read and a way to satisfy reached-sink evidence with a file
        # that no exploit ever produced. With no sandbox there is no admissible evidence.
        if ctx and ctx.sandbox:
            try:
                content_bytes = await ctx.sandbox.read_file(Path(sentinel_path))
                sentinel_content = content_bytes.decode("utf-8", errors="replace")
            except Exception:
                pass

    evidence_present, reason = check_reached_sink_evidence(
        output=output,
        exit_code=exit_code,
        sink_symbol=sink_symbol,
        sentinel_content=sentinel_content,
    )

    return {
        "raw": raw_res,
        "exit_code": exit_code,
        "output": output,
        "evidence_present": evidence_present,
        "evidence_reason": reason,
    }


async def apply_patch(diff_content: str) -> str:
    """Applies a specific code patch to the sandbox context. Code modifications only exist inside the sandbox."""
    ctx = current_run_context.get()
    if ctx is None or ctx.sandbox is None:
        return "ERROR: No active sandbox environment (sandbox unavailable)."
    try:
        sandbox_type = type(ctx.sandbox).__name__
        if sandbox_type in ("StaticOnlyEnvironment", "StaticOnlySandbox"):
            return "ERROR: Patch application failed: dynamic sandbox is disabled in static-only mode."
        res = await ctx.sandbox.apply_patch(diff_content)
        return SecretScrubber.scrub(str(res))
    except Exception as e:
        return f"ERROR: Patch application failed: {SecretScrubber.scrub(str(e))}"

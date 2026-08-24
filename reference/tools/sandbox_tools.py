from core.context import current_run_context
from google.adk.environment import ExecutionResult

async def run_sandbox(command: str) -> str:
    """Executes a command securely inside the configured sandbox. Use this to compile or run the reproduction script."""
    ctx = current_run_context.get()
    if ctx is None or ctx.sandbox is None:
        return "ERROR: No active sandbox environment (sandbox unavailable)."
    try:
        res = await ctx.sandbox.execute(command)
        if isinstance(res, ExecutionResult):
            ctx.sandbox_executed = True
            output = f"{res.stdout}{res.stderr}".strip()
            return f"exit={res.exit_code}\n{output}" if output else f"exit={res.exit_code}"
        if isinstance(res, str):
            if res.startswith("exit="):
                ctx.sandbox_executed = True
            return res
        return str(res)
    except Exception as e:
        return f"ERROR: Sandbox execution failed: {e}"

async def apply_patch(diff_content: str) -> str:
    """Applies a specific code patch to the sandbox context. Code modifications only exist inside the sandbox."""
    ctx = current_run_context.get()
    if ctx is None or ctx.sandbox is None:
        return "ERROR: No active sandbox environment (sandbox unavailable)."
    try:
        return await ctx.sandbox.apply_patch(diff_content)
    except Exception as e:
        return f"ERROR: Patch application failed: {e}"

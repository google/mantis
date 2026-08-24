import abc
import os
from pathlib import Path
from typing import Optional, Union, List
from google.adk.environment import BaseEnvironment as AdkBaseEnvironment, ExecutionResult

from core.context import current_run_context


class BaseEnvironment(AdkBaseEnvironment):
    """Abstract base class extending ADK BaseEnvironment with patch management, lifecycle, and filesystem listing helpers."""

    @abc.abstractmethod
    async def apply_patch(self, diff: str) -> str:
        """Applies a unified diff patch to the isolated sandbox filesystem."""
        pass

    @abc.abstractmethod
    async def preflight(self) -> None:
        """Validates prerequisites (e.g. image availability, KVM access, container runtime)."""
        pass

    @abc.abstractmethod
    async def list_files(self, directory: str = "") -> List[str]:
        """Lists file paths within the sandboxed filesystem under directory."""
        pass

    async def aclose(self) -> None:
        """Alias for close() to maintain backward compatibility with sandbox protocol."""
        await self.close()


class ProxyEnvironment(BaseEnvironment):
    """A proxy environment that routes all file and execution calls to the active RunContext sandbox.

    This allows compiling ADK Workflow and SkillToolset once while safely swapping the underlying
    sandboxed environment per target file during execution.
    """

    def __init__(self, default_workdir: Path = Path("/workspace")):
        super().__init__()
        self._default_workdir = default_workdir

    def _get_active_env(self) -> BaseEnvironment:
        ctx = current_run_context.get()
        if ctx is None or ctx.sandbox is None:
            raise RuntimeError("No active sandboxed execution context found in current_run_context.")
        return ctx.sandbox

    @property
    def working_dir(self) -> Path:
        ctx = current_run_context.get()
        if ctx is not None and ctx.sandbox is not None and hasattr(ctx.sandbox, "working_dir"):
            return ctx.sandbox.working_dir
        return self._default_workdir

    @property
    def is_initialized(self) -> bool:
        ctx = current_run_context.get()
        if ctx is not None and ctx.sandbox is not None and hasattr(ctx.sandbox, "is_initialized"):
            return bool(ctx.sandbox.is_initialized)
        return True

    @is_initialized.setter
    def is_initialized(self, value: bool) -> None:
        ctx = current_run_context.get()
        if ctx is not None and ctx.sandbox is not None and hasattr(ctx.sandbox, "is_initialized"):
            ctx.sandbox.is_initialized = value

    async def initialize(self) -> None:
        ctx = current_run_context.get()
        if ctx is not None and ctx.sandbox is not None and hasattr(ctx.sandbox, "initialize"):
            if not ctx.sandbox.is_initialized:
                await ctx.sandbox.initialize()

    async def close(self) -> None:
        # Close is handled per-task in the pipeline runner
        pass

    async def execute(self, command: str, *, timeout: Optional[float] = None) -> ExecutionResult:
        env = self._get_active_env()
        return await env.execute(command, timeout=timeout)

    async def read_file(self, path: Path) -> bytes:
        env = self._get_active_env()
        return await env.read_file(path)

    async def write_file(self, path: Path, content: Union[str, bytes]) -> None:
        env = self._get_active_env()
        await env.write_file(path, content)

    async def list_files(self, directory: str = "") -> List[str]:
        env = self._get_active_env()
        return await env.list_files(directory)

    async def apply_patch(self, diff: str) -> str:
        env = self._get_active_env()
        return await env.apply_patch(diff)

    async def preflight(self) -> None:
        env = self._get_active_env()
        await env.preflight()


_SHARED_PROXY_ENV: Optional[ProxyEnvironment] = None


def get_shared_proxy_environment() -> ProxyEnvironment:
    """Returns a singleton ProxyEnvironment instance for SkillToolset initialization."""
    global _SHARED_PROXY_ENV
    if _SHARED_PROXY_ENV is None:
        _SHARED_PROXY_ENV = ProxyEnvironment()
    return _SHARED_PROXY_ENV

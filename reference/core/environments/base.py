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

import abc
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import threading
from typing import Optional, Union, List
from google.adk.environment import BaseEnvironment as AdkBaseEnvironment, ExecutionResult

from core.context import current_run_context
from core.truncation import truncate_with_marker, truncation_marker

MAX_GUEST_FILE_BYTES = int(
    os.environ.get("MANTIS_MAX_GUEST_FILE_BYTES", str(16 * 1024 * 1024))
)
_STREAM_CHUNK_BYTES = 65536
_STDLIB_SUBPROCESS_RUN = subprocess.run


@dataclass
class BoundedSubprocessResult:
    stdout: bytes
    stderr: bytes
    stdout_total_bytes: int
    stderr_total_bytes: int
    returncode: int
    timed_out: bool = False
    stdout_overflowed: bool = False
    stderr_overflowed: bool = False


def format_bounded_output(
    raw: bytes,
    total_bytes: int,
    limit_chars: int,
    *,
    what: str,
) -> str:
    """Decodes a byte-capped stream and emits the canonical truncation marker."""
    decoded = raw.decode("utf-8", errors="replace")
    if total_bytes <= len(raw):
        return truncate_with_marker(decoded, limit_chars, what=what)
    kept = decoded[:limit_chars]
    omitted_bytes = max(total_bytes - len(raw), 0)
    estimated_total = max(len(decoded) + omitted_bytes, len(kept) + 1)
    return kept + "\n" + truncation_marker(what, len(kept), estimated_total)


def run_bounded_subprocess(
    argv: List[str],
    *,
    timeout: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    stdin_bytes: Optional[bytes] = None,
    kill_on_stdout_overflow: bool = False,
    mock_text: bool = False,
) -> BoundedSubprocessResult:
    """Runs argv while capping buffered stdout/stderr in host memory.

    Drains pipes in fixed-size chunks so a noisy or adversarial guest cannot
    exhaust host RAM before character-level truncation runs. Falls back to
    ``subprocess.run`` only when tests monkeypatch ``subprocess.run``.
    """
    if subprocess.run is not _STDLIB_SUBPROCESS_RUN:
        run_kwargs: dict = {
            "capture_output": True,
            "text": mock_text,
            "timeout": timeout,
            "shell": False,
        }
        if stdin_bytes is not None:
            run_kwargs["input"] = (
                stdin_bytes.decode("utf-8", errors="replace")
                if mock_text
                else stdin_bytes
            )
        else:
            run_kwargs["stdin"] = subprocess.DEVNULL
        try:
            p = subprocess.run(argv, **run_kwargs)
        except subprocess.TimeoutExpired as e:
            partial = e.stdout or b""
            if isinstance(partial, str):
                partial = partial.encode("utf-8")
            return BoundedSubprocessResult(
                stdout=partial[:max_stdout_bytes],
                stderr=b"",
                stdout_total_bytes=len(partial),
                stderr_total_bytes=0,
                returncode=-1,
                timed_out=True,
                stdout_overflowed=len(partial) > max_stdout_bytes,
                stderr_overflowed=False,
            )
        raw_out = (
            (p.stdout or "").encode("utf-8")
            if isinstance(p.stdout, str)
            else (p.stdout or b"")
        )
        raw_err = (
            (p.stderr or "").encode("utf-8")
            if isinstance(p.stderr, str)
            else (p.stderr or b"")
        )
        return BoundedSubprocessResult(
            stdout=raw_out[:max_stdout_bytes],
            stderr=raw_err[:max_stderr_bytes],
            stdout_total_bytes=len(raw_out),
            stderr_total_bytes=len(raw_err),
            returncode=p.returncode,
            timed_out=False,
            stdout_overflowed=len(raw_out) > max_stdout_bytes,
            stderr_overflowed=len(raw_err) > max_stderr_bytes,
        )

    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )

    out_state = {"buf": bytearray(), "total": 0, "overflow": False}
    err_state = {"buf": bytearray(), "total": 0, "overflow": False}

    def _drain(pipe, limit: int, state: dict, kill_on_overflow: bool) -> None:
        try:
            while True:
                chunk = pipe.read(_STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                state["total"] += len(chunk)
                remaining = limit - len(state["buf"])
                if remaining > 0:
                    state["buf"].extend(chunk[:remaining])
                if state["total"] > limit:
                    state["overflow"] = True
                    if kill_on_overflow:
                        try:
                            proc.kill()
                        except OSError:
                            pass
                        break
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    def _feed_stdin(pipe, payload: bytes) -> None:
        try:
            pipe.write(payload)
        except OSError:
            pass
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    t_out = threading.Thread(
        target=_drain,
        args=(proc.stdout, max_stdout_bytes, out_state, kill_on_stdout_overflow),
        daemon=True,
    )
    t_err = threading.Thread(
        target=_drain,
        args=(proc.stderr, max_stderr_bytes, err_state, False),
        daemon=True,
    )
    t_out.start()
    t_err.start()

    t_in: Optional[threading.Thread] = None
    if stdin_bytes is not None and proc.stdin is not None:
        t_in = threading.Thread(
            target=_feed_stdin,
            args=(proc.stdin, stdin_bytes),
            daemon=True,
        )
        t_in.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            proc.kill()
        except OSError:
            pass
        proc.wait()

    if t_in is not None:
        t_in.join(timeout=2.0)
    t_out.join(timeout=2.0)
    t_err.join(timeout=2.0)

    return BoundedSubprocessResult(
        stdout=bytes(out_state["buf"]),
        stderr=bytes(err_state["buf"]),
        stdout_total_bytes=int(out_state["total"]),
        stderr_total_bytes=int(err_state["total"]),
        returncode=proc.returncode if proc.returncode is not None else -1,
        timed_out=timed_out,
        stdout_overflowed=bool(out_state["overflow"]),
        stderr_overflowed=bool(err_state["overflow"]),
    )


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

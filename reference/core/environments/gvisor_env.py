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

import asyncio
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Optional, Union, List
import uuid

from google.adk.environment import ExecutionResult
from core.truncation import truncate_with_marker
from .base import (
    BaseEnvironment,
    MAX_GUEST_FILE_BYTES,
    format_bounded_output,
    format_posix_exports,
    run_bounded_subprocess,
)
from .static_env import PROTECTED_VCS_DIRS, PROTECTED_METADATA_FILES

# Per-stream cap on what one execute() or apply_patch() hands back. Must stay
# >= 10_000 and the cut must be announced (core.truncation): the reproducer
# reads this trace for the reached-sink sentinel, and a silent cut before the
# sentinel reads as "the PoC never got there".
MAX_OUTPUT = 16000
_MAX_EXEC_CAPTURE_BYTES = MAX_OUTPUT * 4 + 4096
MAX_CONTAINER_LIFETIME_SECONDS = 6 * 3600
ALLOWED_GVISOR_RUNTIMES = frozenset({
    "runsc",
    "runsc-kvm",
    "runsc-systrap",
    "runsc-ptrace",
    "gvisor",
})


class GvisorEnvironment(BaseEnvironment):
    """OCI container sandbox executed under gVisor runtime (docker/podman --runtime=runsc).

    - ISOLATED FILESYSTEM: Target code is copied into a clean container workspace (/workspace).
    - NO HOST FS ACCESS: Container has no mounts to the host filesystem.
    - NETWORKLESS: --network=none guarantees strict network isolation.
    - STATEFUL PATCHING: State persists across execute() and apply_patch() calls within a file run.
    - ADK COMPLIANT: Implements execute(), read_file(), write_file(), initialize(), close().
    """

    def __init__(
        self,
        target_path: str = "",
        image: str = "mantis-sandbox:latest",
        runtime: str = "runsc",
        timeout_seconds: int = 30,
        container_tool: Optional[str] = None,
        workdir: str = "/workspace",
    ):
        super().__init__()
        norm_runtime = str(runtime or "").strip()
        if norm_runtime not in ALLOWED_GVISOR_RUNTIMES:
            raise ValueError(
                f"Invalid gVisor runtime '{runtime}'. Must be one of {sorted(ALLOWED_GVISOR_RUNTIMES)}."
            )
        self.target_path = os.path.abspath(target_path) if target_path else ""
        self.image = image
        self.runtime = norm_runtime
        self.timeout = timeout_seconds
        self._workdir = Path(workdir)

        tool = container_tool
        if not tool:
            for candidate in ("docker", "podman"):
                if shutil.which(candidate) is not None:
                    tool = candidate
                    break
        elif tool not in ("docker", "podman"):
            raise ValueError(f"Invalid container_tool '{tool}'. Must be 'docker' or 'podman'.")

        if not tool or shutil.which(tool) is None:
            raise ValueError(
                f"sandbox type 'gvisor' requires 'docker' or 'podman' with '{runtime}' on PATH. "
                "Install a container engine with gVisor or set sandbox.type to 'static-only'."
            )
        self.tool = tool
        self.container_name = f"mantis-gv-{uuid.uuid4().hex[:12]}"
        self._created = False
        self._started = False
        self._stage_error: Optional[Exception] = None
        self._lock = asyncio.Lock()

    @property
    def working_dir(self) -> Path:
        return self._workdir

    def _run_cmd(self, argv: list[str], stdin: Optional[str] = None, timeout: Optional[int] = None) -> tuple[int, str]:
        t = timeout or self.timeout
        run_kwargs: dict = {
            "capture_output": True,
            "text": True,
            "timeout": t,
        }
        if stdin is None:
            run_kwargs["stdin"] = subprocess.DEVNULL
        else:
            run_kwargs["input"] = stdin
        try:
            p = subprocess.run(argv, **run_kwargs)
            out = (p.stdout or "") + (p.stderr or "")
            return p.returncode, out
        except subprocess.TimeoutExpired:
            return -1, f"SANDBOX-TIMEOUT: command exceeded {t}s."
        except Exception as e:
            return -1, f"SANDBOX-ERROR: {e}"

    async def _ensure(self) -> None:
        fresh = False
        async with self._lock:
            if self._started:
                return
            stage_err = getattr(self, "_stage_error", None)
            if stage_err is not None:
                raise stage_err

            def _init():
                # 1. Create container with runsc runtime, no network, dropped capabilities, and strict resource ceilings
                create_cmd = [
                    self.tool, "create",
                    "--pull=never",
                    "--name", self.container_name,
                    f"--runtime={self.runtime}",
                    "--network=none",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--tmpfs=/tmp:rw,nosuid,nodev,size=512m",
                    "--pids-limit=256",
                    "--memory=4g",
                    "--cpus=2.0",
                    "-w", str(self._workdir),
                    self.image,
                    "sleep", str(MAX_CONTAINER_LIFETIME_SECONDS),
                ]
                rc, out = self._run_cmd(create_cmd)
                if rc != 0:
                    raise RuntimeError(f"Failed to create gVisor container '{self.container_name}': {out}")
                self._created = True

                try:
                    # 2. Start container
                    rc, out = self._run_cmd([self.tool, "start", self.container_name])
                    if rc != 0:
                        raise RuntimeError(f"Failed to start gVisor container '{self.container_name}': {out}")

                    # 3. Stage target file or directory using canonical fail-closed staging helper
                    if self.target_path and os.path.exists(self.target_path):
                        from .staging import stage_to_directory
                        with tempfile.TemporaryDirectory() as stage_dir:
                            count = stage_to_directory(self.target_path, stage_dir)
                            if count > 0:
                                rc, out = self._run_cmd([
                                    self.tool, "cp",
                                    f"{stage_dir}/.",
                                    f"{self.container_name}:{self._workdir}/",
                                ])
                                if rc != 0:
                                    raise RuntimeError(f"Failed to stage files into gVisor container: {out}")
                except Exception as e:
                    self._stage_error = e
                    self._run_cmd([self.tool, "rm", "-f", self.container_name])
                    self._created = False
                    raise

            await asyncio.to_thread(_init)
            self._started = True
            self.is_initialized = True
            fresh = True
        if fresh:
            # Staging is done: anything newer than this was made by the
            # campaign (see core.poc_scaffold). Outside the lock: write_file
            # re-enters _ensure.
            from core.poc_scaffold import mark_staged
            await mark_staged(self.write_file)

    async def initialize(self) -> None:
        await self._ensure()

    @staticmethod
    def _is_container_infra_error(returncode: int, stderr_text: str) -> bool:
        if returncode == 125:
            return True
        low = (stderr_text or "").lower()
        return any(
            m in low
            for m in (
                "no such container",
                "is not running",
                "cannot connect to the docker daemon",
                "cannot connect to podman",
                "container state improper",
            )
        )

    async def execute(self, command: str, *, timeout: Optional[float] = None) -> ExecutionResult:
        await self._ensure()
        t = int(timeout) if timeout is not None else self.timeout
        exec_env = self._consume_exec_env() if hasattr(self, "_consume_exec_env") else None
        effective_cmd = format_posix_exports(exec_env) + command if exec_env else command

        def _exec():
            try:
                res = run_bounded_subprocess(
                    [
                        self.tool, "exec",
                        self.container_name,
                        "/bin/sh", "-c", effective_cmd,
                    ],
                    timeout=t,
                    max_stdout_bytes=_MAX_EXEC_CAPTURE_BYTES,
                    max_stderr_bytes=_MAX_EXEC_CAPTURE_BYTES,
                    mock_text=True,
                )
                stdout_formatted = format_bounded_output(
                    res.stdout, res.stdout_total_bytes, MAX_OUTPUT, what="sandbox stdout"
                )
                if res.timed_out:
                    return ExecutionResult(
                        stdout=stdout_formatted,
                        stderr=f"SANDBOX-TIMEOUT: command exceeded {t}s.",
                        exit_code=124,
                        timed_out=True,
                    )
                stderr_formatted = format_bounded_output(
                    res.stderr, res.stderr_total_bytes, MAX_OUTPUT, what="sandbox stderr"
                )
                if res.returncode != 0 and self._is_container_infra_error(res.returncode, stderr_formatted):
                    stderr_formatted = f"SANDBOX-ERROR: gVisor container execution failed: {stderr_formatted}"
                return ExecutionResult(
                    stdout=stdout_formatted,
                    stderr=stderr_formatted,
                    exit_code=res.returncode,
                    timed_out=False,
                )
            except Exception as e:
                return ExecutionResult(
                    stdout="",
                    stderr=f"SANDBOX-ERROR: {e}",
                    exit_code=1,
                    timed_out=False,
                )

        return await asyncio.to_thread(_exec)

    def _confine_to_workdir(self, candidate: Path, original: Union[Path, str]) -> Path:
        """Lexically normalizes candidate and requires it to stay inside the workdir."""
        norm = Path(os.path.normpath(str(candidate)))
        if norm != self._workdir and self._workdir not in norm.parents:
            raise PermissionError(
                f"Path '{original}' escapes the sandbox workspace '{self._workdir}'."
            )
        return norm

    def _resolve_guest_path(self, path: Union[Path, str]) -> Path:
        p = Path(path)
        if not p.is_absolute():
            return self._confine_to_workdir(self._workdir / p, path)
        try:
            if p == self._workdir or self._workdir in p.parents:
                return self._confine_to_workdir(p, path)
        except PermissionError:
            raise
        except Exception:
            pass
        if self.target_path:
            target_p = Path(self.target_path)
            if target_p.is_file():
                if p == target_p:
                    return self._confine_to_workdir(self._workdir / target_p.name, path)
                if target_p.parent in p.parents or p == target_p.parent:
                    try:
                        rel = p.relative_to(target_p.parent)
                        return self._confine_to_workdir(self._workdir / rel, path)
                    except ValueError:
                        pass
            elif target_p.is_dir():
                if target_p in p.parents or p == target_p:
                    try:
                        rel = p.relative_to(target_p)
                        return self._confine_to_workdir(self._workdir / rel, path)
                    except ValueError:
                        pass
        return self._confine_to_workdir(self._workdir / p.name, path)

    async def _read_started_container_file(self, path: Union[Path, str]) -> bytes:
        resolved_path = self._resolve_guest_path(path)

        def _read():
            res = run_bounded_subprocess(
                [self.tool, "exec", self.container_name, "cat", str(resolved_path)],
                timeout=self.timeout,
                max_stdout_bytes=MAX_GUEST_FILE_BYTES,
                max_stderr_bytes=65536,
                kill_on_stdout_overflow=True,
                mock_text=False,
            )
            if res.timed_out:
                raise TimeoutError(f"Read timed out in gVisor container: {path}")
            if res.stdout_overflowed:
                raise ValueError(
                    f"File '{path}' exceeds maximum sandbox read size ({MAX_GUEST_FILE_BYTES} bytes)."
                )
            if res.returncode != 0:
                err_txt = res.stderr.decode("utf-8", errors="replace")
                if self._is_container_infra_error(res.returncode, err_txt):
                    raise RuntimeError(
                        f"gVisor container '{self.container_name}' unavailable while reading {path}: {err_txt}"
                    )
                raise FileNotFoundError(
                    f"File not found in gVisor container: {path} ({err_txt})"
                )
            return res.stdout

        return await asyncio.to_thread(_read)

    async def read_guest_file(self, path: Union[Path, str]) -> bytes:
        """Dynamic-plane sentinel/scaffold reader: never boots a container or touches host files."""
        if not getattr(self, "_started", False):
            raise FileNotFoundError(
                f"gVisor container not started; guest file unavailable: {path}"
            )
        return await self._read_started_container_file(path)

    async def read_file(self, path: Union[Path, str]) -> bytes:
        await self._ensure()
        return await self._read_started_container_file(path)

    async def write_file(self, path: Union[Path, str], content: Union[str, bytes]) -> None:
        await self._ensure()
        resolved_path = self._resolve_guest_path(path)
        parent_dir = str(resolved_path.parent)
        data = content.encode("utf-8") if isinstance(content, str) else content
        if len(data) > MAX_GUEST_FILE_BYTES:
            raise ValueError(
                f"File '{path}' ({len(data)} bytes) exceeds maximum sandbox write size ({MAX_GUEST_FILE_BYTES} bytes)."
            )

        def _write():
            mkdir_cmd = [self.tool, "exec", self.container_name, "mkdir", "-p", parent_dir]
            subprocess.run(mkdir_cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=self.timeout)

            # SECURITY: Pass destination as positional argument to prevent shell quoting injection
            write_cmd = [
                self.tool, "exec", "-i", self.container_name,
                "/bin/sh", "-c", 'cat > "$1"', "sh", str(resolved_path),
            ]
            p = subprocess.run(write_cmd, input=data, capture_output=True, timeout=self.timeout)
            if p.returncode != 0:
                raise RuntimeError(f"Failed to write file to gVisor container: {resolved_path} ({p.stderr.decode('utf-8', errors='replace')})")

        await asyncio.to_thread(_write)

    async def list_files(self, directory: str = "") -> List[str]:
        await self._ensure()
        resolved_dir = str(self._resolve_guest_path(directory)) if directory else str(self._workdir)

        def _list():
            find_cmd = [
                self.tool, "exec", self.container_name,
                "find", resolved_dir, "-maxdepth", "5", "-not", "-path", "*/.*", "-type", "f"
            ]
            rc, out = self._run_cmd(find_cmd)
            if rc != 0:
                raise RuntimeError(f"Failed to list files in gVisor container: {out}")
            file_list = []
            for line in out.strip().splitlines():
                line = line.strip()
                if line:
                    rel = os.path.relpath(line, str(self._workdir))
                    file_list.append(rel)
            return sorted(file_list)

        return await asyncio.to_thread(_list)

    async def apply_patch(self, diff: str) -> str:
        await self._ensure()

        def _patch():
            rc, out = self._run_cmd(
                [self.tool, "exec", "-i", self.container_name, "patch", "--batch", "--force", "-p1"],
                stdin=diff,
            )
            if rc in (126, 127) or "executable file not found" in out.lower():
                return None  # no patch(1): the caller runs the python3 fallback
            if rc != 0:
                rc_retry, out_retry = self._run_cmd(
                    [self.tool, "exec", "-i", self.container_name, "patch", "--batch", "--force"],
                    stdin=diff,
                )
                if rc_retry == 0:
                    return f"exit=0\n{truncate_with_marker(out_retry, MAX_OUTPUT, what='patch output')}"
                return f"exit={rc_retry}\n{truncate_with_marker(out_retry, MAX_OUTPUT, what='patch output')}"
            return f"exit={rc}\n{truncate_with_marker(out, MAX_OUTPUT, what='patch output')}"

        result = await asyncio.to_thread(_patch)
        if result is not None:
            return result

        # No patch(1) in the image (python:3-slim, distroless): apply with the
        # guest's python3 instead of failing the stage.
        from core.environments.patch_fallback import (
            PATCH_FILE_NAME, PATCH_SCRIPT_NAME, PYTHON_PATCH_SCRIPT, fallback_argv, unavailable_message,
        )
        await self.write_file(Path(PATCH_FILE_NAME), diff)
        await self.write_file(Path(PATCH_SCRIPT_NAME), PYTHON_PATCH_SCRIPT)

        def _fallback():
            # The container was created with -w <workdir>, so exec runs there.
            rc, out = self._run_cmd([self.tool, "exec", self.container_name, *fallback_argv(strip=1)])
            if rc in (126, 127) or "executable file not found" in out.lower():
                return unavailable_message(self.image, out)
            if rc != 0:
                rc0, out0 = self._run_cmd([self.tool, "exec", self.container_name, *fallback_argv(strip=0)])
                if rc0 == 0:
                    return f"exit=0\n{truncate_with_marker(out0, MAX_OUTPUT, what='patch output')}"
            return f"exit={rc}\n{truncate_with_marker(out, MAX_OUTPUT, what='patch output')}"

        return await asyncio.to_thread(_fallback)

    async def preflight(self) -> None:
        def _check():
            out = subprocess.run(
                [self.tool, "info", "--format", "{{json .Runtimes}}"],
                capture_output=True, text=True, timeout=10,
            )
            if out.returncode != 0:
                err_msg = (out.stderr or "").strip() or f"{self.tool} daemon not reachable"
                raise RuntimeError(
                    f"Could not connect to {self.tool} daemon ({err_msg}). "
                    f"Ensure {self.tool} is running, or set sandbox.type to 'static-only'."
                )

            try:
                runtimes = json.loads(out.stdout or "{}")
            except json.JSONDecodeError:
                runtimes = {}

            if self.runtime not in runtimes:
                raise RuntimeError(
                    f"'{self.runtime}' is not a registered {self.tool} runtime. "
                    f"Run `sudo runsc install -- --network=none && sudo systemctl restart {self.tool}`, "
                    "or set sandbox.type to 'microsandbox' or 'static-only'."
                )

            img_out = subprocess.run(
                [self.tool, "image", "inspect", self.image],
                capture_output=True, text=True, timeout=10,
            )
            if img_out.returncode != 0:
                raise RuntimeError(
                    f"sandbox image '{self.image}' not found in the local {self.tool} cache. "
                    f"Run ./install.sh to build it, or set sandbox.type to 'static-only'."
                )
        await asyncio.to_thread(_check)

    async def close(self) -> None:
        if getattr(self, "_started", False) or getattr(self, "_created", False):
            def _cleanup():
                self._run_cmd([self.tool, "rm", "-f", self.container_name])
            await asyncio.to_thread(_cleanup)
            self._created = False
            self._started = False
            self.is_initialized = False

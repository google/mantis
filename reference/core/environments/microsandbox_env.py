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
import os
import shlex
import sys
import uuid
from pathlib import Path
from typing import Optional, Union, List
from google.adk.environment import ExecutionResult
from microsandbox import Sandbox as MsbSandbox, PullPolicy
from microsandbox.types import Network

from .base import BaseEnvironment, MAX_GUEST_FILE_BYTES, format_posix_exports
from .static_env import PROTECTED_VCS_DIRS, PROTECTED_METADATA_FILES
from core.truncation import truncate_with_marker

# Per-stream cap on what one execute() hands back. Must stay >= 10_000 and
# the cut must be announced (core.truncation): the reproducer reads this
# trace for the reached-sink sentinel, and a silent cut before the sentinel
# reads as "the PoC never got there".
MAX_OUTPUT = 16000
#: Hard lifetime of one guest, enforced by the runtime: six hours is longer
#: than any campaign and bounds what a missed close() can cost.
MAX_GUEST_LIFETIME_SECONDS = 6 * 3600
_MAX_FALLBACK_WRITE_BYTES = 65536


def verify_network_none_policy(net: Optional[Network] = None) -> None:
    """Fails closed if the microsandbox SDK's Network.none() ever permits traffic or ports."""
    from microsandbox.types import Action

    candidate = Network.none() if net is None else net
    policy = getattr(candidate, "policy", None)
    if (
        policy is None
        or getattr(policy, "default_egress", None) != Action.DENY
        or getattr(policy, "default_ingress", None) != Action.DENY
        or tuple(getattr(policy, "rules", ())) != ()
        or dict(getattr(candidate, "ports", {})) != {}
    ):
        raise RuntimeError(
            "Microsandbox Network.none() isolation invariant failed: "
            "default egress and ingress must both be Action.DENY with empty rules and ports."
        )


class MicrosandboxEnvironment(BaseEnvironment):
    """Networkless microVM sandbox (libkrun). STATEFUL for the lifetime of one file.

    - NETWORKLESS: Network.none() at creation; no egress, no DNS, no metadata endpoints.
    - FULLY CONFINED: The target code is copied into the guest VM filesystem (/workspace).
    - STATEFUL PATCHING: A patch applied by apply_patch() is visible to later execute() calls.
    - ADK COMPLIANT: Implements execute(), read_file(), write_file(), initialize(), close().
    """

    def __init__(
        self,
        target_path: str = "",
        image: str = "mantis-sandbox:latest",
        timeout_seconds: float = 30.0,
        workdir: str = "/workspace",
        memory: Optional[int] = None,
        cpus: Optional[int] = None,
    ):
        super().__init__()
        if sys.platform.startswith("linux") and not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise RuntimeError(
                "Hardware virtualization unavailable: '/dev/kvm' is not readable/writable. "
                "Ensure KVM is enabled and the user is in the 'kvm' group, or set sandbox.type to 'static-only'."
            )
        self.target_path = os.path.abspath(target_path) if target_path else ""
        self.image = image
        self.timeout = timeout_seconds
        # Guest sizing (sandbox.options.memory in MiB, sandbox.options.cpus).
        # None leaves the runtime's defaults; a compiled target's PoCs (a Go
        # or Rust build) need more than a script's. Bounded so a workflow
        # file cannot ask one VM for the host.
        self.memory = min(int(memory), 16384) if memory else None
        self.cpus = min(int(cpus), 16) if cpus else None
        self._workdir = Path(workdir)
        self._sb: Optional[MsbSandbox] = None
        self._name: Optional[str] = None
        self._stage_error: Optional[Exception] = None
        self._lock = asyncio.Lock()

    @property
    def working_dir(self) -> Path:
        return self._workdir

    async def _ensure(self) -> MsbSandbox:
        lock = getattr(self, "_lock", None)
        if lock is None:
            lock = asyncio.Lock()
            self._lock = lock
        fresh = False
        async with lock:
            if self._stage_error is not None:
                raise self._stage_error
            if self._sb is None:
                verify_network_none_policy()
                name = f"mantis-msb-{uuid.uuid4().hex[:12]}"
                sizing = {}
                if self.memory:
                    sizing["memory"] = self.memory
                if self.cpus:
                    sizing["cpus"] = self.cpus
                sb = await MsbSandbox.create(
                    name=name,
                    image=self.image,
                    network=Network.none(),
                    pull_policy=PullPolicy.NEVER,
                    replace=True,
                    # A guest outlives no campaign: whatever close() misses, the
                    # runtime reaps. Longer than any campaign, shorter than a
                    # forgotten weekend.
                    max_duration=float(MAX_GUEST_LIFETIME_SECONDS),
                    **sizing,
                )
                await sb.fs.mkdir(str(self._workdir))

                if self.target_path and os.path.exists(self.target_path):
                    from .staging import enforce_staging_budget, get_vetted_staging_files
                    try:
                        vetted_files = get_vetted_staging_files(self.target_path)
                        enforce_staging_budget(vetted_files)
                        for src_file, rel_file in vetted_files:
                            dest_file = f"{self._workdir}/{rel_file}"
                            dest_dir = os.path.dirname(dest_file)
                            if dest_dir != str(self._workdir):
                                await sb.fs.mkdir(dest_dir)
                            await sb.fs.copy_from_host(str(src_file), dest_file)
                    except Exception as e:
                        self._stage_error = e
                        self._sb = sb
                        self._name = name
                        raise e

                self._name = name
                self._sb = sb
                self.is_initialized = True
                fresh = True
        if fresh:
            # Staging is done: anything newer than this was made by the
            # campaign (see core.poc_scaffold). Outside the lock: write_file
            # re-enters _ensure.
            from core.poc_scaffold import mark_staged
            await mark_staged(self.write_file)
        return self._sb

    async def initialize(self) -> None:
        await self._ensure()

    async def execute(self, command: str, *, timeout: Optional[float] = None) -> ExecutionResult:
        t = timeout or self.timeout
        exec_env = self._consume_exec_env() if hasattr(self, "_consume_exec_env") else None
        effective_cmd = format_posix_exports(exec_env) + command if exec_env else command
        try:
            sb = await self._ensure()
            out = await sb.shell(effective_cmd, cwd=str(self._workdir), timeout=t)
            stdout_text = out.stdout_text or ""
            stderr_text = getattr(out, "stderr_text", "") or ""
            return ExecutionResult(
                stdout=truncate_with_marker(stdout_text, MAX_OUTPUT, what="sandbox stdout"),
                stderr=truncate_with_marker(stderr_text, MAX_OUTPUT, what="sandbox stderr"),
                exit_code=out.exit_code,
                timed_out=False,
            )
        except Exception as e:
            # The SDK's timeout error says "exec timed out" (ExecTimeoutError),
            # which "timeout" did not match; a hung PoC then read as exit 1,
            # not as a timeout, and a caller that treats "ran but no evidence"
            # as a result (the regression re-run) would have called it fixed.
            text = str(e).lower()
            timed_out = (
                "timeout" in text or "timed out" in text
                or type(e).__name__.lower().endswith("timeouterror")
            )
            prefix = "SANDBOX-TIMEOUT" if timed_out else "SANDBOX-ERROR"
            return ExecutionResult(
                stdout="",
                stderr=f"{prefix}: {type(e).__name__}: {e}",
                exit_code=124 if timed_out else 1,
                timed_out=timed_out,
            )

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

    async def read_file(self, path: Union[Path, str]) -> bytes:
        sb = await self._ensure()
        resolved_path = self._resolve_guest_path(path)
        fs_err: Optional[Exception] = None
        try:
            raw = await sb.fs.read(str(resolved_path))
            data = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
        except Exception as e:
            fs_err = e
            q = shlex.quote(str(resolved_path))
            cap = int(MAX_GUEST_FILE_BYTES)
            cmd = (
                f"if [ -L {q} ]; then echo MSB_ERR:SYMLINK; exit 2; fi; "
                f"if [ ! -f {q} ]; then echo MSB_ERR:MISSING; exit 3; fi; "
                f"sz=$(wc -c < {q}); "
                f"if [ \"$sz\" -gt {cap} ]; then echo \"MSB_ERR:TOO_LARGE:$sz\"; exit 4; fi; "
                f"base64 < {q}"
            )
            out = await sb.shell(cmd, cwd=str(self._workdir), timeout=self.timeout)
            stdout_text = (out.stdout_text or "").strip()
            if out.exit_code == 2 or stdout_text.startswith("MSB_ERR:SYMLINK"):
                raise PermissionError(f"Permission denied: refusing to read symlink in sandbox: {path}")
            if out.exit_code == 4 or stdout_text.startswith("MSB_ERR:TOO_LARGE"):
                raise ValueError(
                    f"File '{path}' exceeds maximum sandbox read size ({cap} bytes)."
                )
            if out.exit_code != 0:
                raise FileNotFoundError(f"File not found in sandbox: {path} ({fs_err})")
            data = base64.b64decode(stdout_text.encode("ascii"))
        if len(data) > MAX_GUEST_FILE_BYTES:
            raise ValueError(
                f"File '{path}' ({len(data)} bytes) exceeds maximum sandbox read size "
                f"({MAX_GUEST_FILE_BYTES} bytes)."
            )
        return data

    async def write_file(self, path: Union[Path, str], content: Union[str, bytes]) -> None:
        sb = await self._ensure()
        resolved_path = self._resolve_guest_path(path)
        data = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        if len(data) > MAX_GUEST_FILE_BYTES:
            raise ValueError(
                f"Payload for '{path}' ({len(data)} bytes) exceeds maximum sandbox write size "
                f"({MAX_GUEST_FILE_BYTES} bytes)."
            )
        parent_dir = str(resolved_path.parent)
        if parent_dir and parent_dir != str(self._workdir):
            try:
                await sb.fs.mkdir(parent_dir)
            except Exception:
                pass
        try:
            await sb.fs.write(str(resolved_path), data)
        except Exception as e:
            if len(data) > _MAX_FALLBACK_WRITE_BYTES:
                raise RuntimeError(
                    f"Failed to write '{path}' via MicroSandbox fs API ({e}), and payload "
                    f"({len(data)} bytes) exceeds safe shell fallback limit ({_MAX_FALLBACK_WRITE_BYTES} bytes)."
                ) from e
            b64_data = base64.b64encode(data).decode("ascii")
            q_parent = shlex.quote(parent_dir)
            q_dest = shlex.quote(str(resolved_path))
            cmd = (
                f"mkdir -p {q_parent} && "
                f"if [ -L {q_dest} ]; then echo MSB_ERR:SYMLINK >&2; exit 2; fi && "
                f"printf '%s' '{b64_data}' | base64 -d > {q_dest}"
            )
            out = await sb.shell(cmd, cwd=str(self._workdir), timeout=self.timeout)
            if out.exit_code == 2:
                raise PermissionError(f"Permission denied: refusing to write through symlink '{path}'.")
            if out.exit_code != 0:
                stderr_text = getattr(out, "stderr_text", "") or out.stdout_text or ""
                raise RuntimeError(
                    f"Failed to write file '{path}' in MicroSandbox (exit={out.exit_code}): {stderr_text.strip()}"
                ) from e

    async def list_files(self, directory: str = "") -> List[str]:
        await self._ensure()
        resolved_dir = str(self._resolve_guest_path(directory)) if directory else "."
        target_dir = shlex.quote(resolved_dir)
        res = await self.execute(f"find {target_dir} -maxdepth 5 -not -path '*/.*' -type f")
        if res.exit_code != 0:
            raise RuntimeError(f"Failed to list files in MicroSandbox: {res.stderr or res.stdout}")
        file_list = []
        for line in res.stdout.strip().splitlines():
            line = line.strip()
            if line:
                rel = os.path.relpath(line, ".")
                file_list.append(rel)
        return sorted(file_list)

    async def apply_patch(self, diff: str) -> str:
        from core.environments.patch_fallback import (
            PATCH_FILE_NAME, PATCH_SCRIPT_NAME, PYTHON_PATCH_SCRIPT, fallback_command, unavailable_message,
        )
        try:
            data = diff.encode("utf-8") if isinstance(diff, str) else diff
            await self.write_file(Path(PATCH_FILE_NAME), data)
            res = await self.execute(f"patch -p1 -i {PATCH_FILE_NAME} < /dev/null")
            output_str = f"exit={res.exit_code}\n{res.stdout}{res.stderr}"
            if res.exit_code == 127:
                # No patch(1) in the image (python:3-slim, distroless): apply
                # with the guest's python3 instead of failing the stage.
                await self.write_file(Path(PATCH_SCRIPT_NAME), PYTHON_PATCH_SCRIPT)
                fb = await self.execute(fallback_command(strip=1))
                fb_out = f"exit={fb.exit_code}\n{fb.stdout}{fb.stderr}"
                if fb.exit_code == 127:
                    return unavailable_message(self.image, fb_out)
                if fb.exit_code != 0:
                    fb0 = await self.execute(fallback_command(strip=0))
                    if fb0.exit_code == 0:
                        return f"exit=0\n{fb0.stdout}{fb0.stderr}"
                return fb_out
            if res.exit_code != 0:
                res_no_p1 = await self.execute(f"patch -i {PATCH_FILE_NAME} < /dev/null")
                output_no_p1 = f"exit={res_no_p1.exit_code}\n{res_no_p1.stdout}{res_no_p1.stderr}"
                if res_no_p1.exit_code == 127:
                    return unavailable_message(self.image, output_no_p1)
                return output_no_p1
            return output_str
        except Exception as e:
            return f"SANDBOX-ERROR: {type(e).__name__}: {e}"

    async def preflight(self) -> None:
        from microsandbox import Image, ImageNotFoundError
        verify_network_none_policy()
        try:
            await Image.get(self.image)
        except ImageNotFoundError as e:
            raise RuntimeError(
                f"sandbox image '{self.image}' not found in the local cache. "
                f"Run ./install.sh to build it, or set sandbox.type to 'gvisor' or 'static-only'. ({e})"
            )

    async def close(self) -> None:
        """Stops and removes the guest. A stop that fails (a PoC that ignores
        SIGTERM, a stuck exec) is followed by a kill and a forced destroy, so
        a campaign never leaves a running VM behind: over a thousand
        campaigns a one-percent leak is ten resident VMs."""
        if self._sb is not None:
            sb, name = self._sb, self._name
            try:
                await sb.stop(timeout=30)
            except Exception:
                try:
                    await sb.kill(timeout=15)
                except Exception:
                    pass
            try:
                await sb.destroy(force=True, timeout=30)
            except Exception:
                pass
            try:
                if name:
                    await MsbSandbox.remove(name)
            except Exception:
                pass
            self._sb = None
            self.is_initialized = False

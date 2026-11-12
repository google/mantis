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

"""Split-plane remote target execution environment for full-product dynamic testing.

Static file reads and directory listings stay strictly read-only on the local
audited checkout via ``StaticOnlyEnvironment`` (INV-4), while dynamic PoC
execution, sidecar sentinel verification (INV-1/INV-2), patch/rebuild hooks, and
per-campaign state resets dispatch over bounded subprocesses to an
operator-provisioned container, hardened SSH host, or explicit ``exec_argv``
runner.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
from pathlib import Path
import posixpath
import shlex
import shutil
from typing import List, Optional, Sequence, Union

from google.adk.environment import ExecutionResult

from core.config import is_placeholder
from core.truncation import truncate_with_marker

from .base import (
    BaseEnvironment,
    MAX_GUEST_FILE_BYTES,
    format_bounded_output,
    format_posix_exports,
    run_bounded_subprocess,
)
from .static_env import StaticOnlyEnvironment

logger = logging.getLogger(__name__)

MAX_OUTPUT = 16000
_MAX_EXEC_CAPTURE_BYTES = MAX_OUTPUT * 4 + 4096
_MAX_TELEMETRY_CHARS = 12000
_MAX_B64_GUEST_FILE_BYTES = ((MAX_GUEST_FILE_BYTES + 2) // 3) * 4 + 64

ALLOWED_TRANSPORTS = frozenset({"container", "ssh", "exec"})
ALLOWED_CONTAINER_TOOLS = frozenset({"docker", "podman"})
ALLOWED_HOST_KEY_POLICIES = frozenset({"yes", "accept-new"})


def _reject_flag_or_control(value: str, field_name: str) -> str:
    cleaned = str(value or "").strip()
    if not cleaned or is_placeholder(cleaned):
        raise ValueError(f"Remote sandbox '{field_name}' must be a non-empty configured value.")
    if cleaned.startswith("-"):
        raise ValueError(
            f"Invalid remote sandbox {field_name} '{cleaned}': must not start with '-'."
        )
    if any(ch in cleaned for ch in ("\x00", "\r", "\n", "\t", " ")):
        raise ValueError(
            f"Invalid remote sandbox {field_name}: whitespace and control characters are not allowed."
        )
    return cleaned


class RemoteTargetEnvironment(BaseEnvironment):
    """Split-plane ADK environment targeting an operator-provisioned runtime.

    - STATIC PLANE (INV-4): ``read_file()`` and ``list_files()`` delegate to
      ``StaticOnlyEnvironment`` over the local source checkout. Local source
      files are never modified.
    - DYNAMIC PLANE (INV-1 / INV-2): ``execute()``, ``write_file()``,
      ``read_guest_file()``, and ``apply_patch()`` run exclusively against the
      remote ``workdir`` via ``shell=False`` bounded subprocesses.
    """

    backend_name = "remote"

    def __init__(
        self,
        target_path: str = "",
        *,
        transport: Optional[str] = None,
        container: str = "",
        container_tool: Optional[str] = None,
        user: Optional[str] = None,
        host: str = "",
        ssh_host: str = "",
        ssh_user: Optional[str] = None,
        port: int = 22,
        identity_file: Optional[str] = None,
        strict_host_key_checking: str = "yes",
        ssh_bin: str = "ssh",
        exec_argv: Optional[Sequence[str]] = None,
        workdir: str = "/workspace",
        timeout_seconds: int = 60,
        healthcheck_cmd: Optional[str] = None,
        reset_cmd: Optional[str] = None,
        reset_argv: Optional[Sequence[str]] = None,
        rebuild_cmd: Optional[str] = None,
        log_cmd: Optional[str] = None,
        log_file: Optional[str] = None,
        **_: object,
    ):
        super().__init__()
        self._static_env = StaticOnlyEnvironment(target_path=target_path, workdir=workdir)
        self.target_path = self._static_env.target_path

        raw_workdir = str(workdir or "/workspace").strip().replace("\\", "/")
        if not raw_workdir.startswith("/") or "\x00" in raw_workdir:
            raise ValueError(
                f"Remote sandbox 'workdir' must be an absolute POSIX path (got '{workdir}')."
            )
        self._workdir_posix = posixpath.normpath(raw_workdir)
        self._workdir = Path(self._workdir_posix)
        self.timeout = max(1, int(timeout_seconds))

        resolved_host = str(host or ssh_host or "").strip()
        if transport:
            norm_transport = str(transport).strip().lower()
        elif exec_argv is not None:
            norm_transport = "exec"
        elif resolved_host:
            norm_transport = "ssh"
        elif str(container or "").strip():
            norm_transport = "container"
        else:
            raise ValueError(
                "RemoteTargetEnvironment requires one of 'container', 'host'/'ssh_host', "
                "or 'exec_argv' in sandbox.options."
            )

        if norm_transport not in ALLOWED_TRANSPORTS:
            raise ValueError(
                f"Invalid remote sandbox transport '{norm_transport}'. "
                f"Must be one of {sorted(ALLOWED_TRANSPORTS)}."
            )
        self.transport = norm_transport

        self.container = ""
        self.container_tool = "docker"
        self.user: Optional[str] = None
        self.host = ""
        self.ssh_user: Optional[str] = None
        self.port = 22
        self.identity_file: Optional[str] = None
        self.strict_host_key_checking = "yes"
        self.ssh_bin = "ssh"
        self.exec_argv: List[str] = []

        if self.transport == "container":
            self.container = _reject_flag_or_control(container, "container")
            if container_tool is not None and str(container_tool).strip():
                ct = str(container_tool).strip()
                if ct not in ALLOWED_CONTAINER_TOOLS:
                    raise ValueError(
                        f"Invalid container_tool '{ct}'. Must be one of {sorted(ALLOWED_CONTAINER_TOOLS)}."
                    )
                self.container_tool = ct
            else:
                for cand in ("docker", "podman"):
                    if shutil.which(cand):
                        self.container_tool = cand
                        break
            if user is not None and str(user).strip():
                self.user = _reject_flag_or_control(str(user), "user")

        elif self.transport == "ssh":
            self.host = _reject_flag_or_control(resolved_host, "host")
            effective_ssh_user = ssh_user if ssh_user is not None else user
            if effective_ssh_user is not None and str(effective_ssh_user).strip():
                u = _reject_flag_or_control(str(effective_ssh_user), "ssh_user")
                if "@" in u:
                    raise ValueError("Invalid remote sandbox ssh_user: must not contain '@'.")
                self.ssh_user = u
            try:
                parsed_port = int(port)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid SSH port '{port}'.") from exc
            if not (1 <= parsed_port <= 65535):
                raise ValueError(f"SSH port must be between 1 and 65535 (got {parsed_port}).")
            self.port = parsed_port

            hk = str(strict_host_key_checking or "yes").strip().lower()
            if hk not in ALLOWED_HOST_KEY_POLICIES:
                raise ValueError(
                    f"Invalid strict_host_key_checking '{strict_host_key_checking}'. "
                    f"Only {sorted(ALLOWED_HOST_KEY_POLICIES)} are permitted."
                )
            self.strict_host_key_checking = hk

            if identity_file is not None and str(identity_file).strip():
                expanded = os.path.expanduser(str(identity_file).strip())
                if expanded.startswith("-") or "\x00" in expanded:
                    raise ValueError(f"Invalid SSH identity_file '{identity_file}'.")
                self.identity_file = expanded

            sb = str(ssh_bin or "ssh").strip()
            if not sb or sb.startswith("-") or "\x00" in sb:
                raise ValueError(f"Invalid ssh_bin '{ssh_bin}'.")
            self.ssh_bin = sb

        elif self.transport == "exec":
            if (
                not isinstance(exec_argv, (list, tuple))
                or len(exec_argv) == 0
                or not all(isinstance(x, str) and bool(x.strip()) and "\x00" not in x for x in exec_argv)
            ):
                raise ValueError(
                    "Remote sandbox 'exec_argv' must be a non-empty list of non-empty strings."
                )
            self.exec_argv = [str(x) for x in exec_argv]

        self.healthcheck_cmd = str(healthcheck_cmd).strip() if healthcheck_cmd else None
        self.reset_cmd = str(reset_cmd).strip() if reset_cmd else None
        if reset_argv is not None:
            if (
                not isinstance(reset_argv, (list, tuple))
                or len(reset_argv) == 0
                or not all(isinstance(x, str) and bool(x.strip()) and "\x00" not in x for x in reset_argv)
            ):
                raise ValueError(
                    "Remote sandbox 'reset_argv' must be a non-empty list of non-empty strings."
                )
            self.reset_argv: Optional[List[str]] = [str(x) for x in reset_argv]
        else:
            self.reset_argv = None
        self.rebuild_cmd = str(rebuild_cmd).strip() if rebuild_cmd else None
        self.log_cmd = str(log_cmd).strip() if log_cmd else None
        if log_file is not None and str(log_file).strip():
            lf = str(log_file).strip()
            if "\x00" in lf or "\n" in lf or "\r" in lf:
                raise ValueError("Invalid remote sandbox 'log_file'.")
            self.log_file: Optional[str] = lf
        else:
            self.log_file = None

        self._started = False
        self.is_initialized = False
        self._lock = asyncio.Lock()

    @property
    def working_dir(self) -> Path:
        return self._workdir

    def _transport_binary(self) -> str:
        if self.transport == "container":
            return self.container_tool
        if self.transport == "ssh":
            return self.ssh_bin
        return self.exec_argv[0]

    def _build_transport_argv(self, remote_shell_cmd: str, *, with_stdin: bool = False) -> List[str]:
        """Builds a ``shell=False`` host argv executing ``remote_shell_cmd`` inside ``workdir``."""
        if self.transport == "container":
            argv = [self.container_tool, "exec"]
            if with_stdin:
                argv.append("-i")
            if self.user:
                argv.extend(["-u", self.user])
            argv.extend(["-w", self._workdir_posix, self.container, "sh", "-c", remote_shell_cmd])
            return argv

        cd_wrapped = f"cd {shlex.quote(self._workdir_posix)} && {remote_shell_cmd}"
        if self.transport == "ssh":
            argv = [
                self.ssh_bin,
                "-T",
                "-oBatchMode=yes",
                "-oForwardAgent=no",
                "-oClearAllForwardings=yes",
                "-oPermitLocalCommand=no",
                "-oConnectTimeout=10",
                f"-oStrictHostKeyChecking={self.strict_host_key_checking}",
                "-p",
                str(self.port),
            ]
            if self.identity_file:
                argv.extend(["-i", self.identity_file])
            target_spec = f"{self.ssh_user}@{self.host}" if self.ssh_user else self.host
            argv.extend(["--", target_spec, cd_wrapped])
            return argv

        return [*self.exec_argv, cd_wrapped]

    def _build_raw_transport_argv(self, remote_shell_cmd: str, *, with_stdin: bool = False) -> List[str]:
        """Builds transport argv without assuming ``workdir`` already exists."""
        if self.transport == "container":
            argv = [self.container_tool, "exec"]
            if with_stdin:
                argv.append("-i")
            if self.user:
                argv.extend(["-u", self.user])
            argv.extend([self.container, "sh", "-c", remote_shell_cmd])
            return argv
        if self.transport == "ssh":
            argv = [
                self.ssh_bin,
                "-T",
                "-oBatchMode=yes",
                "-oForwardAgent=no",
                "-oClearAllForwardings=yes",
                "-oPermitLocalCommand=no",
                "-oConnectTimeout=10",
                f"-oStrictHostKeyChecking={self.strict_host_key_checking}",
                "-p",
                str(self.port),
            ]
            if self.identity_file:
                argv.extend(["-i", self.identity_file])
            target_spec = f"{self.ssh_user}@{self.host}" if self.ssh_user else self.host
            argv.extend(["--", target_spec, remote_shell_cmd])
            return argv
        return [*self.exec_argv, remote_shell_cmd]

    def _confine_to_workdir(self, candidate: str, original: Union[Path, str]) -> str:
        norm = posixpath.normpath(candidate)
        if norm != self._workdir_posix and not norm.startswith(self._workdir_posix.rstrip("/") + "/"):
            raise PermissionError(
                f"Path '{original}' escapes the remote sandbox workspace '{self._workdir_posix}'."
            )
        return norm

    def _resolve_guest_path(self, path: Union[Path, str]) -> str:
        raw = str(path or "").replace("\\", "/").strip()
        if not raw or "\x00" in raw:
            raise PermissionError(f"Invalid remote sandbox path '{path}'.")
        if not raw.startswith("/"):
            parts = [p for p in raw.split("/") if p not in ("", ".")]
            if any(p == ".." for p in parts):
                raise PermissionError(
                    f"Path '{path}' escapes the remote sandbox workspace '{self._workdir_posix}'."
                )
            return self._confine_to_workdir(posixpath.join(self._workdir_posix, raw), path)

        norm = posixpath.normpath(raw)
        if norm == self._workdir_posix or norm.startswith(self._workdir_posix.rstrip("/") + "/"):
            return self._confine_to_workdir(norm, path)

        if self.target_path:
            real_target = os.path.realpath(self.target_path)
            real_cand = os.path.realpath(raw)
            if os.path.isfile(real_target) and real_cand == real_target:
                return self._confine_to_workdir(
                    posixpath.join(self._workdir_posix, os.path.basename(real_target)), path
                )
            if os.path.isdir(real_target) and (
                real_cand == real_target or real_cand.startswith(real_target + os.sep)
            ):
                rel = os.path.relpath(real_cand, real_target).replace(os.sep, "/")
                return self._confine_to_workdir(posixpath.join(self._workdir_posix, rel), path)

        raise PermissionError(
            f"Path '{path}' escapes the remote sandbox workspace '{self._workdir_posix}'."
        )

    def _run_reset_sync(self, *, strict: bool) -> None:
        if self.reset_argv:
            res = run_bounded_subprocess(
                self.reset_argv,
                timeout=self.timeout,
                max_stdout_bytes=_MAX_EXEC_CAPTURE_BYTES,
                max_stderr_bytes=_MAX_EXEC_CAPTURE_BYTES,
            )
            if strict and (res.timed_out or res.returncode != 0):
                err = res.stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(
                    f"Remote sandbox reset_argv failed (exit={res.returncode}): {err}"
                )
        if self.reset_cmd:
            res = run_bounded_subprocess(
                self._build_transport_argv(self.reset_cmd),
                timeout=self.timeout,
                max_stdout_bytes=_MAX_EXEC_CAPTURE_BYTES,
                max_stderr_bytes=_MAX_EXEC_CAPTURE_BYTES,
            )
            if strict and (res.timed_out or res.returncode != 0):
                err = res.stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(
                    f"Remote sandbox reset_cmd failed (exit={res.returncode}): {err}"
                )

    async def preflight(self) -> None:
        """Validates transport binary availability and optional remote target healthcheck."""
        bin_name = self._transport_binary()
        if shutil.which(bin_name) is None and not os.path.exists(bin_name):
            raise ValueError(
                f"sandbox type 'remote' ({self.transport}) requires '{bin_name}' on PATH."
            )

        def _check() -> None:
            if self.healthcheck_cmd:
                res = run_bounded_subprocess(
                    self._build_raw_transport_argv(self.healthcheck_cmd),
                    timeout=min(self.timeout, 15),
                    max_stdout_bytes=65536,
                    max_stderr_bytes=65536,
                    mock_text=True,
                )
                if res.timed_out or res.returncode != 0:
                    detail = (
                        res.stderr.decode("utf-8", errors="replace").strip()
                        or res.stdout.decode("utf-8", errors="replace").strip()
                        or f"exit={res.returncode}"
                    )
                    raise RuntimeError(
                        f"Remote target healthcheck failed ({detail})."
                    )
                return

            if self.transport == "container":
                res = run_bounded_subprocess(
                    [
                        self.container_tool,
                        "inspect",
                        "--format",
                        "{{.State.Running}}",
                        self.container,
                    ],
                    timeout=10.0,
                    max_stdout_bytes=4096,
                    max_stderr_bytes=4096,
                    mock_text=True,
                )
                state = res.stdout.decode("utf-8", errors="replace").strip().lower()
                if res.timed_out or res.returncode != 0 or state != "true":
                    detail = res.stderr.decode("utf-8", errors="replace").strip() or state or "not running"
                    raise RuntimeError(
                        f"Remote target container '{self.container}' is not running ({detail})."
                    )

        await asyncio.to_thread(_check)

    async def _ensure(self) -> None:
        fresh = False
        async with self._lock:
            if self._started:
                return

            def _init() -> None:
                mkdir_cmd = f"mkdir -p {shlex.quote(self._workdir_posix)}"
                res = run_bounded_subprocess(
                    self._build_raw_transport_argv(mkdir_cmd),
                    timeout=self.timeout,
                    max_stdout_bytes=65536,
                    max_stderr_bytes=65536,
                )
                if res.timed_out or res.returncode != 0:
                    err = res.stderr.decode("utf-8", errors="replace").strip()
                    raise RuntimeError(
                        f"Failed to initialize remote sandbox workdir '{self._workdir_posix}': {err}"
                    )
                self._run_reset_sync(strict=True)

            await asyncio.to_thread(_init)
            self._started = True
            self.is_initialized = True
            fresh = True

        if fresh:
            from core.poc_scaffold import mark_staged

            await mark_staged(self.write_file)

    async def initialize(self) -> None:
        await self._ensure()

    async def read_file(self, path: Union[Path, str]) -> bytes:
        """Static-plane read: strictly reads from the local read-only target checkout (INV-4)."""
        return await self._static_env.read_file(Path(path))

    async def list_files(self, directory: str = "") -> List[str]:
        """Static-plane listing: strictly lists the local read-only target checkout (INV-4)."""
        return await self._static_env.list_files(directory)

    async def read_guest_file(self, path: Union[Path, str]) -> bytes:
        """Dynamic-plane read: reads a sidecar sentinel or PoC scaffold from the remote workdir."""
        await self._ensure()
        resolved_posix = self._resolve_guest_path(path)
        qpath = shlex.quote(resolved_posix)
        remote_cmd = (
            f"if [ -L {qpath} ]; then echo 'Permission denied: symlink' >&2; exit 43; fi; "
            f"if [ ! -f {qpath} ]; then echo 'No such file or directory' >&2; exit 44; fi; "
            f"base64 < {qpath} | tr -d '\\r\\n'"
        )
        argv = self._build_transport_argv(remote_cmd)

        def _read() -> bytes:
            res = run_bounded_subprocess(
                argv,
                timeout=self.timeout,
                max_stdout_bytes=_MAX_B64_GUEST_FILE_BYTES,
                max_stderr_bytes=65536,
                kill_on_stdout_overflow=True,
                mock_text=False,
            )
            if res.timed_out:
                raise TimeoutError(f"Read timed out on remote target: {path}")
            if res.stdout_overflowed:
                raise ValueError(
                    f"File '{path}' exceeds maximum sandbox read size ({MAX_GUEST_FILE_BYTES} bytes)."
                )
            if res.returncode == 43:
                raise PermissionError(f"Permission denied reading symlink on remote target: {path}")
            if res.returncode == 44:
                raise FileNotFoundError(f"File not found on remote target: {path}")
            if res.returncode != 0:
                stderr = res.stderr.decode("utf-8", errors="replace")
                if "No such file" in stderr:
                    raise FileNotFoundError(f"File not found on remote target: {path}")
                if "Permission denied" in stderr:
                    raise PermissionError(f"Permission denied reading file on remote target: {path}")
                raise RuntimeError(f"Error reading file '{path}' from remote target: {stderr}")
            try:
                decoded = base64.b64decode(res.stdout.strip())
            except Exception as exc:
                raise RuntimeError(f"Failed to decode remote file '{path}': {exc}") from exc
            if len(decoded) > MAX_GUEST_FILE_BYTES:
                raise ValueError(
                    f"File '{path}' exceeds maximum sandbox read size ({MAX_GUEST_FILE_BYTES} bytes)."
                )
            return decoded

        return await asyncio.to_thread(_read)

    async def write_file(self, path: Union[Path, str], content: Union[str, bytes]) -> None:
        """Dynamic-plane write: stages PoC scripts/scaffolds into remote workdir without touching host."""
        await self._ensure()
        resolved_posix = self._resolve_guest_path(path)
        data = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        if len(data) > MAX_GUEST_FILE_BYTES:
            raise ValueError(
                f"File '{path}' ({len(data)} bytes) exceeds maximum sandbox write size ({MAX_GUEST_FILE_BYTES} bytes)."
            )
        parent_posix = posixpath.dirname(resolved_posix) or self._workdir_posix
        qparent = shlex.quote(parent_posix)
        qdest = shlex.quote(resolved_posix)
        remote_cmd = (
            f"mkdir -p {qparent} && "
            f"if [ -L {qdest} ]; then echo 'Permission denied: symlink' >&2; exit 43; fi && "
            f"cat > {qdest}"
        )
        argv = self._build_transport_argv(remote_cmd, with_stdin=True)

        def _write() -> None:
            res = run_bounded_subprocess(
                argv,
                timeout=self.timeout,
                max_stdout_bytes=65536,
                max_stderr_bytes=65536,
                stdin_bytes=data,
                mock_text=False,
            )
            if res.timed_out:
                raise TimeoutError(f"Write timed out on remote target: {path}")
            if res.returncode == 43:
                raise PermissionError(f"Refusing to overwrite symlink on remote target: {path}")
            if res.returncode != 0:
                stderr = res.stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(f"Failed to write file '{path}' on remote target: {stderr}")

        await asyncio.to_thread(_write)

    @staticmethod
    def _clip_newest_telemetry(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return (
            f"[remote target telemetry clipped to newest {limit} of {len(text)} chars]\n"
            + text[-limit:]
        )

    @staticmethod
    def _is_remote_transport_failure(transport: str, returncode: int, stderr_text: str) -> bool:
        low = (stderr_text or "").lower()
        if transport == "container":
            if returncode == 125:
                return True
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
        if transport == "ssh" and returncode == 255:
            return any(
                m in low
                for m in (
                    "ssh:",
                    "kex_exchange_identification",
                    "connection timed out",
                    "connection refused",
                    "connection closed",
                    "connection reset",
                    "broken pipe",
                    "no route to host",
                    "host key verification failed",
                    "permission denied (publickey",
                )
            )
        return False

    async def execute(self, command: str, *, timeout: Optional[float] = None) -> ExecutionResult:
        """Executes ``command`` inside the remote target workdir and collects optional telemetry."""
        await self._ensure()
        t = float(timeout) if timeout is not None else float(self.timeout)
        exec_env = self._consume_exec_env() if hasattr(self, "_consume_exec_env") else None
        effective_cmd = format_posix_exports(exec_env) + command if exec_env else command
        argv = self._build_transport_argv(effective_cmd, with_stdin=False)

        def _exec() -> ExecutionResult:
            try:
                pre_log_bytes = 0
                if self.log_file:
                    qlog = shlex.quote(self.log_file)
                    pre_res = run_bounded_subprocess(
                        self._build_transport_argv(
                            f"if [ -f {qlog} ]; then wc -c < {qlog} 2>/dev/null || echo 0; else echo 0; fi",
                            with_stdin=False,
                        ),
                        timeout=min(t, 10.0),
                        max_stdout_bytes=4096,
                        max_stderr_bytes=4096,
                        mock_text=True,
                    )
                    try:
                        pre_log_bytes = max(
                            0,
                            int(pre_res.stdout.decode("utf-8", errors="replace").strip() or "0"),
                        )
                    except ValueError:
                        pre_log_bytes = 0

                res = run_bounded_subprocess(
                    argv,
                    timeout=t,
                    max_stdout_bytes=_MAX_EXEC_CAPTURE_BYTES,
                    max_stderr_bytes=_MAX_EXEC_CAPTURE_BYTES,
                    mock_text=True,
                )
                telemetry_blocks: List[str] = []
                if self.log_file:
                    qlog = shlex.quote(self.log_file)
                    delta_cmd = (
                        f"if [ -f {qlog} ]; then "
                        f"cur=$(wc -c < {qlog} 2>/dev/null || echo 0); "
                        f"start={pre_log_bytes + 1}; "
                        f"if [ \"$cur\" -lt \"{pre_log_bytes}\" ]; then start=1; fi; "
                        f"if [ \"$cur\" -ge \"$start\" ]; then tail -c +\"$start\" {qlog}; fi; "
                        f"fi"
                    )
                    delta_res = run_bounded_subprocess(
                        self._build_transport_argv(delta_cmd, with_stdin=False),
                        timeout=min(t, 10.0),
                        max_stdout_bytes=_MAX_EXEC_CAPTURE_BYTES,
                        max_stderr_bytes=65536,
                        mock_text=True,
                    )
                    delta_txt = delta_res.stdout.decode("utf-8", errors="replace").strip()
                    if delta_txt:
                        bounded_delta = self._clip_newest_telemetry(delta_txt, _MAX_TELEMETRY_CHARS)
                        telemetry_blocks.append(f"\n[REMOTE TARGET DELTA TELEMETRY]\n{bounded_delta}")

                if self.log_cmd:
                    log_res = run_bounded_subprocess(
                        self._build_transport_argv(self.log_cmd, with_stdin=False),
                        timeout=min(t, 10.0),
                        max_stdout_bytes=_MAX_EXEC_CAPTURE_BYTES,
                        max_stderr_bytes=65536,
                        mock_text=True,
                    )
                    log_txt = log_res.stdout.decode("utf-8", errors="replace").strip()
                    if log_txt:
                        bounded_log = self._clip_newest_telemetry(log_txt, _MAX_TELEMETRY_CHARS)
                        telemetry_blocks.append(
                            f"\n[REMOTE TARGET TELEMETRY]\n{bounded_log}\n[/REMOTE TARGET TELEMETRY]"
                        )

                stdout_formatted = format_bounded_output(
                    res.stdout, res.stdout_total_bytes, MAX_OUTPUT, what="sandbox stdout"
                )
                for block in telemetry_blocks:
                    stdout_formatted = (
                        f"{stdout_formatted}{block}" if stdout_formatted else block.lstrip("\n")
                    )

                if res.timed_out:
                    return ExecutionResult(
                        stdout=stdout_formatted,
                        stderr=f"SANDBOX-TIMEOUT: Command exceeded {t}s limit.",
                        exit_code=124,
                        timed_out=True,
                    )
                stderr_formatted = format_bounded_output(
                    res.stderr, res.stderr_total_bytes, MAX_OUTPUT, what="sandbox stderr"
                )
                if res.returncode != 0 and self._is_remote_transport_failure(
                    self.transport, res.returncode, stderr_formatted
                ):
                    stderr_formatted = (
                        f"SANDBOX-ERROR: Remote {self.transport} transport failed "
                        f"(exit={res.returncode}): {stderr_formatted}"
                    )
                return ExecutionResult(
                    stdout=stdout_formatted,
                    stderr=stderr_formatted,
                    exit_code=res.returncode,
                    timed_out=False,
                )
            except Exception as exc:
                return ExecutionResult(
                    stdout="",
                    stderr=f"SANDBOX-ERROR: {exc}",
                    exit_code=-1,
                    timed_out=False,
                )

        return await asyncio.to_thread(_exec)

    async def apply_patch(self, diff: str) -> str:
        """Applies a unified diff on the remote target workdir and runs optional ``rebuild_cmd``."""
        await self._ensure()
        diff_bytes = diff.encode("utf-8")

        patch_script = (
            "if command -v git >/dev/null 2>&1 && [ -e .git ]; then "
            "git apply --whitespace=nowarn -; "
            "elif command -v patch >/dev/null 2>&1; then "
            "patch --batch --force -p1; "
            "else exit 127; fi"
        )

        def _run_patch_cmd(cmd_str: str, payload: Optional[bytes]) -> tuple[int, str]:
            res = run_bounded_subprocess(
                self._build_transport_argv(cmd_str, with_stdin=payload is not None),
                timeout=self.timeout,
                max_stdout_bytes=_MAX_EXEC_CAPTURE_BYTES,
                max_stderr_bytes=_MAX_EXEC_CAPTURE_BYTES,
                stdin_bytes=payload,
                mock_text=False,
            )
            if res.timed_out:
                return 124, f"SANDBOX-TIMEOUT: patch command exceeded {self.timeout}s."
            combined = (
                res.stdout.decode("utf-8", errors="replace")
                + res.stderr.decode("utf-8", errors="replace")
            )
            return res.returncode, combined

        rc, out = await asyncio.to_thread(_run_patch_cmd, patch_script, diff_bytes)
        if rc not in (0, 127):
            rc_p0, out_p0 = await asyncio.to_thread(
                _run_patch_cmd,
                "if command -v patch >/dev/null 2>&1; then patch --batch --force -p0; else exit 127; fi",
                diff_bytes,
            )
            if rc_p0 == 0:
                rc, out = rc_p0, out_p0

        if rc == 127:
            from core.environments.patch_fallback import (
                PATCH_FILE_NAME,
                PATCH_SCRIPT_NAME,
                PYTHON_PATCH_SCRIPT,
                fallback_argv,
                unavailable_message,
            )

            await self.write_file(Path(PATCH_FILE_NAME), diff)
            await self.write_file(Path(PATCH_SCRIPT_NAME), PYTHON_PATCH_SCRIPT)
            fb_cmd_1 = " ".join(shlex.quote(a) for a in fallback_argv(strip=1))
            rc, out = await asyncio.to_thread(_run_patch_cmd, fb_cmd_1, None)
            if rc in (126, 127):
                return unavailable_message("remote target", out)
            if rc != 0:
                fb_cmd_0 = " ".join(shlex.quote(a) for a in fallback_argv(strip=0))
                rc0, out0 = await asyncio.to_thread(_run_patch_cmd, fb_cmd_0, None)
                if rc0 == 0:
                    rc, out = 0, out0

        if rc != 0:
            return f"exit={rc}\n{truncate_with_marker(out, MAX_OUTPUT, what='patch output')}"

        if self.rebuild_cmd:
            rb_rc, rb_out = await self.run_rebuild()
            if rb_rc != 0:
                combined_err = f"[PATCH APPLIED; REBUILD FAILED]\n{rb_out}"
                return f"exit={rb_rc}\n{truncate_with_marker(combined_err, MAX_OUTPUT, what='patch rebuild output')}"
            out = f"{out}\n[REBUILD OK]\n{rb_out}".strip()

        return f"exit=0\n{truncate_with_marker(out, MAX_OUTPUT, what='patch output')}"

    async def run_rebuild(self) -> tuple[int, str]:
        """Executes configured ``rebuild_cmd`` inside ``workdir``, returning ``(exit_code, output)``."""
        if not self.rebuild_cmd:
            return 0, ""
        await self._ensure()

        def _rebuild() -> tuple[int, str]:
            res = run_bounded_subprocess(
                self._build_transport_argv(self.rebuild_cmd, with_stdin=False),
                timeout=self.timeout,
                max_stdout_bytes=_MAX_EXEC_CAPTURE_BYTES,
                max_stderr_bytes=_MAX_EXEC_CAPTURE_BYTES,
                mock_text=False,
            )
            if res.timed_out:
                return 124, f"SANDBOX-TIMEOUT: rebuild command exceeded {self.timeout}s."
            combined = (
                res.stdout.decode("utf-8", errors="replace")
                + res.stderr.decode("utf-8", errors="replace")
            )
            return res.returncode, combined

        return await asyncio.to_thread(_rebuild)

    async def close(self) -> None:
        """Restores remote target state via optional ``reset_cmd``/``reset_argv`` when configured."""
        async with self._lock:
            if not self._started:
                return
            try:
                if self.reset_cmd or self.reset_argv:
                    await asyncio.to_thread(self._run_reset_sync, strict=False)
            except Exception as exc:
                logger.warning("Remote sandbox close reset failed: %s", exc)
            finally:
                self._started = False
                self.is_initialized = False

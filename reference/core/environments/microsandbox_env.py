import os
import shlex
import sys
import uuid
from pathlib import Path
from typing import Optional, Union, List
from google.adk.environment import ExecutionResult
from microsandbox import Sandbox as MsbSandbox, PullPolicy
from microsandbox.types import Network

from .base import BaseEnvironment

MAX_OUTPUT = 16000


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
    ):
        super().__init__()
        if sys.platform.startswith("linux") and not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise RuntimeError(
                "Hardware virtualization unavailable: '/dev/kvm' is not readable/writable. "
                "Ensure KVM is enabled and the user is in the 'kvm' group, or set sandbox.type to 'static-only'."
            )
        self.target_path = os.path.realpath(target_path) if target_path else ""
        self.image = image
        self.timeout = timeout_seconds
        self._workdir = Path(workdir)
        self._sb: Optional[MsbSandbox] = None
        self._name: Optional[str] = None
        self._stage_error: Optional[Exception] = None

    @property
    def working_dir(self) -> Path:
        return self._workdir

    async def _ensure(self) -> MsbSandbox:
        if self._stage_error is not None:
            raise self._stage_error
        if self._sb is None:
            name = f"mantis-msb-{uuid.uuid4().hex[:12]}"
            sb = await MsbSandbox.create(
                name=name,
                image=self.image,
                network=Network.none(),
                pull_policy=PullPolicy.NEVER,
                replace=True,
            )
            await sb.fs.mkdir(str(self._workdir))

            if self.target_path and os.path.isfile(self.target_path):
                fname = os.path.basename(self.target_path)
                guest_dest = f"{self._workdir}/{fname}"
                try:
                    await sb.fs.copy_from_host(self.target_path, guest_dest)
                except Exception as e:
                    self._stage_error = e
                    self._sb = sb
                    self._name = name
                    raise e
            elif self.target_path and os.path.isdir(self.target_path):
                # Copy files from directory
                try:
                    for root, _, files in os.walk(self.target_path):
                        for file in files:
                            src_file = os.path.join(root, file)
                            rel_file = os.path.relpath(src_file, self.target_path)
                            dest_file = f"{self._workdir}/{rel_file}"
                            dest_dir = os.path.dirname(dest_file)
                            if dest_dir != str(self._workdir):
                                await sb.fs.mkdir(dest_dir)
                            await sb.fs.copy_from_host(src_file, dest_file)
                except Exception as e:
                    self._stage_error = e
                    self._sb = sb
                    self._name = name
                    raise e

            self._name = name
            self._sb = sb
            self.is_initialized = True
        return self._sb

    async def initialize(self) -> None:
        await self._ensure()

    async def execute(self, command: str, *, timeout: Optional[float] = None) -> ExecutionResult:
        t = timeout or self.timeout
        try:
            sb = await self._ensure()
            out = await sb.shell(command, cwd=str(self._workdir), timeout=t)
            stdout_text = out.stdout_text or ""
            stderr_text = getattr(out, "stderr_text", "") or ""
            return ExecutionResult(
                stdout=stdout_text[:MAX_OUTPUT],
                stderr=stderr_text[:MAX_OUTPUT],
                exit_code=out.exit_code,
                timed_out=False,
            )
        except Exception as e:
            return ExecutionResult(
                stdout="",
                stderr=f"SANDBOX-ERROR: {type(e).__name__}: {e}",
                exit_code=1,
                timed_out="timeout" in str(e).lower(),
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
        try:
            return await sb.fs.read(str(resolved_path))
        except Exception as e:
            # Fallback to shell read if fs.read encounters an issue
            exec_res = await self.execute(f"cat {shlex.quote(str(resolved_path))}")
            if exec_res.exit_code == 0:
                return exec_res.stdout.encode("utf-8")
            raise FileNotFoundError(f"File not found in sandbox: {path} ({e})")

    async def write_file(self, path: Union[Path, str], content: Union[str, bytes]) -> None:
        sb = await self._ensure()
        resolved_path = self._resolve_guest_path(path)
        parent_dir = str(resolved_path.parent)
        if parent_dir and parent_dir != str(self._workdir):
            try:
                await sb.fs.mkdir(parent_dir)
            except Exception:
                pass
        data = content.encode("utf-8") if isinstance(content, str) else content
        try:
            await sb.fs.write(str(resolved_path), data)
        except Exception:
            # Fallback to shell write
            import base64
            b64_data = base64.b64encode(data).decode("ascii")
            await self.execute(
                f"mkdir -p {shlex.quote(parent_dir)} && echo '{b64_data}' | base64 -d > {shlex.quote(str(resolved_path))}"
            )

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
        try:
            data = diff.encode("utf-8") if isinstance(diff, str) else diff
            await self.write_file(Path(".mantis.patch"), data)
            res = await self.execute("patch -p1 -i .mantis.patch < /dev/null")
            output_str = f"exit={res.exit_code}\n{res.stdout}{res.stderr}"
            if res.exit_code == 127:
                return f"SANDBOX-ERROR: patch(1) unavailable in image '{self.image}'\n{output_str}"
            if res.exit_code != 0:
                res_no_p1 = await self.execute("patch -i .mantis.patch < /dev/null")
                output_no_p1 = f"exit={res_no_p1.exit_code}\n{res_no_p1.stdout}{res_no_p1.stderr}"
                if res_no_p1.exit_code == 127:
                    return f"SANDBOX-ERROR: patch(1) unavailable in image '{self.image}'\n{output_no_p1}"
                return output_no_p1
            return output_str
        except Exception as e:
            return f"SANDBOX-ERROR: {type(e).__name__}: {e}"

    async def preflight(self) -> None:
        from microsandbox import Image, ImageNotFoundError
        try:
            await Image.get(self.image)
        except ImageNotFoundError as e:
            raise RuntimeError(
                f"sandbox image '{self.image}' not found in the local cache. "
                f"Run ./install.sh to build it, or set sandbox.type to 'gvisor' or 'static-only'. ({e})"
            )

    async def close(self) -> None:
        if self._sb is not None:
            try:
                await self._sb.stop()
            except Exception:
                pass
            try:
                if self._name:
                    await MsbSandbox.remove(self._name)
            except Exception:
                pass
            finally:
                self._sb = None
                self.is_initialized = False

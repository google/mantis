import os
from pathlib import Path
from typing import Optional, Union, List

from google.adk.environment import ExecutionResult
from .base import BaseEnvironment


class StaticOnlyEnvironment(BaseEnvironment):
    """No-op sandbox for static-only vulnerability pipelines. Dynamic execution is disabled."""

    def __init__(self, target_path: str = "", workdir: str = "/workspace", **_):
        super().__init__()
        self.target_path = os.path.realpath(target_path) if target_path else ""
        self._workdir = Path(workdir)
        self.is_initialized = True

    @property
    def working_dir(self) -> Path:
        return self._workdir

    async def initialize(self) -> None:
        self.is_initialized = True

    async def execute(self, command: str, *, timeout: Optional[float] = None) -> ExecutionResult:
        return ExecutionResult(
            stdout="",
            stderr="SANDBOX-UNAVAILABLE: static-only sandbox; dynamic execution is disabled.",
            exit_code=127,
            timed_out=False,
        )

    async def read_file(self, path: Path) -> bytes:
        if not self.target_path:
            raise FileNotFoundError(f"File not found: target_path is not set ({path})")

        real_target = os.path.realpath(self.target_path)
        base_dir = os.path.dirname(real_target) if os.path.isfile(real_target) else real_target

        path_str = str(path)
        if os.path.isabs(path_str):
            resolved_target = os.path.realpath(path_str)
        else:
            resolved_target = os.path.realpath(os.path.join(base_dir, path_str))

        if os.path.isfile(real_target):
            if resolved_target != real_target:
                raise PermissionError(
                    f"Permission denied: requested file '{path}' resolves to '{resolved_target}', "
                    f"which is outside the target file '{real_target}'"
                )
        else:
            try:
                if os.path.commonpath([real_target, resolved_target]) != real_target:
                    raise PermissionError(
                        f"Permission denied: requested path '{path}' resolves to '{resolved_target}', "
                        f"which is outside the target directory '{real_target}'"
                    )
            except ValueError:
                raise PermissionError(
                    f"Permission denied: requested path '{path}' is on a different drive/scope than '{real_target}'"
                )

        if not os.path.isfile(resolved_target):
            raise FileNotFoundError(f"File not found in static environment: {path} (resolved: {resolved_target})")

        with open(resolved_target, "rb") as f:
            return f.read()

    async def write_file(self, path: Path, content: Union[str, bytes]) -> None:
        if not self.target_path:
            raise PermissionError("Permission denied: target_path is not set")

        real_target = os.path.realpath(self.target_path)
        base_dir = os.path.dirname(real_target) if os.path.isfile(real_target) else real_target

        path_str = str(path)
        if os.path.isabs(path_str):
            resolved_target = os.path.realpath(path_str)
        else:
            resolved_target = os.path.realpath(os.path.join(base_dir, path_str))

        if os.path.isfile(real_target):
            if resolved_target != real_target:
                raise PermissionError(f"Permission denied: cannot write outside target file '{real_target}'")
        else:
            try:
                if os.path.commonpath([real_target, resolved_target]) != real_target:
                    raise PermissionError(f"Permission denied: path '{path}' outside target directory '{real_target}'")
            except ValueError:
                raise PermissionError(f"Permission denied: path outside target directory '{real_target}'")

        os.makedirs(os.path.dirname(resolved_target), exist_ok=True)
        data = content.encode("utf-8") if isinstance(content, str) else content
        with open(resolved_target, "wb") as f:
            f.write(data)

    async def list_files(self, directory: str = "") -> List[str]:
        if not self.target_path:
            raise FileNotFoundError(f"Target path is not set ({directory})")

        real_target = os.path.realpath(self.target_path)
        base_dir = os.path.dirname(real_target) if os.path.isfile(real_target) else real_target

        path_str = str(directory) if directory else ""
        if path_str and os.path.isabs(path_str):
            search_dir = os.path.realpath(path_str)
        elif path_str:
            search_dir = os.path.realpath(os.path.join(base_dir, path_str))
        else:
            search_dir = base_dir

        if os.path.isfile(real_target):
            if search_dir != real_target and search_dir != base_dir:
                raise PermissionError(f"Permission denied: path '{directory}' outside allowed target file '{real_target}'")
            return [os.path.basename(real_target)]

        try:
            if os.path.commonpath([real_target, search_dir]) != real_target:
                raise PermissionError(f"Permission denied: path '{directory}' outside target directory '{real_target}'")
        except ValueError:
            raise PermissionError(f"Permission denied: path '{directory}' is outside target scope")

        if not os.path.exists(search_dir):
            raise FileNotFoundError(f"Directory not found: '{directory}' (resolved: '{search_dir}')")
        if not os.path.isdir(search_dir):
            return [os.path.relpath(search_dir, base_dir)]

        results = []
        for root, dirs, files in os.walk(search_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fn in files:
                if not fn.startswith(".") and not fn.endswith(".db"):
                    rel = os.path.relpath(os.path.join(root, fn), base_dir)
                    results.append(rel)
        return sorted(results)

    async def apply_patch(self, diff: str) -> str:
        return "SANDBOX-UNAVAILABLE: static-only sandbox; no dynamic patches are applied."

    async def preflight(self) -> None:
        pass

    async def close(self) -> None:
        self.is_initialized = False

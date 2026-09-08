import os
from pathlib import Path
from typing import Optional, Union, List

from google.adk.environment import ExecutionResult

from core.llm_gateway import strip_terminal_control
from core.paths import (
    absolute_without_normalizing,
    find_escaping_symlink_component,
    find_traversal_component,
)

from .base import BaseEnvironment

PROTECTED_VCS_DIRS = {".git", ".hg", ".svn", ".jj"}
PROTECTED_METADATA_FILES = {
    ".gitconfig",
    ".gitmodules",
    ".gitattributes",
    ".git-credentials",
    ".netrc",
    ".env",
    ".env.local",
    ".npmrc",
    ".pypirc",
    ".pre-commit-config.yaml",
    ".pre-commit-config.yml",
}


class StaticOnlyEnvironment(BaseEnvironment):
    """No-op sandbox for static-only vulnerability pipelines. Dynamic execution is disabled."""

    def __init__(self, target_path: str = "", workdir: str = "/workspace", **_):
        super().__init__()
        # SECURITY (INV-4): abspath() lexically collapses "link/..", erasing the very
        # component the symlink checks below need to see. Absolutize without normalizing.
        self.target_path = (
            str(absolute_without_normalizing(target_path)) if target_path else ""
        )
        self._workdir = Path(workdir)
        self.is_initialized = True

    def _assert_safe_target(self, action: str) -> None:
        """Refuses scan targets reached through a symlink (leaf or intermediate).

        SECURITY (INV-4): a leaf-only islink() check is bypassed by an attacker-planted
        intermediate symlink; realpath() below would silently relocate the whole jail.
        """
        # The refusal message echoes an attacker-controlled path back to a terminal and
        # into the model transcript, so it is an egress path: strip control characters.
        shown = strip_terminal_control(self.target_path)

        if os.path.islink(self.target_path):
            raise PermissionError(
                f"Permission denied. Refusing to {action} symlinked scan target '{shown}'."
            )
        traversal = find_traversal_component(self.target_path)
        if traversal is not None:
            raise PermissionError(
                f"Permission denied. Refusing to {action} scan target '{shown}': it contains "
                f"a '{traversal}' component."
            )
        escaping = find_escaping_symlink_component(self.target_path)
        if escaping is not None:
            component, link_real = escaping
            raise PermissionError(
                f"Permission denied. Refusing to {action} scan target '{shown}': path component "
                f"'{strip_terminal_control(str(component))}' is a symlink escaping to "
                f"'{strip_terminal_control(str(link_real))}'."
            )

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
        self._assert_safe_target("read from")

        real_target = os.path.realpath(self.target_path)
        base_dir = os.path.dirname(real_target) if os.path.isfile(real_target) else real_target

        path_str = str(path)
        raw_target = path_str if os.path.isabs(path_str) else os.path.join(base_dir, path_str)
        if os.path.islink(raw_target):
            raise PermissionError(f"Permission denied. Refusing to read symlink '{path}'.")

        if os.path.isabs(path_str):
            resolved_target = os.path.realpath(path_str)
        else:
            resolved_target = os.path.realpath(os.path.join(base_dir, path_str))

        if os.path.islink(resolved_target):
            raise PermissionError(f"Permission denied. Refusing to read symlink '{path}'.")

        if os.path.isfile(real_target):
            if resolved_target != real_target:
                raise PermissionError(
                    f"Permission denied. Single-file scans may only read the scanned file '{os.path.basename(real_target)}'."
                )
        else:
            try:
                if os.path.commonpath([real_target, resolved_target]) != real_target:
                    raise PermissionError(
                        f"Permission denied. The filepath '{path}' is outside the allowed directory."
                    )
            except ValueError:
                raise PermissionError(
                    f"Permission denied: requested path '{path}' is on a different drive/scope than '{real_target}'"
                )

        if not os.path.isfile(resolved_target):
            raise FileNotFoundError(f"File not found in static environment: {path} (resolved: {resolved_target})")

        # SECURITY (INV-4): a hard link inside the checkout aliases arbitrary host file
        # content on the same device, and has no distinct target path for realpath()
        # containment to reject. Refuse multiply-linked files.
        if os.lstat(resolved_target).st_nlink > 1:
            raise PermissionError(
                f"Permission denied. Refusing to read hard-linked file '{path}'; it may alias content outside the scan target."
            )

        # Refuse reading from VCS metadata directory or credential files
        rel_from_base = os.path.relpath(resolved_target, base_dir)
        parts = rel_from_base.lower().split(os.sep)
        if any(d in parts for d in PROTECTED_VCS_DIRS) or parts[-1] in PROTECTED_METADATA_FILES:
            raise PermissionError(f"Permission denied. Refusing to read version-control metadata or credential files ('{rel_from_base}').")

        with open(resolved_target, "rb") as f:
            return f.read()

    async def write_file(self, path: Path, content: Union[str, bytes]) -> None:
        if os.environ.get("MANTIS_ALLOW_STATIC_WRITE") != "1":
            raise PermissionError(
                f"Permission denied: modifying host repository files ('{path}') is disabled in static analysis mode. "
                "Store campaign artifacts under 'workspace/'."
            )

        if not self.target_path:
            raise PermissionError("Permission denied: target_path is not set")
        self._assert_safe_target("write into")

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

        # Refuse writing to VCS metadata even if static writes are explicitly enabled
        rel_from_base = os.path.relpath(resolved_target, base_dir)
        parts = rel_from_base.lower().split(os.sep)
        if any(d in parts for d in PROTECTED_VCS_DIRS) or parts[-1] in PROTECTED_METADATA_FILES:
            raise PermissionError(f"Permission denied: refusing to write into version-control metadata or credential files ('{rel_from_base}')")

        # SECURITY (INV-4): the read path refuses hard links; so must the write path.
        # A hard link inside the checkout aliases a host inode on the same device and has
        # no distinct target path for realpath() containment to reject, so writing
        # "inside" the target can mutate a file outside it.
        if os.path.exists(resolved_target) and os.lstat(resolved_target).st_nlink > 1:
            raise PermissionError(
                f"Permission denied: refusing to write to hard-linked file '{rel_from_base}'; "
                "it may alias content outside the scan target."
            )

        os.makedirs(os.path.dirname(resolved_target), exist_ok=True)
        data = content.encode("utf-8") if isinstance(content, str) else content
        with open(resolved_target, "wb") as f:
            f.write(data)

    async def list_files(self, directory: str = "") -> List[str]:
        if not self.target_path:
            raise FileNotFoundError(f"Target path is not set ({directory})")
        self._assert_safe_target("list")

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

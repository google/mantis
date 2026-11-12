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

"""A PoC's companion files: what it needs besides its own wrapper.

The reproducer writes `workspace/repro_<id>.py`, and that is what later runs
re-run. Live, the wrapper was often twenty lines around a harness that lived
somewhere else: a Go program under `workspace/repro_<id>/`, a `_test.go`
dropped into the package it exercises, a helper copied into the module. The
workspace files were persisted (every `write_file` under `workspace/` is)
but never restored with the wrapper; the files written into the target tree
were never persisted at all, because the guest they were written into is
destroyed with the campaign. A later run then re-ran a wrapper whose harness
did not exist, and read the build failure as the exploit failing.

Two halves, both bounded:

- CAPTURE. When a PoC's reached-sink evidence lands for a finding, the
  files created in the guest's target tree since staging (newer than the
  marker the environment drops after staging; not under `workspace/`,
  which is persisted already; not a file the host checkout has, which is
  the target and not a scaffold) are stored as workspace artifacts at
  `workspace/repro_<id>/_target/<path>`. Counts and sizes are capped, and
  only text is kept: a scaffold is source.
- RESTORE. Before an earlier finding's wrapper is re-run, every workspace
  artifact its run left whose path names `repro_<id>` is written back:
  `workspace/...` files at their own paths, `_target/` files at their
  target-tree paths -- unless the guest already has a file there, which
  means the code has since grown one and the scaffold must not replace it.
  A path that would leave the tree is dropped.

Over-capture is accepted: a campaign with several findings stores each
scaffold under every finding confirmed after it was written. Restoring a
scaffold that belongs to a sibling is harmless; failing to restore the one
the wrapper needs is a false "fixed".
"""

from __future__ import annotations

import posixpath
import re
from pathlib import Path
from typing import Awaitable, Callable, Optional

#: Dropped into the guest workdir by each environment once staging is done.
#: Files newer than it were made by the campaign, not copied from the host.
STAGING_MARKER = ".mantis_staged"

#: Where a finding's target-tree scaffold lives among its workspace artifacts.
SCAFFOLD_SUBDIR = "_target"

MAX_SCAFFOLD_FILES = 64
MAX_SCAFFOLD_FILE_BYTES = 256 * 1024
MAX_SCAFFOLD_TOTAL_BYTES = 2 * 1024 * 1024

#: Directories `find` does not descend into. At the top of the tree:
#: `workspace/` (persisted on every write already) and `vendor/` (a build may
#: touch it; nothing there is a scaffold). Anywhere: VCS, dependency trees
#: and caches.
_PRUNED_TOP = ("workspace", "vendor")
_PRUNED_ANYWHERE = (
    ".git", ".hg", ".svn", ".jj", "node_modules", "__pycache__", ".venv", "venv",
    ".cache", ".pytest_cache", ".mypy_cache",
)

_WRAPPER_EXTS = ("py", "sh", "c", "js", "txt")
_SIDECAR_SENTINEL_RE = re.compile(r"^(?:\.mantis_reached_sentinel|sentinel[_-]\d+(?:\.\w+)?)$")


def find_new_files_command(limit: int = 4 * MAX_SCAFFOLD_FILES) -> str:
    """The guest command that lists regular files created since staging.

    POSIX `find` only (`-prune`, `-o`, `-newer`, `-size`, `-print`): the
    guest image may carry busybox. Oversized files are left out in the
    guest so the listing is small; the host caps again.
    """
    prune = " -o ".join(
        [f"-path ./{d}" for d in _PRUNED_TOP] + [f"-name {d}" for d in _PRUNED_ANYWHERE])
    kib = max(1, MAX_SCAFFOLD_FILE_BYTES // 1024)
    return (
        f"test -e {STAGING_MARKER} && find . \\( {prune} \\) -prune -o -type f "
        f"-newer {STAGING_MARKER} -size -{kib}k -print | head -n {int(limit)}"
    )


def safe_target_relpath(raw: str) -> Optional[str]:
    """A target-relative POSIX path with no way out of the tree, or None."""
    text = str(raw or "").strip().replace("\\", "/")
    if text.startswith("./"):
        text = text[2:]
    if not text or text.startswith("/") or "\x00" in text or "\n" in text:
        return None
    norm = posixpath.normpath(text)
    if norm in (".", "") or norm.startswith("/") or norm.startswith("../") or norm == "..":
        return None
    if any(part == ".." for part in norm.split("/")):
        return None
    if norm == STAGING_MARKER or norm.startswith("workspace/") or norm == "workspace":
        return None
    return norm


def scaffold_artifact_path(finding_id: int, rel: str) -> str:
    return f"workspace/repro_{int(finding_id)}/{SCAFFOLD_SUBDIR}/{rel}"


def wrapper_artifact_paths(finding_id: int) -> tuple[str, ...]:
    """The paths a finding's own wrapper may have been written at, in the
    order a restore tries them."""
    return tuple(f"workspace/repro_{int(finding_id)}.{ext}" for ext in _WRAPPER_EXTS)


def _names_finding(filepath: str, finding_id: int) -> bool:
    """Whether `repro_<id>` occurs in the path as a whole token: matches
    `repro_103.py`, `repro_103/main.go`, `zz_repro_103_test.go`; not
    `repro_1030`."""
    return re.search(rf"(?<![0-9A-Za-z])repro_{int(finding_id)}(?![0-9])", filepath) is not None


async def list_new_target_files(sandbox) -> list[str]:
    """Target-relative paths of files the campaign created in the guest's
    target tree. Empty when the guest has no marker or no `find`."""
    try:
        res = await sandbox.execute(find_new_files_command())
    except Exception:
        return []
    if int(getattr(res, "exit_code", 1) or 0) != 0:
        return []
    out = []
    seen = set()
    for line in str(getattr(res, "stdout", "") or "").splitlines():
        rel = safe_target_relpath(line)
        if rel and rel not in seen:
            seen.add(rel)
            out.append(rel)
    return out


async def capture_poc_scaffold(
    sandbox,
    finding_id: int,
    persist: Callable[[str, str, str], None],
    host_root: Optional[str] = None,
) -> list[str]:
    """Stores the files a PoC left in the guest's target tree. `persist`
    receives (artifact_path, content, target_relpath). Returns the paths
    stored. Never raises: a scaffold that cannot be kept costs a later
    re-run its context, not this run its evidence."""
    stored: list[str] = []
    try:
        rels = await list_new_target_files(sandbox)
    except Exception:
        return stored
    total = 0
    for rel in rels:
        if len(stored) >= MAX_SCAFFOLD_FILES or total >= MAX_SCAFFOLD_TOTAL_BYTES:
            break
        if _SIDECAR_SENTINEL_RE.match(posixpath.basename(rel)):
            continue  # sidecar proof file from this run, never a reusable scaffold
        if host_root and _host_has(host_root, rel):
            continue  # a target file the PoC edited: a patch, not a scaffold
        try:
            reader = (
                sandbox.read_guest_file
                if getattr(type(sandbox), "read_guest_file", None) is not None
                else sandbox.read_file
            )
            data = await reader(Path(rel))
        except Exception:
            continue
        if not isinstance(data, (bytes, bytearray)):
            data = str(data).encode("utf-8", errors="replace")
        if len(data) > MAX_SCAFFOLD_FILE_BYTES or total + len(data) > MAX_SCAFFOLD_TOTAL_BYTES:
            continue
        if b"\x00" in data:
            continue  # a binary: built output, not a scaffold
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            continue
        try:
            persist(scaffold_artifact_path(finding_id, rel), text, rel)
        except Exception:
            continue
        total += len(data)
        stored.append(rel)
    return stored


def _host_has(host_root: str, rel: str) -> bool:
    import os
    try:
        root = os.path.realpath(str(host_root))
        cand = os.path.realpath(os.path.join(root, rel))
        return (cand == root or cand.startswith(root + os.sep)) and os.path.lexists(cand)
    except (OSError, ValueError):
        return False


def prior_poc_companions(db_path: str, prior_run_id: str, finding_id: int) -> list[tuple[str, str]]:
    """`[(guest_path, content)]` for every file an earlier run left for the
    finding besides its wrapper, newest row per path. Workspace files keep
    their paths; `_target/` files map to their target-tree paths; anything
    that would leave the tree is dropped."""
    from core.database import read_artifacts_like

    fid = int(finding_id)
    try:
        rows = read_artifacts_like(db_path, prior_run_id, f"%repro\\_{fid}%", artifact_type="workspace_file")
    except Exception:
        return []
    wrappers = set(wrapper_artifact_paths(fid))
    prefix = f"workspace/repro_{fid}/{SCAFFOLD_SUBDIR}/"
    out: list[tuple[str, str]] = []
    for row in rows:
        fp = str(row.get("filepath") or "")
        if fp in wrappers or not _names_finding(fp, fid):
            continue
        if fp.startswith(prefix):
            rel = safe_target_relpath(fp[len(prefix):])
            if not rel:
                continue
            guest_path = rel
        else:
            norm = posixpath.normpath(fp)
            if not norm.startswith("workspace/") or any(p == ".." for p in norm.split("/")):
                continue
            guest_path = norm
        out.append((guest_path, str(row.get("content") or "")))
    return out


async def restore_poc_companions(sandbox, db_path: str, prior_run_id: str, finding_id: int,
                                 ) -> tuple[list[str], list[str]]:
    """Writes an earlier finding's companion files into the guest ahead of
    its wrapper. Returns `(restored, skipped)`: a target-tree file is skipped
    when the guest already has one at that path -- the code grew a file
    there since, and the scaffold must not stand in for it. Never raises."""
    restored: list[str] = []
    skipped: list[str] = []
    try:
        companions = prior_poc_companions(db_path, prior_run_id, finding_id)
    except Exception:
        return restored, skipped
    for guest_path, content in companions:
        in_target = not guest_path.startswith("workspace/")
        if in_target:
            try:
                reader = (
                    sandbox.read_guest_file
                    if getattr(type(sandbox), "read_guest_file", None) is not None
                    else sandbox.read_file
                )
                await reader(Path(guest_path))
                skipped.append(guest_path)
                continue
            except Exception:
                pass
        try:
            await sandbox.write_file(Path(guest_path), content)
            restored.append(guest_path)
        except Exception:
            skipped.append(guest_path)
    return restored, skipped


async def mark_staged(write_file: Callable[[Path, bytes], Awaitable[None]]) -> None:
    """Drops the staging marker through an environment's own write_file.
    Best effort: an environment without it captures no scaffolds and loses
    nothing else."""
    try:
        await write_file(Path(STAGING_MARKER), b"")
    except Exception:
        pass

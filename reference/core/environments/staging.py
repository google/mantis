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

"""Shared, fail-closed filesystem staging logic for Mantis sandbox environments.

Ensures all sandbox backends (gVisor, MicroSandbox, GCE, Docker) use the exact same
proven staging filters:
- followlinks=False
- Strict symlink pruning (refusing islink for both files and directories)
- commonpath containment (verifying realpath stays strictly inside realpath(target))
- Denylisting protected VCS directories (.git, .hg, .svn, .jj) and sensitive metadata files (.env, etc.)
"""

from __future__ import annotations

import os
import stat
import shutil
import tarfile
from pathlib import Path
from typing import List, Tuple, Union

from .static_env import PROTECTED_METADATA_FILES, PROTECTED_VCS_DIRS

MAX_STAGING_FILES = 50_000
MAX_STAGING_BYTES = 512 * 1024 * 1024


def _resolve_staging_limits() -> Tuple[int, int]:
    """Returns `(max_files, max_bytes)` honoring `MANTIS_MAX_STAGING_*` env overrides."""
    max_files = MAX_STAGING_FILES
    raw_files = os.environ.get("MANTIS_MAX_STAGING_FILES", "").strip()
    if raw_files:
        try:
            parsed_f = int(raw_files)
            if parsed_f > 0:
                max_files = parsed_f
        except ValueError:
            pass
    max_bytes = MAX_STAGING_BYTES
    raw_bytes = os.environ.get("MANTIS_MAX_STAGING_BYTES", "").strip()
    if raw_bytes:
        try:
            parsed_b = int(raw_bytes)
            if parsed_b > 0:
                max_bytes = parsed_b
        except ValueError:
            pass
    return max_files, max_bytes


def enforce_staging_budget(vetted: List[Tuple[Path, str]]) -> None:
    """Verifies that staging `vetted` files will not exceed host/guest file or byte caps."""
    max_files, max_bytes = _resolve_staging_limits()
    if len(vetted) > max_files:
        raise RuntimeError(
            f"Refusing to stage checkout: {len(vetted)} files exceeds maximum staging limit "
            f"of {max_files} files (set MANTIS_MAX_STAGING_FILES to raise)."
        )
    total_bytes = 0
    for src_file, _ in vetted:
        try:
            st = os.lstat(src_file)
        except OSError:
            continue
        total_bytes += st.st_size
        if total_bytes > max_bytes:
            raise RuntimeError(
                f"Refusing to stage checkout: cumulative size exceeds maximum staging limit "
                f"of {max_bytes} bytes (set MANTIS_MAX_STAGING_BYTES to raise)."
            )


def get_vetted_staging_files(target_path: Union[str, Path]) -> List[Tuple[Path, str]]:
    """Inspects target_path and returns a list of (source_abs_path, relative_guest_path) tuples.

    Guarantees:
    1. Zero symlink traversal or dereferencing.
    2. Zero ingestion of VCS directories or credential/metadata files.
    3. Strict commonpath containment ensuring no path escape beyond the target root.
    """
    if not target_path or not os.path.exists(target_path):
        return []

    target_str = str(target_path)
    real_target = os.path.realpath(target_str)
    vetted: List[Tuple[Path, str]] = []

    if os.path.islink(target_str):
        # Target itself is a symlink: strictly refuse staging
        return []

    if os.path.isfile(target_str):
        fname = os.path.basename(target_str)
        if fname in PROTECTED_METADATA_FILES or fname in PROTECTED_VCS_DIRS:
            return []
        try:
            if os.lstat(target_str).st_nlink > 1:
                return []
        except OSError:
            return []
        real_src = os.path.realpath(target_str)
        if real_src != real_target:
            return []
        return [(Path(target_str).resolve(), fname)]

    if os.path.isdir(target_str):
        for root, dirs, files in os.walk(target_str, followlinks=False):
            # Prune VCS directories and symlinked directories immediately
            dirs[:] = [
                d for d in dirs
                if d not in PROTECTED_VCS_DIRS and not os.path.islink(os.path.join(root, d))
            ]

            for file in files:
                if file in PROTECTED_METADATA_FILES:
                    continue
                # A gitdir pointer (".git" holding "gitdir: /elsewhere") is a regular
                # FILE, so the directory denylist above never sees it. Prune by name.
                if file in PROTECTED_VCS_DIRS:
                    continue

                src_file = os.path.join(root, file)
                if os.path.islink(src_file):
                    continue

                try:
                    st = os.lstat(src_file)
                except OSError:
                    continue

                # A hard link inside the checkout can alias arbitrary host file content
                # on the same device. realpath() containment cannot detect this because
                # a hard link has no distinct target path. Refuse multiply-linked files.
                if st.st_nlink > 1:
                    continue
                # Regular files only. A FIFO, socket or device node in the checkout
                # (mkfifo needs no privilege; a tarball can carry one) blocks every
                # consumer that opens it -- the index build, the surveyor -- forever.
                if not stat.S_ISREG(st.st_mode):
                    continue

                try:
                    real_src = os.path.realpath(src_file)
                    if os.path.commonpath([real_src, real_target]) != real_target:
                        continue
                except (ValueError, OSError):
                    continue

                rel_file = os.path.relpath(src_file, target_str).replace("\\", "/")
                # Ensure relative path cannot escape via ../
                if rel_file.startswith("..") or "/../" in f"/{rel_file}/":
                    continue

                vetted.append((Path(real_src), rel_file))

    return vetted


def stage_to_directory(target_path: Union[str, Path], dest_dir: Union[str, Path]) -> int:
    """Copies all vetted staging files from target_path into dest_dir, creating parents."""
    dest_path = Path(dest_dir)
    vetted = get_vetted_staging_files(target_path)
    enforce_staging_budget(vetted)
    count = 0

    for src_file, rel_file in vetted:
        out_file = dest_path / rel_file
        out_file.parent.mkdir(parents=True, exist_ok=True)
        # Use copy2 and follow_symlinks=False to strictly preserve non-symlink integrity
        shutil.copy2(src_file, out_file, follow_symlinks=False)
        count += 1

    return count


def create_vetted_tar_archive(target_path: Union[str, Path], tar_output_path: Union[str, Path]) -> int:
    """Creates a compressed tar.gz archive of vetted files with relative paths, without symlinks."""
    vetted = get_vetted_staging_files(target_path)
    enforce_staging_budget(vetted)
    tar_path = Path(tar_output_path)
    tar_path.parent.mkdir(parents=True, exist_ok=True)

    with tarfile.open(tar_path, "w:gz", dereference=False) as tar:
        for src_file, rel_file in vetted:
            # Add file under its relative path name, never dereferencing symlinks
            tar.add(src_file, arcname=rel_file, recursive=False)

    return len(vetted)

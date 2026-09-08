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
import shutil
import tarfile
from pathlib import Path
from typing import List, Tuple, Union

from .static_env import PROTECTED_METADATA_FILES, PROTECTED_VCS_DIRS


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
    tar_path = Path(tar_output_path)
    tar_path.parent.mkdir(parents=True, exist_ok=True)

    with tarfile.open(tar_path, "w:gz", dereference=False) as tar:
        for src_file, rel_file in vetted:
            # Add file under its relative path name, never dereferencing symlinks
            tar.add(src_file, arcname=rel_file, recursive=False)

    return len(vetted)

#!/usr/bin/env python3
"""Validates that all fenced bash commands in skill files use anchored paths.

Prevents agents operating within audited repositories from executing
unanchored repo-relative scripts like `python3 reference/scripts/advise.py`
or `./reference/run.sh`.
"""

from __future__ import annotations

import glob
import os
import re
import sys
from pathlib import Path

FENCE_START_RE = re.compile(r"^\s*```(?:bash|sh|shell)?\s*$")
FENCE_END_RE = re.compile(r"^\s*```\s*$")

# Pattern matching relative invocations of reference scripts or run.sh:
# e.g., 'python3 reference/scripts/...' or './reference/run.sh' or 'reference/scripts/...'
UNANCHORED_RE = re.compile(
    r"""(?:^|[\s"'`|;&])(?:\./)?(reference/(?:scripts/[a-zA-Z0-9_-]+\.py|run\.sh))"""
)


def check_file(path: Path) -> list[str]:
    errors = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as e:
        return [f"Failed to read {path}: {e}"]

    in_fence = False
    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if not in_fence:
            if FENCE_START_RE.match(line) and stripped != "```":
                in_fence = True
        else:
            if FENCE_END_RE.match(line):
                in_fence = False
                continue

            # Inside fenced code block
            # Skip pure comment lines
            if stripped.startswith("#"):
                continue

            # Look for unanchored references:
            for match in UNANCHORED_RE.finditer(line):
                matched_str = match.group(1)
                start_idx = match.start(1)
                prefix = line[:start_idx]
                token = prefix.split()[-1] if prefix.split() else ""
                # If anchored with MANTIS_HOME or an absolute path (/path/to/...)
                if "MANTIS_HOME" in token:
                    continue
                if token.startswith("/") or (token.startswith('"/') or token.startswith("'/")):
                    continue
                errors.append(
                    f"{path}:{line_no}: unanchored invocation '{matched_str}' in code block: {stripped}"
                )

    return errors


def main() -> int:
    if len(sys.argv) > 1:
        target_files = [Path(p) for p in sys.argv[1:]]
    else:
        repo_root = Path(__file__).resolve().parent.parent.parent
        target_files = sorted(
            [Path(p) for p in glob.glob(str(repo_root / "mantis-*/SKILL.md"))]
            + [Path(p) for p in glob.glob(str(repo_root / "reference/skills/*/SKILL.md"))]
        )

    total_errors = []
    for tf in target_files:
        if tf.is_file() and (tf.name == "SKILL.md" or tf.suffix == ".md"):
            errs = check_file(tf)
            total_errors.extend(errs)

    if total_errors:
        print("ERROR: Found unanchored script invocations in skill definitions:", file=sys.stderr)
        for err in total_errors:
            print(f"  {err}", file=sys.stderr)
        print(
            "\nAll script executions in SKILL.md bash blocks MUST be anchored via $MANTIS_HOME or absolute path.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

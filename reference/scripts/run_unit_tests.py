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

"""Parallel module-level unit test runner for the Mantis ADK reference suite.

Discovers the exact same `test*.py` modules as `python -P -m unittest discover
-s . -p "test*.py"` from `reference/`, pre-warms tree-sitter grammars once so
workers never race on first-use cache initialization, and schedules the
heaviest subprocess-intensive suites first across `--jobs N` worker processes.
"""

from __future__ import annotations

import argparse
import concurrent.futures
from dataclasses import dataclass
import fnmatch
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Sequence

_REF_ROOT = Path(__file__).resolve().parent.parent
_SKIP_DIRS = frozenset({
    ".git",
    ".venv",
    "__pycache__",
    "third_party",
    "workspace",
    ".mantis",
    ".pytest_cache",
    ".mypy_cache",
})
_RAN_RE = re.compile(r"^Ran (\d+) tests? in ([0-9.]+)s", re.M)
_SKIPPED_RE = re.compile(r"\bskipped=(\d+)\b")
_TEST_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+test_[A-Za-z0-9_]*\s*\(", re.M)


@dataclass(frozen=True)
class TestModuleSpec:
    """One discovered unittest module under `reference/`."""

    module_name: str
    start_dir: str
    file_name: str
    estimated_weight: int


@dataclass(frozen=True)
class ModuleRunResult:
    """Execution summary for one unittest module subprocess."""

    spec: TestModuleSpec
    returncode: int
    tests_run: int
    skipped: int
    elapsed_seconds: float
    output: str


def _default_jobs() -> int:
    return min(8, max(1, os.cpu_count() or 4))


def _estimate_module_weight(path: Path) -> int:
    """Heuristic LPT scheduling weight so subprocess-heavy suites start at t=0."""
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return 1
    test_defs = len(_TEST_DEF_RE.findall(source))
    subproc_hits = source.count("subprocess.run(") + source.count("subprocess.Popen(")
    sleep_hits = source.count("time.sleep(") + source.count("asyncio.sleep(")
    return max(1, test_defs + 25 * subproc_hits + 5 * sleep_hits)


def discover_test_modules(
    ref_root: Path = _REF_ROOT,
    pattern: str = "test*.py",
) -> list[TestModuleSpec]:
    """Discovers unittest modules matching `unittest discover -s . -p <pattern>`."""
    root = ref_root.resolve()
    found: list[TestModuleSpec] = []

    def _scan_package_dir(pkg_dir: Path, rel_parts: tuple[str, ...]) -> None:
        try:
            entries = sorted(pkg_dir.iterdir(), key=lambda p: p.name)
        except OSError:
            return
        for entry in entries:
            if entry.name in _SKIP_DIRS or entry.name.startswith("."):
                continue
            if entry.is_file() and entry.suffix == ".py" and entry.name != "__init__.py":
                if fnmatch.fnmatch(entry.name, pattern):
                    mod_name = ".".join((*rel_parts, entry.stem)) if rel_parts else entry.stem
                    start_dir = "/".join(rel_parts) if rel_parts else "."
                    found.append(
                        TestModuleSpec(
                            module_name=mod_name,
                            start_dir=start_dir,
                            file_name=entry.name,
                            estimated_weight=_estimate_module_weight(entry),
                        )
                    )
            elif entry.is_dir() and (entry / "__init__.py").is_file():
                _scan_package_dir(entry, (*rel_parts, entry.name))

    _scan_package_dir(root, ())
    # Longest-Processing-Time-first (LPT) ordering minimizes tail stragglers.
    found.sort(key=lambda s: (-s.estimated_weight, s.module_name))
    return found


def _warm_tree_sitter_cache(ref_root: Path) -> None:
    """Pre-loads common tree-sitter grammars once so workers do not race."""
    try:
        ref_str = str(ref_root.resolve())
        added = False
        if ref_str not in sys.path:
            sys.path.insert(0, ref_str)
            added = True
        try:
            from core.structural_index import _load_parser

            for lang in ("python", "javascript", "c", "cpp", "go", "rust", "java"):
                _load_parser(lang)
        finally:
            if added and ref_str in sys.path:
                sys.path.remove(ref_str)
    except Exception:
        pass


def _run_single_module(
    spec: TestModuleSpec,
    ref_root: Path,
    use_safe_path: bool,
) -> ModuleRunResult:
    cmd = [sys.executable]
    if use_safe_path:
        cmd.append("-P")
    cmd.extend([
        "-m",
        "unittest",
        "discover",
        "-s",
        spec.start_dir,
        "-t",
        ".",
        "-p",
        spec.file_name,
    ])
    t0 = time.monotonic()
    proc = subprocess.run(
        cmd,
        cwd=str(ref_root),
        capture_output=True,
        text=True,
    )
    elapsed = time.monotonic() - t0
    combined = (proc.stdout or "") + ("\n" if proc.stdout and proc.stderr else "") + (proc.stderr or "")
    ran_matches = _RAN_RE.findall(proc.stderr or combined)
    tests_run = int(ran_matches[-1][0]) if ran_matches else 0
    skip_matches = _SKIPPED_RE.findall(proc.stderr or combined)
    skipped = int(skip_matches[-1]) if skip_matches else 0
    rc = proc.returncode
    # Fail closed if unittest exited 0 without printing a test-count summary.
    if rc == 0 and not ran_matches:
        rc = 1
    return ModuleRunResult(
        spec=spec,
        returncode=rc,
        tests_run=tests_run,
        skipped=skipped,
        elapsed_seconds=elapsed,
        output=combined,
    )


def run_suite(
    *,
    ref_root: Path = _REF_ROOT,
    pattern: str = "test*.py",
    jobs: int | None = None,
    only_modules: Sequence[str] | None = None,
) -> int:
    specs = discover_test_modules(ref_root=ref_root, pattern=pattern)
    if only_modules:
        wanted = set(only_modules)
        specs = [s for s in specs if s.module_name in wanted or s.file_name in wanted]
    if not specs:
        print(f"ERROR: No unit test modules matched pattern {pattern!r}.", file=sys.stderr)
        return 1

    workers = min(len(specs), max(1, _default_jobs() if jobs is None else int(jobs)))
    use_safe_path = bool(getattr(sys.flags, "safe_path", 0) or os.environ.get("PYTHONSAFEPATH"))
    if workers > 1:
        _warm_tree_sitter_cache(ref_root)

    total_mods = len(specs)
    print(
        f"Running {total_mods} unit test module(s) across {workers} worker(s)...",
        flush=True,
    )
    suite_t0 = time.monotonic()
    results: list[ModuleRunResult] = []

    if workers == 1:
        for idx, spec in enumerate(specs, 1):
            res = _run_single_module(spec, ref_root, use_safe_path)
            results.append(res)
            status = "PASS" if res.returncode == 0 else "FAIL"
            print(
                f"  [{idx:2d}/{total_mods}] {status} {res.elapsed_seconds:6.2f}s  "
                f"{spec.module_name} ({res.tests_run} tests)",
                flush=True,
            )
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(_run_single_module, spec, ref_root, use_safe_path): spec
                for spec in specs
            }
            done_count = 0
            for fut in concurrent.futures.as_completed(future_map):
                done_count += 1
                res = fut.result()
                results.append(res)
                status = "PASS" if res.returncode == 0 else "FAIL"
                print(
                    f"  [{done_count:2d}/{total_mods}] {status} {res.elapsed_seconds:6.2f}s  "
                    f"{res.spec.module_name} ({res.tests_run} tests)",
                    flush=True,
                )

    wall = time.monotonic() - suite_t0
    total_tests = sum(r.tests_run for r in results)
    total_skipped = sum(r.skipped for r in results)
    failed_Mods = [r for r in results if r.returncode != 0]

    if failed_Mods:
        print("\n" + "=" * 80, file=sys.stderr)
        print(f" FAILED UNIT TEST MODULES ({len(failed_Mods)}/{total_mods})", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        for r in sorted(failed_Mods, key=lambda x: x.spec.module_name):
            print(f"\n--- {r.spec.module_name} (exit {r.returncode}, {r.elapsed_seconds:.2f}s) ---", file=sys.stderr)
            print(r.output.rstrip(), file=sys.stderr)
        print(
            f"\nFAILED: {len(failed_Mods)} module(s) failed out of {total_mods} "
            f"({total_tests} tests run, {total_skipped} skipped) in {wall:.1f}s.",
            file=sys.stderr,
            flush=True,
        )
        return 1

    if total_tests == 0:
        print("ERROR: 0 unit tests were executed.", file=sys.stderr)
        return 1

    print(
        f"\nOK: {total_mods} module(s), {total_tests} tests passed "
        f"({total_skipped} skipped) in {wall:.1f}s.",
        flush=True,
    )
    return 0


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=_default_jobs(),
        help="parallel module worker count (default: min(8, cpu_count))",
    )
    parser.add_argument(
        "-p",
        "--pattern",
        default="test*.py",
        help="test filename glob pattern (default: test*.py)",
    )
    parser.add_argument(
        "modules",
        nargs="*",
        help="optional subset of module or file names to run",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args()
    sys.exit(
        run_suite(
            pattern=args.pattern,
            jobs=args.jobs,
            only_modules=args.modules or None,
        )
    )

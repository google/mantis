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

"""Parallel sharded unit test runner for the Mantis ADK reference suite.

Discovers the exact same `test*.py` modules as `python -P -m unittest discover
-s . -p "test*.py"` from `reference/`, splits large multi-class suites into
class-disjoint shards so no single monolith bottlenecks a worker core, pre-warms
tree-sitter grammars once, and schedules Longest-Processing-Time-first (LPT).
"""

from __future__ import annotations

import argparse
import ast
import concurrent.futures
from dataclasses import dataclass
import fnmatch
import importlib
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Sequence
import unittest

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
_CLI_CALL_RE = re.compile(r"\b(?:run_main|self\.refresh)\s*\(|(?:main|launch|pr_scan|advise|configure)\.py\b")


@dataclass(frozen=True)
class TestModuleSpec:
    """One discovered unittest module (or class-disjoint shard) under `reference/`."""

    module_name: str
    start_dir: str
    file_name: str
    estimated_weight: int
    shard_index: int = 0
    num_shards: int = 1

    @property
    def display_name(self) -> str:
        if self.num_shards > 1:
            return f"{self.module_name}[{self.shard_index + 1}/{self.num_shards}]"
        return self.module_name


@dataclass(frozen=True)
class ModuleRunResult:
    """Execution summary for one unittest subprocess."""

    spec: TestModuleSpec
    returncode: int
    tests_run: int
    skipped: int
    elapsed_seconds: float
    output: str


def _default_jobs() -> int:
    return min(8, max(1, os.cpu_count() or 4))


def _analyze_test_file(path: Path) -> tuple[int, int]:
    """Returns `(estimated_weight, num_test_classes)` for LPT scheduling & sharding."""
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return 1, 1
    test_defs = len(_TEST_DEF_RE.findall(source))
    subproc_hits = source.count("subprocess.run(") + source.count("subprocess.Popen(")
    cli_hits = len(_CLI_CALL_RE.findall(source))
    sleep_hits = source.count("time.sleep(") + source.count("asyncio.sleep(")
    weight = max(1, test_defs + 25 * subproc_hits + 15 * cli_hits + 5 * sleep_hits)

    test_classes = 0
    try:
        tree = ast.parse(source)
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                if any(
                    isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("test_")
                    for item in node.body
                ):
                    test_classes += 1
    except SyntaxError:
        test_classes = 1
    return weight, max(1, test_classes)


def discover_test_modules(
    ref_root: Path = _REF_ROOT,
    pattern: str = "test*.py",
    *,
    allow_sharding: bool = False,
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
                    weight, num_classes = _analyze_test_file(entry)
                    shards = 1
                    if allow_sharding and weight >= 180 and num_classes >= 2:
                        shards = min(4, num_classes, max(2, round(weight / 180)))
                    per_shard_weight = max(1, round(weight / shards))
                    for s_idx in range(shards):
                        found.append(
                            TestModuleSpec(
                                module_name=mod_name,
                                start_dir=start_dir,
                                file_name=entry.name,
                                estimated_weight=per_shard_weight,
                                shard_index=s_idx,
                                num_shards=shards,
                            )
                        )
            elif entry.is_dir() and (entry / "__init__.py").is_file():
                _scan_package_dir(entry, (*rel_parts, entry.name))

    _scan_package_dir(root, ())
    # Longest-Processing-Time-first (LPT) ordering minimizes tail stragglers.
    found.sort(key=lambda s: (-s.estimated_weight, s.module_name, s.shard_index))
    return found


def shard_test_classes_for_module(mod: object, shard_index: int, num_shards: int) -> list[type[unittest.TestCase]]:
    """Partitions non-empty `TestCase` classes in `mod` into `num_shards` disjoint slices."""
    loader = unittest.defaultTestLoader
    base_skip = {unittest.TestCase, getattr(unittest, "IsolatedAsyncioTestCase", unittest.TestCase)}
    all_classes: list[type[unittest.TestCase]] = []
    for attr_name in sorted(dir(mod)):
        obj = getattr(mod, attr_name, None)
        if isinstance(obj, type) and issubclass(obj, unittest.TestCase) and obj not in base_skip:
            if loader.loadTestsFromTestCase(obj).countTestCases() > 0:
                all_classes.append(obj)
    return all_classes[shard_index::num_shards]


def _run_worker_shard_main(ref_root: Path, module_name: str, shard_index: int, num_shards: int) -> int:
    ref_str = str(ref_root.resolve())
    if ref_str not in sys.path:
        sys.path.insert(0, ref_str)
    mod = importlib.import_module(module_name)
    classes = shard_test_classes_for_module(mod, shard_index, num_shards)
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite(loader.loadTestsFromTestCase(cls) for cls in classes)
    if suite.countTestCases() == 0:
        # Empty slice (e.g. if AST overcounted classes): print valid 0-test summary cleanly.
        print("Ran 0 tests in 0.000s\n\nOK", file=sys.stderr, flush=True)
        return 0
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


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


def _run_single_spec(
    spec: TestModuleSpec,
    ref_root: Path,
    use_safe_path: bool,
) -> ModuleRunResult:
    cmd = [sys.executable]
    if use_safe_path:
        cmd.append("-P")
    if spec.num_shards > 1:
        cmd.extend([
            str(Path(__file__).resolve()),
            "--worker-shard",
            spec.module_name,
            str(spec.shard_index),
            str(spec.num_shards),
            "--ref-root",
            str(ref_root.resolve()),
        ])
    else:
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
    shard_large_modules: bool = True,
) -> int:
    requested_jobs = max(1, _default_jobs() if jobs is None else int(jobs))
    specs = discover_test_modules(
        ref_root=ref_root,
        pattern=pattern,
        allow_sharding=bool(shard_large_modules and requested_jobs > 1),
    )
    if only_modules:
        wanted = set(only_modules)
        specs = [s for s in specs if s.module_name in wanted or s.file_name in wanted]
    if not specs:
        print(f"ERROR: No unit test modules matched pattern {pattern!r}.", file=sys.stderr)
        return 1

    workers = min(len(specs), requested_jobs)
    use_safe_path = bool(getattr(sys.flags, "safe_path", 0) or os.environ.get("PYTHONSAFEPATH"))
    if workers > 1:
        _warm_tree_sitter_cache(ref_root)

    total_units = len(specs)
    distinct_mods = len({s.module_name for s in specs})
    print(
        f"Running {distinct_mods} unit test module(s) ({total_units} work unit(s)) across {workers} worker(s)...",
        flush=True,
    )
    suite_t0 = time.monotonic()
    results: list[ModuleRunResult] = []

    if workers == 1:
        for idx, spec in enumerate(specs, 1):
            res = _run_single_spec(spec, ref_root, use_safe_path)
            results.append(res)
            status = "PASS" if res.returncode == 0 else "FAIL"
            print(
                f"  [{idx:2d}/{total_units}] {status} {res.elapsed_seconds:6.2f}s  "
                f"{spec.display_name} ({res.tests_run} tests)",
                flush=True,
            )
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(_run_single_spec, spec, ref_root, use_safe_path): spec
                for spec in specs
            }
            done_count = 0
            for fut in concurrent.futures.as_completed(future_map):
                done_count += 1
                res = fut.result()
                results.append(res)
                status = "PASS" if res.returncode == 0 else "FAIL"
                print(
                    f"  [{done_count:2d}/{total_units}] {status} {res.elapsed_seconds:6.2f}s  "
                    f"{res.spec.display_name} ({res.tests_run} tests)",
                    flush=True,
                )

    wall = time.monotonic() - suite_t0
    total_tests = sum(r.tests_run for r in results)
    total_skipped = sum(r.skipped for r in results)
    failed_units = [r for r in results if r.returncode != 0]

    if failed_units:
        print("\n" + "=" * 80, file=sys.stderr)
        print(f" FAILED UNIT TEST SHARDS ({len(failed_units)}/{total_units})", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        for r in sorted(failed_units, key=lambda x: (x.spec.module_name, x.spec.shard_index)):
            print(f"\n--- {r.spec.display_name} (exit {r.returncode}, {r.elapsed_seconds:.2f}s) ---", file=sys.stderr)
            print(r.output.rstrip(), file=sys.stderr)
        print(
            f"\nFAILED: {len(failed_units)} shard(s) failed out of {total_units} "
            f"({total_tests} tests run, {total_skipped} skipped) in {wall:.1f}s.",
            file=sys.stderr,
            flush=True,
        )
        return 1

    if total_tests == 0:
        print("ERROR: 0 unit tests were executed.", file=sys.stderr)
        return 1

    print(
        f"\nOK: {distinct_mods} module(s), {total_tests} tests passed "
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
        help="parallel worker count (default: min(8, cpu_count))",
    )
    parser.add_argument(
        "-p",
        "--pattern",
        default="test*.py",
        help="test filename glob pattern (default: test*.py)",
    )
    parser.add_argument(
        "--no-shard-classes",
        action="store_true",
        help="disable splitting heavy test modules into class-disjoint shards",
    )
    parser.add_argument(
        "--worker-shard",
        nargs=3,
        metavar=("MODULE", "SHARD_IDX", "NUM_SHARDS"),
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--ref-root",
        default=str(_REF_ROOT),
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "modules",
        nargs="*",
        help="optional subset of module or file names to run",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args()
    if args.worker_shard:
        mod_arg, idx_arg, total_arg = args.worker_shard
        sys.exit(_run_worker_shard_main(Path(args.ref_root), mod_arg, int(idx_arg), int(total_arg)))
    sys.exit(
        run_suite(
            ref_root=Path(args.ref_root),
            pattern=args.pattern,
            jobs=args.jobs,
            only_modules=args.modules or None,
            shard_large_modules=not args.no_shard_classes,
        )
    )

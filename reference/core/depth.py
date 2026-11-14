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

"""Continuous `--depth N` (1..100) profile resolution and risk-ranked batching.

Maps a single operator-facing depth knob (`1` = quick shallow triage, `30` =
balanced full-stack + RTL review, `100` = exhaustive full-coverage deep audit)
onto every lever that governs vulnerability recall:

1. Coverage & batch granularity (risk-ranked subsystem-coherent file batches so
   each campaign keeps sharp attention while reusing the cached prefix stem).
2. Reasoning effort (`low` -> `medium` -> `high` -> `max`, clamped per model).
3. Multi-pass orthogonal audit lenses (`1` pass through depth 74; `2` passes at
   75..100, and `3` passes on very small targets at 95..100).
4. Deterministic checklist caps & explorer read discipline.
5. Hunting-stage vulnerability-class & severity aperture (injected into hunting
   stages only -- never reviewer/critic -- to preserve INV-2 independence).

Explicit CLI overrides (`--scan-mode`, `--passes`, `--reasoning-effort`,
`--token-budget`, `--max-time`, etc.) always take precedence over `--depth`.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import math
import os
from pathlib import Path
from typing import Any, Optional, Sequence

MIN_DEPTH = 1
MAX_DEPTH = 100
DEFAULT_DEPTH = 30

# Extensions representing active executable code or hardware RTL (Priority 0).
_ACTIVE_CODE_AND_RTL_EXTS = frozenset({
    # Systems / compiled / memory-unsafe / GPU / firmware
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".m", ".mm", ".s", ".asm",
    ".cu", ".cuh", ".wgsl", ".hlsl", ".glsl", ".dts", ".dtsi", ".ld", ".lds",
    # Memory-safe compiled, mobile, smart contracts & ZK
    ".rs", ".go", ".java", ".kt", ".kts", ".swift", ".cs", ".scala", ".sc", ".ml", ".hs",
    ".erl", ".ex", ".exs", ".zig", ".dart", ".sol", ".vy", ".cairo", ".move", ".circom",
    ".nim", ".cr", ".ada", ".adb", ".ads", ".f90", ".f95", ".cob", ".cbl",
    ".groovy", ".clj", ".cljs", ".fs", ".fsx", ".vb",
    # Interpreted, scripting, web backend & frontend code
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
    ".rb", ".php", ".pl", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".psd1",
    ".lua", ".vue", ".svelte", ".r", ".jl", ".tcl", ".awk", ".bzl",
    # Hardware / RTL (Verilog, SystemVerilog, VHDL)
    ".v", ".vh", ".sv", ".svh", ".vhd", ".vhdl",
})

# Templates, views, IaC, policies, mobile manifests, schemas, and configs (Priority 1).
_TEMPLATE_CONFIG_ASSET_EXTS = frozenset({
    ".html", ".htm", ".pug", ".jade", ".ejs", ".hbs", ".handlebars",
    ".jinja", ".jinja2", ".j2", ".twig", ".erb", ".jsp", ".aspx", ".cshtml",
    ".ftl", ".vm", ".liquid", ".slim", ".haml", ".mustache", ".njk", ".razor",
    ".tf", ".tfvars", ".hcl", ".bicep", ".rego", ".cedar", ".nix", ".cue", ".jsonnet",
    ".yml", ".yaml", ".xml", ".toml", ".conf", ".cfg", ".ini", ".properties",
    ".plist", ".xcconfig", ".entitlements", ".gradle", ".cmake", ".mk", ".dockerfile",
    ".json", ".sql", ".graphql", ".gql", ".proto", ".mojom", ".idl", ".thrift",
    ".capnp", ".fbs", ".avsc", ".aidl", ".wit", ".yang",
    ".key", ".pem", ".pub", ".asc", ".bak", ".old", ".orig", ".env",
})

# Pure styling / locale / non-security prose / binary media & archives excluded from
# primary risk batches (blocklist-default: unknown text/DSL extensions stay eligible
# as Priority 1 so novel languages and domain configs are never silently dropped).
_LOW_SECURITY_NOISE_EXTS = frozenset({
    ".css", ".scss", ".sass", ".less", ".styl",
    ".md", ".rst", ".txt", ".adoc",
    ".lock", ".sum", ".map", ".snap", ".csv", ".tsv", ".log",
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
    ".avif", ".bmp", ".tif", ".tiff",
    ".mp3", ".mp4", ".wav", ".webm",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf",
    ".stl", ".obj", ".vtt", ".srt", ".sha512", ".sha256", ".md5", ".url",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".whl",
    ".pyc", ".o", ".a", ".so", ".dylib", ".dll", ".exe", ".bin", ".wasm",
    ".db", ".sqlite", ".sqlite3", ".pb", ".onnx", ".pt", ".pth", ".safetensors",
})

_LOW_SECURITY_NOISE_DIRS = frozenset({
    "i18n", "locale", "locales", "translations", "l10n",
    ".git", ".github", ".claude", ".cursor", ".junie", ".ai", ".vscode", ".idea",
})

_SECURITY_BASENAMES = frozenset({
    "dockerfile", "containerfile", "docker-compose.yml", "docker-compose.yaml",
    "package.json", "requirements.txt", "pyproject.toml", "go.mod",
    "cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts",
    "gemfile", "composer.json", "makefile", "cmakelists.txt",
    "build.bazel", "workspace.bazel", "jenkinsfile", "procfile", "vagrantfile",
    "kustomization.yaml", "chart.yaml", "values.yaml",
    "androidmanifest.xml", "info.plist", "entitlements.plist",
    "network_security_config.xml",
    "nginx.conf", "httpd.conf", "web.config", "htaccess", ".htaccess",
})

_MAX_FILE_RISK_SCAN_BYTES = 32 * 1024


@dataclass(frozen=True)
class DepthProfile:
    """Resolved deterministic scan parameters for a `--depth N` (1..100) value."""

    depth: int
    tier: str
    reasoning_effort: str
    passes: int
    small_target_passes: int
    coverage_fraction: float
    include_tier2_tests: bool
    whole_file_limit: int
    target_batch_files: int
    max_batches: int
    checklist_max_sinks: int
    checklist_max_entrypoints: int
    checklist_max_chars: int
    checklist_max_fallback_files: int
    checklist_max_sinks_per_file: int
    explorer_max_turns: int
    explorer_read_all_batch: bool
    severity_aperture: str


def parse_depth(raw: Any) -> int:
    """Validates and parses `--depth` into an integer in `[1, 100]`."""
    if isinstance(raw, bool):
        raise ValueError(f"depth must be an integer between {MIN_DEPTH} and {MAX_DEPTH} (got {raw!r})")
    try:
        if isinstance(raw, str):
            cleaned = raw.strip()
            if not cleaned:
                raise ValueError("empty depth")
            val = int(cleaned)
        elif isinstance(raw, int):
            val = raw
        else:
            raise ValueError(f"unsupported type {type(raw).__name__}")
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"depth must be an integer between {MIN_DEPTH} and {MAX_DEPTH} (got {raw!r})"
        ) from exc
    if val < MIN_DEPTH or val > MAX_DEPTH:
        raise ValueError(
            f"depth must be between {MIN_DEPTH} and {MAX_DEPTH} (got {val})"
        )
    return val


def _lerp_int(d: int, d0: int, d1: int, v0: int, v1: int) -> int:
    if d <= d0:
        return v0
    if d >= d1:
        return v1
    t = (d - d0) / float(d1 - d0)
    return int(round(v0 + t * (v1 - v0)))


def _lerp_float(d: int, d0: int, d1: int, v0: float, v1: float) -> float:
    if d <= d0:
        return v0
    if d >= d1:
        return v1
    t = (d - d0) / float(d1 - d0)
    return round(v0 + t * (v1 - v0), 4)


def resolve_depth_profile(depth: int = DEFAULT_DEPTH) -> DepthProfile:
    """Maps `depth` (`1..100`) monotonically onto a `DepthProfile`."""
    d = parse_depth(depth)

    if d <= 15:
        tier = "quick"
        reasoning_effort = "low"
        severity_aperture = "critical_high"
    elif d <= 45:
        tier = "standard"
        reasoning_effort = "low" if d <= 20 else "medium"
        severity_aperture = "standard_fullstack"
    elif d <= 74:
        tier = "thorough"
        reasoning_effort = "high"
        severity_aperture = "thorough_all_classes"
    elif d <= 89:
        tier = "deep"
        reasoning_effort = "high"
        severity_aperture = "exhaustive_all"
    else:
        tier = "exhaustive"
        reasoning_effort = "max"
        severity_aperture = "exhaustive_all"

    passes = 2 if d >= 75 else 1
    small_target_passes = 3 if d >= 95 else passes

    # Coverage fraction of active Tier-1 security-relevant files:
    # 1 -> 0.15, 30 -> 0.45, 60 -> 0.80, 80..100 -> 1.00.
    if d <= 30:
        coverage_fraction = _lerp_float(d, 1, 30, 0.15, 0.45)
    elif d <= 60:
        coverage_fraction = _lerp_float(d, 30, 60, 0.45, 0.80)
    elif d <= 80:
        coverage_fraction = _lerp_float(d, 60, 80, 0.80, 1.00)
    else:
        coverage_fraction = 1.0

    # Single-campaign whole-target ceiling (countable active files):
    # - Depth 1..10 stays a fast 1-campaign triage scan on typical repos.
    # - Depth 30 keeps small repos (<=30 active files) in 1 whole campaign while
    #   splitting medium/large repos into focused risk-ranked batches.
    # - Depth 80..100 shrinks whole_file_limit down to micro-batch size so even
    #   modest repos get undiluted per-batch attention.
    if d <= 10:
        whole_file_limit = 1000
        target_batch_files = 40
        max_batches = 1
    elif d <= 20:
        whole_file_limit = 60
        target_batch_files = _lerp_int(d, 11, 20, 32, 26)
        max_batches = _lerp_int(d, 11, 20, 2, 5)
    elif d <= 40:
        whole_file_limit = _lerp_int(d, 21, 40, 35, 22)
        target_batch_files = _lerp_int(d, 21, 40, 26, 18)
        max_batches = _lerp_int(d, 21, 40, 5, 16)
    elif d <= 70:
        whole_file_limit = _lerp_int(d, 41, 70, 20, 12)
        target_batch_files = _lerp_int(d, 41, 70, 18, 12)
        max_batches = _lerp_int(d, 41, 70, 17, 55)
    elif d <= 85:
        whole_file_limit = _lerp_int(d, 71, 85, 12, 9)
        target_batch_files = _lerp_int(d, 71, 85, 12, 9)
        max_batches = _lerp_int(d, 71, 85, 56, 90)
    else:
        whole_file_limit = _lerp_int(d, 86, 100, 9, 8)
        target_batch_files = _lerp_int(d, 86, 100, 9, 8)
        # Depth 86..100 removes the batch count cap across active Tier-1 files;
        # operator budget guardrails (--token-budget / --max-time) still bound spend.
        max_batches = 0

    # Checklist capacity scales smoothly and monotonically with depth.
    if d <= 30:
        cl_sinks = _lerp_int(d, 1, 30, 15, 45)
        cl_eps = _lerp_int(d, 1, 30, 10, 25)
        cl_chars = _lerp_int(d, 1, 30, 2000, 5000)
        cl_fb = _lerp_int(d, 1, 30, 25, 65)
        cl_per_file = _lerp_int(d, 1, 30, 3, 5)
    elif d <= 70:
        cl_sinks = _lerp_int(d, 30, 70, 45, 110)
        cl_eps = _lerp_int(d, 30, 70, 25, 60)
        cl_chars = _lerp_int(d, 30, 70, 5000, 11000)
        cl_fb = _lerp_int(d, 30, 70, 65, 220)
        cl_per_file = _lerp_int(d, 30, 70, 5, 10)
    else:
        cl_sinks = _lerp_int(d, 70, 100, 110, 200)
        cl_eps = _lerp_int(d, 70, 100, 60, 100)
        cl_chars = _lerp_int(d, 70, 100, 11000, 20000)
        cl_fb = _lerp_int(d, 70, 100, 220, 500)
        cl_per_file = _lerp_int(d, 70, 100, 10, 15)

    explorer_max_turns = _lerp_int(d, 1, 100, 3, 12)
    explorer_read_all_batch = d >= 40
    include_tier2_tests = d >= 95

    return DepthProfile(
        depth=d,
        tier=tier,
        reasoning_effort=reasoning_effort,
        passes=passes,
        small_target_passes=small_target_passes,
        coverage_fraction=coverage_fraction,
        include_tier2_tests=include_tier2_tests,
        whole_file_limit=whole_file_limit,
        target_batch_files=target_batch_files,
        max_batches=max_batches,
        checklist_max_sinks=cl_sinks,
        checklist_max_entrypoints=cl_eps,
        checklist_max_chars=cl_chars,
        checklist_max_fallback_files=cl_fb,
        checklist_max_sinks_per_file=cl_per_file,
        explorer_max_turns=explorer_max_turns,
        explorer_read_all_batch=explorer_read_all_batch,
        severity_aperture=severity_aperture,
    )


def _file_security_priority(rel_path: str) -> Optional[int]:
    """Classifies `rel_path` into priority `0` (active code/RTL), `1` (templates/IaC/configs
    or unknown text DSLs via blocklist-default), or `None` (styling/locale/doc/lock/binary
    noise skipped from primary risk batches)."""
    norm = str(rel_path or "").replace("\\", "/").strip("/")
    if not norm:
        return None
    parts = [p.lower() for p in norm.split("/") if p]
    name = parts[-1]
    dir_parts = parts[:-1]

    if name in (
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
        "cargo.lock", "gemfile.lock", "composer.lock", "go.sum",
        "license", "notice", "changelog", "readme", "authors", "contributors",
        "copying", "patents",
        ".editorconfig", ".gitignore", ".gitattributes", ".prettierrc",
        ".eslintrc", ".stylelintrc", ".browserslistrc", ".npmrc",
    ):
        return None
    if name.endswith((".min.js", ".min.css", ".d.ts.map")):
        return None
    if any(
        tok in name
        for tok in (
            "eslint", "stylelint", "prettier", "vitest",
            "jest.config", "karma.conf", "tsconfig", "babel.config",
            "browserslist",
        )
    ):
        return None

    _, ext = os.path.splitext(name)
    if ext in _LOW_SECURITY_NOISE_EXTS:
        return None
    if any(d in _LOW_SECURITY_NOISE_DIRS for d in dir_parts):
        # Keep GitHub Actions workflows (.github/workflows/*.yml) as Priority 1 configs
        if not (len(parts) >= 3 and parts[0] == ".github" and parts[1] == "workflows"):
            return None
    if name in _SECURITY_BASENAMES:
        return 1
    if ext in _ACTIVE_CODE_AND_RTL_EXTS:
        return 0
    if ext in _TEMPLATE_CONFIG_ASSET_EXTS:
        return 1
    # Blocklist-default: any non-noise file in an unknown language, DSL, or config
    # format stays eligible as Priority 1 rather than being silently dropped.
    return 1


def _score_file_surface(abs_path: str, surface_patterns: Sequence[tuple]) -> float:
    """Fast bounded lexical surface score for a single file (never raises)."""
    try:
        with open(abs_path, "rb") as fh:
            blob = fh.read(_MAX_FILE_RISK_SCAN_BYTES)
    except OSError:
        return 0.0
    text = blob.decode("utf-8", errors="ignore")
    score = 0.0
    for pattern, weight, _tag in surface_patterns:
        if pattern.search(text):
            score += float(weight)
    return score


def _subsystem_key(rel_path: str) -> str:
    """Coherent subsystem bucket key (up to 2 directory levels, '.' for root files)."""
    parts = [p for p in str(rel_path or "").replace("\\", "/").strip("/").split("/") if p]
    if len(parts) <= 1:
        return "."
    return "/".join(parts[: min(2, len(parts) - 1)])


def count_active_security_files(
    target_root: Path,
    discovered_files: Sequence[str],
    *,
    include_tier2: bool = False,
) -> int:
    """Counts active security-relevant first-party files under `target_root`."""
    from core.structural_index import _source_file_tier

    root_real = os.path.realpath(str(target_root)).rstrip("/")
    count = 0
    for fp in discovered_files:
        try:
            rel = os.path.relpath(os.path.realpath(str(fp)), root_real).replace(os.sep, "/")
        except ValueError:
            continue
        if rel.startswith(".."):
            continue
        tier = _source_file_tier(rel)
        if tier >= 3 or (tier == 2 and not include_tier2):
            continue
        if _file_security_priority(rel) is not None:
            count += 1
    return count


def plan_depth_batches(
    target_root: Path,
    discovered_files: Sequence[str],
    profile: DepthProfile,
    astm: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """Builds deterministic, risk-ranked, subsystem-coherent file batches.

    Returns a list of Mantis campaign group dicts:
    `[{"targets": [abs_file_1, ...], "hypothesis": None, "chain": None}, ...]`.

    Guarantees:
    - Every emitted path comes directly from `discovered_files` (no widening).
    - Full-stack + RTL coverage: active code/RTL and templates/configs across
      distinct high-risk subsystems are represented before deep tails of a
      single bulky directory monopolize the batch budget.
    - At `coverage_fraction == 1.0` and `max_batches == 0` (depth 86..100),
      every active Tier-1 security-relevant file is placed in exactly one batch.
    """
    from core.structural_index import _source_file_tier
    from core.surveyor import _SURFACE_PATTERNS

    root_real = os.path.realpath(str(target_root)).rstrip("/")
    if not discovered_files:
        return []

    # Map Surveyor slice prefixes -> (priority_rank, risk_score) when ASTM is available.
    slice_scores: list[tuple[str, float]] = []
    for sl in (astm or {}).get("slices") or []:
        rscore = float(sl.get("risk_score") or 0.0)
        for rp in sl.get("root_paths") or ():
            rp_clean = str(rp or "").replace("\\", "/").strip("/")
            if rp_clean and rp_clean != ".":
                slice_scores.append((rp_clean, rscore))

    def _slice_bonus(rel: str) -> float:
        best = 0.0
        best_len = -1
        for prefix, rscore in slice_scores:
            if rel == prefix or rel.startswith(prefix + "/"):
                if len(prefix) > best_len:
                    best_len = len(prefix)
                    best = rscore
        return best

    # Collect Tier-1 (and optionally bounded Tier-2) security-relevant files.
    tier1_entries: list[dict[str, Any]] = []
    tier2_entries: list[dict[str, Any]] = []
    fallback_entries: list[dict[str, Any]] = []

    for fp in discovered_files:
        fp_str = str(fp)
        try:
            rel = os.path.relpath(os.path.realpath(fp_str), root_real).replace(os.sep, "/")
        except ValueError:
            continue
        if rel.startswith(".."):
            continue
        tier = _source_file_tier(rel)
        prio = _file_security_priority(rel)
        entry = {
            "abs": fp_str,
            "rel": rel,
            "tier": tier,
            "prio": prio if prio is not None else 2,
            "subsys": _subsystem_key(rel),
        }
        if tier == 1 and prio is not None:
            tier1_entries.append(entry)
        elif tier == 2 and prio is not None:
            tier2_entries.append(entry)
        elif tier <= 2:
            fallback_entries.append(entry)

    candidates = list(tier1_entries)
    if profile.include_tier2_tests and len(tier2_entries) <= 200:
        candidates.extend(tier2_entries)
    if not candidates:
        candidates = tier2_entries or fallback_entries
    if not candidates:
        return []

    # Score every candidate file deterministically.
    # For very large repositories (>5,000 candidates), bound lexical reads by
    # prioritizing Surveyor-ranked slices + Priority-0 code/RTL first.
    lexical_cap = 5000
    candidates.sort(key=lambda e: (-_slice_bonus(e["rel"]), e["tier"], e["prio"], e["rel"]))
    for idx, entry in enumerate(candidates):
        s_bonus = _slice_bonus(entry["rel"])
        surf = _score_file_surface(entry["abs"], _SURFACE_PATTERNS) if idx < lexical_cap else 0.0
        # Active code/RTL gets a mild tiebreak boost over plain configs, while
        # configs/templates with strong surface hits (e.g. XSS templates, IaC
        # wildcards, exposed keys) still rank high.
        prio_boost = 1.5 if entry["prio"] == 0 else 0.5
        tier_mult = 1.0 if entry["tier"] == 1 else 0.35
        entry["score"] = round((surf + 1.5 * s_bonus + prio_boost) * tier_mult, 4)

    # Group into subsystem buckets, sorting files inside each bucket highest-risk first.
    by_subsys: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in candidates:
        by_subsys[entry["subsys"]].append(entry)
    for bucket in by_subsys.values():
        bucket.sort(key=lambda e: (-e["score"], e["prio"], e["rel"]))

    # Rank subsystems by mean of top-K file risk + log size (prevents a 400-file
    # low-risk directory from drowning out a 10-file high-risk auth/RTL/config dir).
    def _subsys_rank(subsys_name: str) -> tuple[float, str]:
        items = by_subsys[subsys_name]
        top_k = items[: min(8, len(items))]
        top_mean = sum(e["score"] for e in top_k) / max(1, len(top_k))
        size_factor = 1.0 + 0.12 * math.log1p(len(items))
        return (round(top_mean * size_factor, 4), subsys_name)

    ranked_subsystems = sorted(by_subsys.keys(), key=lambda s: (-_subsys_rank(s)[0], s))

    # Split each subsystem into risk-ordered chunks of `batch_size`.
    # On modest multi-subsystem repos (e.g. 30-100 active files), scale batch size
    # down gracefully (`max(6, len(candidates) // 5)`) so a single bulky directory
    # doesn't consume the entire coverage budget before sibling full-stack/RTL
    # subsystems are represented. Large repos (>=120 files) use `target_batch_files`.
    batch_size = max(
        1,
        min(int(profile.target_batch_files), max(6, len(candidates) // 5)),
    )
    subsys_batches: dict[str, list[list[dict[str, Any]]]] = {}
    for subsys_name in ranked_subsystems:
        items = by_subsys[subsys_name]
        chunks: list[list[dict[str, Any]]] = []
        for i in range(0, len(items), batch_size):
            chunks.append(items[i : i + batch_size])
        subsys_batches[subsys_name] = chunks

    # Coalesce tiny singleton/2-file sibling subsystems (e.g. views/ + config/ +
    # encryptionkeys/) into coherent small batches only when they are below
    # half batch_size, so depth 30 doesn't burn an entire campaign on a 2-file
    # folder while still auditing those files!
    min_standalone = max(3, batch_size // 2)
    standalone_queues: list[tuple[str, list[list[dict[str, Any]]]]] = []
    small_tail: list[dict[str, Any]] = []
    for subsys_name in ranked_subsystems:
        chunks = subsys_batches[subsys_name]
        if len(chunks) == 1 and len(chunks[0]) < min_standalone:
            small_tail.extend(chunks[0])
        else:
            standalone_queues.append((subsys_name, chunks))

    if small_tail:
        small_tail.sort(key=lambda e: (-e["score"], e["subsys"], e["rel"]))
        tail_chunks = [
            small_tail[i : i + batch_size]
            for i in range(0, len(small_tail), batch_size)
        ]
        standalone_queues.append(("__coalesced_misc__", tail_chunks))

    # Order batches using blended top-5/mean chunk risk with wave diversity decay
    # (`0.60 ** wave`):
    # - Wave 0 of every genuinely risky subsystem (backend, frontend, RTL, root
    #   entrypoints, libs) gets full weight (1.0x), guaranteeing full-stack + RTL
    #   breadth even at default depth 30.
    # - Wave 1 of high-risk subsystems (0.60x) still outranks low-risk config/data
    #   directories instead of starving real handlers behind low-signal folders.
    ranked_batches: list[tuple[float, int, str, list[dict[str, Any]]]] = []
    for sname, chunks in standalone_queues:
        for wave, chunk in enumerate(chunks):
            top5 = chunk[: min(5, len(chunk))]
            mean_all = sum(e["score"] for e in chunk) / max(1, len(chunk))
            mean_top = sum(e["score"] for e in top5) / max(1, len(top5))
            blended = 0.5 * mean_all + 0.5 * mean_top
            eff_score = round(blended * (0.60 ** wave), 4)
            ranked_batches.append((eff_score, wave, sname, chunk))
    ranked_batches.sort(key=lambda t: (-t[0], t[1], t[2]))
    ordered_batches = [chunk for _score, _wave, _sname, chunk in ranked_batches]

    # Apply coverage_fraction and max_batches caps.
    target_file_budget = (
        len(candidates)
        if profile.coverage_fraction >= 0.999
        else max(batch_size, int(math.ceil(len(candidates) * profile.coverage_fraction)))
    )
    selected_batches: list[list[dict[str, Any]]] = []
    covered_files = 0
    for chunk in ordered_batches:
        if profile.max_batches > 0 and len(selected_batches) >= profile.max_batches:
            break
        if selected_batches and covered_files >= target_file_budget:
            break
        selected_batches.append(chunk)
        covered_files += len(chunk)

    return [
        {
            "targets": [e["abs"] for e in chunk],
            "hypothesis": None,
            "chain": None,
        }
        for chunk in selected_batches
        if chunk
    ]


def render_depth_hunting_directive(
    profile: DepthProfile,
    *,
    pass_index: int = 1,
    total_passes: int = 1,
    batch_file_count: int = 0,
) -> str:
    """Operator-authored hunting-stage directive calibrated to `profile`.

    Delivered ONLY to hunting stages (`planner`, `explorer`, `researcher`),
    never to `reviewer` or `critic` (INV-2 verification independence).
    """
    lines: list[str] = [
        f"Audit Depth Profile: {profile.depth}/100 ({profile.tier})."
    ]

    if profile.explorer_read_all_batch and batch_file_count > 0:
        lines.append(
            f"- EXPLORER COVERAGE: Read EVERY assigned file in this batch ({batch_file_count} file(s)) "
            f"in parallel (~5 read_file calls/turn, up to {profile.explorer_max_turns} tool turns) "
            "plus any directly referenced auth/sanitizer/helper/RTL-submodule definitions before concluding."
        )
    else:
        lines.append(
            f"- EXPLORER BUDGET: Batch parallel read_file calls (~5/turn, up to {profile.explorer_max_turns} "
            "tool turns) across high-risk entrypoints, handlers, frontend templates/components, configs, and RTL modules."
        )

    if profile.severity_aperture == "critical_high":
        lines.append(
            "- SCOPE & APERTURE (Cross-Domain, Critical/High focus): Prioritize high-impact, "
            "directly exploitable vulnerabilities across whatever domains appear in the assigned files "
            "(web/API/frontend, systems/firmware/eBPF, hardware/RTL, mobile, cloud/K8s/CI-CD/IAM, "
            "smart contracts/ZK, AI/ML/agentic pipelines, desktop/Electron, shell/SQL): RCE, "
            "command/code/SQL/NoSQL/template/workflow injection, memory corruption/FFI UB, auth/authz/IAM "
            "bypass, SSRF, path traversal, unsafe model/object deserialization, high-impact DOM/WebView XSS, "
            "reentrancy/access-control/accounting bugs, and RTL CSR/lock/privilege/JTAG bypass."
        )
    elif profile.severity_aperture == "standard_fullstack":
        lines.append(
            "- SCOPE & APERTURE (Cross-Domain, Critical/High/Medium): Audit EVERY domain represented "
            "in the assigned files: backend/API services, frontend/DOM/templates, systems/firmware/FFI, "
            "hardware/RTL, mobile apps/manifests, cloud/IaC/K8s/CI-CD/policy-as-code, smart contracts/ZK, "
            "AI/ML/agentic code, desktop/Electron/extensions, and shell/SQL scripts. Hunt injection "
            "(SQL/NoSQL/command/SSTI/XXE/CI-workflow/prompt-tool), XSS/WebView/IPC bridges, broken "
            "auth/authz/IDOR/IAM/policy gaps, memory safety & Rust/Zig unsafe FFI, path traversal, SSRF, "
            "unsafe deserialization/model loading, weak crypto/secrets, smart-contract reentrancy/oracle/"
            "delegatecall/tx.origin flaws, and RTL CSR/regwen/JTAG/lifecycle/zeroization/bus isolation bugs."
        )
    elif profile.severity_aperture == "thorough_all_classes":
        lines.append(
            "- SCOPE & APERTURE (Cross-Domain, Thorough): Inspect EVERY assigned file thoroughly across "
            "all applicable security invariants: injection (SQL/NoSQL/command/code/SSTI/XXE/CI/prompt-tool), "
            "XSS/DOM/WebView/Electron IPC, SSRF, path traversal, deserialization & ML weight loading, broken "
            "auth/authz/IDOR/IAM/policy/mobile exported components, memory safety/firmware/DMA/eBPF/FFI, "
            "smart-contract state/reentrancy/access/math/ZK-constraint flaws, business logic & race/TOCTOU, "
            "cryptographic misuse, sensitive data exposure, IaC/K8s/container/CI supply-chain misconfigs, "
            "and comprehensive RTL hardware security (CSR/PMP/MPU/bus access control, debug/DFT/lifecycle "
            "locks, reset/zeroization of secrets, FSM illegal states, synthesis/latch hazards)."
        )
    else:
        lines.append(
            "- SCOPE & APERTURE (Exhaustive Cross-Domain, ALL Severities Critical through Low): "
            "Audit EVERY line and branch of every assigned file across all software, infra, and hardware domains. "
            "Report ALL real security-relevant flaws including subtle and medium/low-severity issues: every "
            "injection variant (SQL/NoSQL/command/code/SSTI/XXE/ReDoS/CI-expression/prompt-tool), all "
            "XSS/DOM/template/WebView/Electron-preload sinks, broken auth/session/JWT/OAuth/2FA/password-reset, "
            "IDOR/BOLA/mass-assignment/client-side-only/IAM/Rego/Cedar policy bypasses, mobile exported "
            "components/deep-links/ATS/cleartext/Keychain flaws, smart-contract reentrancy/delegatecall/tx.origin/"
            "signature-replay/oracle/precision/ZK-underconstrained bugs, AI/ML unsafe pickle/torch.load/trust_remote_code/"
            "agent-sandbox escapes, memory/FFI/firmware/DMA/eBPF bounds & lifetimes, business logic & race/rate-limit "
            "gaps, weak crypto/PRNG/hardcoded keys, sensitive data exposure/backup files/error & observability leaks, "
            "CORS/CSP/header/IaC/K8s/CI supply-chain misconfigs, unvalidated redirects, known-vulnerable dependency "
            "pins, and exhaustive RTL hardware security (CSR/lock/privilege bypass, JTAG/debug/DFT/lifecycle escapes, "
            "secret zeroization/reset leaks, bus/DMA isolation, FSM illegal states, timing/side-channel leaks)."
        )

    if total_passes >= 2:
        if pass_index == 1:
            lines.append(
                f"- PASS {pass_index}/{total_passes} LENS (Primary Attack Surface): Focus first on "
                "untrusted input-to-sink dataflows, injection (code/command/SQL/CI/prompt-tool), "
                "authentication/authorization/IAM/privilege checks, deserialization/XXE/SSRF/traversal, "
                "memory/FFI safety, smart-contract value/access-control bugs, and RTL privilege/CSR/debug locks."
            )
        elif pass_index == 2:
            lines.append(
                f"- PASS {pass_index}/{total_passes} ORTHOGONAL LENS (Subtle & Secondary Classes): "
                "Assume obvious injection/auth bugs are handled elsewhere and hunt the classes typically "
                "missed on a first pass: business logic & state-machine flaws, IDOR/object-level authz, "
                "client-side/DOM/WebView/Electron IPC bypasses, weak crypto/PRNG/JWT quirks, mobile/cloud/"
                "K8s/CI-CD/policy misconfigurations, AI/ML loader & tool-boundary issues, smart-contract "
                "accounting/replay/ZK invariants, sensitive data exposure/exposed files, anti-automation/"
                "observability gaps, vulnerable dependency versions, and subtle RTL reset/zeroization/FSM/bus bugs."
            )
        else:
            lines.append(
                f"- PASS {pass_index}/{total_passes} ORTHOGONAL LENS (Adversarial Corner Cases): "
                "Scrutinize implicit trust assumptions, cross-file boundary mismatches, parser differentials, "
                "error-handling fallbacks, race/TOCTOU windows, default-allow policies/configs, and edge-case hardware/RTL states."
            )

    return "\n".join(lines)

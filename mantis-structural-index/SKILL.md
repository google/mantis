---
name: mantis-structural-index
description: >-
  Builds a content-addressed semantic-unit index from source code for
  structural context. Use when a pinned or live codebase is available and
  structural cross-reference data would improve research quality. Don't use for
  findings analysis, patching, or reporting.
---

# Structural Code Index Builder

This is an **optional first-class stage** in the Pass Lifecycle Contract. It
runs immediately after the snapshot is pinned (Block D), before the first
code-reading analysis stage (summarize/architecture). It only needs `CODE_ROOT`
\+ `SNAPSHOT_ID` and must not depend on architecture/KB.

## System Goal

Structural Code Index Builder. Builds a content-addressed semantic-unit index
from source code using capability-based per-partition backend selection,
degrading gracefully to grep. Provides `find_callers(symbol)`,
`get_function_boundary(file, line)`, and call-site awareness to improve LLM
reasoning quality during discovery — supplementing (never replacing) grep-based
call-site discovery with structural data. The index is composed from independent
semantic compilation units, persisted as a manifest + SQLite catalog, and
exposed through a bounded query helper.

## Command Definition

- **Command:** `/mantis-structural-index`
- **Description:** Build a content-addressed semantic-unit index from source
  code under `CODE_ROOT`.
- **Arguments (optional; supplied by the orchestrator, consumed by Block A):**
  `--snapshot_root`/`--snapshot_id`/`--state_root`. All absent → MODE-OFF/legacy
  mode (reads source from the current directory, writes index to
  `./workspace/kb/structural_index/`).

## Input/Output Contract

- **Reads**:
  - `workspace/.mantis_state.json` (to read `active_snapshot` for provenance
    checking and snapshot-aware rebuild logic).
  - `workspace/kb/structural_index/manifest.json` (to check `snapshot_id` for
    reuse-on-match idempotency — primary check).
  - `workspace/kb/structural_index.jsonl` (backward-compat provenance check if
    manifest absent).
  - `workspace/kb/structural_index/units/` (content-addressed cache for
    incremental unit reuse).
  - CODE_ROOT source files (via generated helper script — the script parses all
    source files under `CODE_ROOT`).
- **Writes**:
  - `workspace/kb/structural_index/manifest.json` (STATE-RELATIVE — atomic
    commit point, written LAST).
  - `workspace/kb/structural_index/catalog.sqlite` (STATE-RELATIVE —
    query-optimized serving store).
  - `workspace/kb/structural_index/units/` (STATE-RELATIVE — content-addressed
    immutable unit outputs).
  - `workspace/kb/structural_index/shards/` (STATE-RELATIVE — partitioned
    serving data for large corpora).
  - `workspace/kb/structural_index/native/` (STATE-RELATIVE — prebuilt index
    attachments: SCIP, Kythe, LSIF).
  - `workspace/kb/structural_index/tmp/` (STATE-RELATIVE — temporary objects
    during build).
  - `workspace/kb/structural_index.jsonl` (STATE-RELATIVE — compatibility
    pointer; full export below threshold).
  - `workspace/helpers/build_structural_index.py` (STATE-RELATIVE — the builder
    helper script).
  - `workspace/helpers/query_structural_index.py` (STATE-RELATIVE — the query
    helper script).
- **Preconditions**:
  - Source files must exist under `CODE_ROOT`. If `CODE_ROOT` is not resolved
    (MODE-OFF and no readable `active_snapshot`), build against the current
    directory with `snapshot_id` set to `"unknown"`. Do NOT skip — this is the
    standalone-efficiency case.
- **Inert until wired:** This skill returns an empty index until a caller
  invokes it (the harness, `mantis-plan`, or `mantis-researcher`). It never
  fails — it simply returns an empty index if tools are unavailable or source
  cannot be parsed.
- **Idempotency Guarantee**:
  - Read-only on `CODE_ROOT`. Writes only to STATE-RELATIVE paths. Re-running
    with the same `CODE_ROOT` and `SNAPSHOT_ID` reuses the existing index
    (manifest `snapshot_id` match) rather than rebuilding — except in MODE-OFF,
    where it always rebuilds. Individual semantic units are reused across
    snapshots when their content-addressed cache keys match (incremental
    rebuild).

## Instructions

### Step 0: Locator Resolution (run first)

```
LOCATOR RESOLUTION (before reading ANY target code or artifact):
0. ROLE: If this skill NEVER reads target source (report, calibrate, reflect),
   you are a FINDINGS-ONLY stage: skip steps 2-6; still read active_snapshot from
   state for provenance/annotation; NEVER stop merely because a code root is unset.
1. Determine CODE_ROOT, in this priority order:
   a. If --target_root is passed on THIS invocation, CODE_ROOT = --target_root.
      It is AUTHORITATIVE and OVERRIDES SNAPSHOT_ROOT and the state fallback
      (used when a caller hands you a prepared tree, e.g. a patched shadow).
   b. Else if --snapshot_root (or SNAPSHOT_ROOT) is passed, use it.
   c. Else read state_root/workspace/.mantis_state.json (state_root from
      --state_root if passed, else ./workspace/... relative to the current dir)
      -> active_snapshot.root / .snapshot_id / .snapshot_pinned.
   d. Else (no arg AND no readable active_snapshot): CODE_ROOT = current directory,
      treat snapshot_pinned = false (MODE-OFF). Do NOT stop.
2. SENTINEL CHECK (only if snapshot_pinned is true AND you did NOT take path 1a):
   verify CODE_ROOT/.mantis_snapshot_id exists and equals SNAPSHOT_ID. If missing
   or different -> STOP "snapshot sentinel mismatch". (A --target_root tree (1a) is
   deliberately mutated and is sentinel-EXEMPT.)
3. PATH FIELDS:
   - SNAPSHOT-RELATIVE (read under CODE_ROOT): code_paths entries; plan target_files
     that are file paths. Strip ONLY a trailing ":<digits>". A code_paths entry
     containing "://" is a URL/endpoint, NOT a file read. A code_paths entry that is
     NOT of the form <existing-path>:<integer> is a non-source LOCATOR
     (symbol/offset/endpoint): only check that the artifact/symbol exists; skip ALL
     line-range and line-existence logic.
   - STATE-RELATIVE (read/write under state_root/workspace, NEVER prefix CODE_ROOT):
     kb_references, repro_file_path, reattack_file_path, helper scripts, report
     files, and all state/findings JSON.
4. Never WRITE under CODE_ROOT when snapshot_pinned is true. Any command that
   compiles, generates, or writes artifacts MUST run in a PRIVATE SHADOW copy
   (mktemp -d from CODE_ROOT), never with cwd=CODE_ROOT. Read-only inspection may
   cd into CODE_ROOT.
5. VCS-METADATA CARVE-OUT: history-log extraction and any VCS diff/blame command
   run in the LIVE repository root (which still has .git/.hg/.repo), NOT CODE_ROOT
   (the snapshot copy strips VCS metadata). Do NOT stop merely because CODE_ROOT
   lacks .git/.hg/.repo.
6. Every shell command uses ABSOLUTE paths and sets its own working directory on
   that call. Do NOT assume the working directory persists between calls.
```

This is a CODE-READING stage — it reads target source files under CODE_ROOT via
the helper script. Block A step 0's findings-only skip does NOT apply.

### Step 1: Idempotency / Freshness Check

1. If `workspace/kb/structural_index/manifest.json` exists, read its
   `snapshot_id` field.
2. If `snapshot_id` matches the current `SNAPSHOT_ID` → **reuse it**. Do not
   rebuild. This bounds cost across retries/crash-resume.
3. If `manifest.json` is absent but `workspace/kb/structural_index.jsonl` exists
   (backward compat), read its provenance header (`_provenance`, `snapshot_id`
   keys). If `snapshot_id` matches → **reuse**. Otherwise proceed to rebuild.
4. If `SNAPSHOT_ID` differs (or is absent) → proceed to rebuild (Steps 2–5). For
   incremental reuse: before rebuilding a semantic unit, check `units/` for a
   content-addressed cache hit (see Content-Addressed Cache Key below). A cache
   hit reuses the unit output without re-extraction.
5. In MODE-OFF, `SNAPSHOT_ID` is `"unknown"`. Because the live tree is mutable
   and `"unknown"` is a constant (not a freshness signal), **always rebuild** in
   MODE-OFF — do not reuse a previous `"unknown"` index. However, individual
   units whose content has not changed may still be reused from the
   content-addressed cache.

### Step 2: Select Backend per Partition

Partition the codebase into semantic units (see Per-Language Semantic Units
below). For each unit, select the most precise backend available in this
environment using a **capability-based, per-partition decision** — not a single
global ladder. The following are **examples, not an exhaustive enum**. The
helper probes each tier per partition and selects the highest available:

1. **Snapshot-matched SCIP / LSIF / Kythe / clangd-static / remote index**
   (precision: `semantic`) — if a pre-built index matching the current
   `snapshot_id` or `root_fingerprint` is available. Most precise: full
   type-aware cross-reference, call hierarchy, and hover/signature data.
2. **Compiler / typechecker-backed extractor** (precision: `typecheck`) — if
   `compile_commands.json`, build context, or typechecker is available.
   Type-accurate symbol resolution and call edges.
3. **Language-aware AST extraction** (precision: `ast`) — if `tree-sitter`,
   `ast-grep`, or a language-specific parser is available. Full AST parsing:
   function boundaries, call expressions, signatures.
4. **Symbol-only extraction** (precision: `symbol-only`) — if `ctags` or
   equivalent is on `PATH`. Symbol table only (function definitions, locations —
   no call graph). Call-site extraction uses a lightweight regex pass within
   known function boundaries.
5. **Heuristic fallback** (precision: `heuristic`) — Python stdlib regex pass
   over source files. Identifies function definitions and call patterns using
   language-agnostic heuristics. Less precise but zero-dependency.
6. **Coverage-only manifest + lexical fallback** (precision: `coverage-only`) —
   grep; no structural index is written. Manifest records `status: "empty"`.
   Consumers fall back to grep-based discovery (today's behavior byte-for-byte).

**LSP is NOT equivalent to SCIP / LSIF.** LSP is an interactive protocol whose
workspace state may be partial or mutable. Use it only when the server can
demonstrate snapshot identity AND complete workspace coverage. A running
language server does not automatically qualify as a `semantic` backend.

**SCIP merging.** SCIP explicitly permits merging complementary information from
indexers with different precision levels. Its format records indexer version and
per-document language metadata. The builder MAY merge results from multiple
indexers (e.g., a SCIP index for Go + tree-sitter for Python) within a single
catalog.

The determinism lives in a runtime-generated versioned helper
(`build_structural_index.py`, `# MANTIS_HELPER_VERSION = 4`, grep-and-regenerate
on reuse) that probes and selects backends per partition. No shipped binaries;
air-gapped-safe.

**Deterministic partial coverage.** On very large source trees, a full rebuild
can dominate stage-0 wall-clock. Replace discovery-order truncation with a
deterministic priority queue:

1. **Explicit target files and symbols** (from `plan.json`, if available).
2. **Changed units and known reverse dependencies** (from Block E diff +
   reverse-dependency edges in the existing catalog).
3. **Containing packages/modules and direct imports** of tier 1+2 units.
4. **Remaining units in normalized path order**.

Apply deterministic `max_units` (default: 10000) or `max_source_bytes` (default:
500MB) bounds to that queue. Persist deferred units in the manifest so another
invocation can resume. Statuses: `complete`, `partial`, `empty`, `failed`.

A consumer should only interpret "no callers" strongly when the relevant
partition is complete, snapshot-matched, covered, and semantically precise.
Otherwise the answer is "no indexed callers", followed by the existing lexical
fallback. The index is HINT-only, so partial coverage is safe (grep remains
authoritative).

### Step 3: Write and Run Helper Scripts

Two runtime-generated helpers are used. Both follow the grep-and-regenerate
pattern: before reuse, grep the first line for the version marker; if absent or
a different integer, REGENERATE.

#### Builder: `build_structural_index.py`

1. Write the builder to `workspace/helpers/build_structural_index.py`. The FIRST
   LINE MUST be exactly `# MANTIS_HELPER_VERSION = 4`. Before reusing an
   existing helper, grep its first lines for `MANTIS_HELPER_VERSION = 4`; if
   that marker is absent or a different integer, REGENERATE the helper.
2. The builder partitions the codebase into semantic units (see Per-Language
   Semantic Units), computes content-addressed cache keys, checks `units/` for
   reuse, selects a backend per partition (Step 2), extracts symbols + edges,
   and writes results to `catalog.sqlite`.
3. The builder must extract:
   - **Symbols**: `symbol_id`, `name`, `qualified_name`, `namespace`,
     `language`, `file_path`, `start_line`, `end_line`, `kind`, `signature`,
     `backend`, `precision`.
   - **Call edges**: `caller_id`, `callee_id`, `callee_name`, `file_path`,
     `line`, `edge_kind`.
   - **Function boundaries**: `symbol_id`, `file_path`, `start_line`,
     `end_line`, `signature`, `language`.
   - **Coverage**: `file_path`, `indexed`, `backend`, `precision`,
     `unit_cache_key`, `status`.
4. The builder writes the manifest LAST (Step 4) and the compatibility pointer.
5. The builder MUST use ABSOLUTE paths and set its own working directory (Block
   A step 6). It MUST NOT write anything under `CODE_ROOT` when
   `snapshot_pinned` is true (Block A step 4). Backends that produce sidecar
   files (ctags `tags`, cscope `cscope.out`, clangd cache) MUST be redirected to
   STATE-RELATIVE paths: `ctags -f <state>/helpers/tags`,
   `cscope -f <state>/helpers/cscope.out`,
   `CLANGD_INDEX_STORAGE=<state>/helpers/`. Read-only LSP/SCIP queries to a
   running server need no redirect.

#### Query helper: `query_structural_index.py`

1. Write the query helper to `workspace/helpers/query_structural_index.py`. The
   FIRST LINE MUST be exactly `# MANTIS_HELPER_VERSION = 4`. Before reusing an
   existing helper, grep its first lines for `MANTIS_HELPER_VERSION = 4`; if
   absent or a different integer, REGENERATE.
2. The query helper provides bounded, paginated operations against
   `catalog.sqlite` (or a remote endpoint — identical API). It IS the
   consumption contract (see Query Interface below).
3. If `catalog.sqlite` is absent but `structural_index.jsonl` exists, the query
   helper falls back to linear scanning of the JSONL file (slower but
   functional). If both are absent, it returns empty results with
   `coverage.partition_status = "empty"`.

### Step 4: Write Manifest and Commit

1. Write the manifest to `workspace/kb/structural_index/tmp/manifest.json`
   first. Then atomically rename it to
   `workspace/kb/structural_index/manifest.json`. This is the atomic commit
   point — the manifest is written LAST, after all units, catalog, and coverage
   data are written.
2. Write a compatibility pointer to `workspace/kb/structural_index.jsonl`
   (STATE-RELATIVE — NEVER under `CODE_ROOT`). Below a configurable threshold
   (default: 10K records), emit a complete JSONL export (provenance header + all
   records). Above the threshold, emit only a provenance header with
   `compat_pointer.full_export = false` and `compat_pointer.symbol_count` set.
   Large consumers MUST use the query interface.
3. The manifest `provider.backend_versions` field records which backend was used
   per language (e.g.,
   `{"go": {"backend_name": "scip-clangd", "precision": "semantic"}, "python": {"backend_name": "tree-sitter", "precision": "ast"}}`),
   so consumers know the precision level.
4. Interrupted builds leave unreferenced temp objects in `tmp/` without
   corrupting the last published index. On resume, check `manifest.json` status
   and `snapshot_id` (Step 1).

### Step 5: Return Results / Notify Caller

1. Return the path to `manifest.json`, `catalog.sqlite`, and the query helper.
   Include a summary (unit count, symbol count, call-edge count, backends used,
   coverage status).
2. If the index is empty (no tools available or no source files found), notify
   the caller: "Structural index is empty — structural context unavailable."
3. Do not notify the user directly — this skill is invoked as a sub-agent by the
   harness, planner, or researcher.

## Index Schema and On-Disk Contract

### On-Disk Layout

```
workspace/kb/structural_index/
├── manifest.json          # Atomic commit point — written LAST
├── catalog.sqlite         # Query-optimized serving store (both directions indexed)
├── units/                 # Content-addressed immutable unit outputs
│   └── ab/cd/abcdef...    # sha256 prefix sharding (2+2 hex dirs)
├── shards/                # Partitioned serving data (large corpora)
│   └── shard_0000.sqlite
├── native/                # Prebuilt index attachments (SCIP, Kythe, LSIF)
│   ├── scip/
│   └── kythe/
└── tmp/                   # Temporary objects during build

workspace/helpers/
├── build_structural_index.py    # Builder (MANTIS_HELPER_VERSION = 4)
└── query_structural_index.py    # Query helper (MANTIS_HELPER_VERSION = 4)

workspace/kb/structural_index.jsonl  # Compatibility pointer
```

### Manifest Schema (`manifest.json`)

```json
{
  "schema_version": 1,
  "snapshot_id": "<SNAPSHOT_ID or 'unknown'>",
  "root_fingerprint": "<sha256 of sorted (path, content_sha256) for all source files>",
  "status": "complete|partial|empty|failed",
  "provider": {
    "kind": "local-build|baseline+overlay|remote",
    "catalog": "catalog.sqlite",
    "backend_versions": {
      "cpp": {"backend_name": "tree-sitter", "backend_version": "0.20.8", "precision": "ast"},
      "go": {"backend_name": "scip-clangd", "backend_version": "0.2.3", "precision": "semantic"}
    }
  },
  "units": {"total": 0, "reused": 0, "rebuild": 0, "failed": 0},
  "coverage": {"total_files": 0, "indexed_files": 0, "failed_files": 0, "deferred_files": 0},
  "shards": [{"id": "", "path": "", "checksum": "", "partition_key": "", "symbol_count": 0, "edge_count": 0}],
  "deferred_units": [{"unit_id": "", "language": "", "files": [], "priority": 4, "reason": ""}],
  "native_indexes": [{"kind": "scip", "path": "", "language": "", "indexer": "", "precision": ""}],
  "baseline": {"source": "ci|local|none", "snapshot_id": "", "manifest_path": ""},
  "overlay": {"units_added": 0, "units_modified": 0, "files": []},
  "compat_pointer": {"path": "structural_index.jsonl", "full_export": true, "symbol_count": 0},
  "created_at": "<ISO 8601>",
  "build_duration_ms": 0
}
```

**Atomic commit**: The manifest is written LAST (atomic rename from `tmp/`).
Interrupted builds leave unreferenced temp objects without corrupting the last
published index.

### SQLite Catalog Schema (`catalog.sqlite`)

```sql
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY, value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS symbols (
    symbol_id       TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    qualified_name  TEXT NOT NULL,
    namespace       TEXT,
    language        TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    start_line      INTEGER NOT NULL,
    end_line        INTEGER,
    kind            TEXT NOT NULL,
    signature       TEXT,
    backend         TEXT NOT NULL,
    precision       TEXT NOT NULL CHECK (precision IN ('semantic','typecheck','ast','symbol-only','heuristic','coverage-only')),
    corpus          TEXT DEFAULT 'default',
    partition_key   TEXT,
    unit_cache_key  TEXT,
    source_layer    TEXT NOT NULL DEFAULT 'baseline'
);

CREATE TABLE IF NOT EXISTS call_edges (
    edge_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    caller_id   TEXT NOT NULL,
    callee_id   TEXT,
    callee_name TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    line        INTEGER NOT NULL,
    edge_kind   TEXT NOT NULL CHECK (edge_kind IN ('direct','indirect','virtual','macro','unresolved')),
    corpus      TEXT DEFAULT 'default',
    partition_key TEXT,
    source_layer TEXT NOT NULL DEFAULT 'baseline',
    FOREIGN KEY (caller_id) REFERENCES symbols(symbol_id),
    FOREIGN KEY (callee_id) REFERENCES symbols(symbol_id)
);

CREATE TABLE IF NOT EXISTS function_boundaries (
    symbol_id   TEXT PRIMARY KEY,
    file_path   TEXT NOT NULL,
    start_line  INTEGER NOT NULL,
    end_line    INTEGER NOT NULL,
    signature   TEXT,
    language    TEXT NOT NULL,
    FOREIGN KEY (symbol_id) REFERENCES symbols(symbol_id)
);

CREATE TABLE IF NOT EXISTS coverage (
    file_path   TEXT NOT NULL,
    indexed     INTEGER NOT NULL DEFAULT 0,
    backend     TEXT,
    precision   TEXT,
    unit_cache_key TEXT,
    status      TEXT NOT NULL DEFAULT 'pending',
    corpus      TEXT DEFAULT 'default',
    partition_key TEXT,
    PRIMARY KEY (file_path, corpus)
);

CREATE TABLE IF NOT EXISTS unit_cache (
    cache_key       TEXT PRIMARY KEY,
    unit_id         TEXT NOT NULL,
    language        TEXT NOT NULL,
    extractor_name  TEXT NOT NULL,
    extractor_version TEXT NOT NULL,
    file_count      INTEGER NOT NULL,
    symbol_count    INTEGER NOT NULL,
    edge_count      INTEGER NOT NULL,
    source_bytes    INTEGER NOT NULL,
    created_at      TEXT NOT NULL,
    snapshot_id     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deferred_units (
    unit_id     TEXT PRIMARY KEY,
    language    TEXT NOT NULL,
    files       TEXT NOT NULL,
    priority    INTEGER NOT NULL,
    reason      TEXT NOT NULL,
    cache_key   TEXT,
    created_at  TEXT NOT NULL
);

-- Indexes: both directions!
CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_symbols_qualified ON symbols(qualified_name);
CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file_path, start_line);
CREATE INDEX IF NOT EXISTS idx_symbols_lang ON symbols(language);
CREATE INDEX IF NOT EXISTS idx_edges_caller ON call_edges(caller_id);
CREATE INDEX IF NOT EXISTS idx_edges_callee ON call_edges(callee_id);
CREATE INDEX IF NOT EXISTS idx_edges_callee_name ON call_edges(callee_name);
CREATE INDEX IF NOT EXISTS idx_edges_file ON call_edges(file_path, line);
CREATE INDEX IF NOT EXISTS idx_boundaries_file ON function_boundaries(file_path, start_line, end_line);
CREATE INDEX IF NOT EXISTS idx_coverage_status ON coverage(status);
CREATE INDEX IF NOT EXISTS idx_deferred_priority ON deferred_units(priority);
```

**Partitioning**: When symbols exceed 500K or edges exceed 2M, partition into
shard SQLite files under `shards/` by `lang:{language}:bucket:{NN}` (stable
hash). Each shard has the same schema. The query helper routes queries to the
correct shard(s) based on the manifest.

### Content-Addressed Cache Key

```python
cache_key = sha256(
    schema_version +
    extractor_name@version +
    language +
    compile_context_digest +
    ordered_input_content_digests +
    dependency_or_interface_digest
)
```

**Critical**: `snapshot_id` is NOT in the cache key. It goes in provenance only.
This permits reuse across commits, branches, and snapshots with identical units.

### Canonical Symbol IDs

**Native IDs** (when semantic backend is available):

- SCIP: `scip:{symbol}`
- Kythe: `kythe:{uri}`
- clangd: `clangd:{usr}`

**Fallback IDs** (when no semantic backend):

```
fallback:{language}:{file_path}:{sha256(qualified_name|start_line|signature)[:16]}
```

This distinguishes namespaces, overloads, methods, local functions, and
duplicate names across languages or repositories.

### Edge Kinds

Edge kinds are kept explicitly separate — never silently merged:

- `direct` — statically resolved call to a known symbol
- `indirect` — function pointer, closure, callback
- `virtual` — virtual method dispatch (runtime-resolved)
- `macro` — call introduced by macro expansion
- `unresolved` — callee name found but no symbol_id resolved

### Per-Language Semantic Units

| Language    | Unit Type        | Compile Context             | Dependency Digest                           |
| ----------- | ---------------- | --------------------------- | ------------------------------------------- |
| C/C++       | Compilation unit | compile_commands.json entry | sha256 of transitive header interfaces      |
| Go          | Package          | go.mod + build tags         | sha256 of imported packages' exported API   |
| Rust        | Crate            | Cargo.toml + features       | sha256 of extern crate signatures           |
| Java/Kotlin | Compiler batch   | module path + classpath     | sha256 of imported class signatures         |
| TypeScript  | Project          | tsconfig.json               | sha256 of imported module type declarations |
| Fallback    | Individual file  | None                        | Empty string                                |

### Baseline + Delta Overlay

- **Static baseline**: Built once in CI for the complete snapshot.
- **Incremental cache**: Immutable unit outputs reused across snapshots.
- **Delta overlay**: Changed/target files indexed locally, layered over
  baseline.
- **Remote serving**: Optional when global index is too costly locally.

At query time, the query helper merges baseline + overlay results. Overlay
symbols supersede baseline symbols for the same file. The manifest records
`provider.kind = "baseline+overlay"` with baseline manifest reference and
overlay unit count.

### Compatibility JSONL Export

The old `structural_index.jsonl` format is retained as a compatibility export
only — it is NOT the query contract. Below the threshold (default 10K records),
a complete JSONL export is emitted. Above the threshold, only a provenance
pointer is written. Large consumers MUST use the query interface.

Line 1 — provenance header:

```json
{"_provenance": true, "snapshot_id": "abc123", "tool": "tree-sitter"}
```

Lines 2+ — structural records (one per line, `_type` discriminator):

```json
{"_type": "function", "key": "src/parser.c:parse_input", "start_line": 45, "end_line": 120, "signature": "int parse_input(char *buf, size_t len)", "calls": ["malloc", "validate_input", "memcpy"]}
{"_type": "call_edge", "caller": "parse_input", "callee": "malloc", "file": "src/parser.c", "line": 78}
{"_type": "call_edge", "caller": "main", "callee": "parse_input", "file": "src/main.c", "line": 203}
```

**Provenance header fields:**

| Field         | Type   | Description                                                                         |
| ------------- | ------ | ----------------------------------------------------------------------------------- |
| `_provenance` | bool   | Always `true` — marks this as the provenance header line                            |
| `snapshot_id` | string | `SNAPSHOT_ID` the index was built against                                           |
| `tool`        | string | Backend used (e.g. `"lsp-clangd"`, `"tree-sitter"`, `"ctags"`, `"regex"`, `"grep"`) |

**Record types:**

| `_type`     | Description                                     | Key fields                                            |
| ----------- | ----------------------------------------------- | ----------------------------------------------------- |
| `function`  | Function definition with boundary and signature | `key`, `start_line`, `end_line`, `signature`, `calls` |
| `call_edge` | A call from caller to callee at file:line       | `caller`, `callee`, `file`, `line`                    |

## Snapshot Safety

1. **Build from `CODE_ROOT`, not live tree (when pinned).** When the snapshot is
   pinned, the structural index is built from the pinned `CODE_ROOT`, ensuring
   it reflects the exact bytes the pipeline is analyzing.
2. **Reuse-on-match.** If `manifest.json` already carries the current
   `SNAPSHOT_ID`, reuse it — do not rebuild. Rebuild only when `SNAPSHOT_ID`
   differs. Individual units may still be reused from the content-addressed
   cache. This bounds cost across retries/crash-resume.
3. **Manifest atomicity.** The manifest is written LAST via atomic rename from
   `tmp/`. Interrupted builds leave unreferenced temp objects without corrupting
   the last published index. On resume, check `manifest.json` status and
   `snapshot_id`.
4. **STALE flag in HALT mode.** When `snapshot_pinned` is false (HALT), the
   index may be built from the unpinned `CODE_ROOT` but is marked as potentially
   stale. Consumers treat structural hints as advisory.
5. **MODE-OFF: build, do not skip.** When `active_snapshot` is absent
   (MODE-OFF), build against the current directory (cwd) with provenance
   `snapshot_id` set to `"unknown"`. This is the standalone-efficiency case —
   the index is still useful for the researcher/planner even without snapshot
   pinning. Do NOT return an empty index merely because the snapshot is absent.

## Consumption Contract

These are runtime instructions for callers — they define how consumers use the
structural index. The structural index is a HINT-only enhancement; skills that
do not use it behave exactly as they do today.

### Query Interface

**The query helper IS the contract.** All consumers use
`query_structural_index.py` (or a compatible remote endpoint). The JSONL file is
NOT the query contract — it is a compatibility export only.

**Operations**:

1. `resolve_symbol(name, language?, file?, namespace?)` →
   `{results, total, ambiguous, coverage}`

   - Returns ALL matches — no silent selection among ambiguous symbols.
   - Caller MUST disambiguate before calling `find_callers` / `find_callees`.

2. `find_callers(symbol_id, limit=100, offset=0)` →
   `{results, total, has_more, coverage}`

   - Bounded, paginated caller lookup.
   - Each result carries `precision`, `backend`, `edge_kind`.
   - Empty results carry `coverage.partition_status`.

3. `find_callees(symbol_id, limit=100, offset=0)` →
   `{results, total, has_more, coverage}`

   - Same shape as `find_callers`.

4. `get_function_boundary(file, line)` →
   `{symbol_id, start_line, end_line, signature, precision, backend}`

5. `get_coverage(file?)` →
   `{total_files, indexed_files, failed, deferred, partition_status, backends_used}`

**Key properties**:

- Bounded results and pagination (prevents loading entire index into memory).
- Explicit name resolution before graph traversal (no silent selection among
  ambiguous symbols).
- Precision and backend attached to every result.
- Coverage attached to empty results.
- Identical operations for local and remote providers (remote via
  `MANTIS_STRUCTURAL_INDEX_URL` env var or manifest `provider.kind = "remote"`).

**Coverage on empty results**:

| `partition_status` | Meaning                       | Consumer action                                          |
| ------------------ | ----------------------------- | -------------------------------------------------------- |
| `complete`         | All files indexed             | "No indexed callers" (still run grep per HINT-only rule) |
| `partial`          | Some files deferred or failed | "Not fully indexed" — MUST run grep fallback             |
| `empty`            | No backend available          | "Not indexed" — MUST run grep fallback                   |
| `failed`           | Backend attempted but failed  | "Index failed" — MUST run grep fallback                  |

### mantis-plan

- Use the structural index query helper for function-level dependency fan-out.
  When planning investigations, call `resolve_symbol()` then `find_callers()` to
  identify all functions that call into a target — this broadens the audit set
  beyond single-file analysis.
- The structural index decides ORDER of investigations (which functions to audit
  first based on call-graph centrality), never MEMBERSHIP. It may broaden the
  audit set (safe over-reporting), but must never REMOVE or drop a file; the
  planner's existing logic remains the membership floor.

### mantis-researcher

- **Wave 1 (Rapid Triage):** Run a repo-wide grep for the function name to build
  the exhaustive set of candidate call-sites — this is the mandatory floor. Then
  use the structural index query helper (`resolve_symbol` then `find_callers`)
  to RANK and prioritize which call-sites to audit first (the index
  distinguishes actual calls from comments/strings/variable names). Audit the
  union of both result sets — the structural index may miss macro-based calls,
  function pointers, and dynamic dispatch, so grep remains the floor.
- **Wave 2 (Deep Audit):** Use `get_function_boundary(file, line)` to start with
  the enclosing function, expanding to callers/callees/file as needed for
  cross-function context — this saves context while preserving coverage.
- If the structural index is absent or empty, fall back to grep-based discovery
  (today's behavior). The structural index is a coverage HINT only — it improves
  audit quality but is never required.

## Safety

Non-negotiable invariants:

1. **Agnostic.** Nothing is ever required; no-tool / parse-fail / not-invoked →
   empty index → grep fallback = today's behavior byte-for-byte. Optional in the
   Pass Lifecycle Contract; a non-conformant harness simply skips it.
2. **HINT-only / union / never MEMBERSHIP.** Consumers audit the union with
   grep; a symbol the index misses must still be reachable by the exhaustive
   sweep. The structural index decides ORDER, never MEMBERSHIP. The query
   contract enforces this: `find_callers` returns HINTs, never authoritative
   membership — consumers MUST union with grep.
3. **No verdicts, touches no findings.** Cannot violate INV-1 and cannot itself
   drop a finding.
4. **Narrow scope: source cross-reference only.** Binary/build-derived
   reachability ("is it compiled into production") is explicitly out of scope —
   a dev customization, not part of this skill, because absence-from-a-build can
   hide a real finding (INV-2). Do not fold build-derived reachability into this
   skill.

A reference blueprint is available at
[mantis-pipeline-adapter/references/mantis-structural-index.md](../mantis-pipeline-adapter/references/mantis-structural-index.md).
It is a stub that points to this SKILL.md as the single source of truth — do not
duplicate spec content there.

---
name: mantis-structural-index
description: >-
  Builds a function-level call graph and symbol table from source code for
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

Structural Code Index Builder. Builds a function-level call graph and symbol
table from source code using the most precise cross-reference backend available
in the environment, degrading gracefully to grep. Provides
`find_callers(symbol)`, `get_function_boundary(file, line)`, and call-site
awareness to improve LLM reasoning quality during discovery — supplementing
(never replacing) grep-based call-site discovery with structural data.

## Command Definition

- **Command:** `/mantis-structural-index`
- **Description:** Build a function-level call graph and symbol table from
  source code under `CODE_ROOT`.
- **Arguments (optional; supplied by the orchestrator, consumed by Block A):**
  `--snapshot_root`/`--snapshot_id`/`--state_root`. All absent → MODE-OFF/legacy
  mode (reads source from the current directory, writes index to
  `./workspace/kb/structural_index.jsonl`).

## Input/Output Contract

- **Reads**:
  - `workspace/.mantis_state.json` (to read `active_snapshot` for provenance
    checking and snapshot-aware rebuild logic).
  - `workspace/kb/structural_index.jsonl` (to check provenance for
    reuse-on-match idempotency).
  - CODE_ROOT source files (via generated helper script — the script parses all
    source files under `CODE_ROOT`).
- **Writes**:
  - `workspace/kb/structural_index.jsonl` (STATE-RELATIVE — the structural index
    artifact).
  - `workspace/helpers/build_structural_index.py` (STATE-RELATIVE — the
    generated helper script).
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
    (reuse-on-match) rather than rebuilding — except in MODE-OFF, where it
    always rebuilds.

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

1. If `workspace/kb/structural_index.jsonl` already exists, read its provenance
   header (the `_provenance`, `snapshot_id` top-level keys).
2. If `snapshot_id` in the header matches the current `SNAPSHOT_ID` → **reuse
   it**. Do not rebuild. This bounds cost across retries/crash-resume.
3. If `SNAPSHOT_ID` differs (or is absent) → proceed to rebuild (Steps 2–5).
4. In MODE-OFF, `SNAPSHOT_ID` is `"unknown"`. Because the live tree is mutable
   and `"unknown"` is a constant (not a freshness signal), **always rebuild** in
   MODE-OFF — do not reuse a previous `"unknown"` index.
5. Changed-files-only incremental rebuild via Block E (changed-since-previous
   diff) is explicitly a **future optimization**, not now. Today the rebuild is
   full (all source files under `CODE_ROOT`).

### Step 2: Probe Backend Availability

Use the most precise cross-reference backend available in this environment,
degrading to grep. The following are **examples, not an exhaustive enum** — the
helper probes each tier and steps down to the first that is available:

1. **LSP** (clangd / gopls / pyright / rust-analyzer / …) or **SCIP / LSIF** —
   if a pre-built index or a running language server is available. Most precise:
   full type-aware cross-reference, call hierarchy, and hover/signature data.
2. **cscope / GNU global** — if available. Language-aware inverted index with
   caller/callee lookups and definition references.
3. **tree-sitter / ast-grep** — if `tree_sitter_languages` is importable or
   `ast-grep` is on `PATH`. Full AST parsing: function boundaries, call
   expressions, signatures.
4. **universal-ctags** — if `ctags` is on `PATH`. Symbol table only (function
   definitions, locations — no call graph). Call-site extraction uses a
   lightweight regex pass within known function boundaries.
5. **stdlib-regex symbol/boundary helper** — fallback Python regex pass over
   source files. Identifies function definitions and call patterns using
   language-agnostic heuristics. Less precise but zero-dependency.
6. **grep** — final fallback. No structural index is written; consumers fall
   back to grep-based discovery (today's behavior byte-for-byte). An empty index
   is produced.

The determinism lives in a runtime-generated versioned helper
(`build_structural_index.py`, `# MANTIS_HELPER_VERSION = 1`, grep-and-regenerate
on reuse) that probes and steps down the ladder. No shipped binaries;
air-gapped-safe.

**Large-tree guard:** On very large source trees (>50K source files), a full
rebuild can dominate stage-0 wall-clock (100MB+ indexes). If the plan has
already identified target files, the helper SHOULD restrict parsing to those
files and their import/call-graph neighborhood rather than the entire tree. If
no plan exists yet, cap at the first 10K functions discovered — the index is
HINT-only, so partial coverage is safe (grep remains authoritative).

### Step 3: Write and Run Helper Script

1. Write a reusable helper script to
   `workspace/helpers/build_structural_index.py`. The FIRST LINE of the script
   MUST be exactly `# MANTIS_HELPER_VERSION = 1`. Before reusing an existing
   helper, grep its first lines for `MANTIS_HELPER_VERSION = 1`; if that marker
   is absent or a different integer (a helper left by an older pipeline
   version), REGENERATE the helper.
2. The script must parse all source files under `CODE_ROOT` and extract:
   - **Function definitions**: `name`, `signature`, `start_line`, `end_line`.
   - **Call edges**: `caller` (enclosing function), `callee` (called function
     name), `file`, `line`.
3. The script probes the available backends (Step 2 ladder) and steps down to
   the first available:
   - **LSP / SCIP / LSIF**: Query the running server or parse the pre-built
     index. Extract function definitions, call hierarchy, and signatures.
   - **cscope / GNU global**: Query the database for definitions and call edges.
   - **tree-sitter**: Parse each file with the appropriate language grammar.
     Walk the AST to extract function definitions and call expressions.
   - **ast-grep**: Use pattern rules to extract function definitions and call
     expressions.
   - **universal-ctags**: Parse the JSON output to extract function definitions
     (name, line). Call-edge extraction uses a lightweight regex pass over the
     source for `identifier(` patterns within known function boundaries.
   - **stdlib-regex**: Use Python `re` to identify function definitions and call
     patterns. Language-agnostic heuristics for common syntax families.
4. Execute the script with `CODE_ROOT` as an argument. The script outputs JSONL
   to stdout (one JSON object per line).
5. The script MUST use ABSOLUTE paths and set its own working directory (Block A
   step 6). It MUST NOT write anything under `CODE_ROOT` when `snapshot_pinned`
   is true (Block A step 4). Backends that produce sidecar files (ctags `tags`,
   cscope `cscope.out`, clangd cache) MUST be redirected to STATE-RELATIVE
   paths: `ctags -f <state>/helpers/tags`,
   `cscope -f <state>/helpers/cscope.out`,
   `CLANGD_INDEX_STORAGE=<state>/helpers/`. LSP/SCIP queries to a running server
   are read-only and need no redirect.

### Step 4: Write `structural_index.jsonl`

1. Capture the JSON output from the helper script.
2. The output is JSONL (one JSON object per line). Line 1 is the provenance
   header; lines 2+ are structural records. The helper script should emit
   records with a `_type` discriminator:

```json
{
  "_provenance": true,
  "snapshot_id": "<SNAPSHOT_ID or 'unknown'>",
  "tool": "<backend-name>"
}
```

3. Write the complete index to `workspace/kb/structural_index.jsonl`
   (STATE-RELATIVE — NEVER under `CODE_ROOT`).
4. The `tool` field records which backend was actually used (e.g.,
   `"lsp-clangd"`, `"scip"`, `"cscope"`, `"tree-sitter"`, `"ast-grep"`,
   `"ctags"`, `"regex"`, `"grep"`), so consumers know the precision level.

### Step 5: Return Results / Notify Caller

1. Return the path to `structural_index.jsonl` and a summary (function count,
   call-site count, tool used).
2. If the index is empty (no tools available or no source files found), notify
   the caller: "Structural index is empty — structural context unavailable."
3. Do not notify the user directly — this skill is invoked as a sub-agent by the
   harness, planner, or researcher.

## `structural_index.jsonl` Format

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

`find_callers(Y)` = filter `callee: Y`; `find_callees(X)` = filter `caller: X`.

## Snapshot Safety

1. **Build from `CODE_ROOT`, not live tree (when pinned).** When the snapshot is
   pinned, the structural index is built from the pinned `CODE_ROOT`, ensuring
   it reflects the exact bytes the pipeline is analyzing.
2. **Reuse-on-match.** If `structural_index.jsonl` already carries the current
   `SNAPSHOT_ID` in its provenance header, reuse it — do not rebuild. Rebuild
   only when `SNAPSHOT_ID` differs. This bounds cost across
   retries/crash-resume.
3. **STALE flag in HALT mode.** When `snapshot_pinned` is false (HALT), the
   index may be built from the unpinned `CODE_ROOT` but is marked as potentially
   stale. Consumers treat structural hints as advisory.
4. **MODE-OFF: build, do not skip.** When `active_snapshot` is absent
   (MODE-OFF), build against the current directory (cwd) with provenance
   `snapshot_id` set to `"unknown"`. This is the standalone-efficiency case —
   the index is still useful for the researcher/planner even without snapshot
   pinning. Do NOT return an empty index merely because the snapshot is absent.

## Consumption Contract

These are runtime instructions for callers — they define how consumers use the
structural index. The structural index is a HINT-only enhancement; skills that
do not use it behave exactly as they do today.

### mantis-plan

- Use the structural index for function-level dependency fan-out. When planning
  investigations, filter `call_edge` records by `callee` to identify all
  functions that call into a target — this broadens the audit set beyond
  single-file analysis.
- The structural index decides ORDER of investigations (which functions to audit
  first based on call-graph centrality), never MEMBERSHIP (it does not add or
  remove files from the audit set — the planner's existing logic decides that).

### mantis-researcher

- **Wave 1 (Rapid Triage):** Use `find_callers(symbol)` from the structural
  index to SUPPLEMENT grep as a ranking HINT for call-site discovery — it
  decides ORDER, never MEMBERSHIP. It MUST NEVER replace the exhaustive Step-3
  call-site sweep; every call-site that a full grep would reach must still be
  audited whether or not it ranks in the structural index. Audit the union of
  grep results and structural index results. The structural index is more
  precise than grep (distinguishes actual calls from comments/strings/variable
  names), but it can miss macro-based calls, function pointers, and dynamic
  dispatch.
- **Wave 2 (Deep Audit):** Use `get_function_boundary(file, line)` to start with
  the enclosing function, expanding to callers/callees/file as needed for
  cross-function context — this saves context while preserving coverage.
- If the structural index is absent or empty, fall back to grep-based discovery
  (today's behavior). The structural index is a coverage HINT only — it improves
  audit quality but is never required.

### Query Interface

The JSONL file is the contract. Consumers read `structural_index.jsonl` directly
(or generate a tiny `query_structural_index.py` helper to return one slice for
large indexes). A kb-query-style query sub-agent or MCP (`find_callers()` etc.)
is the scale upgrade only — do not create a second top-level query skill by
default; that is over-engineering, and it mirrors how consumers already read
`dependencies.json` directly.

## Safety

Non-negotiable invariants:

1. **Agnostic.** Nothing is ever required; no-tool / parse-fail / not-invoked →
   empty index → grep fallback = today's behavior byte-for-byte. Optional in the
   Pass Lifecycle Contract; a non-conformant harness simply skips it.
2. **HINT-only / union / never MEMBERSHIP.** Consumers audit the union with
   grep; a symbol the index misses must still be reachable by the exhaustive
   sweep. The structural index decides ORDER, never MEMBERSHIP.
3. **No verdicts, touches no findings.** Cannot violate INV-1 and cannot itself
   drop a finding.
4. **Narrow scope: source cross-reference only.** Binary/build-derived
   reachability ("is it compiled into production") is explicitly out of scope —
   a dev customization, not part of this skill, because absence-from-a-build can
   hide a real finding (INV-2). Do not fold build-derived reachability into this
   skill.

A complete reference blueprint with additional implementation details is
available at
[mantis-pipeline-adapter/references/mantis-structural-index.md](../mantis-pipeline-adapter/references/mantis-structural-index.md).

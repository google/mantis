# Reference Blueprint: mantis-kb-query Skill

This is a **reference blueprint** for builders implementing Option A of
Guideline 6 (Semantic Retrieval). It is not a top-level skill — no pipeline
stage invokes it directly. Builders use it as a template to create a
`mantis-kb-query` skill in their own environment, invoked as a sub-agent by
`mantis-plan` or `mantis-researcher` when semantic retrieval is available.

## System Goal

Semantic Retrieval Agent. Searches `workspace/kb/chunks.jsonl` using BM25/TF-IDF
similarity to return the most relevant KB entries or code locations for a given
query. Designed for large codebases where manual scanning of `kb/index.md` or
grep-based discovery is insufficient.

## Command Definition

- **Command:** `/mantis-kb-query`
- **Description:** Semantic search over KB and code chunks for large codebases.
- **Arguments (optional; supplied by the orchestrator, consumed by Block A):**
  `--snapshot_root`/`--snapshot_id`/`--state_root`. All absent → MODE-OFF/legacy
  mode (reads chunks from `./workspace/kb/chunks.jsonl` relative to current
  dir).

## Input/Output Contract

- **Reads**:
  - `workspace/kb/chunks.jsonl` (the chunk index, produced by the harness or
    `mantis-architecture` post-Stage-2; one JSON object per line, with an
    optional provenance header line).
  - `workspace/.mantis_state.json` (to read `active_snapshot` for provenance
    checking).
- **Writes**:
  - Outputs top-K matching chunks as JSON to stdout. Does not write any files.
- **Preconditions**:
  - `workspace/kb/chunks.jsonl` must exist. If it does not, output an empty
    result set and notify the caller (do not error or stop).
- **Inert until wired:** This skill returns `[]` and delivers zero value until
  both (1) a `chunks.jsonl` producer exists (the harness post-architecture, or
  the architecture skill instructed to write it), and (2) a caller (planner or
  researcher) is wired to invoke this skill as a sub-agent. It never fails — it
  simply returns empty results until both ends are connected.
- **Idempotency Guarantee**:
  - Read-only. No state mutation. Re-running with the same query and chunks file
    produces identical results.

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

This is a FINDINGS-ONLY stage — it does not read target source code. Block A
step 0's findings-only skip applies: read `active_snapshot` from state for
provenance checking, but do not require a `CODE_ROOT` to proceed.

### Step 1: Check Chunk Availability

1. Resolve the path to `chunks.jsonl`:
   - If `--state_root` is passed, read `<state_root>/workspace/kb/chunks.jsonl`.
   - Else read `workspace/kb/chunks.jsonl` relative to the current directory.
2. If the file does not exist, output an empty JSON array `[]` and notify the
   caller: "chunks.jsonl not found — semantic search unavailable, falling back
   to manual scanning." Do NOT error or stop.
3. If the file exists but is empty (or contains only a provenance header),
   output `[]` and notify the caller.

### Step 2: Provenance Check

1. Read the first line of `chunks.jsonl`. If it is a JSON object with
   `"_provenance": true`, extract `snapshot_id` from it.
2. Read `active_snapshot.snapshot_id` from `workspace/.mantis_state.json` (if
   present).
3. Compare the chunk's `snapshot_id` to the current `SNAPSHOT_ID`:
   - If they match → proceed (chunks are current).
   - If they differ → output results but prepend a warning:
     `"WARNING: chunks.jsonl is stale (built against snapshot_id=X, current=Y). Results may be inaccurate. Rebuild chunks post-architecture."`
   - If `active_snapshot` is absent (MODE-OFF) → skip the check (no snapshot to
     compare against). Proceed without warning.
   - If `snapshot_pinned` is false (HALT mode) → output results with a `STALE`
     flag on each result, same conservative degradation as every other stage.

### Step 3: Execute Search

1. Determine the query string. The caller (planner or researcher) provides this
   as the sub-agent's prompt or as a `--query` argument.

2. Determine the top-K limit (default: 5). The caller may specify a different
   value.

3. Determine the entity type filter (optional). The caller may request only
   `entity`, `vulnerability`, or `code` chunks.

4. **Reusable Deterministic Scripting (versioned):** Write a reusable helper
   script (e.g. `workspace/helpers/search_chunks.py`) whose FIRST LINE is
   exactly `# MANTIS_HELPER_VERSION = 1`. Before reusing an existing helper,
   grep its first lines for `MANTIS_HELPER_VERSION = 1`; if that marker is
   absent or a different integer (a helper left by an older pipeline version),
   REGENERATE the helper. The script must:

   - Read `chunks.jsonl` (skipping the provenance header line if present).
   - Tokenize query and chunk text (lowercase, split on non-alphanumeric).
   - Compute BM25 or TF-IDF similarity scores between the query and each chunk.
     If vector embeddings are available, the script may use cosine similarity
     instead — this is a configuration toggle, not a different script.
   - Optionally filter results by `entity_type` (`entity`, `vulnerability`, or
     `code`).
   - Output the top-K matching chunks as a JSON array to stdout, each containing
     `id`, `source_file`, `entity_type`, `start_line`, `end_line` (null for KB
     chunks, integers for code chunks), `score`, and `chunk_text`.

5. Execute the script with the query, chunks file path, top-K, and optional
   filter as arguments. Capture the JSON output from stdout.

6. Return the results to the caller. Do not write any result files.

### Step 4: Return Results

Return the top-K matching chunks as a JSON array to the caller. Each result
includes:

```json
{
  "id": "auth_module:0",
  "source_file": "workspace/kb/entities/auth_module.md",
  "entity_type": "entity",
  "start_line": null,
  "end_line": null,
  "score": 12.34,
  "chunk_text": "The auth module handles..."
}
```

For code chunks, `start_line` and `end_line` are integers. For KB chunks, they
are `null`.

When complete, return the results to the caller. Do not notify the user directly
— this skill is invoked as a sub-agent by the planner or researcher.

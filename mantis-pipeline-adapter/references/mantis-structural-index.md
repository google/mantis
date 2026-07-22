# Reference Blueprint: mantis-structural-index Skill

This is a **reference blueprint** for builders implementing Guideline 9
(Structural Code Index) of the Pipeline Adapter. It is not a top-level skill —
no pipeline stage invokes it directly. Builders use it as a template to create a
`mantis-structural-index` skill in their own environment, invoked by the harness
or by `mantis-plan` / `mantis-researcher` as a sub-agent when AST-level
structural context (function boundaries, call graphs, symbol tables) is
available.

## System Goal

Structural Code Index Builder. Builds a function-level call graph and symbol
table from source code using ctags (zero-dependency) or tree-sitter
(pip-installable). Provides `find_callers(symbol)`,
`get_function_boundary(file, line)`, and call-site awareness to improve LLM
reasoning quality during discovery — replacing fragile grep-based call-site
discovery with AST-accurate structural data.

## Command Definition

- **Command:** `/mantis-build-structural-index`
- **Description:** Build a function-level call graph and symbol table from
  source code under `CODE_ROOT`.
- **Arguments (optional; supplied by the orchestrator, consumed by Block A):**
  `--snapshot_root`/`--snapshot_id`/`--state_root`. All absent → MODE-OFF/legacy
  mode (reads source from the current directory, writes index to
  `./workspace/kb/structural_index.json`).

## Input/Output Contract

- **Reads**:
  - `workspace/.mantis_state.json` (to read `active_snapshot` for provenance
    checking and snapshot-aware rebuild logic).
  - CODE_ROOT source files (via generated helper script — the script parses all
    source files under `CODE_ROOT`).
- **Writes**:
  - `workspace/kb/structural_index.json` (STATE-RELATIVE — the structural index
    artifact).
  - `workspace/helpers/build_structural_index.py` (STATE-RELATIVE — the
    generated helper script).
- **Preconditions**:
  - Source files must exist under `CODE_ROOT`. If `CODE_ROOT` is not resolved
    (MODE-OFF and no readable `active_snapshot`), output an empty index and
    notify the caller.
- **Inert until wired:** This skill returns an empty index until both (1) a
  caller invokes it (the harness, `mantis-plan`, or `mantis-researcher`), and
  (2) `CODE_ROOT` is resolved. It never fails — it simply returns an empty index
  if tools are unavailable or source cannot be parsed.
- **Idempotency Guarantee**:
  - Read-only on `CODE_ROOT`. Writes only to STATE-RELATIVE paths. Re-running
    with the same `CODE_ROOT` and `SNAPSHOT_ID` produces an identical
    `structural_index.json`.

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

### Step 1: Check Tool Availability

1. Try `import tree_sitter_languages` first (full AST parsing — most accurate).
2. If unavailable, fall back to
   `subprocess.run(["ctags", "-R", "--output-format=json", CODE_ROOT])` (symbol
   table only — less precise but zero-dependency).
3. If neither is available, fall back to an empty index (notify the caller: "No
   structural analysis tool available — returning empty index. Structural
   context unavailable, falling back to grep-based discovery.").

### Step 2: Write and Run Helper Script

1. Write a reusable helper script to
   `workspace/helpers/build_structural_index.py`. The FIRST LINE of the script
   MUST be exactly `# MANTIS_HELPER_VERSION = 2`. Before reusing an existing
   helper, grep its first lines for `MANTIS_HELPER_VERSION = 2`; if that marker
   is absent or a different integer (a helper left by an older pipeline
   version), REGENERATE the helper.
2. The script must parse all source files under `CODE_ROOT` and extract:
   - **Function definitions**: `name`, `signature`, `start_line`, `end_line`.
   - **Call sites**: `caller` (enclosing function), `callee` (called function
     name), `line`.
   - **Callers**: for each function, the list of functions that call it (reverse
     call graph).
3. The script should use whichever tool was detected in Step 1:
   - **tree-sitter**: Parse each file with the appropriate language grammar.
     Walk the AST to extract function definitions and call expressions.
   - **ctags**: Parse the JSON output to extract function definitions (name,
     line). Call-site extraction is limited with ctags — use a lightweight regex
     pass over the source for `identifier(` patterns within known function
     boundaries.
4. Execute the script with `CODE_ROOT` as an argument. The script outputs a JSON
   object to stdout.
5. The script MUST use ABSOLUTE paths and set its own working directory (Block A
   step 6). It MUST NOT write anything under `CODE_ROOT` when `snapshot_pinned`
   is true (Block A step 4).

### Step 3: Write `structural_index.json`

1. Capture the JSON output from the helper script.
2. Add provenance fields to the JSON object (these are top-level keys merged
   into the same JSON, NOT a separate prepended line):

```json
{
  "_provenance": true,
  "snapshot_id": "<SNAPSHOT_ID or 'unknown'>",
  "tool": "tree-sitter"
}
```

3. Write the complete index to `workspace/kb/structural_index.json`
   (STATE-RELATIVE — NEVER under `CODE_ROOT`).
4. The `tool` field records which backend was used (`"tree-sitter"` or
   `"ctags"`), so consumers know the precision level.

### Step 4: Return Results / Notify Caller

1. Return the path to `structural_index.json` and a summary (function count,
   call-site count, tool used).
2. If the index is empty (no tools available or no source files found), notify
   the caller: "Structural index is empty — structural context unavailable."
3. Do not notify the user directly — this skill is invoked as a sub-agent by the
   harness, planner, or researcher.

## `structural_index.json` Format

```json
{
  "_provenance": true,
  "snapshot_id": "abc123",
  "tool": "tree-sitter",
  "functions": {
    "src/parser.c:parse_input": {
      "start_line": 45,
      "end_line": 120,
      "signature": "int parse_input(char *buf, size_t len)",
      "calls": ["malloc", "validate_input", "memcpy"]
    }
  },
  "call_sites": {
    "malloc": [
      {"file": "src/parser.c", "line": 78, "caller": "parse_input"}
    ]
  },
  "callers": {
    "parse_input": [
      {"file": "src/main.c", "line": 203, "caller": "main"}
    ]
  }
}
```

**Top-level fields:**

| Field         | Type   | Description                                       |
| ------------- | ------ | ------------------------------------------------- |
| `_provenance` | bool   | Always `true` — marks this as a provenance header |
| `snapshot_id` | string | `SNAPSHOT_ID` the index was built against         |
| `tool`        | string | `"tree-sitter"` or `"ctags"`                      |
| `functions`   | object | Map of `"file:function"` → function metadata      |
| `call_sites`  | object | Map of `callee` → array of call-site objects      |
| `callers`     | object | Map of `function` → array of caller objects       |

**Function metadata fields:**

| Field        | Type   | Description                                             |
| ------------ | ------ | ------------------------------------------------------- |
| `start_line` | int    | First line of the function definition                   |
| `end_line`   | int    | Last line of the function definition                    |
| `signature`  | string | Function signature (return type + name + parameters)    |
| `calls`      | array  | List of function names called from within this function |

**Call-site / caller object fields:**

| Field    | Type   | Description                          |
| -------- | ------ | ------------------------------------ |
| `file`   | string | Source file (SNAPSHOT-RELATIVE path) |
| `line`   | int    | Line number of the call site         |
| `caller` | string | Name of the enclosing function       |

## Snapshot Safety

1. **Build from `CODE_ROOT`, not live tree.** The structural index is built from
   the pinned snapshot, ensuring it reflects the exact bytes the pipeline is
   analyzing. Never build from a live, mutable repository root.
2. **Rebuild when `SNAPSHOT_ID` changes.** The provenance header records
   `snapshot_id`. Consumers compare it to the current pass's `SNAPSHOT_ID`:
   - If they match → index is current.
   - If they differ → index is stale. The caller should rebuild or treat
     structural hints as advisory only.
   - If `active_snapshot` is absent (MODE-OFF) → skip the rebuild (no
     `CODE_ROOT` to build from). Return empty index.
3. **STALE flag in HALT mode.** When `snapshot_pinned` is false (HALT), the
   index may be built from the unpinned `CODE_ROOT` but should be marked as
   potentially stale. Consumers treat structural hints as advisory.
4. **Skip in MODE-OFF.** When `active_snapshot` is absent, there is no pinned
   snapshot to build from. Return an empty index and notify the caller.

## Per-Skill Augmentation Guidance

These are runtime instructions for callers — they do NOT modify any skill files.
The structural index is an opt-in enhancement; skills that do not use it behave
exactly as they do today.

### mantis-plan

- Use the structural index for function-level dependency fan-out. When planning
  investigations, consult `callers` and `call_sites` to identify all functions
  that call into a target — this broadens the audit set beyond single-file
  analysis.
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

## Safety Properties

Safety guardrails are defined in Guideline 9G of the Pipeline Adapter
([../SKILL.md](../SKILL.md#g-safety-guardrails-9)). Key properties:

- **Opt-in / default off.** When not invoked, the pipeline behaves exactly as it
  does today.
- **Coverage HINTs only.** The structural index decides ORDER, never MEMBERSHIP
  of the audit set.
- **Fallback on failure.** tree-sitter -> ctags -> empty index -> grep fallback.
- **Snapshot-aware.** Built from pinned CODE_ROOT, rebuilt on SNAPSHOT_ID
  change.
- **Read-only on CODE_ROOT.** The helper script only reads source files.

See the Pipeline Adapter for the full invariant analysis.

---
name: mantis-summarize
description: >-
  Pre-processes the repository by generating security-focused summaries (mantis-summary.md) for each directory to make planning and research more efficient.
  Use when starting a review campaign to map the codebase before threat modeling and planning.
  Don't use for executing code reviews, writing test scripts, or patching code.
---

# Summarizer (/mantis-summarize)

## System Goal

Repository Mapper. Automates the generation of security-focused, deterministic
summaries of directory contents to reduce token overhead for downstream planning
and research stages.

## Command Definition

- **Command:** `/mantis-summarize`
- **Description:** Pre-processes the repository by generating security-focused
  summaries (`mantis-summary.md`) for each directory to make planning and
  research more efficient.
- **Arguments (optional; supplied by the orchestrator, consumed by Block A):**
  `--snapshot_root`/`--snapshot_id`/`--state_root`. In PINNED mode, source is
  read under CODE_ROOT but summaries are skipped (see Output location). All
  absent → MODE-OFF (in-tree summaries, as today).

## Input/Output Contract

- **Reads**:
  - `workspace/.mantis_state.json` (to track current loop pass).
  - Codebase directories and source files (excluding `node_modules`, `vendor`,
    `.git`, build outputs, and `tests/`).
  - Child directory summaries (`mantis-summary.md` files from subdirectories).
  - `workspace/historical_learnings.jsonl` (optional, to enrich summaries).
- **Writes**:
  - Traversal script to workspace.
  - MODE-OFF: `mantis-summary.md` in each source directory (as today). PINNED:
    skipped (see Output location).
- **Preconditions**:
  - Source files and directory structure must be present.
- **Idempotency Guarantee**:
  - Deterministically overwrites existing `mantis-summary.md` files in-place
    with updated rollups.

## Instructions

### Step 0: Locator Resolution + output location (run first)

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

Output location (MANDATORY):

- PINNED mode (snapshot_pinned true): summaries are **skipped** this pass. In
  PINNED mode, CODE_ROOT is read-only (Block A step 4), and consumers (plan,
  history, researcher) read `mantis-summary.md` from the source directory in the
  code tree — not from a state-relative mirror. Writing to a mirror that no
  consumer reads would silently waste the work. Do NOT write any
  `mantis-summary.md` files in PINNED mode. (If a future change wires consumers
  to the mirror + re-maps via a provenance marker, this can be revisited; for
  now, PINNED-mode summaries are inert.)
- HALT mode (active_snapshot present + snapshot_pinned=false): behave as
  MODE-OFF (write `mantis-summary.md` into each source directory). The snapshot
  is not read-only (no immutable copy was pinned), so writing into the tree is
  safe.
- MODE-OFF (no `active_snapshot` — today's default): behave exactly as today —
  write `mantis-summary.md` into each source directory.
- In all modes except PINNED, `mantis-summary.md` files must remain invisible to
  every VCS dirty check and be deleted from the target tree before any sync (the
  meta-agent enforces this in Block C STEP 0). Never let a summary make the tree
  look dirty.

Your task is to write and execute a script that will traverse the repository
directory tree and create a `mantis-summary.md` file in each directory
containing source code.

This is an **optional pre-processing phase** designed to drastically reduce the
context window size required for the strategist (`/mantis-plan`), and provide a
quick reference map for researchers (`/mantis-researcher`).

Execute the summarize stage as follows:

1. **Write the Traversal Script (Bottom-Up Hierarchical):** Write a script
   (e.g., Python or bash) in your workspace that walks the repository directory
   tree using a **bottom-up (post-order) traversal**.

   - The script must ignore non-source-code directories such as `node_modules`,
     `vendor`, `.git`, build outputs, and `tests/`.
   - By traversing bottom-up, the script ensures that subdirectories are
     summarized *before* their parent directories.
   - When analyzing a directory, the script should pass the LLM the local source
     files in that directory **PLUS** the `mantis-summary.md` files of its
     immediate subdirectories. Do not pass the raw source files of
     subdirectories to the parent.
   - When analyzing very large directories, context window size might become a
     problem. Instead of passing files and directory summaries in bulk, generate
     per-file summaries or operate in more efficient chunks to avoid passing too
     many tokens for the LLM to handle.

2. **Generate the Security Summary (Map-Reduce):** The script should read
   `workspace/historical_learnings.jsonl` (if it exists) to check for past
   vulnerabilities and security fixes associated with files in the current
   directory, and pass them in context. The script should instruct the LLM or
   agent tool to generate a concise, security-focused summary of the directory.
   To keep token lengths reasonable at higher levels of the directory tree, the
   LLM should abstract away lower-level details, focusing on the rolled-up
   architecture. The prompt used by your script should ask for:

   - **Core Components:** What are the primary files and subdirectories, and
     what do they do?
   - **API Endpoints & Exports:** What functions or classes are exposed to other
     modules?
   - **Trust Boundaries & External Inputs:** Does this directory handle
     untrusted data, network requests, or user input?
   - **Sensitive Operations:** Are there parsers, cryptographic functions, or
     memory management operations?
   - **Historical Vulnerabilities & Fixes:** What files or components in this
     directory have historical vulnerabilities or security-related fixes
     recorded in `workspace/historical_learnings.jsonl`? Summarize the past
     fixes, components affected, and vulnerability classes to highlight past
     regressions or recurring weaknesses.

   The summary must be a reasonable size to incorporate into work on larger
   problems, so aim for several thousand words or fewer.

3. **Output to `mantis-summary.md`:** In MODE-OFF (or HALT), write
   `mantis-summary.md` into the corresponding source directory (overwrite if
   present). In PINNED mode, do NOT write — summaries are skipped this pass (see
   Output location above). Never write into the read-only snapshot.

4. **Execute the Script:** Run the script you just wrote to generate all the
   summaries across the repository. Wait for it to finish successfully.

5. **Complete:** Summaries are now generated. Notify the user.

When complete, notify the user.

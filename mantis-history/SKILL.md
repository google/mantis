---
name: mantis-history
description: >-
  Analyzes the repository's version control system (VCS) history to extract past vulnerabilities, security fixes, and vulnerability patterns.
  Use as an initial pre-processing step to build a historical vulnerabilities database (workspace/historical_learnings.jsonl) that informs subsequent stages about past issues and fixes.
  Don't use for code reviews, writing test scripts, or patching code.
---

# History Analyzer (/mantis-history)

## System Goal

Historical Vulnerability Extractor. Analyzes repository's version control system
(VCS) history to extract past vulnerabilities, security-related fixes, patches,
and associated files, creating a historical learnings database to inform
downstream skills.

## Command Definition

- **Command:** `/mantis-history`
- **Description:** Analyzes repository's version control system (VCS) history to
  extract past vulnerabilities and fixes, producing a structured historical
  learnings file (`workspace/historical_learnings.jsonl`).
- **Arguments (optional; supplied by the orchestrator, consumed by Block A):**
  `--snapshot_root`/`--snapshot_id`/`--state_root`. History reads VCS logs from
  the LIVE repository root (Block A step 5), not the snapshot; it uses
  `--state_root` only to place its cache/output/script. All absent -> DEGRADED
  (behaves as today, live cwd).

## Input/Output Contract

- **Reads**:
  - `workspace/.mantis_state.json` (to track current loop pass).
  - Codebase directory structure and key files (to determine stack).
  - VCS history logs (commit messages, titles, diffs).
  - `mantis-summary.md` (optional, if available).
  - Internal history analysis cache (optional, if exists).
- **Writes**:
  - VCS extraction script (written on-the-fly to workspace).
  - `workspace/historical_learnings.jsonl`.
  - Internal history analysis cache.
  - All under `--state_root/workspace/` (cache, `historical_learnings.jsonl`,
    extraction script): kept outside the target tree. Optional `history_status`
    marker (`UNSUPPORTED_VCS` / `PARTIAL_SHALLOW`).
- **Preconditions**:
  - Target repository and VCS logs must be accessible.
- **Idempotency Guarantee**:
  - The cache is the source of truth: the output DB is rebuilt from it every run
    and is never truncated to empty while the cache is non-empty. The cache is
    invalidated on VCS-history rewrite (`_analyzed_head` no longer reachable) or a
    vcs_type/repo-identity change. On `none`/`unknown` VCS the stage writes an
    empty DB + `history_status=UNSUPPORTED_VCS` and exits.

## Instructions

### Step 0: Locator Resolution (run first)

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

CRITICAL for history: the pinned snapshot copy STRIPS `.git`/`.hg`/`.repo`, so
per Block A step 5 you MUST run every VCS log / diff / blame command in the LIVE
repository root (the working directory Mantis was launched in), NOT under
CODE_ROOT. Do NOT stop because CODE_ROOT lacks VCS metadata. Write the cache,
`workspace/historical_learnings.jsonl`, and your generated extraction script
under `--state_root/workspace/` (STATE-RELATIVE) — never into the target tree,
so a sync/clean cannot wipe them. Record `active_snapshot.snapshot_id` on entries
only for provenance.

Your task is to analyze the codebase architecture, determine what constitutes
security-relevant history, and write a script on-the-fly to extract and document
historical vulnerabilities from the project's version control system (VCS).

Execute the history analysis stage as follows:

1. **Phase 1: Analyze Codebase and Define Target History:**

   - Read existing summaries (e.g. `mantis-summary.md` if available) or quickly
     inspect the root codebase structure to understand the primary files,
     programming languages, and core components.
   - Determine what types of historical security issues (e.g., memory
     corruption, authentication bypass, SQL injection, buffer overflow, or
     others) are relevant to this project and what keywords or commits should be
     targeted.

2. **Phase 2: Write a History Extraction Script:**

   - **VCS-support guard (run BEFORE writing/executing the script):** Determine
     `vcs_type` from `.mantis_state.json` `vcs_info` (or detect it in the LIVE
     root). If `vcs_type` is `none` or `unknown`, OR the VCS history is otherwise
     unreachable: write an EMPTY `workspace/historical_learnings.jsonl`, set a
     top-of-file / sidecar marker `history_status = "UNSUPPORTED_VCS"`, and EXIT —
     never fabricate history. For `multi-vcs` (.repo): either iterate history per
     sub-project, or write the empty file with `history_status = "UNSUPPORTED_VCS"`
     rather than run a git-shaped script that errors. For a SHALLOW git clone
     (`git rev-parse --is-shallow-repository` == true): proceed but set
     `history_status = "PARTIAL_SHALLOW"` so downstream stages do NOT read
     "no historical vuln for this file" as "clean."

   - Read the active pass number from the state file
     `workspace/.mantis_state.json` and resolve the current ISO 8601 timestamp.
   - Write a script (e.g. Python, bash, or your choice) directly in your
     workspace that interacts with your repository version control system (VCS)
     history logs.
   - **Cost-Efficiency & Scale Optimization:** To ensure the historical analysis
     remains cost-effective and runs efficiently, the script must implement the
     following optimizations:
     - **Commit Message/Description Pre-filtering:** Before retrieving diffs,
       the script should dynamically determine relevant keywords for commit
       message screening. It can do this by first inspecting the repository's
       files and languages/domains in scope to establish its primary stack (e.g.
       software versus hardware/RTL), then either querying an LLM/analysis agent
       for a tailored list of security/bug keywords or using a broader set of
       keywords augmented with these specific domain terms. Skip revisions whose
       messages or titles do not match these relevant keywords to avoid
       unnecessarily retrieving and analyzing changesets that are irrelevant to
       the codebase in scope.
     - **Diff Filtering and Size Limits:** Ignore commits that only touch
       non-production code (e.g., tests, documentation, or configuration files).
       Skip commits with excessively large diffs (e.g., more than several
       thousand lines changed), as they are usually automated formatting changes
       or massive refactorings rather than discrete security patches.
     - **Caching Results (cache is the source of truth):** Maintain a local cache
       (JSON or SQLite) under `workspace/` mapping `revision_id -> analyzed`, AND
       storing the full extracted record for each analyzed revision plus an
       `_analyzed_head` high-water mark and the `vcs_type` + repo identity the
       cache was built against. On each run, REBUILD
       `workspace/historical_learnings.jsonl` from the cache (do NOT skip a
       revision merely because the cache says "analyzed" and then leave the output
       empty — that is the desync bug). NEVER truncate a non-empty output DB to
       empty. Only analyze revisions NEWER than `_analyzed_head`.
       **Rewrite detection:** before trusting the cache, verify `_analyzed_head`
       still resolves in the current LIVE history (git: `git cat-file -e
       <_analyzed_head>` succeeds AND `git merge-base --is-ancestor <_analyzed_head>
       HEAD`; hg: `hg log -r <_analyzed_head>` succeeds). If it does not (force-push
       / rebase / squash) OR `vcs_type`/repo identity changed, INVALIDATE the cache
       and re-extract from scratch.
     - **Batch Processing (Batching Diffs):** Instead of making one LLM call per
       commit diff, the script should batch multiple commit diffs and messages
       (e.g. 3 to 5 commits) into a single LLM call. Ask the LLM to analyze all
       commits in the batch and return a JSON array of findings for the batch,
       reducing request overhead and cost.
     - **Model Selection:** Use lightweight and cost-efficient models for the
       initial commit analysis/filtering, and only fall back to heavier model
       tiers if deeper verification of a suspected vulnerability is needed.
   - **Detailed Analysis:** For revisions or commits that look
     security-relevant, the script should retrieve the commit diffs and
     messages/change descriptions.
   - **LLM/Agent Analysis:** The script should make API calls (e.g., via
     subagent messages or Agent API subcommands) or use an LLM subagent to
     analyze the changes' diffs and messages to determine whether a
     revision/commit was a security fix, what component was affected, the
     vulnerability type, impact, and the mitigation diff. Make sure it uses
     batching and caching to minimize API calls.
   - **Missing Information:** Do not overindex on the lack of security-related
     keywords. Many security fixes do not get CVEs, and many security
     vulnerabilities are fixed without realizing they were vulnerabilities.
   - **Output Format:** Instruct your script to output the extracted findings
     into a JSONL file named `workspace/historical_learnings.jsonl`, matching
     the following format:

### Historical Learnings Schema Format (`workspace/historical_learnings.jsonl`)

```json
{
  "revision_id": "...",
  "title": "...",
  "description": "...",
  "code_paths": ["file:line_number"],
  "vuln_type": "...",
  "mitigation_diff": "...",
  "cve": "...",
  "history": [
    {
      "stage": "history_extractor",
      "action": "created",
      "details": "Extracted from repository revision history.",
      "pass_number": <current_pass_number>,
      "timestamp": "<current_iso8601_timestamp>"
    }
  ]
}
```

1. **Phase 3: Execute and Verify:**
   - Run the script you just wrote to analyze the VCS history, process
     revisions, and generate the `workspace/historical_learnings.jsonl` file.
   - Wait for the script to finish and verify that
     `workspace/historical_learnings.jsonl` has been written successfully and
     contains extracted data.

When complete, notify the user.

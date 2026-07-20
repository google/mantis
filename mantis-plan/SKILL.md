---
name: mantis-plan
description: >-
  Formulates a targeted defensive security reviewing plan based on the active threat model and historical learnings.
  Use when starting a security review campaign to map the codebase boundaries and generate a roadmap (workspace/plan.json).
  Don't use for executing code reviews, writing test scripts, or patching code.
---

# Strategist (/mantis-plan)

## System Goal

Security Architect. Analyzes code structure, directory metadata, and historical
records to map the external boundary and formulate an adaptive review roadmap.

## Command Definition

- **Command:** `/mantis-plan`
- **Description:** Formulates a targeted defensive security reviewing plan based
  on the active threat model and historical learnings.
- **Arguments (optional; supplied by the orchestrator, consumed by Block A):**
  - `--snapshot_root` / `SNAPSHOT_ROOT`: absolute path to the pinned read-only
    code snapshot (CODE_ROOT for all snapshot-relative paths).
  - `--snapshot_id` / `SNAPSHOT_ID`: the pass snapshot identifier (sentinel +
    Block B comparisons).
  - `--state_root`: absolute path to the `workspace/` state dir (plan.json,
    .mantis_state.json, findings/, kb/, archive/). STATE-RELATIVE — never
    prefixed with CODE_ROOT.
  - All flags absent -> MODE-OFF/legacy mode (Block A step 1d): behaves exactly
    as today.

## Input/Output Contract

- **Reads**:
  - `workspace/.mantis_state.json` (to track current loop pass).
  - `workspace/kb/THREAT_MODEL.md` (if exists).
  - `workspace/kb/index.md` (checks existence to determine Mode A vs B).
  - Mode A: traverses production directories and source files, reads
    `mantis-summary.md` (if available).
  - Mode B: reads `workspace/kb/index.md`, `workspace/kb/THREAT_MODEL.md`,
    `workspace/archive/.repro_attempts.json` (if exists), VCS diffs or file
    timestamps/hashes.
  - `workspace/.mantis_state.json` NEW fields:
    `active_snapshot.{snapshot_id, snapshot_pinned, vcs_type}`,
    `snapshot_history` (read, written by the meta-agent). `vcs_type` is read
    because Block E branches on it. Plan runs Block E in the LIVE repo root to
    compute `changed_files` / `changed_files_status` (COMPUTED or UNKNOWN) and
    writes them back to state.
- **Writes**:
  - `workspace/plan.json`.
  - Copies retry-eligible finding JSON files from
    `workspace/archive/findings_pass_K/` or `workspace/archive/loopK_findings/`
    (where K is the pass it was archived in) to `workspace/findings/`
    (preserving their original UUID filenames).
- **Preconditions**:
  - Codebase must be accessible.
- **Idempotency Guarantee**:
  - Overwrites `workspace/plan.json` directly. In Mode B, copies a finding back
    verbatim only when Block B is MATCHED and its file is unchanged and present;
    otherwise it schedules a fresh re-discovery investigation. Consults
    `.repro_attempts.json` under the cache read rule.

## Instructions

### Step 0: Locator Resolution (run before everything else)

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

> [!NOTE] **CURRENT-PASS CHECK (defensive; the binding guarantee is on the
> harness per `mantis-pipeline-adapter` Scenario 2):** if `active_snapshot` is
> present AND `active_snapshot.pass != state.pass_number`, treat the snapshot as
> STALE for this pass — STOP "stale active_snapshot: pass mismatch" or degrade
> as HALT (`snapshot_pinned` effectively false: no authoritative verdicts, Block
> B NOT_MATCHED, reproduce `not_attempted`). This catches a custom harness that
> preserved `active_snapshot` across the Stage 15 pass increment without
> re-pinning. The reference meta-agent re-pins every pass, so this check never
> fires there. Block B itself cannot detect this (it is `snapshot_id`-only, not
> `pass`-aware).

Skill-specific notes for the strategist:

- Plan is a CODE-READING stage in Mode A (it crawls production directories); the
  findings-only skip does NOT apply.
- Mode A crawling and every `target_files` path are SNAPSHOT-RELATIVE: crawl and
  resolve them under CODE_ROOT.
- `workspace/kb/`, `workspace/plan.json`, `workspace/.mantis_state.json`,
  `workspace/archive/`, and `workspace/findings/` are STATE-RELATIVE: read/write
  them under --state_root, NEVER under CODE_ROOT.
- Never write, compile, or generate under CODE_ROOT (Block A step 4). The plan
  script writes ONLY workspace/plan.json (state-relative). The VCS diff in Block
  E runs in the LIVE repo root per Block A step 5, NOT CODE_ROOT.

Analyze the repository structure and create a detailed defensive security review
plan that avoids duplication of prior efforts while digging deep into complex
inter-procedural paths and un-scanned code boundaries.

> **Target Agnosticism Directive:** The target you are evaluating may be raw
> source code, a compiled binary, a firmware blob, or a live staging/dev
> endpoint. Ground your planning in whatever format the target is currently in.
> You are authorized and encouraged to use whatever suitable tools are at your
> disposal (e.g., standard Unix tools, `unblob`, `radare2`, `angr`, `objdump`,
> `Ghidra`, `qemu`, `unicorn`) to explore the artifact structure. If source code
> is not available, do not attempt to force a source-code workflow (e.g.
> searching for `.c` or `.py` files); adapt and 'do what works' for the artifact
> at hand.

Execute the planning stage as follows:

1. **Check for Threat Model Context:** Check the knowledge base directory for a
   `workspace/kb/THREAT_MODEL.md` file. If it exists, read the file it
   completely to understand the program's official security boundaries, threat
   actors, assets, high-risk interfaces, and trusted inputs.

2. **Determine Mode & Retrieve Learnings:** Check if the knowledge base index
   `workspace/kb/index.md` exists.

   - **MODE A: First-Pass Exhaustive Mode (No `workspace/kb/index.md` found):**
     If this is the first run, guarantee complete coverage of the codebase. To
     avoid hitting output token limits on large repositories, do not generate
     the `workspace/plan.json` manually in your text response. Instead, execute
     a shell command to run a short script in your preferred language that:

     1. Uses `find` or `os.walk` to crawl all production directories. If a
        `mantis-summary.md` file exists in a directory, use its contents to
        understand the directory structure instead of reading every individual
        source file. Otherwise, crawl all production source code files (e.g.,
        `.c`, `.cpp`, `.py`, `.js`, `.go`, `.rs`, `.java`).
     2. Ignores test folders, build artifacts, and vendor dependencies (e.g.,
        `node_modules`, `.git`, `tests/`).
     3. Programmatically formats the list into the `workspace/plan.json` schema
        and writes it directly to disk. Because this is an automated script,
        instruct it to use a generic, overarching baseline question for the
        `"question"` field (e.g., "Conduct a baseline audit for memory safety
        and logic flaws"), reserving highly contextual custom questions for Mode
        B.

   - **MODE B: Strategic Learning Mode (`workspace/kb/index.md` exists):** Read
     `workspace/kb/index.md` and `workspace/kb/THREAT_MODEL.md` to review the
     compounded historical knowledge of the codebase, including trust
     boundaries, vulnerability classes, and architectural components. Adapt your
     focus to design new, targeted deep dives and regression reviews for
     components and files that have histories of vulnerabilities. You may
     generate the `workspace/plan.json` manually using your file-writing tools
     for this mode, as the scope will be much narrower.

     - **Targeted Re-Evaluation & Retries**: Review the KB index, entity files,
       and the reproduction attempt cache file
       (`workspace/archive/.repro_attempts.json` if it exists). You must
       identify findings that need re-evaluation or retries:

       Also read the snapshot context from `workspace/.mantis_state.json`:
       `active_snapshot.{snapshot_id, snapshot_pinned}` and `snapshot_history`
       (both written by the meta-agent). Then COMPUTE `changed_files` /
       `changed_files_status` for THIS pass by running Block E below in the LIVE
       repository root (per Block A step 5 — VCS-metadata carve-out; the pinned
       --snapshot_root strips .git/.hg/.repo, so the diff MUST run against the
       live tree). Write the computed `changed_files` (array of repo-relative
       paths) and `changed_files_status` (`COMPUTED` or `UNKNOWN`) back to
       `workspace/.mantis_state.json`, then use them for the rest of the stage.
       Also write `changed_files_pass` = the current `pass_number` from state,
       so consumers can detect a stale (prior-pass) diff. Use the following to
       know which files changed since the previous pass:

       CHANGED-SINCE-PREVIOUS: run in the LIVE repository root (NOT
       SNAPSHOT_ROOT). CUR = current commit/revision; PREV = snapshot_history
       entry BEFORE this pass. If PREV missing OR vcs_type in {none,unknown} OR
       the SNAPSHOT_ID for prev or cur is a content:/live:/+content_hash
       fallback OR the diff command errors -> changed_files_status = UNKNOWN.
       Treat EVERY file as CHANGED. NEVER treat as unchanged. NEVER drop. (Note:
       `snapshot_pinned false` alone is NOT a trigger for UNKNOWN — in HALT
       mode, `active_snapshot` is present and `snapshot_history` has a PREV
       entry, so the diff can still run. In MODE-OFF — no `active_snapshot` —
       there is no PREV entry, so PREV is missing and the diff degrades to
       UNKNOWN, but this does NOT force a full Mode-A crawl; see the Mode-A
       trigger below.) Else: git :
       `git diff --name-status -M -C --diff-filter=RAMDCT PREV CUR` (the `-M`
       flag detects renames; `-C` detects copies; `--name-status` outputs
       `R<score>\told_path\tnew_path` for renames so both old and new paths are
       visible; `--diff-filter=RAMDCT` includes Renamed, Added, Modified,
       Deleted, Copied, and Type-changed files) hg :
       `hg status -C --rev PREV:CUR` (`-C`/`--copies` shows the source path on a
       following line for renames/copies; hg codes: A=added, R=removed,
       M=modified) multi-vcs :
       `repo forall -c 'git diff --name-status -M -C --diff-filter=RAMDCT PREV CUR'`
       (any error -> UNKNOWN) A finding's file is CHANGED if any of its
       `code_paths` (path part) is in the set, OR if its path was renamed-to or
       renamed-from (parse `R<score>\told\tnew` lines: both old and new paths
       are in the changed set). If a finding's primary file appears as a rename
       source (old path), treat the NEW path as changed too — the bug likely
       moved with the file.

       Also apply this cache read rule wherever you inspect
       `workspace/archive/.repro_attempts.json`. FIRST pick the cache KEY
       exactly the way `mantis-reproduce` writes it: if the finding has a
       `signature` field, the key is that `signature`; otherwise the key is
       `stable_key = normalized_title + "@" + primary_file_path` (title
       lowercased with all non-alphanumerics removed; `primary_file_path` =
       first `code_paths` entry with any trailing `:line` stripped). THEN read
       the value V under that key: if V is an integer then count=V and
       last_snapshot=UNKNOWN; if V is an object then count=V.count and
       last_snapshot=V.last_snapshot (default UNKNOWN). If no entry is found
       under the chosen key, also try the OTHER key form before concluding
       count=0, so a signature-keyed writer and a stable_key reader never miss
       each other and wrongly reset the attempt budget. (The cache mixes both
       value forms AND both key styles during migration.)

       1. **Schedule for Research:** For findings in the archive marked
          `"NEEDS_RESEARCH"`, schedule a targeted investigation in
          `workspace/plan.json` (to gather missing context and resolve them to
          `"VALID"` or `"FALSE_POSITIVE"`).

       2. **Copy for Retry (snapshot-gated) or Re-discover:** For each archived
          finding that would otherwise be retry-eligible (repro not attempted,
          or `failed_to_reproduce` with fewer than 2 attempts per the cache read
          rule above, or `patch_status` in
          {`VERIFICATION_FAILED`,`ERROR`,`VERIFICATION_INCOMPLETE`}), run:

          ```
          SNAPSHOT MATCH CHECK for finding F (decides MATCHED vs NOT_MATCHED):
          1. If snapshot_pinned is false -> NOT_MATCHED. Stop.
          2. Read F.discovery_commit:
             - missing OR empty OR the literal "MIXED" -> NOT_MATCHED.
             - not exactly equal to SNAPSHOT_ID          -> NOT_MATCHED.
             - exactly equal to SNAPSHOT_ID              -> MATCHED.
          There is no other route to MATCHED; never fuzzy-compare. The global "default the
          field and proceed" backward-compat rule does NOT apply to discovery_commit:
          absent = NOT_MATCHED. (There is NO separate "dirty" gate: a dirty tree's
          SNAPSHOT_ID already embeds the working-tree content hash, so within-pass findings
          MATCH and cross-pass bare-commit findings do not.)
          ```

          Then decide mechanically:

          - **COPY VERBATIM** (fast retry) ONLY if ALL hold: Block B is MATCHED
            for the finding, AND its primary file (first `code_paths`, line
            stripped) is NOT in `changed_files`, AND that file EXISTS under
            CODE_ROOT. Copy the archived `<uuid>.json` back to
            `workspace/findings/<uuid>.json` preserving the UUID **and its
            ORIGINAL `discovery_commit`** (do not re-stamp it — drift must stay
            detectable).

          - **MODE-OFF bypass (3-state rule):** if `active_snapshot` is ABSENT
            in state (MODE-OFF — no `--sync` was requested), Block B always
            returns NOT_MATCHED (`snapshot_pinned is false -> NOT_MATCHED`), so
            the COPY-VERBATIM gate above never fires and every retry- eligible
            finding is RE-DISCOVERed — a regression from today's behavior
            (today, pass ≥2 carries forward unchanged findings when the file
            still exists). In MODE-OFF, COPY-VERBATIM when the finding's primary
            file (first `code_paths`, line stripped) EXISTS under CODE_ROOT
            (drop the `Block B MATCHED` and `file NOT in changed_files`
            conjuncts — there is no `changed_files` diff in MODE-OFF anyway).
            This mirrors `mantis-patch`'s LEGACY-mode carve- out
            (`patch:133-138`, `patch:172-174`). Do NOT gate the bypass on
            `snapshot_pinned==false` — that would also catch HALT mode, where
            the STALE banner legitimately marks the finding as needing
            re-verification. Gate ONLY on `active_snapshot` absent. (Do NOT
            change Block B itself — it is character-identical across skills per
            `README_AGENTS.md:711-718` block-fidelity warning; the fix goes in
            plan's CONSUMERS of Block B, not Block B.)

          - **RE-DISCOVER** in every other case (Block B NOT_MATCHED, or file in
            `changed_files`, or file missing, or
            `changed_files_status`==UNKNOWN): do NOT copy back. Instead append a
            fresh investigation to `workspace/plan.json` that embeds the
            finding's `title`, `description`, and `repro_hints`, sets
            `target_files` to the old code_paths' directory subtree(s) PLUS a
            repository-wide symbol/keyword search for the finding's
            function/struct/title terms (so a moved/renamed bug is re-found),
            and asks the researcher to re-derive the exact lines on the CURRENT
            snapshot. Additionally, record a history note
            `unconfirmed-regression-pending` on the archived finding so it is
            never silently dropped until a pass re-discovers it or a human
            dismisses it.

          - **Line/AST Re-anchoring (Phase 2 incremental efficiency):** Before
            falling back to full RE-DISCOVER, attempt to re-anchor the finding's
            line numbers to the CURRENT snapshot using forward line-tracking
            (reverse blame or diff-hunk offset). This is an optimization: if the
            finding's primary function/symbol still exists nearby, re-anchoring
            produces a line-number HINT that focuses the RE-DISCOVER
            investigation — it does NOT replace re-verification (the snapshot
            changed, so the finding is still re-researched downstream).

            - **How:** Translate the finding's old line FORWARD from PREV to CUR
              (do NOT blame PREV in isolation — that returns the line as of PREV
              and does not map it forward). Run in the LIVE repo root (Block A
              step 5 carve-out): git :
              `git blame --reverse <PREV>..<CUR> -L <old_line>,<old_line> -- <file>`
              (reverse blame follows the line forward to CUR), or add the hunk
              offset from `git diff <PREV> <CUR> -- <file>` to `<old_line>`.
              Then read the mapped line in CODE_ROOT (the current pinned
              snapshot) and confirm the finding's primary function/symbol is
              present within ±50 lines. This yields a CANDIDATE new line number
              only — a search hint for RE-DISCOVER, never a trusted
              re-validation.
            - **When re-anchoring SUCCEEDS** (symbol found at the mapped line):
              use the new line number to FOCUS this finding's RE-DISCOVER
              investigation (point the researcher at the mapped `code_paths`
              location first). Do NOT convert the finding to COPY-VERBATIM and
              do NOT skip re-verification: Block B is NOT_MATCHED, so the
              finding is still re-researched/re-reproduced downstream (a symbol
              can exist at the mapped line yet already be FIXED). Keep
              `discovery_commit`, `signature`, and `lineage_id` unchanged; add a
              history note
              `re-anchored: <old_line> -> <new_line> (search hint)`.
            - **When re-anchoring FAILS** (function deleted, symbol not found,
              diff too large, blame errors, or the code at the old line is
              completely different): fall back to full RE-DISCOVER as above.
              This is the conservative guardrail: on ANY uncertainty,
              re-discover.
            - **Never use re-anchoring to suppress or drop a finding.** It is
              purely a fast-path for line-number updates; if it fails, the
              finding is still re-discovered via the normal path.
            - **VCS-agnostic:** For hg, diff `PREV:CUR`
              (`hg diff --rev PREV:CUR -- <file>`) and apply the hunk offset to
              `<old_line>` to get the forward-mapped line. For no-VCS/binary
              targets, re-anchoring is not applicable; always fall back to
              RE-DISCOVER.

          - **NEVER copy back** a finding whose `"status"` is
            `"FALSE_POSITIVE"`, or `"patch_status"` is `"VERIFIED_SECURE"`, or
            `"repro_status"` is `"reproduced"` (unless patch failed as above),
            or that has reached the 2-attempt cap for the CURRENT snapshot. But
            if such a finding's file IS in `changed_files` or Block B is
            NOT_MATCHED, treat it as a possible regression: RE-DISCOVER it (do
            not trust the old terminal verdict against changed code). **MODE-OFF
            carve-out:** if `active_snapshot` is ABSENT (MODE-OFF), drop the
            `or Block B is NOT_MATCHED` disjunct above — in MODE-OFF, Block B is
            NOT_MATCHED for every finding (artifact of no snapshot, not a signal
            of drift), so leaving the disjunct in would re-open every terminal
            verdict (FALSE_POSITIVE/VERIFIED_SECURE/reproduced) every pass. In
            MODE-OFF, rely ONLY on `file IS in changed_files` (which is
            vacuously false in MODE-OFF — there is no `changed_files` diff), so
            terminal findings are carried forward unchanged. This is today's
            behavior.

     - **Changed / new attack-surface coverage (MANDATORY):** Add an
       investigation titled `Exhaustive Review: <path>` for EVERY path in
       `changed_files` (whether or not it maps to an archived finding). If
       `changed_files_status`==UNKNOWN AND `active_snapshot` is present (HALT or
       PINNED mode — a sync was requested this pass), OR a sync occurred this
       pass (`snapshot_id` != the previous `snapshot_history` entry's id), you
       CANNOT trust a narrow set: fall back to a full **Mode A** exhaustive
       crawl for this pass EVEN IF `kb/index.md` exists (this is the only way to
       catch newly added files). However, in MODE-OFF (no `active_snapshot` — no
       `--sync`), do NOT force a full Mode-A crawl in pass ≥2 even if
       `changed_files_status`==UNKNOWN: this is today's default behavior, and
       forcing Mode-A on every MODE-OFF pass ≥2 would be a regression. In
       MODE-OFF, rely on the existing `kb/index.md` (Mode B) for narrowing, as
       today.

     - **Dependency-aware fan-out (Phase 2 incremental efficiency):** When
       `changed_files_status` is known (not UNKNOWN) and a dependency graph is
       available, EXPAND the investigation scope beyond just the changed files
       themselves. The goal: identify files that IMPORT or DEPEND ON the changed
       files, so the planner can schedule targeted investigations for consumers
       of the changed code (not just the changed code itself).

       - **How:** Build or read a dependency graph from the `workspace/kb/`
         directory. If the KB contains an import/build graph (e.g.,
         `workspace/kb/dependencies.json` or entity-relationship markdown), use
         it to compute the transitive set of files that import or call into the
         changed files. For each changed file F, find all files that import F
         (directly or transitively up to 2 hops). Add these dependent files to
         the investigation scope as `Exhaustive Review: <dependent_file>`
         entries.
       - **When to use:** ONLY when `changed_files_status` is known AND the KB
         contains dependency information. If the KB lacks an import/build graph,
         or the KB is stale (check `kb_snapshot_id` in
         `workspace/.mantis_state.json` against `SNAPSHOT_ID` — if they differ,
         the KB was built against a different snapshot and may be stale), fall
         back to the Phase-1 behavior (full Mode-A crawl or Mode-B narrowing).
       - **Guardrail:** If the dependency graph is incomplete, stale, or any
         uncertainty arises, fall back to Phase-1 re-discovery (treat ALL files
         as potentially affected). Never use dependency narrowing to DROP an
         investigation — it can only ADD targeted investigations for dependent
         files. The changed files themselves are ALWAYS investigated regardless.
       - **VCS-agnostic:** The dependency graph is derived from the KB's
         architecture analysis, not from VCS metadata. It works for any language
         with import/include/use statements that the KB has indexed.

     - **Context Injection (`kb_references`):** For each investigation you plan,
       you must determine which files in the `workspace/kb/` directory (e.g.,
       `workspace/kb/entities/auth_module.md` or
       `workspace/kb/vulnerabilities/CWE-79.md`) provide necessary context for
       the researcher. Include the exact file paths to these markdown files in
       the `"kb_references"` array for that investigation. This shifts the
       burden of context-gathering off the researcher.

     - **Exploratory/Unconstrained Investigations (Moderate Probability):** With
       a moderate probability (e.g., a 25-50% chance per planning pass), include
       either an unconstrained adversarial sweep or a random exploration in the
       plan:

       1. **Adversarial Sweep:** Select a component or directory that the threat
          model currently marks as safe, low-risk, or out of scope. Instruct the
          researcher to perform an unconstrained sweep, ignoring safety
          assumptions in `workspace/kb/THREAT_MODEL.md`.

       2. **Random Digging:** Select a random starting position (file or
          directory) in the codebase. The question for this investigation should
          be minimal and open-ended, simply instructing the researcher to "dig
          into" or "explore" the selected area without specific threat-model
          context or pre-defined vulnerability classes. Set `kb_references` to
          an empty list for this investigation to ensure a fresh look.

       **Token Optimization:** Whether using a script (Mode A) or your
       file-writing tools (Mode B), write the plan directly to disk and do not
       print the JSON contents in your chat response.

3. **Schema Enforcement:** Regardless of the mode, the final
   `workspace/plan.json` file written to disk should match the following schema
   to ensure downstream auditing agents can parse it correctly:

### Plan Schema Format

```json
{
  "investigations": [
    {
      "title": "Exhaustive Review: [relative_file_path]",
      "target_files": ["[relative_file_path_1]", "[relative_file_path_2]"],
      "kb_references": ["workspace/kb/entities/auth_module.md", "workspace/kb/vulnerabilities/CWE-79.md"],
      "question": "Detailed reviewing prompt instructions asking the researcher to trace specific input pathways, variables, memory allocations, or function constraints."
    }
  ]
}
```

Ensure `workspace/plan.json` is successfully written. When you have finished,
notify the user.

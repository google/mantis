---
name: mantis-critic
description: >-
  Assesses the production viability of findings, filtering out debug-only features and assertion traps.
  Use when findings have been validated and you need to confirm they are triggerable in production release builds (with assertions disabled).
  Don't use for writing reproduction scripts or patches.
---

# Critic (/mantis-critic)

## System Goal

Production Viability Expert. Filters validated security findings to confirm if
they remain triggerable in standard release and production configurations.

## Command Definition

- **Command:**
  `/mantis-critic [--target_root=<path>] [--snapshot_root=<path>] [--snapshot_id=<id>] [--state_root=<path>]`
- **Description:** Assesses the production viability of findings, filtering out
  debug-only features and assertion traps.
- **Parameters:**
  - `--target_root`: AUTHORITATIVE path to the target codebase root. Overrides
    all other locator sources and is sentinel-exempt (Block A path 1a). Defaults
    to unset.
  - `--snapshot_root`: Path to the pinned, immutable snapshot copy for this pass
    (a.k.a. `SNAPSHOT_ROOT`). Used as CODE_ROOT when `--target_root` is unset
    (Block A path 1b).
  - `--snapshot_id`: The `SNAPSHOT_ID` the orchestrator computed for this pass.
    Used for the Block A sentinel check and for the per-finding Block B drift
    comparison in Step 3. If omitted, fall back to `active_snapshot.snapshot_id`
    from state.
  - `--state_root`: Path to the root of the Mantis state directory containing
    `workspace/` (defaults to `.`). Every `workspace/...` path in this file is
    resolved relative to `--state_root`; with the default `.` this is identical
    to today's `workspace/`.

## Input/Output Contract

- **Reads**:
  - `workspace/findings/` (loads all findings regardless of status; also reads
    each finding's optional `discovery_commit` for the per-finding snapshot
    match check).
  - `workspace/kb/THREAT_MODEL.md` (if exists, to check deployment intent and
    the KB's recorded `kb_snapshot_id`).
  - `workspace/.mantis_state.json` (to track current loop pass and to read
    `active_snapshot.{root,snapshot_id,snapshot_pinned}` for locator resolution
    and provenance).
  - Target source code files under the resolved CODE_ROOT (the pinned snapshot
    root when `snapshot_pinned`), at paths/lines in `code_paths` with contextual
    offset.
- **Writes**:
  - Updates findings in-place (sets `"production_viability"`,
    `"critic_reasoning"`, and appends history).
  - Appends to `workspace/learnings.jsonl`.
- **Preconditions**:
  - Findings must exist in `workspace/findings/`.
- **Idempotency Guarantee**:
  - Overwrites viability fields in place. It must check if a critic entry for
    the current pass is already recorded in the history array, and check
    `workspace/learnings.jsonl` to ensure it does not write duplicate records if
    run again on the same input.

## Instructions

Evaluate validated findings to determine if they represent actionable security
flaws in a compiled, optimized release build. **Adopt a highly skeptical,
adversarial stance. Do not trust the reasoning of previous stages. Re-verify the
code path independently to definitively prove or disprove production
viability.**

### Locator Resolution (do this first)

Critic is a CODE-READING stage (it inspects the target source), so it is NOT a
findings-only stage: run all of Block A. Resolve CODE_ROOT and the sentinel per
Block A before loading findings.

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

**SNAPSHOT_ID for this stage:** let `SNAPSHOT_ID` be the value of
`--snapshot_id` if provided, else `active_snapshot.snapshot_id` from
`workspace/.mantis_state.json`. If neither is present (no `--snapshot_id` AND no
`active_snapshot` in state), OR Block A resolved CODE_ROOT via path 1d (no args,
current dir), then SNAPSHOT_ID is UNAVAILABLE (MODE-OFF = today's default):
treat every Block B check in Step 3 as NOT_MATCHED and treat the KB freshness
gate in Step 2 as FAILED. Do NOT stop; degrade as described below. When
`active_snapshot` IS present but `snapshot_pinned` is false (HALT mode),
SNAPSHOT_ID is the recorded `live:` id and IS available — Block B still returns
NOT_MATCHED (snapshot_pinned is false), but the Step-3c "MODE-OFF exception"
below does NOT fire: a NOT_MATCHED result is treated as drift →
CONDITIONAL_VIABLE, never NON_VIABLE (which calibrate drops).

Execute the critic evaluation as follows:

1. **Load Findings:** Read the JSON files in the `workspace/findings/`
   directory. You must load all findings regardless of status (including
   `"VALID"`, `"FALSE_POSITIVE"`, `"PROVISIONALLY_VALID"`, and
   `"NEEDS_RESEARCH"`) so they can be processed or logged to long-term memory.
   If none exist, notify the user.

2. **Evaluate Global Repository Intent (KB-freshness gated):** Read
   `workspace/kb/THREAT_MODEL.md` (if it exists). Check the **Deployment
   Intent** section.

   **KB freshness gate — REQUIRED before any blanket mass-mark (3-state rule):**
   Determine the snapshot the KB was built against. Read it from ONE of these
   sources (try in order, first match wins):

   1. The literal `KB_SNAPSHOT:` token on the FIRST line of
      `workspace/kb/THREAT_MODEL.md` (threat-model writes this as a bare header;
      architecture writes comment-wrapped `<!-- KB_SNAPSHOT: ... -->` on each KB
      file). For architecture files, scan for the `KB_SNAPSHOT:` substring
      inside the comment. Do NOT look for `kb_snapshot_id:` or `Snapshot:` —
      those tokens are never written and the gate would never match.
   2. Else the `kb_snapshot_id` value in `workspace/.mantis_state.json` (which
      architecture writes in its state-stamp step).
   3. Else `""` (no prior KB provenance). The blanket mass-mark below is gated
      as follows:

   - **MODE-OFF** (no `active_snapshot` in state — no `--sync`): SKIP the
     freshness gate entirely. The blanket `SAMPLE_OR_TEST` mass-mark is
     permitted as today (byte-for-byte today's behavior) — the KB was built
     against the live tree and there is no snapshot to compare against.
   - **HALT or PINNED** (`active_snapshot` IS present): the blanket mass-mark is
     permitted ONLY if the recorded `KB_SNAPSHOT:` (or `kb_snapshot_id`) is
     present AND is byte-for-byte equal to the current `SNAPSHOT_ID` resolved in
     Locator Resolution above (no fuzzy compare). If it is missing, empty, or
     does not equal `SNAPSHOT_ID`, you MUST NOT mass-mark: skip this blanket
     action entirely and evaluate every finding individually in Steps 3-5.

   Only when the freshness gate passes (or is skipped in MODE-OFF): if the
   threat model explicitly states the entire repository is exclusively a
   tutorial, sample project, or test suite (e.g.,
   `Intent: SAMPLE_OR_TEST_ONLY`), you MUST mark all findings as
   **`SAMPLE_OR_TEST`** regardless of where they are located in the file
   structure, and skip the remaining per-finding viability checks.

3. **Acquire Targeted Code Snippets (snapshot-matched):** For each finding where
   `status` is `"VALID"` or `"PROVISIONALLY_VALID"` (skip this and the following
   evaluation steps for `"FALSE_POSITIVE"` or `"NEEDS_RESEARCH"` findings):

   a. **Resolve the target file** from the finding's `code_paths` per Block A
   step 3: `code_paths` are SNAPSHOT-RELATIVE, so read them under CODE_ROOT.
   Strip a trailing `:<digits>` to get the line number; `://` means a URL, not a
   file; any entry that is not `<path>:<int>` is a non-source LOCATOR — do an
   existence check only, with no line logic.

   b. **Snapshot Match Check (Block B):** compute MATCHED / NOT_MATCHED for this
   finding by comparing its `discovery_commit` against the current
   `SNAPSHOT_ID`.

   SNAPSHOT MATCH CHECK for finding F (decides MATCHED vs NOT_MATCHED):

   1. If snapshot_pinned is false -> NOT_MATCHED. Stop.
   2. Read F.discovery_commit:
      - missing OR empty OR the literal "MIXED" -> NOT_MATCHED.
      - not exactly equal to SNAPSHOT_ID -> NOT_MATCHED.
      - exactly equal to SNAPSHOT_ID -> MATCHED. There is no other route to
        MATCHED; never fuzzy-compare. The global "default the field and proceed"
        backward-compat rule does NOT apply to discovery_commit: absent =
        NOT_MATCHED. (There is NO separate "dirty" gate: a dirty tree's
        SNAPSHOT_ID already embeds the working-tree content hash, so within-pass
        findings MATCH and cross-pass bare-commit findings do not.)

   c. **Drift / missing-file / out-of-range guard (fail-safe — NEVER
   NON_VIABLE):** If Block B yields **NOT_MATCHED**, OR the resolved target file
   does not exist under CODE_ROOT, OR the designated line number is beyond the
   end of the file (out of range), then you MUST NOT run the domain-specific
   viability analysis (Steps 4-5) for this finding and you MUST NOT mark it
   `NON_VIABLE` (a missing file is not dead code; `NON_VIABLE` is the value that
   `mantis-calibrate` DROPS).

   **Exception (MODE-OFF only — no active_snapshot):** if SNAPSHOT_ID is
   UNAVAILABLE (MODE-OFF: no `active_snapshot` in state and no `--snapshot_id`)
   AND the sole cause of NOT_MATCHED is the missing/unavailable SNAPSHOT_ID (not
   a missing file or out-of-range line), treat it as "cannot compare" and fall
   through to normal evaluation (Step 3d). This preserves today's behavior for
   non-sync runs. In HALT mode (`active_snapshot` present,
   `snapshot_pinned=false`), this exception does NOT fire: Block B is
   NOT_MATCHED and the finding is drift → CONDITIONAL_VIABLE (the "Otherwise"
   branch below), never NON_VIABLE (which calibrate drops). The missing-file and
   out-of-range conditions still force CONDITIONAL_VIABLE regardless of pinning
   or mode.

   **Otherwise (drift, missing file, or out-of-range):** set
   `production_viability` = **`CONDITIONAL_VIABLE`** and write a
   `critic_reasoning` drift note naming the cause, e.g.:
   `"Snapshot drift: discovery_commit=<disc> != active SNAPSHOT_ID=<id> (or the target file/line is no longer present at the pinned snapshot); could not re-verify viability, defaulting to CONDITIONAL_VIABLE (conservative)."`
   Then record the update via Step 6 and continue to the next finding. (This
   finding is still logged to long-term memory in Step 7 as
   `CONDITIONAL_VIABLE`.)

   d. **MATCHED, file present, line in range:** read the target file from
   CODE_ROOT and read at least **15 lines of preceding context** and **15 lines
   of succeeding context** around the designated line numbers. This targeted
   window is necessary to analyze surrounding structures and macro definitions.
   Proceed to Steps 4-5.

4. **Evaluate Domain-Specific Viability Constraints:**

   - **For Memory Safety Flaws:** Locate the allocation source of the affected
     buffer. Determine if it is allocated with safety margins or trailing
     padding. If the out-of-bounds access is contained within physical padding,
     mark it **NON_VIABLE**.
   - **For Logic & Authorization Flaws:** Verify that the flawed logic or
     bypassed endpoint is actually accessible in standard production
     deployments. If the flaw relies on a debug-only backdoor, a mock
     authentication provider, or a test-only route, mark it **NON_VIABLE**.

5. **Determine Viability Status:** Assign one of the following viability
   statuses to the finding to ensure we prioritize correctly:

   - **`NON_VIABLE`**: The flaw is unreachable or compiled-out in production.
     This includes:
     - **Disabled Assertions (Memory Flaws):** Bugs that rely on standard
       `assert()`, `debug_abort()`, or development-only panics to trigger
       crash/DoS states, where `NDEBUG` strips them and the code returns safely.
     - **Debug-Only Features:** Conditionally compiled with debug flags (e.g.
       `#ifdef DEBUG`).
     - **Blocked by Environmental Controls:** Blocked by standard,
       non-configurable production environmental controls (e.g., OS-level
       permissions, kernel-level sandboxing, read-only filesystems) that cannot
       be bypassed.
   - **`SAMPLE_OR_TEST`**: The issue resides in example code, test suites,
     fuzzing harnesses, or validation frameworks.
   - **`CONDITIONAL_VIABLE`**: The flaw is exploitable only under specific,
     non-default configurations, optional compiler flags, or custom hardening
     options that may vary across production environments.
   - **`VIABLE`**: The flaw is fully triggerable in a standard
     release/production build.

6. **Token-Optimized File Updates:** To minimize LLM output tokens, **do not
   re-emit or manually rewrite the entire JSON object in your output.** Instead,
   use in-place editing tools (like a short script in your preferred language,
   or `jq`) to programmatically append the new fields to the existing
   `workspace/findings/<id>.json` file.

   You must append the following to the existing object:

   - A `"production_viability"` field (`"VIABLE"`, `"NON_VIABLE"`,
     `"SAMPLE_OR_TEST"`, or `"CONDITIONAL_VIABLE"`).
   - A `"critic_reasoning"` field explaining your evaluation.
   - An entry to the `"history"` array:

   ```json
   {
     "stage": "critic",
     "action": "evaluated",
     "details": "Determined production viability as [VIABLE/NON_VIABLE/SAMPLE_OR_TEST/CONDITIONAL_VIABLE] because [reason]",
     "pass_number": <current_pass_number>,
     "snapshot": "<SNAPSHOT_ID>",
     "timestamp": "<current_iso8601_timestamp>"
   }
   ```

   Set `"snapshot"` to the `SNAPSHOT_ID` resolved in Locator Resolution. If
   `SNAPSHOT_ID` is UNAVAILABLE (MODE-OFF), set it to `""` (or omit the key). Do
   not fabricate an id.

7. **Append to Long-Term Memory:** For each finding you loaded (including
   `NON_VIABLE`, `SAMPLE_OR_TEST`, `CONDITIONAL_VIABLE`, `FALSE_POSITIVE`, and
   `NEEDS_RESEARCH`), append a single structured JSON line to a workspace
   database file named `workspace/learnings.jsonl` (using append mode). This
   ensures validation outcomes are remembered across runs, helping the
   strategist avoid re-scanning them.

   - **Memory Entry Format:**
     `{"title": "[security_flaw_title]", "code_paths": ["[path1:line1]"], "status": "[VIABLE / CONDITIONAL_VIABLE / NON_VIABLE / SAMPLE_OR_TEST / FALSE_POSITIVE / NEEDS_RESEARCH]", "snapshot": "[current SNAPSHOT_ID, or omit in MODE-OFF]"}`

When complete, notify the user.

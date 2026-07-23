---
name: mantis-patch
description: >-
  Generates minimal security fixes using transactional isolation (shadow directories or file backups), applies patches, and verifies them.
  Use when security findings are successfully reproduced and need patches applied and verified.
  Don't use for initial vulnerability research or reproduction payload generation.
---

# Patcher (/mantis-patch)

## System Goal

Security Patching Expert. Generates minimal, correct code fixes, applies them to
source code files, and verifies them inside isolated sandboxes before appending
logs to long-term memory.

## Command Definition

- **Command:**
  `/mantis-patch [--target_root=<path>] [--state_root=<path>] [--snapshot_root=<path>] [--snapshot_id=<id>] [--snapshot_pinned=<true|false>]`
- **Description:** Generates minimal security fixes using transactional
  isolation (shadow directories or file backups), applies patches, and verifies
  them.
- **Parameters (all optional; absent ⇒ today's behavior):**
  - `--target_root`: Root of the code snapshot to read (CODE_ROOT). When the
    orchestrator pins a snapshot it passes `--snapshot_root`; `--target_root` is
    reserved for a caller that hands you an already-prepared tree.
  - `--snapshot_root`: Root of the pinned immutable snapshot for this pass.
  - `--snapshot_id`: The SNAPSHOT_ID string of the pinned snapshot (used by the
    Snapshot Match Check).
  - `--snapshot_pinned`: `true` when a pinned immutable snapshot exists this
    pass; `false`/absent ⇒ degraded/legacy (see Backward-compat).
  - `--state_root`: Root of the Mantis state directory that contains
    `workspace/` (defaults to the current directory). ALL `workspace/...` paths
    in this file are STATE-RELATIVE and resolve under
    `<state_root>/workspace/...`.

## Input/Output Contract

- **Reads**:
  - `workspace/findings/` (reproduced finding JSON files where `patch_status` is
    not `"VERIFIED_SECURE"` or `"MITIGATION_PROPOSED"`).
  - `workspace/.mantis_state.json` (to track current loop pass).
  - `workspace/.mantis_state.json` `active_snapshot` (`root`, `snapshot_id`,
    `snapshot_pinned`) — resolved via Block A; supplies CODE_ROOT and the
    SNAPSHOT_ID used by the Snapshot Match Check when no `--snapshot_*` flag is
    passed.
  - Target source code files.
  - Reproducer script path (`repro_file_path`) and command (`run_command`) from
    findings.
  - Pre-existing backup files matching finding ID (if Option B is used).
- **Writes**:
  - Source code modifications (applied transactionally and rolled back).
  - Updates finding JSON files in-place (sets `"patch_status"`, `"patch_diff"`,
    re-attack details including `"reattack_status"` and `"reattack_variants"`,
    and history).
  - Appends to `workspace/learnings.jsonl`.
  - Reusable helper script `workspace/helpers/append_patch.py`.
- **Preconditions**:
  - Findings must exist in `workspace/findings/`.
- **Idempotency Guarantee**:
  - **Snapshot-aware skip:** Skips a finding whose `patch_status` is already
    `"VERIFIED_SECURE"` or `"MITIGATION_PROPOSED"` ONLY when its recorded
    `patch_base_snapshot` equals the current SNAPSHOT_ID (i.e. it was verified
    against THIS snapshot). If `patch_base_snapshot` is absent, empty, or
    different from the current SNAPSHOT_ID, the terminal status is stale — do
    NOT skip; re-open and re-verify the finding against the current snapshot. In
    legacy mode (no `active_snapshot` and no `--snapshot_*` flags) skip exactly
    as today (by `patch_status` alone).
  - Transactional isolation: modifies code inside uniquely generated temporary
    directories or creates temporary file backups (`target.c.bak-[id]`),
    restoring baseline state upon completion (using `try...finally` rollback
    mechanisms).
  - Reuses the existing `append_patch.py` script once created.

## Instructions

Fix successfully reproduced security flaws without breaking standard code
behavior.

Execute the patching and verification stage as follows:

0. **Snapshot & Locator Resolution (run once, before touching any code):**

   0a. Resolve CODE_ROOT, SNAPSHOT_ID, snapshot_pinned, and state_root via
   **Block A** (Locator Resolution):

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
   > harness per `mantis-pipeline-adapter` Scenario 2):** if `active_snapshot`
   > is present AND `active_snapshot.pass != state.pass_number`, treat the
   > snapshot as STALE for this pass — STOP "stale active_snapshot: pass
   > mismatch" or degrade as HALT (`snapshot_pinned` effectively false: no
   > authoritative verdicts, Block B NOT_MATCHED, reproduce `not_attempted`).
   > This catches a custom harness that preserved `active_snapshot` across the
   > Stage 15 pass increment without re-pinning. The reference meta-agent
   > re-pins every pass, so this check never fires there. Block B itself cannot
   > detect this (it is `snapshot_id`-only, not `pass`-aware).

   For this stage: mantis-patch READS target code (it is NOT a findings-only
   stage), so it runs Block A steps 1–6 in full. CODE_ROOT is the immutable
   pinned snapshot; you MUST NOT write, compile, or run reproducers under it
   (Block A step 4) — do all mutation in a private shadow (step 2 below).

   0b. Determine PATCH_MODE (mechanical, using the resolved values):

   - `active_snapshot` absent AND no `--snapshot_root`/`--snapshot_id`/
     `--target_root` passed ⇒ **LEGACY mode** (today's behavior; the new
     ceilings in step 3 do NOT fire).
   - `snapshot_pinned == true` ⇒ **PINNED mode** (full gates below apply).
   - `snapshot_pinned == false` AND SNAPSHOT_ID begins with the literal `live:`
     ⇒ **HALT/DEGRADED mode** (a snapshot was attempted but could not be pinned;
     authoritative verdicts are forbidden this pass — see step 3).

   0c. For each finding you process, compute its MATCHED/NOT_MATCHED result via
   **Block B** (Snapshot Match Check):

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

   The MATCHED/NOT_MATCHED result is consumed in step 2 (isolation-mode choice)
   and step 3 (verdict). It never on its own downgrades a verdict in PINNED
   mode: a NOT_MATCHED finding is RE-verified against the current snapshot via
   the step-3 gate and, if it passes, is stamped with the current
   `patch_base_snapshot`.

1. **Load Findings to Patch:** Read the JSON files in the `workspace/findings/`
   directory. Filter for findings that are NOT already terminally verified
   AGAINST THE CURRENT SNAPSHOT — i.e. treat a finding as still-to-process
   unless its `patch_status` is `"VERIFIED_SECURE"` or `"MITIGATION_PROPOSED"`
   **and** its `patch_base_snapshot` equals the current SNAPSHOT_ID (Snapshot &
   Locator Resolution step 0). A terminal finding whose `patch_base_snapshot` is
   absent/empty/different is STALE — include it for re-verification. (In LEGACY
   mode, where there is no SNAPSHOT_ID, fall back to filtering on `patch_status`
   alone, exactly as before.) Among the included findings, keep those where
   (either `repro_status` is `"reproduced"` OR the finding is an exploit chain,
   e.g., the title starts with `"Exploit Chain:"`, or history has an entry from
   the `"chainer"` stage, or the `"constituent_findings"` property is present
   and non-empty). If none exist, notify the user.

2. **Generate and Apply Minimal Patches:** For each reproduced security flaw:

   - **Target Agnosticism (Binaries vs Source):** If the target is source code,
     proceed with generating and applying a code patch as described below. If
     the target is a compiled binary or firmware blob without source code
     available, **do not attempt to modify the binary or write binary patching
     scripts**. Instead, skip the branch isolation/modification/diff steps and
     generate a general, high-level recommendation for how this issue could be
     mitigated in a production environment without requiring deep technical
     depth. Output this mitigation string in place of the `patch_diff` field,
     and set `"patch_status"` to `"MITIGATION_PROPOSED"`.

   - **Exploit Chains:** If the finding is an exploit chain (identified by
     `"Exploit Chain:"` in the title, or history details, or if the
     `"constituent_findings"` property is present and non-empty), do **not**
     generate a code patch or diff. Instead, identify its sub-findings by
     reading the `"constituent_findings"` array of UUIDs. Monitor the patch
     status of these constituent findings (listed on disk as
     `workspace/findings/<uuid>.json`). **Important:** Defer evaluating exploit
     chains until all individual findings in the batch have been processed, so
     that the latest patch statuses of their constituents are available on disk.

     Evaluate the exploit chain status using these propagation rules (evaluated
     in order):

     1. **Validity Check:** Read the validity `"status"` of each constituent
        finding. If any constituent's `"status"` is `"FALSE_POSITIVE"`, update
        the exploit chain finding's `"status"` to match it (e.g.
        `"FALSE_POSITIVE"`) and immediately skip any further
        patching/verification for the chain. If any constituent's `"status"` is
        `"DUPLICATE"`, resolve it to its canonical finding by recursively
        following its `"duplicate_of"` property.

        **Duplicate Resolution Process:**

        1. **Locate the Finding File:** The finding file for the duplicate (or
           any parent in the duplicate chain) may have been moved. Search for
           `<uuid>.json` in the following locations in order:
           - `workspace/findings/<uuid>.json` (active findings)
           - `workspace/findings/.trash/<uuid>.json` (de-duplicated trash)
           - `workspace/archive/findings_pass_*/<uuid>.json` or
             `workspace/archive/loop*_findings/<uuid>.json` (archives from
             previous passes) If the file cannot be found in any of these
             locations, treat it as a missing file error.
        2. **Cycle Detection:** Maintain a set of visited finding UUIDs during
           the resolution. If you encounter a UUID that has already been visited
           in the current resolution chain, raise a validation error (cycle
           detected).
        3. **Maximum Depth:** Limit the recursion depth to a maximum of 5 steps.
           If the chain is deeper, abort and report an error.
        4. **Extract Status:** Once you resolve to the canonical finding (one
           whose `"status"` is not `"DUPLICATE"` or does not have
           `"duplicate_of"`), use that canonical finding's `"status"` and
           `"patch_status"` for all downstream checks and propagation. Do not
           update the exploit chain finding itself to `"DUPLICATE"`.

     2. **Missing Files:** If any constituent finding's JSON file is missing
        from the disk, set the chain's `"patch_status"` to `"ERROR"`.

     3. **Constituent Unset or Stale (Pending):** A constituent counts as
        NOT-YET-VERIFIED if EITHER its `"patch_status"` is unset (null or
        missing, indicating it has not yet been reproduced/processed) OR its
        `"patch_status"` is terminal but its `patch_base_snapshot` is
        absent/empty/different from the current SNAPSHOT_ID (verified against a
        stale snapshot — Snapshot & Locator Resolution step 0). If ANY
        constituent is NOT-YET-VERIFIED, the chain's `"patch_status"` must
        remain unset (null or missing) and you must defer/suspend further
        evaluation of the chain until that constituent is re-verified on the
        current snapshot. (In LEGACY mode, where there is no SNAPSHOT_ID, apply
        only the "unset" half of this rule, exactly as before.)

     4. **Constituent Errors:** If any constituent's `"patch_status"` is
        `"ERROR"`, set the chain's `"patch_status"` to `"ERROR"`.

     5. **Constituent Failures:** If any constituent's `"patch_status"` is
        `"VERIFICATION_FAILED"`, set the chain's `"patch_status"` to
        `"VERIFICATION_FAILED"`.

     6. **Successful Propagation:** If all constituents have finished
        verification AGAINST THE CURRENT SNAPSHOT (each is in
        `{"VERIFIED_SECURE", "MITIGATION_PROPOSED", "VERIFICATION_INCOMPLETE"}`
        AND — except in LEGACY mode — each terminal constituent's
        `patch_base_snapshot` equals the current SNAPSHOT_ID):

        - If any constituent is `"MITIGATION_PROPOSED"`, set the chain's
          `"patch_status"` to `"MITIGATION_PROPOSED"`.
        - If no constituent is `"MITIGATION_PROPOSED"` and any constituent is
          `"VERIFICATION_INCOMPLETE"`, set the chain's `"patch_status"` to
          `"VERIFICATION_INCOMPLETE"`.
        - If all constituents are `"VERIFIED_SECURE"`, set the chain's
          `"patch_status"` to `"VERIFIED_SECURE"`.

     Skip branch isolation, testing, and re-attack steps for the chain finding
     itself.

   - *Optional Parallel Trajectory Search:* If your framework supports
     subagents, you may spawn multiple concurrent subagents to design diverse
     patch implementations. Test all generated patches that successfully secure
     the code without breaking standard functionality, and select the *best*
     patch (e.g., the most minimal, readable, and idiomatic fix) rather than
     just the first one that works.

   - Read the original flawed file to grasp function dependencies and
     structures.

   - Design a minimal, correct patch to mitigate the security flaw (e.g. adding
     bound checks, validating sizes, inserting NUL-terminators) without breaking
     other features.

   - **Transactional Isolation (VCS-Agnostic & Safe):** To ensure safety,
     reliability, and VCS-agnosticism, do NOT use VCS-based branch operations
     (such as `git branch`, `git checkout`, or `git stash`).

     You must ensure transactional isolation using a method appropriate for the
     operating environment. **Isolation-method gate (mechanical):**

     - If snapshot_pinned is true (PINNED mode) → **Option A (Temporary
       Directory Shadowing) is MANDATORY. Option B and any method that writes
       under CODE_ROOT are FORBIDDEN** (Block A step 4: never write under a
       pinned snapshot).
     - Else if the finding is a RETRY (it already carries a prior `"patch"`
       history entry or a `patch_base_snapshot`) OR (PINNED mode AND its
       Snapshot Match Check result is NOT_MATCHED) → **Option A is MANDATORY**
       (do not risk editing a live tree that no longer matches the finding). The
       `PINNED mode AND` qualifier on the NOT_MATCHED clause is essential: in
       LEGACY mode (snapshot_pinned=false), Block B returns NOT_MATCHED for
       every finding as an artifact of no snapshot, not as a signal of drift —
       so NOT_MATCHED must only fire when it means "the snapshot changed"
       (PINNED), not when it means "no snapshot exists" (LEGACY).
     - Otherwise (snapshot_pinned is false AND first attempt — no prior
       `"patch"` history entry and no `patch_base_snapshot`) you may choose
       **Option A** (recommended), **Option B: File-Level Backups**, or
       design/implement **Option C: Alternative Isolation** (e.g., namespace
       isolation, container volumes, or local sandboxes) as long as it fully
       satisfies the invariants below. This covers both LEGACY and HALT mode
       first-attempt findings (neither has a prior patch to protect, and neither
       is in the PINNED read-only snapshot regime).

     Whichever method you choose, you must guarantee these invariants:

     1. **Zero Workspace Pollution**: No backup or intermediate build files left
        in the original source tree.
     2. **Concurrency Safety**: Isolation methods must not conflict with other
        concurrent agents.
     3. **Guaranteed Rollback**: Wrap all actions in error traps or
        `try...finally` blocks to restore the original state on failure.

     - **Option A: Temporary Directory Shadowing (Recommended / mandatory when
       pinned)**

       - **Warning/Resource constraint:** For source trees larger than a few
         hundred MB, or when many parallel patch workers share the host, and
         ONLY when NOT in PINNED mode, you may prefer **Option B** (which
         touches only the modified files) to avoid exhausting `/tmp` or memory.
         In PINNED mode Option B is forbidden regardless of size (the snapshot
         is read-only); if a full copy will not fit, do not fabricate a verdict
         — see step 3 HALT handling.

       - **Two-root copy:** Create a uniquely generated SHADOW_ROOT (e.g.
         `mktemp -d` / `tempfile.mkdtemp()`) OUTSIDE both CODE_ROOT and any
         `/workspace/` path, then copy the relevant source tree **FROM
         CODE_ROOT** (the snapshot resolved in Snapshot & Locator Resolution
         step 0), NOT from an implicit cwd, into SHADOW_ROOT. CODE_ROOT stays
         untouched and read-only.

       - Perform all edits, compilation, and reproduction testing inside
         SHADOW_ROOT. Never run a mutating/compiling/reproducing command with
         cwd = CODE_ROOT (Block A step 4).

     - **Critical Guard (Path and Working Directory Safety):** You must ensure
       that every command executed (compilation, testing, verification) runs
       with its working directory (`Cwd`) explicitly set to SHADOW_ROOT. If the
       finding's `run_command` contains absolute paths under CODE_ROOT (the
       snapshot) or under the live source root, you must rewrite that prefix to
       the corresponding path under SHADOW_ROOT before execution.

       **Guard Check:** When performing path rewriting, only rewrite paths that
       represent the target codebase files. If a path starts with or contains a
       `/workspace/` segment (where the Mantis state and findings are stored),
       do NOT replace its prefix (findings/state must remain in the
       authoritative `state_root/workspace/`). This separation is unambiguous
       because a pinned SNAPSHOT_ROOT/CODE_ROOT never contains a `/workspace/`
       segment (guaranteed by the orchestrator's snapshot materialization). Do
       not execute any modification or verification command against CODE_ROOT or
       against `state_root/workspace/`.

     - **{TARGET_ROOT} token substitution (MANDATORY before executing any stored
       command):** `mantis-reproduce` stores
       `run_command`/`reattack_run_command` with the literal token
       `{TARGET_ROOT}` for target-tree paths (Step 3 of reproduce), expecting
       the caller to substitute it. Before executing any stored `run_command` or
       `reattack_run_command`, replace the literal `{TARGET_ROOT}` token with
       the tree being executed against:

       - For the Block-G **unpatched baseline** run: substitute the fresh
         unpatched CODE_ROOT copy (a fresh `mktemp -d` copy taken FROM
         CODE_ROOT).
       - For **post-patch verification** and **attack/reattack** runs:
         substitute SHADOW_ROOT (the patched shadow copy). This substitution
         MUST happen BEFORE the CODE_ROOT→SHADOW_ROOT prefix rewriting above
         (the token may expand to a CODE_ROOT path that then needs rewriting for
         shadow runs). If the literal token survives unsubstituted, the command
         will fail → evidence absent → forced ERROR (Block F/Block G treat
         command-not-found / No-such-file as EVIDENCE ABSENT). Never execute a
         command containing the literal `{TARGET_ROOT}` token.

     - Generate the unified patch diff by comparing the original source files in
       CODE_ROOT (the pinned snapshot) with the modified files in SHADOW_ROOT.
       Use labels so no CODE_ROOT/SHADOW_ROOT absolute prefix leaks into the
       diff headers.

     - Delete the temporary shadow directory completely when finished.

     - **Option B: File-Level Backups (Fallback)**

       - **Concurrency & Exclusivity Warning:** Because Option B modifies files
         directly in the original workspace, it is concurrency-unsafe when run
         in parallel with other workspace-modifying agents. Sequential execution
         must be strictly enforced via locking.
       - **Exclusive Workspace Lock:** Before performing backups or edits, the
         agent **must** acquire an exclusive lock on
         `workspace/.workspace_edit.lock` (using `fcntl.flock` with
         `fcntl.LOCK_EX` in Python, or a similar system-level lock). The agent
         **must** hold this lock continuously throughout the entire patching,
         verification, re-attack, and restoration lifecycle for the finding,
         releasing it only when final baseline files are restored or finalized.
       - **Pre-execution Check:** Prior to editing, scan the workspace for
         pre-existing backup files matching the current finding's ID (e.g.,
         `*.bak-[current_finding_id]`). If found, restore and delete them.
       - **Create Backups:** For every source file you intend to modify, create
         a copy with a unique suffix (e.g.,
         `cp target.c target.c.bak-[finding_id]`).
       - **Net-New Files:** Track any newly created files to delete them on
         rollback.
       - **Apply Modifications:** Edit original target files directly.
       - **Generate Unified Diff:** Compare backup against modified file using
         labels to normalize headers (e.g.,
         `diff -u --label target.c --label target.c target.c.bak-[finding_id] target.c`).

   - **3-Way Patch Rebasing (Phase 2 incremental efficiency):** When a prior
     pass's snapshot and patch are still present on disk (see the reachability
     check below), the patcher can attempt to REBASE a prior pass's patch onto
     the current snapshot instead of generating a fresh patch from scratch. This
     is an optimization for the common case where a prior fix still applies with
     minor line-number shifts.

     - **How:** If ALL reachability conditions (a)-(d) below hold, read
       [3-Way Patch Rebasing](references/patch_rebasing.md) with your
       file-reading tool for the 3-way merge mechanics (`base`/`ours`/`theirs`
       scratch copies, `git merge-file` / `diff3` invocation, conflict-marker
       handling). On ANY uncertainty or if the reference cannot be loaded, fall
       back to fresh patch generation (Phase-1 behavior).
     - **When to use (reachability by OBSERVABLE state, not a flag the patcher
       cannot read):** attempt rebasing ONLY when ALL hold: (a) the prior pass's
       snapshot directory AND the file's prior unpatched version actually EXIST
       on disk under `<state_root>/.mantis_snapshots/` (retention kept them; if
       the base snapshot was GC'd this fails → fall back); (b) the finding's
       `signature` matches an archived finding with a prior `patch_diff` (same
       bug, same signature) — this is the ARCHIVED finding referenced by the
       remaining gates; (c) the ARCHIVED finding's `patch_base_snapshot` is
       present and DIFFERENT from the current `SNAPSHOT_ID` (the snapshot the
       prior patch was verified against has changed; this is the correct
       "snapshot changed" test — do NOT test Block B on the CURRENT finding,
       whose `discovery_commit` is always `== SNAPSHOT_ID` in PINNED mode
       because researcher stamps it, dedupe backfills it, and plan only
       copy-verbatim's MATCHED findings preserving the original
       `discovery_commit`); if the archived finding's `patch_base_snapshot` is
       ABSENT or EMPTY (legacy prior pass, or a pre-Phase-2 patcher that did not
       write it — detected by the helper-version marker at step 6), the
       snapshot-changed test is UNKN and you MUST fall back to fresh patch
       generation (do NOT rebase onto a possibly-unchanged base); and (d) the
       finding's primary file is in `changed_files`. If `signature` is absent
       (legacy finding), condition (b) cannot be satisfied — fall back to fresh
       patch generation. Do NOT gate on `--snapshot_keep`: that flag is set on
       the orchestrator and is NOT passed to or readable by the patch stage; the
       on-disk presence check (a) is the correct observable substitute and works
       under any retention setting (the default keep-2 already retains the
       immediately-prior pass). `changed_files` and `changed_files_status` are
       read from `workspace/.mantis_state.json` (the same state object read for
       `active_snapshot`).

   - **When rebasing SUCCEEDS / FAILS / Guardrail:** See
     [3-Way Patch Rebasing](references/patch_rebasing.md) for the success (clean
     merge → use rebased patch, still run Block G, history note
     `patch-rebased-from: pass_<N-1>`), failure (merge conflict / file deleted /
     renamed → fall back to fresh patch generation), and guardrail (on ANY
     uncertainty, fall back to Phase-1; never apply a rebased patch with
     unresolved conflicts or unrelated changes).

   - **Unpatched-Baseline Re-run in `--reattack` (Phase 2):** When the
     `@mantis-reproduce --reattack` sub-agent is re-attacking a patch on a NEW
     snapshot (Block B NOT_MATCHED, meaning the snapshot changed since the patch
     was verified — in PINNED mode only), the re-attack MUST first re-establish
     the unpatched baseline on the CURRENT snapshot before testing the attack
     against the patched build. This ensures the re-attack is meaningful: if the
     bug no longer triggers on the current unpatched snapshot (e.g., upstream
     code fixed it), the re-attack result is inconclusive, not a pass.

     - **How:** Before running the attack on the patched shadow, run the
       reproducer against a FRESH UNPATCHED copy of the current snapshot (per
       Block G step 1). If the unpatched baseline does NOT trigger (evidence
       absent), set `reattack_status = "inconclusive_baseline_changed"` with a
       history note, and do NOT claim `failed_to_bypass` (the patch was not
       tested against a live bug). If the unpatched baseline DOES trigger,
       proceed with the attack on the patched build as normal.
     - **HALT-mode note:** In HALT mode (`snapshot_pinned=false`, `live:`
       SNAPSHOT_ID), Block B is always NOT_MATCHED, but this does NOT represent
       a genuine snapshot change — it means the tree couldn't be pinned. The
       `@mantis-reproduce --reattack` sub-agent skips the C5 re-baseline in HALT
       (see reproduce C5 HALT guardrail) and follows the existing HALT ceiling.
     - **Guardrail:** This does NOT change the VERIFIED_SECURE gate — Block G
       still requires the unpatched baseline to trigger. This only adds a
       re-baseline step to the re-attack path when the snapshot changed.

3. **Post-Patch Verification Run:** *(Skip this step for binary-only targets
   where no code patch was applied)*. To confirm the patch works, re-run the
   reproducer script inside your isolated execution environment. Use the exact
   `"repro_file_path"` and `"run_command"` from the reproduction entry to verify
   the patch.

   - **Cwd Enforcement:** You must execute the reproducer script with the
     working directory (`Cwd`) set to the shadow directory (if using Option A).
     Ensure the command targets the copy in the shadow directory, not the
     original workspace.

   - **Reached-sink evidence definition** — **Block F** (Reached-Sink Evidence
     Gate). In patch verification the evidence is required on the UNPATCHED
     baseline, never on the post-patch attack run (a correct patch legitimately
     stops the input before the sink):

     ```
     REACHED-SINK EVIDENCE GATE (mechanical):
     Each reproducer produces REACHED-SINK EVIDENCE via ONE channel, recorded in repro_hints:
        (a) script/source harness -> write the exact bytes MANTIS_REACHED_ENTRYPOINT to a
            sidecar file $SENTINEL_FILE and flush+fsync (or unbuffered write) BEFORE
            invoking the sink. (A file survives a crash that truncates buffered stdout.)
        (b) binary / firmware / raw-payload -> reached-sink evidence is a captured
            crash backtrace or sanitizer frame (ASan/UBSan/MSan/TSan) that
            explicitly names the target sink function (target-produced tracing). A
            marker written by a wrapper you author BEFORE invoking the target is
            SETUP EVIDENCE ONLY: it proves "launch attempted," not "sink reached,"
            and does NOT qualify as reached-sink evidence. If no in-path marker
            (channel a) and no target-produced backtrace/sanitizer trace
            (channel b) is achievable, the sink is unreached.
      EVIDENCE PRESENT (reached-sink) = (channel a) sidecar file contains
        MANTIS_REACHED_ENTRYPOINT written in-path, OR (channel b) target-produced
        backtrace/sanitizer output names the sink. A wrapper pre-launch marker alone is
        NOT evidence present.
     EVIDENCE ABSENT includes: any compiler/build nonzero exit; exit 127 (command not
       found); exit 2 with a "No such file" message.
     DECISION GATE (gate the DECISION, not specific verdict strings):
       - Record repro_status = reproduced OR statically_confirmed ONLY if EVIDENCE is
         PRESENT. If ABSENT -> repro_status = not_attempted (retry-eligible), STOP.
       - In patch verification, EVIDENCE is required on the UNPATCHED baseline (Block G),
         NOT on the post-patch attack run (a correct patch legitimately stops the input
         before the sink).
       - If NO evidence channel is achievable for this target, downgrade to
         not_attempted / VERIFICATION_INCOMPLETE. NEVER synthesize the marker.
     ```

   - **Hard gate before any `VERIFIED_SECURE`** — **Block G**
     (Unpatched-Baseline + Benign-Control Gate). Run it inside SHADOW copies of
     CODE_ROOT; the "FRESH UNPATCHED copy of SNAPSHOT_ROOT" in Block G step 1
     means a fresh copy taken FROM CODE_ROOT:

     ```
     UNPATCHED-BASELINE + POST-PATCH GATE (before any VERIFIED_SECURE):
     0. APPLICABILITY: applies ONLY when repro_status == reproduced (a runnable PoC
        exists). If repro_status == statically_confirmed (no runnable PoC),
        VERIFIED_SECURE is NOT applicable -> record MITIGATION_PROPOSED (NEVER ERROR).
     1. UNPATCHED BASELINE: run the reproducer against a FRESH UNPATCHED copy of
        SNAPSHOT_ROOT using Block F. If evidence ABSENT or the bug does NOT trigger ->
        patch_status = ERROR ("reproducer_invalid_on_current_snapshot"); do NOT set
        VERIFIED_SECURE.
     2. POST-PATCH INTEGRITY (distinguish "blocked by patch" from "build break"):
        - REQUIRED: the patched build must COMPILE with exit 0. Nonzero ->
          VERIFICATION_INCOMPLETE.
        - REQUIRED (benign control): run a legitimate BENIGN (non-attack) input through
          the patched build; it MUST reach the sink path (EVIDENCE PRESENT via Block F)
          with no crash. This proves the patch narrowed the bug rather than breaking the
          harness/entrypoint. If NO benign control can be constructed for this target,
          you may NOT claim VERIFIED_SECURE on a clean-run-only basis -> land
          VERIFICATION_INCOMPLETE and record why the benign control was infeasible.
          (Strict mode: a clean compile + clean run WITHOUT a benign control reaching
          the sink is never sufficient for VERIFIED_SECURE.)
     3. ATTACK ON PATCH: run the attack input through the patched build. VERIFIED_SECURE
        requires ALL of: step 1 triggered on unpatched (evidence present), step 2
        integrity holds, step 3 attack does NOT crash/trigger, AND the `--reattack` run
        also fails to bypass. Otherwise VERIFICATION_FAILED.
     ```

     **Sanitizer consistency guardrail (Block G):** All runs in this gate
     (unpatched baseline, benign control, attack, and re-attack) MUST use the
     SAME sanitizer flags that made the unpatched baseline trigger. If the
     baseline triggered via UBSan (exit 0, recover-mode), the attack run must
     also be compiled with UBSan — otherwise the attack might exit 0 without a
     trace even though the bug is still present, producing a false
     `VERIFIED_SECURE` (INV-1 violation). Record the sanitizer flags used in
     `repro_hints` so downstream stages replicate them.

   - **HALT/DEGRADED ceiling:** If PATCH_MODE is HALT/DEGRADED (snapshot_pinned
     false with a `live:` SNAPSHOT_ID), authoritative verdicts are forbidden
     this pass: the best attainable `patch_status` is
     `"VERIFICATION_INCOMPLETE"`. Never emit `"VERIFIED_SECURE"` in this mode.
     (LEGACY mode is unaffected.)

   - **Missing-file rule:** If the reproducer file (`repro_file_path`) or a
     `code_paths` target file cannot be found when you attempt verification, set
     `patch_status` to `"ERROR"`. NEVER treat a missing file as "did not
     reproduce" and NEVER emit `"VERIFIED_SECURE"` from a missing file. (This is
     also what Block F/Block G's "No such file"/`exit 127` → EVIDENCE ABSENT
     path enforces.)

   * **VERIFIED SECURE (all conditions REQUIRED):** Mark `patch_status` as
     `"VERIFIED_SECURE"` ONLY if ALL of the following hold:

     1. **Block G passes in full:** the UNPATCHED baseline triggered the bug
        WITH reached-sink evidence (Block F) on a fresh copy of CODE_ROOT; the
        patched build compiled (exit 0); the benign/integrity control held; and
        the attack input on the patched build does NOT crash/trigger.
     2. **Re-attack fails to bypass:** a fresh, independent
        `@mantis-reproduce --reattack` sub-agent (spawned per the block below)
        writes `reattack_status = "failed_to_bypass"` — meaning a non-empty
        `reattack_variants` array with ≥ 3 valid variant inputs (reproduce Step
        3a) ALL failed to trigger the original vulnerability class on the
        patched shadow. An empty or short variant set caps at
        `VERIFICATION_INCOMPLETE`, never `VERIFIED_SECURE`.
     3. **Not degraded:** PATCH_MODE is not HALT/DEGRADED. If PATCH_MODE is
        HALT/DEGRADED (snapshot mismatch / unpinnable snapshot), the ceiling is
        `"VERIFICATION_INCOMPLETE"`, never `"VERIFIED_SECURE"`. If Block G
        reports its baseline could NOT be established (evidence absent or bug
        does not trigger on the current unpatched snapshot), set `patch_status`
        to `"ERROR"` (`"reproducer_invalid_on_current_snapshot"`) — do NOT emit
        `"VERIFIED_SECURE"`. If Block G's applicability check found
        `repro_status == statically_confirmed`, record `"MITIGATION_PROPOSED"`
        (never ERROR). To ensure true independence, launch a fresh
        `@mantis-reproduce --reattack --finding_id=[finding_id]` sub-agent
        against the PATCHED shadow (a copy of SHADOW_ROOT after your patch is
        applied) to perform the re-attack.

     **Important:** When calling the `@mantis-reproduce` subagent for the
     re-attack:

     - If using **Option A (Shadowing)** (always, in PINNED mode), pass:
       - `--reattack`
       - `--target_root=<PATCHED_SHADOW_ROOT>` — the shadow copy that contains
         your applied patch. Because `--target_root` is AUTHORITATIVE and
         sentinel-EXEMPT (Block A step 1a/2), the sub-agent reads the patched
         tree directly.
       - `--snapshot_pinned=false` — the patched shadow is deliberately mutated,
         so the reproduce sub-agent MUST skip the snapshot sentinel/match check
         for it.
       - `--state_root=<state_root>` — your authoritative state directory (so
         all `reattack_*` fields and history land under
         `state_root/workspace/`).
       - `--finding_id=[finding_id]` of the finding being verified.
     - If using **Option B (Backups)** or **Option C (Alternative)** (only
       possible in LEGACY mode), pass `--reattack`, both roots pointing at the
       live workspace (or leave them default `.`), and
       `--finding_id=[finding_id]`.

     The reproducer agent running with `--reattack` will write its outcomes
     directly into the primary finding's `reattack_status`,
     `reattack_file_path`, `reattack_run_command`, and `reattack_output` fields
     inside the original workspace findings (`state_root/workspace/findings/`),
     keeping the initial `repro_*` fields untouched.

   * **VERIFICATION FAILED:** If the sandbox execution still triggers the bug,
     or if your re-attack successfully bypasses your patch, the patch is
     insufficient. Re-evaluate and adapt your fix.

   * **VERIFICATION INCOMPLETE:** If the initial post-patch verification run
     passed but the subsequent re-attack checks failed/timed out due to sandbox
     infrastructure errors, environment timeouts, or platform restrictions, set
     `"patch_status"` to `"VERIFICATION_INCOMPLETE"`.

   * **Re-attack unset / SNAPSHOT_MISMATCH → VERIFICATION_INCOMPLETE:** If
     `reattack_status` is unset (the re-attack sub-agent left it unset with a
     `SNAPSHOT_MISMATCH` or `setup_failed` history note, or the re-attack did
     not run at all), set `patch_status` to `"VERIFICATION_INCOMPLETE"` — never
     `VERIFIED_SECURE`. An unset re-attack status means independence was not
     confirmed; a `SNAPSHOT_MISMATCH` means the re-attack ran against a
     different snapshot than the patch was verified on. In either case the patch
     is not conclusively verified.

   * **Inconclusive baseline → VERIFICATION_INCOMPLETE:** If `reattack_status`
     is `"inconclusive_baseline_changed"` (the re-attack sub-agent re-ran the
     unpatched baseline on the current snapshot and the bug no longer triggers —
     the baseline changed since the patch was verified), set `patch_status` to
     `"VERIFICATION_INCOMPLETE"` (or `"ERROR"` with details
     `"reproducer_invalid_on_current_snapshot"`) — never `"VERIFIED_SECURE"`.
     The patch was not tested against a live bug on the current snapshot;
     claiming it is secure would be a false authoritative verdict.

4. **Extract Patch and Rollback Transaction:** *(Skip this step for binary-only
   targets)*. Do not leave the codebase in an altered state. Once you have a
   final outcome (either `VERIFIED_SECURE` or you have exhausted your retries):

   - If successful, generate a unified diff representing your exact changes and
     save it to the `"patch_diff"` field:
     - If using **Option A (Shadowing)**, generate this diff by comparing the
       original files in CODE_ROOT with the modified files in the shadow
       directory.
     - If using **Option B (Backups)**, generate this diff by comparing the
       backup file to the modified file, explicitly labeling the headers to
       prevent the backup suffix from appearing (e.g.,
       `diff -u --label target.c --label target.c target.c.bak-[finding_id] target.c`).
     - If using **Option C (Alternative)**, generate a clean, VCS-agnostic
       unified diff comparing the unmodified baseline files to the final patched
       files.
     - If multiple files were modified, generate individual unified diffs and
       concatenate them cleanly into the single `"patch_diff"` string. Do NOT
       use VCS-specific diff commands.
   - **Transactional Clean Up / Rollback**: Restore the codebase to its original
     state.
     - If using **Option A (Shadowing)**, delete the temporary shadow directory
       completely (e.g., `rm -rf <shadow_directory>`). Since the original
       codebase was never modified, no further restoration is needed.
     - If using **Option B (Backups)**, restore the original files by copying
       the backup files back onto the target files (e.g.,
       `cp target.c.bak-[finding_id] target.c`), delete the backup copies
       (`rm target.c.bak-[finding_id]`), and delete any net-new files created
       during the patching process. **Do NOT delete any re-attack/PoC script
       files written inside the `workspace/reproducers/` directory, any helper
       scripts written inside the `workspace/helpers/` directory, or the memory
       database file `workspace/learnings.jsonl`; these must be explicitly
       preserved.**
     - If using **Option C (Alternative)**, execute the corresponding teardown
       or rollback steps to fully purge all modification artifacts, delete any
       temporary resources, and ensure the original workspace is left in its
       clean baseline state.

5. **Append to Long-Term Memory (Continuous Reviewing Link):** For each security
   flaw processed, append a single structured JSON line to a workspace database
   file named `workspace/learnings.jsonl` (using append mode). This allows the
   strategist (`/mantis-plan`) to read these historical records in subsequent
   passes and avoid proposing fixes for already patched files.

   - **Memory Entry Format:**
     `{"title": "[security_flaw_title]", "code_paths": ["[path1:line1]"], "status": "[VERIFIED_SECURE / MITIGATION_PROPOSED / VERIFICATION_INCOMPLETE / VERIFICATION_FAILED / ERROR]", "patch_base_snapshot": "[current SNAPSHOT_ID, or omit in LEGACY mode]", "snapshot": "[current SNAPSHOT_ID, or omit in MODE-OFF]"}`

6. **Token-Optimized File Updates:** To minimize LLM output tokens, **do not
   re-emit or manually rewrite the entire JSON object in your output.** Instead,
   write a reusable helper script (e.g.,
   `state_root/workspace/helpers/append_patch.py`) during your first finding
   update. Make the FIRST line of the helper a version marker comment:
   `# MANTIS_HELPER_VERSION = 2`. Before reusing an existing helper, read its
   first line: if it does NOT contain the exact marker
   `MANTIS_HELPER_VERSION = 2`, the helper is stale (from an older pass/version
   that does not write `patch_base_snapshot`) — regenerate it. Only when the
   marker matches may you reuse it: simply execute the existing helper with the
   new parameters to append the required fields.

   You must append the following to the existing object:

   - A `"patch_status"` field (one of `"VERIFIED_SECURE"`,
     `"MITIGATION_PROPOSED"`, `"VERIFICATION_INCOMPLETE"`,
     `"VERIFICATION_FAILED"`, or `"ERROR"`).
   - A `"patch_base_snapshot"` field set to the current SNAPSHOT_ID (Snapshot &
     Locator Resolution step 0) — the snapshot this verdict was earned on. Omit
     this field only in LEGACY mode (no SNAPSHOT_ID exists). This is what makes
     the snapshot-aware skip (Idempotency Guarantee) and chain propagation
     correct across passes.
   - If a patch was successful, a `"patch_diff"` field containing the unified
     diff.
   - If a re-attack was performed, the `"reattack_status"`,
     `"reattack_file_path"`, `"reattack_run_command"`, `"reattack_output"`, and
     `"reattack_variants"` fields (each object in `"reattack_variants"` MUST
     have EXACTLY `{"description": "...", "triggered": true/false}`).
   - An entry to the `"history"` array:

   ```json
   {
     "stage": "patch",
     "action": "patched",
      "details": "Patch status evaluated as [VERIFIED_SECURE/MITIGATION_PROPOSED/VERIFICATION_INCOMPLETE/VERIFICATION_FAILED/ERROR] on snapshot [patch_base_snapshot or 'legacy']",
     "pass_number": <current_pass_number>,
     "timestamp": "<current_iso8601_timestamp>"
   }
   ```

When complete, notify the user.

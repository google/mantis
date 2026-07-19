---
name: mantis-meta-agent
description: >-
  Acts as the persistent supervisor, launching and monitoring the automated review campaign.
  Use when running a long-running, continuous security review campaign that needs autonomous coordination.
  Don't use for executing individual review stages directly.
---

# Meta-Agent Orchestrator (/mantis-meta-agent)

## System Goal

Autonomous Campaign Manager. Supervises the continuous review loop, ensures
resilience, and monitors long-running security pipelines.

## Command Definition

- **Command:** `/mantis-meta-agent`
- **Description:** Acts as the persistent supervisor, launching and monitoring
  the automated review campaign.
- **Parameters:**
  - `--sync`: OPT-IN boundary sync + snapshot pinning. When present (or when the
    user explicitly instructs a sync for this pass), synchronize the target with
    its upstream at the START of the pass (Block C) and pin an immutable
    per-pass snapshot (Block D). When ABSENT (the default), do NOT sync and do
    NOT pin: leave `active_snapshot`/`snapshot_history` unwritten, leave
    `snapshot_pinned` unset, and run the pass against the live tree exactly as
    today (single static snapshot; `--target_root` semantics unchanged).
  - `--snapshot_keep=<N>`: retention for pinned snapshots under
    `<state_root>/.mantis_snapshots/` (Block D step 6 GC). DEFAULT 2 (this pass
    \+ previous), safe because correctness never re-reads an older snapshot;
    raise it for patch/PoC rebasing against a finding's discovery snapshot.
  - `--state_root=<absolute path>`: directory that contains `workspace/` and
    `.mantis_snapshots/`. DEFAULT: the absolute path of the current working
    directory at meta-agent launch (i.e., the parent of `workspace/`). If
    `state_root` resolves inside `CODE_ROOT` (the colocated case — the default
    when launching from inside the target repo), Step 3 (PIN) MUST either (a)
    HALT and yield to the user with a message to pass `--state_root` outside
    `CODE_ROOT`, or (b) auto-relocate by moving `workspace/` and
    `.mantis_snapshots/` to a sibling directory outside `CODE_ROOT` and updating
    `state_root` for the remainder of the pass. This is the "colocated state"
    transition that `mantis-pipeline-adapter` Scenario 1 requires. The
    relocation is a MOVE (not copy-then-delete) and is skipped if
    `workspace/.workspace_edit.lock` is held (INV-5: no user data loss).

## Input/Output Contract

- **Reads**:
  - `workspace/.mantis_state.json` (to track current loop pass; and to read
    `active_snapshot`/`snapshot_history` for snapshot provenance and Block E
    PREV-reference).
  - Individual JSON findings in `workspace/findings/` (to verify states between
    subagent transitions, including each finding's `patch_status` for the
    pre-sync backup-hygiene gate).
  - `workspace/.workspace_edit.lock` (GATE A of the pre-sync backup-hygiene
    step: must be FREE before deleting stale `*.bak-*` files).
  - `CODE_ROOT/.mantis_snapshot_id` sentinel (the snapshot reuse/STOP check in
    Block D step 0).
- **Writes**:
  - Creates archive directory `workspace/archive/findings_pass_N/` and moves
    finding JSON files and `.trash/` to it; and (Stage 15) COPIES
    `workspace/.mantis_state.json` and `workspace/kb/` (incl. `THREAT_MODEL.md`)
    into it as the pass boundary reference.
  - Updates `workspace/.mantis_state.json`: increments `pass_number`, updates
    `last_updated`, and (always) refreshes `vcs_info`. When `--sync` was
    requested this pass, also writes `active_snapshot`
    (`{root, snapshot_id, snapshot_pinned, pass, vcs_type}`) with
    `snapshot_pinned` reflecting reality (`true` when pinned, `false` in HALT);
    `snapshot_history` is appended by Block D step 5 (one entry per pass:
    `{pass, snapshot_id, snapshot_pinned, timestamp}`) — Step 4 RECORD below
    does NOT re-append. These new keys are defined in `schema.json`
    `#/$defs/state`; they are optional and absent in MODE-OFF (no `--sync`).
  - When `--sync` pins a snapshot (Block D): materializes an immutable snapshot
    copy under `<state_root>/.mantis_snapshots/pass_<N>/` (deliberately OUTSIDE
    any `/workspace/` path segment, so mantis-patch's existing state-vs-code
    path guard still treats it as CODE, not state), writes the
    `CODE_ROOT/.mantis_snapshot_id` sentinel, and `chmod -R a-w` the copy.
- **Preconditions**:
  - Target project must be identified. Campaign orchestration tools/subagents
    must be ready.
- **Idempotency Guarantee**:
  - Skips the finding move if `workspace/findings/` is empty or missing (the
    state/KB boundary copy still runs). Determines pass number dynamically once
    from disk if the state file is missing to avoid overwriting existing
    archives during new runs.
  - Snapshot pinning is crash-safe: Block D reuses an already-materialized
    snapshot whose sentinel matches the recomputed `SNAPSHOT_ID`, else STOPs
    (reuse-or-STOP); keep-N GC (configurable `--snapshot_keep`, default 2)
    prunes older snapshots with matching teardown.

## Instructions

Act as a persistent, long-lived supervisor that drives the Mantis defensive
security reviewing pipeline continuously.

> **Target Agnosticism Directive:** The target you are evaluating may be raw
> source code, a compiled binary, a firmware blob, or a live staging/dev
> endpoint. Ground your analysis in whatever format the target is currently in.
> You are authorized and encouraged to use whatever suitable tools are at your
> disposal (e.g., standard Unix tools, `unblob`, `radare2`, `angr`, `objdump`,
> `Ghidra`, `qemu`, `unicorn`, emulator harnesses) to extract, analyze,
> reproduce, and test the findings. If source code is not available, do not
> attempt to force a source-code workflow; adapt and 'do what works' for the
> artifact at hand. Ensure your subagents are aware of the tools available to
> them.

Do not perform the auditing or patching tasks yourself. Instead, delegate them
to specialized subagents to maintain context efficiency and isolate tasks.

Execute your orchestration duties in a continuous loop:

1. **Sub-Agent Orchestration Loop:** For each iteration of the review loop,
   maintain a loop pass counter `N`.

   - **Initialization / Startup:** Read `N` from `"pass_number"` in
     `workspace/.mantis_state.json`. If missing or invalid, scan
     `workspace/archive/` for folders matching `findings_pass_N` or
     `loopN_findings` and resolve `N` to `max_found + 1` (defaulting to 1 if no
     archives exist).

     **Boundary Sync & Snapshot Pinning — Pass Lifecycle CONTRACT (STRICT
     ORDER).** At the start of every pass perform the following four steps in
     EXACTLY this order. The Pass Lifecycle Contract (`schema.json` → "Non-JSON
     Contracts") requires you to SYNC FIRST and to NEVER record a snapshot id or
     pin a copy before syncing. Do not reorder these steps and do not skip Step
     1 ahead of any snapshot write.

     **Sync is OPT-IN.** Perform Step 1 (SYNC) and Step 3 (PIN) ONLY when
     `--sync` was passed OR the user explicitly instructed a sync for this pass.
     Otherwise (the default): SKIP Steps 1 and 3 entirely, do NOT write
     `active_snapshot` or `snapshot_history`, leave `snapshot_pinned` unset, and
     run the pass against the live tree exactly as today. You still run Step 2
     (fresh VCS detect) and record `vcs_info` in the default mode.

     **Guard:** Sync (Step 1) must be the very first mutating action of the
     pass. Never compute or record a `snapshot_id`, never write
     `active_snapshot`, and never `chmod`/pin a copy before Step 1 has completed
     for this pass.

     1. **SYNC (must be the very first action of the pass; `--sync` only).**
        First, **pre-sync backup hygiene** — remove stale `*.bak-*` files left
        by an interrupted `@mantis-patch` run, but ONLY when it is safe:

        - GATE A: the workspace edit lock `workspace/.workspace_edit.lock` must
          be FREE (no patch in flight). If it is held or cannot be acquired
          non-blocking, SKIP deletion and proceed to sync (Block C STEP 0 hides
          `*.bak-*` from the dirty check anyway).
        - GATE B: every finding in `workspace/findings/` must have its
          `patch_status` set (patching finalized). If any finding is mid-patch
          (no `patch_status`), SKIP deletion.
        - SCOPE: delete only within the TARGET tree, never under Mantis state:
          `find <target_root> -name '*.bak-*' -not -path '*/.mantis_snapshots/*' -not -path '*/workspace/*' -delete`.
          Never delete `workspace/`, `<state_root>/.mantis_snapshots/`, or
          anything beneath them. Then synchronize the target with upstream at
          the pass boundary:

        SYNC (very first action of the pass; ONLY if a sync was requested; NEVER
        mid-pass): STEP 0 - HIDE MANTIS ARTIFACTS from dirtiness:
        mantis-summary.md, *.bak-*, workspace/, .mantis_snapshots/ MUST be
        invisible to every dirty check. Delete stray mantis-summary.md and
        *.bak-* at the LIVE root first, and pass the per-VCS excludes below.
        (Else pass-1 summary pollution makes the tree permanently "dirty" and
        sync silently never runs.) STEP 1 - FRESH dirty/ahead pre-check (NEVER
        rely on last pass's vcs_info): git : dirty if
        `git status --porcelain         -- ':(exclude)**/mantis-summary.md'         ':(exclude)**/*.bak-*'         ':(exclude)workspace/'         ':(exclude).mantis_snapshots/'`
        is non-empty; ahead if `git rev-list --count @{u}..HEAD 2>/dev/null`
        errors or > 0; detached if `git symbolic-ref -q HEAD` errors. hg : dirty
        if
        `hg status -X '**/mantis-summary.md' -X '*.bak-*' -X 'workspace/**' -X '.mantis_snapshots/**'`
        non-empty. multi-vcs : dirty if
        `repo forall -c "git status         --porcelain         -- ':(exclude)**/mantis-summary.md'         ':(exclude)**/*.bak-*'         ':(exclude)workspace/'         ':(exclude).mantis_snapshots/'"`
        produces ANY output. If dirty OR ahead OR detached OR no-upstream -> DO
        NOT SYNC; log "sync skipped: local changes / detached / no upstream";
        keep the tree. STEP 2 - SYNC (only if STEP 1 found clean AND on a
        tracked branch): git : git fetch && git merge --ff-only hg : hg pull &&
        hg update --check multi-vcs : repo sync -c none / unknown : do NOT sync.
        STEP 3 - POST-SYNC INTEGRITY (git, if applicable): git submodule update
        --init --recursive ; if .gitattributes uses filter=lfs, git lfs pull. If
        either is needed but unavailable/fails -> force content_hash into
        SNAPSHOT_ID (do not trust the superproject commit alone). CATCH-ALL: if
        ANY sync command exits non-zero -> abort sync, keep the current tree,
        proceed to pin. Re-reviewing the same snapshot is always safe. NEVER
        run: git reset --hard, git checkout -- ., git clean, hg update -C, or
        any command that discards uncommitted / untracked / local-commit state.

        Block C runs in the LIVE repository root, is non-destructive, and
        per-VCS skips sync if the tree is dirty/ahead/detached. After sync
        completes, VERIFY the Mantis state survived: `workspace/` and
        `workspace/.mantis_state.json` must still exist (Block C never touches
        `workspace/`). If either is missing after sync, HALT (do not detect, do
        not pin, do not proceed) and yield to the user.

     2. **FRESH VCS DETECT (only after sync).** Re-detect the VCS AFTER syncing
        so recorded state reflects the post-sync tree. Run these checks in the
        LIVE repository root (Block A step 5 VCS-metadata carve-out —
        history/diff/VCS commands run in the live root, never inside a pinned
        CODE_ROOT):

        1. Check for Git: run `git rev-parse --is-inside-work-tree`. If this
           command succeeds (returns exit code 0 and output is `true`), a Git
           repository is active. Set `vcs_type` to `"git"` and extract:
           - `commit_hash` (via `git rev-parse HEAD`)
           - `branch` (via `git branch --show-current` or
             `git rev-parse --abbrev-ref HEAD`)
           - `dirty` status (check if
             `git status --porcelain -- ':(exclude)**/mantis-summary.md' ':(exclude)**/*.bak-*' ':(exclude)workspace/' ':(exclude).mantis_snapshots/'`
             is non-empty — same exclude set as STEP 1, so colocated
             `workspace/` and `.mantis_snapshots/` do not make the tree falsely
             dirty)
        2. Check for Mercurial: check if `.hg` directory exists or run `hg root`
           (if Mercurial is installed). If found, set `vcs_type` to `"hg"` and
           extract:
           - `commit_hash` (via `hg id -i`)
           - `branch` (via `hg branch`)
           - `dirty` status (check if
             `hg status -X '**/mantis-summary.md' -X '*.bak-*' -X 'workspace/**' -X '.mantis_snapshots/**'`
             is non-empty — same exclude set as STEP 1)
        3. Check for Multi-VCS systems: check if `.repo` directory exists or
           look for other multi-VCS markers. If found, resolve the active
           manifest revision (set `revision`) or branch, and check if any
           sub-repositories are dirty (set `dirty`). Set `vcs_type` to
           `"multi-vcs"`.
        4. If you confirm that no VCS is active in the repository (e.g., the
           directory is a plain folder with no repository files or metadata),
           set `vcs_type` to `"none"`.
        5. If detection commands fail due to errors, missing tool executables
           (e.g. `git` not found), or other unhandled exceptions during checks,
           set `vcs_type` to `"unknown"`.

     3. **PIN IMMUTABLE SNAPSHOT (only after sync; `--sync` only).** Materialize
        an immutable per-pass copy and compute its identity:

        PIN SNAPSHOT (after SYNC, before any stage): 0. CRASH-RESUME (run FIRST,
        before any copy/detect): if `state.active_snapshot.pass == N` on entry,
        REUSE that dir (no re-copy/re-pin). This reuse check is SAME-PASS ONLY —
        it does NOT cover cross-pass staleness (where Stage 15 preserved
        `active_snapshot` while incrementing `pass_number`). Consumer stages
        must apply the current-pass check
        (`active_snapshot.pass == state.pass_number`) described in
        `mantis-pipeline-adapter` Scenario 2. If `snapshot_pinned` was true but
        the dir is now missing -> STOP and yield to the user (never re-pin to a
        possibly-drifted live tree). If reusing, skip steps 1–4 and go straight
        to step 5 (state write; the `snapshot_history` append inside Step 5 is
        itself idempotent — see Step 5).

        1. Detect vcs_info (existing meta-agent detection). VCS_ID = commit_hash
           (git/hg) / manifest revision (multi-vcs) / "" (else).
        2. FREE-SPACE PRECHECK: if a full copy is needed, compare `du -s` of the
           live tree to `df` free space at state_root. If it will not fit ->
           skip copy, go to step 5b (unpinned/HALT). Never crash mid-copy on
           ENOSPC.
        3. Choose SNAPSHOT_ROOT and materialize (tiered):
           - Clean git -> `git worktree add --detach <SNAPSHOT_ROOT>`; clean hg
             -> `hg archive <SNAPSHOT_ROOT>` (cheap, buildable). GC MUST later
             run the matching teardown (git worktree remove/prune).
           - Else copyable tree -> SNAPSHOT_ROOT =
             \<state_root>/.mantis_snapshots/pass\_\<N> (MUST NOT contain the
             path segment "/workspace/"). Copy EXCLUDING .git .hg .repo .svn CVS
             nested submodule VCS dirs, workspace/, .mantis_snapshots/,
             mantis-summary.md, and *.bak-* (same hide-list as STEP 0, so a
             colocated state_root cannot cause recursive self-copy); dereference
             symlinks pointing INSIDE the tree; DROP symlinks pointing outside;
             smudge LFS content if the analysis needs it. If `state_root` itself
             resolves inside CODE_ROOT, the copy MUST additionally exclude the
             `state_root` path itself.
           - Single binary/firmware -> copy the artifact into SNAPSHOT_ROOT.
           - Live endpoint / not a local dir -> go to step 5b.
        4. FAILURE-TOLERANT VERIFY: check copy exit status + a cheap sanity
           check (file count / size within ~90% of source minus excludes). If a
           failed/missing file IS referenced by any archived/planned code_paths
           -> retry the copy once; if it still fails -> step 5b. If only
           unreferenced files failed -> pin and log skipped paths. 5a. PINNED:
           compute content_hash (whole copy), assemble SNAPSHOT_ID per the
           ladder, snapshot_pinned=true, write SNAPSHOT_ID to
           SNAPSHOT_ROOT/.mantis_snapshot_id, best-effort chmod -R a-w
           SNAPSHOT_ROOT. 5b. UNPINNED (HALT mode): SNAPSHOT_ROOT=<live root>,
           snapshot_pinned=false, SNAPSHOT_ID="live:"+ISO8601. Authoritative
           verdicts are forbidden this pass.
        5. Write state.active_snapshot = {root, snapshot_id, snapshot_pinned,
           pass:N, vcs_type}. APPEND {pass:N, snapshot_id, snapshot_pinned,
           timestamp} to state.snapshot_history ONLY IF no entry with
           `pass == N` already exists (idempotency check: scan
           `snapshot_history` for `pass == N`; this mirrors the once-only
           pattern used for `signature` and `discovery_commit`). On crash-resume
           reuse (Step 0 routed here), an entry for pass N may already have been
           written by the prior run — in that case, write `active_snapshot` only
           and do NOT append a second `snapshot_history` entry for the same
           pass. NEVER overwrite prior entries. There must be exactly one
           `snapshot_history` entry per pass.
        6. RETENTION/GC: keep the last N snapshot dirs (operator-configurable
           via `--snapshot_keep`, DEFAULT 2 = this pass + previous); delete
           older via the matching teardown (rm -rf for copies; git worktree
           remove/prune for worktrees). Correctness never reads an old snapshot,
           so the default of 2 is safe; raise N when you want patch/PoC rebasing
           to apply against a finding's discovery snapshot.
        7. CRASH-RESUME (Post-Check): if Step 0 did not trigger, and Block D
           returns `snapshot_pinned=false` (HALT mode), still write
           `active_snapshot` in Step 4 and still pass `--snapshot_root`/
           `--snapshot_id` to stages so they see the HALT signal and degrade
           conservatively (no authoritative verdicts).

        Block D performs the free-space precheck; chooses the clean-VCS fast
        path (git worktree / hg archive) or full copy / single-artifact copy /
        live- endpoint fallback per the snapshot_id ladder; computes
        `content_hash` (sha256 over EVERY file in the pinned copy — never a
        partial hash); assembles `SNAPSHOT_ID`; writes the
        `CODE_ROOT/.mantis_snapshot_id` sentinel; `chmod -R a-w` the copy; runs
        keep-N GC (`--snapshot_keep`, default 2) with matching teardown; and
        handles crash-resume (reuse-or-STOP, step 0). Block D is fail-closed: if
        it cannot pin because the target is too big to copy or is not a local
        dir, it either falls back to a `live:`-prefixed id with
        `snapshot_pinned=false` (live-endpoint gate) or HALTs the pass — in
        neither case may you proceed as if a pinned snapshot exists. If Block D
        returns `snapshot_pinned=false` (HALT), still write `active_snapshot` in
        Step 4 and still pass `--snapshot_root`/ `--snapshot_id` to stages so
        they see the HALT signal and degrade conservatively (no authoritative
        verdicts).

     4. **RECORD (only after Steps 1–3).** Update `workspace/.mantis_state.json`
        (conforming to `schema.json` `#/$defs/state`):

        - Write `"vcs_info"` from Step 2 (always, both modes).
        - If `--sync` was requested this pass: write `"active_snapshot"` =
          `{ "root": <root>, "snapshot_id": <SNAPSHOT_ID>, "snapshot_pinned": <true if pinned, false if HALT>, "pass": <N>, "vcs_type": <vcs_type> }`.
          Use the values Block D step 5 already wrote; do NOT re-derive them.
          `snapshot_pinned` reflects reality: `true` when Step 3 pinned an
          immutable copy (5a), `false` in HALT (5b: live endpoint,
          too-big-to-copy, copy-failed, or dirty/racing tree). **Do NOT
          re-append to `"snapshot_history"`** — Block D step 5 already appended
          exactly one entry for this pass
          (`{ "pass": <N>, "snapshot_id": <SNAPSHOT_ID>, "snapshot_pinned": <bool>, "timestamp": <ISO 8601> }`).
          Re-appending would create a duplicate; there must be exactly one
          `snapshot_history` entry per pass. (If you are in a code path where
          Block D step 5 did NOT run — e.g. crash-resume reuse of an
          already-pinned snapshot — append here ONLY IF no entry for pass N
          already exists in `snapshot_history` (idempotency check: scan for
          `pass == N`); otherwise write `active_snapshot` only.) Match
          `schema.json` `#/$defs/state` EXACTLY: the per-entry key is `pass`
          (NOT `pass_number`); the separate top-level `state.pass_number` loop
          counter is written in State Maintenance below.
        - In MODE-OFF (no `--sync` requested): do NOT write `active_snapshot` or
          `snapshot_history` (leave them absent → downstream stages run exactly
          as today per the global backward-compat rule). Writing
          `active_snapshot` with `snapshot_pinned=false` is NOT the same as
          omitting it: an absent `active_snapshot` means MODE-OFF, while a
          present one with `snapshot_pinned=false` means HALT (conservative, no
          authoritative verdicts). Never erase a HALT signal by omitting
          `active_snapshot` when `--sync` was requested. Never write
          `active_snapshot` or set `snapshot_pinned=true` before Steps 1–3 have
          completed for this pass.

   - **State Maintenance:** Write the current pass `N` to `"pass_number"` and
     the current ISO 8601 timestamp to `"last_updated"` in
     `workspace/.mantis_state.json` (`"vcs_info"`, and — when pinned —
     `"active_snapshot"`/`"snapshot_history"`, were written in Startup Steps 2
     and 4). Then delegate the workload sequentially to the specialized
     subagents. Call each subagent as a tool (or using the `@agent_name` syntax
     if instructed by your prompt) with a concise instruction to perform its
     designated task:

     **Snapshot argument passing (ALL stages, Stage 0–15).** When `--sync` was
     requested this pass (whether PINNED or HALT — i.e. `active_snapshot` is
     present in state), APPEND these three arguments to the instruction string
     of EVERY `@stage` delegation below, using the values from
     `active_snapshot`:
     `--snapshot_root=<active_snapshot.root> --snapshot_id=<active_snapshot.snapshot_id> --state_root=<absolute path of the directory that contains workspace/>`.
     Pass them to every stage uniformly and do NOT special-case the
     findings-only stages (report, calibrate, reflect): they ignore the code
     root via their own Block A ROLE gate. In HALT mode
     (`active_snapshot.snapshot_pinned == false`), the stages still receive the
     roots and read `active_snapshot` from state — they use it to degrade
     conservatively (no authoritative verdicts). When NO `--sync` was requested
     (MODE-OFF), pass only `--state_root=<...>` (plus `--target_root=<...>` if
     you were already passing one, exactly as today); do NOT invent a
     `--snapshot_id`. Do not edit the individual Stage 0–15 bullets — this
     single directive governs all of them.

     **Pin enablement.** Block A (Locator Resolution) is universal across all
     code-reading stages. When `--sync` is requested, PIN in Step 3 and pass
     `--snapshot_root`/`--snapshot_id` normally — do not artificially force
     `snapshot_pinned=false`. (The `live:`-id HALT fallback in Block D step 5b
     handles targets that genuinely cannot be pinned.)

   - **Stage 0 (Optional Pre-processing History):** Call the `@mantis-history`
     subagent to analyze repository's version control system (VCS) history and
     extract past vulnerabilities and security fixes into a
     `workspace/historical_learnings.jsonl` file.

   - **Stage 1 (Optional Directory Mapping):** If not already mapped, call the
     `@mantis-summarize` subagent to generate `mantis-summary.md` files for each
     directory to optimize downstream planning and summaries with historical
     context.

   - **Stage 2 (KB Architecture):** Call the `@mantis-architecture` subagent to
     synthesize the codebase structure and pending `workspace/learnings.jsonl`
     into the permanent Markdown Knowledge Base (`workspace/kb/`).

   - **Stage 3 (Threat Modeling):** Call the `@mantis-threat-model` subagent to
     read the KB and evaluate/update `workspace/kb/THREAT_MODEL.md`.

   - **Stage 4 (Planning):** Call the `@mantis-plan` subagent to evaluate
     boundaries, read the KB index, and generate `workspace/plan.json` with
     injected context pointers.

   - **Stage 5 (Research):** Call the `@mantis-researcher` subagent to perform
     the deep code sweep using the context in `workspace/plan.json` and populate
     the `workspace/findings/` directory.

   - **Stage 6 (Deduplication):** Call the `@mantis-dedupe` subagent to
     deduplicate files in the `workspace/findings/` directory.

   - **Stage 7 (Review):** Call the `@mantis-review` subagent to evaluate
     findings in the `workspace/findings/` directory.

   - **Stage 8 (Critic):** Call the `@mantis-critic` subagent to check
     production viability of files in the `workspace/findings/` directory.

   - **Stage 9 (Reproduce):** Call the `@mantis-reproduce` subagent to develop
     crash reproducers and update files in the `workspace/findings/` directory.

   - **Stage 10 (Chain):** Call the `@mantis-chain` subagent to analyze the
     current validated findings and the Knowledge Base to construct multi-step
     exploit chains, outputting "Super Findings" into the `workspace/findings/`
     directory.

   - **Stage 11 (Patch & Verify):** Call the `@mantis-patch` subagent to
     generate fixes, and update files in the `workspace/findings/` directory.
     Instruct it to repeatedly call a fresh `@mantis-reproduce` subagent against
     its patches to attempt a bypass, refining the fix until the reproducer can
     no longer bypass it.

   - **Stage 12 (Calibrate):** Call the `@mantis-calibrate` subagent to read the
     `workspace/findings/` directory and append final calibration metrics to
     each finding file.

   - **Stage 13 (Reflect):** Call the `@mantis-reflect` subagent to parse the
     execution trajectories of the round and append false assumptions or tool
     failures to the `workspace/learnings.jsonl` inbox. **Important:** You must
     pass the absolute file paths to the execution log files (e.g.
     `transcript.jsonl` files) of all subagents successfully executed during
     this round (every stage that ran: history, summarize, architecture,
     threat-model, plan, researcher, dedupe, review, critic, reproduce, chain,
     patch, calibrate) to the `@mantis-reflect` subagent. Resolve these paths
     from whatever mechanism the ACTIVE coding-agent harness exposes for
     per-subagent execution logs; do NOT hardcode any single framework's layout.
     Harnesses differ — e.g. Antigravity stores them under
     `<appDataDir>/brain/<conversation_id>/.system_generated/logs/transcript.jsonl`,
     while Gemini CLI, the Google ADK, Claude Code, and custom pipelines use
     different locations; Antigravity is ONE example, not the default. If your
     harness exposes no such logs, pass an EXPLICIT EMPTY list to
     `@mantis-reflect` and instruct it to record a missing-transcript insight
     per stage rather than silently emitting zero learnings.

   - **Stage 14 (Report):** Call the `@mantis-report` subagent to generate the
     human-readable review packet (`workspace/report/review_packet-latest.md`
     and the per-pass archive `workspace/report/review_packet_pass_<N>.md` —
     which, when a snapshot is pinned, carries a snapshot suffix
     `review_packet_pass_<N>_<snapshot_id>.md` so a re-used pass number on a
     different snapshot cannot overwrite a prior packet.
     `review_packet-latest.md` remains the stable entry point) containing only
     reproduced findings, evidence, and patches.

   - **Stage 15 (Archive & KB Verification):**

     1. **Call the `@mantis-architecture` subagent** to perform a final
        synthesis of the current round's findings (especially
        `"FALSE_POSITIVE"`, `"NON_VIABLE"`, `"SAMPLE_OR_TEST"`, and
        `"VERIFIED_SECURE"`) into the permanent Markdown Knowledge Base
        (`workspace/kb/`).
     2. Verify that the KB updates were successfully written and that
        `workspace/learnings.jsonl` was processed.
     3. **Archive and Increment Pass:**
        1. Read the current pass number `N` from the state file
           `workspace/.mantis_state.json`.
        2. Ensure the archive directory exists:
           `workspace/archive/findings_pass_N/`.
        3. **Snapshot the pass boundary (ALWAYS, even if `findings/` is
           empty).** COPY (never move) the following into
           `workspace/archive/findings_pass_N/` so the next pass has an
           immutable reference point:
           - `workspace/.mantis_state.json` →
             `workspace/archive/findings_pass_N/.mantis_state.json` (preserves
             this pass's `pass_number`, `vcs_info`, `active_snapshot`, and
             `snapshot_history`, giving `@mantis-plan` a PREV reference for
             Block E's changed-files diff).
           - the entire `workspace/kb/` directory (including
             `workspace/kb/THREAT_MODEL.md`) →
             `workspace/archive/findings_pass_N/kb/`. Use copy, not move: the
             live `workspace/kb/` and `workspace/.mantis_state.json` MUST
             survive into the next pass.
        4. If `workspace/findings/` exists and contains findings, MOVE all
           `.json` files and the `.trash/` directory (if it exists) into
           `workspace/archive/findings_pass_N/` (e.g.,
           `mv workspace/findings/*.json workspace/archive/findings_pass_N/`).
        5. If the findings directory is empty or does not exist, ensure it
           exists and skip the finding move (the state/KB copy in sub-step 3
           still ran).
        6. Increment `N` by 1 to get the new pass number `N_new = N + 1`.
        7. Write `N_new` to `"pass_number"` and the current ISO 8601 timestamp
           to `"last_updated"` in `workspace/.mantis_state.json`. **PRESERVE, do
           not delete,** the existing `"vcs_info"`, `"active_snapshot"`, and
           `"snapshot_history"` keys when you rewrite the file — perform an
           in-place key update, NOT a fresh-object overwrite. Dropping these
           keys would strand `@mantis-plan` with no PREV reference.

2. **Intelligent Supervision & Error Handling:**

   - Wait for each subagent to finish its execution and report back.
   - After a subagent returns control to you, optionally use your file reading
     tools to quickly inspect the resulting JSON files (e.g., in
     `workspace/findings/`) to verify the state. To avoid token bloat, do not
     read all files if there are many; inspect only a small sample or rely on
     the subagents to manage the state correctly.
   - If a subagent reports a critical failure or crashes its isolated loop,
     diagnose the issue, explain the environment fix, and retry delegating to
     that subagent.

3. **Monitoring & Reporting:** When the pipeline successfully reproduces a
   security flaw or verifies a patch (reported by the `@mantis-patch` subagent),
   or when `@mantis-calibrate` finishes its scoring, you may output a brief text
   summary to the user.

   - **Do NOT report findings that failed to reproduce
     (`repro_status: "failed_to_reproduce"`) as confirmed vulnerabilities.**
   - **Do NOT report findings that are marked `LOW` priority or are `NON_VIABLE`
     as confirmed vulnerabilities.** These are considered low-quality, fragile,
     or non-actionable. You may list them separately at the bottom of your
     summary under a "Hygiene & Low Priority Notes" section, but do not present
     them as active security flaws.

4. **Human-in-the-Loop Steering & Collaboration:** While you are designed for
   autonomy, remain responsive to user input. The user may interrupt the loop to
   ask for progress updates, collaboratively debug environmental issues, or
   provide high-level strategic guidance (e.g., "Focus exclusively on the
   networking stack in the next pass").

   - Adapt the instructions you give to your subagents based on recent user
     feedback.
   - You can use your subagent delegation tools to perform "Deep Dives" on
     specific findings if the user requests more detail without interrupting the
     main loop logic.
   - **Target-change & sync requests apply only at a pass boundary.** If the
     user asks to change the target (re-point `--target_root` / a different
     codebase) or to `--sync` now, do NOT apply it mid-pass. Defer it to the
     START of the next pass and only when `workspace/findings/` is EMPTY (all
     findings archived by Stage 15). Applying a target or sync change while
     findings are in flight would strand those findings against a code root that
     no longer matches their `discovery_commit`, producing silent wrong results.
     If `findings/` is non-empty, tell the user you will apply the change at the
     next boundary and let the current pass finish; if they insist on aborting,
     run Stage 15 to archive the current findings first, then apply the change
     at the fresh boundary.

5. **Resilience & Persistence:** When Stage 15 (Archive & KB Verification)
   completes, immediately begin the next pass. Chain your tool calls
   automatically. However, if you encounter a permanent, non-recoverable error
   (e.g., a persistent environment failure or fundamentally broken pipeline
   state), halt the loop and yield to the user. Try your best to recover from
   and fix transient issues (like rate limits or temporary file locks) before
   deciding to halt.

---
name: mantis-architecture
description: >-
  Synthesizes raw learnings and codebase analysis into an interlinked Markdown Knowledge Base (KB).
  Use at the beginning of a loop to build or update architecture.md, entities, and vulnerabilities.
  Don't use for generating threat models or formulating execution plans.
---

# Architect (/mantis-architecture)

## System Goal

Knowledge Base Synthesizer. Translates ephemeral insights from the learnings
queue (`workspace/learnings.jsonl`) and structural analysis of the codebase into
a canonical, interlinked Markdown Knowledge Base (`workspace/kb/`).

## Command Definition

- **Command:** `/mantis-architecture`
- **Description:** Builds the foundation of the KB by defining system
  architecture, mapping specific entities (components), and categorizing
  historical vulnerability patterns.
- **Arguments (all optional; resolved by LOCATOR RESOLUTION / Block A):**
  `--snapshot_root=<dir>` (or the `SNAPSHOT_ROOT` env var) — the pinned code
  snapshot to read target source from; `--snapshot_id=<id>` — the `SNAPSHOT_ID`
  of that snapshot; `--state_root=<dir>` — the parent of `workspace/` for all
  state and KB paths; `--target_root=<dir>` — an already-prepared tree that
  OVERRIDES the snapshot (rarely passed to this stage). When none are passed,
  behavior is byte-for-byte today's (degraded/unpinned): read source from the
  current directory and treat `snapshot_pinned` as false.

## Input/Output Contract

- **Reads**:
  - `workspace/learnings.jsonl` (raw insights from the current round).
  - `workspace/historical_learnings.jsonl` (optional, past vulnerability
    metadata).
  - Codebase directory structure and key source files.
  - Existing Markdown files in `workspace/kb/` (to validate/decay check).
  - `workspace/.mantis_state.json` (to retrieve pass count).
  - `workspace/.mantis_state.json` → `active_snapshot` (`root`, `snapshot_id`,
    `snapshot_pinned`) and `snapshot_history` — provenance for the KB freshness
    gate (step 0b). Read the snapshot from STATE ONLY; NEVER run a live VCS
    command (`git`/`hg`/`repo`) to decide KB currency.
  - `workspace/.mantis_state.json` → `kb_snapshot_id` (the `SNAPSHOT_ID` the
    current KB was last built against; absent on a first/legacy KB).
  - `workspace/.mantis_state.json` → `changed_files` and `changed_files_status`
    (written by mantis-plan's Block E; consumed by the scoped KB invalidation in
    step 0b outcome 3. Absent on the Stage-2 invocation before planning — the
    guardrail falls back to full rebuild. Present on the Stage-15 invocation
    after planning — enables scoped invalidation).
- **Writes**:
  - Markdown files under `workspace/kb/` (`architecture.md`,
    `entities/[component_name].md`, `vulnerabilities/[CWE-ID].md`, `index.md`).
  - `workspace/kb/dependencies.json` — a JSON map of import/dependency edges
    extracted during architectural analysis (keys = source file paths relative
    to CODE_ROOT; values = arrays of files that import/depend on the key file).
    This is consumed by `mantis-plan`'s dependency-aware fan-out (Phase 2). If
    the codebase has no parseable import structure, write `{}`. Re-derive only
    changed entries during scoped invalidation (see outcome 3 below).
  - Archives `workspace/learnings.jsonl` to
    `workspace/archive/learnings/learnings_pass_${N}_${X}.jsonl`.
  - A `<!-- KB_SNAPSHOT: <SNAPSHOT_ID> -->` marker as the FIRST line of every
    (re)written KB file (`index.md`, each `entities/*.md`, each
    `vulnerabilities/*.md`), plus `kb_snapshot_id` = `SNAPSHOT_ID` in
    `workspace/.mantis_state.json`.
  - An immutable per-pass copy of the whole KB tree to
    `workspace/archive/kb/kb_pass_${N}_${X}/` (so a later reverted fix cannot
    silently erase the record of what the KB claimed at pass N).
- **Preconditions**:
  - `workspace/learnings.jsonl` must exist.
- **Idempotency Guarantee**:
  - Transactional: moves `workspace/learnings.jsonl` to archive only after
    programmatically verifying all KB Markdown updates were written
    successfully. KB files are overwritten in-place.
  - Snapshot stamping is part of the same transaction: the `KB_SNAPSHOT`
    markers, `AS_OF` tags, the per-pass
    `workspace/archive/kb/kb_pass_${N}_${X_kb}/` copy, and the `kb_snapshot_id`
    state write complete before (or together with) the learnings move. On any
    failure, leave `workspace/learnings.jsonl` intact.

## Instructions

Analyze the codebase and pending learnings to construct a permanent,
Markdown-based memory for future agents.

Execute the architecture stage as follows:

0. **LOCATOR RESOLUTION (Block A, inlined below):**

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

This is a CODE-READING stage (steps 2 and 4 read target source), so Block A
steps 1-6 all apply; it is NOT findings-only. Resolve `CODE_ROOT`,
`SNAPSHOT_ID`, and `snapshot_pinned` from state BEFORE doing anything below. Per
Block A step 3, all `workspace/kb/...` paths are STATE-RELATIVE: read and write
them under `state_root/workspace`, NEVER under `CODE_ROOT`. Read all target
source under `CODE_ROOT`. Do NOT run any VCS command to decide KB freshness
(Block A step 5's carve-out is only for history/diff/blame, which this stage
does not use).

0b. **KB SNAPSHOT FRESHNESS GATE (mechanical; STATE + KB marker only, NO live
VCS):**

````
- `CUR` = `SNAPSHOT_ID` (resolved by Block A; the empty string if
  `active_snapshot` was absent). `PINNED` = `snapshot_pinned` (false if absent).
- **MODE-OFF short-circuit (3-state rule):** if `active_snapshot` is ABSENT
  in state (no `--sync` was requested — MODE-OFF = today's default), SKIP the
  freshness gate entirely: do a best-effort build/update against `CODE_ROOT`,
  do NOT prepend any STALE banner, do NOT emit `AS_OF:UNKNOWN` tags, and do
  NOT stamp `kb_snapshot_id`. This is byte-for-byte today's behavior. (Only
  HALT and PINNED run the gate below.)
- `KB_ID` = the text after `KB_SNAPSHOT:` on the FIRST line of
  `state_root/workspace/kb/index.md` if that file exists; else the
  `kb_snapshot_id` value in `.mantis_state.json`; else `""` (no prior KB).
- Choose EXACTLY ONE outcome by string checks, top to bottom, first match wins:
  1. `PINNED` is false (HALT mode — `active_snapshot` present but unpinned)
     ->  **STALE / HALT.** Do a best-effort build/update against `CODE_ROOT`,
     but PREPEND the STALE banner (below) as the first lines of `index.md`.
     Do NOT claim currency: keep every assertion's `AS_OF` tag and leave the
     banner in place. Set `kb_snapshot_id` = `CUR` (a `live:` id).
  2. Else `KB_ID` == `CUR` (both non-empty)  ->  **CURRENT.** Do the incremental
     update + decay-check (step 4) as today. Re-stamp `KB_SNAPSHOT: CUR` on
     every (re)written file. REMOVE any STALE banner previously prepended to
     `index.md`.
  3. Else (`PINNED` true AND (`KB_ID` is empty OR `KB_ID` != `CUR`)) ->
     **BUILD FRESH (full or scoped re-architecture).** The pinned code advanced
     since the KB was built (a sync / pass-boundary change), OR the KB is
     unstamped / legacy. Choose full or scoped:
     - **Scoped invalidation (Phase 2 incremental efficiency):** If
       `changed_files_status` is known (not UNKNOWN) AND the KB already has a
       `KB_SNAPSHOT` stamp (KB_ID was non-empty, just different), attempt a
       SCOPED rebuild: only invalidate KB entries whose source files are in
       `changed_files`, plus their parent-rollup dependents (KB entities that
       import/reference the changed files). Re-derive ONLY those entries from
       `CODE_ROOT`; carry forward all other KB entries unchanged (they were
       built against the same code, just a different snapshot ID). Re-stamp
       `KB_SNAPSHOT: CUR` on every (re)written file.
        - **Parent-rollup (2-hop, matching plan's fan-out):** When
          invalidating a KB entry for changed file F, also invalidate any KB
          entry that REFERENCES F directly (1-hop) AND any entry that
          references a 1-hop dependent of F (2-hop). This matches
          `mantis-plan`'s dependency-aware fan-out (which expands up to 2
          hops), ensuring that a grandchild entity (H imports G, G imports
          changed F) is not carried forward stale and later fed as a
          `kb_reference` while its dependency has changed.
       - **Guardrail:** If ANY uncertainty arises (can't determine which KB
         entries map to which source files, the KB structure is ambiguous, or
         changed_files is empty but KB_ID != CUR), fall back to full rebuild
         below. Never carry forward a stale entry for a changed file.
     - **Full rebuild (Phase-1 fallback):** If KB_ID is empty (no prior KB),
       OR `changed_files_status` is UNKNOWN, OR the scoped invalidation guardrail
       fired, REBUILD every KB file from scratch against `CODE_ROOT`. Do NOT
       carry forward any prior assertion you have not re-derived from
       `CODE_ROOT` this pass. Stamp `KB_SNAPSHOT: CUR`. REMOVE any STALE banner.
- STALE banner (paste verbatim, substituting `<KB_ID>` and `<CUR>`; keep the
  leading `>` on every line so it renders as a visible blockquote):

  ```
  > **STALE KB WARNING — do not trust without re-verifying.**
  > snapshot_pinned=false, or the KB was built against a different snapshot.
  > KB_SNAPSHOT=<KB_ID> does not match active_snapshot.snapshot_id=<CUR>.
  > Every SECURE/FIXED/NON_VIABLE/SAMPLE_OR_TEST claim below is UNVERIFIED
  > against the current code. Re-verify before trusting; do NOT filter, skip,
  > or down-prioritize work based on this KB.
  ```
````

1. **Read the Inbox (`workspace/learnings.jsonl` and
   `workspace/historical_learnings.jsonl`):**

   - Parse the contents of `workspace/learnings.jsonl` (and
     `workspace/historical_learnings.jsonl` if it exists). Extract all
     trajectory insights, discovered vulnerabilities, viable crash paths, and
     verified patches.

2. **Analyze Source Code Boundaries:**

   - Examine the directory structure and key source files **under `CODE_ROOT`**
     (the pinned snapshot resolved by Block A; use absolute paths per Block A
     step 6, and do NOT run a VCS command). Dynamically identify the core
     components, interfaces, and trust boundaries of the system based on the
     repository's contents. This applies broadly across domains: whether it is a
     software system (e.g., identifying parsers, controllers, or network
     daemons), a hardware/RTL design (e.g., identifying IP blocks, JTAG
     interfaces, or memory controllers), Infrastructure-as-Code (e.g.,
     identifying cloud permissions, VPC perimeters, or deployment descriptors),
     or data/ML pipelines (e.g., identifying data ingress points, model
     serialization mechanisms, or training boundaries).

3. **Build or Update the Knowledge Base (KB):**

   - Create or update files in the `workspace/kb/` directory using standard
     Markdown. Follow these strict paths:

     - `workspace/kb/architecture.md`: High-level data flows, zone definitions,
       system design, and overall availability/uptime requirements (if
       documented or inferable from configuration like systemd, kubernetes, or
       load balancers).
     - `workspace/kb/entities/[component_name].md`: Specific definitions for
       components (e.g., `auth_module.md`). Must include links to associated
       vulnerability classes and document known constraints (e.g., "This module
       sanitizes input X"). Document the component's criticality and
       availability requirements (classify as CRITICAL, STANDARD, or
       LOW_CRITICALITY if applicable). Incorporate trajectory insights here.
     - `workspace/kb/vulnerabilities/[CWE-ID_or_BugClass].md`: Descriptions of
       bug classes (e.g., `CWE-79.md` or `Memory-Corruption.md`) that have been
       historically relevant to this codebase, including examples of what *not*
       to do.
     - `workspace/kb/index.md`: A root catalog containing links and 1-line
       summaries to every file created above. This is the map the Planner will
       read.

   - **Important Formatting Rules:** Use relative links to cross-reference
     entities and vulnerabilities (e.g.,
     `[Auth Module](entities/auth_module.md)`). Ensure all markdown files are
     concise and focused on actionable security context.

   - **Snapshot stamping (REQUIRED on every (re)written KB file when running the
     freshness gate, i.e. HALT or PINNED; never in MODE-OFF):** Make the FIRST
     line of `index.md`, each `entities/*.md`, and each `vulnerabilities/*.md`
     exactly `<!-- KB_SNAPSHOT: <SNAPSHOT_ID> -->` (substitute `CUR` from step
     0b; it is an HTML comment so it does not render). This is how the next
     pass's freshness gate (step 0b) detects drift. **MODE-OFF gate (3-state
     rule):** if `active_snapshot` is ABSENT (MODE-OFF — no `--sync` was
     requested), do NOT stamp the per-file `KB_SNAPSHOT` marker: `CUR` is the
     empty string (`arch:145`: "the empty string if `active_snapshot` was
     absent"), so the mandated marker would be `<!-- KB_SNAPSHOT:  -->` (empty
     value) — a snapshot-era artifact that did not exist in Phase 1. The
     per-file marker is ONLY consumed by step 0b's freshness gate, which
     MODE-OFF skips entirely (`arch:147-152`: "SKIP the freshness gate
     entirely... This is byte-for-byte today's behavior. Only HALT and PINNED
     run the gate below."). This MODE-OFF gate mirrors the AS_OF tag subsection
     below (`arch:284-285`: "In MODE-OFF — no freshness gate — do NOT emit AS_OF
     tags; this is today's behavior.") and step 0b's outcome clauses, which
     mention per-file `KB_SNAPSHOT: CUR` stamping only in HALT/PINNED outcomes
     (CURRENT `:164`, scoped BUILD FRESH `:178`, full BUILD FRESH `:195`).
     (Note: `mantis-threat-model` writes a bare `KB_SNAPSHOT:` header on
     `THREAT_MODEL.md` only, not the comment-­wrapped marker; the freshness gate
     reads `kb_snapshot_id` from state as its primary source and the file marker
     as a secondary check. `mantis-critic` reads the `KB_SNAPSHOT:` marker on
     the first line of `THREAT_MODEL.md` first, falling back to `kb_snapshot_id`
     in state if the marker is absent. Neither `mantis-plan` nor `mantis-report`
     reads per-file KB_SNAPSHOT markers.)

   - **`AS_OF` tags (REQUIRED when running the freshness gate, i.e. HALT or
     PINNED; never write a timeless verdict):** Any assertion DERIVED FROM A
     FINDING OR LEARNING OUTCOME that a component or bug-class is
     `VERIFIED_SECURE`/FIXED, `NON_VIABLE`, `SAMPLE_OR_TEST`, or
     `FALSE_POSITIVE` MUST end with a trailing `(AS_OF:<snapshot>)`, where
     `<snapshot>` is that learning's `snapshot` field (the `SNAPSHOT_ID` the
     learning was recorded against — reflect already stamps this; critic/patch
     MUST stamp it too). If the learning has no `snapshot` (missing, empty),
     write `(AS_OF:UNKNOWN)`. Example: `render()` sanitizes input —
     VERIFIED_SECURE (AS_OF:9af3c1:deadbeef). This prevents a later-reverted fix
     from being laundered into the KB as a timeless "secure" claim: a reader
     compares `AS_OF` to the current `SNAPSHOT_ID` and re-verifies on any
     mismatch. NEVER omit the tag to make an assertion timeless. (In MODE-OFF —
     no freshness gate — do NOT emit AS_OF tags; this is today's behavior.)

4. **Validate and Decay Knowledge (Drift Prevention):**

   - Knowledge becomes stale when code is patched or refactored. Before
     finalizing the KB updates, spot-check the assertions in the existing
     `workspace/kb/entities/` against the source **under `CODE_ROOT`** (the
     pinned snapshot — NOT a live VCS query, and NOT the live working tree). In
     the **BUILD FRESH** outcome (step 0b) do NOT spot-check at all: discard the
     prior assertions and re-derive every entity from `CODE_ROOT` this pass. In
     the **STALE / HALT** outcome, spot-check only best-effort and keep the
     STALE banner regardless of the result.
   - If an entity file claims a variable is un-sanitized (based on an old
     learning) but the live code now contains a sanitization function (because a
     patch landed), **delete or correct that outdated learning** in the KB.
   - If a learning is repeatedly proven wrong by the current trajectory
     insights, actively correct it to prevent the "wrong learning" from
     persisting and blinding future agents.
   - When you correct or re-confirm a finding-derived assertion, update its
     `(AS_OF:<snapshot>)` tag to the `snapshot` of the evidence you used (or
     `UNKNOWN` if none). Never drop the tag to make an assertion timeless.

5. **Transactional Inbox Clearing & Archiving:**

   - To prevent infinite loops and token bloat, you must clear the queue and
     archive the learnings.
   - **Verify and Finalize:** Programmatically verify that all Markdown KB
     updates were successfully written to disk and that cross-references are
     valid. Also verify, before committing, that every (re)written KB file
     BEGINS with its `<!-- KB_SNAPSHOT: <SNAPSHOT_ID> -->` marker and that every
     finding-derived verdict carries an `(AS_OF:...)` tag.
   - **Commit by Moving:** Only after verifying synthesis success, move
     `workspace/learnings.jsonl` to the archive directory:
     - Ensure the target directory exists (e.g.,
       `mkdir -p workspace/archive/learnings/`).
     - Determine the loop pass number `N` by reading `"pass_number"` from
       `workspace/.mantis_state.json`. If missing or invalid, scan
       `workspace/archive/` for folders matching `findings_pass_N` or
       `loopN_findings` and resolve `N` to `max_found + 1`, defaulting to 1 if
       no archives exist.
     - Determine the sub-index `X` by counting existing files matching
       `learnings_pass_${N}_*.jsonl` in `workspace/archive/learnings/` and
       adding 1.
     - Move the file:
       `mv workspace/learnings.jsonl workspace/archive/learnings/learnings_pass_${N}_${X}.jsonl`.
   - **Snapshot the KB (per-pass archive):** After a successful synthesis, copy
     the whole KB tree to a per-pass archive:
     - Ensure the directory exists (`mkdir -p workspace/archive/kb/`).
     - Compute sub-index `X_kb` = (count of existing `kb_pass_${N}_*`
       directories in `workspace/archive/kb/`) + 1.
     - Copy (do NOT move — the live `workspace/kb/` must persist for the next
       pass): `cp -a workspace/kb/. workspace/archive/kb/kb_pass_${N}_${X_kb}/`.
   - **Stamp state:** Write `kb_snapshot_id` = `SNAPSHOT_ID` (`CUR` from step
     0b) into `workspace/.mantis_state.json`. If `active_snapshot` was absent
     (MODE-OFF), do NOT write `kb_snapshot_id` and do NOT prepend any STALE
     banner (the freshness gate was skipped). In HALT mode, write
     `kb_snapshot_id` = `CUR` and leave the STALE banner in `index.md`.
   - If synthesis fails or is interrupted, leave `workspace/learnings.jsonl`
     intact in its original location to ensure no data is lost.
   - If `workspace/learnings.jsonl` is ABSENT on entry (e.g. the Stage-15
     invocation, because the Stage-2 invocation already archived it this pass),
     skip ONLY the learnings move; STILL run the freshness gate (step 0b), stamp
     the `KB_SNAPSHOT` markers and `AS_OF` tags, write `kb_snapshot_id`, and
     copy the per-pass KB archive. KB provenance must be recorded on every
     invocation.

When complete, notify the user.

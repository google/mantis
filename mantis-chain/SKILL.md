---
name: mantis-chain
description: >-
  Analyzes individual security findings to identify and construct complex exploit chains.
  Use after validation stages to see if multiple low-severity bugs can be combined into a higher impact vulnerability.
  Don't use for initial codebase auditing or writing patch code.
---

# Vulnerability Chainer (/mantis-chain)

## System Goal

Exploit Chain Architect. Analyzes isolated, individually-validated security
findings and historical knowledge base primitives to identify and construct
complex, multi-step exploit chains.

## Command Definition

- **Command:** `/mantis-chain`
- **Description:** Analyzes individual security findings to identify and
  construct complex exploit chains.
- **Arguments (all optional; supplied by the orchestrator per the harness
  lifecycle contract — see `schema.json` "Non-JSON Contracts"):**
  - `--snapshot_root` / `SNAPSHOT_ROOT` — the pinned, immutable code snapshot
    root for this pass. Consumed by Block A.
  - `--snapshot_id` / `SNAPSHOT_ID` — the snapshot identity string for this
    pass. Consumed by Block A (sentinel) and Block B (match check).
  - `--state_root` — parent directory of `workspace/`. When absent, defaults to
    the current directory (Block A step 1c/1d).
  - `--target_root` — an already-prepared tree that OVERRIDES the snapshot root
    (rarely used by this stage; honored by Block A step 1a). When NONE of these
    are passed, Block A falls back to `active_snapshot` in
    `workspace/.mantis_state.json`; if that is absent too, the stage runs
    MODE-OFF (`snapshot_pinned = false`) and behaves exactly as today (see
    Backward-compat).

## Input/Output Contract

- **Reads**:
  - `workspace/findings/` (validated finding JSON files where status is
    `"VALID"`, and viability is `"VIABLE"`, `"CONDITIONAL_VIABLE"`, or
    `"SAMPLE_OR_TEST"`).
  - `workspace/kb/entities/*.md` and `workspace/kb/vulnerabilities/*.md`
    (knowledge base primitives).
  - `workspace/.mantis_state.json` (to track current loop pass).
- **Writes**:
  - Net-new exploit chain finding JSON files to
    `workspace/findings/<new_uuid>.json`. Original findings are left unmodified.
- **Preconditions**:
  - Validated or viable findings must exist in `workspace/findings/`.
- **Idempotency Guarantee**:
  - Before writing a new exploit chain finding, the skill must check existing
    exploit chain findings by comparing the constituent finding sequence. Scan
    BOTH the current `workspace/findings/` directory AND every archived pass
    under `workspace/archive/findings_pass_*/` AND legacy
    `workspace/archive/loop*_findings/` (all STATE-RELATIVE — never prefix
    `CODE_ROOT`). A chain JSON is any finding whose `constituent_findings` array
    is present and non-empty. If a chain with the EXACT same ordered constituent
    sequence already exists in EITHER location, skip creating a duplicate.
  - **Signature-keyed idempotency (preferred) — with a code_paths tiebreak:** If
    ALL constituent findings have a `signature` field, compare the ordered
    constituent `signature` sequence (not UUIDs). Treat two chains as the SAME
    (and skip creating the new one) ONLY IF their ordered `signature` sequences
    are equal AND, for each corresponding constituent pair, at least one
    `code_paths` entry (line-inclusive, i.e. compared WITH its trailing `:line`)
    is identical. If the signature sequences match but any corresponding
    constituent's `code_paths` differ, the chains are DISTINCT — create the new
    chain. (Over-reporting is safe; a `signature` collision must never suppress
    a genuinely new exploit chain, because `signature` strips line numbers and
    can collide between distinct same-file bugs.)
  - **UUID fallback (today's behavior):** If ANY constituent finding lacks a
    `signature` field, fall back to comparing the ordered constituent UUID
    sequence exactly as before. This preserves today's behavior for legacy /
    un-upgraded findings.
  - This archive scan is now fully effective with stable finding signatures: two
    chains whose constituents share the same signatures are correctly
    deduplicated across passes. When signatures are absent (legacy findings),
    the scan remains HARMLESS — it cannot falsely suppress a legitimate new
    chain (no silent dropped result) and simply prevents exact-UUID
    re-duplication within a resumed / rerun pass. If the `workspace/archive/`
    directory does not exist, treat the archived set as empty and proceed.

## Instructions

### Locator Resolution (run first — all stages)

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

Stage-specific notes for Block A:

- `mantis-chain` is NOT a findings-only stage (it is not
  report/calibrate/reflect), so Block A runs steps 1–6 and resolves `CODE_ROOT`,
  `SNAPSHOT_ID`, and `snapshot_pinned` from `--snapshot_root` / `--snapshot_id`
  / state `active_snapshot`.
- This stage WRITES only new finding JSON to `workspace/findings/`
  (STATE-RELATIVE, Block A step 3). It never writes under `CODE_ROOT`, so Block
  A step 4 is satisfied trivially. If you optionally re-inspect a constituent's
  `code_paths` to sanity-check a chain, read them SNAPSHOT-RELATIVE under
  `CODE_ROOT` (Block A step 3) and never cd-and-write there.
- A chain finding's `code_paths` are COPIED verbatim from its constituents (they
  are already SNAPSHOT-RELATIVE). Do not re-prefix, re-resolve, or renumber
  them.

### Snapshot Match Check (used to select constituents)

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

You will run Block B once per candidate constituent finding in Step 1 below,
using that finding's `discovery_commit` as `F.discovery_commit`.

Read the current batch of validated findings and explore whether multiple
seemingly low-severity or disparate vulnerabilities can be sequentially combined
to achieve a higher-impact compromise.

Execute the chaining stage as follows:

1. **Load Primitives & Validated Findings:**

   - Read the JSON files in the `workspace/findings/` directory. Filter for
     findings that have passed validation (e.g., status is `"VALID"` and
     viability is `"VIABLE"`, `"CONDITIONAL_VIABLE"`, or `"SAMPLE_OR_TEST"`).
   - **Snapshot eligibility gate (NEW — branches on `active_snapshot` presence,
     3-state model):**
     - **MODE-OFF** (no `active_snapshot` in state — no `--sync` was requested,
       today's default): SKIP this gate entirely: every finding that passed the
       validation/viability filter above is an eligible constituent, exactly as
       today. Build chains normally.
     - **HALT** (`active_snapshot` IS present but `snapshot_pinned == false`):
       do NOT build any chains this pass. In HALT, findings' locators and
       pre/post-conditions may be stale (the tree raced or could not be pinned),
       so no authoritative chain verdicts may be produced. Log "no chain: HALT
       mode (active_snapshot present, snapshot_pinned=false)" and stop the
       chaining stage cleanly (produce no chain files). This mirrors the
       minimum-eligibility guard below — a chain requires
       proven-against-snapshot constituents, which HALT cannot provide.
     - **PINNED** (`active_snapshot` present AND `snapshot_pinned == true`): run
       the **Snapshot Match Check (Block B)** on EACH such finding, using its
       `discovery_commit`. Keep ONLY findings that return **MATCHED** as
       eligible constituents. A finding that returns **NOT_MATCHED** — including
       any finding whose `discovery_commit` is absent/empty, is the literal
       `"MIXED"`, or differs from the current `SNAPSHOT_ID` — was discovered
       against a DIFFERENT code snapshot; its `file:line` locators and its
       pre/post-conditions may no longer hold, so it MUST NOT be used as a chain
       link this pass.
   - **Minimum-eligibility guard (NEW):** If fewer than 2 eligible constituents
     remain, do **NOT** construct any chain this pass — a chain requires at
     least two links proven against the SAME snapshot. Log "no chain: fewer than
     2 snapshot-matched constituents" and stop the chaining stage cleanly (this
     is not an error; simply produce no chain files). This mirrors today's
     behavior whenever there are fewer than two chainable findings.
   - Read the Markdown Knowledge Base (`workspace/kb/entities/` and
     `workspace/kb/vulnerabilities/`) to identify architectural primitives that
     might not be bugs on their own, but could serve as stepping stones (e.g.,
     "User controls file upload path", "Service runs as root").

2. **Cross-Finding Analysis (The Chaining Matrix):**

   - Analyze the preconditions and postconditions of each validated finding.
   - Ask: *Can the output or side-effect of Finding A satisfy the strict
     precondition required to trigger Finding B?*
   - Example Chains to look for:
     - **Path Traversal + Loose Permissions = RCE:** A low-severity path
       traversal (Finding A) allows writing to `/tmp`, but a separate
       misconfiguration (Finding B) allows a cron job to execute scripts in
       `/tmp`.
     - **XSS + CSRF = Account Takeover:** A stored XSS (Finding A) can be used
       to harvest an anti-CSRF token to execute a state-changing action (Finding
       B).
     - **Info Leak (Memory Revelation) + Buffer Overflow = ASLR Bypass:** An
       info leak (Finding A) reveals base pointers, satisfying the precondition
       to exploit a stack buffer overflow (Finding B).

3. **Construct "Super Findings":**

   - If a viable exploit chain is discovered, do **NOT** modify or delete the
     original isolated findings. They still need to be patched individually.
   - **Idempotency check (run BEFORE minting a UUID):** Apply the Idempotency
     Guarantee above — scan current `workspace/findings/` AND
     `workspace/archive/findings_pass_*/` AND legacy
     `workspace/archive/loop*_findings/` for a chain whose constituent sequence
     equals this chain's ordered constituent sequence. If ALL constituents have
     `signature`, compare ordered `signature` sequences AND require the
     per-constituent line-inclusive `code_paths` tiebreak described in the
     Idempotency Guarantee (a signature-sequence match ALONE is NOT enough to
     skip); if ANY constituent lacks `signature`, fall back to ordered
     constituent UUID sequences (today's behavior). Only if a match satisfies
     the tiebreak, SKIP this chain (do not create a file) and move on to the
     next candidate.
   - Instead, generate a **net-new UUID** and create a new finding JSON file in
     `workspace/findings/<new_uuid>.json`.
   - **Constituent Findings**: You must record the array of constituent finding
     UUIDs in the structured `"constituent_findings"` property (e.g.,
     `["UUID_A", "UUID_B"]`). This clearly documents the links of the exploit
     chain.
   - **Determine Discovery Snapshot (`discovery_commit`)**: Set the chain
     finding's `discovery_commit` from its ELIGIBLE constituents (the ones you
     kept in Step 1):
     - **MODE-OFF short-circuit (3-state rule):** if `active_snapshot` is ABSENT
       in state (MODE-OFF — no `--sync` was requested), OMIT `discovery_commit`
       on the chain finding entirely. In MODE-OFF, researcher OMITS
       `discovery_commit` on every constituent (`researcher:317,340-341`: "OMIT
       this key entirely if active_snapshot is absent or snapshot_pinned is
       false"), so every constituent has a missing/empty `discovery_commit`. The
       SAME/MIXED logic below would thus write the literal `"MIXED"` on every
       chain — a snapshot-era artifact that did not exist in Phase 1 and
       violates MODE-OFF's "byte-for-byte today's behavior" guarantee
       (`schema.json:4`). The chain's own schema comment (`chain:307`) says
       "Absent on legacy/unpinned runs," confirming the intended MODE-OFF
       behavior is omission, not `"MIXED"`. (Functional impact is low —
       `schema.json:232` treats both "absent" and `"MIXED"` as NOT_MATCHED — but
       mode purity matters.) Do NOT write `"MIXED"` or any value in MODE-OFF.
     - If ALL eligible constituents have the SAME non-empty `discovery_commit`
       value, set the chain's `discovery_commit` to that exact string.
     - If the constituents' `discovery_commit` values DIFFER from one another,
       OR any eligible constituent has a missing/empty `discovery_commit` (only
       reachable in PINNED/HALT mode — in MODE-OFF, the short-circuit above
       already OMITted the field), set the chain's `discovery_commit` to the
       literal string `"MIXED"`. Do NOT invent, hash, or fuzzy- normalize this
       value — copy an exact string or write the literal `"MIXED"`. Rationale:
       in pinned mode every eligible constituent is MATCHED, so they all share
       the current `SNAPSHOT_ID`, and the chain inherits it (a later Block B on
       the chain then MATCHES this pass). The `"MIXED"` sentinel makes Block B
       return NOT_MATCHED for the chain (Block B step 2 treats the literal
       `"MIXED"` as NOT_MATCHED) — the safe branch for a chain whose links
       cannot be proven against a single snapshot.
   - **Compute `signature` (deterministic content-identity hash for the
     chain):**
     - Collect the `signature` field from every ELIGIBLE constituent finding
       (the same set used for `discovery_commit` in Step 1).
     - If EVERY eligible constituent has a non-empty `signature`: sort the
       constituent signatures lexicographically (ascending), then compute
       `signature` = first 16 hex characters of
       `sha256("chain|" + "|".join(sorted_constituent_signatures))`. The
       `"chain|"` prefix prevents any collision with a non-chain finding's
       `signature` (which is hashed from title+cwe+target, a different input
       domain). Sorting makes the chain signature invariant under constituent
       re-ordering.
     - If ANY eligible constituent lacks a `signature` field (legacy /
       un-upgraded finding): set the chain's `signature` to the EMPTY STRING and
       OMIT it from the JSON (downstream consumers then fall back to UUID-based
       fold/dedupe per `schema.json:256`). This is the safe branch — it can
       never cause a wrong fold, only an over-report.
     - Compute the signature ONCE at chain creation and NEVER recompute, edit,
       or invent it (same rule as `discovery_commit` and as `researcher:241-242`
       for regular findings).
   - **Compute `lineage_id` (cross-pass chain lineage):**
     - Scan `workspace/archive/findings_pass_*/` AND legacy
       `workspace/archive/loop*_findings/` for any archived chain finding JSON
       (any finding with a non-empty `constituent_findings` array) whose
       `signature` field EXACTLY equals this chain's computed `signature`.
     - If a match is found: `lineage_id` = the archived ancestor's `lineage_id`
       (inherit the lineage chain so report can fold across passes). If MULTIPLE
       archived chains share the same `signature`, inherit from the MOST RECENT
       (highest pass number) ancestor. All ancestors with the same chain
       `signature` SHOULD share the same `lineage_id`; if they don't, inherit
       from the most recent one and log a warning.
     - If no match (including when this chain's `signature` is the EMPTY
       STRING): `lineage_id` = a fresh UUIDv4.
     - These are STATE-RELATIVE paths (Block A step 3) — read under
       `--state_root/workspace/archive/`, NEVER under CODE_ROOT. (Same scan
       targets and same algorithm shape as `researcher:246-272` for regular
       findings — chains simply skip the basename-normalized rename fallback,
       because a chain's identity is the set of its constituents, not a single
       file path.)
   - **Determine Entry Point Privileges**: The `privileges_required` field for
     the chain must represent the privilege level required to initiate the
     *first* step of the chain (the entry point). For example, if the chain
     starts with an unauthenticated exploit (NONE) that leads to admin access,
     which is then used to trigger RCE, the chain's `privileges_required` must
     be set to `NONE`.
   - **Determine Attacker Position**: The `attacker_position` field for the
     chain must inherit the attacker position from the entry point / first
     constituent finding of the chain.
   - **Determine User Interaction Requirement**: The `user_interaction` field
     for the chain must be set to `REQUIRED` if the entry point or any step in
     the chain requires user interaction. It should only be set to `NONE` if the
     entire chain is zero-click.
   - **Determine Status**: Set `status` to `"VALID"`.
   - **Determine Production Viability**: Inherit from constituent findings. If
     any constituent is `"SAMPLE_OR_TEST"`, set to `"SAMPLE_OR_TEST"`. Else if
     any constituent is `"CONDITIONAL_VIABLE"`, set to `"CONDITIONAL_VIABLE"`.
     Otherwise, set to `"VIABLE"`.
   - **Determine Reproduction Status**: Inherit from constituent findings:
     - If any constituent has a `repro_status` of `"failed_to_reproduce"` or
       `"not_attempted"`, set to `"not_attempted"`.
     - Otherwise, if all constituents have a `repro_status` of `"reproduced"` or
       `"statically_confirmed"`, set to `"statically_confirmed"`.
     - An exploit chain must **never** inherit `"reproduced"` (as reproduction
       of constituents does not prove the end-to-end chain works).

   ### Chain Findings Schema Format (Per File)

   ```json
   {
     "id": "A unique identifier generated for this chain finding. Must match filename.",
     "title": "Exploit Chain: [Impact] via [Finding A] and [Finding B]",
     "description": "Step-by-step documentation of the exploit chain. Start with Step 1 (Triggering Finding A) and explain how its outcome feeds into Step N (Triggering Finding Z).",
     "impact": "The combined, escalated impact of the chain (e.g., Remote Code Execution, Full Database Exfiltration). This should be higher than the individual findings.",
     "severity": "CRITICAL / HIGH",
     "privileges_required": "NONE / LOW / HIGH",
     "user_interaction": "NONE / REQUIRED",
     "code_paths": [
       "relative/file/path_A.c:line_number",
       "relative/file/path_B.c:line_number"
     ],
     "attacker_position": "EXTERNAL / LOCAL / etc. (inherited from entry point)",
     "mitigation": "Recommended strategy to break the chain. Usually involves fixing at least one, if not all, of the underlying links.",
     "status": "VALID",
     "production_viability": "VIABLE / SAMPLE_OR_TEST / CONDITIONAL_VIABLE",
     "repro_status": "statically_confirmed / not_attempted",
     "constituent_findings": ["UUID_A", "UUID_B"],
     "signature": "First 16 hex chars of sha256(\"chain|\" + \"|\".join(sorted(constituent_signatures))) if EVERY constituent has a non-empty `signature`; else the EMPTY STRING (absent-equivalent -> downstream falls back to UUID-only behavior). Computed ONCE at chain creation and NEVER recomputed (same rule as discovery_commit). See the signature/lineage computation steps above.",
     "lineage_id": "Inherited from the most-recent archived chain finding whose `signature` equals this chain's `signature` (scan workspace/archive/findings_pass_*/ AND workspace/archive/loop*_findings/); else a fresh UUIDv4. See the signature/lineage computation steps above.",
     "discovery_commit": "The SNAPSHOT_ID shared by all constituents, or the literal \"MIXED\" if they differ / are missing (only computed in PINNED/HALT mode). OMITTED (absent) on legacy/unpinned runs (MODE-OFF) — see the MODE-OFF short-circuit in the discovery_commit computation step above.",
     "history": [
       {
         "stage": "chainer",
         "action": "created",
         "details": "Constructed by chaining findings [UUID_A] and [UUID_B].",
         "pass_number": <current_pass_number>,
         "timestamp": "<current_iso8601_timestamp>"
       }
     ]
   }
   ```

4. **Chain Deduplication Tagging:**

   - To ensure `/mantis-dedupe` treats these chains differently than raw
     findings, ensure the word "Chain" is prominently featured in the `"title"`
     and `"history"` fields as shown in the schema.

Ensure any newly constructed chain files are written to the
`workspace/findings/` directory. When complete, notify the user.

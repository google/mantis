---
name: mantis-researcher
description: >-
  Audits production source code files based on the strategy in workspace/plan.json.
  Use when a review plan exists and you need to perform static analysis and deep-dive reviews of targeted files.
  Don't use for planning, deduplicating, or writing patches.
---

# Mantis Researcher (/mantis-researcher)

## System Goal

Resilience Code Auditor. Performs rapid triage and deep-dive reviews of source
files to identify boundary checks, preconditions, missing sanitization, and
interface violations.

## Command Definition

- **Command:** `/mantis-researcher`
- **Description:** Audits production source code files based on the strategy in
  `workspace/plan.json`.
- **Arguments (optional; supplied by the orchestrator, consumed by Block A):**
  - `--snapshot_root` / `SNAPSHOT_ROOT`: absolute path to the pinned, read-only
    code snapshot for this pass. This is the CODE_ROOT that all
    snapshot-relative path fields resolve against (Block A step 1b).
  - `--snapshot_id` / `SNAPSHOT_ID`: the pass snapshot identifier. Used for the
    sentinel check (Block A step 2) and stamped verbatim into every finding's
    `discovery_commit`.
  - `--state_root`: absolute path to the `workspace/` state directory
    (`plan.json`, `.mantis_state.json`, `findings/`, `kb/`). State paths are
    STATE-RELATIVE and are NEVER prefixed with CODE_ROOT (Block A step 3).
  - `--target_root` (authoritative override, Block A step 1a) is also honored if
    supplied.
  - **All flags absent -> DEGRADED/legacy mode:** CODE_ROOT falls back to the
    current directory, `snapshot_pinned` is treated as false, and behavior
    matches today's exactly (no `discovery_commit` is written).

## Input/Output Contract

- **Reads**:
  - `workspace/plan.json` (falls back to codebase sweep if missing/empty).
  - `workspace/.mantis_state.json` (to track current loop pass).
  - referenced Markdown files in `"kb_references"` (e.g.
    `workspace/kb/entities/*.md`).
  - Target source code files.
  - `workspace/kb/structural_index/manifest.json` (to check structural index
    availability/status).
  - `workspace/helpers/query_structural_index.py` (to invoke bounded
    structural-index queries).
- **Writes**:
  - Raw finding files to `workspace/findings/<uuid>.json` (creates
    `workspace/findings/` if missing).
- **Preconditions**:
  - Target files must be accessible.
- **Idempotency Guarantee**:
  - Writes new findings as separate files with unique UUIDs. Rely on
    `mantis-dedupe` to cluster and merge duplicate findings on subsequent steps.

## Instructions

### Step 0: Locator Resolution (Snapshot-Aware Path Handling)

Run this BEFORE the numbered research steps below. It fixes the single CODE_ROOT
that every `target_files` / `code_paths` reference in this stage resolves
against, so all sub-agents audit the same pinned snapshot.

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

Skill-specific notes for the researcher:

- The researcher is a CODE-READING stage, so Block A step 0's findings-only skip
  does NOT apply here — you MUST resolve CODE_ROOT and honor the sentinel.
- `workspace/plan.json` `target_files` and finding `code_paths` are
  SNAPSHOT-RELATIVE: resolve them under CODE_ROOT (Block A step 3).
- `kb_references`, `workspace/plan.json`, `workspace/.mantis_state.json`, and
  everything under `workspace/findings/` are STATE-RELATIVE: read/write them
  under --state_root, NEVER under CODE_ROOT.
- Never write, compile, or generate anything under CODE_ROOT when pinned (Block
  A step 4).

Perform a thorough memory-safety, logical-correctness, and robustness review of
the targeted codebase.

Execute the research stage as follows:

1. **Load Reviewing Plan & Context:** Read the active pass number from
   `workspace/.mantis_state.json` and resolve the current ISO 8601 timestamp.
   Read the `workspace/plan.json` file to retrieve the target investigations. If
   `workspace/plan.json` is missing or empty, perform a general list of the
   directories and review any primary source files. If the investigation
   contains a `"kb_references"` array, explicitly read those Markdown files
   (e.g., `workspace/kb/entities/auth.md`) to gain compounded historical context
   before you begin auditing the `"target_files"`. Also read `active_snapshot`
   from `workspace/.mantis_state.json` (`root`, `snapshot_id`,
   `snapshot_pinned`). Hold `active_snapshot.snapshot_id` in memory: it is the
   value you will stamp into every finding's `discovery_commit` (see Findings
   Schema Format). If `active_snapshot` is absent or `snapshot_pinned` is false,
   you are in DEGRADED/legacy mode — do NOT stop (Block A step 1d); you will
   simply omit `discovery_commit`.

2. **Sub-Agent Delegation (Wave-Based Swarm Parallelization):** If the CLI or
   agent platform supports spawning sub-agents (e.g., using specialized
   sub-agent tools or multi-agent orchestrator directives):

   - Do not execute investigations sequentially if sub-agents are supported.
     Split the investigations in `workspace/plan.json` into parallel waves to
     maximize throughput and context efficiency.

   - **Wave 1: Lightweight Rapid Triage (Concurrency Peak):** Spawn concurrent,
     lightweight sub-agents (e.g. up to 10-20 in parallel) to sweep all files
     listed in `workspace/plan.json`. Each sub-agent should only output a fast
     classification: `{"potentially_flawed": true/false, "reason": "..."}`.

   - **Wave 2: Deep Security Flaw Hotspot Audits & Parallel Trajectory Search:**
     Collect all files flagged in Wave 1. Spawn a wave of concurrent deep
     auditor sub-agents (e.g. up to 4-8 in parallel) to focus exclusively on
     those identified hotspots. For particularly complex files, spawn multiple
     subagents targeting the *same* file using either different prompt
     constraints or a diverse set of less expensive LLMs to explore parallel
     attack vectors. Rely on the subsequent deduplication stage to merge any
     overlapping findings.

   - **Token Optimization (Distributed Writes):** Instruct the Wave 2 sub-agents
     to generate unique UUIDs and write their findings directly to individual
     `workspace/findings/<id>.json` files on disk. Do not ask them to return the
     full JSON payload in their messages back to you, as aggregating them will
     blow out your context window. Ask them to only return the list of UUIDs
     they created.

   - **Snapshot Isolation (Wave Pinning) — MANDATORY:** Pass the SAME
     `--snapshot_root` (CODE_ROOT resolved in Step 0) and the same
     `--snapshot_id` value to EVERY Wave-1 and Wave-2 sub-agent, and instruct
     each of them to obey Block A (resolve `target_files`/`code_paths` under
     that CODE_ROOT, honor the sentinel). Any Wave-2 sub-agent that writes a
     finding MUST stamp `discovery_commit` with that snapshot_id, exactly as
     specified in the Findings Schema Format. Sub-agents MUST NOT run
     `git pull`/`fetch`/ `checkout`/`reset`, `hg pull`/`update`, `repo sync`, or
     any command that changes the working tree or switches revisions — the
     snapshot is immutable for the whole pass. A sub-agent that cannot see the
     snapshot must report that, not re-sync.

   - If sub-agents or concurrency are not supported by the current environment,
     fall back to performing the sweeps and deep-dives sequentially.

   - **Structural Index (HINT-only enhancement):** When a structural index is
     available (`workspace/kb/structural_index/manifest.json` exists), use it to
     SUPPLEMENT the wave-based swarm above. The structural index decides ORDER,
     never MEMBERSHIP. It MUST NEVER replace the exhaustive Step-3 call-site
     sweep.

     - **Resolution-first protocol (MANDATORY before any structural query):**

       1. Resolve the symbol first:
          `python3 workspace/helpers/query_structural_index.py resolve_symbol --name "<function_name>" [--language "<lang>"] [--file "<path>"] --state_root <state_root>`
       2. If the response has `ambiguous: true`, investigate ALL matched symbols
          — never silently pick one. Narrow with `--file`/`--language` if
          possible, or schedule investigations for every matched symbol.
       3. Use the resolved `symbol_id` for bounded queries:
          `python3 workspace/helpers/query_structural_index.py find_callers --symbol_id "<id>" --limit 100 --offset 0 --state_root <state_root>`

     - **Coverage-aware interpretation:** Check `coverage.partition_status` in
       every structural index response:

       - `complete` + `precision == semantic` + empty results = "no indexed
         callers" (authoritative for indexed code — still run grep per the
         HINT-only rule).
       - `complete` + `precision != semantic` + empty results = "no indexed
         callers" — NOT authoritative. MUST run exhaustive grep.
       - `partial` / `empty` / `failed` + empty results = "not fully indexed" —
         MUST run exhaustive grep.
       - Use the `precision` and `backend` fields on every result to weight
         trust (`semantic` > `typecheck` > `ast` > `symbol-only` > `heuristic` >
         `coverage-only`).

     - **Wave 1 (Rapid Triage):** Use `find_callers()` to SUPPLEMENT grep as a
       ranking HINT — ORDER, never MEMBERSHIP. Structural index results
       prioritize which files to flag as `potentially_flawed`; they MUST NEVER
       replace the exhaustive Step-3 call-site sweep. Audit the union of grep
       results and structural index results.

     - **Wave 2 (Deep Audit):** Use `get_function_boundary(file, line)` to start
       with the enclosing function, then expand to callers/callees/file as
       needed for deep dive context.

     - **Graceful degradation:** If the structural index is absent (no
       `manifest.json`), empty, or the query helper is missing, fall back to
       grep-based discovery (today's behavior). The structural index is a
       coverage HINT only.

3. **Exhaustive Interface and Call-Site Reviewing:** If a target source file
   defines public or API functions (such as numeric parsers, decoders, encoders,
   or converters) that document explicit size constraints or safety requirements
   (e.g., expecting callers to allocate buffers of a certain size):

   - Run a repo-wide grep for the function name to build the exhaustive set of
     candidate call-sites — this is the mandatory floor. Then use the structural
     index query helper (`resolve_symbol` then `find_callers`) to RANK and
     prioritize which call-sites to audit first (the index distinguishes actual
     calls from comments/strings/variable names). Audit the union of both result
     sets — the structural index may miss macro-based calls, function pointers,
     and dynamic dispatch, so grep remains the floor.
   - Search the codebase to find and review all call-sites of these functions
     across the entire repository to ensure the safety contracts are respected
     globally.
   - Read the calling files and verify if every call-site strictly adheres to
     input constraints, properly manages bounds, and checks sizes.
   - Flag any discrepancies as contract alignment bugs or missing checks.

4. **Unconstrained / Exploratory Investigations:** If the investigation plan in
   `workspace/plan.json` contains instructions or a question explicitly asking
   for an unconstrained sweep, adversarial audit, or random exploration:

   - Ignore existing assumptions of safety and documented trust boundaries in
     `workspace/kb/THREAT_MODEL.md`.
   - Treat all inputs and boundaries as untrusted and potentially malformed.
   - Analyze implementation from scratch with full freedom and autonomy.
   - If it is a random exploration/digging task with minimal instructions, focus
     on mapping the behavior of the target files, identifying key entry points,
     and looking for unexpected side effects or boundary cases without being
     constrained by a specific threat model.

5. **Compile and Write Findings:** Instead of a single monolithic file, create a
   `workspace/findings/` directory if it does not exist. For each potential
   finding, generate a unique UUID and write a valid JSON object into an
   individual file named `workspace/findings/<id>.json`. This keeps findings
   isolated and prevents token limit issues during subsequent analysis. Do not
   include any text before or after the JSON in the files.

   **Signature & Lineage Computation (Step 5a):**

   For each finding, compute `signature`, `lineage_id`, and optionally `cwe`
   BEFORE writing the JSON file:

   1. **`cwe` (optional):** If the vulnerability maps to a known CWE, set the
      `cwe` field to the identifier (e.g., `"CWE-787"`, `"CWE-416"`). If no CWE
      applies, omit the field. This is an input to the signature.

   2. **Compute `signature` (deterministic content-identity hash):**

      - `normalized_title` = finding `title`, lowercased, with ALL
        non-alphanumeric characters stripped (ASCII `[a-zA-Z0-9]` only; all
        other characters including Unicode letters, punctuation, and spaces are
        removed). If stripping leaves `normalized_title` EMPTY (e.g. a title
        composed entirely of non-ASCII/Unicode characters), set
        `normalized_title` = the first 16 hex chars of
        `sha256(<original raw title as UTF-8 bytes>)` so two distinct non-ASCII
        titles do not collide on the empty string.
      - `cwe_part` = the finding's `cwe` field if present and non-null, else the
        empty string.
      - `primary_target` = first `code_paths` entry with trailing `:line`
        stripped (e.g., `src/auth.c:145` → `src/auth.c`). If `code_paths` is
        empty, or the first entry is a non-source LOCATOR (URL containing `://`,
        or a non-file symbol/offset per Block A step 3), use the empty string.
        Order `code_paths` deterministically (primary sink first, kept stable
        across passes) so `primary_target` — and thus the `signature` — does not
        drift between passes. (If the order is unstable the only cost is a
        missed lineage inheritance → the finding is over-reported as new, never
        hidden — but stable order preserves the cross-pass fold.)
      - If `primary_target` is non-empty: `signature` = first 16 hex characters
        of `sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`.
      - If `primary_target` is empty: `signature` = first 16 hex characters of
        `sha256(normalized_title + "|" + cwe_part + "|" + sorted(code_paths).join(","))`.
      - Compute the signature ONCE at finding creation and NEVER recompute,
        edit, or invent it (same rule as `discovery_commit`).

   3. **Compute `lineage_id` (cross-pass lineage chain):**

      - Scan `workspace/archive/findings_pass_*/` and
        `workspace/archive/loop*_findings/` for any archived finding JSON whose
        `signature` field equals this finding's computed `signature`.
      - If a match is found: `lineage_id` = the archived ancestor's `lineage_id`
        (inherit the lineage chain so consumers can fold across passes). If
        MULTIPLE archived findings share the same signature, inherit from the
        MOST RECENT (highest pass number) ancestor. All ancestors with the same
        signature SHOULD share the same lineage_id; if they don't, inherit from
        the most recent one and log a warning.
      - If no match by exact signature: attempt a **basename rename fallback**
        for TRUE renames ONLY. Do NOT recompute the signature (it is computed
        ONCE at creation and never recomputed — invariant #4). Instead:
        1. Compute the CURRENT finding's basename: take `primary_target` (the
           first `code_paths` entry with trailing `:line` stripped, already
           computed for the signature at step 2) and take its basename (e.g.
           `src/auth.c` → `auth.c`). If `primary_target` is empty (non-source
           LOCATOR or empty code_paths), SKIP this fallback — go to fresh UUIDv4
           below.
        2. For each archived finding located in step 3's archive scan:
           reconstruct the ARCHIVED finding's basename from its stored
           `code_paths[0]` (strip the trailing `:line`, take the basename — e.g.
           `lib/old_auth.c:88` → `old_auth.c`). Do NOT recompute the archived
           finding's signature and do NOT compare signatures; compare the two
           basenames as STRINGS.
        3. Inherit an ancestor's `lineage_id` via this fallback ONLY IF (i) the
           basenames match AND (ii) the ancestor's full `primary_target` (its
           `code_paths[0]` with `:line` stripped) NO LONGER EXISTS on the
           current snapshot (check that the old full path is absent under
           CODE_ROOT — this distinguishes a real rename from a second,
           independent file that merely shares a basename). If MULTIPLE archived
           ancestors satisfy (i) and (ii), inherit from the MOST RECENT (highest
           pass number). When you inherit via basename, ALSO add a finding
           history note `lineage-via-basename-rename` so downstream consumers
           treat the link as basename-derived (the report folds two findings
           only when their full `signature`s ALSO match per the SAME-BUG
           predicate, so a basename-derived lineage link never collapses
           distinct bugs).
        4. If the old full path still exists on the current snapshot, do NOT
           inherit — treat as no match (fresh UUIDv4 below).
      - If no match by either exact signature or basename rename: `lineage_id` =
        a fresh UUIDv4.
      - These are STATE-RELATIVE paths (Block A step 3) — read under
        `--state_root/workspace/archive/`, NEVER under CODE_ROOT.

   4. **Write all three fields** (`cwe`, `signature`, `lineage_id`) into the
      finding JSON alongside `discovery_commit`.

   **Mode-independence:** Unlike `discovery_commit` (which is omitted in
   DEGRADED/legacy mode), `signature` and `lineage_id` are ALWAYS computed —
   they are content-identity fields, not snapshot-identity. They work regardless
   of whether the snapshot is pinned, unpinned, or absent (MODE-OFF). This is a
   deliberate Phase-3 improvement: in MODE-OFF, the finding JSON now carries 2–3
   extra optional keys (`cwe`, `signature`, `lineage_id`) that did not exist in
   Phase 1. This does NOT change the snapshot model (no `active_snapshot`, no
   sync, no pin — the 3-state rule is unaffected). The dedupe MODE-OFF fallback
   now prefers `signature` over `stable_key` when present, which is strictly
   MORE discriminating (signature adds `cwe` to the title+path mix), so it can
   only SPLIT entries that `stable_key` would have merged (fresh budgets, more
   conservative = safe) — it can never produce a false merge or suppress a
   legitimate finding. Absent `signature` → today's `stable_key` behavior
   exactly.

   **Missing or unreadable target file:** If a path in `target_files` does not
   exist or cannot be read under CODE_ROOT (e.g. it was deleted or renamed since
   the plan was written), do NOT fabricate a finding, a line number, or file
   contents. Skip that target and record the skip plainly in the `description`
   of any finding it relates to (or omit it entirely). Never invent code you did
   not read.

   **Non-source targets:** For a non-source LOCATOR (binary, firmware, or a URL
   endpoint — see Block A step 3), the `code_paths` entry MUST be a STABLE
   LOCATOR (symbol name, offset, or the bare path) WITHOUT a `:line` suffix. Do
   not attach a fabricated line number to a target you cannot open as text.

### Findings Schema Format (Per File)

```json
{
  "id": "A unique identifier generated for this finding (e.g., a UUID or random hash). This must be included and match the filename.",
  "title": "Authorization bypass or Memory bounds violation in [function_name]",
  "description": "Thorough root cause analysis detailing why the function is flawed under untrusted input.",
  "impact": "Exploit outcome (e.g., Privilege escalation, Memory corruption, Data exfiltration).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["SNAPSHOT-RELATIVE path under CODE_ROOT, e.g. 'relative/file/path.c:145'. For a NON-SOURCE target (binary/firmware/URL, per Block A step 3) use a STABLE LOCATOR (symbol name, offset, or bare path) WITHOUT a fabricated ':line'. Never invent a line number."],
  "discovery_commit": "The active_snapshot.snapshot_id read from workspace/.mantis_state.json at the start of this pass (Step 1). REQUIRED and NON-EMPTY whenever the snapshot is pinned: copy it VERBATIM, set it exactly ONCE at finding creation, and never recompute, edit, or invent it. OMIT this key entirely (do not write \"\" or null) if active_snapshot is absent or snapshot_pinned is false (DEGRADED/legacy mode).",
  "cwe": "CWE-787 (optional; omit if no CWE applies)",
  "signature": "First 16 hex chars of sha256(normalized_title + '|' + cwe_part + '|' + primary_target). Computed once at creation, never recomputed.",
  "lineage_id": "UUIDv4, or inherited from an archived finding with the same signature. Computed once at creation.",
  "mitigation": "Recommended corrective modification.",
  "history": [
    {
      "stage": "researcher",
      "action": "created",
      "details": "Initial audit finding recorded.",
      "pass_number": <current_pass_number>,
      "timestamp": "<current_iso8601_timestamp>"
    }
  ]
}
```

**`discovery_commit` rule (set once, at creation):** This stage is the creation
site for `discovery_commit`. When the snapshot is pinned, every finding you (or
your Wave-2 sub-agents) write MUST carry a non-empty `discovery_commit` equal to
`active_snapshot.snapshot_id`. Downstream stages treat an absent
`discovery_commit` as NOT_MATCHED (the conservative branch), so writing an empty
string or a wrong value would silently corrupt matching — never do it. In
DEGRADED/legacy mode (no `active_snapshot`, or `snapshot_pinned` false) omit the
key so behavior matches today's pipeline.

**`signature`/`lineage_id` rule (set once, at creation):** These fields are
ALWAYS computed (unlike `discovery_commit`, which is omitted in degraded mode).
The signature is a deterministic hash of the finding's content identity; the
lineage_id chains the finding to its archived ancestors. Downstream consumers
(dedupe, chain, report, reproduce) key on signature/lineage with UUID fallback:
absent `signature` → today's UUID behavior exactly (no silent wrong result).

Ensure all individual finding files are written to the `workspace/findings/`
directory. When complete, notify the user.

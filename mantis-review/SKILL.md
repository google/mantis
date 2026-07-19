---
name: mantis-review
description: >-
  Independently reviews findings and filters out false positives.
  Use when consolidated findings need validation against the actual source code.
  Don't use for reproducing crashes or patching code.
---

# Reviewer (/mantis-review)

## System Goal

Independent Validator. Reviews consolidated findings against active source code
to verify validity and filter out noise and false positives.

## Command Definition

- **Command:** `/mantis-review`
- **Description:** Independently reviews findings and filters out false
  positives.

## Input/Output Contract

- **Reads**:
  - `workspace/findings/` (finding JSON files, including each finding's optional
    `discovery_commit` provenance stamp).
  - `workspace/.mantis_state.json` (current loop `pass_number`; and, when
    present, `active_snapshot` = `{root, snapshot_id, snapshot_pinned}` for
    snapshot provenance).
  - Invocation args when passed by the orchestrator: `--snapshot_root`,
    `--snapshot_id`, `--state_root` (and, rarely, `--target_root`).
  - Target source code files at the `code_paths` paths/lines, read under the
    resolved `CODE_ROOT` (the pinned snapshot root — see Instructions Step 0 /
    Block A), never the live tree when a snapshot is pinned.
- **Writes**:
  - Updates findings on disk in-place (sets `"status"`, `"reasoning"`,
    `"repro_hints"`, `"triage_checklist"`, and appends history).
  - Writes helper script `workspace/helpers/append_review.py`.
- **Preconditions**:
  - `workspace/findings/` exists with finding files.
  - Target source code files exist.
- **Idempotency Guarantee**:
  - Modifies finding files in-place using the helper script `append_review.py`,
    which MUST carry `# MANTIS_HELPER_VERSION = 2` as its first line; regenerate
    the helper if that marker is absent or a different integer (see Instructions
    step 5).
  - Idempotency key is **(pass_number, snapshot)**. Before (re)writing a
    finding, scan its `history` array:
    - **SNAPSHOT MODE OFF** (neither `--snapshot_id` was passed NOR is
      `active_snapshot` readable in state): SKIP the review update iff a
      `"stage": "reviewer"` entry already exists for the current `pass_number`
      (byte-for-byte today's behavior).
    - **SNAPSHOT MODE ON**: SKIP the review update iff a `"stage": "reviewer"`
      entry exists whose `pass_number` equals the current pass AND whose
      `snapshot` equals `SNAPSHOT_ID`. A reviewer entry that lacks `snapshot`
      (legacy) or carries a different `snapshot` counts as UNKNOWN → RE-REVIEW
      (do NOT skip), so a finding reviewed under the old skill is re-grounded
      against the current pinned snapshot.

## Instructions

Read and evaluate the deduplicated findings against the actual source code of
the repository. **Assume every finding is a false positive by default. Your job
is to disprove the finding using an adversarial stance. Evaluate the claim based
ONLY on the code and the raw claim itself. Explicitly ignore the original
finder's prose reasoning and justification, as they may be hallucinated.**

Execute your validation as follows:

**Step 0 — Locator Resolution & Snapshot Provenance Gate (do this FIRST, before
reading any finding's code):**

0a. **Resolve where to read code.** **Block A — Locator Resolution** here:

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

The reviewer READS target source, so it is NOT a findings-only stage: run all of
Block A steps 1-6. `CODE_ROOT` is the pinned snapshot root you will read every
`code_paths` entry under. Per Block A step 3, a `code_paths` entry containing
`://` is a URL (existence check only), and any entry not of the form
`<existing-path>:<integer>` is a non-source locator (check the artifact/symbol
exists; skip all line-existence logic). Never STOP merely because `CODE_ROOT`
lacks `.git`/`.hg` (Block A step 5).

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

0b. **Determine SNAPSHOT MODE (once, before touching findings):** - SNAPSHOT
MODE is **OFF** iff `--snapshot_id` was NOT passed on this invocation AND
`workspace/.mantis_state.json` has no readable `active_snapshot`. This is a
legacy / non-sync run: do NOT run the Snapshot Provenance Gate below; review
EVERY finding with steps 1-5 exactly as before. - Otherwise SNAPSHOT MODE is
**ON**. From Block A you now hold `SNAPSHOT_ID` and `snapshot_pinned`. Apply the
Snapshot Provenance Gate (0c) to every finding.

0c. **Snapshot Provenance Gate (SNAPSHOT MODE ON only).** After Step 1 loads the
findings, apply the match check to EACH finding F via **Block B — Snapshot Match
Check**, applied to F:

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

Then, using the idempotency rule (Input/Output Contract → Idempotency Guarantee)
to avoid double-writes:

- **MATCHED** → F is grounded in the current pinned snapshot. Proceed to steps
  2-5 (the full 13-rule review) for F.
- **NOT_MATCHED** (includes: `snapshot_pinned` false / HALT / live-endpoint
  pass; `discovery_commit` missing, empty, or the literal `MIXED`; or
  `discovery_commit != SNAPSHOT_ID`) → F was discovered against a different (or
  absent/unpinned) snapshot; its `code_paths` line numbers may no longer point
  at the same code. **DO NOT run the 13 rules on F. DO NOT mark it
  FALSE_POSITIVE.** Finalize F as a drift `NEEDS_RESEARCH` via the helper (step
  5), writing EXACTLY:
  - `"status": "NEEDS_RESEARCH"`
  - `"reasoning"`:
    `"Snapshot drift: finding discovered against snapshot <F.discovery_commit or 'unknown'>, which does not match the current pinned snapshot <SNAPSHOT_ID>. Not re-validated this pass; routed to re-research."`
  - omit `"repro_hints"` (and, if F carried stale `repro_hints` from a prior
    pass, leave them — they are ignored downstream because status is not
    VALID/PROVISIONALLY_VALID).
  - `"triage_checklist"`: all 13 constraints set to `UNKNOWN` (paste the object
    below verbatim). This object is REQUIRED: appending a `reviewer` history
    entry makes `triage_checklist` mandatory on a non-chain finding
    (`schema.json` lines 365-398), and for a `NEEDS_RESEARCH` finding every
    entry MUST avoid `FAIL`/`passes:false` (`schema.json` lines 418-470).
    Setting `ensure_source_code_coherence` and
    `verify_attacker_control_of_source` to `UNKNOWN` (never `FAIL`) is the whole
    point: a line/path mismatch caused by DRIFT is NOT evidence of
    hallucination, so Rules 12/13 must NOT fire on it.
  - append the `reviewer` `"history"` entry (with `"snapshot"`, per step 5 / the
    history JSON below). Then STOP processing F — skip steps 2-5 for it.

Drift `triage_checklist` (paste verbatim; all 13 keys, all `UNKNOWN`):

```json
{
  "ignore_hypothetical_misuse":        { "outcome": "UNKNOWN", "reason": "snapshot drift: not re-validated against the current pinned snapshot" },
  "ignore_missing_hygiene":            { "outcome": "UNKNOWN", "reason": "snapshot drift: not re-validated against the current pinned snapshot" },
  "require_strict_reproducibility":    { "outcome": "UNKNOWN", "reason": "snapshot drift: not re-validated against the current pinned snapshot" },
  "avoid_pedantic_linting":            { "outcome": "UNKNOWN", "reason": "snapshot drift: not re-validated against the current pinned snapshot" },
  "no_security_flaw_stretching":       { "outcome": "UNKNOWN", "reason": "snapshot drift: not re-validated against the current pinned snapshot" },
  "evaluate_questionable_file_paths":  { "outcome": "UNKNOWN", "reason": "snapshot drift: not re-validated against the current pinned snapshot" },
  "ignore_resource_exhaustion_dos":    { "outcome": "UNKNOWN", "reason": "snapshot drift: not re-validated against the current pinned snapshot" },
  "intrinsic_security_flaws":          { "outcome": "UNKNOWN", "reason": "snapshot drift: not re-validated against the current pinned snapshot" },
  "verify_mitigations_pragmatically":  { "outcome": "UNKNOWN", "reason": "snapshot drift: not re-validated against the current pinned snapshot" },
  "refine_code_paths_strictly":        { "outcome": "UNKNOWN", "reason": "snapshot drift: not re-validated against the current pinned snapshot" },
  "ignore_simd_vector_padding":        { "outcome": "UNKNOWN", "reason": "snapshot drift: not re-validated against the current pinned snapshot" },
  "ensure_source_code_coherence":      { "outcome": "UNKNOWN", "reason": "snapshot drift: line/path mismatch may be caused by drift, not hallucination; not re-validated" },
  "verify_attacker_control_of_source": { "outcome": "UNKNOWN", "reason": "snapshot drift: trust-boundary path not re-traced against the current pinned snapshot" }
}
```

Findings finalized as drift `NEEDS_RESEARCH` in Step 0c are DONE — do not
process them again in steps 2-5. Only MATCHED findings (SNAPSHOT MODE ON) or all
findings (SNAPSHOT MODE OFF) flow into steps 2-5 below.

1. **Load Clustered Findings:** Read the JSON files in the `workspace/findings/`
   directory. If the directory is empty or missing, notify the user.

2. **Source Code Inspection:** For each finding that reached this step (in
   SNAPSHOT MODE ON, only findings that were **MATCHED** in Step 0c; findings
   finalized there as drift `NEEDS_RESEARCH` are already done and are skipped),
   read the file **under `CODE_ROOT`** (the pinned snapshot root resolved in
   Step 0 / Block A — resolve every `code_paths` path relative to `CODE_ROOT`,
   never the live tree) to inspect the exact files and line numbers listed in
   `code_paths` and confirm the finding is grounded in the actual snapshot
   state. Do not make assumptions about the validity of a path without
   inspecting the source code first.

3. **Strict Validation Filtering (Apply the 13 Negative Constraints):** Evaluate
   each finding against these strict criteria. Mark a finding as
   **FALSE_POSITIVE** if it violates any of the following rules:

   01. **Ignore Hypothetical Misuse:** Do not flag security flaws that rely on a
       calling API hypothetically misusing a function, writing bad fallback
       logic, or sending invalid parameters if the function itself behaves
       safely.
   02. **Ignore Missing Hygiene / Defense-In-Depth:** Do not report missing HTTP
       security headers (e.g., `X-Content-Type-Options`), missing authentication
       on local-only test functions, or hardcoded mock databases as security
       flaws.
   03. **Require Strict Reproducibility:** Only mark a finding as VALID if a
       direct, unambiguous, and triggerable flaw exists within the boundaries of
       the code logic. If the finding is extremely fragile (e.g., relies on
       unstable timing that cannot be automated or brute-forced, or requires
       unrealistic environmental conditions to trigger), mark it as
       FALSE_POSITIVE. *Note on Race Conditions:* Do NOT dismiss race conditions
       or timing bugs simply because they have a low success probability (e.g.,
       1 in a million), provided the attack path can be automated and repeatedly
       attempted by an attacker to eventually trigger the exploit.
   04. **Avoid Pedantic Linting:** If the code uses standard safe libraries
       (such as `json.loads`, parameterised SQL queries, or secure standard
       library hashes) but lacks extreme paranoia, mark it as FALSE_POSITIVE.
   05. **No Security Flaw Stretching on Mitigations:** If you are reviewing a
       mitigation or a safe variant of a function that successfully blocks the
       original security flaw class, do NOT invent complex protocol-level
       bypasses or adjacent security flaw classes (e.g., SSRF when reviewing
       Command Injection fixes). If the primary security flaw is successfully
       blocked, mark it as FALSE_POSITIVE.
   06. **Evaluate Questionable File Paths:** Do NOT instantly dismiss a finding
       simply because its path contains `/test`, `/experimental`, or `/mock`.
       Code in these paths is sometimes compiled into production targets or
       reachable via production endpoints. Do not blindly assume it is safe;
       instead, take reasonable measures to trace its usage to confirm whether
       it is actually exposed in production.
   07. **Ignore Resource Exhaustion DoS:** Do not flag functions for lacking
       recursion limits, input size boundaries, or cycle constraints unless the
       primary stated purpose of the module is to defend against DoS attacks.
   08. **Intrinsic Security Flaws:** If a function uses a fundamentally broken
       algorithm (such as MD5, SHA1), hardcodes static secrets, or contains
       direct injection paths in its own logic, mark it as VALID even if it is
       not currently called anywhere in the codebase.
   09. **Verify Mitigations Pragmatically:** Do not hallucinate flaws in active
       mitigations. If the code adds trailing validation slashes or configures
       safe parsing flags, accept that the mitigation works.
   10. **Refine `code_paths` Strictly:** The `code_paths` field should only
       include the exact `filename:line_number` of the flawed code block. Strip
       out any helper files, test harnesses, or correct caller files from
       `code_paths`.
   11. **Ignore SIMD/Vector Padding Violations:** If a finding represents an
       out-of-bounds read or write inside optimized vector routines (e.g., NEON,
       SSE, AVX, VSX), verify if the library employs a global memory allocation
       contract (such as trailing safety padding, like `row_bytes + 16`). If the
       out-of-bounds access is mathematically guaranteed to reside entirely
       within this pre-allocated padding buffer under all execution paths, mark
       the finding as a FALSE_POSITIVE (By Design).
   12. **Ensure Source Code Coherence (Anti-Hallucination):** Verify that every
       file path listed in `code_paths` exists in the repository, and that
       function names, variable names, or line numbers actually exist at those
       locations. If references are missing or incorrect, immediately mark the
       finding as a FALSE_POSITIVE to prevent downstream agents from wasting
       resources on hallucinated bugs.
   13. **Verify Attacker Control of the Source (Trust-Boundary Tracing):**
       Before marking a data-flow finding VALID, identify and cite the file:line
       where untrusted data enters the analyzed codebase (the "Ingress Point")
       from which the specific tainted field's value flows to the sink, OR where
       that field is populated by an untrusted writer.
       - If you have access to the untrusted-side code (e.g. Guest/Client in a
         multi-component repo), cite the writer.
       - If you only have access to the trusted-side code, cite the Host/Server
         ingress point on the data-flow path (e.g., reads from shared memory,
         IPC handlers, HTTP request parameter retrieval).
       - If the source data is proven to originate solely from trusted-side
         origins (server-authored static config, host-plane internal state),
         mark FALSE_POSITIVE.
       - Exception: Do not apply this rule to Intrinsic Security Flaws (Rule 08)
         where the vulnerability exists in library code independent of active
         callers.

   - **Status Resolution:**

     - Mark as **FALSE_POSITIVE** if it violates any of the 13 rules above.
     - Mark as **VALID** if it passes all rules and has a clear, triggerable
       flaw.
     - Mark as **PROVISIONALLY_VALID** if it passes the rules, but you are
       uncertain of its feasibility without dynamic verification (e.g. requires
       complex heap grooming or precise timing).
     - Mark as **NEEDS_RESEARCH** if the review is inconclusive due to high
       complexity, unresolved external APIs, or massive call graphs — OR because
       the finding was **NOT_MATCHED** by the Step 0c Snapshot Provenance Gate
       (snapshot drift). Drift findings are finalized in Step 0c and never reach
       these 13 rules; do NOT re-classify a drift finding as `FALSE_POSITIVE`.
     - **SCHEMA-CRITICAL:** `FALSE_POSITIVE` is the ONLY status for which a
       `triage_checklist` entry may be `"FAIL"` (or `"passes": false`). For any
       `VALID`, `PROVISIONALLY_VALID`, or `NEEDS_RESEARCH` finding, EVERY
       checklist entry must be `PASS` / `NOT_APPLICABLE` / `UNKNOWN` — never
       `FAIL` — or `schema.json` (lines 418-470) will reject the finding. If a
       rule looks failed but you are NOT setting status to `FALSE_POSITIVE`
       (e.g. Rule 12/13 references look off only because of snapshot drift), use
       `UNKNOWN` with a `reason`, not `FAIL`.

   - **Checklist Construction:**

     - Construct the `triage_checklist` object evaluating all 13 negative
       constraints. For each rule, set `outcome` to:
       - `"PASS"`: if the finding satisfies the constraint (does not violate the
         rule, meaning the bug remains potentially valid).
       - `"FAIL"`: if the finding violates the rule. Setting ANY entry to
         `"FAIL"` REQUIRES the finding's `status` to be `FALSE_POSITIVE`
         (`schema.json` lines 418-470 reject `FAIL` on `VALID`/
         `PROVISIONALLY_VALID`/`NEEDS_RESEARCH`). A `FAIL` entry also REQUIRES a
         `reason` (`schema.json` lines 788-797).
       - `"UNKNOWN"`: if the rule applicability is unresolved/needs research
         (REQUIRES a `reason`). Use this — not `"FAIL"` — whenever the finding
         is not being marked `FALSE_POSITIVE`, including all rules on a drift
         `NEEDS_RESEARCH` finding (Step 0c).
       - `"NOT_APPLICABLE"`: if this rule is entirely irrelevant to this class
         of bug (REQUIRES a `reason`).
     - Consistency rule: if `status` is `VALID`, every entry must be `PASS` or
       `NOT_APPLICABLE` (no `UNKNOWN`, no `FAIL`) per `schema.json` lines
       471-507.

4. **Construct Reproduction Script Hints:** For every finding marked as
   **VALID** or **PROVISIONALLY_VALID**, provide high-signal `"repro_hints"`
   explaining how a reproducer agent can trigger the bug, what inputs or payload
   parameters are required, and what crash condition, ASan output, or functional
   validation result (e.g., an unexpected HTTP 200 OK) is expected to confirm
   the security flaw.

5. **Token-Optimized File Updates:** To minimize LLM output tokens, **do not
   re-emit or manually rewrite the entire JSON object in your output.** Instead,
   write a reusable helper script (e.g., `workspace/helpers/append_review.py`)
   during your first finding update. For all subsequent findings, do not
   regenerate the script; simply execute the existing helper script with the new
   parameters to append the required fields.

   **Helper version guard (mechanical):** the helper's FIRST line MUST be the
   comment `# MANTIS_HELPER_VERSION = 2`. Before reusing an existing
   `workspace/helpers/append_review.py`, check that first line (a one-line
   grep): if the marker is ABSENT or a DIFFERENT integer, REGENERATE the helper
   (an old persisted helper would silently omit the `snapshot` provenance field
   and mishandle the drift path). The regenerated helper MUST:

   - accept parameters for `status`, `reasoning`, optional `repro_hints`,
     `triage_checklist` (JSON), `pass_number`, `timestamp`, and `snapshot`
     (write it under key `"snapshot"`, never `"snapshot_id"`);
   - write the reviewer `history` entry INCLUDING `"snapshot"` (the current
     `SNAPSHOT_ID`; omit or write `""` only in SNAPSHOT MODE OFF, where no
     snapshot is in play);
   - enforce the (pass_number, snapshot) idempotency check (Idempotency
     Guarantee): do nothing if a matching reviewer entry already exists.

   You must append the following to the existing object:

   - A `"status"` field (one of `"VALID"`, `"FALSE_POSITIVE"`,
     `"PROVISIONALLY_VALID"`, or `"NEEDS_RESEARCH"`).

   - A `"reasoning"` field.

   - A `"repro_hints"` field (optional for `"NEEDS_RESEARCH"` or
     `"FALSE_POSITIVE"`).

   - A `"triage_checklist"` object containing evaluations for all 13 negative
     constraints (each key in the object maps to the constraint of the matching
     name from Section 3 above):

     ```json
     {
       "ignore_hypothetical_misuse": { "outcome": "PASS" },
       "ignore_missing_hygiene": { "outcome": "PASS" },
       "require_strict_reproducibility": { "outcome": "FAIL", "reason": "Requires unstable 1-in-a-million race condition that cannot be automated." },
       "avoid_pedantic_linting": { "outcome": "PASS" },
       "no_security_flaw_stretching": { "outcome": "PASS" },
       "evaluate_questionable_file_paths": { "outcome": "PASS" },
       "ignore_resource_exhaustion_dos": { "outcome": "PASS" },
       "intrinsic_security_flaws": { "outcome": "PASS" },
       "verify_mitigations_pragmatically": { "outcome": "PASS" },
       "refine_code_paths_strictly": { "outcome": "PASS" },
       "ignore_simd_vector_padding": { "outcome": "PASS" },
       "ensure_source_code_coherence": { "outcome": "PASS" },
       "verify_attacker_control_of_source": { "outcome": "PASS" }
     }
     ```

     For backward compatibility, the schema also permits `"passes": <bool>` as
     an alternative to `"outcome"`, but `"outcome"` is preferred. The `reason`
     must be provided if the outcome is `FAIL`, `UNKNOWN`, or `NOT_APPLICABLE`
     (or if `passes` is `false`) to explain the evaluation; it should be omitted
     for `PASS` / `true` to save tokens.

   - An entry to the `"history"` array (now carrying the snapshot the review was
     performed against, for `(pass_number, snapshot)` idempotency):

   ```json
   {
     "stage": "reviewer",
     "action": "reviewed",
     "details": "Determined status as [VALID/FALSE_POSITIVE/PROVISIONALLY_VALID/NEEDS_RESEARCH] because [reason]",
     "pass_number": <current_pass_number>,
     "snapshot": "<SNAPSHOT_ID>",
     "timestamp": "<current_iso8601_timestamp>"
   }
   ```

   In SNAPSHOT MODE OFF (no snapshot in play), set `"snapshot": ""` (or omit the
   field). `schema.json`'s `history_entry` has no `additionalProperties:false`,
   so this extra field validates unchanged.

When complete, notify the user.

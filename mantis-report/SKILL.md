---
name: mantis-report
description: >-
  Generates a human-readable security review packet compiled from confirmed findings and exploit chains.
  Use at the end of a review cycle to produce stakeholder-facing documentation.
  Don't use for auditing code or verifying patches directly.
---

# Reporter (/mantis-report)

## System Goal

Security Reporting Expert. Synthesizes complex, technical finding logs into a
high-quality, human-readable review packet for developers and stakeholders.

## Command Definition

- **Command:** `/mantis-report`
- **Description:** Generates a human-readable security review packet containing
  confirmed findings and exploit chains.

## Input/Output Contract

- **Reads**:
  - `workspace/findings/*.json` (all active finding files for this pass).
  - `workspace/archive/findings_pass_*/*.json` (archived findings from prior
    passes) and legacy `workspace/archive/loop*_findings/*.json`. The report is
    a campaign-wide view: this pass's full findings plus carried-forward
    findings that prior passes stopped retrying (e.g. hit the retry cap) so they
    do not vanish from the report.
  - `workspace/.mantis_state.json` (to track current loop pass, and to read
    `vcs_info` and `active_snapshot` {`root`, `snapshot_id`, `snapshot_pinned`}
    for provenance).
  - Per-finding snapshot provenance fields, all OPTIONAL: `discovery_commit`,
    `repro_snapshot_id`, `patch_base_snapshot`. When any is absent/empty it is
    rendered as "(not recorded)" — never a reason to drop a finding.
- **Writes**:
  - `workspace/report/review_packet_pass_<N>_<snapshot_tag>.md` (pass- and
    snapshot-tagged markdown report). Falls back to the unsuffixed
    `review_packet_pass_<N>.md` on a legacy pass with no recorded snapshot.
  - Updates copy/symlink at `workspace/report/review_packet-latest.md`.
- **Preconditions**:
  - Calibrated and reproduced findings exist in `workspace/findings/` or
    `workspace/archive/`. The report is a campaign-wide view: it reports the
    current state of every unresolved finding discovered in this or any prior
    pass, de-duplicated to each finding's latest state. A confirmed-but-unfixed
    finding that plan stopped carrying back (e.g. it hit the 2-attempt retry
    cap) does NOT vanish — it appears here at its most recent archived state.
- **Idempotency Guarantee**:
  - Writes to pass-and-snapshot-tagged files. In-place overwrite of
    `review_packet-latest.md`. Re-running the SAME pass on the SAME snapshot
    updates the same tagged file. Re-running the same pass number on a DIFFERENT
    snapshot writes a DISTINCT file (the `<snapshot_tag>` suffix prevents
    cross-snapshot overwrite). Legacy passes with no recorded snapshot keep the
    unsuffixed `review_packet_pass_<N>.md` name and overwrite in place, exactly
    as before.

## Instructions

**Step 0 — Locator Resolution.**

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

Then the following FINDINGS-ONLY notes apply to the Reporter:

- The Reporter is a FINDINGS-ONLY stage (Block A, ROLE step 0): it SKIPS locator
  steps 2–6, does NOT require or resolve a CODE_ROOT, and NEVER stops because a
  code root or sentinel is unset.
- It STILL reads `active_snapshot` (`root`, `snapshot_id`, `snapshot_pinned`)
  and `vcs_info` from `workspace/.mantis_state.json` for provenance — used to
  build the header, the top banners, and the output file name.
- Every path the Reporter touches (`workspace/findings/*.json`,
  `workspace/.mantis_state.json`, `workspace/report/*`, `workspace/archive/*`)
  is STATE-RELATIVE and is NEVER prefixed with CODE_ROOT.

Compile a professional Markdown report detailing the verified/reproduced
vulnerabilities and exploit chains.

Execute the reporting stage as follows:

1. **Load findings — this pass in full, plus carried-forward open findings
   (newest-first fold; no script).** Build a working set keyed by finding
   identity, each finding once at its most-recent state:

   **SAME-BUG PREDICATE** (used for ALL current↔archived dedup, fold, and
   suppression in this stage; over-reporting is always safe here, hiding a real
   finding is never acceptable): two findings are the SAME BUG only if EITHER
   (i) they have the exact same `id` (UUID); OR (ii) ALL THREE hold — they share
   a non-empty `lineage_id`, they share a non-empty `signature`, AND at least
   one `code_paths` entry compared WITH its trailing `:line` (line-inclusive) is
   identical between them. Otherwise they are DISTINCT — render BOTH. NEVER
   treat two findings as the same bug on `lineage_id` alone or `signature`
   alone: both are coarser than a bug's true identity (basename-derived lineage
   can link two distinct same-named files; a `signature` strips the line number
   so it collides between distinct same-file bugs), and collapsing on either
   alone can silently drop a real finding.

   **Design note (re-anchoring vs fold):** `mantis-plan`'s re-anchoring (Phase
   2\) only provides a line hint that steers RE-DISCOVER — it does NOT rewrite
   the carried finding's `code_paths`. A re-discovered finding surfaces at its
   NEW line on the current snapshot. Because the fold predicate requires a
   line-inclusive `code_paths` match, the re-discovered finding will NOT fold
   with its ancestor (the line numbers differ). This is SAFE over-reporting —
   both entries render, the current one shows the new location. A future phase
   could relax the predicate to path-only matching when BOTH findings carry the
   same `signature` AND `lineage_id` AND the ancestor's line is confirmed absent
   on the current snapshot, but the conservative line-inclusive match is used
   today to prevent any silent-drop risk.

   1. Read all active `workspace/findings/*.json` and add every active finding
      to the working set, keyed by its `id` (UUID) — all remediation statuses,
      so this pass's `VERIFIED_SECURE`/`MITIGATION_PROPOSED` fixes still render
      with their patches in Categories 1/2. NEVER collapse two ACTIVE findings,
      even if they share a `lineage_id` or `signature` — keep each active `id`
      as its own entry.
   2. Scan `workspace/archive/findings_pass_<N>/` (and legacy
      `loop<N>_findings/`) in descending pass order. Add an archived finding
      only if it is still OPEN (see 4) AND NO finding already in the working set
      is the SAME BUG as it (per the predicate above) AND no earlier
      (higher-pass) archived copy of the SAME BUG was already added. First copy
      met = latest state; ignore later same-bug copies in lower dirs. (An
      archived finding is suppressed ONLY when a genuine same-bug supersedes it;
      a mere `lineage_id` or `signature` coincidence does NOT suppress it.)
   3. **Supersession fold (Phase 3):** When an archived finding IS the SAME BUG
      (predicate ii) as a current finding, the current finding supersedes it —
      show a single entry at the current (most-recent) state; do not also render
      the archived copy. When the predicate is NOT satisfied (different
      `signature`, e.g. a file rename, or `lineage_id` absent), render both as
      separate entries (safe over-reporting, never hiding).
      - **Under-reporting safeguard:** If the current (superseding) finding
        FAILS the actionable predicate (step 4 below) but the archived ancestor
        would have PASSED it (e.g., the ancestor was `reproduced` and OPEN, but
        the current pass's reproduce resulted in `not_attempted` due to a
        transient build/environment failure on the new snapshot), do NOT let the
        transient downgrade suppress the confirmed-open bug. Instead, keep the
        ancestor's last confirmed state visible in the report (render it with a
        note "Open — repro pending on new snapshot") so a previously-confirmed
        bug can never silently disappear from the report. The current finding's
        newer metadata (e.g., updated `code_paths` line numbers) may still be
        attached as an annotation, but the verdict/status shown must be the
        ancestor's last confirmed state, never the transient downgrade.
   4. **Actionable / quality predicate** (applies to active AND archived):
      include a finding only if it is an exploit chain (`constituent_findings`
      present, or "Exploit Chain" in title/history) OR `repro_status` is
      `reproduced` OR (`repro_status` is `statically_confirmed` AND it carries
      empirical execution evidence — an external stack trace, sanitizer trace
      (ASan/UBSan/MSan/TSan), or crash log). Do not include false positives,
      `NON_VIABLE`, `DUPLICATE`, `failed_to_reproduce`, or ordinary
      `statically_confirmed` findings lacking empirical traces.
   5. **Open predicate** (archived carry-forward in step 2 only): an archived
      finding is "still open" if it satisfies (4) AND `patch_status` is NOT
      `VERIFIED_SECURE`/`MITIGATION_PROPOSED` AND `status` is not
      `FALSE_POSITIVE`/`DUPLICATE` AND `production_viability` is not
      `NON_VIABLE`. (Active findings are loaded regardless of `patch_status` so
      this pass's fixes still appear; archived fixed findings are not re-listed
      every pass — use the optional "Resolved this campaign" rollup for a
      cumulative fixed view.)
   6. **Scale:** process one directory at a time, newest-first; never load the
      whole archive at once.

   - **Severity Filtering:** Exclude findings with a priority of `"LOW"` from
     the main report body. You must place these lower-priority issues into a
     separate, dedicated "Appendix: Low Priority Findings" section at the very
     end of the report, keeping the main report focused on high-risk issues.

2. **Extract Key Artifacts:** For each reproduced finding, extract and format:

   - **Header Metadata:** Title, ID (UUID), Inferred Exposure, Final Risk Score,
     and Qualitative Priority.
   - **Campaign Provenance:** Annotate each open finding with the pass it was
     first discovered in vs. the current pass (e.g.
     `discovered pass 2 · still open as of pass 7`), so carried-over findings
     are visible as such. First-seen = the lowest `pass_number` in the finding's
     `history` entries (or the pass_number of the lowest-numbered archive dir
     that contains it); current state = the copy you kept from the fold above.
   - **Duplicate Advisory:** If the finding has a `possible_duplicate_of` field
     (set by `mantis-dedupe` when a cross-pass candidate was NOT_MATCHED), emit
     an advisory note:
     `Possibly related to finding <UUID> (cross-pass candidate; snapshots differ — not confirmed duplicate).`
     This makes the advisory regression-pointer visible to the stakeholder.
   - **Discovery Snapshot:** Emit `Discovery Snapshot: <discovery_commit>` for
     the finding. If `discovery_commit` is missing or empty, emit
     `Discovery Snapshot: (legacy — not recorded)`. Never omit or drop the
     finding because this field is absent.
   - **Vulnerability Description & Impact:** A clear explanation of the bug and
     the concrete impact on the system.
   - **Reproduction Evidence:**
     - The PoC script path (`repro_file_path`) and execution command
       (`run_command`).
     - A clean snippet of the stdout/stderr showing the successful exploit
       trigger (`repro_output`).
     - **Evidence base:** label the reproduction evidence with the snapshot it
       was gathered on: `Evidence base: <repro_snapshot_id>`. If
       `repro_snapshot_id` is missing or empty, write
       `Evidence base: (not recorded)`. Do NOT assume it equals the header/pass
       snapshot.
   - **Risk Rationale:** The independent validation reasoning (`reasoning`),
     production viability reasoning (`critic_reasoning`), and outrage factor
     analysis (`outrage_commentary`).
   - **Remediation & Patch:**
     - The recommended mitigation strategy.
     - The verified patch diff (`patch_diff`) and re-attack status to prove the
       fix is resilient.
     - **Apply against:** label the patch diff with the snapshot it applies to:
       `Apply against: <patch_base_snapshot>`. If `patch_base_snapshot` is
       missing or empty, write `Apply against: (not recorded)`. If
       `patch_base_snapshot` is present and differs from this finding's
       `discovery_commit`, add a one-line caution that the diff was generated
       against a different snapshot and may not apply cleanly to the discovery
       snapshot.
   - **PII & Secrets Redaction:** Before writing any finding data (including
     description, PoC script/command, and reproducer logs) to the report, you
     **must** scan and redact any hardcoded API keys, tokens, credentials, PII
     (names, emails, phone numbers), internal hostnames/domain names, and overly
     weaponized payload parameters, replacing them with standard placeholders
     like `<REDACTED_SECRET>`, `<REDACTED_PII>`, `<REDACTED_INTERNAL_HOST>`, or
     `<REDACTED_PAYLOAD>` to ensure the report is safe for broader distribution.

3. **Generate Review Packet:**

   - **Report Header & Disclaimer:** At the very top of the report (before the
     Executive Summary):

     **Snapshot provenance banners — emit these BEFORE item 1 below, at the very
     top of the report, each as its own separated blockquote, in this order:**

     a. **Non-authoritative / HALT banner (3-state rule).** Read
     `active_snapshot` from `workspace/.mantis_state.json`. - If
     `active_snapshot` is **absent** (MODE-OFF — no `--sync` was requested,
     today's default): do NOT emit this banner. The run is byte-for-byte today's
     behavior; the report's `VERIFIED_SECURE` findings and other verdicts are
     valid as today. Emitting a NON-AUTHORITATIVE banner here would contradict
     the verdicts the same run produces. - If `active_snapshot` IS present but
     `snapshot_pinned` is `false` (HALT mode): emit as the FIRST line of the
     report:
     `> **WARNING — NON-AUTHORITATIVE RESULTS:** The target could not be         pinned to an immutable snapshot for this pass (HALT mode: the tree         raced or was too big / live / copy-failed). Findings may not         correspond to a stable, reproducible tree, and the ABSENCE of         findings in this report does NOT indicate the target is secure.         Treat all results as provisional.`
     Omit this banner when `active_snapshot` is absent (MODE-OFF) OR when
     `active_snapshot.snapshot_pinned` is `true` (PINNED).

     b. **Dirty working tree warning.** If `vcs_info.dirty` is `true`, emit:
     `> **WARNING — DIRTY WORKING TREE:** The target had uncommitted local       modifications when it was scanned. Results reflect that exact working       tree (captured by content hash), NOT a clean committed revision. The       recorded commit alone will not reproduce this state.`

     c. **Mixed-snapshot banner.** Let HEADER_SID =
     `active_snapshot.snapshot_id`. If HEADER_SID is present and non-empty AND
     any INCLUDED finding has a `discovery_commit` that is missing, empty, or
     not string-equal to HEADER_SID, emit:
     `> **WARNING — MIXED SNAPSHOTS:** This report combines findings       discovered on different code snapshots (e.g. findings retried from       earlier passes). The pass snapshot is <HEADER_SID>. Consult each       finding's "Discovery Snapshot" before acting; line numbers and code       context may differ between snapshots.`
     Compare snapshot IDs as EXACT strings only — no fuzzy or prefix match.

     1. Display the target codebase version information read from `"vcs_info"`
        in `workspace/.mantis_state.json`:

        - If `"vcs_type"` is `"git"`, show:
          `Target Version: Git branch [branch] at commit [commit_hash] [(dirty) if dirty is true]`.
        - If `"vcs_type"` is `"hg"`, show:
          `Target Version: Mercurial branch [branch] at revision [commit_hash] [(dirty) if dirty is true]`.
        - If `"vcs_type"` is `"multi-vcs"`, show:
          `Target Version: Multi-VCS (repo) manifest [revision] [(dirty) if dirty is true]`.
        - If `"vcs_type"` is `"none"`, show:
          `Target Version: None (No version control detected)`.
        - If `"vcs_type"` is `"unknown"`, or if `vcs_info` is missing, show:
          `Target Version: Unknown (VCS detection failed/error)`.

        After the `Target Version:` line, append the pass snapshot identity on a
        second line:

        - If `active_snapshot.snapshot_id` is present and non-empty, write:
          `Snapshot ID: [snapshot_id]  (pinned: [snapshot_pinned])`.
        - If `active_snapshot` is absent or `snapshot_id` is empty, write:
          `Snapshot ID: (legacy — snapshot not recorded)`. This is display-only
          provenance; it does not gate or drop any finding.

     2. Include a prominent disclaimer note stating: *“This report was
        automatically generated by Mantis AI. All findings and patches are
        AI-generated and must be manually verified by a security or subject
        matter expert before deployment or disclosure.”*

   - **Grouping by Patch Status (Exclusivity):** Organize the Executive Summary
     table and the main body of the report by grouping findings. **Exploit
     chains MUST be excluded from these main groups and reported ONLY in their
     dedicated "Exploit Chains (Not End-to-End Reproduced)" section.** For
     standard (non-chain) findings, group them into three distinct categories
     based on their remediation status (strictly mutually exclusive):

     1. **Category 1: Patch Independently Verified**: Findings where
        `patch_status` is `"VERIFIED_SECURE"`.
     2. **Category 2: Patch Proposed / Mitigation Identified**: Findings where
        `patch_status` is in
        `["MITIGATION_PROPOSED", "VERIFICATION_INCOMPLETE"]` OR (`patch_diff` is
        present AND `patch_status` is unset/empty).
     3. **Category 3: Unpatched / Verification Failed**: Findings where
        `patch_status` is in `["VERIFICATION_FAILED", "ERROR"]` OR (`patch_diff`
        is not present AND `patch_status` is unset/empty).

   - **Dedicated Exploit Chains Section:** Create a dedicated section titled
     `"Exploit Chains (Not End-to-End Reproduced)"` specifically for exploit
     chains. Document each chain finding here, listing its title, qualitative
     priority, risk score, and detailing its constituent findings (their IDs and
     individual status). Do not mix exploit chains with standard findings in
     Categories 1, 2, or 3.

   - **Pass-Numbered Output:** Do not overwrite the same `review_packet.md` file
     on every execution. Instead, determine the current run/pass number `N` of
     the pipeline (resolved from `"pass_number"` in
     `workspace/.mantis_state.json`. If missing or invalid, scan
     `workspace/archive/` for folders matching `findings_pass_N` or
     `loopN_findings` and resolve `N` to `max_found + 1`, defaulting to 1 if no
     archives exist). Then derive `<snapshot_tag>` from
     `active_snapshot.snapshot_id`: take the snapshot ID exactly as stored and
     replace every character NOT in `[A-Za-z0-9.-]` with a single underscore `_`
     (do NOT truncate — the result stays well under any filename length limit).
     Write the report to:

     - `workspace/report/review_packet_pass_<N>_<snapshot_tag>.md` when
       `active_snapshot.snapshot_id` is present and non-empty (e.g.
       `review_packet_pass_1_content_9f86d081884c...md`). The `<snapshot_tag>`
       suffix guarantees a reused pass number run against a DIFFERENT snapshot
       writes a distinct file and cannot overwrite the earlier packet.
     - `workspace/report/review_packet_pass_<N>.md` (no suffix — exactly the
       legacy name) when `active_snapshot` is absent or `snapshot_id` is empty,
       preserving today's backward-compatible behavior.

   - **Latest Copy/Symlink:** After writing the pass-numbered report above,
     update a symlink or write a copy of THAT exact file (whether or not it
     carries a `<snapshot_tag>` suffix) to
     `workspace/report/review_packet-latest.md`, so the latest version is always
     reachable. The `review_packet-latest.md` name is unchanged and remains the
     stable entry point for any downstream consumer.

   - Use clean, professional Markdown formatting with clear headers, tables for
     metadata, and syntax-highlighted code blocks for logs and diffs.

   - Include a high-level **Executive Summary** table at the top listing all
     included findings, their priority, and their risk scores.

   - **Optional sections (recommended):**

     - **Resolved this campaign:** A short rollup using the same fold, but
       filtering to findings where `patch_status` is `VERIFIED_SECURE` or
       `MITIGATION_PROPOSED`. This gives stakeholders a visible "what got fixed"
       view alongside the open findings.
     - **Unresolved — retry cap reached:** A callout listing open findings whose
       reproduction attempt count is at the cap. The count is NOT a field on the
       finding JSON; it lives in the cache file
       `state_root/workspace/archive/.repro_attempts.json`, keyed by each
       finding's `signature` (or, if `signature` is absent, by its computed
       `stable_key` = `normalized_title + "@" + primary_file_path` — same key
       selection as `mantis-reproduce`). For each open finding in the working
       set, look up its `signature` (or `stable_key` fallback) in that cache;
       include the finding in this callout if the cached value is at the retry
       cap. Read the cached value per the schema's value-shape rule: a bare
       integer V means `{count: V, last_snapshot: UNKNOWN}`; an object means
       `{count: V.count, last_snapshot: V.last_snapshot or UNKNOWN}`. If the
       cache file is missing or the finding's key is absent, treat its count as
       0 (do not list it here). These are items the planner stopped carrying

   > [!NOTE] **De-dup caveat:** de-dup is by finding identity, per the
   > **SAME-BUG PREDICATE** at the top of this stage: two findings fold only if
   > EITHER (i) they share the exact same `id` (UUID), OR (ii) ALL THREE hold —
   > a shared non-empty `lineage_id`, a shared non-empty `signature`, AND at
   > least one line-inclusive `code_paths` match. NEVER fold on `lineage_id`
   > alone or on `signature` alone (basename-derived lineage can link two
   > distinct same-named files; a `signature` strips the line number so it
   > collides between distinct same-file bugs) — collapsing on either alone can
   > silently drop a real finding. A bug re-discovered under a new UUID that
   > does NOT satisfy predicate (ii) — a regression, a file rename that shifts
   > the line, or a non-deterministic re-find — lists as a SEPARATE entry from
   > its archived ancestor: over-reporting (safe), never hiding. With stable
   > finding signatures and lineage tracking landed (Phase 3), a re-discovered
   > finding folds into its ancestor's single entry ONLY when predicate (ii) is
   > fully satisfied; the UUID-only match remains the safe branch for
   > legacy/un-upgraded findings.

   - **`review_packet-latest.md` is authoritative:** Note that
     `review_packet-latest.md` is now the authoritative current open state of
     the whole campaign (not just the latest pass). The per-pass
     `review_packet_pass_<N>_<snapshot_tag>.md` files remain as-is for
     historical reference.

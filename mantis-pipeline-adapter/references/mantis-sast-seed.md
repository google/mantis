# Reference Blueprint: mantis-sast-seed Skill

This is a **reference blueprint** for builders implementing Guideline 8 (SAST
Seeding) of the Pipeline Adapter. It is not a top-level skill — no pipeline
stage invokes it directly. Builders use it as a template to create a
`mantis-sast-seed` skill in their own environment, invoked by the harness
between Stage 6 (Research) and Stage 7 (Dedupe) to ingest external SAST tool
findings as candidates that must earn their verdict through unchanged downstream
gates.

## System Goal

SAST Finding Ingester. Reads the platform-agnostic `sast_findings.jsonl`
intermediate representation (IR), applies severity/CWE/rule allow-listing,
verifies provenance against the pinned `CODE_ROOT`, and writes Mantis finding
JSONs to `workspace/findings/`. Seeded findings carry status
`PROVISIONALLY_VALID` (when provenance is verified) or `NEEDS_RESEARCH` (when
provenance is unverified or drifted). This is purely additive — it expands
detection breadth by importing whole-program taint classes (injection, path
traversal, deserialization, UAF, format-string) that LLM-only discovery
structurally under-detects.

## Command Definition

- **Command:** `/mantis-sast-seed`
- **Description:** Ingest external SAST tool findings from the JSONL IR into
  Mantis finding format.
- **Arguments (optional; supplied by the orchestrator, consumed by Block A):**
  `--snapshot_root`/`--snapshot_id`/`--state_root`. All absent → MODE-OFF/legacy
  mode (reads `./workspace/sast_findings.jsonl` relative to current dir).

## Input/Output Contract

- **Reads**:
  - `workspace/sast_findings.jsonl` (STATE-RELATIVE — the IR file produced by
    the harness or an external converter; one JSON object per line, with a
    provenance header line).
  - `workspace/sast_allowlist.json` (STATE-RELATIVE, optional —
    severity/CWE/rule filters and caps).
  - `workspace/.mantis_state.json` (to read `active_snapshot` for provenance
    checking).
  - CODE_ROOT source files (for line-existence verification — this is a
    CODE-READING stage).
  - `workspace/archive/findings_pass_*/` (STATE-RELATIVE — for lineage
    inheritance).
- **Writes**:
  - Finding files to `workspace/findings/<uuid>.json` (STATE-RELATIVE).
- **Preconditions**:
  - `workspace/sast_findings.jsonl` should exist. If it does not, output nothing
    and notify the caller (opt-in, default off — the pipeline proceeds normally
    without SAST seeding).
- **Inert until wired:** This skill writes zero findings until both (1) a
  `sast_findings.jsonl` producer exists (the harness or an external converter),
  and (2) the harness invokes this skill between Stage 6 and Stage 7. It never
  fails — it simply outputs nothing until both ends are connected.
- **Idempotency Guarantee**:
  - Writes new findings as separate files with unique UUIDs. Relies on
    `mantis-dedupe` to cluster and merge duplicates with LLM-generated findings.
    Re-running with the same IR produces equivalent findings (new UUIDs, same
    content — dedupe handles the overlap).

## Instructions

### Step 0: Locator Resolution (run first)

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

This is a CODE-READING stage — it reads target source files under CODE_ROOT for
line-existence verification. Block A step 0's findings-only skip does NOT apply.

### Step 1: Check IR Availability

1. Resolve the path to `sast_findings.jsonl`:
   - If `--state_root` is passed, read
     `<state_root>/workspace/sast_findings.jsonl`.
   - Else read `workspace/sast_findings.jsonl` relative to the current
     directory.
2. If the file does not exist, output nothing and notify the caller: "SAST IR
   file not found — SAST seeding unavailable, pipeline proceeding normally." Do
   NOT error or stop.
3. If the file exists but contains only a provenance header (or is empty),
   notify the caller and exit.

### Step 2: Provenance Verification

1. Read the first line of `sast_findings.jsonl`. If it is a JSON object with
   `"_provenance": true`, extract `scan_snapshot_id` from it.

2. Read `active_snapshot.snapshot_id` from `workspace/.mantis_state.json` (if
   present).

3. Apply the provenance verification ladder (evaluate IN ORDER — MODE-OFF and
   HALT are preconditions checked FIRST, before any scan_snapshot_id
   comparison):

   - `active_snapshot` absent (MODE-OFF) → **MODE-OFF**. Omit
     `discovery_commit`. Finding status = `PROVISIONALLY_VALID` (MODE-OFF
     permits all verdicts).
   - `snapshot_pinned` is false (HALT) → **HALT**. Omit `discovery_commit`.
     Finding status = `NEEDS_RESEARCH`.
   - `scan_snapshot_id` present AND equals `SNAPSHOT_ID` → **VERIFIED**. Stamp
     `discovery_commit` with `SNAPSHOT_ID`. Finding status =
     `PROVISIONALLY_VALID`.
   - `scan_snapshot_id` present but differs → **DRIFT**. Omit
     `discovery_commit`. Finding status = `NEEDS_RESEARCH`.
   - `scan_snapshot_id` absent → **UNVERIFIED**. Omit `discovery_commit`.
     Finding status = `NEEDS_RESEARCH`.

   When `discovery_commit` is omitted, downstream stages treat the finding as
   NOT_MATCHED (the conservative branch) — the finding must earn its verdict
   through unchanged downstream gates.

### Step 3: Load Allow-List

1. Read `workspace/sast_allowlist.json` if present.
2. If absent, use defaults: `enabled: true`,
   `severity_filter: ["CRITICAL", "HIGH"]`, `per_rule_cap: 5`, `total_cap: 50`,
   no CWE or rule allowlist.

### Step 4: Parse and Filter Findings

1. Read each finding line (line 2+) from `sast_findings.jsonl`.
2. Apply filters in order:
   - (a) Severity filter: drop findings whose `severity` is not in
     `severity_filter`.
   - (b) CWE allowlist: if `cwe_allowlist.enabled` is true, drop findings whose
     `cwe` is not in `cwes`.
   - (c) Rule allowlist: if `rule_allowlist.enabled` is true, drop findings
     whose `rule_id` is not in `rules`.
   - (d) Per-rule cap: keep at most `per_rule_cap` findings per `rule_id`.
   - (e) Total cap: keep at most `total_cap` findings total.
3. Log how many findings were filtered at each step.

### Step 5: Line-Existence Verification

Only if provenance is VERIFIED or DRIFT and `CODE_ROOT` is resolved:

1. For each surviving finding, verify each `code_paths` entry:
   - Strip the trailing `:line` suffix (per Block A step 3).
   - Check the file exists under `CODE_ROOT`.
   - Check the line number is within the file's line count.
2. If a file is missing or a line is out of range:
   - Downgrade to DRIFT (omit `discovery_commit`, status = `NEEDS_RESEARCH`).
   - Set `sast_provenance.line_verified` to `false`.
3. If all locations verify: set `sast_provenance.line_verified` to `true`.

### Step 6: Compute Finding Fields

For each surviving finding:

- `id`: Fresh UUIDv4.
- `title`: `"<rule_name or rule_id> in <primary_file_basename>"`.
- `description`: Include the SAST tool's message, `rule_id`, `rule_name`,
  `code_paths`, and provenance status. Read the actual source at the reported
  location (±20 lines) and include root-cause analysis.
- `code_paths`: From IR (array of `"file:line"` strings, SNAPSHOT-RELATIVE).
- `impact`: Derived from CWE/severity.
- `severity`: From IR (already mapped to Mantis enum: `CRITICAL`/`HIGH`/
  `MEDIUM`/`LOW`).
- `attacker_position`: `"EXTERNAL"` (conservative default; review will refine).
- `privileges_required`: `"NONE"` (conservative default).
- `user_interaction`: `"NONE"` (conservative default).
- `status`: `PROVISIONALLY_VALID` if VERIFIED or MODE-OFF, else `NEEDS_RESEARCH`
  (DRIFT, UNVERIFIED, or HALT).
- `mitigation`: Generic placeholder ("Review and fix the issue identified by the
  SAST tool").
- `cwe`: From IR if present.
- `signature`: Computed using the EXACT same formula as `mantis-researcher`:
  first 16 hex chars of
  `sha256(normalized_title + "|" + cwe_part + "|" + primary_target)`, where
  `normalized_title` = lowercase(title) with all non-alphanumeric characters
  stripped, `cwe_part` = cwe if present else empty string, `primary_target` =
  first `code_paths` entry with trailing `:line` stripped.
- `lineage_id`: Scan `workspace/archive/findings_pass_*/` for matching
  signature; inherit if found, else fresh UUIDv4 (same algorithm as researcher
  Step 5a #3).
- `discovery_commit`: Set to `SNAPSHOT_ID` ONLY if provenance is VERIFIED. If
  DRIFT or UNVERIFIED → **OMIT entirely** (do NOT write `""` or `null` —
  UNTRUSTED-IF-ABSENT routing). In MODE-OFF → omit (same as researcher DEGRADED
  mode).
- `sast_provenance`:
  `{tool, rule_id, rule_name, original_severity, scan_snapshot_id, line_verified, message}`.
- `repro_hints`: Copy the tool's `message` field (helps reproducer).
- `history`:
  `[{stage: "sast-seed", action: "created", details: "...", pass_number: N, timestamp: ISO8601}]`.

### Step 7: Write Findings

1. Write each finding to `workspace/findings/<uuid>.json`.
2. Notify the caller with the count of findings written and the provenance
   breakdown (VERIFIED vs DRIFT vs UNVERIFIED).

## IR Format Specification (`sast_findings.jsonl`)

The IR is a JSONL file with a provenance header (line 1) and one finding per
line (lines 2+). This is a platform-agnostic intermediate representation — any
SAST tool's output can be converted to this IR by a thin wrapper.

**Provenance header (line 1):**

```json
{"_provenance": true, "scan_snapshot_id": "abc123", "tool": "codeql", "tool_version": "2.15.0", "scan_timestamp": "2026-07-22T12:00:00Z"}
```

**Finding line (line 2+):**

```json
{"rule_id": "cpp/sql-injection", "rule_name": "SQL injection via string concatenation", "cwe": "CWE-89", "severity": "HIGH", "code_paths": ["src/db.c:42"], "message": "User-controlled input concatenated into SQL query"}
```

**Multi-location finding (taint flow):**

```json
{"rule_id": "py/taint", "rule_name": "Path traversal", "cwe": "CWE-22", "severity": "CRITICAL", "code_paths": ["src/input.py:15", "src/router.py:88", "src/filesystem.py:204"], "message": "Tainted data flows from user input to file open"}
```

**Required fields:**

| Field        | Type   | Description                                        |
| ------------ | ------ | -------------------------------------------------- |
| `rule_id`    | string | Rule identifier in the SAST tool's rule set        |
| `severity`   | string | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`         |
| `code_paths` | array  | Array of `"file:line"` strings (SNAPSHOT-RELATIVE) |
| `message`    | string | Finding message from the SAST tool                 |

**Optional fields:**

| Field       | Type   | Description                      |
| ----------- | ------ | -------------------------------- |
| `rule_name` | string | Human-readable rule name         |
| `cwe`       | string | CWE identifier (e.g. `"CWE-89"`) |

## Allow-List Configuration (`workspace/sast_allowlist.json`)

```json
{
  "enabled": true,
  "severity_filter": ["CRITICAL", "HIGH"],
  "cwe_allowlist": {"enabled": true, "cwes": ["CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-787", "CWE-416", "CWE-502"]},
  "rule_allowlist": {"enabled": false, "rules": []},
  "per_rule_cap": 5,
  "total_cap": 50
}
```

When absent, defaults are: `enabled: true`,
`severity_filter: ["CRITICAL", "HIGH"]`, no CWE or rule allowlist,
`per_rule_cap: 5`, `total_cap: 50`. The allow-list prevents noise from external
tools from starving the reproduce retry cap (6 attempts max per finding).

## Conversion Examples (Harness Responsibility)

The harness or an external converter transforms SAST tool output to the IR. This
is NOT the skill's job — the skill reads the IR only.

### SARIF → IR

Extract from each SARIF `result` object:

- `ruleId` → `rule_id`
- `level` → `severity` (see mapping below)
- `locations[0].physicalLocation` → `code_paths` (as `"uri:lineStart"`)
- `message.text` → `message`
- Rule metadata `name` → `rule_name`
- Rule metadata `cwe` tag → `cwe`

### Semgrep JSON → IR

Extract from each Semgrep `result` object:

- `check_id` → `rule_id`
- `extra.severity` → `severity` (see mapping below)
- `path` + `start.line` → `code_paths` (as `"path:line"`)
- `extra.message` → `message`
- `check_id` suffix → `rule_name`
- Rule metadata `metadata.cwe` → `cwe`

### Severity Mapping

| Source level | Mantis severity |
| ------------ | --------------- |
| `error`      | `HIGH`          |
| `warning`    | `MEDIUM`        |
| `note`       | `LOW`           |

SARIF `error` → `HIGH`, `warning` → `MEDIUM`, `note` → `LOW`. Semgrep `ERROR` →
`HIGH`, `WARNING` → `MEDIUM`, `INFO` → `LOW`. (`CRITICAL` is reserved for
findings that the SAST tool flags with highest confidence or that map to
known-critical CWEs.)

## Provenance Verification Detail

The `scan_snapshot_id` in the IR provenance header records which `SNAPSHOT_ID`
the SAST scan ran against. The adapter compares it to the current pass's
`SNAPSHOT_ID` (from `active_snapshot.snapshot_id`):

1. **MODE-OFF** (evaluate FIRST): `active_snapshot` is absent. Omit
   `discovery_commit` (UNTRUSTED-IF-ABSENT routing). Finding status =
   `PROVISIONALLY_VALID` (MODE-OFF permits all verdicts).
2. **HALT** (evaluate SECOND): `snapshot_pinned` is false. Omit
   `discovery_commit`. Finding status = `NEEDS_RESEARCH`.
3. **VERIFIED**: `scan_snapshot_id` is present AND equals `SNAPSHOT_ID`. The
   scan ran against the exact same bytes the pipeline is analyzing. Stamp
   `discovery_commit` with `SNAPSHOT_ID`. Finding status =
   `PROVISIONALLY_VALID`.
4. **DRIFT**: `scan_snapshot_id` is present but differs from `SNAPSHOT_ID`. The
   scan ran against a different snapshot (stale IR). Omit `discovery_commit`
   (UNTRUSTED-IF-ABSENT routing → downstream treats as NOT_MATCHED). Finding
   status = `NEEDS_RESEARCH`.
5. **UNVERIFIED**: `scan_snapshot_id` is absent. Omit `discovery_commit`.
   Finding status = `NEEDS_RESEARCH`.

**Line-existence check** (applies to VERIFIED and DRIFT): For each finding, the
adapter reads the source file at each `code_paths` entry (stripped of `:line`)
under `CODE_ROOT` and verifies the line number falls within the file's line
count. If any file is missing or any line is out of range, downgrade to DRIFT
(omit `discovery_commit`, set `line_verified = false`). This prevents the
adapter from trusting stale findings against a mutated codebase.

**MODE-OFF** (no `active_snapshot`): Omit `discovery_commit`. No line-existence
check (no `CODE_ROOT` to verify against). Findings are written with status
`PROVISIONALLY_VALID` (MODE-OFF permits all verdicts).

**HALT** (`snapshot_pinned` is false): Omit `discovery_commit`. Run
line-existence check if `CODE_ROOT` is available (read-only). Findings are
written with status `NEEDS_RESEARCH`.

**PINNED** (`snapshot_pinned` is true): Full verification. `discovery_commit`
stamped only on VERIFIED findings.

## Pipeline Integration

The harness invokes this skill between Stage 6 (Research) and Stage 7 (Dedupe):

1. **Before the pass:** The harness (or an external CI/CD step) runs the SAST
   tool against the pinned `CODE_ROOT` and converts its output to
   `workspace/sast_findings.jsonl` (IR format).
2. **Invocation:** The harness calls `/mantis-sast-seed` with
   `--snapshot_root=<CODE_ROOT> --snapshot_id=<SNAPSHOT_ID> --state_root=<workspace_parent>`.
3. **Output:** The skill writes finding JSONs to
   `workspace/findings/<uuid>.json`.
4. **Downstream:** `mantis-dedupe` (Stage 7) merges SAST-seeded findings with
   LLM-generated findings. Duplicates are clustered. The review and reproduce
   stages process all findings through unchanged gates.

If `sast_findings.jsonl` does not exist, the skill outputs nothing and the
pipeline proceeds normally (no-op).

## Safety Properties

Safety guardrails are defined in Guideline 8H of the Pipeline Adapter
([../SKILL.md](../SKILL.md#h-safety-guardrails-8)). Key properties:

- **Opt-in / default-off.** If the IR file is absent, the skill outputs nothing.
- **Purely additive.** Seeded findings are candidates that must earn their
  verdict through unchanged downstream gates.
- **Provenance verification prevents false trust.** `discovery_commit` is
  stamped ONLY when provenance is VERIFIED.
- **Allow-listing prevents retry-cap starvation.** Caps bound the number of
  seeded findings entering the pipeline.
- **`sast_provenance` is informational, not a trust anchor.** The finding's
  `discovery_commit` governs Block B snapshot matching.

See the Pipeline Adapter for the full invariant analysis.

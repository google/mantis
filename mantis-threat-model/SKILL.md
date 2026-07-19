---
name: mantis-threat-model
description: >-
  Synthesizes trust boundaries, attack surfaces, and attacker profiles into a living threat model.
  Use as Stage B of the Knowledge Base generation process, reading architecture and entity definitions from the KB.
  Don't use for analyzing source code or extracting raw learnings from JSONL files.
---

# Threat Modeler (/mantis-threat-model)

## System Goal

Security Architect. Synthesizes trust boundaries, attack surfaces, and attacker
profiles into `THREAT_MODEL.md` based exclusively on the entities and
architecture defined in the Knowledge Base (KB).

## Command Definition

- **Command:** `/mantis-threat-model`
- **Description:** Evaluates architectural perimeters, entry points, and trust
  boundaries to construct the threat model.
- **Arguments (all optional; absent → today's behavior):**
  - `--state_root <dir>`: parent of `workspace/`. If absent, use `./workspace/...`
    relative to the current directory. Locates `.mantis_state.json`, the KB, and
    the archive directory.
  - `--snapshot_id <id>`: the `SNAPSHOT_ID` this pass is pinned to. Used ONLY as
    the provenance value stamped into `THREAT_MODEL.md` (the `KB_SNAPSHOT:` line).
    If absent, fall back to `active_snapshot.snapshot_id` from state; if that is
    also absent or `snapshot_pinned` is false, the stamp is the literal `UNPINNED`.
  - `--snapshot_root <dir>`: accepted for interface uniformity but NOT used — this
    stage never reads target source (Block A step 0, findings-only role).

## Input/Output Contract

- **Reads**:
  - `workspace/.mantis_state.json` — `pass_number` (to archive per pass) and, for
    provenance only, `active_snapshot` (`{root, snapshot_id, snapshot_pinned}`).
    Both optional; absent → degraded (see Backward-compat).
  - `workspace/kb/architecture.md`.
  - `workspace/kb/entities/*.md`.
  - The EXISTING `workspace/kb/THREAT_MODEL.md` from the previous pass, if present
    — only its first `KB_SNAPSHOT:` line, for the freshness check in step 0.
- **Writes**:
  - `workspace/kb/THREAT_MODEL.md` (first line is a `KB_SNAPSHOT:` provenance header).
  - Archives the previous `workspace/kb/THREAT_MODEL.md` (if any) to
    `workspace/archive/kb/THREAT_MODEL_pass_${N}.md` BEFORE overwriting.
- **Preconditions**:
  - Knowledge Base files must exist and be populated.
- **Idempotency Guarantee**:
  - Copies the prior `THREAT_MODEL.md` (if any) to the pass archive, then
    deterministically overwrites `workspace/kb/THREAT_MODEL.md` in-place.
    Re-running a pass with an unchanged snapshot reproduces an equivalent model
    plus a `STALE` banner (see step 0 and the final save step).

## Instructions

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

**Role for this stage (findings-only / KB-only).** `/mantis-threat-model` NEVER
reads target source. Every input it uses — `architecture.md`, `entities/*.md`,
the prior `THREAT_MODEL.md`, and `.mantis_state.json` — is STATE-RELATIVE (read
under `state_root/workspace`, NEVER under `CODE_ROOT`). This stage therefore takes
Block A step 0's FINDINGS-ONLY path: SKIP Block A steps 2–6, but STILL read
`active_snapshot` from state for provenance, and NEVER stop merely because a code
root is unset or unpinned.

Maintain a high-level Threat Model that explicitly defines *who* the attackers
are and *where* they can interact with the system, relying on the pre-processed
entities in the KB.

Execute the threat modeling process as follows:

0. **Resolve Snapshot Provenance, Freshness, and Archive the Prior Model:**

   a. **Compute `CUR` (the snapshot this threat model is stamped against):**
      - If `--snapshot_id` was passed → `CUR` = that value.
      - Else if state `active_snapshot.snapshot_pinned` is true → `CUR` =
        `active_snapshot.snapshot_id`.
      - Else → `CUR` = the literal `UNPINNED` (degraded / today's behavior).

   b. **Compute `PREV_TM` (what the last model was stamped against):** read the
      FIRST line matching `^KB_SNAPSHOT:` in the existing
      `workspace/kb/THREAT_MODEL.md`; its value (trimmed) is `PREV_TM`. If the file
      is absent, has no such line, or the value is empty → `PREV_TM` = the empty
      string `""`.

   c. **SYNC-DELTA DECISION (mechanical; exact string equality, no fuzzy compare):**
      - `CUR == "UNPINNED"`      → `SYNC_OCCURRED = true` (degraded: always re-derive).
      - else `PREV_TM == ""`     → `SYNC_OCCURRED = true` (first run / legacy KB).
      - else `PREV_TM != CUR`    → `SYNC_OCCURRED = true` (a sync or dirty edit advanced the snapshot).
      - else (`PREV_TM == CUR`)  → `SYNC_OCCURRED = false` (snapshot unchanged since the last model).

   d. **Archive the prior model (per pass), so overwrite is non-destructive:**
      - Resolve `N`: read `"pass_number"` from `workspace/.mantis_state.json`. If
        missing or invalid, scan `workspace/archive/` for folders matching
        `findings_pass_N` or `loopN_findings` and set `N = max_found + 1`,
        defaulting to `1` if no archives exist. (Same rule the architecture stage
        uses.)
      - If `workspace/kb/THREAT_MODEL.md` exists: ensure `workspace/archive/kb/`
        exists (`mkdir -p workspace/archive/kb/`) and COPY (do NOT move) the file
        to `workspace/archive/kb/THREAT_MODEL_pass_${N}.md`. You will overwrite the
        live file in step 3. If the file does not exist, skip the copy.
      - All paths in this step are STATE-RELATIVE (under `state_root/workspace`);
        NEVER prefix `CODE_ROOT`.

   Carry `CUR`, `SYNC_OCCURRED`, and `N` forward into steps 1–3 and the final save.

1. **Read the Synthesized KB:**

   - Read `workspace/kb/architecture.md` to understand the system's data flows
     and high-level design.
   - Read the files inside `workspace/kb/entities/` to understand the individual
     components and any historical constraints or vulnerability patterns mapped
     to them by the `/mantis-architecture` stage.

2. **Analyze Trust Boundaries:**

   - Evaluate the entities to determine where trust boundaries lie. Where does
     untrusted data cross into a trusted context? Which components are exposed
     to external input?

3. **Synthesize the Threat Model:**

   - Write a comprehensive, structured Markdown file and save it directly to
     `workspace/kb/THREAT_MODEL.md` (overwriting the old one).
   - **Token Optimization:** Use your file-writing tools to write the file
     directly to disk; do not output the threat model text in your chat
     response.

   Include the following sections to ensure downstream planning agents have
   sufficient context:

   - **System Overview Summary:** A concise summary derived from
     `architecture.md`.
   - **Deployment Intent:** State exactly one of `Intent: PRODUCTION` or
     `Intent: SAMPLE_OR_TEST_ONLY`. This verdict has a large blast radius:
     `/mantis-critic` marks EVERY finding `SAMPLE_OR_TEST` (dismissing the whole
     pass) the instant it reads `Intent: SAMPLE_OR_TEST_ONLY`. So
     `SAMPLE_OR_TEST_ONLY` is FAIL-CLOSED behind a mechanical checklist:

     **PRODUCTION-SIGNAL CHECKLIST — you may write `Intent: SAMPLE_OR_TEST_ONLY`
     ONLY IF ALL five checks are TRUE. If ANY is FALSE, or the KB is silent on / you
     are unsure about any one of them, you MUST write `Intent: PRODUCTION`.**
     1. NO entity in `workspace/kb/entities/*.md` is classified `CRITICAL` or
        `STANDARD` availability (either implies an operated/production service).
     2. `architecture.md` names NO externally-reachable service, daemon, server,
        API, or network endpoint, AND NO deployment/packaging descriptor (systemd,
        Dockerfile/`docker`, kubernetes/`k8s`/helm, load balancer, cloud/VPC/IaC,
        CI/CD publish or release).
     3. The KB describes NO installable/publishable package or runtime entrypoint
        (e.g., `console_scripts`/`entry_points`, a `main()`/service binary, a
        published library or package manifest).
     4. EVERY component/path referenced in the KB lies exclusively under
        test/sample directories — its path contains one of `test`, `tests`,
        `example`, `examples`, `sample`, `samples`, `tutorial`, `demo`, `docs`,
        `fixtures` — and NONE lie under production source roots such as `src`,
        `lib`, `pkg`, `internal`, `cmd`, `app`, `server`, or `core`.
     5. NO entity documents a real (non-mock, non-test) untrusted external input
        crossing a trust boundary into privileged/production logic.

     **After a sync (`SYNC_OCCURRED == true` from step 0) you MUST re-run this
     checklist from scratch against the CURRENT KB and MUST NOT inherit a prior
     `Intent:` verdict** — a sync can add production code to a tree that was
     previously sample-only, which would otherwise silently dismiss every new
     finding.
   - **Trust Boundaries:** Clear, rigorous definitions of where untrusted inputs
     meet internal trusted states. Reference the specific entities (e.g.,
     `[Auth Module](entities/auth_module.md)`).
   - **Threat Actors & Vectors:** Define the profiles of potential attackers
     (e.g., Unauthenticated Network Attacker, Malicious Local User) and the
     specific boundaries they can reach.
   - **High-Risk Assets:** The data, execution privileges, or availability
     targets an attacker wants to compromise. **For availability targets,
     classify them into one of these Availability Tiers based on the KB:**
     - `CRITICAL`: 24/7 immediate operational impact if disrupted.
     - `STANDARD`: Important operations; short downtime is tolerable.
     - `LOW_CRITICALITY`: Non-blocking utilities; disruption is a mild
       annoyance.

Stamp and save the model:

- The FIRST line of `workspace/kb/THREAT_MODEL.md` MUST be the provenance stamp
  `KB_SNAPSHOT: ` followed by `CUR` (from step 0) — e.g. `KB_SNAPSHOT: <CUR>`, or
  `KB_SNAPSHOT: UNPINNED` in degraded mode. The next pass reads this back as
  `PREV_TM`, and `/mantis-report` reads it for a provenance banner.
- If `SYNC_OCCURRED == false` (snapshot unchanged since the last model): you MAY
  reuse the prior model's substance, but you MUST insert this STALE banner as the
  line immediately AFTER the `KB_SNAPSHOT:` line:
  `> STALE: Threat model NOT re-evaluated this pass; carried unchanged from snapshot <CUR>.`
  If `SYNC_OCCURRED == true`: do NOT emit the STALE banner — you re-derived every
  section fresh this pass, including the Deployment-Intent checklist.
- Save directly to `workspace/kb/THREAT_MODEL.md` (STATE-RELATIVE; the prior file
  was already copied to the pass archive in step 0d). Use your file-writing tools;
  do not print the model to chat. When complete, notify the user.

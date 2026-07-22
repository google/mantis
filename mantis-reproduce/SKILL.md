---
name: mantis-reproduce
description: >-
  Generates and runs crash reproducers to verify security flaws.
  Use when viable findings exist and you need to write and execute a script or payload to verify the crash.
  Don't use for code auditing or patching.
---

# Reproducer (/mantis-reproduce)

## System Goal

Integration Test Engineer. Designs crash reproducers or inputs and executes them
inside isolated sandbox environments to empirically verify bugs.

## Command Definition

- **Command:**
  `/mantis-reproduce [--reattack] [--finding_id=<uuid>] [--force] [--target_root=<path>] [--state_root=<path>] [--snapshot_root=<path>] [--snapshot_id=<SNAPSHOT_ID>] [--snapshot_pinned=<true|false>]`
- **Description:** Generates and runs crash reproducers to verify security
  flaws.
- **Parameters:**
  - `--reattack`: When executing as part of patch verification to isolate
    re-attack outcomes.
  - `--finding_id`: The specific finding UUID to reproduce. **Must** be provided
    and is required when `--reattack` is specified.
  - `--force`: Override/bypass eligibility checks for targeted normal runs.
  - `--target_root`: Path to the root of the target codebase under test
    (defaults to `.`). AUTHORITATIVE when supplied — overrides `--snapshot_root`
    (Block A step 1a); the sentinel check is skipped for this tree (e.g. a
    patched shadow during re-attack verification).
  - `--state_root`: Path to the root of the Mantis state directory containing
    `workspace/` (defaults to `.`).
  - `--snapshot_root`: Root of the pinned immutable code snapshot for this pass.
    Consumed by Block A (Step 0) when `--target_root` is not supplied.
  - `--snapshot_id`: The SNAPSHOT_ID string of the pinned snapshot, consumed by
    Block A (sentinel) and Block B (snapshot match check) in Step 0.
  - `--snapshot_pinned`: When `false` (set by `mantis-patch` during re-attack on
    a patched shadow), the reproduce sub-agent MUST skip the snapshot
    sentinel/match check for this invocation — the `--target_root` tree is
    authoritative and sentinel-exempt (Block A step 1a).

## Input/Output Contract

- **Reads**:
  - `state_root/workspace/findings/` (viable/conditional findings).
  - `target_root/` (Repository source files to analyze trigger paths).
  - `state_root/workspace/archive/.repro_attempts.json`.
  - `state_root/workspace/.mantis_state.json` (to track current loop pass).
- **Writes**:
  - PoC reproduction files (e.g. `poc_[uuid].py` or `crash_[uuid].payload`
    inside `state_root/workspace/reproducers/`).
  - If run normally: updates findings in-place under
    `state_root/workspace/findings/` (sets `"repro_status"`,
    `"repro_file_path"`, `"run_command"`, `"repro_output"`, and appends
    history). Updates status to `"VALID"` if provisionally valid.
  - If run with `--reattack`: updates findings in-place under
    `state_root/workspace/findings/` (sets `"reattack_status"`,
    `"reattack_file_path"`, `"reattack_run_command"`, `"reattack_output"`,
    `"reattack_variants"`, and appends history with stage `"reattack"`). Does
    not modify `"repro_*"` fields or `"status"`. **Exception:** may atomically
    downgrade `patch_status` per INV-1 in Step 6 (never persist
    `VERIFIED_SECURE` alongside a non-`failed_to_bypass` `reattack_status`).
  - Updates `state_root/workspace/archive/.repro_attempts.json` atomically.
  - Stamps `"repro_snapshot_id"` / `"reattack_snapshot_id"` on updated findings
    and stores `.repro_attempts.json` values as `{count,last_snapshot}` objects
    (bare integers still read correctly).
- **Preconditions**:
  - Findings must exist in `state_root/workspace/findings/`.
  - Sandbox/container runtime environment must be available.
- **Idempotency Guarantee**:
  - Updates findings in place. Uses
    `state_root/workspace/archive/.repro_attempts.lock` file locking and atomic
    temporary file swaps (`os.replace` on
    `state_root/workspace/archive/.repro_attempts.json.tmp`) to guarantee
    concurrency safety and retry stability.
  - Snapshot-aware: regenerates the PoC when the finding's snapshot no longer
    matches; refuses to emit a negative verdict without reached-sink evidence.
    Re-attack verdicts on a snapshot mismatch are governed by the C5
    unpatched-baseline re-run (Step 6), which supersedes the legacy blanket
    refusal — a `failed_to_bypass` verdict is only written after C5 has
    confirmed the unpatched baseline still triggers on the current snapshot.

## Instructions

### Step 0: Locator Resolution + Snapshot Match (run first)

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

Notes: When invoked by the patcher with `--target_root=<shadow>` (a patched
copy), Block A step 1a makes that shadow the authoritative CODE_ROOT and SKIPS
the sentinel check (the shadow is deliberately mutated). Otherwise CODE_ROOT is
the pinned snapshot and the sentinel MUST match. Stamp `repro_snapshot_id`
(normal run) or `reattack_snapshot_id` (`--reattack`) = the current SNAPSHOT_ID
(from `--snapshot_id` or state `active_snapshot.snapshot_id`) on every finding
you update.

Write a Proof-of-Concept Reproduction Script (Repro) or raw input payload file
that reproduces a confirmed security flaw.

Execute the reproduction stage under these constraints:

1. **Load Viable Findings:**

   - If `--finding_id` is supplied:
     - Load only that finding's file
       (`state_root/workspace/findings/<uuid>.json`). Exit if it does not exist.
     - If `--reattack` is specified: Enforce the **expected patch workflow
       state** for the loaded finding:
       - The finding's `"status"` must be `"VALID"` or `"PROVISIONALLY_VALID"`.
       - The finding's `"repro_status"` must be `"reproduced"`.
       - The finding's `"patch_status"` must NOT be `"MITIGATION_PROPOSED"`.
         (`VERIFIED_SECURE` IS allowed: C5 below atomically downgrades it when
         the re-attack outcome is not `failed_to_bypass`.)
       - Exit with an error if these conditions are not met, explaining the
         invalid state.
     - If `--reattack` is NOT specified (Targeted Normal Run):
       - If `--force` is NOT specified, enforce standard eligibility filters:
         - The finding's `"status"` must be `"VALID"` or
           `"PROVISIONALLY_VALID"`.
         - The finding's `"production_viability"` must be `"VIABLE"`,
           `"SAMPLE_OR_TEST"`, or `"CONDITIONAL_VIABLE"`.
         - Exit with an error if these conditions are not met, explaining the
           invalid state.
       - If `--force` is specified, bypass these eligibility checks.
   - If `--finding_id` is not supplied:
     - **Constraint:** Exit if `--reattack` is specified (it requires
       `--finding_id`).
     - Read the JSON files in the `state_root/workspace/findings/` directory.
     - **Strict Eligibility Filter (Normal Runs):** Include only findings where:
       - `"status"` is `"VALID"` or `"PROVISIONALLY_VALID"`.
       - `"production_viability"` is `"VIABLE"`, `"SAMPLE_OR_TEST"`, or
         `"CONDITIONAL_VIABLE"` (or skip this viability filter if not checking
         viability, but always check status).
     - If no applicable findings exist, notify the user and exit.

   **Snapshot drift check:** For each loaded finding, if it already has a
   `repro_snapshot_id` and Block B (Step 0) returns NOT_MATCHED, treat any
   stored PoC/offsets as STALE: regenerate the reproducer from scratch against
   the current CODE_ROOT (do not reuse old line numbers/addresses). If Block B
   is MATCHED you may reuse an existing PoC.

2. **Strict Host Isolation Constraint:**

   - Host command execution is strictly prohibited. Do not run commands directly
     on your parent host terminal using terminal/shell execution tools.
   - All reproducer executions must run isolated. Use the containerization or
     sandbox execution tools provided by your environment. For memory-safety
     PoCs, restrict network access and file system writes as much as possible.
     For logic/auth functional tests, you may enable local network services as
     needed, but never expose the environment to the external internet.

3. **Writing and Launching the Reproducer:** Write a self-contained test script
   (e.g., `poc_[uuid].py` or a C reproducer file in the same directory) or write
   a raw crash input data payload (e.g., `crash_[uuid].payload`) that triggers
   the target bug. **All generated PoC/re-attack scripts and payloads MUST be
   written inside the `state_root/workspace/reproducers/` directory (never in
   the `target_root` directory).** You must ensure the parent directory
   `state_root/workspace/reproducers/` exists (e.g. using `mkdir -p`) before
   writing any files. Analyze the code path and constraints carefully. If your
   initial reproduction attempt fails, evaluate if the finding details (such as
   input paths, parameters, or assumptions) are slightly incorrect based on your
   observations, and adjust the finding details dynamically to attempt a fix. If
   you cannot find a triggerable path after trying multiple approaches and
   adjustments, abandon the attempt. **Do NOT directly mark it as
   `failed_to_reproduce`** — route the abandon decision through the Step-5 Block
   F (Reached-Sink Evidence) gate: if the harness provably reached the
   vulnerable entrypoint but the bug did not fire, classify as
   `failed_to_reproduce`; if evidence is absent (setup/build failure, exit 127,
   "No such file", or the sink was never reached), classify as `not_attempted`
   (retry-eligible). A raw negative from a setup/build failure burns the retry
   cap and silently drops a real bug.

   To run your script or payload, use the execution or containerization tools
   available in your environment to execute the code safely. Select the most
   appropriate runtime image and flags for the target. **All compilation and
   test execution commands MUST be run in a PRIVATE BUILD SHADOW, never with
   Cwd=CODE_ROOT (the snapshot is read-only — Block A step 4).** Before
   compiling, create `BUILD_ROOT=$(mktemp -d)` and copy CODE_ROOT into it (e.g.
   `cp -a CODE_ROOT/. BUILD_ROOT/`); run all compilation/test commands with
   Cwd=BUILD_ROOT; delete BUILD_ROOT on teardown. Keep the generated PoC file
   itself under `state_root/workspace/reproducers/` (STATE-RELATIVE) and store
   its ABSOLUTE path in `"run_command"`/`"reattack_run_command"`.

   **Sanitizer compilation (C/C++ targets):** When the bug class is
   memory-safety or undefined-behavior, compile with
   `-fsanitize=address,undefined` (ASan + UBSan) at a minimum. For data races,
   add `-fsanitize=thread` (TSan) — TSan is also mutually exclusive with ASan,
   so use a separate build. Use `-fno-omit-frame-pointer` for usable stack
   traces. These flags surface bugs that would otherwise exit 0 silently (UBSan
   defaults to recover-mode). **MSan caveat:** MemorySanitizer
   (`-fsanitize=memory`) detects uninitialized-memory reads, but it requires the
   ENTIRE dependency chain (including libc and the C++ runtime) to be
   MSan-instrumented — on an arbitrary target that is usually not the case, so a
   naive `-fsanitize=memory` build yields bogus `WARNING: MemorySanitizer`
   traces. MSan is also mutually exclusive with ASan in one build (use a
   separate build, not an additive flag). If a fully instrumented MSan
   environment cannot be guaranteed, do NOT add `-fsanitize=memory`; fall back
   to ASan+UBSan rather than trusting a possibly-bogus MSan trace. Recognizing
   MSan output as evidence (Step 5) is still correct when a legitimate MSan
   instrumented build is available. **Sanitizer consistency guardrail:** the
   SAME sanitizer flags MUST be used for the baseline, attack, and re-attack
   runs — a different sanitizer can mask the bug and produce a false negative
   (INV-2) or false `VERIFIED_SECURE` (INV-1). See Block G.

   **{TARGET_ROOT} token substitution (numbered step):**

   1. When writing `run_command` or `reattack_run_command`, use the literal
      token `{TARGET_ROOT}` for any path that references the target tree.
   2. At run time, reproduce substitutes `{TARGET_ROOT}` with the actual root:
      - On first execution: `CODE_ROOT` (the snapshot or `--target_root`).
      - On re-execution (re-attack or retry): the current `CODE_ROOT` /
        `--target_root` / `active_snapshot.root`.
   3. This ensures the stored command resolves correctly after snapshot GC —
      never bake an absolute `.mantis_snapshots/pass_<N>` path into the stored
      command.

   **Execute your reproduction using the appropriate environment:** If the
   target is firmware, you may write a script to boot it via `qemu`, `unicorn`,
   or Firmadyne. If it's a binary, you may use dynamic instrumentation or
   standard execution. Use your best judgment to construct a working harness for
   the artifact.

   - *Optional Parallel Trajectory Search:* If your environment or agent
     framework supports spawning subagents, you can deploy multiple concurrent
     agents to attempt writing the reproducer via different logical approaches.
     If any trajectory succeeds, immediately adopt its payload and discard the
     others to escape potential "give up" loops.

3a. **Variant Hunting (re-attack only, MANDATORY):** When invoked with
`--reattack`, you MUST author and execute **N ≥ 3 boundary-mutated variant
inputs** in addition to re-running the original PoC. The schema (`schema.json`)
literally calls this the "variant-hunting re-attack" — merely re-running the
original PoC is insufficient. Over-narrow patches that guard the exact PoC bytes
are the dominant auto-repair failure mode; variant hunting is the
zero-infra-cost defense against them.

**What to generate (bug-class-aware):**

- **Memory-safety bugs (buffer overflow, OOB read/write, UAF, integer
  overflow):** Author at least 3 of:

  - **Off-by-one:** `len = bound`, `len = bound + 1`, `len = bound - 1`.
  - **Size mutations:** `len ± 1`, `len = 0`, `len = SIZE_MAX`, sign flips on
    signed lengths.
  - **Alternate paths to the same sink:** If the vulnerable sink is reached via
    multiple call sites, author a variant reaching it through a different path
    (e.g., different API endpoint, file format variant, or protocol command).
  - **Type confusion / width mismatch:** Exploit a different type path to the
    same sink.

- **Non-memory-safety bugs (logic, auth, injection, SSRF, path traversal):**
  Hunt for actual variants of the same class:

  - **Alternate endpoints/parameters:** Try `/api/v2/echo` when PoC targets
    `/api/v1/echo`, or alternate parameter names.
  - **Equivalent payloads:** `..%2fetc%2fpasswd`, `..\\..\\`, URL-encoding,
    double encoding, unicode normalization variants.
  - **Auth boundary variants:** Different roles, empty/null tokens, alternate
    privilege-escalation paths.
  - **Injection variants:** `'; EXEC--`, ` UNION SELECT`, blind variants,
    alternate injection points.

- **Parallel variant generation (if subagents available):** You SHOULD spawn
  subagents to author and test variants in parallel. Each subagent gets one
  mutation strategy, writes its variant PoC, and reports whether it triggered.
  Aggregate all results before setting `reattack_status`. If subagents are
  unavailable, do them sequentially.

**Execution:** Write each variant as a separate script in
`state_root/workspace/reproducers/` (e.g., `reattack_variant_[uuid]_[N].py`).
Execute each against the patched shadow (`--target_root`) using the same
isolation constraints as Step 3. Record each variant's description and whether
it triggered in the `reattack_variants` array (Step 6).

**Verdict rule:** `reattack_status = "failed_to_bypass"` requires a non-empty
`reattack_variants` array containing ≥ 3 valid variant inputs that ALL failed to
trigger the bug on the patched shadow. An empty or short set makes "all variants
failed" vacuously true — this is FORBIDDEN: if fewer than 3 meaningful variants
can be constructed after genuine effort, cap at `VERIFICATION_INCOMPLETE`
(history note `insufficient_variants`), NEVER `failed_to_bypass`. The `[]` case
may ONLY coexist with a non-`failed_to_bypass` status (e.g., C5 baseline failure
that halted before variant hunting).

**Variant validity guardrail:** A variant counts as a bypass (`triggered = true`
causing `bypassed_patch`) ONLY if it satisfies BOTH:

1. **Same vulnerability class:** The variant reproduces the original bug class —
   same sink function / sanitizer signature / crash type. A junk mutant (e.g.,
   `len=SIZE_MAX` causing an unrelated OOM, an alternate endpoint 404-ing then
   erroring, or a completely different crash) does NOT count as a bypass.
   Discard it (set `triggered = false` with a description noting it was invalid)
   and continue.
2. **Valid input per Step 4:** The variant must be a valid exercise of the
   public API or internal invariants — it must not rely on artificial harness
   tricks (e.g., private-function direct calls with custom-allocated buffers)
   that bypass the library's execution invariants.

Ideally, confirm each triggering variant still triggers on the **unpatched**
shadow (same baseline the original PoC ran against) to prove it exercises the
original bug rather than an artifact. If the unpatched shadow is unavailable
(e.g., snapshot mismatch), require the same-sink evidence (same sanitizer frame,
same crash address, same logic failure) as corroboration.

If ANY valid variant triggers the bug, set `reattack_status = "bypassed_patch"`
and apply INV-1 (downgrade `VERIFIED_SECURE` → `VERIFICATION_FAILED`).

- **Reproduction Status Classification:**

  - **`reproduced`**: The PoC successfully triggered the vulnerability.
  - **`failed_to_reproduce`**: The PoC was executed but did not trigger the
    vulnerability.
  - **`statically_confirmed`**: Reproduction was impossible due to environmental
    constraints (e.g., missing hardware emulators, unavailable external
    services) but the flaw is statically obvious (e.g., hardcoded credentials).
    This is strongly discouraged and should only be used as a last resort.
  - **`not_attempted`**: The reproduction stage was skipped entirely (e.g., due
    to infrastructure setup failure, timeouts, or explicit skip configuration).

4. **Strict Public-API & Internal Invariant Constraints:**

   - Your crash reproducer should interact with the codebase through
     public-facing APIs wherever possible, or strictly respect the library's
     global execution invariants (such as allocator padding) to avoid generating
     artificial, non-viable crashes.
   - Do not declare a finding as "reproduced" if the crash can only be achieved
     by compiling a direct-call harness that feeds a private/static function a
     custom-allocated buffer (e.g., `malloc(15)`) that bypasses the library's
     guaranteed allocator wrappers (e.g., `png_malloc(rowbytes + 48)`).
   - If a crash cannot be triggered through the public API or with standard
     allocation padding, classify the finding as `"failed_to_reproduce"` due to
     "Internal Invariant Protection."

5. **Functional & Crash-Aware Validation:** Analyze the output such as stdout,
   stderr, and exit codes to classify reproduction success depending on the bug
   class:

   Before classifying ANY negative outcome (`failed_to_reproduce`, or in
   `--reattack` mode `failed_to_bypass`), apply this gate:

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

   Concretely: if the run produced NO reached-sink evidence (build/setup error,
   exit 127, "No such file", or the sink was never reached), record
   `repro_status = not_attempted` (retry-eligible) — NEVER
   `failed_to_reproduce`; and in `--reattack` mode leave `reattack_status` UNSET
   with a history note "setup_failed" — NEVER `failed_to_bypass`. Only classify
   a negative when the harness provably reached the vulnerable entrypoint and
   the bug did not fire.

   **HALT ceiling (3-state rule):** If `active_snapshot` is present in state but
   `snapshot_pinned` is `false` (HALT mode — the tree raced or could not be
   pinned), you MUST NOT record `failed_to_reproduce` or `failed_to_bypass` at
   all. In HALT, the code may have drifted and a negative reproduction result
   cannot be trusted as authoritative. Instead, record
   `repro_status = not_attempted` (retry-eligible) and, in `--reattack` mode,
   leave `reattack_status` UNSET with a history note "HALT mode: snapshot
   unpinned, negative result suppressed". This mirrors the authoritative-verdict
   prohibition that applies to all stages in HALT. (In MODE-OFF — no
   `active_snapshot` — classify negatives normally as today.)

   - **Logic & Authorization Bugs:** A successful reproducer is a functional
     unit test or script that explicitly demonstrates the logic failure (e.g.,
     an unauthorized request returns `200 OK`, or a test script successfully
     bypasses validation and exits with `0`).
   - **Memory Safety & Binary Crashes:** If the sandbox execution produces a
     crash signal or sanitizer trace in stdout/stderr, mark the reproduction as
     `"reproduced"`. **Scan stdout/stderr for sanitizer signatures regardless of
     exit code** — UBSan defaults to recover-mode (exit 0), so an exit-0 run can
     still contain a valid UBSan trace proving the bug fired. Check for:
     - AddressSanitizer (ASan) error outputs (e.g. `ERROR: AddressSanitizer`).
     - UndefinedBehaviorSanitizer (UBSan) runtime reports (e.g.
       `runtime error:`, `SUMMARY: UndefinedBehaviorSanitizer`).
     - MemorySanitizer (MSan) error outputs (e.g. `WARNING: MemorySanitizer`).
     - ThreadSanitizer (TSan) race reports (e.g. `WARNING: ThreadSanitizer`).
     - Segmentation faults (SIGSEGV, exit code `139`).
     - Abort signals (SIGABRT, exit code `134`).
     - Crash or core dumps.

6. **Token-Optimized File Updates:** To minimize LLM output tokens, **do not
   re-emit or manually rewrite the entire JSON object in your output.** Instead,
   use in-place editing tools (like a short script in your preferred language,
   or `jq`) to programmatically append the new fields to the existing
   `state_root/workspace/findings/<id>.json` file.

   Additionally, you must **Update the Reproduction Attempt Cache** to help the
   planner track attempts efficiently:

   - Maintain a JSON cache file at
     `state_root/workspace/archive/.repro_attempts.json`. Ensure the parent
     directory `state_root/workspace/archive/` exists (e.g.,
     `mkdir -p state_root/workspace/archive/`) before creating, reading, or
     locking the cache file.
   - Key the cache by a stable identifier that persists across loop runs even if
     UUIDs are regenerated. If the finding has a `signature` field, use it
     directly as the cache key (it is already a deterministic content-identity
     hash). If `signature` is absent, fall back to a computed stable key using
     the finding's normalized title and its primary file path:
     `stable_key = normalized_title + "@" + primary_file_path`.
     - Compute `normalized_title` by converting the title to lowercase and
       removing all non-alphanumeric characters.
     - Compute `primary_file_path` by taking the first entry in `code_paths` and
       stripping any line number suffixes (e.g., converting `src/auth.c:120` to
       `src/auth.c`).
     - **Snapshot-aware cap (value shape `{count, last_snapshot}`):** store each
       cache value as an object `{count, last_snapshot}`. When reading a value
       V: if V is a bare integer, treat count=V and last_snapshot=UNKNOWN; if V
       is an object, use V.count / V.last_snapshot (default UNKNOWN). Before
       incrementing, run Block B comparing the finding's snapshot to the current
       SNAPSHOT_ID: reset `count=0` ONLY when Block B is NOT_MATCHED *because
       the two snapshots are present and actually differ* (a genuine code change
       earns a fresh budget). Do NOT reset on UNKNOWN (absent/`pass_`/unpinned)
       — that would make no-VCS targets retry forever. Additionally keep an
       absolute per-finding-id attempt counter that is NEVER reset, and stop
       retrying once it reaches a hard ceiling (e.g. 6) regardless of snapshot
       changes.
   - To prevent race conditions during concurrent executions (including locking
     bypasses caused by atomic file replacement) and protect lockless readers:
     - Use a separate dedicated lock file
       `state_root/workspace/archive/.repro_attempts.lock` which is never
       deleted or replaced.
     - Perform updates atomically using Python's `fcntl.flock` on this lock
       file:
     * Open the lock file `state_root/workspace/archive/.repro_attempts.lock`
       (creating it if missing) and acquire an exclusive lock (`fcntl.flock`
       with `fcntl.LOCK_EX`) inside a context manager (`with` statement).
     * Read the current contents of the cache file
       `state_root/workspace/archive/.repro_attempts.json` (treating it as `{}`
       if missing or empty).
     * Increment the `count` field of this finding's cache-key entry — keyed by
       `signature` if present, else `stable_key`, the SAME key selection defined
       above (the `{count, last_snapshot}` object) — by 1.
     * Write the updated JSON to a temporary file in the same directory (e.g.,
       `state_root/workspace/archive/.repro_attempts.json.tmp`).
     * Atomically replace the target cache file with the temporary file (e.g.,
       `os.replace` in Python) to ensure readers never see a truncated or
       incomplete file.
     * Close the lock file descriptor to release the lock (automatically handled
       by exiting the `with` context manager).

   Depending on whether the `--reattack` flag is provided:

   - **If run normally (no `--reattack` flag):** You must append or update the
     following on the existing object:

     - `"repro_status"` (`"reproduced"`, `"statically_confirmed"`,
       `"not_attempted"`, or `"failed_to_reproduce"`).

     - `"repro_file_path"`

     - `"run_command"`

     - `"repro_output"`

     - `"repro_snapshot_id"`: the current SNAPSHOT_ID this run executed against.

     - If reproduction succeeds (`repro_status` is evaluated as `"reproduced"`
       or `"statically_confirmed"`) and the finding's current `"status"` is
       `"PROVISIONALLY_VALID"`: BEFORE upgrading, scan the finding's
       `triage_checklist` (if present). If ANY entry has `outcome == "UNKNOWN"`
       (or `passes == false`), do NOT upgrade: leave `status` as
       `"PROVISIONALLY_VALID"`, still set `repro_status` to the success value
       (reproduction DID succeed), and append a history note
       `upgrade-to-VALID-blocked: triage_checklist has UNKNOWN entries (re-review required)`.
       This avoids violating the schema's `VALID ⇒ no UNKNOWN` allOf gate
       (schema.json lines 471-507), which forbids `UNKNOWN`/`passes:false` on
       any `VALID` non-chain finding's `triage_checklist`. Reproduce does NOT
       touch `triage_checklist` entries (the checklist is review's artifact;
       only review may resolve `UNKNOWN` entries). If `triage_checklist` is
       absent (no `reviewer` history entry, e.g. a legacy finding), or NO entry
       is `UNKNOWN`/`passes:false`, you **must** update `"status"` to `"VALID"`.

     - An entry to the `"history"` array:

     ```json
     {
       "stage": "reproduce",
       "action": "reproduced",
       "details": "Reproduction status evaluated as [reproduced/failed_to_reproduce] using command: [run_command]",
       "pass_number": <current_pass_number>,
       "timestamp": "<current_iso8601_timestamp>"
     }
     ```

   - **If run with `--reattack`:** You must append or update the following on
     the existing object (do not touch `repro_*` or `status`):

     - `"reattack_status"` (`"bypassed_patch"`, `"failed_to_bypass"`,
       `"inconclusive_baseline_changed"`).

     - `"bypassed_patch"`: The PoC bypassed the patch and triggered the bug. If
       `patch_status` is `VERIFIED_SECURE`, atomically set
       `patch_status = "VERIFICATION_FAILED"` in the same write (a bypass
       defeats the patch). This is an explicit exception to "do not touch
       status" and applies to both the C5 step-3 path and same-snapshot runs.

     - `"failed_to_bypass"`: The PoC was run but failed to bypass the patch. (No
       downgrade needed — `failed_to_bypass` is the value the allOf gate
       requires for `VERIFIED_SECURE`.)

     - `"inconclusive_baseline_changed"`: The unpatched baseline was re-run (see
       C5 below) and the bug NO LONGER TRIGGERS on the current unpatched code.
       Do NOT claim `failed_to_bypass`. If `patch_status` is `VERIFIED_SECURE`,
       atomically set `patch_status = "VERIFICATION_INCOMPLETE"` in the same
       write.

     - **INV-1 (single source — the schema's `VERIFIED_SECURE` allOf gate):**
       `VERIFIED_SECURE => reattack_status` must be `failed_to_bypass`, and
       `failed_to_bypass` requires a non-empty `reattack_variants` array with ≥
       3 valid variant inputs (Step 3a) that ALL failed to trigger the bug on
       the patched shadow. An empty or short variant set makes "all failed"
       vacuously true — this is FORBIDDEN: cap at `VERIFICATION_INCOMPLETE`
       instead. Any other outcome MUST atomically downgrade `patch_status` in
       the same write — `VERIFICATION_INCOMPLETE` for
       `inconclusive_baseline_changed` or an insufficient variant set,
       `VERIFICATION_FAILED` for `bypassed_patch`. Never persist
       `VERIFIED_SECURE` alongside a non-`failed_to_bypass` `reattack_status`.

     - **Snapshot-mismatch -> governed by C5 below:** When
       `reattack_snapshot_id` != `repro_snapshot_id`, do NOT independently
       record a verdict — follow C5, which re-establishes the unpatched baseline
       on the CURRENT snapshot. If C5 cannot run, fall back to leaving
       `reattack_status` UNSET with a `SNAPSHOT_MISMATCH` history note.

     - **C5 — Unpatched-baseline re-run (Phase 2):** Before running the attack
       on the patched build, if `reattack_snapshot_id` != `repro_snapshot_id` (a
       genuine snapshot change, NOT a HALT-mode `live:` tree), FIRST
       re-establish the unpatched baseline:

       1. Run the reproducer against a FRESH UNPATCHED copy of the current
          snapshot — a fresh `mktemp -d` copy of `active_snapshot.root`, NOT the
          patched shadow. (This is the same unpatched baseline that
          `mantis-patch` Block G step 1 runs; reproduce has no Block G.)
       2. If the unpatched baseline does NOT trigger (evidence absent per Block
          F): set `reattack_status = "inconclusive_baseline_changed"`, do NOT
          proceed with the attack, do NOT claim `failed_to_bypass`. You MUST
          still populate `reattack_file_path`, `reattack_run_command`, and
          `reattack_output` with the baseline re-run's details. Apply INV-1
          (downgrade `VERIFIED_SECURE` -> `VERIFICATION_INCOMPLETE`).
       3. If the unpatched baseline DOES trigger: proceed with the attack
          (`bypassed_patch` or `failed_to_bypass`). Apply INV-1 (downgrade
          `VERIFIED_SECURE` -> `VERIFICATION_FAILED` if `bypassed_patch`).

       - **Sanitizer consistency:** the baseline re-run, attack, and re-attack
         MUST use the same sanitizer flags that made the original baseline
         trigger. If the baseline triggered via UBSan (exit 0), recompiling the
         attack without UBSan would mask the bug and produce a false negative
         (INV-2) or false `failed_to_bypass` (INV-1).
       - **HALT-mode guardrail:** Detect HALT by the PASS's snapshot id in state
         (`active_snapshot.snapshot_id` starts with `live:`), NOT the
         `--snapshot_pinned=false` argument (that's only the sentinel-exemption
         for the patched shadow). In HALT, skip C5 and follow the existing HALT
         ceiling (leave `reattack_status` UNSET with the HALT note).
       - This does NOT change the VERIFIED_SECURE gate — Block G still requires
         the unpatched baseline to trigger.

     - `"reattack_file_path"`

     - `"reattack_run_command"`

     - `"reattack_output"`

     - `"reattack_variants"`: An array of objects, one per variant input
       attempted during Step 3a. Each object MUST have:

       - `"description"`: What the variant does (e.g.,
         `"off-by-one: len=bound+1"`, `"alternate path via /api/v2/echo"`).
       - `"triggered"`: boolean — whether this variant triggered the original
         vulnerability class on the patched shadow (per the variant validity
         guardrail in Step 3a). Invalid/junk mutants that produced an unrelated
         crash or error are recorded as `triggered = false` with a description
         noting invalidity. `reattack_variants` MUST be non-empty (≥ 3 entries)
         for `reattack_status = "failed_to_bypass"`. An empty array `[]` may
         ONLY coexist with a non-`failed_to_bypass` status (e.g., C5 baseline
         failure that halted before variant hunting, or
         `inconclusive_baseline_changed`).

     - `"reattack_snapshot_id"`: the current SNAPSHOT_ID this run executed
       against.

     - An entry to the `"history"` array:

     ```json
     {
       "stage": "reattack",
       "action": "reproduced",
       "details": "Re-attack status evaluated as [bypassed_patch/failed_to_bypass] using command: [reattack_run_command]",
       "pass_number": <current_pass_number>,
       "timestamp": "<current_iso8601_timestamp>"
     }
     ```

7. **Criticism of Reproduction Validity:** To ensure the reproduction is a valid
   example of reproducing the reported vulnerability, have a subagent with a
   fresh context window review and criticize the generated PoC. Seek genuine
   criticism to ensure false reports are never surfaced later.

   **Variant criticism (re-attack only):** When `--reattack` is specified, the
   critic subagent MUST also verify that the variant inputs (Step 3a) are
   genuinely diverse — not trivially identical mutations (e.g., changing a
   comment while keeping the same payload). If the critic finds the variants are
   not meaningfully diverse, record a history note
   `variant_diversity_insufficient` and re-author variants before finalizing
   `reattack_status`.

When complete, notify the user.

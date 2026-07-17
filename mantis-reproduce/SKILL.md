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

-   **Command:** `/mantis-reproduce [--reattack] [--finding_id=<uuid>]
    [--target_root=<path>] [--state_root=<path>]`
-   **Description:** Generates and runs crash reproducers to verify security
    flaws.
-   **Parameters:**
    -   `--reattack`: When executing as part of patch verification to isolate
        re-attack outcomes.
    -   `--finding_id`: The specific finding UUID to reproduce. **Must** be
        provided and is required when `--reattack` is specified.
    -   `--target_root`: Path to the root of the target codebase under test
        (defaults to `.`).
    -   `--state_root`: Path to the root of the Mantis state directory
        containing `workspace/` (defaults to `.`).

## Input/Output Contract

-   **Reads**:
    -   `state_root/workspace/findings/` (viable/conditional findings).
    -   `target_root/` (Repository source files to analyze trigger paths).
    -   `state_root/workspace/archive/.repro_attempts.json`.
    -   `state_root/workspace/.mantis_state.json` (to track current loop pass).
-   **Writes**:
    -   PoC reproduction files (e.g. `poc_[uuid].py` or `crash_[uuid].payload`
        inside `state_root/workspace/reproducers/`).
    -   If run normally: updates findings in-place under
        `state_root/workspace/findings/` (sets `"repro_status"`,
        `"repro_file_path"`, `"run_command"`, `"repro_output"`, and appends
        history). Updates status to `"VALID"` if provisionally valid.
    -   If run with `--reattack`: updates findings in-place under
        `state_root/workspace/findings/` (sets `"reattack_status"`,
        `"reattack_file_path"`, `"reattack_run_command"`, `"reattack_output"`,
        and appends history with stage `"reattack"`). Does not modify
        `"repro_*"` fields or `"status"`.
    -   Updates `state_root/workspace/archive/.repro_attempts.json` atomically.
-   **Preconditions**:
    -   Findings must exist in `state_root/workspace/findings/`.
    -   Sandbox/container runtime environment must be available.
-   **Idempotency Guarantee**:
    -   Updates findings in place. Uses
        `state_root/workspace/archive/.repro_attempts.lock` file locking and
        atomic temporary file swaps (`os.replace` on
        `state_root/workspace/archive/.repro_attempts.json.tmp`) to guarantee
        concurrency safety and retry stability.

## Instructions

Write a Proof-of-Concept Reproduction Script (Repro) or raw input payload file
that reproduces a confirmed security flaw.

Execute the reproduction stage under these constraints:

1.  **Load Viable Findings:**

    -   If `--finding_id` is supplied: load only that finding's file
        (`state_root/workspace/findings/<uuid>.json`). Exit if it does not
        exist.
    -   If `--finding_id` is not supplied: read the JSON files in the
        `state_root/workspace/findings/` directory. Filter for findings where
        `production_viability` is `"VIABLE"`, `"SAMPLE_OR_TEST"`, or
        `"CONDITIONAL_VIABLE"` (or skip the filter if you're not checking
        viability). If no applicable findings exist, notify the user.
    -   **Constraint:** Enforce that `--finding_id` is strictly required if
        `--reattack` is specified, preventing re-attacks from running against
        unrelated findings.

2.  **Strict Host Isolation Constraint:**

    -   Host command execution is strictly prohibited. Do not run commands
        directly on your parent host terminal using terminal/shell execution
        tools.
    -   All reproducer executions must run isolated. Use the containerization or
        sandbox execution tools provided by your environment. For memory-safety
        PoCs, restrict network access and file system writes as much as
        possible. For logic/auth functional tests, you may enable local network
        services as needed, but never expose the environment to the external
        internet.

3.  **Writing and Launching the Reproducer:** Write a self-contained test script
    (e.g., `poc_[uuid].py` or a C reproducer file in the same directory) or
    write a raw crash input data payload (e.g., `crash_[uuid].payload`) that
    triggers the target bug. **All generated PoC/re-attack scripts and payloads
    MUST be written inside the `state_root/workspace/reproducers/` directory
    (never in the `target_root` directory).** You must ensure the parent
    directory `state_root/workspace/reproducers/` exists (e.g. using `mkdir -p`)
    before writing any files. Analyze the code path and constraints carefully.
    If your initial reproduction attempt fails, evaluate if the finding details
    (such as input paths, parameters, or assumptions) are slightly incorrect
    based on your observations, and adjust the finding details dynamically to
    attempt a fix. If you cannot find a triggerable path after trying multiple
    approaches and adjustments, abandon the attempt and mark it as
    `failed_to_reproduce`.

    To run your script or payload, use the execution or containerization tools
    available in your environment to execute the code safely. Select the most
    appropriate runtime image and flags for the target. **All compilation and
    test execution commands MUST be run with current working directory (Cwd) set
    to `target_root`.** Resolve and use the absolute path of the generated POC
    file (e.g. using python's `os.path.abspath` on
    `state_root/workspace/reproducers/poc_[uuid].py`) when generating and
    storing the `"run_command"` or `"reattack_run_command"`.

    **Execute your reproduction using the appropriate environment:** If the
    target is firmware, you may write a script to boot it via `qemu`, `unicorn`,
    or Firmadyne. If it's a binary, you may use dynamic instrumentation or
    standard execution. Use your best judgment to construct a working harness
    for the artifact.

    -   *Optional Parallel Trajectory Search:* If your environment or agent
        framework supports spawning subagents, you can deploy multiple
        concurrent agents to attempt writing the reproducer via different
        logical approaches. If any trajectory succeeds, immediately adopt its
        payload and discard the others to escape potential "give up" loops.

    -   **Reproduction Status Classification:**

        -   **`reproduced`**: The PoC successfully triggered the vulnerability.
        -   **`failed_to_reproduce`**: The PoC was executed but did not trigger
            the vulnerability.
        -   **`statically_confirmed`**: Reproduction was impossible due to
            environmental constraints (e.g., missing hardware emulators,
            unavailable external services) but the flaw is statically obvious
            (e.g., hardcoded credentials). This is strongly discouraged and
            should only be used as a last resort.
        -   **`not_attempted`**: The reproduction stage was skipped entirely
            (e.g., due to infrastructure setup failure, timeouts, or explicit
            skip configuration).

4.  **Strict Public-API & Internal Invariant Constraints:**

    -   Your crash reproducer should interact with the codebase through
        public-facing APIs wherever possible, or strictly respect the library's
        global execution invariants (such as allocator padding) to avoid
        generating artificial, non-viable crashes.
    -   Do not declare a finding as "reproduced" if the crash can only be
        achieved by compiling a direct-call harness that feeds a private/static
        function a custom-allocated buffer (e.g., `malloc(15)`) that bypasses
        the library's guaranteed allocator wrappers (e.g.,
        `png_malloc(rowbytes + 48)`).
    -   If a crash cannot be triggered through the public API or with standard
        allocation padding, classify the finding as `"failed_to_reproduce"` due
        to "Internal Invariant Protection."

5.  **Functional & Crash-Aware Validation:** Analyze the output such as stdout,
    stderr, and exit codes to classify reproduction success depending on the bug
    class:

    -   **Logic & Authorization Bugs:** A successful reproducer is a functional
        unit test or script that explicitly demonstrates the logic failure
        (e.g., an unauthorized request returns `200 OK`, or a test script
        successfully bypasses validation and exits with `0`).
    -   **Memory Safety & Binary Crashes:** If the sandbox execution completes
        with a non-zero exit code but the stderr/stdout displays memory
        corruption signals, mark the reproduction as `"reproduced"`. Check for:
        -   AddressSanitizer (ASan) error outputs (e.g. `ERROR:
            AddressSanitizer`).
        -   Segmentation faults (SIGSEGV, exit code `139`).
        -   Abort signals (SIGABRT, exit code `134`).
        -   Crash or core dumps.

6.  **Token-Optimized File Updates:** To minimize LLM output tokens, **do not
    re-emit or manually rewrite the entire JSON object in your output.**
    Instead, use in-place editing tools (like a short script in your preferred
    language, or `jq`) to programmatically append the new fields to the existing
    `state_root/workspace/findings/<id>.json` file.

    Additionally, you must **Update the Reproduction Attempt Cache** to help the
    planner track attempts efficiently:

    -   Maintain a JSON cache file at
        `state_root/workspace/archive/.repro_attempts.json`. Ensure the parent
        directory `state_root/workspace/archive/` exists (e.g., `mkdir -p
        state_root/workspace/archive/`) before creating, reading, or locking the
        cache file.
    -   Key the cache by a stable identifier that persists across loop runs even
        if UUIDs are regenerated. Use a combination of the finding's normalized
        title and its primary file path: `stable_key = normalized_title + "@" +
        primary_file_path`.
        -   Compute `normalized_title` by converting the title to lowercase and
            removing all non-alphanumeric characters.
        -   Compute `primary_file_path` by taking the first entry in
            `code_paths` and stripping any line number suffixes (e.g.,
            converting `src/auth.c:120` to `src/auth.c`).
    -   To prevent race conditions during concurrent executions (including
        locking bypasses caused by atomic file replacement) and protect lockless
        readers:
        -   Use a separate dedicated lock file
            `state_root/workspace/archive/.repro_attempts.lock` which is never
            deleted or replaced.
        -   Perform updates atomically using Python's `fcntl.flock` on this lock
            file:
            1.  Open the lock file
                `state_root/workspace/archive/.repro_attempts.lock` (creating it
                if missing) and acquire an exclusive lock (`fcntl.flock` with
                `fcntl.LOCK_EX`) inside a context manager (`with` statement).
            2.  Read the current contents of the cache file
                `state_root/workspace/archive/.repro_attempts.json` (treating it
                as `{}` if missing or empty).
            3.  Increment the integer value for this finding's `stable_key`
                by 1.
            4.  Write the updated JSON to a temporary file in the same directory
                (e.g., `state_root/workspace/archive/.repro_attempts.json.tmp`).
            5.  Atomically replace the target cache file with the temporary file
                (e.g., `os.replace` in Python) to ensure readers never see a
                truncated or incomplete file.
            6.  Close the lock file descriptor to release the lock
                (automatically handled by exiting the `with` context manager).

    Depending on whether the `--reattack` flag is provided:

    *   **If run normally (no `--reattack` flag):** You must append or update
        the following on the existing object:

        -   `"repro_status"` (`"reproduced"`, `"statically_confirmed"`,
            `"not_attempted"`, or `"failed_to_reproduce"`).
        -   `"repro_file_path"`
        -   `"run_command"`
        -   `"repro_output"`
        -   If reproduction succeeds (`repro_status` is evaluated as
            `"reproduced"` or `"statically_confirmed"`) and the finding's
            current `"status"` is `"PROVISIONALLY_VALID"`, you **must** update
            `"status"` to `"VALID"`.
        -   An entry to the `"history"` array:

            ```json
            {
              "stage": "reproduce",
              "action": "reproduced",
              "details": "Reproduction status evaluated as [reproduced/failed_to_reproduce] using command: [run_command]",
              "pass_number": <current_pass_number>,
              "timestamp": "<current_iso8601_timestamp>"
            }
            ```

    *   **If run with `--reattack`:** You must append or update the following on
        the existing object (do not touch `repro_*` or `status`):

        -   `"reattack_status"` (`"bypassed_patch"`, `"failed_to_bypass"`).
            -   `"bypassed_patch"`: The new/modified PoC successfully bypassed
                the patch and triggered the bug.
            -   `"failed_to_bypass"`: The PoC was run but failed to bypass the
                patch.
        -   `"reattack_file_path"`
        -   `"reattack_run_command"`
        -   `"reattack_output"`
        -   An entry to the `"history"` array:

            ```json
            {
              "stage": "reattack",
              "action": "reproduced",
              "details": "Re-attack status evaluated as [bypassed_patch/failed_to_bypass] using command: [reattack_run_command]",
              "pass_number": <current_pass_number>,
              "timestamp": "<current_iso8601_timestamp>"
            }
            ```

7.  **Criticism of Reproduction Validity:** To ensure the reproduction is a
    valid example of reproducing the reported vulnerability, have a subagent
    with a fresh context window review and criticize the generated PoC. Seek
    genuine criticism to ensure false reports are never surfaced later.

When complete, notify the user.

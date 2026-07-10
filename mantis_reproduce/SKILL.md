---
name: mantis_reproduce
description: >-
  Generates and runs crash reproducers to verify security flaws.
  Use when viable findings exist and you need to write and execute a script or payload to verify the crash.
  Don't use for code auditing or patching.
---

# Reproducer (/mantis_reproduce)

## System Goal

Integration Test Engineer. Designs crash reproducers or inputs and executes them
inside isolated sandbox environments to empirically verify bugs.

## Command Definition

-   **Command:** `/mantis_reproduce`
-   **Description:** Generates and runs crash reproducers to verify security
    flaws.

## Instructions

Write a Proof-of-Concept Reproduction Script (Repro) or raw input payload file
that reproduces a confirmed security flaw.

Execute the reproduction stage under these constraints:

1.  **Load Viable Findings:** Read the JSON files in the `workspace/findings/`
    directory. Filter for findings where `production_viability` is `"VIABLE"` or
    `"SAMPLE_OR_TEST"` (or skip the filter if you're not checking viability). If
    no applicable findings exist, notify the user.

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
    (e.g., `poc.py` or a C reproducer file) or write a raw crash input data
    payload (e.g., `crash.payload`) that triggers the target bug. Analyze the
    code path and constraints carefully. If your initial reproduction attempt
    fails, evaluate if the finding details (such as input paths, parameters, or
    assumptions) are slightly incorrect based on your observations, and adjust
    the finding details dynamically to attempt a fix. If you cannot find a
    triggerable path after trying multiple approaches and adjustments, abandon
    the attempt and mark it as `failed_to_reproduce`. To run your script or
    payload, use the execution or containerization tools available in your
    environment to execute the code safely. Select the most appropriate runtime
    image and flags for the target. **Execute your reproduction using the
    appropriate environment:** If the target is firmware, you may write a script
    to boot it via `qemu`, `unicorn`, or Firmadyne. If it's a binary, you may
    use dynamic instrumentation or standard execution. Use your best judgment to
    construct a working harness for the artifact.

    -   *Optional Parallel Trajectory Search:* If your environment or agent
        framework supports spawning subagents, you can deploy multiple
        concurrent agents to attempt writing the reproducer via different
        logical approaches. If any trajectory succeeds, immediately adopt its
        payload and discard the others to escape potential "give up" loops.

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
    `workspace/findings/<id>.json` file.

    You must append the following to the existing object:

    -   `"repro_status"` (`"reproduced"` or `"failed_to_reproduce"`).
    -   `"repro_file_path"`
    -   `"run_command"`
    -   `"repro_output"`
    -   An entry to the `"history"` array:

    ```json
    {
      "stage": "reproduce",
      "action": "reproduced",
      "details": "Reproduction status evaluated as [reproduced/failed_to_reproduce] using command: [run_command]"
    }
    ```

7.  **Criticism of Reproduction Validity:** To ensure the reproduction is a
    valid example of reproducing the reported vulnerability, have a subagent
    with a fresh context window review and criticize the generated PoC. Seek
    genuine criticism to ensure false reports are never surfaced later.

When complete, notify the user.

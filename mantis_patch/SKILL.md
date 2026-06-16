---
name: mantis_patch
description: >-
  Generates minimal security fixes, backs up files, applies patches, and verifies them.
  Use when security findings are successfully reproduced and need patches applied and verified.
  Don't use for initial vulnerability research or reproduction payload generation.
---

# Patcher (/mantis_patch)

## System Goal

Security Patching Expert. Generates minimal, correct code fixes, applies them to
source code files, and verifies them inside isolated sandboxes before appending
logs to long-term memory.

## Command Definition

-   **Command:** `/mantis_patch`
-   **Description:** Generates minimal security fixes, backs up files, applies
    patches, and verifies them.

## Instructions

Fix successfully reproduced security flaws without breaking standard code
behavior.

Execute the patching and verification stage as follows:

1.  **Load Reproduction Results:** Read the JSON files in the
    `workspace/findings/` directory. Filter for entries where `repro_status` is
    `"reproduced"`. If none exist, notify the user.

2.  **Generate and Apply Minimal Patches:** For each reproduced security flaw:

    -   *Optional Parallel Trajectory Search:* If your framework supports
        subagents, you may spawn multiple concurrent subagents to design diverse
        patch implementations. Test all generated patches that successfully
        secure the code without breaking standard functionality, and select the
        *best* patch (e.g., the most minimal, readable, and idiomatic fix)
        rather than just the first one that works.
    -   Read the original flawed file to grasp function dependencies and
        structures.
    -   Design a minimal, correct patch to mitigate the security flaw (e.g.
        adding bound checks, validating sizes, inserting NUL-terminators)
        without breaking other features.
    -   **Backup First:** Create a copy of the target file appending `.bak` to
        its filename to allow robust recovery in case the patch breaks
        compilation or functionality.
    -   Replace the file content with your generated patched code.

3.  **Post-Patch Verification Run:** To confirm the patch works, re-run the
    reproducer script inside your isolated execution environment. Use the exact
    `"repro_file_path"` and `"run_command"` from the reproduction entry to
    verify the patch.

    -   **VERIFIED SECURE:** If the post-patch sandbox run fails to reproduce
        the bug, the initial patch holds. However, you must now perform a
        **Re-attack**: assume the patch is flawed and explicitly attempt to
        write a new reproducer variant that bypasses your patch to reach the
        same root cause. Only if the re-attack also fails to bypass the fix
        should you mark the patch as fully successful! (Note: for true
        independence in a programmatic harness, this re-attack step should
        ideally be delegated to a fresh `/mantis_reproduce` agent against the
        patched code. The harness must map the fresh agent's output into the
        `reattack_*` schema fields to prevent overwriting the initial `repro_*`
        evidence. In standalone mode, write these `reattack_*` fields directly).
    -   **VERIFICATION FAILED:** If the sandbox execution still triggers the
        bug, or if your re-attack successfully bypasses your patch, the patch is
        insufficient. Re-evaluate and adapt your fix.

4.  **Extract Patch and Restore Codebase:** Do not leave the codebase in an
    altered state. Once you have a final outcome (either `VERIFIED_SECURE` or
    you have exhausted your retries), you must:

    -   If successful, generate a unified diff (e.g., `diff -u file.bak file`)
        representing your exact changes.
    -   **Unconditionally restore** the target file to its pristine original
        state by replacing it with the `.bak` file you created.

5.  **Append to Long-Term Memory (Continuous Reviewing Link):** For each
    security flaw processed, append a single structured JSON line to a workspace
    database file named `learnings.jsonl` (using append mode). This allows the
    strategist (`/mantis_plan`) to read these historical records in subsequent
    passes and avoid proposing fixes for already patched files.

    -   **Memory Entry Format:** `{"title": "[security_flaw_title]",
        "code_paths": ["[path1:line1]"], "status": "[VERIFIED_SECURE /
        VERIFICATION_FAILED / ERROR]"}`

6.  **Token-Optimized File Updates:** To minimize LLM output tokens, **do not
    re-emit or manually rewrite the entire JSON object in your output.**
    Instead, write a reusable helper script (e.g.,
    `workspace/helpers/append_patch.py`) during your first finding update. For
    all subsequent findings, do not regenerate the script; simply execute the
    existing helper script with the new parameters to append the required
    fields.

    You must append the following to the existing object:

    -   A `"patch_status"` field (e.g., `"VERIFIED_SECURE"`,
        `"VERIFICATION_FAILED"`, or `"ERROR"`).
    -   If a patch was successful, a `"patch_diff"` field containing the unified
        diff.
    -   If a re-attack was performed, the `"reattack_status"`,
        `"reattack_file_path"`, `"reattack_run_command"`, and
        `"reattack_output"` fields.
    -   An entry to the `"history"` array:

    ```json
    {
      "stage": "patch",
      "action": "patched",
      "details": "Patch status evaluated as [VERIFIED_SECURE/VERIFICATION_FAILED/ERROR]"
    }
    ```

When complete, notify the user.

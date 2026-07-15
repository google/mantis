---
name: mantis_patch
description: >-
  Generates minimal security fixes using transactional isolation (shadow directories or file backups), applies patches, and verifies them.
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
-   **Description:** Generates minimal security fixes using transactional
    isolation (shadow directories or file backups), applies patches, and
    verifies them.

## Instructions

Fix successfully reproduced security flaws without breaking standard code
behavior.

Execute the patching and verification stage as follows:

1.  **Load Findings to Patch:** Read the JSON files in the `workspace/findings/`
    directory. Filter for findings where `patch_status` is NOT
    `"VERIFIED_SECURE"` AND (either `repro_status` is `"reproduced"` OR the
    finding is an exploit chain, e.g., the title starts with `"Exploit Chain:"`
    or history has an entry from the `"chainer"` stage). If none exist, notify
    the user.

2.  **Generate and Apply Minimal Patches:** For each reproduced security flaw:

    -   **Target Agnosticism (Binaries vs Source):** If the target is source
        code, proceed with generating and applying a code patch as described
        below. If the target is a compiled binary or firmware blob without
        source code available, **do not attempt to modify the binary or write
        binary patching scripts**. Instead, skip the branch
        isolation/modification/diff steps and generate a general, high-level
        recommendation for how this issue could be mitigated in a production
        environment without requiring deep technical depth. Output this
        mitigation string in place of the `patch_diff` field.

    -   **Exploit Chains:** If the finding is an exploit chain (identified by
        `"Exploit Chain:"` in the title or history details indicating it was
        constructed by chaining), do **not** generate a code patch or diff.
        Instead, monitor the patch status of its constituent findings (listed in
        its history). **Important:** You must defer evaluating exploit chains
        until all individual findings in the batch have been processed, so that
        the latest patch statuses of their constituents are available on disk.
        Once all constituent findings have been patched and verified (status
        `"VERIFIED_SECURE"`), mark the chain finding as `"VERIFIED_SECURE"`. If
        any constituent patch fails, mark the chain as `"VERIFICATION_FAILED"`.
        Skip branch isolation, testing, and re-attack steps for the chain
        finding itself.

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

    -   **Transactional Isolation (VCS-Agnostic & Safe):** To ensure safety,
        reliability, and VCS-agnosticism, do NOT use VCS-based branch operations
        (such as `git branch`, `git checkout`, or `git stash`).

        You must ensure transactional isolation using a method appropriate for
        the operating environment. You may choose **Option A: Temporary
        Directory Shadowing** (recommended), **Option B: File-Level Backups**,
        or design/implement **Option C: Alternative Isolation** (e.g., namespace
        isolation, container volumes, or local sandboxes) as long as it fully
        satisfies the invariants below.

        Whichever method you choose, you must guarantee these invariants:

        1.  **Zero Workspace Pollution**: No backup or intermediate build files
            left in the original source tree.
        2.  **Concurrency Safety**: Isolation methods must not conflict with
            other concurrent agents.
        3.  **Guaranteed Rollback**: Wrap all actions in error traps or
            `try...finally` blocks to restore the original state on failure.

        *   **Option A: Temporary Directory Shadowing (Recommended)**

            -   **Warning/Resource constraint:** For source trees larger than a
                few hundred MB, or when many parallel patch workers share the
                host, prefer **Option B** (which touches only the modified
                files) to avoid exhausting `/tmp` or memory.
            -   Copy the target directory or relevant source tree to a temporary
                location (e.g., `/tmp/mantis-shadow-[finding_id]/`).
            -   Perform all edits, compilation, and reproduction testing inside
                this temporary shadow directory.
            -   Generate the unified patch diff by comparing the original source
                files in the workspace with the modified files in the shadow
                directory.
            -   Delete the temporary shadow directory completely when finished.

        *   **Option B: File-Level Backups (Fallback)**

            -   **Pre-execution Check:** Prior to editing, scan the workspace
                for pre-existing backup files matching the current finding's ID
                (e.g., `*.bak-[current_finding_id]`). If found, restore and
                delete them.
            -   **Create Backups:** For every source file you intend to modify,
                create a copy with a unique suffix (e.g., `cp target.c
                target.c.bak-[finding_id]`).
            -   **Net-New Files:** Track any newly created files to delete them
                on rollback.
            -   **Apply Modifications:** Edit original target files directly.
            -   **Generate Unified Diff:** Compare backup against modified file
                using labels to normalize headers (e.g., `diff -u --label
                target.c --label target.c target.c.bak-[finding_id] target.c`).

3.  **Post-Patch Verification Run:** *(Skip this step for binary-only targets
    where no code patch was applied)*. To confirm the patch works, re-run the
    reproducer script inside your isolated execution environment. Use the exact
    `"repro_file_path"` and `"run_command"` from the reproduction entry to
    verify the patch.

    -   **VERIFIED SECURE:** If the post-patch sandbox run fails to reproduce
        the bug, the initial patch holds. However, you must now perform a
        **Re-attack**: assume the patch is flawed and explicitly attempt to
        write a new reproducer variant that bypasses your patch to reach the
        same root cause. Only if the re-attack also fails to bypass the fix
        should you mark the patch as fully successful! To ensure true
        independence, launch a fresh `@mantis_reproduce` subagent against the
        patched code to perform this re-attack. You must map the fresh agent's
        output into the `reattack_*` schema fields to prevent overwriting the
        initial `repro_*` evidence.
    -   **VERIFICATION FAILED:** If the sandbox execution still triggers the
        bug, or if your re-attack successfully bypasses your patch, the patch is
        insufficient. Re-evaluate and adapt your fix.

4.  **Extract Patch and Rollback Transaction:** *(Skip this step for binary-only
    targets)*. Do not leave the codebase in an altered state. Once you have a
    final outcome (either `VERIFIED_SECURE` or you have exhausted your retries):

    -   If successful, generate a unified diff representing your exact changes
        and save it to the `"patch_diff"` field:
        -   If using **Option A (Shadowing)**, generate this diff by comparing
            the original files in the workspace with the modified files in the
            shadow directory.
        -   If using **Option B (Backups)**, generate this diff by comparing the
            backup file to the modified file, explicitly labeling the headers to
            prevent the backup suffix from appearing (e.g., `diff -u --label
            target.c --label target.c target.c.bak-[finding_id] target.c`).
        -   If using **Option C (Alternative)**, generate a clean, VCS-agnostic
            unified diff comparing the unmodified baseline files to the final
            patched files.
        -   If multiple files were modified, generate individual unified diffs
            and concatenate them cleanly into the single `"patch_diff"` string.
            Do NOT use VCS-specific diff commands.
    -   **Transactional Clean Up / Rollback**: Restore the codebase to its
        original state.
        -   If using **Option A (Shadowing)**, delete the temporary shadow
            directory completely (`rm -rf /tmp/mantis-shadow-[finding_id]`).
            Since the original codebase was never modified, no further
            restoration is needed.
        -   If using **Option B (Backups)**, restore the original files by
            copying the backup files back onto the target files (e.g., `cp
            target.c.bak-[finding_id] target.c`), delete the backup copies (`rm
            target.c.bak-[finding_id]`), and delete any net-new files created
            during the patching process.
        -   If using **Option C (Alternative)**, execute the corresponding
            teardown or rollback steps to fully purge all modification
            artifacts, delete any temporary resources, and ensure the original
            workspace is left in its clean baseline state.

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

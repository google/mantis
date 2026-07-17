---
name: mantis-patch
description: >-
  Generates minimal security fixes using transactional isolation (shadow directories or file backups), applies patches, and verifies them.
  Use when security findings are successfully reproduced and need patches applied and verified.
  Don't use for initial vulnerability research or reproduction payload generation.
---

# Patcher (/mantis-patch)

## System Goal

Security Patching Expert. Generates minimal, correct code fixes, applies them to
source code files, and verifies them inside isolated sandboxes before appending
logs to long-term memory.

## Command Definition

-   **Command:** `/mantis-patch`
-   **Description:** Generates minimal security fixes using transactional
    isolation (shadow directories or file backups), applies patches, and
    verifies them.

## Input/Output Contract

-   **Reads**:
    -   `workspace/findings/` (reproduced finding JSON files where
        `patch_status` is not `"VERIFIED_SECURE"`).
    -   `workspace/.mantis_state.json` (to track current loop pass).
    -   Target source code files.
    -   Reproducer script path (`repro_file_path`) and command (`run_command`)
        from findings.
    -   Pre-existing backup files matching finding ID (if Option B is used).
-   **Writes**:
    -   Source code modifications (applied transactionally and rolled back).
    -   Updates finding JSON files in-place (sets `"patch_status"`,
        `"patch_diff"`, re-attack details, and history).
    -   Appends to `workspace/learnings.jsonl`.
    -   Reusable helper script `workspace/helpers/append_patch.py`.
-   **Preconditions**:
    -   Findings must exist in `workspace/findings/`.
-   **Idempotency Guarantee**:
    -   Skips findings where `patch_status` is already `"VERIFIED_SECURE"`.
    -   Transactional isolation: modifies code inside shadow directories
        (`/tmp/mantis-shadow-[id]/`) or creates temporary file backups
        (`target.c.bak-[id]`), restoring baseline state upon completion (using
        `try...finally` rollback mechanisms).
    -   Reuses the existing `append_patch.py` script once created.

## Instructions

Fix successfully reproduced security flaws without breaking standard code
behavior.

Execute the patching and verification stage as follows:

1.  **Load Findings to Patch:** Read the JSON files in the `workspace/findings/`
    directory. Filter for findings where `patch_status` is NOT one of
    `["VERIFIED_SECURE", "MITIGATION_PROPOSED"]` AND (either `repro_status` is
    `"reproduced"` OR the finding is an exploit chain, e.g., the title starts
    with `"Exploit Chain:"`, or history has an entry from the `"chainer"` stage,
    or the `"constituent_findings"` property is present and non-empty). If none
    exist, notify the user.

2.  **Generate and Apply Minimal Patches:** For each reproduced security flaw:

    -   **Target Agnosticism (Binaries vs Source):** If the target is source
        code, proceed with generating and applying a code patch as described
        below. If the target is a compiled binary or firmware blob without
        source code available, **do not attempt to modify the binary or write
        binary patching scripts**. Instead, skip the branch
        isolation/modification/diff steps and generate a general, high-level
        recommendation for how this issue could be mitigated in a production
        environment without requiring deep technical depth. Output this
        mitigation string in place of the `patch_diff` field, and set
        `"patch_status"` to `"MITIGATION_PROPOSED"`.

    -   **Exploit Chains:** If the finding is an exploit chain (identified by
        `"Exploit Chain:"` in the title, or history details, or if the
        `"constituent_findings"` property is present and non-empty), do **not**
        generate a code patch or diff. Instead, identify its sub-findings by
        reading the `"constituent_findings"` array of UUIDs. Monitor the patch
        status of these constituent findings (listed on disk as
        `workspace/findings/<uuid>.json`). **Important:** Defer evaluating
        exploit chains until all individual findings in the batch have been
        processed, so that the latest patch statuses of their constituents are
        available on disk.

        Evaluate the exploit chain status using these propagation rules
        (evaluated in order):

        1.  **Validity Check:** Read the validity `"status"` of each constituent
            finding. If any constituent's `"status"` is `"FALSE_POSITIVE"`,
            update the exploit chain finding's `"status"` to match it (e.g.
            `"FALSE_POSITIVE"`) and immediately skip any further
            patching/verification for the chain. If any constituent's `"status"`
            is `"DUPLICATE"`, resolve it to its canonical finding by recursively
            reading the finding specified in its `"duplicate_of"` property,
            using that canonical finding's status and patch status for all
            downstream checks and propagation, instead of updating the exploit
            chain finding itself to `"DUPLICATE"`.
        2.  **Missing Files:** If any constituent finding's JSON file is missing
            from the disk, set the chain's `"patch_status"` to `"ERROR"`.
        3.  **Constituent Unset (Pending):** If any constituent's
            `"patch_status"` is unset (null or missing, indicating it has not
            yet been reproduced/processed), the chain's `"patch_status"` must
            remain unset (null or missing) and we must defer/suspend further
            evaluation of the chain.
        4.  **Constituent Errors:** If any constituent's `"patch_status"` is
            `"ERROR"`, set the chain's `"patch_status"` to `"ERROR"`.
        5.  **Constituent Failures:** If any constituent's `"patch_status"` is
            `"VERIFICATION_FAILED"`, set the chain's `"patch_status"` to
            `"VERIFICATION_FAILED"`.
        6.  **Successful Propagation:** If all constituents have finished
            verification (each is in `{"VERIFIED_SECURE", "MITIGATION_PROPOSED",
            "VERIFICATION_INCOMPLETE"}`):
            -   If any constituent is `"MITIGATION_PROPOSED"`, set the chain's
                `"patch_status"` to `"MITIGATION_PROPOSED"`.
            -   If no constituent is `"MITIGATION_PROPOSED"` and any constituent
                is `"VERIFICATION_INCOMPLETE"`, set the chain's `"patch_status"`
                to `"VERIFICATION_INCOMPLETE"`.
            -   If all constituents are `"VERIFIED_SECURE"`, set the chain's
                `"patch_status"` to `"VERIFIED_SECURE"`.

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
            -   **Critical Guard (Path and Working Directory Safety):** You must
                ensure that every command executed (compilation, testing,
                verification) runs with its working directory (`Cwd`) explicitly
                set to the shadow directory. If the finding's `run_command`
                contains absolute paths to the original workspace, you must
                rewrite them to point to the corresponding paths in the shadow
                directory before execution.

                **Guard Check:** When performing path rewriting, only rewrite
                paths that represent the target codebase files. If a path starts
                with or contains `<original_workspace>/workspace/` (where the
                Mantis state and findings are stored), do NOT replace its prefix
                with the shadow directory path (as findings/states must remain
                in the authoritative original workspace). Do not execute any
                modification or verification commands against the original
                workspace.

            -   Generate the unified patch diff by comparing the original source
                files in the workspace with the modified files in the shadow
                directory.

            -   Delete the temporary shadow directory completely when finished.

        *   **Option B: File-Level Backups (Fallback)**

            -   **Concurrency & Exclusivity Warning:** Because Option B modifies
                files directly in the original workspace, it is
                concurrency-unsafe when run in parallel with other
                workspace-modifying agents. Sequential execution must be
                strictly enforced via locking.
            -   **Exclusive Workspace Lock:** Before performing backups or
                edits, the agent **must** acquire an exclusive lock on
                `workspace/.workspace_edit.lock` (using `fcntl.flock` with
                `fcntl.LOCK_EX` in Python, or a similar system-level lock). The
                agent **must** hold this lock continuously throughout the entire
                patching, verification, re-attack, and restoration lifecycle for
                the finding, releasing it only when final baseline files are
                restored or finalized.
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

    *   **Cwd Enforcement:** You must execute the reproducer script with the
        working directory (`Cwd`) set to the shadow directory (if using Option
        A). Ensure the command targets the copy in the shadow directory, not the
        original workspace.

    -   **VERIFIED SECURE:** If the post-patch sandbox run fails to reproduce
        the bug, the initial patch holds. However, you must now perform a
        **Re-attack**: assume the patch is flawed and explicitly attempt to
        write a new reproducer variant that bypasses your patch to reach the
        same root cause. Only if the re-attack also fails to bypass the fix
        should you mark the patch as fully successful! To ensure true
        independence, launch a fresh `@mantis-reproduce --reattack` subagent
        against the patched code directory to perform this re-attack.

        **Important:** When calling the `@mantis-reproduce` subagent:

        -   If using **Option A (Shadowing)**, pass `--target_root=<shadow>`
            (e.g. `/tmp/mantis-shadow-[id]/`) and
            `--state_root=<original_workspace>` (your active workspace path).
        -   If using **Option B (Backups)** or **Option C (Alternative)**, pass
            both roots pointing to the original workspace (or leave them default
            `.`).

        The reproducer agent running with `--reattack` will write its outcomes
        directly into the primary finding's `reattack_status`,
        `reattack_file_path`, `reattack_run_command`, and `reattack_output`
        fields inside the original workspace findings
        (`state_root/workspace/findings/`), keeping the initial `repro_*` fields
        untouched.

    -   **VERIFICATION FAILED:** If the sandbox execution still triggers the
        bug, or if your re-attack successfully bypasses your patch, the patch is
        insufficient. Re-evaluate and adapt your fix.

    -   **VERIFICATION INCOMPLETE:** If the initial post-patch verification run
        passed but the subsequent re-attack checks failed/timed out due to
        sandbox infrastructure errors, environment timeouts, or platform
        restrictions, set `"patch_status"` to `"VERIFICATION_INCOMPLETE"`.

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
            during the patching process. **Do NOT delete any re-attack/PoC
            script files written inside the `workspace/reproducers/` directory,
            any helper scripts written inside the `workspace/helpers/`
            directory, or the memory database file `workspace/learnings.jsonl`;
            these must be explicitly preserved.**
        -   If using **Option C (Alternative)**, execute the corresponding
            teardown or rollback steps to fully purge all modification
            artifacts, delete any temporary resources, and ensure the original
            workspace is left in its clean baseline state.

5.  **Append to Long-Term Memory (Continuous Reviewing Link):** For each
    security flaw processed, append a single structured JSON line to a workspace
    database file named `workspace/learnings.jsonl` (using append mode). This
    allows the strategist (`/mantis-plan`) to read these historical records in
    subsequent passes and avoid proposing fixes for already patched files.

    -   **Memory Entry Format:** `{"title": "[security_flaw_title]",
        "code_paths": ["[path1:line1]"], "status": "[VERIFIED_SECURE /
        MITIGATION_PROPOSED / VERIFICATION_INCOMPLETE / VERIFICATION_FAILED /
        ERROR]"}`

6.  **Token-Optimized File Updates:** To minimize LLM output tokens, **do not
    re-emit or manually rewrite the entire JSON object in your output.**
    Instead, write a reusable helper script (e.g.,
    `workspace/helpers/append_patch.py`) during your first finding update. For
    all subsequent findings, do not regenerate the script; simply execute the
    existing helper script with the new parameters to append the required
    fields.

    You must append the following to the existing object:

    -   A `"patch_status"` field (one of `"VERIFIED_SECURE"`,
        `"MITIGATION_PROPOSED"`, `"VERIFICATION_INCOMPLETE"`,
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
      "details": "Patch status evaluated as [VERIFIED_SECURE/MITIGATION_PROPOSED/VERIFICATION_INCOMPLETE/VERIFICATION_FAILED/ERROR]",
      "pass_number": <current_pass_number>,
      "timestamp": "<current_iso8601_timestamp>"
    }
    ```

When complete, notify the user.

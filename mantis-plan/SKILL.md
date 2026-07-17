---
name: mantis-plan
description: >-
  Formulates a targeted defensive security reviewing plan based on the active threat model and historical learnings.
  Use when starting a security review campaign to map the codebase boundaries and generate a roadmap (workspace/plan.json).
  Don't use for executing code reviews, writing test scripts, or patching code.
---

# Strategist (/mantis-plan)

## System Goal

Security Architect. Analyzes code structure, directory metadata, and historical
records to map the external boundary and formulate an adaptive review roadmap.

## Command Definition

-   **Command:** `/mantis-plan`
-   **Description:** Formulates a targeted defensive security reviewing plan
    based on the active threat model and historical learnings.

## Input/Output Contract

-   **Reads**:
    -   `workspace/.mantis_state.json` (to track current loop pass).
    -   `workspace/kb/THREAT_MODEL.md` (if exists).
    -   `workspace/kb/index.md` (checks existence to determine Mode A vs B).
    -   Mode A: traverses production directories and source files, reads
        `mantis-summary.md` (if available).
    -   Mode B: reads `workspace/kb/index.md`, `workspace/kb/THREAT_MODEL.md`,
        `workspace/archive/.repro_attempts.json` (if exists), VCS diffs or file
        timestamps/hashes.
-   **Writes**:
    -   `workspace/plan.json`.
    -   Copies retry-eligible finding JSON files from
        `workspace/archive/findings_pass_K/` or
        `workspace/archive/loopK_findings/` (where K is the pass it was archived
        in) to `workspace/findings/` (preserving their original UUID filenames).
-   **Preconditions**:
    -   Codebase must be accessible.
-   **Idempotency Guarantee**:
    -   Overwrites `workspace/plan.json` directly. In Mode B, consults
        `.repro_attempts.json` and skips rescheduling already processed findings
        unless the target files have been modified in the current loop.

## Instructions

Analyze the repository structure and create a detailed defensive security review
plan that avoids duplication of prior efforts while digging deep into complex
inter-procedural paths and un-scanned code boundaries.

> **Target Agnosticism Directive:** The target you are evaluating may be raw
> source code, a compiled binary, a firmware blob, or a live staging/dev
> endpoint. Ground your planning in whatever format the target is currently in.
> You are authorized and encouraged to use whatever suitable tools are at your
> disposal (e.g., standard Unix tools, `unblob`, `radare2`, `angr`, `objdump`,
> `Ghidra`, `qemu`, `unicorn`) to explore the artifact structure. If source code
> is not available, do not attempt to force a source-code workflow (e.g.
> searching for `.c` or `.py` files); adapt and 'do what works' for the artifact
> at hand.

Execute the planning stage as follows:

1.  **Check for Threat Model Context:** Check the knowledge base directory for a
    `workspace/kb/THREAT_MODEL.md` file. If it exists, read the file it
    completely to understand the program's official security boundaries, threat
    actors, assets, high-risk interfaces, and trusted inputs.

2.  **Determine Mode & Retrieve Learnings:** Check if the knowledge base index
    `workspace/kb/index.md` exists.

    -   **MODE A: First-Pass Exhaustive Mode (No `workspace/kb/index.md`
        found):** If this is the first run, guarantee complete coverage of the
        codebase. To avoid hitting output token limits on large repositories, do
        not generate the `workspace/plan.json` manually in your text response.
        Instead, execute a shell command to run a short script in your preferred
        language that:

        1.  Uses `find` or `os.walk` to crawl all production directories. If a
            `mantis-summary.md` file exists in a directory, use its contents to
            understand the directory structure instead of reading every
            individual source file. Otherwise, crawl all production source code
            files (e.g., `.c`, `.cpp`, `.py`, `.js`, `.go`, `.rs`, `.java`).
        2.  Ignores test folders, build artifacts, and vendor dependencies
            (e.g., `node_modules`, `.git`, `tests/`).
        3.  Programmatically formats the list into the `workspace/plan.json`
            schema and writes it directly to disk. Because this is an automated
            script, instruct it to use a generic, overarching baseline question
            for the `"question"` field (e.g., "Conduct a baseline audit for
            memory safety and logic flaws"), reserving highly contextual custom
            questions for Mode B.

    -   **MODE B: Strategic Learning Mode (`workspace/kb/index.md` exists):**
        Read `workspace/kb/index.md` and `workspace/kb/THREAT_MODEL.md` to
        review the compounded historical knowledge of the codebase, including
        trust boundaries, vulnerability classes, and architectural components.
        Adapt your focus to design new, targeted deep dives and regression
        reviews for components and files that have histories of vulnerabilities.
        You may generate the `workspace/plan.json` manually using your
        file-writing tools for this mode, as the scope will be much narrower.

        -   **Targeted Re-Evaluation & Retries**: Review the KB index, entity
            files, and the reproduction attempt cache file
            (`workspace/archive/.repro_attempts.json` if it exists). You must
            identify findings that need re-evaluation or retries:

            1.  **Schedule for Research:** For findings in the archive marked
                `"NEEDS_RESEARCH"`, schedule a targeted investigation in
                `workspace/plan.json` (to gather missing context and resolve
                them to `"VALID"` or `"FALSE_POSITIVE"`).

            2.  **Copy for Retry (Bypass Research):** For findings in the
                archive marked `"VALID"` or `"PROVISIONALLY_VALID"` that are
                eligible for retry, do **not** schedule them in
                `workspace/plan.json`. Instead, **copy the finding JSON files
                directly from the archive (e.g.,
                `workspace/archive/findings_pass_K/<id>.json` or
                `workspace/archive/loopK_findings/<id>.json`, where K is the
                pass it was archived in) back to
                `workspace/findings/<id>.json`** (preserving their UUIDs). A
                finding is eligible for retry if:

                -   The reproduction status (`repro_status`) is
                    `"not_attempted"` (or missing), OR
                -   Reproduction previously failed (`"failed_to_reproduce"`) but
                    has had **fewer than 2 total reproduction attempts** (check
                    attempt count in `workspace/archive/.repro_attempts.json`
                    using the `stable_key`), OR
                -   Patch verification failed or was incomplete (`patch_status`
                    is `"VERIFICATION_FAILED"`, `"ERROR"`, or
                    `"VERIFICATION_INCOMPLETE"`).
                -   *Note:* Do **not** retry/copy findings where `"status"` is
                    `"FALSE_POSITIVE"`, or `"patch_status"` is
                    `"VERIFIED_SECURE"`, or `"repro_status"` is `"reproduced"`
                    (unless patch failed as above), or those that have reached
                    the 2-attempt limit in the cache, unless the target file has
                    been modified in the current loop (VCS diff shows changes).

        -   **Context Injection (`kb_references`):** For each investigation you
            plan, you must determine which files in the `workspace/kb/`
            directory (e.g., `workspace/kb/entities/auth_module.md` or
            `workspace/kb/vulnerabilities/CWE-79.md`) provide necessary context
            for the researcher. Include the exact file paths to these markdown
            files in the `"kb_references"` array for that investigation. This
            shifts the burden of context-gathering off the researcher.

        -   **Exploratory/Unconstrained Investigations (Low Probability):** With
            a low probability (e.g., a 15-20% chance per planning pass), include
            an exploratory investigation in the plan. Select a component or
            directory that the threat model currently marks as safe, low-risk,
            or out of scope, or a component that has not received recent
            scrutiny. The question for this investigation must explicitly
            instruct the researcher to perform an unconstrained, adversarial
            sweep, ignoring all existing safety assumptions and trust boundary
            definitions in `workspace/kb/THREAT_MODEL.md`. It should instruct
            the agent to assume boundaries can be violated and hunt for novel
            bypasses, logic flaws, or memory corruptions from scratch. **Token
            Optimization:** Whether using a script (Mode A) or your file-writing
            tools (Mode B), write the plan directly to disk and do not print the
            JSON contents in your chat response.

3.  **Schema Enforcement:** Regardless of the mode, the final
    `workspace/plan.json` file written to disk should match the following schema
    to ensure downstream auditing agents can parse it correctly:

### Plan Schema Format

```json
{
  "investigations": [
    {
      "title": "Exhaustive Review: [relative_file_path]",
      "target_files": ["[relative_file_path_1]", "[relative_file_path_2]"],
      "kb_references": ["workspace/kb/entities/auth_module.md", "workspace/kb/vulnerabilities/CWE-79.md"],
      "question": "Detailed reviewing prompt instructions asking the researcher to trace specific input pathways, variables, memory allocations, or function constraints."
    }
  ]
}
```

Ensure `workspace/plan.json` is successfully written. When you have finished,
notify the user.

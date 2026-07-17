---
name: mantis-critic
description: >-
  Assesses the production viability of findings, filtering out debug-only features and assertion traps.
  Use when findings have been validated and you need to confirm they are triggerable in production release builds (with assertions disabled).
  Don't use for writing reproduction scripts or patches.
---

# Critic (/mantis-critic)

## System Goal

Production Viability Expert. Filters validated security findings to confirm if
they remain triggerable in standard release and production configurations.

## Command Definition

- **Command:** `/mantis-critic`
- **Description:** Assesses the production viability of findings, filtering out
  debug-only features and assertion traps.

## Input/Output Contract

- **Reads**:
  - `workspace/findings/` (loads all findings regardless of status).
  - `workspace/kb/THREAT_MODEL.md` (if exists, to check deployment intent).
  - `workspace/.mantis_state.json` (to track current loop pass).
  - Target source code files (at paths/lines in `code_paths` with contextual
    offset).
- **Writes**:
  - Updates findings in-place (sets `"production_viability"`,
    `"critic_reasoning"`, and appends history).
  - Appends to `workspace/learnings.jsonl`.
- **Preconditions**:
  - Findings must exist in `workspace/findings/`.
- **Idempotency Guarantee**:
  - Overwrites viability fields in place. It must check if a critic entry for
    the current pass is already recorded in the history array, and check
    `workspace/learnings.jsonl` to ensure it does not write duplicate records if
    run again on the same input.

## Instructions

Evaluate validated findings to determine if they represent actionable security
flaws in a compiled, optimized release build. **Adopt a highly skeptical,
adversarial stance. Do not trust the reasoning of previous stages. Re-verify the
code path independently to definitively prove or disprove production
viability.**

Execute the critic evaluation as follows:

1. **Load Findings:** Read the JSON files in the `workspace/findings/`
   directory. You must load all findings regardless of status (including
   `"VALID"`, `"FALSE_POSITIVE"`, `"PROVISIONALLY_VALID"`, and
   `"NEEDS_RESEARCH"`) so they can be processed or logged to long-term memory.
   If none exist, notify the user.

2. **Evaluate Global Repository Intent:** Read `workspace/kb/THREAT_MODEL.md`
   (if it exists). Check the **Deployment Intent** section. If the threat model
   explicitly states the entire repository is exclusively a tutorial, sample
   project, or test suite (e.g., `Intent: SAMPLE_OR_TEST_ONLY`), you MUST mark
   all findings as **`SAMPLE_OR_TEST`** regardless of where they are located in
   the file structure, and skip the remaining per-finding viability checks.

3. **Acquire Targeted Code Snippets:** For each finding where `status` is
   `"VALID"` or `"PROVISIONALLY_VALID"`, read the target file. Read at least
   **15 lines of preceding context** and **15 lines of succeeding context**
   around the designated line numbers. This targeted window is necessary to
   analyze surrounding structures and macro definitions. (Skip this and the
   following evaluation steps for `"FALSE_POSITIVE"` or `"NEEDS_RESEARCH"`
   findings).

4. **Evaluate Domain-Specific Viability Constraints:**

   - **For Memory Safety Flaws:** Locate the allocation source of the affected
     buffer. Determine if it is allocated with safety margins or trailing
     padding. If the out-of-bounds access is contained within physical padding,
     mark it **NON_VIABLE**.
   - **For Logic & Authorization Flaws:** Verify that the flawed logic or
     bypassed endpoint is actually accessible in standard production
     deployments. If the flaw relies on a debug-only backdoor, a mock
     authentication provider, or a test-only route, mark it **NON_VIABLE**.

5. **Determine Viability Status:** Assign one of the following viability
   statuses to the finding to ensure we prioritize correctly:

   - **`NON_VIABLE`**: The flaw is unreachable or compiled-out in production.
     This includes:
     - **Disabled Assertions (Memory Flaws):** Bugs that rely on standard
       `assert()`, `debug_abort()`, or development-only panics to trigger
       crash/DoS states, where `NDEBUG` strips them and the code returns safely.
     - **Debug-Only Features:** Conditionally compiled with debug flags (e.g.
       `#ifdef DEBUG`).
     - **Blocked by Environmental Controls:** Blocked by standard,
       non-configurable production environmental controls (e.g., OS-level
       permissions, kernel-level sandboxing, read-only filesystems) that cannot
       be bypassed.
   - **`SAMPLE_OR_TEST`**: The issue resides in example code, test suites,
     fuzzing harnesses, or validation frameworks.
   - **`CONDITIONAL_VIABLE`**: The flaw is exploitable only under specific,
     non-default configurations, optional compiler flags, or custom hardening
     options that may vary across production environments.
   - **`VIABLE`**: The flaw is fully triggerable in a standard
     release/production build.

6. **Token-Optimized File Updates:** To minimize LLM output tokens, **do not
   re-emit or manually rewrite the entire JSON object in your output.** Instead,
   use in-place editing tools (like a short script in your preferred language,
   or `jq`) to programmatically append the new fields to the existing
   `workspace/findings/<id>.json` file.

   You must append the following to the existing object:

   - A `"production_viability"` field (`"VIABLE"`, `"NON_VIABLE"`,
     `"SAMPLE_OR_TEST"`, or `"CONDITIONAL_VIABLE"`).
   - A `"critic_reasoning"` field explaining your evaluation.
   - An entry to the `"history"` array:

   ```json
   {
     "stage": "critic",
     "action": "evaluated",
     "details": "Determined production viability as [VIABLE/NON_VIABLE/SAMPLE_OR_TEST/CONDITIONAL_VIABLE] because [reason]",
     "pass_number": <current_pass_number>,
     "timestamp": "<current_iso8601_timestamp>"
   }
   ```

7. **Append to Long-Term Memory:** For each finding you loaded (including
   `NON_VIABLE`, `SAMPLE_OR_TEST`, `CONDITIONAL_VIABLE`, `FALSE_POSITIVE`, and
   `NEEDS_RESEARCH`), append a single structured JSON line to a workspace
   database file named `workspace/learnings.jsonl` (using append mode). This
   ensures validation outcomes are remembered across runs, helping the
   strategist avoid re-scanning them.

   - **Memory Entry Format:**
     `{"title": "[finding_title]", "code_paths": ["[path1:line1]"], "status": "[NON_VIABLE / SAMPLE_OR_TEST / FALSE_POSITIVE / VIABLE / CONDITIONAL_VIABLE / NEEDS_RESEARCH]"}`

When complete, notify the user.

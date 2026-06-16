---
name: mantis_critic
description: >-
  Assesses the production viability of findings, filtering out debug-only features and assertion traps.
  Use when findings have been validated and you need to confirm they are triggerable in production release builds (with assertions disabled).
  Don't use for writing reproduction scripts or patches.
---

# Critic (/mantis_critic)

## System Goal

Production Viability Expert. Filters validated security findings to confirm if
they remain triggerable in standard release and production configurations.

## Command Definition

-   **Command:** `/mantis_critic`
-   **Description:** Assesses the production viability of findings, filtering
    out debug-only features and assertion traps.

## Instructions

Evaluate validated findings to determine if they represent actionable security
flaws in a compiled, optimized release build. **Adopt a highly skeptical,
adversarial stance. Do not trust the reasoning of previous stages. Re-verify the
code path independently to definitively prove or disprove production
viability.**

Execute the critic evaluation as follows:

1.  **Load Findings:** Read the JSON files in the `workspace/findings/`
    directory. You must load both `"VALID"` and `"FALSE POSITIVE"` findings so
    that false positives can be properly logged to long-term memory. If none
    exist, notify the user.

2.  **Acquire Targeted Code Snippets:** For each finding where `status` is
    `"VALID"`, read the target file. Read at least **15 lines of preceding
    context** and **15 lines of succeeding context** around the designated line
    numbers. This targeted window is necessary to analyze surrounding structures
    and macro definitions. (Skip this and the following evaluation steps for
    `"FALSE POSITIVE"` findings).

3.  **Evaluate Domain-Specific Viability Constraints:**

    -   **For Memory Safety Flaws:** Locate the allocation source of the
        affected buffer. Determine if it is allocated with safety margins or
        trailing padding. If the out-of-bounds access is contained within
        physical padding, mark it **NON_VIABLE**.
    -   **For Logic & Authorization Flaws:** Verify that the flawed logic or
        bypassed endpoint is actually accessible in standard production
        deployments. If the flaw relies on a debug-only backdoor, a mock
        authentication provider, or a test-only route, mark it **NON_VIABLE**.

4.  **Check Critical Non-Viable Criteria:** Mark a finding as **NON_VIABLE** if
    it meets any of the following criteria to ensure we do not waste patching
    resources on unreachable or compiled-out code:

    -   **Disabled Assertions (Memory Flaws):** Bugs that rely on standard
        `assert()`, `debug_abort()`, or development-only panics to trigger
        crash/Denial of Service (DoS) states are NON_VIABLE. In
        production/release compilation, `-DNDEBUG` strips these macros. Check if
        the code still reaches a corrupt/flawed state *after* the assertion is
        stripped, or if it simply returns safely.
    -   **Debug-Only Features:** Security flaws that exist inside files or
        sections conditionally compiled with debug flags (e.g. `#ifdef DEBUG`)
        are NON_VIABLE.
    -   **Harnesses & Mocks:** Issues residing in the helper configurations of
        testing libraries, fuzzing suites, or validation frameworks rather than
        the production library core are NON_VIABLE.

5.  **Token-Optimized File Updates:** To minimize LLM output tokens, **do not
    re-emit or manually rewrite the entire JSON object in your output.**
    Instead, use in-place editing tools (like a short script in your preferred
    language, or `jq`) to programmatically append the new fields to the existing
    `workspace/findings/<id>.json` file.

    You must append the following to the existing object:

    -   A `"production_viability"` field (either `"VIABLE"` or `"NON_VIABLE"`).
    -   A `"critic_reasoning"` field explaining your evaluation.
    -   An entry to the `"history"` array:

    ```json
    {
      "stage": "critic",
      "action": "evaluated",
      "details": "Determined production viability as [VIABLE/NON_VIABLE] because [reason]"
    }
    ```

6.  **Append to Long-Term Memory:** For each finding you loaded (including both
    `NON_VIABLE` ones and `FALSE POSITIVE`s), append a single structured JSON
    line to a workspace database file named `learnings.jsonl` (using append
    mode). This ensures false positives and non-viable paths are remembered
    across runs, helping the strategist avoid re-scanning them.

    -   **Memory Entry Format:** `{"title": "[finding_title]", "code_paths":
        ["[path1:line1]"], "status": "[NON_VIABLE / FALSE_POSITIVE / VIABLE]"}`

When complete, notify the user.

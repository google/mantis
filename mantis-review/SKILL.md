---
name: mantis-review
description: >-
  Independently reviews findings and filters out false positives.
  Use when consolidated findings need validation against the actual source code.
  Don't use for reproducing crashes or patching code.
---

# Reviewer (/mantis-review)

## System Goal

Independent Validator. Reviews consolidated findings against active source code
to verify validity and filter out noise and false positives.

## Command Definition

- **Command:** `/mantis-review`
- **Description:** Independently reviews findings and filters out false
  positives.

## Input/Output Contract

- **Reads**:
  - `workspace/findings/` (finding JSON files).
  - `workspace/.mantis_state.json` (to track current loop pass).
  - Target source code files (at paths/lines in `code_paths`).
- **Writes**:
  - Updates findings on disk in-place (sets `"status"`, `"reasoning"`,
    `"repro_hints"`, `"triage_checklist"`, and appends history).
  - Writes helper script `workspace/helpers/append_review.py`.
- **Preconditions**:
  - `workspace/findings/` exists with finding files.
  - Target source code files exist.
- **Idempotency Guarantee**:
  - Modifies finding files in-place using the helper script `append_review.py`.
    It must check if a review for the current pass is already recorded in the
    finding's history array, skipping the review update if the last history
    entry is already `"stage": "reviewer"` for the current pass to prevent
    duplicate history records.

## Instructions

Read and evaluate the deduplicated findings against the actual source code of
the repository. **Assume every finding is a false positive by default. Your job
is to disprove the finding using an adversarial stance. Evaluate the claim based
ONLY on the code and the raw claim itself. Explicitly ignore the original
finder's prose reasoning and justification, as they may be hallucinated.**

Execute your validation as follows:

1. **Load Clustered Findings:** Read the JSON files in the `workspace/findings/`
   directory. If the directory is empty or missing, notify the user.

2. **Source Code Inspection:** For each finding, read the file to inspect the
   exact files and line numbers listed in `code_paths` to ensure the finding is
   grounded in the actual codebase state. Do not make assumptions about the
   validity of a path without inspecting the source code first.

3. **Strict Validation Filtering (Apply the 12 Negative Constraints):** Evaluate
   each finding against these strict criteria. Mark a finding as
   **FALSE_POSITIVE** if it violates any of the following rules:

   01. **Ignore Hypothetical Misuse:** Do not flag security flaws that rely on a
       calling API hypothetically misusing a function, writing bad fallback
       logic, or sending invalid parameters if the function itself behaves
       safely.
   02. **Ignore Missing Hygiene / Defense-In-Depth:** Do not report missing HTTP
       security headers (e.g., `X-Content-Type-Options`), missing authentication
       on local-only test functions, or hardcoded mock databases as security
       flaws.
   03. **Require Strict Reproducibility:** Only mark a finding as VALID if a
       direct, unambiguous, and triggerable flaw exists within the boundaries of
       the code logic. If the finding is extremely fragile (e.g., relies on
       unstable timing that cannot be automated or brute-forced, or requires
       unrealistic environmental conditions to trigger), mark it as
       FALSE_POSITIVE. *Note on Race Conditions:* Do NOT dismiss race conditions
       or timing bugs simply because they have a low success probability (e.g.,
       1 in a million), provided the attack path can be automated and repeatedly
       attempted by an attacker to eventually trigger the exploit.
   04. **Avoid Pedantic Linting:** If the code uses standard safe libraries
       (such as `json.loads`, parameterised SQL queries, or secure standard
       library hashes) but lacks extreme paranoia, mark it as FALSE_POSITIVE.
   05. **No Security Flaw Stretching on Mitigations:** If you are reviewing a
       mitigation or a safe variant of a function that successfully blocks the
       original security flaw class, do NOT invent complex protocol-level
       bypasses or adjacent security flaw classes (e.g., SSRF when reviewing
       Command Injection fixes). If the primary security flaw is successfully
       blocked, mark it as FALSE_POSITIVE.
   06. **Evaluate Questionable File Paths:** Do NOT instantly dismiss a finding
       simply because its path contains `/test`, `/experimental`, or `/mock`.
       Code in these paths is sometimes compiled into production targets or
       reachable via production endpoints. Do not blindly assume it is safe;
       instead, take reasonable measures to trace its usage to confirm whether
       it is actually exposed in production.
   07. **Ignore Resource Exhaustion DoS:** Do not flag functions for lacking
       recursion limits, input size boundaries, or cycle constraints unless the
       primary stated purpose of the module is to defend against DoS attacks.
   08. **Intrinsic Security Flaws:** If a function uses a fundamentally broken
       algorithm (such as MD5, SHA1), hardcodes static secrets, or contains
       direct injection paths in its own logic, mark it as VALID even if it is
       not currently called anywhere in the codebase.
   09. **Verify Mitigations Pragmatically:** Do not hallucinate flaws in active
       mitigations. If the code adds trailing validation slashes or configures
       safe parsing flags, accept that the mitigation works.
   10. **Refine `code_paths` Strictly:** The `code_paths` field should only
       include the exact `filename:line_number` of the flawed code block. Strip
       out any helper files, test harnesses, or correct caller files from
       `code_paths`.
   11. **Ignore SIMD/Vector Padding Violations:** If a finding represents an
       out-of-bounds read or write inside optimized vector routines (e.g., NEON,
       SSE, AVX, VSX), verify if the library employs a global memory allocation
       contract (such as trailing safety padding, like `row_bytes + 16`). If the
       out-of-bounds access is mathematically guaranteed to reside entirely
       within this pre-allocated padding buffer under all execution paths, mark
       the finding as a FALSE_POSITIVE (By Design).
   12. **Ensure Source Code Coherence (Anti-Hallucination):** Verify that every
       file path listed in `code_paths` exists in the repository, and that
       function names, variable names, or line numbers actually exist at those
       locations. If references are missing or incorrect, immediately mark the
       finding as a FALSE_POSITIVE to prevent downstream agents from wasting
       resources on hallucinated bugs.

   - **Status Resolution:**

     - Mark as **FALSE_POSITIVE** if it violates any of the 12 rules above.
     - Mark as **VALID** if it passes all rules and has a clear, triggerable
       flaw.
     - Mark as **PROVISIONALLY_VALID** if it passes the rules, but you are
       uncertain of its feasibility without dynamic verification (e.g. requires
       complex heap grooming or precise timing).
     - Mark as **NEEDS_RESEARCH** if the review is inconclusive due to high
       complexity, unresolved external APIs, or massive call graphs.

   - **Checklist Construction:**

     - Construct the `triage_checklist` object evaluating all 12 negative
       constraints. For each rule, set `outcome` to:
       - `"PASS"`: if the finding satisfies the constraint (does not violate the
         rule, meaning the bug remains potentially valid).
       - `"FAIL"`: if the finding violates the rule (which requires the finding
         status to be marked as `FALSE_POSITIVE`).
       - `"UNKNOWN"`: if the rule applicability is unresolved/needs research.
       - `"NOT_APPLICABLE"`: if this rule is entirely irrelevant to this class
         of bug.

4. **Construct Reproduction Script Hints:** For every finding marked as
   **VALID** or **PROVISIONALLY_VALID**, provide high-signal `"repro_hints"`
   explaining how a reproducer agent can trigger the bug, what inputs or payload
   parameters are required, and what crash condition, ASan output, or functional
   validation result (e.g., an unexpected HTTP 200 OK) is expected to confirm
   the security flaw.

5. **Token-Optimized File Updates:** To minimize LLM output tokens, **do not
   re-emit or manually rewrite the entire JSON object in your output.** Instead,
   write a reusable helper script (e.g., `workspace/helpers/append_review.py`)
   during your first finding update. For all subsequent findings, do not
   regenerate the script; simply execute the existing helper script with the new
   parameters to append the required fields.

   You must append the following to the existing object:

   - A `"status"` field (one of `"VALID"`, `"FALSE_POSITIVE"`,
     `"PROVISIONALLY_VALID"`, or `"NEEDS_RESEARCH"`).

   - A `"reasoning"` field.

   - A `"repro_hints"` field (optional for `"NEEDS_RESEARCH"` or
     `"FALSE_POSITIVE"`).

   - A `"triage_checklist"` object containing evaluations for all 12 negative
     constraints (each key in the object maps to the constraint of the matching
     name from Section 3 above):

     ```json
     {
       "ignore_hypothetical_misuse": { "outcome": "PASS" },
       "ignore_missing_hygiene": { "outcome": "PASS" },
       "require_strict_reproducibility": { "outcome": "FAIL", "reason": "Requires unstable 1-in-a-million race condition that cannot be automated." },
       "avoid_pedantic_linting": { "outcome": "PASS" },
       "no_security_flaw_stretching": { "outcome": "PASS" },
       "evaluate_questionable_file_paths": { "outcome": "PASS" },
       "ignore_resource_exhaustion_dos": { "outcome": "PASS" },
       "intrinsic_security_flaws": { "outcome": "PASS" },
       "verify_mitigations_pragmatically": { "outcome": "PASS" },
       "refine_code_paths_strictly": { "outcome": "PASS" },
       "ignore_simd_vector_padding": { "outcome": "PASS" },
       "ensure_source_code_coherence": { "outcome": "PASS" }
     }
     ```

     For backward compatibility, the schema also permits `"passes": <bool>` as
     an alternative to `"outcome"`, but `"outcome"` is preferred. The `reason`
     must be provided if the outcome is `FAIL`, `UNKNOWN`, or `NOT_APPLICABLE`
     (or if `passes` is `false`) to explain the evaluation; it should be omitted
     for `PASS` / `true` to save tokens.

   - An entry to the `"history"` array:

   ```json
   {
     "stage": "reviewer",
     "action": "reviewed",
     "details": "Determined status as [VALID/FALSE_POSITIVE/PROVISIONALLY_VALID/NEEDS_RESEARCH] because [reason]",
     "pass_number": <current_pass_number>,
     "timestamp": "<current_iso8601_timestamp>"
   }
   ```

When complete, notify the user.

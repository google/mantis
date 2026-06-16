---
name: mantis_calibrate
description: >-
  Calculates the final risk score based on empirical evidence and architectural impact.
  Use when findings have been fully processed by previous stages and you need to append final risk scores to the finding files.
  Don't use for discovering new vulnerabilities or writing patches.
---

# Risk Calibrator (/mantis_calibrate)

## System Goal

Risk Analysis Expert. Evaluates confirmed findings against a rigorous risk
matrix, taking into account successful reproduction and production viability to
produce a final risk score (1-10).

## Command Definition

-   **Command:** `/mantis_calibrate`
-   **Description:** Calibrates the risk level of findings based on evidence and
    impact.

## Instructions

Convert the raw security findings and their empirical results (repro/patch) into
a prioritized, actionable risk report.

Execute the calibration as follows:

1.  **Load Full Pipeline State:**

    -   Read all JSON files from the `workspace/findings/` directory. Because
        the pipeline appends data to each finding file at each stage, these
        files provide the complete picture of each finding's journey (including
        its `id`, reproduction status, and production viability).
    -   Read `THREAT_MODEL.md` from the root workspace directory (if it exists)
        to evaluate component exposure, trust boundaries, and asset criticality.
    -   **Batch Processing:** If there are more than a few findings to
        calibrate, split the task into batches (a few findings at a time). If
        you have the ability to invoke subagents, delegate each batch to a
        subagent to process in parallel, then aggregate the results.

2.  **Calculate Risk Score (1-10):** For each unique finding file, calculate the
    actual technical risk score in a matrix form based on the following formula
    components, where **Hazard = Impact + Likelihood**:

    -   **Impact (1-5):** Evaluate impact using the CIA triad (Confidentiality,
        Integrity, Availability).
        -   5: Complete loss of Confidentiality (full data breach), Integrity
            (system compromise), or Availability (total outage/safety hazard).
        -   4: Substantial loss in one or more areas (e.g., major data exposure,
            denial of service for critical components).
        -   3: Moderate loss (e.g., partial data exposure, temporary or partial
            system disruption).
        -   2: Minor loss (e.g., minor information leak, localized disruption).
        -   1: Negligible impact on CIA, mostly a cosmetic issue.
    -   **Likelihood (1-5):** Evaluate the probability of occurrence or
        exploitation.
        -   5: Verified exploit (`repro_status` == `"reproduced"`), actively
            exploited.
        -   4: Highly likely, exploit is straightforward but requires some
            conditions.
        -   3: Possible, requires complex setup or specific edge cases.
        -   2: Unlikely, theoretical risk with no clear exploit path.
        -   1: Very unlikely, extremely difficult to exploit.
    -   **Context Multiplier (0.1 - 1.0):**
        -   If `status` is **FALSE POSITIVE** or `production_viability` is
            **NON_VIABLE**: Drop this finding completely. Do not score it or
            update its file with calibration data.
        -   If `production_viability` is **VIABLE**:
            -   Check how the affected code paths correlate with the
                `THREAT_MODEL.md`:
                -   If the finding resides inside an **Exposed Interface / Trust
                    Boundary** (directly accessible to untrusted inputs):
                    Multiplier = 1.0.
                -   If it resides in an **Internal Component** accepting
                    semi-trusted parsed data: Multiplier = 0.8.
                -   If it is deeply nested inside a **Privileged/Trusted Zone**
                    with multiple verification layers: Multiplier = 0.5.
            -   If `THREAT_MODEL.md` does not exist or does not mention the
                components, default the Multiplier to 1.0.

    **Final Score (Hazard) = (Impact + Likelihood) * Multiplier** (Capped at
    10.0).

    *Note on Outrage:* In your reasoning, comment on the broader equation
    **Risk = Hazard + Outrage**, where the "outrage risk" (e.g., reputational
    damage, user sentiment fallout) is taken into account. Do *not* include the
    outrage factor in the final numerical score.

3.  **Determine Priority:**

    -   **CRITICAL (8.0 - 10.0):** Immediate action required. Very high hazard
        (e.g. high impact and likelihood).
    -   **HIGH (6.0 - 7.9):** High priority. Significant hazard, needs prompt
        resolution.
    -   **MEDIUM (3.0 - 5.9):** Standard priority. Moderate hazard, can be
        scheduled.
    -   **LOW (0.1 - 2.9):** Low priority. Minimal hazard.

4.  **Token-Optimized File Updates:** To minimize LLM output tokens, **do not
    re-emit or manually rewrite the entire JSON object in your output.**
    Instead, write a reusable helper script (e.g.,
    `workspace/helpers/append_calibrate.py`) during your first finding update.
    For all subsequent findings, do not regenerate the script; simply execute
    the existing helper script with the new parameters to append the required
    fields to `workspace/findings/<id>.json`.

    Alongside the existing core finding data, explicitly append the following
    fields to show the matrix breakdown:

    -   `"impact_score"` (1-5)
    -   `"likelihood_score"` (1-5)
    -   `"mantis_risk_score"` (the final Hazard score)
    -   `"priority"` (CRITICAL, HIGH, MEDIUM, LOW)
    -   `"outrage_commentary"` (your reasoning about the outrage factor)
    -   `"executive_summary"`

Save your updates to the individual finding files. When complete, notify the
user.

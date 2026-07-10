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
    -   Read `workspace/kb/THREAT_MODEL.md` from the Knowledge Base (if it
        exists) to evaluate component exposure, trust boundaries, and asset
        criticality.
    -   **Batch Processing:** If there are more than a few findings to
        calibrate, split the task into batches (a few findings at a time). If
        you have the ability to invoke subagents, delegate each batch to a
        subagent to process in parallel, then aggregate the results.

2.  **Calculate Risk Score (1-10):** For each unique finding file, calculate the
    actual technical risk score in a matrix form based on the following formula
    components, where **Hazard = Impact + Likelihood**:

    -   **Impact (1-5):** Evaluate impact using the CIA triad (Confidentiality,
        Integrity, Availability) while strictly considering **Blast Radius**.
        -   5: Complete, systemic loss of Confidentiality (full data breach) or
            Integrity (system compromise, e.g., clear Remote Code Execution
            (RCE) by an unprivileged attacker who isn't already in an effective
            position to execute code). MUST NOT be used for attackers who
            already have execution privileges.
        -   4: Substantial loss in one or more areas. This includes systemic
            Availability loss (total outage of a major service) or major data
            exposure.
        -   3: Moderate loss (e.g., partial data exposure, temporary or partial
            system disruption).
        -   2: Minor loss (e.g., minor information leak, localized disruption).
            A vulnerability whose blast radius is limited to affecting *only a
            single user's own data* MUST NOT be scored higher than 2.
        -   1: Negligible impact on CIA, mostly a cosmetic issue. Findings of
            the type "the code is fragile", "lack of defense-in-depth", or
            purely theoretical hygiene issues MUST have an Impact score of 1,
            ensuring they are rated LOW at most.
        -   *Note on Internal Admin & Lateral Movement:* If a finding requires
            pre-existing administrative privileges (internal privilege
            escalation, e.g., admin to super-admin) or only allows lateral
            movement/pivoting between internal components from an already
            compromised state, cap its individual Impact score at 2. Its
            escalated risk will be captured separately if it is successfully
            chained into a "Super Finding" by the chainer.
    -   **Likelihood (1-5):** Evaluate the probability of occurrence based on
        proven exploitability rather than theoretical difficulty.
        -   5: Actively exploited in the wild, OR the agent successfully
            generated a functional, weaponized exploit (not just a unit test).
        -   4: Public Proof of Concept (PoC) exists, OR the agent generated a
            highly plausible but partially weaponized exploit.
        -   3: No functional exploit, but the attack vector is trivial to
            automate.
        -   2: Theoretical and highly complex (requires local access, strict
            timing).
        -   1: Strictly theoretical risk with no known exploit path.
    -   **Context Multiplier (0.1 - 1.0):**
        -   If `status` is **FALSE POSITIVE** or `production_viability` is
            **NON_VIABLE**: Drop this finding completely. Do not score it or
            update its file with calibration data.
        -   If `production_viability` is **VIABLE**:
            -   **Network/Trust Exposure:**
                -   If the finding resides inside an **Exposed Interface / Trust
                    Boundary** (directly accessible to untrusted inputs): 1.0.
                -   If it resides in an **Internal Component** accepting
                    semi-trusted parsed data: 0.8.
                -   If deeply nested inside a **Privileged/Trusted Zone**: 0.5.
            -   **Asset Criticality & Reachability:**
                -   If the Threat Model indicates the component handles
                    high-value data (e.g., PII, core secrets), keep the
                    multiplier high.
                -   If it affects a low-value target (e.g., internal analytics,
                    sandboxed test data), reduce the multiplier (e.g., 0.5).
                -   If static/dynamic analysis proves the vulnerable code is
                    effectively "dead code" (never called in runtime execution
                    paths), drastically reduce the multiplier to 0.2.
            -   If `workspace/kb/THREAT_MODEL.md` does not exist or does not
                mention the components, default the Multiplier to 1.0.
        -   If `production_viability` is **SAMPLE_OR_TEST**:
            -   Set the Context Multiplier to a reduced value (e.g. `0.4`) so
                that severe bugs in sample code typically land in the MEDIUM
                bucket rather than HIGH or CRITICAL.
            -   In the `executive_summary`, explicitly state that this is not a
                production bug. The recommendation MUST focus on fixing the
                example/test so that developers do not copy insecure patterns
                into production code.

    **Final Score (Hazard) = (Impact + Likelihood) * Multiplier** (Capped at
    10.0).

    *Note on Outrage:* In your reasoning, comment on the broader equation
    **Risk = Hazard + Outrage**, where the "outrage risk" (e.g., reputational
    damage, user sentiment fallout) is taken into account. Do *not* include the
    outrage factor in the final numerical score.

3.  **Critical Sanity Triage (Downgrading Weak Findings):** Before determining
    the final priority, perform a second-level sanity check on the quality of
    the finding and its accumulated evidence. You **MUST** force-downgrade the
    finding's priority to **LOW** (and cap its final score at **2.0**) if it
    meets any of the following "weak finding" criteria:

    -   **Speculative Viability on Repro Failure:** The reproduction failed
        (`repro_status: "failed_to_reproduce"`), and the reasoning for why it is
        still viable in production is highly speculative, theoretical, or relies
        on unverified assumptions about downstream systems.
    -   **Minor Configuration Hygiene:** The issue represents a minor deviation
        from best-practice configuration (e.g., slightly loose permissions on an
        internal directory, lack of modern encryption on low-value internal
        transport) but does not lead to a clear exploit path, privilege
        escalation, or data exposure.
    -   **Vague Code Paths / Fragile Assumptions:** The finding's description or
        reasoning relies on unverified assumptions about caller behavior or
        adjacent system components that are not documented in the active
        Knowledge Base.
    -   **Unreliable/Noisy Triggers:** The finding represents an issue that can
        technically be triggered but is highly likely to be ignored in practice
        due to high noise, or is indistinguishable from normal system operations
        without causing real harm.

4.  **Determine Priority:**

    -   **CRITICAL (8.0 - 10.0):** Immediate action required. Very high hazard
        (e.g. high impact and likelihood). **Must NOT be used unless it
        represents a clear RCE (or equivalent total loss) by an unprivileged
        attacker who is not already in an effective position to compromise the
        system.**
    -   **HIGH (6.0 - 7.9):** High priority. Significant hazard, needs prompt
        resolution.
    -   **MEDIUM (3.0 - 5.9):** Standard priority. Moderate hazard, can be
        scheduled.
    -   **LOW (0.1 - 2.9):** Low priority. Minimal hazard. **Any finding of the
        type "the code is fragile", purely hygiene/defense-in-depth, or one that
        exclusively affects a single user's own data MUST be capped at LOW
        priority regardless of the calculated score.**

5.  **Token-Optimized File Updates:** To minimize LLM output tokens, **do not
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

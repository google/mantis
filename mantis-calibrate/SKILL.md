---
name: mantis-calibrate
description: >-
  Calculates the final risk score based on empirical evidence and architectural impact.
  Use when findings have been fully processed by previous stages and you need to append final risk scores to the finding files.
  Don't use for discovering new vulnerabilities or writing patches.
---

# Risk Calibrator (/mantis-calibrate)

## System Goal

Risk Analysis Expert. Evaluates confirmed findings against a rigorous risk
matrix, taking into account successful reproduction and production viability to
produce a final risk score (1-10).

## Command Definition

-   **Command:** `/mantis-calibrate`
-   **Description:** Calibrates the risk level of findings based on evidence and
    impact.

## Input/Output Contract

-   **Reads**:
    -   `workspace/findings/*.json` (all finding files to load full pipeline
        state).
    -   `workspace/kb/THREAT_MODEL.md` (if exists, to check threat boundary
        overrides and asset criticality).
    -   `workspace/.mantis_state.json` (to track current loop pass).
-   **Writes**:
    -   Updates finding files in-place with scoring/calibration fields
        (`impact_score`, `likelihood_score`, `availability_tier`,
        `inferred_exposure`, `attacker_position`, `mantis_risk_score`,
        `priority`, `sanity_triage_applied`, `calibration_checklist`,
        `outrage_commentary`, `executive_summary`).
    -   Reusable helper script `workspace/helpers/append_calibrate.py`.
-   **Preconditions**:
    -   Confirmed or raw findings must exist in `workspace/findings/`.
-   **Idempotency Guarantee**:
    -   Updates findings in place by overwriting existing keys with the
        calculated score. Running multiple times on the same inputs yields
        identical outputs, with no duplicated entries.

## Instructions

Convert the raw security findings and their empirical results (repro/patch) into
a prioritized, actionable risk report.

Execute the calibration as follows:

1.  **Load Full Pipeline State:**

    -   Read all JSON files from the `workspace/findings/` directory. Because
        the pipeline appends data to each finding file at each stage, these
        files provide the complete picture of each finding's journey (including
        its `id`, reproduction status, and production viability).
    -   **Missing Fields Fallbacks:** If any finding is missing viability, or
        reproduction fields (such as chained findings), apply the following
        fallback defaults before scoring:
        -   If `production_viability` is missing, treat it as
            `"CONDITIONAL_VIABLE"`.
        -   If `repro_status` is missing, treat it as `"not_attempted"`.
    -   Read `workspace/kb/THREAT_MODEL.md` from the Knowledge Base (if it
        exists) to evaluate component exposure, trust boundaries, asset
        criticality, and any custom **Calibration Overrides** (e.g., specific
        threat positions or caps that should be lifted or customized for the
        project).
    -   **Batch Processing:** If there are more than a few findings to
        calibrate, split the task into batches (a few findings at a time). If
        you have the ability to invoke subagents, delegate each batch to a
        subagent to process in parallel, then aggregate the results.

2.  **Calculate Risk Score (1-10):** For each unique finding file, calculate the
    actual technical risk score in a matrix form based on the following formula
    components, where **Hazard = Impact + Likelihood**:

    -   **Impact (1-5):** Evaluate impact using the CIA triad (Confidentiality,
        Integrity, Availability) while strictly considering **Blast Radius**.
        -   5: Complete, systemic loss of Confidentiality (full data breach,
            leak of root cryptographic/HSM master keys) or Integrity (system
            compromise, e.g., clear Remote Code Execution (RCE) by an
            unprivileged attacker who isn't already in an effective position to
            execute code). MUST NOT be used for attackers who already have
            execution privileges.
        -   4: Substantial loss in one or more areas. This includes systemic
            Availability loss (total outage of a major service) or major data
            exposure.
        -   3: Moderate loss (e.g., partial data exposure, temporary or partial
            system disruption).
        -   2: Minor loss (e.g., minor information leak, localized disruption).
            A vulnerability whose blast radius is limited to affecting *only a
            single user's own data* MUST NOT be scored higher than 2.
            *Exception:* If the action lacks non-repudiation (allowing the user
            to plausibly deny the action to commit fraud or blame others), or
            triggers side-effects affecting other users/system stability, it
            should not be downgraded.
        -   1: Negligible impact on CIA, mostly a cosmetic issue. Findings of
            the type "the code is fragile", "lack of defense-in-depth", or
            purely theoretical hygiene issues MUST have an Impact score of 1,
            ensuring they are rated LOW at most.
        -   **Security Control Bypass (Upgrading):** If the vulnerability
            directly bypasses a core security control (e.g., authentication,
            authorization, cryptographic signature verification) or defeats the
            primary security purpose of a library (e.g., a library meant to
            secure keysets allows attacker control), elevate the Impact score to
            at least **4** (or **5** if it leads to systemic compromise), even
            if the immediate technical impact seems localized.
        -   *Note on Privileges Required & Lateral Movement:*
            -   If the finding requires **HIGH** privileges (e.g.,
                administrative privileges, admin-to-super-admin escalation) or
                only allows lateral movement/pivoting between internal
                components from an already compromised state, cap its individual
                Impact score at **2**, unless the exploit results in escaping
                the container boundary (to the host node) or cross-tenant
                escalation.
            -   If the finding requires **LOW** privileges (e.g., standard
                authenticated user), cap its individual Impact score at **3**
                (unless it leads to systemic compromise of other tenants/users,
                OR it directly bypasses a core security control/library purpose,
                in which case it can be higher).
            -   These caps apply to *individual* findings. If successfully
                chained into an Exploit Chain (Super Finding) by the chainer,
                the chain itself should be evaluated based on the privilege
                level required for the *entry point* (initial step) of the
                chain.
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
        -   **Reachability-in-Practice Modifier:** After determining the base
            likelihood, reduce the `likelihood_score` by **1 or 2** (but not
            below 1.0) if the exploit path relies on uncommon or non-default
            usage patterns. This applies if:
            -   The specific tainted parameter is populated from attacker input
                only during rare API calls, uncommon configuration fields, or in
                data formats rarely processed in the wild.
            -   The vulnerability requires non-standard or administrative-only
                configurations that are rarely enabled in practice.
    -   **Context Multiplier (0.1 - 1.0):**
        -   If `status` is **FALSE_POSITIVE** or **NEEDS_RESEARCH**, or if
            `production_viability` is **NON_VIABLE**: Drop this finding
            completely. Do not score it or update its file with calibration
            data.
        -   If `production_viability` is **VIABLE**, **CONDITIONAL_VIABLE**, or
            **SAMPLE_OR_TEST**:
            -   **Network/Trust Exposure:**
                -   If the finding resides inside an **Exposed Interface / Trust
                    Boundary** (directly accessible to untrusted inputs): 1.0.
                -   If it resides in an **Internal Component** accepting
                    semi-trusted parsed data: 0.8.
                -   If deeply nested inside a **Privileged/Trusted Zone**: 0.5.
                -   **Inference when Threat Model is Missing/Incomplete:** If
                    `workspace/kb/THREAT_MODEL.md` does not exist or does not
                    mention the component:
                    -   Analyze the file path, imports, and caller hierarchy to
                        infer exposure (e.g., public APIs vs internal helpers).
                    -   Default the Exposure Multiplier to **0.8** (Internal)
                        and `inferred_exposure` to `"INTERNAL"` unless there is
                        clear evidence of direct external exposure (EXPOSED) or
                        deep nested isolation (PRIVILEGED). Local SUID/LPE
                        binaries should default to `"INTERNAL"` exposure.
                    -   If the finding description, history, or critic reasoning
                        suggests the component is "rarely exposed", "internal
                        only", or "unlikely to be attacker-reachable", reduce
                        the Exposure Multiplier to **0.5** or lower.
            -   **Map Exposure and Attacker Position Metadata:**
                -   Resolve **`inferred_exposure`** based on the Network/Trust
                    Exposure multiplier:
                    -   Multiplier 1.0 (Exposed Interface) -> `"EXPOSED"`
                    -   Multiplier 0.8 (Internal Component) -> `"INTERNAL"`
                    -   Multiplier 0.5 (Privileged/Trusted Zone) ->
                        `"PRIVILEGED"`
                -   **Evaluate Attacker Position (declared in finding):**
                    -   Read `attacker_position` from the finding JSON.
                    -   **Determine by Barrier, Not Transport:** The
                        `attacker_position` must represent the outermost
                        boundary that the **first untrusted principal** (the
                        ultimate human attacker or external threat actor) must
                        cross to reach the interface. Do not key on the
                        transport protocol (e.g., HTTP, gRPC, IPC) or the
                        immediate protocol peer.
                        -   **Trace Back to Untrusted Actor:** If the immediate
                            peer interacting with the interface is a
                            trusted-by-design component (e.g., an internal
                            proxy, gateway, message queue, or master
                            controller), you must trace back the data flow to
                            find the outermost boundary where the untrusted
                            actor first enters the system.
                        -   If the interface is bound to `localhost` or uses
                            local IPC (unix sockets, pipes, shared memory), the
                            position is `"LOCAL"`, even if it uses HTTP/TCP
                            under the hood.
                        -   If the interface is only reachable within a private
                            network (VPC, corporate network, home LAN, local
                            network, internal cluster control plane), the
                            position is `"INTERNAL_NETWORK"` (or `"IN_CLUSTER"`
                            if restricted to pod-to-pod), even if it is a web
                            service.
                        -   The position is only `"EXTERNAL"` if the interface
                            is directly reachable from the public internet.
                        -   If the interface requires physical contact, hardware
                            interaction (e.g., JTAG, debug probes, chip
                            decapping), or local wireless proximity (e.g., NFC,
                            Bluetooth), the position must be
                            `"PHYSICAL_TEMPORARY"` or `"PHYSICAL_LONG_TERM"`,
                            regardless of the protocol used.
                    -   **Normalize Free-text:** If the value is present but is
                        a free-text string that does not exactly match one of
                        the valid enum values (e.g. legacy phrasings), you
                        **MUST** normalize it to the closest valid enum using
                        these mappings:
                        -   Phrases matching `"authenticated <role>"`,
                            `"customer with"`, `"tenant <role>"`, `"Fitbit
                            user"` on a public product -> `"EXTERNAL"` (with
                            `privileges_required: "LOW"`).
                        -   Phrases matching `"local user"`, `"local shell"`,
                            `"local access"` -> `"LOCAL"`.
                        -   Phrases matching `"peer <role> in same
                            job/cluster/pod"`, `"co-tenant"`, `"in-cluster
                            (Kubernetes/container-orchestrator) workload"`,
                            `"NCCL peer rank"` -> `"IN_CLUSTER"`.
                        -   Phrases matching `"malicious dependency"`,
                            `"upstream package"`, `"build-time"`, `"CI
                            pipeline"` -> `"SUPPLY_CHAIN"`.
                        -   Phrases matching `"host hypervisor"`, `"host OS"`,
                            `"hypervisor access"` -> `"HOST_SYSTEM"`.
                        -   Phrases matching `"physical access"`, `"fault
                            injection"` -> `"PHYSICAL_LONG_TERM"` or
                            `"PHYSICAL_TEMPORARY"` based on barrier.
                    -   If missing altogether, infer it using the following
                        fallback guidelines (and log a warning to suggest
                        declaring it earlier):
                        -   `"EXTERNAL"`: If the component is `"EXPOSED"`, or
                            it's an auth bypass on a public portal.
                        -   `"LOCAL"`: If it's a local privilege escalation
                            (LPE) or SUID exploit.
                        -   `"IN_CLUSTER"`: If it targets in-cluster
                            infrastructure (CSI/CNI) from a pod.
                        -   `"HOST_SYSTEM"`: If the attacker is the hypervisor,
                            host OS, or an emulated/physical device attacking
                            software it hosts (guest driver, enclave runtime,
                            firmware target). This enum is strictly for the
                            outer-to-inner direction. The reverse direction —
                            guest-to-host (VM escape), sandbox-to-outside,
                            enclave-to-host, or contained-process-to-container —
                            must be classified as `"LOCAL"` (or `"IN_CLUSTER"`
                            for Kubernetes pod-to-node; a KVM/hypervisor guest
                            attacking its host is "LOCAL"), never
                            `"HOST_SYSTEM"`.
                        -   `"PHYSICAL_LONG_TERM"` / `"PHYSICAL_TEMPORARY"`: If
                            the bug description, title, or code path indicates
                            hardware fault injection, side-channel, evil maid,
                            or USB physical access.
                        -   `"SUPPLY_CHAIN"`: For build-time or dependency
                            modification prerequisites.
                        -   `"INTERNAL_NETWORK"`: Default fallback for other
                            internal components.
                    -   **Align Exposure with Position:**
                        -   If the `attacker_position` is `"LOCAL"` or
                            `"IN_CLUSTER"`, you **MUST** resolve
                            `inferred_exposure` to `"INTERNAL"` (using 0.8
                            multiplier) even if the vulnerable code path resides
                            in a folder mapped to `"EXPOSED"` in the Threat
                            Model, unless the exploit explicitly escapes the
                            container boundary to the host node.
                        -   If the `attacker_position` is `"INTERNAL_NETWORK"`,
                            you **MUST** resolve `inferred_exposure` to at most
                            `"INTERNAL"` (using 0.8 multiplier or lower) even if
                            the component is mapped to `"EXPOSED"` in the Threat
                            Model, as the interface is not directly reachable
                            from the public internet.
                        -   If the `attacker_position` is `"EXTERNAL"`, you
                            **MUST** resolve `inferred_exposure` to `"EXPOSED"`
                            (using 1.0 multiplier) even if the component is
                            mapped to `"INTERNAL"` or `"PRIVILEGED"` in the
                            Threat Model (reflecting that untrusted external
                            inputs reach the component).
            -   **Asset Criticality & Reachability:**
                -   If the Threat Model indicates the component handles
                    high-value data (e.g., PII, core secrets), keep the
                    multiplier high.
                -   If it affects a low-value target (e.g., internal analytics,
                    sandboxed test data), reduce the multiplier (e.g., 0.5).
                -   **Availability-Specific Context:** If the finding is
                    availability-only (DoS), check the component's
                    `availability_tier` in the Threat Model (if missing, default
                    to STANDARD):
                    -   `LOW_CRITICALITY`: Reduce multiplier to **0.5**.
                    -   `STANDARD`: Reduce multiplier to **0.8**.
                    -   `CRITICAL`: Keep multiplier at **1.0**.
                -   If static/dynamic analysis proves the vulnerable code is
                    effectively "dead code" (never called in runtime execution
                    paths), drastically reduce the multiplier to 0.2.
            -   **User Interaction:**
                -   If `user_interaction` is **REQUIRED** (e.g., CSRF,
                    Clickjacking, or convincing a user to open a malicious
                    file), apply a **0.7** multiplier to the Context Multiplier
                    (e.g., if exposure is Internal (0.8) and user interaction is
                    required, the combined multiplier is 0.8 * 0.7 = 0.56). This
                    ensures these findings are capped below the CRITICAL
                    threshold.
        -   If `production_viability` is **SAMPLE_OR_TEST**:
            -   Apply a **0.4** scaling factor to the Context Multiplier (i.e.,
                multiply the current Context Multiplier by **0.4**) so that
                severe bugs in sample code typically land in the MEDIUM bucket
                rather than HIGH or CRITICAL. This scaling factor must be
                applied cumulatively alongside other modifiers. Do not override
                the Context Multiplier directly to `0.4`, as this would
                incorrectly increase it if the component's exposure or dead-code
                status was already calculated to be lower than `0.4` (e.g.
                `0.2`).
            -   In the `executive_summary`, explicitly state that this is not a
                production bug. The recommendation MUST focus on fixing the
                example/test so that developers do not copy insecure patterns
                into production code.
        -   If `production_viability` is **CONDITIONAL_VIABLE**:
            -   Apply a **0.7** scaling factor to the Context Multiplier (i.e.,
                multiply the current Context Multiplier by **0.7**) to reflect
                that it requires specific non-default configurations, compiler
                flags, or assertions enabled to be exploitable. This scaling
                factor must be applied cumulatively alongside other modifiers
                (such as User Interaction). Do not override the Context
                Multiplier directly to `0.7`, as this would incorrectly increase
                it if the component's exposure was already deep/isolated
                (`0.5`).
            -   In the `executive_summary`, document the specific conditions
                required for viability.

    **Final Score (Hazard) = (Impact + Likelihood) * Multiplier** (Capped at
    10.0).

    *Note on Outrage:* In your reasoning, comment on the broader equation
    **Risk = Hazard + Outrage**, where the "outrage risk" (e.g., reputational
    damage, user sentiment fallout) is taken into account. Do *not* include the
    outrage factor in the final numerical score.

3.  **Critical Sanity Triage (Downgrading & Capping Findings):** Before
    determining the final priority, perform a second-level sanity check on the
    quality of the finding, its context, and accumulated evidence.

    **Core Principle - Marginal Capability:** The final severity and priority of
    a finding are strictly bounded by the *marginal capability* gained by the
    attacker over their prerequisite position. If the exploit does not grant the
    attacker significant new control, access, or capabilities beyond what is
    already inherent to their starting position (or already possessed via
    legitimate means), the finding must be capped or downgraded.

    The complete, detailed definitions of the 27 calibration sanity rules are
    stored in the reference catalogue at
    [Calibration Rules](references/calibration_rules.md). You MUST evaluate each
    finding against the 27 rules listed there.

    Check if the `THREAT_MODEL.md` defines any `Calibration Overrides` (e.g.,
    `LIFT_CAP: PHYSICAL_LONG_TERM`). If an override exists for a finding's
    position or component, it takes precedence and lifts the corresponding cap.
    Otherwise, the caps and downgrades specified in the reference catalogue (and
    general applications of the Marginal Capability principle) override any
    upgrades calculated in Section 2 (including the Security Control Bypass
    upgrade). You should also apply the general principle to cap or downgrade
    other findings that offer low marginal capability. **Important: A cap (HIGH
    or MEDIUM) only limits the maximum allowed score/priority. It must NOT
    upgrade a lower score/priority (e.g., a finding with a score of 5.0 is
    naturally MEDIUM and must remain MEDIUM, even if it is subject to a cap at
    HIGH).**

    **Precedence & UNKNOWN Rules Policy:**

    -   Evaluate ALL rules. If multiple caps apply, the **most restrictive**
        wins (Force-LOW > cap-MEDIUM > cap-HIGH).
    -   **Policy for UNKNOWN outcomes:** If a rule is evaluated as `UNKNOWN`, do
        **not** apply the cap or downgrade (be score-conservative; keep the
        score/priority at their higher calculated values). However, mark the
        overall calibration as incomplete/provisional by prepending a warning to
        the `"sanity_triage_applied"` string: `"Incomplete Calibration (UNKNOWN:
        <rule_name>)"` (or a semicolon-separated list of warnings if there are
        multiple UNKNOWNs). This signals that manual review is required to
        resolve the rule status.
    -   Record every rule that successfully fired/applied in
        `sanity_triage_applied` as a semicolon-separated list, most restrictive
        first (e.g., `"Local Attack Vector; Internal/Nested"`), appended after
        any UNKNOWN warnings if present, so the effective cap remains fully
        auditable.

4.  **Determine Priority:**

    -   **CRITICAL (8.0 - 10.0):** Immediate action required. Very high hazard
        (e.g. high impact and likelihood). **Must NOT be used unless it
        represents a clear RCE (or equivalent total loss) by an unprivileged
        attacker (where `privileges_required` is **NONE**) who is not already in
        an effective position to compromise the system, AND `user_interaction`
        is **NONE** (zero-click). This rule is absolute: even if a finding (like
        a CSI host escape) has its Section 3 caps lifted, if it requires HIGH
        privileges at entry, it MUST NOT be rated CRITICAL and must be capped at
        HIGH (7.9). Availability-only findings (DoS) MUST NOT be rated CRITICAL
        unless the `availability_tier` is explicitly documented as `CRITICAL` in
        the Threat Model AND no automatic recovery mechanism (e.g. auto-restart,
        load balancer failover) mitigates the impact.**
    -   **HIGH (6.0 - 7.9):** High priority. Significant hazard, needs prompt
        resolution.
    -   **MEDIUM (3.0 - 5.9):** Standard priority. Moderate hazard, can be
        scheduled.
    -   **LOW (0.1 - 2.9):** Low priority. Minimal hazard. **Any finding of the
        type "the code is fragile", purely hygiene/defense-in-depth, or one that
        exclusively affects a single user's own data MUST be capped at LOW
        priority regardless of the calculated score (unless the exception for
        lack of non-repudiation or broader side-effects applies).**

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
    -   `"availability_tier"` (CRITICAL, STANDARD, LOW_CRITICALITY or null)
    -   `"inferred_exposure"` (EXPOSED, INTERNAL, or PRIVILEGED)
    -   `"attacker_position"` (preserved from input, or populated from fallback
        inference if missing)
    -   `"mantis_risk_score"` (the final Hazard score)
    -   `"priority"` (CRITICAL, HIGH, MEDIUM, LOW)
    -   `"sanity_triage_applied"` (semicolon-separated list of Section 3 rules
        that fired, most-restrictive first, or null)
    -   `"calibration_checklist"` object containing evaluations for all 27
        sanity caps. Each key in the object maps to the sanity cap rule of the
        matching name:

        ```json
        {
          "repro_failure": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "unreachable_inputs": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "third_party_reachability": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "minor_config_hygiene": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "non_security_critical": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "vague_code_paths": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "unreliable_triggers": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "prerequisite_shell": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "physical_long_term": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "trusted_controller_zero_delta": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "standard_host_attacks": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "static_confirmation": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "strict_xss": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "internal_nested": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "probabilistic_llm": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "supply_chain_prerequisites": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "non_default_config": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "confidential_computing_host": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "trusted_controller_critical_bypass": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "local_attack_vector": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "self_contained_blast": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "rarely_exposed": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "equivalent_primitives": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "documented_insecure_config": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "physical_temporary": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "high_privilege_external": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" },
          "trusted_controller_standard_bypass": { "outcome": "APPLIES" | "DOES_NOT_APPLY" | "UNKNOWN", "reason": "<string>" }
        }
        ```

        For each rule, `outcome` must be set to:

        -   `"APPLIES"`: if the sanity cap rule applies (fires) to this finding,
            capping or downgrading its score/priority. A detailed `reason`
            string is **required**.
        -   `"DOES_NOT_APPLY"`: if the sanity cap rule does not apply. The
            `reason` field is **optional** and may be omitted to optimize
            tokens.
        -   `"UNKNOWN"`: if it is unresolved. A detailed `reason` string is
            **required**.

        For backward compatibility, the schema also permits `"fires": <bool>`
        (with `reason` required only if `fires` is `true`), but the new
        `"outcome"` format is preferred.

    -   `"outrage_commentary"` (your reasoning about the outrage factor)

    -   `"executive_summary"`

    -   An entry to the `"history"` array:

        ```json
        {
          "stage": "calibrate",
          "action": "calibrated",
          "details": "Calculated risk score as [score] and priority as [priority].",
          "pass_number": <current_pass_number>,
          "timestamp": "<current_iso8601_timestamp>"
        }
        ```

Save your updates to the individual finding files. When complete, notify the
user.

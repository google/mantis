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
                            job/cluster/pod"`, `"co-tenant"`, `"adjacent
                            workload"`, `"NCCL peer rank"` -> `"IN_CLUSTER"`.
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
                            firmware target).
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

3.  **Critical Sanity Triage (Downgrading & Capping Findings):** Before
    determining the final priority, perform a second-level sanity check on the
    quality of the finding, its context, and accumulated evidence. Check if the
    `THREAT_MODEL.md` defines any `Calibration Overrides` (e.g., `LIFT_CAP:
    PHYSICAL_LONG_TERM`). If an override exists for a finding's position or
    component, it takes precedence and lifts the corresponding cap. Otherwise,
    the caps and downgrades below override any upgrades calculated in Section 2
    (including the Security Control Bypass upgrade), and you **MUST**
    force-downgrade or cap the finding's priority and score if it meets any of
    the following criteria. **Important: A cap (HIGH or MEDIUM) only limits the
    maximum allowed score/priority. It must NOT upgrade a lower score/priority
    (e.g., a finding with a score of 5.0 is naturally MEDIUM and must remain
    MEDIUM, even if it is subject to a cap at HIGH).**

    **Precedence:** Evaluate ALL rules below. If multiple caps apply, the **most
    restrictive** wins (Force-LOW > cap-MEDIUM > cap-HIGH). Record every rule
    that fired in `sanity_triage_applied` as a semicolon-separated list, most
    restrictive first (e.g., `"Local Attack Vector; Internal/Nested"`), so the
    effective cap is auditable.

    *   **Force-Downgrade to LOW (Cap at 2.0 / LOW Priority):**

        -   **Reproduction Failure or Not Attempted:** The reproduction failed
            (`repro_status: "failed_to_reproduce"`) or was not attempted
            (`repro_status: "not_attempted"`). Regardless of theoretical
            production viability.
        -   **Unreachable / Uncontrolled Inputs:** The finding relies on inputs
            that are documented as highly unlikely to be user-controlled, and no
            path from a trust boundary is proven.
        -   **Third-Party / Supply Chain Reachability:** Vulnerabilities in
            third-party libraries (dependency CVEs) where a reachable path from
            application input to the vulnerable function has not been actively
            demonstrated.
        -   **Minor Configuration Hygiene:** Minor deviations from best practice
            (e.g., slightly loose permissions on internal dirs, lack of modern
            encryption on low-value internal transport) without a clear exploit
            path.
        -   **Non-Security Critical Components:** The finding affects a
            component or data with no security sensitivity (e.g., public info,
            signatures on non-security payloads, cosmetic outputs).
        -   **Vague Code Paths / Fragile Assumptions:** Relying on unverified
            assumptions about caller behavior or adjacent system components.
        -   **Unreliable/Noisy Triggers:** Triggers that are likely to be
            ignored in practice or indistinguishable from normal operations.
        -   **Prerequisite Shell Access (Equivalent Primitives):** The attacker
            already possesses local shell access on the target container or host
            with the **same or higher** privilege level than the exploit
            provides, rendering the gained access redundant (e.g., exploiting a
            bug to get a standard user shell when already logged in as a
            standard user, or exploiting a local buffer overflow to run commands
            as root when already running as root). This does NOT apply to
            low-to-high privilege escalation (e.g., standard user to root),
            which should cap at MEDIUM.

        -   **Physical Long-Term / Laboratory Access:** If the attack requires
            long-term physical access to the device or specialized laboratory
            equipment (e.g., fault injection, side-channel analysis, chip
            decapping). Force-downgrade to **LOW (2.0)** due to the extreme
            execution barrier and requirement for physical possession.

        -   **Standard Host-to-Guest Attacks:** If the attacker position is
            `HOST_SYSTEM` (host hypervisor attacking guest) on standard
            deployments (non-Confidential Computing). Force-downgrade to **LOW
            (2.0)** (equivalent primitives), as the host OS/hypervisor already
            possesses total control over the guest by design. **Default
            assumption:** treat as non-Confidential Computing (this rule fires)
            UNLESS the Threat Model, code path, or finding description
            explicitly names Confidential Computing, guest enclaves, TEE, SEV,
            TDX, SGX, or attestation (in which case apply the CC Host Attacks
            cap-HIGH rule instead).

    *   **Force-Cap to HIGH (Cap at 7.9 / Maximum HIGH Priority):**

        -   **Static Confirmation:** Statically confirmed but not empirically
            reproduced (`repro_status: "statically_confirmed"`). Cap
            `likelihood_score` at **3**, apply **0.8** multiplier to Hazard, and
            MUST NOT be CRITICAL. *Exception:* If the finding details
            (description, history, or reproduction output) include a valid
            external stack trace, sanitizer trace (e.g. ASan, UBSan, MSan),
            crash log, or core dump proving the vulnerability was triggered in
            execution (e.g., in a prior run or by external tools), treat it as
            empirically reproduced (Likelihood 5) and do not apply this static
            cap.
        -   **Strict XSS Caps:** All XSS vulnerabilities. Default to MEDIUM or
            LOW; cap at HIGH (7.9) only for stored XSS on critical admin pages
            with zero-click execution for the admin.
        -   **Internal / Nested Components:** Any finding with a Network/Trust
            Exposure multiplier less than 1.0 (i.e., Internal Component or
            Privileged Zone). If the calculated score lands in the CRITICAL
            range, cap the score at **7.9** and downgrade the priority to HIGH.
            *Exception:* Do NOT cap at HIGH if the component is core in-cluster
            infrastructure (e.g., CNI, CSI, admission webhook, service mesh) AND
            the impact escapes to the host node (e.g., node-root file R/W) or
            allows cross-tenant escalation. These remain eligible for CRITICAL.
            **This rule MUST NOT fire when the `attacker_position` is
            `"EXTERNAL"` (since per the alignment rule in Section 2, the
            exposure is forced to `EXPOSED` (1.0), which precludes this cap).**
        -   **Probabilistic LLM Vectors:** Attacks relying on probabilistic LLM
            behavior (e.g., prompt injection, jailbreaking) to trigger a
            vulnerability. Cap at **HIGH** (7.9) and default to **MEDIUM** or
            **LOW**. *Exception:* If the attacker can query the LLM/system
            repeatedly without rate limits, concurrency limits, or security
            blocking/alerting that would impede the attack (allowing them to
            brute-force and effectively eliminate the non-determinism), this cap
            may be lifted.
        -   **Supply-Chain / Build-Time Prerequisites:** If the exploit requires
            the attacker to already possess a supply-chain position (e.g.,
            ability to poison dependencies, modify upstream source) or write
            access to the build pipeline to trigger the vulnerability. Cap at
            **HIGH (7.9)** since the entry barrier is extremely high, but the
            downstream compromise is systemic. (Force-downgrade to LOW/2.0 only
            if they already possess shell access on the target, as per the
            Prerequisite Shell Access rule).
        -   **Non-Default Configurations:** Findings that are only exploitable
            under non-default configurations. Cap at **HIGH (7.9)** to reflect
            the additional configuration barrier.

        -   **Confidential Computing Host Attacks:** If the attacker position is
            `HOST_SYSTEM` (the host OS or hypervisor attacking guest enclaves or
            confidential VMs) in Confidential Computing deployments. Cap at
            **HIGH (7.9)** because while the host has full control of the
            platform, confidential computing enclaves are designed to protect
            against host-level compromise. (If not a CC deployment, see the
            Standard Host-to-Guest Attacks rule under LOW).

    *   **Force-Cap to MEDIUM (Cap at 5.9 / Maximum MEDIUM Priority):**

        -   **Local Attack Vector:** Vulnerabilities requiring local shell
            access (e.g., local privilege escalation, SUID exploitation) without
            VM escape. (Downgrade to LOW/2.0 if it only affects a single user's
            isolated data).
        -   **Intra-Customer / Same-Tenant:** Attacks restricted to the same
            tenant boundary the attacker already controls, with no cross-tenant
            escalation or host compromise.
        -   **Rarely Exposed Components:** Findings in components documented as
            'rarely exposed' or 'unlikely to be user controlled'.
        -   **Equivalent Primitives (No Boundary Breach):** The attacker profile
            capable of triggering the vulnerability already possesses equivalent
            access, privileges, or capabilities (primitives) through standard
            system features (e.g., an admin exploiting a bug to download a file
            they can already download via the UI). Cap at **MEDIUM (5.9)** to
            maintain visibility for defense-in-depth cleanup.
        -   **Documented Insecure Configurations:** Non-default configurations
            that are explicitly documented in public manuals as insecure,
            diagnostic-only, or strictly non-production. Cap at **MEDIUM
            (5.9)**.

        -   **Physical Temporary Access:** If the attack requires temporary
            physical access to the device (e.g., USB key insertion, evil maid
            attacks) without long-term laboratory analysis. Cap at **MEDIUM
            (5.9)**.

        -   **High-Privilege External Access:** Exploits with
            `attacker_position: "EXTERNAL"` that require `privileges_required:
            "HIGH"` (e.g., admin RCE on public portals). Cap at **MEDIUM
            (5.9)**, unless the exploit results in escaping the container
            boundary (to host node) or cross-tenant escalation.

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
    -   `"outrage_commentary"` (your reasoning about the outrage factor)
    -   `"executive_summary"`

Save your updates to the individual finding files. When complete, notify the
user.

# Mantis Skills State Schema Reference

This document serves as the inter-stage contract for harness builders. It
defines the structure of the JSON objects and files that the Mantis skills read
and write.

## 1. Finding Object (`workspace/findings/<uuid>.json`)

The finding object is the core state unit for a discovered vulnerability. It
evolves sequentially as different skills process it.

### Base Fields (Written by `/mantis_researcher`)

-   **`id`** (String): Unique identifier matching the filename.
-   **`title`** (String): A concise summary of the vulnerability.
-   **`description`** (String): Detailed explanation of the flaw and its
    mechanism.
-   **`code_paths`** (Array of Strings): Exact locations of the flaw (e.g.,
    `["src/auth.c:145"]`, binary memory addresses, function offsets, or specific
    files within an extracted firmware blob).
-   **`impact`** (String): The potential consequence of the vulnerability.
-   **`severity`** (Enum): Initial severity estimate (`"CRITICAL"`, `"HIGH"`,
    `"MEDIUM"`, `"LOW"`, `"INFO"`).
-   **`mitigation`** (String): Recommended corrective modification.
-   **`history`** (Array of Objects): A chronological log of actions taken on
    this finding.
    -   Format: `{"stage": "string", "action": "string", "details": "string"}`

### Validation Fields (Written by `/mantis_review`)

-   **`status`** (Enum): The validity of the finding.
    -   Values: `"VALID"`, `"FALSE_POSITIVE"`
-   **`reasoning`** (String): The reviewer's independent rationale for the
    status.
-   **`repro_hints`** (String): Instructions for the reproducer agent on how to
    trigger the bug.

### Viability Fields (Written by `/mantis_critic`)

-   **`production_viability`** (Enum): Whether the bug is triggerable in a
    release build.
    -   Values: `"VIABLE"`, `"NON_VIABLE"`
-   **`critic_reasoning`** (String): Rationale for viability (e.g., "Not
    protected by allocator padding").

### Reproduction Fields (Written by `/mantis_reproduce`)

-   **`repro_status`** (Enum): The outcome of the reproduction attempt.
    -   Values: `"reproduced"`, `"failed_to_reproduce"`
-   **`repro_file_path`** (String): Path to the generated PoC script or payload.
-   **`run_command`** (String): The exact command used to execute the PoC.
-   **`repro_output`** (String): Standard output and error from the sandbox run.

### Chain / Super Finding Overrides (Written by `/mantis_chain`)

*Note: Chains are written as net-new `UUID.json` files that inherit the Base
Fields schema, but with the following specific formatting.*

-   **`title`** (String): Must explicitly contain "Exploit Chain" and list the
    impact and underlying findings.
-   **`code_paths`** (Array of Strings): The union of all file paths involved in
    the multi-step chain.
-   **`history`** (Array of Objects): Must include an entry detailing which
    underlying UUIDs were chained together.

### Patch Fields (Written by `/mantis_patch` (incl. re-attack))

-   **`patch_status`** (Enum): The outcome of the patching and re-attack
    attempts.
    -   Values: `"VERIFIED_SECURE"`, `"VERIFICATION_FAILED"`, `"ERROR"`
-   **`patch_diff`** (String): The unified diff of the verified fix, OR for
    binary-only targets, a general recommendation on how this could be mitigated
    in a production environment.
-   **`reattack_status`** (Enum): The outcome of the variant-hunting re-attack
    attempt against the patch.
    -   Values: `"bypassed_patch"`, `"failed_to_bypass"`
-   **`reattack_file_path`** (String): Path to the newly generated re-attack
    script.
-   **`reattack_run_command`** (String): The exact execution command used for
    the re-attack.
-   **`reattack_output`** (String): Standard output and error from the re-attack
    run.

### Calibration Fields (Written by `/mantis_calibrate`)

-   **`impact_score`** (Integer: 1-5): The calculated impact on CIA triad.
-   **`likelihood_score`** (Integer: 1-5): The probability of occurrence or
    exploitation.
-   **`mantis_risk_score`** (Float: 0.1-10.0): The final calculated risk score
    (Hazard).
-   **`priority`** (String): Qualitative priority bucket (e.g., `"CRITICAL"`,
    `"HIGH"`, `"MEDIUM"`, `"LOW"`).
-   **`outrage_commentary`** (String): Reasoning about the outrage factor (e.g.
    reputational damage).
-   **`executive_summary`** (String): High-level summary of the risk for
    stakeholders.

--------------------------------------------------------------------------------

## 2. Planning State (`plan.json`)

Written by `/mantis_plan`, read by `/mantis_researcher`.

-   **`investigations`** (Array of Objects): A list of targeted investigations
    for the current pass.
    -   **`title`** (String): Title of the investigation (e.g., "Exhaustive
        Review: src/api").
    -   **`target_files`** (Array of Strings): The exact file paths the
        researcher should audit.
    -   **`kb_references`** (Array of Strings): Target file paths to the
        Markdown Knowledge Base (e.g., `["workspace/kb/entities/auth.md"]`) to
        provide exact context for the investigation.
    -   **`question`** (String): Detailed prompting instructions asking the
        researcher to trace specific input pathways or constraints.

--------------------------------------------------------------------------------

## 3. Historical Learning State (`learnings.jsonl`)

Appended by `/mantis_review`, `/mantis_reflect`, `/mantis_critic`, and
`/mantis_patch`. Read and explicitly cleared by `/mantis_architecture`.

Each line is a JSON object representing a finalized outcome or an insight from a
trajectory.

-   **Format:** `{"type": "trajectory_insight", "action": "add | update |
    remove", "target_entity": "[e.g., auth_module.py]", "insight":
    "[description]", "source_stage": "[e.g., mantis_researcher]"}`
-   Alternatively for findings: `{"title": "[finding_title]", "code_paths":
    ["[path1:line1]"], "status": "[VIABLE / NON_VIABLE / FALSE_POSITIVE /
    VERIFIED_SECURE / VERIFICATION_FAILED / ERROR]"}`

This file serves as an ephemeral inbox/queue for new learnings. It is
periodically synthesized into the permanent Markdown Knowledge Base
(`workspace/kb/`) to prevent infinite loops and token bloat.

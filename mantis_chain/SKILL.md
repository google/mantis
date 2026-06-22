---
name: mantis_chain
description: >-
  Analyzes individual security findings to identify and construct complex exploit chains.
  Use after validation stages to see if multiple low-severity bugs can be combined into a higher impact vulnerability.
  Don't use for initial codebase auditing or writing patch code.
---

# Vulnerability Chainer (/mantis_chain)

## System Goal

Exploit Chain Architect. Analyzes isolated, individually-validated security
findings and historical knowledge base primitives to identify and construct
complex, multi-step exploit chains.

## Command Definition

-   **Command:** `/mantis_chain`
-   **Description:** Analyzes individual security findings to identify and
    construct complex exploit chains.

## Instructions

Read the current batch of validated findings and explore whether multiple
seemingly low-severity or disparate vulnerabilities can be sequentially combined
to achieve a higher-impact compromise.

Execute the chaining stage as follows:

1.  **Load Primitives & Validated Findings:**

    -   Read the JSON files in the `workspace/findings/` directory. Filter for
        findings that have passed validation (e.g., status is `"VALID"` or
        viability is `"VIABLE"`).
    -   Read the Markdown Knowledge Base (`workspace/kb/entities/` and
        `workspace/kb/vulnerabilities/`) to identify architectural primitives
        that might not be bugs on their own, but could serve as stepping stones
        (e.g., "User controls file upload path", "Service runs as root").

2.  **Cross-Finding Analysis (The Chaining Matrix):**

    -   Analyze the preconditions and postconditions of each validated finding.
    -   Ask: *Can the output or side-effect of Finding A satisfy the strict
        precondition required to trigger Finding B?*
    -   Example Chains to look for:
        -   **Path Traversal + Loose Permissions = RCE:** A low-severity path
            traversal (Finding A) allows writing to `/tmp`, but a separate
            misconfiguration (Finding B) allows a cron job to execute scripts in
            `/tmp`.
        -   **XSS + CSRF = Account Takeover:** A stored XSS (Finding A) can be
            used to harvest an anti-CSRF token to execute a state-changing
            action (Finding B).
        -   **Info Leak (Memory Revelation) + Buffer Overflow = ASLR Bypass:**
            An info leak (Finding A) reveals base pointers, satisfying the
            precondition to exploit a stack buffer overflow (Finding B).

3.  **Construct "Super Findings":**

    -   If a viable exploit chain is discovered, do **NOT** modify or delete the
        original isolated findings. They still need to be patched individually.
    -   Instead, generate a **net-new UUID** and create a new finding JSON file
        in `workspace/findings/<new_uuid>.json`.
    -   This "Super Finding" must clearly document the sequence of execution.

    ### Chain Findings Schema Format (Per File)

    ```json
    {
      "id": "A unique identifier generated for this chain finding. Must match filename.",
      "title": "Exploit Chain: [Impact] via [Finding A] and [Finding B]",
      "description": "Step-by-step documentation of the exploit chain. Start with Step 1 (Triggering Finding A) and explain how its outcome feeds into Step N (Triggering Finding Z).",
      "impact": "The combined, escalated impact of the chain (e.g., Remote Code Execution, Full Database Exfiltration). This should be higher than the individual findings.",
      "severity": "CRITICAL / HIGH",
      "code_paths": [
        "relative/file/path_A.c:line_number",
        "relative/file/path_B.c:line_number"
      ],
      "mitigation": "Recommended strategy to break the chain. Usually involves fixing at least one, if not all, of the underlying links.",
      "history": [
        {
          "stage": "chainer",
          "action": "created",
          "details": "Constructed by chaining findings [UUID_A] and [UUID_B]."
        }
      ]
    }
    ```

4.  **Chain Deduplication Tagging:**

    -   To ensure `/mantis_dedupe` treats these chains differently than raw
        findings, ensure the word "Chain" is prominently featured in the
        `"title"` and `"history"` fields as shown in the schema.

Ensure any newly constructed chain files are written to the
`workspace/findings/` directory. When complete, notify the user.

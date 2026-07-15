---
name: mantis_report
description: >-
  Generates a human-readable security review packet compiled from reproduced findings.
  Use at the end of a review cycle to produce stakeholder-facing documentation.
  Don't use for auditing code or verifying patches directly.
---

# Reporter (/mantis_report)

## System Goal

Security Reporting Expert. Synthesizes complex, technical finding logs into a
high-quality, human-readable review packet for developers and stakeholders.

## Command Definition

-   **Command:** `/mantis_report`
-   **Description:** Generates a human-readable security review packet
    containing only reproduced findings.

## Instructions

Compile a professional Markdown report detailing only the verified and
reproduced vulnerabilities.

Execute the reporting stage as follows:

1.  **Load and Filter Findings:**

    -   Read all JSON files from the `workspace/findings/` directory.
    -   **Strict Filter:** Include only actionable findings. You MUST include:
        1.  Findings where `repro_status` is `"reproduced"`.
        2.  Findings where `repro_status` is `"statically_confirmed"` BUT
            contain valid external stack traces, sanitizer traces (e.g.
            ASan/UBSan), or crash logs proving empirical execution impact
            (treated as empirically reproduced by calibration).
        3.  Valid Exploit Chains (constructed by the chainer, identified by
            "Exploit Chain" in the title/history) even if they inherited a
            status of `"statically_confirmed"`. Do **not** include false
            positives, non-viable findings, findings that failed to reproduce,
            or ordinary statically confirmed findings that lack empirical
            execution traces.
    -   **Severity Filtering:** Exclude findings with a priority of `"LOW"` or
        `"INFO"` from the main report body. You must place these lower-priority
        issues into a separate, dedicated "Appendix: Low and Info Severity
        Findings" section at the very end of the report, keeping the main report
        focused on high-risk issues.

2.  **Extract Key Artifacts:** For each reproduced finding, extract and format:

    -   **Header Metadata:** Title, ID (UUID), Inferred Exposure, Final Risk
        Score, and Qualitative Priority.
    -   **Vulnerability Description & Impact:** A clear explanation of the bug
        and the concrete impact on the system.
    -   **Reproduction Evidence:**
        -   The PoC script path (`repro_file_path`) and execution command
            (`run_command`).
        -   A clean snippet of the stdout/stderr showing the successful exploit
            trigger (`repro_output`).
    -   **Risk Rationale:** The independent validation reasoning (`reasoning`),
        production viability reasoning (`critic_reasoning`), and outrage factor
        analysis (`outrage_commentary`).
    -   **Remediation & Patch:**
        -   The recommended mitigation strategy.
        -   The verified patch diff (`patch_diff`) and re-attack status to prove
            the fix is resilient.
    -   **PII & Secrets Redaction:** Before writing any finding data (including
        description, PoC script/command, and reproducer logs) to the report, you
        **must** scan and redact any hardcoded API keys, tokens, credentials,
        PII (names, emails, phone numbers), internal hostnames/domain names, and
        overly weaponized payload parameters, replacing them with standard
        placeholders like `<REDACTED_SECRET>`, `<REDACTED_PII>`,
        `<REDACTED_INTERNAL_HOST>`, or `<REDACTED_PAYLOAD>` to ensure the report
        is safe for broader distribution.

3.  **Generate Review Packet:**

    -   **Grouping by Patch Status:** Organize the Executive Summary table and
        the main body of the report by grouping findings into three distinct
        sections based on their remediation status:
        1.  **Patch Independently Verified:** Findings where `patch_status` is
            `"VERIFIED_SECURE"` (meaning the patch was successfully verified and
            passed variant re-attack checks).
        2.  **Patch Proposed:** Findings that contain a `patch_diff` but
            `patch_status` is NOT `"VERIFIED_SECURE"`.
        3.  **Unpatched:** Findings with no `patch_diff` present, or where
            `patch_status` is `"VERIFICATION_FAILED"` or `"ERROR"`.
    -   **Pass-Numbered Output:** Do not overwrite the same `review_packet.md`
        file on every execution. Instead, determine the current run/pass number
        of the pipeline (e.g., by checking existing reports in the directory or
        tracking run sequences). Write the report to a pass-numbered file:
        `workspace/report/review_packet_pass_<N>.md` (where `<N>` is the
        sequential pass number, e.g., `review_packet_pass_1.md`).
    -   **Latest Copy/Symlink:** After writing the pass-numbered report, update
        a symlink or write a copy of the file to
        `workspace/report/review_packet-latest.md` pointing/copying to the
        newest pass report, so that the latest version is always reachable.
    -   Use clean, professional Markdown formatting with clear headers, tables
        for metadata, and syntax-highlighted code blocks for logs and diffs.
    -   Include a high-level **Executive Summary** table at the top listing all
        included findings, their priority, and their risk scores.

When complete, notify the user.

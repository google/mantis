---
name: mantis_researcher
description: >-
  Audits production source code files based on the strategy in plan.json.
  Use when a review plan exists and you need to perform static analysis and deep-dive reviews of targeted files.
  Don't use for planning, deduplicating, or writing patches.
---

# Mantis Researcher (/mantis_researcher)

## System Goal

Resilience Code Auditor. Performs rapid triage and deep-dive reviews of source
files to identify boundary checks, preconditions, missing sanitization, and
interface violations.

## Command Definition

-   **Command:** `/mantis_researcher`
-   **Description:** Audits production source code files based on the strategy
    in `plan.json`.

## Instructions

Perform a thorough memory-safety, logical-correctness, and robustness review of
the targeted codebase.

Execute the research stage as follows:

1.  **Load Reviewing Plan:** Read the `plan.json` file to retrieve the target
    investigations. If `plan.json` is missing or empty, perform a general list
    of the directories and review any primary source files.

2.  **Sub-Agent Delegation (Wave-Based Swarm Parallelization):** If the CLI or
    agent platform supports spawning sub-agents (e.g., using specialized
    sub-agent tools or multi-agent orchestrator directives):

    -   Do not execute investigations sequentially if sub-agents are supported.
        Split the investigations in `plan.json` into parallel waves to maximize
        throughput and context efficiency.
    -   **Wave 1: Lightweight Rapid Triage (Concurrency Peak):** Spawn
        concurrent, lightweight sub-agents (e.g. up to 10-20 in parallel) to
        sweep all files listed in `plan.json`. Each sub-agent should only output
        a fast classification: `{"potentially_flawed": true/false, "reason":
        "..."}`.
    -   **Wave 2: Deep Security Flaw Hotspot Audits & Parallel Trajectory
        Search:** Collect all files flagged in Wave 1. Spawn a wave of
        concurrent deep auditor sub-agents (e.g. up to 4-8 in parallel) to focus
        exclusively on those identified hotspots. For particularly complex
        files, spawn multiple subagents targeting the *same* file using either
        different prompt constraints or a diverse set of less expensive LLMs to
        explore parallel attack vectors. Rely on the subsequent deduplication
        stage to merge any overlapping findings.
    -   **Token Optimization (Distributed Writes):** Instruct the Wave 2
        sub-agents to generate unique UUIDs and write their findings directly to
        individual `workspace/findings/<id>.json` files on disk. Do not ask them
        to return the full JSON payload in their messages back to you, as
        aggregating them will blow out your context window. Ask them to only
        return the list of UUIDs they created.
    -   If sub-agents or concurrency are not supported by the current
        environment, fall back to performing the sweeps and deep-dives
        sequentially.

3.  **Exhaustive Interface and Call-Site Reviewing:** If a target source file
    defines public or API functions (such as numeric parsers, decoders,
    encoders, or converters) that document explicit size constraints or safety
    requirements (e.g., expecting callers to allocate buffers of a certain
    size):

    -   Search the codebase to find and review all call-sites of these functions
        across the entire repository to ensure the safety contracts are
        respected globally.
    -   Read the calling files and verify if every call-site strictly adheres to
        input constraints, properly manages bounds, and checks sizes.
    -   Flag any discrepancies as contract alignment bugs or missing checks.

4.  **Compile and Write Findings:** Instead of a single monolithic file, create
    a `workspace/findings/` directory if it does not exist. For each potential
    finding, generate a unique UUID and write a valid JSON object into an
    individual file named `workspace/findings/<id>.json`. This keeps findings
    isolated and prevents token limit issues during subsequent analysis. Do not
    include any text before or after the JSON in the files.

### Findings Schema Format (Per File)

```json
{
  "id": "A unique identifier generated for this finding (e.g., a UUID or random hash). This must be included and match the filename.",
  "title": "Authorization bypass or Memory bounds violation in [function_name]",
  "description": "Thorough root cause analysis detailing why the function is flawed under untrusted input.",
  "impact": "Exploit outcome (e.g., Privilege escalation, Memory corruption, Data exfiltration).",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW / INFO",
  "code_paths": ["relative/file/path.c:line_number"],
  "mitigation": "Recommended corrective modification.",
  "history": [
    {
      "stage": "researcher",
      "action": "created",
      "details": "Initial audit finding recorded."
    }
  ]
}
```

Ensure all individual finding files are written to the `workspace/findings/`
directory. When complete, notify the user.

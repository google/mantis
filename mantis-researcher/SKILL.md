---
name: mantis-researcher
description: >-
  Audits production source code files based on the strategy in workspace/plan.json.
  Use when a review plan exists and you need to perform static analysis and deep-dive reviews of targeted files.
  Don't use for planning, deduplicating, or writing patches.
---

# Mantis Researcher (/mantis-researcher)

## System Goal

Resilience Code Auditor. Performs rapid triage and deep-dive reviews of source
files to identify boundary checks, preconditions, missing sanitization, and
interface violations.

## Command Definition

- **Command:** `/mantis-researcher`
- **Description:** Audits production source code files based on the strategy in
  `workspace/plan.json`.

## Input/Output Contract

- **Reads**:
  - `workspace/plan.json` (falls back to codebase sweep if missing/empty).
  - `workspace/.mantis_state.json` (to track current loop pass).
  - referenced Markdown files in `"kb_references"` (e.g.
    `workspace/kb/entities/*.md`).
  - Target source code files.
- **Writes**:
  - Raw finding files to `workspace/findings/<uuid>.json` (creates
    `workspace/findings/` if missing).
- **Preconditions**:
  - Target files must be accessible.
- **Idempotency Guarantee**:
  - Writes new findings as separate files with unique UUIDs. Rely on
    `mantis-dedupe` to cluster and merge duplicate findings on subsequent steps.

## Instructions

Perform a thorough memory-safety, logical-correctness, and robustness review of
the targeted codebase.

Execute the research stage as follows:

1. **Load Reviewing Plan & Context:** Read the active pass number from
   `workspace/.mantis_state.json` and resolve the current ISO 8601 timestamp.
   Read the `workspace/plan.json` file to retrieve the target investigations. If
   `workspace/plan.json` is missing or empty, perform a general list of the
   directories and review any primary source files. If the investigation
   contains a `"kb_references"` array, explicitly read those Markdown files
   (e.g., `workspace/kb/entities/auth.md`) to gain compounded historical context
   before you begin auditing the `"target_files"`.

2. **Sub-Agent Delegation (Wave-Based Swarm Parallelization):** If the CLI or
   agent platform supports spawning sub-agents (e.g., using specialized
   sub-agent tools or multi-agent orchestrator directives):

   - Do not execute investigations sequentially if sub-agents are supported.
     Split the investigations in `workspace/plan.json` into parallel waves to
     maximize throughput and context efficiency.
   - **Wave 1: Lightweight Rapid Triage (Concurrency Peak):** Spawn concurrent,
     lightweight sub-agents (e.g. up to 10-20 in parallel) to sweep all files
     listed in `workspace/plan.json`. Each sub-agent should only output a fast
     classification: `{"potentially_flawed": true/false, "reason": "..."}`.
   - **Wave 2: Deep Security Flaw Hotspot Audits & Parallel Trajectory Search:**
     Collect all files flagged in Wave 1. Spawn a wave of concurrent deep
     auditor sub-agents (e.g. up to 4-8 in parallel) to focus exclusively on
     those identified hotspots. For particularly complex files, spawn multiple
     subagents targeting the *same* file using either different prompt
     constraints or a diverse set of less expensive LLMs to explore parallel
     attack vectors. Rely on the subsequent deduplication stage to merge any
     overlapping findings.
   - **Token Optimization (Distributed Writes):** Instruct the Wave 2 sub-agents
     to generate unique UUIDs and write their findings directly to individual
     `workspace/findings/<id>.json` files on disk. Do not ask them to return the
     full JSON payload in their messages back to you, as aggregating them will
     blow out your context window. Ask them to only return the list of UUIDs
     they created.
   - If sub-agents or concurrency are not supported by the current environment,
     fall back to performing the sweeps and deep-dives sequentially.

3. **Exhaustive Interface and Call-Site Reviewing:** If a target source file
   defines public or API functions (such as numeric parsers, decoders, encoders,
   or converters) that document explicit size constraints or safety requirements
   (e.g., expecting callers to allocate buffers of a certain size):

   - Search the codebase to find and review all call-sites of these functions
     across the entire repository to ensure the safety contracts are respected
     globally.
   - Read the calling files and verify if every call-site strictly adheres to
     input constraints, properly manages bounds, and checks sizes.
   - Flag any discrepancies as contract alignment bugs or missing checks.

4. **Unconstrained / Exploratory Investigations:** If the investigation plan in
   `workspace/plan.json` contains instructions or a question explicitly asking
   for an unconstrained sweep or adversarial audit (ignoring existing
   assumptions):

   - Ignore existing assumptions of safety and documented trust boundaries in
     `workspace/kb/THREAT_MODEL.md`.
   - Treat all inputs and boundaries as untrusted and potentially malformed.
   - Analyze implementation from scratch with full freedom and autonomy,
     searching for any bypasses, logic flaws, or memory corruptions regardless
     of whether the component is thought to be safe or out of scope.

5. **Compile and Write Findings:** Instead of a single monolithic file, create a
   `workspace/findings/` directory if it does not exist. For each potential
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
  "severity": "CRITICAL / HIGH / MEDIUM / LOW",
  "privileges_required": "NONE / LOW / HIGH",
  "attacker_position": "EXTERNAL / INTERNAL_NETWORK / IN_CLUSTER / LOCAL / HOST_SYSTEM / SUPPLY_CHAIN / PHYSICAL_TEMPORARY / PHYSICAL_LONG_TERM",
  "user_interaction": "NONE / REQUIRED",
  "status": "PROVISIONALLY_VALID",
  "code_paths": ["relative/file/path.c:line_number"],
  "mitigation": "Recommended corrective modification.",
  "history": [
    {
      "stage": "researcher",
      "action": "created",
      "details": "Initial audit finding recorded.",
      "pass_number": <current_pass_number>,
      "timestamp": "<current_iso8601_timestamp>"
    }
  ]
}
```

Ensure all individual finding files are written to the `workspace/findings/`
directory. When complete, notify the user.

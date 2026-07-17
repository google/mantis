---
name: mantis-history
description: >-
  Analyzes the repository's version control system (VCS) history to extract past vulnerabilities, security fixes, and vulnerability patterns.
  Use as an initial pre-processing step to build a historical vulnerabilities database (workspace/historical_learnings.jsonl) that informs subsequent stages about past issues and fixes.
  Don't use for code reviews, writing test scripts, or patching code.
---

# History Analyzer (/mantis-history)

## System Goal

Historical Vulnerability Extractor. Analyzes repository's version control system
(VCS) history to extract past vulnerabilities, security-related fixes, patches,
and associated files, creating a historical learnings database to inform
downstream skills.

## Command Definition

- **Command:** `/mantis-history`
- **Description:** Analyzes repository's version control system (VCS) history to
  extract past vulnerabilities and fixes, producing a structured historical
  learnings file (`workspace/historical_learnings.jsonl`).

## Input/Output Contract

- **Reads**:
  - `workspace/.mantis_state.json` (to track current loop pass).
  - Codebase directory structure and key files (to determine stack).
  - VCS history logs (commit messages, titles, diffs).
  - `mantis-summary.md` (optional, if available).
  - Internal history analysis cache (optional, if exists).
- **Writes**:
  - VCS extraction script (written on-the-fly to workspace).
  - `workspace/historical_learnings.jsonl`.
  - Internal history analysis cache.
- **Preconditions**:
  - Target repository and VCS logs must be accessible.
- **Idempotency Guarantee**:
  - The extraction script maintains a local cache of analyzed `revision_id`s,
    skipping any already processed commits.

## Instructions

Your task is to analyze the codebase architecture, determine what constitutes
security-relevant history, and write a script on-the-fly to extract and document
historical vulnerabilities from the project's version control system (VCS).

Execute the history analysis stage as follows:

1. **Phase 1: Analyze Codebase and Define Target History:**

   - Read existing summaries (e.g. `mantis-summary.md` if available) or quickly
     inspect the root codebase structure to understand the primary files,
     programming languages, and core components.
   - Determine what types of historical security issues (e.g., memory
     corruption, authentication bypass, SQL injection, buffer overflow, or
     others) are relevant to this project and what keywords or commits should be
     targeted.

2. **Phase 2: Write a History Extraction Script:**

   - Read the active pass number from the state file
     `workspace/.mantis_state.json` and resolve the current ISO 8601 timestamp.
   - Write a script (e.g. Python, bash, or your choice) directly in your
     workspace that interacts with your repository version control system (VCS)
     history logs.
   - **Cost-Efficiency & Scale Optimization:** To ensure the historical analysis
     remains cost-effective and runs efficiently, the script must implement the
     following optimizations:
     - **Commit Message/Description Pre-filtering:** Before retrieving diffs,
       the script should dynamically determine relevant keywords for commit
       message screening. It can do this by first inspecting the repository's
       files and languages/domains in scope to establish its primary stack (e.g.
       software versus hardware/RTL), then either querying an LLM/analysis agent
       for a tailored list of security/bug keywords or using a broader set of
       keywords augmented with these specific domain terms. Skip revisions whose
       messages or titles do not match these relevant keywords to avoid
       unnecessarily retrieving and analyzing changesets that are irrelevant to
       the codebase in scope.
     - **Diff Filtering and Size Limits:** Ignore commits that only touch
       non-production code (e.g., tests, documentation, or configuration files).
       Skip commits with excessively large diffs (e.g., more than several
       thousand lines changed), as they are usually automated formatting changes
       or massive refactorings rather than discrete security patches.
     - **Caching Results:** The script should maintain a local cache (e.g., in a
       JSON or SQLite file) mapping `revision_id` to whether it was analyzed. If
       a revision has already been processed and cached, skip it. This makes
       repeated historical analyses instant and zero-cost.
     - **Batch Processing (Batching Diffs):** Instead of making one LLM call per
       commit diff, the script should batch multiple commit diffs and messages
       (e.g. 3 to 5 commits) into a single LLM call. Ask the LLM to analyze all
       commits in the batch and return a JSON array of findings for the batch,
       reducing request overhead and cost.
     - **Model Selection:** Use lightweight and cost-efficient models for the
       initial commit analysis/filtering, and only fall back to heavier model
       tiers if deeper verification of a suspected vulnerability is needed.
   - **Detailed Analysis:** For revisions or commits that look
     security-relevant, the script should retrieve the commit diffs and
     messages/change descriptions.
   - **LLM/Agent Analysis:** The script should make API calls (e.g., via
     subagent messages or Agent API subcommands) or use an LLM subagent to
     analyze the changes' diffs and messages to determine whether a
     revision/commit was a security fix, what component was affected, the
     vulnerability type, impact, and the mitigation diff. Make sure it uses
     batching and caching to minimize API calls.
   - **Missing Information:** Do not overindex on the lack of security-related
     keywords. Many security fixes do not get CVEs, and many security
     vulnerabilities are fixed without realizing they were vulnerabilities.
   - **Output Format:** Instruct your script to output the extracted findings
     into a JSONL file named `workspace/historical_learnings.jsonl`, matching
     the following format:

### Historical Learnings Schema Format (`workspace/historical_learnings.jsonl`)

```json
{
  "revision_id": "...",
  "title": "...",
  "description": "...",
  "code_paths": ["file:line_number"],
  "vuln_type": "...",
  "mitigation_diff": "...",
  "cve": "...",
  "history": [
    {
      "stage": "history_extractor",
      "action": "created",
      "details": "Extracted from repository revision history.",
      "pass_number": <current_pass_number>,
      "timestamp": "<current_iso8601_timestamp>"
    }
  ]
}
```

1. **Phase 3: Execute and Verify:**
   - Run the script you just wrote to analyze the VCS history, process
     revisions, and generate the `workspace/historical_learnings.jsonl` file.
   - Wait for the script to finish and verify that
     `workspace/historical_learnings.jsonl` has been written successfully and
     contains extracted data.

When complete, notify the user.

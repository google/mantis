---
name: mantis_plan
description: >-
  Formulates a targeted defensive security reviewing plan based on the active threat model and historical learnings.
  Use when starting a security review campaign to map the codebase boundaries and generate a roadmap (plan.json).
  Don't use for executing code reviews, writing test scripts, or patching code.
---

# Strategist (/mantis_plan)

## System Goal

Security Architect. Analyzes code structure, directory metadata, and historical
records to map the external boundary and formulate an adaptive review roadmap.

## Command Definition

-   **Command:** `/mantis_plan`
-   **Description:** Formulates a targeted defensive security reviewing plan
    based on the active threat model and historical learnings.

## Instructions

Analyze the repository structure and create a detailed defensive security review
plan that avoids duplication of prior efforts while digging deep into complex
inter-procedural paths and un-scanned code boundaries.

Execute the planning stage as follows:

1.  **Check for Threat Model Context:** Check the root of the workspace
    directory for a `THREAT_MODEL.md` file. If it exists, read the file it
    completely to understand the program's official security boundaries, threat
    actors, assets, high-risk interfaces, and trusted inputs.

2.  **Determine Mode & Retrieve Learnings:** Check if the workspace contains a
    `learnings.jsonl` file.

    -   **MODE A: First-Pass Exhaustive Mode (No `learnings.jsonl` found):** If
        this is the first run, guarantee complete coverage of the codebase. To
        avoid hitting output token limits on large repositories, do not generate
        the `plan.json` manually in your text response. Instead, execute a shell
        command to run a short script in your preferred language that:

        1.  Uses `find` or `os.walk` to crawl all production source code files
            (e.g., `.c`, `.cpp`, `.py`, `.js`, `.go`, `.rs`, `.java`).
        2.  Ignores test folders, build artifacts, and vendor dependencies
            (e.g., `node_modules`, `.git`, `tests/`).
        3.  Programmatically formats the list into the `plan.json` schema and
            writes it directly to disk. Because this is an automated script,
            instruct it to use a generic, overarching baseline question for the
            `"question"` field (e.g., "Conduct a baseline audit for memory
            safety and logic flaws"), reserving highly contextual custom
            questions for Mode B.

    -   **MODE B: Strategic Learning Mode (`learnings.jsonl` exists):** Read
        `learnings.jsonl` to review previously analyzed files, findings, and
        repair statuses. Adapt your focus to design new, targeted deep dives
        (e.g., tracing complex untrusted data flow across files, reviewing
        adjacent components, regression reviews) rather than repeating
        exhaustive file-by-file reviews. List the contents of the directory to
        explore specific areas. You may generate the `plan.json` manually using
        your file-writing tools for this mode, as the scope will be much
        narrower. **Token Optimization:** Whether using a script (Mode A) or
        your file-writing tools (Mode B), write the plan directly to disk and do
        not print the JSON contents in your chat response.

3.  **Schema Enforcement:** Regardless of the mode, the final `plan.json` file
    written to disk should match the following schema to ensure downstream
    auditing agents can parse it correctly:

### Plan Schema Format

```json
{
  "investigations": [
    {
      "title": "Exhaustive Review: [relative_file_path]",
      "target_files": ["[relative_file_path_1]", "[relative_file_path_2]"],
      "question": "Detailed reviewing prompt instructions asking the researcher to trace specific input pathways, variables, memory allocations, or function constraints."
    }
  ]
}
```

Ensure `plan.json` is successfully written. When you have finished, notify the
user.

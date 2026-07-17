---
name: mantis-summarize
description: >-
  Pre-processes the repository by generating security-focused summaries (mantis-summary.md) for each directory to make planning and research more efficient.
  Use when starting a review campaign to map the codebase before threat modeling and planning.
  Don't use for executing code reviews, writing test scripts, or patching code.
---

# Summarizer (/mantis-summarize)

## System Goal

Repository Mapper. Automates the generation of security-focused, deterministic
summaries of directory contents to reduce token overhead for downstream planning
and research stages.

## Command Definition

- **Command:** `/mantis-summarize`
- **Description:** Pre-processes the repository by generating security-focused
  summaries (`mantis-summary.md`) for each directory to make planning and
  research more efficient.

## Input/Output Contract

- **Reads**:
  - `workspace/.mantis_state.json` (to track current loop pass).
  - Codebase directories and source files (excluding `node_modules`, `vendor`,
    `.git`, build outputs, and `tests/`).
  - Child directory summaries (`mantis-summary.md` files from subdirectories).
  - `workspace/historical_learnings.jsonl` (optional, to enrich summaries).
- **Writes**:
  - Traversal script to workspace.
  - `mantis-summary.md` file in each directory containing source code.
- **Preconditions**:
  - Source files and directory structure must be present.
- **Idempotency Guarantee**:
  - Deterministically overwrites existing `mantis-summary.md` files in-place
    with updated rollups.

## Instructions

Your task is to write and execute a script that will traverse the repository
directory tree and create a `mantis-summary.md` file in each directory
containing source code.

This is an **optional pre-processing phase** designed to drastically reduce the
context window size required for the strategist (`/mantis-plan`), and provide a
quick reference map for researchers (`/mantis-researcher`) and threat model
generator (`/mantis-threat-model`).

Execute the summarize stage as follows:

1. **Write the Traversal Script (Bottom-Up Hierarchical):** Write a script
   (e.g., Python or bash) in your workspace that walks the repository directory
   tree using a **bottom-up (post-order) traversal**.

   - The script must ignore non-source-code directories such as `node_modules`,
     `vendor`, `.git`, build outputs, and `tests/`.
   - By traversing bottom-up, the script ensures that subdirectories are
     summarized *before* their parent directories.
   - When analyzing a directory, the script should pass the LLM the local source
     files in that directory **PLUS** the `mantis-summary.md` files of its
     immediate subdirectories. Do not pass the raw source files of
     subdirectories to the parent.
   - When analyzing very large directories, context window size might become a
     problem. Instead of passing files and directory summaries in bulk, generate
     per-file summaries or operate in more efficient chunks to avoid passing too
     many tokens for the LLM to handle.

2. **Generate the Security Summary (Map-Reduce):** The script should read
   `workspace/historical_learnings.jsonl` (if it exists) to check for past
   vulnerabilities and security fixes associated with files in the current
   directory, and pass them in context. The script should instruct the LLM or
   agent tool to generate a concise, security-focused summary of the directory.
   To keep token lengths reasonable at higher levels of the directory tree, the
   LLM should abstract away lower-level details, focusing on the rolled-up
   architecture. The prompt used by your script should ask for:

   - **Core Components:** What are the primary files and subdirectories, and
     what do they do?
   - **API Endpoints & Exports:** What functions or classes are exposed to other
     modules?
   - **Trust Boundaries & External Inputs:** Does this directory handle
     untrusted data, network requests, or user input?
   - **Sensitive Operations:** Are there parsers, cryptographic functions, or
     memory management operations?
   - **Historical Vulnerabilities & Fixes:** What files or components in this
     directory have historical vulnerabilities or security-related fixes
     recorded in `workspace/historical_learnings.jsonl`? Summarize the past
     fixes, components affected, and vulnerability classes to highlight past
     regressions or recurring weaknesses.

   The summary must be a reasonable size to incorporate into work on larger
   problems, so aim for several thousand words or fewer.

3. **Output to `mantis-summary.md`:** The script must write the resulting
   summary into a file named `mantis-summary.md` inside the corresponding
   directory. Overwrite it if it already exists.

4. **Execute the Script:** Run the script you just wrote to generate all the
   summaries across the repository. Wait for it to finish successfully.

When complete, notify the user.

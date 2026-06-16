---
name: mantis_threat_model
description: >-
  Generates or updates the THREAT_MODEL.md using historical review findings and architectural context.
  Use when starting a review campaign to establish context, or after findings are validated to update the living threat model with empirical data.
  Don't use for writing code, executing tests, or generating patches.
---

# Threat Modeler (/mantis_threat_model)

## System Goal

Security Architect. Iteratively develops and refines the project's living threat
model based on empirical security flaw data and historical learnings.

## Command Definition

-   **Command:** `/mantis_threat_model`
-   **Description:** Generates or updates the `THREAT_MODEL.md` using historical
    review findings and architectural context.

## Instructions

Maintain a living Threat Model for the repository, helping it dynamically evolve
as new security flaws are discovered and patched in the continuous review loop.

Execute the threat modeling process as follows:

1.  **Load Current State:**

    -   Check if `THREAT_MODEL.md` exists in the workspace root. If it exists,
        read the file. If it does not exist, prepare to create it from scratch
        by quickly reviewing the root codebase structure.
    -   Read `learnings.jsonl` (if it exists). This file contains the empirical
        truths of the codebase—what security flaws have actually been
        reproduced, patched, or proven to be false positives.

2.  **Analyze and Synthesize:**

    -   Evaluate how recent findings from `learnings.jsonl` affect the existing
        trust boundaries. Did a verified crash reproducer demonstrate a bypass
        of a boundary we previously thought was secure?
    -   Identify new high-risk assets, flawed components, or repeated failure
        vectors (e.g., "The parser module consistently suffers from OOB reads").

3.  **Write/Update the Threat Model:** Write a comprehensive, structured
    Markdown file and save it directly to `THREAT_MODEL.md` (overwriting the old
    one). **Token Optimization:** Use your file-writing tools to write the file
    directly to disk; do not output the threat model text in your chat response.
    Include the following sections to ensure downstream planning agents have
    sufficient context:

    -   **System Overview & Architecture:** A high-level description of the
        software's components and data flow.
    -   **Trust Boundaries:** Clear definitions of where untrusted inputs meet
        internal trusted states.
    -   **High-Risk Assets:** The data, execution privileges, or availability
        targets an untrusted input source wants to compromise.
    -   **Threat Actors & Vectors:** Potential untrusted input sources (e.g.,
        untrusted local user, remote network untrusted input source).
    -   **Empirical Learnings (Living Section):** A dedicated section
        summarizing the structural weaknesses proven by recent `learnings.jsonl`
        data. Use this to explicitly warn the `/mantis_plan` and
        `/mantis_researcher` agents about areas that require ongoing resilience
        scrutiny.

Save your final output directly to `THREAT_MODEL.md`. When complete, notify the
user.

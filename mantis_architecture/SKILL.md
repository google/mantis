---
name: mantis_architecture
description: >-
  Synthesizes raw learnings and codebase analysis into an interlinked Markdown Knowledge Base (KB).
  Use at the beginning of a loop to build or update architecture.md, entities, and vulnerabilities.
  Don't use for generating threat models or formulating execution plans.
---

# Architect (/mantis_architecture)

## System Goal

Knowledge Base Synthesizer. Translates ephemeral insights from the learnings
queue (`learnings.jsonl`) and structural analysis of the codebase into a
canonical, interlinked Markdown Knowledge Base (`workspace/kb/`).

## Command Definition

-   **Command:** `/mantis_architecture`
-   **Description:** Builds the foundation of the KB by defining system
    architecture, mapping specific entities (components), and categorizing
    historical vulnerability patterns.

## Instructions

Analyze the codebase and pending learnings to construct a permanent,
Markdown-based memory for future agents.

Execute the architecture stage as follows:

1.  **Read the Inbox (`learnings.jsonl` and `historical_learnings.jsonl`):**

    -   Parse the contents of `learnings.jsonl` (and
        `historical_learnings.jsonl` if it exists). Extract all trajectory
        insights, discovered vulnerabilities, viable crash paths, and verified
        patches.

2.  **Analyze Source Code Boundaries:**

    -   Examine the directory structure and key source files. Dynamically
        identify the core components, interfaces, and trust boundaries of the
        system based on the repository's contents. This applies broadly across
        domains: whether it is a software system (e.g., identifying parsers,
        controllers, or network daemons), a hardware/RTL design (e.g.,
        identifying IP blocks, JTAG interfaces, or memory controllers),
        Infrastructure-as-Code (e.g., identifying cloud permissions, VPC
        perimeters, or deployment descriptors), or data/ML pipelines (e.g.,
        identifying data ingress points, model serialization mechanisms, or
        training boundaries).

3.  **Build or Update the Knowledge Base (KB):**

    -   Create or update files in the `workspace/kb/` directory using standard
        Markdown. Follow these strict paths:

        -   `workspace/kb/architecture.md`: High-level data flows, zone
            definitions, and system design.
        -   `workspace/kb/entities/[component_name].md`: Specific definitions
            for components (e.g., `auth_module.md`). Must include links to
            associated vulnerability classes and document known constraints
            (e.g., "This module sanitizes input X"). Incorporate trajectory
            insights here.
        -   `workspace/kb/vulnerabilities/[CWE-ID_or_BugClass].md`: Descriptions
            of bug classes (e.g., `CWE-79.md` or `Memory-Corruption.md`) that
            have been historically relevant to this codebase, including examples
            of what *not* to do.
        -   `workspace/kb/index.md`: A root catalog containing links and 1-line
            summaries to every file created above. This is the map the Planner
            will read.

    -   **Important Formatting Rules:** Use relative links to cross-reference
        entities and vulnerabilities (e.g., `[Auth
        Module](entities/auth_module.md)`). Ensure all markdown files are
        concise and focused on actionable security context.

4.  **Validate and Decay Knowledge (Drift Prevention):**

    -   Knowledge becomes stale when code is patched or refactored. Before
        finalizing the KB updates, spot-check the assertions in the existing
        `workspace/kb/entities/` against the live source code.
    -   If an entity file claims a variable is un-sanitized (based on an old
        learning) but the live code now contains a sanitization function
        (because a patch landed), **delete or correct that outdated learning**
        in the KB.
    -   If a learning is repeatedly proven wrong by the current trajectory
        insights, actively correct it to prevent the "wrong learning" from
        persisting and blinding future agents.

5.  **Clear the Inbox (State Management):**

    -   To prevent infinite loops and token bloat in future rounds, you must
        clear the queue. After all insights from `learnings.jsonl` have been
        successfully synthesized into the Markdown KB, programmatically
        **empty** the `learnings.jsonl` file. The KB is now the single source of
        truth.

When complete, notify the user.

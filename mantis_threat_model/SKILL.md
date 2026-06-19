---
name: mantis_threat_model
description: >-
  Synthesizes trust boundaries, attack surfaces, and attacker profiles into a living threat model.
  Use as Stage B of the Knowledge Base generation process, reading architecture and entity definitions from the KB.
  Don't use for analyzing source code or extracting raw learnings from JSONL files.
---

# Threat Modeler (/mantis_threat_model)

## System Goal

Security Architect. Synthesizes trust boundaries, attack surfaces, and attacker
profiles into `THREAT_MODEL.md` based exclusively on the entities and
architecture defined in the Knowledge Base (KB).

## Command Definition

-   **Command:** `/mantis_threat_model`
-   **Description:** Generates or updates `workspace/kb/THREAT_MODEL.md` using
    the structural data provided by the `/mantis_architecture` stage.

## Instructions

Maintain a high-level Threat Model that explicitly defines *who* the attackers
are and *where* they can interact with the system, relying on the pre-processed
entities in the KB.

Execute the threat modeling process as follows:

1.  **Read the Synthesized KB:**

    -   Read `workspace/kb/architecture.md` to understand the system's data
        flows and high-level design.
    -   Read the files inside `workspace/kb/entities/` to understand the
        individual components and any historical constraints or vulnerability
        patterns mapped to them by the `/mantis_architecture` stage.

2.  **Analyze Trust Boundaries:**

    -   Evaluate the entities to determine where trust boundaries lie. Where
        does untrusted data cross into a trusted context? Which components are
        exposed to external input?

3.  **Synthesize the Threat Model:**

    -   Write a comprehensive, structured Markdown file and save it directly to
        `workspace/kb/THREAT_MODEL.md` (overwriting the old one).
    -   **Token Optimization:** Use your file-writing tools to write the file
        directly to disk; do not output the threat model text in your chat
        response.

    Include the following sections to ensure downstream planning agents have
    sufficient context:

    -   **System Overview Summary:** A concise summary derived from
        `architecture.md`.
    -   **Trust Boundaries:** Clear, rigorous definitions of where untrusted
        inputs meet internal trusted states. Reference the specific entities
        (e.g., `[Auth Module](entities/auth_module.md)`).
    -   **Threat Actors & Vectors:** Define the profiles of potential attackers
        (e.g., Unauthenticated Network Attacker, Malicious Local User) and the
        specific boundaries they can reach.
    -   **High-Risk Assets:** The data, execution privileges, or availability
        targets an attacker wants to compromise.

Save your final output directly to `workspace/kb/THREAT_MODEL.md`. When
complete, notify the user.

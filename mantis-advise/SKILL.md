---
name: mantis-advise
description: >-
  Proactive security advisor and guardrail assistant for secure code development.
  Use to query threat models, historical vulnerability lineages, verified patch patterns, triaged false positives, and learned trajectory invariants before and during code edits to prevent repeat mistakes.
  Don't use for automated multi-pass red-team exploitation or fuzzing.
---

# Security Advisor (/mantis-advise)

## System Goal

Proactive Secure Development Advisor. Functions as a security guardrail and
advisory assistant for developers and coding agents. Queries Mantis threat
models, historical vulnerability lineages, verified remediation patterns,
triaged false positives, and learned trajectory invariants to ensure that new
code and refactors are implemented securely from the start.

## Command Definition

- **Command:** `/mantis-advise`
- **Description:** Queries security knowledge for a given target file or module,
  evaluates proposed changes against known threat boundaries, and provides
  verified secure implementation guidance.
- **Execution Command:**
  ```bash
  python3 reference/scripts/advise.py --file <target_file> [--db knowledge.db]
  ```
- **Arguments (optional):**
  - `--file` / `-f` (or `--target` / `-t`): Target source file or component path
    (e.g. `src/auth.py` or `api/app.py`). Defaults to repo-wide scope if
    omitted.
  - `--db` / `-d`: Path to Mantis SQLite database (default: auto-discovers
    `knowledge.db` or `workspace/knowledge.db`).
  - `--lineage` / `-l`: Query lifecycle and recurrence for a specific lineage
    UUID.
  - `--signature` / `-s`: Query lifecycle for a specific content signature hash.
  - `--json`: Emit structured JSON output instead of formatted markdown.

## How to Fetch Guidance

All Mantis knowledge (threat models, historical findings, verified patches,
triaged false positives, and learned invariants) lives in the SQLite database
(`knowledge.db`). Do not look for flat files on disk (like `learnings.jsonl` or
`workspace/findings/*.json`). Use one of the two execution doors below:

### Mechanism 1: CLI Execution (Recommended for Coding Agents)

Coding agents with standard bash access should run
`reference/scripts/advise.py`:

1. **Query Security Guidance for Target File**:

   ```bash
   python3 reference/scripts/advise.py --file src/auth.py
   ```

   *Prints*: Actionable security advisory markdown with active threat model,
   historical vulnerabilities, verified patch diffs, triaged false positives,
   and invariants.

2. **Query Specific Bug Lineage & Recurrence**:

   ```bash
   python3 reference/scripts/advise.py --lineage c3a5e982-1234-5678-9abc-def012345678
   ```

3. **Machine-Readable JSON**:

   ```bash
   python3 reference/scripts/advise.py --file src/auth.py --json
   ```

### Mechanism 2: Python Tool Invocation (Inside Pipeline / Harness)

When running inside an agent harness or Python environment:

```python
from core.database import query_security_guidance

guidance = query_security_guidance(db_path="knowledge.db", filepath="src/auth.py")
print(guidance["guidance_summary"])
```

Or via tool helper:

```python
get_security_guidance(filepath="src/auth.py")
```

## Input/Output Contract

- **Reads**:
  - `knowledge.db` (`findings`, `campaign_artifacts`, `learnings`, and
    `risk_scores` tables).
  - Target source code files (under repository root).
- **Writes**:
  - Structured Security Advisory & Guardrail recommendations formatted for the
    active developer or coding agent.

## Core Advisory Protocols

### Protocol 1: Pre-Implementation Security Context Check

Before authoring code or refactoring an existing module:

1. **Run the Advisor**: Execute
   `python3 reference/scripts/advise.py --file <target_file>`.
2. **Review Advisory Context**:
   - **Trust Boundaries**: Identify who interacts with this module (untrusted
     public internet, authenticated users, internal microservices).
   - **Historical Pitfalls**: Review all vulnerabilities previously confirmed or
     reproduced on this file. Pay specific attention to recurring `lineage_id`
     chains.
   - **Verified Safe Idioms**: Review verified patch diffs from prior passes
     marked `VERIFIED_SECURE`.
   - **Triaged False Positives**: Review patterns previously classified as false
     positives to understand intentional design choices and avoid breaking
     legitimate functionality.

### Protocol 2: Trust Boundary Verification

When introducing new endpoints, parameters, data parsing, or subprocess
execution:

1. **Input Normalization & Validation**:

   - Never trust input from external boundaries without canonicalization and
     strict schema enforcement.
   - For file paths: resolve against jail boundaries using strict
     `os.path.abspath` or `Path.resolve()` checks (`startswith(jail_dir)`).
   - For OS command execution: strictly use `shlex.quote` or array-based
     `subprocess.run(["cmd", arg])` without `shell=True`.

2. **Defense-in-Depth**:

   - Ensure server-side validation even if client-side validation is present.
   - Ensure zero-privilege assumptions (e.g. no unnecessary IAM permissions,
     bounded execution timeouts).

### Protocol 3: Lineage & Recurrence Defense

1. When fixing a reported vulnerability or refactoring a vulnerable component,
   check the bug's `lineage_id` via
   `python3 reference/scripts/advise.py --file <target_file>`.
2. Ensure the new implementation completely closes all attack vectors
   demonstrated in prior re-attack verification test suites.

## Output Format

The Advisor outputs clean, actionable recommendations:

````markdown
# Security Advisory: <target_file>

### 1. Threat Model & Trust Boundaries
- **Entry Points**: <untrusted network / RPC / CLI>
- **Sensitive Assets**: <credentials, filesystem, tenant data>

### 2. Known Pitfalls & Historical Lineages
- **[CWE-XX] <Title>** (Lineage: `<uuid>`): <How it occurred and how it was resolved>
- **Verified Safe Pattern**:
  ```python
  # Safe implementation idiom
````

### 3. False Positive Context (Intentional Behavior)

- **<Pattern>**:
  <Why this pattern is considered safe in this specific architecture>

### 4. Implementation Checklist

- [ ] Validated against path traversal / injection / deserialization.
- [ ] Adheres to verified patch patterns.
- [ ] Respects trust boundary isolation.

```
```

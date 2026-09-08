---
name: mantis-advise
description: >-
  Proactive security advisor and architectural remediation assistant for secure code development.
  Use to query threat models, historical vulnerability lineages, verified patch patterns, triaged false positives, and learned trajectory invariants before code edits or to generate architectural remediation plans for confirmed findings.
  Don't use for automated multi-pass red-team exploitation or fuzzing.
---

# Security Advisor & Remediation Engine (/mantis-advise)

## System Goal

Proactive Secure Development & Architectural Remediation Engine. Functions as a
security guardrail, advisory assistant, and architectural remediator for
developers and coding agents. Queries Mantis threat models, historical
vulnerability lineages, verified remediation patterns, triaged false positives,
and learned trajectory invariants to ensure that new code and refactors are
implemented securely from the start, and to synthesize robust architectural
remediations for confirmed vulnerabilities.

## Command Definition

- **Command:** `/mantis-advise`
- **Description:** Queries security knowledge for a given target file or module,
  evaluates proposed changes against known threat boundaries, and provides
  verified secure implementation guidance or architectural remediation plans.
- **Execution Command:**
  ```bash
  python3 "${MANTIS_HOME:-/path/to/mantis}/reference/scripts/advise.py" --file <target_file> [--db knowledge.db]
  ```
- **Arguments (optional):**
  - `--file` / `-f` (or `--target` / `-t`): Target source file or component path
    (e.g. `src/auth.py` or `api/app.py`). Defaults to repo-wide scope if
    omitted.
  - `--remediate` / `-r`: Finding ID, lineage UUID, or file to generate an
    architectural remediation dossier and verification plan for.
  - `--db` / `-d`: Path to Mantis SQLite database (default: auto-discovers
    `knowledge.db` or `workspace/knowledge.db`).
  - `--lineage` / `-l`: Query lifecycle and recurrence for a specific lineage
    UUID.
  - `--signature` / `-s`: Query lifecycle for a specific content signature hash.
  - `--json`: Emit structured JSON output instead of formatted markdown.
  - `--full`: Emit unabridged OKF markdown bodies and un-truncated diffs.

## How to Fetch Guidance

All Mantis knowledge (threat models, historical findings, verified patches,
triaged false positives, and learned invariants) lives in the SQLite database
(`knowledge.db`). Do not look for flat files on disk (like `learnings.jsonl` or
`workspace/findings/*.json`). Use one of the two execution doors below:

### Mechanism 1: CLI Execution (Recommended for Coding Agents)

Coding agents with standard bash access should run `advise.py` using its
installation-anchored absolute path.

**Path Anchoring Requirement (CRITICAL)**: The advisor script resides within the
Mantis installation directory at `reference/scripts/advise.py`. **You MUST
invoke this script via an absolute path or via `$MANTIS_HOME`**. NEVER execute
`python3 reference/scripts/advise.py` using a relative path inside the audited
target repository, as untrusted repositories could spoof scripts or cause
command failures.

1. **Query Security Guidance for Target File**:

   ```bash
   python3 "$MANTIS_HOME/reference/scripts/advise.py" --file src/auth.py
   ```

   *Prints*: Actionable security advisory markdown with active threat model,
   historical vulnerabilities, verified patch diffs, triaged false positives,
   and invariants.

2. **Query Specific Bug Lineage & Recurrence**:

   ```bash
   python3 "$MANTIS_HOME/reference/scripts/advise.py" --lineage c3a5e982-1234-5678-9abc-def012345678
   ```

3. **Machine-Readable JSON**:

   ```bash
   python3 "$MANTIS_HOME/reference/scripts/advise.py" --file src/auth.py --json
   ```

4. **Architectural Remediation Dossier for a Finding**:

   ```bash
   python3 "$MANTIS_HOME/reference/scripts/advise.py" --remediate <finding_id>
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
   `python3 "$MANTIS_HOME/reference/scripts/advise.py" --file <target_file>`.
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
   `python3 "$MANTIS_HOME/reference/scripts/advise.py" --file <target_file>`.
2. Ensure the new implementation completely closes all attack vectors
   demonstrated in prior re-attack verification test suites.

### Protocol 4: Architectural Vulnerability Remediation & Sandbox Verification

When resolving a confirmed security flaw (in pipeline or standalone):

1. **Grounding Context**:

   - Query
     `python3 "$MANTIS_HOME/reference/scripts/advise.py" --remediate <finding_id>`
     (or `get_security_guidance(filepath=...)`).
   - Extract active OKF Threat Boundaries and Security Invariants.
   - Inspect prior verified safe patterns from matching lineage history.

2. **Architectural Synthesis**:

   - Do NOT produce superficial point-hacks (e.g. `return None`, hardcoded
     `False`, or commenting out endpoints) that lobotomize functionality.
   - Refactor root-cause sinks using safe idioms (parameterization, strict
     bounds, array argv, canonicalized paths).

3. **Sandbox Verification (INV-1 & INV-2)**:

   - Apply the unified diff patch to the guest workspace (`apply_patch`).
   - Run the finding reproducer (`run_sandbox_with_evidence`).
   - Verify that the attack fails to reach the sink
     (`reattack_status == "failed_to_bypass"`).
   - Verify that existing functional test suites pass without regression.

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

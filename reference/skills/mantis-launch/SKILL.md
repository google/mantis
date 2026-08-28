---
name: mantis-launch
description: >-
  Launches automated vulnerability review campaigns on target files or repositories.
  Use to initiate Mantis vulnerability review pipelines with automated preflight checks, environment auto-configuration, and runtime overrides (sandboxes, models, endpoints).
  Don't use for configuring settings without scanning or for manual single-stage reviews.
---

# Campaign Launcher (/mantis-launch)

## System Goal

Autonomous Security Review Pipeline Launcher. Initiates end-to-end vulnerability
discovery, independent verification, exploit viability analysis, crash
reproduction, automated patch generation, and risk calibration campaigns across
a target file or entire codebase repository.

Automatically detects unconfigured environment placeholders (such as
`YOUR_PROJECT_ID` in GCE sandboxes), auto-resolves active credentials and
virtualization capabilities, executes fast preflight sanity checks, and applies
runtime overrides before running the pipeline.

## Command Definition

- **Command:** `/mantis-launch`
- **Description:** Launches automated multi-agent vulnerability discovery and
  validation campaigns.
- **Execution Commands:**
  ```bash
  # From reference/ directory:
  ./run.sh <target_file_or_dir> [flags...]
  # or: python3 scripts/launch.py <target_file_or_dir> [flags...]

  # From repository root:
  ./reference/run.sh <target_file_or_dir> [flags...]
  # or: python3 reference/scripts/launch.py <target_file_or_dir> [flags...]
  ```
- **CLI Options:**
  - `target` (positional): Path to a single source file (e.g. `src/auth.py`) or
    a root repository directory (e.g. `.` or `/path/to/repo`).
  - `--sandbox` / `-s`: Override sandbox mechanism (`static-only`, `gvisor`,
    `microsandbox`, `gce`).
  - `--model` / `-m`: Override AI model (e.g. `gemini-3.7-flash`,
    `vertex_ai/claude-opus-5`, `vertex_ai/zai_org/glm-5.2-maas`,
    `openai/{MODEL_ID}`).
  - `--api-base`: Custom endpoint URL for OpenAI-compatible LLM deployments
    (e.g. `http://localhost:8000/v1`).
  - `--reasoning-effort`: Reasoning effort level (`low`, `medium`, `high`).
  - `--timeout`: LLM request timeout in seconds.
  - `--db` / `-d`: Custom path to SQLite knowledge database (default:
    `knowledge.db`).
  - `--workflow` / `-w`: Path to custom `workflow.json` layout definition.
  - `--preflight-only` / `--test` / `--preflight`: Run preflight checks and exit
    without starting the campaign.
  - `--interactive`: Launch interactive configuration wizard before execution.
  - `--dry-run`: Display launch plan and indexed files without calling AI
    models.
  - `--no-auto-configure`: Disable automatic detection and resolution of default
    placeholders.

## Automated Auto-Healing & Preflight

Before starting a security campaign, `mantis-launch`:

1. **Placeholder Auto-Detection**: Inspects `workflow.json` for unconfigured
   defaults (e.g. `project: "YOUR_PROJECT_ID"`).
2. **Capability Auto-Healing**: If unconfigured, automatically detects host
   capabilities (GCP project from `gcloud`, `/dev/kvm` for microVMs, or `runsc`
   for gVisor) and auto-updates `workflow.json` or falls back safely to
   `static-only`.
3. **Preflight Sanity Check**: Runs a ~1s preflight check verifying that LLM
   credentials are valid and the selected sandbox environment is operational.

## Common CLI Workflows

### 1. Launch Standard Review on Target File or Repository

```bash
# Scan a specific file
./reference/run.sh src/server/auth.py

# Scan an entire repository
./reference/run.sh .
```

### 2. Launch with Static Analysis Only (Zero Sandbox Requirements)

```bash
./reference/run.sh . --sandbox static-only
```

### 3. Launch with Specific Model (e.g. Claude or Custom OpenAI Server)

```bash
# Vertex AI Claude
./reference/run.sh . --model vertex_ai/claude-opus-5

# Local vLLM / Ollama server
./reference/run.sh . --model openai/custom-model --api-base http://localhost:8000/v1
```

### 4. Verify Preflight Readiness Without Scanning

```bash
python3 reference/scripts/launch.py . --preflight-only
```

### 5. Inspect Results After Launch

All findings, exploit reproduction logs, verified patches, and risk calibration
scores are recorded in `knowledge.db`. Query guidance using `mantis-advise`:

```bash
python3 reference/scripts/advise.py --file src/server/auth.py
```

## Input/Output Contract

- **Reads**:
  - Target source code files (under target path or repository).
  - `workflow.json` (declarative graph layout and config).
- **Writes**:
  - `knowledge.db` (`findings`, `campaign_artifacts`, `risk_scores`, `learnings`
    tables).
  - `sessions.db` (ADK session state trajectories).
  - Formatted terminal report and execution logs.

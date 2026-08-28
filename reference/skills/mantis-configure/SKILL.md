---
name: mantis-configure
description: >-
  Configures and validates Mantis pipeline environments, sandbox mechanisms, and AI models.
  Use to set up workflow.json, auto-detect host capabilities, switch between sandboxes (static-only, gvisor, microsandbox, gce), select AI models, and run fast 1-2s preflight tests.
  Don't use for scanning source code or running attack campaigns.
---

# Pipeline Configurator (/mantis-configure)

## System Goal

Environment and Model Configurator. Configures `workflow.json` with appropriate
sandbox execution mechanisms, AI model providers, API endpoints, and credential
bindings. Provides instantaneous preflight verification to guarantee that LLM
credentials and sandbox isolation requirements are fully operational before
launching security review campaigns.

## Command Definition

- **Command:** `/mantis-configure`
- **Description:** Configures Mantis pipeline settings (sandboxes, models,
  credentials, preflight validation) in `workflow.json`.
- **Execution Command:**
  ```bash
  # From reference/ directory:
  python3 scripts/configure.py [flags...]

  # From repository root:
  python3 reference/scripts/configure.py [flags...]
  ```
- **CLI Options:**
  - `--sandbox` / `-s`: Sandbox mechanism (`static-only`, `gvisor`,
    `microsandbox`, `gce`).
  - `--model` / `-m`: Default LLM model (e.g. `gemini-3.7-flash`,
    `vertex_ai/claude-opus-5`, `vertex_ai/zai_org/glm-5.2-maas`,
    `openai/{MODEL_ID}`).
  - `--api-base`: Custom endpoint URL for OpenAI-compatible LLM servers (e.g.
    `http://localhost:8000/v1`).
  - `--reasoning-effort`: Reasoning effort level (`low`, `medium`, `high`).
  - `--timeout`: LLM request timeout in seconds.
  - `--project` / `-p`: GCP Project ID (for GCE sandbox or Vertex AI routing).
  - `--zone` / `-z`: GCP Zone (e.g. `us-central1-b`).
  - `--image` / `-i`: Sandbox image name (e.g. `mantis-sandbox-image` or
    `mantis-sandbox:latest`).
  - `--subnet`: GCE Subnet name (e.g. `mantis-isolated-subnet`).
  - `--workdir`: Sandbox guest workdir (default: `/workspace`).
  - `--workflow` / `-w`: Path to `workflow.json` (defaults to auto-discovery).
  - `--db` / `-d`: Path to SQLite knowledge database (default: `knowledge.db`).
  - `--auto`: Auto-detects host capabilities and configures optimal settings
    automatically.
  - `--save`: Explicitly saves configuration changes to `workflow.local.json`.
  - `--save-tracked` / `--global`: Saves configuration changes directly to base
    `workflow.json`.
  - `--interactive`: Interactive step-by-step terminal wizard.
  - `--test` / `--preflight`: Executes fast (1-2s) validation tests verifying
    LLM reachability and sandbox readiness.
  - `--show`: Displays current configuration and diagnostic status.
  - `--dry-run`: Simulates configuration changes without modifying files.
  - `--update-nodes`: Updates all agent nodes in `workflow.json` to use the
    specified default model.
  - `--json`: Outputs configuration status and preflight diagnostics in JSON.

## Supported Sandbox Mechanisms

| Sandbox        | Description                                                       | Isolation Level          | Requirements                                 |
| :------------- | :---------------------------------------------------------------- | :----------------------- | :------------------------------------------- |
| `static-only`  | Static analysis only; reproducer and dynamic patching disabled.   | Zero Host Risk           | None (Always available)                      |
| `gvisor`       | Networkless OCI container executed under Google gVisor (`runsc`). | Process & Kernel sandbox | `docker` or `podman` with `runsc` registered |
| `microsandbox` | Ephemeral Linux microVM with hardware virtualization.             | Virtual Machine          | `/dev/kvm` read/write access                 |
| `gce`          | Hardened ephemeral Google Compute Engine VM via IAP SSH tunnel.   | Cloud Hypervisor         | `gcloud` CLI, active GCP auth & project      |

## Supported Model Providers

1. **Gemini Models (Google / Vertex AI)**:
   - `gemini-3.7-flash`, `gemini-3.5-flash-lite`
   - `vertex_ai/gemini-3.7-flash`, `vertex_ai/gemini-3.5-flash-lite`
2. **Claude Models (Vertex AI Model Garden)**:
   - `vertex_ai/claude-opus-5`
3. **MaaS & Open Source Models (Vertex Model Garden)**:
   - `vertex_ai/zai_org/glm-5.2-maas`
4. **Custom OpenAI-Compatible Endpoints**:
   - `openai/{MODEL_ID}` or `vertex_ai/openai/{MODEL_ID}`
   - Supports custom `--api-base` (e.g. vLLM, Ollama, LiteLLM proxy),
     `--reasoning-effort`, and `--timeout`.

## Common CLI Workflows

### 1. Fast Preflight Verification (~1s)

Check if LLM credentials and sandbox requirements are operational:

```bash
python3 reference/scripts/configure.py --test
```

### 2. Auto-Detect and Configure

Automatically inspect host capabilities (`/dev/kvm`, `docker/runsc`, `gcloud`)
and select the best available sandbox:

```bash
python3 reference/scripts/configure.py --auto
```

### 3. Switch to Static Analysis (Zero Dependencies)

```bash
python3 reference/scripts/configure.py --sandbox static-only
```

### 4. Configure gVisor Container Sandbox

```bash
python3 reference/scripts/configure.py --sandbox gvisor --image mantis-sandbox:latest
```

### 5. Configure GCE Ephemeral Cloud Sandbox

```bash
python3 reference/scripts/configure.py --sandbox gce --project my-gcp-project --zone us-central1-b
```

### 6. Switch AI Model to Claude or Custom Endpoint

```bash
# Vertex AI Claude
python3 reference/scripts/configure.py --model vertex_ai/claude-opus-5

# Custom Local vLLM / OpenAI server
python3 reference/scripts/configure.py --model openai/my-model --api-base http://localhost:8000/v1
```

### 7. Interactive Configuration Wizard

```bash
python3 reference/scripts/configure.py --interactive
```

## Python API Reference

When invoked programmatically from Python:

```python
from scripts.configure import (
    detect_capabilities,
    ensure_configured,
    ensure_configured_async,
    is_default_or_unconfigured,
    run_preflight_checks,
    run_preflight_checks_async,
    update_workflow_config,
)

# 1. Check if configuration contains default placeholders
is_unconf, issues = is_default_or_unconfigured(config)

# 2. Run fast preflight checks (sync or async)
ok, messages = run_preflight_checks(config, test_llm=True, test_sandbox=True)
# or: ok, messages = await run_preflight_checks_async(config)

# 3. Ensure configured (auto-resolves defaults if unconfigured)
valid_config = ensure_configured(auto=True)
# or: valid_config = await ensure_configured_async(auto=True)
```

## Input/Output Contract

- **Reads**:
  - `workflow.json` and optional `workflow.local.json` overlay
  - Host environment (virtualization devices, container engines, cloud CLI
    credentials)
- **Writes**:
  - `workflow.local.json` (or `workflow.json` when `--save-tracked` is set)

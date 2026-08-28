# ADK Reference Implementation with Mantis Skills

This directory contains a reference implementation of Mantis built directly on
top of the **Agent Development Kit (ADK)** using the full suite of canonical
**Mantis Skills** and **isolated sandboxed execution environments**.

## Getting Started

First, install python3-venv such as with `sudo apt install python3-venv`, then
run the install script. Mantis comes with automated configuration and launcher
tools (`mantis-configure` and `mantis-launch`):

```bash
cd reference && ./install.sh

# 0. Authenticate Google Cloud Application Default Credentials (ADC) if using Vertex AI
gcloud auth application-default login

# 1. Fast Configuration & Capability Auto-Detection (or --interactive wizard)
python3 scripts/configure.py --auto

# 2. Fast Preflight Validation (~1s)
python3 scripts/configure.py --test

# 3. Launch Vulnerability Review Campaign (file or repository)
./run.sh path/to/code            # a file or a directory
```

### Local Configuration Overlay (`workflow.local.json`)

Mantis uses a layered configuration pattern:

- **`workflow.json` (Tracked)**: Contains base pipeline definitions, nodes,
  edges, and default placeholder configurations (`YOUR_PROJECT_ID`).
- **`workflow.local.json` (Gitignored)**: Contains machine-specific settings
  (such as auto-resolved GCP projects, custom sandbox paths, and model
  configurations). When present, it automatically merges on top of
  `workflow.json`.

When you run `./run.sh` or `scripts/configure.py --auto`, Mantis auto-heals
unconfigured placeholders and writes the resolved settings into
`workflow.local.json`. This ensures your `git status` remains clean after
running campaigns. To opt out of auto-healing, pass `--no-auto-configure`. To
explicitly save changes to the base tracked `workflow.json`, use
`--save-tracked` (or `--global`).

You can customize the sandbox execution mechanism (`static-only`, `gvisor`,
`microsandbox`, `gce`) or AI model at any time:

```bash
# Switch to Static-only (zero host virtualization requirements)
python3 scripts/configure.py --sandbox static-only

# Or pass runtime overrides directly to launch:
./run.sh path/to/code --sandbox static-only --model gemini-3.7-flash
```

Once you have run it you can add the mantis-advise skill to your favorite coding
agent and use that while developing your code to have your coding agent attempt
to create fewer vulnerabilities. To try it manually you can run the script:

```
python3 scripts/advise.py --file path/to/file.py   # query accumulated knowledge
```

## Configuration & Launch Skills

- **`mantis-configure`**
  ([`skills/mantis-configure/SKILL.md`](skills/mantis-configure/SKILL.md) /
  [`scripts/configure.py`](scripts/configure.py)): Manages pipeline settings via
  `workflow.local.json` overlay or base `workflow.json`, auto-detects host
  virtualization and cloud capabilities, configures sandboxes and LLM providers,
  and executes instantaneous (~1s) preflight sanity checks.
- **`mantis-launch`**
  ([`skills/mantis-launch/SKILL.md`](skills/mantis-launch/SKILL.md) /
  [`scripts/launch.py`](scripts/launch.py)): Autonomous campaign launcher.
  Auto-heals unconfigured placeholders (e.g. `YOUR_PROJECT_ID`) into
  `workflow.local.json`, validates preflight readiness, accepts CLI overrides,
  and executes the 16-agent review graph over target files or repositories.
- **`mantis-advise`** ([`mantis-advise/SKILL.md`](../mantis-advise/SKILL.md) /
  [`scripts/advise.py`](scripts/advise.py)): Developer security advisor. Queries
  threat models, historical lineages, verified patch diffs, and triaged false
  positives from `knowledge.db`.

## Core Pipeline Stages

The pipeline in `workflow.json` orchestrates 16 canonical Mantis skills across
the complete vulnerability campaign lifecycle:

01. **`history`** (`mantis-history`): Extracts commit history, churn hotspots,
    and developer activity logs.
02. **`structural_index`** (`mantis-structural-index`): Generates code AST,
    symbol graphs, and function boundaries.
03. **`summarizer`** (`mantis-summarize`): Synthesizes codebase structure and
    high-level functionality overview.
04. **`architect`** (`mantis-architecture`): Constructs the structured Markdown
    Knowledge Base (`workspace/kb/`).
05. **`threat_modeler`** (`mantis-threat-model`): Maps threat actors, entry
    points, and trust boundaries (`workspace/kb/THREAT_MODEL.md`).
06. **`planner`** (`mantis-plan`): Formulates prioritized review targets and
    questions (`workspace/plan.json`).
07. **`researcher`** (`mantis-researcher`): Executes deep static analysis sweeps
    and flags potential flaws.
08. **`deduplicator`** (`mantis-dedupe`): Clusters and deduplicates candidate
    findings across passes.
09. **`reviewer`** (`mantis-review`): Filters out false positives and evaluates
    reachability (`ReviewVerdict`).
10. **`critic`** (`mantis-critic`): Conducts adversarial viability review
    (`CriticVerdict`).
11. **`reproducer`** (`mantis-reproduce`): Synthesizes and runs dynamic exploit
    PoCs inside the isolated sandbox (`ReproVerdict`).
12. **`chainer`** (`mantis-chain`): Chains related findings into multi-stage
    exploit trajectories.
13. **`patcher`** (`mantis-patch`): Creates remediation patches and tests them
    via re-attack verification in the sandbox.
14. **`calibrator`** (`mantis-calibrate`): Calibrates final risk scores (0–100)
    and justification.
15. **`reflector`** (`mantis-reflect`): Rotates learnings and feedback into the
    knowledge base (`workspace/learnings.jsonl`).
16. **`reporter`** (`mantis-report`): Compiles the final review packet and
    executive summary (`workspace/report/review_packet-latest.md`).

## Sandboxing & Isolation

The reference harness implements ADK's `BaseEnvironment` interface:

- **`GceEnvironment`**: Hardened Google Compute Engine (GCE) ephemeral VM
  isolation (single-VM only). Golden machine image, private non-internet VPC,
  link-local DNS blackholing, IAM token suppression, and IAP SSH tunneling. See
  [GCE Sandbox Setup Guide](docs/gce_sandbox_setup.md).
- **`MicrosandboxEnvironment`**: Hardware microVM isolation (libkrun / KVM).
  Networkless (`Network.none()`), guest-isolated filesystem at `/workspace`.
- **`GvisorEnvironment`**: OCI container isolation via gVisor (`runsc`).
  Networkless (`--network=none`), container-isolated filesystem at `/workspace`.
- **`StaticOnlyEnvironment`**: Safe no-op environment for static-only scans.

### Configuring the Sandbox Backend in `workflow.json`

To change the sandbox backend, update the `"config.sandbox"` block in
[`workflow.json`](workflow.json):

#### 1. Static-Only (`"static-only"`)

Zero dependencies. Dynamic exploit execution and patch testing are skipped.

```json
"sandbox": {
  "type": "static-only"
}
```

#### 2. gVisor (`"gvisor"`)

Local OCI container isolation via Docker/Podman with gVisor `runsc` and
`--network=none`.

```json
"sandbox": {
  "type": "gvisor",
  "options": {
    "image": "mantis-sandbox:latest",
    "runtime": "runsc",
    "timeout_seconds": 600
  }
}
```

#### 3. MicroSandbox (`"microsandbox"`)

In-process hardware microVM isolation via `libkrun` and `Network.none()`.

```json
"sandbox": {
  "type": "microsandbox",
  "options": {
    "image": "mantis-sandbox:latest",
    "timeout_seconds": 600
  }
}
```

#### 4. Hardened GCE VM (`"gce"`)

Ephemeral cloud VM in an isolated VPC with link-local DNS blackholing.

```json
"sandbox": {
  "type": "gce",
  "options": {
    "project": "YOUR_PROJECT_ID",
    "zone": "us-central1-b",
    "image": "mantis-sandbox-image",
    "subnet": "mantis-isolated-subnet",
    "workdir": "/workspace",
    "tunnel_through_iap": true,
    "no_service_account": true,
    "no_external_ip": true,
    "verify_isolation": true,
    "timeout_seconds": 600
  }
}
```

| Sandbox Type         | Dynamic Execution | Prerequisites                                       |
| :------------------- | :---------------: | :-------------------------------------------------- |
| **`"static-only"`**  |        ❌         | None                                                |
| **`"gvisor"`**       |        ✅         | Docker/Podman + `runsc` runtime                     |
| **`"microsandbox"`** |        ✅         | Hardware virtualization (`/dev/kvm`)                |
| **`"gce"`**          |        ✅         | GCP Project, Isolated VPC/Subnet, Custom Disk Image |

### Quickstart: Isolated GCE Sandbox Setup

An automated setup script is provided at
[`reference/scripts/setup_gce_sandbox.sh`](scripts/setup_gce_sandbox.sh):

```bash
# Automated setup (provisions VPC, subnet, firewall, DNS policy):
PROJECT_ID=your-gcp-project SOURCE_INSTANCE=your-dev-vm ./reference/scripts/setup_gce_sandbox.sh
```

Or run the parameterized commands manually:

```bash
# Configuration variables
REGION="us-central1"
ZONE="us-central1-a"
VPC_NAME="mantis-isolated-vpc"
SUBNET_NAME="mantis-isolated-subnet"
IMAGE_NAME="mantis-golden-image-v1"
DEV_BUILD_VM="my-dev-build-vm"

# 1. Custom Isolated VPC & Subnet (no internet, no Cloud NAT, no Google API access)
gcloud compute networks create "${VPC_NAME}" --subnet-mode=custom
gcloud compute networks subnets create "${SUBNET_NAME}" \
    --network="${VPC_NAME}" \
    --region="${REGION}" \
    --range=10.0.0.0/24 \
    --no-enable-private-ip-google-access

# 2. Allow SSH strictly from Google Cloud Identity-Aware Proxy (IAP)
gcloud compute firewall-rules create "allow-iap-ssh-${VPC_NAME}" \
    --network="${VPC_NAME}" \
    --allow=tcp:22 \
    --source-ranges=35.235.240.0/20

# 3. Block recursive public DNS exfiltration via Cloud DNS Response Policy
gcloud dns response-policies create mantis-block-public-dns \
    --project="${PROJECT_ID}" \
    --networks="${VPC_NAME}" \
    --description="Block all public DNS lookups"
gcloud dns response-policies rules create block-all-domains \
    --project="${PROJECT_ID}" \
    --response-policy=mantis-block-public-dns \
    --dns-name="*." \
    --local-data=name="*.",type="A",ttl=300,rrdatas="0.0.0.0"

# 4. Create Assessment Disk Image from your pre-warmed build/dev VM
gcloud compute images create "${IMAGE_NAME}" \
    --project="${PROJECT_ID}" \
    --source-disk="${DEV_BUILD_VM}" \
    --source-disk-zone="${ZONE}" \
    --force \
    --description="Assessment disk image with pre-warmed build dependencies for Mantis"
```

## Typed Domain Tools Suite

For maximum reliability and structured database grounding, the harness provides
strictly-typed domain tools backed by Pydantic models and SQLite persistence:

- **`report_findings(report)`**: Validates `VulnerabilityReport` and writes
  findings.
- **`get_findings()`**: Retrieves recorded findings for the current target file.
- **`dedupe_findings(primary_title, duplicate_titles, reason)`**: Merges
  duplicates.
- **`record_plan(plan)`**: Validates `ReviewPlan` and records
  `workspace/plan.json`.
- **`record_threat_model(threat_model)`**: Validates `ThreatModel` and records
  `THREAT_MODEL.md`.
- **`record_summary(summary)`**: Validates `CodebaseSummary` and records
  `mantis-summary.md`.
- **`record_exploit_chain(chain)`**: Validates and records `ExploitChain`.
- **`score_risk(score, reasoning)`**: Validates $0 \\le \\text{score} \\le 100$
  and records risk calibration.
- **`record_learning(learning)`**: Validates `LearningEntry` and rotates
  learnings into SQLite.
- **`generate_report(report)`**: Validates `ExecutiveReport` and writes
  `review_packet-latest.md`.

## Schema Single-Source-of-Truth & Code Generation

All state contracts and Pydantic models in `core/schemas.py` are generated
directly from the root canonical `schema.json`:

```bash
python3 reference/scripts/generate_schemas.py
```

This guarantees 100% schema alignment across all Mantis skills, external
orchestrators, and the ADK reference harness without manual duplication.

## Integration Pattern

Each agent node in `workflow.json` declares its assigned skill and additional
tools:

```json
{
  "id": "researcher",
  "type": "agent",
  "skill": "../mantis-researcher",
  "tools": ["read_file", "write_file", "list_files", "report_findings", "get_findings"]
}
```

When compiled by `core/graph_loader.py`, each skill is loaded via
`google.adk.skills.load_skill_from_dir` and attached to the agent as a
`SkillToolset` connected to the active sandboxed environment.

### No-Skill / Custom System Prompt Alternative

As an alternative to loading a canonical Mantis skill directory,
`core/graph_loader.py` also supports configuring an agent node with a custom
markdown prompt file via `system_prompt` (such as
[`prompts/system-researcher.md`](prompts/system-researcher.md)):

```json
{
  "id": "researcher",
  "type": "agent",
  "system_prompt": "prompts/system-researcher.md",
  "tools": ["read_file", "write_file", "list_files", "report_findings", "get_findings"]
}
```

When `system_prompt` is specified instead of `skill`, `core/graph_loader.py`
loads the agent's instructions directly from the given file and attaches the
specified tools directly to the agent without instantiating a `SkillToolset`.

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

# 2. Fast Preflight Validation (~1s) & Live Reachability Probe
python3 scripts/configure.py --test --probe

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
  and executes preflight sanity checks and live reachability probes (`--probe`).
- **`mantis-launch`**
  ([`skills/mantis-launch/SKILL.md`](skills/mantis-launch/SKILL.md) /
  [`scripts/launch.py`](scripts/launch.py)): Autonomous campaign launcher.
  Auto-heals unconfigured placeholders (e.g. `YOUR_PROJECT_ID`) into
  `workflow.local.json`, validates preflight readiness, accepts CLI overrides,
  and executes the 16-agent review graph over target files or repositories.
- **`mantis-advise`** ([`scripts/advise.py`](scripts/advise.py)): Developer
  security advisor. Queries threat models, historical lineages, verified patch
  diffs, and triaged false positives from `knowledge.db`.

## Research Graph Synthesis & Evolution Flywheel

Mantis features **research graph synthesis**, enabling autonomous construction
of tailored multi-agent review topologies for specific vulnerability classes or
audit objectives:

```bash
# Synthesize a specialized research graph tailored to an audit objective:
./run.sh path/to/code --objective "Audit for memory safety, bounds checks, and use-after-free in packet parsers"

# Inspect the synthesized graph structure without executing:
./run.sh path/to/code --objective "Audit for SSRF in webhook handlers" --inspect --dry-run
```

### Synthesis Archetypes & Deterministic Gates

Research graph synthesis generates specialized graph specifications validated
through deterministic architectural gates:

1. **Tool Registry Gate**: Only strictly whitelisted ADK tools (`read_file`,
   `list_files`, `get_findings`, `report_findings`, etc.) are permitted.
2. **Topological & Cycle Validation Gate**: Synthesizer ensures connected, valid
   DAG structures with validated cyclical feedback loops (e.g. patch
   verification loops).
3. **Structured Verdict Mapping**: Review, Critic, and Reproducer nodes are
   automatically bound to structured Pydantic schemas (`ReviewVerdict`,
   `CriticVerdict`, `ReproVerdict`).
4. **Sandbox Policy Gate**: Sandbox backends are strictly clamped to operator
   policy or archetype defaults (`static-only`), preventing untrusted LLM
   outputs from escalating execution privileges.

### Hardened Budgets & Checkpointing

Mantis enforces multi-dimensional ceilings across every campaign:

- **Wall-Clock Time**: `--max-time 2h` (ISO duration / time format).
- **Token Budget**: `--token-budget 10M` (raw integer or human-readable format).
- **Graph Steps & Node Visits**: `--max-steps 500 --max-node-visits 50`.
- **State Resumption**: `--resume <run_id>` seamlessly resumes paused campaigns
  from SQLite checkpoints with monotonic status preservation.

## Core Pipeline Stages

The pipeline in `workflow.json` orchestrates 15 canonical stages across the
complete vulnerability campaign lifecycle:

01. **`history`**: Extracts commit history, churn hotspots, and developer
    activity logs.
02. **`structural_index`**: Generates code AST, symbol graphs, and function
    boundaries.
03. **`architect`**: Constructs the structured Markdown Knowledge Base
    (`workspace/kb/`).
04. **`threat_modeler`**: Maps threat actors, entry points, and trust boundaries
    (`workspace/kb/THREAT_MODEL.md`).
05. **`planner`**: Formulates prioritized review targets and questions
    (`workspace/plan.json`).
06. **`researcher`**: Executes deep static analysis sweeps and flags potential
    flaws.
07. **`deduplicator`**: Clusters and deduplicates candidate findings across
    passes.
08. **`reviewer`**: Filters out false positives and evaluates reachability
    (`ReviewVerdict`).
09. **`critic`**: Conducts adversarial viability review (`CriticVerdict`).
10. **`reproducer`**: Synthesizes and runs dynamic exploit PoCs inside the
    isolated sandbox (`ReproVerdict`).
11. **`chainer`**: Chains related findings into multi-stage exploit
    trajectories.
12. **`patcher`**: Autonomous remediation conductor with strict separation of
    duties; delegates code authoring to isolated subagents, commissions
    independent third-party re-attackers with parallel adversarial trajectory
    search, and enforces dual-gate sandbox verification.
13. **`calibrator`**: Calibrates final risk scores (0–100) and justification.
14. **`reflector`**: Rotates learnings and feedback into the knowledge base
    (`workspace/learnings.jsonl`).
15. **`reporter`**: Compiles the final review packet and executive summary
    (`workspace/report/review_packet-latest.md`).

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

### Target Boundary & Isolation Model

- **Boundary vs. Filter**: The target repository jail is a strict boundary
  around the target checkout directory, not an in-tree content filter. Pointing
  Mantis at a directory exposes the files within that directory to analysis by
  design. Outside the target directory, access is strictly blocked. Inside the
  target directory, only protected VCS directories (`.git`, `.hg`, `.svn`,
  `.jj`) and 11 sensitive metadata/credential filenames (`.gitconfig`,
  `.gitmodules`, `.gitattributes`, `.git-credentials`, `.netrc`, `.env`,
  `.env.local`, `.npmrc`, `.pypirc`, `.pre-commit-config.yaml`,
  `.pre-commit-config.yml`) are denied. Other files inside the target (e.g.
  `.env.production`, `.aws/credentials`, `secrets.yaml`) are within the analyzed
  target scope and will be read if requested.
- **Untrusted Git Hardening**: All host git inspection tools (`get_git_diff`,
  `get_git_log`, `ls-files`) are hardened with `--no-ext-diff`, `--no-textconv`,
  `-c diff.external=`, `-c diff.tool=`, `-c core.attributesFile=/dev/null`, and
  `GIT_CONFIG_NOSYSTEM=1`. This prevents repositories carrying attacker-authored
  `.git/config` or `.gitattributes` files from executing arbitrary binaries or
  external diff drivers on the host during commit history or diff analysis.
- **Workflow Discovery**: By default, Mantis discovers `workflow.json` strictly
  from the reference package installation paths and will not probe an arbitrary
  `workflow.json` located in the current working directory, preventing untrusted
  repository graph hijacking. Custom workflows must be explicitly specified via
  `--workflow <path>`.

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

## Schema Single-Source-of-Truth

All state contracts and Pydantic models in `core/schemas.py` implement the root
canonical `schema.json`, providing runtime type safety and invariant enforcement
(INV-1 through INV-6) across all Mantis skills, external orchestrators, and the
ADK reference harness.

## Integration Pattern

Each agent node in `workflow.json` declares its node identifier and attached
tools:

```json
{
  "id": "researcher",
  "type": "agent",
  "tools": ["read_file", "write_file", "list_files", "report_findings", "get_findings"]
}
```

When compiled by `core/graph_loader.py`, the agent node's `id` automatically
maps to its high-density system prompt in `core/prompts.py` (or literal
`system_prompt`), with domain tools attached directly to the agent and stage
isolation enforced (`include_contents="none"`).

### Custom System Prompt Alternative

`core/graph_loader.py` also supports configuring an agent node with literal
instruction text via `system_prompt`:

```json
{
  "id": "custom_auditor",
  "type": "agent",
  "system_prompt": "You are a specialized auditor inspecting cryptographic primitives. Focus on key reuse and weak RNG.",
  "tools": ["read_file", "list_files", "report_findings", "get_findings"]
}
```

When `system_prompt` is specified, `core/graph_loader.py` uses the literal
instruction text directly rather than resolving the default prompt by `id`.

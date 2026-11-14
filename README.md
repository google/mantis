# Mantis: Portable Toolkit for Building Secure Software

> [!CAUTION] **USE AT YOUR OWN RISK. BE EXTREMELY CAREFUL.** This suite is
> designed to generate and execute autonomously generated code that may be
> unstable or perform unexpected actions. **USE THIS ONLY IN ISOLATED,
> RESTRICTED ENVIRONMENTS.** Never run this suite on a machine with access to
> production systems, sensitive data, or internal networks.

> [!IMPORTANT] **RESPONSIBLE USE** AI models are non-deterministic and can
> hallucinate findings or generate incorrect patches. **All findings must be
> manually verified by a security expert before being reported.** Do not
> mass-file unverified, AI-generated reports to open-source maintainers. A
> failure to automatically reproduce a vulnerability does not definitively mean
> it is a false positive, nor does a successful reproducer guarantee the bug is
> exploitable in all contexts. Use Mantis responsibly.

> [!WARNING] **The pull request scan is untested.** The GitHub Action in
> `action/`, the `mantis-pr-scan` and `mantis-knowledge-refresh` workflows under
> `.github/workflows/`, and `reference/scripts/setup_github_action.sh` have been
> reviewed and exercised against stubs, but have not yet been run end-to-end
> against a live project. Do not use the action to gate merges. The status note
> at the top of
> [reference/docs/github-action.md](reference/docs/github-action.md) lists what
> execution has not verified and will be removed when it has.

Mantis is a set of skills along with an ADK reference harness for building
secure software in the new AI era of software development.

- [`skills/`](skills/) -- the method: the skills an agent loads on demand, from
  threat modelling through research, review, patching and reporting.
- [`reference/`](reference/) -- an ADK harness that runs the method as a
  pipeline, with its own two skills to configure and launch it. Meant to be
  adapted; works as is.
- [`action/`](action/) -- a GitHub Action that runs the harness over a pull
  request (see the warning above).

## Getting Started

### Prerequisites

- **OS**: Linux, WSL2, or macOS (Apple Silicon supports local microVM sandboxes;
  Intel macOS works in `static-only` mode; native Windows is unsupported).
- **Python**: **3.12 – 3.14** with `venv` (on Debian/Ubuntu:
  `sudo apt install python3-venv`).
- **LLM credentials** (pick one):
  - **Vertex AI**: `gcloud auth application-default login`
  - **Gemini API**: `export GEMINI_API_KEY=...`
  - **Others**: set the provider environment variable per
    [LiteLLM Providers](https://docs.litellm.ai/docs/providers) (or pass
    `--api-base` for custom/local endpoints)

### 1. Install

```bash
cd reference && ./install.sh
```

`install.sh` creates `reference/.venv` and, if `docker`/`podman`/`buildah` is
available, builds the optional local sandbox image for dynamic reproduction. If
no container/VM tooling is available, Mantis falls back cleanly to
`static-only`.

### 2. Configure & verify

```bash
# Auto-detect credentials, model defaults, and sandbox capabilities
# (or pass --interactive for a guided wizard). Writes gitignored workflow.local.json.
.venv/bin/python3 scripts/configure.py --auto

# Optional: switch model or force static-only (zero VM/container requirements)
.venv/bin/python3 scripts/configure.py --sandbox static-only --model gemini-3.8-flash

# Fast preflight check (~1s) + live LLM reachability probe
.venv/bin/python3 scripts/configure.py --test --probe
```

### 3. Run your first scan

`./run.sh` activates `reference/.venv` automatically and accepts either a single
file or a repository directory:

```bash
# Balanced full-stack + firmware/RTL scan (defaults to --depth 30)
./run.sh /path/to/repo

# Fast triage (Critical/High focus, single campaign on typical repos)
./run.sh /path/to/repo --depth 10

# Exhaustive multi-pass deep audit across the repository
./run.sh /path/to/repo --depth 100

# Scan a single file
./run.sh /path/to/file.py
```

`--depth` takes any integer from **1** (fast shallow triage) to **100**
(exhaustive full-coverage multi-pass audit) and defaults to **30**. It smoothly
scales risk-ranked file coverage, batch granularity, reasoning effort,
deterministic sink checklists, and pass count while always respecting existing
budget guardrails (`--token-budget`, `--max-time`) and explicit CLI overrides
(`--scan-mode`, `--passes`, `--reasoning-effort`, `--model`, `--sandbox`). See
[reference/README.md](reference/README.md#audit-depth) for the full breakdown.

### 4. Inspect results & use Mantis during development

Every run prints a summary to the terminal and saves verified findings, threat
models, risk scores, coverage, and learnings in `reference/knowledge.db` (custom
path via `--db`):

```bash
# Query accumulated threat models, findings, and prior fixes for a file
.venv/bin/python3 scripts/advise.py --file /path/to/repo/src/auth.py
```

- **SARIF 2.1.0 export**: set `"sarif_output": "workspace/mantis.sarif"` in
  `workflow.local.json` (see
  [reference/README.md](reference/README.md#output-sarif)).
- **IDE / coding-agent sidecar (MCP)**: connect MCP-capable coding agents (such
  as Gemini CLI) via [reference/docs/mcp.md](reference/docs/mcp.md) for live
  `mantis_check_change` diff gating and background scans.

### Common Options

```bash
# One-shot model or sandbox override without changing workflow.local.json
./run.sh /path/to/repo --sandbox static-only --model vertex_ai/gemini-3.8-flash

# Steer the planner in plain language, or exclude vendored/generated paths
./run.sh /path/to/repo --focus "look for IDOR"
./run.sh /path/to/repo --exclude vendor,testdata --exclude 'third_party/*'

# Choose an explicit scan mode, or verify fixes incrementally after editing code
./run.sh /path/to/repo --scan-mode file-by-file   # or whole, cross-functional, auto
./run.sh /path/to/repo --scan-mode changed        # new run after edits (omit --resume)

# Resume an interrupted or budget-paused run on the same snapshot
./run.sh /path/to/repo --resume                   # inherits recorded scan mode

# Export/import learned knowledge alongside a repository (.mantis/knowledge/)
.venv/bin/python3 scripts/knowledge.py export --db knowledge.db --repo /path/to/repo
./run.sh /path/to/repo --import-knowledge /path/to/repo/.mantis/knowledge

# Control spend ceilings and parallelism (SQLite lock wait defaults to max(60s, 15s x --parallel))
./run.sh /path/to/repo --max-tokens 2M --cache-discount 1
./run.sh /path/to/repo --no-budget --parallel 32 --db-timeout 600   # or MANTIS_DB_TIMEOUT=600

# Synthesize a custom multi-agent research graph for a specific objective
./run.sh /path/to/repo --objective "Audit for SSRF in webhook handlers"
```

See [reference/README.md](reference/README.md) for the complete CLI reference,
scan modes, sandboxes, and Harness² evolution loop.

## Overview of Mantis

Mantis is roughly designed to:

- Review history of a codebase to look for historical vulnerabilities we do not
  wish to repeat
- Build a semantic tree-sitter index (20+ native grammars across backend,
  frontend, mobile, smart contracts, shell/IaC/policy, and firmware/RTL) and
  discover repository docs (`README.md`, `SECURITY.md`, `THREAT_MODEL.md`,
  architecture specs) as untrusted intent context to verify against real code
- Automatically generate a threat model
- Build up a set of hypotheses for individual agents to research (or simply
  "scan every file")
- Execute on those research plans
- Deduplicate existing findings
- Triage/critique findings to combat hallucination and statically verify
  production viability
- Reproduce the vulnerability to varying degrees, depending on available
  environments, anywhere from a static guess at what an exploit might look like
  up to a unit test or even spinning up a mock server to attempt to exploit
- Look across known vulnerabilities to attempt to build more impactful chains
- Patch discovered vulnerabilities, using an adversarial loop to verify the
  vulnerability is really fixed
- Calibrate all findings based on an established rubric to combat LLM inflation
  of severity (surfacing the most critical risks to humans instead of spewing
  thousands of "criticals")
- Reflect on each iteration of the loop to look for things we've learned in the
  now completed round of research
- Based on all of the collected learnings, threat model, and knowledge base, use
  the `/mantis-advise` skill (or the [MCP server](reference/docs/mcp.md)) to
  develop code more securely and ensure that during development you do not
  repeat prior mistakes or trigger edge cases in code that were previously
  protected by some guard that was removed

Additionally, the ADK reference harness shows some of the neat ways in which we
can build agentic workflows. Specifically, `reference/workflow.json` shows how a
deep review is done, and research graph synthesis
(`./run.sh target --objective "..."`) allows generating custom graph topologies
on the fly. This is a very powerful construct because you can use this to build
any kind of agentic deep dive security review you might imagine.

Mantis works out of the box across full-stack web apps, backend/systems code,
firmware/RTL (Verilog, SystemVerilog, VHDL, embedded/eBPF), Smart Contracts/ZK,
CI/CD supply chains, mobile (Swift, Objective-C, Dart, Android), AI/ML/agentic
pipelines, desktop/browser extensions, and Cloud/IaC/policy repos — with
blocklist-default file selection so novel languages and DSLs are never silently
dropped. It is also intended to be a starting point rather than a rigid set of
instructions: you can further adapt, tune, and extend the
[skills and specialized domain guides](README_AGENTS.md#adaptability--specialized-domains)
to fit your organization's specific stack. We provide an ADK-based reference
harness which works out of the box, but any competent coding agent should be
able to convert this to use your framework of choice.

We strongly recommend using AI to iterate on Mantis or integrate it with your
existing harness. Use your internal documentation, coding standards, and build
systems to augment the threat models you use for scanning. We also strongly
recommend adapting risk calibration to your environment and risk tolerance.

Above all, while orchestrated vulnerability discovery is incredibly powerful and
useful, it is even more important to use this in a suitably isolated environment
to prevent impacting production systems. The ADK reference harness provides some
example sandboxes for testing, but if you use the most advanced frontier models
you should go beyond this and additionally set up an additional sandboxing layer
that itself contains very strong monitoring to look for escape attempts.

## License

Mantis is licensed under the [Apache License, Version 2.0](LICENSE). Every
Python and shell file carries the license header;
`reference/scripts/check_license_headers.py` (run by `pre-commit` and the test
suite) keeps it that way.

## Disclaimers

This is not an officially supported Google product. If you are looking for a
managed and hosted code security agent rather than building your own, we
recommend [CodeMender](https://cloud.google.com/security/codemender). This
project is not eligible for the
[Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

This project is intended for demonstration purposes only. It is not intended for
use in a production environment.

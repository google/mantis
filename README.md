# Mantis Skills: Portable Toolkit for Building Security Review Harnesses

> [!CAUTION] **USE AT YOUR OWN RISK. BE EXTREMELY CAREFUL.** This suite is
> designed to generate and execute autonomously generated code that may be
> unstable or perform unexpected actions. **USE THIS ONLY IN ISOLATED,
> RESTRICTED ENVIRONMENTS.** Never run this suite on a machine with access to
> production systems, sensitive data, or internal networks. See the "Unattended
> Cloud Deployment" section for mandatory hardening requirements.

> [!IMPORTANT] **RESPONSIBLE USE** AI models are non-deterministic and can
> hallucinate findings or generate incorrect patches. **All findings must be
> manually verified by a security expert before being reported.** Do not
> mass-file unverified, AI-generated reports to open-source maintainers. A
> failure to automatically reproduce a vulnerability does not definitively mean
> it is a false positive, nor does a successful reproducer guarantee the bug is
> exploitable in all contexts. Use these skills responsibly.

Mantis is a decoupled, sequential, and security-focused set of skills designed
for use with Coding Agents. It is intended to be a starting point rather than a
rigid set of instructions. You should adapt, tune, and extend these skills to
fit your organization's specific software or hardware stack.

The Mantis skills can be adapted to
[specialized domains](README_AGENTS.md#adaptability--specialized-domains) (such
as Hardware/RTL, Infrastructure as Code, ML pipelines, or compiled firmware).

We strongly recommend using AI to iterate on these skills and using your
internal documentation, coding standards, and build systems to augment the
threat model. We also strongly recommend adapting risk calibration to your
environment and risk tolerance.

For more information on securing AI systems, see Google's
[Secure AI Framework (SAIF)](https://safety.google/safety/saif/).

Above all, while orchestrated vulnerability discovery is incredibly powerful and
useful, it is even more important to use this in a suitably isolated environment
to prevent impacting production systems. See the notes on unattended cloud
deployment later in this guide.

______________________________________________________________________

## Architecture and Sequential Flow

For a detailed breakdown of the pipeline stages, sequential flow, and
inter-stage contracts, please refer to the
[Agent Reference Guide](README_AGENTS.md).

______________________________________________________________________

## Prerequisites and Setup

Before executing any skills, ensure your local CLI environment is fully
configured. Because Mantis is intended to be platform agnostic we do not
recommend any specific software. We have used it with Gemini CLI and Antigravity
CLI, among others. Any coding agent framework should work. We have used these
skills successfully with both the Google ADK and Antigravity SDK. You might also
consider:

1. **Docker** For testing containers.

2. **gVisor (runsc)**: For enhanced security when executing untrusted
   AI-generated crash reproducer code, register the `runsc` runtime in your
   Docker daemon configuration (`/etc/docker/daemon.json`):

   ```json
   {
     "runtimes": {
       "runsc": {
         "path": "runsc"
       }
     }
   }
   ```

3. **Relevant Cloud SDKs**: If running remote cloud sandboxes instead of local
   containers.

### Installing the Skills

You can install these skills either globally (available across all projects) or
locally to a specific workspace. You can also ask your coding agent for help.
Clone this repo then tell your coding agent you want to use these skills to
review your codebase!

To install the skills via CLI:

```shell
npx skills add google/mantis
```

______________________________________________________________________

## Beginner's Guide & Best Practices

If you are new to automated AI-assisted defensive security reviews, keep these
recommendations in mind:

### 1. "Interactive Mode" (Human-in-the-Loop)

To get started with Mantis, you should run the pipeline in an "Interactive
Mode".

Launch your coding agent in your usual software or hardware development
workflow. Then, type the slash commands (e.g., `/mantis-plan`) individually. Do
not use `--yolo` or `--dangerously-skip-permissions` flags or any kind of
automatic approval of actions without carefully considering the security
implications.

Your coding agent should pause and prompt you for human approval before
executing any sensitive command (especially when the `/mantis-reproduce` or
`/mantis-patch` agents attempt write to files or run code). This allows you to
inspect what the AI intends to run. To run without human approval you must
implemenent strong boundaries to keep the agents contained.

### 2. Hardened Security & The "No Host-Run" Rule

AI models can sometimes generate code payloads that break the host. Run scripts
or generated code *only* inside a sandbox if you aren't reading them.

The `/mantis-reproduce` and `/mantis-patch` skills are explicitly instructed to
execute payloads inside isolated container environments with networking disabled
(`--network none`, for example), but you still must take care to ensure that
they don't make mistakes and skip this step.

**Disclaimer:** While these instructions are designed to maintain isolation,
**AI agents are non-deterministic**. They may occasionally attempt unsafe
actions or bypass intended constraints if the local environment allows it. These
instructions do NOT provide an absolute guarantee of safety. Always prioritize
running this suite in a dedicated, isolated VM to provide a reasonable security
boundary that the AI cannot escape.

### 3. Model Choice & Tiered Efficiency

To maximize the speed and efficiency of your automated pipeline, you should
strategically pair the right
[AI model class with the specific task](README_AGENTS.md#model-selection--efficiency-guidelines).
You do not need to use the heaviest, most advanced frontier models for every
stage.

### 4. Understanding False Positives (The "Negative Filter" Rule)

AI-based scanning will produce
[false positives](README_AGENTS.md#understanding-false-positives-the-negative-filter-rule)
(the review stage applies negative rules to filter them).

- **Expect Noise**: Customize the negative validation filters in
  `/mantis-review` to match your codebase.
- **Iterate Small**: Start with narrow-scope scans to tune the pipeline rather
  than running a repository-wide sweep on Day 1.

______________________________________________________________________

## Running the Pipeline (Manual Mode)

You can execute the reviewing stages sequentially from **inside** your active
CLI terminal.

1. Start your CLI from your terminal.

2. Inside the interactive UI prompt, type the skills sequentially:

   ```text
   # 0. (Optional) Analyze repository's version control system (VCS) history and extract past vulnerabilities
   /mantis-history

   # 1. (Optional) Generate mantis-summary.md directory maps
   /mantis-summarize

   # 2. Synthesize codebase structure and historical learnings into the Markdown Knowledge Base
   /mantis-architecture

   # 3. Iteratively develop the project's living threat model based on the KB
   /mantis-threat-model

   # 4. Map target external boundary and build scanning roadmap, injecting KB references
   /mantis-plan

   # 5. Run multi-threaded/sequential security flaw sweep using injected context
   /mantis-researcher

   # 6. Consolidate overlapping files and duplicate bugs
   /mantis-dedupe

   # 7. Verify code validity & filter false positives
   /mantis-review

   # 8. Eliminate non-viable production issues
   /mantis-critic

   # 9. Generate proof-of-concept crash reproducers and run them in sandboxes
   /mantis-reproduce

   # 10. Combine validated individual findings into multi-step exploit chains
   /mantis-chain

   # 11. Apply minimal fixes and verify they block the crash reproducer
   /mantis-patch

   # 12. Calculate final matrix risk ratings and append to individual findings
   /mantis-calibrate

   # 13. Extract insights from execution trajectories and append to the learnings inbox
   /mantis-reflect

   # 14. Generate human-readable security review packet report
   /mantis-report

   # 15. (Manual Step) Review the report. Optionally, you can apply & commit approved patches to your codebase. To continue analysis, archive workspace/findings/, and loop back to Step 2 to start the next pass.
   ```

______________________________________________________________________

## Building Deterministic Pipelines & Non-Determinism

For information on how to build production-grade deterministic pipelines
wrapping these skills, and how to manage LLM non-determinism, see the
[Agent Reference Guide](README_AGENTS.md).

______________________________________________________________________

## Advanced / Unattended Cloud Deployment (GCE)

Running the continuous review loop 24/7 in an unattended state requires a
hardened environment to mitigate security risks (such as prompt injection). For
the step-by-step hardened Google Compute Engine (GCE) deployment guide, see the
[Agent Reference Guide](README_AGENTS.md#advanced--unattended-cloud-deployment-gce).

______________________________________________________________________

## Meta-Agent Orchestration & Evaluation

For details on autonomous Meta-Agent execution and how to evaluate/optimize
skill performance, see the [Agent Reference Guide](README_AGENTS.md).

______________________________________________________________________

## Roadmap / Future Work

- **Continuous Pipeline:** The current pipeline is designed to be run as a
  point-in-time review of a codebase, and not as something that is intended to
  regularly sync with upstream changes mid-run. It should be straightforward (if
  a little tricky) to tweak the pipeline to better support this, but it probably
  will not work today.
- **Skill Self-Improvement (Meta-Learning):** The current
  `workspace/learnings.jsonl` and Knowledge Base (KB) architecture tracks
  codebase-specific empirical outcomes to adapt the `THREAT_MODEL.md` and
  context pointers. Future iterations of the pipeline could take this a step
  further and use this historical data to reflect on and automatically rewrite
  its own `SKILL.md` prompts. For example, if a certain type of hallucination is
  repeatedly caught by the Critic, a self-improvement meta-agent could update
  the Researcher's `SKILL.md` instructions to explicitly filter out that
  specific pattern before it even reaches the Review stage. **Security Note:**
  Committing automated changes to `SKILL.md` files must always be human-gated to
  prevent an attacker from using prompt injection (e.g., via a malicious payload
  in a target file) to trick the meta-agent into ignoring a vulnerability class
  globally.
- **Software Dark Factory:** Integrate this pipeline into an entirely AI driven
  software development. Instead of vulnerable discovery for action by humans,
  Mantis would become the autonomous vulnerability research and release gating
  component of the dark factory. Before the dark factory can push to production,
  it must have had N hours of adversarial vulnerability research or "red
  teaming" by a pipeline like Mantis.

______________________________________________________________________

## Troubleshooting Guide

### 1. Loop Iterations are Re-Evaluating the Same Code

- **Symptom:** The loop keeps reviewing the same files and reporting identical
  bugs.
- **Solution:** Ensure `/mantis-architecture` completes successfully and writes
  its synthesized knowledge to the `workspace/kb/` directory. The `/mantis-plan`
  strategist checks this Knowledge Base to dynamically skip already analyzed
  areas. Check that file permissions allow writing to `workspace/kb/`.

### 2. Other Issues

- **Symptom:** Something isn't working.
- **Solution:** Ask an AI coding tool to review your pipeline and the
  conversations or trajectories that are leading to the unexpected behavior.
  They will often give you useful insights.

This is not an officially supported Google product. This project is not eligible
for the
[Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

This project is intended for demonstration purposes only. It is not intended for
use in a production environment.

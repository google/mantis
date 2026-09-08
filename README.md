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

Mantis is a set of skills along with an ADK reference harness for building
secure software in the new AI era of software development.

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

# 4. (Optional) Run Research Graph Synthesis for a Specific Objective
./run.sh path/to/code --objective "Audit for Server-Side Request Forgery and SSRF in webhook handlers"
```

## Overview of Mantis

Mantis is roughly designed to:

- Review history of a codebase to look for historical vulnerabilities we do not
  wish to repeat
- Build a semantic index (and/or summaries) of the codebase for efficient code
  navigation
- Automatically generate a threat model
- Build up a set of hypotheses for individual agents to research (or simply
  "scan every file")
- Execute on those research plans
- Deduplicate existing findings
- Triage/critique findings to combat hallucination and statically verify
  production viability
- Reproduce the vulnerability to varying degrees, depending on available
  environments, anywhere from a static guess at what an exploit might look up up
  to a unit test or even spinning up a mock server to attempt to exploit
- Look across known vulnerabilities to attempt to build more impactful chains
- Patch discovered vulnerabilities, using an adversarial loop to verify the
  vulnerability is really fixed
- Calibrate all findings based on an established rubric to combat LLM inflation
  of severity (surfacing the most critical risks to humans instead of spewing
  thousands of "criticals")
- Reflect on each iteration of the loop to look for things we've learned in the
  now completed round of research
- Based on all of the collected learnings, threat model, and knowledge base, use
  the `/mantis-advise` skill to develop code more securely and ensure that
  during development you do not repeat prior mistakes or trigger edge cases in
  code that were previously protected by some guard that was removed

Additionally, the ADK reference harness shows some of the neat ways in which we
can build agentic workflows. Specifically, `reference/workflow.json` shows how a
deep review is done, and research graph synthesis
(`./run.sh target --objective "..."`) allows generating custom graph topologies
on the fly. This is a very powerful construct because you can use this to build
any kind of agentic deep dive security review you might imagine.

Mantis is intended to be a starting point rather than a rigid set of
instructions. You should adapt, tune, and extend this harness to fit your
organization's specific software or hardware stack. We provide an ADK-based
reference harness which works out of the box, but any competent coding agent
should be able to convert this to use your framework of choice.

The Mantis skills can be adapted to
[specialized domains](README_AGENTS.md#adaptability--specialized-domains) (such
as Hardware/RTL, Infrastructure as Code, ML pipelines, or compiled firmware).

We strongly recommend using AI to iterate on these skills and using your
internal documentation, coding standards, and build systems to augment the
threat models you use for scanning. We also strongly recommend adapting risk
calibration to your environment and risk tolerance.

Above all, while orchestrated vulnerability discovery is incredibly powerful and
useful, it is even more important to use this in a suitably isolated environment
to prevent impacting production systems. The ADK reference harness provides some
example sandboxes for testing, but if you use the most advanced frontier models
you should go beyond this and additionally set up an additional sandboxing layer
that itself contains very strong monitoring to look for escape attempts.

## Disclaimers

This is not an officially supported Google product. This project is not eligible
for the
[Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

This project is intended for demonstration purposes only. It is not intended for
use in a production environment.

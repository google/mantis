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

# 4. (Optional) Tell the planner what to hunt for, in plain language (standard pipeline)
./run.sh path/to/code --focus "look for IDOR"

# 4b. (Optional) Leave vendored or generated code out of the scan
./run.sh path/to/code --exclude vendor,testdata --exclude 'third_party/*'

# 4c. (Optional) Keep what Mantis learned in the repository, and read it back next time
python3 scripts/knowledge.py export --db knowledge.db --repo path/to/code   # writes .mantis/knowledge/
./run.sh path/to/code --import-knowledge path/to/code/.mantis/knowledge

# 4d. (Optional) Choose a scan mode, then verify fixes incrementally on the same knowledge.db
./run.sh path/to/code --scan-mode file-by-file   # or whole, cross-functional, auto (see reference/README.md)
./run.sh path/to/code --scan-mode changed        # new run after editing code (omit --resume)

# 4e. (Optional) Resume an interrupted or partially failed run on the same snapshot
./run.sh path/to/code --resume                   # inherits the run's recorded scan mode

# 5. (Optional) Set or remove the spend ceiling for a run
./run.sh path/to/code --max-tokens 2M --cache-discount 1   # hard cap, every token at full price
./run.sh path/to/code --no-budget --parallel 32            # no ceiling, for long unattended runs
#    Parallel campaigns share one SQLite database; a writer waits up to
#    15s x --parallel (min 60s) for the lock. Raise it on slow disks:
./run.sh path/to/code --parallel 32 --db-timeout 600   # or MANTIS_DB_TIMEOUT=600

# 6. (Optional) Research Graph Synthesis: designs a new agent-graph topology for your objective
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

## License

Mantis is licensed under the [Apache License, Version 2.0](LICENSE). Every
Python and shell file carries the license header;
`reference/scripts/check_license_headers.py` (run by `pre-commit` and the test
suite) keeps it that way.

## Disclaimers

This is not an officially supported Google product. This project is not eligible
for the
[Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

This project is intended for demonstration purposes only. It is not intended for
use in a production environment.

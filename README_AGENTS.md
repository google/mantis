# Mantis Skills: Reference Guide for AI Agents

This document is the canonical reference guide for AI Agents operating in this
workspace. It describes the Mantis pipeline architecture, the individual skills
(stages), the inter-stage data contracts, and the design patterns required to
run and extend the pipeline.

As an agent, you must adhere to the contracts, file paths, and execution
patterns defined in this document.

______________________________________________________________________

## Adaptability & Specialized Domains

While the default skills look for generic security issues, business logic
problems, and authorization vulnerabilities in typical web/cloud applications,
they can be adapted for:

- **Hardware / RTL Reviews**: Auditing Register-Transfer Level (RTL) designs
  (SystemVerilog, VHDL) for security properties or logical bugs.
- **Infrastructure-as-Code (IaC)**: Analyzing cloud deployment boundaries,
  Terraform state, or Kubernetes RBAC configurations for privilege escalation
  paths.
- **Data & ML Pipelines**: Auditing training data ingress, model serialization
  formats (e.g., Pickle vulnerabilities), or boundary constraints between data
  science notebooks and production.
- **Compiled Binaries & Firmware (Gray-Box Auditing)**: Pointing the suite at
  compiled release artifacts (using tools like `unblob`, `Ghidra`, `radare2`,
  `qemu`, or `unicorn`) without providing source code. The intent of this mode
  is to emulate a third-party security researcher, allowing you to see exactly
  what vulnerabilities are discoverable by adversaries who only have access to
  your released binaries.
- **Custom Test Environments**: Replacing the default container reproduction
  stage with isolated VMs, physical hardware testbeds (via USB/serial), or
  custom simulators.

______________________________________________________________________

## Architecture and Sequential Flow

The Mantis Skills suite is designed as a modular, decoupled set of tools that
can be executed sequentially or in parallel. Each stage reads and writes to a
shared state stored on disk.

> [!IMPORTANT] **Snapshot Model (opt-in living/synced support):** By default the
> pipeline reviews a **single, static snapshot** of the target and does not sync
> or watch a live codebase — this is the unchanged, default behavior. When the
> **opt-in** snapshot model is enabled (`--sync` / snapshot arguments), each
> pass pins its own **immutable** copy of the target, every stage reads that
> pinned copy (so edits made mid-pass are ignored), every finding is stamped
> with the snapshot it was discovered against, and the target is synced only
> **non-destructively, at a pass boundary**. Run WITHOUT these arguments and
> each stage runs in MODE-OFF — byte-for-byte today's behavior (a point-in-time
> review of the current directory with all verdicts permitted) — rather than
> stopping. Reserve "non-authoritative" for HALT mode (`--sync` requested but
> snapshot could not be pinned). See [The Snapshot Model](#the-snapshot-model)
> for the full contract.

```mermaid
graph TD
    subgraph CoreStages [Pipeline Execution Loop]
        Meta["/mantis-meta-agent (Supervisor)"] --> Hist["/mantis-history (History Extractor)"]
        Hist --> Sum["/mantis-summarize (Summarizer)"]
        Sum --> Arch["/mantis-architecture (KB Architect)"]
        Arch --> TM["/mantis-threat-model (Threat Modeler)"]
        TM --> Plan["/mantis-plan (Strategist)"]
        Plan --> Res["/mantis-researcher (Auditor)"]
        Res --> Ded["/mantis-dedupe (Deduplicator)"]
        Ded --> Rev["/mantis-review (Reviewer)"]
        Rev --> Cri["/mantis-critic (Viability Critic)"]
        Cri --> Rep["/mantis-reproduce (Reproducer)"]
        Rep --> Cha["/mantis-chain (Chainer)"]
        Cha --> Pat["/mantis-patch (Patcher)"]
        Pat --> Cal["/mantis-calibrate (Calibrator)"]
        Cal --> Ref["/mantis-reflect (Reflector)"]
        Ref --> Rpt["/mantis-report (Reporter)"]
        Rpt -.->|Next Loop Iteration| Arch
    end

    FileHist[("workspace/historical_learnings.jsonl")]
    FileSum[("mantis-summary.md")]
    FileKB[/"workspace/kb/ (Markdown KB)"/]
    FilePlan[("workspace/plan.json")]
    FileFind[("workspace/findings/*.json")]
    FileLearn[("workspace/learnings.jsonl")]
    FileRpt[/"workspace/report/review_packet-latest.md"/]

    Meta --> Hist
    Hist --> Sum
    Sum --> Arch
    Arch --> TM
    TM --> Plan
    Plan --> Res
    Res --> Ded
    Ded --> Rev
    Rev --> Cri
    Cri --> Rep
    Rep --> Cha
    Cha --> Pat
    Pat -.->|Re-attack Bypass Loop| Rep
    Pat --> Cal
    Cal --> Ref
    Ref --> Rpt

    Hist -.->|Generates| FileHist
    Hist -.->|Reads| FileSum
    Sum -.->|Reads| FileHist
    Sum -.->|Generates| FileSum
    Arch -.->|Reads| FileHist
    Arch -.->|Generates| FileKB
    Arch -.->|Reads/Clears| FileLearn
    TM -.->|Reads/Updates| FileKB
    Plan -.->|Reads| FileKB
    Plan -.->|Reads| FileSum
    Plan -.->|Generates| FilePlan

    Res -.->|Reads| FilePlan
    Res -.->|Reads| FileKB
    Res -.->|Creates| FileFind
    Ded -.->|Reads| FileLearn
    Ded -.->|Merges| FileFind
    Rev -.->|Updates| FileFind
    Cri -.->|Updates| FileFind
    Rep -.->|Updates| FileFind
    Cha -.->|Reads| FileKB
    Cha -.->|Creates| FileFind
    Pat -.->|Updates| FileFind
    Cal -.->|Updates| FileFind

    Ref -.->|Parses Trajectories & Appends| FileLearn
    Cri -.->|Appends| FileLearn
    Pat -.->|Appends| FileLearn

    Rpt -.->|Reads| FileFind
    Rpt -.->|Generates| FileRpt
```

01. **`/mantis-meta-agent` (Supervisor):** A persistent, overarching agent that
    launches the continuous loop, monitors execution, handles errors, reports
    findings, and archives the `workspace/findings/` directory between loops.
02. **`/mantis-history` (History Extractor):** An optional pre-processing step
    that analyzes the repository's version control system (VCS) history to
    extract past vulnerabilities, security fixes, and vulnerability patterns,
    saving findings to `workspace/historical_learnings.jsonl`.
03. **`/mantis-summarize` (Summarizer):** An optional pre-processing step that
    generates a `mantis-summary.md` for each directory, reading past
    vulnerabilities from `workspace/historical_learnings.jsonl` to enrich
    summaries and provide a quick reference map to optimize downstream planning
    and research.
04. **`/mantis-architecture` (Knowledge Base Architect):** Analyzes the codebase
    and clears the `workspace/learnings.jsonl` inbox to synthesize a permanent,
    interlinked Markdown Knowledge Base (`workspace/kb/`) detailing entities,
    data flows, and historical vulnerability classes.
05. **`/mantis-threat-model` (Threat Modeler):** Evaluates the entities and
    architecture defined in the KB to establish or refine a living
    `workspace/kb/THREAT_MODEL.md`, focusing on trust boundaries and attacker
    profiles.
06. **`/mantis-plan` (Strategist):** Scans workspace boundaries and reads the KB
    indices to output a targeted review strategy into `workspace/plan.json`,
    injecting specific `kb_references` file paths for context.
07. **`/mantis-researcher` (Mantis Researcher):** Executes file-by-file triage
    and deep security flaw reviews, outputting hotspots as individual JSON files
    in `workspace/findings/`.
08. **`/mantis-dedupe` (Deduplicator):** Groups index-based duplicate findings,
    merging records and deleting redundancies within `workspace/findings/`.
09. **`/mantis-review` (Validator):** Filters out false positives using strict
    pragmatic constraints, updating the status in
    `workspace/findings/<id>.json`.
10. **`/mantis-critic` (Critic):** Verifies release-build crash reproducibility
    (ignoring debug/assert checks), updates production viability in
    `workspace/findings/<id>.json`, and appends false positives/non-viable paths
    to `workspace/learnings.jsonl`.
11. **`/mantis-reproduce` (Proof-of-Concept Developer):** Writes
    Proof-of-Concept Reproduction Scripts (Repros) or raw payloads, executes
    them in isolated environments such as gVisor or Virtual Machines, and
    updates reproduction status in `workspace/findings/<id>.json`.
12. **`/mantis-chain` (Vulnerability Chainer):** Analyzes individual validated
    findings and knowledge base primitives to identify and construct complex
    multi-step exploit chains, creating new "Super Findings" in
    `workspace/findings/`.
13. **`/mantis-patch` (Patcher):** Generates and applies code fixes, runs
    post-patch validation tests inside the sandbox, updates patch status in
    `workspace/findings/<id>.json`, and appends logs to
    `workspace/learnings.jsonl`.
14. **`/mantis-calibrate` (Risk Calibrator):** Calculates a final numerical
    Mantis Risk Score (1-10) for each finding in the workspace directory based
    on impact, evidence, and viability, appending the results directly to each
    `workspace/findings/<id>.json` file.
15. **`/mantis-reflect` (Reflector):** Parses the execution trajectories of the
    agents from the current round, extracting false assumptions, tool failures,
    and successes, and appends these structured insights to the
    `workspace/learnings.jsonl` inbox.
16. **`/mantis-report` (Reporter):** Generates a human-readable security review
    packet containing verified/reproduced findings, evidence, risk rationales,
    and patch information at `workspace/report/review_packet-latest.md` (and
    archives to `review_packet_pass_<N>.md`).

______________________________________________________________________

## The Snapshot Model

Mantis can review **living / synced codebases** through a **snapshot-per-pass**
model. It is **opt-in and default off**: with no `--sync` flag and no snapshot
arguments, a run behaves byte-for-byte as before — a single, point-in-time
review of whatever is on disk (see *MODE-OFF / HALT*, below). Enabling it makes
long-running, continuous reviews of a changing codebase correct instead of
silently wrong.

**Opt-in, default off.** Passing `--sync` (or instructing `/mantis-meta-agent`
to sync) enables the model. Without it, `snapshot_pinned` is never set and every
snapshot-aware check falls through to its pre-existing behavior.

**Each pass pins one immutable snapshot.** At the very start of a pass the
orchestrator materializes an isolated, read-only copy of the target — a
`git worktree` / `hg archive` when the tree is clean, a full copy otherwise —
under `.mantis_snapshots/` (never under `workspace/`). It writes a sentinel file
`.mantis_snapshot_id` into that copy and records the snapshot in state. Every
stage then reads target code through this pinned root (`--snapshot_root`),
identified by a `SNAPSHOT_ID` (`--snapshot_id`).

**How `SNAPSHOT_ID` is computed (the ladder).** The id is computed once per
pass:

- clean git / hg → `commit_hash`
- dirty git / hg → `commit_hash:content_hash`
- multi-vcs (`.repo`) → `revision:content_hash` (a bare manifest revision is a
  branch name and is never trusted for equality on its own)
- no VCS / unknown, copyable → `content:<content_hash>`
- single binary / firmware → `sha256:<artifact_hash>`
- live endpoint / uncopyable / copy failed → `live:<ISO8601>`, and the pass runs
  **unpinned**

`content_hash` is a SHA-256 over **every** file in the pinned copy. Because the
dirty / no-VCS / multi-vcs tiers embed that content hash, an **unchanged dirty
or no-VCS tree still matches across passes** and receives full verification and
deduplication, while a tree that actually changed does not.

**Findings are pinned to their discovery snapshot.** Each finding records a
`discovery_commit` — the `SNAPSHOT_ID` it was found against. Trusting decisions
(dedupe filtering, false-positive / non-viable verdicts, reproduction, patching,
chaining) proceed only when a finding's `discovery_commit` **exactly equals**
the current `SNAPSHOT_ID`. A finding discovered against a different or absent
snapshot is re-researched / re-verified — never silently filtered, dropped, or
marked secure.

**Edits made mid-pass are ignored.** Because every stage reads the pinned copy,
changes to the live tree *during* a pass cannot shift line numbers, break
reproducers, or corrupt patches within that pass. Builds and generated artifacts
are written to a private temporary shadow, never under the pinned root. New code
is picked up at the **next** pass boundary.

**Boundary sync is non-destructive and only at a pass boundary.** When enabled,
sync is the first action of a pass and runs only when `workspace/findings/` is
empty (the previous pass's findings have been archived), so no in-flight finding
is stranded across a code change. Sync is strictly non-destructive: it is
skipped entirely if the tree is dirty, ahead of upstream, on a detached HEAD, or
has no upstream, and it never runs `git reset --hard`, `git checkout -- .`,
`git clean`, `hg update -C`, or anything else that discards local work. When it
does run it is fast-forward only (`git fetch && git merge --ff-only`,
`hg pull && hg update --check`, `repo sync -c`); any failure keeps the current
tree and proceeds. After a successful sync the code has changed, so the
Knowledge Base and directory summaries from the previous snapshot are stale and
must be **force-refreshed** (re-run `/mantis-architecture`) before planning the
new pass.

**MODE-OFF / HALT (never deadlocks).** The 3-state snapshot model (per
`schema.json`) branches on `active_snapshot` presence:

- **MODE-OFF** (`active_snapshot` ABSENT — plain interactive / manual use, or an
  orchestrator that does not implement the lifecycle): the stage does **not**
  stop. It runs byte-for-byte as today's behavior — a point-in-time review of
  the current directory with **all verdicts permitted** (`VERIFIED_SECURE`,
  `failed_to_reproduce`, `DUPLICATE`, etc. are all emittable, because MODE-OFF
  is defined as exactly today's behavior). Every snapshot match check reports
  "not matched" (no `active_snapshot` to compare against). Mid-run edits are not
  frozen.

- **HALT** (`active_snapshot` PRESENT with `snapshot_pinned = false` — `--sync`
  was requested but the snapshot could not be pinned: live endpoint,
  too-big-to-copy, copy failure, dirty/racing tree): the stage does **not**
  stop, but runs **degraded**: results are non-authoritative, and no
  authoritative `VERIFIED_SECURE` / `failed_to_reproduce` verdict is emitted
  (the HALT ceiling forces `not_attempted` / `VERIFICATION_INCOMPLETE` instead).
  Live-endpoint or uncopyable targets run in HALT by design when `--sync` is
  requested.

**Absent → conservative (backward compatible).** Every new field is optional.
Any absent / empty / null new field routes to the safe branch: absent
`discovery_commit` → re-research; absent `snapshot_history` predecessor → treat
all files as changed; absent reached-sink evidence → `not_attempted` (never a
negative verdict); absent `active_snapshot` → MODE-OFF (byte-for-byte today's
behavior; all verdicts permitted). No new `required` field or `allOf` gate is
added, so existing workspaces and pre-upgrade findings validate and run
unchanged.

**New optional state/finding fields and stage flags.**

- **State** (`workspace/.mantis_state.json`): `active_snapshot`
  `{root, snapshot_id, snapshot_pinned, pass, vcs_type}`; append-only
  `snapshot_history` (one `{pass, snapshot_id, snapshot_pinned, timestamp}`
  entry per pass, never overwritten); `vcs_info` continues to record `vcs_type`
  / `commit_hash` / `revision` / `dirty`.
- **Finding**: `discovery_commit` — the `SNAPSHOT_ID` the finding was discovered
  against.
- **Flags every stage accepts**: `--snapshot_root=<pinned copy>`,
  `--snapshot_id=<SNAPSHOT_ID>`, `--state_root=<workspace parent>`, and
  (orchestrator only) `--sync` to enable boundary sync. `--target_root`
  overrides all of these when a caller hands a stage a prepared tree (for
  example, a patched shadow during re-attack verification).

Any conformant harness (CLI, ADK, or a custom deterministic pipeline) implements
this per pass: sync first, detect VCS and compute `SNAPSHOT_ID`, pin the
immutable copy and write the sentinel, record `active_snapshot` / append
`snapshot_history`, run every stage with `--snapshot_root` / `--snapshot_id` /
`--state_root`, then archive findings and increment the pass. A harness that
does not implement it leaves `snapshot_pinned` unset and gets today's behavior.

______________________________________________________________________

## Building Deterministic Pipelines (Production-Grade)

While the `/mantis-meta-agent` provides dynamic steering for exploratory
security research, we highly recommend wrapping the Mantis Skills in a
**deterministic programmatic pipeline** for use in enterprise or production
settings.

While Python, Bash, or CI/CD workflows are common choices for writing these
deterministic pipelines or custom helper scripts, **Rust** is another option
that some teams have found effective. Rust can be well-suited for
agent-generated code due to:

- **Type and Memory Safety:** Rust's strong static typing and borrow checker
  catch memory safety issues and certain type-level bugs at compile time. While
  this does not prevent logic errors, it can reduce common runtime crashes.
- **Compiler Feedback:** The Rust compiler provides detailed error messages and
  structured suggestions. Some LLMs can utilize this feedback to iteratively
  resolve syntax and type errors during generation.
- **Performance:** Rust provides native performance and predictability, which
  can be beneficial for high-throughput coordination.

The choice of language should depend on your team's familiarity and the target
environment. Some anecdotal reports suggest Rust can work well for complex
orchestrations, but success rates vary significantly based on the specific task,
prompt design, and the model class used.

By treating the individual skills (like `/mantis-researcher`, `/mantis-review`,
and `/mantis-reproduce`) as microservices that read and write JSON state in the
`workspace/findings/` directory, you can build a rigid orchestrator that
provides stronger reliability and security guarantees. Better yet, you should
use more durable and resilient databases instead of json files on a single
machine.

**Before building your harness, strictly adhere to the inter-stage data
contracts defined in [schema.json](schema.json).**

### The Pipeline Adapter Skill (/mantis-pipeline-adapter)

To get started on brainstorming your custom pipeline for high reliability, token
efficiency (such as using UUID-based referencing), and adaptability to custom
environments (via MCP), see the
[Pipeline Adapter Guide](mantis-pipeline-adapter/SKILL.md).

### SAST Seeding (External Tool Ingestion)

For teams that want to augment LLM discovery with findings from external SAST
tools (CodeQL, Semgrep, etc.), the Pipeline Adapter Guide includes a **SAST
Seeding** pattern (Guideline 8). This opt-in adapter ingests external tool
findings as `PROVISIONALLY_VALID` / `NEEDS_RESEARCH` candidates that must earn
their verdict through the unchanged downstream gates. It is purely additive — no
existing skills are modified. The adapter uses a platform-agnostic JSONL IR
format (not SARIF) that any SAST tool can convert to. See
[mantis-pipeline-adapter/references/mantis-sast-seed.md](mantis-pipeline-adapter/references/mantis-sast-seed.md).

### Structural Code Index (AST-Level Context)

For large codebases where grep-based call-site discovery is unreliable, the
Pipeline Adapter Guide includes a **Structural Code Index** pattern (Guideline
9). This opt-in adapter builds a function-level call graph and symbol table
using ctags (zero-dependency) or tree-sitter (pip-installable). See
[mantis-pipeline-adapter/references/mantis-structural-index.md](mantis-pipeline-adapter/references/mantis-structural-index.md).

> **Note on Standalone vs. Harness Mode:** When using Mantis Skills directly
> from the CLI in standalone mode, skills like `/mantis-review` or
> `/mantis-patch` will instruct the LLM to write temporary reusable Python
> scripts to update the JSON state files. However, in a true programmatic
> harness, your orchestrator should override these instructions and provide
> native tool calls or functions for state management to avoid forcing the LLM
> to write one-off scripts.

### Why Build a Programmatic Harness?

- **Determinism:** Some stages such as the reproduction agent or patch agent
  include recommendations to have subagents criticize the repro or patch. While
  it is reasonable to demonstrate the overall workflow, a more deterministic
  critic stage that the agent cannot bypass by "forgetting" to call the critic
  subagent will likely produce better results.
- **Mitigates Prompt Injection Risk:** An LLM orchestrating shell commands is
  susceptible to host-level prompt injection if it ingests malicious code.
  Moving the orchestration to a hardened deterministic pipeline removes the
  LLM's control over the host environment.
- **Enforces Strict Sandboxing:** Rather than relying on the LLM to remember to
  use `--network none` when executing a crash reproducer, your deterministic
  harness can programmatically enforce that untrusted AI-generated payloads are
  executed exclusively within a locked-down VM, container, or gVisor sandbox.
- **CI/CD Integration:** A deterministic script executing the static analysis
  and deduplication stages is predictable and easily integrated into standard
  automated workflows like GitHub Actions or Jenkins.
- **Scale:** The pipeline can be decomposed into several pieces, allowing you to
  scale horizontally across a suitably sized fleet during periods of low
  utilization.
- **Deterministic Reporting:** While the pipeline relies on machine-readable
  JSON files (`workspace/findings/*.json`) to safely maintain internal state, a
  programmatic harness can deterministically translate these JSON findings into
  human-readable Markdown reports or automatically file them into bug-tracking
  systems without risking LLM hallucination or state corruption. Only use an LLM
  for deterministic subsets of this reporting process, such as providing an
  executive summary if necessary.

### The Hybrid Approach

To maintain the dynamic, adaptive nature of the suite while ensuring
deterministic execution, you can build a pipeline that:

1. **Iterates Programmatically:** A harness loops over the workspace, invoking
   the static and dynamic skills via the CLI.
2. **Feeds Learnings Back:** The harness takes the resulting
   `workspace/learnings.jsonl` file and invokes `/mantis-plan` to generate a
   newly updated `workspace/plan.json`, effectively allowing the AI to guide the
   deterministic runner on what to analyze next.
3. **Hardcodes the Execution Sandbox:** You can optionally configure the
   deterministic versions of `/mantis-reproduce` and `/mantis-patch` to *only
   generate* the patch or script file, leaving the actual execution and grading
   to your harness in a strictly controlled sandbox.

______________________________________________________________________

## Exploit Chains and Reproduction Limits

The Mantis pipeline supports identifying complex, multi-step exploit chains (via
`/mantis-chain`), but **it does not attempt to programmatically write or execute
end-to-end reproduction scripts for these chains**.

- **Constituent Reproduction Only:** The pipeline only reproduces the
  individual, constituent findings.
- **Static Confirmation:** An exploit chain finding is marked as
  `statically_confirmed` if all its constituent findings have been individually
  confirmed (either reproduced or statically confirmed).
- **Simplification Decision:** This is an intentional design decision to limit
  complexity, as automated multi-stage exploit orchestration is highly
  environment-dependent. Users wishing to verify end-to-end chains must write
  custom orchestrators or manually verify the combined flow.

______________________________________________________________________

## Patch Verification and Re-attack Constraints

The `schema.json` contract defines validation rules for findings that have been
patched. While `/mantis-patch` is designed to verify patches using a re-attack
step (confirming `reattack_status`), the schema supports several distinct
verification outcome statuses:

- **`VERIFIED_SECURE`**: Completed verification, meaning the post-patch run
  passed AND a successful variant-hunting re-attack was executed. The
  independent re-attack agent authors N ≥ 3 boundary-mutated variant inputs
  (off-by-one around the fixed bound, len±1, sign flips, alternate paths to the
  same sink for memory-safety bugs; equivalent payloads and alternate endpoints
  for non-memory-safety bugs) and the patched shadow must survive ALL of them
  before `VERIFIED_SECURE` is set. An empty or short variant set caps at
  `VERIFICATION_INCOMPLETE` — a vacuous "all zero variants failed" never
  qualifies. A variant only counts as a bypass if it reproduces the original
  vulnerability class (same sink/crash type); junk mutants are discarded.
- **`MITIGATION_PROPOSED`**: Set for binary targets where code patching is not
  possible but a functional or architectural mitigation is proposed in
  `patch_diff`. These may bypass code modification and re-attack checks.
- **`VERIFICATION_INCOMPLETE`**: Set when the initial post-patch verification
  run passed but the subsequent re-attack checks were interrupted or failed due
  to environment timeouts, infrastructure errors, or sandbox limits.

Re-attack fields (`reattack_status`, etc.) are strictly required only when
`patch_status` is `VERIFIED_SECURE`. This is an intentional design decision to
support binary-only targets and verification fallbacks.

______________________________________________________________________

## The Reality of Non-Determinism

A critical concept to understand when using AI for security research is
**Non-Determinism**.

- **Coverage is not an absolute guarantee:** Even though Stage 2
  (`/mantis-plan`) attempts to use programmatic shell scripts to map your entire
  codebase, the agent running those scripts is fundamentally non-deterministic.
  It might occasionally fail to run the script correctly, hallucinate
  parameters, or skip steps.
- **Trajectory/Conversation analysis:** One way to mitigate the lack of
  determinism is to programmatically review all the tool calls made by the
  agents to see what they've done. This can be used to calculate coverage and
  efficiency metrics, although what those numbers mean exactly we will leave to
  your imagination.
- **Reasoning shifts across loops:** Because the LLM's analysis is
  non-deterministic, it may miss a subtle business logic flaw or authorization
  bypass on Pass 1 but identify it clearly on Pass 5 as its internal "attention"
  shifts or as it gains context from other findings. This is why we generally
  recommend running this scanning pipeline many times.
- **Diminishing Returns:** You might expect the pipeline to eventually "finish"
  and stop reporting bugs. In reality, the discovery of findings often does not
  stop completely; rather, the *quality and severity* of the findings will
  eventually degrade as the LLM starts hallucinating or reaching for pedantic
  non-issues.

The continuous loop is designed to leverage this non-determinism allowing the AI
multiple passes to catch things it missed. However, **it is up to each user to
experiment with the suite, review the Risk Calibrator scores on the findings,
and determine for themselves when the quality of findings has dropped enough to
pause the loop.** In the long term you will also have to determine how often to
rescan, such as when new models with greater capabilities are made available or
when a codebase has received sufficiently large changes to warrant a complete
rescan instead of just an analysis of a given diff or changelist.

______________________________________________________________________

## Meta-Agent Orchestration Pattern

For a truly autonomous and persistent security operation, you can employ the
**Meta-Agent Orchestration** pattern by invoking the `/mantis-meta-agent` skill.
In this setup, a high-level "Meta-Agent" (a long-lived Gemini or Antigravity CLI
session) is responsible for driving the entire reviewing pipeline.

### The Meta-Agent's Role:

- **Orchestration:** The Meta-Agent manages the execution of each stage natively
  using CLI subagent delegation.
- **Persistence:** It operates in a single, long-lived conversation that spans
  days or weeks, ensuring that the review continues working towards the goal of
  security flaw discovery, patching, and reporting even while you are in
  meetings, away for the evening, or over the weekend.
- **Supervision:** It keeps an eye on the task, handles minor environmental
  hiccups, reads logs, and ensures the pipeline remains operational.
- **Interactive Steering:** A major advantage of this pattern is that you can
  chat with the Meta-Agent while subagents are working. You can ask for status
  updates, collaboratively debug environment issues, or provide high-level
  strategic guidance (e.g., "Deep dive on the image parser") to influence the
  swarm's focus in real-time or in the next loop.
- **Security Boundaries:** While you can run the Meta-Agent with auto-approve
  flags (`--dangerously-skip-permissions`), you must strictly confine it within
  the hardened security boundaries previously described (VPC-SC, no external
  internet, and restricted IAM roles).

This pattern transforms the suite from a set of disjointed tools into a
continuous, self-driving security research operation.

______________________________________________________________________

## Model Selection & Efficiency Guidelines

To maximize the speed and efficiency of your automated pipeline, you should
strategically pair the right AI model class with the specific task. You do not
need to use the heaviest, most advanced frontier models for every stage:

- **Tier 1 (Triage & Deduplication):** For rapid classification sweeps (e.g.,
  Wave 1 of `/mantis-researcher`) or clustering similar text patterns
  (`/mantis-dedupe`), choose fast "flash" or "lite" tier models. These tasks do
  not require immense logic depth, just rapid text parsing, allowing you to
  parallelize massive file sweeps with zero bottleneck. Avoid models that are so
  low-powered they struggle with basic instructions, but don't slow your
  pipeline down by over-allocating intelligence here. Consider allowing the
  planner to specify a difficulty level for a given research task to allow
  targeting simpler questions at faster models, while allowing for some more
  complex vulnerability discovery tasks to benefit from the most advanced
  frontier models.
- **Tier 2 (Deep Reasoning):** Save your most powerful, heavy-reasoning flagship
  models for the highly complex stages that demand deep context and zero-shot
  problem solving: `/mantis-reproduce` (writing functional crash reproducers)
  and `/mantis-patch` (writing side-effect-free codebase fixes).
- **Tip:** For very large repositories, configure your plan `/mantis-plan` to
  focus on specific high-risk subfolders (e.g. `src/crypto/` or `api/`) to keep
  the scan focused and efficient.

Try different tiers of models in different parts of your pipeline to see what
works well and what does not.

______________________________________________________________________

## Understanding False Positives (The "Negative Filter" Rule)

AI-based vulnerability scanning, like SAST of old, can lead to a frustrating
number of false positives. Unlike SAST of old, there are ways to tune this
without creating highly complex rules. Try things and see what works and what
doesn't, then adapt.

- **What to expect:** AI scanners can be overly enthusiastic. To address this,
  the `/mantis-review` stage runs a strict validator applying negative rules.
  (These rules are by no means set in stone but must be adapted, reframed, or
  even split out into a different stage of their own if it suits your use case.)
- **Low/hardening risks are NOT false positives:** Effective risk calibration is
  critical as a first stage of triage of vulnerabilities. Take care when tuning
  your pipeline to ensure the difference between a false positive and something
  that is currently below the risk tolerance bar does not negatively impact your
  ability to detect vulnerabilities.
- **Pragmatism:** Try things and see what works and what doesn't, then adapt.
- **Don't open the firehose all at once:** It is far more efficient to run a
  small scan, triage a few items, and use this to feed back into constructing
  your scanning pipeline. Running a scan over everything and reporting all the
  potential vulnerabilities might work, but in our experience is unlikely to be
  the most successful way to adopt this new technology.

______________________________________________________________________

## Evaluating and Optimizing Mantis Skills

Evaluating an autonomous, multi-agent pipeline like Mantis is notoriously
difficult. Running full end-to-end evaluations for every prompt tweak is
cost-prohibitive in both time and API tokens. To safely modify these skills or
optimize model costs, you should adopt a **Tiered Evaluation Strategy** and
measure proxy metrics rather than just binary success.

### The Tiered Evaluation Strategy

Do not evaluate the entire loop unless necessary. Split your evaluations into
three tiers:

1. **Tier 1: Static Checks**
   - **What it is:** Fast, programmatic linting of the skill files.
   - **What to measure:** Do the `SKILL.md` files parse? Are the YAML
     frontmatters correct? Do they define the required tools? Are the system
     prompts within the context window limits?
2. **Tier 2: Isolated "Unit" Evals**
   - **What it is:** Evaluating a single skill (e.g., `/mantis-patch`) in a
     vacuum, entirely decoupled from the rest of the pipeline.
   - **The Setup:** Feed a static, hardcoded input (a mocked `findings.json` and
     a target file) to a single skill and observe its output.
   - **What to measure:**
     - **Format:** Did it output the expected JSON schema or valid diff?
     - **Tool Use:** Did it attempt to call the correct tools (`run_command` vs
       `view_file`)?
     - **LLM-as-a-Judge:** Use a cheaper, faster model to grade the qualitative
       output with a strict rubric (e.g., "Did the patch address the SQL
       injection? Yes/No.").
3. **Tier 3: The "Golden Dataset" End-to-End Eval**
   - **What it is:** A full run of the entire pipeline. Only run this when doing
     a major release or swapping base model classes (e.g., upgrading to a newer
     flagship model).
   - **The Setup:** Curate a tiny dataset of 3-5 real-world, representative
     vulnerable repositories.
   - **What to measure:** Binary outcomes. Did the final test suite pass? Did
     `/mantis-reproduce` generate a working PoC? You could also perform human
     evaluation to see if there were novel vulnerabilities discovered.

### Measuring the "Unmeasurable"

When evaluating intermediate stages (like `/mantis-researcher`), binary success
is difficult to define. Instead, track these proxy metrics to gauge skill
degradation:

- **Tool Error Rate:** Count how many times the agent's tool calls fail (e.g.,
  bad bash syntax, invalid file paths). A spike in tool errors after a prompt
  change indicates the skill's instruction set has degraded or that the prompts
  might need to be adapted to a new model or coding agent harness.
- **Trajectory Efficiency (Turns/Tokens):** If `/mantis-reproduce` used to write
  a PoC in 5 turns, and after a prompt tweak it takes 150 turns or loops
  repeatedly, that is a measurable regression in efficiency.
- **The "Give Up" Rate:** How often does the agent explicitly output phrases
  like "I cannot determine", "I am stuck", or enter an infinite loop before
  hitting a token limit?

### The "Shadow Eval" Method

Do not build a massive evaluation harness on day one. Instead, build your
dataset organically:

1. When running the pipeline manually, wait for the agents to fail at a specific
   task.
2. Save that exact starting state (the user prompt, the workspace files, the
   JSON state).
3. Fix the skill prompts until the agent succeeds.
4. Turn that specific, isolated state into your first automated test.

By building your eval dataset exclusively from real-world failures, you ensure
you are only spending tokens testing regressions that actually matter.

#### Optimizing Parallelism and Model Selection

When tweaking the pipeline or introducing features like Parallel Trajectory
search, you should run experiments to ensure you are getting a return on your
token investment:

- **Try Different Models:** For any given stage, experiment with swapping the
  flagship model for a cheaper, faster model or a specialized coding model. Use
  the Tier 2 "Unit" Evals to verify if the cheaper model degrades the success
  rate before rolling it out.
- **Evaluate Parallel Trajectories:** If you implement parallel trajectory
  search (e.g., spawning multiple `Researchers` or `Patchers`), test different
  numbers of concurrent agents (e.g., 2, 3, or 5). If running parallel
  researchers always results in them finding the exact same vulnerabilities,
  then the parallelization is not yielding unique value and is just burning
  tokens. Conversely, if parallel patchers consistently produce a much cleaner,
  more idiomatic fix than a single agent, the compute cost can be justified.

______________________________________________________________________

## Code Style & Formatting

To maintain consistency across all skill files, we enforce automatic Markdown
formatting using the public `mdformat` tool with GFM and frontmatter support.

### Setup and Enforcement

This repository includes a `.pre-commit-config.yaml` file to enforce formatting
before every commit.

1. **Install `pre-commit`:**
   ```bash
   pip install pre-commit
   ```
2. **Activate the git hooks:**
   ```bash
   pre-commit install
   ```

Once activated, `pre-commit` will automatically format any modified Markdown
files when you run `git commit`.

### Manual Formatting

If you want to run the formatter manually:

- **Via pre-commit (Recommended):**

  ```bash
  pre-commit run --all-files
  ```

  This is the **only** fully safe method. It creates an isolated venv with the
  correct `mdformat` version (0.7.21) and the required plugins (`mdformat-gfm`,
  `mdformat-frontmatter`), and preserves YAML frontmatter.

- **Via `mdformat` directly (NOT recommended):** If you install `mdformat`
  manually, you **must** install the required plugins and use the `--number` and
  `--wrap 80` flags to match repository standards:

  ```bash
  pip install mdformat==0.7.21 mdformat-gfm mdformat-frontmatter
  mdformat --number --wrap 80 .
  ```

  > [!WARNING] Running bare `mdformat` without `mdformat-frontmatter` will
  > **destroy YAML frontmatter** in all SKILL.md files (replacing `---`
  > delimiters with underscores and collapsing the YAML into a markdown
  > heading). Never run `mdformat` directly unless you have installed the
  > plugins above. If you see `pip show mdformat-frontmatter` return "not
  > found", do NOT run `mdformat`.

> [!CAUTION] **Verbatim blocks (Block A/B/C/D/E/F/G) are wrapped in code fences
> (```` ``` ````) in all SKILL.md files.** This protects them from `mdformat`
> rewrapping. The blocks must remain character-identical across all skills.
> Never insert content *inside* their fences — add notes *after* the closing
> ```` ``` ````. If you run `mdformat`, **verify with `git diff` that no fenced
> block content was modified** before committing.

## Advanced / Unattended Cloud Deployment (GCE)

Running the continuous review loop 24/7 in a fully autonomous, unattended state
presents unique security risks, particularly **host-level prompt injection**.
Beyond this, agents might simply make mistakes and perform actions you did not
intend.

**As a result, deploying to a hardened VM such as an isolated Google Compute
Engine (GCE) instance is a STRICT REQUIREMENT for unattended mode.**
(Alternatively you can build a more structured deterministic pipeline where
individual risky actions are sandboxed, although this will require more up front
effort).

### 1. Hardened GCE Environment

To provide a security boundary that an AI agent cannot easily escape, you MUST
configure your environment as follows:

- **Network Isolation:** Provision the GCE VM with **no external internet
  access**, or at least use a secure web proxy with a trusted allowlist and good
  rate limiting and egress controls.
- **VPC Service Controls (VPC-SC):** Place the VM inside a VPC-SC perimeter.
  This is an important defense against data exfiltration if an agent is
  compromised.
- **Least-Privilege Service Account:** Attach a dedicated IAM Service Account to
  the VM with strictly limited roles. Do *not* use broad roles like
  `roles/aiplatform.user` or `roles/storage.objectAdmin`. Instead:
  - **Custom AI Role:** Create a custom IAM role that *only* grants
    `aiplatform.endpoints.predict` and `aiplatform.endpoints.generateContent`.
    This restricts the agent to only query models and prevents modifying AI
    infrastructure.
  - **Append-Only GCS Storage:** To store intermediate results or backups, grant
    the service account `roles/storage.objectCreator` and
    `roles/storage.objectViewer` to a specific GCS bucket. **Crucially, do not
    grant delete permissions (`storage.objects.delete`).** Also consider other
    append-only storage mechanisms.
  - **GCS Versioning:** Enable Object Versioning on the GCS bucket. This
    provides a mechanism so that even if the AI or an untrusted crash reproducer
    payload overwrites a file (like `workspace/learnings.jsonl`), previous
    states are preserved as non-current versions, preventing the AI from
    permanently deleting the history.

### 2. Bypassing Interactive Prompts (Unattended Mode)

**Warning:** Only use these flags if the **Hardened GCE Environment** (above) is
fully implemented. By default, the CLI tools require manual confirmation before
executing system commands. To run the pipeline entirely unattended, you must
pass the appropriate auto-approve flag when starting the CLI, such as
`--dangerously-skip-permissions` or `--yolo`.

### 3. Automated Security Flaw Alerting (Cloud Pub/Sub)

When running unattended, you might desire an isolated way to be notified when
the pipeline discovers a high-confidence security flaw. There are numerous ways
to do this, including connecting the pipeline to **Google Cloud Pub/Sub**.

1. **Setup:** Create a Pub/Sub topic (e.g., `mantis-verified-vulns`) and grant
   your GCE VM's Service Account the `roles/pubsub.publisher` role.
2. **Hooking it up:** The `/mantis-meta-agent` skill can be instructed to
   trigger notifications natively. You can instruct the meta-agent to run
   `gcloud pubsub topics publish mantis-verified-vulns --message="$(cat workspace/findings/<id>.json)"`
   whenever a security flaw is successfully reproduced.
3. **Routing:** Subscribe a Google Cloud Function or Cloud Run service to that
   Pub/Sub topic to route the alert payload directly into your team's chat,
   issue tracker, or paging system. This cleanly decouples the isolated scanning
   environment from your internal alerting infrastructure.

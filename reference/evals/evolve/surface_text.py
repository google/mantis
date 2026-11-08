# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""What a proposer is told it can change on the Mantis surface.

Harness2 ships this text for OpenCode and Codex harnesses (skills, scripts,
plugins, hooks). None of those exist on the Mantis pipeline, so the levers,
their costs and the rules that discard a proposal are restated for the three
files on this surface. Registered into the vendored ``prompts`` module via
``register_surface`` (the one local patch) so upstream's propose / aggregate /
select / experience prompts render for the ``mantis`` surface unchanged.
"""

from __future__ import annotations

from evals.evolve._vendor import load_harness2
from evals.evolve.surface import GUIDANCE_FILE, MAX_NODE_PROMPT_CHARS, PROMPTS_DIR, SURFACE_NAME, WORKFLOW_FILE

SURFACE_MD = f"""\
# WHAT YOU CAN CHANGE

The harness is the configuration of a multi-stage security-audit pipeline. It is a tree of
three kinds of file, each with a different cost and reach:

| path | what it is | when it is in context |
|---|---|---|
| `{WORKFLOW_FILE}` | the stages (nodes), their wiring (edges and routes), the TOOLS each stage may call, each stage's model and effort | shapes every run; costs nothing per call |
| `{PROMPTS_DIR}/<node_id>.md` | the system instruction of ONE stage | ALWAYS ON for that stage -- every token competes with that stage's own output on every one of its calls |
| `{GUIDANCE_FILE}` | text appended to EVERY stage's instruction | ALWAYS ON for every stage -- the most expensive place to put anything |

What a stage is called decides what it is told: `prompts/researcher.md` is the researcher's
instruction. Prompt files exist only for the stages the base workflow ships. A stage you ADD
carries its instruction inline, as `"system_prompt"` on its node in `{WORKFLOW_FILE}`; a stage
you REMOVE needs nothing else done -- its prompt file is simply no longer read.

The cheap levers, in order of preference:
  - WHICH TOOLS A STAGE GETS. A stage without `find_callers` cannot trace a caller; a stage
    without `get_function_boundary` reads whole files. Tools come from a CLOSED registry --
    you may give a stage a tool that exists, never invent one. Some tools depend on an
    earlier stage's output: `find_symbol`, `find_callers`, `find_callees` and
    `get_function_boundary` read the index the `structural_index` stage builds, and answer
    "Structural index unavailable" without it -- a digest row showing those tools with (✗n)
    means the stage paid for calls that returned nothing. Removing `structural_index` removes
    every structural tool with it.
  - WIRING. Two complementary researcher stages fanning out from the threat model and
    converging on dedupe; a classifier that routes unconfirmed findings to the reproducer;
    a stage removed because the trajectories show it adds turns and no findings.
  - PER-STAGE MODEL AND EFFORT. A cheap model for dedupe, a strong one for the reviewer.
  - PROMPT TEXT last, and only for a rule the trajectories show was needed: a stage that
    reads the same file whole five times needs "read function spans with
    get_function_boundary", not a paragraph on diligence. If you add always-on text, cut
    something else to pay for it. Each stage's prompt is capped at {MAX_NODE_PROMPT_CHARS} characters
    including the shared guidance.

THREE RULES THAT DISCARD THE WHOLE PROPOSAL. Validation runs before any rollout, and a
harness that fails it is thrown away entire:

1. THE TOOL SET IS CLOSED. Every tool on every stage must be in the registry; the error
   names the registry. Global `config` (including `config.sandbox`, `evidence_sources`,
   `api_base`, and `sarif_output`), per-node `api_base`, and `budget` are locked to the base
   workflow -- what the pipeline may execute, spend, and contact is the operator's decision,
   not the harness's.
2. `{WORKFLOW_FILE}` MUST STAY VALID. It is parsed by a strict schema: unknown keys, a
   route that names no edge, a classifier without its verdict schema, a node with no path
   from START -- each is rejected with the exact message the loader produces.
3. THE FINDINGS ARE NOT YOURS TO SHAPE. A harness changes HOW the pipeline works, never
   WHAT it reports: do not instruct a stage to report more findings, to confirm findings
   without evidence, or to lower severity thresholds. Evidence tiers are set by sandbox
   sentinels and re-attacks the pipeline runs itself; prose cannot promote a finding.

# HOW TO MAKE A CHANGE

The harness is in `context/harness/`, and it is YOURS TO EDIT. Use the write tool to change
files in place; your edits on disk ARE the proposal. Files you do not touch are inherited
unchanged -- do not rewrite a file to keep it the same. Delete a prompt file to fall back to
the stage's built-in instruction.

If the evidence does not argue for any change, leave everything as it is and say KEEP_BASE
in your notes. That is a real answer, not a failure: adaptation the evidence does not support
costs context and buys nothing.

Then reply with ONE `<notes>` block and nothing else: for each change, the moment in a
trajectory that motivated it. The notes are read by a person, not applied by a machine.
"""

INV_TEMPLATE = """\
# YOUR DIMENSION: INV -- how the pipeline WORKS

You own procedure, tool use and completion -- not what counts as a vulnerability. Trace each
stage's trajectory, find its earliest observed divergence, and match it to the cheapest lever:

- WHOLE-FILE READING: a stage that dumps files it could have navigated needs
  `find_symbol` / `find_callers` / `get_function_boundary` on its tool list and one line
  telling it when to use them -- not a longer prompt.
- TOOL ERRORS AND RETRIES: distinguish a bad argument from a missing capability; give one
  bounded fallback and a stop condition; never prescribe blind repetition.
- WASTED TURNS: a stage that reasons for many calls and reports nothing is a stage whose
  always-on text is too long or whose tools do not fit its job; cut before you add.
- COVERAGE GAPS: a flow the trajectories show was never traced across files is a wiring or
  tool problem (a second researcher arm, a caller-tracing tool), not a prompt problem.
- ORDINARY SEQUENCING: prefer concise guidance. Do not add text for a one-off mistake.

{levers}

Do not change what evidence a finding needs, how severity is scored, or which verdicts a
reviewer may give. A parallel candidate owns the domain lens; stay on how the pipeline works.
"""

DOM_TEMPLATE = """\
# YOUR DIMENSION: DOM -- what a PRACTITIONER knows about THIS codebase

You own the auditor's model of the target: its trust boundaries, its entry points, where
its sinks live, which of its sanitisers are real, and what an expert would check first.

Turn it into checkable, stage-specific guidance:

- ENTRY POINTS AND SINKS: name the request handlers, the data stores, the subprocess and
  network calls the trajectories actually show, and tell the threat modeler and researcher
  to start there. "In this codebase, every route under `web/` calls a `services/` function
  that owns the sink" is worth more than any generic rule.
- WORKSPACE FACTS ARE THE MOST VALUABLE THING YOU CAN ENCODE. Where the evidence establishes
  that a sanitiser is applied (or is not), that a module has no callers, that tests and
  vendored code are out of scope, write the fact itself, labelled "in this codebase".
  A guessed fact is worse than none.
- DECISION RULES FOR THE REVIEWER AND CRITIC: what distinguishes a reachable sink from a
  dead one here; which patterns the trajectories show were dismissed correctly.

{levers}

Two hard rules:
- Never invent an authority, a CWE mapping, or a fact the trajectories do not show.
- Never tell a stage to report more, to confirm without evidence, or to skip verification.

Do not change tools, wiring, models or budgets. A parallel candidate owns procedure; stay on
practitioner knowledge of this codebase.
"""

TTS_SURFACE = SURFACE_MD


def register() -> None:
    """Registers the ``mantis`` surface text into the vendored prompts module (idempotent)."""
    load_harness2()
    from harness2.core import prompts as h2prompts

    h2prompts.register_surface(SURFACE_NAME, surface_md=SURFACE_MD, inv=INV_TEMPLATE, dom=DOM_TEMPLATE, tts_surface=TTS_SURFACE)

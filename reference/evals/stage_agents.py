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

from contextlib import contextmanager
import os
import shutil
import tempfile
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from core.config import ExtendedReviewVerdict, get_llm_kwargs, ResilientLiteLlm
from core.llm_gateway import UNTRUSTED_CODE_AUDIT_GUARD
from core.prompts import get_stage_prompt

LiteLlm = ResilientLiteLlm
from core.schemas import ReviewVerdict, CriticVerdict, ReproVerdict, ExecutiveReport
from tools import TOOLS

STAGE_OUTPUT_SCHEMAS = {
    'reviewer': ExtendedReviewVerdict or ReviewVerdict,
    'critic': CriticVerdict,
    'reproducer': ReproVerdict,
    'reporter': ExecutiveReport,
}

STAGE_CONFIGS = {
    'planner': {
        'skill': 'mantis-plan',
        # The planner node's tools in workflow.json. Used as the predecessor
        # in research_eval.py's planned arms (fresh vs forked researcher).
        'tools': ['read_file', 'write_file', 'list_files', 'get_summary', 'get_threat_model', 'record_plan', 'get_plan'],
        'instruction': (
            'You are the Security Planner stage in the Mantis review pipeline. Produce a focused, '
            'prioritized vulnerability research plan for the application under the directory '
            "'app/': call list_files('app'), read the entry points and the modules they reach, and "
            'record the plan with record_plan: which files and functions to inspect, for which '
            'vulnerability classes, and why. Do not report findings yourself.'
        ),
    },
    'researcher': {
        'skill': 'mantis-researcher',
        # Same tool list as the researcher node in workflow.json, so the eval
        # measures the production toolset. research_eval.py can replace it
        # via tools_override for toolset A/B runs.
        'tools': [
            'read_file', 'write_file', 'list_files', 'get_summary', 'get_threat_model',
            'get_plan', 'report_findings', 'get_findings', 'find_symbol', 'find_callers',
            'find_callees', 'get_function_boundary', 'record_regression_check',
        ],
        'instruction': get_stage_prompt('researcher', 'mantis-researcher'),
    },
    'deduplicator': {
        'skill': 'mantis-dedupe',
        'tools': ['read_file', 'write_file', 'list_files', 'get_findings', 'report_findings', 'dedupe_findings'],
        'instruction': get_stage_prompt('deduplicator', 'mantis-dedupe'),
    },
    'reviewer': {
        'skill': 'mantis-review',
        'tools': [
            'read_file', 'get_findings', 'get_threat_model', 'get_summary', 'find_symbol',
            'find_callers', 'find_callees', 'get_function_boundary', 'record_regression_check',
        ],
        'instruction': get_stage_prompt('reviewer', 'mantis-review'),
    },
    'critic': {
        'skill': 'mantis-critic',
        'tools': [
            'read_file', 'get_findings', 'get_threat_model', 'find_symbol',
            'find_callers', 'find_callees', 'get_function_boundary',
        ],
        'instruction': get_stage_prompt('critic', 'mantis-critic'),
    },
    'calibrator': {
        'skill': 'mantis-calibrate',
        'tools': ['score_risk', 'calibrate_finding', 'get_findings', 'get_threat_model', 'read_file', 'write_file'],
        'instruction': get_stage_prompt('calibrator', 'mantis-calibrate'),
    },
    'reproducer': {
        'skill': 'mantis-reproduce',
        'tools': [
            'run_sandbox', 'run_sandbox_with_evidence', 'get_findings', 'get_threat_model',
            'read_file', 'write_file', 'get_function_boundary', 'find_callers',
            'get_prior_poc', 'record_regression_check',
        ],
        'instruction': get_stage_prompt('reproducer', 'mantis-reproduce'),
    },
    'patcher': {
        'skill': 'mantis-coder',
        'tools': [
            'apply_patch', 'record_patch', 'run_sandbox', 'run_sandbox_with_evidence',
            'read_file', 'write_file', 'get_findings', 'get_security_guidance',
            'query_lineage', 'find_symbol', 'find_callers', 'find_callees', 'get_function_boundary',
        ],
        'instruction': get_stage_prompt('patcher', 'mantis-coder'),
    },
    'reflector': {
        'skill': 'mantis-reflect',
        'tools': ['read_file', 'write_file', 'get_findings', 'record_learning'],
        'instruction': get_stage_prompt('reflector', 'mantis-reflect'),
    },
    'reporter': {
        'skill': 'mantis-report',
        'tools': ['read_file', 'write_file', 'get_findings', 'get_plan', 'get_threat_model', 'get_summary', 'generate_report'],
        'instruction': get_stage_prompt('reporter', 'mantis-report'),
    },
}

def build_stage_agent(stage_name: str, model_id: str = None, reasoning_effort: str = None, tools_override: list = None,
                      include_contents: str = None, before_model_callback: list = None, instruction_suffix: str = None,
                      instruction_override: str = None):
    """Builds one pipeline stage as a standalone ADK agent for benchmarking.

    ``tools_override`` replaces the stage's tool list for this build only
    (used by research_eval.py for toolset A/B runs). Names still resolve
    through tools.TOOLS, so an override cannot inject an unregistered tool.
    ``include_contents`` / ``before_model_callback`` / ``instruction_suffix``
    shape a stage that runs after another in one graph (research_eval.py's
    planned arms): production nodes run with include_contents="none", a
    forked stage carries the fork callback, and a stage that is not first
    gets its briefing in its instruction since it sees no seed message.
    ``instruction_override`` replaces the stage's own instruction: a per-file
    campaign's planner must not be told to list and read the whole application.
    """
    model_id = model_id or os.environ.get('EVAL_MODEL', 'vertex_ai/gemini-3.8-flash')
    reasoning_effort = reasoning_effort or os.environ.get('EVAL_REASONING_EFFORT', 'low')

    _, llm_kwargs = get_llm_kwargs(model_id=model_id, reasoning_effort=reasoning_effort)

    cfg = STAGE_CONFIGS.get(
        stage_name,
        {
            'skill': f'mantis-{stage_name}',
            'tools': list(TOOLS.keys()),
            'instruction': get_stage_prompt(stage_name, f'mantis-{stage_name}'),
        },
    )
    tool_names = tools_override if tools_override is not None else cfg['tools']
    tools_list = [TOOLS[t] for t in tool_names if t in TOOLS]

    instruction = instruction_override if instruction_override else cfg['instruction']
    if instruction_suffix:
        instruction = f"{instruction}\n\n{instruction_suffix}"

    guard_text = UNTRUSTED_CODE_AUDIT_GUARD.strip()
    if guard_text not in instruction:
        instruction = f"{instruction.rstrip()}\n\n{guard_text}"

    output_schema = STAGE_OUTPUT_SCHEMAS.get(stage_name)
    if output_schema is not None:
        schema_label = "ReviewVerdict" if stage_name == "reviewer" else output_schema.__name__
        instruction = (
            f"{instruction.rstrip()}\n\n"
            f"CRITICAL TERMINATION CONTRACT: When your analysis for this stage is complete, "
            f"submit your final verdict using the 'set_model_response' tool (e.g. set_model_response(route=..., reason=...)) "
            f"or emit it directly as raw JSON response text conforming to '{schema_label}' "
            f"(e.g. {{\"route\": \"...\", \"reason\": \"...\"}}). "
            f"Do NOT call write_file, run_sandbox, or any other general tool to signal completion, and do NOT write dummy marker or verdict files "
            f"(e.g. do NOT write 'verdict.json', 'done.txt', or 'status.json'). Also do NOT run probe shell commands "
            f"(e.g. do NOT run 'echo done', 'echo 1', 'true', or 'exit 0')."
        )
        if stage_name == "reviewer" and output_schema is ExtendedReviewVerdict:
            instruction = (
                f"{instruction}\n\n"
                f"PER-FINDING VERDICTS: Each finding returned by get_findings is an INDEPENDENT "
                f"vulnerability claim and deserves its own judgment. When more than one finding is "
                f"in scope, your verdict JSON MUST include a \"finding_verdicts\" list with exactly one "
                f"entry per finding: {{\"finding_id\": <numeric id from get_findings>, \"route\": "
                f"\"confirmed\" | \"false_positive\", \"reason\": \"<one sentence for THIS finding>\"}}. "
                f"Never let one finding's weakness dismiss its siblings, and never let one finding's "
                f"strength confirm them. The top-level route/reason then summarize the overall outcome "
                f"(confirmed if ANY finding is confirmed)."
            )

    from core.graph_loader import LiteralInstruction, _make_after_tool_guard_callback

    after_tool_cb = _make_after_tool_guard_callback(stage_name, tool_names, model=model_id)

    extra = {}
    if include_contents is not None:
        extra['include_contents'] = include_contents
    if before_model_callback:
        extra['before_model_callback'] = list(before_model_callback)
    return Agent(
        name=stage_name,
        model=LiteLlm(**llm_kwargs),
        instruction=LiteralInstruction(instruction),
        tools=tools_list,
        output_schema=output_schema,
        after_tool_callback=after_tool_cb,
        **extra,
    )


@contextmanager
def eval_run_context(jail_dir=None, db_path=""):
    """Installs a jailed RunContext for eval harnesses that invoke real tools.

    SECURITY (INV-4): the tools in TOOLS are host-boundary enforcing only while a
    RunContext is installed; they derive their jail from it. Eval harnesses must not
    invoke them bare — wrap the run in this context manager so every filesystem and
    sandbox operation is bounded by a disposable scratch jail rather than $CWD.
    """
    from core.context import RunContext, current_run_context

    tmp_dir = None
    if jail_dir is None:
        tmp_dir = tempfile.mkdtemp(prefix="mantis_eval_jail_")
        jail_dir = tmp_dir

    ctx, token = install_eval_run_context(jail_dir, db_path)
    try:
        yield ctx
    finally:
        current_run_context.reset(token)
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def install_eval_run_context(jail_dir, db_path="", target_file=""):
    """Installs a jailed RunContext and returns ``(ctx, reset_token)``.

    Used directly by run_eval.py, which owns its temp directories, and by the
    eval_run_context() context manager above. RunContext declares ``jail_dir: str``,
    so the value is normalized here rather than at each call site.
    """
    from core.context import RunContext, current_run_context

    jail_str = str(jail_dir)
    ctx = RunContext(
        jail_dir=jail_str,
        db_path=str(db_path or os.path.join(jail_str, "eval_knowledge.db")),
        target_file=target_file,
        run_id="eval",
    )
    return ctx, current_run_context.set(ctx)

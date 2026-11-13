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
import json
import os
from pathlib import Path
import shutil
import tempfile
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from core.config import (
    DEFAULT_MODEL,
    DeferredEnvLiteLlm,
    ExtendedCriticVerdict,
    ExtendedReviewVerdict,
    ResilientLiteLlm,
    get_llm_kwargs,
    resolve_model_id,
)
from core.llm_gateway import UNTRUSTED_CODE_AUDIT_GUARD
from core.prompts import get_stage_prompt

LiteLlm = ResilientLiteLlm
from core.schemas import ReviewVerdict, CriticVerdict, ReproVerdict, ExecutiveReport
from tools import TOOLS

STAGE_OUTPUT_SCHEMAS = {
    'reviewer': ExtendedReviewVerdict or ReviewVerdict,
    'critic': ExtendedCriticVerdict or CriticVerdict,
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


def _load_shipped_workflow_meta() -> tuple[dict, dict]:
    """Returns `(config_dict, {node_id: node_dict})` from shipped `reference/workflow.json`."""
    wf_path = Path(__file__).resolve().parent.parent / 'workflow.json'
    try:
        raw = json.loads(wf_path.read_text(encoding='utf-8'))
        cfg = raw.get('config') if isinstance(raw.get('config'), dict) else {}
        nodes = {
            str(n.get('id')): n
            for n in (raw.get('nodes') or [])
            if isinstance(n, dict) and n.get('id')
        }
        return cfg, nodes
    except Exception:
        return {}, {}


def _default_stage_reasoning_effort(stage_name: str) -> str:
    cfg, nodes = _load_shipped_workflow_meta()
    node = nodes.get(stage_name) or {}
    return str(node.get('reasoning_effort') or cfg.get('reasoning_effort') or 'low')


def build_stage_agent(
    stage_name: str,
    model_id: str = None,
    reasoning_effort: str = None,
    tools_override: list = None,
    include_contents: str = None,
    before_model_callback: list = None,
    instruction_suffix: str = None,
    instruction_override: str = None,
    *,
    include_production_callbacks: bool = True,
    include_checklist: bool = True,
    include_context_editing: bool = True,
):
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
    import functools

    wf_cfg, _ = _load_shipped_workflow_meta()
    model_id = model_id or os.environ.get('EVAL_MODEL', 'vertex_ai/gemini-3.8-flash')
    reasoning_effort = (
        reasoning_effort
        or os.environ.get('EVAL_REASONING_EFFORT')
        or _default_stage_reasoning_effort(stage_name)
    )

    resolved_model = resolve_model_id(model_id, DEFAULT_MODEL)
    llm_kwargs_resolver = functools.partial(
        get_llm_kwargs,
        model_id=model_id,
        reasoning_effort=reasoning_effort,
        config=wf_cfg or None,
    )
    deferred_env = False
    llm_kwargs = {}
    try:
        resolved_model, llm_kwargs = llm_kwargs_resolver()
    except ValueError as exc:
        if 'VERTEXAI_PROJECT or GOOGLE_CLOUD_PROJECT' in str(exc):
            deferred_env = True
        else:
            raise

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
        if stage_name == "reviewer":
            schema_label = "ReviewVerdict"
        elif stage_name == "critic":
            schema_label = "CriticVerdict"
        else:
            schema_label = output_schema.__name__
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
        elif stage_name == "critic" and output_schema is ExtendedCriticVerdict:
            instruction = (
                f"{instruction}\n\n"
                f"PER-FINDING VERDICTS: Each finding returned by get_findings is an INDEPENDENT "
                f"vulnerability claim and deserves its own reachability/viability judgment. When more "
                f"than one finding is in scope, your verdict JSON MUST include a \"finding_verdicts\" "
                f"list with one entry per finding: {{\"finding_id\": <numeric id from get_findings>, "
                f"\"route\": \"viable\" | \"non_viable\", \"reason\": \"<one sentence for THIS finding>\"}}. "
                f"Never let one unreachable finding dismiss its viable siblings. The top-level "
                f"route/reason summarize the overall outcome (viable if ANY finding is viable)."
            )

    from core.graph_loader import (
        GlobalConfig,
        LiteralInstruction,
        _context_editing_keeps,
        _make_after_tool_guard_callback,
        _make_campaign_directive_before_model_callback,
        _make_client_context_editing_before_model_callback,
        _make_node_context_ceiling_before_model_callback,
        _make_on_tool_error_callback,
        _make_stage_experience_before_model_callback,
    )

    after_tool_cb = _make_after_tool_guard_callback(stage_name, tool_names, model=resolved_model)
    on_tool_error_cb = _make_on_tool_error_callback(stage_name)

    raw_max_cont = wf_cfg.get("max_node_continuations") if isinstance(wf_cfg, dict) else None
    max_continuations = (
        GlobalConfig().max_node_continuations if raw_max_cont is None else int(raw_max_cont)
    )

    callbacks: list = list(before_model_callback or [])
    if include_production_callbacks:
        prod_cbs = [
            _make_stage_experience_before_model_callback(stage_name),
            _make_campaign_directive_before_model_callback(stage_name) if include_checklist else None,
            (
                _make_client_context_editing_before_model_callback(
                    stage_name, model=resolved_model, config=wf_cfg or {},
                )
                if include_context_editing
                else None
            ),
            _make_node_context_ceiling_before_model_callback(
                stage_name,
                model=resolved_model,
                has_schema=bool(output_schema is not None),
                keep_tool_results=_context_editing_keeps(llm_kwargs.get("context_management")),
                llm_factory=(
                    (lambda kw=dict(llm_kwargs): ResilientLiteLlm(**kw)) if llm_kwargs else None
                ),
                max_continuations=max_continuations,
            ),
        ]
        callbacks.extend(cb for cb in prod_cbs if cb is not None)

    extra = {}
    if include_contents is not None:
        extra['include_contents'] = include_contents
    if callbacks:
        extra['before_model_callback'] = callbacks

    model_inst = (
        DeferredEnvLiteLlm(model=str(model_id or DEFAULT_MODEL), env_resolver=llm_kwargs_resolver)
        if deferred_env
        else LiteLlm(**llm_kwargs)
    )
    return Agent(
        name=stage_name,
        model=model_inst,
        instruction=LiteralInstruction(instruction),
        tools=tools_list,
        output_schema=output_schema,
        after_tool_callback=after_tool_cb,
        on_tool_error_callback=on_tool_error_cb,
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

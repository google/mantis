from pathlib import Path
import os
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.skills import load_skill_from_dir
from core.config import get_llm_kwargs
from core.schemas import ReviewVerdict, CriticVerdict, ReproVerdict, ExecutiveReport
from tools import TOOLS

STAGE_OUTPUT_SCHEMAS = {
    'reviewer': ReviewVerdict,
    'critic': CriticVerdict,
    'reproducer': ReproVerdict,
    'reporter': ExecutiveReport,
}

STAGE_CONFIGS = {
    'deduplicator': {
        'skill': 'mantis-dedupe',
        'tools': ['read_file', 'write_file', 'get_findings', 'report_findings', 'dedupe_findings'],
        'instruction': 'You are the deduplicator stage in the Mantis review pipeline. Retrieve findings using get_findings, analyze duplicate clusters carefully, and merge true duplicates using dedupe_findings. Do NOT merge distinct vulnerabilities.'
    },
    'reviewer': {
        'skill': 'mantis-review',
        'tools': ['read_file', 'get_findings', 'get_threat_model', 'get_summary'],
        'instruction': 'You are the reviewer stage in the Mantis review pipeline. Evaluate findings against the active codebase and 13 triage rejection constraints. Return a ReviewVerdict with route="confirmed" for true vulnerabilities or route="false_positive" for benign/mock/unreachable/hygiene code.'
    },
    'critic': {
        'skill': 'mantis-critic',
        'tools': ['read_file', 'get_findings', 'get_threat_model'],
        'instruction': 'You are the critic stage in the Mantis review pipeline. Assess technical exploit viability and untrusted attacker reachability. Return a CriticVerdict with route="viable" if reachable and exploitable, or route="non_viable" if blocked by framework invariants or missing attack vectors.'
    },
    'calibrator': {
        'skill': 'mantis-calibrate',
        'tools': ['score_risk', 'calibrate_finding', 'get_findings', 'get_threat_model', 'read_file'],
        'instruction': 'You are the calibrator stage in the Mantis review pipeline. Evaluate finding severity, impact, likelihood, and sanity caps. Call calibrate_finding or score_risk to assign risk scores on the 0.1 - 10.0 scale and priority levels.'
    },
    'reproducer': {
        'skill': 'mantis-reproduce',
        'tools': ['run_sandbox', 'get_findings', 'get_threat_model', 'read_file', 'write_file'],
        'instruction': 'You are the reproducer stage in the Mantis review pipeline. Execute exploit PoCs in the sandbox. Return ReproVerdict with route="success" if the exploit triggers, or route="failed_repro" if not.'
    },
    'patcher': {
        'skill': 'mantis-patch',
        'tools': ['apply_patch', 'run_sandbox', 'read_file', 'write_file', 'get_findings'],
        'instruction': 'You are the patcher stage in the Mantis review pipeline. Synthesize minimal unified diff patches using apply_patch and verify that PoC reattack is blocked (VERIFIED_SECURE).'
    },
    'reflector': {
        'skill': 'mantis-reflect',
        'tools': ['read_file', 'write_file', 'get_findings', 'record_learning'],
        'instruction': 'You are the reflector stage in the Mantis review pipeline. Extract strategic cross-pass learnings and call record_learning with appropriate categories and tags.'
    },
    'reporter': {
        'skill': 'mantis-report',
        'tools': ['read_file', 'write_file', 'get_findings', 'get_plan', 'get_threat_model', 'get_summary', 'generate_report'],
        'instruction': 'You are the reporter stage in the Mantis review pipeline. Compile the final executive review packet and call generate_report with an ExecutiveReport object.'
    },
}

def build_stage_agent(stage_name: str, model_id: str = None, reasoning_effort: str = None):
    model_id = model_id or os.environ.get('EVAL_MODEL', 'vertex_ai/gemini-3.7-flash')
    reasoning_effort = reasoning_effort or os.environ.get('EVAL_REASONING_EFFORT', 'low')
    
    _, llm_kwargs = get_llm_kwargs(model_id=model_id, reasoning_effort=reasoning_effort)
    
    cfg = STAGE_CONFIGS.get(stage_name, {'skill': f'mantis-{stage_name}', 'tools': list(TOOLS.keys()), 'instruction': f'You are the {stage_name} stage.'})
    skill_path = Path(__file__).resolve().parent.parent.parent / cfg['skill']
    tools_list = [TOOLS[t] for t in cfg['tools'] if t in TOOLS]
    
    instruction = cfg['instruction']
    if skill_path.is_dir() and (skill_path / 'SKILL.md').exists():
        skill_obj = load_skill_from_dir(str(skill_path))
        if hasattr(skill_obj, 'instructions') and skill_obj.instructions:
            instruction = f"{instruction}\n\n[SKILL GUIDANCE]\n{skill_obj.instructions[:1000]}"

    output_schema = STAGE_OUTPUT_SCHEMAS.get(stage_name)

    return Agent(
        name=stage_name,
        model=LiteLlm(**llm_kwargs),
        instruction=instruction,
        tools=tools_list,
        output_schema=output_schema,
    )

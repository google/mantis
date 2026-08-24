import os
from pathlib import Path
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.skills import load_skill_from_dir

from core.config import get_llm_kwargs
from tools import TOOLS

def build_deduplicator_agent():
    eval_model = os.environ.get('EVAL_MODEL', 'vertex_ai/gemini-3.5-flash-lite')
    eval_effort = os.environ.get('EVAL_REASONING_EFFORT', 'low')

    _, llm_kwargs = get_llm_kwargs(
        model_id=eval_model,
        reasoning_effort=eval_effort,
    )

    skill_path = Path(__file__).resolve().parent.parent.parent / 'mantis-dedupe'
    tools_list = [TOOLS[t] for t in ['read_file', 'write_file', 'get_findings', 'report_findings', 'dedupe_findings'] if t in TOOLS]

    if skill_path.is_dir() and (skill_path / 'SKILL.md').exists():
        skill_obj = load_skill_from_dir(str(skill_path))
        agent_tools = tools_list + [skill_obj]
        instruction = (
            "You are the 'deduplicator' stage in the Mantis vulnerability review pipeline.\n"
            f"Execute your assigned skill '{skill_obj.frontmatter.name}' using your available tools.\n"
            "Retrieve findings using get_findings, analyze duplicates, and merge or update findings using dedupe_findings and report_findings."
        )
    else:
        agent_tools = tools_list
        instruction = (
            "You are the 'deduplicator' stage in the Mantis vulnerability review pipeline.\n"
            "Retrieve findings using get_findings, analyze duplicates, and merge or update findings using dedupe_findings and report_findings."
        )

    return Agent(
        name='deduplicator',
        model=LiteLlm(**llm_kwargs),
        instruction=instruction,
        tools=agent_tools,
    )

async def get_agent_async():
    return build_deduplicator_agent()

def get_agent():
    return build_deduplicator_agent()

root_agent = build_deduplicator_agent()

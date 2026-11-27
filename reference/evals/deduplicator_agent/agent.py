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

import os
from pathlib import Path
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.skills import load_skill_from_dir
from google.adk.tools.skill_toolset import SkillToolset

from core.config import get_llm_kwargs, ResilientLiteLlm

LiteLlm = ResilientLiteLlm
from tools import TOOLS

def build_deduplicator_agent():
    eval_model = os.environ.get('EVAL_MODEL', 'vertex_ai/gemini-3.5-flash-lite')
    eval_effort = os.environ.get('EVAL_REASONING_EFFORT', 'low')

    _, llm_kwargs = get_llm_kwargs(
        model_id=eval_model,
        reasoning_effort=eval_effort,
    )

    skill = load_skill_from_dir(str(Path(__file__).resolve().parents[3] / 'skills' / 'mantis-dedupe'))
    tools_list = [TOOLS[t] for t in ['read_file', 'write_file', 'get_findings', 'dedupe_findings'] if t in TOOLS]
    agent_tools = tools_list + [SkillToolset(skills=[skill])]
    instruction = (
        "You are the 'deduplicator' stage in the Mantis vulnerability review pipeline.\n"
        f"Execute your assigned skill '{skill.frontmatter.name}' using your available tools.\n"
        "Retrieve findings using get_findings, analyze duplicates, and merge duplicate findings using dedupe_findings."
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

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

"""The Mantis harness as an editable file tree, and how it compiles back.

Harness2 edits a harness as files under ``context/harness/``. For Mantis the
harness is the ADK reference pipeline's configuration, so the tree is:

    workflow.json          nodes, edges, per-node tools (closed allowlist),
                           per-node model/effort (config, budget, sandbox locked)
    prompts/<node_id>.md   the system instruction of each agent node
    tool_guidance.md       text appended to every agent node's instruction

``base_tree`` renders the shipped workflow into that shape (prompts come from
``core.prompts.get_stage_prompt`` exactly as the loader would resolve them);
``compile_tree`` folds an edited tree back into one ``workflow.json`` whose
nodes carry ``system_prompt``, which ``core.graph_loader.load_workflow_from_json``
already accepts -- the loader is not touched. ``validate_tree`` is what a
proposal has to pass, with every problem in one message so it can be fed
back verbatim as retry feedback.

Why this surface and not Harness2's: Mantis has no on-demand skills in the
production pipeline, no scripts a model may author, and a closed tool set
that is the enforcement for INV-4. The levers a proposer has are the ones the
pipeline already honours: which tools a node gets, what it is told, how the
nodes are wired, and how much it may spend.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from evals.evolve._vendor import load_harness2

WORKFLOW_FILE = "workflow.json"
PROMPTS_DIR = "prompts"
GUIDANCE_FILE = "tool_guidance.md"
SURFACE_NAME = "mantis"

# Per-node cap on the always-on text a proposal may give one agent node
# (prompt file + tool guidance). The same reasoning as Harness2's cap: every
# always-on token competes with the agent's own output budget, and the
# costliest failure is a run that reasons until the budget is gone and
# reports nothing. It is the synthesizer's cap, imported so there is one
# number; this check fires earlier, with the proposer's file named.
try:
    from core.graph_loader import MAX_NODE_SYSTEM_PROMPT_CHARS as MAX_NODE_PROMPT_CHARS
except Exception:  # pragma: no cover - keeps this module importable without ADK
    MAX_NODE_PROMPT_CHARS = 12_000
# Cap on the whole tree's always-on text as Harness2 counts it (every
# always_on file concatenated). workflow.json sits on that list only so the
# allowlist admits it, so this is generous; the per-node cap is the real one.
TREE_ALWAYS_ON_MAX = 200_000

_NODE_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]*$")


def _agent_nodes(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [n for n in workflow.get("nodes") or [] if isinstance(n, dict) and n.get("type", "agent") == "agent"]


def prompt_path(node_id: str) -> str:
    return f"{PROMPTS_DIR}/{node_id}.md"


def on_surface(rel: str, workflow: Optional[Dict[str, Any]] = None) -> bool:
    """Whether ``rel`` is one of the three file kinds this surface edits.

    Stricter than upstream ``tree.is_allowed``, which admits ``scripts/*.py``
    for every surface because OpenCode and Codex harnesses carry scripts.
    Mantis's pipeline never executes a harness-authored script, so one would
    be inert -- but inert is not the same as allowed: a tree is rejected
    rather than silently carrying a file nothing reads.

    ``prompts/<node_id>.md`` exists only for the agent nodes of the workflow
    the surface was built from (the base). Upstream's tree readers admit a
    fixed ``always_on`` list, so a prompt file cannot follow a node a
    proposal adds; a **new** stage carries its instruction inline as
    ``system_prompt`` in ``workflow.json`` instead, and ``compile_tree``
    honours both.
    """
    rel = str(rel or "").replace("\\", "/").strip().strip("/")
    if not rel or rel.startswith("/") or ".." in rel.split("/"):
        return False
    if rel in (WORKFLOW_FILE, GUIDANCE_FILE):
        return True
    if rel.startswith(PROMPTS_DIR + "/") and rel.endswith(".md") and rel.count("/") == 1:
        node_id = rel[len(PROMPTS_DIR) + 1:-3]
        if not _NODE_ID_RE.match(node_id):
            return False
        if workflow is None:
            return True
        return node_id in {str(n.get("id")) for n in _agent_nodes(workflow)}
    return False


def surface_for(workflow: Dict[str, Any]):
    """The editable surface for this workflow: workflow.json, one prompt per agent node, guidance."""
    h2 = load_harness2()
    from harness2.core.tree import SurfaceSpec  # noqa: F401  (vendored)

    files = [WORKFLOW_FILE, GUIDANCE_FILE] + [prompt_path(n["id"]) for n in _agent_nodes(workflow) if _NODE_ID_RE.match(str(n.get("id", "")))]
    return SurfaceSpec(
        name=SURFACE_NAME,
        always_on=tuple(files),
        always_on_max=TREE_ALWAYS_ON_MAX,
        always_on_cap_reason=(
            "each node's prompt is in context on every one of that node's LLM calls; "
            "fewer, sharper words beat more"
        ),
        skill_dir="skills",
        skill_name_rule="not used on this surface",
        trigger_hint="",
        autotrigger_file=GUIDANCE_FILE,
        trigger_line="",
        subagent_requires_mode=False,
        plugin_dir=None,
        hooks_file=None,
        hook_events=frozenset(),
        compile_skill_scripts=False,
        reject_empty_always_on=False,
        stubs=(),
    )


# --- Base tree --------------------------------------------------------------------------


def base_tree(workflow_path: Path | str) -> Dict[str, str]:
    """Renders the shipped workflow as a harness tree.

    Prompts are resolved the way the loader resolves them (``system_prompt``
    if the node has one, else the stage prompt for its id/skill), so what the
    proposer reads is what the node is told -- minus the untrusted-code
    guard, which the loader appends and which is not on the surface.
    """
    from core.prompts import get_stage_prompt

    raw = json.loads(Path(workflow_path).read_text(encoding="utf-8"))
    tree: Dict[str, str] = {}
    # workflow.json without inline prompts: the prompt files are the one place
    # prompts live on this surface, so an edit cannot be shadowed.
    stripped = json.loads(json.dumps(raw))
    for node in _agent_nodes(stripped):
        node.pop("system_prompt", None)
    tree[WORKFLOW_FILE] = json.dumps(stripped, indent=2, sort_keys=False) + "\n"
    for node in _agent_nodes(raw):
        node_id = str(node.get("id") or "")
        if not _NODE_ID_RE.match(node_id):
            continue
        prompt = node.get("system_prompt") or get_stage_prompt(node_id, str(node.get("skill") or ""))
        tree[prompt_path(node_id)] = str(prompt).rstrip() + "\n"
    tree[GUIDANCE_FILE] = ""
    return tree


def write_base_harness(workflow_path: Path | str, dest: Path | str) -> Path:
    """Materialises ``base_tree`` under ``dest`` and returns it."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    for rel, content in base_tree(workflow_path).items():
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return dest


def read_tree(harness_dir: Path | str, workflow_for_surface: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Reads a harness directory into a tree, admitting only on-surface files."""
    load_harness2()
    from harness2.core import tree as h2tree

    harness_dir = Path(harness_dir)
    wf_path = harness_dir / WORKFLOW_FILE
    workflow = workflow_for_surface or (json.loads(wf_path.read_text(encoding="utf-8")) if wf_path.exists() else {"nodes": []})
    return h2tree.read_tree(surface_for(workflow), harness_dir)


# --- Compile ----------------------------------------------------------------------------


def compile_tree(tree: Dict[str, str]) -> Dict[str, Any]:
    """Folds prompt files and guidance back into one workflow dict.

    An empty or missing prompt file means "the loader's default", never an
    empty instruction: ``tree.write_tree`` creates missing always-on files as
    empty, and an empty instruction would silently lobotomise a node.
    """
    if WORKFLOW_FILE not in tree:
        raise ValueError(f"the harness has no {WORKFLOW_FILE}; it is required and must stay valid JSON")
    try:
        workflow = json.loads(tree[WORKFLOW_FILE])
    except ValueError as exc:
        raise ValueError(f"{WORKFLOW_FILE} is not valid JSON: {exc}") from exc
    if not isinstance(workflow, dict):
        raise ValueError(f"{WORKFLOW_FILE} must be a JSON object")
    guidance = (tree.get(GUIDANCE_FILE) or "").strip()
    for node in _agent_nodes(workflow):
        node_id = str(node.get("id") or "")
        prompt = (tree.get(prompt_path(node_id)) or "").strip()
        inline = str(node.get("system_prompt") or "").strip()
        text = prompt or inline
        if guidance:
            text = (text + "\n\n" + guidance).strip() if text else guidance
        if text:
            node["system_prompt"] = text
        else:
            node.pop("system_prompt", None)
    return workflow


def compile_to_file(tree: Dict[str, str], dest: Path | str) -> Path:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(compile_tree(tree), indent=2) + "\n", encoding="utf-8")
    return dest


# --- Validate ---------------------------------------------------------------------------


def validate_tree(tree: Dict[str, str], base: Dict[str, str]) -> Dict[str, Any]:
    """Every problem with a proposed tree, raised as one ValueError.

    Checks, in order: the tree parses and compiles; no node's always-on text
    exceeds ``MAX_NODE_PROMPT_CHARS``; the sandbox tier did not change (a
    proposal may not widen what the pipeline can execute); every tool on every
    node is in the closed registry; and the compiled workflow loads through
    the production loader, which enforces the rest of the contract (verdict
    schemas, routes, stamps). Returns a census on success.
    """
    errs: List[str] = []
    try:
        workflow = compile_tree(tree)
    except ValueError as exc:
        raise ValueError(str(exc))
    try:
        base_workflow = compile_tree(base)
    except ValueError:
        base_workflow = {}

    guidance_len = len((tree.get(GUIDANCE_FILE) or "").strip())
    for node in _agent_nodes(workflow):
        node_id = str(node.get("id") or "")
        if not _NODE_ID_RE.match(node_id):
            errs.append(f"node id {node_id!r} is not a valid identifier (letters, digits, _ and - only)")
            continue
        if not str(node.get("system_prompt") or "").strip() and not str(node.get("skill") or "").strip():
            errs.append(
                f"node '{node_id}' has neither a system_prompt nor a skill, so it would run with no instruction; "
                "a new stage must carry its instruction inline as \"system_prompt\""
            )
        total = len(str(node.get("system_prompt") or ""))
        if total > MAX_NODE_PROMPT_CHARS:
            errs.append(
                f"node '{node_id}': always-on text is {total} chars (prompt + {guidance_len} of guidance), "
                f"over the {MAX_NODE_PROMPT_CHARS} cap; every token is paid on every call of that node -- cut, do not add"
            )

    base_cfg = base_workflow.get("config") if isinstance(base_workflow.get("config"), dict) else {}
    new_cfg = workflow.get("config") if isinstance(workflow.get("config"), dict) else {}
    base_sb_dict = base_cfg.get("sandbox") if isinstance(base_cfg.get("sandbox"), dict) else {}
    new_sb_dict = new_cfg.get("sandbox") if isinstance(new_cfg.get("sandbox"), dict) else {}
    base_sb = base_sb_dict.get("type")
    new_sb = new_sb_dict.get("type")
    if base_sb is not None and new_sb != base_sb:
        errs.append(
            f"config.sandbox.type changed from {base_sb!r} to {new_sb!r}; a proposal may not change the "
            "sandbox tier -- what the pipeline may execute is the operator's decision, not the harness's"
        )
    if base_workflow:
        changed_cfg = sorted(
            k for k in (set(base_cfg) | set(new_cfg)) if base_cfg.get(k) != new_cfg.get(k)
        )
        other_sb_changed = {k: v for k, v in base_sb_dict.items() if k != "type"} != {
            k: v for k, v in new_sb_dict.items() if k != "type"
        }
        non_sb_type_cfg = [k for k in changed_cfg if k != "sandbox" or other_sb_changed or new_sb == base_sb]
        if non_sb_type_cfg:
            errs.append(
                f"config keys {non_sb_type_cfg} changed from the base workflow; global config "
                "(sandbox options, api_base, evidence_sources, sarif_output, etc.) is operator-owned and locked"
            )
        if workflow.get("budget") != base_workflow.get("budget"):
            errs.append(
                "budget changed from the base workflow; spend ceilings are the operator's decision, not the harness's"
            )

    base_node_api_bases = {str(n.get("id")): n.get("api_base") for n in _agent_nodes(base_workflow)}
    for node in _agent_nodes(workflow):
        node_id = str(node.get("id") or "")
        expected_api_base = base_node_api_bases.get(node_id, None)
        if node.get("api_base") != expected_api_base:
            errs.append(
                f"node '{node_id}': api_base changed from {expected_api_base!r} to {node.get('api_base')!r}; "
                "a proposal may not redirect LLM traffic to another endpoint"
            )

    try:
        from tools import TOOLS
        allowed = set(TOOLS)
    except Exception:  # pragma: no cover - registry unavailable in minimal environments
        allowed = set()
    if allowed:
        for node in _agent_nodes(workflow):
            bad = [t for t in node.get("tools") or [] if t not in allowed]
            if bad:
                errs.append(
                    f"node '{node.get('id')}': tools {bad} are not in the registry; the tool set is closed "
                    f"(available: {', '.join(sorted(allowed))})"
                )

    base_node_ids = {str(n.get("id")) for n in _agent_nodes(base_workflow)}
    for rel in tree:
        if not on_surface(rel):
            errs.append(
                f"{rel} is not on the editable surface; this harness is {WORKFLOW_FILE}, "
                f"{PROMPTS_DIR}/<node_id>.md and {GUIDANCE_FILE} only -- the pipeline never reads anything else"
            )
        elif rel.startswith(PROMPTS_DIR + "/") and rel.endswith(".md"):
            node_id = rel[len(PROMPTS_DIR) + 1:-3]
            if node_id in base_node_ids:
                # A base stage, kept or removed. If removed, its prompt file
                # stays on the always-on list (upstream stubs it back as "")
                # and compile ignores it; nothing to fix either way.
                continue
            if (tree.get(rel) or "").strip():
                # A prompt file for a stage the base does not ship: compile
                # would fold it in, but the harvest/write_tree round trip only
                # carries the base's always-on files, so it would be lost.
                errs.append(
                    f"{rel} is a prompt file for a stage that is not in the base workflow; a new stage carries "
                    f"its instruction inline as \"system_prompt\" on its node in {WORKFLOW_FILE} (prompt files exist "
                    "only for the stages the base workflow ships)"
                )

    if errs:
        raise ValueError(" | ".join(errs))

    # The production loader has the final word.
    with tempfile.TemporaryDirectory(prefix="mantis-harness-validate-") as tmp:
        compiled = compile_to_file(tree, Path(tmp) / WORKFLOW_FILE)
        try:
            from core.graph_loader import load_workflow_from_json
            load_workflow_from_json(str(compiled), load_local=False)
        except Exception as exc:
            raise ValueError(f"the compiled workflow does not load: {type(exc).__name__}: {str(exc)[:600]}")

    return {
        "agent_nodes": len(_agent_nodes(workflow)),
        "edges": len(workflow.get("edges") or []),
        "prompt_files": sum(1 for rel in tree if rel.startswith(PROMPTS_DIR + "/")),
        "guidance_chars": guidance_len,
        "tools": sorted({t for n in _agent_nodes(workflow) for t in n.get("tools") or []}),
    }


def diff_summary(base: Dict[str, str], proposed: Dict[str, str]) -> Dict[str, Any]:
    """Which files a proposal touched, for the human reading the adoption diff."""
    load_harness2()
    from harness2.core import tree as h2tree

    try:
        workflow = json.loads(proposed.get(WORKFLOW_FILE) or base.get(WORKFLOW_FILE) or "{}")
    except ValueError:
        workflow = {"nodes": []}
    return h2tree.diff_summary(surface_for(workflow), base, proposed)

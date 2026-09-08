"""Research Graph Synthesizer for Mantis ADK.

Implements:
1. Safe LLM-Driven Research Graph Synthesis: Generates specialized DAG and bounded-cyclic
   Google ADK workflows tailored to specific vulnerability classes (e.g. TOCTOU race conditions,
   supply chain CI/CD audits, multi-party protocol states, kernel memory corruption).
2. Deterministic Compiler Safety Gates: Enforces strict tool whitelisting, cycle bounding,
   sandbox policy preservation, identifier validity, and graph topology integrity.
3. Archetype detection and deterministic fallback for kernel, cloud_iam, and web_api domains.
4. Clean recipe serialization and persistence under workspace/workflows/recipes/<domain>/.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.budget import BudgetConfig
from core.config import (
    DEFAULT_MODEL,
    RECOMMENDED_MODELS,
    get_llm_kwargs,
    normalize_model_id,
    MantisAuthError,
    ResilientLiteLLMClient,
    is_auth_error,
    format_auth_error_message,
)
from core.graph_loader import ClassifierNode, EdgeSpec, GlobalConfig, SandboxConfig, WorkflowSpec
from tools import TOOLS

logger = logging.getLogger(__name__)

DEFAULT_SYNTHESIZER_MODEL = "vertex_ai/gemini-3.7-flash"
VALID_TOOLS: Set[str] = set(TOOLS.keys())

KNOWN_SKILLS: Set[str] = {
    "mantis-threat-model",
    "mantis-researcher",
    "mantis-dedupe",
    "mantis-review",
    "mantis-critic",
    "mantis-reproduce",
    "mantis-patch",
    "mantis-coder",
    "mantis-calibrate",
    "mantis-report",
    "mantis-reflect",
    "mantis-plan",
    "mantis-chain",
    "mantis-history",
    "mantis-architecture",
    "mantis-advise",
    "mantis-structural-index",
}

VALID_OUTPUT_SCHEMAS: Set[str] = {
    "ReviewVerdict",
    "CriticVerdict",
    "ReproVerdict",
    "VulnerabilityReport",
    "ExecutiveReport",
    "ExploitChain",
}

VALID_STATUSES: Set[str] = {
    "discovered",
    "static_confirmed",
    "dynamic_confirmed",
    "patch_verified",
    "reported",
}

SYNTHESIS_SYSTEM_PROMPT = """You are the Mantis ADK Research Graph Architect.
Your task is to analyze a security vulnerability auditing objective and target codebase context, and synthesize a domain-tailored, single-tier Google ADK workflow specification in JSON.

### WORKFLOW SPECIFICATION SCHEMA:
A valid workflow JSON has the following top-level structure:
```json
{
  "name": "workflow_<domain_slug>",
  "config": {
    "db_path": "knowledge.db",
    "default_model": "vertex_ai/gemini-3.7-flash",
    "sandbox": {"type": "static-only | gvisor | microsandbox | gce"}
  },
  "nodes": [ ... ],
  "edges": [ ... ]
}
```

### NODE TYPES & SPECIFICATIONS:
1. Agent Nodes ("type": "agent"):
   - "id": Unique Python identifier string (e.g. "threat_model", "concurrency_auditor", "reproducer").
   - "skill": Name of a standard skill from the Known Skills list (e.g. "mantis-researcher", "mantis-reproduce") OR omit if using custom inline "system_prompt".
   - "system_prompt": (Optional) Direct inline string instruction for specialized agents (e.g. "Audit async Rust channels for deadlock hazards.").
   - "tools": Array of tool names chosen STRICTLY from the Registered Tools Whitelist below.
   - "output_schema": (Optional) Pydantic structured output model for classifier routing:
     * "ReviewVerdict": emits {"route": "confirmed" | "false_positive", "reason": "..."}
     * "CriticVerdict": emits {"route": "viable" | "non_viable", "reason": "..."}
     * "ReproVerdict": emits {"route": "success" | "failed_repro", "reason": "..."}
   - "output_key": State key to store verdict (must be "verdict" when output_schema is specified).
   - "on_enter_status": (Optional) Monotonic database state stamp ("static_confirmed" or "dynamic_confirmed").

2. Classifier Nodes ("type": "classifier"):
   - "id": Unique Python identifier string (e.g. "review_decision", "race_check", "repro_decision").
   - "routes": Array of possible routing outcomes (e.g. ["confirmed"], ["viable"], ["success"]).
   - "max_visits": Integer from 1 to 10 bounding loop iterations (use 1 for linear graphs, 2-3 for cyclic stress-testing loops).

### REGISTERED TOOLS WHITELIST (Only allocate tools from this list):
- Research & State Tools:
  * "read_file": Read target codebase files and workspace documents.
  * "write_file": Write auxiliary scripts, test cases, and PoCs.
  * "list_files": Inspect target file hierarchy and directories.
  * "report_findings": Record discovered vulnerability findings into knowledge.db (REQUIRED on discovery/research nodes).
  * "get_findings": Retrieve existing findings from knowledge.db.
  * "score_risk": Compute initial risk score.
  * "calibrate_finding": Apply 25 sanity triage caps and compute calibrated risk score.
  * "record_plan" / "get_plan": Save and retrieve campaign audit plans.
  * "record_threat_model" / "get_threat_model": Save and retrieve threat models.
  * "record_summary" / "get_summary": Save and retrieve architectural summaries.
  * "record_exploit_chain": Link constituent findings into composite exploit chains.
  * "record_learning": Log trajectory insights into learnings journal.
  * "dedupe_findings": Deduplicate similar findings.
  * "generate_report": Render final executive summary and SARIF reports.
  * "get_security_guidance": Fetch domain security standards (e.g. OWASP, CIS benchmarks).
  * "query_lineage": Query vulnerability finding history and snapshot provenance.
- Sandbox & Dynamic Execution Tools:
  * "run_sandbox": Run bash commands inside isolated container/VM sandbox.
  * "apply_patch": Apply unified diff patch inside sandbox.
  * "run_sandbox_with_evidence": Execute exploit PoC and verify reached-sink sentinel or crash trace.

### KNOWN STANDARD SKILLS:
"mantis-threat-model", "mantis-researcher", "mantis-dedupe", "mantis-review", "mantis-critic",
"mantis-reproduce", "mantis-coder", "mantis-patch", "mantis-calibrate", "mantis-report", "mantis-reflect",
"mantis-plan", "mantis-chain", "mantis-history", "mantis-architecture", "mantis-advise", "mantis-structural-index".

### GRAPH TOPOLOGY & ROUTING RULES:
1. START Edge: Workflow MUST begin with {"from": "START", "to": "<first_node>"}. No "on" allowed on START edge.
2. Agent Transitions: Edges from agent nodes MUST NOT have "on" conditions.
3. Classifier Transitions:
   - Every route in the classifier's "routes" list MUST have an outgoing edge: {"from": "<classifier_id>", "to": "<target>", "on": "<route>"}.
   - Every classifier MUST have an "on": "__DEFAULT__" fallback edge to handle unexpected verdicts or exit paths.
4. Connectivity: Every declared node must be connected. No orphan nodes.
5. Terminal Sink: The graph MUST contain at least one terminal sink node (a node with no outgoing edges, e.g. "reporter" or "reflector").
6. Cyclic Loops: For concurrency / race condition stress-testing or iterative refinement, route the classifier's success/retry edge back to the analyzer/reproducer, set max_visits between 2 and 5, and route "__DEFAULT__" to the downstream calibrator/reporter to guarantee loop termination.

### FEW-SHOT REFERENCE EXAMPLES:

Example 1: Static CI/CD & Configuration Audit (Linear Pipeline)
```json
{
  "name": "workflow_cicd_supply_chain",
  "config": {
    "sandbox": {"type": "static-only"}
  },
  "nodes": [
    {"id": "threat_model", "type": "agent", "skill": "mantis-threat-model", "tools": ["read_file", "list_files", "record_threat_model"]},
    {"id": "cicd_analyzer", "type": "agent", "system_prompt": "Audit GitHub Actions and Dockerfiles for unpinned dependencies and script injections.", "tools": ["read_file", "list_files", "report_findings", "get_findings", "get_security_guidance"]},
    {"id": "reviewer", "type": "agent", "skill": "mantis-review", "tools": ["get_findings", "read_file"], "output_schema": "ReviewVerdict", "output_key": "verdict"},
    {"id": "review_decision", "type": "classifier", "routes": ["confirmed"], "max_visits": 1},
    {"id": "calibrator", "type": "agent", "skill": "mantis-calibrate", "tools": ["get_findings", "calibrate_finding", "score_risk", "read_file"]},
    {"id": "reporter", "type": "agent", "skill": "mantis-report", "tools": ["get_findings", "generate_report", "read_file"]}
  ],
  "edges": [
    {"from": "START", "to": "threat_model"},
    {"from": "threat_model", "to": "cicd_analyzer"},
    {"from": "cicd_analyzer", "to": "reviewer"},
    {"from": "reviewer", "to": "review_decision"},
    {"from": "review_decision", "to": "calibrator", "on": "confirmed"},
    {"from": "review_decision", "to": "calibrator", "on": "__DEFAULT__"},
    {"from": "calibrator", "to": "reporter"}
  ]
}
```

Example 2: Concurrency & TOCTOU Race Condition Audit (Bounded Cyclic Loop)
```json
{
  "name": "workflow_toctou_concurrency",
  "config": {
    "sandbox": {"type": "gvisor"}
  },
  "nodes": [
    {"id": "threat_model", "type": "agent", "skill": "mantis-threat-model", "tools": ["read_file", "list_files", "record_threat_model"]},
    {"id": "race_analyzer", "type": "agent", "system_prompt": "Audit file descriptor operations and shared memory for TOCTOU race windows.", "tools": ["read_file", "list_files", "report_findings", "get_findings"]},
    {"id": "race_reproducer", "type": "agent", "skill": "mantis-reproduce", "tools": ["run_sandbox_with_evidence", "read_file", "write_file", "get_findings"], "output_schema": "ReproVerdict", "output_key": "verdict"},
    {"id": "repro_decision", "type": "classifier", "routes": ["success"], "max_visits": 3},
    {"id": "patcher", "type": "agent", "skill": "mantis-patch", "tools": ["apply_patch", "run_sandbox_with_evidence", "read_file", "write_file", "get_findings"]},
    {"id": "calibrator", "type": "agent", "skill": "mantis-calibrate", "tools": ["get_findings", "calibrate_finding", "score_risk", "read_file"]},
    {"id": "reporter", "type": "agent", "skill": "mantis-report", "tools": ["get_findings", "generate_report", "read_file"]}
  ],
  "edges": [
    {"from": "START", "to": "threat_model"},
    {"from": "threat_model", "to": "race_analyzer"},
    {"from": "race_analyzer", "to": "race_reproducer"},
    {"from": "race_reproducer", "to": "repro_decision"},
    {"from": "repro_decision", "to": "patcher", "on": "success"},
    {"from": "repro_decision", "to": "calibrator", "on": "__DEFAULT__"},
    {"from": "patcher", "to": "calibrator"},
    {"from": "calibrator", "to": "reporter"}
  ]
}
```

Return ONLY valid JSON matching the WorkflowSpec structure.
"""


def slugify(text: str) -> str:
    """Converts a descriptive objective into a clean filesystem-friendly slug."""
    clean = re.sub(r"[^\w\s-]", "", text).strip().lower()
    return re.sub(r"[-\s]+", "_", clean)[:40] or "custom_audit"


def extract_json_from_response(text: str) -> dict:
    """Extracts a JSON dictionary from an LLM response string."""
    cleaned = text.strip()
    # 1. Try direct JSON parse
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    # 2. Try matching markdown code block ```json ... ```
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(1))
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    # 3. Try finding outermost matching braces
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        try:
            data = json.loads(cleaned[first_brace : last_brace + 1])
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    raise ValueError(f"Could not extract valid JSON object from LLM response (length={len(text)}).")


# Domain Archetypes for targeted graph synthesis
DOMAIN_ARCHETYPES: Dict[str, Dict[str, Any]] = {
    "kernel": {
        "keywords": ["kernel", "ioctl", "driver", "syscall", "kasan", "ebpf", "memory corruption"],
        "researcher_tools": ["read_file", "list_files", "report_findings", "get_findings", "get_threat_model", "record_threat_model"],
        "reproducer_tools": ["run_sandbox", "run_sandbox_with_evidence", "read_file", "write_file", "get_findings"],
        "patcher_tools": ["apply_patch", "run_sandbox", "run_sandbox_with_evidence", "read_file", "write_file", "get_findings", "get_security_guidance", "query_lineage"],
        "sandbox_type": "gvisor",
    },
    "cloud_iam": {
        "keywords": ["cloud", "iam", "aws", "gcp", "azure", "privilege escalation", "permission", "rbac", "policy"],
        "researcher_tools": ["read_file", "list_files", "report_findings", "get_findings", "get_threat_model", "record_threat_model", "get_security_guidance"],
        "reproducer_tools": ["run_sandbox", "run_sandbox_with_evidence", "read_file", "write_file", "get_findings"],
        "patcher_tools": ["apply_patch", "read_file", "write_file", "get_findings", "get_security_guidance", "query_lineage"],
        "sandbox_type": "static-only",
    },
    "web_api": {
        "keywords": ["web", "api", "rest", "graphql", "jwt", "sqli", "xss", "ssrf", "auth", "endpoint"],
        "researcher_tools": ["read_file", "list_files", "report_findings", "get_findings", "get_threat_model", "record_threat_model"],
        "reproducer_tools": ["run_sandbox", "run_sandbox_with_evidence", "read_file", "write_file", "get_findings"],
        "patcher_tools": ["apply_patch", "run_sandbox", "run_sandbox_with_evidence", "read_file", "write_file", "get_findings", "get_security_guidance", "query_lineage"],
        "sandbox_type": "microsandbox",
    },
}


class ResearchGraphSynthesizer:
    """Synthesizes domain-tailored ADK research graph specifications from objectives.
    
    Supports both safe LLM-driven research graph synthesis with deterministic compiler gates
    and deterministic archetype-based synthesis with fail-safe fallback.
    """

    def __init__(self, default_model: str = DEFAULT_SYNTHESIZER_MODEL, db_path: str = "knowledge.db"):
        self.default_model = default_model
        self.db_path = db_path

    def detect_domain_archetype(self, objective: str) -> str:
        """Matches user objective against known domain archetypes or defaults to standard."""
        lower_obj = objective.lower()
        for archetype, cfg in DOMAIN_ARCHETYPES.items():
            if any(kw in lower_obj for kw in cfg["keywords"]):
                return archetype
        return "standard"

    def synthesize_archetype(
        self,
        objective: str,
        budget_config: Optional[BudgetConfig] = None,
        target_root: str = ".",
        sandbox_type: Optional[str] = None,
    ) -> WorkflowSpec:
        """Synthesizes a complete, runnable WorkflowSpec tailored to the detected archetype."""
        domain_slug = slugify(objective)
        archetype = self.detect_domain_archetype(objective)
        cfg_archetype = DOMAIN_ARCHETYPES.get(archetype, {})

        researcher_tools = cfg_archetype.get(
            "researcher_tools",
            ["read_file", "list_files", "report_findings", "get_findings", "get_threat_model", "record_threat_model"],
        )
        reproducer_tools = cfg_archetype.get(
            "reproducer_tools",
            ["run_sandbox", "run_sandbox_with_evidence", "read_file", "write_file", "get_findings"],
        )
        patcher_tools = cfg_archetype.get(
            "patcher_tools",
            ["apply_patch", "run_sandbox", "run_sandbox_with_evidence", "read_file", "write_file", "get_findings", "get_security_guidance", "query_lineage"],
        )
        if sandbox_type:
            final_sandbox_type = "static-only" if sandbox_type in ("static-only", "static") else sandbox_type
        else:
            final_sandbox_type = cfg_archetype.get("sandbox_type", "static-only")

        if final_sandbox_type == "static-only":
            researcher_tools = [t for t in researcher_tools if t not in ("run_sandbox", "run_sandbox_with_evidence")]
            reproducer_tools = [t for t in reproducer_tools if t not in ("run_sandbox", "run_sandbox_with_evidence")]
            patcher_tools = [t for t in patcher_tools if t not in ("run_sandbox", "run_sandbox_with_evidence")]

        budget_dict = dataclasses.asdict(budget_config) if budget_config else dataclasses.asdict(BudgetConfig())

        # Build declarative nodes
        nodes: List[Dict[str, Any]] = [
            {
                "id": "threat_model",
                "type": "agent",
                "skill": "mantis-threat-model",
                "tools": ["read_file", "list_files", "record_threat_model", "get_threat_model"],
            },
            {
                "id": "researcher",
                "type": "agent",
                "skill": "mantis-researcher",
                "tools": researcher_tools,
            },
            {
                "id": "dedupe",
                "type": "agent",
                "skill": "mantis-dedupe",
                "tools": ["get_findings", "report_findings", "dedupe_findings"],
            },
            {
                "id": "reviewer",
                "type": "agent",
                "skill": "mantis-review",
                "tools": ["get_findings", "read_file", "write_file"],
                "output_schema": "ReviewVerdict",
                "output_key": "verdict",
            },
            {
                "id": "critic",
                "type": "agent",
                "skill": "mantis-critic",
                "tools": ["get_findings", "read_file"],
                "output_schema": "CriticVerdict",
                "output_key": "verdict",
            },
            {
                "id": "review_decision",
                "type": "classifier",
                "routes": ["viable"],
                "max_visits": 1,
            },
            {
                "id": "reproducer",
                "type": "agent",
                "skill": "mantis-reproduce",
                "tools": reproducer_tools,
                "on_enter_status": "static_confirmed",
                "output_schema": "ReproVerdict",
                "output_key": "verdict",
            },
            {
                "id": "repro_decision",
                "type": "classifier",
                "routes": ["success"],
                "max_visits": 1,
            },
            {
                "id": "patcher",
                "type": "agent",
                "skill": "mantis-coder",
                "tools": patcher_tools,
                "on_enter_status": "dynamic_confirmed",
            },
            {
                "id": "calibrator",
                "type": "agent",
                "skill": "mantis-calibrate",
                "tools": ["get_findings", "calibrate_finding", "score_risk", "read_file"],
            },
            {
                "id": "reporter",
                "type": "agent",
                "skill": "mantis-report",
                "tools": ["get_findings", "generate_report", "read_file"],
            },
            {
                "id": "reflector",
                "type": "agent",
                "skill": "mantis-reflect",
                "tools": ["get_findings", "record_learning"],
            },
        ]

        # Connect the edges
        edges: List[Dict[str, Any]] = [
            {"from": "START", "to": "threat_model"},
            {"from": "threat_model", "to": "researcher"},
            {"from": "researcher", "to": "dedupe"},
            {"from": "dedupe", "to": "reviewer"},
            {"from": "reviewer", "to": "critic"},
            {"from": "critic", "to": "review_decision"},
            {"from": "review_decision", "to": "reproducer", "on": "viable"},
            {"from": "review_decision", "to": "calibrator", "on": "__DEFAULT__"},
            {"from": "reproducer", "to": "repro_decision"},
            {"from": "repro_decision", "to": "patcher", "on": "success"},
            {"from": "repro_decision", "to": "calibrator", "on": "__DEFAULT__"},
            {"from": "patcher", "to": "calibrator"},
            {"from": "calibrator", "to": "reporter"},
            {"from": "reporter", "to": "reflector"},
        ]

        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        metadata = {
            "domain": domain_slug,
            "archetype": archetype,
            "objective": objective,
            "synthesis_mode": "deterministic_archetype",
            "created_at": timestamp,
        }

        spec_dict = {
            "name": f"workflow_{domain_slug}",
            "config": {
                "db_path": self.db_path,
                "default_model": self.default_model,
                "sandbox": {"type": final_sandbox_type},
            },
            "nodes": nodes,
            "edges": edges,
            "evolution_metadata": metadata,
            "budget": budget_dict,
        }

        return WorkflowSpec.model_validate(spec_dict)

    def sanitize_and_validate_spec(
        self,
        raw_dict: dict,
        objective: str,
        budget_config: Optional[BudgetConfig] = None,
        target_root: str = ".",
        sandbox_type: Optional[str] = None,
        default_model: Optional[str] = None,
    ) -> WorkflowSpec:
        """Applies deterministic compiler safety gates to sanitize and compile LLM output.
        
        Deterministic Gates Enforced:
        1. Tool Whitelist Gate: Drops unknown tools; enforces report_findings on analysis nodes.
        2. Identifier & Graph Integrity Gate: Validates identifier syntax, non-empty START, no orphans.
        3. Cycle Bounding Gate: Clamps max_visits to [1, 10]; guarantees __DEFAULT__ and route edges.
        4. Sandbox Policy Gate: Strictly respects operator sandbox overrides without silent downgrades.
        5. Invariant Gate: Associates output schemas (ReviewVerdict, CriticVerdict, ReproVerdict) and
           verifies final Pydantic model validation.
        """
        domain_slug = slugify(objective)
        archetype = self.detect_domain_archetype(objective)
        cfg_archetype = DOMAIN_ARCHETYPES.get(archetype, {})

        # Name sanitization
        workflow_name = raw_dict.get("name") or f"workflow_{domain_slug}"
        workflow_name = re.sub(r"[^\w-]", "_", str(workflow_name)).strip("_") or f"workflow_{domain_slug}"

        # Gate 6: Model & Endpoint Security Gate
        # Never accept LLM-generated api_base to prevent SSRF / prompt exfiltration.
        # Enforce model pinning to operator's choice; if unpinned, validate strictly against RECOMMENDED_MODELS.
        raw_cfg = raw_dict.get("config", {}) if isinstance(raw_dict.get("config"), dict) else {}
        if default_model:
            chosen_model = normalize_model_id(default_model)
        elif raw_cfg.get("default_model"):
            raw_model = str(raw_cfg["default_model"]).strip()
            norm_model = normalize_model_id(raw_model)
            if norm_model in RECOMMENDED_MODELS or raw_model in RECOMMENDED_MODELS:
                chosen_model = norm_model
            else:
                logger.warning(
                    f"[SYNTHESIZER SECURITY GATE] Untrusted model '{raw_model}' rejected. Falling back to {self.default_model}."
                )
                chosen_model = self.default_model
        else:
            chosen_model = self.default_model

        # Gate 4: Sandbox Policy Gate (A3: LLM choice cannot escalate execution backend)
        if sandbox_type:
            final_sandbox = "static-only" if sandbox_type in ("static-only", "static") else sandbox_type
        else:
            final_sandbox = cfg_archetype.get("sandbox_type", "static-only")

        if isinstance(raw_cfg.get("sandbox"), dict) and raw_cfg["sandbox"].get("type"):
            requested_sb = str(raw_cfg["sandbox"]["type"]).strip()
            if requested_sb != final_sandbox:
                logger.warning(
                    f"[SYNTHESIZER SECURITY GATE] LLM requested sandbox backend '{requested_sb}' without operator flag; clamped to '{final_sandbox}'."
                )

        raw_retry = raw_cfg.get("retry_attempts", 3)
        try:
            retry_attempts = max(1, min(5, int(raw_retry)))
        except (TypeError, ValueError):
            retry_attempts = 3

        raw_seed = raw_cfg.get("seed_prompt", "Initial Task Input: Evaluate {filepath}")
        seed_prompt = str(raw_seed)[:1000] if isinstance(raw_seed, str) else "Initial Task Input: Evaluate {filepath}"

        config_dict = {
            "db_path": self.db_path or raw_cfg.get("db_path", "knowledge.db"),
            "default_model": chosen_model,
            "sandbox": {"type": final_sandbox},
            "retry_attempts": retry_attempts,
            "seed_prompt": seed_prompt,
        }

        # Gate 1 & 2: Node Sanitization & Whitelisting
        raw_nodes = raw_dict.get("nodes", [])
        if not isinstance(raw_nodes, list) or len(raw_nodes) == 0:
            raise ValueError("Spec must contain a non-empty list of nodes.")

        sanitized_nodes: List[Dict[str, Any]] = []
        seen_node_ids: Set[str] = set()
        id_mapping: Dict[str, str] = {}

        for idx, n in enumerate(raw_nodes):
            if not isinstance(n, dict):
                continue
            raw_id = str(n.get("id", "")).strip()
            clean_id = re.sub(r"[^\w]", "_", raw_id.lower()).strip("_")
            if not clean_id or clean_id == "start" or not clean_id.isidentifier():
                clean_id = f"stage_{idx + 1}"

            # Uniqueness check
            base_clean = clean_id
            counter = 1
            while clean_id in seen_node_ids:
                clean_id = f"{base_clean}_{counter}"
                counter += 1
            seen_node_ids.add(clean_id)
            id_mapping[raw_id] = clean_id

            node_type = str(n.get("type", "agent")).strip().lower()

            if node_type == "classifier":
                # Gate 3: Classifier Route & Cycle Bounding
                routes = n.get("routes", [])
                if not isinstance(routes, list) or not routes:
                    routes = ["viable"]
                clean_routes = []
                for r in routes:
                    r_str = str(r).strip()
                    if r_str and r_str not in clean_routes:
                        clean_routes.append(r_str)
                if not clean_routes:
                    clean_routes = ["viable"]

                try:
                    mv = int(n.get("max_visits", 1))
                except (TypeError, ValueError):
                    mv = 1
                # Clamp max_visits to safe range [1, 10]
                mv = max(1, min(10, mv))

                sanitized_nodes.append({
                    "id": clean_id,
                    "type": "classifier",
                    "routes": clean_routes,
                    "max_visits": mv,
                })
            else:
                # Gate 1: Tool Whitelisting for Agent Node
                raw_tools = n.get("tools", [])
                if not isinstance(raw_tools, list):
                    raw_tools = []
                clean_tools = [t for t in raw_tools if t in VALID_TOOLS]
                if final_sandbox == "static-only":
                    clean_tools = [t for t in clean_tools if t not in ("run_sandbox", "run_sandbox_with_evidence")]

                skill = n.get("skill")
                system_prompt = n.get("system_prompt")
                if isinstance(system_prompt, str):
                    sp_clean = system_prompt.strip()
                    # Refuse filesystem paths or traversal attempts
                    if sp_clean.startswith(("/", "./", "../")) or (len(sp_clean) < 100 and sp_clean.endswith((".md", ".txt", ".py", ".json", ".sh"))):
                        system_prompt = None
                    elif len(sp_clean) > 8192:
                        system_prompt = sp_clean[:8192]
                    else:
                        system_prompt = sp_clean
                else:
                    system_prompt = None

                if skill and isinstance(skill, str):
                    skill_clean = skill.strip()
                    if skill_clean in KNOWN_SKILLS:
                        skill = skill_clean
                    elif f"mantis-{skill_clean}" in KNOWN_SKILLS:
                        skill = f"mantis-{skill_clean}"
                    elif not system_prompt:
                        skill = "mantis-researcher"
                    else:
                        skill = None
                elif not system_prompt:
                    # Inferred skill from node id
                    inferred = f"mantis-{clean_id}"
                    if inferred in KNOWN_SKILLS:
                        skill = inferred
                    elif any(k in clean_id for k in ("research", "discover", "scanner", "analyz")):
                        skill = "mantis-researcher"
                    elif "repro" in clean_id:
                        skill = "mantis-reproduce"
                    elif any(k in clean_id for k in ("patch", "coder", "remediat")):
                        skill = "mantis-coder"
                    elif "review" in clean_id:
                        skill = "mantis-review"
                    elif "critic" in clean_id:
                        skill = "mantis-critic"
                    elif "threat" in clean_id:
                        skill = "mantis-threat-model"
                    elif "dedupe" in clean_id:
                        skill = "mantis-dedupe"
                    elif "calibrat" in clean_id:
                        skill = "mantis-calibrate"
                    elif "report" in clean_id:
                        skill = "mantis-report"
                    elif "reflect" in clean_id:
                        skill = "mantis-reflect"
                    else:
                        skill = "mantis-researcher"

                # Ensure required core tools on discovery/analysis nodes
                if any(k in clean_id or (skill and k in skill) for k in ("research", "audit", "discover", "scan", "analyz")):
                    if "report_findings" not in clean_tools and "threat" not in clean_id:
                        clean_tools.append("report_findings")
                    if "get_findings" not in clean_tools:
                        clean_tools.append("get_findings")
                    if "read_file" not in clean_tools:
                        clean_tools.append("read_file")
                    if "list_files" not in clean_tools:
                        clean_tools.append("list_files")

                # Ensure get_findings for downstream review / reproduction / patching
                if any(k in clean_id for k in ("review", "critic", "dedupe", "repro", "patch", "calibrat", "report", "reflect")):
                    if "get_findings" not in clean_tools:
                        clean_tools.append("get_findings")

                # Gate 5: Structured Output Schema Mapping
                output_schema = n.get("output_schema")
                if output_schema and output_schema not in VALID_OUTPUT_SCHEMAS:
                    output_schema = None
                output_key = n.get("output_key")
                if "review" in clean_id or (skill and "review" in skill):
                    output_schema = "ReviewVerdict"
                    output_key = output_key or "verdict"
                elif "critic" in clean_id or (skill and "critic" in skill):
                    output_schema = "CriticVerdict"
                    output_key = output_key or "verdict"
                elif "repro" in clean_id or (skill and "reproduce" in skill):
                    output_schema = "ReproVerdict"
                    output_key = output_key or "verdict"

                on_enter_status = n.get("on_enter_status")
                if on_enter_status and on_enter_status not in VALID_STATUSES:
                    on_enter_status = None
                if ("repro" in clean_id or (skill and "reproduce" in skill)) and not on_enter_status:
                    on_enter_status = "static_confirmed"
                elif ("patch" in clean_id or (skill and "patch" in skill)) and not on_enter_status:
                    on_enter_status = "dynamic_confirmed"

                # Gate 6: Node-level Model & Reasoning Sanitization
                node_model = None
                raw_node_model = n.get("model")
                if raw_node_model and isinstance(raw_node_model, str):
                    norm_node_model = normalize_model_id(raw_node_model.strip())
                    if norm_node_model in RECOMMENDED_MODELS or raw_node_model in RECOMMENDED_MODELS:
                        node_model = norm_node_model
                    else:
                        logger.warning(
                            f"[SYNTHESIZER SECURITY GATE] Untrusted node model '{raw_node_model}' on node '{clean_id}' dropped."
                        )

                node_reasoning_effort = None
                raw_effort = n.get("reasoning_effort")
                if raw_effort and str(raw_effort).lower().strip() in ("none", "low", "medium", "high"):
                    node_reasoning_effort = str(raw_effort).lower().strip()

                agent_dict: Dict[str, Any] = {
                    "id": clean_id,
                    "type": "agent",
                    "tools": clean_tools or ["read_file", "list_files", "get_findings", "report_findings"],
                }
                if node_model:
                    agent_dict["model"] = node_model
                if node_reasoning_effort:
                    agent_dict["reasoning_effort"] = node_reasoning_effort
                if skill:
                    agent_dict["skill"] = skill
                if system_prompt:
                    agent_dict["system_prompt"] = str(system_prompt)
                if output_schema:
                    agent_dict["output_schema"] = output_schema
                if output_key:
                    agent_dict["output_key"] = output_key
                if on_enter_status:
                    agent_dict["on_enter_status"] = on_enter_status

                sanitized_nodes.append(agent_dict)

        # Gate 2 & 3: Edge Sanitization & Topological Validation
        node_dict = {n["id"]: n for n in sanitized_nodes}
        raw_edges = raw_dict.get("edges", [])
        sanitized_edges: List[Dict[str, Any]] = []
        seen_edge_pairs: Set[Tuple[str, str]] = set()

        if isinstance(raw_edges, list):
            for e in raw_edges:
                if not isinstance(e, dict):
                    continue
                from_id = str(e.get("from", e.get("from_node", ""))).strip()
                to_id = str(e.get("to", e.get("to_node", ""))).strip()

                if from_id != "START":
                    from_id = id_mapping.get(from_id, from_id)
                to_id = id_mapping.get(to_id, to_id)

                if from_id != "START" and from_id not in node_dict:
                    continue
                if to_id not in node_dict:
                    continue

                route = e.get("on")

                if from_id == "START":
                    key = ("START", to_id)
                    if key not in seen_edge_pairs:
                        seen_edge_pairs.add(key)
                        sanitized_edges.append({"from": "START", "to": to_id})
                    continue

                from_node = node_dict[from_id]
                if from_node["type"] == "agent":
                    key = (from_id, to_id)
                    if key not in seen_edge_pairs:
                        seen_edge_pairs.add(key)
                        sanitized_edges.append({"from": from_id, "to": to_id})
                elif from_node["type"] == "classifier":
                    if route is None:
                        route = "__DEFAULT__"
                    key = (from_id, to_id)
                    if key not in seen_edge_pairs:
                        seen_edge_pairs.add(key)
                        sanitized_edges.append({"from": from_id, "to": to_id, "on": route})

        # Ensure START edge exists
        has_start = any(e["from"] == "START" for e in sanitized_edges)
        if not has_start and sanitized_nodes:
            first_id = sanitized_nodes[0]["id"]
            sanitized_edges.insert(0, {"from": "START", "to": first_id})
            seen_edge_pairs.add(("START", first_id))

        # Ensure all classifier routes have outgoing edges + __DEFAULT__ fallback
        for n in sanitized_nodes:
            if n["type"] == "classifier":
                c_id = n["id"]
                routes = n["routes"]
                existing_out_routes: Set[str] = set()
                for e in sanitized_edges:
                    if e["from"] == c_id:
                        on_val = e.get("on")
                        if isinstance(on_val, list):
                            existing_out_routes.update(on_val)
                        elif on_val:
                            existing_out_routes.add(on_val)

                c_idx = next(i for i, node in enumerate(sanitized_nodes) if node["id"] == c_id)
                default_target = (
                    sanitized_nodes[c_idx + 1]["id"]
                    if c_idx + 1 < len(sanitized_nodes)
                    else sanitized_nodes[-1]["id"]
                )

                for r in routes:
                    if r not in existing_out_routes:
                        if (c_id, default_target) not in seen_edge_pairs:
                            sanitized_edges.append({"from": c_id, "to": default_target, "on": r})
                            seen_edge_pairs.add((c_id, default_target))
                            existing_out_routes.add(r)

                if "__DEFAULT__" not in existing_out_routes:
                    sink_id = sanitized_nodes[-1]["id"]
                    fallback_target = sink_id if sink_id != c_id else default_target
                    if (c_id, fallback_target) in seen_edge_pairs:
                        for e in sanitized_edges:
                            if e["from"] == c_id and e["to"] == fallback_target:
                                if isinstance(e.get("on"), list):
                                    e["on"].append("__DEFAULT__")
                                elif isinstance(e.get("on"), str):
                                    e["on"] = [e["on"], "__DEFAULT__"]
                                break
                    else:
                        sanitized_edges.append({"from": c_id, "to": fallback_target, "on": "__DEFAULT__"})
                        seen_edge_pairs.add((c_id, fallback_target))

        # Connect any orphan nodes
        referenced_nodes = {e["from"] for e in sanitized_edges if e["from"] != "START"} | {
            e["to"] for e in sanitized_edges
        }
        for i, n in enumerate(sanitized_nodes):
            if n["id"] not in referenced_nodes:
                prev_id = sanitized_nodes[i - 1]["id"] if i > 0 else "START"
                if prev_id == "START":
                    sanitized_edges.append({"from": "START", "to": n["id"]})
                elif (prev_id, n["id"]) not in seen_edge_pairs:
                    sanitized_edges.append({"from": prev_id, "to": n["id"]})
                    seen_edge_pairs.add((prev_id, n["id"]))

        # Ensure at least one terminal sink
        terminal_sinks = set(node_dict.keys()) - {
            e["from"] for e in sanitized_edges if e["from"] != "START"
        }
        if not terminal_sinks:
            reporter_id = "reporter_sink"
            if reporter_id in node_dict:
                reporter_id = f"reporter_sink_{len(sanitized_nodes)}"
            sanitized_nodes.append({
                "id": reporter_id,
                "type": "agent",
                "skill": "mantis-report",
                "tools": ["get_findings", "generate_report", "read_file"],
            })
            last_node = sanitized_nodes[-2]["id"]
            sanitized_edges.append({"from": last_node, "to": reporter_id})

        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        metadata = {
            "domain": domain_slug,
            "archetype": archetype,
            "objective": objective,
            "synthesis_mode": "llm_research_graph",
            "created_at": timestamp,
        }
        budget_dict = dataclasses.asdict(budget_config) if budget_config else dataclasses.asdict(BudgetConfig())

        spec_dict = {
            "name": workflow_name,
            "config": config_dict,
            "nodes": sanitized_nodes,
            "edges": sanitized_edges,
            "evolution_metadata": metadata,
            "budget": budget_dict,
        }

        return WorkflowSpec.model_validate(spec_dict)

    def synthesize_with_llm(
        self,
        objective: str,
        budget_config: Optional[BudgetConfig] = None,
        target_root: str = ".",
        sandbox_type: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
        max_repair_attempts: int = 3,
    ) -> WorkflowSpec:
        """Synthesizes a specialized research graph using an LLM, backed by multi-turn compiler feedback."""
        chosen_model = model or self.default_model
        try:
            import litellm

            _, llm_kwargs = get_llm_kwargs(
                chosen_model,
                DEFAULT_MODEL,
                api_base=None,
                timeout=timeout or 60.0,
            )

            user_prompt = (
                f'Synthesize an optimal Google ADK workflow specification for the following security audit objective:\n\n'
                f'OBJECTIVE: "{objective}"\n'
                f'TARGET ROOT: "{target_root}"\n'
                f'SANDBOX POLICY: "{sandbox_type or "auto"}"\n\n'
                f'Design a specialized node topology, tools, cyclic loops (if needed), and agent prompts tailored to this bug class. '
                f'Return ONLY valid JSON matching the WorkflowSpec structure.'
            )

            messages: List[Dict[str, str]] = [
                {"role": "system", "content": SYNTHESIS_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ]

            last_error: Optional[str] = None
            for attempt in range(max_repair_attempts):
                call_kwargs = dict(llm_kwargs)
                call_kwargs["model"] = chosen_model
                call_kwargs["messages"] = messages

                response = litellm.completion(**call_kwargs)
                raw_text = response.choices[0].message.content

                try:
                    raw_dict = extract_json_from_response(raw_text)
                    spec = self.sanitize_and_validate_spec(
                        raw_dict=raw_dict,
                        objective=objective,
                        budget_config=budget_config,
                        target_root=target_root,
                        sandbox_type=sandbox_type,
                        default_model=chosen_model,
                    )
                    return spec
                except Exception as compile_err:
                    last_error = str(compile_err)
                    logger.warning(
                        f"[SYNTHESIZER COMPILER FEEDBACK] Attempt {attempt + 1}/{max_repair_attempts} failed compiler validation: {compile_err}."
                    )
                    if attempt + 1 < max_repair_attempts:
                        messages.append({"role": "assistant", "content": raw_text})
                        messages.append({
                            "role": "user",
                            "content": (
                                f"The workflow specification you generated failed compiler validation with the following error:\n"
                                f"{compile_err}\n\n"
                                f"Please fix the specification to satisfy all architecture rules and return the corrected JSON."
                            ),
                        })

            raise ValueError(f"Failed after {max_repair_attempts} compiler attempts: {last_error}")

        except MantisAuthError:
            raise
        except Exception as e:
            if is_auth_error(e):
                raise MantisAuthError(
                    format_auth_error_message(e, model=chosen_model),
                    original_exception=e,
                ) from None
            logger.warning(
                f"[SYNTHESIZER WARNING] LLM research graph synthesis failed ({e}). Falling back to safe archetype synthesis."
            )
            return self.synthesize_archetype(
                objective=objective,
                budget_config=budget_config,
                target_root=target_root,
                sandbox_type=sandbox_type,
            )

    def synthesize(
        self,
        objective: str,
        budget_config: Optional[BudgetConfig] = None,
        target_root: str = ".",
        sandbox_type: Optional[str] = None,
        use_llm: bool = False,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> WorkflowSpec:
        """Synthesizes a complete, runnable WorkflowSpec tailored to the given objective."""
        if use_llm:
            return self.synthesize_with_llm(
                objective=objective,
                budget_config=budget_config,
                target_root=target_root,
                sandbox_type=sandbox_type,
                model=model,
                timeout=timeout,
            )
        return self.synthesize_archetype(
            objective=objective,
            budget_config=budget_config,
            target_root=target_root,
            sandbox_type=sandbox_type,
        )

    @staticmethod
    def persist_recipe(
        spec: WorkflowSpec,
        workspace_root: Path | str,
    ) -> Path:
        """Saves synthesized recipe to workspace/workflows/recipes/<domain>/workflow.json."""
        root = Path(workspace_root)
        domain = (
            spec.evolution_metadata.get("domain", "custom_audit")
            if spec.evolution_metadata
            else "custom_audit"
        )

        recipe_dir = root / "workflows" / "recipes" / domain
        recipe_dir.mkdir(parents=True, exist_ok=True)

        recipe_path = recipe_dir / "workflow.json"
        data = spec.model_dump(by_alias=True, exclude_none=True)
        json_str = json.dumps(data, indent=2)
        recipe_path.write_text(json_str, encoding="utf-8")

        return recipe_path


# Backwards compatibility alias
WorkflowSynthesizer = ResearchGraphSynthesizer



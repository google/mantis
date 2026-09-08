import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from typing import Annotated, Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from google import adk
from google.adk.workflow import Workflow, Edge, START, node, RetryConfig, DEFAULT_ROUTE
from google.adk.models import LlmRequest
from google.adk.models.lite_llm import LiteLlm
from google.adk.agents.context import Context
from google.genai import types
from core.prompts import get_stage_prompt, STAGE_PROMPTS


from core.config import get_llm_kwargs, DEFAULT_MODEL, ResilientLiteLlm

LiteLlm = ResilientLiteLlm
from core.environments import ENVIRONMENTS, get_shared_proxy_environment
from core.sandbox import SANDBOXES
from core.llm_gateway import UNTRUSTED_CODE_AUDIT_GUARD
from tools import TOOLS

DEFAULT_SEED_PROMPT = "Initial Task Input: Evaluate {filepath}"

# Seed-prompt placeholder grammar. Only identifier-shaped fields are treated as
# placeholders, so a prompt containing literal JSON braces stays valid; any such field
# carrying a format spec, conversion or attribute/index access is captured here so the
# validator can reject it explicitly rather than silently expanding it.
_SEED_FIELD_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)[^{}]*\}")
_SEED_ALLOWED_FIELDS = frozenset({"filepath", "run_id"})
_MAX_SEED_PROMPT_CHARS = 20000


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AgentNode(_Base):
    id: str
    type: Literal["agent"]
    skill: Optional[str] = None
    system_prompt: Optional[str] = None
    model: Optional[str] = None
    api_base: Optional[str] = None
    timeout: Optional[float] = Field(default=None, gt=0)
    reasoning_effort: Optional[str] = None
    tools: list[str] = Field(default_factory=list)
    on_enter_status: Optional[str] = None
    output_schema: Optional[str] = None   # class name in core.schemas
    output_key: Optional[str] = None      # session-state key to write it to
    include_contents: Optional[Literal["default", "none"]] = None


class ClassifierNode(_Base):
    id: str
    type: Literal["classifier"]
    routes: list[str] = Field(min_length=1)
    max_visits: int = Field(default=1, ge=0)


NodeSpec = Annotated[AgentNode | ClassifierNode, Field(discriminator="type")]


class EdgeSpec(_Base):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    from_node: str = Field(alias="from")
    to_node: str = Field(alias="to")
    on: Optional[str | list[str]] = None


class SandboxConfig(_Base):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    type: str = "static-only"
    image: Optional[str] = None
    runtime: Optional[str] = None
    container_tool: Optional[str] = None
    timeout_seconds: Optional[int] = None
    options: dict[str, Any] = Field(default_factory=dict)


class GlobalConfig(_Base):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    db_path: str = "knowledge.db"
    default_model: str = DEFAULT_MODEL
    api_base: Optional[str] = None
    timeout: Optional[float] = Field(default=None, gt=0)
    reasoning_effort: Optional[str] = None
    retry_attempts: int = Field(default=3, ge=0)
    seed_prompt: str = Field(default=DEFAULT_SEED_PROMPT, max_length=_MAX_SEED_PROMPT_CHARS)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    sync_upstream: bool = False
    pin_snapshot: bool = True
    pass_number: int = 1
    snapshot_keep: int = 2
    enable_compaction: bool = True
    compaction_token_threshold: int = Field(default=500000, gt=0)
    compaction_event_retention: int = Field(default=50, ge=0)
    enable_context_cache: bool = True
    budget: Optional[dict[str, Any]] = None

    @field_validator("seed_prompt")
    @classmethod
    def validate_seed_prompt(cls, v: str) -> str:
        """Validates the seed prompt WITHOUT expanding it.

        SECURITY: str.format on attacker-reachable text is a denial-of-service
        primitive — a format spec such as ``{filepath:>999999999}`` allocates the
        requested width, and the payload persists into synthesized recipe JSON so it
        re-fires on every subsequent load. The prompt is substituted literally at use
        time (see main.py), so validation must be purely syntactic: only the bare
        tokens below may appear, with no format spec, conversion or attribute access.
        """
        for match in _SEED_FIELD_RE.finditer(v):
            token, name = match.group(0), match.group(1)
            if token[1:-1] != name:
                raise ValueError(
                    f"Global 'seed_prompt' contains an unsupported placeholder '{token}': "
                    "format specs (':'), conversions ('!') and attribute/index access "
                    "('.', '[') are not permitted."
                )
            if name not in _SEED_ALLOWED_FIELDS:
                raise ValueError(
                    f"Global 'seed_prompt' contains an unknown placeholder '{token}'. "
                    f"Permitted placeholders: {sorted(_SEED_ALLOWED_FIELDS)}."
                )
        if "{filepath}" not in v:
            raise ValueError("Global 'seed_prompt' is invalid: must contain '{filepath}' placeholder")
        return v


class WorkflowSpec(_Base):
    name: str = "declarative_workflow"
    config: GlobalConfig = Field(default_factory=GlobalConfig)
    nodes: list[NodeSpec] = Field(default_factory=list)
    edges: list[EdgeSpec] = Field(default_factory=list)
    evolution_metadata: Optional[dict[str, Any]] = None
    budget: Optional[dict[str, Any]] = None


def create_classifier(node_id: str, routes: list[str], max_visits: int = 1):
    async def _classify(ctx: Context, node_input: Any = None):
        state_key = f"{node_id}_visits"
        visits = ctx.state.get(state_key, 0) + 1

        verdict = None
        if isinstance(node_input, dict) and "route" in node_input:
            verdict = node_input
        elif hasattr(node_input, "route") and getattr(node_input, "route") is not None:
            verdict = node_input
        elif isinstance(node_input, str):
            try:
                parsed = json.loads(node_input)
                if isinstance(parsed, dict) and "route" in parsed:
                    verdict = parsed
                elif isinstance(parsed, str) and parsed in routes:
                    verdict = parsed
            except Exception:
                if node_input in routes:
                    verdict = node_input

        if verdict is None:
            verdict = ctx.state.get("verdict") or (node_input if isinstance(node_input, dict) else {})

        if isinstance(verdict, dict):
            route = verdict.get("route")
        elif hasattr(verdict, "route"):
            route = getattr(verdict, "route")
        elif isinstance(verdict, str):
            route = verdict
        else:
            route = None

        if isinstance(route, str):
            route = route.lower().strip()

        if max_visits and max_visits > 1 and visits >= max_visits:
            return adk.Event(output=node_input, state={state_key: visits}, route="exceeded")

        if route and route in routes:
            return adk.Event(output=node_input, state={state_key: visits}, route=route)

        if route and route != DEFAULT_ROUTE and route not in ("false_positive", "non_viable", "failed_repro", "not_attempted"):
            print(f"[{node_id}] verdict '{route}' not in declared routes {routes}; routing to fallback")

        return adk.Event(output=node_input, state={state_key: visits}, route=DEFAULT_ROUTE)

    return node(_classify, name=node_id)


def _parse_finding_calibration(
    resp_text: str,
    f_id: int,
    fallback_finding: dict[str, Any],
):
    from core.schemas import FindingCalibration

    cleaned = resp_text.strip()
    if "```json" in cleaned:
        cleaned = cleaned.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in cleaned:
        cleaned = cleaned.split("```", 1)[1].split("```", 1)[0].strip()

    if not (cleaned.startswith("{") and cleaned.endswith("}")):
        m = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if m:
            cleaned = m.group(0)

    if cleaned.startswith("{") and cleaned.endswith("}"):
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict):
                parsed["finding_id"] = f_id
                return FindingCalibration.model_validate(parsed)
        except Exception:
            pass

    # Regex score match (for scripted test replies or unstructured replies: e.g. "Score: 90")
    score_match = re.search(r"(?:score|calibration)[:\s]+([0-9]+(?:\.[0-9]+)?)", resp_text, re.IGNORECASE)
    if score_match:
        try:
            val = float(score_match.group(1))
            if val > 10.0 and val <= 100.0:
                val = val / 10.0
            val = max(0.1, min(10.0, val))
            pri = "CRITICAL" if val >= 8.0 else ("HIGH" if val >= 6.0 else ("MEDIUM" if val >= 3.0 else "LOW"))
            imp = 5 if val >= 8.0 else (4 if val >= 6.0 else (3 if val >= 3.0 else 2))
            lik = 4 if val >= 6.0 else 3
            return FindingCalibration(
                finding_id=f_id,
                mantis_risk_score=val,
                priority=pri,
                impact_score=imp,
                likelihood_score=lik,
                reasoning=resp_text.strip() or "Calibration score parsed from response",
            )
        except Exception:
            pass

    # Deterministic fallback based on initial severity & repro status
    sev = str(fallback_finding.get("severity") or "MEDIUM").upper()
    repro = str(fallback_finding.get("repro_status") or "not_attempted")
    if repro == "failed_to_reproduce":
        val, pri, imp, lik = 2.0, "LOW", 2, 2
        sanity = "repro_failure"
    elif sev == "CRITICAL" and repro == "reproduced":
        val, pri, imp, lik = 8.5, "CRITICAL", 5, 4
        sanity = ""
    elif sev in ("CRITICAL", "HIGH"):
        val, pri, imp, lik = 6.5, "HIGH", 4, 3
        sanity = "static_confirmation" if repro != "reproduced" else ""
    elif sev == "MEDIUM":
        val, pri, imp, lik = 4.5, "MEDIUM", 3, 3
        sanity = ""
    else:
        val, pri, imp, lik = 2.0, "LOW", 2, 2
        sanity = ""

    return FindingCalibration(
        finding_id=f_id,
        mantis_risk_score=val,
        priority=pri,
        impact_score=imp,
        likelihood_score=lik,
        sanity_triage_applied=sanity,
        reasoning=f"Fallback calibration based on {sev} severity and {repro} repro status.",
    )


def _update_finding_artifact(
    db_path: str,
    run_id: str,
    finding: dict[str, Any],
    calib: Any,
) -> None:
    from datetime import datetime, timezone
    from core.database import read_artifact, record_artifact

    f_id = finding.get("id")
    art_path = f"workspace/findings/{f_id}.json"

    existing_raw = read_artifact(db_path, filepath=art_path, run_id=run_id)
    data = None
    if existing_raw:
        try:
            data = json.loads(existing_raw)
        except Exception:
            data = None
    if not isinstance(data, dict):
        data = dict(finding)

    data["id"] = f_id
    data["mantis_risk_score"] = calib.mantis_risk_score
    data["priority"] = calib.priority
    data["impact_score"] = calib.impact_score
    data["likelihood_score"] = calib.likelihood_score
    data["inferred_exposure"] = calib.inferred_exposure
    if getattr(calib, "attacker_position", None):
        data["attacker_position"] = calib.attacker_position
    if getattr(calib, "availability_tier", None):
        data["availability_tier"] = calib.availability_tier
    if getattr(calib, "sanity_triage_applied", None):
        data["sanity_triage_applied"] = calib.sanity_triage_applied
    if getattr(calib, "executive_summary", None):
        data["executive_summary"] = calib.executive_summary
    if getattr(calib, "calibration_checklist", None):
        data["calibration_checklist"] = calib.calibration_checklist

    hist = data.get("history") or []
    if not isinstance(hist, list):
        hist = []
    hist.append({
        "stage": "calibrate",
        "action": "calibrated",
        "details": f"Calculated risk score as {calib.mantis_risk_score:.1f} and priority as {calib.priority}.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    data["history"] = hist

    record_artifact(
        db_path,
        run_id,
        "workspace_file",
        art_path,
        json.dumps(data, indent=2),
        metadata={"resource": data.get("filepath", ""), "agent_authored": True},
    )


def create_calibrator_node(
    node_id: str,
    llm_model: Any,
    system_instruction: str,
):
    """Creates a deterministic per-finding calibration loop node with structured output schemas."""
    async def _calibrate(ctx: Context, node_input: Any = None):
        from core.context import current_run_context
        from core.database import (
            read_findings,
            update_finding_calibration,
            record_calibration,
            read_artifact,
        )
        from core.schemas import FindingCalibration

        run_ctx = current_run_context.get()
        db_path = (getattr(run_ctx, "db_path", None) or ctx.state.get("db_path") or "knowledge.db")
        run_id = (getattr(run_ctx, "run_id", None) or ctx.state.get("run_id") or "")
        target_file = (getattr(run_ctx, "target_file", None) or "")

        findings = []
        if db_path and os.path.exists(db_path):
            try:
                findings = read_findings(db_path, run_id=run_id)
                if not findings and not run_id:
                    findings = read_findings(db_path)
            except Exception:
                findings = []

        candidates = []
        for f in findings:
            stat = str(f.get("status") or "").lower()
            if stat in ("false_positive", "non_viable", "duplicate_merged"):
                continue
            if str(f.get("production_viability") or "").upper() == "NON_VIABLE":
                continue
            if os.path.exists(db_path):
                art_raw = read_artifact(db_path, filepath=f"workspace/findings/{f.get('id')}.json", run_id=run_id)
                if art_raw:
                    try:
                        art_data = json.loads(art_raw)
                        if isinstance(art_data, dict):
                            if str(art_data.get("status", "")).lower() in ("false_positive", "non_viable", "duplicate_merged"):
                                continue
                            if str(art_data.get("production_viability", "")).upper() == "NON_VIABLE":
                                continue
                    except Exception:
                        pass
            candidates.append(f)

        if not candidates:
            print(f"[{node_id}] Zero candidate findings to calibrate in database '{db_path}'.", flush=True)
            return adk.Event(output="No candidate findings to calibrate.")

        print(f"\n[{node_id}] Deterministic per-finding calibration loop: {len(candidates)} finding(s) to calibrate.", flush=True)

        tm_text = ""
        if os.path.exists(db_path):
            tm_text = read_artifact(db_path, artifact_type="threat_model", run_id=run_id) or ""
            if not tm_text:
                tm_text = read_artifact(db_path, filepath="workspace/kb/THREAT_MODEL.md", run_id=run_id) or ""

        calibrated_results: list[FindingCalibration] = []

        from google.adk.tools.set_model_response_tool import SetModelResponseTool
        set_response_tool = SetModelResponseTool(FindingCalibration)

        for idx, f in enumerate(candidates, 1):
            f_id = f.get("id")
            f_title = f.get("title", f"Finding {idx}")
            f_path = f.get("filepath", "")
            f_cwe = f.get("cwe", "")
            f_desc = f.get("description", "")
            f_sev = f.get("severity", "MEDIUM")
            f_stat = f.get("status", "static_confirmed")
            f_repro = f.get("repro_status", "not_attempted")
            f_viab = f.get("production_viability", "CONDITIONAL_VIABLE")
            f_lines = f.get("line_numbers") or []
            f_code_paths = f.get("code_paths") or []
            f_rem = f.get("remediation", "")
            f_reason = f.get("triage_reasoning") or ""

            finding_prompt = (
                f"Evaluate and calibrate the following vulnerability finding strictly according to the Mantis calibration matrix and rules:\n\n"
                f"- Finding ID: {f_id}\n"
                f"- Title: {f_title}\n"
                f"- Filepath: {f_path}\n"
                f"- Line Numbers: {f_lines}\n"
                f"- Code Paths: {f_code_paths}\n"
                f"- Vulnerability Class (CWE): {f_cwe}\n"
                f"- Initial Severity: {f_sev}\n"
                f"- Lifecycle Status: {f_stat}\n"
                f"- Reproduction Status: {f_repro}\n"
                f"- Production Viability: {f_viab}\n"
                f"- Description: {f_desc}\n"
                f"- Proposed Remediation: {f_rem}\n"
                f"- Upstream Triage Reasoning: {f_reason}\n"
            )
            if tm_text:
                finding_prompt += f"\nTarget Threat Model Context:\n{tm_text[:2000]}\n"

            finding_prompt += (
                "\nRequired Output: Call the 'set_model_response' tool with the structured calibration verdict containing:\n"
                "1. finding_id (int)\n"
                "2. mantis_risk_score (float, 0.1 to 10.0, where Hazard = (Impact + Likelihood) * Multiplier)\n"
                "3. priority (CRITICAL, HIGH, MEDIUM, LOW)\n"
                "4. impact_score (1 to 5)\n"
                "5. likelihood_score (1 to 5)\n"
                "6. inferred_exposure (EXPOSED, INTERNAL, or PRIVILEGED)\n"
                "7. sanity_triage_applied (semicolon-separated string of fired rules)\n"
                "8. reasoning (justification of scores and applicable caps)\n"
                "9. executive_summary (concise stakeholder summary)\n"
            )

            req = LlmRequest(
                contents=[types.Content(parts=[types.Part.from_text(text=finding_prompt)], role="user")],
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    tools=[set_response_tool],
                ),
            )

            resp_text = ""
            structured_data = None
            usage_meta = None
            try:
                async for resp in llm_model.generate_content_async(req):
                    if hasattr(resp, "content") and resp.content and hasattr(resp.content, "parts"):
                        for part in resp.content.parts:
                            if getattr(part, "function_call", None):
                                fc = part.function_call
                                if getattr(fc, "name", "") == "set_model_response":
                                    args = getattr(fc, "args", {})
                                    if isinstance(args, dict):
                                        structured_data = dict(args)
                            elif getattr(part, "text", None):
                                resp_text += part.text
                    if hasattr(resp, "usage_metadata") and resp.usage_metadata:
                        usage_meta = resp.usage_metadata
            except Exception as call_err:
                from core.config import is_auth_error, MantisAuthError
                from core.budget import BudgetExceededError
                if is_auth_error(call_err) or isinstance(call_err, (MantisAuthError, BudgetExceededError)):
                    raise
                print(f"  [{node_id}] LLM call error on finding {f_id}: {call_err}; falling back to deterministic scoring", file=sys.stderr, flush=True)

            if run_ctx and getattr(run_ctx, "budget_controller", None) and usage_meta:
                total_t = int(getattr(usage_meta, "total_token_count", 0) or 0)
                cached_t = int(getattr(usage_meta, "cached_content_token_count", 0) or 0)
                run_ctx.budget_controller.record_tokens(total_t, cached_t)

            calib = None
            if structured_data:
                try:
                    structured_data["finding_id"] = int(f_id)
                    calib = FindingCalibration.model_validate(structured_data)
                except Exception:
                    calib = None
            if calib is None:
                calib = _parse_finding_calibration(resp_text, f_id=int(f_id), fallback_finding=f)
            calibrated_results.append(calib)

            try:
                update_finding_calibration(
                    db_path,
                    int(f_id),
                    calib.mantis_risk_score,
                    impact_score=calib.impact_score,
                    likelihood_score=calib.likelihood_score,
                    priority=calib.priority,
                    run_id=run_id,
                )

                record_calibration(
                    db_path,
                    f_path or target_file,
                    calib.mantis_risk_score,
                    calib.reasoning,
                    run_id=run_id,
                )

                _update_finding_artifact(db_path, run_id, f, calib)
            except Exception as db_err:
                print(f"  [{node_id}] Warning: DB update for finding {f_id} failed: {db_err}", file=sys.stderr, flush=True)

            print(f"  [{node_id}] Calibrated Finding {f_id} ('{f_title}'): Score={calib.mantis_risk_score:.1f}, Priority={calib.priority}, Impact={calib.impact_score}/5, Likelihood={calib.likelihood_score}/5", flush=True)

        summary_lines = [
            f"Calibrated {len(calibrated_results)} finding(s) with deterministic structured output:"
        ]
        for c in calibrated_results:
            summary_lines.append(f"  • Finding {c.finding_id}: Score {c.mantis_risk_score:.1f} ({c.priority})")

        out_msg = "\n".join(summary_lines)
        return adk.Event(output=out_msg)

    return node(_calibrate, name=node_id)

def merge_config_dicts(base: dict, overlay: dict) -> dict:
    """Deeply merges overlay dictionary into base dictionary.
    
    Cleanly replaces sandbox configurations when switching sandbox mechanisms
    or resetting options to avoid inheriting incompatible base options.
    """
    merged = dict(base)
    for k, v in overlay.items():
        if k == "sandbox" and isinstance(v, dict):
            base_sb = merged.get("sandbox", {}) if isinstance(merged.get("sandbox"), dict) else {}
            base_type = base_sb.get("type")
            new_type = v.get("type", base_type)
            if new_type in ("static-only", "static"):
                merged["sandbox"] = {"type": new_type, "options": {}}
                sb_proj = v.get("options", {}).get("project") if isinstance(v.get("options"), dict) else None
                if sb_proj and not merged.get("project"):
                    merged["project"] = sb_proj
            elif new_type != base_type or ("options" in v and v["options"] == {}):
                merged["sandbox"] = dict(v)
                if "options" not in merged["sandbox"] or not isinstance(merged["sandbox"]["options"], dict):
                    merged["sandbox"]["options"] = {}
            else:
                merged["sandbox"] = {
                    "type": new_type,
                    "options": merge_config_dicts(
                        base_sb.get("options", {}) if isinstance(base_sb.get("options"), dict) else {},
                        v.get("options", {}) if isinstance(v.get("options"), dict) else {},
                    ),
                }
        elif k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
            merged[k] = merge_config_dicts(merged[k], v)
        else:
            merged[k] = v
    return merged


def load_raw_workflow_with_overlay(json_path: str, load_local: bool = True) -> tuple[dict, str]:
    """Loads workflow JSON and merges local overlay (e.g. workflow.local.json) if present."""
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"Workflow layout JSON not found at: {json_path}")

    with open(json_path, 'r', encoding='utf-8') as f:
        raw_json = json.load(f)

    if not isinstance(raw_json, dict):
        raise ValueError(f"Workflow layout JSON at {json_path} must be a dictionary.")

    base_dir = os.path.dirname(os.path.abspath(json_path))
    base_name = os.path.basename(json_path)
    stem = base_name[:-5] if base_name.endswith(".json") else base_name
    local_candidates = [
        os.path.join(base_dir, f"{stem}.local.json"),
        os.path.join(base_dir, f".{stem}.local.json"),
    ]

    abs_json = os.path.abspath(json_path)
    if load_local:
        for cand in local_candidates:
            if os.path.exists(cand) and os.path.abspath(cand) != abs_json:
                try:
                    with open(cand, 'r', encoding='utf-8') as lf:
                        local_data = json.load(lf)
                    if isinstance(local_data, dict):
                        if "config" in local_data and isinstance(local_data["config"], dict):
                            raw_json["config"] = merge_config_dicts(
                                raw_json.get("config", {}), local_data["config"]
                            )
                        # Also check top-level config keys placed directly at root of overlay
                        for top_k in (
                            "sandbox",
                            "default_model",
                            "api_base",
                            "timeout",
                            "reasoning_effort",
                            "db_path",
                            "seed_prompt",
                        ):
                            if top_k in local_data and (
                                "config" not in local_data
                                or top_k not in local_data.get("config", {})
                            ):
                                if top_k == "sandbox" and isinstance(local_data[top_k], dict):
                                    raw_json.setdefault("config", {})["sandbox"] = merge_config_dicts(
                                        {"sandbox": raw_json.get("config", {}).get("sandbox", {})},
                                        {"sandbox": local_data["sandbox"]},
                                    )["sandbox"]
                                elif isinstance(local_data[top_k], dict) and isinstance(raw_json.get("config", {}).get(top_k), dict):
                                    raw_json.setdefault("config", {})[top_k] = merge_config_dicts(
                                        raw_json.get("config", {}).get(top_k, {}), local_data[top_k]
                                    )
                                else:
                                    raw_json.setdefault("config", {})[top_k] = local_data[top_k]
                        for k in ("name", "nodes", "edges"):
                            if k in local_data:
                                raw_json[k] = local_data[k]
                    break
                except Exception as e:
                    print(f"[CONFIG WARNING] Could not load local overlay {cand}: {e}")

    return raw_json, base_dir


def load_workflow_from_json(
    json_path: str,
    model_override: Optional[str] = None,
    api_base_override: Optional[str] = None,
    sandbox_override: Optional[dict | str] = None,
    db_override: Optional[str] = None,
    timeout_override: Optional[float] = None,
    reasoning_effort_override: Optional[str] = None,
    load_local: bool = True,
) -> tuple[Workflow, dict]:
    raw_json, base_dir = load_raw_workflow_with_overlay(json_path, load_local=load_local)

    spec = WorkflowSpec.model_validate(raw_json)

    # Apply global runtime overrides if provided
    if model_override:
        spec.config.default_model = model_override
    if api_base_override:
        spec.config.api_base = api_base_override
    if timeout_override is not None:
        spec.config.timeout = timeout_override
    if reasoning_effort_override:
        spec.config.reasoning_effort = reasoning_effort_override
    if db_override:
        spec.config.db_path = db_override
    if sandbox_override:
        if isinstance(sandbox_override, str):
            spec.config.sandbox = SandboxConfig(type=sandbox_override)
        elif isinstance(sandbox_override, dict):
            spec.config.sandbox = SandboxConfig.model_validate(sandbox_override)

    errors = []

    if spec.config.sandbox.type not in SANDBOXES and spec.config.sandbox.type not in ENVIRONMENTS:
        errors.append(
            f"Unknown sandbox type '{spec.config.sandbox.type}'. Available: {sorted(ENVIRONMENTS)}"
        )

    nodes = {}
    node_specs = {}
    declared_node_ids = set()

    for node_cfg in spec.nodes:
        node_id = node_cfg.id
        if not node_id.isidentifier():
            errors.append(f"Node id '{node_id}' is not a valid Python identifier.")
            continue
        if node_id == "START":
            errors.append("Node id 'START' is reserved for workflow entry.")
            continue
        if node_id in declared_node_ids:
            errors.append(f"Duplicate node id '{node_id}' found.")
            continue
        declared_node_ids.add(node_id)

        if isinstance(node_cfg, ClassifierNode):
            if len(node_cfg.routes) != len(set(node_cfg.routes)):
                errors.append(f"Classifier '{node_id}' routes contain duplicates: {node_cfg.routes}.")
            nodes[node_id] = create_classifier(node_id, node_cfg.routes, max_visits=node_cfg.max_visits)
            allowed_routes = set(node_cfg.routes) | {DEFAULT_ROUTE}
            if node_cfg.max_visits > 1:
                allowed_routes.add("exceeded")
            node_specs[node_id] = {"type": "classifier", "routes": allowed_routes}
            continue

        if isinstance(node_cfg, AgentNode):
            node_has_error = False
            try:
                _, llm_kwargs = get_llm_kwargs(
                    node_cfg.model,
                    spec.config.default_model,
                    api_base=node_cfg.api_base,
                    default_api_base=spec.config.api_base,
                    timeout=node_cfg.timeout,
                    default_timeout=spec.config.timeout,
                    reasoning_effort=node_cfg.reasoning_effort,
                    default_reasoning_effort=spec.config.reasoning_effort,
                    global_model_override=model_override,
                    config=spec.config.model_dump(),
                )
            except Exception as e:
                errors.append(f"Node {node_id}: {str(e)}")
                node_has_error = True
                llm_kwargs = {}

            instruction = ""
            agent_tools = []
            tools_list = []
            for t in node_cfg.tools:
                if t in TOOLS:
                    tools_list.append(TOOLS[t])
                else:
                    errors.append(f"Node {node_id}: Unknown tool '{t}'")
                    node_has_error = True

            if node_cfg.system_prompt:
                # System prompt is strictly literal instruction text (A2: no file path loading)
                instruction = node_cfg.system_prompt
            else:
                instruction = get_stage_prompt(node_id, node_cfg.skill or "")
            agent_tools = tools_list

            schema_cls = None
            if node_cfg.output_schema:
                import core.schemas
                schema_cls = getattr(core.schemas, node_cfg.output_schema, None)
                if schema_cls is None:
                    errors.append(f"Node {node_id}: unknown output_schema '{node_cfg.output_schema}'")
                    node_has_error = True

            if node_has_error:
                continue

            # Invariant: Every agent node MUST include the untrusted code audit guard (covers both skill and system_prompt)
            guard_text = UNTRUSTED_CODE_AUDIT_GUARD.strip()
            if guard_text not in instruction:
                instruction = f"{instruction.rstrip()}\n\n{guard_text}"

            if node_id == "calibrator" or (node_cfg.skill and "mantis-calibrate" in node_cfg.skill):
                model_inst = LiteLlm(**llm_kwargs)
                nodes[node_id] = create_calibrator_node(
                    node_id=node_id,
                    llm_model=model_inst,
                    system_instruction=instruction,
                )
                node_specs[node_id] = {"type": "agent"}
                continue

            if schema_cls:
                instruction = (
                    f"{instruction.rstrip()}\n\n"
                    f"CRITICAL TERMINATION CONTRACT: When your analysis for this stage is complete, "
                    f"submit your final verdict using the 'set_model_response' tool (e.g. set_model_response(route=..., reason=...)) "
                    f"or emit it directly as raw JSON response text conforming to '{node_cfg.output_schema}' "
                    f"(e.g. {{\"route\": \"...\", \"reason\": \"...\"}}). "
                    f"Do NOT call write_file, run_sandbox, or any other general tool to signal completion, and do NOT write dummy marker or verdict files "
                    f"(e.g. do NOT write 'verdict.json', 'done.txt', or 'status.json'). Also do NOT run probe shell commands "
                    f"(e.g. do NOT run 'echo done', 'echo 1', 'true', or 'exit 0')."
                )

            agent_kwargs: dict[str, Any] = {
                "name": node_id,
                "model": LiteLlm(**llm_kwargs),
                "instruction": instruction,
                "tools": agent_tools,
                "output_schema": schema_cls,
                "output_key": node_cfg.output_key,
            }
            if node_cfg.include_contents is not None:
                agent_kwargs["include_contents"] = node_cfg.include_contents
            else:
                agent_kwargs["include_contents"] = "none"

            agent = adk.Agent(**agent_kwargs)
            node_retry = (
                RetryConfig(
                    max_attempts=spec.config.retry_attempts,
                    initial_delay=5.0,
                    max_delay=60.0,
                    backoff_factor=2.0,
                    jitter=0.5,
                )
                if spec.config.retry_attempts > 1
                else None
            )
            nodes[node_id] = node(agent, name=node_id, retry_config=node_retry)
            node_specs[node_id] = {"type": "agent"}

    # Wire Edges
    edge_map = {}
    edge_nodes_referenced = set()
    node_out_routes = {nid: set() for nid in nodes}

    for edge_cfg in spec.edges:
        from_str = edge_cfg.from_node
        to_str = edge_cfg.to_node
        route = edge_cfg.on

        if from_str == "START":
            from_node = START
            if route is not None:
                errors.append(f"Edge from START to '{to_str}' must not have a route condition ('on': '{route}').")
        else:
            if from_str not in declared_node_ids:
                errors.append(f"Edge references unknown from_node: '{from_str}'")
                continue
            from_node = nodes.get(from_str)
            if from_node is None:
                continue
            edge_nodes_referenced.add(from_str)

        if to_str not in declared_node_ids:
            errors.append(f"Edge references unknown to_node: '{to_str}'")
            continue
        to_node = nodes.get(to_str)
        if to_node is None:
            continue
        edge_nodes_referenced.add(to_str)

        # Validate route consistency
        if from_str in node_specs:
            nspec = node_specs[from_str]
            if nspec["type"] == "classifier":
                declared_routes = nspec["routes"]
                if route is None:
                    errors.append(
                        f"Edge from classifier '{from_str}' to '{to_str}' is missing route condition ('on')."
                    )
                elif isinstance(route, list):
                    for r in route:
                        if r not in declared_routes:
                            errors.append(
                                f"Edge from classifier '{from_str}' references undeclared route '{r}'."
                            )
                        else:
                            node_out_routes[from_str].add(r)
                elif route not in declared_routes:
                    errors.append(
                        f"Edge from classifier '{from_str}' references undeclared route '{route}'."
                    )
                else:
                    node_out_routes[from_str].add(route)
            elif nspec["type"] == "agent":
                if route is not None:
                    errors.append(
                        f"Edge from agent '{from_str}' to '{to_str}' must not specify a route condition ('on': '{route}'). Agents do not emit routes."
                    )

        key = (from_str, to_str)
        if key in edge_map:
            errors.append(f"Duplicate edge from '{from_str}' to '{to_str}'. Use a list in 'on' to specify multiple routes.")
        else:
            edge_map[key] = {"from_node": from_node, "to_node": to_node, "route": route}

    # Validate that all declared classifier routes have outgoing edges
    for node_id, nspec in node_specs.items():
        if nspec["type"] == "classifier":
            orig_node = next((n for n in spec.nodes if n.id == node_id), None)
            if orig_node and isinstance(orig_node, ClassifierNode):
                declared = set(orig_node.routes)
                used = node_out_routes.get(node_id, set())
                missing = declared - used
                if missing:
                    errors.append(
                        f"Node '{node_id}' declared route(s) {sorted(missing)} with no outgoing edge."
                    )

    # Orphan node validation
    for node_id in nodes:
        if node_id not in edge_nodes_referenced:
            errors.append(f"Node '{node_id}' is defined in 'nodes' but is not connected by any edge.")

    # Terminal sink validation
    if nodes:
        terminal_nodes = set(nodes.keys()) - {f for (f, _) in edge_map if f != "START"}
        if len(terminal_nodes) == 0:
            errors.append(
                "Workflow must have at least one terminal sink node, but found none (cycle without sink)."
            )

    if errors:
        raise ValueError("Graph validation failed:\n" + "\n".join(errors))

    edges = [
        Edge(from_node=item["from_node"], to_node=item["to_node"], route=item["route"])
        if item["route"] is not None
        else Edge(from_node=item["from_node"], to_node=item["to_node"])
        for item in edge_map.values()
    ]

    node_status_map = {
        node_cfg.id: node_cfg.on_enter_status
        for node_cfg in spec.nodes
        if isinstance(node_cfg, AgentNode) and node_cfg.on_enter_status is not None
    }
    cfg = spec.config.model_dump()
    cfg["on_enter_status"] = node_status_map
    if spec.budget:
        cfg["budget"] = spec.budget
    elif "budget" in raw_json and isinstance(raw_json["budget"], dict):
        cfg["budget"] = raw_json["budget"]

    return (
        Workflow(
            name=spec.name,
            edges=edges
        ),
        cfg
    )


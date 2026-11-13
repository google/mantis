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

import functools
import hashlib
import json
import os
import re
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from google import adk
from google.adk.workflow import Workflow, Edge, START, node, RetryConfig, DEFAULT_ROUTE
from google.adk.models import LlmRequest
from google.adk.models.lite_llm import LiteLlm
from google.adk.agents.context import Context
from google.genai import types
from core.prompts import (
    ARCHITECT_PREFIX_STEM_ADDENDUM,
    PLANNER_PREFIX_STEM_ADDENDUM,
    PREFIX_FORKED_STAGE_ADDENDUM,
    PREFIX_GROUP_BASE_INSTRUCTION,
    STAGE_PROMPTS,
    THREAT_MODELER_PREFIX_STEM_ADDENDUM,
    get_stage_prompt,
)


from core.config import (
    ConfigValidationError,
    DEFAULT_MODEL,
    DEFAULT_VERTEX_FAST_MODEL,
    DeferredEnvLiteLlm,
    ExtendedCriticVerdict,
    ExtendedReviewVerdict,
    ResilientLiteLlm,
    _HANDOFF_PLAIN_TEXT_TURN,
    _HandoffLiteLlm,
    get_llm_kwargs,
    is_claude_model,
    resolve_model_id,
    validate_llm_env_vars,
)
from core.config import context_editing_keeps as _context_editing_keeps

LiteLlm = ResilientLiteLlm
from core.environments import ENVIRONMENTS, get_shared_proxy_environment
from core.sandbox import SANDBOXES
from core.llm_gateway import UNTRUSTED_CODE_AUDIT_GUARD

# What a node may stamp on the findings in its scope when it completes. A
# strict subset of the status vocabulary: `patch_verified` is the harness's
# highest-assurance word, earned only through the re-attack flow, and the
# MCP change gate treats it as closed -- a workflow that stamped it would
# silence every finding in the campaign; `reported` would reopen dismissals.
# Enforced here, where the stamp callback is attached, so a hand-written
# workflow, a synthesized graph, and a persisted recipe all meet the same gate.
NODE_STAMP_STATUSES = frozenset({"static_confirmed", "dynamic_confirmed"})
from tools import TOOLS

DEFAULT_SEED_PROMPT = "Initial Task Input: Evaluate {filepath}"

# Seed-prompt placeholder grammar. Only identifier-shaped fields are treated as
# placeholders, so a prompt containing literal JSON braces stays valid; any such field
# carrying a format spec, conversion or attribute/index access is captured here so the
# validator can reject it explicitly rather than silently expanding it.
_SEED_FIELD_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)[^{}]*\}")
_SEED_ALLOWED_FIELDS = frozenset({"filepath", "run_id"})
_MAX_SEED_PROMPT_CHARS = 20000

# Caps on always-on prompt text. Every token that rides in the system
# instruction on every turn competes with the agent's output budget, and the
# costliest failure a stage can have is to reason until the budget is gone and
# produce nothing. Two seams add text to a node's instruction and each is
# bounded at its seam:
#
# - MAX_APPENDED_INSTRUCTION_CHARS bounds the stage-experience block that
#   _make_stage_experience_before_model_callback appends at request time. It
#   is TRUNCATED, never refused: recall is advisory, so a long memory costs the
#   agent its least-ranked lessons, not the run. The cut is announced by a
#   trailing marker line; nothing is dropped silently.
# - MAX_NODE_SYSTEM_PROMPT_CHARS bounds a synthesizer-authored node
#   `system_prompt`. There it is a VALIDATION error (core.synthesizer), because
#   the synthesizer runs inside a repair loop that can feed the error back to
#   the model, and a truncated instruction is a different instruction. The
#   shipped workflow.json carries no inline prompts (its stage prompts are
#   ~1 KB) and synthesize_archetype's longest is ~1.3 KB, so 12000 leaves
#   roughly 9x headroom for a specialised prompt without admitting a
#   skill-file-sized one.
MAX_APPENDED_INSTRUCTION_CHARS = 4000
MAX_NODE_SYSTEM_PROMPT_CHARS = 12000
_APPENDED_TRUNCATION_MARKER = (
    "[STAGE EXPERIENCE truncated: {omitted} chars omitted; "
    "fewer, better-evidenced lessons are worth more than more]"
)


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
    # The agent node whose transcript this node's requests begin with: a
    # fork of that stage's conversation instead of a fresh context. See
    # _make_fork_before_model_callback for what is inherited and why.
    fork_from: Optional[str] = None
    # Shared-prefix KV-cache group name (e.g. "audit_stem"). Nodes sharing a
    # prefix_group receive a byte-identical base system_instruction and unified
    # tool schema, with stage-specific prompts/directives moved to each stage's
    # opening user turn and per-stage tool permissions enforced in Python.
    prefix_group: Optional[str] = None
    # Short-circuit this node via before_agent_callback when RunContext.sandbox
    # is an explicit static-only environment (preserving completion stamps).
    skip_when_static: bool = False


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
    fast_model: Optional[str] = None
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
    # Session compaction is off unless the operator turns it on. Every node
    # runs with include_contents="none" and sees only its own events, so a
    # summary of earlier events never reaches a prompt -- except by the one
    # route that is harmful: the token-threshold compactor runs before a
    # model call and summarises the CURRENT stage's own tool results out
    # from under it. A stage whose working set it rewrote re-read that
    # state and was compacted again, indefinitely; and models that bind
    # reasoning to its prefix (preserved thinking) reject the rewritten
    # request outright. The node context ceiling (graph_loader) bounds a
    # stage's working set without editing anything already sent.
    enable_compaction: bool = False
    compaction_token_threshold: int = Field(default=500000, gt=0)
    compaction_event_retention: int = Field(default=50, ge=0)
    # How many fresh contexts a stage may continue into after filling the
    # model's window (see MAX_NODE_CONTINUATIONS for the reasoning behind
    # the default). 0 ends or fails the stage at its first ceiling.
    max_node_continuations: int = Field(default=6, ge=0)
    context_editing_trigger_tokens: Optional[int] = Field(default=None, gt=0)
    enable_context_cache: bool = True
    enable_narrative_report: bool = False
    # Stream model turns (default). The request timeout then applies
    # between chunks, so a long thinking turn that keeps producing is never
    # cut short, while a hung connection still is (core.config
    # llm_streaming_enabled; MANTIS_LLM_STREAM overrides).
    llm_streaming: bool = True
    budget: Optional[dict[str, Any]] = None
    # Optional absolute input-token trigger cap for context editing (e.g. 180000).
    context_editing_trigger_tokens: Optional[int] = Field(default=None, gt=0)
    # Optional per-sandbox-backend option map preserved across --sandbox switches.
    sandbox_profiles: Optional[dict[str, dict[str, Any]]] = None
    # Paths under the target that are not scanned: patterns relative to the
    # target, see core.exclusions. A list, or one comma-separated string.
    exclude: Optional[list[str] | str] = None

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


_DISMISSAL_ROUTES = ("false_positive", "non_viable")


def _persist_dismissal_verdict(node_id: str, route, verdict) -> None:
    """Record a dismissal verdict as the finding status, deterministically.

    The reviewer and critic ROUTE dismissals but hold no write tool, and the
    only status stamps fire on promotion edges (on_enter_status). Without this,
    a rejected finding stayed `reported` forever: exports looked clean only
    because `reported` is suppressed, and cross-run false-positive learning
    never saw a single dismissed row. The route vocabulary maps one-to-one onto
    the status vocabulary, so the classifier -- harness code, already the
    single point where every verdict passes -- is where the record is made.

    Verdicts whose reason begins with "Fallback:" are synthesized by
    _sanitize_structured_response for safety-blocked or non-schema model
    output. Routing them is fail-closed; RECORDING them would teach every
    future run that the finding was reviewed and dismissed when no review
    happened. Route it, never learn it.

    Best-effort by design: a broken database must never break routing.
    """
    if route not in _DISMISSAL_ROUTES:
        return
    try:
        reason = ""
        if isinstance(verdict, dict):
            reason = str(verdict.get("reason") or "")
        elif hasattr(verdict, "reason"):
            reason = str(getattr(verdict, "reason") or "")
        if reason.lstrip().startswith("Fallback:"):
            return
        from core.context import current_run_context
        rc = current_run_context.get()
        if rc is None or not rc.db_path or not rc.run_id or not rc.target_file:
            return
        from core.database import update_status
        rc_pass = int(getattr(rc, "pass_index", 1) or 1)
        note = f"[{node_id}] {reason}" if reason else ""
        promoted = getattr(rc, "promoted_finding_ids", None)
        if promoted is not None:
            if not promoted:
                return
            update_status(
                rc.db_path,
                rc.target_file,
                rc.run_id,
                route,
                finding_ids=sorted(int(i) for i in promoted),
                campaign=rc.target_file,
                pass_index=rc_pass,
                note=note,
            )
            rc.promoted_finding_ids = set()
        else:
            update_status(
                rc.db_path,
                rc.target_file,
                rc.run_id,
                route,
                campaign=rc.target_file,
                pass_index=rc_pass,
                note=note,
            )
    except Exception as exc:
        print(f"[{node_id}] could not persist '{route}' verdict: {exc}", file=sys.stderr)


def _coerce_finding_verdicts(verdict) -> list[dict]:
    """Normalizes the optional per-finding verdict list into plain dicts.

    A live run pushed 14 findings through ONE campaign-level ReviewVerdict:
    a single review opinion covered 14 independent vulnerabilities, so one
    bad call either dismissed or promoted all of them at once. The extended
    ReviewVerdict (core.config) lets the reviewer return one entry per
    finding; this helper accepts the pydantic object, its dict dump, or the
    parsed model JSON, because the classifier receives whichever of those
    forms survived the output_key/session-state round-trip.

    Returns [] whenever the field is absent, empty, or unusable. The empty
    list IS the INV-6 fail-safe contract: the classifier then falls back to
    campaign-level routing and persistence exactly as before this field
    existed, so old workflows, old models, and refusal fallbacks lose
    nothing.
    """
    raw = None
    if isinstance(verdict, dict):
        raw = verdict.get("finding_verdicts")
    elif hasattr(verdict, "finding_verdicts"):
        raw = getattr(verdict, "finding_verdicts")
    if not raw or not isinstance(raw, (list, tuple)):
        return []

    entries: list[dict] = []
    for item in raw:
        if isinstance(item, dict):
            fid = item.get("finding_id")
            route = item.get("route")
            reason = item.get("reason")
        else:
            fid = getattr(item, "finding_id", None)
            route = getattr(item, "route", None)
            reason = getattr(item, "reason", None)
        if not isinstance(route, str) or not route.strip():
            # An entry with no route can neither be routed nor persisted;
            # dropping it (rather than failing the batch) keeps the other
            # findings' verdicts alive.
            continue
        try:
            fid = int(fid)
        except (TypeError, ValueError):
            # Identifier the DB cannot address. The entry still counts for
            # the aggregate route below, but persistence will skip it.
            fid = None
        entries.append({
            "finding_id": fid,
            # Statuses are lowercase everywhere in the pipeline; normalize
            # here once so persistence and routing agree on the vocabulary.
            "route": route.lower().strip(),
            "reason": str(reason or ""),
        })
    return entries


def _persist_finding_dismissals(node_id: str, entries: list[dict]) -> None:
    """Records each per-finding dismissal individually, deterministically.

    Same contract as _persist_dismissal_verdict, applied per finding instead
    of per campaign: statuses are lowercase, verdicts whose reason begins
    with "Fallback:" are routed but NEVER persisted (route it, never learn
    it), persistence is best-effort (a DB hiccup must not kill the
    campaign), and the monotonic guard in the database layer -- not this
    code -- keeps dismissals from ever overwriting dynamic proof.

    Stamps address the finding ID, not the filepath. A filepath stamp lands
    on every finding at that path, which forced two guards (skip paths with
    a promoted sibling, skip paths with an unreviewed sibling) and still
    left the skipped finding `reported` -- where a later filepath-wide
    static_confirmed stamp from the reproducer would promote it right past
    the reviewer's dismissal. Addressing the row directly needs no guards:
    the stamp judges exactly the claim the reviewer judged, and the terminal
    status it sets protects the row from later promotion stamps.
    """
    dismissals = [
        e for e in entries
        if e["route"] in _DISMISSAL_ROUTES
        and not e["reason"].lstrip().startswith("Fallback:")
    ]
    if not dismissals:
        return
    try:
        from core.context import current_run_context
        rc = current_run_context.get()
        if rc is None or not rc.db_path or not rc.run_id:
            return
        from core.database import update_finding_status_by_id

        scope = getattr(rc, "target_file", None) or None
        rc_pass = int(getattr(rc, "pass_index", 1) or 1)
        promoted = getattr(rc, "promoted_finding_ids", None)
        for e in dismissals:
            if e["finding_id"] is None:
                continue
            try:
                note = f"[{node_id}] {e['reason']}" if e.get("reason") else ""
                update_finding_status_by_id(
                    rc.db_path, e["finding_id"], rc.run_id, e["route"],
                    scope_path=scope, campaign=scope,
                    pass_index=rc_pass, note=note,
                )
                if promoted is not None:
                    promoted.discard(int(e["finding_id"]))
            except Exception as exc:
                print(
                    f"[{node_id}] could not persist '{e['route']}' for finding {e['finding_id']}: {exc}",
                    file=sys.stderr,
                )
    except Exception as exc:
        print(f"[{node_id}] per-finding dismissal persistence skipped: {exc}", file=sys.stderr)


_PROMOTION_ROUTE_STATUS = {
    "confirmed": "confirmed",
    "viable": "static_confirmed",
}


def _persist_finding_promotions(
    node_id: str,
    entries: list[dict],
    route: Optional[str],
    verdict: Any,
) -> None:
    """Stamps reviewer/critic promotions deterministically and tracks the
    surviving promoted finding cohort on RunContext.promoted_finding_ids.

    Placed strictly below _persist_dismissal_verdict so first-occurrence text
    rewrites on _persist_dismissal_verdict never collide here.
    """
    try:
        from core.context import current_run_context
        rc = current_run_context.get()
        if rc is None or not rc.db_path or not rc.run_id:
            return
        from core.database import CONFIRMED_LIVE_STATUSES, read_findings, update_finding_status_by_id, update_status

        scope = getattr(rc, "target_file", None) or None
        rc_pass = int(getattr(rc, "pass_index", 1) or 1)
        prior_promoted = getattr(rc, "promoted_finding_ids", None)

        if entries:
            open_ids = set(
                _active_campaign_finding_ids(rc.db_path, rc.target_file, rc.run_id, pass_index=rc_pass)
            )
            mentioned_ids = {int(e["finding_id"]) for e in entries if e.get("finding_id") is not None}
            omitted = sorted(open_ids - mentioned_ids)
            unknown = sorted(mentioned_ids - open_ids)
            if omitted or unknown:
                print(
                    f"[{node_id}] partial finding_verdicts coverage (omitted={omitted}, out_of_scope={unknown}).",
                    file=sys.stderr,
                )

            promo_entries = [
                e for e in entries
                if e.get("finding_id") is not None
                and e.get("route") in _PROMOTION_ROUTE_STATUS
                and not str(e.get("reason") or "").lstrip().startswith("Fallback:")
            ]
            has_non_fallback_judgment = any(
                e.get("finding_id") is not None
                and not str(e.get("reason") or "").lstrip().startswith("Fallback:")
                for e in entries
            )
            is_critic_stage = "critic" in node_id or any(
                e.get("route") in ("viable", "non_viable") for e in entries
            )
            surviving: set[int] = set()
            for e in promo_entries:
                fid = int(e["finding_id"])
                if is_critic_stage and prior_promoted is not None and fid not in prior_promoted:
                    print(
                        f"[{node_id}] skipping promotion of unreviewed finding #{fid} (not in reviewer-promoted cohort).",
                        file=sys.stderr,
                    )
                    continue
                target_status = _PROMOTION_ROUTE_STATUS[e["route"]]
                note = f"[{node_id}] {e['reason']}" if e.get("reason") else ""
                try:
                    update_finding_status_by_id(
                        rc.db_path,
                        fid,
                        rc.run_id,
                        target_status,
                        scope_path=scope,
                        campaign=scope,
                        pass_index=rc_pass,
                        note=note,
                    )
                    surviving.add(fid)
                except Exception as exc:
                    print(
                        f"[{node_id}] could not persist '{target_status}' for finding {fid}: {exc}",
                        file=sys.stderr,
                    )
            if has_non_fallback_judgment:
                rc.promoted_finding_ids = surviving
            return

        # Empty finding_verdicts == INV-6 campaign-level fallback.
        if route not in _PROMOTION_ROUTE_STATUS:
            return
        reason = ""
        if isinstance(verdict, dict):
            reason = str(verdict.get("reason") or "")
        elif hasattr(verdict, "reason"):
            reason = str(getattr(verdict, "reason") or "")
        if str(reason or "").lstrip().startswith("Fallback:"):
            return
        if not rc.target_file:
            return
        target_status = _PROMOTION_ROUTE_STATUS[route]
        note = f"[{node_id}] {reason}" if reason else ""
        if prior_promoted is not None:
            if not prior_promoted:
                return
            update_status(
                rc.db_path,
                rc.target_file,
                rc.run_id,
                target_status,
                finding_ids=sorted(int(i) for i in prior_promoted),
                campaign=rc.target_file,
                pass_index=rc_pass,
                note=note,
            )
        else:
            update_status(
                rc.db_path,
                rc.target_file,
                rc.run_id,
                target_status,
                campaign=rc.target_file,
                pass_index=rc_pass,
                note=note,
            )
            rows = read_findings(
                rc.db_path,
                run_id=rc.run_id,
                scope_path=scope,
                campaign=scope,
                pass_index=rc_pass,
            )
            rc.promoted_finding_ids = {
                int(r["id"])
                for r in rows
                if r.get("id") is not None and str(r.get("status") or "").lower() in CONFIRMED_LIVE_STATUSES
            }
    except Exception as exc:
        print(f"[{node_id}] finding promotion persistence skipped: {exc}", file=sys.stderr)


def _derive_campaign_route(entries: list[dict], declared_routes: Sequence[str] = ()) -> str:
    """Aggregates per-finding verdicts into the single campaign route.

    Any promoted finding routes the campaign forward: promotion means at
    least one vulnerability still needs the downstream stages, and the
    dismissed siblings were already recorded individually by
    _persist_finding_dismissals, so nothing is lost by moving on. Only when
    EVERY entry is a dismissal does the campaign route to dismissal; the
    modal dismissal route wins (first-seen breaks ties) so a
    13-false_positive / 1-non_viable split reads as the false_positive
    campaign it substantively is.
    """
    if declared_routes:
        declared_set = {str(r).lower().strip() for r in declared_routes}
        for e in entries:
            if e["route"] in declared_set:
                return e["route"]
    for e in entries:
        if e["route"] not in _DISMISSAL_ROUTES:
            return e["route"]
    counts: dict[str, int] = {}
    order: list[str] = []
    for e in entries:
        r = e["route"]
        if r not in counts:
            order.append(r)
        counts[r] = counts.get(r, 0) + 1
    return max(order, key=lambda r: counts[r])


def _active_campaign_finding_ids(
    db_path: str,
    target_file: str,
    run_id: str,
    pass_index: Optional[int] = None,
) -> list[int]:
    """Ids of the campaign's findings that a stamp could still move."""
    from core.database import read_findings

    closed = {"false_positive", "duplicate_merged", "non_viable", "sample_or_test", "mitigated", "patch_verified"}
    try:
        rows = read_findings(
            db_path,
            run_id=run_id,
            scope_path=target_file or None,
            campaign=target_file or None,
            pass_index=pass_index,
        )
    except Exception:
        return []
    return [int(r["id"]) for r in rows
            if r.get("id") is not None and str(r.get("status") or "").lower() not in closed]


def stamp_finding_ids(rc, new_status: str) -> Optional[list[int]]:
    """Which findings a completion stamp of `new_status` may touch.

    None: the whole campaign (the coverage statuses: a reviewer that finished
    reviewed everything in scope). A list: only those ids. An empty list:
    nothing earned it.

    The dynamic statuses are earned per finding, by that finding's own PoC
    (RunContext.finding_evidence, written by run_sandbox_with_evidence). The
    stamp used to read one campaign-wide bit, `sandbox_executed`, so in a
    whole-tree run one reached sink marked every finding dynamically
    confirmed -- a reader of the report could not tell the fifteen that were
    reproduced from the one that was not. With evidence attributed to
    findings, only those are stamped. Evidence that reached a sink but named
    no finding (a PoC run without finding_id or a sentinel_<id> path) is
    attributed only when the campaign has exactly one open finding, where it
    cannot mean anything else; otherwise it stamps nothing, and the note the
    caller prints says so.
    """
    status = str(new_status or "").lower().strip()
    if status == "static_confirmed":
        promoted = getattr(rc, "promoted_finding_ids", None)
        if promoted is not None:
            return sorted(int(i) for i in promoted)
        return None
    if status not in ("dynamic_confirmed", "patch_verified"):
        return None
    evidence = dict(getattr(rc, "finding_evidence", None) or {})
    if status == "dynamic_confirmed":
        earned = [int(k) for k, v in evidence.items() if isinstance(v, dict) and v.get("reproduced")]
    else:
        earned = [int(k) for k, v in evidence.items()
                  if isinstance(v, dict) and v.get("reproduced") and v.get("reattacked")
                  and not v.get("reattack_present")]
    if earned:
        return sorted(set(earned))
    if status == "dynamic_confirmed" and getattr(rc, "sandbox_executed", False):
        rc_pass = int(getattr(rc, "pass_index", 1) or 1)
        open_ids = _active_campaign_finding_ids(rc.db_path, rc.target_file, rc.run_id, pass_index=rc_pass)
        if len(open_ids) == 1:
            return open_ids
    return []


def apply_completion_stamp(rc, new_status: str, node_id: str = "") -> Optional[list[int]]:
    """Writes a node's completion status for the campaign in `rc`, per finding
    where the status is per finding. Returns the ids stamped (None when the
    stamp was campaign-wide). Best-effort: a DB hiccup must not kill the
    campaign, so errors are reported, not raised."""
    from core.database import update_status

    status = str(new_status or "").lower().strip()
    if rc is None or not rc.db_path or not rc.run_id or not rc.target_file:
        return []
    if status in ("dynamic_confirmed", "patch_verified") and not getattr(rc, "sandbox_executed", False):
        return []
    ids = stamp_finding_ids(rc, status)
    rc_pass = int(getattr(rc, "pass_index", 1) or 1)
    pass_kw = {"pass_index": rc_pass} if rc_pass > 1 else {}
    try:
        if ids is None:
            update_status(rc.db_path, rc.target_file, rc.run_id, status, campaign=rc.target_file, **pass_kw)
        else:
            if ids:
                update_status(rc.db_path, rc.target_file, rc.run_id, status, finding_ids=ids,
                              campaign=rc.target_file, **pass_kw)
            if status in ("dynamic_confirmed", "patch_verified"):
                left = [i for i in _active_campaign_finding_ids(rc.db_path, rc.target_file, rc.run_id, pass_index=rc_pass)
                        if i not in set(ids)]
                tag = f"[{node_id}] " if node_id else ""
                shown = ", ".join(str(i) for i in ids) if ids else "none"
                print(f"{tag}{status}: finding(s) {shown} by their own reached-sink evidence; "
                      f"{len(left)} other(s) keep their earlier status"
                      + (" (evidence was not attributed to a finding: pass finding_id or a "
                         "sentinel_<finding_id> path)" if not ids else ""),
                      file=sys.stderr)
    except Exception as exc:
        print(f"[{node_id or 'stamp'}] could not stamp completion status '{status}': {exc}", file=sys.stderr)
    return ids


def _is_end_of_agent(ev: Any) -> bool:
    """ADK carries the end-of-agent marker on ``Event.actions.end_of_agent``."""
    actions = getattr(ev, "actions", None)
    return bool(getattr(actions, "end_of_agent", False) or getattr(ev, "end_of_agent", False))


def _invocation_aborted_or_dangling(callback_context: Any, node_id: str) -> bool:
    """Returns True when ADK paused/aborted the node with an error_code or unanswered FunctionCall.

    Under ResumabilityConfig (ResumeAction.PAUSE) or mid-turn model/tool aborts,
    base_agent.run_async can still enter _handle_after_agent_callback when the
    generator exits cleanly without raising. Checking negatively for explicit
    abort markers preserves normal model-less test agents and bare callback
    contexts while blocking premature coverage stamps on incomplete turns.
    """
    inv_ctx = getattr(callback_context, "_invocation_context", None)
    sess = getattr(inv_ctx, "session", None)
    if inv_ctx is None or sess is None:
        return False
    events = getattr(sess, "events", None)
    if not isinstance(events, (list, tuple)) or not events:
        return False
    inv_id = getattr(inv_ctx, "invocation_id", None)
    inv_branch = getattr(inv_ctx, "branch", None)

    def _matches_node(ev: Any) -> bool:
        if inv_id and getattr(ev, "invocation_id", None) != inv_id:
            return False
        if getattr(ev, "author", None) == node_id:
            return True
        ev_branch = str(getattr(ev, "branch", "") or "")
        if inv_branch and ev_branch == str(inv_branch):
            return True
        tail = ev_branch.split(".")[-1].split("/")[-1].split("@")[0]
        return tail == node_id

    node_events = [ev for ev in events if _matches_node(ev)]
    if not node_events:
        return False

    real_evs = [ev for ev in node_events if not _is_end_of_agent(ev)]
    if real_evs and getattr(real_evs[-1], "error_code", None):
        return True

    unanswered_fcs: set[str] = set()
    unanswered_names: list[str] = []
    for ev in real_evs:
        content = getattr(ev, "content", None)
        parts = getattr(content, "parts", None) or ()
        for part in parts:
            fc = getattr(part, "function_call", None)
            if fc is not None:
                fc_id = getattr(fc, "id", None)
                if fc_id:
                    unanswered_fcs.add(str(fc_id))
                else:
                    unanswered_names.append(str(getattr(fc, "name", "") or "call"))
            fr = getattr(part, "function_response", None)
            if fr is not None:
                fr_id = getattr(fr, "id", None)
                if fr_id and str(fr_id) in unanswered_fcs:
                    unanswered_fcs.discard(str(fr_id))
                else:
                    fr_name = str(getattr(fr, "name", "") or "call")
                    if fr_name in unanswered_names:
                        unanswered_names.remove(fr_name)
    return bool(unanswered_fcs or unanswered_names)


def _make_completion_stamp_callback(node_id: str, on_enter_status: str):
    """Builds an after-agent callback that stamps coverage on SUCCESS only.

    The stamp used to fire the moment the node's name first appeared in the
    event stream -- on entry, before the node had done any work. A campaign
    that crashed mid-node had therefore already stamped its target (e.g.
    `static_confirmed` on reproducer entry): the coverage ledger claimed the
    scan happened when it demonstrably did not finish. A crashed campaign
    must not stamp its target as covered/scanned.

    ADK's after_agent_callback runs only after the agent's _run_async_impl
    completed without raising (exceptions propagate out of run_async before
    _handle_after_agent_callback is reached), so anchoring the stamp here
    converts it from "the node was entered" to "the node actually finished".

    The two guards main.py applied at entry time are preserved verbatim:
    dynamic statuses (`dynamic_confirmed`, `patch_verified`) still require
    ctx.sandbox_executed -- a node that never reached a sandbox cannot claim
    dynamic proof, INV-1 -- and persistence stays best-effort: a DB hiccup
    must not kill the campaign. Statuses are lowercase; update_status
    enforces the vocabulary and its own monotonic terminal clauses. The
    dynamic statuses are then written per finding (apply_completion_stamp):
    only findings whose own PoC reached a sink.
    """
    new_status = str(on_enter_status).lower().strip()

    def _stamp_on_success(callback_context=None, **_kwargs):
        try:
            import asyncio
            task = asyncio.current_task()
            if task is not None and getattr(task, "cancelling", lambda: 0)() > 0:
                return None
        except Exception:
            pass
        if _invocation_aborted_or_dangling(callback_context, node_id):
            return None
        try:
            from core.context import current_run_context
            rc = current_run_context.get()
            if rc is None or not rc.db_path or not rc.run_id or not rc.target_file:
                return None
            if new_status in ("dynamic_confirmed", "patch_verified") and not rc.sandbox_executed:
                return None
            apply_completion_stamp(rc, new_status, node_id)
            if new_status == "static_confirmed" and getattr(rc, "sandbox_executed", False):
                apply_completion_stamp(rc, "dynamic_confirmed", node_id)
        except Exception as exc:
            print(
                f"[{node_id}] could not stamp completion status '{new_status}': {exc}",
                file=sys.stderr,
            )
        # None: no content override, no state delta -- the callback is a
        # pure side effect and must not alter the event stream.
        return None

    return _stamp_on_success


def _parse_verdict_value(raw: Any, routes: Sequence[str] = ()) -> Any:
    """Parses a verdict payload from dict, Pydantic model, or raw/fenced/accumulated JSON text."""
    if raw is None:
        return None
    if isinstance(raw, dict) and "route" in raw:
        return raw
    if hasattr(raw, "route") and getattr(raw, "route") is not None:
        return raw
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return None
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict) and "route" in parsed:
                return parsed
            if isinstance(parsed, str) and parsed in routes:
                return parsed
        except Exception:
            pass
        # Salvage fenced or trailing JSON object (e.g. when ADK output_key
        # accumulated intermediate tool-turn text ahead of the final raw JSON).
        decoder = json.JSONDecoder()
        last_route_dict: Optional[dict] = None
        pos = 0
        while True:
            brace = stripped.find("{", pos)
            if brace == -1:
                break
            try:
                obj, end_pos = decoder.raw_decode(stripped, brace)
                if isinstance(obj, dict) and "route" in obj:
                    last_route_dict = obj
                pos = end_pos
            except Exception:
                pos = brace + 1
        if last_route_dict is not None:
            return last_route_dict
        if stripped in routes:
            return stripped
    return None


def create_classifier(node_id: str, routes: list[str], max_visits: int = 1):

    async def _classify(ctx: Context, node_input: Any = None):
        state_key = f"{node_id}_visits"
        visits = ctx.state.get(state_key, 0) + 1

        verdict = _parse_verdict_value(node_input, routes)

        if verdict is None:
            state_verdict = ctx.state.get("verdict")
            verdict = (
                _parse_verdict_value(state_verdict, routes)
                or state_verdict
                or (node_input if isinstance(node_input, dict) else {})
            )

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

        # Per-finding verdicts (P6). A live run pushed 14 findings through ONE
        # campaign-level ReviewVerdict, so a single review opinion silently
        # covered 14 independent vulnerabilities. When the reviewer supplies
        # the optional finding_verdicts list, each finding's dismissal is
        # recorded individually and the campaign route is DERIVED from the
        # aggregate (any promotion routes forward; all-dismissed routes to the
        # modal dismissal), overriding the top-level route field -- the
        # aggregate is computed from per-finding judgments and is therefore
        # strictly better informed than the single summary route. An empty or
        # absent list is the INV-6 fail-safe: fall through to the pre-P6
        # campaign-level persistence and routing below, unchanged.
        finding_entries = _coerce_finding_verdicts(verdict)
        if finding_entries:
            _persist_finding_dismissals(node_id, finding_entries)
            _persist_finding_promotions(node_id, finding_entries, route, verdict)
            route = _derive_campaign_route(finding_entries, declared_routes=routes)
        else:
            # Persisted on the PARSED route, before any routing decision: dismissal
            # routes are deliberately undeclared in workflow.json (they fall through
            # DEFAULT_ROUTE to the calibrator), so a declared-routes-only hook would
            # never see them -- which is precisely how they went unrecorded before.
            _persist_dismissal_verdict(node_id, route, verdict)
            _persist_finding_promotions(node_id, [], route, verdict)

        state_out = {state_key: visits, "verdict": None}

        if max_visits and max_visits > 1 and visits >= max_visits:
            return adk.Event(output=node_input, state=state_out, route="exceeded")

        if route == "success" and "success" in routes and "repro" in node_id:
            try:
                from core.context import current_run_context

                rc_gate = current_run_context.get()
                if rc_gate is not None and getattr(rc_gate, "sandbox", None) is not None:
                    ev_map = getattr(rc_gate, "finding_evidence", None) or {}
                    has_ev = (
                        any(isinstance(v, dict) and v.get("reproduced") for v in ev_map.values())
                        if ev_map
                        else True
                    )
                    if not getattr(rc_gate, "sandbox_executed", False) or not has_ev:
                        print(
                            f"[INV-1 GUARD] {node_id}: downgrading unverified 'success' verdict "
                            f"(sandbox_executed={getattr(rc_gate, 'sandbox_executed', False)}) to fallback.",
                            file=sys.stderr,
                        )
                        route = DEFAULT_ROUTE
            except Exception:
                pass

        if route and route in routes:
            return adk.Event(output=node_input, state=state_out, route=route)

        if route and route != DEFAULT_ROUTE and route not in ("false_positive", "non_viable", "failed_repro", "not_attempted"):
            print(f"[{node_id}] verdict '{route}' not in declared routes {routes}; routing to fallback")

        return adk.Event(output=node_input, state=state_out, route=DEFAULT_ROUTE)

    return node(_classify, name=node_id)


def campaign_has_findings_to_triage(
    db_path: str, run_id: str, target_file: str, pass_index: Optional[int] = None
):
    """True if the current campaign recorded any finding still worth triaging.

    Returns None when the question cannot be answered (missing or unreadable
    database). Callers must treat None as "run the full pipeline": an error
    may never skip stages.
    """
    from core.database import read_findings, FALSE_POSITIVE_STATUSES
    from core.paths import resolve_db_path

    if not db_path:
        return None
    try:
        resolved_db = resolve_db_path(db_path) if not os.path.isabs(str(db_path)) else db_path
    except Exception:
        resolved_db = db_path
    if not os.path.exists(resolved_db):
        return None
    eff_pass = pass_index
    if eff_pass is None:
        try:
            from core.context import current_run_context

            rc = current_run_context.get()
            if rc is not None:
                eff_pass = max(1, int(getattr(rc, "pass_index", 1) or 1))
        except Exception:
            eff_pass = None
    try:
        rows = read_findings(
            resolved_db,
            run_id=run_id,
            scope_path=target_file or None,
            campaign=target_file or None,
            pass_index=eff_pass,
        )
    except Exception:
        return None
    inactive = set(FALSE_POSITIVE_STATUSES) | {"duplicate_merged"}
    return any(str(r.get("status") or "").lower() not in inactive for r in rows)


# Repo-scope prefix stages that may reuse their own completed artifacts across
# campaigns of one run, mapped to the artifact type that proves completion.
_PREFIX_REUSE_ARTIFACTS = {
    "architect": "summary",
    "threat_modeler": "threat_model",
}
# Where the recording tools put each of those artifacts (tools/research_tools:
# record_summary, record_threat_model); a reused one is recorded there again
# under the reusing campaign.
_PREFIX_REUSE_PATHS = {
    "summary": "workspace/.structured/summary.json",
    "threat_model": "workspace/.structured/threat_model.json",
}

# main.py owns the scan-mode vocabulary; the literals are mirrored here because
# importing main from this module would be circular. A test pins them equal.
_SCAN_MODE_CROSS_FUNCTIONAL = "cross-functional"
_SCAN_MODE_CHANGED = "changed"

# Shared Harness²-inspired tool-loop guard constants and helpers (c8).
ABORT_GUARD_MIN_TOOL_CALLS = 8
ABORT_GUARD_PROMPT = (
    "Your previous reply ended the run without doing the audit: no findings "
    "were reported and no tools were called. Do not answer with prose only. "
    "Tool calls must go through the function-calling interface -- writing "
    "one out as text, like 'call:api:read_file{...}', does nothing. "
    "Resume now: call list_files('app'), read the source, and report every "
    "confirmed vulnerability via report_findings before you finish."
)
PSEUDO_TOOL_CALL_RE = re.compile(
    r"(?:\bcall:\w+:\w+\s*\{|<tool_call>|<function=|<minimax:tool_call|```tool_call)",
    re.IGNORECASE,
)
READ_FILE_REPEAT_THRESHOLD = 3


def count_event_tool_calls(event: Any) -> int:
    """Function calls carried by one ADK event. A streamed turn yields the
    same call again as partial chunks before the final event; only the
    final event counts. Never raises."""
    try:
        if getattr(event, "partial", False):
            return 0
        parts = getattr(getattr(event, "content", None), "parts", None) or []
        return sum(1 for part in parts if getattr(part, "function_call", None))
    except Exception:
        return 0


def event_has_pseudo_tool_call(event: Any) -> bool:
    """True when a text part spells out a tool call instead of making one.
    Judged on final events only: a partial chunk is a fragment. Never raises."""
    try:
        if getattr(event, "partial", False):
            return False
        parts = getattr(getattr(event, "content", None), "parts", None) or []
        if any(
            PSEUDO_TOOL_CALL_RE.search(getattr(part, "text", None) or "")
            for part in parts
        ):
            return True
        output = getattr(event, "output", None)
        return bool(isinstance(output, str) and PSEUDO_TOOL_CALL_RE.search(output))
    except Exception:
        return False


def should_rearm_run(
    findings_count: int,
    tool_calls: int,
    rearms_used: int = 0,
    pseudo_tool_call: bool = False,
) -> bool:
    """True only for the first run that ends with nothing reported and
    nearly nothing attempted -- or that ended on a tool call written as
    text, which no tool-count threshold can tell from a deliberate stop."""
    return (
        rearms_used == 0
        and findings_count == 0
        and (tool_calls < ABORT_GUARD_MIN_TOOL_CALLS or pseudo_tool_call)
    )


def compute_prefix_fingerprint(
    node_id: str,
    instruction: str = "",
    tools: Sequence[str] = (),
    model: str = "",
    snapshot_id: str = "",
) -> str:
    """Computes a content-addressed fingerprint (Harness² runmark) for a stage."""
    payload = json.dumps(
        {
            "instruction": instruction,
            "model": model,
            "node_id": node_id,
            "snapshot_id": snapshot_id,
            "tools": sorted(str(t) for t in tools),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _instruction_digest(instruction: str) -> str:
    """sha256 of an instruction with its whitespace collapsed.

    Re-wrapping a prompt, fixing its indentation, or a trailing newline does
    not change what the model is told; a fingerprint that flipped on those
    would mark every covered slice stale on each cosmetic edit, and the
    operator would learn to ignore it.
    """
    collapsed = " ".join(str(instruction or "").split())
    return hashlib.sha256(collapsed.encode("utf-8")).hexdigest()


def compute_harness_fingerprint(
    nodes: Sequence[dict],
    default_model: str = "",
    sandbox: str = "",
) -> str:
    """Content-addressed identity of a resolved harness configuration.

    The coverage ledger records that a slice was examined; this says by WHAT.
    After an upgrade -- a tool added to a node, a stronger model, a rewritten
    stage prompt, a different sandbox tier -- a slice covered under the old
    configuration was never seen by the new one, and without this stamp
    `--resume` and `auto` treat it as done forever. Stamped on every
    campaign_spend row (cost.record_spend) and compared on reuse
    (cost.uncovered_files, cost.run_ledger).

    `nodes` is one dict per graph node: `id`, and for agent nodes `tools`
    (names), `model` (resolved id) and `instruction` (final text, after the
    loader's appended guard and output contract). Order never matters: nodes
    sort by id and tools by name. Instructions enter as a whitespace-collapsed
    digest (see _instruction_digest), so cosmetic prompt edits do not change
    the result and the payload never holds prompt text.

    Deliberately NOT in the hash: edges, budgets, timeouts, retry counts,
    reasoning effort, API bases and exclusions. Those tune how much a run
    does, not what the harness is capable of finding; folding them in would
    make every budget tweak look like an upgrade. 16 hex characters, like
    compute_prefix_fingerprint.
    """
    normalized = []
    for raw in nodes or []:
        if not isinstance(raw, dict) or not raw.get("id"):
            continue
        entry = {
            "id": str(raw["id"]),
            "instruction": _instruction_digest(raw.get("instruction") or ""),
            "model": str(raw.get("model") or ""),
            "tools": sorted(str(t) for t in (raw.get("tools") or [])),
        }
        # A fork changes what the stage sees, so it is part of what the
        # harness can find; only present when set, so graphs without one
        # keep the fingerprint they had.
        if raw.get("fork_from"):
            entry["fork_from"] = str(raw["fork_from"])
        if raw.get("prefix_group"):
            entry["prefix_group"] = str(raw["prefix_group"])
        if raw.get("skip_when_static"):
            entry["skip_when_static"] = True
        normalized.append(entry)
    normalized.sort(key=lambda n: n["id"])
    payload = json.dumps(
        {
            "default_model": str(default_model or ""),
            "nodes": normalized,
            "sandbox": str(sandbox or ""),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _make_on_tool_error_callback(node_id: str):
    """Converts unhandled tool runtime exceptions into structured FunctionResponse dicts.

    Control-plane exceptions (BudgetExceededError, MantisAuthError,
    NodeContextExhausted, asyncio.CancelledError) always re-raise untouched so
    budget enforcement, auth fail-fast, node ceiling handoffs, and task
    cancellation are never swallowed.
    """

    def _on_tool_error(
        tool: Any = None,
        args: Optional[dict[str, Any]] = None,
        tool_context: Any = None,
        error: Optional[Exception] = None,
        **kwargs: Any,
    ) -> Optional[dict[str, Any]]:
        import asyncio
        from core.budget import BudgetExceededError
        from core.config import MantisAuthError
        from core.llm_gateway import sanitize_egress_text

        err = error if error is not None else kwargs.get("error")
        if isinstance(
            err,
            (BudgetExceededError, MantisAuthError, NodeContextExhausted, asyncio.CancelledError),
        ):
            raise err
        tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", None) or "tool"
        raw_msg = str(err) if err is not None else "unknown tool error"
        clean_msg = sanitize_egress_text(raw_msg)[:500]
        err_type = type(err).__name__ if err is not None else "Error"
        print(
            f"[{node_id}] Tool '{tool_name}' raised {err_type}: {clean_msg}",
            file=sys.stderr,
        )
        return {"error": f"Tool '{tool_name}' failed ({err_type}): {clean_msg}"}

    return _on_tool_error


class LiteralInstruction:
    """An ADK ``InstructionProvider`` that returns fixed text.

    ADK renders a *string* instruction as a template: ``{name}`` is a
    session-state lookup, ``{artifact.x}`` an artifact load, and a key that
    does not exist raises ``KeyError`` when the stage first runs. A callable
    instruction is used verbatim (``canonical_instruction`` returns it with
    ``bypass_state_injection=True``). Mantis node prompts are literal: they
    quote code, and code has braces. This object is that callable, and reads
    like the string it carries so callers that inspect an agent's prompt
    (tests, the synthesizer's audit) keep working.
    """

    __slots__ = ("text",)

    def __init__(self, text: str):
        self.text = str(text or "")

    def __call__(self, _ctx: Any = None) -> str:
        return self.text

    def __str__(self) -> str:
        return self.text

    def __repr__(self) -> str:
        return f"LiteralInstruction({self.text[:60]!r}...)" if len(self.text) > 60 else f"LiteralInstruction({self.text!r})"

    def __contains__(self, item: object) -> bool:
        return str(item) in self.text

    def __len__(self) -> int:
        return len(self.text)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, LiteralInstruction):
            return self.text == other.text
        if isinstance(other, str):
            return self.text == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.text)

    def startswith(self, *args: Any) -> bool:
        return self.text.startswith(*args)

    def endswith(self, *args: Any) -> bool:
        return self.text.endswith(*args)


def _literal_instruction(text: str) -> LiteralInstruction:
    return text if isinstance(text, LiteralInstruction) else LiteralInstruction(text)


def _make_after_tool_guard_callback(node_id: str, tool_names: Sequence[str] = (), model: Any = None):
    """Bounds every tool response to the node's model, then steers repeat whole-file reads.

    The bound: one tool response may occupy at most
    ``core.config.TOOL_RESPONSE_WINDOW_FRACTION`` of the model's input window
    (``resolve_tool_response_char_cap``). Per-tool byte limits are sized for
    the largest windows; a 1 MiB read or a run-long recorded summary that fits
    a million-token model is 1.1x a 272k window on its own, and the request
    guard then refuses the whole turn. The cut keeps the untrusted-content
    fence closed and puts the marker after it (``bound_fenced_text``).
    """
    has_structural_nav = (
        "get_function_boundary" in tool_names or "find_symbol" in tool_names
    )
    local_counts: dict[str, int] = {}
    cap_cache: dict[str, Optional[int]] = {}

    def _cap() -> Optional[int]:
        if "cap" not in cap_cache:
            try:
                from core.config import resolve_tool_response_char_cap
                cap_cache["cap"] = resolve_tool_response_char_cap(model) if model else None
            except Exception:
                cap_cache["cap"] = None
        return cap_cache["cap"]

    def _bounded(tool_name: str, tool_response: Any) -> tuple[Any, bool]:
        cap = _cap()
        if not cap:
            return tool_response, False
        # The headroom the stage has left decides the cap for THIS result:
        # never more than the static per-response cap, never less than the
        # floor, and within the reserve only what still fits. Cutting a
        # result before it is appended edits nothing already sent, so the
        # prefix under any retained reasoning stays intact.
        room = node_context_headroom(node_id)
        notice = ""
        if room is not None:
            headroom, reserve = room
            from core.config import MIN_TOOL_RESPONSE_CHARS
            fits = max(0, headroom - reserve) * NODE_CONTEXT_CHARS_PER_TOKEN
            cap = max(MIN_TOOL_RESPONSE_CHARS, min(cap, fits))
            if headroom <= reserve:
                notice = (
                    f"\n\n[CONTEXT NOTICE] About {headroom:,} tokens of this stage's working "
                    "context remain. Record your results through tools and give your final "
                    "answer now; further tool output will be cut to fit."
                )
        from core.truncation import bound_fenced_text
        what = f"{tool_name} output" if tool_name else "tool output"
        if isinstance(tool_response, str):
            cut = len(tool_response) > cap
            if cut:
                _observe("tool_result_cuts")
            text = bound_fenced_text(tool_response, cap, what) if cut else tool_response
            return (text + notice, True) if (cut or notice) else (tool_response, False)
        if isinstance(tool_response, dict):
            if isinstance(tool_response.get("result"), str):
                cut = len(tool_response["result"]) > cap
                if not cut and not notice:
                    return tool_response, False
                if cut:
                    _observe("tool_result_cuts")
                updated = dict(tool_response)
                text = bound_fenced_text(tool_response["result"], cap, what) if cut else tool_response["result"]
                updated["result"] = text + notice
                return updated, True
            if isinstance(tool_response.get("output"), str) or isinstance(tool_response.get("raw"), str):
                updated = dict(tool_response)
                cut = False
                for key in ("output", "raw"):
                    val = updated.get(key)
                    if isinstance(val, str) and len(val) > cap:
                        updated[key] = bound_fenced_text(val, cap, what)
                        cut = True
                if cut:
                    _observe("tool_result_cuts")
                if notice:
                    updated["context_notice"] = notice.strip()
                return (updated, True) if (cut or notice) else (tool_response, False)
            if notice:
                updated = dict(tool_response)
                updated["context_notice"] = notice.strip()
                return updated, True
        return tool_response, False

    def _after_tool(
        tool: Any,
        args: dict[str, Any],
        tool_context: Any,
        tool_response: Any,
    ) -> Any:
        import asyncio
        from core.budget import BudgetExceededError
        from core.config import MantisAuthError

        try:
            tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "")
            tool_response, changed = _bounded(str(tool_name or ""), tool_response)
            if changed and "[CONTEXT NOTICE]" not in str(tool_response):
                print(
                    f"[{node_id}] {tool_name} response exceeded the per-response cap for this "
                    f"model ({_cap():,} chars); cut with a marker.",
                    file=sys.stderr, flush=True,
                )
            steered = _steer(tool_name, args, tool_response)
            if steered is not None:
                return steered
            return tool_response if changed else None
        except (BudgetExceededError, MantisAuthError, NodeContextExhausted, asyncio.CancelledError):
            raise
        except Exception as exc:
            print(f"[{node_id}] after_tool_callback ignored error: {exc}", file=sys.stderr)
            return None

    def _steer(tool_name: Any, args: Any, tool_response: Any) -> Any:
        if not has_structural_nav:
            return None
        if tool_name != "read_file" or not isinstance(args, dict):
            return None
        # read_file's bounds default to 0 (= whole file) and models routinely
        # echo declared defaults, so `start_line=0, end_line=0` is an
        # un-windowed read too. Only a positive bound counts as windowed.
        if args.get("start_line") or args.get("end_line"):
            return None
        filepath = str(args.get("filepath") or args.get("path") or "").strip()
        if not filepath:
            return None

        counts = local_counts
        try:
            from core.context import current_run_context

            ctx = current_run_context.get()
            if ctx is not None and isinstance(getattr(ctx, "read_file_counts", None), dict):
                counts = ctx.read_file_counts
        except Exception:
            pass

        key = f"{node_id}:{filepath}"
        counts[key] = counts.get(key, 0) + 1
        if counts[key] < READ_FILE_REPEAT_THRESHOLD:
            return None

        # The suggested calls must match the real tool signatures
        # (tools/structural_tools.py): get_function_boundary(filepath, line)
        # and find_symbol(name). A hint that names a parameter the tool does
        # not have sends an already-stuck model into a validation error.
        hint = (
            f"[HARNESS STEERING HINT: You have read '{filepath}' {counts[key]} times "
            f"without line bounds in stage '{node_id}'. Prefer "
            f"find_symbol(name='<function or class>') to locate a definition, "
            f"get_function_boundary(filepath='{filepath}', line=<line number>) to get "
            f"the enclosing function's exact span, or pass start_line/end_line to "
            f"read_file.]"
        )
        if isinstance(tool_response, str):
            return f"{tool_response}\n\n{hint}"
        if isinstance(tool_response, dict) and isinstance(tool_response.get("result"), str):
            updated = dict(tool_response)
            updated["result"] = f"{tool_response['result']}\n\n{hint}"
            return updated
        return None

    return _after_tool


def prefix_reuse_applies(scan_mode: str, jail_dir: str, path_root: str, target: str) -> bool:
    """Whether a campaign may share the repo-scope prefix stages' work with
    the other campaigns of its run.

    Cross-functional campaigns share the repository jail by construction. A
    `changed` campaign shares it when the jail is the repository root (the
    caller's --path-root, or the target itself when none is given) and the
    campaign is a directory: a single-file campaign reads its one file
    only, so it neither produces a repo-wide summary nor consumes one.
    Every other mode keeps per-campaign prefixes.
    """
    if scan_mode == _SCAN_MODE_CROSS_FUNCTIONAL:
        return True
    if scan_mode != _SCAN_MODE_CHANGED or not jail_dir or not target:
        return False
    jail = os.path.realpath(str(jail_dir))
    return jail == os.path.realpath(str(path_root or jail_dir)) and os.path.isdir(str(target))


def _artifact_says_something(content: Any) -> bool:
    """A prefix artifact that can stand for a finished stage: not blank, and
    not a record whose every field is empty (an empty summary is stored as
    {"overview": "", "key_modules": [], "tech_stack": []})."""
    text = str(content or "").strip()
    if not text:
        return False
    try:
        parsed = json.loads(text)
    except ValueError:
        return True

    def empty(v) -> bool:
        if isinstance(v, str):
            return not v.strip()
        if isinstance(v, (list, dict)):
            return all(empty(i) for i in (v.values() if isinstance(v, dict) else v))
        return v is None

    return not empty(parsed)


def _enclosing_subrepo_key(jail_dir: str, target_file: str) -> str:
    """When `jail_dir` is a multi-repository parent directory and `target_file`
    sits inside a nested git checkout (`<jail>/<repo>/.git`), returns the real
    path of that nested checkout so Repo A's summary/threat_model is never
    reused for Repo B. Returns '' when `target_file` shares the root checkout."""
    if not jail_dir or not target_file:
        return ""
    try:
        jail_real = os.path.realpath(str(jail_dir)).rstrip("/")
        cur = os.path.realpath(str(target_file)).rstrip("/")
        if os.path.isfile(cur):
            cur = os.path.dirname(cur)
        while cur and cur != jail_real and cur.startswith(jail_real + os.sep):
            if os.path.exists(os.path.join(cur, ".git")):
                return cur
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
    except OSError:
        return ""
    return ""


def _make_prefix_reuse_callbacks(node_id: str):
    """Before/after callbacks that let a repo-scope prefix stage reuse itself.

    Where campaigns share the repository jail (prefix_reuse_applies:
    cross-functional runs, and changed runs over the repository root), the
    architect / threat modeler re-derive the same repo-wide summary and
    threat model on every campaign. The before-callback returns reuse text
    -- which the runtime treats as the agent's output, skipping the LLM
    call -- only when ALL of:

      * the campaign shares the jail (prefix_reuse_applies). Per-campaign
        jails make reuse wrong, so file-by-file, single-file and unknown
        campaigns always re-run;
      * this process already ran the stage to completion for this run_id,
        in a campaign that shares the jail. Process-local on purpose: a
        resumed run re-derives against the resynced checkout instead of
        trusting a pre-restart artifact;
      * that campaign's artifact row exists and says something: an empty
        summary is not a finished architect.

    The reused artifact is then recorded again under this campaign. Each
    campaign's tools read their own campaign's rows (get_summary,
    get_threat_model), so without the copy a reusing campaign saw NO_DATA
    where the stage it skipped would have left its output.

    Everything else -- missing context, missing or empty artifact, any
    exception -- falls through to running the stage, which is the behavior
    that shipped (INV-6). What reuse costs is the per-campaign briefing
    nuance these stages would otherwise see; what it buys is their LLM
    spend on every campaign after the first.
    """
    # run_id -> the campaign (target) whose completed stage is reused.
    import asyncio

    completed_runs: dict[str, str] = {}
    local_inflight: dict[str, asyncio.Event] = {}

    def _runs_map(ctx) -> dict[str, str]:
        shared = getattr(ctx, "shared_prefix_runs", None)
        if isinstance(shared, dict):
            return shared.setdefault(node_id, {})
        return completed_runs

    def _inflight_map(ctx) -> dict[str, asyncio.Event]:
        shared = getattr(ctx, "shared_prefix_runs", None)
        if isinstance(shared, dict):
            inflight_root = shared.setdefault("_inflight", {})
            if isinstance(inflight_root, dict):
                return inflight_root.setdefault(node_id, {})
        return local_inflight

    def _run_key(ctx) -> str:
        pass_idx = max(1, int(getattr(ctx, "pass_index", 1) or 1))
        base = f"{ctx.run_id}::pass{pass_idx}" if pass_idx > 1 else str(ctx.run_id)
        subrepo = _enclosing_subrepo_key(
            getattr(ctx, "jail_dir", ""), getattr(ctx, "target_file", "")
        )
        return f"{base}::{subrepo}" if subrepo else base

    def _shares_jail(ctx) -> bool:
        return prefix_reuse_applies(getattr(ctx, "scan_mode", ""), getattr(ctx, "jail_dir", ""),
                                    getattr(ctx, "path_root", ""), getattr(ctx, "target_file", ""))

    def _try_reuse(ctx, runs_map: dict[str, str], rkey: str):
        try:
            if rkey not in runs_map:
                return None
            from core.database import read_artifact, record_artifact
            from core.paths import resolve_db_path

            db = resolve_db_path(ctx.db_path)
            kind = _PREFIX_REUSE_ARTIFACTS[node_id]
            producer = runs_map[rkey]
            artifact = read_artifact(db, artifact_type=kind, run_id=ctx.run_id, resource=producer)
            if not _artifact_says_something(artifact):
                return None
            own = str(getattr(ctx, "artifact_resource", "") or getattr(ctx, "target_file", "") or "")
            if own != producer:
                record_artifact(db, ctx.run_id, kind, _PREFIX_REUSE_PATHS[kind], artifact,
                                metadata={"resource": own, "snapshot_id": getattr(ctx, "snapshot_id", ""),
                                          "reused_from": producer})
            return types.Content(
                role="model",
                parts=[types.Part(text=(
                    f"[{node_id}] Reused the {kind} "
                    f"artifact recorded by an earlier campaign of this run: "
                    f"the campaigns share the repository jail, so "
                    f"this stage's repo-wide input is unchanged. No new "
                    f"analysis was performed.{' It is recorded for this campaign too.' if own != producer else ''}"
                ))],
            )
        except Exception:
            return None

    def _claim_inflight_event(inflight: dict[str, asyncio.Event], rkey: str) -> None:
        ev = asyncio.Event()
        inflight[rkey] = ev
        try:
            owner_task = asyncio.current_task()
        except RuntimeError:
            owner_task = None
        # Remember who produces: a node-level retry of the producing stage
        # runs in the SAME task and must not wait on its own claim.
        ev._mantis_owner = owner_task  # type: ignore[attr-defined]
        if owner_task is not None:
            def _release_on_task_done(_t, _inf=inflight, _rk=rkey, _ev=ev) -> None:
                if _inf.get(_rk) is _ev:
                    _inf.pop(_rk, None)
                _ev.set()

            owner_task.add_done_callback(_release_on_task_done)

    def _before(callback_context=None):
        try:
            from core.context import current_run_context

            ctx = current_run_context.get()
            if ctx is None or not ctx.run_id or not ctx.db_path:
                return None
            if not _shares_jail(ctx):
                return None
            runs_map = _runs_map(ctx)
            rkey = _run_key(ctx)
            reused = _try_reuse(ctx, runs_map, rkey)
            if reused is not None:
                return reused
            try:
                asyncio.get_running_loop()
                has_loop = True
            except RuntimeError:
                has_loop = False
            if not has_loop or (
                int(getattr(ctx, "parallel_workers", 1) or 1) <= 1
                and not isinstance(getattr(ctx, "shared_prefix_runs", None), dict)
            ):
                return None
            inflight = _inflight_map(ctx)
            ev = inflight.get(rkey)
            if ev is None:
                _claim_inflight_event(inflight, rkey)
                return None
            owner = getattr(ev, "_mantis_owner", None)
            if owner is not None and owner is asyncio.current_task():
                # A retry of the producing attempt (ADK node retry re-enters
                # the callback in the same task): keep the claim and run.
                return None

            async def _await_producer():
                wait_ev = ev
                try:
                    while wait_ev is not None:
                        await wait_ev.wait()
                        got = _try_reuse(ctx, runs_map, rkey)
                        if got is not None:
                            return got
                        wait_ev = inflight.get(rkey)
                        if wait_ev is None:
                            runs_map.pop(rkey, None)
                            _claim_inflight_event(inflight, rkey)
                            return None
                    return None
                except Exception:
                    return None

            return _await_producer()
        except Exception:
            return None

    def _after(callback_context=None):
        # The runtime fires this only when the stage completed without
        # raising; the artifact row is still verified at reuse time.
        try:
            from core.context import current_run_context

            ctx = current_run_context.get()
            if ctx and ctx.run_id and _shares_jail(ctx):
                own_res = str(getattr(ctx, "artifact_resource", "") or getattr(ctx, "target_file", "") or "")
                rkey = _run_key(ctx)
                try:
                    cur_task = asyncio.current_task()
                except RuntimeError:
                    cur_task = None
                cancelling = bool(
                    cur_task is not None
                    and hasattr(cur_task, "cancelling")
                    and cur_task.cancelling() > 0
                )
                if not cancelling:
                    rmap = _runs_map(ctx)
                    if rkey not in rmap:
                        rmap[rkey] = own_res
                    elif rmap[rkey] != own_res and ctx.db_path:
                        from core.database import read_artifact
                        from core.paths import resolve_db_path

                        db = resolve_db_path(ctx.db_path)
                        kind = _PREFIX_REUSE_ARTIFACTS[node_id]
                        prev_art = read_artifact(
                            db, artifact_type=kind, run_id=ctx.run_id, resource=rmap[rkey]
                        )
                        if not _artifact_says_something(prev_art):
                            own_art = read_artifact(
                                db, artifact_type=kind, run_id=ctx.run_id, resource=own_res
                            )
                            if _artifact_says_something(own_art):
                                rmap[rkey] = own_res
                ev = _inflight_map(ctx).pop(rkey, None)
                if ev is not None:
                    ev.set()
        except Exception:
            pass
        return None

    return _before, _after


def bound_appended_instruction(
    block: str, cap: int = MAX_APPENDED_INSTRUCTION_CHARS
) -> tuple[str, int]:
    """Bounds a stage-experience block to `cap` characters without breaking its fence.

    Returns `(bounded, omitted)`; `omitted` is 0 and `bounded is block` when
    nothing had to go. Otherwise whole lesson lines are dropped from the
    BOTTOM of the CP-4 fenced body -- render_stage_learnings_for_agent emits
    them best-ranked first, so the bottom is the least-evidenced, oldest
    lesson -- the closing delimiter is kept so the fence never stays open
    over whatever instruction follows, and a trailing marker line states how
    many characters were cut. The marker sits OUTSIDE the fence: it is
    harness text about the block, not prior-run prose.

    The result is never longer than `cap`, including the marker.
    """
    if len(block) <= cap:
        return block, 0

    from core.llm_gateway import UNTRUSTED_DATA_END, UNTRUSTED_DATA_START

    # Reserve the marker's room at its widest: the omitted count can never
    # exceed the block's own length.
    budget = max(0, cap - 1 - len(_APPENDED_TRUNCATION_MARKER.format(omitted=len(block))))

    def _whole_lines(candidates: list[str]) -> str:
        kept_text = ""
        for line in candidates:
            trial = f"{kept_text}\n{line}" if kept_text else line
            if len(trial) > budget:
                break
            kept_text = trial
        return kept_text

    lines = block.split("\n")
    open_i = next((i for i, line in enumerate(lines) if line.startswith(UNTRUSTED_DATA_START)), -1)
    close_i = next(
        (i for i in range(len(lines) - 1, -1, -1) if lines[i].startswith(UNTRUSTED_DATA_END)),
        -1,
    )
    if open_i != -1 and close_i > open_i:
        head, tail = lines[: open_i + 1], lines[close_i:]
        body: list[str] = []
        for line in lines[open_i + 1 : close_i]:
            if len("\n".join(head + body + [line] + tail)) > budget:
                break
            body.append(line)
        kept = "\n".join(head + body + tail)
        if len(kept) > budget:
            # Not even an empty fence fits (a cap far below the module
            # constant). Keep whatever header fits and no fence at all, so no
            # delimiter is ever left half-written or unmatched.
            kept = _whole_lines(lines[:open_i])
    else:
        # Not fenced (nothing renders such a block today; defensive). Cut at a
        # line boundary so no lesson is left half-said.
        kept = _whole_lines(lines)

    omitted = len(block) - len(kept)
    return f"{kept}\n{_APPENDED_TRUNCATION_MARKER.format(omitted=omitted)}", omitted


def _render_stage_experience_block(
    node_id: str,
    cached_blocks: dict[tuple[str, str, str], str],
    truncation_state: list[bool],
) -> str:
    """Renders and caches the bounded `[STAGE EXPERIENCE]` block for `node_id`."""
    stage_key = "researcher" if node_id.startswith("researcher") else node_id
    from core.context import current_run_context
    from core.paths import resolve_db_path

    ctx = current_run_context.get()
    if ctx is None or not ctx.db_path:
        return ""
    if not bool(getattr(ctx, "enable_memory", True)):
        return ""
    if int(getattr(ctx, "pass_index", 1) or 1) > 1:
        return ""
    resolved_db = resolve_db_path(ctx.db_path)
    if not os.path.exists(resolved_db):
        return ""
    target_file = str(getattr(ctx, "target_file", "") or "")
    cache_key = (
        resolved_db,
        str(getattr(ctx, "run_id", "") or ""),
        target_file,
    )
    if cache_key not in cached_blocks:
        from core.memory import render_stage_learnings_for_agent

        rendered = render_stage_learnings_for_agent(
            resolved_db,
            stage_key,
            target=target_file,
        )
        bounded, omitted = bound_appended_instruction(rendered)
        if omitted and not truncation_state[0]:
            truncation_state[0] = True
            print(
                f"[{node_id}] stage experience for '{stage_key}' rendered to "
                f"{len(rendered)} chars; appended {len(bounded)} "
                f"(cap {MAX_APPENDED_INSTRUCTION_CHARS}), {omitted} omitted. "
                f"The block carries a truncation marker.",
                file=sys.stderr,
            )
        cached_blocks[cache_key] = bounded
    return str(cached_blocks.get(cache_key) or "")


def _stamp_active_node(node_id: str) -> Any:
    """Stamps `RunContext.active_node = node_id` at stage entry/turn-1 before events stream."""
    try:
        from core.context import current_run_context

        ctx = current_run_context.get()
        if ctx is not None:
            ctx.active_node = node_id
        return ctx
    except Exception:
        return None


def _make_stage_experience_before_model_callback(node_id: str):
    """Injects stage-targeted <experience> lessons into the agent's LlmRequest.

    The block is rendered once per campaign (cached by database, run and
    target) and bounded to MAX_APPENDED_INSTRUCTION_CHARS before it is
    appended; a cut is reported once per node on stderr and always in the
    block itself, so an operator reading the prompt can see memory was
    shortened rather than wonder why a lesson is missing.
    """
    cached_blocks: dict[tuple[str, str, str], str] = {}
    truncation_state = [False]

    def _before_model(callback_context: Any = None, llm_request: Any = None) -> None:
        _stamp_active_node(node_id)
        try:
            if llm_request is None:
                return None
            sys_inst = str(
                getattr(getattr(llm_request, "config", None), "system_instruction", "") or ""
            )
            if "[STAGE EXPERIENCE" in sys_inst:
                return None
            block = _render_stage_experience_block(node_id, cached_blocks, truncation_state)
            if not block:
                return None
            if hasattr(llm_request, "append_instructions"):
                llm_request.append_instructions([block])
        except Exception:
            pass
        return None

    return _before_model


# Share of the model's input window a node's own context may reach before
# the stage is restarted or ended. Below the pre-dispatch refusal
# (core.config, 0.9) so the stage ends in order -- its findings, notes and
# evidence already recorded -- instead of the campaign aborting on a
# request that cannot fit. Above the tool-response cap (0.25 per response)
# so ordinary stages never see it.
NODE_CONTEXT_CEILING_RATIO = 0.8

# Share of the window kept in hand below the ceiling. Once a stage's
# headroom is inside this reserve, every tool result it receives carries a
# notice to record its work and finish, and each new result is cut to what
# still fits.
NODE_CONTEXT_RESERVE_RATIO = 0.08

# Characters per token for the ceiling estimate. Denser than the fail-open
# constant the request guard uses (4): the payloads that fill a context are
# tool responses -- code and JSON -- and recorded findings measured 2.2
# chars/token. A conservative estimate ends a stage a little early; a
# generous one lets it reach the refusal.
NODE_CONTEXT_CHARS_PER_TOKEN = 3

# How many times a stage may continue in a fresh context before it is ended.
# A continuation is ADK's own node retry, admitted for NodeContextExhausted
# alone (core.config's retry predicate) and counted here rather than by
# RetryConfig: the retried attempt gets a new anchor and the previous
# attempt's events leave the prompt -- append-only by construction, which
# models that bind reasoning to its prefix require -- and it starts from the
# handoff the previous attempt wrote. Stages with an output schema cannot be
# ended with a synthetic text (the schema check would fail the node), so at
# the cap they raise once more, non-retryably, and the campaign is recorded
# failed; a schema-less stage ends with its recorded work in place.
MAX_NODE_CONTINUATIONS = 6

# Characters of a handoff carried into the next attempt's instruction.
MAX_HANDOFF_CHARS = 12000

NODE_CONTEXT_CEILING_TEXT = (
    "[CONTEXT CEILING] This stage's working context has reached the model's "
    "window. The stage ends here; everything it recorded through tools stands, "
    "and the next stage reads it from the store."
)

# What the stage is asked for when its context is full: the note its next
# attempt starts from. Written by the model that did the work, with the
# whole context in front of it, as the last call of the attempt.
NODE_CONTEXT_HANDOFF_PROMPT = (
    "CONTEXT HANDOFF. Your working context has reached its limit. This stage "
    "continues in a fresh context that will contain only your instructions, "
    "your tools and the handoff you write now. Write it for yourself:\n"
    "1. The stage objective and the target.\n"
    "2. What you have established, each item with where it is recorded "
    "(finding ids, workspace files, file paths and line ranges, symbols).\n"
    "3. What you ruled out, and the evidence.\n"
    "4. Open hypotheses and the exact next steps, in priority order.\n"
    "5. Anything in progress (a sandbox command, a patch, a PoC) and its last "
    "result.\n"
    "Be specific and compact: paths, identifiers, numbers. Plain text. Do not "
    "call tools."
)

NODE_CONTEXT_CONTINUATION_MARKER = "[CONTINUATION"

NODE_CONTEXT_EDITING_NOTICE = (
    "\n\n[CONTEXT EDITING] When this stage's context grows large, the provider "
    "clears your older tool results and leaves a placeholder in their place; "
    "the newest ones stay. Record what you rely on through tools as you go "
    "(findings in the store, notes under workspace/) rather than counting on "
    "re-reading an earlier tool result."
)

HANDOFF_ARTIFACT_PREFIX = "workspace/.handoff/"


class NodeContextExhausted(RuntimeError):
    """A stage's own working context reached the model's window.

    Raised from the before-model callback. While `retryable`, ADK's node
    retry runs the stage again with a fresh context (a continuation, see
    MAX_NODE_CONTINUATIONS); the handoff the attempt wrote travels through
    the campaign's budget slot and the artifact store into the next
    attempt's instruction. Non-retryable once the continuations are spent.
    """

    def __init__(self, message: str, retryable: bool = True):
        super().__init__(message)
        self.retryable = retryable


def _continuation_block(handoff: str, number: int) -> str:
    """The instruction block a continued attempt carries: the same bytes on
    every call of the attempt. The handoff is model-written text about the
    target, so it is fenced like every other model-to-model channel."""
    from core.llm_gateway import wrap_untrusted_content

    text = (handoff or "").strip() or "(no handoff was written; read your workspace notes first)"
    if len(text) > MAX_HANDOFF_CHARS:
        text = text[:MAX_HANDOFF_CHARS] + "\n[handoff truncated]"
    return (
        f"\n\n{NODE_CONTEXT_CONTINUATION_MARKER} {number}] This is a fresh context: the "
        f"previous attempt{'s' if number > 1 else ''} of this stage used the window. "
        "Everything recorded through tools is intact -- findings in the store, "
        "notes under workspace/. Start from the handoff below, do not redo what it "
        "records as done, and record results as you go.\n"
        + wrap_untrusted_content(text, filename="stage_handoff")
    )


def _request_chars(llm_request: Any, keep_tool_results: Optional[int] = None) -> int:
    """Characters in a request: instruction, every content part, tool schemas.
    Counts the request as built -- what the model would be sent -- so it is
    the same number whatever the session looks like.

    With `keep_tool_results`, the request is counted as the provider reads it
    under context editing: every tool result but the newest that many as the
    provider's placeholder (core.config.anthropic_context_editing)."""
    total = 0
    config = getattr(llm_request, "config", None)
    total += len(str(getattr(config, "system_instruction", "") or ""))
    responses: list[int] = []
    for content in getattr(llm_request, "contents", None) or []:
        for part in getattr(content, "parts", None) or []:
            text = getattr(part, "text", None)
            if text:
                total += len(text)
            call = getattr(part, "function_call", None)
            if call is not None:
                total += len(json.dumps(getattr(call, "args", None) or {}, default=str))
            response = getattr(part, "function_response", None)
            if response is not None:
                responses.append(len(json.dumps(getattr(response, "response", None) or {}, default=str)))
    if keep_tool_results is None:
        total += sum(responses)
    else:
        kept = responses[-keep_tool_results:] if keep_tool_results else []
        total += sum(kept) + 32 * (len(responses) - len(kept))
    tools = getattr(llm_request, "tools_dict", None) or {}
    total += 2000 * len(tools)
    return total


def _observe(name: str, n: int = 1) -> None:
    """Counts a context-management event on the run's spend report."""
    try:
        from core.budget import observe
        observe(name, n)
    except Exception:
        pass


def _node_context_slot(node_id: str) -> Optional[dict]:
    """This campaign's budget record for `node_id`, created on first use;
    None outside a campaign. {"tokens": last estimated request size,
    "limit": the window, "continuations": how many fresh contexts this stage
    has had, "handoff": the note the latest continuation started from}."""
    try:
        from core.context import current_run_context
        ctx = current_run_context.get()
    except Exception:
        return None
    if ctx is None or not hasattr(ctx, "node_context"):
        return None
    return ctx.node_context.setdefault(
        node_id, {"tokens": 0, "limit": 0, "continuations": 0, "handoff": ""}
    )


def node_context_headroom(node_id: str) -> Optional[tuple[int, int]]:
    """(tokens left below the ceiling, reserve in tokens) for the stage in the
    current campaign, or None when no request has been measured yet or the
    window is unknown. The after-tool guard sizes new tool results with it."""
    slot = _node_context_slot(node_id)
    if not slot or not slot.get("limit"):
        return None
    limit = int(slot["limit"])
    ceiling = int(limit * NODE_CONTEXT_CEILING_RATIO)
    return max(0, ceiling - int(slot.get("tokens") or 0)), int(limit * NODE_CONTEXT_RESERVE_RATIO)


def _handoff_artifact_path(node_id: str) -> str:
    return f"{HANDOFF_ARTIFACT_PREFIX}{node_id}.md"


def _store_handoff(node_id: str, handoff: str, number: int) -> None:
    """Persists the handoff with this campaign's artifacts, so a --resume in a
    new process continues from it too. Never raises: a handoff that cannot be
    stored still travels in the campaign's slot."""
    try:
        from core.context import current_run_context
        from core.database import record_artifact
        ctx = current_run_context.get()
        if ctx is None or not ctx.db_path or not ctx.run_id:
            return
        record_artifact(
            ctx.db_path, ctx.run_id, "handoff", _handoff_artifact_path(node_id), handoff,
            metadata={"resource": getattr(ctx, "target_file", "") or "", "continuation": number, "node": node_id},
        )
    except Exception as exc:
        print(f"[CONTEXT CEILING] {node_id}: handoff not stored ({exc}).", file=sys.stderr)


def _stored_handoff(node_id: str) -> tuple[str, int]:
    """(handoff, continuation number) recorded for this campaign's stage by an
    earlier process, or ("", 0)."""
    try:
        from core.context import current_run_context
        from core.database import read_artifact_record
        ctx = current_run_context.get()
        if ctx is None or not ctx.db_path or not ctx.run_id:
            return "", 0
        rec = read_artifact_record(
            ctx.db_path, _handoff_artifact_path(node_id), run_id=ctx.run_id,
            resource=getattr(ctx, "target_file", "") or "",
        )
        if not rec:
            return "", 0
        try:
            meta = json.loads(rec.get("metadata_json") or "{}")
        except (TypeError, ValueError):
            meta = {}
        number = int(meta.get("continuation") or 0) if isinstance(meta, dict) else 0
        return str(rec.get("content") or ""), number
    except Exception:
        return "", 0


async def _write_handoff(
    node_id: str, llm: Any, llm_request: Any, limit_tokens: Optional[int] = None
) -> tuple[str, int]:
    """Asks the stage's model for the handoff: one more request on the same
    prefix -- instruction, tools and history as sent -- plus the handoff prompt
    as a new user turn, tools switched off for the answer. When the accumulated
    request has already grown close to or past the pre-dispatch budget guard
    (>=85% of `limit_tokens`), oldest tool responses are cleared on the copy
    (and thinking signatures stripped) so the handoff call itself cannot
    overflow and leave an empty handoff.
    Returns (handoff text, tokens used); ("", 0) when no model is available
    or the call fails, which must never block the continuation."""
    if llm is None:
        return "", 0
    try:
        request = llm_request.model_copy(deep=True)
        eff_limit = limit_tokens
        if not eff_limit:
            try:
                from core.config import _effective_context_window
                eff_limit = _effective_context_window(
                    getattr(llm, "model", None) or getattr(llm_request, "model", None)
                )
            except Exception:
                eff_limit = None
        if eff_limit and eff_limit > 0:
            est_tokens = (
                _request_chars(request) + len(NODE_CONTEXT_HANDOFF_PROMPT)
            ) // NODE_CONTEXT_CHARS_PER_TOKEN
            if est_tokens >= int(eff_limit * 0.85):
                target_tokens = max(1, int(eff_limit * 0.65))
                # Strip thinking blocks/signatures before trimming earlier turns
                # so providers that bind thinking to prefix accept the trimmed copy.
                cleaned_contents = []
                for content in list(request.contents or []):
                    kept_parts = []
                    for part in getattr(content, "parts", None) or []:
                        if getattr(part, "thought", False):
                            continue
                        if getattr(part, "thought_signature", None):
                            part = part.model_copy(update={"thought_signature": None})
                        kept_parts.append(part)
                    if kept_parts:
                        content.parts = kept_parts
                        cleaned_contents.append(content)
                request.contents = cleaned_contents
                for content, idx, _chars in _function_response_parts(request):
                    if _request_chars(request) // NODE_CONTEXT_CHARS_PER_TOKEN <= target_tokens:
                        break
                    _clear_function_response(content, idx)
        request.contents = list(request.contents or []) + [
            types.Content(role="user", parts=[types.Part.from_text(text=NODE_CONTEXT_HANDOFF_PROMPT)])
        ]
        try:
            request.config.tool_config = types.ToolConfig(
                function_calling_config=types.FunctionCallingConfig(mode="NONE")
            )
        except Exception:
            pass
        text_parts: list[str] = []
        tokens = 0
        handoff_tok = _HANDOFF_PLAIN_TEXT_TURN.set(True)
        try:
            async for response in llm.generate_content_async(request, stream=False):
                content = getattr(response, "content", None)
                for part in (getattr(content, "parts", None) or []):
                    if getattr(part, "text", None) and not getattr(part, "thought", False):
                        text_parts.append(part.text)
                usage = getattr(response, "usage_metadata", None)
                if usage and getattr(usage, "total_token_count", None):
                    tokens = int(usage.total_token_count)
        finally:
            _HANDOFF_PLAIN_TEXT_TURN.reset(handoff_tok)
        return "".join(text_parts).strip(), tokens
    except Exception as exc:
        print(f"[CONTEXT CEILING] {node_id}: handoff call failed ({type(exc).__name__}: {str(exc)[:160]}).",
              file=sys.stderr)
        return "", 0


CLEARED_TOOL_RESULT_TEXT = "[cleared by context editing]"
NODE_CONTEXT_CLEARED_KEY = "cleared_tool_results"


def _function_response_parts(llm_request: Any) -> list:
    """`[(content, part_index, chars)]` for every tool result in the request,
    in order: the list client-side context editing clears from the front."""
    out: list = []
    for content in getattr(llm_request, "contents", None) or []:
        parts = getattr(content, "parts", None) or []
        for i, part in enumerate(parts):
            response = getattr(part, "function_response", None)
            if response is None:
                continue
            payload = getattr(response, "response", None) or {}
            if isinstance(payload, dict) and payload.get("result") == CLEARED_TOOL_RESULT_TEXT and len(payload) == 1:
                out.append((content, i, 0))
            else:
                out.append((content, i, len(json.dumps(payload, default=str))))
    return out


def _clear_function_response(content: Any, index: int) -> None:
    """Replaces one tool result with the placeholder. ADK hands the request a
    shallow copy of each Content and Part, so a new Part in the copied list
    leaves the session's events untouched; the call id stays so the pairing
    with its function call holds."""
    part = content.parts[index]
    response = part.function_response
    content.parts[index] = types.Part(function_response=types.FunctionResponse(
        name=getattr(response, "name", None),
        id=getattr(response, "id", None),
        response={"result": CLEARED_TOOL_RESULT_TEXT},
    ))


FORK_NOTICE_MARKER = "[FORKED CONTEXT]"
PREFIX_U_STATE_KEY_PREFIX = "_mantis_prefix_u:"
ACTIVE_STAGE_HEADER_PREFIX = "[ACTIVE STAGE ASSIGNMENT: "


def _final_attempt_events(events: Any, author_id: str) -> list[Any]:
    """Events from `author_id`'s final non-empty retry/continuation attempt.

    ADK node retries and `NodeContextExhausted` continuations append attempt 1's
    events followed by an `error_code` event and then attempt 2's events under
    the same `author`. Splitting on `error_code` markers (and distinct non-empty
    `node_info.path` invocations) and selecting the last non-empty segment
    ensures downstream forks inherit only the surviving attempt while keeping a
    trailing standalone error event after completed work safe.
    """
    segments: list[list[Any]] = [[]]
    current_path = ""
    want = str(author_id)
    for ev in events or ():
        if str(getattr(ev, "author", "") or "") != want:
            continue
        if getattr(ev, "partial", False) or _is_end_of_agent(ev):
            continue
        if getattr(ev, "error_code", None):
            if segments[-1]:
                segments.append([])
            current_path = ""
            continue
        ev_path = str(getattr(getattr(ev, "node_info", None), "path", "") or "")
        if ev_path and current_path and ev_path != current_path:
            if segments[-1]:
                segments.append([])
        if ev_path:
            current_path = ev_path
        segments[-1].append(ev)
    return next((seg for seg in reversed(segments) if seg), [])


def _part_is_adk_visible(part: Any) -> bool:
    """Mirrors ADK `_is_part_invisible(..., include_thoughts=False)`."""
    if getattr(part, "function_call", None) or getattr(part, "function_response", None):
        return True
    if getattr(part, "thought_signature", None):
        return True
    if getattr(part, "tool_call", None) or getattr(part, "tool_response", None):
        return True
    if getattr(part, "thought", False):
        return False
    return bool(
        getattr(part, "text", None)
        or getattr(part, "inline_data", None)
        or getattr(part, "file_data", None)
        or getattr(part, "executable_code", None)
        or getattr(part, "code_execution_result", None)
    )


def forked_contents(
    events: Any,
    parent_id: str,
    *,
    preserve_signatures: bool = False,
) -> list:
    """The parent stage's transcript as request contents: every event from
    `parent_id`'s final attempt in this campaign's session.

    When `preserve_signatures=False` (legacy per-edge `fork_from`), thinking
    parts and `thought_signature`s are stripped because the child has its own
    system instruction and tool declarations.

    When `preserve_signatures=True` (`prefix_group` shared-prefix stem with
    matching model), `part.thought` and `part.thought_signature` are preserved
    verbatim so the request prefix `[S_base, T_shared, *stem]` is 100%
    byte-identical to the stem's wire requests, satisfying Gemini 3 signature
    verification and enabling Turn-1 implicit KV-cache hits.
    """
    out: list = []
    for ev in _final_attempt_events(events, parent_id):
        content = getattr(ev, "content", None)
        parts = getattr(content, "parts", None) if content is not None else None
        if not parts:
            continue
        if preserve_signatures:
            if not any(_part_is_adk_visible(p) for p in parts):
                continue
            kept = [p.model_copy() for p in parts]
        else:
            kept = []
            for part in parts:
                if getattr(part, "thought", False):
                    continue
                if getattr(part, "thought_signature", None):
                    part = part.model_copy(update={"thought_signature": None})
                kept.append(part)
        if kept:
            out.append(types.Content(role=getattr(content, "role", None) or "model", parts=kept))
    return out


def _root_seed_user_content(events: Any) -> Optional[types.Content]:
    """Extracts the campaign's initial `author=='user'` seed message from `events`, if present."""
    for ev in events or ():
        if str(getattr(ev, "author", "") or "") != "user":
            continue
        if getattr(ev, "partial", False) or getattr(ev, "error_code", None):
            continue
        ev_path = str(getattr(getattr(ev, "node_info", None), "path", "") or "")
        if ev_path:
            continue
        content = getattr(ev, "content", None)
        parts = getattr(content, "parts", None) if content is not None else None
        if not parts:
            continue
        if any(getattr(p, "function_response", None) for p in parts):
            continue
        user_parts = [p.model_copy() for p in parts if not getattr(p, "thought", False)]
        if user_parts:
            return types.Content(role="user", parts=user_parts)
    return None


_SHORTCIRCUIT_ANCESTOR_PHRASES = (
    "] Reused the ",
    "] Reused repo-root ",
    "] Recorded deterministic single-file ",
    "Skipped stage in static-only sandbox mode.",
    "Skipped dynamic reproduction in static-only sandbox mode.",
)


def _is_shortcircuit_only_transcript(contents: Sequence[Any]) -> bool:
    """True when `contents` consists solely of a harness `before_agent_callback` short-circuit reply."""
    if len(contents) != 1 or getattr(contents[0], "role", "") != "model":
        return False
    parts = getattr(contents[0], "parts", None) or ()
    if not parts or any(getattr(p, "function_call", None) is not None for p in parts):
        return False
    combined = "\n".join(str(getattr(p, "text", "") or "") for p in parts)
    return any(marker in combined for marker in _SHORTCIRCUIT_ANCESTOR_PHRASES)


def forked_prefix_contents(
    events: Any,
    ancestor_chain: Sequence[str],
    *,
    state: Optional[dict[str, Any]] = None,
    preserve_signatures: bool = True,
) -> list:
    """Reconstructs the transitive `[u_0, *anc_1, u_1, *anc_2, ...]` stem transcript
    across `ancestor_chain` for a `prefix_group` stage.

    ADK removes a single-turn workflow node's injected `user` opener event from
    `session.events` in its `finally:` block once the node finishes. Each
    `prefix_group` node therefore records its exact opening `u_stage` text under
    `PREFIX_U_STATE_KEY_PREFIX + node_id` (and in `RunContext.node_context`),
    allowing downstream stages to replay the exact byte-for-byte `[u_stage,
    m_1, fr_1, ..., m_final]` sequence sent during the stem. When called on
    synthetic unit-test event lists where callbacks have not populated state,
    falls back deterministically to the root `author=='user'` seed event.
    """
    out: list[types.Content] = []
    state_map = state if isinstance(state, dict) else {}
    rc_nodes: dict[str, Any] = {}
    try:
        from core.context import current_run_context

        rc = current_run_context.get()
        if rc is not None and isinstance(getattr(rc, "node_context", None), dict):
            rc_nodes = rc.node_context
    except Exception:
        rc_nodes = {}

    for anc_id in ancestor_chain:
        anc_contents = forked_contents(
            events, anc_id, preserve_signatures=preserve_signatures
        )
        if not anc_contents:
            continue

        u_anc: Optional[types.Content] = None
        stored_text = state_map.get(f"{PREFIX_U_STATE_KEY_PREFIX}{anc_id}")
        if not stored_text and isinstance(rc_nodes.get(anc_id), dict):
            stored_text = rc_nodes[anc_id].get("prefix_u_text")
        if not stored_text and _is_shortcircuit_only_transcript(anc_contents):
            continue
        if isinstance(stored_text, str) and stored_text:
            u_anc = types.Content(
                role="user", parts=[types.Part.from_text(text=stored_text)]
            )
        elif not out:
            u_anc = _root_seed_user_content(events)
            if u_anc is None and getattr(anc_contents[0], "role", "") == "model":
                u_anc = types.Content(
                    role="user",
                    parts=[types.Part.from_text(text=f"{ACTIVE_STAGE_HEADER_PREFIX}{anc_id}]")],
                )
        elif getattr(anc_contents[0], "role", "") == "model":
            u_anc = types.Content(
                role="user",
                parts=[types.Part.from_text(text=f"{ACTIVE_STAGE_HEADER_PREFIX}{anc_id}]")],
            )

        if u_anc is not None and getattr(anc_contents[0], "role", "") == "model":
            if out and getattr(out[-1], "role", "") == "user":
                merged_parts = list(getattr(out[-1], "parts", None) or []) + list(
                    getattr(u_anc, "parts", None) or []
                )
                out[-1] = types.Content(role="user", parts=merged_parts)
            else:
                out.append(u_anc)

        for item in anc_contents:
            item_role = getattr(item, "role", "") or "model"
            if (
                out
                and item_role == "user"
                and getattr(out[-1], "role", "") == "user"
                and not any(getattr(p, "function_response", None) for p in (getattr(item, "parts", None) or []))
                and not any(getattr(p, "function_response", None) for p in (getattr(out[-1], "parts", None) or []))
            ):
                merged = list(getattr(out[-1], "parts", None) or []) + list(
                    getattr(item, "parts", None) or []
                )
                out[-1] = types.Content(role="user", parts=merged)
            else:
                out.append(item)
    return out


def _make_fork_before_model_callback(node_id: str, parent_id: str):
    """Starts this node's requests with `parent_id`'s transcript from the
    same campaign: a fork of that stage's conversation instead of a fresh
    context.

    What it is for: a stage that would otherwise re-derive its
    predecessor's reading of the code -- the researcher re-opening what
    the planner just read, the reproducer re-walking the path to the sink
    -- continues from it instead. Not for the stages whose value is
    independence (reviewer, critic, calibrator, the patcher's re-attack):
    a judge forked from the stage it judges inherits that stage's
    confidence. Whether a fork helps or harms is a measurement, per edge
    and per model, which is why it is a node knob (`fork_from`) and not a
    default.

    Mechanics: on every model call the parent's events are read from the
    session (ADK rebuilds a request from the session each call, so this is
    re-applied, never persisted) and prepended to the request's contents;
    the node's own events follow. The same parent events on every call
    keep the prefix stable for prompt caching. A one-line notice is
    appended to the instruction once. Runs first among the before-model
    callbacks, so the ceiling measures and context editing trims the
    inherited transcript like the node's own.
    """
    async def _before_model(callback_context: Any = None, llm_request: Any = None):
        _stamp_active_node(node_id)
        if llm_request is None or callback_context is None:
            return None
        try:
            session = getattr(callback_context, "session", None)
            events = getattr(session, "events", None) if session is not None else None
            inherited = forked_contents(events, parent_id)
        except Exception:
            return None
        if not inherited:
            return None
        own = list(getattr(llm_request, "contents", None) or [])
        # ADK opens a node's turn with its predecessor's final reply as a
        # user message. When that predecessor is the parent, the inherited
        # transcript already ends with the same text: keep ADK's copy, drop
        # the duplicate.
        if own and inherited:
            last, first = inherited[-1], own[0]
            last_parts = getattr(last, "parts", None) or []
            first_parts = getattr(first, "parts", None) or []
            if (
                getattr(last, "role", "") == "model" and getattr(first, "role", "") == "user"
                and len(last_parts) == 1 and len(first_parts) == 1
                and getattr(last_parts[0], "text", None)
                and last_parts[0].text == getattr(first_parts[0], "text", None)
            ):
                inherited = inherited[:-1]
        llm_request.contents = inherited + own
        if hasattr(llm_request, "append_instructions"):
            sys_inst = str(getattr(getattr(llm_request, "config", None), "system_instruction", "") or "")
            if FORK_NOTICE_MARKER not in sys_inst:
                llm_request.append_instructions([
                    f"\n\n{FORK_NOTICE_MARKER} The conversation before your own turns is the '{parent_id}' "
                    "stage's work in this campaign: its reading of the code, its tool results and its "
                    "conclusions. Build on it. Do not repeat reads it already made unless you need a "
                    "different range; verify what matters for your own task rather than restating its "
                    "claims."
                ])
        _observe("forked_requests")
        return None

    return _before_model


def _count_protected_inherited_tool_responses(llm_request: Any, node_id: str) -> int:
    """Counts `function_response` parts belonging to the inherited stem before `node_id`'s own turn."""
    marker = f"{ACTIVE_STAGE_HEADER_PREFIX}{node_id}]"
    count = 0
    found_marker = False
    for content in getattr(llm_request, "contents", None) or ():
        parts = getattr(content, "parts", None) or ()
        if getattr(content, "role", "") == "user" and any(
            marker in (getattr(p, "text", None) or "") for p in parts
        ):
            found_marker = True
            break
        for part in parts:
            if getattr(part, "function_response", None) is not None:
                count += 1
    return count if found_marker else 0


def _strip_claude_thoughts_up_to_last_cleared(
    llm_request: Any, last_cleared_content: Any
) -> None:
    """Strips prefix-bound `thought` blocks and `thought_signature` metadata
    from `role='model'` turns at or before `last_cleared_content` when
    client-side context editing mutates historical tool results on a Claude
    route (e.g. Bedrock Converse or OpenRouter), keeping `function_call`
    pairings and recent kept turns intact."""
    contents = list(getattr(llm_request, "contents", None) or [])
    last_idx = next((i for i, c in enumerate(contents) if c is last_cleared_content), -1)
    if last_idx < 0:
        return
    updated_contents = []
    for idx, content in enumerate(contents):
        if idx <= last_idx and getattr(content, "role", None) == "model":
            kept_parts = []
            for part in getattr(content, "parts", None) or []:
                if getattr(part, "thought", False):
                    continue
                if getattr(part, "thought_signature", None) is not None:
                    part = part.model_copy(update={"thought_signature": None})
                kept_parts.append(part)
            if kept_parts:
                content.parts = kept_parts
                updated_contents.append(content)
        else:
            updated_contents.append(content)
    llm_request.contents = updated_contents


def _make_client_context_editing_before_model_callback(
    node_id: str,
    model: Any = None,
    config: Any = None,
    *,
    preserve_system_prefix: bool = False,
):
    """Clears a stage's older tool results before dispatch, for models that
    do not run server-side `clear_tool_uses_20250919` (Gemini, OpenAI, and
    non-direct Claude routes like Bedrock Converse / OpenRouter):
    the harness-side counterpart of Anthropic context editing, same trigger,
    keep and clear-at-least (core.config.client_context_editing).

    Deterministic and monotonic within a stage attempt: the campaign's
    budget slot remembers how many of the oldest results are cleared, every
    request clears exactly those (ADK rebuilds the request from the session
    on each call, so the clearing is re-applied, never persisted), and the
    count only grows -- at the trigger, by at least clear-at-least worth of
    results, never into the newest `keep`. Between edits the request prefix
    is therefore stable, which is what implicit prompt caching needs; each
    edit costs one cache miss, as the provider's own edit does. Reset by a
    continuation, whose attempt starts with no tool results of its own.

    Runs before the ceiling callback, which then measures the request as
    cleared. Direct Anthropic / Vertex Claude models get None here: the
    provider edits for them.
    """
    editing_cache: dict[str, Any] = {}

    def _editing() -> Optional[dict]:
        if "editing" not in editing_cache:
            try:
                from core.config import client_context_editing
                editing_cache["editing"] = client_context_editing(model, config=config) if model else None
            except Exception:
                editing_cache["editing"] = None
        return editing_cache["editing"]

    async def _before_model(callback_context: Any = None, llm_request: Any = None):
        if llm_request is None:
            return None
        editing = _editing()
        if not editing:
            return None
        slot = _node_context_slot(node_id)
        if slot is None:
            return None
        keep = max(0, int(editing.get("keep") or 0))
        all_responses = _function_response_parts(llm_request)
        protected = (
            _count_protected_inherited_tool_responses(llm_request, node_id)
            if preserve_system_prefix
            else 0
        )
        responses = all_responses[protected:]
        clearable = max(0, len(responses) - keep)
        cleared = min(max(0, int(slot.get(NODE_CONTEXT_CLEARED_KEY) or 0)), clearable)
        if not preserve_system_prefix and hasattr(llm_request, "append_instructions"):
            sys_inst = str(getattr(getattr(llm_request, "config", None), "system_instruction", "") or "")
            if "[CONTEXT EDITING]" not in sys_inst:
                llm_request.append_instructions([NODE_CONTEXT_EDITING_NOTICE])
        for content, index, _chars in responses[:cleared]:
            _clear_function_response(content, index)
        effective_cleared = cleared
        estimated = _request_chars(llm_request) // NODE_CONTEXT_CHARS_PER_TOKEN
        trigger = int(editing.get("trigger_tokens") or 0)
        if trigger and estimated >= trigger and cleared < clearable:
            # At least clear-at-least worth, and enough to get back under
            # the trigger, so one edit (one cache miss) buys a long stretch.
            target = int(editing.get("clear_at_least_tokens") or 0) * NODE_CONTEXT_CHARS_PER_TOKEN
            total_chars = estimated * NODE_CONTEXT_CHARS_PER_TOKEN
            freed = 0
            new_cleared = cleared
            while new_cleared < clearable and (
                new_cleared == cleared or freed < target
                or (total_chars - freed) // NODE_CONTEXT_CHARS_PER_TOKEN >= trigger
            ):
                freed += responses[new_cleared][2]
                new_cleared += 1
            for content, index, _chars in responses[cleared:new_cleared]:
                _clear_function_response(content, index)
            effective_cleared = new_cleared
            slot[NODE_CONTEXT_CLEARED_KEY] = new_cleared
            _observe("context_edits_applied")
            _observe("context_edit_cleared_tokens", freed // NODE_CONTEXT_CHARS_PER_TOKEN)
            print(
                f"\n[CONTEXT EDITING] {node_id}: ~{estimated:,} tokens of working context at the "
                f"{trigger:,}-token trigger; cleared {new_cleared - cleared} older tool result(s) "
                f"(~{freed // NODE_CONTEXT_CHARS_PER_TOKEN:,} tokens), {new_cleared} of "
                f"{len(responses)} now cleared, newest {keep} kept.",
                file=sys.stderr,
            )
        elif slot.get(NODE_CONTEXT_CLEARED_KEY) != cleared:
            slot[NODE_CONTEXT_CLEARED_KEY] = cleared
        if effective_cleared > 0 and is_claude_model(model):
            _strip_claude_thoughts_up_to_last_cleared(
                llm_request, responses[effective_cleared - 1][0]
            )
        return None

    return _before_model


def _make_node_context_ceiling_before_model_callback(
    node_id: str, model: Any = None, has_schema: bool = False, keep_tool_results: Optional[int] = None,
    llm_factory: Any = None, max_continuations: Optional[int] = None,
    *, preserve_system_prefix: bool = False,
):
    """Keeps a stage's own context inside the model's window, append-only.

    Models that bind reasoning to its prefix (preserved thinking) reject a
    request whose earlier messages, instruction or tools changed under a
    retained thinking block, so this never edits a request: no trimming of
    old tool responses, no summarisation in place. Instead:

    * every call, it records the request's estimated size in the campaign's
      budget slot, which the after-tool guard reads to size NEW tool results
      to the headroom left and to warn the model when the reserve is reached;
    * at the ceiling it asks the model for a handoff (one more request on the
      unchanged prefix), stores it, and raises NodeContextExhausted so ADK's
      node retry runs the stage again in a fresh context -- a continuation.
      The continued attempt carries the handoff in its instruction, the same
      bytes on every one of its calls, so its prefix is stable too;
    * after MAX_NODE_CONTINUATIONS, a schema-less stage ends with a final
      response (no model call); a stage with an output schema raises once
      more, non-retryably, since a synthetic text would fail its schema.

    `llm_factory` returns the model client used for the handoff call; None
    means no handoff is written (the continuation still happens, from the
    workspace notes). With `keep_tool_results` (the model's requests carry
    Anthropic context editing), the request is measured as the provider
    reads it. Runs last among the before-model callbacks so the instruction
    it measures is the one sent.
    """
    limit_cache: dict[str, Optional[int]] = {}
    llm_cache: dict[str, Any] = {}

    def _limit() -> Optional[int]:
        if "limit" not in limit_cache:
            try:
                from core.config import resolve_context_limit, resolve_input_token_cap
                limits = [l for l in (resolve_context_limit(model) if model else None,
                                      resolve_input_token_cap()) if l]
                limit_cache["limit"] = min(limits) if limits else None
            except Exception:
                limit_cache["limit"] = None
        return limit_cache["limit"]

    def _cap() -> int:
        # Read at call time so a test may patch the module default.
        return int(MAX_NODE_CONTINUATIONS if max_continuations is None else max_continuations)

    def _llm() -> Any:
        if "llm" not in llm_cache:
            try:
                llm_cache["llm"] = llm_factory() if llm_factory else None
            except Exception:
                llm_cache["llm"] = None
        return llm_cache["llm"]

    async def _before_model(callback_context: Any = None, llm_request: Any = None):
        if llm_request is None:
            return None
        limit = _limit()
        if not limit:
            return None
        slot = _node_context_slot(node_id)
        if slot is not None and not slot.get("continuations") and not slot.get("handoff"):
            # A new process picking up this campaign: continue from the
            # handoff an earlier process stored, if any.
            stored, number = _stored_handoff(node_id)
            if stored:
                slot["handoff"], slot["continuations"] = stored, max(1, number)
        continuations = int(slot.get("continuations") or 0) if slot else 0
        if not preserve_system_prefix and hasattr(llm_request, "append_instructions"):
            sys_inst = str(getattr(getattr(llm_request, "config", None), "system_instruction", "") or "")
            if keep_tool_results is not None and "[CONTEXT EDITING]" not in sys_inst:
                llm_request.append_instructions([NODE_CONTEXT_EDITING_NOTICE])
            if continuations and NODE_CONTEXT_CONTINUATION_MARKER not in sys_inst:
                llm_request.append_instructions([_continuation_block(slot.get("handoff", ""), continuations)])
        estimated = _request_chars(llm_request, keep_tool_results) // NODE_CONTEXT_CHARS_PER_TOKEN
        if slot is not None:
            slot["tokens"] = estimated
            slot["limit"] = limit
        ceiling = int(limit * NODE_CONTEXT_CEILING_RATIO)
        if estimated < ceiling:
            return None
        may_continue = slot is not None and continuations < _cap()
        if may_continue:
            handoff, used = await _write_handoff(node_id, _llm(), llm_request, limit_tokens=limit)
            if used:
                try:
                    from core.context import current_run_context
                    bc = getattr(current_run_context.get(), "budget_controller", None)
                    if bc is not None:
                        bc.record_tokens(used)
                except Exception:
                    pass
            number = continuations + 1
            slot["continuations"] = number
            slot["handoff"] = handoff
            slot["tokens"] = 0
            # The continued attempt has no tool results of its own yet.
            slot[NODE_CONTEXT_CLEARED_KEY] = 0
            _store_handoff(node_id, handoff, number)
            _observe("continuations")
            print(
                f"\n[CONTEXT CEILING] {node_id}: ~{estimated:,} tokens of working context "
                f"against a {limit:,}-token window (ceiling {ceiling:,}); continuing in a "
                f"fresh context (continuation {number}/{_cap()}, handoff "
                f"{len(handoff):,} chars).",
                file=sys.stderr,
            )
            raise NodeContextExhausted(
                f"{node_id}: ~{estimated:,} tokens of working context against a "
                f"{limit:,}-token window; the stage continues in a fresh context.",
                retryable=True,
            )
        if has_schema or slot is None:
            print(
                f"\n[CONTEXT CEILING] {node_id}: ~{estimated:,} tokens of working context "
                f"against a {limit:,}-token window after {continuations} continuation(s); "
                "the stage cannot be ended with a synthetic answer (output schema); failing it.",
                file=sys.stderr,
            )
            _observe("ceiling_failures")
            raise NodeContextExhausted(
                f"{node_id}: context exhausted after {continuations} continuation(s).",
                retryable=False,
            )
        print(
            f"\n[CONTEXT CEILING] {node_id}: ~{estimated:,} tokens of working context "
            f"against a {limit:,}-token window (ceiling {ceiling:,}) after {continuations} "
            "continuation(s); ending the stage with its recorded work in place.",
            file=sys.stderr,
        )
        _observe("ceiling_ends")
        from google.adk.models import LlmResponse
        return LlmResponse(
            content=types.Content(role="model", parts=[types.Part.from_text(text=NODE_CONTEXT_CEILING_TEXT)])
        )

    return _before_model


CAMPAIGN_DIRECTIVE_MARKER = "[CAMPAIGN DIRECTIVE]"
CAMPAIGN_CONTEXT_MARKER = "[CAMPAIGN CONTEXT]"
AUDIT_CHECKLIST_MARKER = "[DETERMINISTIC AUDIT CHECKLIST]"
OPERATOR_FOCUS_MARKER = "[OPERATOR FOCUS]"
OPERATOR_SEED_REPORT_MARKER = "[OPERATOR SEED REPORT]"
#: Characters of campaign context appended per node. Larger than the stage
#: experience cap: the memory block alone lists every earlier finding here.
MAX_CAMPAIGN_CONTEXT_CHARS = 8000
#: Characters of campaign directive appended per node: the change-scoped
#: file list, the prior-findings brief and the PoC re-run note together.
MAX_CAMPAIGN_DIRECTIVE_CHARS = 12000
#: Stages that receive the deterministic slice sink/entrypoint checklist so
#: planning and vulnerability discovery cover indexed sinks systematically
#: without biasing independent downstream review/critic stages.
CHECKLIST_STAGES = ("planner", "explorer", "researcher")
#: Hunting stages that receive operator `--focus` and `--seed-report` across
#: all scan modes. Verification/judge stages (`reviewer`, `critic`,
#: `reproducer`, `patcher`, `calibrator`) are deliberately excluded to preserve
#: independent separation-of-duties neutrality (INV-2).
HUNTING_STAGES = ("architect", "threat_modeler", "planner", "researcher", "explorer")
#: The stages that decide where to look. Matched by node id prefix, so
#: `researcher_2` in a parallel archetype counts. The reproducer, patcher,
#: calibrator, reflector and reporter work from this run's findings through
#: tools, and earlier runs' findings in their instructions would be a way
#: for history to leak into this run's report.
CONTEXT_STAGES = ("architect", "threat_modeler", "planner", "explorer", "researcher", "reviewer", "critic")


def _wants_campaign_context(node_id: str) -> bool:
    nid = str(node_id or "")
    return any(nid == s or nid.startswith(s + "_") or nid.startswith(s + "-") for s in CONTEXT_STAGES)


def _wants_audit_checklist(node_id: str) -> bool:
    nid = str(node_id or "")
    return any(nid == s or nid.startswith(s + "_") or nid.startswith(s + "-") for s in CHECKLIST_STAGES)


def _wants_operator_steering(node_id: str) -> bool:
    nid = str(node_id or "")
    return any(nid == s or nid.startswith(s + "_") or nid.startswith(s + "-") for s in HUNTING_STAGES)


def _close_open_fence(text: str) -> str:
    """A cut that fell inside an untrusted-data block gets the closing
    delimiter back, so the fence never stays open over the instruction
    that follows (the same rule bound_appended_instruction keeps)."""
    from core.llm_gateway import UNTRUSTED_DATA_END, UNTRUSTED_DATA_START

    opened = text.count(UNTRUSTED_DATA_START.split(" ")[0])
    closed = text.count(UNTRUSTED_DATA_END)
    if opened > closed:
        return text + "\n" + UNTRUSTED_DATA_END
    return text


def _render_campaign_directive_blocks(
    node_id: str,
    existing_text: str = "",
) -> list[str]:
    """Renders bounded campaign context, checklist, and directive blocks missing from `existing_text`."""
    from core.context import current_run_context

    ctx = current_run_context.get()
    if ctx is None:
        return []
    wants_context = _wants_campaign_context(node_id)
    wants_checklist = _wants_audit_checklist(node_id)
    wants_steering = _wants_operator_steering(node_id)
    directive = str(getattr(ctx, "campaign_directive", "") or "")
    if (
        node_id in _PREFIX_REUSE_ARTIFACTS
        and getattr(ctx, "scan_mode", "") == _SCAN_MODE_CROSS_FUNCTIONAL
        and prefix_reuse_applies(
            getattr(ctx, "scan_mode", ""),
            getattr(ctx, "jail_dir", ""),
            getattr(ctx, "path_root", ""),
            getattr(ctx, "target_file", ""),
        )
    ):
        # The repo-scope summary / threat model are reused by every slice of
        # this run: withhold the slice-narrowing directive from them.
        directive = (
            "Shared Repository Prefix Stage: your architectural summary and threat model "
            "are reused across all subsystem slices of this run. Build a repository-wide "
            "model and enumerate from the repository root with list_files('.') rather "
            "than restricting scope to a single slice."
        )
    context = str(getattr(ctx, "campaign_context", "") or "") if wants_context else ""
    seed_block = str(getattr(ctx, "seed_report_block", "") or "") if wants_steering else ""
    op_focus = str(getattr(ctx, "operator_focus", "") or "") if wants_steering else ""
    checklist = ""
    if wants_checklist:
        cached_cl = getattr(ctx, "audit_checklist", None)
        if cached_cl is None and (
            getattr(ctx, "db_path", "")
            or getattr(ctx, "target_file", "")
            or getattr(ctx, "path_root", "")
        ):
            from core.checklist import build_slice_audit_checklist

            cached_cl = build_slice_audit_checklist(ctx)
            ctx.audit_checklist = cached_cl
        checklist = str(cached_cl or "")
    if not directive and not context and not checklist and not seed_block and not op_focus:
        return []
    # Data before instruction: untrusted context / seed evidence come first, and
    # the trusted operator focus last, so it is never enclosed by a fence.
    blocks: list[str] = []
    if context and CAMPAIGN_CONTEXT_MARKER not in existing_text:
        block = f"\n\n{CAMPAIGN_CONTEXT_MARKER}{context}"
        if len(block) > MAX_CAMPAIGN_CONTEXT_CHARS:
            block = _close_open_fence(block[:MAX_CAMPAIGN_CONTEXT_CHARS]) + "\n[campaign context truncated]"
        blocks.append(block)
    if seed_block and OPERATOR_SEED_REPORT_MARKER not in existing_text:
        blocks.append(_close_open_fence(f"\n\n{OPERATOR_SEED_REPORT_MARKER}{seed_block}"))
    if checklist and AUDIT_CHECKLIST_MARKER not in existing_text:
        blocks.append(_close_open_fence(checklist))
    if directive and CAMPAIGN_DIRECTIVE_MARKER not in existing_text:
        block = f"\n\n{CAMPAIGN_DIRECTIVE_MARKER}{directive}"
        if len(block) > MAX_CAMPAIGN_DIRECTIVE_CHARS:
            block = _close_open_fence(block[:MAX_CAMPAIGN_DIRECTIVE_CHARS]) + "\n[directive truncated]"
        blocks.append(block)
    if op_focus and OPERATOR_FOCUS_MARKER not in existing_text:
        blocks.append(f"\n\n{OPERATOR_FOCUS_MARKER}{op_focus}")
    return blocks


def _make_campaign_directive_before_model_callback(node_id: str):
    """Appends the campaign's directive and context (RunContext
    .campaign_directive / .campaign_context) to this node's model requests.

    Nodes run with include_contents="none": each sees its instruction and
    the previous node's reply, and only the first node sees the seed
    message. What a campaign is about (a change-scoped run's file list),
    and what earlier runs established here (the memory block, the leads,
    the slice briefing), therefore cannot ride in the seed; they are
    appended to each node's instructions, the way stage experience is.
    The directive reaches every node; the context reaches the stages that
    decide where to look (CONTEXT_STAGES); operator `--focus` and
    `--seed-report` reach `HUNTING_STAGES` only across all scan modes.
    Data before instruction, so trusted operator directives are never enclosed
    by a context or seed block's untrusted-data fence.
    Idempotent per request (markers), bounded, never the reason a request
    fails.
    """
    def _before_model(callback_context: Any = None, llm_request: Any = None) -> None:
        _stamp_active_node(node_id)
        try:
            if llm_request is None:
                return None
            sys_inst = str(
                getattr(getattr(llm_request, "config", None), "system_instruction", "") or ""
            )
            blocks = _render_campaign_directive_blocks(node_id, existing_text=sys_inst)
            if blocks and hasattr(llm_request, "append_instructions"):
                llm_request.append_instructions(blocks)
        except Exception:
            pass
        return None

    return _before_model


def _make_active_node_before_tool_callback(node_id: str):
    """Stamps `ctx.active_node = node_id` before any tool invocation on non-prefix_group agents."""

    def _before_tool(
        tool: Any = None,
        args: Optional[dict[str, Any]] = None,
        tool_context: Any = None,
        **_kwargs: Any,
    ) -> Optional[dict[str, Any]]:
        _stamp_active_node(node_id)
        return None

    return _before_tool


def _make_prefix_group_before_tool_callback(node_id: str, allowed_tools: Sequence[str]):
    """Deterministically enforces per-stage tool permissions and stamps `ctx.active_node` (`INV-2`)."""
    allowed_set = frozenset(str(t) for t in allowed_tools)
    allowed_sorted = sorted(allowed_set)

    def _before_tool(
        tool: Any = None,
        args: Optional[dict[str, Any]] = None,
        tool_context: Any = None,
        **_kwargs: Any,
    ) -> Optional[dict[str, Any]]:
        _stamp_active_node(node_id)
        tool_name = str(getattr(tool, "name", None) or getattr(tool, "__name__", "") or "")
        if tool_name not in allowed_set:
            return {
                "error": (
                    f"Tool '{tool_name}' is not permitted in stage '{node_id}'. "
                    f"Allowed tools: {allowed_sorted}"
                )
            }
        return None

    return _before_tool


def _is_in_scope_stem_code_read(ctx: Any, tool_name: str, call_args: Any) -> bool:
    """Checks whether `tool_name(call_args)` reads an in-scope target source file (never workspace/*)."""
    from core.budget import CODE_READ_TOOLS

    if tool_name not in CODE_READ_TOOLS or not isinstance(call_args, dict):
        return False
    raw_fp = str(call_args.get("filepath") or "").strip()
    if not raw_fp:
        return False
    clean_fp = raw_fp.replace("\\", "/").lstrip("./")
    if (
        clean_fp in ("workspace", "findings", "mantis-summary.md", "learnings.jsonl")
        or clean_fp.startswith("workspace/")
        or clean_fp.startswith("findings/")
    ):
        return False
    if ctx is None or not getattr(ctx, "jail_dir", None) or not getattr(ctx, "target_file", None):
        return True
    try:
        jail_real = os.path.realpath(ctx.jail_dir).rstrip("/")
        if os.path.isfile(ctx.target_file):
            return True
        scope_roots = [
            os.path.realpath(str(p)).rstrip("/")
            for p in (ctx.target_file, *getattr(ctx, "group_targets", ()))
            if p
        ]
        if not scope_roots or any(sr == jail_real for sr in scope_roots):
            return True
        sb = getattr(ctx, "sandbox", None)
        workdir = str(getattr(sb, "working_dir", "") or "/workspace").replace("\\", "/").rstrip("/") or "/workspace"
        rel_cand = clean_fp
        if rel_cand == workdir or rel_cand.startswith(workdir + "/"):
            rel_cand = rel_cand[len(workdir):].lstrip("/")
        candidates = [os.path.realpath(os.path.join(jail_real, rel_cand)).rstrip("/")]
        path_root = str(getattr(ctx, "path_root", "") or "").strip()
        if path_root and os.path.isdir(path_root):
            candidates.append(os.path.realpath(os.path.join(path_root, rel_cand)).rstrip("/"))
        return any(
            cand == sr or cand.startswith(sr + os.sep)
            for cand in candidates
            for sr in scope_roots
        )
    except OSError:
        return True


def _count_inherited_in_scope_code_reads(ctx: Any, contents: Sequence[Any]) -> int:
    """Counts non-error, in-scope `CODE_READ_TOOLS` invocations present in `contents`."""
    from core.budget import CODE_READ_TOOLS

    pending_by_id: dict[str, str] = {}
    pending_by_name: dict[str, int] = {}
    credited = 0
    for c in contents or ():
        for part in getattr(c, "parts", None) or ():
            call = getattr(part, "function_call", None)
            if call is not None:
                c_name = str(getattr(call, "name", "") or "")
                c_args = getattr(call, "args", None) or {}
                if c_name in CODE_READ_TOOLS and _is_in_scope_stem_code_read(ctx, c_name, c_args):
                    c_id = str(getattr(call, "id", "") or "")
                    if c_id:
                        pending_by_id[c_id] = c_name
                    else:
                        pending_by_name[c_name] = pending_by_name.get(c_name, 0) + 1
            fn_resp = getattr(part, "function_response", None)
            if fn_resp is not None:
                r_name = str(getattr(fn_resp, "name", "") or "")
                r_id = str(getattr(fn_resp, "id", "") or "")
                matched = False
                if r_id and r_id in pending_by_id:
                    pending_by_id.pop(r_id, None)
                    matched = True
                elif pending_by_name.get(r_name, 0) > 0:
                    pending_by_name[r_name] -= 1
                    matched = True
                if not matched:
                    continue
                raw_resp = getattr(fn_resp, "response", {})
                if isinstance(raw_resp, dict):
                    resp_text = str(
                        raw_resp.get("response")
                        or raw_resp.get("result")
                        or raw_resp.get("output")
                        or raw_resp
                    )
                else:
                    resp_text = str(raw_resp)
                is_untrusted = resp_text.startswith("<<<UNTRUSTED_SOURCE_CODE_DATA_START")
                is_err = not is_untrusted and resp_text.startswith(
                    (
                        "SANDBOX-ERROR",
                        "ERROR SAVING DB",
                        "FATAL ERROR",
                        "Error",
                        "ERROR",
                        "NO_DATA:",
                        "SANDBOX-UNAVAILABLE",
                    )
                )
                if not is_err:
                    credited += 1
    return credited


def _chain_before_agent_callbacks(*callbacks: Any):
    """Composes multiple `before_agent_callback` callables, returning the first non-None `Content`."""
    active = [cb for cb in callbacks if callable(cb)]
    if len(active) == 1:
        return active[0]

    def _chained(callback_context: Any = None):
        for cb in active:
            res = cb(callback_context)
            if res is not None:
                return res
        return None

    return _chained


def _make_single_file_stem_skip_before_agent_callback(node_id: str):
    """Skips `architect`, `threat_modeler`, and `planner` on single-file campaigns (`ctx.sandbox is not None`),
    reusing repo-root artifacts when present and persisting a deterministic single-file audit plan."""

    def _before_agent(callback_context: Any = None):
        try:
            from core.context import current_run_context
            from core.database import read_artifact, record_artifact
            from core.paths import resolve_db_path

            ctx = current_run_context.get()
            if ctx is None or ctx.sandbox is None:
                return None
            target = str(getattr(ctx, "target_file", "") or "")
            if not target or not os.path.isfile(target):
                return None
            if not ctx.db_path or not ctx.run_id:
                return None
            db = resolve_db_path(ctx.db_path)
            if not os.path.exists(db):
                return None

            own = str(getattr(ctx, "artifact_resource", "") or target)
            jail_or_root = str(getattr(ctx, "path_root", "") or getattr(ctx, "jail_dir", "") or "")
            canon_root = os.path.realpath(jail_or_root) if jail_or_root else ""
            try:
                rel_fp = (
                    os.path.relpath(os.path.realpath(target), canon_root).replace(os.sep, "/")
                    if canon_root and os.path.realpath(target).startswith(canon_root + os.sep)
                    else os.path.basename(target)
                )
            except ValueError:
                rel_fp = os.path.basename(target)

            if node_id in _PREFIX_REUSE_ARTIFACTS:
                kind = _PREFIX_REUSE_ARTIFACTS[node_id]
                art = None
                if canon_root:
                    art = read_artifact(db, artifact_type=kind, run_id=ctx.run_id, resource=canon_root)
                if not _artifact_says_something(art):
                    art = read_artifact(db, artifact_type=kind, run_id=ctx.run_id, resource=own)
                if _artifact_says_something(art):
                    if own != canon_root:
                        record_artifact(
                            db,
                            ctx.run_id,
                            kind,
                            _PREFIX_REUSE_PATHS[kind],
                            art,
                            metadata={
                                "resource": own,
                                "snapshot_id": getattr(ctx, "snapshot_id", ""),
                                "reused_from": canon_root or own,
                            },
                        )
                    ctx.active_node = node_id
                    return types.Content(
                        role="model",
                        parts=[
                            types.Part.from_text(
                                text=f"[{node_id}] Reused repo-root {kind} artifact for single-file campaign."
                            )
                        ],
                    )
                if kind == "summary":
                    det_payload = json.dumps(
                        {"overview": f"Single-file security audit target: {rel_fp}", "key_modules": [rel_fp], "tech_stack": []},
                        indent=2,
                    )
                else:
                    det_payload = json.dumps(
                        {"entry_points": [rel_fp], "trust_boundaries": [], "threats": [f"Audit untrusted inputs and sinks in {rel_fp}"]},
                        indent=2,
                    )
                record_artifact(
                    db,
                    ctx.run_id,
                    kind,
                    _PREFIX_REUSE_PATHS[kind],
                    det_payload,
                    metadata={"resource": own, "snapshot_id": getattr(ctx, "snapshot_id", "")},
                )
                ctx.active_node = node_id
                return types.Content(
                    role="model",
                    parts=[
                        types.Part.from_text(
                            text=f"[{node_id}] Recorded deterministic single-file {kind} for '{rel_fp}'."
                        )
                    ],
                )

            if node_id == "planner":
                det_plan = json.dumps(
                    {
                        "pass_number": int(getattr(ctx, "pass_index", 1) or 1),
                        "investigations": [
                            {
                                "title": f"Audit {rel_fp}",
                                "target_files": [rel_fp],
                                "priority": "high",
                                "focus_areas": ["input validation", "authorization", "dangerous sinks"],
                            }
                        ],
                        "rationale": f"Single-file campaign targeting {rel_fp}.",
                    },
                    indent=2,
                )
                record_artifact(
                    db,
                    ctx.run_id,
                    "plan",
                    "workspace/.structured/plan.json",
                    det_plan,
                    metadata={"resource": own, "snapshot_id": getattr(ctx, "snapshot_id", "")},
                )
                ctx.active_node = node_id
                return types.Content(
                    role="model",
                    parts=[
                        types.Part.from_text(
                            text=f"[{node_id}] Recorded deterministic single-file audit plan for '{rel_fp}'."
                        )
                    ],
                )
        except Exception:
            return None
        return None

    return _before_agent


def _make_deduplicator_skip_before_agent_callback(node_id: str):
    """Skips `deduplicator` LLM invocation when `ctx.sandbox is not None` and `<= 1` active finding exists."""

    def _before_agent(callback_context: Any = None):
        try:
            from core.context import current_run_context
            from core.paths import resolve_db_path

            ctx = current_run_context.get()
            if ctx is None or ctx.sandbox is None or not ctx.db_path or not ctx.run_id:
                return None
            db = resolve_db_path(ctx.db_path)
            if not os.path.exists(db):
                return None
            eff_pass = max(1, int(getattr(ctx, "pass_index", 1) or 1))
            open_ids = _active_campaign_finding_ids(
                db,
                str(getattr(ctx, "target_file", "") or ""),
                ctx.run_id,
                pass_index=eff_pass,
            )
            if len(open_ids) <= 1:
                ctx.active_node = node_id
                return types.Content(
                    role="model",
                    parts=[
                        types.Part.from_text(
                            text=f"[{node_id}] Skipped deduplication: {len(open_ids)} active finding(s) in scope."
                        )
                    ],
                )
        except Exception:
            return None
        return None

    return _before_agent


def _make_static_skip_before_agent_callback(
    node_id: str,
    *,
    stamp_status: str = "",
    emit_repro_verdict: bool = False,
):
    """Short-circuits `history` (whenever `ctx.sandbox is not None`) or `reproducer`
    (when `RunContext.sandbox` is an explicit static-only environment), preserving completion stamps."""
    norm_stamp = str(stamp_status or "").strip().lower()

    def _before_agent(callback_context: Any = None):
        try:
            from core.context import current_run_context

            ctx = current_run_context.get()
            if ctx is None or ctx.sandbox is None:
                return None
            if node_id != "history" and type(ctx.sandbox).__name__ not in (
                "StaticOnlyEnvironment",
                "StaticOnlySandbox",
            ):
                return None
            ctx.active_node = node_id
            if norm_stamp:
                apply_completion_stamp(ctx, norm_stamp, node_id)
            if node_id == "history" and ctx.db_path and ctx.run_id:
                try:
                    from core.database import record_artifact
                    from core.paths import resolve_db_path

                    db = resolve_db_path(ctx.db_path)
                    if os.path.exists(db):
                        own_res = str(getattr(ctx, "artifact_resource", "") or getattr(ctx, "target_file", "") or "")
                        record_artifact(
                            db,
                            ctx.run_id,
                            "workspace_file",
                            "workspace/historical_learnings.jsonl",
                            '{"history_status": "SKIPPED_STATIC_SANDBOX"}',
                            metadata={"resource": own_res, "snapshot_id": getattr(ctx, "snapshot_id", "")},
                        )
                except Exception:
                    pass
            if emit_repro_verdict:
                verdict_text = json.dumps({
                    "route": "failed_repro",
                    "reason": f"[{node_id}] Skipped dynamic reproduction in static-only sandbox mode.",
                })
                _store_callback_state_value(callback_context, "verdict", verdict_text)
                return types.Content(role="model", parts=[types.Part.from_text(text=verdict_text)])
            return types.Content(
                role="model",
                parts=[types.Part.from_text(text=f"[{node_id}] Skipped stage in static-only sandbox mode.")],
            )
        except Exception:
            return None

    return _before_agent


def _extract_callback_state_dict(callback_context: Any) -> dict[str, Any]:
    """Reads merged state dictionary from `callback_context` and `session` without raising."""
    merged: dict[str, Any] = {}
    if callback_context is None:
        return merged
    sess = getattr(callback_context, "session", None)
    if sess is None:
        sess = getattr(getattr(callback_context, "_invocation_context", None), "session", None)
    for holder in (sess, callback_context):
        if holder is None:
            continue
        st = getattr(holder, "state", None)
        if st is None:
            continue
        try:
            if hasattr(st, "to_dict"):
                merged.update(st.to_dict())
            elif isinstance(st, dict):
                merged.update(st)
        except Exception:
            pass
    return merged


def _store_callback_state_value(callback_context: Any, key: str, value: str) -> None:
    """Writes `key=value` into `callback_context.state` (persisting via ADK `state_delta`) and `session.state`."""
    if callback_context is None:
        return
    try:
        cb_state = getattr(callback_context, "state", None)
        if cb_state is not None:
            cb_state[key] = value
    except Exception:
        pass
    try:
        sess = getattr(callback_context, "session", None)
        if sess is None:
            sess = getattr(getattr(callback_context, "_invocation_context", None), "session", None)
        sess_state = getattr(sess, "state", None) if sess is not None else None
        if isinstance(sess_state, dict):
            sess_state[key] = value
    except Exception:
        pass


def _make_prefix_group_before_model_callback(
    node_id: str,
    *,
    base_instruction: str,
    stage_role_prompt: str,
    ancestor_chain: Sequence[str] = (),
    parent_id: Optional[str] = None,
    preserve_signatures: bool = True,
    prefix_group: str = "",
    enable_explicit_stem_cache: bool = False,
):
    """Builds the shared-prefix request envelope (`[S_base, T_shared, *inherited, u_stage, *own_turns]`).

    All stage-specific prompt instructions, experience lessons, campaign context/checklists/directives,
    active findings snapshots, and structured output reminders are combined deterministically into
    `u_stage` (`role="user"`), cached across Turns 1..N of `node_id` and recorded into session state so
    any downstream stage forking from `node_id` replays the exact byte-identical prefix.
    """
    exp_cached_blocks: dict[tuple[str, str, str], str] = {}
    exp_truncation_state = [False]
    ancestors = tuple(str(a) for a in ancestor_chain if a)
    state_key = f"{PREFIX_U_STATE_KEY_PREFIX}{node_id}"

    async def fork_before_model(callback_context: Any = None, llm_request: Any = None):
        if llm_request is None:
            return None
        try:
            from core.context import current_run_context

            ctx = current_run_context.get()
            if ctx is not None:
                ctx.active_node = node_id
        except Exception:
            ctx = None

        session = getattr(callback_context, "session", None) if callback_context is not None else None
        if session is None and callback_context is not None:
            session = getattr(getattr(callback_context, "_invocation_context", None), "session", None)
        events = getattr(session, "events", None) if session is not None else None
        state_dict = _extract_callback_state_dict(callback_context)

        inherited: list[types.Content] = []
        if ancestors and events:
            try:
                inherited = forked_prefix_contents(
                    events,
                    ancestors,
                    state=state_dict,
                    preserve_signatures=preserve_signatures,
                )
            except Exception:
                inherited = []

        own = list(getattr(llm_request, "contents", None) or [])
        has_opener = bool(
            own
            and getattr(own[0], "role", "") == "user"
            and not any(getattr(p, "function_response", None) for p in (getattr(own[0], "parts", None) or []))
        )
        opener_text = ""
        if has_opener:
            opener_text = "\n".join(
                str(getattr(p, "text", "") or "")
                for p in (getattr(own[0], "parts", None) or [])
                if getattr(p, "text", None) and not getattr(p, "thought", False)
            ).strip()
        own_tail = own[1:] if has_opener else own

        is_first_turn_of_attempt = not any(
            getattr(c, "role", "") == "model"
            or any(getattr(p, "function_response", None) for p in (getattr(c, "parts", None) or []))
            for c in own
        )

        slot = _node_context_slot(node_id)
        if slot is not None and not slot.get("continuations") and not slot.get("handoff"):
            stored_ho, ho_num = _stored_handoff(node_id)
            if stored_ho:
                slot["handoff"], slot["continuations"] = stored_ho, max(1, ho_num)
        continuations = int(slot.get("continuations") or 0) if slot else 0

        if (
            (node_id == "researcher" or node_id.startswith("researcher_"))
            and is_first_turn_of_attempt
            and continuations == 0
            and inherited
            and ctx is not None
        ):
            bc = getattr(ctx, "budget_controller", None)
            already_credited = bool(slot.get("credited_inherited_reads")) if slot is not None else False
            if bc is not None and not already_credited and events:
                try:
                    from core.budget import AUDIT_NODES

                    non_audit_ancestors = [a for a in ancestors if a not in AUDIT_NODES]
                    anc_to_credit = (
                        non_audit_ancestors
                        if int(getattr(bc, "audit_code_reads", 0) or 0) > 0
                        else list(ancestors)
                    )
                    if anc_to_credit:
                        credit_contents = forked_prefix_contents(
                            events,
                            anc_to_credit,
                            state=state_dict,
                            preserve_signatures=False,
                        )
                        stem_reads = _count_inherited_in_scope_code_reads(ctx, credit_contents)
                        if stem_reads > 0:
                            bc.audit_code_reads += stem_reads
                    if slot is not None:
                        slot["credited_inherited_reads"] = True
                except Exception:
                    pass

        u_stage_text: Optional[str] = None
        if not is_first_turn_of_attempt:
            cached_u = state_dict.get(state_key)
            if not cached_u and slot is not None:
                cached_u = slot.get("prefix_u_text")
            if isinstance(cached_u, str) and cached_u:
                u_stage_text = cached_u

        if not u_stage_text:
            sections: list[str] = [f"{ACTIVE_STAGE_HEADER_PREFIX}{node_id}]\n{stage_role_prompt}"]
            if inherited and parent_id:
                sections.append(
                    f"\n\n{FORK_NOTICE_MARKER} The conversation turns before this message are the "
                    f"'{parent_id}' stem's work in this campaign: its reading of the code, tool "
                    f"results, and structural context. Build on those file reads directly without "
                    f"repeating reads already in context unless you need a different line range; "
                    f"execute ONLY your own '{node_id}' stage assignment independently."
                )
            else:
                seed_content = _root_seed_user_content(events)
                seed_text = ""
                if seed_content is not None:
                    seed_text = "\n".join(
                        str(getattr(p, "text", "") or "")
                        for p in (getattr(seed_content, "parts", None) or [])
                        if getattr(p, "text", None)
                    ).strip()
                if seed_text:
                    sections.append(f"\n\n[CAMPAIGN TASK INPUT]\n{seed_text}")
                if opener_text and opener_text != seed_text:
                    sections.append(f"\n\n[UPSTREAM STAGE SUMMARY]\n{opener_text}")

            try:
                exp_block = _render_stage_experience_block(
                    node_id, exp_cached_blocks, exp_truncation_state
                )
                if exp_block:
                    sections.append(f"\n\n{exp_block}")
            except Exception:
                pass

            try:
                dir_blocks = _render_campaign_directive_blocks(node_id, existing_text="")
                if dir_blocks:
                    sections.extend(dir_blocks)
            except Exception:
                pass

            try:
                snap_block = ResilientLiteLlm.get_or_render_findings_snapshot(
                    f"prefix_stage:{node_id}:{continuations}"
                )
                if snap_block:
                    sections.append(snap_block)
            except Exception:
                pass

            if continuations and slot is not None:
                sections.append(_continuation_block(slot.get("handoff", ""), continuations))

            u_stage_text = "".join(sections)
            _store_callback_state_value(callback_context, state_key, u_stage_text)
            if slot is not None:
                slot["prefix_u_text"] = u_stage_text

        u_stage_content = types.Content(
            role="user", parts=[types.Part.from_text(text=u_stage_text)]
        )
        if inherited and getattr(inherited[-1], "role", "") == "user":
            merged_parts = list(getattr(inherited[-1], "parts", None) or []) + list(
                u_stage_content.parts or []
            )
            llm_request.contents = (
                list(inherited[:-1])
                + [types.Content(role="user", parts=merged_parts)]
                + own_tail
            )
        else:
            llm_request.contents = list(inherited) + [u_stage_content] + own_tail

        if getattr(llm_request, "config", None) is not None:
            llm_request.config.system_instruction = base_instruction

        if inherited:
            _observe("forked_requests")
            if (
                enable_explicit_stem_cache
                and preserve_signatures
                and prefix_group
                and getattr(inherited[-1], "role", "") == "model"
            ):
                setattr(
                    llm_request,
                    "_mantis_stem_cache",
                    {
                        "slot_key": f"{prefix_group}:{','.join(ancestors)}:{len(inherited)}",
                        "stem_len": len(inherited),
                    },
                )
            else:
                setattr(llm_request, "_mantis_stem_cache", None)
        else:
            setattr(llm_request, "_mantis_stem_cache", None)
        return None

    return fork_before_model


def _make_reporter_skip_before_agent_callback(node_id: str):
    """Short-circuits per-campaign `reporter` LLM execution when either:
    1. `ctx.defer_reporter` is True (multi-campaign sweeps, which run a single
       post-run consolidated report after cross-campaign deduplication), or
    2. the campaign is provably clean (`campaign_has_findings_to_triage` is False).

    Preserves the `reporter` node in the ADK event stream and `workflow.json`
    topology while saving thousands of no-op LLM calls across large sweeps.
    """
    def _before(callback_context=None):
        try:
            from core.context import current_run_context
            from core.database import read_artifact, record_artifact
            from core.paths import resolve_db_path

            ctx = current_run_context.get()
            if ctx is None:
                return None
            if bool(getattr(ctx, "defer_reporter", False)):
                ctx.active_node = node_id
                return types.Content(
                    role="model",
                    parts=[types.Part(text=(
                        f"[{node_id}] Deferred per-campaign report to post-run "
                        "consolidated reporting."
                    ))],
                )
            if not ctx.db_path or not ctx.run_id:
                return None
            db = resolve_db_path(ctx.db_path)
            target_scope = str(getattr(ctx, "target_file", "") or "")
            has_live = campaign_has_findings_to_triage(
                db, ctx.run_id, target_scope
            )
            if has_live is False:
                if not read_artifact(db, artifact_type="report", run_id=ctx.run_id):
                    clean_rpt = json.dumps({
                        "executive_summary": "No active vulnerability findings were confirmed in scope.",
                        "critical_findings_count": 0,
                        "recommendations": [],
                    }, indent=2)
                    record_artifact(
                        db, ctx.run_id, "report", "workspace/.structured/report.json", clean_rpt
                    )
                ctx.active_node = node_id
                return types.Content(
                    role="model",
                    parts=[types.Part(text=(
                        f"[{node_id}] Zero active findings in scope; recorded "
                        "clean report summary without LLM call."
                    ))],
                )
            if (
                has_live is True
                and getattr(ctx, "sandbox", None) is not None
                and not bool(getattr(ctx, "enable_narrative_report", False))
            ):
                from core.database import is_suppressed, read_findings

                eff_pass = max(1, int(getattr(ctx, "pass_index", 1) or 1))
                rows = read_findings(
                    db,
                    run_id=ctx.run_id,
                    scope_path=target_scope or None,
                    campaign=target_scope or None,
                    pass_index=eff_pass,
                )
                active_rows = [
                    r for r in rows if not is_suppressed(str(r.get("status") or ""))
                ]
                if active_rows:
                    if not read_artifact(db, artifact_type="report", run_id=ctx.run_id):
                        crit_n = sum(
                            1
                            for r in active_rows
                            if str(r.get("severity") or "").strip().upper() == "CRITICAL"
                        )
                        recs: list[str] = []
                        for r in active_rows:
                            rem = str(r.get("remediation") or r.get("mitigation") or "").strip()
                            if rem and rem not in recs:
                                recs.append(rem)
                            if len(recs) >= 10:
                                break
                        det_rpt = json.dumps(
                            {
                                "executive_summary": (
                                    f"Confirmed {len(active_rows)} active vulnerability finding(s) in scope."
                                ),
                                "critical_findings_count": crit_n,
                                "recommendations": recs,
                            },
                            indent=2,
                        )
                        record_artifact(
                            db, ctx.run_id, "report", "workspace/.structured/report.json", det_rpt
                        )
                    ctx.active_node = node_id
                    return types.Content(
                        role="model",
                        parts=[types.Part(text=(
                            f"[{node_id}] Recorded deterministic executive report summary "
                            f"for {len(active_rows)} finding(s) without LLM call."
                        ))],
                    )
        except Exception:
            return None
        return None

    return _before


def _make_reflector_after_model_callback(node_id: str):
    """Parses and persists the <experience> blocks emitted by the reflector.

    A reply that carries no block -- including the explicit `NO_ENTRY`
    answer -- touches nothing; memory is written only through
    core.memory.record_reflection_output's evidence gate.
    """

    def _after_model(callback_context: Any = None, llm_response: Any = None) -> None:
        try:
            if llm_response is None:
                return None
            parts = getattr(getattr(llm_response, "content", None), "parts", None) or []
            text = "\n".join(
                str(getattr(p, "text", "") or "")
                for p in parts
                if getattr(p, "text", None) and not getattr(p, "thought", False)
            )
            if not text or "<experience>" not in text.lower():
                return None
            from core.context import current_run_context
            from core.memory import record_reflection_output
            from core.paths import resolve_db_path

            ctx = current_run_context.get()
            if ctx is None or not ctx.db_path or not ctx.run_id:
                return None
            record_reflection_output(
                resolve_db_path(ctx.db_path),
                ctx.run_id,
                text,
            )
        except Exception:
            pass
        return None

    return _after_model


def create_findings_gate(node_id: str):
    """Deterministic zero-findings short-circuit after the researcher.

    Most campaigns in a file-by-file sweep are clean, yet the graph still
    walked deduplicator -> reviewer -> calibrator -> reflector for them.
    This gate reads the campaign's findings and routes "clean" (straight to
    the reporter) only when the researcher recorded nothing worth triaging.
    Everything else -- findings present, no database, a read error -- falls
    through to the default route and the full pipeline runs as before.
    """
    async def _gate(ctx: Context, node_input: Any = None):
        rc = _stamp_active_node(node_id)
        db_path = (getattr(rc, "db_path", None) or ctx.state.get("db_path") or "")
        run_id = (getattr(rc, "run_id", None) or ctx.state.get("run_id") or "")
        target_file = (getattr(rc, "target_file", None) or "")

        if campaign_has_findings_to_triage(db_path, run_id, target_file) is False:
            print(f"[{node_id}] Zero findings recorded for this campaign; skipping triage stages.", flush=True)
            return adk.Event(output="No findings recorded for this campaign.", route="clean")
        return adk.Event(output=node_input, route=DEFAULT_ROUTE)

    return node(_gate, name=node_id)


def create_structural_index_node(node_id: str):
    """Deterministic tree-sitter structural index build.

    This stage used to be an LLM agent hand-writing a JSONL index that no
    downstream tool ever queried. It now builds the real catalog the
    structural navigation tools (find_symbol, find_callers, find_callees,
    get_function_boundary) read. Fail-safe: any failure publishes nothing
    and the campaign proceeds exactly as it would without an index.
    """
    async def _build(ctx: Context, node_input: Any = None):
        rc = _stamp_active_node(node_id)
        try:
            import asyncio
            from core.paths import resolve_db_path
            from core.structural_index import build_structural_index, git_snapshot_id, state_dir_for_db

            # The operator-declared repository root outranks the jail: a
            # single-file scan's jail is the file's parent directory, and
            # indexing that would re-root the shared catalog at a
            # subdirectory -- cross-directory callers vanish for the
            # researcher during the scan and for every catalog consumer
            # after it.
            jail = getattr(rc, "path_root", "") or getattr(rc, "jail_dir", None) or ""
            db_path = (getattr(rc, "db_path", None) or ctx.state.get("db_path") or "")
            if not jail or not db_path:
                msg = "Structural index skipped: no target checkout in context."
                print(f"[{node_id}] {msg}", flush=True)
                return adk.Event(output=msg, route=DEFAULT_ROUTE)
            state_dir = state_dir_for_db(resolve_db_path(db_path))
            # Pinned, a rebuild of the same clean checkout reuses the
            # published catalog instead of re-resolving every call edge.
            # Offloaded to a worker thread so tree-sitter parsing and SQLite
            # catalog writes do not block the asyncio event loop.
            def _build_sync() -> dict[str, Any]:
                snap = getattr(rc, "snapshot_id", "") or git_snapshot_id(jail)
                return build_structural_index(jail, state_dir, snap)

            res = await asyncio.to_thread(_build_sync)
            cov = res.get("coverage") or {}
            units = res.get("units") or {}
            summary = (
                f"Structural index {res.get('status', 'failed')}: "
                f"{cov.get('indexed_files', 0)}/{cov.get('total_files', 0)} files indexed, "
                f"{units.get('total', 0)} units ({units.get('reused', 0)} reused)."
            )
            print(f"[{node_id}] {summary}", flush=True)
            return adk.Event(output=summary, route=DEFAULT_ROUTE)
        except Exception as e:
            msg = (
                f"Structural index unavailable ({type(e).__name__}); "
                "downstream stages fall back to read_file."
            )
            print(f"[{node_id}] {msg}", flush=True)
            return adk.Event(output=msg, route=DEFAULT_ROUTE)

    return node(_build, name=node_id)


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
    resource: Optional[str] = None,
) -> None:
    from datetime import datetime, timezone
    from core.database import read_artifact, record_artifact

    f_id = finding.get("id")
    art_path = f"workspace/findings/{f_id}.json"
    eff_res = str(resource) if resource is not None else None

    existing_raw = read_artifact(db_path, filepath=art_path, run_id=run_id, resource=eff_res)
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
        metadata={"resource": eff_res if eff_res is not None else data.get("filepath", ""), "agent_authored": True},
    )


def create_calibrator_node(
    node_id: str,
    llm_model: Any,
    system_instruction: str,
):
    """Creates a deterministic per-finding calibration loop node with structured output schemas."""
    async def _calibrate(ctx: Context, node_input: Any = None):
        from core.database import (
            read_findings,
            update_finding_calibration,
            record_calibration,
            read_artifact,
        )
        from core.schemas import FindingCalibration

        run_ctx = _stamp_active_node(node_id)
        db_path = (getattr(run_ctx, "db_path", None) or ctx.state.get("db_path") or "knowledge.db")
        try:
            from core.paths import resolve_db_path

            if db_path and not os.path.isabs(str(db_path)):
                db_path = resolve_db_path(str(db_path))
        except Exception:
            pass
        run_id = (getattr(run_ctx, "run_id", None) or ctx.state.get("run_id") or "")
        target_file = str(getattr(run_ctx, "target_file", None) or ctx.state.get("filepath") or "")
        pass_idx = max(1, int(getattr(run_ctx, "pass_index", 1) or 1)) if run_ctx is not None else None
        own_res = str(
            (getattr(run_ctx, "artifact_resource", "") if run_ctx is not None else "")
            or target_file
            or ""
        )

        findings = []
        if db_path and os.path.exists(db_path):
            try:
                # Campaign scope, not run scope: multi-target runs share one
                # run_id, and an unscoped read re-calibrated every earlier
                # campaign's findings on each later campaign.
                findings = read_findings(
                    db_path,
                    run_id=run_id,
                    scope_path=target_file or None,
                    campaign=target_file or None,
                    pass_index=pass_idx,
                )
                if not findings and not run_id:
                    findings = read_findings(
                        db_path,
                        scope_path=target_file or None,
                        campaign=target_file or None,
                        pass_index=pass_idx,
                    )
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
                art_raw = read_artifact(
                    db_path, filepath=f"workspace/findings/{f.get('id')}.json", run_id=run_id, resource=own_res
                )
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
            tm_text = read_artifact(db_path, artifact_type="threat_model", run_id=run_id, resource=own_res) or ""
            if not tm_text:
                tm_text = read_artifact(db_path, filepath="workspace/kb/THREAT_MODEL.md", run_id=run_id, resource=own_res) or ""

        calibrated_results: list[FindingCalibration] = []

        from core.config import structured_llm_request

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

            # Registered through append_tools, not GenerateContentConfig(tools=):
            # the LiteLlm adapter drops a bare BaseTool there (see
            # core.config.structured_llm_request).
            req = structured_llm_request(finding_prompt, system_instruction, FindingCalibration)

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
                run_ctx.budget_controller.record_tokens(
                    total_t, cached_t,
                    prompt_count=int(getattr(usage_meta, "prompt_token_count", 0) or 0),
                    output_count=int(getattr(usage_meta, "candidates_token_count", 0) or 0))

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
                    scope_path=target_file or None,
                    campaign=target_file or None,
                )

                record_calibration(
                    db_path,
                    f_path or target_file,
                    calib.mantis_risk_score,
                    calib.reasoning,
                    run_id=run_id,
                )

                _update_finding_artifact(db_path, run_id, f, calib, resource=own_res)
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
            elif new_type != base_type:
                merged["sandbox"] = dict(v)
                if "options" not in merged["sandbox"] or not isinstance(merged["sandbox"]["options"], dict):
                    merged["sandbox"]["options"] = {}
            else:
                merged["sandbox"] = dict(base_sb)
                for sb_k, sb_v in v.items():
                    if sb_k != "options":
                        merged["sandbox"][sb_k] = sb_v
                merged["sandbox"]["type"] = new_type
                merged["sandbox"]["options"] = merge_config_dicts(
                    base_sb.get("options", {}) if isinstance(base_sb.get("options"), dict) else {},
                    v.get("options", {}) if isinstance(v.get("options"), dict) else {},
                )
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
    base_cfg = raw_json.get("config") if isinstance(raw_json.get("config"), dict) else {}
    overlay_meta: dict[str, Any] = {
        "base_timeout_was_shipped_180": (
            os.path.basename(abs_json) == "workflow.json" and base_cfg.get("timeout") == 180
        ),
        "local_timeout_set": False,
        "local_reasoning_effort": None,
    }
    ignore_local = str(os.environ.get("MANTIS_IGNORE_LOCAL_CONFIG", "") or "").strip().lower() in (
        "1",
        "true",
        "yes",
    )
    if load_local and not ignore_local:
        for cand in local_candidates:
            if os.path.exists(cand) and os.path.abspath(cand) != abs_json:
                try:
                    with open(cand, 'r', encoding='utf-8') as lf:
                        local_data = json.load(lf)
                except json.JSONDecodeError as je:
                    raise ConfigValidationError(
                        f"Malformed JSON in local configuration overlay '{cand}' "
                        f"(line {je.lineno}, column {je.colno}: {je.msg}). "
                        "Fix or remove the file, or set MANTIS_IGNORE_LOCAL_CONFIG=1."
                    ) from je
                except OSError as oe:
                    raise ConfigValidationError(
                        f"Could not read local configuration overlay '{cand}': {oe}"
                    ) from oe
                if not isinstance(local_data, dict):
                    raise ConfigValidationError(
                        f"Local configuration overlay '{cand}' must be a JSON object, "
                        f"got {type(local_data).__name__}."
                    )
                local_cfg = local_data.get("config") if isinstance(local_data.get("config"), dict) else {}
                if "timeout" in local_cfg or "timeout" in local_data:
                    overlay_meta["local_timeout_set"] = True
                if local_cfg.get("reasoning_effort") or local_data.get("reasoning_effort"):
                    overlay_meta["local_reasoning_effort"] = (
                        local_cfg.get("reasoning_effort") or local_data.get("reasoning_effort")
                    )
                if "config" in local_data and isinstance(local_data["config"], dict):
                    raw_json["config"] = merge_config_dicts(
                        raw_json.get("config", {}), local_data["config"]
                    )
                # Also check top-level config keys placed directly at root of overlay
                for top_k in (
                    "sandbox",
                    "default_model",
                    "fast_model",
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

    raw_json["_overlay_meta"] = overlay_meta
    return raw_json, base_dir


class _BarrierAgent(adk.Agent):
    """An agent node that waits for ALL of its predecessors before running.

    ADK's Workflow consults the private ``_requires_all_predecessors`` property
    (the same one ``google.adk.workflow.JoinNode`` sets) to decide whether a
    node fires on the first incoming trigger or buffers until every
    predecessor has COMPLETED. Fan-in nodes that are reached only by
    unconditional edges (two parallel researcher arms converging at dedupe)
    use this class so the join happens once instead of once per arm.

    Known consequence: if any predecessor fails, the barrier never fires and
    nothing downstream of it runs. That matches ADK's JoinNode semantics.

    Defined at module level on purpose: tests spy on ``adk.Agent`` by swapping
    it for a plain function, and a class statement inside the loader would
    then try to use that function as a metaclass.
    """

    @property
    def _requires_all_predecessors(self) -> bool:
        return True


def validate_workflow_topology(
    spec: WorkflowSpec,
    *,
    strict_synthesis: bool = False,
    require_promotion_gate: Optional[bool] = None,
) -> tuple[list[str], list[str]]:
    """Pure static topology & promotion-path validator for WorkflowSpec.

    When `strict_synthesis=True`, raises `ValueError` on any topology or
    missing-promotion-path violation so the LLM synthesis compiler-feedback
    loop repairs the graph instead of emitting a dead-end workflow.
    """
    errors: list[str] = []
    warnings: list[str] = []

    nodes_by_id = {n.id: n for n in spec.nodes}
    adj: dict[str, set[str]] = {"START": set(), **{nid: set() for nid in nodes_by_id}}
    seen_pairs: set[tuple[str, str]] = set()
    classifier_out_routes: dict[str, set[str]] = {
        n.id: set() for n in spec.nodes if isinstance(n, ClassifierNode)
    }

    for edge_cfg in spec.edges:
        f_id = edge_cfg.from_node
        t_id = edge_cfg.to_node
        route = edge_cfg.on
        if f_id != "START" and f_id not in nodes_by_id:
            errors.append(f"Edge references unknown from_node: '{f_id}'")
            continue
        if t_id not in nodes_by_id:
            errors.append(f"Edge references unknown to_node: '{t_id}'")
            continue
        if (f_id, t_id) in seen_pairs:
            errors.append(f"Duplicate edge from '{f_id}' to '{t_id}'.")
        seen_pairs.add((f_id, t_id))
        adj.setdefault(f_id, set()).add(t_id)

        if isinstance(route, list) and DEFAULT_ROUTE in route:
            errors.append(
                f"Edge from '{f_id}' to '{t_id}' cannot combine '{DEFAULT_ROUTE}' in a route list."
            )
        if f_id in classifier_out_routes:
            if isinstance(route, list):
                classifier_out_routes[f_id].update(str(r) for r in route)
            elif route is not None:
                classifier_out_routes[f_id].add(str(route))

    if nodes_by_id:
        out_sources = {e.from_node for e in spec.edges if e.from_node != "START"}
        terminal_nodes = set(nodes_by_id.keys()) - out_sources
        if len(terminal_nodes) == 0:
            errors.append("Workflow must have at least one terminal sink node.")
        elif len(terminal_nodes) > 1:
            msg = (
                f"Workflow has multiple terminal sink nodes {sorted(terminal_nodes)}; "
                "converge all paths onto a single terminal sink node (e.g. 'reporter')."
            )
            if strict_synthesis:
                errors.append(msg)
            else:
                warnings.append(msg)

        # Reachability from START
        visited: set[str] = set()
        queue = list(adj.get("START", ()))
        while queue:
            cur = queue.pop(0)
            if cur in visited:
                continue
            visited.add(cur)
            for nxt in adj.get(cur, ()):
                if nxt not in visited:
                    queue.append(nxt)
        unreachable = sorted(set(nodes_by_id.keys()) - visited)
        if unreachable:
            msg = f"Unreachable node(s) from START: {unreachable}."
            if strict_synthesis:
                errors.append(msg)
            else:
                warnings.append(msg)

    for cid, used_routes in classifier_out_routes.items():
        if DEFAULT_ROUTE not in used_routes:
            msg = f"Classifier '{cid}' has no '{DEFAULT_ROUTE}' fallback edge."
            if strict_synthesis:
                errors.append(msg)
            else:
                warnings.append(msg)

    # Guaranteed finding promotion path check (synthesizer-1):
    reporting_nodes = [
        n.id
        for n in spec.nodes
        if isinstance(n, AgentNode) and "report_findings" in (n.tools or [])
    ]
    if reporting_nodes:
        has_verdict_classifier_pair = False
        has_stamp_node = False
        for n in spec.nodes:
            if not isinstance(n, AgentNode):
                continue
            if str(n.on_enter_status or "").strip().lower() in NODE_STAMP_STATUSES:
                has_stamp_node = True
            if n.output_schema in ("ReviewVerdict", "CriticVerdict"):
                for target_id in adj.get(n.id, ()):
                    if isinstance(nodes_by_id.get(target_id), ClassifierNode):
                        has_verdict_classifier_pair = True
        if not (has_verdict_classifier_pair or has_stamp_node):
            msg = (
                f"Workflow declares 'report_findings' on {reporting_nodes} without any finding "
                "promotion gate: include a 'ReviewVerdict'/'CriticVerdict' reviewer/critic node "
                "followed by a classifier node (e.g. 'review_decision'), or a stage with "
                "on_enter_status='static_confirmed', so confirmed findings exit 'reported' status."
            )
            check_promo = strict_synthesis if require_promotion_gate is None else bool(require_promotion_gate)
            if check_promo:
                errors.append(msg)
            else:
                warnings.append(msg)

    if strict_synthesis and errors:
        raise ValueError("Graph topology validation failed:\n" + "\n".join(errors))
    return errors, warnings


# Low-effort mechanical stages that route to `config.fast_model` when the
# operator configures one and the node does not pin its own `model`. On the
# default Vertex Gemini route (with `fast_model` unset and no custom API base
# or global model override), they default to `DEFAULT_VERTEX_FAST_MODEL`
# (`vertex_ai/gemini-3.5-flash-lite`), preserving campaign cost and harness
# fingerprints while still allowing non-Vertex `default_model` configurations
# to run with zero Vertex dependencies.
_FAST_TIER_NODE_IDS = frozenset({"history", "deduplicator"})


def _resolve_fast_tier_default(
    default_model: str,
    fast_model: Optional[str],
    model_override: Optional[str],
    api_base: Optional[str],
) -> str:
    if fast_model:
        return fast_model
    if model_override or (os.environ.get("MANTIS_MODEL") or os.environ.get("MODEL_ID") or "").strip():
        return default_model
    if api_base or (os.environ.get("LLM_API_BASE") or "").strip():
        return default_model
    resolved_default = resolve_model_id(None, default_model, model_override)
    if resolved_default.startswith("vertex_ai/gemini-"):
        return DEFAULT_VERTEX_FAST_MODEL
    return default_model


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
    overlay_meta = raw_json.pop("_overlay_meta", {}) if isinstance(raw_json, dict) else {}
    validate_llm_env_vars()

    spec = WorkflowSpec.model_validate(raw_json)

    # Shipped `workflow.json` carries a legacy `timeout: 180` that predates
    # effort-scaled thinking timeouts (`REQUEST_TIMEOUT_BY_EFFORT`, up to 1800s).
    # Clear it when neither `workflow.local.json` nor `--timeout` explicitly set
    # a timeout so `default_request_timeout(model, effort)` governs.
    if (
        overlay_meta.get("base_timeout_was_shipped_180")
        and not overlay_meta.get("local_timeout_set")
        and timeout_override is None
    ):
        spec.config.timeout = None

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
        base_sb_dump = spec.config.sandbox.model_dump()
        if isinstance(sandbox_override, str):
            merged_sb = merge_config_dicts(
                {"sandbox": base_sb_dump}, {"sandbox": {"type": sandbox_override}}
            )["sandbox"]
            profiles = spec.config.sandbox_profiles
            if (
                sandbox_override != spec.config.sandbox.type
                and isinstance(profiles, dict)
                and isinstance(profiles.get(sandbox_override), dict)
            ):
                merged_sb = merge_config_dicts(
                    {"sandbox": merged_sb},
                    {"sandbox": {"type": sandbox_override, **profiles[sandbox_override]}},
                )["sandbox"]
            spec.config.sandbox = SandboxConfig.model_validate(merged_sb)
        elif isinstance(sandbox_override, dict):
            merged_sb = merge_config_dicts(
                {"sandbox": base_sb_dump}, {"sandbox": sandbox_override}
            )["sandbox"]
            spec.config.sandbox = SandboxConfig.model_validate(merged_sb)

    errors = []

    if spec.config.sandbox.type not in SANDBOXES and spec.config.sandbox.type not in ENVIRONMENTS:
        errors.append(
            f"Unknown sandbox type '{spec.config.sandbox.type}'. Available: {sorted(ENVIRONMENTS)}"
        )

    # Tools this deployment declared for itself.
    #
    # Built HERE, after the sandbox type is known and before any node resolves its tool
    # list, because an executable tool's permission depends on the effective backend. A
    # Lane B tool whose floor is not met fails the graph load; it is never quietly
    # dropped, because the run would then produce a report that reflects less analysis
    # than was configured while looking exactly like one that had it all.
    #
    # Custom tools are merged UNDER the built-ins, and a name collision is refused
    # inside build_custom_tools rather than resolved here. Letting a declared tool win a
    # collision would point an audited chokepoint at unreviewed code; letting the
    # built-in win silently would give the operator a tool that is not the one they
    # declared.
    custom_tools: dict = {}
    try:
        from core.custom_tools import build_custom_tools

        custom_tools = build_custom_tools(
            spec.config.model_dump(),
            builtin_names=tuple(TOOLS),
            effective_sandbox=spec.config.sandbox.type,
        )
    except Exception as e:
        errors.append(f"Custom tools: {e}")

    resolvable_tools = {**TOOLS, **custom_tools}

    unconditional_in_edges: dict[str, int] = {}
    conditional_in_edges: dict[str, int] = {}
    for edge_cfg in spec.edges:
        if edge_cfg.on is None:
            unconditional_in_edges[edge_cfg.to_node] = (
                unconditional_in_edges.get(edge_cfg.to_node, 0) + 1
            )
        else:
            conditional_in_edges[edge_cfg.to_node] = (
                conditional_in_edges.get(edge_cfg.to_node, 0) + 1
            )

    nodes = {}
    node_specs = {}
    declared_node_ids = set()
    # Agent nodes by id, for `fork_from`: a fork names a stage whose
    # transcript exists, i.e. another agent node of this graph.
    agent_nodes_by_id: dict[str, AgentNode] = {
        n.id: n for n in spec.nodes if isinstance(n, AgentNode)
    }
    agent_node_ids = set(agent_nodes_by_id.keys())
    # Pre-resolve per-node model IDs, shared tool unions, and canonical reasoning_effort
    # for prefix_group nodes (Vertex Gemini binds thinkingLevel into its implicit KV-cache key).
    pre_resolved_models: dict[str, str] = {}
    prefix_group_tool_names: dict[str, list[str]] = {}
    prefix_group_nodes: dict[str, list[AgentNode]] = {}
    prefix_group_reasoning_effort: dict[str, Optional[str]] = {}
    for n_pre in spec.nodes:
        if not isinstance(n_pre, AgentNode) or n_pre.id == "structural_index":
            continue
        n_def_model = (
            _resolve_fast_tier_default(
                spec.config.default_model,
                spec.config.fast_model,
                model_override,
                n_pre.api_base or spec.config.api_base,
            )
            if (not n_pre.model and n_pre.id in _FAST_TIER_NODE_IDS)
            else spec.config.default_model
        )
        pre_resolved_models[n_pre.id] = resolve_model_id(
            n_pre.model, n_def_model, model_override
        )
        if n_pre.prefix_group is not None and not n_pre.system_prompt:
            pg_name = n_pre.prefix_group.strip()
            if not pg_name:
                errors.append(f"Node {n_pre.id}: prefix_group must be a non-empty string when set.")
            else:
                prefix_group_nodes.setdefault(pg_name, []).append(n_pre)
                bucket = prefix_group_tool_names.setdefault(pg_name, [])
                for t_name in n_pre.tools:
                    if t_name not in bucket:
                        bucket.append(t_name)
    for pg_name, t_list in list(prefix_group_tool_names.items()):
        prefix_group_tool_names[pg_name] = sorted(t_list)
    for pg_name, pg_members in prefix_group_nodes.items():
        member_ids = {m.id for m in pg_members}
        root_member = next(
            (m for m in pg_members if not m.fork_from or m.fork_from not in member_ids),
            pg_members[0],
        )
        prefix_group_reasoning_effort[pg_name] = (
            root_member.reasoning_effort or spec.config.reasoning_effort
        )

    # Material for the harness fingerprint (compute_harness_fingerprint):
    # every node by id, and for agent nodes the resolved tools, model and
    # final instruction. Gathered here because this loop is the only place
    # the final instruction text exists.
    harness_nodes: list[dict] = []
    resolved_node_models: list[str] = []

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
            harness_nodes.append({"id": node_id})
            if len(node_cfg.routes) != len(set(node_cfg.routes)):
                errors.append(f"Classifier '{node_id}' routes contain duplicates: {node_cfg.routes}.")
            if node_id == "findings_gate":
                # Deterministic DB-backed gate, not a verdict parser; same
                # interception-by-id pattern as the calibrator node.
                nodes[node_id] = create_findings_gate(node_id)
            else:
                nodes[node_id] = create_classifier(node_id, node_cfg.routes, max_visits=node_cfg.max_visits)
            allowed_routes = set(node_cfg.routes) | {DEFAULT_ROUTE}
            if node_cfg.max_visits > 1:
                allowed_routes.add("exceeded")
            node_specs[node_id] = {"type": "classifier", "routes": allowed_routes}
            continue

        if isinstance(node_cfg, AgentNode):
            if node_id == "structural_index":
                # Deterministic replacement, intercepted by id so the
                # workflow.json node and topology stay untouched. No model
                # or tools are built: the stage makes no LLM calls.
                nodes[node_id] = create_structural_index_node(node_id)
                node_specs[node_id] = {"type": "agent"}
                harness_nodes.append({"id": node_id})
                continue
            node_has_error = False
            node_default_model = (
                _resolve_fast_tier_default(
                    spec.config.default_model,
                    spec.config.fast_model,
                    model_override,
                    node_cfg.api_base or spec.config.api_base,
                )
                if (not node_cfg.model and node_id in _FAST_TIER_NODE_IDS)
                else spec.config.default_model
            )
            # What this node will call, as the identity the fingerprint
            # stamps: resolved through the same precedence get_llm_kwargs
            # applies, and available whether or not the credentials it goes
            # on to need are present.
            node_model_id = resolve_model_id(
                node_cfg.model, node_default_model, model_override
            )
            if node_model_id not in resolved_node_models:
                resolved_node_models.append(node_model_id)
            node_pg = None if node_cfg.system_prompt else ((node_cfg.prefix_group or "").strip() or None)
            effective_reasoning_effort = node_cfg.reasoning_effort
            if node_pg and node_pg in prefix_group_reasoning_effort:
                pg_effort = prefix_group_reasoning_effort[node_pg]
                node_eff = node_cfg.reasoning_effort or spec.config.reasoning_effort
                if node_eff != pg_effort:
                    print(
                        f"[graph_loader] node '{node_id}' in prefix_group '{node_pg}': "
                        f"normalizing reasoning_effort '{node_eff}' -> '{pg_effort}' to preserve "
                        "provider KV-cache prefix parity.",
                        file=sys.stderr,
                    )
                effective_reasoning_effort = pg_effort

            # The exact call graph build used to make eagerly, frozen as a
            # zero-argument resolver so it can run either here (normal path)
            # or inside DeferredEnvLiteLlm at first LLM call (hermetic path).
            # Freezing the arguments NOW matters: spec/node config is loop
            # state that must not be re-read later through a stale closure.
            effective_node_api_base = api_base_override or node_cfg.api_base
            effective_node_timeout = (
                timeout_override if timeout_override is not None else node_cfg.timeout
            )
            # Operator-wide reasoning effort (CLI `--reasoning-effort`, env
            # `REASONING_EFFORT`, or `workflow.local.json`) applies to EVERY node
            # uniformly, so it beats per-node values without breaking
            # prefix_group KV-cache parity. Otherwise the prefix_group-normalized
            # effort (or the node's own) is used.
            global_effort_override = (
                reasoning_effort_override
                or (os.environ.get("REASONING_EFFORT") or "").strip()
                or overlay_meta.get("local_reasoning_effort")
            )
            effective_node_effort = global_effort_override or effective_reasoning_effort
            llm_kwargs_resolver = functools.partial(
                get_llm_kwargs,
                node_cfg.model,
                node_default_model,
                api_base=effective_node_api_base,
                default_api_base=spec.config.api_base,
                timeout=effective_node_timeout,
                default_timeout=spec.config.timeout,
                reasoning_effort=effective_node_effort,
                default_reasoning_effort=spec.config.reasoning_effort,
                global_model_override=model_override,
                config=spec.config.model_dump(),
                explicit_reasoning_effort=bool(reasoning_effort_override),
            )
            deferred_env = False
            llm_kwargs = {}
            try:
                _, llm_kwargs = llm_kwargs_resolver()
            except ConfigValidationError:
                raise
            except ValueError as e:
                if "VERTEXAI_PROJECT or GOOGLE_CLOUD_PROJECT" in str(e):
                    # Missing cloud credentials, and ONLY missing cloud
                    # credentials, defer to call time. Building a graph is
                    # pure local data flow; holding a GCP project is only
                    # needed to actually call the model. Coupling them made 9
                    # hermetic tests fail at build time without ever intending
                    # an LLM call. Every other error (unknown model syntax,
                    # bad timeout, malformed config) still fails the build
                    # here, loudly -- deferral is not a general error dump.
                    deferred_env = True
                else:
                    errors.append(f"Node {node_id}: {str(e)}")
                    node_has_error = True
            except Exception as e:
                errors.append(f"Node {node_id}: {str(e)}")
                node_has_error = True

            instruction = ""
            agent_tools = []
            tools_list = []
            for t in node_cfg.tools:
                if t in resolvable_tools:
                    tools_list.append(resolvable_tools[t])
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
                elif node_cfg.output_schema == "ReviewVerdict" and ExtendedReviewVerdict is not None:
                    # P6: bind the extended schema so the reviewer CAN return
                    # per-finding verdicts. This must happen at bind time, not
                    # in response sanitization: ADK re-validates the agent's
                    # final text against the bound schema class
                    # (validate_schema -> model_validate_json), and the
                    # canonical ReviewVerdict is extra="forbid" -- a response
                    # carrying finding_verdicts would be rejected by the
                    # runtime itself before any harness code saw it. The
                    # extended model's finding_verdicts defaults to [], so
                    # every wire-format-valid ReviewVerdict remains valid
                    # unchanged (INV-6); when config could not define the
                    # extended model, the canonical schema stays bound and
                    # behavior is exactly pre-P6.
                    schema_cls = ExtendedReviewVerdict
                elif node_cfg.output_schema == "CriticVerdict" and ExtendedCriticVerdict is not None:
                    schema_cls = ExtendedCriticVerdict
            ancestor_chain: list[str] = []
            if node_cfg.fork_from is not None:
                if node_cfg.fork_from == node_id:
                    errors.append(f"Node {node_id}: fork_from names itself.")
                    node_has_error = True
                elif node_cfg.fork_from not in agent_node_ids:
                    errors.append(f"Node {node_id}: fork_from '{node_cfg.fork_from}' is not an agent node of this graph.")
                    node_has_error = True
                else:
                    seen_anc: list[str] = []
                    cur_fk: Optional[str] = node_cfg.fork_from
                    while cur_fk:
                        if cur_fk == node_id or cur_fk in seen_anc:
                            errors.append(f"Node {node_id}: fork_from cycle detected involving '{cur_fk}'.")
                            node_has_error = True
                            break
                        if cur_fk not in agent_nodes_by_id:
                            errors.append(f"Node {node_id}: transitive fork_from '{cur_fk}' is not an agent node of this graph.")
                            node_has_error = True
                            break
                        seen_anc.append(cur_fk)
                        cur_fk = agent_nodes_by_id[cur_fk].fork_from
                    ancestor_chain = list(reversed(seen_anc))

            if node_has_error:
                continue

            prefix_group = None if node_cfg.system_prompt else ((node_cfg.prefix_group or "").strip() or None)
            is_prefix_group = bool(prefix_group)

            # Invariant: Every agent node MUST include the untrusted code audit guard (covers both skill and system_prompt)
            guard_text = UNTRUSTED_CODE_AUDIT_GUARD.strip()
            if not is_prefix_group and guard_text not in instruction:
                instruction = f"{instruction.rstrip()}\n\n{guard_text}"

            model_extra_kwargs: dict[str, Any] = {}
            if is_prefix_group:
                model_extra_kwargs["preserve_system_prefix"] = True
                if schema_cls is not None:
                    model_extra_kwargs["output_schema_override"] = schema_cls

            # One model instance per node, built here so the calibrator path
            # and the regular agent path share the hermetic deferral: when
            # credentials were missing at build time, DeferredEnvLiteLlm
            # carries the frozen resolver and runs it (fail-closed) on the
            # first real LLM call; the model string passed at construction is
            # only a display placeholder until then.
            if deferred_env:
                model_inst = DeferredEnvLiteLlm(
                    model=str(node_cfg.model or spec.config.default_model or DEFAULT_MODEL),
                    env_resolver=llm_kwargs_resolver,
                    **model_extra_kwargs,
                )
            else:
                model_inst = LiteLlm(**llm_kwargs, **model_extra_kwargs)

            if node_id == "calibrator" or (node_cfg.skill and "mantis-calibrate" in node_cfg.skill):
                if guard_text not in instruction:
                    instruction = f"{instruction.rstrip()}\n\n{guard_text}"
                nodes[node_id] = create_calibrator_node(
                    node_id=node_id,
                    llm_model=model_inst,
                    system_instruction=instruction,
                )
                node_specs[node_id] = {"type": "agent"}
                harness_nodes.append({
                    "id": node_id,
                    "tools": list(node_cfg.tools),
                    "model": node_model_id,
                    "instruction": instruction,
                })
                continue

            if is_prefix_group and not node_cfg.system_prompt:
                if node_id == "architect":
                    instruction = f"{instruction.rstrip()}\n{ARCHITECT_PREFIX_STEM_ADDENDUM}"
                elif node_id == "threat_modeler":
                    instruction = f"{instruction.rstrip()}\n{THREAT_MODELER_PREFIX_STEM_ADDENDUM}"
                elif node_id == "planner":
                    instruction = f"{instruction.rstrip()}\n{PLANNER_PREFIX_STEM_ADDENDUM}"
                if node_cfg.fork_from:
                    instruction = f"{instruction.rstrip()}\n{PREFIX_FORKED_STAGE_ADDENDUM}"

            if schema_cls:
                if is_prefix_group:
                    instruction = (
                        f"{instruction.rstrip()}\n\n"
                        f"CRITICAL TERMINATION CONTRACT: When your analysis for this stage is complete, "
                        f"emit your final verdict directly as raw JSON response text conforming to '{node_cfg.output_schema}' "
                        f"(e.g. {{\"route\": \"...\", \"reason\": \"...\"}}). "
                        f"Do NOT call write_file, run_sandbox, set_model_response, or any other tool to signal completion, "
                        f"and do NOT write dummy marker or verdict files (e.g. do NOT write 'verdict.json', 'done.txt', or 'status.json'). "
                        f"Also do NOT run probe shell commands (e.g. do NOT run 'echo done', 'echo 1', 'true', or 'exit 0')."
                    )
                else:
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
                if node_cfg.output_schema == "ReviewVerdict" and schema_cls is ExtendedReviewVerdict:
                    # P6: one verdict per finding. A live run pushed 14
                    # findings through ONE campaign-level verdict, so a single
                    # review opinion silently judged 14 independent
                    # vulnerabilities. The instruction rides here -- the
                    # harness-owned instruction seam -- rather than in the
                    # skill prompt, because it describes the OUTPUT CONTRACT
                    # of this binding, and it is only appended when the
                    # extended schema is actually bound: telling the model to
                    # emit finding_verdicts against the strict schema would
                    # make ADK reject every response.
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
                elif node_cfg.output_schema == "CriticVerdict" and schema_cls is ExtendedCriticVerdict:
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

            stage_role_prompt = instruction
            if is_prefix_group:
                allowed_sorted_str = ", ".join(sorted(str(t) for t in node_cfg.tools))
                stage_role_prompt = (
                    f"{stage_role_prompt.rstrip()}\n\n"
                    f"STAGE TOOL PERMISSIONS: In stage '{node_id}', you may ONLY call: [{allowed_sorted_str}]. "
                    f"Any other tool in the shared schema is forbidden for this stage."
                )
                reminder_suffix = ResilientLiteLlm.render_stage_turn_reminder(
                    schema_cls,
                    has_set_model_response=False,
                    has_report_findings=("report_findings" in node_cfg.tools),
                )
                if reminder_suffix:
                    stage_role_prompt = f"{stage_role_prompt}{reminder_suffix}"
                agent_instruction_text = PREFIX_GROUP_BASE_INSTRUCTION
                shared_names = prefix_group_tool_names.get(prefix_group or "", [])
                effective_agent_tools = [
                    resolvable_tools[t_name]
                    for t_name in shared_names
                    if t_name in resolvable_tools
                ]
                effective_output_schema = None
            else:
                agent_instruction_text = instruction
                effective_agent_tools = agent_tools
                effective_output_schema = schema_cls

            harness_entry: dict[str, Any] = {
                "id": node_id,
                "tools": list(node_cfg.tools),
                "model": node_model_id,
                "instruction": stage_role_prompt if is_prefix_group else instruction,
                "fork_from": node_cfg.fork_from or "",
            }
            if prefix_group:
                harness_entry["prefix_group"] = prefix_group
            if node_cfg.skip_when_static:
                harness_entry["skip_when_static"] = True
            harness_nodes.append(harness_entry)

            agent_kwargs: dict[str, Any] = {
                "name": node_id,
                "model": model_inst,
                # Handed to ADK as a provider, not a string: a string instruction
                # is a template in which `{name}` is a session-state lookup that
                # raises KeyError at run time when no such key exists. Mantis
                # prompts are literal text -- they quote code, and code has
                # braces (`f"... WHERE name='{name}'"` killed a live rollout at
                # the threat modeler). Nothing in Mantis uses state templating
                # in node instructions; the seed prompt's {filepath} is
                # substituted by main.py itself.
                "instruction": _literal_instruction(agent_instruction_text),
                "tools": effective_agent_tools,
                "output_schema": effective_output_schema,
                "output_key": node_cfg.output_key,
            }
            if node_cfg.include_contents is not None:
                agent_kwargs["include_contents"] = node_cfg.include_contents
            else:
                agent_kwargs["include_contents"] = "none"

            stamp_status = str(node_cfg.on_enter_status or "").strip().lower()
            if stamp_status and stamp_status not in NODE_STAMP_STATUSES:
                # A workflow file -- hand-written, synthesized, or recipe
                # persisted by an earlier run -- may only stamp the two
                # coverage statuses. patch_verified is earned through the
                # re-attack flow and closes findings at the MCP gate;
                # reported would reopen dismissals. Refuse rather than trust.
                print(
                    f"[graph_loader] node '{node_id}': on_enter_status "
                    f"'{node_cfg.on_enter_status}' is not a status a node may stamp "
                    f"(allowed: {sorted(NODE_STAMP_STATUSES)}); ignoring it.",
                    file=sys.stderr,
                )
                stamp_status = ""
            if stamp_status:
                # P4: coverage stamps fire on successful node COMPLETION, not
                # entry. main.py used to stamp the moment a node's name first
                # appeared in the event stream -- i.e. before the node did any
                # work -- so a campaign that crashed mid-reproducer had
                # already stamped its target static_confirmed: a crashed
                # campaign must not stamp its target as covered/scanned. ADK
                # runs after_agent_callback only when _run_async_impl
                # completed without raising (base_agent.run_async lets
                # exceptions propagate before _handle_after_agent_callback),
                # which makes it exactly the "this node actually finished"
                # signal the entry stamp only pretended to be. The
                # on_enter_status map exported to main.py is emptied below so
                # the old entry-time stamp cannot double-fire.
                agent_kwargs["after_agent_callback"] = _make_completion_stamp_callback(
                    node_id, stamp_status
                )

            if (
                node_cfg.skip_when_static
                or node_id == "history"
                or (node_id == "reproducer" and node_cfg.output_schema == "ReproVerdict")
            ):
                agent_kwargs["before_agent_callback"] = _make_static_skip_before_agent_callback(
                    node_id,
                    stamp_status=stamp_status,
                    emit_repro_verdict=(node_cfg.output_schema == "ReproVerdict"),
                )
            elif node_id in _PREFIX_REUSE_ARTIFACTS and not node_cfg.on_enter_status:
                # Repo-scope prefix reuse (cross-functional / changed runs) plus
                # deterministic single-file stem bypass when ctx.sandbox is set.
                before_reuse, after_reuse = _make_prefix_reuse_callbacks(node_id)
                agent_kwargs["before_agent_callback"] = _chain_before_agent_callbacks(
                    _make_single_file_stem_skip_before_agent_callback(node_id),
                    before_reuse,
                )
                agent_kwargs["after_agent_callback"] = after_reuse
            elif node_id == "planner" and "before_agent_callback" not in agent_kwargs:
                agent_kwargs["before_agent_callback"] = (
                    _make_single_file_stem_skip_before_agent_callback(node_id)
                )
            elif node_id == "deduplicator" and "before_agent_callback" not in agent_kwargs:
                agent_kwargs["before_agent_callback"] = (
                    _make_deduplicator_skip_before_agent_callback(node_id)
                )
            elif (
                node_id == "reporter"
                or (node_cfg.skill and "mantis-report" in node_cfg.skill)
            ) and "before_agent_callback" not in agent_kwargs:
                agent_kwargs["before_agent_callback"] = (
                    _make_reporter_skip_before_agent_callback(node_id)
                )

            # Every agent node: bounds each tool response to its model's window
            # and, where the node has structural navigation, steers repeated
            # whole-file reads toward it.
            if is_prefix_group:
                agent_kwargs["before_tool_callback"] = _make_prefix_group_before_tool_callback(
                    node_id, node_cfg.tools
                )
            else:
                agent_kwargs["before_tool_callback"] = _make_active_node_before_tool_callback(
                    node_id
                )
            agent_kwargs["after_tool_callback"] = _make_after_tool_guard_callback(
                node_id, node_cfg.tools, model=node_model_id
            )
            agent_kwargs["on_tool_error_callback"] = _make_on_tool_error_callback(
                node_id
            )

            if is_prefix_group:
                pg_members_here = prefix_group_nodes.get(prefix_group or "", [])
                pg_parent_ids = {m.fork_from for m in pg_members_here if m.fork_from}
                same_prefix_and_model = bool(
                    ancestor_chain
                    and all(
                        (agent_nodes_by_id[a].prefix_group or "").strip() == prefix_group
                        and pre_resolved_models.get(a) == node_model_id
                        for a in ancestor_chain
                    )
                )
                agent_kwargs["before_model_callback"] = [
                    _make_prefix_group_before_model_callback(
                        node_id,
                        base_instruction=agent_instruction_text,
                        stage_role_prompt=stage_role_prompt,
                        ancestor_chain=ancestor_chain,
                        parent_id=node_cfg.fork_from,
                        preserve_signatures=same_prefix_and_model,
                        prefix_group=prefix_group or "",
                        enable_explicit_stem_cache=(node_id not in pg_parent_ids),
                    ),
                    _make_client_context_editing_before_model_callback(
                        node_id,
                        model=node_model_id,
                        config=spec.config.model_dump(),
                        preserve_system_prefix=True,
                    ),
                    _make_node_context_ceiling_before_model_callback(
                        node_id,
                        model=node_model_id,
                        has_schema=bool(node_cfg.output_schema),
                        keep_tool_results=_context_editing_keeps(llm_kwargs.get("context_management")),
                        llm_factory=(
                            (lambda kw=dict(llm_kwargs): _HandoffLiteLlm(**kw, preserve_system_prefix=True))
                            if llm_kwargs
                            else None
                        ),
                        max_continuations=spec.config.max_node_continuations,
                        preserve_system_prefix=True,
                    ),
                ]
            else:
                agent_kwargs["before_model_callback"] = [
                    _make_stage_experience_before_model_callback(node_id),
                    _make_campaign_directive_before_model_callback(node_id),
                    # Models without prefix binding: the harness clears older
                    # tool results itself (None for Claude, whose provider does).
                    _make_client_context_editing_before_model_callback(
                        node_id, model=node_model_id, config=spec.config.model_dump(),
                    ),
                    # Last: measures the request as the three above leave it.
                    _make_node_context_ceiling_before_model_callback(
                        node_id, model=node_model_id, has_schema=bool(node_cfg.output_schema),
                        keep_tool_results=_context_editing_keeps(llm_kwargs.get("context_management")),
                        # The handoff is written by the stage's own model, built
                        # from the same kwargs; None under the hermetic path.
                        llm_factory=(
                            (lambda kw=dict(llm_kwargs): _HandoffLiteLlm(**kw)) if llm_kwargs else None
                        ),
                        max_continuations=spec.config.max_node_continuations,
                    ),
                ]
                if node_cfg.fork_from:
                    # First: the inherited transcript is part of the request the
                    # callbacks below measure and trim.
                    agent_kwargs["before_model_callback"].insert(
                        0, _make_fork_before_model_callback(node_id, node_cfg.fork_from))
            if node_id == "reflector" or (
                node_cfg.skill and "mantis-reflect" in node_cfg.skill
            ):
                agent_kwargs["after_model_callback"] = (
                    _make_reflector_after_model_callback(node_id)
                )

            agent_cls = (
                _BarrierAgent
                if unconditional_in_edges.get(node_id, 0) > 1
                and conditional_in_edges.get(node_id, 0) == 0
                else adk.Agent
            )
            agent = agent_cls(**agent_kwargs)
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
                    if DEFAULT_ROUTE in route:
                        errors.append(
                            f"Edge from classifier '{from_str}' to '{to_str}' cannot combine '{DEFAULT_ROUTE}' with other routes in a list."
                        )
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

    _, topo_warnings = validate_workflow_topology(spec, strict_synthesis=False)
    for w in topo_warnings:
        print(f"[WORKFLOW WARNING] {w}", file=sys.stderr)

    if errors:
        raise ValueError("Graph validation failed:\n" + "\n".join(errors))

    edges = [
        Edge(from_node=item["from_node"], to_node=item["to_node"], route=item["route"])
        if item["route"] is not None
        else Edge(from_node=item["from_node"], to_node=item["to_node"])
        for item in edge_map.values()
    ]

    cfg = spec.config.model_dump()
    # P4: exported EMPTY on purpose. Coverage stamps moved into each stamped
    # agent's after_agent_callback (see _make_completion_stamp_callback), which
    # fires only after the node body completed without an exception. main.py
    # still consumes cfg["on_enter_status"] and stamps at node ENTRY -- the
    # exact behavior that let a crashed campaign mark its target as scanned --
    # so the map it receives must be empty. The key itself stays present
    # because it is part of the config contract main.py reads unconditionally.
    cfg["on_enter_status"] = {}
    cfg["resolved_node_models"] = list(resolved_node_models)
    if model_override:
        cfg["_cli_model_override"] = model_override
    if api_base_override:
        cfg["_cli_api_base"] = api_base_override
    if timeout_override is not None:
        cfg["_cli_timeout"] = timeout_override
    if reasoning_effort_override:
        cfg["_cli_reasoning_effort"] = reasoning_effort_override
    if overlay_meta.get("local_reasoning_effort"):
        cfg["_local_reasoning_effort"] = overlay_meta["local_reasoning_effort"]
    if spec.budget:
        cfg["budget"] = spec.budget
    elif "budget" in raw_json and isinstance(raw_json["budget"], dict):
        cfg["budget"] = raw_json["budget"]
    # What this harness IS, for the coverage ledger: main.py stamps it on
    # every spend row and compares it when deciding what a resumed or
    # coverage-driven run may skip. Empty on any failure, which every consumer
    # reads as "unknown" -- rows are written without a fingerprint and no
    # mismatch is ever reported (INV-6); a broken hash must not cost the run.
    try:
        cfg["harness_fingerprint"] = compute_harness_fingerprint(
            harness_nodes,
            default_model=resolve_model_id(None, spec.config.default_model, model_override),
            sandbox=spec.config.sandbox.type,
        )
    except Exception as exc:
        print(f"[graph_loader] harness fingerprint unavailable: {exc}", file=sys.stderr)
        cfg["harness_fingerprint"] = ""

    return (
        Workflow(
            name=spec.name,
            edges=edges
        ),
        cfg
    )


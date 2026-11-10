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

"""Post-run cross-campaign semantic deduplication and aggregate report synthesis.

After all parallel/multi-slice/multi-pass campaigns complete, this module:
1. Consolidates exact and semantic root-cause duplicates across campaigns while
   deterministically preserving the highest-assurance finding (`patch_verified`
   > `dynamic_confirmed` > `static_confirmed` > `reported`).
2. Synthesizes a single run-wide executive report (`workspace/.structured/report.json`
   and `workspace/review_packet-latest.md`) so multi-campaign runs do not spend
   N redundant LLM reporter turns.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from pydantic import BaseModel, ConfigDict, Field

from core.correlator import (
    _enclosing_symbols_for_row,
    _load_structural_index,
    _symbols_from_code_paths,
)
from core.database import (
    consolidate_duplicate_findings,
    finding_assurance_rank,
    is_consolidatable_status,
    read_artifact,
    read_findings,
    record_artifact,
)
from core.llm_gateway import sanitize_egress_text, wrap_untrusted_content
from core.schemas import ExecutiveReport

logger = logging.getLogger(__name__)

MAX_CLUSTER_SIZE = 10
MAX_LLM_CLUSTERS = 16
_WORD_RE = re.compile(r"[a-z0-9_]{3,}")
_STOPWORDS = frozenset({
    "the", "and", "for", "with", "via", "from", "into", "when", "that", "this",
    "vulnerability", "missing", "improper", "lack", "allows", "allow", "user",
    "input", "data", "file", "function", "method", "endpoint", "handler",
})


class DuplicateMergeProposal(BaseModel):
    """One verified same-root-cause duplicate group within a candidate cluster."""

    model_config = ConfigDict(extra="ignore")
    primary_id: int = Field(description="Database ID of the clearest / best-evidenced finding to keep")
    duplicate_ids: List[int] = Field(
        default_factory=list,
        description="Database IDs of findings in the cluster that report the EXACT same root-cause defect",
    )
    reason: str = Field(default="", description="Concise technical explanation of why these share one root cause")


class SemanticDedupeBatchResult(BaseModel):
    """Structured LLM adjudication over one candidate cluster of related findings."""

    model_config = ConfigDict(extra="ignore")
    merges: List[DuplicateMergeProposal] = Field(
        default_factory=list,
        description="Groups of true root-cause duplicates to merge; empty when all findings are distinct defects.",
    )


def _tokens(text: str) -> Set[str]:
    return {w for w in _WORD_RE.findall(str(text or "").lower()) if w not in _STOPWORDS}


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / float(len(a | b))


def _lines_set(finding: Dict[str, Any]) -> Set[int]:
    raw = finding.get("line_numbers")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = []
    if not isinstance(raw, (list, tuple)):
        return set()
    return {int(x) for x in raw if isinstance(x, int) and not isinstance(x, bool) and x > 0}


def _lines_close(a: Set[int], b: Set[int], window: int = 8) -> bool:
    if not a or not b:
        return False
    return any(abs(x - y) <= window for x in a for y in b)


def _norm_cwe(finding: Dict[str, Any]) -> str:
    raw = str(finding.get("cwe") or "").strip().upper()
    m = re.search(r"CWE-(\d+)", raw)
    return f"CWE-{m.group(1)}" if m else ""


def _tier1_exact_groups(
    findings: Sequence[Dict[str, Any]], idx: Any
) -> List[Tuple[int, List[int], str]]:
    """Deterministic zero-LLM consolidation of exact/near-exact cross-pass or
    cross-slice duplicates (matching signature, lineage_id, or same file + line
    proximity/symbol + CWE/high lexical overlap)."""
    parent: Dict[int, int] = {int(f["id"]): int(f["id"]) for f in findings}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    by_sig: Dict[str, int] = {}
    by_lin: Dict[str, int] = {}
    syms_by_id: Dict[int, Set[str]] = {}
    lines_by_id: Dict[int, Set[int]] = {}
    toks_by_id: Dict[int, Set[str]] = {}

    for f in findings:
        fid = int(f["id"])
        sig = str(f.get("signature") or "").strip()
        lin = str(f.get("lineage_id") or "").strip()
        if sig:
            if sig in by_sig:
                union(by_sig[sig], fid)
            else:
                by_sig[sig] = fid
        if lin:
            if lin in by_lin:
                union(by_lin[lin], fid)
            else:
                by_lin[lin] = fid
        syms = set(_symbols_from_code_paths(f.get("code_paths"))) | set(
            _enclosing_symbols_for_row(idx, f)
        )
        syms_by_id[fid] = syms
        lines_by_id[fid] = _lines_set(f)
        toks_by_id[fid] = _tokens(f"{f.get('title', '')} {f.get('description', '')}")

    n = len(findings)
    for i in range(n):
        fi = findings[i]
        idi = int(fi["id"])
        fpi = str(fi.get("filepath") or "").strip()
        cwei = _norm_cwe(fi)
        for j in range(i + 1, n):
            fj = findings[j]
            idj = int(fj["id"])
            if find(idi) == find(idj):
                continue
            fpj = str(fj.get("filepath") or "").strip()
            if not fpi or fpi != fpj:
                continue
            cwej = _norm_cwe(fj)
            if cwei and cwej and cwei != cwej:
                continue
            same_loc = _lines_close(lines_by_id[idi], lines_by_id[idj]) or bool(
                syms_by_id[idi] and (syms_by_id[idi] & syms_by_id[idj])
            )
            if not same_loc:
                continue
            sim = _jaccard(toks_by_id[idi], toks_by_id[idj])
            same_cwe_and_overlap = bool(cwei and cwei == cwej and sim >= 0.35)
            if sim >= 0.70 or same_cwe_and_overlap:
                union(idi, idj)

    buckets: Dict[int, List[Dict[str, Any]]] = {}
    for f in findings:
        buckets.setdefault(find(int(f["id"])), []).append(f)

    groups: List[Tuple[int, List[int], str]] = []
    for members in buckets.values():
        if len(members) < 2:
            continue
        ordered = sorted(
            members,
            key=lambda r: (
                -finding_assurance_rank(r.get("status")),
                -float(r.get("mantis_risk_score") or 0.0),
                int(r["id"]),
            ),
        )
        prim = int(ordered[0]["id"])
        dups = [int(m["id"]) for m in ordered[1:]]
        groups.append((prim, dups, "Deterministic signature/location root-cause match across passes/slices"))
    return groups


_ARROW_SPLIT_RE = re.compile(r"\s*(?:->|=>|→)\s*")


def _files_and_symbols_for_finding(f: Dict[str, Any], idx: Any) -> Tuple[Set[str], Set[str]]:
    files: Set[str] = set()
    fp = str(f.get("filepath") or "").strip()
    if fp:
        files.add(fp)
    raw_cp = f.get("code_paths")
    if isinstance(raw_cp, str):
        try:
            raw_cp = json.loads(raw_cp)
        except Exception:
            raw_cp = [raw_cp] if raw_cp.strip() else []
    expanded_cp: List[str] = []
    if isinstance(raw_cp, (list, tuple, set)):
        for entry in raw_cp:
            for hop in _ARROW_SPLIT_RE.split(str(entry or "")):
                hop = hop.strip()
                if not hop:
                    continue
                expanded_cp.append(hop)
                head = hop.split(":", 1)[0].strip()
                if ("/" in head or "." in head) and not head.isdigit():
                    files.add(head)
    syms = set(_symbols_from_code_paths(expanded_cp)) | set(
        _enclosing_symbols_for_row(idx, f)
    )
    return files, syms


def _candidate_semantic_clusters(
    findings: Sequence[Dict[str, Any]], idx: Any
) -> List[List[Dict[str, Any]]]:
    """Groups remaining open findings into small connected components sharing a
    filepath/code_path file, symbol, direct AST call-graph edge, or bounded CWE
    for LLM duplicate review."""
    if len(findings) < 2:
        return []
    by_id = {int(f["id"]): f for f in findings}
    ids = sorted(by_id)
    adj: Dict[int, Set[int]] = {i: set() for i in ids}

    by_file: Dict[str, List[int]] = {}
    by_sym: Dict[str, List[int]] = {}
    by_cwe: Dict[str, List[int]] = {}
    row_syms: Dict[int, Set[str]] = {}
    for f in findings:
        fid = int(f["id"])
        files, syms = _files_and_symbols_for_finding(f, idx)
        for fp in files:
            by_file.setdefault(fp, []).append(fid)
        row_syms[fid] = syms
        for s in syms:
            by_sym.setdefault(s, []).append(fid)
        cwe = _norm_cwe(f)
        if cwe:
            by_cwe.setdefault(cwe, []).append(fid)

    for group_ids in (*by_file.values(), *by_sym.values()):
        if 2 <= len(group_ids) <= 20:
            for a in group_ids:
                for b in group_ids:
                    if a != b:
                        adj[a].add(b)

    for cwe_ids in by_cwe.values():
        if 2 <= len(cwe_ids) <= 8:
            for a in cwe_ids:
                for b in cwe_ids:
                    if a != b:
                        adj[a].add(b)

    # Also connect findings linked by a direct call-graph edge in catalog.sqlite
    if idx is not None and any(row_syms.values()):
        all_syms = {s for ss in row_syms.values() for s in ss}
        for fid, syms in row_syms.items():
            for sym in list(syms)[:4]:
                try:
                    resolved = idx.resolve_symbol(sym, limit=3).get("results") or []
                    for sym_row in resolved:
                        for callee in (idx.find_callees(sym_row, limit=25).get("results") or []):
                            cname = str(callee.get("callee_name") or "")
                            if cname in all_syms:
                                for other_id in by_sym.get(cname, ()):
                                    if other_id != fid:
                                        adj[fid].add(other_id)
                                        adj[other_id].add(fid)
                except Exception:
                    continue

    visited: Set[int] = set()
    clusters: List[List[Dict[str, Any]]] = []
    for start in ids:
        if start in visited or not adj[start]:
            continue
        comp: List[int] = []
        queue = [start]
        visited.add(start)
        while queue:
            cur = queue.pop(0)
            comp.append(cur)
            for nxt in sorted(adj[cur]):
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append(nxt)
        if len(comp) >= 2:
            for offset in range(0, len(comp), MAX_CLUSTER_SIZE):
                chunk = comp[offset : offset + MAX_CLUSTER_SIZE]
                if len(chunk) >= 2:
                    clusters.append([by_id[i] for i in chunk])
        if len(clusters) >= MAX_LLM_CLUSTERS:
            break
    return clusters


def _can_call_llm(config: Optional[dict]) -> bool:
    if not isinstance(config, dict):
        return False
    api_base = str(config.get("api_base") or "")
    model = str(config.get("default_model") or "")
    if api_base.endswith(":9") or "nonexistent" in model:
        return False
    return bool(model)


async def _run_structured_one_shot(
    prompt: str,
    system_instruction: str,
    schema_cls: Any,
    config: Optional[dict],
) -> Any:
    """Executes a single structured ADK `set_model_response` LLM call against `schema_cls`."""
    from core.config import ResilientLiteLlm, get_llm_kwargs, structured_llm_request

    cfg = config or {}
    _, llm_kw = get_llm_kwargs(
        cfg.get("default_model"),
        api_base=cfg.get("api_base"),
        reasoning_effort=cfg.get("reasoning_effort"),
        config=cfg,
    )
    llm = ResilientLiteLlm(**llm_kw)
    req = structured_llm_request(prompt, system_instruction, schema_cls)
    resp_text = ""
    structured: Optional[Dict[str, Any]] = None
    async for resp in llm.generate_content_async(req):
        content = getattr(resp, "content", None)
        for part in getattr(content, "parts", None) or []:
            fc = getattr(part, "function_call", None)
            if fc is not None and getattr(fc, "name", "") == "set_model_response":
                args = getattr(fc, "args", None)
                if isinstance(args, dict):
                    structured = dict(args)
            elif getattr(part, "text", None):
                resp_text += part.text
    if structured is not None:
        return schema_cls.model_validate(structured)
    cleaned = resp_text.strip()
    if "```" in cleaned:
        cleaned = cleaned.split("```json")[-1].split("```")[0].strip()
    return schema_cls.model_validate_json(cleaned)


async def consolidate_run_findings(
    db_path: str,
    run_id: str,
    config: Optional[dict] = None,
    llm_callable: Any = None,
) -> Dict[str, Any]:
    """Consolidates duplicate open findings across campaigns in `run_id`.

    Runs Tier 1 deterministic consolidation unconditionally and Tier 2 structured
    LLM semantic consolidation when candidate clusters exist and an LLM is
    configured (or `llm_callable` is injected). Never raises (INV-6).
    """
    summary = {"tier1_merged": 0, "tier2_merged": 0, "clusters_checked": 0}
    try:
        all_rows = read_findings(db_path, run_id=run_id)
        active = [f for f in all_rows if is_consolidatable_status(f.get("status"))]
        if len(active) < 2:
            return summary

        idx = _load_structural_index(db_path)

        # Tier 1: deterministic exact/near-exact duplicates
        for prim_id, dup_ids, reason in _tier1_exact_groups(active, idx):
            _elected, count = consolidate_duplicate_findings(
                db_path, run_id, prim_id, dup_ids, reason=reason
            )
            summary["tier1_merged"] += count

        # Refresh open findings after Tier 1
        active = [
            f for f in read_findings(db_path, run_id=run_id)
            if is_consolidatable_status(f.get("status"))
        ]
        if len(active) < 2:
            return summary

        clusters = _candidate_semantic_clusters(active, idx)
        if not clusters:
            return summary

        if llm_callable is None and not _can_call_llm(config):
            return summary

        sys_inst = (
            "You are Mantis's post-run cross-campaign semantic deduplicator. "
            "Multiple slice campaigns or passes audited this repository in parallel. "
            "Merge ONLY findings that describe the EXACT SAME underlying root-cause "
            "software defect (for example, a caller campaign and a callee campaign "
            "reporting the same unsanitized sink, or two passes wording the same flaw "
            "differently). NEVER merge distinct vulnerabilities that sit at different "
            "sinks in the same file or represent distinct steps of an exploit chain."
        )

        for cluster in clusters:
            summary["clusters_checked"] += 1
            cluster_ids = {int(f["id"]) for f in cluster}
            payload = [
                {
                    "id": int(f["id"]),
                    "filepath": f.get("filepath"),
                    "line_numbers": f.get("line_numbers"),
                    "code_paths": f.get("code_paths"),
                    "cwe": f.get("cwe"),
                    "severity": f.get("severity"),
                    "status": f.get("status"),
                    "title": str(f.get("title") or "")[:200],
                    "description": str(f.get("description") or "")[:600],
                }
                for f in cluster
            ]
            prompt = (
                "Adjudicate whether any findings in the candidate cluster below are "
                "duplicates of the exact same root-cause defect:\n\n"
                + wrap_untrusted_content(
                    json.dumps(payload, indent=2, default=str),
                    filename="candidate_duplicate_cluster",
                )
            )
            try:
                if llm_callable is not None:
                    result = await llm_callable(prompt, SemanticDedupeBatchResult)
                else:
                    result = await _run_structured_one_shot(
                        prompt=prompt,
                        system_instruction=sys_inst,
                        schema_cls=SemanticDedupeBatchResult,
                        config=config,
                    )
            except Exception as exc:
                logger.debug("Semantic dedupe cluster skipped: %s", exc)
                continue

            already_used: Set[int] = set()
            for proposal in (result.merges or []):
                pid = int(proposal.primary_id)
                dids = [
                    int(d)
                    for d in (proposal.duplicate_ids or [])
                    if int(d) in cluster_ids and int(d) != pid and int(d) not in already_used
                ]
                if pid not in cluster_ids or pid in already_used or not dids:
                    continue
                already_used.add(pid)
                already_used.update(dids)
                _elected, count = consolidate_duplicate_findings(
                    db_path,
                    run_id,
                    pid,
                    dids,
                    reason=proposal.reason or "Cross-campaign semantic root-cause duplicate",
                )
                summary["tier2_merged"] += count
    except Exception as exc:
        logger.warning("Post-run consolidation degraded safely: %s", exc)
    return summary


def _deterministic_executive_report(active_findings: Sequence[Dict[str, Any]]) -> Tuple[ExecutiveReport, str]:
    """Builds a clean deterministic ExecutiveReport + markdown review packet."""
    if not active_findings:
        rpt = ExecutiveReport(
            executive_summary="No active vulnerability findings were confirmed across the audited scope.",
            critical_findings_count=0,
            recommendations=[],
        )
        md = "# Mantis Security Review Packet\n\nNo active vulnerability findings recorded.\n"
        return rpt, md

    crit_n = sum(1 for f in active_findings if str(f.get("severity") or "").upper() == "CRITICAL")
    high_n = sum(1 for f in active_findings if str(f.get("severity") or "").upper() == "HIGH")
    exec_sum = (
        f"Consolidated audit identified {len(active_findings)} active vulnerability "
        f"finding(s) ({crit_n} CRITICAL, {high_n} HIGH) across the target scope."
    )
    recs: List[str] = []
    md_lines = [
        "# Mantis Consolidated Security Review Packet",
        "",
        f"**Executive Summary**: {sanitize_egress_text(exec_sum)}",
        "",
        "## Active Findings",
        "",
    ]
    ordered = sorted(
        active_findings,
        key=lambda f: (
            -float(f.get("mantis_risk_score") or 0.0),
            -finding_assurance_rank(f.get("status")),
            int(f.get("id") or 0),
        ),
    )
    for f in ordered:
        title = sanitize_egress_text(str(f.get("title") or "Untitled"))
        fp = sanitize_egress_text(str(f.get("filepath") or ""))
        sev = sanitize_egress_text(str(f.get("severity") or "MEDIUM"))
        score = f.get("mantis_risk_score")
        score_str = f" (Risk: {float(score):.1f}/10.0)" if score is not None else ""
        rem = sanitize_egress_text(str(f.get("remediation") or "").strip())
        if rem and len(recs) < 10:
            recs.append(f"{fp}: {rem[:240]}")
        md_lines.append(f"- **[{sev}] {fp} — {title}**{score_str} (`{f.get('status')}`)")
        if rem:
            md_lines.append(f"  - Remediation: {rem[:300]}")
    rpt = ExecutiveReport(
        executive_summary=exec_sum,
        critical_findings_count=crit_n,
        recommendations=recs,
    )
    return rpt, "\n".join(md_lines) + "\n"


async def synthesize_aggregate_report(
    db_path: str,
    run_id: str,
    active_findings: Sequence[Dict[str, Any]],
    config: Optional[dict] = None,
) -> bool:
    """Synthesizes and persists a single post-run aggregate report for `run_id`.

    Zero-finding runs write a deterministic clean report with 0 LLM calls.
    Runs with active findings synthesize one executive summary via LLM when
    reachable, degrading cleanly to `_deterministic_executive_report`.
    """
    if not db_path or not run_id:
        return False
    try:
        rpt_obj, packet_md = _deterministic_executive_report(active_findings)
        if active_findings and _can_call_llm(config):
            try:
                compact_items = [
                    {
                        "id": f.get("id"),
                        "filepath": f.get("filepath"),
                        "severity": f.get("severity"),
                        "status": f.get("status"),
                        "mantis_risk_score": f.get("mantis_risk_score"),
                        "title": str(f.get("title") or "")[:180],
                        "remediation": str(f.get("remediation") or "")[:240],
                    }
                    for f in active_findings[:60]
                ]
                arch = read_artifact(db_path, artifact_type="summary", run_id=run_id) or ""
                prompt = (
                    "Synthesize a concise run-wide ExecutiveReport over the consolidated "
                    "active vulnerability findings below:\n\n"
                    + (
                        wrap_untrusted_content(arch[:2000], filename="architecture_summary") + "\n\n"
                        if arch
                        else ""
                    )
                    + wrap_untrusted_content(
                        json.dumps(compact_items, indent=2, default=str),
                        filename="consolidated_active_findings",
                    )
                )
                rpt_obj = await _run_structured_one_shot(
                    prompt=prompt,
                    system_instruction=(
                        "Compile a concise, accurate executive vulnerability summary and "
                        "prioritized remediation list strictly grounded in the provided findings."
                    ),
                    schema_cls=ExecutiveReport,
                    config=config,
                )
            except Exception as exc:
                logger.debug("Aggregate LLM report degraded to deterministic summary: %s", exc)

        record_artifact(
            db_path, run_id, "report", "workspace/.structured/report.json", rpt_obj.model_dump_json(indent=2)
        )
        record_artifact(
            db_path, run_id, "workspace_file", "workspace/review_packet-latest.md", packet_md
        )
        return True
    except Exception as exc:
        logger.warning("Failed to record aggregate report: %s", exc)
        return False

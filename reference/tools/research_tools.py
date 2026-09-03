from pathlib import Path
import json
import logging
import os
import posixpath
from typing import Optional
from core.schemas import VulnerabilityReport
from core.database import (
    write_findings,
    read_findings,
    record_calibration,
    record_artifact,
    read_artifact,
    query_historical_lineage,
    query_security_guidance,
    _db,
)
from core.context import current_run_context

logger = logging.getLogger(__name__)

MAX_READ_SIZE = 1024 * 1024  # 1 MiB


def _persist_artifact(ctx, artifact_type: str, filepath: str, content: str):
    """Persists an artifact solely to the SQLite database campaign_artifacts table."""
    if ctx.db_path:
        meta = {
            "resource": getattr(ctx, "target_file", ""),
            "snapshot_id": getattr(ctx, "snapshot_id", ""),
        }
        record_artifact(ctx.db_path, ctx.run_id, artifact_type, filepath, content, metadata=meta)


async def read_file(filepath: str) -> str:
    """Reads content from the SQLite campaign artifact store or the sandboxed execution context."""
    ctx = current_run_context.get()
    if ctx is None:
        return "Error: No active execution context."

    clean_path = filepath.replace("\\", "/").removeprefix("./")

    # 1. Handle workspace virtual artifacts (strictly in SQLite database)
    if clean_path.startswith("workspace/") or clean_path in ("mantis-summary.md", "workspace"):
        if ctx.db_path and os.path.exists(ctx.db_path):
            # Check campaign_artifacts by exact filepath first (returns documents written via write_file)
            art = read_artifact(ctx.db_path, filepath=clean_path, run_id=ctx.run_id)
            if not art and clean_path.startswith("workspace/"):
                art = read_artifact(ctx.db_path, filepath=clean_path.removeprefix("workspace/"), run_id=ctx.run_id)
            if not art:
                art = read_artifact(ctx.db_path, filepath=os.path.basename(clean_path), run_id=ctx.run_id)

            # Fallback for structured harness artifacts if no document exists at this exact path
            if not art:
                if clean_path in ("workspace/kb/THREAT_MODEL.md", "workspace/THREAT_MODEL.md", "THREAT_MODEL.md"):
                    art = read_artifact(ctx.db_path, artifact_type="threat_model", run_id=ctx.run_id)
                elif clean_path in ("mantis-summary.md", "workspace/mantis-summary.md"):
                    art = read_artifact(ctx.db_path, artifact_type="summary", run_id=ctx.run_id)
                elif clean_path in ("workspace/plan.json", "plan.json"):
                    art = read_artifact(ctx.db_path, artifact_type="plan", run_id=ctx.run_id)
                elif clean_path.startswith("workspace/report/review_packet") or clean_path in ("workspace/review_packet.md", "review_packet-latest.md"):
                    art = read_artifact(ctx.db_path, artifact_type="report", run_id=ctx.run_id)

            if art is not None:
                if len(art) > MAX_READ_SIZE:
                    return art[:MAX_READ_SIZE] + f"\n\n[TRUNCATED: File exceeds {MAX_READ_SIZE} characters/bytes limit]"
                return art

            # Check findings virtual paths
            if clean_path.startswith("workspace/findings") or clean_path.startswith("findings"):
                finding_target = clean_path.split("/")[-1].removesuffix(".json") if "/" in clean_path else ""
                findings = read_findings(ctx.db_path, run_id=ctx.run_id)
                if findings:
                    for f in findings:
                        f_id = str(f.get("id"))
                        f_lineage = str(f.get("lineage_id") or "")
                        if finding_target in (f_id, f_lineage) or finding_target in ("*", "findings", ""):
                            return json.dumps(f if finding_target not in ("*", "findings", "") else findings, indent=2)
                    return json.dumps(findings, indent=2)

            # Check learnings virtual JSONL
            if clean_path in ("workspace/learnings.jsonl", "learnings.jsonl"):
                try:
                    with _db(ctx.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute("SELECT category, learning, tags, timestamp FROM learnings WHERE run_id = ?", (ctx.run_id,))
                        rows = cursor.fetchall()
                        if rows:
                            lines = [json.dumps({"category": r[0], "learning": r[1], "tags": json.loads(r[2]) if r[2] else [], "timestamp": r[3]}) for r in rows]
                            return "\n".join(lines)
                except Exception:
                    pass

            return f"NO_DATA: File not found in workspace: {filepath}"

    # Sandbox / Filesystem reads for source code
    if ctx.sandbox is not None and hasattr(ctx.sandbox, "read_file"):
        try:
            content_bytes = await ctx.sandbox.read_file(Path(filepath))
            text = content_bytes.decode("utf-8", errors="replace")
            if len(text) > MAX_READ_SIZE:
                return text[:MAX_READ_SIZE] + f"\n\n[TRUNCATED: File exceeds {MAX_READ_SIZE} characters/bytes limit]"
            return text
        except (PermissionError, FileNotFoundError) as e:
            return f"Error: {e}"
        except Exception as e:
            # SECURITY: When a sandbox is configured, never fall back to the host
            # filesystem. An in-guest induced error (e.g. FIFO timeout) would
            # otherwise silently convert sandboxed reads into host reads.
            return f"Error: sandbox read failed for '{filepath}': {type(e).__name__}: {e}"

    # Host filesystem jail fallback (static-only mode; enforcing boundary check)
    target_path = Path(ctx.target_file).resolve() if ctx.target_file else Path.cwd()
    jail_dir = target_path if target_path.is_dir() else target_path.parent
    clean_fp = filepath.replace("\\", "/").removeprefix("./")
    target_path_real = (jail_dir / clean_fp).resolve()

    try:
        target_path_real.relative_to(jail_dir)
    except ValueError:
        return f"Error: Permission denied. The filepath '{filepath}' is outside the allowed directory."

    if not target_path_real.exists():
        return f"Error: File not found at '{filepath}'."

    if target_path.is_file() and target_path_real != target_path:
        return f"Error: Permission denied. Single-file scans may only read the scanned file '{target_path.name}'."

    try:
        with open(target_path_real, "r", encoding="utf-8", errors="replace") as f:
            text = f.read(MAX_READ_SIZE + 1)
            if len(text) > MAX_READ_SIZE:
                return text[:MAX_READ_SIZE] + f"\n\n[TRUNCATED: File exceeds {MAX_READ_SIZE} characters/bytes limit]"
            return text
    except Exception as e:
        return f"Error reading file '{filepath}': {e}"


def report_findings(report: VulnerabilityReport) -> str:
    """Submit the structured report of all vulnerabilities found in the file."""
    ctx = current_run_context.get()
    if ctx is None:
        return "Error: No active execution context."
    try:
        if isinstance(report, VulnerabilityReport):
            findings = report.findings
        elif isinstance(report, dict):
            report_obj = VulnerabilityReport.model_validate(report)
            findings = report_obj.findings
        elif isinstance(report, list):
            report_obj = VulnerabilityReport(findings=report)
            findings = report_obj.findings
        else:
            return f"ERROR SAVING DB: Invalid report payload type '{type(report).__name__}'."
            
        write_findings(ctx.db_path, ctx.target_file, findings, run_id=ctx.run_id)
        return f"SUCCESS: Saved {len(findings)} finding(s) to database."
    except Exception as e:
        return f"ERROR SAVING DB: {e}"


def get_findings(filepath: str = "") -> str:
    """Retrieves recorded vulnerability findings for the current run context or target file."""
    ctx = current_run_context.get()
    if ctx is None or not ctx.db_path:
        return "Error: No active execution context or database path."
    if not os.path.exists(ctx.db_path):
        return f"ERROR: Database file not found at '{ctx.db_path}'."
    try:
        clean_fp = filepath.strip().replace("\\", "/").removeprefix("./")
        if clean_fp.endswith("/") or clean_fp in ("workspace/findings", "workspace/findings/", "findings", "workspace", ""):
            clean_fp = ""
        findings = read_findings(ctx.db_path, filepath=clean_fp if clean_fp else None, run_id=ctx.run_id)
        if not findings:
            target_desc = f" for '{filepath}'" if filepath else ""
            return f"NO_DATA: Zero findings recorded in database{target_desc}."
        return json.dumps(findings, indent=2)
    except Exception as e:
        return f"ERROR RETRIEVING FINDINGS: {e}"


def score_risk(score: float, reasoning: str, filepath: str = "") -> str:
    """Records the per-file peak risk calibration score (0.1 - 10.0 scale) for the target file."""
    ctx = current_run_context.get()
    if ctx is None or not ctx.db_path:
        return "Error: No active execution context or database path."
    try:
        val = float(score)
        # Normalize 100-point scale input (e.g. 64 -> 6.4)
        if val > 10.0 and val <= 100.0:
            val = val / 10.0
        if not (0.0 <= val <= 10.0):
            return f"Error: Risk score must be between 0.0 and 10.0, got {score!r}."
        target = filepath or ctx.target_file
        record_calibration(ctx.db_path, target, val, reasoning, run_id=ctx.run_id)
        return f"SUCCESS: Recorded per-file risk score {val:.1f}/10.0 for '{target}'. Reasoning: {reasoning}"
    except (ValueError, TypeError):
        return f"Error: Invalid numerical risk score: {score!r}"
    except Exception as e:
        return f"ERROR SAVING RISK SCORE: {e}"


def calibrate_finding(
    finding_id: int,
    mantis_risk_score: float,
    impact_score: int,
    likelihood_score: int,
    priority: str,
    reasoning: str = "",
) -> str:
    """Calibrates an individual vulnerability finding with its calculated risk score (0.1 - 10.0 scale), impact, likelihood, and priority."""
    from core.database import update_finding_calibration
    ctx = current_run_context.get()
    if ctx is None or not ctx.db_path:
        return "Error: No active execution context or database path."
    try:
        val = float(mantis_risk_score)
        if val > 10.0 and val <= 100.0:
            val = val / 10.0
        if not (0.1 <= val <= 10.0):
            return f"Error: mantis_risk_score must be between 0.1 and 10.0, got {mantis_risk_score!r}."
        if not (1 <= int(impact_score) <= 5):
            return f"Error: impact_score must be between 1 and 5, got {impact_score!r}."
        if not (1 <= int(likelihood_score) <= 5):
            return f"Error: likelihood_score must be between 1 and 5, got {likelihood_score!r}."
        pri = str(priority).upper()
        if pri not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return f"Error: priority must be CRITICAL, HIGH, MEDIUM, or LOW, got {priority!r}."
        update_finding_calibration(
            ctx.db_path,
            int(finding_id),
            val,
            int(impact_score),
            int(likelihood_score),
            pri,
            run_id=ctx.run_id or "",
        )
        return f"SUCCESS: Calibrated finding {finding_id} -> Risk Score: {val:.1f}/10.0, Priority: {pri}, Impact: {impact_score}/5, Likelihood: {likelihood_score}/5."
    except Exception as e:
        return f"ERROR CALIBRATING FINDING: {e}"


async def write_file(filepath: str, content: str) -> str:
    """Writes content to a file in the workspace artifact store or the sandboxed workspace."""
    from core.database import update_finding_calibration
    ctx = current_run_context.get()
    if ctx is None:
        return "Error: No active execution context."

    clean_fp = filepath.replace("\\", "/").removeprefix("./")
    if clean_fp.startswith("workspace/") or clean_fp in ("mantis-summary.md",):
        if clean_fp != "mantis-summary.md":
            # SECURITY: Normalize before recording. Un-normalized paths
            # ("workspace/kb//abs/path.md", "workspace/../..") would become OKF
            # concept IDs and could escape the export directory.
            norm_fp = posixpath.normpath(clean_fp)
            if (
                not norm_fp.startswith("workspace/")
                or ".." in norm_fp.split("/")
                or posixpath.isabs(norm_fp.removeprefix("workspace/"))
            ):
                return (
                    f"Error: Permission denied. Workspace artifact path "
                    f"'{filepath}' must stay under 'workspace/'."
                )
            clean_fp = norm_fp

        if ctx.db_path:
            meta = {
                "resource": getattr(ctx, "target_file", ""),
                "snapshot_id": getattr(ctx, "snapshot_id", ""),
            }
            record_artifact(ctx.db_path, ctx.run_id, "workspace_file", clean_fp, content, metadata=meta)
            # Sync any per-finding calibration updates into the findings table
            if clean_fp.startswith("workspace/findings") or clean_fp == "workspace/findings_update.json":
                try:
                    parsed = json.loads(content)
                    items = parsed if isinstance(parsed, list) else [parsed]
                    for item in items:
                        f_id = item.get("id")
                        if f_id is not None and "mantis_risk_score" in item:
                            try:
                                val = float(item["mantis_risk_score"])
                                if val > 10.0 and val <= 100.0:
                                    val = val / 10.0
                                update_finding_calibration(
                                    ctx.db_path,
                                    int(f_id),
                                    val,
                                    impact_score=int(item["impact_score"]) if "impact_score" in item else None,
                                    likelihood_score=int(item["likelihood_score"]) if "likelihood_score" in item else None,
                                    priority=str(item.get("priority")),
                                    run_id=ctx.run_id or "",
                                )
                            except (ValueError, TypeError):
                                pass
                except Exception:
                    pass
        # If dynamic sandbox is active, also sync artifact into guest workspace filesystem
        if ctx.sandbox is not None and hasattr(ctx.sandbox, "write_file") and type(ctx.sandbox).__name__ != "StaticOnlyEnvironment":
            try:
                await ctx.sandbox.write_file(Path(clean_fp), content)
            except Exception as e:
                logger.debug(f"Failed to sync workspace artifact '{clean_fp}' into sandbox: {e}")
        return f"SUCCESS: Recorded artifact '{clean_fp}' ({len(content)} characters)."

    if ctx.sandbox is not None and hasattr(ctx.sandbox, "write_file"):
        try:
            await ctx.sandbox.write_file(Path(filepath), content)
            return f"SUCCESS: Wrote {len(content)} characters to {filepath}"
        except Exception as e:
            return f"Error writing file in sandbox: {e}"

    # SECURITY: Outside a dynamic sandbox, do not allow writing directly to the host checkout.
    return (
        f"Error: Permission denied. Direct modification of host files '{filepath}' "
        "is disabled outside a dynamic sandbox. Store artifacts under 'workspace/'."
    )


async def list_files(directory: str = "") -> str:
    """Lists files in the target workspace or campaign artifact store."""
    ctx = current_run_context.get()
    if ctx is None:
        return "Error: No active execution context."

    clean_dir = directory.replace("\\", "/").strip("./").strip("/")
    if clean_dir.startswith("workspace") or clean_dir == "findings":
        items = set()
        if ctx.db_path and os.path.exists(ctx.db_path):
            try:
                with _db(ctx.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT filepath FROM campaign_artifacts WHERE run_id = ? OR run_id = ''", (ctx.run_id,))
                    for (fp,) in cursor.fetchall():
                        fp_norm = fp.replace("\\", "/").removeprefix("./")
                        # Filter out internal structured metadata from user-facing directory list
                        if "workspace/.structured" in fp_norm:
                            continue
                        if clean_dir == "workspace" or fp_norm.startswith(clean_dir):
                            items.add(fp_norm)
            except Exception:
                pass

            findings = read_findings(ctx.db_path, run_id=ctx.run_id)
            if not findings and ctx.run_id:
                findings = read_findings(ctx.db_path, run_id="")
            if clean_dir in ("workspace/findings", "findings", "workspace"):
                for f in findings:
                    items.add(f"workspace/findings/{f['id']}.json")
            if clean_dir == "workspace" and not items:
                items.add("workspace/plan.json")
                items.add("workspace/kb/THREAT_MODEL.md")
        return json.dumps(sorted(list(items)), indent=2)

    if ctx.sandbox is not None and hasattr(ctx.sandbox, "list_files"):
        try:
            files = await ctx.sandbox.list_files(directory)
            return json.dumps(files, indent=2)
        except PermissionError as pe:
            return f"Error: Permission denied. {pe}"
        except FileNotFoundError as fe:
            return f"Error: {fe}"
        except Exception as e:
            return f"Error listing files in sandbox: {e}"

    jail = os.path.realpath(ctx.jail_dir)
    base_dir = os.path.dirname(jail) if os.path.isfile(jail) else jail
    target_dir = os.path.realpath(os.path.join(base_dir, directory)) if directory else base_dir

    try:
        if os.path.isfile(jail):
            if target_dir != jail and target_dir != base_dir:
                return f"Error: Permission denied. Path outside allowed scope."
            return json.dumps([os.path.basename(jail)], indent=2)

        if os.path.commonpath([jail, target_dir]) != jail:
            return f"Error: Permission denied. Directory outside allowed scope."
        if not os.path.exists(target_dir):
            return f"Error: Directory not found at '{directory}'"
        if not os.path.isdir(target_dir):
            return json.dumps([os.path.basename(target_dir)], indent=2)

        files = []
        for root, dirs, filenames in os.walk(target_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fn in sorted(filenames):
                if not fn.startswith("."):
                    rel = os.path.relpath(os.path.join(root, fn), base_dir)
                    files.append(rel)
        return json.dumps(sorted(files), indent=2)
    except Exception as e:
        return f"Error listing files: {e}"


def record_plan(plan: dict) -> str:
    """Validates and records the strategic review plan solely into the SQLite database."""
    from core.schemas import ReviewPlan
    ctx = current_run_context.get()
    if ctx is None:
        return "Error: No active execution context."
    try:
        plan_obj = ReviewPlan.model_validate(plan) if isinstance(plan, dict) else plan
        content_json = plan_obj.model_dump_json(indent=2)
        _persist_artifact(ctx, "plan", "workspace/.structured/plan.json", content_json)
        return f"SUCCESS: Recorded review plan with {len(plan_obj.investigations)} targeted investigation(s)."
    except Exception as e:
        return f"ERROR SAVING PLAN: {e}"


def get_plan() -> str:
    """Retrieves the recorded review plan directly from the SQLite database."""
    ctx = current_run_context.get()
    if ctx is None or not ctx.db_path:
        return "Error: No active execution context or database path."
    art = read_artifact(ctx.db_path, artifact_type="plan", run_id=ctx.run_id)
    if not art:
        art = read_artifact(ctx.db_path, filepath="workspace/plan.json", run_id=ctx.run_id)
    if art:
        return art
    return "NO_DATA: No review plan recorded in database."


def record_threat_model(threat_model: dict) -> str:
    """Validates and records the architectural threat model solely into the SQLite database."""
    from core.schemas import ThreatModel
    ctx = current_run_context.get()
    if ctx is None:
        return "Error: No active execution context."
    try:
        tm_obj = ThreatModel.model_validate(threat_model) if isinstance(threat_model, dict) else threat_model
        content_json = tm_obj.model_dump_json(indent=2)
        _persist_artifact(ctx, "threat_model", "workspace/.structured/threat_model.json", content_json)
        return f"SUCCESS: Recorded threat model with {len(tm_obj.threat_actors)} threat actor(s) and {len(tm_obj.trust_boundaries)} boundary(ies)."
    except Exception as e:
        return f"ERROR SAVING THREAT MODEL: {e}"


def get_threat_model() -> str:
    """Retrieves the recorded threat model directly from the SQLite database."""
    ctx = current_run_context.get()
    if ctx is None or not ctx.db_path:
        return "Error: No active execution context or database path."
    art = read_artifact(ctx.db_path, artifact_type="threat_model", run_id=ctx.run_id)
    if not art:
        art = read_artifact(ctx.db_path, filepath="workspace/kb/THREAT_MODEL.md", run_id=ctx.run_id)
    if art:
        return art
    return "NO_DATA: No threat model recorded in database."


def record_summary(summary: dict) -> str:
    """Validates and records the codebase architectural summary solely into the SQLite database."""
    from core.schemas import CodebaseSummary
    ctx = current_run_context.get()
    if ctx is None:
        return "Error: No active execution context."
    try:
        sum_obj = CodebaseSummary.model_validate(summary) if isinstance(summary, dict) else summary
        content_json = sum_obj.model_dump_json(indent=2)
        _persist_artifact(ctx, "summary", "workspace/.structured/summary.json", content_json)
        return f"SUCCESS: Recorded codebase summary with {len(sum_obj.key_modules)} module(s)."
    except Exception as e:
        return f"ERROR SAVING SUMMARY: {e}"


def get_summary() -> str:
    """Retrieves the recorded codebase summary directly from the SQLite database."""
    ctx = current_run_context.get()
    if ctx is None or not ctx.db_path:
        return "Error: No active execution context or database path."
    art = read_artifact(ctx.db_path, artifact_type="summary", run_id=ctx.run_id)
    if not art:
        art = read_artifact(ctx.db_path, filepath="mantis-summary.md", run_id=ctx.run_id)
    if art:
        return art
    return "NO_DATA: No codebase summary recorded in database."


def record_exploit_chain(chain: dict) -> str:
    """Validates and records a multi-stage exploit chain solely into the SQLite database."""
    from core.schemas import ExploitChain
    ctx = current_run_context.get()
    if ctx is None:
        return "Error: No active execution context."
    try:
        chain_obj = ExploitChain.model_validate(chain) if isinstance(chain, dict) else chain
        content_json = chain_obj.model_dump_json(indent=2)
        _persist_artifact(ctx, "exploit_chain", f"workspace/chains/{chain_obj.chain_title}.json", content_json)
        return f"SUCCESS: Recorded exploit chain '{chain_obj.chain_title}' spanning {len(chain_obj.finding_titles)} finding(s)."
    except Exception as e:
        return f"ERROR SAVING EXPLOIT CHAIN: {e}"


def record_learning(learning: dict) -> str:
    """Validates and persists a learning entry solely into the SQLite database."""
    from core.schemas import LearningEntry
    from core.database import record_learning as db_record_learning
    ctx = current_run_context.get()
    if ctx is None:
        return "Error: No active execution context."
    try:
        learn_obj = LearningEntry.model_validate(learning) if isinstance(learning, dict) else learning
        if ctx.db_path:
            db_record_learning(ctx.db_path, ctx.run_id, learn_obj.category, learn_obj.learning, learn_obj.tags)
        return f"SUCCESS: Recorded learning under category '{learn_obj.category}'."
    except Exception as e:
        return f"ERROR SAVING LEARNING: {e}"


def dedupe_findings(primary_title: str, duplicate_titles: list[str], reason: str) -> str:
    """Merges and suppresses duplicate findings in the state store."""
    from core.database import merge_findings as db_merge_findings
    ctx = current_run_context.get()
    if ctx is None or not ctx.db_path:
        return "Error: No active execution context or database path."
    try:
        count = db_merge_findings(ctx.db_path, primary_title, duplicate_titles, reason, run_id=ctx.run_id)
        return f"SUCCESS: Deduplicated {count} finding(s) under primary title '{primary_title}'."
    except Exception as e:
        return f"ERROR DEDUPLICATING FINDINGS: {e}"


def generate_report(report: dict) -> str:
    """Validates and records the executive vulnerability review packet solely into the SQLite database."""
    from core.schemas import ExecutiveReport
    ctx = current_run_context.get()
    if ctx is None:
        return "Error: No active execution context."
    try:
        rpt_obj = ExecutiveReport.model_validate(report) if isinstance(report, dict) else report
        content_json = rpt_obj.model_dump_json(indent=2)
        _persist_artifact(ctx, "report", "workspace/.structured/report.json", content_json)
        return f"SUCCESS: Generated executive report with {len(rpt_obj.recommendations)} recommendation(s)."
    except Exception as e:
        return f"ERROR GENERATING REPORT: {e}"


def get_security_guidance(filepath: str = "", db_path: str = "") -> str:
    """Retrieves threat model context, historical vulnerability lineages, verified patch patterns,
    triaged false positives, and learned trajectory invariants to guide secure code development.
    Can be called inside an active pipeline run context or standalone against knowledge.db.
    """
    resolved_db = db_path
    resolved_run_id = None
    target = filepath

    ctx = current_run_context.get()
    if ctx is not None:
        resolved_db = resolved_db or ctx.db_path
        resolved_run_id = ctx.run_id
        target = target or ctx.target_file or ""

    if not resolved_db:
        # Standalone auto-discovery
        candidates = [
            os.path.join(os.getcwd(), "knowledge.db"),
            os.path.join(os.getcwd(), "workspace", "knowledge.db"),
            os.path.join(os.getcwd(), "reference", "knowledge.db"),
            os.path.join(os.getcwd(), "findings.db"),
            os.path.join(os.getcwd(), "workspace", "findings.db"),
            os.path.join(os.getcwd(), "reference", "findings.db"),
        ]
        for c in candidates:
            if os.path.exists(c):
                resolved_db = c
                break

    if not resolved_db or not os.path.exists(resolved_db):
        return "Error: No active execution context and knowledge.db not found."

    try:
        guidance = query_security_guidance(resolved_db, filepath=target, run_id=resolved_run_id)
        return guidance.get("guidance_summary", "")
    except Exception as e:
        return f"ERROR RETRIEVING SECURITY GUIDANCE: {e}"


def query_lineage(signature: str = "", lineage_id: str = "", filepath: str = "", db_path: str = "") -> str:
    """Queries cross-pass vulnerability lineages to track bug recurrence, status progression, and verified fixes.
    Can be called inside an active pipeline run context or standalone against knowledge.db.
    """
    resolved_db = db_path
    ctx = current_run_context.get()
    if ctx is not None:
        resolved_db = resolved_db or ctx.db_path

    if not resolved_db:
        candidates = [
            os.path.join(os.getcwd(), "knowledge.db"),
            os.path.join(os.getcwd(), "workspace", "knowledge.db"),
            os.path.join(os.getcwd(), "reference", "knowledge.db"),
            os.path.join(os.getcwd(), "findings.db"),
            os.path.join(os.getcwd(), "workspace", "findings.db"),
            os.path.join(os.getcwd(), "reference", "findings.db"),
        ]
        for c in candidates:
            if os.path.exists(c):
                resolved_db = c
                break

    if not resolved_db or not os.path.exists(resolved_db):
        return "Error: No active execution context and knowledge.db not found."

    try:
        records = query_historical_lineage(resolved_db, signature=signature, lineage_id=lineage_id, filepath=filepath)
        if not records:
            return f"NO_DATA: No lineage records found matching signature='{signature}', lineage_id='{lineage_id}', filepath='{filepath}'."

        lines = [f"# Lineage History ({len(records)} record(s))", ""]
        for r in records:
            lines.append(f"- **[{r.get('timestamp')}] Lineage `{r.get('lineage_id')}` (Sig: `{r.get('signature')}`)**")
            lines.append(f"  - **File**: `{r.get('filepath')}` | **Severity**: {r.get('severity')} | **Status**: `{r.get('status')}`")
            lines.append(f"  - **Title**: {r.get('title')}")
            if r.get("cwe"):
                lines.append(f"  - **CWE**: {r.get('cwe')}")
            if r.get("triage_reasoning"):
                lines.append(f"  - **Triage Reasoning**: {r.get('triage_reasoning')}")
            if r.get("patch_status"):
                lines.append(f"  - **Patch Status**: `{r.get('patch_status')}`")
            if r.get("patch_diff"):
                lines.append(f"  - **Patch Diff**:\n```diff\n{r.get('patch_diff').strip()}\n```")
        return "\n".join(lines)
    except Exception as e:
        return f"ERROR QUERYING LINEAGE: {e}"


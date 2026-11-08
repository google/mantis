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
import sys
import json
import time
import asyncio
import argparse
import tempfile
from pathlib import Path
from typing import Dict, Any, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.context import RunContext, current_run_context
from core.database import init_db, write_findings, read_findings
from evals.stage_agents import build_stage_agent, install_eval_run_context
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

DEFAULT_MODELS = [
    ("vertex_ai/gemini-3.1-flash-lite", "low"),
    ("vertex_ai/gemini-3.1-flash-lite", "high"),
    ("vertex_ai/gemini-3.5-flash-lite", "low"),
    ("vertex_ai/gemini-3.5-flash-lite", "high"),
    ("vertex_ai/gemini-3.5-flash", "low"),
    ("vertex_ai/gemini-3.5-flash", "high"),
    ("vertex_ai/gemini-3.6-flash", "low"),
    ("vertex_ai/gemini-3.6-flash", "high"),
    ("vertex_ai/gemini-3.8-flash", "low"),
    ("vertex_ai/gemini-3.8-flash", "high"),
]

def score_dedup_partition(db_findings: List[Dict[str, Any]], ground_truth: Dict[str, Any]) -> Dict[str, Any]:
    title_to_id = {f["title"]: f["id"] for f in ground_truth.get("findings", [])}
    merged_ids = set()
    active_ids = set()
    for f in db_findings:
        fid = title_to_id.get(f.get("title"))
        if not fid:
            continue
        if f.get("status") == "duplicate_merged":
            merged_ids.add(fid)
        else:
            active_ids.add(fid)
    tp = 0; fn = 0; fp = 0; tn = 0
    false_merges = []; missed_merges = []
    clusters = ground_truth.get("ground_truth_clusters", {})
    for cname, cinfo in clusters.items():
        fids = cinfo.get("finding_ids", [])
        relation = cinfo.get("relation", "DUPLICATE")
        if relation == "DUPLICATE":
            is_merged = any(fid in merged_ids for fid in fids[1:])
            if is_merged:
                tp += 1
            else:
                fn += 1
                missed_merges.append(cname)
        else:
            is_falsely_merged = any(fid in merged_ids for fid in fids)
            if is_falsely_merged:
                fp += 1
                false_merges.append(cname)
            else:
                tn += 1
    # tp + fp == 0 means the stage never merged anything: there is no evidence
    # about merge precision either way, so report it as undefined rather than
    # perfect -- a dead model must not outscore a working one (issue #8).
    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    if precision is None:
        f1 = None
    else:
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    safety = tn / (tn + fp) if (tn + fp) > 0 else 1.0
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "precision": precision, "recall": recall, "f1": f1, "safety": safety, "false_merges": false_merges, "missed_merges": missed_merges}

def _extract_route_from_event(event: Any, valid_routes: tuple[str, ...]) -> str | None:
    """Extracts a route verdict from an ADK event (JSON text, set_model_response call, or prose)."""
    if not hasattr(event, "content") or not event.content:
        return None
    found = None
    for p in getattr(event.content, "parts", None) or []:
        fc = getattr(p, "function_call", None)
        if fc is not None and getattr(fc, "name", "") == "set_model_response":
            args = getattr(fc, "args", None)
            if isinstance(args, dict):
                r = str(args.get("route") or "").strip().lower()
                if r in valid_routes:
                    found = r
        txt_raw = getattr(p, "text", None)
        if txt_raw:
            stripped = txt_raw.strip()
            if stripped.startswith("{"):
                try:
                    parsed = json.loads(stripped)
                    if isinstance(parsed, dict):
                        r = str(parsed.get("route") or "").strip().lower()
                        if r in valid_routes:
                            found = r
                            continue
                except ValueError:
                    pass
            txt = txt_raw.lower()
            for candidate in valid_routes:
                if (
                    f'"route": "{candidate}"' in txt
                    or f'"route":"{candidate}"' in txt
                    or f"'route': '{candidate}'" in txt
                    or f"'route':'{candidate}'" in txt
                    or f"route: {candidate}" in txt
                ):
                    found = candidate
    return found


async def eval_deduplicator(model_id: str, effort: str, dataset_path: Path) -> Dict[str, Any]:
    import shutil

    with open(dataset_path, "r", encoding="utf-8") as f:
        syn = json.load(f)
    temp_dir = tempfile.mkdtemp(prefix="mantis_eval_dedupe_")
    db_path = os.path.join(temp_dir, "eval.db")
    init_db(db_path)
    ctx, tok = install_eval_run_context(temp_dir, db_path, "")
    try:
        write_findings(db_path, "", syn["findings"], run_id=ctx.run_id)
        agent = build_stage_agent("deduplicator", model_id=model_id, reasoning_effort=effort)
        session_service = InMemorySessionService()
        runner = Runner(agent=agent, session_service=session_service, app_name="eval_app")
        session = await session_service.create_session(app_name="eval_app", user_id="eval_user")
        prompt = (
            "You are the deduplicator stage. 1. Call get_findings() to retrieve all recorded findings "
            "(this benchmark provides finding records only; no source tree is mounted on disk). "
            "2. Disambiguate findings. 3. Call dedupe_findings(primary_title, duplicate_titles, reason) "
            "for true duplicates. 4. Do NOT merge distinct vulnerabilities (stored vs reflected XSS, "
            "timing vs expiry, concurrency vs arithmetic)."
        )
        content = types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
        t0 = time.time()
        schema_err = 0
        try:
            async for _ in runner.run_async(session_id=session.id, user_id="eval_user", new_message=content):
                pass
        except Exception:
            schema_err += 1
        latency = time.time() - t0
        findings = read_findings(db_path, run_id=ctx.run_id)
        res = score_dedup_partition(findings, syn)
        res["latency"] = latency
        res["schema_errors"] = schema_err
        return res
    finally:
        current_run_context.reset(tok)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


async def eval_reviewer(model_id: str, effort: str, dataset_path: Path) -> Dict[str, Any]:
    import shutil

    with open(dataset_path, "r", encoding="utf-8") as f:
        rdata = json.load(f)
    temp_dir = tempfile.mkdtemp(prefix="mantis_eval_rev_")
    try:
        agent = build_stage_agent("reviewer", model_id=model_id, reasoning_effort=effort)
        session_service = InMemorySessionService()
        runner = Runner(agent=agent, session_service=session_service, app_name="eval_app")
        tp = 0; fp = 0; tn = 0; fn = 0; no_verdict = 0; errors = 0; t0 = time.time()
        for idx, case in enumerate(rdata["cases"]):
            case_db = os.path.join(temp_dir, f"eval_{idx}.db")
            init_db(case_db)
            ctx, tok = install_eval_run_context(temp_dir, case_db, "")
            try:
                finding = case["finding"]
                exp_route = case["ground_truth"]["expected_route"]
                write_findings(case_db, "", [finding], run_id=ctx.run_id)
                session = await session_service.create_session(app_name="eval_app", user_id="eval_user")
                prompt = (
                    f"Review finding: Title: {finding['title']} at {finding['filepath']}. "
                    f"Description: {finding['description']}. "
                    "Note: This synthetic triage benchmark provides only the finding metadata via "
                    "get_findings() (no source files are mounted on disk; evaluate strictly from the "
                    "finding record and do not reject merely because source files cannot be opened). "
                    "Output a ReviewVerdict with route='confirmed' or route='false_positive'."
                )
                content = types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
                # None until a verdict is actually parsed: a case where the model never
                # answers, or the call fails, must not inherit the negative class and
                # score as a correct rejection (issue #8).
                last_route = None
                try:
                    async for event in runner.run_async(session_id=session.id, user_id="eval_user", new_message=content):
                        extracted = _extract_route_from_event(event, ("confirmed", "false_positive"))
                        if extracted is not None:
                            last_route = extracted
                except Exception:
                    errors += 1
                if last_route is None:
                    no_verdict += 1
                elif exp_route == "confirmed":
                    if last_route == "confirmed":
                        tp += 1
                    else:
                        fn += 1
                else:
                    if last_route == "false_positive":
                        tn += 1
                    else:
                        fp += 1
            finally:
                current_run_context.reset(tok)
        latency = time.time() - t0
        total_cases = len(rdata["cases"])
        total_pos = sum(1 for c in rdata["cases"] if c["ground_truth"]["expected_route"] == "confirmed")
        # Classifier metrics are computed over parsed verdicts only; precision is
        # undefined (not perfect) when the model never made a positive prediction.
        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        # Operational metrics keep counting silence: a real finding with no verdict
        # is still a dropped finding, exactly like an explicit dismissal.
        recall = tp / total_pos if total_pos > 0 else 0.0
        fatal_drops = total_pos - tp
        safety = (total_cases - fatal_drops) / total_cases if total_cases > 0 else 1.0
        return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "no_verdict": no_verdict, "errors": errors, "precision": precision, "recall": recall, "safety": safety, "fatal_drops": fatal_drops, "noise_admitted": fp, "latency": latency}
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


async def eval_critic(model_id: str, effort: str, dataset_path: Path) -> Dict[str, Any]:
    import shutil

    with open(dataset_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    temp_dir = tempfile.mkdtemp(prefix="mantis_eval_crit_")
    try:
        agent = build_stage_agent("critic", model_id=model_id, reasoning_effort=effort)
        session_service = InMemorySessionService()
        runner = Runner(agent=agent, session_service=session_service, app_name="eval_app")
        tp = 0; fp = 0; tn = 0; fn = 0; no_verdict = 0; errors = 0; t0 = time.time()
        for idx, case in enumerate(cdata["cases"]):
            case_db = os.path.join(temp_dir, f"eval_{idx}.db")
            init_db(case_db)
            ctx, tok = install_eval_run_context(temp_dir, case_db, "")
            try:
                finding = case["finding"]
                exp_route = case["ground_truth"]["expected_route"]
                write_findings(case_db, "", [finding], run_id=ctx.run_id)
                session = await session_service.create_session(app_name="eval_app", user_id="eval_user")
                prompt = (
                    f"Assess exploit viability: Title: {finding['title']} at {finding['filepath']}. "
                    f"Description: {finding['description']}. "
                    "Note: This synthetic viability benchmark provides only the finding metadata via "
                    "get_findings() (no source files are mounted on disk; assess viability strictly "
                    "from the finding record and do not reject merely because source files cannot be opened). "
                    "Output a CriticVerdict with route='viable' or route='non_viable'."
                )
                content = types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
                # None until a verdict is actually parsed; see eval_reviewer (issue #8).
                last_route = None
                try:
                    async for event in runner.run_async(session_id=session.id, user_id="eval_user", new_message=content):
                        extracted = _extract_route_from_event(event, ("viable", "non_viable"))
                        if extracted is not None:
                            last_route = extracted
                except Exception:
                    errors += 1
                if last_route is None:
                    no_verdict += 1
                elif exp_route == "viable":
                    if last_route == "viable":
                        tp += 1
                    else:
                        fn += 1
                else:
                    if last_route == "non_viable":
                        tn += 1
                    else:
                        fp += 1
            finally:
                current_run_context.reset(tok)
        latency = time.time() - t0
        total_pos = sum(1 for c in cdata["cases"] if c["ground_truth"]["expected_route"] == "viable")
        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        recall = tp / total_pos if total_pos > 0 else 0.0
        return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "no_verdict": no_verdict, "errors": errors, "precision": precision, "recall": recall, "latency": latency}
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


async def eval_calibrator(model_id: str, effort: str, dataset_path: Path) -> Dict[str, Any]:
    import shutil

    with open(dataset_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    temp_dir = tempfile.mkdtemp(prefix="mantis_eval_cal_")
    db_path = os.path.join(temp_dir, "eval.db")
    init_db(db_path)
    ctx, tok = install_eval_run_context(temp_dir, db_path, "")
    try:
        write_findings(db_path, "", [c["finding"] for c in cdata["cases"]], run_id=ctx.run_id)
        agent = build_stage_agent("calibrator", model_id=model_id, reasoning_effort=effort)
        session_service = InMemorySessionService()
        runner = Runner(agent=agent, session_service=session_service, app_name="eval_app")
        session = await session_service.create_session(app_name="eval_app", user_id="eval_user")
        prompt = (
            "You are the calibrator stage. 1. Call get_findings() to retrieve findings and their numeric "
            "database `id` values. 2. Call calibrate_finding(finding_id, mantis_risk_score, impact_score, "
            "likelihood_score, priority) for EVERY finding returned by get_findings() on the 0.1-10.0 scale."
        )
        content = types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
        t0 = time.time()
        errors = 0
        try:
            async for _ in runner.run_async(session_id=session.id, user_id="eval_user", new_message=content):
                pass
        except Exception:
            errors += 1
        latency = time.time() - t0
        findings = read_findings(db_path, run_id=ctx.run_id)
        f_by_title = {f.get("title", ""): f for f in findings}
        correct_priorities = 0
        score_errors = []
        unscored = 0
        for case in cdata["cases"]:
            f_title = case["finding"].get("title", "")
            f_row = f_by_title.get(f_title, {})
            gt = case["ground_truth"]
            assigned_score = f_row.get("mantis_risk_score")
            if assigned_score is None:
                # No substitute score: a run that scored nothing must not earn an
                # MAE measured from an invented 5.0 (issue #8). Unscored findings
                # are excluded from the MAE and reported separately.
                unscored += 1
            else:
                min_s = gt.get("expected_min_score", 1.0)
                max_s = gt.get("expected_max_score", 10.0)
                mid_s = (min_s + max_s) / 2.0
                score_errors.append(abs(assigned_score - mid_s))
            assigned_prio = str(f_row.get("priority") or "").upper()
            expected_prio = str(gt.get("expected_priority", "")).upper()
            if expected_prio and (expected_prio in assigned_prio or any(p in assigned_prio for p in expected_prio.split("_") if p)):
                correct_priorities += 1
        mae = sum(score_errors) / len(score_errors) if score_errors else None
        prio_acc = correct_priorities / len(cdata["cases"]) if cdata["cases"] else 0.0
        return {"mae": mae, "priority_accuracy": prio_acc, "unscored": unscored, "errors": errors, "latency": latency}
    finally:
        current_run_context.reset(tok)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

async def run_stage_benchmark(stage: str, models: List[tuple], runs: int = 1, toolset: str = "baseline"):
    os.environ["VERTEXAI_LOCATION"] = os.environ.get("VERTEXAI_LOCATION", "global")
    evals_dir = Path(__file__).resolve().parent
    stage_dataset_map = {
        "dedupe": evals_dir / "synthetic_dataset.json",
        "review": evals_dir / "review_dataset.json",
        "critic": evals_dir / "critic_dataset.json",
        "calibrate": evals_dir / "calibrate_dataset.json",
        # research carries its own target + ground truth pair; see research_eval.py.
        "research": evals_dir / "research_target" / "ground_truth.json",
    }
    dataset_path = stage_dataset_map.get(stage)
    if not dataset_path or not dataset_path.exists():
        print(f"Error: Dataset for stage {stage} not found at {dataset_path}")
        return
    print("=" * 110)
    print(f"   MANTIS ADK EVALUATION BENCHMARK: Stage = {stage.upper()} ({runs} run(s) per configuration)")
    print("=" * 110)
    print(f"Dataset: {dataset_path.name}")
    if stage == "research":
        print(f"Toolset: {toolset}")
    print(f"Candidate Configurations: {len(models)}")
    print("-" * 110)
    summary_rows = []
    for idx, (model_id, effort) in enumerate(models, 1):
        short_name = model_id.replace("vertex_ai/", "")
        print(f"[{idx}/{len(models)}] Benchmarking: {short_name} (effort: {effort}, runs: {runs})...")
        run_results = []
        for r in range(runs):
            if stage == "dedupe": res = await eval_deduplicator(model_id, effort, dataset_path)
            elif stage == "review": res = await eval_reviewer(model_id, effort, dataset_path)
            elif stage == "critic": res = await eval_critic(model_id, effort, dataset_path)
            elif stage == "calibrate": res = await eval_calibrator(model_id, effort, dataset_path)
            elif stage == "research":
                from evals.research_eval import eval_researcher
                res = await eval_researcher(model_id, effort, toolset=toolset)
            else: res = {}
            run_results.append(res)
        latencies = [r.get("latency", 0.0) for r in run_results]
        avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
        min_lat = min(latencies) if latencies else 0.0; max_lat = max(latencies) if latencies else 0.0
        if stage == "dedupe":
            # None = undefined (no positive predictions); skipped rather than
            # averaged so a dead run cannot lift the mean (issue #8).
            precisions = [p for p in (r.get("precision") for r in run_results) if p is not None]
            recalls = [r.get("recall", 0.0) for r in run_results]
            false_merges = [r.get("fp", 0) for r in run_results]
            max_fp = max(false_merges) if false_merges else 0
            avg_prec_s = f"{(sum(precisions) / len(precisions))*100:.0f}%" if precisions else "n/a"
            avg_rec = sum(recalls) / len(recalls) if recalls else 0.0
            worst_safety = min(r.get("safety", 1.0) for r in run_results) if run_results else 1.0
            row = {"model": short_name, "effort": effort, "max_false_merges": max_fp, "avg_precision": avg_prec_s, "avg_recall": f"{avg_rec*100:.0f}%", "worst_safety": f"{worst_safety*100:.0f}%", "latency": f"{avg_lat:.2f}s ({min_lat:.1f}s-{max_lat:.1f}s)"}
            print(f"--> [DEDUPE] Worst FP: {max_fp} | Avg Prec: {avg_prec_s} | Avg Rec: {avg_rec*100:.0f}% | Latency: {avg_lat:.2f}s")
            summary_rows.append(row)
        elif stage == "review":
            fatal_drops = [r.get("fatal_drops", 0) for r in run_results]
            noise_adm = [r.get("noise_admitted", 0) for r in run_results]
            no_verdicts = [r.get("no_verdict", 0) for r in run_results]
            max_drops = max(fatal_drops) if fatal_drops else 0
            max_nv = max(no_verdicts) if no_verdicts else 0
            avg_noise = sum(noise_adm) / len(noise_adm) if noise_adm else 0.0
            worst_safety = min(r.get("safety", 1.0) for r in run_results) if run_results else 1.0
            row = {"model": short_name, "effort": effort, "max_fatal_drops": max_drops, "avg_noise_admitted": f"{avg_noise:.1f}", "max_no_verdict": max_nv, "worst_safety": f"{worst_safety*100:.0f}%", "latency": f"{avg_lat:.2f}s ({min_lat:.1f}s-{max_lat:.1f}s)"}
            print(f"--> [REVIEW] Worst Fatal Drops: {max_drops} | Avg Noise: {avg_noise:.1f} | Max NoVerdict: {max_nv} | Latency: {avg_lat:.2f}s")
            summary_rows.append(row)
        elif stage == "critic":
            precisions = [p for p in (r.get("precision") for r in run_results) if p is not None]
            recalls = [r.get("recall", 0.0) for r in run_results]
            no_verdicts = [r.get("no_verdict", 0) for r in run_results]
            max_nv = max(no_verdicts) if no_verdicts else 0
            avg_prec_s = f"{(sum(precisions) / len(precisions))*100:.0f}%" if precisions else "n/a"
            avg_rec = sum(recalls) / len(recalls) if recalls else 0.0
            row = {"model": short_name, "effort": effort, "avg_precision": avg_prec_s, "avg_recall": f"{avg_rec*100:.0f}%", "max_no_verdict": max_nv, "latency": f"{avg_lat:.2f}s ({min_lat:.1f}s-{max_lat:.1f}s)"}
            print(f"--> [CRITIC] Avg Prec: {avg_prec_s} | Avg Rec: {avg_rec*100:.0f}% | Max NoVerdict: {max_nv} | Latency: {avg_lat:.2f}s")
            summary_rows.append(row)
        elif stage == "calibrate":
            maes = [m for m in (r.get("mae") for r in run_results) if m is not None]
            prio_accs = [r.get("priority_accuracy", 0.0) for r in run_results]
            unscored_counts = [r.get("unscored", 0) for r in run_results]
            max_unscored = max(unscored_counts) if unscored_counts else 0
            avg_mae_s = f"{(sum(maes) / len(maes)):.2f}" if maes else "n/a"
            avg_prio = sum(prio_accs) / len(prio_accs) if prio_accs else 0.0
            row = {"model": short_name, "effort": effort, "avg_mae": avg_mae_s, "prio_acc": f"{avg_prio*100:.0f}%", "max_unscored": max_unscored, "latency": f"{avg_lat:.2f}s ({min_lat:.1f}s-{max_lat:.1f}s)"}
            print(f"--> [CALIBRATE] MAE: {avg_mae_s} | Priority Acc: {avg_prio*100:.0f}% | Max Unscored: {max_unscored} | Latency: {avg_lat:.2f}s")
            summary_rows.append(row)
        elif stage == "research":
            from evals.research_eval import summarize_research_runs

            agg = summarize_research_runs(run_results)
            avg_rec = agg["avg_recall"]
            # Report worst-case recall across runs too: a configuration that
            # only sometimes finds the cross-file bugs is not reliable.
            worst_rec = agg["worst_recall"]
            avg_cross = agg["avg_cross_file_recall"]
            avg_prec = agg["avg_precision"]
            avg_tokens = agg["avg_tokens"]
            avg_tptf = agg["avg_tokens_per_detected"]
            validity = f"{agg['graded']}/{agg['runs']} graded"
            if agg["zero_finding_runs"]:
                validity += f", {agg['zero_finding_runs']} zero"
            if agg["cap_hits"]:
                validity += f", {agg['cap_hits']} capped"
            if agg["rearms"]:
                validity += f", {agg['rearms']} re-armed"
            row = {"model": short_name, "effort": effort, "avg_recall": f"{avg_rec*100:.0f}%", "worst_recall": f"{worst_rec*100:.0f}%", "cross_recall": f"{avg_cross*100:.0f}%", "avg_precision": f"{avg_prec*100:.0f}%", "tokens_per_detected": f"{avg_tptf:,.0f}" if avg_tptf else "n/a", "validity": validity, "latency": f"{avg_lat:.2f}s ({min_lat:.1f}s-{max_lat:.1f}s)"}
            print(f"--> [RESEARCH] Avg Rec: {avg_rec*100:.0f}% (worst {worst_rec*100:.0f}%) | Cross-file Rec: {avg_cross*100:.0f}% | Prec: {avg_prec*100:.0f}% | Tokens: {avg_tokens:,.0f} | Reads un/windowed: {agg['avg_unwindowed_reads']:.1f} | Nav calls: {agg['avg_structural_nav_calls']:.1f} | {validity} | Latency: {avg_lat:.2f}s")
            if len(agg["ground_truth_versions"]) > 1 or len(agg["config_fingerprints"]) > 1:
                print("    WARNING: these runs mix ground-truth versions or configurations; the averages above blend different measurements.")
            summary_rows.append(row)
    print("\n" + "=" * 110)
    print(f"                    STAGE: {stage.upper()} BENCHMARK RESULTS SUMMARY ({runs} RUNS)")
    print("=" * 110)
    if stage == "dedupe":
        print(f"{'Model':<22} | {'Effort':<6} | {'Max False Merges':<17} | {'Avg Prec':<9} | {'Avg Rec':<8} | {'Worst Safety':<13} | {'Latency Distribution'}")
        print("-" * 110)
        for r in summary_rows:
            print(f"{r['model']:<22} | {r['effort']:<6} | {r['max_false_merges']:<17} | {r['avg_precision']:<9} | {r['avg_recall']:<8} | {r['worst_safety']:<13} | {r['latency']}")
    elif stage == "review":
        print(f"{'Model':<22} | {'Effort':<6} | {'Max Fatal Drops':<16} | {'Avg Noise Admitted':<19} | {'Max NoVerdict':<13} | {'Worst Safety':<13} | {'Latency Distribution'}")
        print("-" * 110)
        for r in summary_rows:
            print(f"{r['model']:<22} | {r['effort']:<6} | {r['max_fatal_drops']:<16} | {r['avg_noise_admitted']:<19} | {r['max_no_verdict']:<13} | {r['worst_safety']:<13} | {r['latency']}")
    elif stage == "critic":
        print(f"{'Model':<22} | {'Effort':<6} | {'Avg Precision':<15} | {'Avg Recall':<12} | {'Max NoVerdict':<13} | {'Latency Distribution'}")
        print("-" * 110)
        for r in summary_rows:
            print(f"{r['model']:<22} | {r['effort']:<6} | {r['avg_precision']:<15} | {r['avg_recall']:<12} | {r['max_no_verdict']:<13} | {r['latency']}")
    elif stage == "calibrate":
        print(f"{'Model':<22} | {'Effort':<6} | {'Risk Score MAE':<15} | {'Priority Acc':<13} | {'Max Unscored':<13} | {'Latency Distribution'}")
        print("-" * 110)
        for r in summary_rows:
            print(f"{r['model']:<22} | {r['effort']:<6} | {r['avg_mae']:<15} | {r['prio_acc']:<13} | {r['max_unscored']:<13} | {r['latency']}")
    elif stage == "research":
        print(f"{'Model':<22} | {'Effort':<6} | {'Avg Rec':<8} | {'Worst Rec':<10} | {'XFile Rec':<10} | {'Avg Prec':<9} | {'Tok/Detected':<13} | {'Validity':<22} | {'Latency Distribution'}")
        print("-" * 110)
        for r in summary_rows:
            print(f"{r['model']:<22} | {r['effort']:<6} | {r['avg_recall']:<8} | {r['worst_recall']:<10} | {r['cross_recall']:<10} | {r['avg_precision']:<9} | {r['tokens_per_detected']:<13} | {r['validity']:<22} | {r['latency']}")
    print("=" * 110)

async def main():
    parser = argparse.ArgumentParser(description="Run Mantis Multi-Stage Evaluation Benchmark")
    parser.add_argument("--stage", type=str, default="dedupe", choices=["dedupe", "review", "critic", "calibrate", "research", "all"], help="Target pipeline stage")
    parser.add_argument("--model", type=str, default=None, help="Specific model ID to evaluate")
    parser.add_argument("--effort", type=str, default=None, help="Reasoning effort level")
    parser.add_argument("--runs", type=int, default=3, help="Number of evaluation runs to compute distributions")
    parser.add_argument("--toolset", type=str, default="baseline", help="Researcher toolset variant (research stage only); see research_eval.TOOLSETS")
    args = parser.parse_args()
    if args.model:
        efforts = [args.effort] if args.effort else ["low", "high"]
        models = [(args.model, eff) for eff in efforts]
    else:
        models = DEFAULT_MODELS
    stages = ["dedupe", "review", "critic", "calibrate", "research"] if args.stage == "all" else [args.stage]
    for s in stages:
        await run_stage_benchmark(s, models, runs=args.runs, toolset=args.toolset)

if __name__ == "__main__":
    asyncio.run(main())

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
from evals.stage_agents import build_stage_agent
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
    ("vertex_ai/gemini-3.7-flash", "low"),
    ("vertex_ai/gemini-3.7-flash", "high"),
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
    precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fp == 0 else 0.0)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    safety = tn / (tn + fp) if (tn + fp) > 0 else 1.0
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "precision": precision, "recall": recall, "f1": f1, "safety": safety, "false_merges": false_merges, "missed_merges": missed_merges}

async def eval_deduplicator(model_id: str, effort: str, dataset_path: Path) -> Dict[str, Any]:
    with open(dataset_path, "r", encoding="utf-8") as f:
        syn = json.load(f)
    temp_dir = tempfile.mkdtemp(prefix="mantis_eval_dedupe_")
    db_path = os.path.join(temp_dir, "eval.db"); init_db(db_path)
    write_findings(db_path, "", syn["findings"])
    ctx = RunContext(jail_dir=temp_dir, db_path=db_path, target_file="workspace/app")
    current_run_context.set(ctx)
    agent = build_stage_agent("deduplicator", model_id=model_id, reasoning_effort=effort)
    session_service = InMemorySessionService()
    runner = Runner(agent=agent, session_service=session_service, app_name="eval_app")
    session = await session_service.create_session(app_name="eval_app", user_id="eval_user")
    prompt = "You are the deduplicator stage. 1. Call get_findings() to retrieve all recorded findings. 2. Disambiguate findings. 3. Call dedupe_findings(primary_title, duplicate_titles, reason) for true duplicates. 4. Do NOT merge distinct vulnerabilities (stored vs reflected XSS, timing vs expiry, concurrency vs arithmetic)."
    content = types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
    t0 = time.time(); schema_err = 0
    try:
        async for _ in runner.run_async(session_id=session.id, user_id="eval_user", new_message=content): pass
    except Exception: schema_err += 1
    latency = time.time() - t0
    findings = read_findings(db_path)
    res = score_dedup_partition(findings, syn)
    res["latency"] = latency; res["schema_errors"] = schema_err
    import shutil
    if os.path.exists(temp_dir): shutil.rmtree(temp_dir)
    return res

async def eval_reviewer(model_id: str, effort: str, dataset_path: Path) -> Dict[str, Any]:
    with open(dataset_path, "r", encoding="utf-8") as f:
        rdata = json.load(f)
    temp_dir = tempfile.mkdtemp(prefix="mantis_eval_rev_")
    db_path = os.path.join(temp_dir, "eval.db"); init_db(db_path)
    write_findings(db_path, "", [c["finding"] for c in rdata["cases"]])
    ctx = RunContext(jail_dir=temp_dir, db_path=db_path, target_file="workspace/app")
    current_run_context.set(ctx)
    agent = build_stage_agent("reviewer", model_id=model_id, reasoning_effort=effort)
    session_service = InMemorySessionService()
    runner = Runner(agent=agent, session_service=session_service, app_name="eval_app")
    tp = 0; fp = 0; tn = 0; fn = 0; t0 = time.time()
    for case in rdata["cases"]:
        session = await session_service.create_session(app_name="eval_app", user_id="eval_user")
        finding = case["finding"]; exp_route = case["ground_truth"]["expected_route"]
        prompt = f"Review finding: Title: {finding['title']} at {finding['filepath']}. Description: {finding['description']}. Output a ReviewVerdict with route='confirmed' or route='false_positive'."
        content = types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
        last_route = "false_positive"
        try:
            async for event in runner.run_async(session_id=session.id, user_id="eval_user", new_message=content):
                if hasattr(event, "content") and event.content:
                    for p in event.content.parts:
                        if p.text:
                            txt = p.text.lower()
                            if '"route": "confirmed"' in txt or "'route': 'confirmed'" in txt or "route: confirmed" in txt:
                                last_route = "confirmed"
                            elif '"route": "false_positive"' in txt or "'route': 'false_positive'" in txt or "route: false_positive" in txt:
                                last_route = "false_positive"
        except Exception: pass
        if exp_route == "confirmed":
            if last_route == "confirmed": tp += 1
            else: fn += 1
        else:
            if last_route == "false_positive": tn += 1
            else: fp += 1
    latency = time.time() - t0
    precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fp == 0 else 0.0)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    safety = (len(rdata["cases"]) - fn) / len(rdata["cases"]) if len(rdata["cases"]) > 0 else 1.0
    import shutil
    if os.path.exists(temp_dir): shutil.rmtree(temp_dir)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "safety": safety, "fatal_drops": fn, "noise_admitted": fp, "latency": latency}

async def eval_critic(model_id: str, effort: str, dataset_path: Path) -> Dict[str, Any]:
    with open(dataset_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    temp_dir = tempfile.mkdtemp(prefix="mantis_eval_crit_")
    db_path = os.path.join(temp_dir, "eval.db"); init_db(db_path)
    write_findings(db_path, "", [c["finding"] for c in cdata["cases"]])
    ctx = RunContext(jail_dir=temp_dir, db_path=db_path, target_file="workspace/app")
    current_run_context.set(ctx)
    agent = build_stage_agent("critic", model_id=model_id, reasoning_effort=effort)
    session_service = InMemorySessionService()
    runner = Runner(agent=agent, session_service=session_service, app_name="eval_app")
    tp = 0; fp = 0; tn = 0; fn = 0; t0 = time.time()
    for case in cdata["cases"]:
        session = await session_service.create_session(app_name="eval_app", user_id="eval_user")
        finding = case["finding"]; exp_route = case["ground_truth"]["expected_route"]
        prompt = f"Assess exploit viability: Title: {finding['title']} at {finding['filepath']}. Description: {finding['description']}. Output a CriticVerdict with route='viable' or route='non_viable'."
        content = types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
        last_route = "non_viable"
        try:
            async for event in runner.run_async(session_id=session.id, user_id="eval_user", new_message=content):
                if hasattr(event, "content") and event.content:
                    for p in event.content.parts:
                        if p.text:
                            txt = p.text.lower()
                            if '"route": "viable"' in txt or "'route': 'viable'" in txt or "route: viable" in txt:
                                last_route = "viable"
                            elif '"route": "non_viable"' in txt or "'route': 'non_viable'" in txt or "route: non_viable" in txt:
                                last_route = "non_viable"
        except Exception: pass
        if exp_route == "viable":
            if last_route == "viable": tp += 1
            else: fn += 1
        else:
            if last_route == "non_viable": tn += 1
            else: fp += 1
    latency = time.time() - t0
    precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fp == 0 else 0.0)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    import shutil
    if os.path.exists(temp_dir): shutil.rmtree(temp_dir)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "latency": latency}

async def eval_calibrator(model_id: str, effort: str, dataset_path: Path) -> Dict[str, Any]:
    with open(dataset_path, "r", encoding="utf-8") as f:
        cdata = json.load(f)
    temp_dir = tempfile.mkdtemp(prefix="mantis_eval_cal_")
    db_path = os.path.join(temp_dir, "eval.db"); init_db(db_path)
    write_findings(db_path, "", [c["finding"] for c in cdata["cases"]])
    ctx = RunContext(jail_dir=temp_dir, db_path=db_path, target_file="workspace/app")
    current_run_context.set(ctx)
    agent = build_stage_agent("calibrator", model_id=model_id, reasoning_effort=effort)
    session_service = InMemorySessionService()
    runner = Runner(agent=agent, session_service=session_service, app_name="eval_app")
    session = await session_service.create_session(app_name="eval_app", user_id="eval_user")
    prompt = "You are the calibrator stage. 1. Call get_findings() to retrieve findings. 2. Call calibrate_finding(finding_id, mantis_risk_score, impact_score, likelihood_score, priority) for each finding on the 0.1-10.0 scale."
    content = types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
    t0 = time.time()
    try:
        async for _ in runner.run_async(session_id=session.id, user_id="eval_user", new_message=content): pass
    except Exception: pass
    latency = time.time() - t0
    findings = read_findings(db_path)
    f_by_title = {f.get("title", ""): f for f in findings}
    correct_priorities = 0
    score_errors = []
    for case in cdata["cases"]:
        f_title = case["finding"].get("title", "")
        f_row = f_by_title.get(f_title, {})
        gt = case["ground_truth"]
        assigned_score = f_row.get("mantis_risk_score")
        if assigned_score is None:
            assigned_score = 5.0
        min_s = gt.get("expected_min_score", 1.0)
        max_s = gt.get("expected_max_score", 10.0)
        mid_s = (min_s + max_s) / 2.0
        score_errors.append(abs(assigned_score - mid_s))
        assigned_prio = str(f_row.get("priority") or "").upper()
        expected_prio = str(gt.get("expected_priority", "")).upper()
        if expected_prio and (expected_prio in assigned_prio or any(p in assigned_prio for p in expected_prio.split("_") if p)):
            correct_priorities += 1
    mae = sum(score_errors) / len(score_errors) if score_errors else 0.0
    prio_acc = correct_priorities / len(cdata["cases"]) if cdata["cases"] else 0.0
    import shutil
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    return {"mae": mae, "priority_accuracy": prio_acc, "latency": latency}

async def run_stage_benchmark(stage: str, models: List[tuple], runs: int = 1):
    os.environ["VERTEXAI_LOCATION"] = os.environ.get("VERTEXAI_LOCATION", "global")
    evals_dir = Path(__file__).resolve().parent
    stage_dataset_map = {
        "dedupe": evals_dir / "synthetic_dataset.json",
        "review": evals_dir / "review_dataset.json",
        "critic": evals_dir / "critic_dataset.json",
        "calibrate": evals_dir / "calibrate_dataset.json",
    }
    dataset_path = stage_dataset_map.get(stage)
    if not dataset_path or not dataset_path.exists():
        print(f"Error: Dataset for stage {stage} not found at {dataset_path}")
        return
    print("=" * 110)
    print(f"   MANTIS ADK EVALUATION BENCHMARK: Stage = {stage.upper()} ({runs} run(s) per configuration)")
    print("=" * 110)
    print(f"Dataset: {dataset_path.name}")
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
            else: res = {}
            run_results.append(res)
        latencies = [r.get("latency", 0.0) for r in run_results]
        avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
        min_lat = min(latencies) if latencies else 0.0; max_lat = max(latencies) if latencies else 0.0
        if stage == "dedupe":
            precisions = [r.get("precision", 0.0) for r in run_results]
            recalls = [r.get("recall", 0.0) for r in run_results]
            false_merges = [r.get("fp", 0) for r in run_results]
            max_fp = max(false_merges) if false_merges else 0
            avg_prec = sum(precisions) / len(precisions) if precisions else 0.0
            avg_rec = sum(recalls) / len(recalls) if recalls else 0.0
            worst_safety = min(r.get("safety", 1.0) for r in run_results) if run_results else 1.0
            row = {"model": short_name, "effort": effort, "max_false_merges": max_fp, "avg_precision": f"{avg_prec*100:.0f}%", "avg_recall": f"{avg_rec*100:.0f}%", "worst_safety": f"{worst_safety*100:.0f}%", "latency": f"{avg_lat:.2f}s ({min_lat:.1f}s-{max_lat:.1f}s)"}
            print(f"--> [DEDUPE] Worst FP: {max_fp} | Avg Prec: {avg_prec*100:.0f}% | Avg Rec: {avg_rec*100:.0f}% | Latency: {avg_lat:.2f}s")
            summary_rows.append(row)
        elif stage == "review":
            fatal_drops = [r.get("fatal_drops", 0) for r in run_results]
            noise_adm = [r.get("noise_admitted", 0) for r in run_results]
            max_drops = max(fatal_drops) if fatal_drops else 0
            avg_noise = sum(noise_adm) / len(noise_adm) if noise_adm else 0.0
            worst_safety = min(r.get("safety", 1.0) for r in run_results) if run_results else 1.0
            row = {"model": short_name, "effort": effort, "max_fatal_drops": max_drops, "avg_noise_admitted": f"{avg_noise:.1f}", "worst_safety": f"{worst_safety*100:.0f}%", "latency": f"{avg_lat:.2f}s ({min_lat:.1f}s-{max_lat:.1f}s)"}
            print(f"--> [REVIEW] Worst Fatal Drops: {max_drops} | Avg Noise: {avg_noise:.1f} | Latency: {avg_lat:.2f}s")
            summary_rows.append(row)
        elif stage == "critic":
            precisions = [r.get("precision", 0.0) for r in run_results]
            recalls = [r.get("recall", 0.0) for r in run_results]
            avg_prec = sum(precisions) / len(precisions) if precisions else 0.0
            avg_rec = sum(recalls) / len(recalls) if recalls else 0.0
            row = {"model": short_name, "effort": effort, "avg_precision": f"{avg_prec*100:.0f}%", "avg_recall": f"{avg_rec*100:.0f}%", "latency": f"{avg_lat:.2f}s ({min_lat:.1f}s-{max_lat:.1f}s)"}
            print(f"--> [CRITIC] Avg Prec: {avg_prec*100:.0f}% | Avg Rec: {avg_rec*100:.0f}% | Latency: {avg_lat:.2f}s")
            summary_rows.append(row)
        elif stage == "calibrate":
            maes = [r.get("mae", 0.0) for r in run_results]
            prio_accs = [r.get("priority_accuracy", 0.0) for r in run_results]
            avg_mae = sum(maes) / len(maes) if maes else 0.0
            avg_prio = sum(prio_accs) / len(prio_accs) if prio_accs else 0.0
            row = {"model": short_name, "effort": effort, "avg_mae": f"{avg_mae:.2f}", "prio_acc": f"{avg_prio*100:.0f}%", "latency": f"{avg_lat:.2f}s ({min_lat:.1f}s-{max_lat:.1f}s)"}
            print(f"--> [CALIBRATE] MAE: {avg_mae:.2f} | Priority Acc: {avg_prio*100:.0f}% | Latency: {avg_lat:.2f}s")
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
        print(f"{'Model':<22} | {'Effort':<6} | {'Max Fatal Drops':<16} | {'Avg Noise Admitted':<19} | {'Worst Safety':<13} | {'Latency Distribution'}")
        print("-" * 110)
        for r in summary_rows:
            print(f"{r['model']:<22} | {r['effort']:<6} | {r['max_fatal_drops']:<16} | {r['avg_noise_admitted']:<19} | {r['worst_safety']:<13} | {r['latency']}")
    elif stage == "critic":
        print(f"{'Model':<22} | {'Effort':<6} | {'Avg Precision':<15} | {'Avg Recall':<12} | {'Latency Distribution'}")
        print("-" * 110)
        for r in summary_rows:
            print(f"{r['model']:<22} | {r['effort']:<6} | {r['avg_precision']:<15} | {r['avg_recall']:<12} | {r['latency']}")
    elif stage == "calibrate":
        print(f"{'Model':<22} | {'Effort':<6} | {'Risk Score MAE':<15} | {'Priority Acc':<13} | {'Latency Distribution'}")
        print("-" * 110)
        for r in summary_rows:
            print(f"{r['model']:<22} | {r['effort']:<6} | {r['avg_mae']:<15} | {r['prio_acc']:<13} | {r['latency']}")
    print("=" * 110)

async def main():
    parser = argparse.ArgumentParser(description="Run Mantis Multi-Stage Evaluation Benchmark")
    parser.add_argument("--stage", type=str, default="dedupe", choices=["dedupe", "review", "critic", "calibrate", "all"], help="Target pipeline stage")
    parser.add_argument("--model", type=str, default=None, help="Specific model ID to evaluate")
    parser.add_argument("--effort", type=str, default=None, help="Reasoning effort level")
    parser.add_argument("--runs", type=int, default=3, help="Number of evaluation runs to compute distributions")
    args = parser.parse_args()
    if args.model:
        efforts = [args.effort] if args.effort else ["low", "high"]
        models = [(args.model, eff) for eff in efforts]
    else:
        models = DEFAULT_MODELS
    stages = ["dedupe", "review", "critic", "calibrate"] if args.stage == "all" else [args.stage]
    for s in stages:
        await run_stage_benchmark(s, models, runs=args.runs)

if __name__ == "__main__":
    asyncio.run(main())

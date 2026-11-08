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

"""Mantis as a Harness2 benchmark adapter: how a harness is rolled out and read.

Harness2 asks an adapter for three things: run one rollout of a harness on a
task and leave a run directory behind (``execute``), say what that run
produced (``delivered`` / ``deliverable_text`` / ``trajectory``), and validate
a proposed harness tree (``validate_tree``). Everything else -- proposing,
probing, composing, selecting, reflecting -- is upstream method logic.

Two adapters share one implementation:

* ``MantisRepoAdapter`` -- the user's own code. Tasks are target directories
  (a repository, or named subsystems of it). There is no ground truth and
  ``score`` says so by returning ``None``; selection is driven by the
  pipeline's own INV-1 evidence tiers (``evidence_vector``), never by an
  answer key.
* ``MantisEvalAdapter`` -- generated dev targets from
  ``evals.research_targets``. ``score`` matches findings against the
  target's ground truth, and is called only by ``harness2.core.judge`` after
  selection has committed, which is the only place an answer key may enter.
  Holdout seeds are refused at construction.

A rollout is the production pipeline (``main.py``) run as a subprocess with a
compiled candidate ``workflow.json``; its stdout is the trajectory, its
knowledge DB holds the findings and their evidence. Completion is recorded
with Harness2's runmark only after the process returned normally; a run that
died leaves no marker and is re-rolled rather than served as evidence.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from evals.evolve import surface as hsurface
from evals.evolve._vendor import load_harness2

REFERENCE_ROOT = Path(__file__).resolve().parent.parent.parent

# What the pipeline must never see, as glob patterns on a file's name: the
# proposer may not read these from a rollout (Harness2's leak globs) and a
# target that carries one is rolled out from a copy without it.
ANSWER_KEY_GLOBS = ("*ground_truth*.json", "*_dataset*.json")

# Evidence tiers, strongest first. Weights are deliberately coarse: the
# ordering is what matters for selection, and a sandbox-proven reach is not
# "a bit better" than a static read -- it is a different kind of evidence.
EVIDENCE_WEIGHTS: Dict[str, float] = {
    "patch_verified": 3.0,
    "dynamic_confirmed": 3.0,
    "reproduced": 2.0,
    "static_confirmed": 1.0,
    "confirmed": 1.0,
    "viable": 0.5,
    "reported": 0.0,
}
SEVERITY_WEIGHTS: Dict[str, float] = {"critical": 1.5, "high": 1.25, "medium": 1.0, "low": 0.5, "info": 0.25}
DISMISSED_STATUSES = ("false_positive", "non_viable", "sample_or_test")
# Anything a verdict stage upheld. The non-regression floor is built from these
# (intersected over base runs), so a static-only workflow -- where nothing can
# reach dynamic_confirmed -- still has a floor.
CONFIRMED_STATUSES = ("static_confirmed", "confirmed", "viable", "reproduced", "dynamic_confirmed", "patch_verified")
MACHINE_VERIFIED_STATUSES = ("dynamic_confirmed", "patch_verified", "reproduced")
DEFAULT_ROLLOUT_TIMEOUT_SECONDS = 3 * 3600

_TOOL_CALL_RE = re.compile(r"^\[TOOL CALL: ([^\]]+)\] args=(.*)$")
_TOOL_RESP_RE = re.compile(r"^\[TOOL (RESPONSE|FEEDBACK|FATAL ERROR): ([^\]]+)\] ?(.*)$")
_NODE_RE = re.compile(r"^-- (\S+)(?: -> (\S+))?$")
_EVENT_ERR_RE = re.compile(r"^\[EVENT ERROR ([^\]]+)\] ?(.*)$")


# --- Running the pipeline --------------------------------------------------------------


@dataclass
class RunSettings:
    model: str = ""
    effort: str = ""
    token_budget: Optional[int] = None
    max_llm_calls: Optional[int] = None
    scan_mode: str = "whole"
    # A safety net under the token budget, not the budget: the full graph over
    # a few dozen files takes an hour or more at a reasoning model's pace, and
    # a rollout the timeout kills is a rollout paid for and thrown away.
    timeout_seconds: int = DEFAULT_ROLLOUT_TIMEOUT_SECONDS
    extra_args: List[str] = field(default_factory=list)
    python: str = sys.executable


def build_command(target: Path, workflow_path: Path, run_dir: Path, settings: RunSettings) -> List[str]:
    cmd = [
        settings.python, str(REFERENCE_ROOT / "main.py"), str(target),
        "--workflow", str(workflow_path),
        "--db", str(run_dir / "knowledge.db"),
        "--spend-report", str(run_dir / "spend.json"),
        "--transcript-out", str(run_dir / "transcript.raw.jsonl"),
        "--scan-mode", settings.scan_mode,
        "--yes",
    ]
    if settings.model:
        cmd += ["--model", settings.model]
    if settings.effort:
        cmd += ["--reasoning-effort", settings.effort]
    if settings.token_budget:
        cmd += ["--token-budget", str(settings.token_budget)]
    if settings.max_llm_calls:
        cmd += ["--max-llm-calls", str(settings.max_llm_calls)]
    cmd += list(settings.extra_args)
    return cmd


def run_pipeline(target: Path, workflow_path: Path, run_dir: Path, settings: RunSettings) -> Dict[str, Any]:
    """Runs main.py once; returns {exit_code, wall_seconds, timed_out}. Never raises."""
    run_dir.mkdir(parents=True, exist_ok=True)
    cmd = build_command(target, workflow_path, run_dir, settings)
    (run_dir / "command.txt").write_text(" ".join(cmd) + "\n", encoding="utf-8")
    env = dict(os.environ)
    env.setdefault("VERTEXAI_LOCATION", "global")
    env.setdefault("PYTHONUNBUFFERED", "1")
    started = time.time()
    timed_out = False
    with (run_dir / "stdout.log").open("wb") as out:
        try:
            proc = subprocess.run(cmd, cwd=str(REFERENCE_ROOT), stdout=out, stderr=subprocess.STDOUT,
                                  env=env, timeout=settings.timeout_seconds, check=False)
            code = proc.returncode
        except subprocess.TimeoutExpired:
            code, timed_out = -1, True
        except OSError as exc:
            out.write(f"[adapter] could not start pipeline: {exc}\n".encode())
            code = -2
    return {"exit_code": code, "wall_seconds": round(time.time() - started, 1), "timed_out": timed_out}


# --- Reading a run ----------------------------------------------------------------------


def transcript_rows_to_events(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The structured transcript main.py --transcript-out writes, as adapter events.

    This is the preferred source: tool responses are complete (clipped only
    at core.transcript's generous limits, with a marker), not the console's
    500-character echo, and no line of a file read can be mistaken for prose.
    """
    events: List[Dict[str, Any]] = []
    for row in rows:
        kind = str(row.get("type") or "")
        node = str(row.get("node") or row.get("author") or "")
        if kind == "tool_call":
            events.append({"type": "tool_call", "node": node, "name": str(row.get("name") or ""), "args": str(row.get("args") or "")})
        elif kind == "tool_response":
            events.append({"type": "tool_response", "node": node, "name": str(row.get("name") or ""), "text": str(row.get("response") or "")})
        elif kind == "text":
            text = str(row.get("text") or "").strip()
            if text:
                events.append({"type": "message", "node": node, "text": text})
        elif kind == "error":
            events.append({"type": "error", "node": node, "name": str(row.get("name") or ""), "text": str(row.get("text") or "")})
    return events


def parse_stdout_to_events(text: str) -> List[Dict[str, Any]]:
    """Fallback when no structured transcript exists: the console stream as events.

    main.py prints node banners, ``[TOOL CALL: name] args=...`` and
    ``[TOOL RESPONSE: name] ...`` lines, and the model's prose in between.
    The console clips every tool response to ~500 characters, and a
    multi-line response spills into following lines, so this is a sketch of
    the run, not a record; ``summary.json`` says which source was used.
    """
    events: List[Dict[str, Any]] = []
    prose: List[str] = []
    node = ""

    def flush_prose():
        nonlocal prose
        body = "\n".join(prose).strip()
        if body:
            events.append({"type": "message", "node": node, "text": body})
        prose = []

    for raw in text.splitlines():
        line = raw.rstrip("\r")
        m = _NODE_RE.match(line)
        if m:
            flush_prose()
            node = m.group(1).split("/")[-1].split("@")[0]
            events.append({"type": "node", "node": node, "route": m.group(2) or ""})
            continue
        m = _TOOL_CALL_RE.match(line)
        if m:
            flush_prose()
            events.append({"type": "tool_call", "node": node, "name": m.group(1), "args": m.group(2)})
            continue
        m = _TOOL_RESP_RE.match(line)
        if m:
            flush_prose()
            kind = {"RESPONSE": "tool_response", "FEEDBACK": "tool_response", "FATAL ERROR": "error"}[m.group(1)]
            events.append({"type": kind, "node": node, "name": m.group(2), "text": m.group(3)})
            continue
        m = _EVENT_ERR_RE.match(line)
        if m:
            flush_prose()
            events.append({"type": "error", "node": node, "name": m.group(1), "text": m.group(2)})
            continue
        prose.append(line)
    flush_prose()
    return events


def render_trajectory(events: Sequence[Dict[str, Any]], obs_trunc: int) -> str:
    """Harness2's shared [ACTION]/[OBSERVATION]/[ERROR] grammar, one event per block."""
    from core.truncation import truncate_with_marker

    lines: List[str] = []
    for i, ev in enumerate(events, 1):
        node = f" ({ev.get('node')})" if ev.get("node") else ""
        kind = ev.get("type")
        if kind == "node":
            lines.append(f"[STAGE {i}]{node} entered" + (f" via route {ev['route']}" if ev.get("route") else ""))
        elif kind == "tool_call":
            lines.append(f"[ACTION {i}]{node} {ev.get('name')} {truncate_with_marker(str(ev.get('args') or ''), obs_trunc, 'tool arguments')}")
        elif kind == "tool_response":
            lines.append(f"[OBSERVATION {i}]{node} {ev.get('name')}: {truncate_with_marker(str(ev.get('text') or ''), obs_trunc, 'tool output')}")
        elif kind == "error":
            lines.append(f"[ERROR {i}]{node} {ev.get('name')}: {truncate_with_marker(str(ev.get('text') or ''), obs_trunc, 'error output')}")
        else:
            lines.append(f"[MESSAGE {i}]{node} {truncate_with_marker(str(ev.get('text') or ''), obs_trunc, 'model message')}")
    return "\n\n".join(lines) + ("\n" if lines else "")


def _call_filepath(args: Any) -> str:
    """The file a tool call names, if any, from its repr'd args."""
    m = re.search(r"'(?:filepath|path)':\s*'([^']*)'", str(args or ""))
    return m.group(1) if m else ""


def _is_whole_file_read(args: Any) -> bool:
    text = str(args or "")
    for key in ("start_line", "end_line"):
        m = re.search(rf"'{key}':\s*(\d+)", text)
        if m and int(m.group(1)) > 0:
            return False
    return True


# A tool response that did not give the stage what it asked for. Counted per
# tool in the digest so a reader sees "find_symbol×12 (12 unproductive)" and
# not just "find_symbol×12": live, an aggregator kept a proposal that removed
# the stage those tools depend on because the call counts looked like use.
_UNPRODUCTIVE_RESPONSE_RE = re.compile(
    r"^\s*(?:ERROR\b|Error\b|SANDBOX-ERROR|SANDBOX-UNAVAILABLE|FATAL|refused\b|NO_DATA\b|"
    r"Structural index unavailable|no such file|not found\b|Unknown tool|Tool .* not found|"
    r'\{\s*"error"\s*:)',
    re.IGNORECASE,
)


def is_unproductive_response(text: Any) -> bool:
    body = str(text or "")
    if not body.strip():
        return True
    return bool(_UNPRODUCTIVE_RESPONSE_RE.match(body))


def render_digest(events: Sequence[Dict[str, Any]], body: str = "") -> str:
    """A one-screen map of a trajectory, for a reader that cannot read all of it.

    A rollout of the full graph over a few dozen files renders to ~1 MB; the
    proposer reads it 20 KB at a time and cannot see the shape of the run
    from inside one page. This puts the shape first: per stage, how many tool
    calls of which kind, how many whole-file versus windowed reads, which
    files were read most, what the stage reported, and where in the rendered
    text the stage starts, so the reader can jump instead of paging.
    """
    per_stage: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []

    def stage(name: str) -> Dict[str, Any]:
        if name not in per_stage:
            per_stage[name] = {"calls": {}, "unproductive": {}, "whole_reads": 0, "windowed_reads": 0, "files": {},
                               "reported": 0, "errors": 0, "messages": 0, "first_event": None}
            order.append(name)
        return per_stage[name]

    for i, ev in enumerate(events, 1):
        name = str(ev.get("node") or "?")
        st = stage(name)
        if st["first_event"] is None:
            st["first_event"] = i
        kind = ev.get("type")
        if kind == "tool_call":
            tool = str(ev.get("name") or "")
            st["calls"][tool] = st["calls"].get(tool, 0) + 1
            if tool == "read_file":
                if _is_whole_file_read(ev.get("args")):
                    st["whole_reads"] += 1
                else:
                    st["windowed_reads"] += 1
            fp = _call_filepath(ev.get("args"))
            if fp and tool in ("read_file", "get_function_boundary", "find_callers", "find_symbol"):
                st["files"][fp] = st["files"].get(fp, 0) + 1
            if tool == "report_findings":
                st["reported"] += str(ev.get("args") or "").count("'title'")
        elif kind == "tool_response":
            if is_unproductive_response(ev.get("text")):
                tool = str(ev.get("name") or "")
                st["unproductive"][tool] = st["unproductive"].get(tool, 0) + 1
        elif kind == "error":
            st["errors"] += 1
        elif kind == "message":
            st["messages"] += 1

    # Line offsets of each stage's first event in the rendered body, so the
    # digest can say "stage X starts at line N" (N counted in the final file,
    # digest included -- the digest's own length is added after it is built).
    starts: Dict[str, int] = {}
    if body:
        first_idx = {st["first_event"]: name for name, st in per_stage.items() if st["first_event"] is not None}
        for line_no, line in enumerate(body.split("\n"), 1):
            m = re.match(r"\[(?:STAGE|ACTION|OBSERVATION|ERROR|MESSAGE) (\d+)\]", line)
            if m:
                name = first_idx.get(int(m.group(1)))
                if name and name not in starts:
                    starts[name] = line_no

    total_calls = sum(sum(st["calls"].values()) for st in per_stage.values())
    lines = [
        "# TRAJECTORY DIGEST (harness-generated map; the full trajectory follows)",
        f"events: {len(events)}  tool calls: {total_calls}  stages: {len(order)}  rendered: ~{len(body):,} chars",
        "Read this map, then open targeted line ranges of the stages you care about; the file is "
        "far larger than one read.",
        "",
    ]
    header = ["stage", "tool calls (by tool; ✗n = n answered with an error/empty/unavailable)", "reads whole/windowed", "reported", "errors", "starts at line"]
    rows = []
    for name in order:
        st = per_stage[name]
        def _fmt(t: str, n: int) -> str:
            bad = st["unproductive"].get(t, 0)
            return f"{t}×{n}" + (f" (✗{bad})" if bad else "")
        calls = ", ".join(_fmt(t, n) for t, n in sorted(st["calls"].items(), key=lambda kv: (-kv[1], kv[0]))[:6]) or "-"
        rows.append([name, calls, f"{st['whole_reads']}/{st['windowed_reads']}", str(st["reported"]),
                     str(st["errors"]), "?" if name not in starts else "@DIGEST_OFFSET+" + str(starts[name])])
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join("---" for _ in header) + "|")
    for r in rows:
        lines.append("| " + " | ".join(r) + " |")
    hot = {}
    for st in per_stage.values():
        for fp, n in st["files"].items():
            hot[fp] = hot.get(fp, 0) + n
    if hot:
        top = sorted(hot.items(), key=lambda kv: -kv[1])[:12]
        lines.append("")
        lines.append("most-touched files: " + ", ".join(f"{fp} ×{n}" for fp, n in top))
    lines.append("")
    lines.append("# FULL TRAJECTORY")
    digest = "\n".join(lines) + "\n\n"
    # Now that the digest's length is known, make the offsets absolute.
    return _apply_shift(digest, digest.count("\n"))


def _apply_shift(digest: str, shift: int) -> str:
    def repl(m: re.Match) -> str:
        return str(int(m.group(1)) + shift)
    return re.sub(r"@DIGEST_OFFSET\+(\d+)", repl, digest)


def evidence_vector(findings: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """What the pipeline itself established about a run's findings -- no answer key.

    Counts findings by INV-1 tier and folds them into one severity-weighted
    score. ``verified_keys`` identifies the findings that reached a machine
    proof (sandbox sentinel or re-attack), which is what a non-regression
    check compares across candidates.
    """
    by_status: Dict[str, int] = {}
    score = 0.0
    verified: List[str] = []
    confirmed: List[str] = []
    live = 0
    dismissed = 0
    for f in findings:
        status = str(f.get("status") or "reported").strip().lower()
        by_status[status] = by_status.get(status, 0) + 1
        sev = str(f.get("severity") or "medium").strip().lower()
        if status in DISMISSED_STATUSES:
            dismissed += 1
            score -= 0.25 * SEVERITY_WEIGHTS.get(sev, 1.0)
            continue
        live += 1
        w = EVIDENCE_WEIGHTS.get(status, 0.0) * SEVERITY_WEIGHTS.get(sev, 1.0)
        score += w
        if status in CONFIRMED_STATUSES:
            confirmed.append(_finding_key(f))
        if status in MACHINE_VERIFIED_STATUSES:
            verified.append(_finding_key(f))
    return {
        "by_status": dict(sorted(by_status.items())),
        "live": live,
        "dismissed": dismissed,
        "verified": len(verified),
        "verified_keys": sorted(set(verified)),
        "confirmed": len(confirmed),
        "confirmed_keys": sorted(set(confirmed)),
        "score": round(score, 3),
    }


def _finding_key(f: Dict[str, Any]) -> str:
    """An identity for a finding that survives across independent rollouts.

    Each rollout has its own knowledge DB, so lineage ids do not compare;
    titles are paraphrased from run to run. File plus weakness class is what
    two runs reporting the same bug agree on. Falls back to the leading title
    words when no CWE/class is recorded.
    """
    path = str(f.get("filepath") or "").replace("\\", "/").strip("/")
    cwe = str(f.get("cwe") or f.get("cwe_id") or f.get("vulnerability_class") or f.get("class") or "").strip().lower()
    cwe = re.sub(r"[^a-z0-9]+", "", cwe)
    if cwe:
        return f"{path}#{cwe}"
    title = re.sub(r"[^a-z0-9]+", " ", str(f.get("title") or "").lower()).strip()
    return f"{path}::{' '.join(title.split()[:6])}"


def render_findings_report(findings: Sequence[Dict[str, Any]], evidence: Dict[str, Any]) -> str:
    """The deliverable as text: what was found and how firmly, nothing about a score."""
    lines = [f"# Findings ({evidence.get('live', 0)} live, {evidence.get('verified', 0)} machine-verified, "
             f"{evidence.get('dismissed', 0)} dismissed)", ""]
    for f in sorted(findings, key=lambda x: (-EVIDENCE_WEIGHTS.get(str(x.get('status') or 'reported'), 0.0), str(x.get('filepath') or ''))):
        status = str(f.get("status") or "reported")
        lines.append(f"## [{status}] {f.get('title') or '(untitled)'}")
        lines.append(f"- file: {f.get('filepath') or '?'}  lines: {f.get('line_numbers') or f.get('lines') or '?'}")
        lines.append(f"- severity: {f.get('severity') or '?'}  cwe: {f.get('cwe') or f.get('cwe_id') or '?'}")
        if f.get("repro_status") or f.get("reattack_status"):
            lines.append(f"- repro: {f.get('repro_status') or '-'}  re-attack: {f.get('reattack_status') or '-'}")
        desc = str(f.get("description") or "").strip()
        if desc:
            lines.append("")
            lines.append(desc)
        lines.append("")
    return "\n".join(lines) + "\n"


def _read_findings(db_path: Path, run_id: str) -> List[Dict[str, Any]]:
    if not db_path.exists():
        return []
    try:
        from core.database import read_findings
        rows = read_findings(str(db_path), run_id=run_id or None)
        return [dict(r) for r in rows]
    except Exception:
        return []


# --- The adapter ------------------------------------------------------------------------


class MantisAdapterBase:
    """Shared rollout/read logic. Subclasses decide what a task is and whether it can be scored."""

    name = "mantis"

    def __init__(self, *, workflow_path: Path | str, runs_root: Path | str, settings: Optional[RunSettings] = None,
                 domain: str = "mantis", work: str = "", runner: Optional[Callable[..., Dict[str, Any]]] = None,
                 obs_trunc: int = 20_000):
        h2 = load_harness2()
        from harness2.core.spec import BenchPrompts, BenchSpec, ChannelSpec

        self.workflow_path = Path(workflow_path)
        self.runs_root = Path(runs_root)
        self.settings = settings or RunSettings()
        self._domain = domain
        self._runner = runner or run_pipeline
        self._base_workflow = json.loads(self.workflow_path.read_text(encoding="utf-8"))
        self._base_tree = hsurface.base_tree(self.workflow_path)
        self.substrate = _MantisSubstrate(self._base_workflow)
        # The channel kind is an upstream label; MantisProposer overrides call()
        # and never shells out to an OpenCode or Claude binary.
        channel = ChannelSpec("opencode", self.settings.model or "mantis/adk")
        self.spec = BenchSpec(
            name=self.name,
            runs_root=self.runs_root,
            install_mode="workspace_config",
            prompts=BenchPrompts(
                work=work or (
                    "audit a codebase for real, exploitable vulnerabilities and report each with "
                    "the file, the mechanism end to end, and the strongest evidence the pipeline "
                    "could establish for it"
                ),
                domain_word="codebase",
                deliverable_word="findings report",
            ),
            channels={"proposer": channel, "selector": channel},
            leak_globs=ANSWER_KEY_GLOBS,
            allow_subagents=False,
            obs_trunc=max(10_000, int(obs_trunc)),
        )

    # -- tasks: subclass responsibility
    def tasks(self, split: str = "all") -> List[str]:  # pragma: no cover - abstract
        raise NotImplementedError

    def target_for(self, task_id: str) -> Path:  # pragma: no cover - abstract
        raise NotImplementedError

    def domain_of(self, task_id: str) -> str:
        return self._domain

    def task_prompt(self, task_id: str) -> str:
        return (f"Audit the code under '{self.target_for(task_id).name}' for real, exploitable "
                "vulnerabilities. Trace data from untrusted inputs to dangerous operations, including "
                "across files, and report every confirmed flaw with its file, lines and mechanism.")

    def task_files(self, task_id: str) -> Optional[Path]:
        # The trajectories already carry every file the pipeline read; copying
        # the whole target into each proposer context would be the one cost
        # that dominates, for little the proposer could not see already.
        return None

    # -- harness
    def base_harness(self) -> Path:
        dest = self.runs_root / "base_harness"
        if not (dest / hsurface.WORKFLOW_FILE).exists():
            hsurface.write_base_harness(self.workflow_path, dest)
        return dest

    def base_tree(self) -> Dict[str, str]:
        return dict(self._base_tree)

    def validate_tree(self, tree: Dict[str, str]) -> None:
        hsurface.validate_tree(tree, self._base_tree)

    # -- rollout
    def run_dir_for(self, run_id: str) -> Path:
        return self.runs_root / "rollouts" / run_id

    def execute(self, task_id: str, harness_dir: Optional[Path], run_id: str, *, timeout: Optional[int] = None) -> Path:
        load_harness2()
        from harness2.core import runmark

        run_dir = self.run_dir_for(run_id)
        if runmark.is_complete(run_dir, harness_dir=harness_dir):
            return run_dir
        if run_dir.exists():
            shutil.rmtree(run_dir)
        run_dir.mkdir(parents=True)

        tree = hsurface.read_tree(harness_dir, self._base_workflow) if harness_dir is not None else self.base_tree()
        # Omitted-is-inherited: a proposal only carries what it changed.
        merged = dict(self._base_tree)
        merged.update(tree)
        hsurface.validate_tree(merged, self._base_tree)
        workflow_path = hsurface.compile_to_file(merged, run_dir / "workflow.json")

        settings = self.settings
        if timeout:
            settings = RunSettings(**{**settings.__dict__, "timeout_seconds": int(timeout)})
        outcome = self._runner(self.target_for(task_id), workflow_path, run_dir, settings)
        self._write_artifacts(run_dir, outcome)
        if outcome.get("exit_code") == 0:
            spend = _read_json(run_dir / "spend.json", {})
            runmark.mark_complete(run_dir, run_id=run_id, harness_dir=harness_dir,
                                  extra={"task_id": task_id, "pipeline_run_id": spend.get("run_id", ""),
                                         "tokens": spend.get("tokens", 0)})
        return run_dir

    def _write_artifacts(self, run_dir: Path, outcome: Dict[str, Any]) -> None:
        spend = _read_json(run_dir / "spend.json", {})
        pipeline_run_id = str(spend.get("run_id") or "")
        findings = _read_findings(run_dir / "knowledge.db", pipeline_run_id)
        evidence = evidence_vector(findings)
        from core.transcript import read_transcript
        rows = read_transcript(run_dir / "transcript.raw.jsonl") if (run_dir / "transcript.raw.jsonl").exists() else []
        if rows:
            events, trajectory_source = transcript_rows_to_events(rows), "transcript"
        else:
            stdout = (run_dir / "stdout.log").read_text(encoding="utf-8", errors="replace") if (run_dir / "stdout.log").exists() else ""
            events, trajectory_source = parse_stdout_to_events(stdout), "stdout"
        (run_dir / "trajectory.jsonl").write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in events), encoding="utf-8")
        (run_dir / "findings.json").write_text(json.dumps(findings, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
        (run_dir / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (run_dir / "findings.md").write_text(render_findings_report(findings, evidence), encoding="utf-8")
        summary = {**outcome, "pipeline_run_id": pipeline_run_id, "tokens": spend.get("tokens", 0),
                   "llm_calls": spend.get("llm_calls", 0), "events": len(events), "findings": len(findings),
                   "trajectory_source": trajectory_source, "evidence": evidence}
        (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")

    # -- reading
    def delivered(self, run_dir: Path) -> bool:
        summary = _read_json(Path(run_dir) / "summary.json", {})
        return summary.get("exit_code") == 0 and (Path(run_dir) / "findings.json").exists()

    def describe_outcome(self, run_dir: Path) -> str:
        """One line on how a rollout ended, for the driver's log and adoption.json.

        A failed base rollout used to be reported as "no .adapt_complete", which
        is true and says nothing. This says whether the pipeline timed out or
        exited non-zero, after how long, at which stage, with how many findings
        already in the DB -- enough to decide between raising
        ``--rollout-timeout``, reading the stage's transcript, and giving up.
        """
        run_dir = Path(run_dir)
        summary = _read_json(run_dir / "summary.json", {})
        if not summary:
            return "no summary.json: the rollout never ran or was cut before it was recorded"
        code = summary.get("exit_code")
        wall = float(summary.get("wall_seconds") or 0.0)
        last_stage = ""
        from core.transcript import read_transcript
        for row in reversed(read_transcript(run_dir / "transcript.raw.jsonl")):
            if row.get("node"):
                last_stage = str(row["node"])
                break
        where = f" at stage {last_stage}" if last_stage else ""
        found = int(summary.get("findings") or 0)
        if summary.get("timed_out"):
            how = f"timed out after {wall:.0f}s (--rollout-timeout){where}"
        elif code == 0:
            how = f"exited 0 after {wall:.0f}s"
        elif code == -2:
            how = "could not start (see stdout.log)"
        else:
            how = f"exited {code} after {wall:.0f}s{where}"
        tail = ""
        if code != 0:
            tail = f"; last stderr lines in stdout.log; {found} finding(s) were in the DB"
        return how + tail

    def trajectory(self, run_dir: Path, *, obs_trunc: int) -> str:
        path = Path(run_dir) / "trajectory.jsonl"
        if not path.exists():
            return "(no trajectory: the run left no event stream)"
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        body = render_trajectory(events, obs_trunc)
        return render_digest(events, body) + body

    def deliverable_files(self, run_dir: Path) -> Dict[str, str]:
        path = Path(run_dir) / "findings.md"
        return {"findings.md": path.read_text(encoding="utf-8")} if path.exists() else {}

    def deliverable_text(self, run_dir: Path) -> str:
        return self.deliverable_files(run_dir).get("findings.md", "")

    def evidence(self, run_dir: Path) -> Dict[str, Any]:
        return _read_json(Path(run_dir) / "evidence.json", {})

    def score(self, run_dir: Path, task_id: str) -> Optional[dict]:  # pragma: no cover - overridden
        return None


class _MantisSubstrate:
    name = "mantis"

    def __init__(self, workflow: Dict[str, Any]):
        self._workflow = workflow

    def surface(self):
        return hsurface.surface_for(self._workflow)


class MantisRepoAdapter(MantisAdapterBase):
    """The user's code: tasks are target directories; there is no answer key.

    If a target does carry one anyway (the checked-in research target does,
    so does any generated target copied whole), the pipeline gets a copy
    with it left out. The adapter's leak globs name what counts."""

    #: What the pipeline must never see, as glob patterns on a file's name.
    ANSWER_KEY_GLOBS = ANSWER_KEY_GLOBS

    def __init__(self, *, targets: Dict[str, Path | str], **kw):
        super().__init__(**kw)
        if not targets:
            raise ValueError("at least one task -> target directory is required")
        self._targets = {str(k): Path(v) for k, v in targets.items()}
        for tid, path in self._targets.items():
            if not path.is_dir():
                raise ValueError(f"task {tid!r}: {path} is not a directory")
        self._jails: Dict[str, Path] = {}

    def tasks(self, split: str = "all") -> List[str]:
        return sorted(self._targets)

    def _answer_keys_in(self, target: Path) -> List[Path]:
        found: List[Path] = []
        for pattern in self.ANSWER_KEY_GLOBS:
            found.extend(p for p in target.rglob(pattern) if p.is_file())
        return sorted(set(found))

    def target_for(self, task_id: str) -> Path:
        target = self._targets[task_id]
        if task_id in self._jails:
            return self._jails[task_id]
        keys = self._answer_keys_in(target)
        if not keys:
            self._jails[task_id] = target
            return target
        # Copy without the answer key(s). Done once per adapter: every
        # rollout of this task (base and candidates) sees the same tree. The
        # copy keeps the target's name, which the task prompt shows.
        jail = self.runs_root / "targets" / task_id / (target.name or "app")
        if not jail.exists():
            jail.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(target, jail,
                            ignore=shutil.ignore_patterns(*self.ANSWER_KEY_GLOBS, "__pycache__", "*.pyc"))
        leaked = self._answer_keys_in(jail)
        if leaked:
            raise RuntimeError(f"answer key leaked into the rollout copy of {task_id}: {leaked[0]}")
        names = ", ".join(str(k.relative_to(target)) for k in keys)
        print(f"[evolve] {task_id}: rolling out on a copy without {names}", file=sys.stderr)
        self._jails[task_id] = jail
        return jail

    def score(self, run_dir: Path, task_id: str) -> Optional[dict]:
        # No ground truth exists for a user's repository, and nothing here
        # pretends otherwise: None is "not judged", never zero.
        return None


class MantisEvalAdapter(MantisAdapterBase):
    """Generated dev targets with ground truth; scoring only after selection."""

    def __init__(self, *, seeds: Sequence[int], size: str = "small", **kw):
        super().__init__(**kw)
        from evals.research_targets import gen

        self._seeds = [int(s) for s in seeds]
        for seed in self._seeds:
            gen.assert_not_holdout(seed, "harness evolution")
        self._size = size
        self._gen = gen

    def tasks(self, split: str = "all") -> List[str]:
        return [f"seed-{s}" for s in self._seeds]

    def domain_of(self, task_id: str) -> str:
        return f"{self._domain}/{self._size}"

    def _seed(self, task_id: str) -> int:
        return int(task_id.split("-", 1)[1])

    def target_for(self, task_id: str) -> Path:
        seed = self._seed(task_id)
        root = self.runs_root / "targets" / f"{seed}_{self._size}"
        jail = root / "app"
        if not (jail / "app.py").exists():
            full = root / "full"
            self._gen.write_target(full, seed, self._size)
            # The pipeline must never see the answer key: copy without it.
            from evals.research_eval import GROUND_TRUTH_BASENAME
            shutil.copytree(full, jail, dirs_exist_ok=True, ignore=shutil.ignore_patterns(GROUND_TRUTH_BASENAME, "__pycache__"))
        return jail

    def ground_truth_path(self, task_id: str) -> Path:
        from evals.research_eval import GROUND_TRUTH_BASENAME
        self.target_for(task_id)
        return self.runs_root / "targets" / f"{self._seed(task_id)}_{self._size}" / "full" / GROUND_TRUTH_BASENAME

    def score(self, run_dir: Path, task_id: str) -> Optional[dict]:
        """Called only by harness2.core.judge, only after selection committed."""
        from evals.research_eval import load_research_ground_truth, score_research_findings

        findings = _read_json(Path(run_dir) / "findings.json", None)
        if not isinstance(findings, list):
            return None
        gt = load_research_ground_truth(self.ground_truth_path(task_id))
        r = score_research_findings(findings, gt)
        return {"n_passed": r["detected"], "n_criteria": r["ground_truth_total"],
                "all_pass": r["detected"] == r["ground_truth_total"], "detail": r}


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default

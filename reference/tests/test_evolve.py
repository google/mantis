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

"""The Harness2 loop over a Mantis harness, end to end with no model:
surface round-trip and validation, the adapter over a fake pipeline, the
ADK proposer over a scripted agent, evidence-first selection, and one full
Propose-Probe-Compose iteration whose ledger identity holds."""

from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from core.database import init_db, write_findings  # noqa: E402
from evals.evolve import adapter as ad  # noqa: E402
from evals.evolve import run as ev_run  # noqa: E402
from evals.evolve import selection as ev_sel  # noqa: E402
from evals.evolve import surface as S  # noqa: E402
from evals.evolve import surface_text  # noqa: E402
from evals.evolve._vendor import load_harness2  # noqa: E402
from evals.evolve.proposer import MantisProposer, make_context_tools  # noqa: E402

WORKFLOW = _REF_ROOT / "workflow.json"
EDIT_MARKER = "Prefer get_function_boundary over whole-file reads."


# --- Fakes ---------------------------------------------------------------------------------


def fake_pipeline(target: Path, workflow_path: Path, run_dir: Path, settings) -> dict:
    """Stands in for main.py: leaves spend.json, knowledge.db and stdout.log behind.

    A harness whose researcher prompt carries EDIT_MARKER "finds" one more,
    machine-verified bug; every harness finds the base static one.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    wf = json.loads(workflow_path.read_text(encoding="utf-8"))
    researcher = next(n for n in wf["nodes"] if n["id"] == "researcher")
    improved = EDIT_MARKER in str(researcher.get("system_prompt") or "")
    run_id = f"pipe-{run_dir.name}"
    db = run_dir / "knowledge.db"
    init_db(str(db))
    findings = [{"title": "SQL injection in find_user", "severity": "HIGH", "status": "static_confirmed",
                 "description": "f-string query", "line_numbers": [12], "filepath": "dal/users.py", "cwe": "CWE-89"}]
    if improved:
        findings.append({"title": "Command injection in export", "severity": "CRITICAL", "status": "dynamic_confirmed",
                         "description": "shell=True with request data", "line_numbers": [30], "filepath": "services/export.py", "cwe": "CWE-78"})
    write_findings(str(db), "dal/users.py", findings, run_id=run_id)
    (run_dir / "spend.json").write_text(json.dumps({"run_id": run_id, "tokens": 400_000 if improved else 500_000,
                                                    "llm_calls": 20, "exit_code": 0}), encoding="utf-8")
    # The console echo clips every tool response and spills file lines as prose...
    (run_dir / "stdout.log").write_text(
        "-- mantis_vulnerability_pipeline@1/researcher@1\n"
        "[TOOL CALL: read_file] args={'filepath': 'dal/users.py'}\n"
        "[TOOL RESPONSE: read_file] <<<UNTRUSTED_SOURCE_CODE_DATA_START path=dal/users.py>>>\n"
        "def find_user(name):\n    return conn.execute(f\"SELECT * FROM users WHERE name='{name}'\")\n"
        "I will report the query flaw.\n"
        "[TOOL CALL: report_findings] args={'findings': [...]}\n"
        "[TOOL RESPONSE: report_findings] Recorded 1 finding(s).\n", encoding="utf-8")
    # ...while --transcript-out carries the complete rows (the adapter must prefer these).
    big_file = "def find_user(name):\n" + "    pass\n" * 400 + "    return conn.execute(f\"SELECT * FROM users WHERE name='{name}'\")\n"
    rows = [
        {"author": "researcher", "node": "researcher", "type": "tool_call", "name": "read_file", "args": "{'filepath': 'dal/users.py'}"},
        {"author": "researcher", "node": "researcher", "type": "tool_response", "name": "read_file", "response": big_file},
        {"author": "researcher", "node": "researcher", "type": "text", "text": "I will report the query flaw."},
        {"author": "researcher", "node": "researcher", "type": "tool_call", "name": "report_findings", "args": "{'findings': [...]}"},
        {"author": "researcher", "node": "researcher", "type": "tool_response", "name": "report_findings", "response": "Recorded 1 finding(s)."},
        {"author": "reviewer", "node": "reviewer", "type": "error", "name": "RateLimitError", "text": "429 slow down"},
    ]
    (run_dir / "transcript.raw.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return {"exit_code": 0, "wall_seconds": 1.0, "timed_out": False}


def scripted_agent(*, mission: str, system: str, context_root: Path, touched, label: str, timeout, read_only=False):
    """Edits like a proposer would, chooses like a selector would, reflects like a reflector would."""
    harness = context_root / "harness"
    if label.startswith("select."):
        ids = sorted(p.stem for p in (context_root / "candidates").glob("*.md"))
        return {"text": f"<why>Both reports are equivalent; the first is plainer.</why>\n```choice\n{ids[0]}\n```", "steps": 2, "tokens": 100}
    if label.startswith("experience."):
        return {"text": ("<experience>\ncue: auditing a Flask service with route -> service -> store layers\n"
                         "lesson: give the researcher get_function_boundary and tell it to prefer spans over whole files\n"
                         "evidence: the agg1 rollout's researcher reported the export sink the base missed after reading spans\n"
                         "confidence: medium\n</experience>"), "steps": 1, "tokens": 50}
    # inv / dom / agg proposals: append one line to the researcher prompt.
    p = harness / "prompts" / "researcher.md"
    if p.exists():
        p.write_text(p.read_text(encoding="utf-8").rstrip() + "\n" + EDIT_MARKER + "\n", encoding="utf-8")
        touched.append("prompts/researcher.md")
    return {"text": "<notes>researcher: the base trajectory read dal/users.py whole three times; spans are cheaper.</notes>",
            "steps": 3, "tokens": 200}


def _adapter(tmp: Path, target: Path) -> ad.MantisRepoAdapter:
    return ad.MantisRepoAdapter(targets={"demo": target}, workflow_path=WORKFLOW, runs_root=tmp / "runs",
                                settings=ad.RunSettings(model="m", timeout_seconds=60), runner=fake_pipeline, domain="demo")


# --- Surface -------------------------------------------------------------------------------


class SurfaceTest(unittest.TestCase):
    def test_base_tree_compiles_back_to_an_equivalent_workflow(self):
        tree = S.base_tree(WORKFLOW)
        self.assertIn("workflow.json", tree)
        self.assertIn("prompts/researcher.md", tree)
        compiled = S.compile_tree(tree)
        original = json.loads(WORKFLOW.read_text(encoding="utf-8"))
        self.assertEqual([n["id"] for n in compiled["nodes"]], [n["id"] for n in original["nodes"]])
        researcher = next(n for n in compiled["nodes"] if n["id"] == "researcher")
        self.assertIn("Researcher", researcher["system_prompt"])

    def test_validation_names_every_problem_at_once(self):
        tree = S.base_tree(WORKFLOW)
        bad = dict(tree)
        wf = json.loads(bad["workflow.json"])
        next(n for n in wf["nodes"] if n["id"] == "researcher")["tools"].append("not_a_tool")
        wf["config"]["sandbox"]["type"] = "gce"
        bad["workflow.json"] = json.dumps(wf)
        bad["prompts/ghost.md"] = "for a node that does not exist"
        bad["prompts/critic.md"] = "x" * (S.MAX_NODE_PROMPT_CHARS + 1)
        with self.assertRaises(ValueError) as cm:
            S.validate_tree(bad, tree)
        msg = str(cm.exception)
        for needle in ("not_a_tool", "sandbox.type", "ghost.md", "critic", "cap"):
            self.assertIn(needle, msg)

    def test_validation_and_execute_reject_config_budget_and_api_base_tampering(self):
        tree = S.base_tree(WORKFLOW)

        def mutate_wf(fn):
            cand = dict(tree)
            wf = json.loads(cand["workflow.json"])
            fn(wf)
            cand["workflow.json"] = json.dumps(wf)
            return cand

        cases = [
            ("evidence_sources", lambda wf: wf["config"].update({"evidence_sources": [{"type": "os:system"}]})),
            ("sandbox", lambda wf: wf["config"]["sandbox"].update({"runtime": "runc", "options": {"gcloud_bin": "/tmp/evil"}})),
            ("api_base", lambda wf: wf["config"].update({"api_base": "http://127.0.0.1:9999"})),
            ("sarif_output", lambda wf: wf["config"].update({"sarif_output": "/tmp/out.sarif"})),
            ("budget", lambda wf: wf.update({"budget": {"max_cost_usd": 999999.0}})),
            ("api_base", lambda wf: next(n for n in wf["nodes"] if n["id"] == "researcher").update({"api_base": "http://evil.invalid"})),
        ]
        for expected_substr, mutator in cases:
            with self.subTest(expected=expected_substr):
                bad = mutate_wf(mutator)
                with self.assertRaises(ValueError) as cm:
                    S.validate_tree(bad, tree)
                self.assertIn(expected_substr, str(cm.exception))

        # Direct adapter.execute() also enforces validate_tree before compiling/running.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            target = tmp_p / "repo"; target.mkdir(); (target / "app.py").write_text("print(1)\n")
            adapter = _adapter(tmp_p, target)
            evil_harness = tmp_p / "evil_harness"; evil_harness.mkdir()
            bad_wf = json.loads(tree["workflow.json"])
            bad_wf["config"]["evidence_sources"] = [{"type": "os:system"}]
            (evil_harness / "workflow.json").write_text(json.dumps(bad_wf), encoding="utf-8")
            with self.assertRaises(ValueError):
                adapter.execute("demo", evil_harness, "demo--evil1")

    def test_surface_admits_only_the_three_file_kinds(self):
        wf = json.loads(WORKFLOW.read_text())
        self.assertTrue(S.on_surface("workflow.json", wf))
        self.assertTrue(S.on_surface("prompts/researcher.md", wf))
        self.assertTrue(S.on_surface("tool_guidance.md", wf))
        # Upstream's regex admits scripts/*.py for every surface; ours does not, and
        # validate_tree rejects a tree that carries one.
        self.assertFalse(S.on_surface("scripts/evil.py", wf))
        self.assertFalse(S.on_surface("../workflow.json", wf))
        self.assertFalse(S.on_surface("prompts/not_a_node.md", wf))
        self.assertFalse(S.on_surface("prompts/nested/researcher.md", wf))
        tree = S.base_tree(WORKFLOW)
        bad = dict(tree); bad["scripts/evil.py"] = "print(1)"
        with self.assertRaises(ValueError) as cm:
            S.validate_tree(bad, tree)
        self.assertIn("not on the editable surface", str(cm.exception))

    def test_a_proposal_may_add_a_stage_inline_and_remove_one(self):
        tree = S.base_tree(WORKFLOW)
        wf = json.loads(tree["workflow.json"])
        # Add a second researcher arm with an inline instruction, wired threat_modeler -> arm -> deduplicator.
        researcher = next(n for n in wf["nodes"] if n["id"] == "researcher")
        arm = json.loads(json.dumps(researcher)); arm["id"] = "researcher_domain"
        arm["system_prompt"] = "You are the domain researcher arm. Audit auth and trust boundaries; report via report_findings."
        wf["nodes"].append(arm)
        in_edges = [e for e in wf["edges"] if e["to"] == "researcher"]
        out_edges = [e for e in wf["edges"] if e["from"] == "researcher"]
        for e in in_edges:
            wf["edges"].append({**e, "to": "researcher_domain"})
        for e in out_edges:
            wf["edges"].append({**e, "from": "researcher_domain"})
        added = dict(tree); added["workflow.json"] = json.dumps(wf, indent=2)
        census = S.validate_tree(added, tree)
        self.assertEqual(census["agent_nodes"], len([n for n in wf["nodes"] if n.get("type", "agent") == "agent"]))
        compiled = S.compile_tree(added)
        self.assertIn("domain researcher arm", next(n for n in compiled["nodes"] if n["id"] == "researcher_domain")["system_prompt"])
        # A prompt FILE for the new stage is the wrong place, and the message says where the right one is.
        wrong = dict(added); wrong["prompts/researcher_domain.md"] = "domain arm prompt"
        with self.assertRaises(ValueError) as cm:
            S.validate_tree(wrong, tree)
        self.assertIn("system_prompt", str(cm.exception))
        self.assertFalse(S.on_surface("prompts/researcher_domain.md", json.loads(tree["workflow.json"])))
        # A new stage with no instruction at all is refused.
        mute = json.loads(json.dumps(wf)); next(n for n in mute["nodes"] if n["id"] == "researcher_domain").pop("system_prompt")
        next(n for n in mute["nodes"] if n["id"] == "researcher_domain").pop("skill", None)
        mute_tree = dict(tree); mute_tree["workflow.json"] = json.dumps(mute)
        with self.assertRaises(ValueError) as cm:
            S.validate_tree(mute_tree, tree)
        self.assertIn("no instruction", str(cm.exception))

        # Remove a stage: its (inherited, or upstream-stubbed) prompt file is ignored, not an error.
        # The removal must rewire the route that fed it; the loader has the final word on that.
        wf2 = json.loads(tree["workflow.json"])
        wf2["nodes"] = [n for n in wf2["nodes"] if n["id"] != "chainer"]
        wf2["edges"] = [e for e in wf2["edges"] if "chainer" not in (e["from"], e["to"])]
        wf2["edges"].append({"from": "repro_classifier", "to": "patcher", "on": "success"})
        removed = dict(tree); removed["workflow.json"] = json.dumps(wf2)
        S.validate_tree(removed, tree)                       # inherited prompts/chainer.md present
        removed["prompts/chainer.md"] = ""                   # upstream write_tree stubs always-on files as ""
        S.validate_tree(removed, tree)
        self.assertNotIn("chainer", {n["id"] for n in S.compile_tree(removed)["nodes"]})
        # Removing it without rewiring is refused by the production loader, with the orphaned route named.
        dangling = json.loads(tree["workflow.json"])
        dangling["nodes"] = [n for n in dangling["nodes"] if n["id"] != "chainer"]
        dangling["edges"] = [e for e in dangling["edges"] if "chainer" not in (e["from"], e["to"])]
        with self.assertRaises(ValueError) as cm:
            S.validate_tree({**tree, "workflow.json": json.dumps(dangling)}, tree)
        self.assertIn("repro_classifier", str(cm.exception))

    def test_registered_surface_text_renders_all_prompt_families(self):
        surface_text.register()
        from harness2.core import prompts as P
        from harness2.core.spec import BenchPrompts
        bp = BenchPrompts(work="audit a codebase for real vulnerabilities", domain_word="codebase")
        for text in (P.propose(bp, "INV", "mantis", k=1, index=1), P.propose(bp, "DOM", "mantis", k=1, index=1),
                     P.aggregate(bp, "mantis", k=1, index=1)):
            self.assertIn("workflow.json", text)
            self.assertIn("KEEP_BASE", text)
            self.assertIn("THE TOOL SET IS CLOSED", text)


# --- Adapter -------------------------------------------------------------------------------


class AdapterTest(unittest.TestCase):
    def test_stdout_parses_into_events_and_renders_with_truncation(self):
        events = ad.parse_stdout_to_events(
            "-- wf@1/researcher@1\nthinking...\n[TOOL CALL: read_file] args={'filepath': 'a.py'}\n"
            "[TOOL RESPONSE: read_file] " + "x" * 50 + "\n[EVENT ERROR BadRequestError] boom\n-- wf@1/reviewer@1 -> confirmed\n")
        kinds = [e["type"] for e in events]
        self.assertEqual(kinds, ["node", "message", "tool_call", "tool_response", "error", "node"])
        self.assertEqual(events[2]["node"], "researcher")
        text = ad.render_trajectory(events, obs_trunc=10_000)
        self.assertIn("[ACTION 3] (researcher) read_file", text)
        self.assertIn("[ERROR 5]", text)
        self.assertIn("[MANTIS TRUNCATION:", ad.render_trajectory(events, obs_trunc=20))

    def test_structured_transcript_is_preferred_over_the_clipped_console(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = tmp / "repo"; target.mkdir(); (target / "app.py").write_text("print(1)\n")
            adapter = _adapter(tmp, target)
            rd = adapter.execute("demo", None, "demo--base1")
            summary = json.loads((rd / "summary.json").read_text())
            self.assertEqual(summary["trajectory_source"], "transcript")
            text = adapter.trajectory(rd, obs_trunc=50_000)
            # One observation holding the whole file, not an empty observation followed by file lines as prose.
            self.assertEqual(text.count("[OBSERVATION"), 2)
            head, _, tail = text.partition("[OBSERVATION 2]")
            self.assertNotIn("pass", head)
            self.assertGreaterEqual(tail.split("[MESSAGE")[0].count("    pass\n"), 300)
            messages = [blk.strip() for blk in text.split("\n\n") if blk.strip().startswith("[MESSAGE")]
            self.assertEqual(len(messages), 1)
            self.assertIn("I will report the query flaw.", messages[0])
            self.assertIn("[ERROR 6] (reviewer) RateLimitError", text)
            cmd = ad.build_command(target, rd / "workflow.json", rd, ad.RunSettings())
            self.assertIn("--transcript-out", cmd)
            self.assertIn(str(rd / "transcript.raw.jsonl"), cmd)

    def test_console_fallback_is_labelled_as_such(self):
        def no_transcript(target, workflow_path, run_dir, settings):
            out = fake_pipeline(target, workflow_path, run_dir, settings)
            (run_dir / "transcript.raw.jsonl").unlink()
            return out
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = tmp / "repo"; target.mkdir(); (target / "app.py").write_text("print(1)\n")
            adapter = ad.MantisRepoAdapter(targets={"demo": target}, workflow_path=WORKFLOW, runs_root=tmp / "runs",
                                           settings=ad.RunSettings(model="m"), runner=no_transcript, domain="demo")
            rd = adapter.execute("demo", None, "demo--base1")
            self.assertEqual(json.loads((rd / "summary.json").read_text())["trajectory_source"], "stdout")

    def test_the_trajectory_opens_with_a_digest_whose_offsets_are_real(self):
        events = [
            {"type": "tool_call", "node": "architect", "name": "list_files", "args": "{}"},
            {"type": "tool_response", "node": "architect", "name": "list_files", "text": "a.py\nb.py"},
            {"type": "tool_call", "node": "architect", "name": "read_file", "args": "{'filepath': 'a.py'}"},
            {"type": "tool_response", "node": "architect", "name": "read_file", "text": "x\n" * 300},
            {"type": "tool_call", "node": "researcher", "name": "read_file", "args": "{'filepath': 'a.py', 'start_line': 10, 'end_line': 40}"},
            {"type": "tool_response", "node": "researcher", "name": "read_file", "text": "y\n" * 30},
            {"type": "tool_call", "node": "researcher", "name": "report_findings", "args": "{'findings': [{'title': 'A'}, {'title': 'B'}]}"},
            {"type": "tool_response", "node": "researcher", "name": "report_findings", "text": "Recorded 2"},
            {"type": "error", "node": "reviewer", "name": "RateLimitError", "text": "429"},
        ]
        body = ad.render_trajectory(events, 20_000)
        digest = ad.render_digest(events, body)
        full = digest + body
        self.assertTrue(full.startswith("# TRAJECTORY DIGEST"))
        self.assertIn("| architect | list_files×1, read_file×1 | 1/0 | 0 | 0 |", digest)
        self.assertIn("| researcher | read_file×1, report_findings×1 | 0/1 | 2 | 0 |", digest)
        self.assertIn("| reviewer | - | 0/0 | 0 | 1 |", digest)
        self.assertIn("most-touched files: a.py ×2", digest)
        # The "starts at line" column points at the stage's first event in the final file.
        for stage, marker in (("architect", "[ACTION 1] (architect)"), ("researcher", "[ACTION 5] (researcher)"),
                              ("reviewer", "[ERROR 9] (reviewer)")):
            row = next(r for r in digest.splitlines() if r.startswith(f"| {stage} "))
            line_no = int(row.split("|")[-2].strip())
            self.assertTrue(full.splitlines()[line_no - 1].startswith(marker), (stage, line_no))
        # And the adapter serves it in front of the body.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = tmp / "repo"; target.mkdir(); (target / "app.py").write_text("print(1)\n")
            adapter = _adapter(tmp, target)
            rd = adapter.execute("demo", None, "demo--base1")
            text = adapter.trajectory(rd, obs_trunc=50_000)
            self.assertTrue(text.startswith("# TRAJECTORY DIGEST"))
            self.assertIn("# FULL TRAJECTORY", text)
            self.assertIn("[OBSERVATION 2]", text)

    def test_the_digest_counts_unproductive_tool_answers(self):
        """An aggregator kept a proposal that removed structural_index because the call counts of the
        structural tools looked like use; every one of those calls had answered 'unavailable'."""
        events = [
            {"type": "tool_call", "node": "researcher", "name": "find_symbol", "args": "{'name': 'run_backup'}"},
            {"type": "tool_response", "node": "researcher", "name": "find_symbol",
             "text": "Structural index unavailable. Fall back to read_file and list_files; ..."},
            {"type": "tool_call", "node": "researcher", "name": "find_callers", "args": "{'symbol': 'load_blob'}"},
            {"type": "tool_response", "node": "researcher", "name": "find_callers", "text": "Structural index unavailable."},
            {"type": "tool_call", "node": "researcher", "name": "read_file", "args": "{'filepath': 'a.py'}"},
            {"type": "tool_response", "node": "researcher", "name": "read_file", "text": "def f(): pass\n"},
            {"type": "tool_call", "node": "researcher", "name": "get_findings", "args": "{}"},
            {"type": "tool_response", "node": "researcher", "name": "get_findings", "text": "NO_DATA: Zero findings recorded in database."},
            {"type": "tool_call", "node": "patcher", "name": "apply_patch", "args": "{'diff_content': '...'}"},
            {"type": "tool_response", "node": "patcher", "name": "apply_patch", "text": "SANDBOX-ERROR: patch(1) unavailable in image 'x'"},
            {"type": "tool_call", "node": "patcher", "name": "run_sandbox", "args": "{'command': 'ls'}"},
            {"type": "tool_response", "node": "patcher", "name": "run_sandbox", "text": "exit=0\napp.py\n"},
        ]
        digest = ad.render_digest(events, ad.render_trajectory(events, 20_000))
        row = next(r for r in digest.splitlines() if r.startswith("| researcher "))
        self.assertIn("find_symbol×1 (✗1)", row)
        self.assertIn("find_callers×1 (✗1)", row)
        self.assertIn("get_findings×1 (✗1)", row)
        self.assertIn("read_file×1 |", row + " |")
        self.assertNotIn("read_file×1 (✗", row)
        prow = next(r for r in digest.splitlines() if r.startswith("| patcher "))
        self.assertIn("apply_patch×1 (✗1)", prow)
        self.assertNotIn("run_sandbox×1 (✗", prow)
        self.assertIn("✗n = n answered with an error/empty/unavailable", digest)
        self.assertTrue(ad.is_unproductive_response(""))
        self.assertFalse(ad.is_unproductive_response("Recorded 3 finding(s)."))

    def test_a_failed_rollout_is_described_not_just_declared(self):
        def killed(target, workflow_path, run_dir, settings):
            fake_pipeline(target, workflow_path, run_dir, settings)
            return {"exit_code": -1, "wall_seconds": float(settings.timeout_seconds), "timed_out": True}
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = tmp / "repo"; target.mkdir(); (target / "app.py").write_text("print(1)\n")
            adapter = ad.MantisRepoAdapter(targets={"demo": target}, workflow_path=WORKFLOW, runs_root=tmp / "runs",
                                           settings=ad.RunSettings(model="m", timeout_seconds=120), runner=killed, domain="demo")
            rd = adapter.execute("demo", None, "demo--base1")
            self.assertFalse(adapter.delivered(rd))
            text = adapter.describe_outcome(rd)
            self.assertIn("timed out after 120s (--rollout-timeout)", text)
            self.assertIn("at stage reviewer", text, "the last stage the transcript saw")
            self.assertIn("finding(s) were in the DB", text)
            self.assertIn("never ran", adapter.describe_outcome(tmp / "nowhere"))
        # The default is a safety net under the token budget, not a budget of its own.
        self.assertGreaterEqual(ad.DEFAULT_ROLLOUT_TIMEOUT_SECONDS, 2 * 3600)
        self.assertEqual(ad.RunSettings().timeout_seconds, ad.DEFAULT_ROLLOUT_TIMEOUT_SECONDS)

    def test_evidence_vector_weights_tiers_and_tracks_verified_keys(self):
        ev = ad.evidence_vector([
            {"status": "dynamic_confirmed", "severity": "high", "filepath": "a.py", "title": "Cmd injection"},
            {"status": "static_confirmed", "severity": "medium", "filepath": "b.py", "title": "SQLi"},
            {"status": "false_positive", "severity": "low", "filepath": "c.py", "title": "nope"},
        ])
        self.assertEqual((ev["live"], ev["dismissed"], ev["verified"]), (2, 1, 1))
        self.assertEqual(ev["verified_keys"], ["a.py::cmd injection"])
        self.assertEqual(ev["confirmed_keys"], ["a.py::cmd injection", "b.py::sqli"])
        self.assertGreater(ev["score"], 3.0)
        # Keys compare across independent rollouts: file + CWE, not a per-DB lineage or a paraphrased title.
        k1 = ad._finding_key({"filepath": "dal/users.py", "cwe": "CWE-89", "title": "SQL injection in find_user", "lineage_id": "L1"})
        k2 = ad._finding_key({"filepath": "dal/users.py", "cwe": "cwe-89", "title": "Unsanitised query string", "lineage_id": "L2"})
        self.assertEqual(k1, k2)
        self.assertEqual(k1, "dal/users.py#cwe89")

    def test_execute_is_idempotent_by_runmark_and_leaves_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = tmp / "repo"; target.mkdir(); (target / "app.py").write_text("print(1)\n")
            adapter = _adapter(tmp, target)
            rd = adapter.execute("demo", None, "demo--base1")
            for name in ("summary.json", "findings.json", "evidence.json", "findings.md", "trajectory.jsonl", ".adapt_complete"):
                self.assertTrue((rd / name).exists(), name)
            self.assertTrue(adapter.delivered(rd))
            self.assertIn("[ACTION", adapter.trajectory(rd, obs_trunc=10_000))
            self.assertIn("static_confirmed", adapter.deliverable_text(rd))
            stamp = (rd / "summary.json").stat().st_mtime_ns
            rd2 = adapter.execute("demo", None, "demo--base1")
            self.assertEqual(rd, rd2)
            self.assertEqual((rd / "summary.json").stat().st_mtime_ns, stamp, "a complete run must not be re-rolled")
            self.assertIsNone(adapter.score(rd, "demo"))

    def test_repo_adapter_rolls_out_a_target_with_an_answer_key_from_a_copy_without_it(self):
        """evals/research_target carries ground_truth.json beside the app. The
        repo adapter used to hand that directory to the pipeline as it was,
        so every rollout could list (and read) the answer key. It now rolls
        out from a copy with the leak globs removed; a target without one is
        used in place, unchanged."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = tmp / "repo"; target.mkdir(); (target / "app.py").write_text("print(1)\n")
            (target / "ground_truth.json").write_text("{}")
            (target / "sub").mkdir(); (target / "sub" / "bench_dataset.json").write_text("[]")
            (target / "sub" / "x.py").write_text("y = 1\n")
            adapter = _adapter(tmp, target)
            seen: list = []

            def recording_runner(t, wf, rd, settings):
                seen.append(Path(t))
                return fake_pipeline(t, wf, rd, settings)
            adapter._runner = recording_runner
            jail = adapter.target_for("demo")
            self.assertNotEqual(jail, target)
            self.assertTrue((jail / "app.py").exists())
            self.assertTrue((jail / "sub" / "x.py").exists())
            self.assertFalse((jail / "ground_truth.json").exists(), "the answer key must never reach the pipeline")
            self.assertFalse((jail / "sub" / "bench_dataset.json").exists())
            self.assertEqual(adapter.target_for("demo"), jail, "one copy per task, shared by every rollout")
            adapter.execute("demo", None, "demo--base1")
            self.assertEqual(seen, [jail], "the pipeline must run on the copy, not the original")
            # A target with nothing to hide is used where it is.
            plain = tmp / "plain"; plain.mkdir(); (plain / "app.py").write_text("print(2)\n")
            adapter2 = ad.MantisRepoAdapter(targets={"p": plain}, workflow_path=WORKFLOW, runs_root=tmp / "runs2",
                                            settings=ad.RunSettings(model="m", timeout_seconds=60), runner=fake_pipeline, domain="demo")
            self.assertEqual(adapter2.target_for("p"), plain)

    def test_eval_adapter_refuses_holdout_and_scores_only_through_score(self):
        from evals.research_targets import gen
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(gen.HoldoutViolation):
                ad.MantisEvalAdapter(seeds=[gen.HOLDOUT_SEEDS[0]], workflow_path=WORKFLOW, runs_root=Path(tmp) / "r", runner=fake_pipeline)
            adapter = ad.MantisEvalAdapter(seeds=[gen.DEV_SEEDS[0]], size="small", workflow_path=WORKFLOW,
                                           runs_root=Path(tmp) / "r", runner=fake_pipeline)
            jail = adapter.target_for("seed-1000")
            self.assertTrue((jail / "app.py").exists())
            self.assertFalse((jail / "ground_truth.json").exists(), "the answer key must never reach the pipeline")
            rd = adapter.execute("seed-1000", None, "seed-1000--base1")
            scored = adapter.score(rd, "seed-1000")
            self.assertIsNotNone(scored)
            self.assertGreater(scored["n_criteria"], 0)


# --- Proposer ------------------------------------------------------------------------------


class ProposerTest(unittest.TestCase):
    def test_tools_are_jailed_and_surface_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "context"
            (root / "harness" / "prompts").mkdir(parents=True)
            (root / "harness" / "prompts" / "researcher.md").write_text("a\nb\nc\n")
            touched = []
            ls, rf, wf, df = make_context_tools(root, lambda rel: rel.startswith("prompts/") or rel == "workflow.json", touched)
            self.assertIn("harness/prompts/researcher.md", ls(""))
            self.assertTrue(rf("harness/prompts/researcher.md", 2, 3).startswith("2: b\n3: c\n[read budget:"))
            self.assertIn("refused", rf("../../etc/passwd"))
            self.assertIn("refused", wf("scripts/x.py", "print(1)"))
            self.assertIn("wrote", wf("prompts/researcher.md", "new"))
            self.assertIn("refused", df("workflow.json"))
            self.assertEqual(touched, ["prompts/researcher.md"])

    def test_thought_parts_never_reach_the_reply_and_partials_are_skipped(self):
        import types as _t
        from evals.evolve.proposer import collect_reply_text
        mk = lambda **kw: _t.SimpleNamespace(**{"text": None, "function_call": None, "thought": False, **kw})
        ev = lambda parts, partial=False, tokens=0: _t.SimpleNamespace(
            content=_t.SimpleNamespace(parts=parts), partial=partial,
            usage_metadata=_t.SimpleNamespace(total_token_count=tokens) if tokens else None)
        out = collect_reply_text([
            ev([mk(text="let me think about the candidates...", thought=True)], tokens=10),
            ev([mk(function_call=_t.SimpleNamespace(name="read_file"))]),
            ev([mk(text="<pick>c_al")], partial=True),
            ev([mk(text="<why>plainer</why>\n```choice\nA\n```")], tokens=20),
            ev([mk(text="trailing scratchpad", thought=True)]),
        ])
        self.assertEqual(out["text"], "<why>plainer</why>\n```choice\nA\n```")
        self.assertEqual((out["steps"], out["tokens"]), (1, 30))

    def test_selector_and_reflector_sessions_are_read_only(self):
        load_harness2()
        from harness2.core.spec import ChannelSpec
        seen = {}

        def recording_agent(*, system, read_only, context_root, **kw):
            seen["read_only"], seen["system"] = read_only, system
            tools = make_context_tools(context_root, lambda rel: True, [], read_only=read_only)
            seen["tools"] = [t.__name__ for t in tools]
            return {"text": "<why>x</why>\n```choice\nA\n```"}

        with tempfile.TemporaryDirectory() as tmp:
            ctx = Path(tmp) / "ctx"; (ctx / "harness").mkdir(parents=True)
            prop = MantisProposer(ChannelSpec("opencode", "m"), agent_runner=recording_agent)
            prop.call("choose", ctx, "select.agg1")                       # no harvest -> read-only
            self.assertTrue(seen["read_only"])
            self.assertEqual(seen["tools"], ["list_files", "read_file"])
            self.assertNotIn("edit files", seen["system"])
            prop.call("propose", ctx, "inv1.a1", harvest="context/harness")  # harvest -> editing
            self.assertFalse(seen["read_only"])
            self.assertIn("write_harness_file", seen["tools"])

    def test_call_harvests_the_edited_harness_and_audits(self):
        load_harness2()
        from harness2.core.proposer import ProposerError
        from harness2.core.spec import ChannelSpec
        with tempfile.TemporaryDirectory() as tmp:
            ctx = Path(tmp) / "ctx"; (ctx / "harness" / "prompts").mkdir(parents=True)
            (ctx / "harness" / "prompts" / "researcher.md").write_text("base\n")
            prop = MantisProposer(ChannelSpec("opencode", "m"), audit_dir=Path(tmp) / "audit", agent_runner=scripted_agent)
            reply = prop.call("mission", ctx, "inv1.a1", harvest="context/harness")
            self.assertTrue(reply.ok)
            self.assertIn("<notes>", reply.text)
            self.assertIn(EDIT_MARKER, (reply.workspace / "prompts" / "researcher.md").read_text())
            self.assertEqual("base\n", (ctx / "harness" / "prompts" / "researcher.md").read_text(), "the original context is untouched")
            self.assertTrue((Path(tmp) / "audit" / "sessions" / "inv1.a1" / "response.md").exists())

            empty = MantisProposer(ChannelSpec("opencode", "m"), agent_runner=lambda **kw: {"text": ""})
            with self.assertRaises(ProposerError):
                empty.call("mission", ctx, "inv1.a2", max_attempts=1)

    def test_a_session_is_always_wall_clock_bounded(self):
        """Upstream calls without a timeout; a hung connection must not hang the loop."""
        load_harness2()
        from harness2.core.proposer import ProposerError
        from harness2.core.spec import ChannelSpec
        import evals.evolve.proposer as P
        seen = []

        def recording_agent(*, timeout, **kw):
            seen.append(timeout)
            return {"text": "<notes>ok</notes>"}

        with tempfile.TemporaryDirectory() as tmp:
            ctx = Path(tmp) / "ctx"; (ctx / "harness").mkdir(parents=True)
            MantisProposer(ChannelSpec("opencode", "m"), agent_runner=recording_agent).call("m", ctx, "inv1.a1")
            self.assertEqual(seen[-1], 3600, "the channel's own timeout when the caller gives none")
            MantisProposer(ChannelSpec("opencode", "m", timeout=0), agent_runner=recording_agent).call("m", ctx, "inv1.a1")
            self.assertEqual(seen[-1], P.DEFAULT_SESSION_TIMEOUT_SECONDS)
            MantisProposer(ChannelSpec("opencode", "m"), agent_runner=recording_agent).call("m", ctx, "inv1.a1", timeout=42)
            self.assertEqual(seen[-1], 42, "an explicit timeout is respected")

            # The real session runner enforces it: a runner that never returns is cut off,
            # and the call reports a ProposerError instead of sleeping forever.
            def hanging(*, mission, system, context_root, touched, label, timeout, read_only=False):
                import asyncio
                async def forever():
                    await asyncio.sleep(3600)
                return asyncio.run(asyncio.wait_for(forever(), timeout=timeout))
            prop = MantisProposer(ChannelSpec("opencode", "m"), agent_runner=hanging)
            with self.assertRaises(ProposerError) as cm:
                prop.call("m", ctx, "inv1.a1", timeout=0.05, max_attempts=1)
            self.assertIn("TimeoutError", str(cm.exception))

    def test_the_proposer_model_has_a_request_timeout(self):
        import evals.evolve.proposer as P
        from core.config import get_llm_kwargs
        _, kw = get_llm_kwargs(model_id="openai/m1", default_timeout=P.PROPOSER_LLM_TIMEOUT_SECONDS)
        self.assertEqual(kw.get("timeout"), P.PROPOSER_LLM_TIMEOUT_SECONDS)
        self.assertGreaterEqual(P.PROPOSER_LLM_TIMEOUT_SECONDS, 600, "a writing turn can legitimately run for minutes")

    def test_the_proposer_output_budget_is_large_and_clamped_to_the_model(self):
        import evals.evolve.proposer as P
        self.assertGreaterEqual(P.PROPOSER_MAX_OUTPUT_TOKENS, 32_000)
        self.assertEqual(P.proposer_max_output_tokens("totally/unknown-model"), P.PROPOSER_MAX_OUTPUT_TOKENS)
        with unittest.mock.patch("litellm.get_max_tokens", return_value=16_384):
            self.assertEqual(P.proposer_max_output_tokens("openai/small"), 16_384)
        with unittest.mock.patch("litellm.get_max_tokens", side_effect=Exception("no such model")):
            self.assertEqual(P.proposer_max_output_tokens("x"), P.PROPOSER_MAX_OUTPUT_TOKENS)
        self.assertIn("ONE file per turn", P._TOOL_INSTRUCTIONS)

    def test_reads_are_budgeted_per_session_and_say_so(self):
        import evals.evolve.proposer as P
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "context"; (root / "rollouts").mkdir(parents=True)
            (root / "rollouts" / "base1.md").write_text("".join(f"line {i} {'x' * 60}\n" for i in range(5000)))
            budget = {}
            ls, rf = make_context_tools(root, lambda rel: True, [], read_only=True, read_budget_chars=50_000, budget=budget)
            first = rf("rollouts/base1.md", 1, 200)
            self.assertIn("1: line 0", first)
            self.assertRegex(first, r"\[read budget: [\d,]+ of 50,000 characters left this session; file has 5,000 lines\]")
            served_after_one = budget["served"]
            self.assertGreater(served_after_one, 10_000)
            # Keep reading until the budget is spent; the cut is announced, then reads stop serving content.
            out = ""
            for start in range(200, 5000, 200):
                out = rf("rollouts/base1.md", start, start + 200)
                if "read budget exhausted" in out:
                    break
            self.assertIn("read budget exhausted", out)
            self.assertNotIn("line 4", out.split("exhausted")[0] if "line 4" in out else "")
            self.assertLessEqual(budget["served"], 50_000 + P.MAX_TOOL_OUTPUT_CHARS)
            self.assertIn("rollouts/base1.md", ls(""), "listing is not budgeted")

    def test_describe_event_is_compact_and_never_raises(self):
        from types import SimpleNamespace as NS
        import evals.evolve.proposer as P
        ev = NS(partial=False, usage_metadata=NS(total_token_count=1234), error_code=None, content=NS(parts=[
            NS(function_call=NS(name="read_file", args={"path": "rollouts/base1.md", "start_line": 1, "end_line": 300, "note": "z" * 200}),
               function_response=None, text=None, thought=False),
            NS(function_call=None, function_response=NS(name="read_file", response={"result": "y" * 5000}), text=None, thought=False),
            NS(function_call=None, function_response=None, text="I think", thought=True),
            NS(function_call=None, function_response=None, text="<notes>done</notes>", thought=False),
        ]))
        lines = P.describe_event(ev)
        self.assertEqual(len(lines), 3, lines)
        self.assertTrue(lines[0].startswith("call read_file {"))
        self.assertIn("'note': 'zzz", lines[0]); self.assertIn("...'", lines[0]); self.assertNotIn("z" * 100, lines[0])
        self.assertEqual(lines[1], "response read_file 5,000 chars")
        self.assertIn("text 19 chars (turn tokens: 1,234)", lines[2])
        self.assertEqual(P.describe_event(None), [])
        self.assertEqual(P.describe_event(NS(partial=True)), [])

    def test_each_session_is_its_own_process_and_a_hung_one_is_killed(self):
        """Upstream runs sessions concurrently in threads; LiteLLM's async client is per-loop. One process each."""
        import evals.evolve.proposer as P
        from harness2.core.spec import ChannelSpec
        load_harness2()
        with tempfile.TemporaryDirectory() as tmp:
            ctx = Path(tmp) / "context"; (ctx / "harness").mkdir(parents=True)
            prop = MantisProposer(ChannelSpec("opencode", "m"), surface_workflow={"nodes": []})
            touched = []
            # Stand in for the child interpreter: a script that prints progress, then a result line.
            fake_child = Path(tmp) / "child.py"
            fake_child.write_text(
                "import json, sys, time\n"
                "spec = json.load(open(sys.argv[sys.argv.index('--session') + 1]))\n"
                "import os\n"
                "print(f\"[proposer {spec['label']} +0.1s] call read_file {{}}\", file=sys.stderr)\n"
                "if spec['label'].startswith('hang'):\n    time.sleep(30)\n"
                "print(json.dumps({'text': '<notes>ok</notes>', 'steps': 3, 'touched': ['prompts/researcher.md'],\n"
                "                  'read_chars': 1234, 'mission_len': len(spec['mission']), 'ro': spec['read_only'],\n"
                "                  'wf': spec['surface_workflow'], 'cap': os.environ.get('MANTIS_LLM_EMPTY_TURN_MAX_ATTEMPTS')}))\n")
            real_run = P.subprocess.run

            def run_with_fake_child(cmd, **kw):
                self.assertEqual(cmd[1:3], ["-m", "evals.evolve.proposer"])
                return real_run([cmd[0], str(fake_child), *cmd[3:]], **kw)

            with unittest.mock.patch.object(P.subprocess, "run", side_effect=run_with_fake_child), \
                    unittest.mock.patch.object(P, "SESSION_UNWIND_GRACE_SECONDS", 0.2):
                out = prop._run_session_subprocess(mission="m" * 50, system="s", context_root=ctx, touched=touched,
                                                   label="inv1.a1", timeout=20, read_only=False)
                self.assertEqual(out["text"], "<notes>ok</notes>")
                self.assertEqual(out["mission_len"], 50)
                self.assertFalse(out["ro"])
                self.assertEqual(out["wf"], {"nodes": []}, "the surface workflow crosses to the child")
                self.assertEqual(out["cap"], str(P.PROPOSER_EMPTY_TURN_MAX_ATTEMPTS), "a proposer empty turn is not transient")
                self.assertEqual(touched, ["prompts/researcher.md"], "the child's edits are reported back")
                t0 = time.time()
                with self.assertRaises(TimeoutError) as cm:
                    prop._run_session_subprocess(mission="m", system="s", context_root=ctx, touched=[],
                                                 label="hang.a1", timeout=1, read_only=True)
                self.assertLess(time.time() - t0, 5, "the child was killed, not waited for")
                self.assertIn("killed", str(cm.exception))

    def test_a_salvaged_partial_proposal_says_so_in_its_reply_and_in_the_warnings(self):
        import evals.evolve.proposer as P
        from evals.evolve import run as ev_run
        load_harness2()
        from harness2.core.spec import ChannelSpec
        note = P.salvage_note("inv1.a1", 3, "exceeded 60s")
        self.assertTrue(note.startswith("<notes>"))
        self.assertIn(P.SALVAGED_MARKER, note)
        self.assertIn("3 file(s)", note)
        self.assertIn("no rationale", note)

        # The subprocess launcher: a child that writes a file and then hangs is killed and salvaged, with the note.
        with tempfile.TemporaryDirectory() as tmp:
            ctx = Path(tmp) / "context"; (ctx / "harness" / "prompts").mkdir(parents=True)
            (ctx / "harness" / "prompts" / "researcher.md").write_text("base\n")
            prop = MantisProposer(ChannelSpec("opencode", "m"), surface_workflow={"nodes": []})
            fake_child = Path(tmp) / "child.py"
            fake_child.write_text(
                "import json, sys, time, pathlib\n"
                "spec = json.load(open(sys.argv[sys.argv.index('--session') + 1]))\n"
                "root = pathlib.Path(spec['context_root']) / 'harness' / 'prompts'\n"
                "(root / 'researcher.md').write_text('edited\\n')\n"
                "time.sleep(30)\n")
            real_run = P.subprocess.run
            with unittest.mock.patch.object(P.subprocess, "run",
                                            side_effect=lambda cmd, **kw: real_run([cmd[0], str(fake_child), *cmd[3:]], **kw)), \
                    unittest.mock.patch.object(P, "SESSION_UNWIND_GRACE_SECONDS", 0.2):
                touched = []
                out = prop._run_session_subprocess(mission="m", system="s", context_root=ctx, touched=touched,
                                                   label="inv1.a1", timeout=1, read_only=False)
            self.assertTrue(out.get("salvaged"))
            self.assertEqual(touched, ["prompts/researcher.md"])
            self.assertIn(P.SALVAGED_MARKER, out["text"])

        # And the driver surfaces it next to the other warnings.
        class _Reply:  # the shape _warnings reads from proposer._calls
            def __init__(self, label, text): self.label, self.text = label, text
        class _Prop:
            _calls = [_Reply("dom1.a1", "<notes>fine</notes>"), _Reply("inv1.a1", note)]
        class _Res:
            stages = []; k = 1
        class _Sel:
            ok = True; error = ""
        warns = ev_run._warnings(_Res(), _Sel(), False, proposer=_Prop())
        self.assertTrue(any("salvaged" in w and "['inv1.a1']" in w for w in warns), warns)
        self.assertFalse(any("dom1" in w for w in warns))

    def test_the_session_entry_point_reports_a_failed_session_without_a_traceback(self):
        import evals.evolve.proposer as P
        with tempfile.TemporaryDirectory() as tmp:
            ctx = Path(tmp) / "context"; ctx.mkdir()
            spec = Path(tmp) / "spec.json"
            spec.write_text(json.dumps({"mission": "m", "system": "s", "context_root": str(ctx), "label": "x.a1",
                                        "read_only": True, "model_id": "openai/nonexistent", "max_steps": 2, "timeout": 3}))
            import io, contextlib
            err = io.StringIO()
            with unittest.mock.patch.dict("os.environ", {"OPENAI_API_KEY": "dummy", "LLM_API_BASE": "http://127.0.0.1:9",
                                                          "MANTIS_LLM_MAX_PATIENCE_SECONDS": "0"}), \
                    contextlib.redirect_stderr(err):
                code = P._session_main(["--session", str(spec)])
            self.assertEqual(code, 1)
            self.assertIn("session failed", err.getvalue())

    def test_run_bounded_returns_results_raises_errors_and_abandons_a_stuck_session(self):
        import asyncio
        import evals.evolve.proposer as P

        async def fine():
            return {"text": "ok"}
        self.assertEqual(P.run_bounded(fine, timeout=5, label="t")["text"], "ok")

        async def broken():
            raise ValueError("boom")
        with self.assertRaises(ValueError):
            P.run_bounded(broken, timeout=5, label="t")

        async def cooperative_hang():
            await asyncio.sleep(3600)
        t0 = time.time()
        with self.assertRaises(TimeoutError) as cm:
            P.run_bounded(cooperative_hang, timeout=0.2, label="t")
        self.assertLess(time.time() - t0, 5)
        self.assertIn("exceeded", str(cm.exception))

        # A session whose cleanup refuses to unwind (blocking sleep in a finally) is abandoned, not waited on.
        async def uncancellable():
            try:
                await asyncio.sleep(3600)
            finally:
                time.sleep(3)  # longer than the test's grace below
        with unittest.mock.patch.object(P, "SESSION_UNWIND_GRACE_SECONDS", 0.5):
            t0 = time.time()
            with self.assertRaises(TimeoutError) as cm:
                P.run_bounded(uncancellable, timeout=0.2, label="t")
            self.assertLess(time.time() - t0, 2.5, "the caller did not wait for the stuck cleanup")
            self.assertIn("abandoned", str(cm.exception))


# --- Selection -----------------------------------------------------------------------------


class SelectionTest(unittest.TestCase):
    class _RV:
        def __init__(self, label, run_dir, ok=True, delivered=True, error=""):
            self.label, self.run_dir, self.ok, self.delivered, self.error, self.run_id = label, run_dir, ok, delivered, error, label

    class _Adapter:
        def __init__(self, evidence):
            self._ev = evidence

        def evidence(self, run_dir):
            return self._ev.get(Path(run_dir).name, {})

    def _dir(self, tmp, name, tokens):
        d = Path(tmp) / name; d.mkdir()
        (d / "summary.json").write_text(json.dumps({"tokens": tokens}))
        return d

    def test_non_regression_then_evidence_then_cost(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = self._RV("base1", self._dir(tmp, "base1", 500))
            a = self._RV("agg1", self._dir(tmp, "agg1", 400))
            b = self._RV("agg2", self._dir(tmp, "agg2", 300))
            c = self._RV("agg3", self._dir(tmp, "agg3", 100), ok=False, error="died")
            adapter = self._Adapter({
                "base1": {"score": 1.0, "verified": 1, "verified_keys": ["x::k"], "confirmed_keys": ["x::k"], "live": 1, "dismissed": 0},
                "agg1": {"score": 4.0, "verified": 2, "verified_keys": ["x::k", "y::z"], "confirmed_keys": ["x::k", "y::z"], "live": 2, "dismissed": 0},
                "agg2": {"score": 6.0, "verified": 1, "verified_keys": ["y::z"], "confirmed_keys": ["y::z"], "live": 3, "dismissed": 0},   # lost x::k
            })
            table = ev_sel.rank_candidates(adapter, {"agg1": a, "agg2": b, "agg3": c}, [base])
            self.assertEqual(table["base_verified_floor"], ["x::k"])
            self.assertEqual(table["eligible"], ["agg1"])
            self.assertEqual(table["ranked"][1]["regressed"], ["x::k"])
            self.assertIn("agg3", table["dropped"])
            self.assertEqual(table["tie"], [])

    def test_static_only_regression_is_caught_by_the_score_floor(self):
        """On the shipped static-only workflow nothing reaches dynamic_confirmed, so the
        machine-verified floor is empty; a candidate that found nothing must still lose."""
        with tempfile.TemporaryDirectory() as tmp:
            base = self._RV("base1", self._dir(tmp, "base1", 500))
            a = self._RV("agg1", self._dir(tmp, "agg1", 100))
            adapter = self._Adapter({
                "base1": {"score": 7.5, "verified": 0, "verified_keys": [], "confirmed": 5,
                          "confirmed_keys": ["a.py#cwe89", "b.py#cwe78", "c.py#cwe22", "d.py#cwe918", "e.py#cwe798"], "live": 5, "dismissed": 0},
                "agg1": {"score": 0.0, "verified": 0, "verified_keys": [], "confirmed": 0, "confirmed_keys": [], "live": 0, "dismissed": 0},
            })
            table = ev_sel.rank_candidates(adapter, {"agg1": a}, [base])
            self.assertEqual(table["base_floor"]["score"], 7.5)
            self.assertEqual(len(table["base_floor"]["keys"]), 5)
            self.assertEqual(table["eligible"], [])
            self.assertTrue(table["ranked"][0]["below_base_score"])
            self.assertEqual(len(table["ranked"][0]["regressed"]), 5)
            sel = ev_sel.select("t", 1, "agg", {"agg1": a}, [base], adapter=adapter, selector=None, work_dir=Path(tmp) / "w")
            self.assertFalse(sel.ok)
            self.assertIn("below the weakest base run", sel.error)

    def test_tie_is_detected_only_within_epsilon(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = self._RV("base1", self._dir(tmp, "base1", 500))
            a = self._RV("agg1", self._dir(tmp, "agg1", 400))
            b = self._RV("agg2", self._dir(tmp, "agg2", 300))
            adapter = self._Adapter({"base1": {"score": 1.0, "verified_keys": [], "confirmed_keys": []},
                                     "agg1": {"score": 3.0, "verified_keys": [], "confirmed_keys": []},
                                     "agg2": {"score": 3.2, "verified_keys": [], "confirmed_keys": []}})
            table = ev_sel.rank_candidates(adapter, {"agg1": a, "agg2": b}, [base])
            self.assertEqual(sorted(table["tie"]), ["agg1", "agg2"])
            self.assertEqual(table["eligible"][0], "agg2")  # higher score first, before the tie-break


# --- The loop ------------------------------------------------------------------------------


class EvolveIterationTest(unittest.TestCase):
    def test_one_iteration_end_to_end_with_scripted_proposer(self):
        load_harness2()
        from harness2.core import library as h2lib
        from harness2.core.spec import ChannelSpec
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = tmp / "repo"; target.mkdir(); (target / "app.py").write_text("print(1)\n")
            adapter = _adapter(tmp, target)
            prop = MantisProposer(ChannelSpec("opencode", "m"), audit_dir=tmp / "audit", agent_runner=scripted_agent,
                                  surface_ok=lambda rel: ev_run._on_surface(adapter, rel))
            library = h2lib.Library(root=tmp / "library", domain="demo", surface=adapter.substrate.surface())
            record = ev_run.evolve_task("demo", adapter=adapter, proposer=prop, selector=prop, work_dir=tmp / "task",
                                        k=1, mode="agg", library=library, log=lambda s: None)
            self.assertEqual(record["status"], "ok", json.dumps(record.get("selection"), indent=1, default=str))
            self.assertEqual(record["chosen_label"], "agg1")
            self.assertFalse(record["kept_base"])
            self.assertEqual(record["selection"]["ok"], True)
            self.assertIn("machine-verified", record["selection"]["why"])
            # Budget identity: 4k rollouts, 3k sessions, no duplicate labels.
            self.assertEqual((record["ledger"]["R"], record["ledger"]["P"]), (4, 3))
            # The adopted tree carries the edit and the diff shows it.
            self.assertEqual(record["diff"]["modified"], ["prompts/researcher.md"])
            self.assertIn(EDIT_MARKER, record["unified_diff"])
            self.assertIn(EDIT_MARKER, (Path(record["adopted_dir"]) / "prompts" / "researcher.md").read_text())
            # Reflection produced an evidence-backed experience and the library kept it.
            self.assertTrue(record["experience"].get("evidence"))
            self.assertEqual(library.entries(), ["demo"])
            self.assertTrue((library.dir / "INDEX.md").exists())
            # The production workflow was not touched.
            self.assertNotIn(EDIT_MARKER, WORKFLOW.read_text(encoding="utf-8"))
            # Adoption is a dry run without --yes, and validates before writing.
            scratch_wf = tmp / "workflow.json"; scratch_wf.write_text(WORKFLOW.read_text(encoding="utf-8"))
            self.assertFalse(ev_run.adopt(Path(record["adopted_dir"]), scratch_wf, yes=False, log=lambda s: None))
            self.assertNotIn(EDIT_MARKER, scratch_wf.read_text())
            self.assertTrue(ev_run.adopt(Path(record["adopted_dir"]), scratch_wf, yes=True, log=lambda s: None))
            self.assertIn(EDIT_MARKER, scratch_wf.read_text())
            self.assertTrue(scratch_wf.with_suffix(".json.bak").exists())

    def test_keep_base_is_a_real_answer(self):
        load_harness2()
        from harness2.core.spec import ChannelSpec

        def keep_base_agent(*, label, **kw):
            if label.startswith("experience."):
                return {"text": "NO_ENTRY"}
            return {"text": "<notes>KEEP_BASE: the trajectories show no divergence worth a change.</notes>"}

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target = tmp / "repo"; target.mkdir(); (target / "app.py").write_text("print(1)\n")
            adapter = _adapter(tmp, target)
            prop = MantisProposer(ChannelSpec("opencode", "m"), agent_runner=keep_base_agent)
            record = ev_run.evolve_task("demo", adapter=adapter, proposer=prop, selector=prop, work_dir=tmp / "task",
                                        k=1, mode="agg", library=None, log=lambda s: None)
            self.assertEqual(record["status"], "ok")
            self.assertTrue(record["kept_base"])
            self.assertTrue(all(s["kept_base"] for s in record["stages"]))
            self.assertNotIn("adopted_dir", record)
            self.assertTrue(any("KEEP_BASE" in w for w in record["warnings"]))


if __name__ == "__main__":
    unittest.main()

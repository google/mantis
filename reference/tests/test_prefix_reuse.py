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

"""Tests for cross-campaign reuse of repo-scope prefix stage artifacts.

In cross-functional mode every campaign shares the repository jail, so the
architect and threat modeler re-derive the same repo-wide artifacts on every
campaign of a run. The reuse callbacks let campaigns 2..N of one process skip
those stages once the artifact row exists. These tests pin the fail-safe
gates: any missing precondition must run the stage (callback returns None).
No LLM calls.
"""

from __future__ import annotations

import inspect
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from core.context import RunContext, current_run_context
from core.database import init_db, record_artifact
from core.graph_loader import (
    _PREFIX_REUSE_ARTIFACTS,
    _SCAN_MODE_CHANGED,
    _SCAN_MODE_CROSS_FUNCTIONAL,
    _make_prefix_reuse_callbacks,
)


class _CallbackTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_prefix_reuse_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = os.path.realpath(self._tmp.name)
        self.db = os.path.join(self.tmp, "knowledge.db")
        init_db(self.db)

    def install_ctx(self, scan_mode=_SCAN_MODE_CROSS_FUNCTIONAL, run_id="r1"):
        ctx = RunContext(
            jail_dir=self.tmp,
            db_path=self.db,
            run_id=run_id,
            scan_mode=scan_mode,
        )
        token = current_run_context.set(ctx)
        self.addCleanup(current_run_context.reset, token)
        return ctx

    def record_summary(self, run_id="r1"):
        record_artifact(
            self.db, run_id, "summary",
            "workspace/.structured/summary.json", json.dumps({"ok": True}),
        )


class PrefixReuseCallbackTest(_CallbackTest):
    def test_skips_only_after_completion_and_artifact(self):
        before, after = _make_prefix_reuse_callbacks("architect")
        self.install_ctx()
        self.record_summary()
        # Campaign #1: nothing completed yet, the stage must run.
        self.assertIsNone(before())
        after()
        # Campaign #2: completed and the artifact row exists -> skip.
        content = before()
        self.assertIsNotNone(content)
        self.assertIn("Reused the summary", content.parts[0].text)

    def test_file_by_file_never_skips_or_marks(self):
        before, after = _make_prefix_reuse_callbacks("architect")
        self.install_ctx(scan_mode="file-by-file")
        self.record_summary()
        after()
        self.assertIsNone(before())
        # The file-by-file completion must not seed a later cross-functional
        # skip either: per-file campaigns never prove the repo-wide artifact.
        self.install_ctx(scan_mode=_SCAN_MODE_CROSS_FUNCTIONAL)
        self.assertIsNone(before())

    def test_unknown_mode_never_skips(self):
        before, after = _make_prefix_reuse_callbacks("architect")
        self.install_ctx(scan_mode="")
        self.record_summary()
        after()
        self.assertIsNone(before())

    def test_missing_artifact_runs_the_stage(self):
        before, after = _make_prefix_reuse_callbacks("architect")
        self.install_ctx()
        after()
        self.assertIsNone(before())

    def test_no_context_runs_the_stage(self):
        before, _ = _make_prefix_reuse_callbacks("architect")
        self.assertIsNone(current_run_context.get())
        self.assertIsNone(before())

    def test_fresh_process_reruns(self):
        # Completion is process-local by design: a resumed run re-derives
        # against the resynced checkout instead of trusting an old artifact.
        before, after = _make_prefix_reuse_callbacks("architect")
        self.install_ctx()
        self.record_summary()
        after()
        self.assertIsNotNone(before())
        fresh_before, _ = _make_prefix_reuse_callbacks("architect")
        self.assertIsNone(fresh_before())

    def test_completion_is_per_run(self):
        before, after = _make_prefix_reuse_callbacks("architect")
        self.install_ctx(run_id="r1")
        self.record_summary(run_id="r1")
        after()
        self.record_summary(run_id="r2")
        self.install_ctx(run_id="r2")
        self.assertIsNone(before())

    def test_threat_modeler_requires_its_own_artifact(self):
        before, after = _make_prefix_reuse_callbacks("threat_modeler")
        self.install_ctx()
        self.record_summary()  # wrong artifact type for this node
        after()
        self.assertIsNone(before())
        record_artifact(
            self.db, "r1", "threat_model",
            "workspace/.structured/threat_model.json", json.dumps({"ok": True}),
        )
        content = before()
        self.assertIsNotNone(content)
        self.assertIn("Reused the threat_model", content.parts[0].text)

    def test_distinct_nested_git_subrepos_do_not_cross_pollinate_prefixes(self):
        """When jail_dir is a parent folder over multiple git repositories
        (repoA/.git, repoB/.git), Repo A's summary/threat_model is reused within
        Repo A slices but never copied into Repo B."""
        repo_a_slice1 = os.path.join(self.tmp, "repoA", "svc1")
        repo_a_slice2 = os.path.join(self.tmp, "repoA", "svc2")
        repo_b_slice1 = os.path.join(self.tmp, "repoB", "api")
        for d in (repo_a_slice1, repo_a_slice2, repo_b_slice1):
            os.makedirs(d, exist_ok=True)
        os.makedirs(os.path.join(self.tmp, "repoA", ".git"), exist_ok=True)
        os.makedirs(os.path.join(self.tmp, "repoB", ".git"), exist_ok=True)

        before, after = _make_prefix_reuse_callbacks("architect")
        ctx_a1 = self.install_ctx()
        ctx_a1.target_file = repo_a_slice1
        record_artifact(
            self.db, "r1", "summary", "workspace/.structured/summary.json",
            json.dumps({"overview": "REPO-A"}), metadata={"resource": repo_a_slice1},
        )
        after()

        # Second slice inside repoA reuses repoA's summary
        ctx_a2 = self.install_ctx()
        ctx_a2.target_file = repo_a_slice2
        self.assertIsNotNone(before())

        # Slice inside repoB has its own .git root -> must run its own architect
        ctx_b1 = self.install_ctx()
        ctx_b1.target_file = repo_b_slice1
        self.assertIsNone(before())


class VocabularyPinTest(unittest.TestCase):
    def test_loader_literal_matches_main(self):
        # graph_loader mirrors the literal because importing main would be
        # circular; this pin is what keeps the two from drifting.
        import main as main_module

        self.assertEqual(
            main_module.SCAN_MODE_CROSS_FUNCTIONAL, _SCAN_MODE_CROSS_FUNCTIONAL
        )
        self.assertEqual(main_module.SCAN_MODE_CHANGED, _SCAN_MODE_CHANGED)


class ChangedRunReuseTest(_CallbackTest):
    """A `changed` run whose jail is the repository root: its directory
    campaigns share the prefix like cross-functional ones, and a reusing
    campaign's tools see the reused artifacts as its own."""

    def setUp(self):
        super().setUp()
        for d in ("alpha", "beta"):
            os.makedirs(os.path.join(self.tmp, d))
            Path(self.tmp, d, "m.py").write_text("x = 1\n")
        Path(self.tmp, "root.py").write_text("y = 2\n")

    def campaign(self, target, path_root=None, scan_mode=_SCAN_MODE_CHANGED):
        ctx = RunContext(jail_dir=self.tmp, db_path=self.db, run_id="r1", scan_mode=scan_mode,
                         target_file=os.path.join(self.tmp, target) if target else self.tmp,
                         path_root=self.tmp if path_root is None else path_root)
        token = current_run_context.set(ctx)
        self.addCleanup(current_run_context.reset, token)
        return ctx

    def test_a_reusing_campaign_sees_the_reused_artifacts(self):
        from tools.research_tools import get_summary, get_threat_model, record_summary, record_threat_model

        arch_before, arch_after = _make_prefix_reuse_callbacks("architect")
        tm_before, tm_after = _make_prefix_reuse_callbacks("threat_modeler")
        self.campaign("alpha")
        self.assertIsNone(arch_before())
        self.assertIn("SUCCESS", record_summary({"overview": "ALPHA-OVERVIEW", "key_modules": ["alpha"]}))
        arch_after()
        self.assertIsNone(tm_before())
        self.assertIn("SUCCESS", record_threat_model({"threats": ["TENANT-ESCAPE"]}))
        tm_after()

        self.campaign("beta")
        self.assertIsNotNone(arch_before(), "campaign B reuses the architect")
        self.assertIsNotNone(tm_before(), "and the threat modeler")
        self.assertIn("ALPHA-OVERVIEW", get_summary(), "B's tools see the reused summary, not NO_DATA")
        self.assertIn("TENANT-ESCAPE", get_threat_model())

    def test_an_empty_summary_is_not_a_reuse_proof(self):
        before, after = _make_prefix_reuse_callbacks("architect")
        ctx = self.campaign("alpha")
        record_artifact(self.db, "r1", "summary", "workspace/.structured/summary.json",
                        json.dumps({"overview": "", "key_modules": [], "tech_stack": []}),
                        metadata={"resource": ctx.target_file})
        after()
        self.campaign("beta")
        self.assertIsNone(before(), "an empty summary must not skip the architect")

    def test_only_directory_campaigns_over_the_root_jail_share(self):
        before, after = _make_prefix_reuse_callbacks("architect")
        ctx = self.campaign("root.py")  # a single-file campaign: never a producer
        record_artifact(self.db, "r1", "summary", "workspace/.structured/summary.json",
                        json.dumps({"overview": "ROOT"}), metadata={"resource": ctx.target_file})
        after()
        self.campaign("beta")
        self.assertIsNone(before())
        ctx = self.campaign("alpha")
        record_artifact(self.db, "r1", "summary", "workspace/.structured/summary.json",
                        json.dumps({"overview": "ALPHA"}), metadata={"resource": ctx.target_file})
        after()
        self.campaign("root.py")
        self.assertIsNone(before(), "nor a consumer")
        self.campaign("beta", path_root=os.path.join(self.tmp, "elsewhere"))
        self.assertIsNone(before(), "a jail that is not the repository root shares nothing")
        self.campaign("beta", scan_mode="file-by-file")
        self.assertIsNone(before())
        self.campaign("beta")
        self.assertIsNotNone(before())

    def test_the_producers_artifact_is_reused_not_a_later_one(self):
        from core.database import read_artifact
        from tools.research_tools import get_summary

        before, after = _make_prefix_reuse_callbacks("architect")
        ctx = self.campaign("alpha")
        record_artifact(self.db, "r1", "summary", "workspace/.structured/summary.json",
                        json.dumps({"overview": "ALPHA"}), metadata={"resource": ctx.target_file})
        after()
        # A single-file campaign ran its own architect in between.
        record_artifact(self.db, "r1", "summary", "workspace/.structured/summary.json",
                        json.dumps({"overview": "ROOT-ONLY"}),
                        metadata={"resource": os.path.join(self.tmp, "root.py")})
        ctx = self.campaign("beta")
        self.assertIsNotNone(before())
        self.assertIn("ALPHA", get_summary())
        self.assertEqual(json.loads(read_artifact(self.db, artifact_type="summary", run_id="r1",
                                                  resource=ctx.target_file))["overview"], "ALPHA")


class SummaryRecordingTest(_CallbackTest):
    def test_the_architects_own_field_names_are_kept(self):
        from core.schemas import CodebaseSummary

        # The shape the architect actually sent (measured): no `overview`.
        s = CodebaseSummary.model_validate({
            "system_purpose": "Multi-tenant actor platform.",
            "architecture_overview": "ateapi control plane, atelet node agent.",
            "attack_surface": "1. gRPC endpoints",
            "trust_boundaries": ["Worker <-> atelet", "atelet <-> ateapi"],
            "critical_components": ["cmd/atelet/workersupport.go"],
        })
        self.assertTrue(s.overview.startswith("ateapi control plane, atelet node agent."), s.overview)
        for kept in ("Multi-tenant actor platform.", "1. gRPC endpoints", "- Worker <-> atelet",
                     "Trust boundaries:"):
            self.assertIn(kept, s.overview)
        self.assertEqual(s.key_modules, ["cmd/atelet/workersupport.go"])
        # The canonical spelling is unchanged.
        s = CodebaseSummary.model_validate({"overview": "O", "key_modules": [{"name": "m"}],
                                            "tech_stack": ["Go"]})
        self.assertEqual((s.overview, s.key_modules, s.tech_stack), ("O", [{"name": "m"}], ["Go"]))
        s = CodebaseSummary.model_validate({"summary": "S", "modules": "one", "technologies": "Go"})
        self.assertEqual((s.overview, s.key_modules, s.tech_stack), ("S", ["one"], ["Go"]))

    def test_record_summary_refuses_an_empty_summary(self):
        from tools.research_tools import record_summary

        self.install_ctx()
        for empty in ({}, {"overview": "  ", "key_modules": []}, {"tech_stack": ["Go"]}):
            out = record_summary(empty)
            self.assertTrue(out.startswith("ERROR SAVING SUMMARY"), out)
        from core.database import read_artifact

        self.assertIsNone(read_artifact(self.db, artifact_type="summary", run_id="r1"))
        self.assertIn("SUCCESS", record_summary({"architecture_overview": "A"}))


class _ToolCallingEndpoint:
    """An OpenAI-compatible endpoint that records each request. A request
    offering record_summary or record_threat_model, with no tool result in
    it yet, gets a call to that tool with a non-empty argument; everything
    else gets a short text answer."""

    def __init__(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        self.requests: list = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                outer.requests.append(body)
                tools = {t.get("function", {}).get("name") for t in body.get("tools") or []}
                msgs = list(body.get("messages") or [])
                active_stage = None
                stage_msg_idx = -1
                for idx_m, m in enumerate(msgs):
                    txt = str(m.get("content") or "")
                    if "[ACTIVE STAGE ASSIGNMENT: " in txt:
                        active_stage = txt.split("[ACTIVE STAGE ASSIGNMENT: ", 1)[1].split("]", 1)[0].strip()
                        stage_msg_idx = idx_m
                tail_msgs = msgs[stage_msg_idx + 1:] if stage_msg_idx >= 0 else msgs
                answered = any(m.get("role") == "tool" for m in tail_msgs)
                message = {"role": "assistant", "content": "No issues found."}
                call = None
                if active_stage is not None:
                    if not answered and active_stage == "architect" and "record_summary" in tools:
                        call = ("record_summary", {"summary": {"architecture_overview": "SHARED-ARCH"}})
                    elif not answered and active_stage == "threat_modeler" and "record_threat_model" in tools:
                        call = ("record_threat_model", {"threat_model": {"threats": ["SHARED-THREAT"]}})
                else:
                    if not answered and "record_summary" in tools:
                        call = ("record_summary", {"summary": {"architecture_overview": "SHARED-ARCH"}})
                    elif not answered and "record_threat_model" in tools:
                        call = ("record_threat_model", {"threat_model": {"threats": ["SHARED-THREAT"]}})
                if call:
                    message = {"role": "assistant", "content": None, "tool_calls": [{
                        "id": f"c{len(outer.requests)}", "type": "function",
                        "function": {"name": call[0], "arguments": json.dumps(call[1])}}]}
                data = json.dumps({
                    "id": "x", "object": "chat.completion", "created": 0, "model": "fake",
                    "choices": [{"index": 0, "finish_reason": "tool_calls" if call else "stop",
                                 "message": message}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110},
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ChangedRunEndToEndTest(unittest.TestCase):
    """A listed changed run over the repository root (the PR driver's
    one-process shape): the first campaign's architect and threat modeler
    run, told every changed file; the second campaign reuses them."""

    def test_the_second_campaign_reuses_the_first_campaigns_prefix(self):
        import subprocess

        endpoint = _ToolCallingEndpoint()
        self.addCleanup(endpoint.close)
        tmp = tempfile.mkdtemp(prefix="mantis_shared_prefix_")
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        repo = os.path.join(tmp, "repo")
        for rel in ("alpha/a.py", "beta/b.py"):
            Path(repo, rel).parent.mkdir(parents=True, exist_ok=True)
            Path(repo, rel).write_text("def f(x):\n    return x\n")
        env = {k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}
        env.update({"OPENAI_API_KEY": "dummy", "LLM_TIMEOUT": "10", "MANTIS_LLM_MAX_PATIENCE_SECONDS": "5",
                    "MANTIS_LLM_STREAM": "0"})
        proc = subprocess.run(
            [sys.executable, os.path.join(_REF_ROOT, "main.py"), repo, "--scan-mode", "changed", "--yes",
             "--changed-files", "alpha/a.py", "--changed-files", "beta/b.py", "--path-root", repo,
             "--sandbox", "static-only", "--model", "openai/fake", "--api-base", endpoint.url,
             "--db", os.path.join(tmp, "k.db"), "--max-llm-calls", "60"],
            capture_output=True, text=True, timeout=300, env=env, cwd=_REF_ROOT)
        out = proc.stdout + proc.stderr

        def _last_stage(req: dict) -> str | None:
            found = None
            for m in req.get("messages") or []:
                txt = str(m.get("content") or "")
                if "[ACTIVE STAGE ASSIGNMENT: " in txt:
                    found = txt.split("[ACTIVE STAGE ASSIGNMENT: ", 1)[1].split("]", 1)[0].strip()
            return found

        stage_for_tool = {"record_summary": "architect", "record_threat_model": "threat_modeler"}

        def offering(tool):
            want_stage = stage_for_tool.get(tool)
            out_reqs = []
            for r in endpoint.requests:
                tset = {t.get("function", {}).get("name") for t in r.get("tools") or []}
                if tool not in tset:
                    continue
                st = _last_stage(r)
                if st is not None and want_stage is not None:
                    if st == want_stage:
                        out_reqs.append(r)
                else:
                    out_reqs.append(r)
            return out_reqs

        self.assertEqual(out.count("Reused the summary"), 1, out[-3000:])
        self.assertEqual(out.count("Reused the threat_model"), 1)
        arch = offering("record_summary")
        self.assertEqual(len(arch), 2, "one architect (call + answer), not one per campaign")
        first = json.dumps(arch[0])
        self.assertIn("SHARED ARCHITECTURE AND THREAT MODEL", first)
        self.assertTrue("beta/b.py" in first and "alpha/a.py" in first,
                        "the producing campaign is told every changed file")
        self.assertEqual(len(offering("record_threat_model")), 2)


class WiringPinTest(unittest.TestCase):
    def test_loader_attaches_reuse_callbacks(self):
        import core.graph_loader as gl

        src = inspect.getsource(gl.load_workflow_from_json)
        self.assertIn(
            "node_id in _PREFIX_REUSE_ARTIFACTS and not node_cfg.on_enter_status",
            src,
        )
        self.assertIn("_make_prefix_reuse_callbacks(node_id)", src)

    def test_reuse_covers_exactly_the_repo_scope_stages(self):
        self.assertEqual(
            _PREFIX_REUSE_ARTIFACTS,
            {"architect": "summary", "threat_modeler": "threat_model"},
        )

    def test_shipped_workflow_keeps_reuse_active(self):
        # The attach guard defers to a completion stamp; the shipped workflow
        # must not declare one on the reuse nodes, or reuse silently dies.
        workflow = json.loads(
            (Path(_REF_ROOT) / "workflow.json").read_text(encoding="utf-8")
        )
        for node in workflow["nodes"]:
            if node["id"] in _PREFIX_REUSE_ARTIFACTS:
                self.assertNotIn("on_enter_status", node)


class ToolLoopGuardTest(unittest.TestCase):
    """Tests for the configuration fingerprint utility and the read_file tool-loop guard."""

    def test_compute_prefix_fingerprint_changes_on_prompt_or_tools_or_model(self):
        from core.graph_loader import compute_prefix_fingerprint

        fp_base = compute_prefix_fingerprint(
            "architect",
            instruction="Map architecture",
            tools=["list_files", "read_file"],
            model="gemini-3.8-flash",
            snapshot_id="snap-1",
        )
        fp_reordered = compute_prefix_fingerprint(
            "architect",
            instruction="Map architecture",
            tools=["read_file", "list_files"],
            model="gemini-3.8-flash",
            snapshot_id="snap-1",
        )
        self.assertEqual(fp_base, fp_reordered)
        fp_changed_prompt = compute_prefix_fingerprint(
            "architect",
            instruction="Map architecture v2",
            tools=["list_files", "read_file"],
            model="gemini-3.8-flash",
            snapshot_id="snap-1",
        )
        self.assertNotEqual(fp_base, fp_changed_prompt)

    def test_after_tool_guard_steers_after_repeated_unbounded_read_file(self):
        from core.graph_loader import _make_after_tool_guard_callback

        guard = _make_after_tool_guard_callback(
            "researcher",
            ["read_file", "get_function_boundary", "find_symbol"],
        )

        class _DummyTool:
            name = "read_file"

        tool = _DummyTool()
        ctx = RunContext(jail_dir="/tmp", db_path="/tmp/db.sqlite", run_id="r1")
        tok = current_run_context.set(ctx)
        try:
            # First unbounded read returns None (keep original output).
            self.assertIsNone(guard(tool, {"filepath": "app/auth.py"}, None, "line1\nline2"))
            # Echoed defaults (0 = whole file) are an unbounded read too.
            self.assertIsNone(
                guard(
                    tool,
                    {"filepath": "app/auth.py", "start_line": 0, "end_line": 0},
                    None,
                    "line1\nline2",
                )
            )
            # Bounded read does not increment counter or trigger hint.
            self.assertIsNone(
                guard(
                    tool,
                    {"filepath": "app/auth.py", "start_line": 1, "end_line": 20},
                    None,
                    "line1\nline2",
                )
            )
            # Third unbounded read appends steering hint.
            res = guard(tool, {"filepath": "app/auth.py"}, None, "line1\nline2")
            self.assertIsInstance(res, str)
            self.assertIn("HARNESS STEERING HINT", res)
            self.assertIn("get_function_boundary", res)
        finally:
            current_run_context.reset(tok)

    def test_after_tool_guard_hint_matches_real_tool_signatures(self):
        """Every tool call the hint suggests must be one the tools accept.

        The hint reaches a model that is already looping; a parameter name the
        tool does not have turns the nudge into a validation error.
        """
        from core.graph_loader import _make_after_tool_guard_callback
        from tools import structural_tools

        guard = _make_after_tool_guard_callback(
            "researcher", ["read_file", "get_function_boundary", "find_symbol"]
        )

        class _DummyTool:
            name = "read_file"

        res = None
        for _ in range(3):
            res = guard(_DummyTool(), {"filepath": "app/auth.py"}, None, "body")
        self.assertIsInstance(res, str)

        gfb_params = set(inspect.signature(structural_tools.get_function_boundary).parameters)
        fs_params = set(inspect.signature(structural_tools.find_symbol).parameters)
        for call in re.finditer(r"(get_function_boundary|find_symbol)\(([^)]*)\)", res):
            tool_name, arg_text = call.group(1), call.group(2)
            named = set(re.findall(r"(\w+)=", arg_text))
            allowed = gfb_params if tool_name == "get_function_boundary" else fs_params
            self.assertTrue(
                named and named <= allowed,
                f"hint suggests {tool_name}({arg_text}) but it accepts {sorted(allowed)}",
            )

if __name__ == "__main__":
    unittest.main()

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

"""Campaigns of one run do not see each other's workspace.

Under --parallel, several campaigns share one run id and the clock. The
artifact store keyed rows by (run_id, filepath): campaign B's planner
overwrote campaign A's plan at workspace/.structured/plan.json before A's
researcher read it, and read_file("workspace/notes.md") returned a sibling's
agent-written text unfenced. Rows now belong to the campaign that wrote them
(metadata.resource) and a campaign reads its own rows and run-level rows.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from core.context import RunContext, current_run_context  # noqa: E402
from core.database import init_db, read_artifact, read_artifact_record, record_artifact  # noqa: E402

RUN = "11111111-2222-3333-4444-555555555555"


class ArtifactIsolationTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_art_")
        self.db = os.path.join(self.tmp, "k.db")
        init_db(self.db)
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        self.a = os.path.join(self.repo, "a.py")
        self.b = os.path.join(self.repo, "b.py")
        for p in (self.a, self.b):
            Path(p).write_text("x = 1\n")
        self.token = None

    async def asyncTearDown(self):
        if self.token is not None:
            current_run_context.reset(self.token)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _ctx(self, target):
        if self.token is not None:
            current_run_context.reset(self.token)
        ctx = RunContext(jail_dir=self.repo, db_path=self.db, target_file=target, run_id=RUN, active_node="researcher")
        self.token = current_run_context.set(ctx)
        return ctx

    def test_a_write_replaces_only_its_own_campaigns_row(self):
        record_artifact(self.db, RUN, "plan", "workspace/.structured/plan.json", "PLAN-A", metadata={"resource": self.a})
        record_artifact(self.db, RUN, "plan", "workspace/.structured/plan.json", "PLAN-B", metadata={"resource": self.b})
        self.assertEqual(read_artifact(self.db, artifact_type="plan", run_id=RUN, resource=self.a), "PLAN-A")
        self.assertEqual(read_artifact(self.db, artifact_type="plan", run_id=RUN, resource=self.b), "PLAN-B")
        record_artifact(self.db, RUN, "plan", "workspace/.structured/plan.json", "PLAN-A2", metadata={"resource": self.a})
        self.assertEqual(read_artifact(self.db, artifact_type="plan", run_id=RUN, resource=self.a), "PLAN-A2")
        self.assertEqual(read_artifact(self.db, artifact_type="plan", run_id=RUN, resource=self.b), "PLAN-B",
                         "A's rewrite did not touch B's plan")

    def test_run_level_rows_are_visible_to_every_campaign_and_own_rows_win(self):
        record_artifact(self.db, RUN, "report", "workspace/.structured/report.json", "RUN-REPORT")
        self.assertEqual(read_artifact(self.db, artifact_type="report", run_id=RUN, resource=self.a), "RUN-REPORT")
        record_artifact(self.db, RUN, "workspace_file", "workspace/notes.md", "A's notes", metadata={"resource": self.a})
        record_artifact(self.db, RUN, "workspace_file", "workspace/notes.md", "B's notes", metadata={"resource": self.b})
        self.assertEqual(read_artifact(self.db, filepath="workspace/notes.md", run_id=RUN, resource=self.a), "A's notes")
        self.assertEqual(read_artifact(self.db, filepath="workspace/notes.md", run_id=RUN, resource=self.b), "B's notes")
        self.assertIsNone(read_artifact(self.db, filepath="workspace/notes.md", run_id=RUN, resource=os.path.join(self.repo, "c.py")),
                          "a third campaign sees neither sibling's notes")
        # Without a resource the old answer (newest row) is unchanged, for callers outside a campaign.
        self.assertEqual(read_artifact(self.db, filepath="workspace/notes.md", run_id=RUN), "B's notes")
        rec = read_artifact_record(self.db, filepath="workspace/notes.md", run_id=RUN, resource=self.a)
        self.assertIn(self.a, rec["metadata_json"])

    async def test_the_tools_read_and_list_their_own_campaign(self):
        import tools.research_tools as rt

        self._ctx(self.a)
        await rt.write_file("workspace/notes.md", "A's notes")
        self.assertTrue(rt.record_plan({"investigations": [{"title": "look at a", "target_files": ["a.py"]}]}).startswith("SUCCESS"))
        self._ctx(self.b)
        await rt.write_file("workspace/notes.md", "B's notes")
        self.assertTrue(rt.record_plan({"investigations": [{"title": "look at b", "target_files": ["b.py"]}]}).startswith("SUCCESS"))
        self.assertIn("B's notes", await rt.read_file("workspace/notes.md"))
        self.assertNotIn("A's notes", await rt.read_file("workspace/notes.md"))
        self.assertIn("look at b", rt.get_plan())
        self.assertNotIn("look at a", rt.get_plan())
        listing = await rt.list_files("workspace")
        self.assertIn("workspace/notes.md", listing)
        self._ctx(self.a)
        self.assertIn("A's notes", await rt.read_file("workspace/notes.md"))
        self.assertIn("look at a", rt.get_plan())
        self.assertNotIn("look at b", rt.get_plan())


class SandboxLifecycleTest(unittest.TestCase):
    def test_execute_reports_the_sdk_timeout_as_a_timeout(self):
        import asyncio

        from core.environments import microsandbox_env as M

        class ExecTimeoutError(Exception):
            pass

        env = M.MicrosandboxEnvironment.__new__(M.MicrosandboxEnvironment)
        env.timeout = 1.0
        env._workdir = Path("/workspace")
        env._stage_error = None

        class SB:
            async def shell(self, command, cwd=None, timeout=None):
                raise ExecTimeoutError("exec timed out after 1s")

        async def ensure():
            return SB()
        env._ensure = ensure
        res = asyncio.run(env.execute("sleep 100"))
        self.assertTrue(res.timed_out)
        self.assertEqual(res.exit_code, 124)
        self.assertIn("SANDBOX-ERROR", res.stderr)

    def test_close_kills_and_destroys_when_stop_fails(self):
        import asyncio

        from core.environments import microsandbox_env as M

        calls = []

        class SB:
            async def stop(self, timeout=None):
                calls.append("stop"); raise RuntimeError("StopTimeoutError")

            async def kill(self, timeout=None):
                calls.append("kill")

            async def destroy(self, force=False, timeout=None):
                calls.append(f"destroy(force={force})")

        env = M.MicrosandboxEnvironment.__new__(M.MicrosandboxEnvironment)
        env._sb = SB(); env._name = "mantis-msb-test"; env.is_initialized = True
        removed = []

        async def fake_remove(name):
            removed.append(name)
        from unittest import mock
        with mock.patch.object(M.MsbSandbox, "remove", side_effect=fake_remove):
            asyncio.run(env.close())
        self.assertEqual(calls, ["stop", "kill", "destroy(force=True)"])
        self.assertEqual(removed, ["mantis-msb-test"])
        self.assertIsNone(env._sb)

    def test_the_guest_has_a_hard_lifetime(self):
        import inspect

        from core.environments import microsandbox_env as M

        self.assertIn("max_duration=float(MAX_GUEST_LIFETIME_SECONDS)", inspect.getsource(M.MicrosandboxEnvironment._ensure))
        self.assertLessEqual(M.MAX_GUEST_LIFETIME_SECONDS, 24 * 3600)


class HostPathOracleTest(unittest.IsolatedAsyncioTestCase):
    async def test_outside_the_jail_the_answer_does_not_depend_on_host_existence(self):
        import tools.research_tools as rt
        from core.environments.static_env import StaticOnlyEnvironment

        tmp = tempfile.mkdtemp(prefix="mantis_oracle_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        repo = os.path.join(tmp, "repo"); os.makedirs(repo)
        target = os.path.join(repo, "only.py"); Path(target).write_text("x = 1\n")
        ctx = RunContext(jail_dir=repo, db_path="", target_file=target, run_id=RUN,
                         sandbox=StaticOnlyEnvironment(target_path=target))
        token = current_run_context.set(ctx)
        try:
            exists = await rt.read_file("../../../../etc/passwd")
            missing = await rt.read_file("../../../../etc/definitely-not-a-file-xyz")
        finally:
            current_run_context.reset(token)
        self.assertEqual(exists, missing, "the answer must not say whether the host path exists")
        self.assertNotIn("x = 1", exists)
        # A sibling INSIDE the jail still gets the single-file refusal, and a
        # missing sibling the sandbox's answer: existence is only disclosed
        # for paths the jail already covers.
        Path(repo, "sibling.py").write_text("y = 2\n")
        token = current_run_context.set(ctx)
        try:
            sibling = await rt.read_file("sibling.py")
        finally:
            current_run_context.reset(token)
        self.assertIn("Single-file scans may only read", sibling)
        self.assertNotIn("y = 2", sibling)


class SingleFileScopeTest(unittest.IsolatedAsyncioTestCase):
    """A one-file campaign over a tree reads its file and no other, however
    the path is spelled, and lists only its own directory. The guest holds
    the whole tree (a PoC needs the module), so the gate judges the request
    the way the guest resolves it, not the way the host jail does."""

    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_scope_")
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(self.repo, "cmd", "a"))
        os.makedirs(os.path.join(self.repo, "internal", "b"))
        self.target = os.path.join(self.repo, "cmd", "a", "main.go")
        Path(self.target).write_text("package main\n")
        Path(self.repo, "cmd", "a", "helper.go").write_text("package main // helper\n")
        Path(self.repo, "internal", "b", "secret.go").write_text("package b // SECRET-B\n")
        self.reads = []

        class WholeTreeGuest:
            """Serves the whole tree under /workspace, like the microVM does."""
            is_initialized = True
            working_dir = Path("/workspace")

            def __init__(s, repo):
                s.repo = repo

            async def read_file(s, p):
                p = Path(p)
                rel = p.relative_to("/workspace") if p.is_absolute() else p
                norm = os.path.normpath(os.path.join(s.repo, str(rel)))
                if not norm.startswith(s.repo + os.sep):
                    raise PermissionError(f"Path '{p}' escapes the sandbox workspace '/workspace'.")
                self.reads.append(norm)
                return Path(norm).read_bytes()

        self.ctx = RunContext(jail_dir=self.repo, db_path="", target_file=self.target, run_id=RUN,
                              sandbox=WholeTreeGuest(self.repo), active_node="architect")
        self.token = current_run_context.set(self.ctx)

    async def asyncTearDown(self):
        current_run_context.reset(self.token)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_only_the_scanned_file_is_readable_whatever_the_spelling(self):
        import tools.research_tools as rt

        own = await rt.read_file("cmd/a/main.go")
        self.assertIn("package main", own)
        for spelling in ("internal/b/secret.go", "/workspace/internal/b/secret.go",
                         "../../../../workspace/internal/b/secret.go", "cmd/a/helper.go", "./internal/b/secret.go"):
            out = await rt.read_file(spelling)
            self.assertNotIn("SECRET-B", out, spelling)
            self.assertNotIn("helper", out, spelling)
            self.assertIn("Single-file scans may only read the scanned file 'cmd/a/main.go'", out, spelling)
            # get_function_boundary refuses the same bodies; the hint must
            # not send the agent from one refusal into another.
            self.assertNotIn("get_function_boundary", out, spelling)
        self.assertEqual({os.path.basename(r) for r in self.reads}, {"main.go"}, "the guest was never asked for another file")

    async def test_list_files_shows_the_own_directory_only(self):
        import tools.research_tools as rt

        out = await rt.list_files("")
        self.assertIn("cmd/a/main.go", out)
        self.assertIn("cmd/a/helper.go", out)
        self.assertNotIn("secret.go", out)
        self.assertIn("single-file campaign", out)
        out = await rt.list_files("internal/b")
        self.assertNotIn("secret.go", out, "no other directory is listed, whatever is asked for")


class CampaignGuardTest(unittest.TestCase):
    def test_per_campaign_guards_fail_the_campaign_and_the_sweep_continues(self):
        import ast
        import inspect
        import textwrap

        import main

        self.assertEqual(main._CAMPAIGN_GUARDS, {"node_tool_calls_ceiling", "node_visits_ceiling", "graph_steps",
                                                 "campaign_tokens"})
        for run_level in ("wall_clock", "token_budget", "llm_calls_limit"):
            self.assertNotIn(run_level, main._CAMPAIGN_GUARDS)
        src = inspect.getsource(main.pipeline)
        handler = src[src.index("except BudgetExceededError as be:"):]
        handler = handler[:handler.index("except MantisAuthError")]
        self.assertIn("_CAMPAIGN_GUARDS", handler)
        self.assertIn("_record_guard_failure(", handler)
        self.assertNotIn("record_spend(", handler, "no cost observation from a cut-off campaign")
        self.assertIn("continue", handler)
        self.assertIn('"failed": True', inspect.getsource(main._record_guard_failure))
        self.assertIn("tokens=0", inspect.getsource(main._record_guard_failure))
        self.assertIn("len(targets_to_scan) > 1", handler, "a single-campaign run still pauses")


class _ChargingEndpoint:
    """An OpenAI-compatible endpoint that answers every request with a
    short text and bills `heavy` tokens for a request that mentions
    `marker`, 1,000 otherwise."""

    def __init__(self, marker: str, heavy: int):
        import json
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode("utf-8", "replace")
                usage = heavy if marker in body else 1_000
                data = json.dumps({
                    "id": "x", "object": "chat.completion", "created": 0, "model": "fake",
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant", "content": "No issues found."}}],
                    "usage": {"prompt_tokens": usage - 10, "completion_tokens": 10, "total_tokens": usage},
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


class CampaignTokenShareTest(unittest.TestCase):
    """--max-campaign-tokens: each campaign's own token ceiling. A campaign
    that reaches it stops, a failed ledger row (resumable, covering
    nothing), and the other campaigns go on; the spend report says how each
    campaign ended, which is what a driver running several changed files in
    one process reads per file."""

    def test_the_scope_trips_on_its_own_tokens_only(self):
        from core.budget import BudgetConfig, BudgetController, BudgetExceededError, CampaignBudgetScope

        run = BudgetController(config=BudgetConfig(max_tokens=1_000_000, cache_discount=1.0), run_id="r")
        first = CampaignBudgetScope(run, max_tokens=100)
        first.record_tokens(60)
        with self.assertRaises(BudgetExceededError) as cm:
            first.record_tokens(60)
        self.assertEqual(cm.exception.trigger, "campaign_tokens")
        second = CampaignBudgetScope(run, max_tokens=100)
        second.record_tokens(90)  # the sibling's 120 are not its own
        self.assertEqual(run.accumulated_tokens, 210, "the run still sees every campaign's spend")
        unbounded = CampaignBudgetScope(run)
        unbounded.record_tokens(10_000)
        self.assertEqual(unbounded.campaign_max_tokens, 0)

    def test_the_spend_report_carries_each_campaigns_outcome_and_is_rewritten(self):
        import json

        import main
        from core.budget import BudgetConfig, BudgetController, CampaignBudgetScope

        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path = os.path.join(tmp, "spend.json")
        saved = dict(main._SPEND_REPORT)
        self.addCleanup(lambda: (main._SPEND_REPORT.clear(), main._SPEND_REPORT.update(saved)))
        run = BudgetController(config=BudgetConfig(cache_discount=1.0), run_id="r")
        main._SPEND_REPORT.clear()
        main._SPEND_REPORT.update({"controller": run, "path": path})
        scope = CampaignBudgetScope(run)
        scope.record_step("history")
        scope.record_step("researcher")
        scope.record_step("reporter")
        scope.record_tokens(500, cached_count=200)
        main._note_campaign_spend("/r/a", ["/r/a/x.py"], scope, "done", elapsed_seconds=3.04)
        on_disk = json.loads(Path(path).read_text())
        self.assertIsNone(on_disk["exit_code"], "rewritten as the campaign ends, before the exit")
        self.assertEqual(on_disk["campaigns"], [{
            "target": "/r/a", "files": ["/r/a/x.py"], "status": "done", "pause_trigger": "",
            "tokens": 500, "fresh_tokens": 300, "cached_tokens": 200, "llm_calls": 1,
            "elapsed_seconds": 3.0, "nodes": ["history", "researcher", "reporter"]}])
        # The first word on a campaign stands.
        main._note_campaign_spend("/r/a", ["/r/a/x.py"], scope, "paused", pause_trigger="token_budget")
        self.assertEqual(json.loads(Path(path).read_text())["campaigns"][0]["status"], "done")
        main.write_spend_report(path, 0)
        self.assertEqual(json.loads(Path(path).read_text())["exit_code"], 0)

    def test_a_campaign_over_its_share_stops_and_the_others_go_on(self):
        import json
        import subprocess

        endpoint = _ChargingEndpoint(marker="alpha/a.py", heavy=150_000)
        self.addCleanup(endpoint.close)
        tmp = tempfile.mkdtemp(prefix="mantis_share_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        repo = os.path.join(tmp, "repo")
        for rel in ("alpha/a.py", "beta/b.py"):
            Path(repo, rel).parent.mkdir(parents=True, exist_ok=True)
            Path(repo, rel).write_text("def f(x):\n    return x\n")
        spend, db = os.path.join(tmp, "spend.json"), os.path.join(tmp, "k.db")
        env = {k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}
        env.update({"OPENAI_API_KEY": "dummy", "LLM_TIMEOUT": "10", "MANTIS_LLM_MAX_PATIENCE_SECONDS": "5",
                    "MANTIS_LLM_STREAM": "0"})
        proc = subprocess.run(
            [sys.executable, str(_REF_ROOT / "main.py"), repo, "--scan-mode", "changed", "--yes",
             "--changed-files", "alpha/a.py", "--changed-files", "beta/b.py",
             "--sandbox", "static-only", "--model", "openai/fake", "--api-base", endpoint.url,
             "--db", db, "--max-campaign-tokens", "200k", "--max-tokens", "10M", "--cache-discount", "1",
             "--max-llm-calls", "60", "--spend-report", spend],
            capture_output=True, text=True, timeout=300, env=env, cwd=str(_REF_ROOT))
        out = proc.stdout + proc.stderr
        report = json.loads(Path(spend).read_text())
        by = {Path(c["target"]).name: c for c in report["campaigns"]}
        self.assertEqual(set(by), {"alpha", "beta"}, out[-3000:])
        self.assertEqual(by["alpha"]["status"], "paused")
        self.assertEqual(by["alpha"]["pause_trigger"], "campaign_tokens")
        self.assertGreaterEqual(by["alpha"]["tokens"], 200_000)
        self.assertEqual(by["beta"]["status"], "done", "the other campaign went on and finished")
        self.assertIn("reporter", by["beta"]["nodes"])
        self.assertLess(by["beta"]["tokens"], 200_000)
        self.assertEqual(report["pause_trigger"], "", "the run itself did not pause")
        self.assertIn("stopped by its own guard (campaign_tokens", out)
        import sqlite3

        with sqlite3.connect(db) as conn:
            rows = conn.execute("SELECT target, metadata_json FROM campaign_spend").fetchall()
        alpha = [json.loads(m or "{}") for t, m in rows if Path(t).name == "alpha"]
        self.assertEqual(alpha, [{"failed": True, "guard": "campaign_tokens"}], "resumable, covering nothing")


class PatientSessionStoreTest(unittest.IsolatedAsyncioTestCase):
    """ADK's session store is the one database every campaign writes to on
    every event. Its stock five-second lock wait aborted campaigns under
    --parallel ("database is locked" out of runner.run_async) after their
    findings were already saved. The store now waits as long as the
    knowledge database does and runs in WAL."""

    async def test_the_session_store_waits_like_the_knowledge_db_and_uses_wal(self):
        import sqlite3
        from unittest import mock

        import aiosqlite

        import main
        from core.database import DB_TIMEOUT_ENV

        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path = os.path.join(tmp, "sessions.db")
        seen = {}
        real_connect = aiosqlite.connect

        def spy(*args, **kwargs):
            seen["timeout"] = kwargs.get("timeout")
            return real_connect(*args, **kwargs)

        with mock.patch.dict(os.environ, {DB_TIMEOUT_ENV: "300"}), mock.patch.object(aiosqlite, "connect", spy):
            service = main._PatientSqliteSessionService(db_path=path)
            session = await service.create_session(app_name="mantis", user_id="u")
            got = await service.get_session(app_name="mantis", user_id="u", session_id=session.id)
        self.assertIsNotNone(got)
        self.assertEqual(got.id, session.id)
        self.assertEqual(seen["timeout"], 300.0, "the run's --db-timeout, not aiosqlite's 5s")
        with sqlite3.connect(path) as conn:
            self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")

        # Never shorter than the stock wait, whatever the run asked for.
        with mock.patch.dict(os.environ, {DB_TIMEOUT_ENV: "0"}), mock.patch.object(aiosqlite, "connect", spy):
            async with main._PatientSqliteSessionService(db_path=path)._get_db_connection():
                pass
        self.assertEqual(seen["timeout"], 5.0)


class ParallelRampTest(unittest.TestCase):
    def test_the_ramp_flag_reaches_the_pipeline_and_staggers_the_workers(self):
        import inspect

        import main
        from scripts.launch import build_parser, run_launch

        self.assertEqual(build_parser().parse_args(["target"]).parallel_ramp, 0.0, "off by default")
        args = build_parser().parse_args(["target", "--parallel", "8", "--parallel-ramp", "10"])
        self.assertEqual(args.parallel_ramp, 10.0)
        self.assertIn("parallel_ramp", inspect.signature(run_launch).parameters)
        self.assertIn("parallel_ramp_seconds=parallel_ramp", inspect.getsource(run_launch))
        self.assertIn("parallel_ramp_seconds", inspect.signature(main.pipeline).parameters)
        src = inspect.getsource(main.pipeline)
        self.assertIn("await asyncio.sleep(index * ramp)", src, "worker i waits i*ramp before its first campaign")
        self.assertIn("_staggered_worker(i) for i in range(worker_count)", src)


class AuthFailureStopsTheRunTest(unittest.TestCase):
    """A credential failure in a parallel worker returns EXIT_AUTH, and the
    run returns it -- before the post-loop summary. The pool used to check
    for the sequential loop's `1` only, so three workers printed the
    authentication banner and the process exited 0 behind a "completed"
    summary (measured)."""

    def test_the_run_exits_with_the_auth_code_not_zero(self):
        import json
        import subprocess
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                body = json.dumps({"error": {"message": "Incorrect API key provided", "type": "invalid_request_error",
                                             "code": "invalid_api_key"}}).encode()
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        tmp = tempfile.mkdtemp(prefix="mantis_auth_exit_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        repo = os.path.join(tmp, "repo")
        os.makedirs(repo)
        for name in ("a", "b", "c"):
            Path(repo, f"{name}.py").write_text(f"def {name}():\n    return 1\n")
        env = {k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}
        env.update({"OPENAI_API_KEY": "dummy", "LLM_TIMEOUT": "10", "MANTIS_LLM_MAX_PATIENCE_SECONDS": "5"})
        proc = subprocess.run(
            [sys.executable, str(_REF_ROOT / "main.py"), repo, "--scan-mode", "file-by-file", "--yes",
             "--parallel", "2", "--sandbox", "static-only", "--model", "openai/fake",
             "--api-base", f"http://127.0.0.1:{httpd.server_address[1]}", "--db", os.path.join(tmp, "k.db")],
            capture_output=True, text=True, timeout=300, env=env, cwd=str(_REF_ROOT))
        out = proc.stdout + proc.stderr
        from core.config import EXIT_AUTH
        self.assertEqual(proc.returncode, EXIT_AUTH, out[-3000:])
        self.assertIn("AUTHENTICATION ERROR", out)
        self.assertNotIn("Pipeline Execution Completed", out, "no 'completed' summary after a credential failure")


if __name__ == "__main__":
    unittest.main()

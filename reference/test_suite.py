import os
import sys
import ast
import json
import sqlite3
import shutil
import tempfile
import asyncio
import subprocess
import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from pydantic import Field
from google import adk
from google.genai import types
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.apps.app import App
from google.adk.workflow import DEFAULT_ROUTE

from core.config import get_llm_kwargs, DEFAULT_MODEL
from core.context import RunContext, current_run_context
from core.database import (
    init_db,
    write_findings,
    read_findings,
    record_calibration,
    read_risk_scores,
    update_status,
    record_artifact,
    read_artifact,
    record_learning,
    query_historical_lineage,
    query_security_guidance,
    generate_rca_summary,
    resolve_ancestor_lineage,
    extract_target_symbol,
    normalize_cwe,
    _db,
)
from core.schemas import VulnerabilityFinding
from core.graph_loader import (
    create_classifier,
    load_workflow_from_json,
    GlobalConfig,
    AgentNode,
)
from core.sandbox import (
    StaticOnlySandbox,
    SANDBOXES,
    build_sandbox,
    GvisorSandbox,
    MicrosandboxSandbox,
    GceSandbox,
)
from core.environments.gce_env import ISOLATION_PROBE_SCRIPT
from pathlib import Path
from main import APP_NAME, USER_ID, execute_sub_task, discover_files, is_binary_file
from tools.research_tools import (
    read_file,
    write_file,
    list_files,
    get_findings,
    get_plan,
    get_threat_model,
    get_summary,
    get_security_guidance,
    query_lineage,
)
from tools.sandbox_tools import run_sandbox, apply_patch


class TestMantisReferenceSuite(unittest.IsolatedAsyncioTestCase):

    async def test_shipped_graph_execution_covers_all_edges(self):
        """Exercises all edges of the shipped workflow using ScriptedLlm across 3 scripts."""
        workflow_path = os.path.join(os.path.dirname(__file__), "workflow.json")

        scripts = [
            # Script 1: Confirmed bug & successful repro & patch -> full pipeline -> dynamic_confirmed
            (
                [
                    "History extracted.",
                    "Structural index built.",
                    "Architecture KB created.",
                    "Threat model created.",
                    "Plan created.",
                    "Found SQL injection in query handler.",
                    "Findings deduplicated.",
                    json.dumps({"route": "confirmed", "reason": "Review completed."}),
                    json.dumps({"route": "viable", "reason": "Exploit is viable."}),
                    json.dumps({"route": "success", "reason": "Exploit successfully reproduced vulnerability."}),
                    "Exploit chained.",
                    "Patch created and applied successfully.",
                    "Calibration score: 90",
                    "Learnings reflected.",
                    "Report generated.",
                ],
                [
                    "history", "structural_index", "architect", "threat_modeler",
                    "planner", "researcher", "deduplicator", "reviewer", "reviewer_classifier",
                    "critic", "critic_classifier", "reproducer", "repro_classifier",
                    "chainer", "patcher", "calibrator", "reflector", "reporter"
                ],
                "dynamic_confirmed"
            ),
            # Script 2: False positive -> reported (suppressed)
            (
                [
                    "History extracted.",
                    "Structural index built.",
                    "Architecture KB created.",
                    "Threat model created.",
                    "Plan created.",
                    "Found potential buffer overflow.",
                    "Findings deduplicated.",
                    json.dumps({"route": "false_positive", "reason": "Input is bounded."}),
                    "Calibration score: 0",
                    "Learnings reflected.",
                    "Report generated.",
                ],
                [
                    "history", "structural_index", "architect", "threat_modeler",
                    "planner", "researcher", "deduplicator", "reviewer", "reviewer_classifier",
                    "calibrator", "reflector", "reporter"
                ],
                "reported"
            ),
            # Script 3: Repro fails -> calibrator -> static_confirmed
            (
                [
                    "History extracted.",
                    "Structural index built.",
                    "Architecture KB created.",
                    "Threat model created.",
                    "Plan created.",
                    "Found logic bug.",
                    "Findings deduplicated.",
                    json.dumps({"route": "confirmed", "reason": "Analysis done."}),
                    json.dumps({"route": "viable", "reason": "Exploit is viable."}),
                    json.dumps({"route": "failed_repro", "reason": "Exploit attempt failed."}),
                    "Calibration score: 15",
                    "Learnings reflected.",
                    "Report generated.",
                ],
                [
                    "history", "structural_index", "architect", "threat_modeler",
                    "planner", "researcher", "deduplicator", "reviewer", "reviewer_classifier",
                    "critic", "critic_classifier", "reproducer", "repro_classifier",
                    "calibrator", "reflector", "reporter"
                ],
                "static_confirmed"
            ),
        ]

        for script_replies, expected_node_order, expected_status in scripts:
            queue = list(script_replies)

            class ScriptedLlm(BaseLlm):
                async def generate_content_async(self, llm_request, stream: bool = False):
                    text = queue.pop(0) if queue else "done"
                    yield LlmResponse(content=types.Content(parts=[types.Part.from_text(text=text)]))

            with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
                with patch("core.graph_loader.LiteLlm", lambda **_: ScriptedLlm(model="scripted")):
                    wf, cfg = load_workflow_from_json(workflow_path)

            app = App(name=APP_NAME, root_agent=wf)
            ss = InMemorySessionService()
            sess_id = f"sess_{expected_node_order[1]}"
            run_id = f"run_{expected_node_order[1]}"
            target_file = "file.py"

            temp_dir = tempfile.mkdtemp()
            try:
                db_path = os.path.join(temp_dir, "test.db")
                init_db(db_path)
                f = VulnerabilityFinding(
                    title="Flaw", severity="High", description="desc", line_numbers=[1], remediation="rem"
                )
                write_findings(db_path, target_file, [f], run_id=run_id)
                self.assertEqual(read_findings(db_path, target_file, run_id=run_id)[0]["status"], "reported")

                await ss.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=sess_id)
                runner = Runner(app=app, session_service=ss)

                status_map = cfg.get("on_enter_status", {})
                msg = types.Content(parts=[types.Part.from_text(text="Evaluate file.py")], role="user")
                executed_nodes = []
                async for ev in runner.run_async(user_id=USER_ID, session_id=sess_id, new_message=msg):
                    path = getattr(getattr(ev, "node_info", None), "path", None)
                    if path:
                        node_name = path.split("/")[-1].split("@")[0]
                        if status_map and node_name in status_map:
                            update_status(db_path, target_file, run_id, status_map[node_name])
                        if not executed_nodes or executed_nodes[-1] != node_name:
                            executed_nodes.append(node_name)
                await runner.close()
                self.assertEqual(executed_nodes, expected_node_order)

                findings = read_findings(db_path, target_file, run_id=run_id)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["status"], expected_status)
            finally:
                shutil.rmtree(temp_dir)

    async def test_execute_sub_task_status_lifecycle(self):
        """Verifies execute_sub_task status lifecycle propagation across all paths (dynamic_confirmed, static_confirmed, reported)."""
        workflow_path = os.path.join(os.path.dirname(__file__), "workflow.json")

        scenarios = [
            (
                [
                    "History extracted.",
                    "Structural index built.",
                    "Architecture KB created.",
                    "Threat model created.",
                    "Plan created.",
                    "Analysis done.",
                    "Findings deduplicated.",
                    json.dumps({"route": "confirmed", "reason": "Analysis done."}),
                    json.dumps({"route": "viable", "reason": "Exploit viable."}),
                    json.dumps({"route": "success", "reason": "Exploit verified."}),
                    "Exploit chained.",
                    "Patch applied",
                    "Score: 90",
                    "Learnings reflected.",
                    "Report generated.",
                ],
                "dynamic_confirmed",
                True,
            ),
            (
                [
                    "History extracted.",
                    "Structural index built.",
                    "Architecture KB created.",
                    "Threat model created.",
                    "Plan created.",
                    "Analysis done.",
                    "Findings deduplicated.",
                    json.dumps({"route": "confirmed", "reason": "Analysis done."}),
                    json.dumps({"route": "viable", "reason": "Exploit viable."}),
                    json.dumps({"route": "failed_repro", "reason": "Exploit failed."}),
                    json.dumps({"route": "failed_repro", "reason": "Exploit failed."}),
                    "Score: 20",
                    "Learnings reflected.",
                    "Report generated.",
                ],
                "static_confirmed",
                False,
            ),
            (
                [
                    "History extracted.",
                    "Structural index built.",
                    "Architecture KB created.",
                    "Threat model created.",
                    "Plan created.",
                    "Analysis done.",
                    "Findings deduplicated.",
                    json.dumps({"route": "false_positive", "reason": "Score: 0"}),
                    "Score: 0",
                    "Learnings reflected.",
                    "Report generated.",
                ],
                "reported",
                False,
            ),
        ]

        for replies, expected_status, sb_exec in scenarios:
            with self.subTest(expected_status=expected_status):
                queue = list(replies)

                class ScriptedLlm(BaseLlm):
                    async def generate_content_async(self, llm_request, stream: bool = False):
                        text = queue.pop(0) if queue else "done"
                        yield LlmResponse(content=types.Content(parts=[types.Part.from_text(text=text)]))

                with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
                    with patch("core.graph_loader.LiteLlm", lambda **_: ScriptedLlm(model="scripted")):
                        wf, cfg = load_workflow_from_json(workflow_path)

                app = App(name=APP_NAME, root_agent=wf)
                ss = InMemorySessionService()
                runner = Runner(app=app, session_service=ss)

                temp_dir = tempfile.mkdtemp()
                try:
                    db_path = os.path.join(temp_dir, "test.db")
                    init_db(db_path)
                    target_file = "test_target.py"
                    run_id = f"run-{expected_status}"

                    f = VulnerabilityFinding(
                        title="SQL Injection", severity="Critical", description="raw query", line_numbers=[42], remediation="use ORM"
                    )
                    write_findings(db_path, target_file, [f], run_id=run_id)
                    self.assertEqual(read_findings(db_path, target_file, run_id=run_id)[0]["status"], "reported")

                    ctx = RunContext(jail_dir=temp_dir, db_path=db_path, target_file=target_file, run_id=run_id, sandbox_executed=sb_exec)
                    tok = current_run_context.set(ctx)
                    try:
                        err = await execute_sub_task(
                            runner=runner,
                            session_service=ss,
                            filepath=target_file,
                            run_id=run_id,
                            db_path=db_path,
                            status_map=cfg.get("on_enter_status", {}),
                        )
                        self.assertFalse(err)

                        findings = read_findings(db_path, target_file, run_id=run_id)
                        self.assertEqual(len(findings), 1)
                        self.assertEqual(findings[0]["status"], expected_status)
                    finally:
                        current_run_context.reset(tok)
                finally:
                    await runner.close()
                    shutil.rmtree(temp_dir)

    def test_workflow_loader_validations(self):
        """Validates graph loader error paths and token diagnostics."""
        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
            temp_dir = tempfile.mkdtemp()
            try:
                prompts_dir = os.path.join(temp_dir, "prompts")
                os.makedirs(prompts_dir, exist_ok=True)
                with open(os.path.join(prompts_dir, "prompt.md"), "w") as f:
                    f.write("Instructions")

                # 1. Unknown node reference in edge
                bad_edge_cfg = {
                    "nodes": [{"id": "a", "type": "agent", "system_prompt": "prompts/prompt.md"}],
                    "edges": [{"from": "START", "to": "a"}, {"from": "a", "to": "non_existent_node"}]
                }
                path = os.path.join(temp_dir, "bad_edge.json")
                with open(path, "w") as f:
                    json.dump(bad_edge_cfg, f)
                with self.assertRaises(ValueError) as ctx:
                    load_workflow_from_json(path)
                self.assertIn("non_existent_node", str(ctx.exception))

                # 2. Duplicate node id
                dup_cfg = {
                    "nodes": [
                        {"id": "node_x", "type": "agent", "system_prompt": "prompts/prompt.md"},
                        {"id": "node_x", "type": "agent", "system_prompt": "prompts/prompt.md"}
                    ],
                    "edges": [{"from": "START", "to": "node_x"}]
                }
                path = os.path.join(temp_dir, "dup.json")
                with open(path, "w") as f:
                    json.dump(dup_cfg, f)
                with self.assertRaises(ValueError) as ctx:
                    load_workflow_from_json(path)
                self.assertIn("node_x", str(ctx.exception))

                # 3. Undeclared route in edge
                bad_route_cfg = {
                    "nodes": [
                        {"id": "cls", "type": "classifier", "routes": ["confirmed", "false_positive"]},
                        {"id": "cal", "type": "agent", "system_prompt": "prompts/prompt.md"}
                    ],
                    "edges": [
                        {"from": "START", "to": "cls"},
                        {"from": "cls", "to": "cal", "on": "unrecognized_route"}
                    ]
                }
                path = os.path.join(temp_dir, "bad_route.json")
                with open(path, "w") as f:
                    json.dump(bad_route_cfg, f)
                with self.assertRaises(ValueError) as ctx:
                    load_workflow_from_json(path)
                self.assertIn("unrecognized_route", str(ctx.exception))

                # 4. Unknown output_schema
                bad_schema_cfg = {
                    "nodes": [
                        {"id": "agent_bad_schema", "type": "agent", "system_prompt": "prompts/prompt.md", "output_schema": "NonExistentSchema"}
                    ],
                    "edges": [{"from": "START", "to": "agent_bad_schema"}]
                }
                path = os.path.join(temp_dir, "bad_schema.json")
                with open(path, "w") as f:
                    json.dump(bad_schema_cfg, f)
                with self.assertRaises(ValueError) as ctx:
                    load_workflow_from_json(path)
                self.assertIn("unknown output_schema 'NonExistentSchema'", str(ctx.exception))
            finally:
                shutil.rmtree(temp_dir)

    async def test_classifier_edge_cases(self):
        """Table-driven unit testing for classifier structured verdict reading and max_visits."""
        test_cases = [
            ({"route": "success", "reason": "verified"}, ["success", "failed_repro"], 1, "success"),
            ({"route": "false_positive", "reason": "benign"}, ["confirmed", "false_positive"], 1, "false_positive"),
            ({"route": "confirmed", "reason": "flaw"}, ["confirmed", "false_positive"], 1, "confirmed"),
            ({"route": "unrecognized", "reason": "unknown"}, ["confirmed", "false_positive"], 1, DEFAULT_ROUTE),
            ({}, ["confirmed", "false_positive"], 1, DEFAULT_ROUTE),
            (None, ["confirmed", "false_positive"], 1, DEFAULT_ROUTE),
        ]
        for verdict, routes, max_v, expected_route in test_cases:
            with self.subTest(verdict=verdict, expected_route=expected_route):
                c = create_classifier("test_cls", routes, max_visits=max_v)
                ctx = MagicMock()
                ctx.state = {"verdict": verdict} if verdict is not None else {}
                evt = await c._func(ctx, node_input="ignored")
                self.assertEqual(evt.actions.route, expected_route)
                self.assertEqual(evt.output, "ignored")

        # Object with .route attribute (e.g. ReviewVerdict or ReproVerdict)
        from core.schemas import ReviewVerdict
        c_obj = create_classifier("test_obj_cls", ["confirmed"])
        ctx_obj = MagicMock()
        ctx_obj.state = {"verdict": ReviewVerdict(route="confirmed", reason="exploit verified")}
        evt_obj = await c_obj._func(ctx_obj)
        self.assertEqual(evt_obj.actions.route, "confirmed")

        # max_visits lifecycle test
        c_multi = create_classifier("repro_cls", ["success"], max_visits=2)
        ctx = MagicMock()
        ctx.state = {"verdict": {"route": "failed_repro", "reason": "attempt 1"}}
        evt1 = await c_multi._func(ctx)
        self.assertEqual(evt1.actions.route, DEFAULT_ROUTE)
        ctx.state["repro_cls_visits"] = 1
        evt2 = await c_multi._func(ctx)
        self.assertEqual(evt2.actions.route, "exceeded")

    def test_database_deduplication_and_normalization(self):
        """Tests SQLite uniqueness deduplication, line sorting normalization, risk recording, and status lifecycle."""
        temp_dir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(temp_dir, "test.db")
            target = os.path.join(temp_dir, "test.py")
            init_db(db_path)

            # 1. Default status is 'reported'
            f1 = VulnerabilityFinding(title="XSS", severity="High", description="d1", line_numbers=[20, 10], remediation="r1")
            write_findings(db_path, target, [f1], run_id="run-1")
            rows = read_findings(db_path, target, run_id="run-1")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["status"], "reported")
            self.assertEqual(rows[0]["line_numbers"], [10, 20])

            # Deduplication on (filepath, title, description, line_numbers, run_id)
            f2 = VulnerabilityFinding(title="XSS", severity="Critical", description="d1", line_numbers=[10, 20], remediation="r2")
            write_findings(db_path, target, [f2], run_id="run-1")
            rows = read_findings(db_path, target, run_id="run-1")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["severity"], "CRITICAL")

            # 2. Distinct description creates new row
            f3 = VulnerabilityFinding(title="XSS", severity="Low", description="d2", line_numbers=[10, 20], remediation="r3")
            write_findings(db_path, target, [f3], run_id="run-1")
            self.assertEqual(len(read_findings(db_path, target, run_id="run-1")), 2)

            # 3. Status lifecycle update (file-scoped and repo-scoped)
            update_status(db_path, target, "run-1", "static_confirmed")
            rows_static = read_findings(db_path, target, run_id="run-1", status="static_confirmed")
            self.assertEqual(len(rows_static), 2)
            self.assertEqual(len(read_findings(db_path, target, run_id="run-1", status="reported")), 0)

            update_status(db_path, target, "run-1", "dynamic_confirmed")
            rows_dynamic = read_findings(db_path, target, run_id="run-1", status="dynamic_confirmed")
            self.assertEqual(len(rows_dynamic), 2)

            # 4. Specific filepath attribution under repo-scoped run
            f_repo = VulnerabilityFinding(
                filepath="src/auth.py",
                title="Auth Bypass",
                severity="high",
                description="Token signature omitted",
                line_numbers=[42],
                remediation="verify sig",
            )
            self.assertEqual(f_repo.severity, "HIGH")
            self.assertEqual(f_repo.filepath, "src/auth.py")
            write_findings(db_path, temp_dir, [f_repo], run_id="run-repo")
            repo_rows = read_findings(db_path, temp_dir, run_id="run-repo")
            self.assertEqual(len(repo_rows), 1)
            self.assertEqual(repo_rows[0]["filepath"], "src/auth.py")
            self.assertEqual(repo_rows[0]["severity"], "HIGH")

            # 5. None status in finding payload safely defaults to 'reported'
            f_none = {"title": "CSRF", "severity": "Medium", "description": "no csrf token", "line_numbers": [5], "remediation": "add token", "status": None}
            write_findings(db_path, target, [f_none], run_id="run-2")
            rows_none = read_findings(db_path, target, run_id="run-2")
            self.assertEqual(len(rows_none), 1)
            self.assertEqual(rows_none[0]["status"], "reported")
            self.assertEqual(rows_none[0]["severity"], "MEDIUM")

            # 6. Risk scores (0.1 - 10.0 canonical scale)
            record_calibration(db_path, target, 8.5, "High risk flaw", run_id="run-1")
            scores = read_risk_scores(db_path, target, run_id="run-1")
            self.assertEqual(len(scores), 1)
            self.assertEqual(scores[0]["score"], 8.5)
        finally:
            shutil.rmtree(temp_dir)

    def test_database_schema_version_enforcement(self):
        """Tests that PRAGMA user_version is stamped and mismatched schema versions fail fast with actionable guidance."""
        from core.database import CURRENT_SCHEMA_VERSION, _db
        temp_dir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(temp_dir, "version_test.db")
            # 1. Fresh init stamps CURRENT_SCHEMA_VERSION
            init_db(db_path)
            with _db(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA user_version")
                self.assertEqual(cursor.fetchone()[0], CURRENT_SCHEMA_VERSION)

            # 2. Outdated version (e.g. version 0 from older schema) raises RuntimeError on init_db
            with _db(db_path, check_version=False) as conn:
                conn.cursor().execute("PRAGMA user_version = 0")

            with self.assertRaises(RuntimeError) as ctx_err:
                init_db(db_path)
            self.assertIn("Database schema version mismatch", str(ctx_err.exception))
            self.assertIn("please delete", str(ctx_err.exception))

            # 3. Outdated version also raises fail-fast on read operations
            with self.assertRaises(RuntimeError) as ctx_read:
                read_findings(db_path)
            self.assertIn("Database schema version mismatch", str(ctx_read.exception))
        finally:
            shutil.rmtree(temp_dir)

    def test_update_status_preserves_merged_and_suppressed_findings(self):
        """Tests that update_status advances candidate findings without resurrecting merged or false positive verdicts."""
        temp_dir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(temp_dir, "test.db")
            init_db(db_path)
            target = os.path.join(temp_dir, "app.py")

            f1 = {"title": "SQLi Primary", "severity": "CRITICAL", "description": "query 1", "line_numbers": [10]}
            f2 = {"title": "SQLi Duplicate", "severity": "CRITICAL", "description": "query 2", "line_numbers": [12]}
            f3 = {"title": "Test Bug", "severity": "LOW", "description": "sample test code", "line_numbers": [20]}
            write_findings(db_path, target, [f1, f2, f3], run_id="run-1")

            # Deduplicator marks f2 as duplicate_merged, reviewer marks f3 as false_positive
            all_findings = read_findings(db_path, target, run_id="run-1")
            id2 = all_findings[1]["id"]
            id3 = all_findings[2]["id"]

            with _db(db_path) as conn:
                conn.cursor().execute("UPDATE findings SET status = 'duplicate_merged' WHERE id = ?", (id2,))
                conn.cursor().execute("UPDATE findings SET status = 'false_positive' WHERE id = ?", (id3,))

            # Downstream reproducer enters with on_enter_status: static_confirmed
            update_status(db_path, target, "run-1", "static_confirmed")

            updated = read_findings(db_path, target, run_id="run-1")
            self.assertEqual(updated[0]["status"], "static_confirmed")
            # Terminal verdicts are strictly preserved
            self.assertEqual(updated[1]["status"], "duplicate_merged")
            self.assertEqual(updated[2]["status"], "false_positive")
        finally:
            shutil.rmtree(temp_dir)

    def test_strict_run_id_isolation_and_no_cross_run_bleeds(self):
        """Tests that runs are strictly isolated and never borrow findings or artifacts from prior runs."""
        temp_dir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(temp_dir, "test.db")
            init_db(db_path)
            target = os.path.join(temp_dir, "app.py")

            # Run 1 writes findings and artifacts
            f1 = {"title": "R1 Finding", "severity": "HIGH", "description": "run 1 flaw"}
            write_findings(db_path, target, [f1], run_id="run-1")
            record_artifact(db_path, "run-1", "plan", "workspace/plan.json", "RUN 1 PLAN")

            # Run 2 queries its own findings and artifacts
            r2_findings = read_findings(db_path, target, run_id="run-2")
            self.assertEqual(len(r2_findings), 0)

            r2_artifact = read_artifact(db_path, filepath="workspace/plan.json", run_id="run-2")
            self.assertIsNone(r2_artifact)

            # update_status under Run 2 does NOT mutate Run 1 findings
            update_status(db_path, target, "run-2", "dynamic_confirmed")
            r1_findings = read_findings(db_path, target, run_id="run-1")
            self.assertEqual(r1_findings[0]["status"], "reported")
        finally:
            shutil.rmtree(temp_dir)

    async def test_sqlite_session_service_persistence_and_rehydration(self):
        """Tests that SqliteSessionService persists session trajectories and allows full rehydration."""
        from google.adk.sessions.sqlite_session_service import SqliteSessionService
        temp_dir = tempfile.mkdtemp()
        try:
            sessions_db = os.path.join(temp_dir, "sessions.db")
            session_svc = SqliteSessionService(db_path=sessions_db)

            # 1. Create session with custom state
            session_id = "test_run_session_1"
            await session_svc.create_session(
                app_name=APP_NAME,
                user_id=USER_ID,
                session_id=session_id,
                state={"run_id": "run-xyz", "target_file": "app.py"}
            )

            # 2. Verify tables created in sessions.db
            conn = sqlite3.connect(sessions_db)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [t[0] for t in cur.fetchall()]
            self.assertIn("sessions", tables)
            self.assertIn("events", tables)
            conn.close()

            # 3. Rehydrate session and verify state
            rehydrated = await session_svc.get_session(app_name=APP_NAME, user_id=USER_ID, session_id=session_id)
            self.assertIsNotNone(rehydrated)
            self.assertEqual(rehydrated.id, session_id)
            self.assertEqual(rehydrated.state.get("run_id"), "run-xyz")
            self.assertEqual(rehydrated.state.get("target_file"), "app.py")
        finally:
            shutil.rmtree(temp_dir)

    async def test_read_file_jail_security(self):
        """Tests directory traversal prevention and boundary enforcement in read_file and StaticOnlyEnvironment."""
        temp_dir = tempfile.mkdtemp()
        try:
            jail_dir = os.path.join(temp_dir, "jail")
            os.makedirs(jail_dir)
            inside_file = os.path.join(jail_dir, "inside.txt")
            with open(inside_file, "w") as f:
                f.write("content_inside")

            outside_file = os.path.join(temp_dir, "outside.txt")
            with open(outside_file, "w") as f:
                f.write("secret")

            # 1. No context
            self.assertIn("No active execution context", await read_file("inside.txt"))

            # 2. Test StaticOnlyEnvironment directly in single-file mode
            single_file_env = StaticOnlySandbox(target_path=inside_file)
            # 2a. Requesting the target file succeeds
            self.assertEqual((await single_file_env.read_file(Path("inside.txt"))).decode("utf-8"), "content_inside")
            # 2b. Requesting another file raises PermissionError (never silently returns target file)
            with self.assertRaises(PermissionError):
                await single_file_env.read_file(Path("other.txt"))
            # 2c. Requesting an absolute path outside raises PermissionError
            with self.assertRaises(PermissionError):
                await single_file_env.read_file(Path(outside_file))

            # 3. Test StaticOnlyEnvironment in directory mode
            dir_env = StaticOnlySandbox(target_path=jail_dir)
            self.assertEqual((await dir_env.read_file(Path("inside.txt"))).decode("utf-8"), "content_inside")
            with self.assertRaises(PermissionError):
                await dir_env.read_file(Path("../outside.txt"))
            with self.assertRaises(PermissionError):
                await dir_env.read_file(Path(outside_file))
            with self.assertRaises(FileNotFoundError):
                await dir_env.read_file(Path("missing.txt"))

            # 4. Test read_file tool with active sandbox attached
            ctx_sb = RunContext(jail_dir=jail_dir, db_path="", target_file=inside_file, sandbox=dir_env)
            tok = current_run_context.set(ctx_sb)
            try:
                self.assertIn("content_inside", await read_file("inside.txt"))
                self.assertIn("Permission denied", await read_file("../outside.txt"))
                self.assertIn("Permission denied", await read_file(outside_file))
                self.assertIn("File not found", await read_file("missing.txt"))
            finally:
                current_run_context.reset(tok)

            # 5. Test read_file tool with direct host fallback (no sandbox)
            ctx_host = RunContext(jail_dir=jail_dir, db_path="", target_file=inside_file, sandbox=None)
            tok = current_run_context.set(ctx_host)
            try:
                self.assertIn("content_inside", await read_file("inside.txt"))
                self.assertIn("Permission denied", await read_file("../outside.txt"))
                self.assertIn("Permission denied", await read_file(outside_file))
                self.assertIn("File not found", await read_file("missing.txt"))
            finally:
                current_run_context.reset(tok)
        finally:
            shutil.rmtree(temp_dir)

    async def test_list_files_jail_security(self):
        """Tests file listing, directory traversal prevention, and failure reporting across sandboxes."""
        temp_dir = tempfile.mkdtemp()
        try:
            jail_dir = os.path.join(temp_dir, "jail")
            os.makedirs(os.path.join(jail_dir, "src"))
            file_a = os.path.join(jail_dir, "src", "app.py")
            with open(file_a, "w") as f:
                f.write("print('app')")
            file_b = os.path.join(jail_dir, "README.md")
            with open(file_b, "w") as f:
                f.write("# README")

            outside_dir = os.path.join(temp_dir, "outside")
            os.makedirs(outside_dir)
            with open(os.path.join(outside_dir, "secret.py"), "w") as f:
                f.write("secret")

            # 1. No context
            self.assertIn("No active execution context", await list_files())

            # 2. StaticOnlySandbox in directory mode
            dir_env = StaticOnlySandbox(target_path=jail_dir)
            files = await dir_env.list_files()
            self.assertEqual(files, ["README.md", "src/app.py"])

            # 2a. Subdirectory listing
            sub_files = await dir_env.list_files("src")
            self.assertEqual(sub_files, ["src/app.py"])

            # 2b. Out-of-scope traversal raises PermissionError
            with self.assertRaises(PermissionError):
                await dir_env.list_files("../outside")

            # 2c. Non-existent directory raises FileNotFoundError
            with self.assertRaises(FileNotFoundError):
                await dir_env.list_files("non_existent_subdir")

            # 3. StaticOnlySandbox in single-file mode
            single_env = StaticOnlySandbox(target_path=file_a)
            self.assertEqual(await single_env.list_files(), ["app.py"])
            with self.assertRaises(PermissionError):
                await single_env.list_files("../outside")

            # 4. list_files tool with active sandbox attached
            ctx_sb = RunContext(jail_dir=jail_dir, db_path="", target_file=file_a, sandbox=dir_env)
            tok = current_run_context.set(ctx_sb)
            try:
                res_json = await list_files()
                self.assertEqual(json.loads(res_json), ["README.md", "src/app.py"])
                self.assertIn("Permission denied", await list_files("../outside"))
                self.assertIn("Directory not found", await list_files("missing"))
            finally:
                current_run_context.reset(tok)

            # 5. list_files tool with direct host fallback (no sandbox)
            ctx_host = RunContext(jail_dir=jail_dir, db_path="", target_file=file_a, sandbox=None)
            tok = current_run_context.set(ctx_host)
            try:
                res_host = await list_files()
                self.assertEqual(json.loads(res_host), ["README.md", "src/app.py"])
                self.assertIn("Permission denied", await list_files("../outside"))
                self.assertIn("Directory not found", await list_files("missing"))
            finally:
                current_run_context.reset(tok)
        finally:
            shutil.rmtree(temp_dir)

    async def test_sandbox_tools_with_context(self):
        """Verifies sandbox tool delegators correctly plumb through current_run_context."""
        self.assertIn("No active sandbox", await run_sandbox("echo 1"))
        self.assertIn("No active sandbox", await apply_patch("diff"))

        mock_sb = AsyncMock()
        mock_sb.execute.return_value = "exit=0\nok"
        mock_sb.apply_patch.return_value = "exit=0\npitched"

        ctx = RunContext(jail_dir="/tmp", db_path="", sandbox=mock_sb)
        tok = current_run_context.set(ctx)
        try:
            res_exec = await run_sandbox("echo test")
            self.assertEqual(res_exec, "exit=0\nok")
            mock_sb.execute.assert_called_once_with("echo test")
            self.assertTrue(ctx.sandbox_executed)

            res_patch = await apply_patch("test_diff")
            self.assertEqual(res_patch, "exit=0\npitched")
            mock_sb.apply_patch.assert_called_once_with("test_diff")
        finally:
            current_run_context.reset(tok)

        # Failure string (e.g. SANDBOX-UNAVAILABLE) does NOT set sandbox_executed
        mock_sb_unavail = AsyncMock()
        mock_sb_unavail.execute.return_value = "SANDBOX-UNAVAILABLE: no sandbox configured; nothing was executed."
        ctx_unavail = RunContext(jail_dir="/tmp", db_path="", sandbox=mock_sb_unavail)
        tok = current_run_context.set(ctx_unavail)
        try:
            self.assertFalse(ctx_unavail.sandbox_executed)
            res_fail = await run_sandbox("echo test")
            self.assertIn("SANDBOX-UNAVAILABLE", res_fail)
            self.assertFalse(ctx_unavail.sandbox_executed)
        finally:
            current_run_context.reset(tok)


    async def test_sandbox_seam(self):
        """Tests sandbox dispatch, StaticOnlySandbox, custom plugin seam, and gVisor/Microsandbox platform checks."""
        with self.assertRaises(ValueError):
            build_sandbox({"type": "invalid_type"})

        static_sb = build_sandbox({"type": "static-only"})
        self.assertIsInstance(static_sb, StaticOnlySandbox)
        await static_sb.preflight()
        res_st = await static_sb.execute("whoami")
        self.assertEqual(res_st.exit_code, 127)
        self.assertIn("SANDBOX-UNAVAILABLE", res_st.stderr)

        class CustomSeam:
            def __init__(self, target_path: str = "", **_): pass
            async def execute(self, cmd: str) -> str: return "custom_ok"
            async def apply_patch(self, diff: str) -> str: return "custom_patch"
            async def preflight(self) -> None: pass
            async def aclose(self): pass

        SANDBOXES["custom"] = CustomSeam
        try:
            custom_sb = build_sandbox({"type": "custom"})
            await custom_sb.preflight()
            self.assertEqual(await custom_sb.execute("test"), "custom_ok")
        finally:
            SANDBOXES.pop("custom", None)

        # 1. When docker/podman is NOT on PATH (e.g. clean macOS or minimal Linux host)
        with patch("shutil.which", return_value=None):
            with self.assertRaises(ValueError) as ctx_missing:
                GvisorSandbox()
            self.assertIn("requires 'docker' or 'podman'", str(ctx_missing.exception))

        # 2. When docker/podman is present on PATH
        with patch("shutil.which", side_effect=lambda x: f"/usr/bin/{x}" if x in ("docker", "podman") else None):
            with self.assertRaises(ValueError):
                GvisorSandbox(container_tool="missing_tool_xyz")

            # Test build_sandbox for gvisor
            gv_built = build_sandbox({"type": "gvisor"})
            self.assertIsInstance(gv_built, GvisorSandbox)
            self.assertEqual(gv_built.tool, "docker")

            # 2a. Preflight fails when docker daemon is unreachable
            with patch("subprocess.run") as mock_subproc:
                mock_subproc.return_value = MagicMock(returncode=1, stdout="", stderr="Cannot connect to Docker daemon")
                with self.assertRaises(RuntimeError) as ctx_daemon:
                    await gv_built.preflight()
                self.assertIn("Could not connect to docker daemon", str(ctx_daemon.exception))

            # 2b. Preflight fails when runtime is not registered in docker
            with patch("subprocess.run") as mock_subproc:
                mock_subproc.return_value = MagicMock(returncode=0, stdout='{"runc": {}}', stderr="")
                with self.assertRaises(RuntimeError) as ctx_runsc:
                    await gv_built.preflight()
                self.assertIn("not a registered docker runtime", str(ctx_runsc.exception))

            # 2c. Preflight fails when sandbox image is missing in docker cache
            with patch("subprocess.run") as mock_subproc:
                mock_subproc.side_effect = [
                    MagicMock(returncode=0, stdout='{"runsc": {}}', stderr=""),
                    MagicMock(returncode=1, stdout="", stderr="Error: No such image"),
                ]
                with self.assertRaises(RuntimeError) as ctx_img:
                    await gv_built.preflight()
                self.assertIn("sandbox image 'mantis-sandbox:latest' not found in the local docker cache", str(ctx_img.exception))

            # 2d. Preflight succeeds when runtime and image are present
            with patch("subprocess.run") as mock_subproc:
                mock_subproc.side_effect = [
                    MagicMock(returncode=0, stdout='{"runsc": {}}', stderr=""),
                    MagicMock(returncode=0, stdout="[ok]", stderr=""),
                ]
                await gv_built.preflight()

            # Mocked containerized gVisor execution test
            gv = GvisorSandbox(container_tool="docker")
            gv._run_cmd = MagicMock()
            gv._run_cmd.side_effect = [
                (0, "container_id"),
                (0, ""),
                (0, "patch applied\n"),
                (0, ""),
            ]
            with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="hello gvisor\n", stderr="")):
                out_exec = await gv.execute("echo hello")
                self.assertEqual(out_exec.exit_code, 0)
                self.assertIn("hello gvisor", out_exec.stdout)
            out_patch = await gv.apply_patch("diff_text")
            self.assertIn("patch applied", out_patch)
            await gv.aclose()

        # 3. Microsandbox KVM access check on Linux
        from microsandbox import ImageNotFoundError
        with patch("sys.platform", "linux"):
            with patch("os.access", return_value=False):
                with self.assertRaises(RuntimeError) as ctx_kvm:
                    MicrosandboxSandbox()
                self.assertIn("Hardware virtualization unavailable", str(ctx_kvm.exception))
                self.assertIn("static-only", str(ctx_kvm.exception))

            with patch("os.access", return_value=True):
                msb = MicrosandboxSandbox()
                self.assertEqual(msb.image, "mantis-sandbox:latest")

            # 4. Microsandbox missing image failure in preflight
            with patch("os.access", return_value=True):
                sb_missing = MicrosandboxSandbox(image="missing-image-not-in-cache:latest")
                with patch("microsandbox.Image.get", side_effect=ImageNotFoundError("image not found")):
                    with self.assertRaises(RuntimeError) as ctx_img:
                        await sb_missing.preflight()
                    self.assertIn("sandbox image 'missing-image-not-in-cache:latest' not found in the local cache", str(ctx_img.exception))

                # Preflight success when Image.get succeeds
                with patch("microsandbox.Image.get", AsyncMock()):
                    await sb_missing.preflight()

                # 5. Verify MsbSandbox.create passes pull_policy=PullPolicy.NEVER
                from microsandbox import PullPolicy
                mock_msb_instance = AsyncMock()
                mock_msb_instance.fs.mkdir = AsyncMock()
                mock_msb_instance.fs.copy_from_host = AsyncMock()
                with patch("microsandbox.Sandbox.create", AsyncMock(return_value=mock_msb_instance)) as mock_msb_create:
                    sb_created = MicrosandboxSandbox(image="mantis-sandbox:latest")
                    await sb_created._ensure()
                    mock_msb_create.assert_called_once()
                    _, kwargs_create = mock_msb_create.call_args
                    self.assertEqual(kwargs_create.get("pull_policy"), PullPolicy.NEVER)
                    self.assertEqual(kwargs_create.get("image"), "mantis-sandbox:latest")

                # 6. Verify staging ignores symlinks and protected VCS/metadata files
                with tempfile.TemporaryDirectory() as temp_target:
                    norm_path = os.path.join(temp_target, "app.py")
                    with open(norm_path, "w") as f:
                        f.write("print('hello')")
                    env_path = os.path.join(temp_target, ".env")
                    with open(env_path, "w") as f:
                        f.write("SECRET=123")
                    git_dir = os.path.join(temp_target, ".git")
                    os.makedirs(git_dir, exist_ok=True)
                    with open(os.path.join(git_dir, "config"), "w") as f:
                        f.write("secret git config")
                    link_path = os.path.join(temp_target, "bad_link.py")
                    try:
                        os.symlink("/etc/passwd", link_path)
                    except OSError:
                        pass

                    mock_msb_staging = AsyncMock()
                    mock_msb_staging.fs.mkdir = AsyncMock()
                    mock_msb_staging.fs.copy_from_host = AsyncMock()
                    with patch("microsandbox.Sandbox.create", AsyncMock(return_value=mock_msb_staging)):
                        sb_staging = MicrosandboxSandbox(target_path=temp_target)
                        await sb_staging._ensure()
                        copied_sources = [call.args[0] for call in mock_msb_staging.fs.copy_from_host.call_args_list]
                        real_norm = os.path.realpath(norm_path)
                        real_env = os.path.realpath(env_path)
                        real_link = os.path.realpath(link_path)
                        self.assertIn(real_norm, copied_sources)
                        self.assertNotIn(real_env, copied_sources)
                        self.assertNotIn(real_link, copied_sources)
                        self.assertTrue(all(".git" not in src for src in copied_sources))

    async def test_gce_sandbox_lifecycle_and_security_hardening(self):
        """Tests GceEnvironment dispatch, security hardening flags, IAP tunneling, host isolation, and execution."""
        # 1. Dispatch via build_sandbox
        gce_sb = build_sandbox({
            "type": "gce",
            "options": {
                "project": "test-project-123",
                "zone": "us-west1-b",
                "source_machine_image": "mantis-golden-image-v1",
                "subnet": "mantis-isolated-subnet",
                "timeout_seconds": 45,
            }
        })
        self.assertIsInstance(gce_sb, GceSandbox)
        self.assertEqual(gce_sb.project, "test-project-123")
        self.assertEqual(gce_sb.zone, "us-west1-b")
        self.assertEqual(gce_sb.source_machine_image, "mantis-golden-image-v1")
        self.assertEqual(gce_sb.subnet, "mantis-isolated-subnet")

        # 2. Preflight validations
        # 2a. Fails when gcloud binary is missing
        with patch("shutil.which", return_value=None):
            with patch("os.path.exists", return_value=False):
                sb_no_bin = GceSandbox(gcloud_bin="missing_gcloud_xyz")
                with self.assertRaises(ValueError) as ctx_err:
                    await sb_no_bin.preflight()
                self.assertIn("requires 'missing_gcloud_xyz' on PATH", str(ctx_err.exception))

        # 2b. Fails when GCP project is not specified
        with patch.dict(os.environ, {}, clear=True):
            sb_no_proj = GceSandbox(project="", gcloud_bin="/usr/bin/gcloud")
            sb_no_proj._run_gcloud = MagicMock(return_value=(1, "unset"))
            with patch("shutil.which", return_value="/usr/bin/gcloud"):
                with self.assertRaises(ValueError) as ctx_proj:
                    await sb_no_proj.preflight()
                self.assertIn("GCP project not specified", str(ctx_proj.exception))

        # 2c. Fails when GCP project is set to default placeholder (e.g. YOUR_PROJECT_ID)
        sb_placeholder = GceSandbox(project="YOUR_PROJECT_ID", gcloud_bin="/usr/bin/gcloud")
        with patch("shutil.which", return_value="/usr/bin/gcloud"):
            with self.assertRaises(ValueError) as ctx_ph:
                await sb_placeholder.preflight()
            self.assertIn("default placeholder 'YOUR_PROJECT_ID'", str(ctx_ph.exception))

        # 2d. Fails when no active gcloud authentication
        sb_auth_fail = GceSandbox(project="test-proj", gcloud_bin="/usr/bin/gcloud")
        sb_auth_fail._run_gcloud = MagicMock(return_value=(0, ""))
        with patch("shutil.which", return_value="/usr/bin/gcloud"):
            with self.assertRaises(RuntimeError) as ctx_auth:
                await sb_auth_fail.preflight()
            self.assertIn("No active Google Cloud authentication found", str(ctx_auth.exception))

        # 2e. Preflight passes when active account is found
        sb_pass = GceSandbox(project="test-proj", gcloud_bin="/usr/bin/gcloud")
        sb_pass._run_gcloud = MagicMock(return_value=(0, "user@example.com\n"))
        with patch("shutil.which", return_value="/usr/bin/gcloud"):
            await sb_pass.preflight()

        # 3. Instance Creation & Security Invariants Verification
        created_cmds = []
        def mock_run_gcloud(argv, **kwargs):
            cmd_str = " ".join(argv)
            created_cmds.append(argv)
            if "instances create" in cmd_str:
                return 0, "Created [https://www.googleapis.com/compute/v1/projects/...]."
            elif "compute ssh" in cmd_str:
                return 0, "workspace ready"
            elif "instances delete" in cmd_str:
                return 0, "Deleted instance"
            return 0, "ok"

        gce_test = GceSandbox(
            project="sec-proj",
            zone="us-central1-a",
            image="projects/sec-proj/global/images/dev-disk-v1",
            subnet="mantis-isolated-subnet",
            no_service_account=True,
            no_external_ip=True,
            tunnel_through_iap=True,
        )
        gce_test._run_gcloud = MagicMock(side_effect=mock_run_gcloud)

        await gce_test._ensure()
        self.assertTrue(gce_test.is_initialized)

        # Inspect the 'instances create' command
        create_argv = next(cmd for cmd in created_cmds if cmd[0] == "compute" and cmd[1] == "instances" and cmd[2] == "create")
        self.assertIn("--no-service-account", create_argv)
        self.assertIn("--no-scopes", create_argv)
        self.assertIn("--no-address", create_argv)
        self.assertIn("--image=projects/sec-proj/global/images/dev-disk-v1", create_argv)
        self.assertIn("--subnet=mantis-isolated-subnet", create_argv)
        self.assertIn("--shielded-secure-boot", create_argv)
        self.assertIn("--shielded-vtpm", create_argv)
        self.assertIn("--shielded-integrity-monitoring", create_argv)
        self.assertIn("--metadata=disable-legacy-endpoints=TRUE,block-project-ssh-keys=TRUE", create_argv)
        self.assertNotIn("--maintenance-policy=TERMINATE", create_argv)
        self.assertIn("--max-run-duration=30m", create_argv)
        self.assertIn("--instance-termination-action=DELETE", create_argv)
        self.assertIn("--labels=mantis-sandbox=true,created-by=mantis", create_argv)

        # 4. Command Execution & Host Isolation (shell=False)
        with patch("subprocess.run") as mock_subproc:
            mock_subproc.return_value = MagicMock(returncode=0, stdout="guest_output\n", stderr="")
            res = await gce_test.execute("echo 'hello payload'")
            self.assertEqual(res.exit_code, 0)
            self.assertEqual(res.stdout, "guest_output\n")
            self.assertFalse(res.timed_out)

            # Verify subprocess.run call on host has shell=False and --tunnel-through-iap
            mock_subproc.assert_called_once()
            called_args, called_kwargs = mock_subproc.call_args
            self.assertFalse(called_kwargs.get("shell", True))
            host_argv = called_args[0]
            self.assertIn("--tunnel-through-iap", host_argv)
            self.assertIn("--command", host_argv)
            self.assertIn("cd /workspace && echo 'hello payload'", host_argv)

        # 5. Stdin Streaming Patch Application (Unbounded by argv)
        with patch("subprocess.run") as mock_subproc_patch:
            mock_subproc_patch.return_value = MagicMock(returncode=0, stdout="patch applied cleanly\n", stderr="")
            out_patch = await gce_test.apply_patch("diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n")
            self.assertIn("patch applied cleanly", out_patch)
            mock_subproc_patch.assert_called_once()
            self.assertEqual(mock_subproc_patch.call_args[1].get("input"), "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n")

        # 6. Base64 File Read & Stdin Streaming File Write (Untruncated Large File Test > 20,000 bytes)
        import base64
        large_payload = b"SECURE_VULN_PAYLOAD_LINE_" * 800  # 20,000 bytes (> 16,000 char MAX_OUTPUT limit)
        b64_large = base64.b64encode(large_payload)
        with patch("subprocess.run") as mock_subproc_read:
            mock_subproc_read.return_value = MagicMock(returncode=0, stdout=b64_large, stderr=b"")
            read_bytes = await gce_test.read_file(Path("src/don't_break.py"))  # tests shlex.quote with apostrophe
            self.assertEqual(len(read_bytes), 20000)
            self.assertEqual(read_bytes, large_payload)

        with patch("subprocess.run") as mock_subproc_write:
            mock_subproc_write.return_value = MagicMock(returncode=0, stdout="", stderr="")
            await gce_test.write_file(Path("src/config.json"), '{"env": "test"}')
            mock_subproc_write.assert_called_once()
            self.assertEqual(mock_subproc_write.call_args[1].get("input"), b'{"env": "test"}')

        # 7. File Listing
        with patch("subprocess.run") as mock_subproc_list:
            mock_subproc_list.return_value = MagicMock(returncode=0, stdout="src/app.py\nsrc/utils.py\n", stderr="")
            file_list = await gce_test.list_files("src")
            self.assertEqual(file_list, ["src/app.py", "src/utils.py"])

        # 8. Teardown & Ephemeral Cleanup
        await gce_test.close()
        self.assertFalse(gce_test.is_initialized)
        delete_argv = next(cmd for cmd in created_cmds if cmd[0] == "compute" and cmd[1] == "instances" and cmd[2] == "delete")
        self.assertIn(gce_test.instance_name, delete_argv)
        self.assertIn("--quiet", delete_argv)

        # 9. Provisioning Failure Cleanup (No Deadlock on Error Path)
        gce_fail = GceSandbox(project="sec-proj", zone="us-central1-a")
        gce_fail._run_gcloud = MagicMock(side_effect=[(1, "ERROR: Quota exceeded"), (0, "Deleted")])
        with self.assertRaises(RuntimeError) as ctx_fail:
            await gce_fail._ensure()
        self.assertIn("Failed to create GCE VM instance", str(ctx_fail.exception))
        self.assertFalse(gce_fail.is_initialized)

        # 10. Active Isolation Verification Failure (Fail-Closed on DNS/Network/IAM Leaks)
        # 10a. Statically verify that ISOLATION_PROBE_SCRIPT compiles with zero syntax errors
        code_obj = compile(ISOLATION_PROBE_SCRIPT, "<probe>", "exec")
        self.assertIsNotNone(code_obj)

        # 10b. Runtime audit failure (exit code 42)
        gce_iso_fail = GceSandbox(project="sec-proj", zone="us-central1-a", verify_isolation=True)
        gce_iso_fail._run_gcloud = MagicMock(side_effect=[
            (0, "Created instance"),
            (0, "mkdir ready"),
            (42, "ISOLATION_FAILURE: DNS: Public DNS recursion resolved example.com to 93.184.216.34 (attach Cloud DNS Response Policy *. -> 0.0.0.0)"),
            (0, "Deleted instance"),
        ])
        with self.assertRaises(RuntimeError) as ctx_iso:
            await gce_iso_fail._ensure()
        self.assertIn("failed security isolation audit", str(ctx_iso.exception))
        self.assertIn("Public DNS recursion resolved", str(ctx_iso.exception))
        self.assertFalse(gce_iso_fail.is_initialized)

        # 11. Probe Execution Failure (e.g. python3 missing from golden image)
        gce_probe_err = GceSandbox(project="sec-proj", zone="us-central1-a", verify_isolation=True)
        gce_probe_err._run_gcloud = MagicMock(side_effect=[
            (0, "Created instance"),
            (0, "mkdir ready"),
            (127, "bash: python3: command not found"),
            (0, "Deleted instance"),
        ])
        with self.assertRaises(RuntimeError) as ctx_probe_err:
            await gce_probe_err._ensure()
        self.assertIn("failed to execute isolation probe (ensure python3 is installed", str(ctx_probe_err.exception))
        self.assertFalse(gce_probe_err.is_initialized)

    def test_isolation_probe_script_syntax_and_ast_compilation(self):
        """Tests that ISOLATION_PROBE_SCRIPT compiles cleanly and parses as valid Python AST."""
        import ast
        from core.environments.gce_env import ISOLATION_PROBE_SCRIPT

        # Assert clean compile without SyntaxError
        code_obj = compile(ISOLATION_PROBE_SCRIPT, "<isolation_probe>", "exec")
        self.assertIsNotNone(code_obj)

        # Assert valid AST tree structure
        tree = ast.parse(ISOLATION_PROBE_SCRIPT)
        self.assertIsInstance(tree, ast.Module)
        self.assertGreater(len(tree.body), 0)

    async def test_gce_preflight_machine_image_and_no_service_account_mutual_exclusion(self):
        """Tests that GceEnvironment preflight rejects source_machine_image when no_service_account=True."""
        gce_invalid = GceSandbox(
            project="test-proj",
            zone="us-central1-a",
            source_machine_image="projects/test-proj/global/machineImages/my-image",
            no_service_account=True,
        )
        with self.assertRaises(ValueError) as ctx:
            await gce_invalid.preflight()
        self.assertIn("GCP Machine Images ('source_machine_image') lock the source VM's IAM service account", str(ctx.exception))
        self.assertIn("capture a custom disk image instead", str(ctx.exception))

    async def test_research_tools_write_file_sandbox_sync_error_logging(self):
        """Tests that write_file handles and logs sandbox sync failures gracefully without NameError."""
        import logging
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_sync_log.db")
        init_db(db_file)
        try:
            mock_sandbox = MagicMock()
            mock_sandbox.write_file = AsyncMock(side_effect=RuntimeError("IAP SSH connection reset"))
            ctx = RunContext(
                jail_dir=temp_dir,
                db_path=db_file,
                target_file="app.py",
                run_id="test-log-run",
                sandbox=mock_sandbox,
            )
            tok = current_run_context.set(ctx)
            try:
                with self.assertLogs("tools.research_tools", level=logging.DEBUG) as cm:
                    res = await write_file("workspace/plan.json", '{"pass_number": 1}')
                    self.assertIn("SUCCESS: Recorded artifact", res)
                    self.assertTrue(any("Failed to sync workspace artifact" in log_line for log_line in cm.output))
            finally:
                current_run_context.reset(tok)
        finally:
            shutil.rmtree(temp_dir)

    def test_database_lineage_and_signature_persistence_and_inheritance(self):
        """Tests that findings preserve signature/lineage_id and inherit lineage across runs."""
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_lineage.db")
        try:
            init_db(db_file)

            # Pass 1: Initial discovery
            f1 = {
                "title": "Path Traversal in /view",
                "severity": "HIGH",
                "description": "User input passed to open() directly",
                "line_numbers": [42, 43],
                "cwe": "CWE-22",
                "remediation": "Validate path containment using os.path.abspath",
            }
            write_findings(db_file, "src/handler.py", [f1], run_id="run-pass-1", status="reported")

            findings_p1 = read_findings(db_file, filepath="src/handler.py", run_id="run-pass-1")
            self.assertEqual(len(findings_p1), 1)
            sig1 = findings_p1[0]["signature"]
            lineage1 = findings_p1[0]["lineage_id"]
            self.assertTrue(sig1)
            self.assertTrue(lineage1)
            self.assertEqual(findings_p1[0]["cwe"], "CWE-22")

            # Pass 2: Subsequent discovery of the same bug in a new run -> inherits lineage1!
            f2 = {
                "title": "Path Traversal in /view",
                "severity": "HIGH",
                "description": "User input passed to open() directly",
                "line_numbers": [42, 43],
                "cwe": "CWE-22",
            }
            write_findings(db_file, "src/handler.py", [f2], run_id="run-pass-2", status="dynamic_confirmed")

            findings_p2 = read_findings(db_file, filepath="src/handler.py", run_id="run-pass-2")
            self.assertEqual(len(findings_p2), 1)
            self.assertEqual(findings_p2[0]["signature"], sig1)
            self.assertEqual(findings_p2[0]["lineage_id"], lineage1)

            # Query historical lineage across all runs
            history = query_historical_lineage(db_file, lineage_id=lineage1)
            self.assertEqual(len(history), 2)
            self.assertEqual(history[0]["run_id"], "run-pass-1")
            self.assertEqual(history[1]["run_id"], "run-pass-2")

            # Tool query_lineage output
            ctx = RunContext(jail_dir=temp_dir, db_path=db_file, run_id="run-pass-2")
            tok = current_run_context.set(ctx)
            try:
                res = query_lineage(lineage_id=lineage1)
                self.assertIn("Lineage History (2 record(s))", res)
                self.assertIn("CWE-22", res)
            finally:
                current_run_context.reset(tok)
        finally:
            shutil.rmtree(temp_dir)

    def test_stable_lineage_matching_across_title_phrasing_and_line_shifts(self):
        """Tests that backticks, title paraphrasing, and line insertions all resolve to the same lineage."""
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_stable_sig.db")
        try:
            init_db(db_file)

            # 1. First run: "SQL Injection in `get_user`", line 9
            f1 = {
                "title": "SQL Injection in `get_user`",
                "severity": "HIGH",
                "description": "User input passed to database query in get_user()",
                "line_numbers": [9],
                "cwe": "CWE-89",
            }
            write_findings(db_file, "app.py", [f1], run_id="run-1")
            r1 = read_findings(db_file, filepath="app.py", run_id="run-1")
            lineage_root = r1[0]["lineage_id"]
            self.assertTrue(lineage_root)

            # 2. Second run: "SQL Injection in get_user" (no backticks), line 9
            f2 = {
                "title": "SQL Injection in get_user",
                "severity": "HIGH",
                "description": "User input passed to database query in get_user()",
                "line_numbers": [9],
            }
            write_findings(db_file, "app.py", [f2], run_id="run-2")
            r2 = read_findings(db_file, filepath="app.py", run_id="run-2")
            self.assertEqual(r2[0]["lineage_id"], lineage_root)

            # 3. Third run: "SQL Injection in get_user", line 11 (two lines added above it)
            f3 = {
                "title": "SQL Injection in get_user",
                "severity": "HIGH",
                "description": "User input passed to database query in get_user()",
                "line_numbers": [11],
            }
            write_findings(db_file, "app.py", [f3], run_id="run-3")
            r3 = read_findings(db_file, filepath="app.py", run_id="run-3")
            self.assertEqual(r3[0]["lineage_id"], lineage_root)

            # 4. Fourth run: LLM rephrases: "SQL Injection via Unsanitized Query Parameter" (in get_user)
            f4 = {
                "title": "SQL Injection via Unsanitized Query Parameter",
                "severity": "CRITICAL",
                "description": "Unsanitized parameter in function get_user allows SQL injection",
                "line_numbers": [11],
            }
            write_findings(db_file, "app.py", [f4], run_id="run-4")
            r4 = read_findings(db_file, filepath="app.py", run_id="run-4")
            self.assertEqual(r4[0]["lineage_id"], lineage_root)

            # 5. Fifth run: LLM rephrases: "SQL Injection via Unsanitized User Input" (in get_user)
            f5 = {
                "title": "SQL Injection via Unsanitized User Input",
                "severity": "HIGH",
                "description": "User input passed directly into query string in get_user()",
                "line_numbers": [15],
            }
            write_findings(db_file, "app.py", [f5], run_id="run-5")
            r5 = read_findings(db_file, filepath="app.py", run_id="run-5")
            self.assertEqual(r5[0]["lineage_id"], lineage_root)

            # Query lineage history -> exactly 5 occurrences under the same lineage!
            history = query_historical_lineage(db_file, lineage_id=lineage_root)
            self.assertEqual(len(history), 5)

            # 6. NEGATIVE CONTROL: Distinct function in same file must NOT share lineage!
            f_distinct = {
                "title": "SQL Injection in list_orders",
                "severity": "HIGH",
                "description": "User input passed to database query in list_orders()",
                "line_numbers": [42],
                "cwe": "CWE-89",
            }
            write_findings(db_file, "app.py", [f_distinct], run_id="run-6")
            r6 = read_findings(db_file, filepath="app.py", run_id="run-6")
            distinct_lineage = r6[0]["lineage_id"]
            self.assertNotEqual(distinct_lineage, lineage_root)

            # Assert 2 distinct lineages on app.py
            all_rows = read_findings(db_file, filepath="app.py")
            unique_lineages = set(r["lineage_id"] for r in all_rows)
            self.assertEqual(len(unique_lineages), 2)
        finally:
            shutil.rmtree(temp_dir)

    def test_synthetic_dataset_lineage_resolution_benchmark(self):
        """Tests that synthetic dataset negative controls have 0 false merges in lineage resolution."""
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_eval_lineage.db")
        try:
            init_db(db_file)
            dataset_path = os.path.join(os.path.dirname(__file__), "evals", "synthetic_dataset.json")
            with open(dataset_path, "r", encoding="utf-8") as f:
                syn = json.load(f)

            id_to_finding = {f["id"]: f for f in syn["findings"]}

            # Write findings in separate passes simulating successive discoveries
            for f in syn["findings"]:
                write_findings(db_file, f.get("filepath", ""), [f], run_id=f"run-{f['id']}")

            # Verify negative controls have 0 false merges
            for cname, cinfo in syn["ground_truth_clusters"].items():
                fids = cinfo["finding_ids"]
                relation = cinfo.get("relation", "DUPLICATE")
                if relation == "DISTINCT":
                    # Distinct findings must NEVER share a lineage_id
                    lineages = []
                    for fid in fids:
                        fobj = id_to_finding[fid]
                        rows = read_findings(db_file, filepath=fobj["filepath"], run_id=f"run-{fid}")
                        self.assertEqual(len(rows), 1)
                        lineages.append(rows[0]["lineage_id"])
                    self.assertEqual(
                        len(set(lineages)),
                        len(fids),
                        f"Safety violation: Negative control cluster '{cname}' had false merge: {lineages}",
                    )
        finally:
            shutil.rmtree(temp_dir)

    def test_filepath_directory_isolation_and_advisory_scoping(self):
        """Tests that api/app.py and admin/app.py maintain strict directory isolation in lineage and advisory."""
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_path_isolation.db")
        try:
            init_db(db_file)

            # 1. Finding in api/app.py
            f_api = {
                "title": "SQL Injection in get_user",
                "severity": "HIGH",
                "description": "User input passed to database query in get_user()",
                "line_numbers": [10],
                "cwe": "CWE-89",
            }
            write_findings(db_file, "api/app.py", [f_api], run_id="run-api")

            # 2. Same-named function and vulnerability in admin/app.py
            f_admin = {
                "title": "SQL Injection in get_user",
                "severity": "CRITICAL",
                "description": "Admin query string concatenation in get_user()",
                "line_numbers": [10],
                "cwe": "CWE-89",
            }
            write_findings(db_file, "admin/app.py", [f_admin], run_id="run-admin")

            # 3. Same file in a subsequent pass reported with absolute path /repo/api/app.py under target /repo
            f_api_abs = {
                "title": "SQL Injection in get_user",
                "severity": "HIGH",
                "description": "User input passed to database query in get_user()",
                "line_numbers": [10],
                "cwe": "CWE-89",
                "filepath": "/repo/api/app.py",
            }
            write_findings(db_file, "/repo", [f_api_abs], run_id="run-api-abs")

            # Assert absolute /repo/api/app.py inherits lineage from api/app.py
            r_api_abs = read_findings(db_file, filepath="api/app.py", run_id="run-api-abs")
            self.assertEqual(len(r_api_abs), 1)
            self.assertEqual(r_api_abs[0]["filepath"], "api/app.py")

            # Assert 2 distinct lineages overall (api/app.py unified, admin/app.py isolated)
            r_api = read_findings(db_file, filepath="api/app.py", run_id="run-api")
            r_admin = read_findings(db_file, filepath="admin/app.py", run_id="run-admin")
            self.assertEqual(len(r_api), 1)
            self.assertEqual(len(r_admin), 1)
            self.assertEqual(r_api_abs[0]["lineage_id"], r_api[0]["lineage_id"])
            self.assertNotEqual(r_api[0]["lineage_id"], r_admin[0]["lineage_id"])
            self.assertNotEqual(r_api[0]["signature"], r_admin[0]["signature"])

            # Assert advisory scoping is strictly isolated
            guidance_api = query_security_guidance(db_file, filepath="api/app.py")
            self.assertEqual(len(guidance_api["confirmed_vulnerabilities"]), 2)
            self.assertEqual(guidance_api["confirmed_vulnerabilities"][0]["filepath"], "api/app.py")

            guidance_admin = query_security_guidance(db_file, filepath="admin/app.py")
            self.assertEqual(len(guidance_admin["confirmed_vulnerabilities"]), 1)
            self.assertEqual(guidance_admin["confirmed_vulnerabilities"][0]["filepath"], "admin/app.py")
        finally:
            shutil.rmtree(temp_dir)

    def test_normalize_cwe_variations(self):
        """Tests that normalize_cwe canonicalizes diverse CWE inputs and handles invalid/unknown values safely."""
        self.assertEqual(normalize_cwe("CWE-89"), "CWE-89")
        self.assertEqual(normalize_cwe("cwe-89"), "CWE-89")
        self.assertEqual(normalize_cwe("cwe_89"), "CWE-89")
        self.assertEqual(normalize_cwe("cwe 89"), "CWE-89")
        self.assertEqual(normalize_cwe("89"), "CWE-89")
        self.assertEqual(normalize_cwe(89), "CWE-89")
        self.assertEqual(normalize_cwe("CWE-0089"), "CWE-89")
        self.assertEqual(normalize_cwe("CWE-79: Reflected XSS"), "CWE-79")
        self.assertIsNone(normalize_cwe(None))
        self.assertIsNone(normalize_cwe(""))
        self.assertIsNone(normalize_cwe("CWE-UNKNOWN"))
        self.assertIsNone(normalize_cwe("unknown"))
        self.assertIsNone(normalize_cwe("NONE"))
        self.assertIsNone(normalize_cwe("NULL"))
        self.assertIsNone(normalize_cwe("UNDEFINED"))
        self.assertIsNone(normalize_cwe("N/A"))

    def test_extract_target_symbol_resilience(self):
        """Tests that extract_target_symbol cleanly differentiates target symbols from file paths and handles varied formats."""
        # 1. code_paths with filepath and line number does NOT extract the filepath as a symbol
        sym = extract_target_symbol(
            title="Missing rate limit on login endpoint",
            description="Unchecked login attempts",
            code_paths=["api/login.py:50"],
        )
        self.assertNotIn("api/login.py", sym)
        self.assertNotIn(".py", sym)

        # 2. code_paths with file:line:symbol extracts the symbol segment
        sym_part = extract_target_symbol(
            title="Authentication bypass",
            description="Token check omitted",
            code_paths=["auth/service.py:100:authenticate_jwt"],
        )
        self.assertEqual(sym_part, "authenticate_jwt")

        # 3. code_paths with dict item extracts symbol/function
        sym_dict = extract_target_symbol(
            title="SQL Injection",
            description="Raw query",
            code_paths=[{"symbol": "fetch_user_records", "file": "db.py"}],
        )
        self.assertEqual(sym_dict, "fetch_user_records")

        # 4. Backticks with a filepath (e.g. `src/auth.py`) is skipped, backticks with function name is preserved
        sym_fn = extract_target_symbol(title="Buffer overflow in `parse_header`")
        self.assertEqual(sym_fn, "parse_header")
        sym_fp = extract_target_symbol(title="Vulnerability in `src/parser.c`", description="Flaw in function parse_tokens")
        self.assertEqual(sym_fp, "parse_tokens")

    def test_deterministic_lineage_resolution_positive_controls(self):
        """Tests that semantically equivalent findings merge into the same lineage via deterministic anchors."""
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_pos_controls.db")
        try:
            init_db(db_file)

            # Positive Control 1: SQL Injection phrasing variations in services/user/routes.py (same file, CWE, symbol)
            f1_pos = {
                "title": "SQL Injection in get_user",
                "severity": "HIGH",
                "filepath": "services/user/routes.py",
                "description": "User input passed to database query in get_user() without parameterization",
                "line_numbers": [42],
                "cwe": "CWE-89",
            }
            f2_pos = {
                "title": "SQL Injection via Unsanitized Query Parameter",
                "severity": "CRITICAL",
                "filepath": "services/user/routes.py",
                "description": "Unsanitized parameter in function get_user allows SQL injection into raw database query string",
                "line_numbers": [45],
                "cwe": "CWE-89",
            }

            write_findings(db_file, f1_pos["filepath"], [f1_pos], run_id="run-pos-1")
            write_findings(db_file, f2_pos["filepath"], [f2_pos], run_id="run-pos-2")

            r1 = read_findings(db_file, filepath="services/user/routes.py", run_id="run-pos-1")
            r2 = read_findings(db_file, filepath="services/user/routes.py", run_id="run-pos-2")
            self.assertEqual(len(r1), 1)
            self.assertEqual(len(r2), 1)
            self.assertEqual(r1[0]["lineage_id"], r2[0]["lineage_id"])
            self.assertIsNone(r1[0]["embedding"])
            self.assertIsNone(r2[0]["embedding"])

            # Positive Control 2: Deserialization in services/cart/session.py with hydrate_session
            f1_deser = {
                "title": "Insecure Deserialization in hydrate_session",
                "severity": "CRITICAL",
                "filepath": "services/cart/session.py",
                "description": "Unconstrained pickle deserialization in hydrate_session leads to remote code execution",
                "line_numbers": [88],
                "cwe": "CWE-502",
            }
            f2_deser = {
                "title": "Untrusted Object Deserialization in hydrate_session handler",
                "severity": "CRITICAL",
                "filepath": "services/cart/session.py",
                "description": "Arbitrary code execution via untrusted serialized payload passed to hydrate_session",
                "line_numbers": [92],
                "cwe": "CWE-502",
            }
            write_findings(db_file, f1_deser["filepath"], [f1_deser], run_id="run-deser-1")
            write_findings(db_file, f2_deser["filepath"], [f2_deser], run_id="run-deser-2")

            rd1 = read_findings(db_file, filepath="services/cart/session.py", run_id="run-deser-1")
            rd2 = read_findings(db_file, filepath="services/cart/session.py", run_id="run-deser-2")
            self.assertEqual(rd1[0]["lineage_id"], rd2[0]["lineage_id"])
        finally:
            shutil.rmtree(temp_dir)

    def test_deterministic_lineage_resolution_negative_controls(self):
        """Tests that distinct vulnerability classes fail closed and never false-merge."""
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_neg_controls.db")
        try:
            init_db(db_file)

            # Negative Control 1: SQL Injection vs Command Injection in the same file
            f_sqli = {
                "title": "SQL Injection in get_user",
                "severity": "HIGH",
                "filepath": "services/user/routes.py",
                "description": "User input passed to database query in get_user()",
                "line_numbers": [20],
                "cwe": "CWE-89",
            }
            f_cmdi = {
                "title": "Command Injection in execute_backup",
                "severity": "CRITICAL",
                "filepath": "services/user/routes.py",
                "description": "Unescaped shell argument passed to os.system in execute_backup()",
                "line_numbers": [95],
                "cwe": "CWE-78",
            }
            write_findings(db_file, f_sqli["filepath"], [f_sqli], run_id="run-neg-1")
            write_findings(db_file, f_cmdi["filepath"], [f_cmdi], run_id="run-neg-2")

            r_sqli = read_findings(db_file, filepath="services/user/routes.py", run_id="run-neg-1")
            r_cmdi = read_findings(db_file, filepath="services/user/routes.py", run_id="run-neg-2")
            self.assertNotEqual(r_sqli[0]["lineage_id"], r_cmdi[0]["lineage_id"])

            # Negative Control 2: Stored XSS vs Reflected XSS in same file
            dataset_path = os.path.join(os.path.dirname(__file__), "evals", "synthetic_dataset.json")
            if os.path.exists(dataset_path):
                with open(dataset_path, "r", encoding="utf-8") as f:
                    syn = json.load(f)
                id_to_finding = {f["id"]: f for f in syn["findings"]}
                f301 = id_to_finding[301]
                f302 = id_to_finding[302]
                write_findings(db_file, f301["filepath"], [f301], run_id="run-xss-1")
                write_findings(db_file, f302["filepath"], [f302], run_id="run-xss-2")
                rx1 = read_findings(db_file, filepath=f301["filepath"], run_id="run-xss-1")
                rx2 = read_findings(db_file, filepath=f302["filepath"], run_id="run-xss-2")
                self.assertNotEqual(rx1[0]["lineage_id"], rx2[0]["lineage_id"])

                # Negative Control 3: Timing side-channel vs Token expiration in auth/token.py
                f401 = id_to_finding[401]
                f402 = id_to_finding[402]
                write_findings(db_file, f401["filepath"], [f401], run_id="run-auth-1")
                write_findings(db_file, f402["filepath"], [f402], run_id="run-auth-2")
                ra1 = read_findings(db_file, filepath=f401["filepath"], run_id="run-auth-1")
                ra2 = read_findings(db_file, filepath=f402["filepath"], run_id="run-auth-2")
                self.assertNotEqual(ra1[0]["lineage_id"], ra2[0]["lineage_id"])
        finally:
            shutil.rmtree(temp_dir)

    def test_line_proximity_and_signature_anchors(self):
        """Tests exact signature and strict line proximity matching for lineage inheritance."""
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_anchors.db")
        try:
            init_db(db_file)
            f_base = {
                "title": "Flaw",
                "severity": "CRITICAL",
                "filepath": "parser.c",
                "description": "Flaw at line 100",
                "line_numbers": [100],
                "cwe": "CWE-120",
                "signature": "sig_exact_anchor_123",
            }
            write_findings(db_file, "parser.c", [f_base], run_id="run-base")
            r_base = read_findings(db_file, filepath="parser.c", run_id="run-base")
            base_lid = r_base[0]["lineage_id"]

            with _db(db_file) as conn:
                cur = conn.cursor()

                # 1. Exact signature match inherits lineage_id
                sig_lid = resolve_ancestor_lineage(
                    cur,
                    filepath="parser.c",
                    signature="sig_exact_anchor_123",
                    cwe="CWE-120",
                    title="Different Title",
                )
                self.assertEqual(sig_lid, base_lid)

                # 2. Line proximity match within <= 3 lines when symbol is empty
                prox_lid = resolve_ancestor_lineage(
                    cur,
                    filepath="parser.c",
                    signature="new_sig",
                    cwe="CWE-120",
                    symbol="",
                    title="Flaw",
                    line_numbers="[102]",
                )
                self.assertEqual(prox_lid, base_lid)

                # 3. Line proximity beyond > 3 lines fails closed to fresh lineage_id
                far_lid = resolve_ancestor_lineage(
                    cur,
                    filepath="parser.c",
                    signature="new_sig_far",
                    cwe="CWE-120",
                    symbol="",
                    title="Flaw",
                    line_numbers="[150]",
                )
                self.assertNotEqual(far_lid, base_lid)
        finally:
            shutil.rmtree(temp_dir)

    def test_cwe_structural_guard_prevents_false_merge_deterministic(self):
        """Tests that distinct CWE classifications prevent false merges in deterministic lineage resolution."""
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_cwe_guard.db")
        try:
            init_db(db_file)
            f_sqli = {
                "title": "SQL Injection in get_user",
                "severity": "CRITICAL",
                "description": "Raw string concatenation in SQL query",
                "cwe": "CWE-89",
            }
            write_findings(db_file, "app.py", [f_sqli], run_id="run-1")
            findings = read_findings(db_file, filepath="app.py", run_id="run-1")
            sqli_lid = findings[0]["lineage_id"]
            self.assertTrue(sqli_lid)

            with _db(db_file) as conn:
                cur = conn.cursor()
                # Query with distinct Command Injection CWE-78 mints a new lineage ID
                new_lid = resolve_ancestor_lineage(
                    cur,
                    filepath="app.py",
                    signature="diff_sig_cmdi",
                    cwe="CWE-78",
                    symbol="exec_cmd",
                    title="Command Injection in exec_cmd",
                    description="Unsanitized command execution",
                )
                self.assertNotEqual(new_lid, sqli_lid)

                # Query with matching file, CWE-89, and symbol inherits lineage ID
                matching_lid = resolve_ancestor_lineage(
                    cur,
                    filepath="app.py",
                    signature="diff_sig_sql_variant",
                    cwe="cwe-89",
                    symbol="get_user",
                    title="SQL Injection variant in get_user",
                )
                self.assertEqual(matching_lid, sqli_lid)
        finally:
            shutil.rmtree(temp_dir)

    def test_query_security_guidance_aggregation(self):
        """Tests that query_security_guidance and get_security_guidance aggregate full advisory context."""
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_guidance.db")
        try:
            init_db(db_file)

            # 1. Threat Model
            record_artifact(
                db_file,
                run_id="run-test",
                artifact_type="threat_model",
                filepath="workspace/kb/THREAT_MODEL.md",
                content="### Trust Boundaries\n- Zone 1: Public Internet\n- Zone 2: Vault Worker Backend",
            )

            # 2. Confirmed Vulnerability with verified patch
            confirmed_f = {
                "title": "OS Command Injection in /backup",
                "severity": "CRITICAL",
                "description": "Unsanitized user parameter passed to os.system",
                "cwe": "CWE-78",
                "remediation": "Use subprocess.run(['tar', ...]) without shell=True",
                "status": "dynamic_confirmed",
                "reattack_status": "failed_to_bypass",
                "patch_status": "VERIFIED_SECURE",
                "patch_diff": "--- a/app.py\n+++ b/app.py\n@@ -10 +10 @@\n-os.system(cmd)\n+subprocess.run(['tar', target])",
            }
            write_findings(db_file, "app.py", [confirmed_f], run_id="run-test")

            # 3. Triaged False Positive
            fp_f = {
                "title": "Potential SSRF in /metrics",
                "severity": "LOW",
                "description": "Hardcoded metrics fetch endpoint",
                "cwe": "CWE-918",
                "reasoning": "Endpoint is fixed to loopback 127.0.0.1:9090 and cannot be manipulated by users",
                "status": "false_positive",
            }
            write_findings(db_file, "app.py", [fp_f], run_id="run-test")

            # 4. Learning Invariant
            record_learning(
                db_file,
                run_id="run-test",
                category="SANDBOX_ISOLATION",
                learning="All sandbox file operations must validate containment within jail_dir",
                tags=["jail", "security"],
            )

            # Query guidance
            guidance = query_security_guidance(db_file, filepath="app.py", run_id="run-test")
            self.assertEqual(guidance["filepath"], "app.py")
            self.assertIn("Vault Worker Backend", guidance["threat_model"])
            self.assertEqual(len(guidance["confirmed_vulnerabilities"]), 1)
            self.assertEqual(len(guidance["false_positives"]), 1)
            self.assertEqual(len(guidance["learned_invariants"]), 1)

            # Test tool invocation
            ctx = RunContext(jail_dir=temp_dir, db_path=db_file, target_file="app.py", run_id="run-test")
            tok = current_run_context.set(ctx)
            try:
                summary = get_security_guidance("app.py")
                self.assertIn("# Security Advisory & Development Guidance for: app.py", summary)
                self.assertIn("Zone 2: Vault Worker Backend", summary)
                self.assertIn("OS Command Injection in /backup", summary)
                self.assertIn("Verified Patch Diff", summary)
                self.assertIn("Potential SSRF in /metrics", summary)
                self.assertIn("SANDBOX_ISOLATION", summary)
            finally:
                current_run_context.reset(tok)

            # Test CLI script execution
            import subprocess
            import sys
            cli_script = os.path.join(os.path.dirname(__file__), "scripts", "advise.py")
            cli_res = subprocess.run(
                [sys.executable, cli_script, "--file=app.py", f"--db={db_file}"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("# Security Advisory & Development Guidance for: app.py", cli_res.stdout)
            self.assertIn("OS Command Injection in /backup", cli_res.stdout)

            cli_json = subprocess.run(
                [sys.executable, cli_script, "--file=app.py", f"--db={db_file}", "--json"],
                capture_output=True,
                text=True,
                check=True,
            )
            parsed_json = json.loads(cli_json.stdout)
            self.assertEqual(parsed_json["filepath"], "app.py")
            self.assertEqual(len(parsed_json["confirmed_vulnerabilities"]), 1)
        finally:
            shutil.rmtree(temp_dir)

    def test_get_llm_kwargs_resolution_and_precedence(self):
        """Tests LLM resolution precedence for model_id and api_base across all tiers."""
        # 1. Defaults
        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "proj-1", "VERTEXAI_LOCATION": "loc-1"}, clear=True):
            mid, kwargs = get_llm_kwargs()
            self.assertEqual(mid, DEFAULT_MODEL)
            self.assertEqual(kwargs["model"], DEFAULT_MODEL)
            self.assertEqual(kwargs["vertex_project"], "proj-1")
            self.assertEqual(kwargs["vertex_location"], "loc-1")
            self.assertNotIn("api_base", kwargs)

        # 1b. Default location falls back to global
        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "proj-1"}, clear=True):
            mid, kwargs = get_llm_kwargs()
            self.assertEqual(kwargs["vertex_location"], "global")

        # 2. MODEL_ID environment variable
        with patch.dict(os.environ, {"MODEL_ID": "openai/gpt-4o", "VERTEXAI_PROJECT": "proj-1"}, clear=True):
            mid, kwargs = get_llm_kwargs()
            self.assertEqual(mid, "openai/gpt-4o")
            self.assertEqual(kwargs["model"], "openai/gpt-4o")
            self.assertNotIn("api_base", kwargs)

        # 3. Explicit node model_id overrides MODEL_ID env and default
        with patch.dict(os.environ, {"MODEL_ID": "openai/gpt-4o"}, clear=True):
            mid, kwargs = get_llm_kwargs(model_id="ollama/llama3", default_model="fallback-model")
            self.assertEqual(mid, "ollama/llama3")
            self.assertEqual(kwargs["model"], "ollama/llama3")

        # 4. LLM_API_BASE environment variable
        with patch.dict(os.environ, {"LLM_API_BASE": "http://env-api-base:8000"}, clear=True):
            mid, kwargs = get_llm_kwargs(model_id="ollama/llama3")
            self.assertEqual(kwargs["api_base"], "http://env-api-base:8000")

        # 5. default_api_base is used when LLM_API_BASE is unset
        with patch.dict(os.environ, {}, clear=True):
            mid, kwargs = get_llm_kwargs(model_id="ollama/llama3", default_api_base="http://config-api-base:7000")
            self.assertEqual(kwargs["api_base"], "http://config-api-base:7000")

        # 6. LLM_API_BASE env overrides default_api_base (config)
        with patch.dict(os.environ, {"LLM_API_BASE": "http://env-api-base:8000"}, clear=True):
            mid, kwargs = get_llm_kwargs(model_id="ollama/llama3", default_api_base="http://config-api-base:7000")
            self.assertEqual(kwargs["api_base"], "http://env-api-base:8000")

        # 7. Explicit api_base parameter (node override) overrides LLM_API_BASE env AND default_api_base
        with patch.dict(os.environ, {"LLM_API_BASE": "http://env-api-base:8000"}, clear=True):
            mid, kwargs = get_llm_kwargs(
                model_id="ollama/llama3",
                api_base="http://param-api-base:9000",
                default_api_base="http://config-api-base:7000"
            )
            self.assertEqual(kwargs["api_base"], "http://param-api-base:9000")

        # 8. LLM_TIMEOUT environment variable
        with patch.dict(os.environ, {"LLM_TIMEOUT": "300"}, clear=True):
            mid, kwargs = get_llm_kwargs(model_id="ollama/llama3")
            self.assertEqual(kwargs["timeout"], 300.0)

        # 9. LLM_REQUEST_TIMEOUT environment variable fallback
        with patch.dict(os.environ, {"LLM_REQUEST_TIMEOUT": "450.5"}, clear=True):
            mid, kwargs = get_llm_kwargs(model_id="ollama/llama3")
            self.assertEqual(kwargs["timeout"], 450.5)

        # 10. default_timeout is used when LLM_TIMEOUT is unset
        with patch.dict(os.environ, {}, clear=True):
            mid, kwargs = get_llm_kwargs(model_id="ollama/llama3", default_timeout=600.0)
            self.assertEqual(kwargs["timeout"], 600.0)

        # 11. LLM_TIMEOUT env overrides default_timeout
        with patch.dict(os.environ, {"LLM_TIMEOUT": "180"}, clear=True):
            mid, kwargs = get_llm_kwargs(model_id="ollama/llama3", default_timeout=600.0)
            self.assertEqual(kwargs["timeout"], 180.0)

        # 12. Explicit timeout parameter (node override) overrides LLM_TIMEOUT env AND default_timeout
        with patch.dict(os.environ, {"LLM_TIMEOUT": "180"}, clear=True):
            mid, kwargs = get_llm_kwargs(model_id="ollama/llama3", timeout=90.0, default_timeout=600.0)
            self.assertEqual(kwargs["timeout"], 90.0)

        # 13. Non-vertex model does not require VERTEXAI_PROJECT
        with patch.dict(os.environ, {}, clear=True):
            mid, kwargs = get_llm_kwargs(model_id="ollama/llama3")
            self.assertEqual(mid, "ollama/llama3")
            self.assertNotIn("vertex_project", kwargs)

    def test_per_node_model_and_api_base_in_workflow(self):
        """Validates that GlobalConfig parses api_base and AgentNode supports per-node model and api_base overrides."""
        temp_dir = tempfile.mkdtemp()
        try:
            prompts_dir = os.path.join(temp_dir, "prompts")
            os.makedirs(prompts_dir, exist_ok=True)
            prompt_file = os.path.join(prompts_dir, "researcher.md")
            with open(prompt_file, "w") as f:
                f.write("Evaluate input")

            workflow_def = {
                "name": "custom_workflow",
                "config": {
                    "api_base": "http://custom-proxy.internal:8080",
                    "default_model": "vertex_ai/gemini-3.6-flash",
                    "timeout": 600.0
                },
                "nodes": [
                    {
                        "id": "agent_override",
                        "type": "agent",
                        "model": "ollama/deepseek-r1",
                        "api_base": "http://node-custom.internal:11434",
                        "timeout": 120.0,
                        "system_prompt": "prompts/researcher.md"
                    },
                    {
                        "id": "agent_default",
                        "type": "agent",
                        "system_prompt": "prompts/researcher.md"
                    },
                    {
                        "id": "agent_model_only",
                        "type": "agent",
                        "model": "openai/gpt-4o",
                        "system_prompt": "prompts/researcher.md"
                    }
                ],
                "edges": [
                    {"from": "START", "to": "agent_override"},
                    {"from": "agent_override", "to": "agent_default"},
                    {"from": "agent_default", "to": "agent_model_only"}
                ]
            }
            wf_path = os.path.join(temp_dir, "workflow.json")
            with open(wf_path, "w") as f:
                json.dump(workflow_def, f)

            captured_agent_calls = []

            def fake_agent(name, model, instruction, tools, *args, **kwargs):
                captured_agent_calls.append({"name": name, "model": model})
                mock_a = MagicMock()
                mock_a.name = name
                return mock_a

            with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
                with patch("google.adk.Agent", side_effect=fake_agent):
                    wf, cfg = load_workflow_from_json(wf_path)

            self.assertEqual(cfg.get("api_base"), "http://custom-proxy.internal:8080")
            self.assertEqual(len(captured_agent_calls), 3)

            # Node 1: per-node model, api_base, and timeout overrides
            self.assertEqual(captured_agent_calls[0]["name"], "agent_override")
            self.assertEqual(captured_agent_calls[0]["model"].model, "ollama/deepseek-r1")
            self.assertEqual(captured_agent_calls[0]["model"]._additional_args["api_base"], "http://node-custom.internal:11434")
            self.assertEqual(captured_agent_calls[0]["model"]._additional_args["timeout"], 120.0)

            # Node 2: inherits global default_model, global api_base, and global timeout
            self.assertEqual(captured_agent_calls[1]["name"], "agent_default")
            self.assertEqual(captured_agent_calls[1]["model"].model, "vertex_ai/gemini-3.6-flash")
            self.assertEqual(captured_agent_calls[1]["model"]._additional_args["api_base"], "http://custom-proxy.internal:8080")
            self.assertEqual(captured_agent_calls[1]["model"]._additional_args["timeout"], 600.0)

            # Node 3: per-node model override, inherits global api_base and global timeout
            self.assertEqual(captured_agent_calls[2]["name"], "agent_model_only")
            self.assertEqual(captured_agent_calls[2]["model"].model, "openai/gpt-4o")
            self.assertEqual(captured_agent_calls[2]["model"]._additional_args["api_base"], "http://custom-proxy.internal:8080")
            self.assertEqual(captured_agent_calls[2]["model"]._additional_args["timeout"], 600.0)
        finally:
            shutil.rmtree(temp_dir)

    def test_global_config_snapshot_and_sync_fields(self):
        """Ensures GlobalConfig parses snapshot, sync, and extra fields cleanly."""
        cfg = GlobalConfig(
            sync_upstream=True,
            pin_snapshot=False,
            pass_number=2,
            snapshot_keep=5,
            custom_extra_option="allowed",
        )
        self.assertTrue(cfg.sync_upstream)
        self.assertFalse(cfg.pin_snapshot)
        self.assertEqual(cfg.pass_number, 2)
        self.assertEqual(cfg.snapshot_keep, 5)
        self.assertEqual(getattr(cfg, "custom_extra_option", None), "allowed")

    def test_discover_files(self):
        """Verifies discover_files handles single files, git repos, hidden directories, db_path exclusion, and binary filtering."""
        temp_dir = tempfile.mkdtemp()
        try:
            p_dir = Path(temp_dir)
            f1 = p_dir / "app.py"
            f1.write_text("print(1)")
            
            # 1. Single file target
            self.assertEqual(discover_files(f1), [str(f1)])

            # 2. Unicode text file with non-ASCII characters (Japanese, Chinese, Emoji, Accents)
            f_unicode = p_dir / "unicode_app.py"
            f_unicode.write_text("# 日本語テスト 🚀 \n# 漏洞分析 \nprint('crème brûlée')", encoding="utf-8")
            self.assertFalse(is_binary_file(f_unicode))

            # 3. Binary file containing null bytes (.pyc, compiled object, image)
            f_binary = p_dir / "compiled.pyc"
            f_binary.write_bytes(b"\x61\x0d\x0d\x0a\x00\x00\x00\x00\x7fELF\x02\x01\x01\x00")
            self.assertTrue(is_binary_file(f_binary))

            # 4. Directory with hidden files and subdirectories
            hidden_dir = p_dir / ".venv" / "lib"
            hidden_dir.mkdir(parents=True)
            (hidden_dir / "secret.py").write_text("hidden")

            f2 = p_dir / "utils.py"
            f2.write_text("def helper(): pass")

            db_file = p_dir / "knowledge.db"
            db_file.write_bytes(b"SQLite format 3\x00")

            discovered = discover_files(p_dir, db_path=str(db_file))
            self.assertEqual(discovered, [str(f1), str(f_unicode), str(f2)])
            self.assertNotIn(str(f_binary), discovered)
            self.assertNotIn(str(hidden_dir / "secret.py"), discovered)
            self.assertNotIn(str(db_file), discovered)

            # 5. Subdirectory of a git repo with tracked dotfiles
            repo_dir = p_dir / "git_repo"
            repo_dir.mkdir()
            subprocess.run(["git", "init"], cwd=str(repo_dir), capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=str(repo_dir), check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo_dir), check=True)
            sub_dir = repo_dir / "packages" / "auth"
            sub_dir.mkdir(parents=True)
            (sub_dir / ".env.example").write_text("API_KEY=test")
            (sub_dir / "index.ts").write_text("export const x = 1;")
            subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo_dir), check=True)

            discovered_sub = discover_files(sub_dir)
            self.assertIn(str(sub_dir / ".env.example"), discovered_sub)
            self.assertIn(str(sub_dir / "index.ts"), discovered_sub)
        finally:
            shutil.rmtree(temp_dir)

    async def test_schemas_and_dynamic_confirmed_gating(self):
        """Tests ReviewVerdict and ReproVerdict schema validation and dynamic_confirmed gating in execute_sub_task."""
        from core.schemas import ReviewVerdict, ReproVerdict
        rv = ReviewVerdict(route="confirmed", reason="Exploitable vulnerability found.")
        self.assertEqual(rv.route, "confirmed")
        with self.assertRaises(Exception):
            ReviewVerdict(route="invalid_route", reason="bad")

        rp = ReproVerdict(route="success", reason="Exploit passed.")
        self.assertEqual(rp.route, "success")
        with self.assertRaises(Exception):
            ReproVerdict(route="invalid_route", reason="bad")

        # Test execute_sub_task dynamic_confirmed gating when sandbox_executed is False vs True
        workflow_path = os.path.join(os.path.dirname(__file__), "workflow.json")
        full_queue = [
            "History extracted.",
            "Structural index built.",
            "Architecture KB created.",
            "Threat model created.",
            "Plan created.",
            "Analysis done.",
            "Findings deduplicated.",
            json.dumps({"route": "confirmed", "reason": "Analysis done."}),
            json.dumps({"route": "viable", "reason": "Exploit viable."}),
            json.dumps({"route": "success", "reason": "Exploit verified."}),
            "Exploit chained.",
            "Patch applied",
            "Score: 90",
            "Learnings reflected.",
            "Report generated.",
        ]
        queue = list(full_queue)

        class ScriptedLlm(BaseLlm):
            async def generate_content_async(self, llm_request, stream: bool = False):
                text = queue.pop(0) if queue else "done"
                yield LlmResponse(content=types.Content(parts=[types.Part.from_text(text=text)]))

        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
            with patch("core.graph_loader.LiteLlm", lambda **_: ScriptedLlm(model="scripted")):
                wf, cfg = load_workflow_from_json(workflow_path)

        app = App(name=APP_NAME, root_agent=wf)
        ss = InMemorySessionService()
        runner = Runner(app=app, session_service=ss)

        temp_dir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(temp_dir, "test.db")
            init_db(db_path)
            target_file = "test_target.py"
            run_id = "run-gated"

            f = VulnerabilityFinding(
                title="SQL Injection", severity="Critical", description="raw query", line_numbers=[42], remediation="use ORM"
            )
            write_findings(db_path, target_file, [f], run_id=run_id)

            # 1. When sandbox_executed is False in RunContext, finding status is kept at static_confirmed
            ctx_gated = RunContext(jail_dir=temp_dir, db_path=db_path, target_file=target_file, run_id=run_id, sandbox_executed=False)
            tok = current_run_context.set(ctx_gated)
            try:
                err = await execute_sub_task(
                    runner=runner,
                    session_service=ss,
                    filepath=target_file,
                    run_id=run_id,
                    db_path=db_path,
                    status_map=cfg.get("on_enter_status", {}),
                )
                self.assertFalse(err)
                findings = read_findings(db_path, target_file, run_id=run_id)
                self.assertEqual(findings[0]["status"], "static_confirmed")
            finally:
                current_run_context.reset(tok)

            # 2. When sandbox_executed is True in RunContext, finding status is elevated to dynamic_confirmed
            queue = list(full_queue)
            run_id_dyn = "run-gated-dyn"
            write_findings(db_path, target_file, [f], run_id=run_id_dyn)
            ctx_dyn = RunContext(jail_dir=temp_dir, db_path=db_path, target_file=target_file, run_id=run_id_dyn, sandbox_executed=True)
            tok = current_run_context.set(ctx_dyn)
            try:
                err = await execute_sub_task(
                    runner=runner,
                    session_service=ss,
                    filepath=target_file,
                    run_id=run_id_dyn,
                    db_path=db_path,
                    status_map=cfg.get("on_enter_status", {}),
                )
                self.assertFalse(err)
                findings = read_findings(db_path, target_file, run_id=run_id_dyn)
                self.assertEqual(findings[0]["status"], "dynamic_confirmed")
            finally:
                current_run_context.reset(tok)

            # 3. When current_run_context is None (no context), finding status is NOT elevated to dynamic_confirmed
            queue = list(full_queue)
            run_id_noctx = "run-gated-noctx"
            write_findings(db_path, target_file, [f], run_id=run_id_noctx)
            err = await execute_sub_task(
                runner=runner,
                session_service=ss,
                filepath=target_file,
                run_id=run_id_noctx,
                db_path=db_path,
                status_map=cfg.get("on_enter_status", {}),
            )
            self.assertFalse(err)
            findings = read_findings(db_path, target_file, run_id=run_id_noctx)
            self.assertEqual(findings[0]["status"], "static_confirmed")
        finally:
            await runner.close()
            shutil.rmtree(temp_dir)

    def test_resilient_llm_safety_refusal_sanitization(self):
        """Tests that ResilientLiteLlm._sanitize_structured_response converts model refusals into valid schema verdicts."""
        from google.adk.models import LlmResponse
        from google.genai import types
        from core.config import ResilientLiteLlm
        from core.schemas import ReproVerdict, ReviewVerdict, CriticVerdict

        # 1. ReproVerdict refusal fallback
        r1 = LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text="Sorry, I cannot fulfill this request regarding command injection.")]))
        s1 = ResilientLiteLlm._sanitize_structured_response(r1, ReproVerdict)
        v1 = ReproVerdict.model_validate_json(s1.content.parts[0].text)
        self.assertEqual(v1.route, "failed_repro")
        self.assertIn("Sorry", v1.reason)

        # 2. ReviewVerdict refusal fallback
        r2 = LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text="I am unable to review this exploit pattern.")]))
        s2 = ResilientLiteLlm._sanitize_structured_response(r2, ReviewVerdict)
        v2 = ReviewVerdict.model_validate_json(s2.content.parts[0].text)
        self.assertEqual(v2.route, "confirmed")

        # 3. CriticVerdict refusal fallback
        r3 = LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text="I cannot assist with determining viability of attacks.")]))
        s3 = ResilientLiteLlm._sanitize_structured_response(r3, CriticVerdict)
        v3 = CriticVerdict.model_validate_json(s3.content.parts[0].text)
        self.assertEqual(v3.route, "non_viable")

        # 4. Valid JSON passes through untouched
        valid_json = json.dumps({"route": "success", "reason": "Empirically verified."})
        r4 = LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text=valid_json)]))
        s4 = ResilientLiteLlm._sanitize_structured_response(r4, ReproVerdict)
        self.assertEqual(s4.content.parts[0].text, valid_json)

        # 5. Tool call passes through untouched
        r5 = LlmResponse(content=types.Content(role="model", parts=[types.Part(function_call=types.FunctionCall(name="set_model_response", args={"route": "success", "reason": "done"}))]))
        s5 = ResilientLiteLlm._sanitize_structured_response(r5, ReproVerdict)
        self.assertIsNotNone(getattr(s5.content.parts[0], "function_call", None))

        # 6. FinishReason.SAFETY gets sanitized and converted to FinishReason.STOP
        r6 = LlmResponse(
            finish_reason=types.FinishReason.SAFETY,
            error_code="SAFETY",
            error_message="Finished with SAFETY",
            content=types.Content(role="model", parts=[types.Part.from_text(text="I cannot fulfill this request.")]),
        )
        s6 = ResilientLiteLlm._sanitize_structured_response(r6, ReproVerdict)
        v6 = ReproVerdict.model_validate_json(s6.content.parts[0].text)
        self.assertEqual(v6.route, "failed_repro")
        self.assertEqual(s6.finish_reason, types.FinishReason.STOP)
        self.assertIsNone(s6.error_code)

    async def test_domain_tools_and_database_persistence(self):
        """Tests all domain tools for planning, threat modeling, summarizing, chaining, learning, deduplication, and reporting."""
        from tools.research_tools import (
            record_plan,
            record_threat_model,
            record_summary,
            record_exploit_chain,
            record_learning,
            dedupe_findings,
            generate_report,
            write_file,
            score_risk,
        )
        from core.database import read_learnings, read_risk_scores

        temp_dir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(temp_dir, "test_domain.db")
            init_db(db_path)
            run_id = "test-domain-run"
            ctx = RunContext(jail_dir=temp_dir, db_path=db_path, target_file="app.py", run_id=run_id)
            tok = current_run_context.set(ctx)
            try:
                # 1. record_plan, verify no disk file created, read_file('workspace/plan.json'), get_plan()
                res_plan = record_plan({
                    "pass_number": 1,
                    "investigations": [
                        {"title": "Auth review", "target_files": ["auth.py"], "focus_areas": ["IDOR"]}
                    ],
                    "rationale": "Audit auth first."
                })
                self.assertIn("SUCCESS", res_plan)
                # Confirm no physical file was written to disk (DB-only storage)
                self.assertFalse(os.path.exists(os.path.join(temp_dir, "workspace", "plan.json")))
                read_plan_text = await read_file("workspace/plan.json")
                self.assertIn("Auth review", read_plan_text)
                self.assertIn("auth.py", get_plan())

                # Invalid plan schema raises clean error
                bad_plan = record_plan({"invalid_field": 123})
                self.assertIn("ERROR", bad_plan)

                # 2. record_threat_model, read_file('workspace/kb/THREAT_MODEL.md'), get_threat_model()
                res_tm = record_threat_model({
                    "threat_actors": ["Anonymous Remote Attacker"],
                    "trust_boundaries": ["HTTP Request Gateway"],
                    "entry_points": ["/api/v1/auth/login"],
                    "key_risks": ["Account takeover"]
                })
                self.assertIn("SUCCESS", res_tm)
                read_tm_text = await read_file("workspace/kb/THREAT_MODEL.md")
                self.assertIn("Anonymous Remote Attacker", read_tm_text)
                self.assertIn("HTTP Request Gateway", get_threat_model())

                # 3. record_summary, read_file('mantis-summary.md'), get_summary()
                res_sum = record_summary({
                    "overview": "Authentication service backend.",
                    "key_modules": ["auth", "models", "api"],
                    "tech_stack": ["Python", "FastAPI", "PostgreSQL"]
                })
                self.assertIn("SUCCESS", res_sum)
                read_sum_text = await read_file("mantis-summary.md")
                self.assertIn("Authentication service backend.", read_sum_text)
                self.assertIn("FastAPI", get_summary())

                # 4. record_exploit_chain, read_file('workspace/chains/...')
                res_chain = record_exploit_chain({
                    "chain_title": "auth-bypass-to-rce",
                    "finding_titles": ["IDOR in user profile", "Unsafe deserialization"],
                    "attack_path": "Abuse IDOR to gain admin session, then trigger pickle payload.",
                    "combined_impact": "Full Remote Code Execution as root."
                })
                self.assertIn("SUCCESS", res_chain)
                read_chain_text = await read_file("workspace/chains/auth-bypass-to-rce.json")
                self.assertIn("Full Remote Code Execution", read_chain_text)

                # 5. record_learning
                res_learn = record_learning({
                    "category": "false_positive_filter",
                    "learning": "Framework middleware validates CSRF token globally.",
                    "tags": ["csrf", "fastapi"]
                })
                self.assertIn("SUCCESS", res_learn)
                learnings = read_learnings(db_path, run_id=run_id)
                self.assertEqual(len(learnings), 1)
                self.assertEqual(learnings[0]["category"], "false_positive_filter")

                # 6. dedupe_findings
                f1 = VulnerabilityFinding(title="SQL Injection A", severity="High", description="raw query A", line_numbers=[10])
                f2 = VulnerabilityFinding(title="SQL Injection B", severity="High", description="raw query B", line_numbers=[12])
                write_findings(db_path, "app.py", [f1, f2], run_id=run_id)
                res_dedupe = dedupe_findings(
                    primary_title="SQL Injection A",
                    duplicate_titles=["SQL Injection B"],
                    reason="Identical vulnerability root cause."
                )
                self.assertIn("SUCCESS", res_dedupe)
                findings = read_findings(db_path, "app.py", run_id=run_id)
                self.assertEqual(len(findings), 2)
                f2_updated = [f for f in findings if f["title"] == "SQL Injection B"][0]
                self.assertEqual(f2_updated["status"], "duplicate_merged")
                f1_kept = [f for f in findings if f["title"] == "SQL Injection A"][0]
                self.assertNotEqual(f1_kept["status"], "duplicate_merged")

                # Test safe deduplication: deduplicating when primary_title is in duplicate_titles
                # must NOT mark primary finding as duplicate_merged
                res_dedupe_self = dedupe_findings(
                    primary_title="SQL Injection A",
                    duplicate_titles=["SQL Injection A"],
                    reason="Deduplicating against itself or rephrased titles."
                )
                findings_after_self = read_findings(db_path, "app.py", run_id=run_id)
                f1_still_kept = [f for f in findings_after_self if f["title"] == "SQL Injection A"][0]
                self.assertNotEqual(f1_still_kept["status"], "duplicate_merged")

                # Test in-place update in write_findings when matching exact key or passing ID
                f1_updated = VulnerabilityFinding(
                    title="SQL Injection A",
                    severity="Critical",
                    description="raw query A",
                    line_numbers=[10],
                )
                write_findings(db_path, "app.py", [f1_updated], run_id=run_id)
                findings_after_update = read_findings(db_path, "app.py", run_id=run_id)
                self.assertEqual(len(findings_after_update), 2)
                f1_updated_row = [f for f in findings_after_update if f["title"] == "SQL Injection A"][0]
                self.assertEqual(f1_updated_row["id"], f1_kept["id"])
                self.assertEqual(f1_updated_row["severity"], "CRITICAL")

                # Test in-place update by explicit ID with rephrased description
                f1_rephrased = {
                    "id": f1_kept["id"],
                    "title": "SQL Injection A",
                    "severity": "Critical",
                    "description": "rephrased description for raw query A",
                    "line_numbers": [10],
                }
                write_findings(db_path, "app.py", [f1_rephrased], run_id=run_id)
                findings_after_rephrase = read_findings(db_path, "app.py", run_id=run_id)
                self.assertEqual(len(findings_after_rephrase), 2)
                f1_rephrased_row = [f for f in findings_after_rephrase if f["title"] == "SQL Injection A"][0]
                self.assertEqual(f1_rephrased_row["id"], f1_kept["id"])
                self.assertEqual(f1_rephrased_row["description"], "rephrased description for raw query A")

                # Test deduplication by explicit IDs protecting primary_id
                res_dedupe_ids = dedupe_findings(
                    primary_title="SQL Injection A",
                    primary_id=f1_kept["id"],
                    duplicate_ids=[f1_kept["id"], f2_updated["id"]],
                    reason="Explicit ID merge test."
                )
                self.assertIn("SUCCESS", res_dedupe_ids)
                findings_after_ids = read_findings(db_path, "app.py", run_id=run_id)
                f1_after_ids = [f for f in findings_after_ids if f["id"] == f1_kept["id"]][0]
                self.assertNotEqual(f1_after_ids["status"], "duplicate_merged")

                # 7. generate_report
                res_rpt = generate_report({
                    "executive_summary": "Comprehensive security review identified 1 critical chain.",
                    "critical_findings_count": 1,
                    "recommendations": ["Fix IDOR check in auth.py", "Migrate from pickle to JSON"]
                })
                self.assertIn("SUCCESS", res_rpt)

                # 8. report_findings directly with canonical findings and alias keys
                from tools.research_tools import report_findings
                res_rf1 = report_findings({
                    "findings": [{
                        "filepath": "src/crypto.py",
                        "title": "Hardcoded Secret Key",
                        "severity": "high",
                        "description": "AES key hardcoded in source.",
                        "line_numbers": [88],
                        "mitigation": "Load from environment variables."
                    }]
                })
                self.assertIn("SUCCESS: Saved 1 finding", res_rf1)

                res_rf2 = report_findings({
                    "vulnerabilities": [{
                        "filepath": "src/api.py",
                        "title": "Missing Rate Limit",
                        "severity": "medium",
                        "description": "Unthrottled endpoint allows brute force.",
                        "remediation": "Apply TokenBucket rate limiter."
                    }]
                })
                self.assertIn("SUCCESS: Saved 1 finding", res_rf2)

                # 9. get_findings fail-closed and data paths (both run-wide fallback and explicit file filtering)
                res_get = get_findings()
                self.assertIn("SQL Injection A", res_get)
                self.assertIn("Hardcoded Secret Key", res_get)
                self.assertIn("Missing Rate Limit", res_get)

                # Explicitly filtered query for adjacent file
                res_get_crypto = get_findings("src/crypto.py")
                self.assertIn("Hardcoded Secret Key", res_get_crypto)
                self.assertNotIn("SQL Injection A", res_get_crypto)

                # 10. Dual-channel document unshadowing: write_file document vs record_* structured metadata
                rich_doc = "# Deep Threat Model\n\nFull 3.3KB architectural threat analysis with trust boundaries and STRIDE matrices."
                await write_file("workspace/kb/THREAT_MODEL.md", rich_doc)
                # read_file returns the rich document written by write_file, NOT the structured record_* JSON
                read_doc = await read_file("workspace/kb/THREAT_MODEL.md")
                self.assertEqual(read_doc, rich_doc)
                # get_threat_model still returns the structured harness metadata
                self.assertIn("Anonymous Remote Attacker", get_threat_model())

                # 11. Graph status stamping and canonical filepath joinability
                target_file = ctx.target_file
                f_prov = {
                    "filepath": "app.py",
                    "title": "SQLi in get_user",
                    "severity": "CRITICAL",
                    "description": "f-string SQL query",
                    "status": "PROVISIONALLY_VALID"  # LLM skill prose status
                }
                report_findings({"findings": [f_prov]})
                score_risk(9.0, "Critical SQL injection vulnerability")

                findings_rows = read_findings(db_path, filepath=target_file, run_id=run_id)
                scores_rows = read_risk_scores(db_path, filepath=target_file, run_id=run_id)
                # Graph status authority: initialized to 'reported'
                self.assertEqual(findings_rows[0]["status"], "reported")
                # Canonical filepaths match between findings and risk_scores (joinable)
                self.assertEqual(findings_rows[0]["filepath"], scores_rows[0]["filepath"])
                self.assertEqual(findings_rows[0]["filepath"], target_file)
                self.assertEqual(scores_rows[0]["score"], 9.0)

                # update_status updates findings correctly using canonical target_file
                update_status(db_path, target_file, run_id, "static_confirmed")
                updated_findings = read_findings(db_path, filepath=target_file, run_id=run_id)
                self.assertEqual(updated_findings[0]["status"], "static_confirmed")

                # 12. Per-finding calibration tool and schema persistence
                from tools.research_tools import calibrate_finding
                finding_id = updated_findings[0]["id"]
                res_cal = calibrate_finding(
                    finding_id=finding_id,
                    mantis_risk_score=6.4,
                    impact_score=5,
                    likelihood_score=3,
                    priority="HIGH",
                    reasoning="Unauthenticated RCE under static confirmation multiplier."
                )
                self.assertIn("SUCCESS: Calibrated finding", res_cal)
                calibrated_rows = read_findings(db_path, filepath=target_file, run_id=run_id)
                target_finding = [f for f in calibrated_rows if f["id"] == finding_id][0]
                self.assertEqual(target_finding["mantis_risk_score"], 6.4)
                self.assertEqual(target_finding["impact_score"], 5)
                self.assertEqual(target_finding["likelihood_score"], 3)
                self.assertEqual(target_finding["priority"], "HIGH")
            finally:
                current_run_context.reset(tok)
        finally:
            shutil.rmtree(temp_dir)

    def test_get_findings_error_and_no_data_paths(self):
        """Validates that get_findings returns explicit ERROR or NO_DATA on missing DB / zero records."""
        # 1. No context
        tok = current_run_context.set(None)
        try:
            self.assertIn("Error", get_findings())
        finally:
            current_run_context.reset(tok)

        # 2. Non-existent DB file
        ctx_missing = RunContext(jail_dir="/tmp", db_path="/tmp/non_existent_db_12345.db", target_file="app.py", run_id="r1")
        tok = current_run_context.set(ctx_missing)
        try:
            self.assertIn("ERROR: Database file not found", get_findings())
        finally:
            current_run_context.reset(tok)

        # 3. Valid DB with zero records
        temp_dir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(temp_dir, "empty.db")
            init_db(db_path)
            ctx_empty = RunContext(jail_dir=temp_dir, db_path=db_path, target_file="empty_file.py", run_id="r1")
            tok = current_run_context.set(ctx_empty)
            try:
                self.assertIn("NO_DATA: Zero findings recorded", get_findings())
            finally:
                current_run_context.reset(tok)
        finally:
            shutil.rmtree(temp_dir)

    async def test_empty_artifacts_and_cross_run_isolation(self):
        """Validates read_file empty string preservation, list_files run_id isolation, get_summary fallback, and sandbox scoping."""
        from tools.research_tools import list_files, read_file, write_file, get_summary
        from tools.sandbox_tools import run_sandbox
        from core.environments.static_env import StaticOnlyEnvironment

        temp_dir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(temp_dir, "test_iso.db")
            init_db(db_path)

            # 1. Legacy findings recorded with empty run_id
            write_findings(db_path, "legacy.py", [{
                "title": "Legacy Finding",
                "severity": "HIGH",
                "description": "Legacy vuln",
                "filepath": "legacy.py",
                "line_numbers": [1],
            }], run_id="")

            # 2. Fresh run context
            ctx_fresh = RunContext(
                jail_dir=temp_dir,
                db_path=db_path,
                target_file="target.py",
                run_id="run_fresh_123",
                sandbox=StaticOnlyEnvironment(target_path=temp_dir),
                active_node="architect",
            )
            tok = current_run_context.set(ctx_fresh)
            try:
                # list_files must NOT leak legacy findings into fresh run
                res_list = await list_files("workspace/findings")
                self.assertEqual(json.loads(res_list), [])

                # write_file with empty string must be readable as empty string (not NO_DATA)
                await write_file("workspace/historical_learnings.jsonl", "")
                read_hist = await read_file("workspace/historical_learnings.jsonl")
                self.assertEqual(read_hist, "")

                # workspace/learnings.jsonl when 0 rows must return empty string
                read_learn = await read_file("workspace/learnings.jsonl")
                self.assertEqual(read_learn, "")

                # get_summary falls back to workspace/kb/architecture.md when no summary recorded
                await write_file("workspace/kb/architecture.md", "# Service Architecture\n\nFastAPI backend.")
                sum_text = get_summary()
                self.assertIn("FastAPI backend", sum_text)

                # run_sandbox in non-reproducer node does NOT mention repro_status or failed_repro
                res_sb = await run_sandbox("which ctags")
                self.assertIn("SANDBOX-UNAVAILABLE", res_sb)
                self.assertNotIn("repro_status", res_sb)
                self.assertNotIn("failed_repro", res_sb)

                # in reproducer node, run_sandbox DOES provide repro guidance
                ctx_fresh.active_node = "reproducer"
                res_sb_repro = await run_sandbox("python3 exploit.py")
                self.assertIn("repro_status", res_sb_repro)
            finally:
                current_run_context.reset(tok)
        finally:
            shutil.rmtree(temp_dir)

    def test_schema_json_and_core_schemas_alignment(self):
        """Verifies that schema.json exists and core.schemas exports all expected models."""
        schema_path = Path(__file__).resolve().parent.parent / "schema.json"
        self.assertTrue(schema_path.exists(), f"schema.json must exist at {schema_path}")

        with open(schema_path, "r", encoding="utf-8") as f:
            schema_data = json.load(f)

        self.assertIn("$defs", schema_data)
        self.assertIn("finding", schema_data["$defs"])
        self.assertIn("plan", schema_data["$defs"])
        self.assertIn("learning_entry", schema_data["$defs"])

        import core.schemas as cs
        expected_classes = [
            "FindingSchema",
            "PlanSchema",
            "LearningEntrySchema",
            "HistoryEntrySchema",
            "TriageChecklistSchema",
            "CalibrationChecklistSchema",
            "StateSchema",
            "TxLogEntrySchema",
            "ExecutionLogEntrySchema",
            "InvestigationTargetSchema",
            "VulnerabilityReport",
            "ReviewVerdict",
            "CriticVerdict",
            "ReproVerdict",
            "ThreatModel",
            "CodebaseSummary",
            "ExploitChain",
            "ExecutiveReport",
        ]
        for cls_name in expected_classes:
            self.assertTrue(hasattr(cs, cls_name), f"Expected {cls_name} to be exported by core.schemas")

    def test_schema_model_round_trip_serialization(self):
        """Verifies serialization, deserialization, alias choices, and normalization across generated models."""
        from core.schemas import (
            FindingSchema,
            VulnerabilityFinding,
            LearningEntrySchema,
            LearningEntry,
            HistoryEntrySchema,
            StateSchema,
            ReviewPlan,
            TriageChecklistSchema,
            CalibrationChecklistSchema,
        )

        # 1. FindingSchema & VulnerabilityFinding alias round-trip
        finding_raw = {
            "id": "f-12345",
            "title": "SQL Injection in User Login",
            "description": "Direct parameter interpolation in SQL query.",
            "code_paths": ["src/db/auth.py:42"],
            "impact": "Account takeover",
            "severity": "low",  # Lowercase test for uppercase normalization
            "remediation": "Use parameterized queries.",  # Alias test for mitigation
            "filepath": "src/db/auth.py",
            "line_numbers": [42],
            "score": 85,
        }
        f_obj = FindingSchema.model_validate(finding_raw)
        self.assertEqual(f_obj.severity, "LOW")  # Verified normalization
        self.assertEqual(f_obj.remediation, "Use parameterized queries.")
        self.assertEqual(f_obj.mitigation, "Use parameterized queries.")

        dumped = f_obj.model_dump()
        f_obj_reloaded = VulnerabilityFinding.model_validate(dumped)
        self.assertEqual(f_obj_reloaded.id, "f-12345")
        self.assertEqual(f_obj_reloaded.severity, "LOW")

        # 2. HistoryEntrySchema alias round-trip ('pass' -> 'pass_num' / 'pass_number')
        hist_raw = {
            "stage": "researcher",
            "pass": 2,
            "action": "discovered",
            "details": "Found flaw",
            "timestamp": "2026-08-23T10:00:00Z",
        }
        hist_obj = HistoryEntrySchema.model_validate(hist_raw)
        self.assertEqual(hist_obj.pass_number, 2)
        self.assertEqual(hist_obj.stage, "researcher")

        # 3. LearningEntrySchema & LearningEntry alias round-trip ('learning' -> 'insight')
        learn_raw = {
            "type": "trajectory_insight",
            "action": "add",
            "target_entity": "auth.py",
            "learning": "Auth bypass flaw requires active session.",
            "category": "security_insight",
            "tags": ["auth", "idor"],
        }
        learn_obj = LearningEntry.model_validate(learn_raw)
        self.assertEqual(learn_obj.insight, "Auth bypass flaw requires active session.")
        self.assertEqual(learn_obj.learning, "Auth bypass flaw requires active session.")
        learn_dumped = learn_obj.model_dump()
        self.assertIn("Auth bypass", str(learn_dumped))

        # 4. StateSchema round-trip
        state_raw = {
            "pass": 1,
            "last_updated": "2026-08-23T10:00:00Z",
            "vcs_info": {"vcs_type": "git", "commit_hash": "abc1234", "branch": "main", "dirty": False},
        }
        state_obj = StateSchema.model_validate(state_raw)
        self.assertEqual(state_obj.pass_number, 1)


    def test_schema_json_definitions_registry(self):
        """Verifies that SCHEMA_DEFINITIONS maps canonical schema names to the generated classes."""
        from core.schemas import (
            SCHEMA_DEFINITIONS,
            FindingSchema,
            PlanSchema,
            LearningEntrySchema,
            StateSchema,
            TriageChecklistSchema,
            CalibrationChecklistSchema,
        )
        self.assertEqual(SCHEMA_DEFINITIONS.get("finding"), FindingSchema)
        self.assertEqual(SCHEMA_DEFINITIONS.get("plan"), PlanSchema)
        self.assertEqual(SCHEMA_DEFINITIONS.get("learning_entry"), LearningEntrySchema)
        self.assertEqual(SCHEMA_DEFINITIONS.get("state"), StateSchema)
        self.assertEqual(SCHEMA_DEFINITIONS.get("triage_checklist"), TriageChecklistSchema)
        self.assertEqual(SCHEMA_DEFINITIONS.get("calibration_checklist"), CalibrationChecklistSchema)

    async def test_execute_sub_task_tool_error_detection(self):
        """Verifies that tool-level error strings in function responses are captured by execute_sub_task."""
        mock_runner = MagicMock()
        mock_ss = AsyncMock()

        # Mock an event with a failing tool response
        mock_event_fail = MagicMock()
        mock_event_fail.error_code = None
        mock_event_fail.node_info.path = "root/researcher"
        mock_event_fail.actions.route = None

        mock_part_fn_call = MagicMock()
        mock_part_fn_call.text = None
        mock_part_fn_call.function_call = MagicMock(name="report_findings", args={"report": {}})
        mock_part_fn_call.function_response = None

        mock_part_fn_resp = MagicMock()
        mock_part_fn_resp.text = None
        mock_part_fn_resp.function_call = None
        mock_part_fn_resp.function_response = MagicMock(
            name="report_findings",
            response={"response": "ERROR SAVING DB: table findings is locked"}
        )

        mock_event_fail.content.parts = [mock_part_fn_call, mock_part_fn_resp]

        async def _run_async_gen(**_):
            yield mock_event_fail

        mock_runner.run_async = _run_async_gen

        # Should return True (indicating failure / error detected)
        task_failed = await execute_sub_task(
            runner=mock_runner,
            session_service=mock_ss,
            filepath="test_file.py",
            run_id="test-run",
        )
        self.assertTrue(task_failed)

        # Mock an event with a successful tool response
        mock_event_ok = MagicMock()
        mock_event_ok.error_code = None
        mock_event_ok.node_info.path = "root/researcher"
        mock_event_ok.actions.route = None

        mock_part_ok_resp = MagicMock()
        mock_part_ok_resp.text = None
        mock_part_ok_resp.function_call = None
        mock_part_ok_resp.function_response = MagicMock(
            name="report_findings",
            response={"response": "SUCCESS: Saved 1 finding(s) to database."}
        )
        mock_event_ok.content.parts = [mock_part_ok_resp]

        async def _run_async_ok(**_):
            yield mock_event_ok

        mock_runner.run_async = _run_async_ok

        # Should return False (indicating clean success)
        task_ok = await execute_sub_task(
            runner=mock_runner,
            session_service=mock_ss,
            filepath="test_file.py",
            run_id="test-run",
        )
        self.assertFalse(task_ok)

    def test_model_tiering_and_reasoning_effort_propagation(self):
        """Verifies that model tiering and adaptive reasoning effort levels propagate accurately."""
        from core.config import get_llm_kwargs
        from core.graph_loader import load_workflow_from_json

        # Test get_llm_kwargs directly with global and node overrides
        model_id, kwargs_default = get_llm_kwargs(
            model_id=None,
            default_model="vertex_ai/gemini-3.7-flash",
            default_reasoning_effort="medium",
        )
        self.assertEqual(model_id, "vertex_ai/gemini-3.7-flash")
        self.assertEqual(kwargs_default.get("reasoning_effort"), "medium")

        # Test node override
        model_id_node, kwargs_node = get_llm_kwargs(
            model_id="vertex_ai/gemini-3.5-flash-lite",
            default_model="vertex_ai/gemini-3.7-flash",
            reasoning_effort="low",
            default_reasoning_effort="medium",
        )
        self.assertEqual(model_id_node, "vertex_ai/gemini-3.5-flash-lite")
        self.assertEqual(kwargs_node.get("reasoning_effort"), "low")

        # Test loading workflow.json and verifying DAG compilation
        wf_path = os.path.join(os.path.dirname(__file__), "workflow.json")
        wf, wf_config = load_workflow_from_json(wf_path, load_local=False)
        self.assertIsNotNone(wf)
        self.assertEqual(wf_config.get("default_model"), "vertex_ai/gemini-3.7-flash")
        self.assertEqual(wf_config.get("reasoning_effort"), "medium")
        self.assertEqual(wf_config.get("on_enter_status", {}).get("reproducer"), "static_confirmed")
        self.assertEqual(wf_config.get("on_enter_status", {}).get("patcher"), "dynamic_confirmed")

    def test_adk_evaluation_suite_schemas_and_eval_cases(self):
        """Verifies that ADK evaluation dataset and config files adhere to Google ADK EvalSet schema."""
        import json
        from google.adk.evaluation.eval_set import EvalSet
        from google.adk.evaluation.eval_config import EvalConfig

        eval_dir = os.path.join(os.path.dirname(__file__), "evals")
        dataset_path = os.path.join(eval_dir, "deduplication.test.json")
        synthetic_path = os.path.join(eval_dir, "synthetic_dataset.json")
        config_path = os.path.join(eval_dir, "test_config.json")

        self.assertTrue(os.path.exists(dataset_path), f"Eval dataset missing at {dataset_path}")
        self.assertTrue(os.path.exists(synthetic_path), f"Synthetic dataset missing at {synthetic_path}")
        self.assertTrue(os.path.exists(config_path), f"Eval config missing at {config_path}")

        with open(dataset_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
        eval_set = EvalSet.model_validate(raw_data)
        self.assertEqual(eval_set.eval_set_id, "mantis_synthetic_webapp_deduplication_bench")
        self.assertGreaterEqual(len(eval_set.eval_cases), 4)

        with open(synthetic_path, "r", encoding="utf-8") as f:
            raw_syn = json.load(f)
        self.assertIn("findings", raw_syn)
        self.assertIn("ground_truth_clusters", raw_syn)
        self.assertGreaterEqual(len(raw_syn["findings"]), 8)

        with open(config_path, "r", encoding="utf-8") as f:
            raw_cfg = json.load(f)
        eval_config = EvalConfig.model_validate(raw_cfg)
        self.assertIn("tool_trajectory_avg_score", eval_config.criteria)
        self.assertIn("response_match_score", eval_config.criteria)

    def test_advise_cli_script_execution(self):
        """Tests that scripts/advise.py executes standalone without active run context and formats guidance."""
        import subprocess
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_advise_cli.db")
        try:
            init_db(db_file)
            record_artifact(db_file, "run-1", "threat_model", "workspace/kb/THREAT_MODEL.md", "# Threat Model\nAdmin trust boundary.")
            write_findings(db_file, "src/auth.py", [{
                "title": "SQL Injection in get_user",
                "severity": "HIGH",
                "description": "Unsanitized query parameter in get_user()",
                "cwe": "CWE-89",
                "reattack_status": "failed_to_bypass",
                "patch_status": "VERIFIED_SECURE",
                "patch_diff": "--- a\n+++ b\n+ safe_query()",
            }], run_id="run-1")

            script_path = os.path.join(os.path.dirname(__file__), "scripts", "advise.py")

            # 1. Test markdown advisory output
            proc = subprocess.run(
                [sys.executable, script_path, "--db", db_file, "--file", "src/auth.py"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertIn("# Security Advisory & Development Guidance for: src/auth.py", proc.stdout)
            self.assertIn("SQL Injection in get_user", proc.stdout)
            self.assertIn("VERIFIED_SECURE", proc.stdout)

            # 2. Test JSON advisory output
            proc_json = subprocess.run(
                [sys.executable, script_path, "--db", db_file, "--file", "src/auth.py", "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc_json.returncode, 0)
            data = json.loads(proc_json.stdout)
            self.assertEqual(data["filepath"], "src/auth.py")
            self.assertEqual(len(data["confirmed_vulnerabilities"]), 1)
        finally:
            shutil.rmtree(temp_dir)

    def test_no_skill_system_prompt_loading_and_execution(self):
        """Validates loading an agent configured with literal system_prompt instruction text without a skill (A2)."""
        temp_dir = tempfile.mkdtemp()
        try:
            prompt_src = os.path.join(os.path.dirname(__file__), "prompts", "system-researcher.md")
            self.assertTrue(os.path.exists(prompt_src), "prompts/system-researcher.md must exist as canonical no-skill example")

            with open(prompt_src, "r", encoding="utf-8") as f:
                prompt_content = f.read()

            workflow_def = {
                "name": "no_skill_workflow",
                "nodes": [
                    {
                        "id": "researcher",
                        "type": "agent",
                        "system_prompt": prompt_content,
                        "tools": ["read_file", "report_findings"]
                    }
                ],
                "edges": [
                    {"from": "START", "to": "researcher"}
                ]
            }
            wf_path = os.path.join(temp_dir, "workflow.json")
            with open(wf_path, "w") as f:
                json.dump(workflow_def, f)

            with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
                wf, cfg = load_workflow_from_json(wf_path)
                self.assertIsNotNone(wf)
                self.assertEqual(len(wf.edges), 1)
                self.assertTrue(wf.edges[0].to_node.instruction.startswith(prompt_content.strip()))
                self.assertIn("UNTRUSTED CODE AUDIT", wf.edges[0].to_node.instruction)

            # Test A2 literal path handling: literal path strings are preserved verbatim without reading disk contents
            literal_path_def = {
                "nodes": [
                    {
                        "id": "researcher_literal",
                        "type": "agent",
                        "system_prompt": "prompts/non_existent.md"
                    }
                ],
                "edges": [
                    {"from": "START", "to": "researcher_literal"}
                ]
            }
            literal_wf_path = os.path.join(temp_dir, "literal_workflow.json")
            with open(literal_wf_path, "w") as f:
                json.dump(literal_path_def, f)

            with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
                wf2, cfg2 = load_workflow_from_json(literal_wf_path)
                self.assertTrue(wf2.edges[0].to_node.instruction.startswith("prompts/non_existent.md"))
                self.assertIn("UNTRUSTED CODE AUDIT", wf2.edges[0].to_node.instruction)
        finally:
            shutil.rmtree(temp_dir)

    def test_okf_markdown_parsing_and_trust_tiers(self):
        """Tests that parse_okf_markdown accurately extracts OKF v0.2 frontmatter and infers trust tiers."""
        from core.database import parse_okf_markdown

        # 1. Human verified -> human_reviewed trust tier
        human_md = """---
type: Component Entity
title: Authentication Module
description: Handles JWT verification and session state.
resource: src/auth/jwt.py
tags: [auth, jwt, critical]
status: stable
verified:
  - by: human:security-lead
    at: 2026-08-27T12:00:00Z
sources:
  - id: jwt-src
    resource: src/auth/jwt.py
---

# Details
Module validates signatures before forwarding claims.
"""
        parsed_human = parse_okf_markdown(human_md, default_concept_id="entities/auth_module.md")
        self.assertIsNotNone(parsed_human)
        self.assertEqual(parsed_human["type"], "Component Entity")
        self.assertEqual(parsed_human["title"], "Authentication Module")
        self.assertEqual(parsed_human["resource"], "src/auth/jwt.py")
        self.assertEqual(parsed_human["trust_tier"], "human_reviewed")
        self.assertEqual(parsed_human["tags"], ["auth", "jwt", "critical"])
        self.assertIn("Module validates signatures", parsed_human["body_markdown"])

        # 2. Process verified -> machine_confirmed trust tier
        proc_md = """---
type: Threat Boundary
title: Public Ingress Perimeter
resource: api/routes.py
verified:
  - by: process:runsc-reproduce
    at: 2026-08-27T12:00:00Z
---
Unauthenticated route boundary.
"""
        parsed_proc = parse_okf_markdown(proc_md, default_concept_id="threats/ingress.md")
        self.assertIsNotNone(parsed_proc)
        self.assertEqual(parsed_proc["trust_tier"], "machine_confirmed")

        # 3. No verifier -> unverified trust tier
        unver_md = """---
type: Security Invariant
title: Input Sanitization Invariant
resource: src/parser.py
---
All XML input must disable external entity resolution.
"""
        parsed_unver = parse_okf_markdown(unver_md, default_concept_id="invariants/xml.md")
        self.assertIsNotNone(parsed_unver)
        self.assertEqual(parsed_unver["trust_tier"], "unverified")

        # 4. Fallback when no frontmatter is provided
        raw_md = "# Core Database Architecture\nHandles relational persistence."
        parsed_raw = parse_okf_markdown(raw_md, default_concept_id="workspace/kb/entities/db.md")
        self.assertIsNotNone(parsed_raw)
        self.assertEqual(parsed_raw["type"], "Component Entity")
        self.assertEqual(parsed_raw["title"], "Core Database Architecture")
        self.assertEqual(parsed_raw["trust_tier"], "unverified")

        # 5. Patch diffs starting with '--- a/file.py' and containing '--- a/file2.py' are NOT eaten
        multi_file_patch = """--- a/src/auth.py
+++ b/src/auth.py
@@ -1,3 +1,3 @@
- old_code()
+ new_code()
--- a/src/payment.py
+++ b/src/payment.py
@@ -10,2 +10,2 @@
- charge()
+ verify_and_charge()
"""
        parsed_patch = parse_okf_markdown(multi_file_patch, default_concept_id="patches/auth_patch.md")
        self.assertIsNotNone(parsed_patch)
        self.assertEqual(parsed_patch["body_markdown"].strip(), multi_file_patch.strip())
        self.assertIn("--- a/src/auth.py", parsed_patch["body_markdown"])
        self.assertIn("--- a/src/payment.py", parsed_patch["body_markdown"])
        self.assertIn("new_code()", parsed_patch["body_markdown"])

    def test_okf_concept_crud_and_queries(self):
        """Tests SQLite CRUD and indexed queries for OKF concepts."""
        from core.database import init_db, record_okf_concept, read_okf_concepts
        temp_dir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(temp_dir, "okf_test.db")
            init_db(db_path)

            concept1 = {
                "concept_id": "entities/auth",
                "type": "Component Entity",
                "title": "Auth Entity",
                "resource": "src/auth.py",
                "tags": ["auth", "crypto"],
                "status": "stable",
                "trust_tier": "human_reviewed",
                "verified_by": [{"by": "human:lead"}],
                "description": "Auth component",
                "body_markdown": "Body text for auth",
            }
            concept2 = {
                "concept_id": "threats/db_boundary",
                "type": "Threat Boundary",
                "title": "Database Boundary",
                "resource": "src/db.py",
                "tags": ["storage"],
                "status": "stable",
                "trust_tier": "machine_confirmed",
                "verified_by": [{"by": "process:scanner"}],
                "description": "DB trust boundary",
                "body_markdown": "Body text for db",
            }

            record_okf_concept(db_path, "run-1", concept1)
            record_okf_concept(db_path, "run-1", concept2)

            # Query by resource
            auth_concepts = read_okf_concepts(db_path, resource="src/auth.py")
            self.assertEqual(len(auth_concepts), 1)
            self.assertEqual(auth_concepts[0]["concept_id"], "entities/auth")
            self.assertEqual(auth_concepts[0]["trust_tier"], "human_reviewed")
            self.assertIn("auth", auth_concepts[0]["tags"])

            # Query by type
            threats = read_okf_concepts(db_path, concept_type="Threat Boundary")
            self.assertEqual(len(threats), 1)
            self.assertEqual(threats[0]["title"], "Database Boundary")

            # Exact matching does not match wildcards like src/myXfile.py or vendor/src/my_file.py
            concept3 = {
                "concept_id": "entities/my_file",
                "type": "Component Entity",
                "title": "My File",
                "resource": "src/my_file.py",
                "trust_tier": "unverified",
            }
            concept4 = {
                "concept_id": "entities/my_other_file",
                "type": "Component Entity",
                "title": "My X File",
                "resource": "src/myXfile.py",
                "trust_tier": "unverified",
            }
            concept5 = {
                "concept_id": "entities/vendor_my_file",
                "type": "Component Entity",
                "title": "Vendor My File",
                "resource": "vendor/src/my_file.py",
                "trust_tier": "unverified",
            }
            record_okf_concept(db_path, "run-1", concept3)
            record_okf_concept(db_path, "run-1", concept4)
            record_okf_concept(db_path, "run-1", concept5)

            exact_lookup = read_okf_concepts(db_path, resource="src/my_file.py")
            self.assertEqual(len(exact_lookup), 1)
            self.assertEqual(exact_lookup[0]["concept_id"], "entities/my_file")
            self.assertEqual(exact_lookup[0]["resource"], "src/my_file.py")

            # Query by tag
            storage_tagged = read_okf_concepts(db_path, tag="storage")
            self.assertEqual(len(storage_tagged), 1)
            self.assertEqual(storage_tagged[0]["concept_id"], "threats/db_boundary")
        finally:
            shutil.rmtree(temp_dir)

    def test_okf_auto_indexing_from_record_artifact(self):
        """Tests that record_artifact automatically indexes markdown files with OKF frontmatter into okf_concepts."""
        from core.database import init_db, record_artifact, read_okf_concepts
        temp_dir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(temp_dir, "auto_index.db")
            init_db(db_path)

            okf_content = """---
type: Component Entity
title: Payment Router
resource: src/payment.py
tags: [pci, payment]
verified:
  - by: human:security-auditor
---
Routes tokenized charges to gateway.
"""
            record_artifact(db_path, "run-1", "entity", "workspace/kb/entities/payment.md", okf_content)

            # Confirm stored in okf_concepts
            concepts = read_okf_concepts(db_path, resource="src/payment.py")
            self.assertEqual(len(concepts), 1)
            self.assertEqual(concepts[0]["title"], "Payment Router")
            self.assertEqual(concepts[0]["trust_tier"], "human_reviewed")
            self.assertEqual(concepts[0]["tags"], ["pci", "payment"])

            # Test architecture.md without frontmatter maps to Architecture Summary
            arch_content = "# High Level System Architecture\nExplains microservice topology."
            record_artifact(db_path, "run-1", "summary", "workspace/kb/architecture.md", arch_content)
            arch_concepts = read_okf_concepts(db_path, concept_type="Architecture Summary")
            self.assertEqual(len(arch_concepts), 1)
            self.assertEqual(arch_concepts[0]["title"], "High Level System Architecture")

            # Test non-markdown artifact (e.g. raw diff/binary) does not create junk concepts
            record_artifact(db_path, "run-1", "patch", "workspace/temp.bin", "BINARY_DATA_BLOB")
            bin_concepts = read_okf_concepts(db_path, resource="workspace/temp.bin")
            self.assertEqual(len(bin_concepts), 0)

            # Test markdown artifact without frontmatter inherits resource and snapshot_id from metadata
            from core.database import update_status, query_security_guidance
            entity_no_fm = "# Auth Controller\nValidates incoming JWT tokens."
            record_artifact(
                db_path,
                "run-1",
                "entity",
                "workspace/kb/entities/auth.md",
                entity_no_fm,
                metadata={"resource": "src/auth.py", "snapshot_id": "snap-987"}
            )
            auth_c = read_okf_concepts(db_path, resource="src/auth.py")
            self.assertEqual(len(auth_c), 1)
            self.assertEqual(auth_c[0]["title"], "Auth Controller")
            self.assertEqual(auth_c[0]["snapshot_id"], "snap-987")
            self.assertEqual(auth_c[0]["trust_tier"], "unverified")

            # Test repo-wide document (Threat Model) retains resource="" even if metadata carries target_file
            tm_content = "# System Threat Model\nTop level threat model."
            record_artifact(
                db_path,
                "run-1",
                "threat_model",
                "workspace/kb/THREAT_MODEL.md",
                tm_content,
                metadata={"resource": "src/auth.py", "snapshot_id": "snap-987"}
            )
            tm_c = read_okf_concepts(db_path, concept_type="Threat Model")
            self.assertEqual(len(tm_c), 1)
            self.assertEqual(tm_c[0]["resource"], "")  # Must be repo-wide!

            # Add an unrelated concept for src/billing.py
            record_artifact(
                db_path,
                "run-1",
                "entity",
                "workspace/kb/entities/billing.md",
                "# Billing Engine\nProcesses recurring invoices.",
                metadata={"resource": "src/billing.py", "snapshot_id": "snap-987"}
            )

            # Add a human-reviewed concept for src/auth.py
            human_reviewed_c = """---
type: Component Entity
title: Auth Token Parser
resource: src/auth.py
verified:
  - by: human:security-lead
    at: 2026-08-01T00:00:00Z
---
Parses JWT claims.
"""
            record_artifact(db_path, "run-1", "entity", "workspace/kb/entities/token_parser.md", human_reviewed_c)

            # Test update_status upgrades trust_tier to machine_confirmed ONLY for target_file (src/auth.py)
            update_status(db_path, "src/auth.py", "run-1", "dynamic_confirmed")

            # 1. src/auth.py unverified concept upgraded
            auth_c_upgraded = read_okf_concepts(db_path, resource="src/auth.py")
            auth_ctrl = [c for c in auth_c_upgraded if c["title"] == "Auth Controller"][0]
            self.assertEqual(auth_ctrl["trust_tier"], "machine_confirmed")
            self.assertIn("sandbox_dynamic_confirmed", auth_ctrl["verified_by"][0]["by"])
            self.assertIn("at", auth_ctrl["verified_by"][0])

            # 2. src/auth.py human-reviewed concept NOT demoted, attestation appended
            token_parser = [c for c in auth_c_upgraded if c["title"] == "Auth Token Parser"][0]
            self.assertEqual(token_parser["trust_tier"], "human_reviewed")  # Preserved!
            self.assertEqual(len(token_parser["verified_by"]), 2)  # Appended!
            self.assertEqual(token_parser["verified_by"][0]["by"], "human:security-lead")
            self.assertIn("sandbox_dynamic_confirmed", token_parser["verified_by"][1]["by"])

            # 3. Unrelated concept (src/billing.py) NOT attested!
            billing_c = read_okf_concepts(db_path, resource="src/billing.py")
            self.assertEqual(len(billing_c), 1)
            self.assertEqual(billing_c[0]["trust_tier"], "unverified")
            self.assertEqual(len(billing_c[0]["verified_by"]), 0)

            # 4. Repo-wide Threat Model NOT attested by single-file sandbox run!
            tm_c_after = read_okf_concepts(db_path, concept_type="Threat Model")
            self.assertEqual(tm_c_after[0]["trust_tier"], "unverified")
            self.assertEqual(len(tm_c_after[0]["verified_by"]), 0)

            # 4b. Test idempotency of attestations: repeated confirmation updates timestamp without duplicating entries
            update_status(db_path, "src/auth.py", "run-1", "dynamic_confirmed")
            auth_c_second = read_okf_concepts(db_path, resource="src/auth.py")
            auth_ctrl_second = [c for c in auth_c_second if c["title"] == "Auth Controller"][0]
            token_parser_second = [c for c in auth_c_second if c["title"] == "Auth Token Parser"][0]
            self.assertEqual(len(auth_ctrl_second["verified_by"]), 1)
            self.assertEqual(len(token_parser_second["verified_by"]), 2)
            self.assertIn("T", token_parser_second["verified_by"][0]["at"])

            # 5. Verify file scoping: query for totally unrelated file gets repo-wide concepts, NOT auth/billing entities!
            unrelated_guidance = query_security_guidance(db_path, filepath="src/totally_unrelated.py", run_id="run-1")
            unrelated_titles = [c["title"] for c in unrelated_guidance["okf_concepts"]]
            self.assertIn("High Level System Architecture", unrelated_titles)
            self.assertIn("System Threat Model", unrelated_titles)
            self.assertNotIn("Auth Controller", unrelated_titles)
            self.assertNotIn("Billing Engine", unrelated_titles)

            # 6. Verify query_security_guidance for src/auth.py gets auth concepts + repo-wide
            guidance = query_security_guidance(db_path, filepath="src/auth.py", run_id="run-1")
            self.assertEqual(guidance["trust_tier"], "HUMAN-REVIEWED")
            auth_guidance_titles = [c["title"] for c in guidance["okf_concepts"]]
            self.assertIn("Auth Controller", auth_guidance_titles)
            self.assertIn("Auth Token Parser", auth_guidance_titles)
            self.assertNotIn("Billing Engine", auth_guidance_titles)
        finally:
            shutil.rmtree(temp_dir)

    async def _async_test_write_file_kb_metadata_scoping(self):
        from core.context import RunContext, current_run_context
        from tools.research_tools import write_file
        from core.database import init_db, read_okf_concepts
        temp_dir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(temp_dir, "write_file.db")
            init_db(db_path)
            ctx = RunContext(
                jail_dir=temp_dir,
                db_path=db_path,
                target_file="src/auth.py",
                run_id="run-wf",
                snapshot_id="snap-abc",
            )
            token = current_run_context.set(ctx)
            try:
                # 1. Component Entity
                await write_file("workspace/kb/entities/auth.md", "# Auth Entity\nAuthenticates users.")
                # 2. Threat Model
                await write_file("workspace/kb/THREAT_MODEL.md", "# Threat Model\nHigh level threats.")
                # 3. Architecture Summary
                await write_file("workspace/kb/architecture.md", "# Architecture\nOverall system topology.")
            finally:
                current_run_context.reset(token)

            # Assertions
            auth_c = read_okf_concepts(db_path, resource="src/auth.py")
            self.assertEqual(len(auth_c), 1)
            self.assertEqual(auth_c[0]["title"], "Auth Entity")
            self.assertEqual(auth_c[0]["resource"], "src/auth.py")
            self.assertEqual(auth_c[0]["snapshot_id"], "snap-abc")

            tm_c = read_okf_concepts(db_path, concept_type="Threat Model")
            self.assertEqual(len(tm_c), 1)
            self.assertEqual(tm_c[0]["title"], "Threat Model")
            self.assertEqual(tm_c[0]["resource"], "")  # Repo-wide!
            self.assertEqual(tm_c[0]["snapshot_id"], "snap-abc")

            arch_c = read_okf_concepts(db_path, concept_type="Architecture Summary")
            self.assertEqual(len(arch_c), 1)
            self.assertEqual(arch_c[0]["title"], "Architecture")
            self.assertEqual(arch_c[0]["resource"], "")  # Repo-wide!
            self.assertEqual(arch_c[0]["snapshot_id"], "snap-abc")
        finally:
            shutil.rmtree(temp_dir)

    def test_write_file_kb_metadata_scoping(self):
        """Tests that write_file correctly scopes entity documents to target_file while keeping threat models repo-wide."""
        asyncio.run(self._async_test_write_file_kb_metadata_scoping())

    def test_okf_bundle_export_and_import(self):
        """Tests exporting concepts from SQLite to an OKF directory bundle and re-importing into another database."""
        from core.database import init_db, record_okf_concept, export_okf_bundle, import_okf_bundle, read_okf_concepts
        temp_dir = tempfile.mkdtemp()
        try:
            src_db = os.path.join(temp_dir, "src.db")
            dst_db = os.path.join(temp_dir, "dst.db")
            export_dir = os.path.join(temp_dir, "okf_bundle")
            init_db(src_db)
            init_db(dst_db)

            concept = {
                "concept_id": "entities/crypto_vault",
                "type": "Component Entity",
                "title": "Crypto Vault",
                "resource": "src/vault.py",
                "tags": ["crypto", "vault"],
                "status": "stable",
                "trust_tier": "human_reviewed",
                "verified_by": [{"by": "human:lead"}],
                "description": "AES-GCM key storage",
                "body_markdown": "# Crypto Vault\nImplements hardware-backed key derivation.",
            }
            record_okf_concept(src_db, "run-1", concept)

            # Add an unsafe concept attempting directory traversal to test logging confinement
            unsafe_concept = {
                "concept_id": "../../unsafe_escape",
                "type": "Malicious",
                "title": "Unsafe Escape",
                "resource": "src/escape.py",
                "body_markdown": "Attempted traversal.",
            }
            record_okf_concept(src_db, "run-1", unsafe_concept)

            # Export to OKF bundle directory
            exported_files = export_okf_bundle(src_db, export_dir)
            self.assertTrue(os.path.exists(os.path.join(export_dir, "index.md")))
            self.assertTrue(any(f.startswith("crypto_vault-") and f.endswith(".md") for f in os.listdir(os.path.join(export_dir, "entities"))))
            self.assertFalse(os.path.exists(os.path.join(export_dir, "..", "unsafe_escape.md")))

            # Check index.md content
            with open(os.path.join(export_dir, "index.md"), "r", encoding="utf-8") as fh:
                idx_txt = fh.read()
            self.assertIn('okf_version: "0.2"', idx_txt)
            self.assertIn("Crypto Vault", idx_txt)

            # Import bundle into dst_db
            imported_count = import_okf_bundle(dst_db, export_dir, run_id="imported_run")
            self.assertGreaterEqual(imported_count, 1)

            # Verify concept exists in dst_db
            dst_concepts = read_okf_concepts(dst_db, resource="src/vault.py")
            self.assertEqual(len(dst_concepts), 1)
            self.assertEqual(dst_concepts[0]["title"], "Crypto Vault")
            self.assertEqual(dst_concepts[0]["trust_tier"], "unverified")
        finally:
            shutil.rmtree(temp_dir)

    def test_advise_guidance_with_okf_and_diff_injection(self):
        """Tests that query_security_guidance combines scoped OKF concepts, trust tiers, and verified few-shot diffs."""
        from core.database import init_db, record_okf_concept, write_findings, query_security_guidance
        temp_dir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(temp_dir, "advise_okf.db")
            init_db(db_path)

            # Add scoped OKF threat boundary & invariant
            record_okf_concept(db_path, "run-1", {
                "concept_id": "threats/auth_ingress",
                "type": "Threat Boundary",
                "title": "Auth Ingress Perimeter",
                "resource": "src/auth.py",
                "trust_tier": "human_reviewed",
                "verified_by": [{"by": "human:lead"}],
                "body_markdown": "Accepts unauthenticated bearer tokens from public clients.",
            })
            record_okf_concept(db_path, "run-1", {
                "concept_id": "invariants/token_sanitize",
                "type": "Security Invariant",
                "title": "Token Sanitization",
                "resource": "src/auth.py",
                "trust_tier": "machine_confirmed",
                "description": "Must strip control characters from username claims.",
            })

            # Add verified patch finding
            write_findings(db_path, "src/auth.py", [{
                "title": "Unsanitized Token Header",
                "filepath": "src/auth.py",
                "severity": "HIGH",
                "status": "patch_verified",
                "cwe": "CWE-79",
                "description": "Header injection in token parser.",
                "remediation": "Sanitize header before forwarding.",
                "patch_status": "applied",
                "patch_diff": "--- a/src/auth.py\n+++ b/src/auth.py\n@@ -10,2 +10,2 @@\n- hdr = req.header\n+ hdr = sanitize(req.header)\n",
            }], run_id="run-1")

            guidance = query_security_guidance(db_path, filepath="src/auth.py")
            summary = guidance["guidance_summary"]

            self.assertEqual(guidance["trust_tier"], "HUMAN-REVIEWED")
            self.assertIn("[OKF TRUST TIER: HUMAN-REVIEWED]", summary)
            self.assertIn("Auth Ingress Perimeter", summary)
            self.assertIn("Token Sanitization", summary)
            self.assertIn("Verified Patch Diff (Few-Shot Pattern)", summary)
            self.assertIn("hdr = sanitize(req.header)", summary)
        finally:
            shutil.rmtree(temp_dir)

    def test_advise_cli_execution_with_okf_features(self):
        """Tests that scripts/advise.py runs as a CLI command supporting --file, --json, and --export-okf."""
        from core.database import init_db, record_okf_concept
        temp_dir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(temp_dir, "cli_test.db")
            init_db(db_path)
            record_okf_concept(db_path, "run-1", {
                "concept_id": "entities/crypto",
                "type": "Component Entity",
                "title": "Crypto Engine",
                "resource": "src/crypto.py",
                "trust_tier": "machine_confirmed",
                "description": "AES operations",
                "body_markdown": "Uses 256-bit keys.",
            })

            advise_script = os.path.join(os.path.dirname(__file__), "scripts", "advise.py")

            # 1. Test CLI query --json
            res_json = subprocess.run(
                [sys.executable, advise_script, "--db", db_path, "--file", "src/crypto.py", "--json"],
                capture_output=True,
                text=True,
                check=True
            )
            data = json.loads(res_json.stdout)
            self.assertEqual(data["filepath"], "src/crypto.py")
            self.assertEqual(data["trust_tier"], "SANDBOX-CONFIRMED")
            self.assertIn("Crypto Engine", data["guidance_summary"])

            # 2. Test CLI --export-okf
            export_target = os.path.join(temp_dir, "cli_export_bundle")
            res_exp = subprocess.run(
                [sys.executable, advise_script, "--db", db_path, "--export-okf", export_target],
                capture_output=True,
                text=True,
                check=True
            )
            self.assertIn("Exported", res_exp.stdout)
            self.assertTrue(os.path.exists(os.path.join(export_target, "index.md")))

            # 3. Test CLI --import-okf into a fresh db
            imported_db = os.path.join(temp_dir, "imported_via_cli.db")
            res_imp = subprocess.run(
                [sys.executable, advise_script, "--db", imported_db, "--import-okf", export_target],
                capture_output=True,
                text=True,
                check=True
            )
            self.assertIn("Imported", res_imp.stdout)

            # 4. Test CLI --remediate generating architectural remediation dossier
            from core.database import write_findings
            write_findings(db_path, "src/crypto.py", [{
                "filepath": "src/crypto.py",
                "title": "Insecure AES padding",
                "severity": "HIGH",
                "description": "PKCS#7 padding oracle vulnerability.",
                "remediation": "Use AES-GCM authenticated encryption.",
                "status": "dynamic_confirmed",
                "lineage_id": "c3a5e982-1234-5678-9abc-def012345678",
                "repro_cmd": "python3 repro_aes.py",
            }], run_id="run-1", status="dynamic_confirmed")
            res_rem = subprocess.run(
                [sys.executable, advise_script, "--db", db_path, "--remediate", "src/crypto.py"],
                capture_output=True,
                text=True,
                check=True
            )
            self.assertIn("Architectural Remediation Dossier", res_rem.stdout)
            self.assertIn("Insecure AES padding", res_rem.stdout)
            self.assertIn("Crypto Engine", res_rem.stdout)
            self.assertIn("Use AES-GCM authenticated encryption", res_rem.stdout)
            self.assertIn("Bypass Prevention", res_rem.stdout)
        finally:
            shutil.rmtree(temp_dir)


class TestMantisConfigureAndLaunch(unittest.IsolatedAsyncioTestCase):
    """Unit and integration tests for configure.py, launch.py, model routing, and preflight checks."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.sample_wf_path = os.path.join(self.temp_dir, "workflow.json")
        self.sample_wf_def = {
            "name": "test_pipeline",
            "config": {
                "db_path": "test_knowledge.db",
                "default_model": "vertex_ai/gemini-3.7-flash",
                "sandbox": {
                    "type": "gce",
                    "options": {
                        "project": "YOUR_PROJECT_ID",
                        "zone": "us-central1-b",
                    }
                }
            },
            "nodes": [
                {
                    "id": "agent_node",
                    "type": "agent",
                    "system_prompt": "prompt.md",
                    "tools": ["read_file"]
                }
            ],
            "edges": [
                {"from": "START", "to": "agent_node"}
            ]
        }
        with open(os.path.join(self.temp_dir, "prompt.md"), "w") as pf:
            pf.write("Test agent instructions.")
        with open(self.sample_wf_path, "w") as f:
            json.dump(self.sample_wf_def, f, indent=2)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_is_placeholder(self):
        from scripts.configure import is_placeholder

        self.assertTrue(is_placeholder("YOUR_PROJECT_ID"))
        self.assertTrue(is_placeholder("YOUR_PROJECT"))
        self.assertTrue(is_placeholder("<YOUR_PROJECT_ID>"))
        self.assertTrue(is_placeholder("<PROJECT_ID>"))
        self.assertTrue(is_placeholder("YOUR_API_KEY"))
        self.assertTrue(is_placeholder("TODO"))
        self.assertTrue(is_placeholder("CHANGE_ME"))
        self.assertTrue(is_placeholder("REPLACE_ME"))
        self.assertTrue(is_placeholder(""))
        self.assertTrue(is_placeholder(None))

        # Real project / model strings with 'todo' as substring are NOT placeholders
        self.assertFalse(is_placeholder("todo-app-prod"))
        self.assertFalse(is_placeholder("acme-todo-svc"))
        self.assertFalse(is_placeholder("my-gcp-project-123"))
        self.assertFalse(is_placeholder("vertex_ai/gemini-3.7-flash"))
        self.assertFalse(is_placeholder("openai/gpt-4o"))

    def test_is_default_or_unconfigured(self):
        from scripts.configure import is_default_or_unconfigured

        # 1. Unconfigured with default YOUR_PROJECT_ID
        cfg_unconf = {
            "default_model": "vertex_ai/gemini-3.7-flash",
            "sandbox": {"type": "gce", "options": {"project": "YOUR_PROJECT_ID"}}
        }
        with patch.dict(os.environ, {}, clear=True):
            is_unconf, issues = is_default_or_unconfigured(cfg_unconf)
            self.assertTrue(is_unconf)
            self.assertTrue(any("YOUR_PROJECT_ID" in iss for iss in issues))

        # 2. Configured static-only sandbox
        cfg_static = {
            "default_model": "gemini-3.7-flash",
            "sandbox": {"type": "static-only", "options": {}}
        }
        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "valid-proj"}):
            is_unconf, issues = is_default_or_unconfigured(cfg_static)
            self.assertFalse(is_unconf)
            self.assertEqual(len(issues), 0)

        # 3. Configured GCE sandbox with real project
        cfg_gce = {
            "default_model": "vertex_ai/gemini-3.7-flash",
            "sandbox": {"type": "gce", "options": {"project": "my-real-project"}}
        }
        with patch("shutil.which", return_value="/usr/bin/gcloud"):
            with patch.dict(os.environ, {"VERTEXAI_PROJECT": "my-real-project"}):
                is_unconf, issues = is_default_or_unconfigured(cfg_gce)
                self.assertFalse(is_unconf)
                self.assertEqual(len(issues), 0)

        # 4. Placeholder in model name
        cfg_bad_model = {
            "default_model": "openai/YOUR_API_KEY",
            "sandbox": {"type": "static-only"}
        }
        is_unconf, issues = is_default_or_unconfigured(cfg_bad_model)
        self.assertTrue(is_unconf)

        # 5. gVisor missing docker/podman
        cfg_gv = {
            "default_model": "vertex_ai/gemini-3.7-flash",
            "sandbox": {"type": "gvisor"}
        }
        with patch("shutil.which", return_value=None):
            with patch.dict(os.environ, {"VERTEXAI_PROJECT": "valid-proj"}):
                is_unconf, issues = is_default_or_unconfigured(cfg_gv)
                self.assertTrue(is_unconf)
                self.assertTrue(any("docker" in iss.lower() for iss in issues))

    def test_detect_capabilities(self):
        from scripts.configure import detect_capabilities

        caps = detect_capabilities()
        self.assertIsInstance(caps, dict)
        self.assertIn("kvm", caps)
        self.assertIn("docker", caps)
        self.assertIn("gcloud", caps)
        self.assertIn("available_sandboxes", caps)
        self.assertIn("recommended_sandbox", caps)
        self.assertIn("static-only", caps["available_sandboxes"])

    def test_update_workflow_config(self):
        from scripts.configure import update_workflow_config, load_workflow_dict, get_local_workflow_path

        updates = {
            "default_model": "vertex_ai/claude-opus-5",
            "api_base": "http://localhost:8000/v1",
            "timeout": 45.0,
            "reasoning_effort": "high",
            "db_path": "custom.db",
            "sandbox": {
                "type": "gvisor",
                "options": {"image": "mantis-sandbox:latest"}
            }
        }
        # 1. Default update saves to workflow.local.json overlay
        updated = update_workflow_config(self.sample_wf_path, updates, save=True, update_all_nodes=True, save_tracked=False)
        self.assertEqual(updated["config"]["default_model"], "vertex_ai/claude-opus-5")
        self.assertEqual(updated["config"]["api_base"], "http://localhost:8000/v1")
        self.assertEqual(updated["config"]["timeout"], 45.0)
        self.assertEqual(updated["config"]["reasoning_effort"], "high")
        self.assertEqual(updated["config"]["db_path"], "custom.db")
        self.assertEqual(updated["config"]["sandbox"]["type"], "gvisor")
        self.assertEqual(updated["config"]["sandbox"]["options"]["image"], "mantis-sandbox:latest")

        local_path = get_local_workflow_path(self.sample_wf_path)
        self.assertTrue(os.path.exists(local_path))

        # Base workflow.json on disk remains unchanged
        base_raw = load_workflow_dict(self.sample_wf_path, load_local=False)
        self.assertEqual(base_raw["config"]["default_model"], "vertex_ai/gemini-3.7-flash")

        # Merged load reflects overlay
        reloaded = load_workflow_dict(self.sample_wf_path, load_local=True)
        self.assertEqual(reloaded["config"]["default_model"], "vertex_ai/claude-opus-5")

        # 2. save_tracked=True updates base workflow.json
        update_workflow_config(self.sample_wf_path, {"default_model": "vertex_ai/zai_org/glm-5.2-maas"}, save=True, save_tracked=True)
        base_tracked = load_workflow_dict(self.sample_wf_path, load_local=False)
        self.assertEqual(base_tracked["config"]["default_model"], "vertex_ai/zai_org/glm-5.2-maas")

        # 3. Sandbox downgrade to static-only cleans options dictionary
        downgrade_updates = {"sandbox": {"type": "static-only", "options": {}}}
        cleaned = update_workflow_config(self.sample_wf_path, downgrade_updates, save=True, save_tracked=False)
        self.assertEqual(cleaned["config"]["sandbox"]["type"], "static-only")
        self.assertEqual(cleaned["config"]["sandbox"]["options"], {})

    def test_workflow_local_overlay(self):
        from core.graph_loader import load_workflow_from_json
        from scripts.configure import get_local_workflow_path

        # Create base workflow.json with placeholder
        with open(self.sample_wf_path, "w") as f:
            json.dump({
                "name": "overlay_workflow",
                "config": {
                    "default_model": "vertex_ai/gemini-3.7-flash",
                    "sandbox": {"type": "gce", "options": {"project": "YOUR_PROJECT_ID"}}
                },
                "nodes": [{"id": "test_agent", "type": "agent", "system_prompt": "prompt.md"}],
                "edges": [{"from": "START", "to": "test_agent"}]
            }, f)

        # Write workflow.local.json overlay
        local_path = get_local_workflow_path(self.sample_wf_path)
        with open(local_path, "w") as f:
            json.dump({
                "config": {
                    "sandbox": {"type": "gce", "options": {"project": "my-local-overlay-proj"}}
                }
            }, f)

        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "my-local-overlay-proj"}):
            wf, cfg = load_workflow_from_json(self.sample_wf_path)
            self.assertEqual(cfg["sandbox"]["type"], "gce")
            self.assertEqual(cfg["sandbox"]["options"]["project"], "my-local-overlay-proj")

        # Verify base workflow.json remains untouched on disk
        with open(self.sample_wf_path, "r") as f:
            base_disk = json.load(f)
        self.assertEqual(base_disk["config"]["sandbox"]["options"]["project"], "YOUR_PROJECT_ID")

    def test_run_preflight_checks(self):
        from scripts.configure import run_preflight_checks, run_preflight_checks_async

        # 1. Static sandbox passes preflight instantly
        cfg_static = {
            "default_model": "vertex_ai/gemini-3.7-flash",
            "sandbox": {"type": "static-only"}
        }
        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
            ok, msgs = run_preflight_checks(cfg_static)
            self.assertTrue(ok)
            self.assertTrue(any("PASSED" in m for m in msgs))

        # 2. GCE sandbox with placeholder project fails preflight
        cfg_gce_bad = {
            "default_model": "vertex_ai/gemini-3.7-flash",
            "sandbox": {"type": "gce", "options": {"project": "YOUR_PROJECT_ID"}}
        }
        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
            ok, msgs = run_preflight_checks(cfg_gce_bad)
            self.assertFalse(ok)
            self.assertTrue(any("placeholder" in m.lower() for m in msgs))

        # 3. GCE sandbox with valid credentials tests softened preflight message
        cfg_gce_good = {
            "default_model": "vertex_ai/gemini-3.7-flash",
            "sandbox": {"type": "gce", "options": {"project": "my-gce-project"}}
        }
        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "my-gce-project"}):
            with patch("shutil.which", return_value="/usr/bin/gcloud"):
                with patch("subprocess.run") as mock_sub:
                    mock_sub.return_value = MagicMock(returncode=0, stdout="active-user@google.com\n")
                    ok, msgs = run_preflight_checks(cfg_gce_good)
                    self.assertTrue(ok)
                    gce_msg = next((m for m in msgs if "SANDBOX PREFLIGHT" in m), "")
                    self.assertIn("GCE credentials & project verified (Project: my-gce-project)", gce_msg)
                    self.assertIn("Note: Ephemeral VM creation requires pre-provisioned VPC/Subnet/Image", gce_msg)

        # 4. Anthropic model without ANTHROPIC_API_KEY fails preflight
        cfg_anthropic = {
            "default_model": "anthropic/claude-3-5-sonnet",
            "sandbox": {"type": "static-only"}
        }
        with patch.dict(os.environ, {}, clear=True):
            ok, msgs = run_preflight_checks(cfg_anthropic)
            self.assertFalse(ok)
            self.assertTrue(any("ANTHROPIC_API_KEY" in m for m in msgs))

        # 5. Anthropic model with ANTHROPIC_API_KEY passes preflight
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}):
            ok, msgs = run_preflight_checks(cfg_anthropic)
            self.assertTrue(ok)

        # 6. OpenAI-compatible model with api_base passes preflight
        cfg_openai = {
            "default_model": "openai/custom-model",
            "api_base": "http://localhost:8000/v1",
            "sandbox": {"type": "static-only"}
        }
        ok, msgs = run_preflight_checks(cfg_openai)
        self.assertTrue(ok)

        # 7. Vertex AI OpenAI model passes preflight with api_base or project
        cfg_vertex_openai = {
            "default_model": "vertex_ai/openai/custom-model",
            "api_base": "http://localhost:8000/v1",
            "sandbox": {"type": "static-only"}
        }
        ok, msgs = run_preflight_checks(cfg_vertex_openai)
        self.assertTrue(ok)

        # 8. GLM 5.2 MaaS model with Vertex AI project passes preflight
        cfg_glm = {
            "default_model": "vertex_ai/zai_org/glm-5.2-maas",
            "sandbox": {"type": "static-only"}
        }
        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
            ok, msgs = run_preflight_checks(cfg_glm)
            self.assertTrue(ok)

        # 9. Async preflight checks execution
        async def _test_async():
            with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
                a_ok, a_msgs = await run_preflight_checks_async(cfg_static)
                self.assertTrue(a_ok)
                # Safe sync wrapper inside event loop does not raise RuntimeError
                s_ok, s_msgs = run_preflight_checks(cfg_static)
                self.assertTrue(s_ok)

        asyncio.run(_test_async())

    def test_ensure_configured(self):
        from scripts.configure import ensure_configured, load_workflow_dict, get_local_workflow_path

        # Auto-configure auto-resolves placeholder GCE and saves to workflow.local.json
        with patch.dict(os.environ, {"GOOGLE_CLOUD_PROJECT": "auto-discovered-proj"}):
            with patch("scripts.configure.detect_capabilities", return_value={
                "kvm": False, "docker": False, "podman": False, "container_tool": None,
                "runsc": False, "gcloud": True, "gcp_auth": True, "gcp_account": "user@google.com",
                "gcp_project": "auto-discovered-proj", "vertex_project": "auto-discovered-proj",
                "gemini_api_key": False, "anthropic_api_key": False, "openai_api_key": False,
                "llm_api_base": None, "recommended_sandbox": "gce",
                "available_sandboxes": ["static-only", "gce"]
            }):
                resolved = ensure_configured(self.sample_wf_path, auto=True)
                self.assertEqual(resolved["sandbox"]["options"]["project"], "auto-discovered-proj")

                # Verify local overlay was created
                local_path = get_local_workflow_path(self.sample_wf_path)
                self.assertTrue(os.path.exists(local_path))

                # Base workflow.json on disk is still unmodified placeholder
                base_raw = load_workflow_dict(self.sample_wf_path, load_local=False)
                self.assertEqual(base_raw["config"]["sandbox"]["options"]["project"], "YOUR_PROJECT_ID")

        # Auto-configure falls back cleanly to static-only with options={} when GCE is unavailable
        import io
        from contextlib import redirect_stdout
        with patch("scripts.configure.detect_capabilities", return_value={
            "kvm": False, "docker": False, "podman": False, "container_tool": None,
            "runsc": False, "gcloud": False, "gcp_auth": False, "gcp_account": None,
            "gcp_project": None, "vertex_project": None,
            "gemini_api_key": False, "anthropic_api_key": False, "openai_api_key": False,
            "llm_api_base": None, "recommended_sandbox": "static-only",
            "available_sandboxes": ["static-only"]
        }):
            # 1. By default without MANTIS_ALLOW_SANDBOX_DOWNGRADE=1, ensure_configured fails closed
            with self.assertRaises(SystemExit) as cm:
                ensure_configured(self.sample_wf_path, auto=True)
            self.assertEqual(cm.exception.code, 2)

            # 2. When operator explicitly allows downgrade, it proceeds session-only
            with patch.dict(os.environ, {"MANTIS_ALLOW_SANDBOX_DOWNGRADE": "1"}):
                f = io.StringIO()
                with redirect_stdout(f):
                    resolved_fallback = ensure_configured(self.sample_wf_path, auto=True)
                output = f.getvalue()
                self.assertIn("⚠️  [REPRO DISABLED]", output)
                self.assertIn("Operator-approved downgrade", output)
                self.assertEqual(resolved_fallback["sandbox"]["type"], "static-only")
                self.assertEqual(resolved_fallback["sandbox"]["options"], {})

                # Also verify downgrade was NEVER persisted to workflow.local.json!
                reloaded = load_workflow_dict(self.sample_wf_path, load_local=True)
                self.assertNotEqual(reloaded["config"]["sandbox"]["type"], "static-only")

    def test_merge_config_dicts_sandbox_transitions(self):
        from core.graph_loader import merge_config_dicts
        from scripts.configure import merge_dicts

        for merge_fn in (merge_config_dicts, merge_dicts):
            # 1. Downgrading from GCE to static-only replaces options with {}
            base = {"sandbox": {"type": "gce", "options": {"project": "YOUR_PROJECT_ID", "zone": "us-central1-b"}}}
            overlay = {"sandbox": {"type": "static-only", "options": {}}}
            merged = merge_fn(base, overlay)
            self.assertEqual(merged["sandbox"]["type"], "static-only")
            self.assertEqual(merged["sandbox"]["options"], {})

            # 2. Transition from GCE to gVisor does not leak GCE options
            overlay_gv = {"sandbox": {"type": "gvisor", "options": {"container_tool": "docker"}}}
            merged_gv = merge_fn(base, overlay_gv)
            self.assertEqual(merged_gv["sandbox"]["type"], "gvisor")
            self.assertEqual(merged_gv["sandbox"]["options"], {"container_tool": "docker"})

            # 3. Same type merges options cleanly
            overlay_proj = {"sandbox": {"type": "gce", "options": {"project": "my-real-project"}}}
            merged_gce = merge_fn(base, overlay_proj)
            self.assertEqual(merged_gce["sandbox"]["type"], "gce")
            self.assertEqual(merged_gce["sandbox"]["options"]["project"], "my-real-project")
            self.assertEqual(merged_gce["sandbox"]["options"]["zone"], "us-central1-b")

    def test_configure_cli_operations(self):
        from scripts.configure import build_parser, main as configure_main, get_local_workflow_path

        # 1. Test CLI status show
        test_args = ["--workflow", self.sample_wf_path, "--show", "--json"]
        with patch("sys.argv", ["configure.py"] + test_args):
            with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
                rc = configure_main()
                self.assertEqual(rc, 0)

        # 2. Test CLI dry-run update does not write files
        test_args = ["--workflow", self.sample_wf_path, "--sandbox", "static-only", "--dry-run"]
        with patch("sys.argv", ["configure.py"] + test_args):
            rc = configure_main()
            self.assertEqual(rc, 0)

        # 3. Test CLI --auto --dry-run never mutates workflow.json or workflow.local.json
        local_path = get_local_workflow_path(self.sample_wf_path)
        if os.path.exists(local_path):
            os.remove(local_path)
        test_args = ["--workflow", self.sample_wf_path, "--auto", "--dry-run"]
        with patch("sys.argv", ["configure.py"] + test_args):
            with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
                rc = configure_main()
                self.assertEqual(rc, 0)
                self.assertFalse(os.path.exists(local_path))

        # 4. Test CLI test flag on static sandbox
        test_args = ["--workflow", self.sample_wf_path, "--sandbox", "static-only", "--test"]
        with patch("sys.argv", ["configure.py"] + test_args):
            with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
                rc = configure_main()
                self.assertEqual(rc, 0)

        # 5. Test CLI save-tracked flag modifies base workflow.json
        test_args = ["--workflow", self.sample_wf_path, "--model", "gemini-3.7-flash", "--save-tracked"]
        with patch("sys.argv", ["configure.py"] + test_args):
            with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
                rc = configure_main()
                self.assertEqual(rc, 0)

    def test_llm_project_resolution_fallback(self):
        from core.config import get_llm_kwargs

        # When env vars are cleared, get_llm_kwargs falls back to config project or sandbox project
        with patch.dict(os.environ, {}, clear=True):
            # 1. Fallback to config["project"]
            m, kwargs = get_llm_kwargs(
                model_id="vertex_ai/gemini-3.7-flash",
                config={"project": "fallback-project-alpha"}
            )
            self.assertEqual(kwargs.get("vertex_project"), "fallback-project-alpha")

            # 2. Fallback to config["sandbox"]["options"]["project"]
            m, kwargs = get_llm_kwargs(
                model_id="vertex_ai/gemini-3.7-flash",
                config={"sandbox": {"options": {"project": "fallback-sb-project"}}}
            )
            self.assertEqual(kwargs.get("vertex_project"), "fallback-sb-project")

            # 3. Placeholder in config is ignored
            with patch("google.auth.default", side_effect=Exception("No credentials")):
                with self.assertRaises(ValueError):
                    get_llm_kwargs(
                        model_id="vertex_ai/gemini-3.7-flash",
                        config={"sandbox": {"options": {"project": "YOUR_PROJECT_ID"}}}
                    )

            # 4. Placeholder in env var is ignored and falls back to config
            with patch.dict(os.environ, {"VERTEXAI_PROJECT": "YOUR_PROJECT_ID", "GOOGLE_CLOUD_PROJECT": ""}):
                m, kwargs = get_llm_kwargs(
                    model_id="vertex_ai/gemini-3.7-flash",
                    config={"project": "fallback-after-env-placeholder"}
                )
                self.assertEqual(kwargs.get("vertex_project"), "fallback-after-env-placeholder")

    def test_model_catalog_configuration(self):
        from core.config import RECOMMENDED_MODELS, DEFAULT_MODEL

        # 1. Check RECOMMENDED_MODELS and DEFAULT_MODEL catalog
        self.assertIn("vertex_ai/claude-opus-5", RECOMMENDED_MODELS)
        self.assertNotIn("anthropic/claude-opus-5", RECOMMENDED_MODELS)
        self.assertIn("vertex_ai/zai_org/glm-5.2-maas", RECOMMENDED_MODELS)
        self.assertEqual(DEFAULT_MODEL, "vertex_ai/gemini-3.7-flash")

    def test_model_normalization_and_routing(self):
        from core.config import normalize_model_id, get_llm_kwargs

        # Bare gemini model routes to vertex_ai when GCP env is set
        with patch.dict(os.environ, {"GOOGLE_CLOUD_PROJECT": "proj-123", "GEMINI_API_KEY": ""}):
            normalized = normalize_model_id("gemini-3.7-flash")
            self.assertEqual(normalized, "vertex_ai/gemini-3.7-flash")

        # Global model override takes precedence
        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "proj-123"}):
            model_id, kwargs = get_llm_kwargs(
                model_id="vertex_ai/gemini-3.5-flash-lite",
                global_model_override="vertex_ai/claude-opus-5",
            )
            self.assertEqual(model_id, "vertex_ai/claude-opus-5")
            self.assertEqual(kwargs["vertex_project"], "proj-123")

        # MANTIS_MODEL env var overrides node model
        with patch.dict(os.environ, {"MANTIS_MODEL": "openai/custom-vllm", "LLM_API_BASE": "http://localhost:8000/v1"}):
            model_id, kwargs = get_llm_kwargs(model_id="vertex_ai/gemini-3.7-flash")
            self.assertEqual(model_id, "openai/custom-vllm")
            self.assertEqual(kwargs["api_base"], "http://localhost:8000/v1")

        # vertex_ai/zai_org/glm-5.2-maas routing to OpenAPI endpoint
        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "proj-123"}):
            model_id, kwargs = get_llm_kwargs(model_id="vertex_ai/zai_org/glm-5.2-maas")
            self.assertEqual(model_id, "vertex_ai/openai/zai-org/glm-5.2-maas")
            self.assertEqual(kwargs["vertex_project"], "proj-123")

        # vertex_ai/openai/{MODEL_ID} with api_base
        model_id, kwargs = get_llm_kwargs(
            model_id="vertex_ai/openai/my-model",
            api_base="http://localhost:8000/v1",
        )
        self.assertEqual(model_id, "vertex_ai/openai/my-model")
        self.assertEqual(kwargs["api_base"], "http://localhost:8000/v1")

    def test_graph_loader_runtime_overrides(self):
        # Update sample workflow to use static-only sandbox and valid prompt
        with open(self.sample_wf_path, "w") as f:
            json.dump({
                "name": "override_workflow",
                "config": {"default_model": "vertex_ai/gemini-3.7-flash", "sandbox": {"type": "static-only"}},
                "nodes": [{"id": "test_agent", "type": "agent", "system_prompt": "prompt.md"}],
                "edges": [{"from": "START", "to": "test_agent"}]
            }, f)

        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "proj-123"}):
            wf, cfg = load_workflow_from_json(
                self.sample_wf_path,
                model_override="openai/override-model",
                api_base_override="http://localhost:9000/v1",
                sandbox_override="static-only",
                db_override="runtime.db",
                timeout_override=120.0,
                reasoning_effort_override="high",
            )
            self.assertEqual(cfg["default_model"], "openai/override-model")
            self.assertEqual(cfg["api_base"], "http://localhost:9000/v1")
            self.assertEqual(cfg["db_path"], "runtime.db")
            self.assertEqual(cfg["timeout"], 120.0)
            self.assertEqual(cfg["reasoning_effort"], "high")

    def test_launch_script_operations(self):
        from scripts.launch import run_launch

        # 1. Non-existent target fails with exit code 1
        rc = run_launch(target="/non/existent/path/xyz.py", workflow_path=self.sample_wf_path)
        self.assertEqual(rc, 1)

        # 2. Dry run over existing target file returns exit code 0
        with open(self.sample_wf_path, "w") as f:
            json.dump({
                "name": "launch_workflow",
                "config": {"default_model": "vertex_ai/gemini-3.7-flash", "sandbox": {"type": "static-only"}},
                "nodes": [{"id": "test_agent", "type": "agent", "system_prompt": "prompt.md"}],
                "edges": [{"from": "START", "to": "test_agent"}]
            }, f)

        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "proj-123"}):
            rc = run_launch(
                target=os.path.join(self.temp_dir, "prompt.md"),
                workflow_path=self.sample_wf_path,
                dry_run=True,
            )
            self.assertEqual(rc, 0)

        # 3. Preflight only returns exit code 0
        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "proj-123"}):
            rc = run_launch(
                target=os.path.join(self.temp_dir, "prompt.md"),
                workflow_path=self.sample_wf_path,
                preflight_only=True,
            )
            self.assertEqual(rc, 0)

        # 4. Auto-healing on unconfigured placeholder in launch
        with open(self.sample_wf_path, "w") as f:
            json.dump({
                "name": "launch_unconf_workflow",
                "config": {
                    "default_model": "vertex_ai/gemini-3.7-flash",
                    "sandbox": {"type": "gce", "options": {"project": "YOUR_PROJECT_ID"}}
                },
                "nodes": [{"id": "test_agent", "type": "agent", "system_prompt": "prompt.md"}],
                "edges": [{"from": "START", "to": "test_agent"}]
            }, f)

        with patch.dict(os.environ, {"GOOGLE_CLOUD_PROJECT": "auto-resolved-proj", "VERTEXAI_PROJECT": "auto-resolved-proj"}):
            with patch("scripts.configure.detect_capabilities", return_value={
                "kvm": False, "docker": False, "podman": False, "container_tool": None,
                "runsc": False, "gcloud": True, "gcp_auth": True, "gcp_account": "user@google.com",
                "gcp_project": "auto-resolved-proj", "vertex_project": "auto-resolved-proj",
                "gemini_api_key": False, "anthropic_api_key": False, "openai_api_key": False,
                "llm_api_base": None, "recommended_sandbox": "gce",
                "available_sandboxes": ["static-only", "gce"]
            }):
                with patch("scripts.configure._check_sandbox_preflight", return_value=(True, "Sandbox ready")):
                    rc = run_launch(
                        target=os.path.join(self.temp_dir, "prompt.md"),
                        workflow_path=self.sample_wf_path,
                        preflight_only=True,
                    )
                    self.assertEqual(rc, 0)

        # 5. Launch with live probe flag enabled
        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "proj-123"}):
            with patch("scripts.configure._probe_llm_reachability", return_value=(True, "LLM reachability verified.")):
                rc = run_launch(
                    target=os.path.join(self.temp_dir, "prompt.md"),
                    workflow_path=self.sample_wf_path,
                    sandbox="static-only",
                    preflight_only=True,
                    probe_llm=True,
                )
                self.assertEqual(rc, 0)

    def test_llm_reachability_probe(self):
        from scripts.configure import (
            _probe_llm_reachability,
            _check_llm_preflight,
            run_preflight_checks,
        )

        # 1. Probe success
        mock_resp = MagicMock()
        mock_resp.choices = [MagicMock()]
        with patch("litellm.completion", return_value=mock_resp) as mock_comp:
            ok, msg = _probe_llm_reachability(
                "vertex_ai/claude-opus-5",
                {"vertex_project": "test-proj", "vertex_location": "us"},
                prompt="test",
                max_tokens=256,
                timeout=15.0,
            )
            self.assertTrue(ok)
            self.assertIn("verified", msg)
            mock_comp.assert_called_once()
            call_kwargs = mock_comp.call_args[1]
            self.assertEqual(call_kwargs["messages"], [{"role": "user", "content": "test"}])
            self.assertEqual(call_kwargs["max_tokens"], 256)
            self.assertEqual(call_kwargs["timeout"], 15.0)

        # 2. Probe failure with exception
        with patch("litellm.completion", side_effect=RuntimeError("Connection refused to vertex")):
            ok, msg = _probe_llm_reachability(
                "vertex_ai/claude-opus-5",
                {"vertex_project": "test-proj"},
            )
            self.assertFalse(ok)
            self.assertIn("Connection refused", msg)

        # 3. Preflight probe integration (probe=True vs probe=False)
        cfg = {
            "default_model": "vertex_ai/gemini-3.7-flash",
            "sandbox": {"type": "static-only"},
        }
        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "test-project"}):
            # Static check only (probe=False) does not call completion
            with patch("litellm.completion") as mock_comp:
                ok, msg = _check_llm_preflight(cfg, probe=False)
                self.assertTrue(ok)
                mock_comp.assert_not_called()

            # Active probe (probe=True) calls completion
            with patch("litellm.completion", return_value=mock_resp) as mock_comp:
                ok, msg = _check_llm_preflight(cfg, probe=True)
                self.assertTrue(ok)
                self.assertIn("Live probe: OK", msg)
                mock_comp.assert_called_once()

            # MANTIS_PROBE_LLM env var triggers probe
            with patch.dict(os.environ, {"MANTIS_PROBE_LLM": "1"}):
                with patch("litellm.completion", return_value=mock_resp) as mock_comp:
                    ok, msgs = run_preflight_checks(cfg)
                    self.assertTrue(ok)
                    self.assertTrue(any("Live probe: OK" in m for m in msgs))
                    mock_comp.assert_called_once()


        # 4. Probe 429 rate limit retry and recovery
        class Mock429(Exception):
            status_code = 429
            def __str__(self):
                return 'vertex_aiException - {"error": {"code": 429, "message": "Quota exceeded for aiplatform.googleapis.com/us_multi_region_online_prediction_input_tokens_per_minute_per_base_model with base model: anthropic-claude-opus-5.", "status": "RESOURCE_EXHAUSTED"}}'

        # Probe recovers after transient 429
        probe_calls = 0
        def _flaky_completion(*args, **kwargs):
            nonlocal probe_calls
            probe_calls += 1
            if probe_calls == 1:
                raise Mock429()
            return mock_resp

        with patch("litellm.completion", side_effect=_flaky_completion) as mock_comp, patch("time.sleep") as mock_sleep:
            ok, msg = _probe_llm_reachability(
                "vertex_ai/claude-opus-5",
                {"vertex_project": "test-proj"},
            )
            self.assertTrue(ok)
            self.assertIn("verified", msg)
            self.assertEqual(mock_comp.call_count, 2)
            mock_sleep.assert_called_once()
            self.assertGreaterEqual(mock_sleep.call_args[0][0], 5.0)

        # Probe persistent 429 returns verified reachability with rate-limit detail
        with patch("litellm.completion", side_effect=Mock429()) as mock_comp, patch("time.sleep"):
            ok, msg = _probe_llm_reachability(
                "vertex_ai/claude-opus-5",
                {"vertex_project": "test-proj"},
            )
            self.assertTrue(ok)
            self.assertIn("rate-limited", msg)
            self.assertIn("Quota exceeded", msg)
            self.assertEqual(mock_comp.call_count, 3)

    def test_39_resilient_llm_rate_limit_backoff(self):
        """Validates ResilientLiteLlm and ResilientLiteLLMClient full jitter backoff (min 5s offset, 1h patience) on 429 quota exhaustion."""
        from core.config import (
            is_rate_limit_error,
            extract_retry_after,
            extract_rate_limit_detail,
            compute_full_jitter_delay,
            ResilientLiteLLMClient,
            ResilientLiteLlm,
        )
        import litellm

        class MockQuotaExhausted(Exception):
            status_code = 429
            def __str__(self):
                return 'vertex_aiException - {"error": {"code": 429, "message": "Quota exceeded for aiplatform.googleapis.com/us_multi_region_online_prediction_input_tokens_per_minute_per_base_model with base model: anthropic-claude-opus-5.", "status": "RESOURCE_EXHAUSTED"}}'

        # 1. Full jitter calculation & min offset (5.0s) verification
        for _ in range(20):
            d0 = compute_full_jitter_delay(0, initial_delay=5.0, min_offset=5.0, max_delay=60.0)
            self.assertEqual(d0, 5.0)
            d1 = compute_full_jitter_delay(1, initial_delay=5.0, min_offset=5.0, max_delay=60.0)
            self.assertTrue(5.0 <= d1 <= 10.0)
            d2 = compute_full_jitter_delay(2, initial_delay=5.0, min_offset=5.0, max_delay=60.0)
            self.assertTrue(5.0 <= d2 <= 20.0)
            d5 = compute_full_jitter_delay(5, initial_delay=5.0, min_offset=5.0, max_delay=60.0)
            self.assertTrue(5.0 <= d5 <= 60.0)

        # Retry-After and max remaining patience capping
        d_retry = compute_full_jitter_delay(1, retry_after=12.0, min_offset=5.0, max_delay=60.0)
        self.assertTrue(d_retry >= 12.0)
        d_cap = compute_full_jitter_delay(5, max_remaining=3.5, min_offset=5.0, max_delay=60.0)
        self.assertEqual(d_cap, 3.5)

        # 2. Error classification helpers
        self.assertTrue(is_rate_limit_error(MockQuotaExhausted()))
        self.assertTrue(is_rate_limit_error(RuntimeError("429 RESOURCE_EXHAUSTED quota exceeded")))
        if hasattr(litellm, "RateLimitError"):
            try:
                rate_err = litellm.RateLimitError(
                    message="Rate limit exceeded",
                    model="anthropic-claude-opus-5",
                    llm_provider="vertex_ai",
                )
                self.assertTrue(is_rate_limit_error(rate_err))
            except Exception:
                pass
        self.assertFalse(is_rate_limit_error(RuntimeError("401 Unauthorized")))
        self.assertFalse(is_rate_limit_error(ValueError("Invalid syntax")))

        detail = extract_rate_limit_detail(MockQuotaExhausted())
        self.assertIn("us_multi_region_online_prediction_input_tokens_per_minute_per_base_model", detail)

        # 3. ResilientLiteLLMClient acompletion backoff and recovery
        client = ResilientLiteLLMClient()
        call_count = 0
        from litellm.types.utils import ModelResponse, Choices, Message
        mock_success = ModelResponse()
        mock_success.choices = [Choices(message=Message(content="Resilient reply"))]

        async def _mock_acompletion(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise MockQuotaExhausted()
            return mock_success

        with patch("litellm.acompletion", side_effect=_mock_acompletion), patch("asyncio.sleep") as mock_sleep:
            res = asyncio.run(
                client.acompletion(
                    model="vertex_ai/claude-opus-5",
                    messages=[{"role": "user", "content": "hello"}],
                )
            )
            self.assertEqual(res.choices[0].message.content, "Resilient reply")
            self.assertEqual(call_count, 3)
            self.assertEqual(mock_sleep.call_count, 2)
            for sleep_call in mock_sleep.call_args_list:
                self.assertGreaterEqual(sleep_call[0][0], 5.0)

        # 4. ResilientLiteLLMClient patience exhaustion test
        async def _mock_always_429(*args, **kwargs):
            raise MockQuotaExhausted()

        fake_time_seq = [0.0, 3605.0]
        with patch("litellm.acompletion", side_effect=_mock_always_429), patch("time.time", side_effect=lambda: fake_time_seq.pop(0) if fake_time_seq else 4000.0):
            with self.assertRaises(MockQuotaExhausted):
                asyncio.run(
                    client.acompletion(
                        model="vertex_ai/claude-opus-5",
                        messages=[{"role": "user", "content": "hello"}],
                    )
                )

        # 5. ResilientLiteLlm generate_content_async recovery
        llm = ResilientLiteLlm(model="vertex_ai/claude-opus-5")
        gen_calls = 0

        from google.adk.models import LlmRequest, LlmResponse
        from google.genai import types

        async def _mock_gen_acompletion(*args, **kwargs):
            nonlocal gen_calls
            gen_calls += 1
            if gen_calls == 1:
                raise MockQuotaExhausted()
            return mock_success

        with patch("litellm.acompletion", side_effect=_mock_gen_acompletion), patch("asyncio.sleep") as mock_sleep:
            req = types.Content(role="user", parts=[types.Part.from_text(text="audit")])
            llm_req = LlmRequest(model="vertex_ai/claude-opus-5", contents=[req])
            responses = []
            async def _consume():
                async for r in llm.generate_content_async(llm_req):
                    responses.append(r)
            asyncio.run(_consume())
            self.assertEqual(len(responses), 1)
            self.assertEqual(gen_calls, 2)
            self.assertEqual(mock_sleep.call_count, 1)
            self.assertGreaterEqual(mock_sleep.call_args[0][0], 5.0)

    def test_auth_error_handling_and_no_retry(self):
        """Validates that LLM auth errors (RefreshError, ADC expiry, invalid_grant)
        are cleanly detected, formatted into actionable user instructions without tracebacks,
        and fail immediately without retrying or opening browser popups."""
        import google.auth.exceptions
        import litellm
        from core.config import (
            MantisAuthError,
            is_auth_error,
            format_auth_error_message,
            ResilientLiteLLMClient,
            ResilientLiteLlm,
        )

        # 1. Verify reauth popup suppression
        import google.oauth2.reauth
        self.assertFalse(google.oauth2.reauth.is_interactive())

        import google.oauth2.credentials
        creds = google.oauth2.credentials.Credentials(token="fake-token")
        self.assertFalse(creds._enable_reauth_refresh)

        # 2. Verify is_auth_error detection
        refresh_err = google.auth.exceptions.RefreshError(
            "Reauthentication is needed. Please run 'gcloud auth application-default login' to reauthenticate."
        )
        self.assertTrue(is_auth_error(refresh_err))

        default_creds_err = google.auth.exceptions.DefaultCredentialsError(
            "Your default credentials were not found."
        )
        self.assertTrue(is_auth_error(default_creds_err))

        litellm_auth_err = litellm.AuthenticationError(
            "AuthenticationError: Invalid API Key provided",
            model="gemini-3.7-flash",
            llm_provider="vertex_ai",
        )
        self.assertTrue(is_auth_error(litellm_auth_err))

        # Wrapped exception detection
        wrapped = RuntimeError("ADK Runner execution failed")
        wrapped.__cause__ = refresh_err
        self.assertTrue(is_auth_error(wrapped))

        # Non-auth errors
        self.assertFalse(is_auth_error(ValueError("syntax error")))
        self.assertFalse(is_auth_error(RuntimeError("connection reset")))

        # 3. Verify format_auth_error_message content
        banner = format_auth_error_message(refresh_err, model="vertex_ai/gemini-3.7-flash")
        self.assertIn("AUTHENTICATION ERROR", banner)
        self.assertIn("gcloud auth application-default login", banner)
        self.assertIn("export GOOGLE_APPLICATION_CREDENTIALS", banner)
        self.assertNotIn("Traceback", banner)

        # 4. Verify ResilientLiteLLMClient raises MantisAuthError immediately without retrying
        client = ResilientLiteLLMClient()
        attempt_count = 0

        async def _mock_auth_fail(*args, **kwargs):
            nonlocal attempt_count
            attempt_count += 1
            raise refresh_err

        with patch("litellm.acompletion", side_effect=_mock_auth_fail), patch("asyncio.sleep") as mock_sleep:
            with self.assertRaises(MantisAuthError) as ctx:
                asyncio.run(
                    client.acompletion(
                        model="vertex_ai/gemini-3.7-flash",
                        messages=[{"role": "user", "content": "test"}],
                    )
                )
            self.assertEqual(attempt_count, 1)  # No retry!
            mock_sleep.assert_not_called()
            self.assertIn("gcloud auth application-default login", str(ctx.exception))

        # Synchronous completion raises MantisAuthError immediately
        sync_attempts = 0

        def _mock_sync_auth_fail(*args, **kwargs):
            nonlocal sync_attempts
            sync_attempts += 1
            raise refresh_err

        with patch("litellm.completion", side_effect=_mock_sync_auth_fail), patch("time.sleep") as mock_time_sleep:
            with self.assertRaises(MantisAuthError):
                client.completion(
                    model="vertex_ai/gemini-3.7-flash",
                    messages=[{"role": "user", "content": "test"}],
                )
            self.assertEqual(sync_attempts, 1)
            mock_time_sleep.assert_not_called()

        # 5. ResilientLiteLlm.generate_content_async raises MantisAuthError immediately
        llm = ResilientLiteLlm(model="vertex_ai/gemini-3.7-flash")
        from google.adk.models import LlmRequest
        from google.genai import types

        req = types.Content(role="user", parts=[types.Part.from_text(text="audit")])
        llm_req = LlmRequest(model="vertex_ai/gemini-3.7-flash", contents=[req])

        with patch("litellm.acompletion", side_effect=_mock_auth_fail), patch("asyncio.sleep") as mock_sleep:
            async def _consume():
                async for _ in llm.generate_content_async(llm_req):
                    pass
            with self.assertRaises(MantisAuthError):
                asyncio.run(_consume())
            mock_sleep.assert_not_called()

        # 6. Verify ExpectedErrorLoggingFilter suppresses tracebacks for MantisAuthError
        # and BudgetExceededError, while preserving full tracebacks for unexpected errors
        import logging
        from core.config import ExpectedErrorLoggingFilter
        from core.budget import BudgetExceededError

        filter_inst = ExpectedErrorLoggingFilter()

        # Auth error record with exc_info -> should be suppressed
        auth_record = logging.LogRecord(
            name="google_adk.google.adk.runners",
            level=logging.ERROR,
            pathname="runners.py",
            lineno=1065,
            msg="Root node test failed.",
            args=(),
            exc_info=(MantisAuthError, MantisAuthError("auth fail"), None),
        )
        self.assertFalse(filter_inst.filter(auth_record))

        # BudgetExceededError record with exc_info -> should be suppressed
        budget_err = BudgetExceededError(
            trigger="max_time",
            current_value=100.0,
            limit_value=50.0,
            run_id="run-1",
        )
        budget_record = logging.LogRecord(
            name="google_adk.google.adk.runners",
            level=logging.ERROR,
            pathname="runners.py",
            lineno=1065,
            msg="Root node test failed.",
            args=(),
            exc_info=(BudgetExceededError, budget_err, None),
        )
        self.assertFalse(filter_inst.filter(budget_record))

        # Unexpected error (e.g. ValueError) -> must NOT be suppressed!
        unexpected_record = logging.LogRecord(
            name="google_adk.google.adk.runners",
            level=logging.ERROR,
            pathname="runners.py",
            lineno=1065,
            msg="Root node test failed.",
            args=(),
            exc_info=(ValueError, ValueError("unexpected bug"), None),
        )
        self.assertTrue(filter_inst.filter(unexpected_record))

        # 7. Verify message-text matching filter for LiteLLM credential load failures
        msg_record = logging.LogRecord(
            name="LiteLLM",
            level=logging.ERROR,
            pathname="vertex_llm_base.py",
            lineno=485,
            msg="Failed to load vertex credentials: %s",
            args=("Reauthentication is needed. Please run `gcloud auth application-default login` to reauthenticate.",),
            exc_info=None,
        )
        self.assertFalse(filter_inst.filter(msg_record))

        # 8. Verify format_auth_error_message avoids duplicate banners
        double_banner = format_auth_error_message(Exception(banner))
        self.assertEqual(double_banner.count("❌ [AUTHENTICATION ERROR]"), 1)

        # 9. Verify ADK node retry hook prevents retrying on auth errors and budget errors
        from google.adk.workflow._retry_config import RetryConfig
        from google.adk.workflow._node_state import NodeState
        from google.adk.workflow.utils._retry_utils import _should_retry_node

        retry_cfg = RetryConfig(max_attempts=3)
        node_st = NodeState(attempt_count=1)

        self.assertFalse(_should_retry_node(refresh_err, retry_cfg, node_st))
        self.assertFalse(_should_retry_node(default_creds_err, retry_cfg, node_st))
        self.assertFalse(_should_retry_node(MantisAuthError("auth fail"), retry_cfg, node_st))
        self.assertFalse(_should_retry_node(budget_err, retry_cfg, node_st))
        self.assertTrue(_should_retry_node(ValueError("transient error"), retry_cfg, node_st))

    def test_token_refreshable_auth_error_and_single_refresh_retry(self):
        """Validates that expired access tokens (401 / expired) trigger a single automatic
        auth refresh and request retry, while unrecoverable auth failures do not retry."""
        import litellm
        from core.config import (
            is_token_refreshable_auth_error,
            clear_vertex_credential_caches,
            ResilientLiteLLMClient,
        )
        from litellm.llms.vertex_ai.vertex_llm_base import VertexBase

        # 1. Test is_token_refreshable_auth_error
        err_401 = litellm.AuthenticationError("401 Unauthorized", model="gemini", llm_provider="vertex_ai")
        err_401.status_code = 401
        self.assertTrue(is_token_refreshable_auth_error(err_401))

        err_expired = RuntimeError("The credentials are expired and could not be refreshed")
        self.assertTrue(is_token_refreshable_auth_error(err_expired))

        # Unrecoverable errors must return False
        err_reauth = RuntimeError("Reauthentication is needed. Please run 'gcloud auth application-default login'")
        self.assertFalse(is_token_refreshable_auth_error(err_reauth))

        err_api_key = litellm.AuthenticationError("Invalid API Key provided", model="gemini", llm_provider="vertex_ai")
        self.assertFalse(is_token_refreshable_auth_error(err_api_key))

        # 2. Test clear_vertex_credential_caches clears mapping across VertexBase instances
        vb = VertexBase()
        vb._credentials_project_mapping[("key", "proj")] = ("token", "proj")
        self.assertEqual(len(vb._credentials_project_mapping), 1)
        clear_vertex_credential_caches()
        self.assertEqual(len(vb._credentials_project_mapping), 0)

        # 3. Test ResilientLiteLLMClient retries once on refreshable 401 when try_refresh_auth succeeds
        client = ResilientLiteLLMClient()
        attempts = 0

        async def _mock_recovering_acompletion(*args, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                e = litellm.AuthenticationError("401 Unauthorized", model="gemini", llm_provider="vertex_ai")
                e.status_code = 401
                raise e
            return "ok"

        with patch("litellm.acompletion", side_effect=_mock_recovering_acompletion), \
             patch("core.config.try_refresh_auth", return_value=True) as mock_refresh:
            res = asyncio.run(
                client.acompletion(
                    model="vertex_ai/gemini-3.7-flash",
                    messages=[{"role": "user", "content": "test"}],
                )
            )
            self.assertEqual(res, "ok")
            self.assertEqual(attempts, 2)
            mock_refresh.assert_called_once()

    def test_strict_budget_parsing(self):
        """Verifies strict parsing for durations and token ceilings without silent fallbacks."""
        from core.budget import parse_duration_seconds, parse_token_budget, BudgetConfig

        # Valid durations
        self.assertEqual(parse_duration_seconds("1d"), 86400.0)
        self.assertEqual(parse_duration_seconds("2days"), 172800.0)
        self.assertEqual(parse_duration_seconds("12h"), 43200.0)
        self.assertEqual(parse_duration_seconds("30m"), 1800.0)
        self.assertEqual(parse_duration_seconds("3600s"), 3600.0)
        self.assertEqual(parse_duration_seconds(100), 100.0)

        # Invalid durations must raise ValueError
        for bad_val in ("100xyz", "2weeks", "-5s", "", None):
            with self.assertRaises(ValueError):
                parse_duration_seconds(bad_val)

        # Valid token budgets
        self.assertEqual(parse_token_budget("1B"), 1_000_000_000)
        self.assertEqual(parse_token_budget("2billion"), 2_000_000_000)
        self.assertEqual(parse_token_budget("10M"), 10_000_000)
        self.assertEqual(parse_token_budget("500k"), 500_000)
        self.assertEqual(parse_token_budget("10000"), 10000)
        self.assertEqual(parse_token_budget(5000), 5000)

        # Invalid token budgets must raise ValueError
        for bad_val in ("100xyz", "-10M", "", None):
            with self.assertRaises(ValueError):
                parse_token_budget(bad_val)

        # BudgetConfig.from_dict preserves defaults for omitted, but raises on invalid
        cfg = BudgetConfig.from_dict({"max_time": "1d", "token_budget": "1B"})
        self.assertEqual(cfg.max_wall_clock_seconds, 86400.0)
        self.assertEqual(cfg.max_tokens, 1_000_000_000)

        with self.assertRaises(ValueError):
            BudgetConfig.from_dict({"max_time": "bad_duration"})
        with self.assertRaises(ValueError):
            BudgetConfig.from_dict({"token_budget": "bad_tokens"})

    def test_resumption_invocation_scope(self):
        """Verifies intermediate node end_of_agent does not mark root invocation as ended."""
        from main import APP_NAME

        class MockAction:
            def __init__(self, end_of_agent: bool):
                self.end_of_agent = end_of_agent

        class MockEvent:
            def __init__(self, inv_id: str, author: str, end_of_agent: bool):
                self.invocation_id = inv_id
                self.author = author
                self.actions = MockAction(end_of_agent)

        inv_id = "inv-123"

        # 1. Intermediate nodes finished, but root pipeline did not emit end_of_agent
        events_paused = [
            MockEvent(inv_id, "history", True),
            MockEvent(inv_id, "architect", True),
            MockEvent(inv_id, "researcher", True),
            MockEvent(inv_id, "critic", False),  # paused mid-turn
        ]

        has_ended_paused = any(
            getattr(e, "invocation_id", None) == inv_id
            and getattr(getattr(e, "actions", None), "end_of_agent", False)
            and getattr(e, "author", None) in (APP_NAME, "mantis_vulnerability_pipeline")
            for e in events_paused
        )
        self.assertFalse(has_ended_paused, "Paused intermediate node must not mark invocation as ended")

        # 2. Root pipeline emitted end_of_agent (standard workflow)
        events_finished = list(events_paused) + [
            MockEvent(inv_id, "mantis_vulnerability_pipeline", True)
        ]
        has_ended_finished = any(
            getattr(e, "invocation_id", None) == inv_id
            and getattr(getattr(e, "actions", None), "end_of_agent", False)
            and getattr(e, "author", None) in ("mantis_vulnerability_pipeline",)
            for e in events_finished
        )
        self.assertTrue(has_ended_finished, "Root pipeline end_of_agent must mark invocation as ended")

        # 3. Synthesized/custom workflow root agent name
        custom_root_name = "workflow_audit_kernel_ioctl_handlers"
        events_synth_paused = [
            MockEvent(inv_id, "researcher", True),
            MockEvent(inv_id, "critic", False),
        ]
        has_ended_synth_paused = any(
            getattr(e, "invocation_id", None) == inv_id
            and getattr(getattr(e, "actions", None), "end_of_agent", False)
            and getattr(e, "author", None) in (custom_root_name, "mantis_vulnerability_pipeline")
            for e in events_synth_paused
        )
        self.assertFalse(has_ended_synth_paused)

        events_synth_finished = list(events_synth_paused) + [
            MockEvent(inv_id, custom_root_name, True)
        ]
        has_ended_synth_finished = any(
            getattr(e, "invocation_id", None) == inv_id
            and getattr(getattr(e, "actions", None), "end_of_agent", False)
            and getattr(e, "author", None) in (custom_root_name, "mantis_vulnerability_pipeline")
            for e in events_synth_finished
        )
        self.assertTrue(has_ended_synth_finished, "Synthesized workflow root agent end_of_agent must mark invocation as ended")

    def test_finding_file_attribution_and_repair(self):
        """Verifies canonical_filepath and write_findings repair missing filepaths from code_paths."""
        import tempfile
        from core.database import canonical_filepath, write_findings, read_findings, init_db
        from core.context import RunContext, current_run_context
        from tools.research_tools import report_findings

        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "test_k.db")
            init_db(db_file)
            repo_dir = os.path.join(td, "my_repo")
            os.makedirs(os.path.join(repo_dir, "core"), exist_ok=True)
            target_file = os.path.join(repo_dir, "core", "llm.py")
            with open(target_file, "w") as f:
                f.write("# code\n")

            ctx = RunContext(
                jail_dir=repo_dir,
                target_file=repo_dir,  # Repo-scope mode: target is directory!
                db_path=db_file,
                run_id="run-attr",
            )
            token = current_run_context.set(ctx)
            try:
                # 1. canonical_filepath on repo_dir must return empty string, NOT 'Users/...' or mangled path
                self.assertEqual(canonical_filepath(repo_dir), "")

                # 2. Finding with empty filepath but valid code_paths gets repaired
                f_unattributed = {
                    "title": "Boundary Escape",
                    "severity": "HIGH",
                    "description": "Flaw description",
                    "code_paths": ["core/llm.py:42"],
                }
                write_findings(db_file, repo_dir, [f_unattributed], run_id="run-attr")
                rows = read_findings(db_file, run_id="run-attr")
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["filepath"], "core/llm.py")
                self.assertEqual(rows[0]["line_numbers"], [42])

                # 3. report_findings returns validation feedback when filepath cannot be determined
                f_no_file = {
                    "title": "Abstract Flaw",
                    "severity": "LOW",
                    "description": "No code paths or file",
                    "filepath": "",
                    "code_paths": [],
                }
                res = report_findings({"findings": [f_no_file]})
                self.assertTrue(res.startswith("Error: Finding 'Abstract Flaw' has missing or invalid 'filepath'"))
            finally:
                current_run_context.reset(token)


class ShipAuditPreflightTests(unittest.TestCase):
    """Regression tests verifying resolution of the 5 Pre-Ship Audit findings."""

    def test_detect_vcs_info_annotations_and_tool_declaration(self):
        """Item 1: Verify typing imports and evaluation for detect_vcs_info."""
        import typing
        from tools.research_tools import detect_vcs_info
        from google.adk.tools.function_tool import FunctionTool

        hints = typing.get_type_hints(detect_vcs_info)
        self.assertIn("target_path", hints)
        self.assertIn("return", hints)

        tool = FunctionTool(detect_vcs_info)
        decl = tool._get_declaration()
        self.assertEqual(decl.name, "detect_vcs_info")

    def test_safe_markdown_fence_and_inline_escaping(self):
        """Item 2: Verify safe_markdown_fence prevents fence-break and safe_markdown_inline demotes headings."""
        from core.llm_gateway import safe_markdown_fence, safe_markdown_inline

        diff_with_backticks = "--- a/test.py\n+++ b/test.py\n@@ -1,2 +1,3 @@\n+```\n+# Injected Heading\n+```"
        fenced = safe_markdown_fence(diff_with_backticks, lang="diff")
        self.assertTrue(fenced.startswith("````diff\n"))
        self.assertTrue(fenced.endswith("\n````"))

        inlined = safe_markdown_inline("# Host Heading\nNormal line\n---")
        self.assertIn("> # Host Heading", inlined)
        self.assertIn("> ---", inlined)

    def test_static_confirmed_findings_visible_in_advisory(self):
        """Item 4: Verify static_confirmed findings are returned by query_security_guidance."""
        with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
            init_db(tmp.name)
            conn = sqlite3.connect(tmp.name)
            conn.execute(
                "INSERT INTO findings (id, run_id, title, severity, filepath, line_numbers, status, description, remediation) "
                "VALUES (1, 'run_static', 'Command Injection', 'CRITICAL', 'api/exec.py', '[\"10\"]', 'static_confirmed', 'popen flaw', 'use argv')"
            )
            conn.commit()
            conn.close()

            from core.database import query_security_guidance
            guidance = query_security_guidance(tmp.name, filepath="api/exec.py")
            summary = guidance.get("guidance_summary", "")
            self.assertIn("Command Injection", summary)
            self.assertIn("static_confirmed", summary)
            self.assertEqual(len(guidance.get("confirmed_vulnerabilities", [])), 1)

    def test_inject_active_findings_state_non_mutation_and_dedup(self):
        """Item 5: Verify _inject_active_findings_state does not mutate session dicts in place and dedups cleanly."""
        from google.genai import types
        from core.config import ResilientLiteLlm

        with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
            init_db(tmp.name)
            conn = sqlite3.connect(tmp.name)
            conn.execute(
                "INSERT INTO findings (id, run_id, title, severity, filepath, line_numbers, status) "
                "VALUES (1, 'run_dedup', 'SQL Injection in Auth\nMultiline title', 'HIGH', 'src/auth.py', '[\"42\"]', 'static_confirmed')"
            )
            conn.commit()
            conn.close()

            ctx = RunContext(jail_dir=".", db_path=tmp.name, run_id="run_dedup")
            tok = current_run_context.set(ctx)
            try:
                orig_resp = {"output": "original tool result"}
                fr_part = types.Part(
                    function_response=types.FunctionResponse(name="read_file", response=orig_resp)
                )
                content = types.Content(role="user", parts=[fr_part])

                class MockReq:
                    contents = [content]

                req = MockReq()
                ResilientLiteLlm._inject_active_findings_state(req)

                # 1. Original response dict MUST NOT be mutated in place
                self.assertEqual(orig_resp["output"], "original tool result")

                # 2. Request part got state block with scrubbed title
                new_resp = req.contents[0].parts[0].function_response.response
                self.assertIn("[STATE STORE: RECORDED FINDINGS", str(new_resp))
                self.assertNotIn("Multiline title\n", str(new_resp))

                # 3. Repeated dispatch dedup
                ResilientLiteLlm._inject_active_findings_state(req)
                count = str(req.contents[0].parts[0].function_response.response).count("[STATE STORE: RECORDED FINDINGS")
                self.assertEqual(count, 1)
            finally:
                current_run_context.reset(tok)


if __name__ == "__main__":
    unittest.main()



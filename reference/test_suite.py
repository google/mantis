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

from core.config import get_llm_kwargs, DEFAULT_MODEL, DEFAULT_EMBEDDING_MODEL
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
    _db,
)
from core.embeddings import (
    vector_to_blob,
    blob_to_vector,
    cosine_similarity,
    compute_embedding,
    compute_mock_embedding,
    get_embedding_kwargs,
    find_nearest_lineage,
    DEFAULT_SIMILARITY_THRESHOLD,
    normalize_cwe,
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
                    "Summary generated.",
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
                    "history", "structural_index", "summarizer", "architect", "threat_modeler",
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
                    "Summary generated.",
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
                    "history", "structural_index", "summarizer", "architect", "threat_modeler",
                    "planner", "researcher", "deduplicator", "reviewer", "reviewer_classifier",
                    "calibrator", "reflector", "reporter"
                ],
                "reported"
            ),
            # Script 3: Repro fails, retries once, exceeds max_visits -> calibrator -> static_confirmed
            (
                [
                    "History extracted.",
                    "Structural index built.",
                    "Summary generated.",
                    "Architecture KB created.",
                    "Threat model created.",
                    "Plan created.",
                    "Found logic bug.",
                    "Findings deduplicated.",
                    json.dumps({"route": "confirmed", "reason": "Analysis done."}),
                    json.dumps({"route": "viable", "reason": "Exploit is viable."}),
                    json.dumps({"route": "failed_repro", "reason": "Exploit attempt 1 failed."}),  # repro 1
                    json.dumps({"route": "failed_repro", "reason": "Exploit attempt 2 failed."}),  # repro 2 (retry)
                    "Calibration score: 15",
                    "Learnings reflected.",
                    "Report generated.",
                ],
                [
                    "history", "structural_index", "summarizer", "architect", "threat_modeler",
                    "planner", "researcher", "deduplicator", "reviewer", "reviewer_classifier",
                    "critic", "critic_classifier", "reproducer", "repro_classifier",
                    "reproducer", "repro_classifier", "calibrator", "reflector", "reporter"
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
                    "Summary generated.",
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
                    "Summary generated.",
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
                    "Summary generated.",
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
                self.assertEqual(await read_file("inside.txt"), "content_inside")
                self.assertIn("Permission denied", await read_file("../outside.txt"))
                self.assertIn("Permission denied", await read_file(outside_file))
                self.assertIn("File not found", await read_file("missing.txt"))
            finally:
                current_run_context.reset(tok)

            # 5. Test read_file tool with direct host fallback (no sandbox)
            ctx_host = RunContext(jail_dir=jail_dir, db_path="", target_file=inside_file, sandbox=None)
            tok = current_run_context.set(ctx_host)
            try:
                self.assertEqual(await read_file("inside.txt"), "content_inside")
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
            self.assertEqual(mock_subproc_patch.call_args[1].get("input"), b"diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n")

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

    def test_vector_serialization_deserialization_roundtrip(self):
        """Tests vector serialization to blob and deserialization back to floats across boundary conditions."""
        # 1. Standard float vector
        orig = [0.123456, -0.789012, 0.0, 1.5, -3.14159, 42.0]
        blob = vector_to_blob(orig)
        self.assertIsInstance(blob, bytes)
        self.assertEqual(len(blob), len(orig) * 4)
        restored = blob_to_vector(blob)
        self.assertEqual(len(restored), len(orig))
        for a, b in zip(orig, restored):
            self.assertAlmostEqual(a, b, places=5)

        # 2. Large dimensional vector (768 & 256 dims)
        for dim in (256, 768):
            large_vec = [float(i) * 0.001 for i in range(dim)]
            blob_large = vector_to_blob(large_vec)
            restored_large = blob_to_vector(blob_large)
            self.assertEqual(len(restored_large), dim)
            for a, b in zip(large_vec, restored_large):
                self.assertAlmostEqual(a, b, places=5)

        # 3. Tuple and iterable inputs
        tup_orig = (1.0, 2.5, -3.0)
        blob_tup = vector_to_blob(tup_orig)
        self.assertEqual(blob_to_vector(blob_tup), [1.0, 2.5, -3.0])

        # 4. Empty vector and None
        self.assertEqual(vector_to_blob([]), b"")
        self.assertEqual(vector_to_blob(None), b"")
        self.assertEqual(blob_to_vector(b""), [])
        self.assertEqual(blob_to_vector(None), [])

        # 5. Malformed or truncated byte sequences (e.g. 1, 3, 5, 7 bytes) - must not raise struct.error
        for bad_len in (1, 2, 3, 5, 6, 7, 9):
            corrupt_blob = b"\x00" * bad_len
            parsed = blob_to_vector(corrupt_blob)
            self.assertIsInstance(parsed, list)
            self.assertEqual(len(parsed), bad_len // 4)

    def test_cosine_similarity_computation(self):
        """Tests fast in-process cosine similarity calculation across boundary and error conditions."""
        # Identical vectors -> 1.0
        v1 = [1.0, 2.0, 3.0, 4.0]
        self.assertAlmostEqual(cosine_similarity(v1, v1), 1.0, places=5)

        # Scaled identical direction -> 1.0
        v2 = [2.0, 4.0, 6.0, 8.0]
        self.assertAlmostEqual(cosine_similarity(v1, v2), 1.0, places=5)

        # Orthogonal vectors -> 0.0
        v_ortho_a = [1.0, 0.0]
        v_ortho_b = [0.0, 1.0]
        self.assertAlmostEqual(cosine_similarity(v_ortho_a, v_ortho_b), 0.0, places=5)

        # Opposite vectors -> -1.0
        v_opp_a = [1.0, -2.0]
        v_opp_b = [-1.0, 2.0]
        self.assertAlmostEqual(cosine_similarity(v_opp_a, v_opp_b), -1.0, places=5)

        # Degenerate cases (empty, zero norm, dimension mismatch) -> 0.0
        self.assertEqual(cosine_similarity([], [1.0]), 0.0)
        self.assertEqual(cosine_similarity([0.0, 0.0], [1.0, 1.0]), 0.0)
        self.assertEqual(cosine_similarity([1.0, 2.0], [1.0, 2.0, 3.0]), 0.0)

        # NaN and Inf resilience -> 0.0
        self.assertEqual(cosine_similarity([float("nan"), 1.0], [1.0, 1.0]), 0.0)
        self.assertEqual(cosine_similarity([float("inf"), 1.0], [1.0, 1.0]), 0.0)

    def test_get_embedding_kwargs_precedence_and_config(self):
        """Tests embedding model and client parameter resolution across function args, config dict, and environment variables."""
        # 1. Default model
        with patch.dict(os.environ, {}, clear=True):
            model, kwargs = get_embedding_kwargs()
            self.assertEqual(model, DEFAULT_EMBEDDING_MODEL)

        # 2. Config dictionary precedence
        cfg = {
            "embedding_model": "vertex_ai/gemini-custom-emb",
            "api_base": "http://localhost:8000/v1",
            "timeout": 45.0,
            "api_key": "test-key-123",
            "vertex_project": "proj-cfg",
            "vertex_location": "us-east4",
        }
        with patch.dict(os.environ, {"EMBEDDING_MODEL": "env-model"}):
            model, kwargs = get_embedding_kwargs(config=cfg)
            self.assertEqual(model, "vertex_ai/gemini-custom-emb")
            self.assertEqual(kwargs["api_base"], "http://localhost:8000/v1")
            self.assertEqual(kwargs["timeout"], 45.0)
            self.assertEqual(kwargs["api_key"], "test-key-123")
            self.assertEqual(kwargs["vertex_project"], "proj-cfg")
            self.assertEqual(kwargs["vertex_location"], "us-east4")

        # 3. Direct function argument overrides config dict
        model, kwargs = get_embedding_kwargs(
            model="openai/text-embedding-3-small",
            api_base="http://custom:9000/v1",
            timeout=10.0,
            api_key="override-key",
            config=cfg,
        )
        self.assertEqual(model, "openai/text-embedding-3-small")
        self.assertEqual(kwargs["api_base"], "http://custom:9000/v1")
        self.assertEqual(kwargs["timeout"], 10.0)
        self.assertEqual(kwargs["api_key"], "override-key")

        # 4. Bare gemini embedding model auto-routes to vertex_ai when GCP project is available
        with patch.dict(os.environ, {"VERTEXAI_PROJECT": "gcp-proj", "GOOGLE_CLOUD_PROJECT": "gcp-proj"}):
            model, kwargs = get_embedding_kwargs(model="gemini-embedding-001")
            self.assertEqual(model, "vertex_ai/gemini-embedding-001")
            self.assertEqual(kwargs["vertex_project"], "gcp-proj")

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

    def test_semantic_embeddings_positive_controls(self):
        """Tests that semantically equivalent findings with different phrasing/logs merge into the same lineage (similarity >= 0.88)."""
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_pos_controls.db")
        try:
            init_db(db_file)

            # Positive Control 1: SQL Injection phrasing variations in services/user/routes.py
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

            rca1 = generate_rca_summary(f1_pos)
            rca2 = generate_rca_summary(f2_pos)
            v1 = compute_embedding(rca1, mock_mode=True)
            v2 = compute_embedding(rca2, mock_mode=True)
            sim_pos = cosine_similarity(v1, v2)
            self.assertGreaterEqual(sim_pos, 0.88, f"Positive control failed threshold 0.88 (got {sim_pos})")

            # Positive Control 2: Insecure Deserialization phrasing variations in services/cart/session.py
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
            rca_d1 = generate_rca_summary(f1_deser)
            rca_d2 = generate_rca_summary(f2_deser)
            v_d1 = compute_embedding(rca_d1, mock_mode=True)
            v_d2 = compute_embedding(rca_d2, mock_mode=True)
            sim_deser = cosine_similarity(v_d1, v_d2)
            self.assertGreaterEqual(sim_deser, 0.88, f"Deserialization positive control failed threshold 0.88 (got {sim_deser})")

            # Verify end-to-end lineage resolution merges positive controls into same lineage_id
            write_findings(db_file, f1_pos["filepath"], [f1_pos], run_id="run-pos-1")
            write_findings(db_file, f2_pos["filepath"], [f2_pos], run_id="run-pos-2")

            r1 = read_findings(db_file, filepath="services/user/routes.py", run_id="run-pos-1")
            r2 = read_findings(db_file, filepath="services/user/routes.py", run_id="run-pos-2")
            self.assertEqual(len(r1), 1)
            self.assertEqual(len(r2), 1)
            self.assertEqual(r1[0]["lineage_id"], r2[0]["lineage_id"])
        finally:
            shutil.rmtree(temp_dir)

    def test_semantic_embeddings_negative_controls(self):
        """Tests that distinct vulnerability classes maintain low similarity (< 0.70) and never false-merge."""
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

            rca_sqli = generate_rca_summary(f_sqli)
            rca_cmdi = generate_rca_summary(f_cmdi)
            v_sqli = compute_embedding(rca_sqli, mock_mode=True)
            v_cmdi = compute_embedding(rca_cmdi, mock_mode=True)
            sim_distinct = cosine_similarity(v_sqli, v_cmdi)
            self.assertLess(sim_distinct, 0.70, f"Negative control failed: similarity {sim_distinct} >= 0.70")

            # Negative Control 2: Stored XSS vs Reflected XSS in same file (Finding 301 vs 302)
            dataset_path = os.path.join(os.path.dirname(__file__), "evals", "synthetic_dataset.json")
            with open(dataset_path, "r", encoding="utf-8") as f:
                syn = json.load(f)
            id_to_finding = {f["id"]: f for f in syn["findings"]}

            f301 = id_to_finding[301]
            f302 = id_to_finding[302]
            rca301 = generate_rca_summary(f301)
            rca302 = generate_rca_summary(f302)
            v301 = compute_embedding(rca301, mock_mode=True)
            v302 = compute_embedding(rca302, mock_mode=True)
            sim_xss = cosine_similarity(v301, v302)
            self.assertLess(sim_xss, 0.70, f"XSS negative control failed: similarity {sim_xss} >= 0.70")

            # Negative Control 3: Timing side-channel vs Token expiration in auth/token.py (Finding 401 vs 402)
            f401 = id_to_finding[401]
            f402 = id_to_finding[402]
            rca401 = generate_rca_summary(f401)
            rca402 = generate_rca_summary(f402)
            v401 = compute_embedding(rca401, mock_mode=True)
            v402 = compute_embedding(rca402, mock_mode=True)
            sim_auth = cosine_similarity(v401, v402)
            self.assertLess(sim_auth, 0.70, f"Auth negative control failed: similarity {sim_auth} >= 0.70")

            # Verify in SQLite database: they produce distinct lineage IDs and never false-merge
            write_findings(db_file, f_sqli["filepath"], [f_sqli], run_id="run-neg-1")
            write_findings(db_file, f_cmdi["filepath"], [f_cmdi], run_id="run-neg-2")

            r_sqli = read_findings(db_file, filepath="services/user/routes.py", run_id="run-neg-1")
            r_cmdi = read_findings(db_file, filepath="services/user/routes.py", run_id="run-neg-2")
            self.assertNotEqual(r_sqli[0]["lineage_id"], r_cmdi[0]["lineage_id"])
        finally:
            shutil.rmtree(temp_dir)

    def test_offline_mock_embedding_mode_deterministic_execution(self):
        """Tests deterministic embedding computation in offline/mock mode without network or credentials."""
        text = (
            "Component: api/v1/auth.py\n"
            "Vulnerability Class: CWE-287\n"
            "Root Cause Mechanism: Missing JWT signature validation\n"
            "Failure Condition: Attacker supplies unsigned token\n"
            "Taint Dataflow: token -> verify_token -> auth_context"
        )
        # Compute multiple times in mock mode
        v1 = compute_embedding(text, mock_mode=True)
        v2 = compute_embedding(text, mock_mode=True)
        self.assertEqual(len(v1), 256)
        self.assertEqual(v1, v2)

        # Verify environment variable override
        with patch.dict(os.environ, {"MOCK_EMBEDDINGS": "1"}):
            v_env = compute_embedding(text)
            self.assertEqual(v_env, v1)

        with patch.dict(os.environ, {"MANTIS_OFFLINE_EMBEDDINGS": "1"}):
            v_offline = compute_embedding(text)
            self.assertEqual(v_offline, v1)

    def test_3_tier_deduplication_ladder_integration(self):
        """Tests end-to-end integration across Tier 1 (Exact Anchors), Tier 2 (RCA), and Tier 3 (Vector Similarity)."""
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_3tier_ladder.db")
        try:
            init_db(db_file)

            # Tier 1 exact match test
            f_base = {
                "title": "SQL Injection in get_user",
                "severity": "HIGH",
                "filepath": "app.py",
                "description": "User input passed to database query in get_user()",
                "line_numbers": [10],
                "cwe": "CWE-89",
            }
            write_findings(db_file, "app.py", [f_base], run_id="run-base")
            r_base = read_findings(db_file, filepath="app.py", run_id="run-base")
            base_lineage = r_base[0]["lineage_id"]
            self.assertTrue(base_lineage)
            self.assertTrue(r_base[0]["rca_summary"])
            self.assertTrue(r_base[0]["embedding"])

            # Verify lineage_vectors table was populated
            with _db(db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT lineage_id, rca_summary, embedding FROM lineage_vectors WHERE lineage_id = ?", (base_lineage,))
                lv_row = cursor.fetchone()
                self.assertIsNotNone(lv_row)
                self.assertEqual(lv_row["lineage_id"], base_lineage)
                self.assertTrue(len(lv_row["embedding"]) > 0)

            # Tier 3 vector nearest neighbor match
            with _db(db_file) as conn:
                cursor = conn.cursor()
                query_vec = r_base[0]["embedding"]
                nearest_lid = find_nearest_lineage(cursor, query_vec, threshold=0.90, filepath="app.py")
                self.assertEqual(nearest_lid, base_lineage)

                # Path normalization resilience (./app.py and None)
                nearest_rel = find_nearest_lineage(cursor, query_vec, threshold=0.90, filepath="./app.py")
                self.assertEqual(nearest_rel, base_lineage)
                nearest_none_fp = find_nearest_lineage(cursor, query_vec, threshold=0.90, filepath=None)
                self.assertEqual(nearest_none_fp, base_lineage)

                # Dimension mismatch between query vector and DB vector returns None safely
                dim_mismatch_vec = [1.0] * 512
                self.assertIsNone(find_nearest_lineage(cursor, dim_mismatch_vec, threshold=0.90, filepath="app.py"))

                # Query with distinct vector -> should return None
                dummy_vec = [-x for x in query_vec]
                none_lid = find_nearest_lineage(cursor, dummy_vec, threshold=0.90, filepath="app.py")
                self.assertIsNone(none_lid)
        finally:
            shutil.rmtree(temp_dir)

    def test_embedding_fallback_explicit_warning(self):
        """Tests that live embedding failures emit a visible ⚠️ [EMBEDDING FALLBACK] warning to stderr and degrade cleanly to mock."""
        import io
        from contextlib import redirect_stderr
        import core.embeddings as emb_mod

        # Reset warned state for test
        emb_mod._WARNED_FALLBACK = False

        err_stream = io.StringIO()
        with redirect_stderr(err_stream):
            with patch("litellm.embedding", side_effect=RuntimeError("Simulated network/auth timeout")):
                vec = compute_embedding("Component: app.py\nRoot Cause: Test flaw", mock_mode=False)
        
        err_output = err_stream.getvalue()
        self.assertIn("⚠️  [EMBEDDING FALLBACK]", err_output)
        self.assertIn("Simulated network/auth timeout", err_output)
        self.assertEqual(len(vec), 256)

    def test_embedding_dimension_mismatch_warning(self):
        """Tests that dimension mismatches between query and stored vectors emit ⚠️ [EMBEDDING MISMATCH] warning."""
        import io
        from contextlib import redirect_stderr
        import core.embeddings as emb_mod

        emb_mod._WARNED_DIM_MISMATCH = False
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_dim_mismatch.db")
        try:
            init_db(db_file)
            with _db(db_file) as conn:
                cur = conn.cursor()
                # Insert a 256-dim mock vector
                mock_blob = vector_to_blob([0.1] * 256)
                cur.execute(
                    "INSERT INTO lineage_vectors (lineage_id, filepath, model, dimension, embedding) VALUES (?, ?, ?, ?, ?)",
                    ("lin-old", "app.py", "mock", 256, mock_blob),
                )
                
                # Query with 512-dim vector
                err_stream = io.StringIO()
                with redirect_stderr(err_stream):
                    res = find_nearest_lineage(cur, [0.1] * 512, filepath="app.py")
                
                self.assertIsNone(res)
                err_output = err_stream.getvalue()
                self.assertIn("⚠️  [EMBEDDING MISMATCH]", err_output)
                self.assertIn("Stored lineage vectors have dimension 256", err_output)
        finally:
            shutil.rmtree(temp_dir)

    def test_cwe_structural_guard_prevents_false_merge(self):
        """Tests that distinct, incompatible CWE classifications skip vector comparison and prevent false merges even with 0.99+ similarity."""
        # Verify normalize_cwe helper directly across various representations
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
        self.assertIsNone(normalize_cwe("N/A"))

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
                query_vec = findings[0]["embedding"]
                # Query with exact same vector (cosine similarity 1.0 > 0.99) but distinct CWE-78 (Command Injection)
                res_diff_cwe = find_nearest_lineage(cur, query_vec, filepath="app.py", cwe="CWE-78")
                self.assertIsNone(res_diff_cwe)

                # Query with distinct Deserialization CWE-502
                res_deser_cwe = find_nearest_lineage(cur, query_vec, filepath="app.py", cwe="CWE-502")
                self.assertIsNone(res_deser_cwe)

                # Query with matching CWE-89 succeeds
                res_same_cwe = find_nearest_lineage(cur, query_vec, filepath="app.py", cwe="CWE-89")
                self.assertEqual(res_same_cwe, sqli_lid)

                # Query with case/format variant cwe-89 succeeds
                res_norm_cwe = find_nearest_lineage(cur, query_vec, filepath="app.py", cwe="cwe-89")
                self.assertEqual(res_norm_cwe, sqli_lid)

                # Query with integer 89 succeeds
                res_int_cwe = find_nearest_lineage(cur, query_vec, filepath="app.py", cwe=89)
                self.assertEqual(res_int_cwe, sqli_lid)

                # Query with unknown CWE allows fallback to vector similarity
                res_unknown_cwe = find_nearest_lineage(cur, query_vec, filepath="app.py", cwe="CWE-UNKNOWN")
                self.assertEqual(res_unknown_cwe, sqli_lid)

                # Test resolve_ancestor_lineage end-to-end: distinct CWE mints new lineage ID
                new_lid = resolve_ancestor_lineage(
                    cur,
                    filepath="app.py",
                    signature="diff_sig_cmdi",
                    cwe="CWE-78",
                    symbol="exec_cmd",
                    title="Command Injection in exec_cmd",
                    description="Unsanitized command execution",
                    embedding=query_vec,
                )
                self.assertNotEqual(new_lid, sqli_lid)
        finally:
            shutil.rmtree(temp_dir)

    def test_dynamic_embedding_similarity_threshold_env(self):
        """Tests that EMBEDDING_SIMILARITY_THRESHOLD dynamically affects resolve_ancestor_lineage and find_nearest_lineage."""
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_dynamic_threshold.db")
        try:
            init_db(db_file)
            vec_a = [1.0] + [0.0] * 255
            # Orthogonal / slightly correlated vector with cosine similarity ~ 0.707
            vec_b = [0.7071, 0.7071] + [0.0] * 254

            with _db(db_file) as conn:
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO lineage_vectors (lineage_id, filepath, cwe, model, dimension, embedding) VALUES (?, ?, ?, ?, ?, ?)",
                    ("lid-baseline", "app.py", "CWE-89", "mock", 256, vector_to_blob(vec_a)),
                )

                # 1. Under default threshold (0.90), similarity ~0.707 does NOT match
                res_default = find_nearest_lineage(cur, vec_b, filepath="app.py", cwe="CWE-89")
                self.assertIsNone(res_default)

                # 2. Dynamically set EMBEDDING_SIMILARITY_THRESHOLD to 0.50 -> matches
                with patch.dict(os.environ, {"EMBEDDING_SIMILARITY_THRESHOLD": "0.50"}):
                    res_low = find_nearest_lineage(cur, vec_b, filepath="app.py", cwe="CWE-89")
                    self.assertEqual(res_low, "lid-baseline")

                    # Also verify resolve_ancestor_lineage inherits under dynamic threshold
                    res_resolve = resolve_ancestor_lineage(
                        cur,
                        filepath="app.py",
                        signature="sig-b",
                        cwe="CWE-89",
                        symbol="sym_b",
                        title="SQL flaw",
                        description="desc",
                        embedding=vec_b,
                    )
                    self.assertEqual(res_resolve, "lid-baseline")

                # 3. Explicit parameter overrides environment variable
                with patch.dict(os.environ, {"EMBEDDING_SIMILARITY_THRESHOLD": "0.50"}):
                    res_explicit = find_nearest_lineage(cur, vec_b, threshold=0.95, filepath="app.py", cwe="CWE-89")
                    self.assertIsNone(res_explicit)

                # 4. Invalid / malformed environment variable gracefully falls back to default
                with patch.dict(os.environ, {"EMBEDDING_SIMILARITY_THRESHOLD": "invalid_float"}):
                    res_invalid = find_nearest_lineage(cur, vec_b, filepath="app.py", cwe="CWE-89")
                    self.assertIsNone(res_invalid)

                # 5. Module-level import resilience when EMBEDDING_SIMILARITY_THRESHOLD='high' or out of range (-3, 2.5)
                import importlib
                import io
                from contextlib import redirect_stderr
                import core.embeddings as emb_mod
                with patch.dict(os.environ, {"EMBEDDING_SIMILARITY_THRESHOLD": "high"}):
                    err_stream = io.StringIO()
                    with redirect_stderr(err_stream):
                        importlib.reload(emb_mod)
                    self.assertEqual(emb_mod.DEFAULT_SIMILARITY_THRESHOLD, 0.90)
                    self.assertIn("Invalid EMBEDDING_SIMILARITY_THRESHOLD='high'", err_stream.getvalue())

                # Out-of-range negative threshold (-3) must warn and fall back to 0.90 (never clamp to -1.0)
                with patch.dict(os.environ, {"EMBEDDING_SIMILARITY_THRESHOLD": "-3"}):
                    err_stream = io.StringIO()
                    with redirect_stderr(err_stream):
                        importlib.reload(emb_mod)
                    self.assertEqual(emb_mod.DEFAULT_SIMILARITY_THRESHOLD, 0.90)
                    self.assertIn("is outside valid range [0.0, 1.0]", err_stream.getvalue())

                # Out-of-range positive threshold (2.5) must warn and fall back to 0.90
                with patch.dict(os.environ, {"EMBEDDING_SIMILARITY_THRESHOLD": "2.5"}):
                    err_stream = io.StringIO()
                    with redirect_stderr(err_stream):
                        importlib.reload(emb_mod)
                    self.assertEqual(emb_mod.DEFAULT_SIMILARITY_THRESHOLD, 0.90)
                    self.assertIn("is outside valid range [0.0, 1.0]", err_stream.getvalue())

                # Restore default module state
                importlib.reload(emb_mod)
        finally:
            shutil.rmtree(temp_dir)

    def test_warn_dim_mismatch_outputs_model_name_from_sqlite(self):
        """Tests that _warn_dim_mismatch accurately prints the stored model name from SQLite records."""
        import io
        from contextlib import redirect_stderr
        import core.embeddings as emb_mod

        emb_mod._WARNED_DIM_MISMATCH = False
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "test_model_mismatch.db")
        try:
            init_db(db_file)
            with _db(db_file) as conn:
                cur = conn.cursor()
                mock_blob = vector_to_blob([0.1] * 3072)
                cur.execute(
                    "INSERT INTO lineage_vectors (lineage_id, filepath, cwe, model, dimension, embedding) VALUES (?, ?, ?, ?, ?, ?)",
                    ("lin-vertex", "app.py", "CWE-89", "vertex_ai/gemini-embedding-001", 3072, mock_blob),
                )

                err_stream = io.StringIO()
                with redirect_stderr(err_stream):
                    res = find_nearest_lineage(cur, [0.1] * 256, filepath="app.py", cwe="CWE-89")

                self.assertIsNone(res)
                err_output = err_stream.getvalue()
                self.assertIn("⚠️  [EMBEDDING MISMATCH]", err_output)
                self.assertIn("Stored lineage vectors have dimension 3072 (model: 'vertex_ai/gemini-embedding-001')", err_output)
                self.assertIn("while query vector has dimension 256", err_output)
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

    def test_global_config_forbids_unknown_fields(self):
        """Ensures GlobalConfig extra='forbid' still rejects unrecognized fields."""
        with self.assertRaises(Exception):
            GlobalConfig(unknown_field="invalid")

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
            "Summary generated.",
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

    def test_schema_codegen_single_source_of_truth(self):
        """Verifies that schema.json is the single source of truth and codegen produces valid Pydantic models."""
        from scripts.generate_schemas import SCHEMA_JSON_PATH, generate_pydantic_code
        self.assertTrue(SCHEMA_JSON_PATH.exists(), f"schema.json must exist at {SCHEMA_JSON_PATH}")

        with open(SCHEMA_JSON_PATH, "r", encoding="utf-8") as f:
            schema_data = json.load(f)

        self.assertIn("$defs", schema_data)
        self.assertIn("finding", schema_data["$defs"])
        self.assertIn("plan", schema_data["$defs"])
        self.assertIn("learning_entry", schema_data["$defs"])

        code = generate_pydantic_code(schema_data)
        self.assertIn("class FindingSchema(BaseModel):", code)
        self.assertIn("class PlanSchema(BaseModel):", code)
        self.assertIn("VulnerabilityFinding = FindingSchema", code)
        self.assertIn("ReviewPlan = PlanSchema", code)
        self.assertIn("LearningEntry = LearningEntrySchema", code)
        self.assertIn("class ReviewVerdict(BaseModel):", code)

    def test_schema_codegen_ast_and_property_coverage(self):
        """Verifies that generated code parses into valid Python AST and covers all schema.json $defs."""
        from scripts.generate_schemas import SCHEMA_JSON_PATH, generate_pydantic_code
        with open(SCHEMA_JSON_PATH, "r", encoding="utf-8") as f:
            schema_data = json.load(f)

        code = generate_pydantic_code(schema_data)
        parsed_ast = ast.parse(code)
        self.assertIsNotNone(parsed_ast)

        # Verify class definitions generated from $defs
        class_names = [node.name for node in ast.walk(parsed_ast) if isinstance(node, ast.ClassDef)]
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
            self.assertIn(cls_name, class_names, f"Expected {cls_name} to be generated by codegen")

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

    def test_schema_codegen_dynamic_schema_evolution(self):
        """Verifies that adding new definitions or properties to schema.json dynamically generates matching models."""
        from scripts.generate_schemas import generate_pydantic_code
        mock_schema_data = {
            "$defs": {
                "finding": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "title": {"type": "string"},
                        "exploit_maturity": {"type": "string", "enum": ["poc", "functional", "high"]}
                    }
                },
                "custom_diagnostic_result": {
                    "type": "object",
                    "description": "Diagnostic evaluation metric generated during custom audit stages.",
                    "properties": {
                        "check_id": {"type": "string"},
                        "passed": {"type": "boolean"},
                        "score": {"type": "number"}
                    },
                    "required": ["check_id", "passed"]
                }
            }
        }
        gen_code = generate_pydantic_code(mock_schema_data)
        parsed = ast.parse(gen_code)
        self.assertIsNotNone(parsed)

        # Verify dynamic class generation from the new definition
        self.assertIn("class CustomDiagnosticResultSchema(BaseModel):", gen_code)
        self.assertIn("check_id: str = Field()", gen_code)
        self.assertIn("passed: bool = Field()", gen_code)
        self.assertIn("score: Optional[float] = Field(default=None)", gen_code)
        # Verify dynamic property generation on finding
        self.assertIn("exploit_maturity: Optional[Literal[\"poc\", \"functional\", \"high\"]]", gen_code)

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
        """Validates loading an agent configured with system_prompt (prompts/system-researcher.md) without a skill."""
        temp_dir = tempfile.mkdtemp()
        try:
            prompt_src = os.path.join(os.path.dirname(__file__), "prompts", "system-researcher.md")
            self.assertTrue(os.path.exists(prompt_src), "prompts/system-researcher.md must exist as canonical no-skill example")

            prompts_dir = os.path.join(temp_dir, "prompts")
            os.makedirs(prompts_dir, exist_ok=True)
            shutil.copy(prompt_src, os.path.join(prompts_dir, "system-researcher.md"))

            workflow_def = {
                "name": "no_skill_workflow",
                "nodes": [
                    {
                        "id": "researcher",
                        "type": "agent",
                        "system_prompt": "prompts/system-researcher.md",
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
                self.assertEqual(wf.edges[0].to_node.name, "researcher")
                with open(prompt_src, "r", encoding="utf-8") as f:
                    expected_instructions = f.read()
                self.assertEqual(wf.edges[0].to_node.instruction, expected_instructions)

            # Test fail-fast when system_prompt points to a missing file
            bad_wf_def = {
                "nodes": [
                    {
                        "id": "researcher_bad",
                        "type": "agent",
                        "system_prompt": "prompts/non_existent.md"
                    }
                ],
                "edges": [
                    {"from": "START", "to": "researcher_bad"}
                ]
            }
            bad_wf_path = os.path.join(temp_dir, "bad_workflow.json")
            with open(bad_wf_path, "w") as f:
                json.dump(bad_wf_def, f)

            with self.assertRaises(ValueError) as ctx:
                load_workflow_from_json(bad_wf_path)
            self.assertIn("System prompt not found", str(ctx.exception))
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

            # Export to OKF bundle directory
            exported_files = export_okf_bundle(src_db, export_dir)
            self.assertTrue(os.path.exists(os.path.join(export_dir, "index.md")))
            self.assertTrue(os.path.exists(os.path.join(export_dir, "entities", "crypto_vault.md")))

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
            self.assertEqual(dst_concepts[0]["trust_tier"], "human_reviewed")
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

    def test_mythos_scrub_verification(self):
        from core.config import RECOMMENDED_MODELS, DEFAULT_MODEL
        import subprocess

        # 1. Check RECOMMENDED_MODELS does not contain mythos
        for m in RECOMMENDED_MODELS:
            self.assertNotIn("mythos", m.lower())
        self.assertNotIn("mythos", DEFAULT_MODEL.lower())
        self.assertIn("vertex_ai/claude-opus-5", RECOMMENDED_MODELS)
        self.assertNotIn("anthropic/claude-opus-5", RECOMMENDED_MODELS)
        self.assertIn("vertex_ai/zai_org/glm-5.2-maas", RECOMMENDED_MODELS)

        # 2. Git grep check across repo to verify 0 mythos occurrences in tracked files
        repo_root = str(Path(__file__).resolve().parent.parent)
        res = subprocess.run(
            ["git", "grep", "-i", "mythos", "--", ":!reference/test_suite.py"],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            res.stdout.strip(),
            "",
            f"Tracked files contain 'mythos' references:\n{res.stdout}"
        )

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


if __name__ == "__main__":
    unittest.main()

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

"""Tests for post-run cross-campaign semantic deduplication, deferred/clean
reporter short-circuiting, and bounded workspace/findings reads."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from core.consolidator import (
    DuplicateMergeProposal,
    SemanticDedupeBatchResult,
    consolidate_run_findings,
    synthesize_aggregate_report,
)
from core.context import RunContext, current_run_context
from core.database import (
    init_db,
    read_artifact,
    read_findings,
    update_finding_calibration,
    update_finding_status_by_id,
    write_findings,
)
from core.graph_loader import _make_reporter_skip_before_agent_callback
from tools.research_tools import read_file


class ConsolidatorTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_consolidator_")
        self.root = os.path.realpath(self._tmp.name)
        self.db = os.path.join(self.root, "knowledge.db")
        init_db(self.db)
        self.run_id = "run-consolidate-1"

    async def asyncTearDown(self):
        self._tmp.cleanup()

    async def test_tier1_exact_duplicates_merge_and_elect_highest_assurance(self):
        write_findings(
            self.db,
            "svc_a",
            [{
                "title": "SQL injection in get_user query",
                "filepath": "db/users.py",
                "description": "Unsanitized user_id concatenated into SQL query in get_user",
                "line_numbers": [42],
                "cwe": "CWE-89",
                "code_paths": ["db/users.py:42:get_user"],
                "severity": "HIGH",
            }],
            run_id=self.run_id,
        )
        write_findings(
            self.db,
            "svc_b",
            [{
                "title": "SQL injection via user_id in get_user",
                "filepath": "db/users.py",
                "description": "Raw SQL string interpolation of user_id inside get_user query",
                "line_numbers": [44],
                "cwe": "CWE-89",
                "code_paths": ["db/users.py:44:get_user"],
                "severity": "CRITICAL",
            }],
            run_id=self.run_id,
        )
        rows = read_findings(self.db, run_id=self.run_id)
        self.assertEqual(len(rows), 2)
        id1, id2 = rows[0]["id"], rows[1]["id"]
        # Promote the second finding to dynamic_confirmed; Tier 1 must keep id2 as primary!
        update_finding_status_by_id(self.db, id2, self.run_id, "dynamic_confirmed")
        update_finding_calibration(self.db, id1, 8.4, 4, 4, "CRITICAL", run_id=self.run_id)

        stats = await consolidate_run_findings(self.db, self.run_id)
        self.assertEqual(stats["tier1_merged"], 1)

        after = {r["id"]: r for r in read_findings(self.db, run_id=self.run_id)}
        self.assertEqual(after[id2]["status"], "dynamic_confirmed")
        self.assertEqual(after[id2]["mantis_risk_score"], 8.4, "calibrated score carried over to surviving primary")
        self.assertEqual(after[id1]["status"], "duplicate_merged")

    async def test_tier2_semantic_adjudicator_merges_cross_file_same_sink_but_protects_assurance_and_distinct_bugs(self):
        # Caller slice reported the bug at api/routes.py calling run_cmd;
        # callee slice reported the exact same bug at util/shell.py:run_cmd;
        # a third finding in api/routes.py is a distinct XSS bug that must NOT merge.
        write_findings(
            self.db,
            "api",
            [
                {
                    "title": "Command injection via shell helper",
                    "filepath": "api/routes.py",
                    "description": "Endpoint passes untrusted host header to run_cmd",
                    "line_numbers": [18],
                    "cwe": "CWE-78",
                    "code_paths": ["api/routes.py:18:ping_endpoint", "util/shell.py:9:run_cmd"],
                    "severity": "CRITICAL",
                },
                {
                    "title": "Reflected XSS in error banner",
                    "filepath": "api/routes.py",
                    "description": "Unescaped query param echoed in HTML response",
                    "line_numbers": [95],
                    "cwe": "CWE-79",
                    "code_paths": ["api/routes.py:95:error_banner"],
                    "severity": "MEDIUM",
                },
            ],
            run_id=self.run_id,
        )
        write_findings(
            self.db,
            "util",
            [{
                "title": "OS command injection in run_cmd",
                "filepath": "util/shell.py",
                "description": "subprocess.Popen(..., shell=True) on caller argument",
                "line_numbers": [9],
                "cwe": "CWE-78",
                "code_paths": ["util/shell.py:9:run_cmd"],
                "severity": "CRITICAL",
            }],
            run_id=self.run_id,
        )
        by_title = {r["title"]: r for r in read_findings(self.db, run_id=self.run_id)}
        caller_id = by_title["Command injection via shell helper"]["id"]
        callee_id = by_title["OS command injection in run_cmd"]["id"]
        xss_id = by_title["Reflected XSS in error banner"]["id"]

        # Mark callee_id as dynamic_confirmed, and have the mock LLM mistakenly nominate
        # the lower-assurance caller_id as primary: consolidate_duplicate_findings must
        # deterministically flip election so dynamic_confirmed callee_id survives!
        update_finding_status_by_id(self.db, callee_id, self.run_id, "dynamic_confirmed")

        async def _mock_adjudicator(_prompt, _schema):
            return SemanticDedupeBatchResult(
                merges=[
                    DuplicateMergeProposal(
                        primary_id=caller_id,
                        duplicate_ids=[callee_id],
                        reason="Both findings describe the exact same ping_endpoint -> run_cmd shell injection",
                    )
                ]
            )

        stats = await consolidate_run_findings(
            self.db, self.run_id, llm_callable=_mock_adjudicator
        )
        self.assertEqual(stats["tier2_merged"], 1)

        after = {r["id"]: r for r in read_findings(self.db, run_id=self.run_id)}
        self.assertEqual(after[callee_id]["status"], "dynamic_confirmed", "machine-verified row must win primary election")
        self.assertEqual(after[caller_id]["status"], "duplicate_merged")
        self.assertEqual(after[xss_id]["status"], "reported", "distinct XSS finding stays untouched")

        active = [r for r in after.values() if r["status"] != "duplicate_merged"]
        ok = await synthesize_aggregate_report(self.db, self.run_id, active)
        self.assertTrue(ok)
        rpt_json = json.loads(read_artifact(self.db, artifact_type="report", run_id=self.run_id))
        self.assertEqual(rpt_json["critical_findings_count"], 1)
        packet = read_artifact(self.db, filepath="workspace/review_packet-latest.md", run_id=self.run_id)
        self.assertIn("OS command injection in run_cmd", packet)
        self.assertIn("Reflected XSS in error banner", packet)

    async def test_reporter_callback_skips_deferred_and_clean_campaigns_and_bounds_findings_reads(self):
        cb = _make_reporter_skip_before_agent_callback("reporter")

        # 1. Deferred multi-campaign mode skips per-campaign reporter immediately
        ctx_def = RunContext(
            jail_dir=self.root, db_path=self.db, target_file="a.py", run_id=self.run_id, defer_reporter=True
        )
        tok = current_run_context.set(ctx_def)
        try:
            res = cb()
            self.assertIsNotNone(res)
            self.assertIn("Deferred", res.parts[0].text)
        finally:
            current_run_context.reset(tok)

        # 2. Single clean campaign skips LLM call and records clean report
        ctx_clean = RunContext(
            jail_dir=self.root, db_path=self.db, target_file="clean.py", run_id=self.run_id, defer_reporter=False
        )
        tok2 = current_run_context.set(ctx_clean)
        try:
            res2 = cb()
            self.assertIsNotNone(res2)
            self.assertIn("Zero active findings", res2.parts[0].text)
            self.assertIsNotNone(read_artifact(self.db, artifact_type="report", run_id=self.run_id))
        finally:
            current_run_context.reset(tok2)

        # 3. Single campaign WITH an open finding runs the reporter LLM (callback returns None)
        write_findings(
            self.db, "vuln.py",
            [{"title": "Real Bug", "filepath": "vuln.py", "description": "d", "line_numbers": [3]}],
            run_id=self.run_id,
        )
        write_findings(
            self.db, "other.py",
            [{"title": "Sibling Bug", "filepath": "other.py", "description": "d", "line_numbers": [7]}],
            run_id=self.run_id,
        )
        ctx_vuln = RunContext(
            jail_dir=self.root,
            db_path=self.db,
            target_file="vuln.py",
            run_id=self.run_id,
            active_node="reviewer",
            defer_reporter=False,
        )
        tok3 = current_run_context.set(ctx_vuln)
        try:
            self.assertIsNone(cb())
            # read_file("workspace/findings") obeys campaign scoping for non-run-wide stages
            virtual_read = await read_file("workspace/findings")
            self.assertIn("Real Bug", virtual_read)
            self.assertNotIn("Sibling Bug", virtual_read)
        finally:
            current_run_context.reset(tok3)

    async def test_valid_status_findings_consolidate_while_dismissed_stay_excluded(self):
        write_findings(
            self.db,
            "api.py",
            [
                {
                    "title": "SQLi in list_orders via customer filter",
                    "filepath": "api.py",
                    "line_numbers": [5],
                    "cwe": "CWE-89",
                    "status": "valid",
                    "description": "Concatenates customer into SQL query.",
                }
            ],
            run_id=self.run_id,
        )
        write_findings(
            self.db,
            "api.py",
            [
                {
                    "title": "SQL injection in list_orders customer filter",
                    "filepath": "api.py",
                    "line_numbers": [6],
                    "cwe": "CWE-89",
                    "status": "valid",
                    "description": "Concatenates customer into SQL query.",
                },
                {
                    "title": "Dismissed SQLi lookalike in list_orders",
                    "filepath": "api.py",
                    "line_numbers": [5],
                    "cwe": "CWE-89",
                    "status": "false_positive",
                    "description": "Concatenates customer into SQL query.",
                },
            ],
            run_id=self.run_id,
        )
        stats = await consolidate_run_findings(self.db, self.run_id)
        self.assertEqual(stats["tier1_merged"], 1)
        rows = read_findings(self.db, run_id=self.run_id)
        statuses = sorted(r["status"] for r in rows)
        self.assertEqual(statuses, ["duplicate_merged", "false_positive", "valid"])

    async def test_structured_one_shot_adapter_and_arrow_code_paths_cluster(self):
        from unittest import mock

        from google.adk.models.llm_response import LlmResponse
        from google.genai import types

        write_findings(
            self.db,
            "api/orders.py",
            [
                {
                    "title": "SQLi in list_orders",
                    "filepath": "api/orders.py",
                    "line_numbers": [5],
                    "cwe": "CWE-89",
                    "code_paths": ["api/orders.py:5 -> db/raw.py:3"],
                    "description": "Passes unsanitized clause to db/raw.py:3.",
                }
            ],
            run_id=self.run_id,
        )
        write_findings(
            self.db,
            "db/raw.py",
            [
                {
                    "title": "Unparameterized SQL in execute_filter",
                    "filepath": "db/raw.py",
                    "line_numbers": [3],
                    "cwe": "CWE-89",
                    "code_paths": ["api/orders.py:5 -> db/raw.py:3"],
                    "description": "Concatenates raw_clause into SQL query.",
                }
            ],
            run_id=self.run_id,
        )
        rows = read_findings(self.db, run_id=self.run_id)
        id1, id2 = rows[0]["id"], rows[1]["id"]

        async def _fake_gen(_self, _req, **_kw):
            yield LlmResponse(
                content=types.Content(
                    role="model",
                    parts=[
                        types.Part(
                            function_call=types.FunctionCall(
                                name="set_model_response",
                                args={
                                    "merges": [
                                        {
                                            "primary_id": id2,
                                            "duplicate_ids": [id1],
                                            "reason": "Same SQLi sink in db/raw.py:3",
                                        }
                                    ]
                                },
                            )
                        )
                    ],
                )
            )

        with mock.patch("core.config.ResilientLiteLlm.generate_content_async", new=_fake_gen):
            stats = await consolidate_run_findings(
                self.db, self.run_id, config={"default_model": "vertex_ai/gemini-2.5-flash"}
            )
        self.assertEqual(stats["clusters_checked"], 1)
        self.assertEqual(stats["tier2_merged"], 1)


if __name__ == "__main__":
    unittest.main()

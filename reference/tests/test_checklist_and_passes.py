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

"""Tests for deterministic slice AST sink/entrypoint checklists and --passes."""

from __future__ import annotations

import asyncio
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from core.checklist import build_slice_audit_checklist
from core.context import RunContext, current_run_context
from core.database import init_db, read_findings
from core.graph_loader import (
    AUDIT_CHECKLIST_MARKER,
    _make_campaign_directive_before_model_callback,
)
from core.structural_index import build_structural_index, state_dir_for_db
from tools.research_tools import get_findings, report_findings


class ChecklistBuilderTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_checklist_")
        self.addCleanup(self._tmp.cleanup)
        self.root = os.path.realpath(self._tmp.name)
        self.repo = os.path.join(self.root, "repo")
        self.slice_a = os.path.join(self.repo, "auth")
        self.slice_b = os.path.join(self.repo, "payments")
        os.makedirs(self.slice_a)
        os.makedirs(self.slice_b)
        Path(self.slice_a, "handlers.py").write_text(
            "import os\n"
            "import pickle\n\n"
            "def login_handler(req):\n"
            "    data = pickle.loads(req.body)\n"
            "    os.system(data['cmd'])\n",
            encoding="utf-8",
        )
        Path(self.slice_b, "charge.py").write_text(
            "def charge_endpoint(db, sql):\n"
            "    return db.execute(sql)\n",
            encoding="utf-8",
        )
        self.db = os.path.join(self.root, "knowledge.db")
        init_db(self.db)

    def test_ast_checklist_is_deterministic_slice_scoped_and_fenced(self):
        manifest = build_structural_index(self.repo, state_dir_for_db(self.db), "unknown")
        self.assertIn(manifest.get("status"), ("complete", "partial"))

        ctx_a = RunContext(
            jail_dir=self.repo,
            db_path=self.db,
            target_file=self.slice_a,
            group_targets=(self.slice_a,),
            run_id="r1",
        )
        first = build_slice_audit_checklist(ctx_a)
        second = build_slice_audit_checklist(ctx_a)
        self.assertEqual(first, second, "checklist ordering must be 100% deterministic")
        self.assertIn(AUDIT_CHECKLIST_MARKER, first)
        self.assertIn("UNTRUSTED", first)
        # Tier 1 command_exec (system) appears before Tier 2 code_eval_deser (loads)
        self.assertLess(first.index("[command_exec]"), first.index("[code_eval_deser]"))
        self.assertIn("auth/handlers.py:6 -> system()", first)
        self.assertIn("auth/handlers.py:5 -> loads()", first)
        self.assertIn("login_handler", first)
        # Sibling slice B must not appear in slice A's checklist
        self.assertNotIn("payments/charge.py", first)

    def test_lexical_fallback_works_without_catalog(self):
        no_index_db = os.path.join(self.root, "empty.db")
        init_db(no_index_db)
        ctx_b = RunContext(
            jail_dir=self.repo,
            db_path=no_index_db,
            target_file=self.slice_b,
            group_targets=(self.slice_b,),
            run_id="r1",
        )
        checklist = build_slice_audit_checklist(ctx_b)
        self.assertIn("payments/charge.py", checklist)

    def test_callback_injects_checklist_only_into_planner_and_researcher(self):
        from google.adk.models import LlmRequest

        build_structural_index(self.repo, state_dir_for_db(self.db), "unknown")
        ctx = RunContext(
            jail_dir=self.repo,
            db_path=self.db,
            target_file=self.slice_a,
            group_targets=(self.slice_a,),
            run_id="r1",
        )
        tok = current_run_context.set(ctx)
        self.addCleanup(current_run_context.reset, tok)

        for stage in ("planner", "researcher", "researcher_domain"):
            req = LlmRequest()
            req.config.system_instruction = "base"
            _make_campaign_directive_before_model_callback(stage)(None, req)
            self.assertIn(AUDIT_CHECKLIST_MARKER, str(req.config.system_instruction), stage)

        for non_checklist_stage in ("architect", "threat_modeler", "reviewer", "critic"):
            req = LlmRequest()
            req.config.system_instruction = "base"
            _make_campaign_directive_before_model_callback(non_checklist_stage)(None, req)
            self.assertNotIn(
                AUDIT_CHECKLIST_MARKER, str(req.config.system_instruction), non_checklist_stage
            )


class MultiPassBlindAuditTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_passes_")
        self.addCleanup(self._tmp.cleanup)
        self.root = os.path.realpath(self._tmp.name)
        self.repo = os.path.join(self.root, "repo")
        os.makedirs(self.repo)
        self.target = os.path.join(self.repo, "app.py")
        Path(self.target).write_text(
            "def run(a, b):\n    x = a\n    y = b\n    return x, y\n",
            encoding="utf-8",
        )
        self.db = os.path.join(self.root, "knowledge.db")
        init_db(self.db)

    def test_passes_cli_validation(self):
        from scripts.launch import build_parser, main as launch_main

        parser = build_parser()
        self.assertEqual(parser.parse_args(["repo"]).passes, 1)
        self.assertEqual(parser.parse_args(["repo", "--passes", "3"]).passes, 3)
        with patch.object(sys, "argv", ["launch.py", "repo", "--passes", "0"]), \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                launch_main()
        self.assertEqual(cm.exception.code, 64)

    def test_blind_pass_researcher_isolation_and_multi_pass_union(self):
        import main as mantis_main

        seen_sessions: list[str] = []
        seen_blind_reads: list[str] = []

        async def _fake_exec(_runner, _ss, filepath, rid, **kw):
            ctx = current_run_context.get()
            seen_sessions.append(kw.get("session_suffix", ""))
            ctx.active_node = "researcher"
            seen_blind_reads.append(get_findings())
            p_idx = ctx.pass_index
            res = report_findings({
                "findings": [{
                    "title": f"Distinct Bug From Pass {p_idx}",
                    "filepath": "app.py",
                    "description": f"Bug found independently in pass {p_idx}",
                    "line_numbers": [p_idx + 1],
                    "severity": "HIGH",
                }]
            })
            self.assertIn("SUCCESS", res)
            kw["budget_controller"].audit_code_reads += 1
            return False

        env = {k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}
        env["OPENAI_API_KEY"] = "dummy"
        with patch.dict(os.environ, env, clear=True), \
             patch.object(mantis_main, "execute_sub_task", side_effect=_fake_exec), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            rc = asyncio.run(
                mantis_main.pipeline(
                    scan_target=self.repo,
                    db_override=self.db,
                    model_override="openai/nonexistent",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    auto_configure=False,
                    assume_yes=True,
                    passes=2,
                )
            )
        self.assertEqual(rc, 0)
        self.assertEqual(seen_sessions, ["", "_pass2"])
        # Both pass 1 and pass 2 researchers saw NO_DATA before reporting (blind passes!)
        self.assertTrue(all(r.startswith("NO_DATA") for r in seen_blind_reads), seen_blind_reads)
        saved = read_findings(self.db)
        self.assertEqual(
            {f["title"] for f in saved},
            {"Distinct Bug From Pass 1", "Distinct Bug From Pass 2"},
        )


if __name__ == "__main__":
    unittest.main()

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

"""Phase-1 CL 2 regression tests: status vocabulary, per-finding verdicts,
synthesizer promotion gates, and diff-bound patch verification."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from google.genai import types  # noqa: E402

import core.config as cfg_mod  # noqa: E402
import core.database as db_mod  # noqa: E402
import core.diversity as div_mod  # noqa: E402
import core.graph_loader as gl  # noqa: E402
from core.config import ResilientLiteLlm  # noqa: E402
from core.context import RunContext, current_run_context  # noqa: E402
from core.database import (  # noqa: E402
    init_db,
    is_suppressed,
    mitigate_finding,
    read_findings,
    record_finding_patch,
    update_finding_status_by_id,
    update_status,
    write_findings,
)
from core.sarif import build_sarif  # noqa: E402
from core.schemas import CriticVerdict  # noqa: E402
from core.synthesizer import (  # noqa: E402
    SYNTHESIS_SYSTEM_PROMPT,
    ResearchGraphSynthesizer,
)
from tools.research_tools import record_patch  # noqa: E402


class _FakeCtx:
    def __init__(self):
        self.state = {}


class TestCanonicalStatusAndSurfaces(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_cl2_surf_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = os.path.join(self.tmp, "k.db")
        init_db(self.db)

    def test_status_partition_and_mitigated_suppression(self):
        self.assertTrue(hasattr(db_mod, "CLOSED_STATUSES"))
        self.assertTrue(hasattr(db_mod, "CONFIRMED_LIVE_STATUSES"))
        self.assertTrue(hasattr(db_mod, "OPEN_CONFIRMED_STATUSES"))
        self.assertTrue(hasattr(db_mod, "UNTRIAGED_STATUSES"))
        self.assertTrue(hasattr(db_mod, "is_untriaged"))

        self.assertIn("mitigated", db_mod.CLOSED_STATUSES)
        self.assertIn("mitigated", db_mod.SUPPRESSED_STATUSES)
        self.assertTrue(is_suppressed("mitigated"))
        self.assertTrue(is_suppressed("MITIGATED"))
        self.assertTrue(db_mod.is_untriaged("reported"))
        self.assertTrue(db_mod.is_untriaged("REPORTED"))
        self.assertFalse(db_mod.is_untriaged("confirmed"))
        self.assertFalse(is_suppressed("confirmed"))
        self.assertFalse(is_suppressed("viable"))
        self.assertFalse(is_suppressed("static_confirmed"))

        write_findings(
            self.db,
            self.tmp,
            [
                {
                    "title": "Closed SQLi",
                    "severity": "HIGH",
                    "description": "d",
                    "filepath": "app.py",
                    "line_numbers": [10],
                    "status": "static_confirmed",
                }
            ],
            run_id="r1",
        )
        rows = read_findings(self.db, run_id="r1")
        self.assertTrue(mitigate_finding(self.db, rows[0]["id"], "fixed in commit"))
        updated = read_findings(self.db, run_id="r1")
        self.assertEqual(updated[0]["status"], "mitigated")
        doc, _ = build_sarif(updated, scan_root=self.tmp, include_suppressed=False)
        self.assertEqual(doc["runs"][0]["results"], [])

    def test_diversity_excludes_mitigated_and_archived_from_kept(self):
        findings = [
            {"filepath": "a/one.py", "severity": "HIGH", "cwe": "CWE-89", "status": "confirmed"},
            {"filepath": "a/two.py", "severity": "LOW", "cwe": "CWE-79", "status": "false_positive"},
            {"filepath": "b/three.py", "severity": "HIGH", "cwe": "CWE-22", "status": "mitigated"},
            {"filepath": "c/four.py", "severity": "MEDIUM", "cwe": "CWE-78", "status": "archived"},
            {"filepath": "d/five.py", "severity": "MEDIUM", "cwe": "CWE-89", "status": "reported"},
        ]
        metrics = div_mod.measure(findings, examined_areas=["a", "b", "c", "d"])
        self.assertEqual(metrics["findings_kept"], 2)
        self.assertEqual(metrics["findings_rejected"], 1)
        self.assertEqual(metrics["findings_unreviewed"], 1)
        self.assertEqual(metrics["findings_reviewed"], 2)

    def test_sarif_include_suppressed_downgrades_untriaged_reported_to_note(self):
        findings = [
            {
                "filepath": "app.py",
                "title": "Unreviewed candidate",
                "severity": "CRITICAL",
                "description": "candidate",
                "line_numbers": [12],
                "status": "reported",
                "cwe": "CWE-89",
            },
            {
                "filepath": "app.py",
                "title": "Confirmed SQLi",
                "severity": "HIGH",
                "description": "verified",
                "line_numbers": [30],
                "status": "confirmed",
                "cwe": "CWE-89",
            },
        ]
        doc_default, _ = build_sarif(findings, scan_root=self.tmp, include_suppressed=False)
        self.assertEqual(len(doc_default["runs"][0]["results"]), 1)
        self.assertIn("Confirmed SQLi", doc_default["runs"][0]["results"][0]["message"]["text"])

        doc_pr, _ = build_sarif(findings, scan_root=self.tmp, include_suppressed=True)
        by_title = {
            r["message"]["text"].splitlines()[0]: r for r in doc_pr["runs"][0]["results"]
        }
        self.assertEqual(by_title["Unreviewed candidate"]["level"], "note")
        self.assertEqual(by_title["Unreviewed candidate"]["properties"].get("mantis/triage"), "untriaged")
        self.assertIn("untriaged", by_title["Unreviewed candidate"]["message"]["text"].lower())
        self.assertEqual(by_title["Confirmed SQLi"]["level"], "error")

    def test_pass_index_migration_and_pass_scoped_crud(self):
        legacy_db = os.path.join(self.tmp, "legacy_v3.db")
        conn = sqlite3.connect(legacy_db)
        try:
            conn.execute(
                """
                CREATE TABLE findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    filepath TEXT,
                    title TEXT,
                    severity TEXT,
                    description TEXT,
                    line_numbers TEXT NOT NULL DEFAULT '[]',
                    remediation TEXT,
                    status TEXT NOT NULL DEFAULT 'reported',
                    mantis_risk_score REAL,
                    impact_score INTEGER,
                    likelihood_score INTEGER,
                    priority TEXT,
                    signature TEXT,
                    lineage_id TEXT,
                    cwe TEXT,
                    triage_reasoning TEXT,
                    patch_diff TEXT,
                    patch_status TEXT,
                    rca_summary TEXT,
                    embedding BLOB,
                    code_paths TEXT NOT NULL DEFAULT '[]',
                    campaign TEXT,
                    UNIQUE(filepath, title, description, line_numbers, run_id)
                )
                """
            )
            conn.execute(
                "INSERT INTO findings (run_id, filepath, title, severity, description, line_numbers, status) "
                "VALUES ('r_leg', 'app.py', 'Same Bug', 'HIGH', 'same desc', '[42]', 'false_positive')"
            )
            conn.execute(f"PRAGMA user_version = {db_mod.CURRENT_SCHEMA_VERSION}")
            conn.commit()
        finally:
            conn.close()

        init_db(legacy_db)
        # Pass 2 reporting the exact same finding at the exact same line neither
        # overwrites Pass 1's row nor inherits Pass 1's false_positive dismissal.
        write_findings(
            legacy_db,
            "app.py",
            [
                {
                    "filepath": "app.py",
                    "title": "Same Bug",
                    "severity": "HIGH",
                    "description": "same desc",
                    "line_numbers": [42],
                }
            ],
            run_id="r_leg",
            pass_index=2,
        )
        p1_rows = read_findings(legacy_db, run_id="r_leg", pass_index=1)
        p2_rows = read_findings(legacy_db, run_id="r_leg", pass_index=2)
        all_rows = read_findings(legacy_db, run_id="r_leg")
        self.assertEqual(len(p1_rows), 1)
        self.assertEqual(len(p2_rows), 1)
        self.assertEqual(len(all_rows), 2)
        self.assertEqual(p1_rows[0]["status"], "false_positive")
        self.assertEqual(p2_rows[0]["status"], "reported")

        update_status(legacy_db, "app.py", "r_leg", "confirmed", pass_index=2)
        self.assertEqual(read_findings(legacy_db, run_id="r_leg", pass_index=1)[0]["status"], "false_positive")
        self.assertEqual(read_findings(legacy_db, run_id="r_leg", pass_index=2)[0]["status"], "confirmed")


class TestPerFindingVerdictsAndSanitizer(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_cl2_verdicts_")
        self.db = os.path.join(self.tmp, "v.db")
        init_db(self.db)
        self.rc = RunContext(
            jail_dir=self.tmp,
            db_path=self.db,
            target_file=self.tmp,
            run_id="r_v",
        )
        self._tok = current_run_context.set(self.rc)

    async def asyncTearDown(self):
        current_run_context.reset(self._tok)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seed(self, title: str, filepath: str = "app.py", line: int = 10) -> int:
        write_findings(
            self.db,
            self.tmp,
            [
                {
                    "title": title,
                    "severity": "HIGH",
                    "description": f"desc {title}",
                    "filepath": filepath,
                    "line_numbers": [line],
                    "cwe": "CWE-89",
                }
            ],
            run_id="r_v",
        )
        rows = read_findings(self.db, run_id="r_v")
        return next(int(r["id"]) for r in rows if r["title"] == title)

    def _statuses(self) -> dict[int, str]:
        return {int(r["id"]): r["status"] for r in read_findings(self.db, run_id="r_v")}

    async def test_shipped_critic_binds_extended_critic_verdict(self):
        self.assertTrue(hasattr(cfg_mod, "ExtendedCriticVerdict"))
        ext_cls = cfg_mod.ExtendedCriticVerdict
        strict_json = CriticVerdict(route="viable", reason="reachable").model_dump_json()
        parsed = ext_cls.model_validate_json(strict_json)
        self.assertEqual(parsed.route, "viable")
        self.assertEqual(parsed.finding_verdicts, [])

        wf_path = Path(_REF_ROOT) / "workflow.json"
        wf, _ = gl.load_workflow_from_json(str(wf_path), load_local=False)
        critic_agent = None
        for edge in wf.edges:
            for n in (edge.from_node, edge.to_node):
                agent = getattr(n, "agent", n)
                if getattr(agent, "name", None) == "critic":
                    critic_agent = agent
                    break
        self.assertIsNotNone(critic_agent)
        self.assertIs(critic_agent.output_schema, ext_cls)
        self.assertIn("PER-FINDING VERDICTS:", critic_agent.instruction(None))

    async def test_sanitizer_salvages_fenced_and_embedded_json_without_fallback(self):
        ext_critic = cfg_mod.ExtendedCriticVerdict

        class _Resp:
            partial = False
            finish_reason = None
            error_code = None
            error_message = None

            def __init__(self, text: str):
                self.content = types.Content(
                    role="model", parts=[types.Part.from_text(text=text)]
                )

        wrapped = (
            "After tracing callers in app.py {foo}, here is my final verdict:\n"
            "```json\n"
            '{"route": "viable", "reason": "Reachable via POST /login", '
            '"finding_verdicts": [{"finding_id": 1, "route": "viable", "reason": "direct sink"}]}\n'
            "```\nDone."
        )
        out = ResilientLiteLlm._sanitize_structured_response(_Resp(wrapped), ext_critic)
        payload = json.loads(out.content.parts[0].text)
        self.assertEqual(payload["route"], "viable")
        self.assertFalse(payload["reason"].startswith("Fallback:"))
        self.assertEqual(len(payload["finding_verdicts"]), 1)

        # Genuine refusal still fails closed with Fallback: and increments verdict_fallbacks.
        before_fb = self.rc.verdict_fallbacks
        refused = ResilientLiteLlm._sanitize_structured_response(
            _Resp("I cannot assist with this request."), ext_critic
        )
        ref_payload = json.loads(refused.content.parts[0].text)
        self.assertEqual(ref_payload["route"], "non_viable")
        self.assertTrue(ref_payload["reason"].startswith("Fallback:"))
        self.assertEqual(ref_payload["finding_verdicts"], [])
        self.assertEqual(self.rc.verdict_fallbacks, before_fb + 1)

    async def test_full_promotion_pipeline_survives_critic_fallback_and_blocks_laundering(self):
        f1 = self._seed("Confirmed Viable", "a.py", 10)
        f2 = self._seed("Confirmed NonViable", "b.py", 20)
        f3 = self._seed("Reviewer Omitted", "c.py", 30)
        f4 = self._seed("Reviewer Dismissed", "d.py", 40)

        rev_cls = gl.create_classifier("reviewer_classifier", ["confirmed"])
        crit_cls = gl.create_classifier("critic_classifier", ["viable"])

        # 1. Reviewer confirms f1 & f2, dismisses f4, omits f3.
        ev_rev = await rev_cls._func(
            _FakeCtx(),
            {
                "route": "confirmed",
                "reason": "two real bugs",
                "finding_verdicts": [
                    {"finding_id": f1, "route": "confirmed", "reason": "tainted sql"},
                    {"finding_id": f2, "route": "confirmed", "reason": "ssrf"},
                    {"finding_id": f4, "route": "false_positive", "reason": "parameterized"},
                ],
            },
        )
        self.assertEqual(ev_rev.actions.route, "confirmed")
        st = self._statuses()
        self.assertEqual(st[f1], "confirmed")
        self.assertEqual(st[f2], "confirmed")
        self.assertEqual(st[f3], "reported")
        self.assertEqual(st[f4], "false_positive")
        self.assertEqual(self.rc.promoted_finding_ids, {f1, f2})

        # 2. Critic hits Fallback: non_viable -> f1 and f2 stay 'confirmed' (live in SARIF!).
        await crit_cls._func(
            _FakeCtx(),
            {"route": "non_viable", "reason": "Fallback: truncated", "finding_verdicts": []},
        )
        st = self._statuses()
        self.assertEqual(st[f1], "confirmed")
        self.assertEqual(st[f2], "confirmed")
        doc, _ = build_sarif(read_findings(self.db, run_id="r_v"), scan_root=self.tmp)
        self.assertEqual(len(doc["runs"][0]["results"]), 2)

        # 3. Critic now emits per-finding verdicts AND tries to smuggle omitted f3 as viable.
        ev_crit = await crit_cls._func(
            _FakeCtx(),
            {
                "route": "viable",
                "reason": "f1 viable",
                "finding_verdicts": [
                    {"finding_id": f1, "route": "viable", "reason": "reachable"},
                    {"finding_id": f2, "route": "non_viable", "reason": "dead handler"},
                    {"finding_id": f3, "route": "viable", "reason": "attempted bypass"},
                ],
            },
        )
        self.assertEqual(ev_crit.actions.route, "viable")
        st = self._statuses()
        self.assertEqual(st[f1], "static_confirmed")
        self.assertEqual(st[f2], "non_viable")
        self.assertEqual(st[f3], "reported", "Reviewer-omitted finding must not bypass reviewer via critic.")
        self.assertEqual(self.rc.promoted_finding_ids, {f1})

        # 4. Reproducer completion stamp promotes dynamic_confirmed ONLY on f1 with evidence,
        # and never launders omitted f3 to static_confirmed.
        self.rc.sandbox_executed = True
        self.rc.finding_evidence = {str(f1): {"reproduced": True}}
        cb = gl._make_completion_stamp_callback("reproducer", "static_confirmed")
        cb(callback_context=object())
        st = self._statuses()
        self.assertEqual(st[f1], "dynamic_confirmed")
        self.assertEqual(st[f2], "non_viable")
        self.assertEqual(st[f3], "reported")

    async def test_declared_routes_prevent_unknown_route_hijack(self):
        f1 = self._seed("Needs Research", "a.py", 5)
        f2 = self._seed("Real Bug", "b.py", 15)
        rev_cls = gl.create_classifier("reviewer_classifier", ["confirmed"])
        ev = await rev_cls._func(
            _FakeCtx(),
            {
                "route": "confirmed",
                "reason": "f2 confirmed",
                "finding_verdicts": [
                    {"finding_id": f1, "route": "needs_research", "reason": "unclear"},
                    {"finding_id": f2, "route": "confirmed", "reason": "verified"},
                ],
            },
        )
        self.assertEqual(ev.actions.route, "confirmed")
        self.assertEqual(self._statuses()[f2], "confirmed")
        # 1-arg contract preserved for TestDeriveCampaignRoute
        self.assertEqual(
            gl._derive_campaign_route(
                [
                    {"finding_id": 1, "route": "false_positive", "reason": ""},
                    {"finding_id": 2, "route": "weird_route", "reason": ""},
                ]
            ),
            "weird_route",
        )


class TestSynthesizerPromotionGateAndPatchGuard(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_cl2_synth_")
        self.db = os.path.join(self.tmp, "s.db")
        init_db(self.db)

    async def asyncTearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_archetype_wires_reviewer_decision_findings_gate_and_record_patch(self):
        synth = ResearchGraphSynthesizer()
        spec = synth.synthesize_archetype(objective="Web REST API SQL injection audit")
        node_map = {n.id: n for n in spec.nodes}
        self.assertIn("structural_index", node_map)
        self.assertIn("findings_gate", node_map)
        self.assertIn("reviewer_decision", node_map)
        self.assertIn("record_patch", node_map["patcher"].tools)

        edges = {(e.from_node, e.to_node): e.on for e in spec.edges}
        self.assertIn(("reviewer", "reviewer_decision"), edges)
        self.assertEqual(edges.get(("reviewer_decision", "critic")), "confirmed")

        # Terminal sink must be unique ('reporter') and load cleanly into ADK 2.14.
        out_sources = {e.from_node for e in spec.edges if e.from_node != "START"}
        sinks = {n.id for n in spec.nodes} - out_sources
        self.assertEqual(sinks, {"reporter"})

        recipe = ResearchGraphSynthesizer.persist_recipe(spec, Path(self.tmp))
        wf, _ = gl.load_workflow_from_json(str(recipe), load_local=False)
        self.assertIsNotNone(wf)

    def test_prompt_examples_sanitize_and_load_into_adk(self):
        synth = ResearchGraphSynthesizer()
        blocks = re.findall(r"Example \d+:.*?```json\s*(\{.*?\})\s*```", SYNTHESIS_SYSTEM_PROMPT, re.S)
        self.assertGreaterEqual(len(blocks), 2)
        for i, block in enumerate(blocks, 1):
            raw = json.loads(block)
            spec = synth.sanitize_and_validate_spec(raw, objective=f"example {i}", strict_synthesis=True)
            p = Path(self.tmp) / f"ex_{i}.json"
            p.write_text(json.dumps(spec.model_dump(by_alias=True, exclude_none=True)), encoding="utf-8")
            wf, _ = gl.load_workflow_from_json(str(p), load_local=False)
            self.assertIsNotNone(wf)

    @patch("litellm.completion")
    def test_strict_synthesis_rejects_zero_promotion_graph_into_repair_loop(self, mock_comp):
        zero_promo = {
            "name": "workflow_dead_end",
            "config": {"sandbox": {"type": "static-only"}},
            "nodes": [
                {
                    "id": "analyzer",
                    "type": "agent",
                    "skill": "mantis-researcher",
                    "tools": ["read_file", "report_findings"],
                },
                {
                    "id": "reporter",
                    "type": "agent",
                    "skill": "mantis-report",
                    "tools": ["get_findings", "generate_report"],
                },
            ],
            "edges": [
                {"from": "START", "to": "analyzer"},
                {"from": "analyzer", "to": "reporter"},
            ],
        }
        repaired = {
            "name": "workflow_repaired",
            "config": {"sandbox": {"type": "static-only"}},
            "nodes": [
                {
                    "id": "analyzer",
                    "type": "agent",
                    "skill": "mantis-researcher",
                    "tools": ["read_file", "report_findings"],
                },
                {
                    "id": "reviewer",
                    "type": "agent",
                    "skill": "mantis-review",
                    "tools": ["get_findings", "read_file"],
                    "output_schema": "ReviewVerdict",
                    "output_key": "verdict",
                },
                {
                    "id": "review_decision",
                    "type": "classifier",
                    "routes": ["confirmed"],
                    "max_visits": 1,
                },
                {
                    "id": "calibrator",
                    "type": "agent",
                    "skill": "mantis-calibrate",
                    "tools": ["get_findings", "calibrate_finding", "score_risk"],
                },
                {
                    "id": "reporter",
                    "type": "agent",
                    "skill": "mantis-report",
                    "tools": ["get_findings", "generate_report"],
                },
            ],
            "edges": [
                {"from": "START", "to": "analyzer"},
                {"from": "analyzer", "to": "reviewer"},
                {"from": "reviewer", "to": "review_decision"},
                {"from": "review_decision", "to": "calibrator", "on": "confirmed"},
                {"from": "review_decision", "to": "reporter", "on": "__DEFAULT__"},
                {"from": "calibrator", "to": "reporter"},
            ],
        }
        r1, c1 = MagicMock(), MagicMock()
        c1.message.content = json.dumps(zero_promo)
        r1.choices = [c1]
        r2, c2 = MagicMock(), MagicMock()
        c2.message.content = json.dumps(repaired)
        r2.choices = [c2]
        mock_comp.side_effect = [r1, r2]

        synth = ResearchGraphSynthesizer()
        spec = synth.synthesize_with_llm(objective="Audit CI scripts")
        self.assertEqual(spec.name, "workflow_repaired")
        self.assertEqual(mock_comp.call_count, 2)
        feedback_msg = mock_comp.call_args_list[1][1]["messages"][3]["content"]
        self.assertIn("promotion", feedback_msg.lower())

    async def test_record_finding_patch_binds_verified_secure_to_verified_diff(self):
        write_findings(
            self.db,
            self.tmp,
            [
                {
                    "title": "SQLi",
                    "severity": "CRITICAL",
                    "description": "raw query",
                    "filepath": "app.py",
                    "line_numbers": [15],
                    "status": "dynamic_confirmed",
                }
            ],
            run_id="r_patch",
        )
        fid = int(read_findings(self.db, run_id="r_patch")[0]["id"])
        ev_ok = {str(fid): {"reproduced": True, "reattacked": True, "reattack_present": False}}
        res1 = record_finding_patch(
            self.db,
            fid,
            run_id="r_patch",
            patch_diff="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-bad()\n+safe_A()\n",
            reattack_status="failed_to_bypass",
            verified_evidence=True,
            finding_evidence=ev_ok,
        )
        self.assertEqual(res1["patch_status"], "VERIFIED_SECURE")
        self.assertEqual(res1["status"], "patch_verified")

        # Subsequent bypassed patch attempt must NOT overwrite the verified diff!
        ev_bad = {str(fid): {"reproduced": True, "reattacked": True, "reattack_present": True}}
        res2 = record_finding_patch(
            self.db,
            fid,
            run_id="r_patch",
            patch_diff="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-bad()\n+broken_B()\n",
            reattack_status="bypassed",
            verified_evidence=True,
            finding_evidence=ev_bad,
        )
        self.assertTrue(res2.get("rejected_unverified_diff"))
        row = read_findings(self.db, run_id="r_patch")[0]
        self.assertEqual(row["patch_status"], "VERIFIED_SECURE")
        self.assertIn("+safe_A()", row["patch_diff"])
        self.assertNotIn("+broken_B()", row["patch_diff"])

        # Tool wrapper surfaces explicit refusal message
        class _DynamicSb:
            pass

        rc = RunContext(
            jail_dir=self.tmp,
            db_path=self.db,
            target_file=self.tmp,
            run_id="r_patch",
            sandbox=_DynamicSb(),
            sandbox_executed=True,
            finding_evidence=ev_bad,
        )
        tok = current_run_context.set(rc)
        try:
            msg = record_patch(
                fid,
                "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-bad()\n+broken_C()\n",
                reattack_status="bypassed",
            )
            self.assertIn("ERROR", msg)
            self.assertIn("VERIFIED_SECURE", msg)
        finally:
            current_run_context.reset(tok)


if __name__ == "__main__":
    unittest.main()

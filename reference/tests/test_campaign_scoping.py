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

"""Tests for campaign-scoped findings access and per-finding status stamps.

Multi-target runs share one run_id across campaigns. These tests pin the
three deterministic fixes for that: get_findings defaults to campaign
scope, dismissal stamps address the finding id (so a later filepath-wide
promotion cannot launder a dismissed sibling), and the zero-findings gate
only skips triage stages when it can prove the campaign is clean. No LLM
calls.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from core.context import RunContext, current_run_context
from core.database import (
    init_db,
    read_findings,
    update_finding_status_by_id,
    update_status,
    write_findings,
)


def _finding(title, filepath, description="d", code_paths=None):
    f = {"title": title, "filepath": filepath, "description": description}
    if code_paths:
        f["code_paths"] = code_paths
    return f


def _statuses_by_title(db_path, run_id="r1"):
    return {
        f["title"]: str(f["status"]).lower()
        for f in read_findings(db_path, run_id=run_id)
    }


class _DbTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_scope_test_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = os.path.realpath(self._tmp.name)
        self.db = os.path.join(self.tmp, "knowledge.db")
        init_db(self.db)

    def install_ctx(self, target_file="", active_node="", run_id="r1"):
        ctx = RunContext(
            jail_dir=self.tmp,
            db_path=self.db,
            target_file=target_file,
            run_id=run_id,
            active_node=active_node,
        )
        token = current_run_context.set(ctx)
        self.addCleanup(current_run_context.reset, token)
        return ctx


class UpdateFindingStatusByIdTest(_DbTest):
    def setUp(self):
        super().setUp()
        write_findings(
            self.db, "",
            [_finding("real", "app/login.py"), _finding("bogus", "app/login.py")],
            run_id="r1",
        )
        self.ids = {f["title"]: f["id"] for f in read_findings(self.db, run_id="r1")}

    def test_dismissal_survives_later_filepath_promotion(self):
        # The laundering case: dismiss one sibling by id, then promote the
        # whole file the way the reproducer's completion stamp does.
        update_finding_status_by_id(self.db, self.ids["bogus"], "r1", "false_positive")
        update_status(self.db, "app/login.py", "r1", "static_confirmed")
        statuses = _statuses_by_title(self.db)
        self.assertEqual(statuses["real"], "static_confirmed")
        self.assertEqual(statuses["bogus"], "false_positive")

    def test_dismissal_never_overwrites_dynamic_proof(self):
        update_status(self.db, "app/login.py", "r1", "dynamic_confirmed")
        update_finding_status_by_id(self.db, self.ids["real"], "r1", "false_positive")
        self.assertEqual(_statuses_by_title(self.db)["real"], "dynamic_confirmed")

    def test_wrong_run_id_updates_nothing(self):
        update_finding_status_by_id(self.db, self.ids["real"], "other_run", "false_positive")
        self.assertEqual(_statuses_by_title(self.db)["real"], "reported")

    def test_non_integer_id_is_ignored(self):
        update_finding_status_by_id(self.db, "not-an-id", "r1", "false_positive")
        self.assertEqual(set(_statuses_by_title(self.db).values()), {"reported"})


class ReadFindingsScopePathTest(_DbTest):
    def setUp(self):
        super().setUp()
        write_findings(
            self.db, "",
            [
                _finding("in-file", "app/login.py"),
                _finding("in-subdir", "app/sub/x.py"),
                _finding("outside", "lib/util.py"),
                _finding("prefix-collision", "application/evil.py"),
            ],
            run_id="r1",
        )

    def _titles(self, scope):
        return {f["title"] for f in read_findings(self.db, run_id="r1", scope_path=scope)}

    def test_directory_scope_is_component_aligned(self):
        # "app" must match app/ but never application/.
        self.assertEqual(self._titles("app"), {"in-file", "in-subdir"})

    def test_file_scope_matches_exactly(self):
        self.assertEqual(self._titles("app/login.py"), {"in-file"})

    def test_no_scope_returns_everything(self):
        self.assertEqual(len(self._titles(None)), 4)

    def test_root_scope_is_no_filter(self):
        self.assertEqual(len(self._titles(".")), 4)

    def test_cross_directory_finding_is_kept_by_its_code_paths(self):
        # A slice campaign on app/ can trace a flow into server/lib and
        # report the finding at the sink file. The in-scope citation in
        # code_paths must keep it visible to the campaign that found it.
        write_findings(
            self.db, "",
            [_finding("cross-dir", "server/lib/db.js",
                      code_paths=["app/login.js:42", "server/lib/db.js:7"])],
            run_id="r1",
        )
        self.assertIn("cross-dir", self._titles("app"))

    def test_code_paths_matching_is_quote_anchored(self):
        # Scope "app" must not match a citation of application/.
        write_findings(
            self.db, "",
            [_finding("decoy-citation", "lib/z.py",
                      code_paths=["application/evil.py:3"])],
            run_id="r1",
        )
        self.assertNotIn("decoy-citation", self._titles("app"))


class UpdateStatusScopeSymmetryTest(_DbTest):
    """update_status must promote exactly what read_findings(scope_path=...)
    lets the campaign see -- the two share _campaign_scope_clause."""

    def setUp(self):
        super().setUp()
        write_findings(
            self.db, "",
            [
                _finding("cross-dir", "server/lib/db.js",
                         code_paths=["app/login.js:42", "server/lib/db.js:7"]),
                _finding("decoy-citation", "lib/z.py",
                         code_paths=["application/evil.py:3"]),
                _finding("outside", "lib/util.py"),
            ],
            run_id="r1",
        )

    def test_campaign_stamp_promotes_cross_directory_finding(self):
        # The app campaign reviewed and reproduced this finding (read_findings
        # keeps it in scope via code_paths); the completion stamp must promote
        # it too, or it stays "reported" and is suppressed at export.
        update_status(self.db, "app", "r1", "static_confirmed")
        self.assertEqual(_statuses_by_title(self.db)["cross-dir"], "static_confirmed")

    def test_campaign_stamp_is_quote_anchored(self):
        update_status(self.db, "app", "r1", "static_confirmed")
        statuses = _statuses_by_title(self.db)
        self.assertEqual(statuses["decoy-citation"], "reported")
        self.assertEqual(statuses["outside"], "reported")

    def test_stamp_scope_equals_read_scope(self):
        update_status(self.db, "app", "r1", "static_confirmed")
        promoted = {t for t, s in _statuses_by_title(self.db).items()
                    if s == "static_confirmed"}
        visible = {f["title"]
                   for f in read_findings(self.db, run_id="r1", scope_path="app")}
        self.assertEqual(promoted, visible)


class GetFindingsCampaignScopeTest(_DbTest):
    def setUp(self):
        super().setUp()
        write_findings(
            self.db, "",
            [_finding("mine", "app/a.py"), _finding("other-campaign", "other/b.py")],
            run_id="r1",
        )

    def _titles(self, raw):
        import json
        if raw.startswith("NO_DATA") or raw.startswith("Error") or raw.startswith("ERROR"):
            return raw
        # get_findings fences its JSON as untrusted data (CP-4); the payload
        # is the bracketed body between the fence lines.
        body = raw[raw.index("["):raw.rindex("]") + 1]
        return {f["title"] for f in json.loads(body)}

    def test_triage_stages_see_only_their_campaign(self):
        from tools.research_tools import get_findings
        self.install_ctx(target_file="app/a.py", active_node="reviewer")
        self.assertEqual(self._titles(get_findings()), {"mine"})

    def test_reporter_and_chainer_see_the_whole_run(self):
        from tools.research_tools import get_findings
        for stage in ("reporter", "chainer"):
            self.install_ctx(target_file="app/a.py", active_node=stage)
            self.assertEqual(
                self._titles(get_findings()), {"mine", "other-campaign"}, stage
            )

    def test_whole_repo_campaign_stays_run_wide(self):
        from tools.research_tools import get_findings
        self.install_ctx(target_file="", active_node="reviewer")
        self.assertEqual(self._titles(get_findings()), {"mine", "other-campaign"})

    def test_explicit_filepath_argument_still_works(self):
        from tools.research_tools import get_findings
        self.install_ctx(target_file="app/a.py", active_node="reviewer")
        self.assertEqual(self._titles(get_findings("other/b.py")), {"other-campaign"})

    def _rows(self, raw):
        import json
        body = raw[raw.index("["):raw.rindex("]") + 1]
        return {f["title"]: f for f in json.loads(body)}

    def test_run_wide_stages_get_other_campaigns_as_an_index(self):
        # The full record is the campaign's own; the rest of the run is an
        # index (id, file, title, severity, status), one get_findings(filepath)
        # away. A sweep's reporter otherwise read every campaign's description
        # and root cause -- hundreds of thousands of tokens -- on every turn.
        from tools.research_tools import get_findings
        for stage in ("reporter", "chainer"):
            self.install_ctx(target_file="app/a.py", active_node=stage)
            rows = self._rows(get_findings())
            self.assertIn("description", rows["mine"], stage)
            self.assertNotIn("scope", rows["mine"], stage)
            other = rows["other-campaign"]
            self.assertEqual(other["scope"], "other_campaign", stage)
            self.assertNotIn("description", other, stage)
            self.assertEqual(other["filepath"], "other/b.py", stage)
            self.assertIn("status", other, stage)
            # The index entry names the way back to the record.
            self.assertEqual(self._titles(get_findings("other/b.py")), {"other-campaign"})

    def test_whole_repo_campaign_keeps_full_records(self):
        from tools.research_tools import get_findings
        self.install_ctx(target_file="", active_node="reporter")
        rows = self._rows(get_findings())
        self.assertTrue(all("description" in f and "scope" not in f for f in rows.values()))

    def test_full_record_payload_is_capped_closed_findings_first(self):
        from unittest import mock

        import tools.research_tools as rt
        from core.database import update_finding_status_by_id
        big = "x" * 5000
        write_findings(
            self.db, "",
            [_finding(f"f{i}", "app/a.py", description=big) for i in range(20)],
            run_id="r1",
        )
        ids = {f["title"]: f["id"] for f in read_findings(self.db, run_id="r1")}
        for i in range(10):
            update_finding_status_by_id(self.db, ids[f"f{i}"], "r1", "false_positive")
        self.install_ctx(target_file="app/a.py", active_node="reviewer")
        with mock.patch.object(rt, "GET_FINDINGS_FULL_CHARS", 60_000):
            rows = self._rows(rt.get_findings())
        full = {t for t, f in rows.items() if "description" in f}
        indexed = {t for t, f in rows.items() if f.get("scope") == "this_campaign"}
        self.assertEqual(len(rows), 21, "nothing disappears; some rows shrink")
        self.assertTrue({f"f{i}" for i in range(10)} <= indexed, "closed findings go to the index first")
        self.assertTrue(full, "open findings stay full while they fit")
        self.assertLessEqual(
            len(rt.json.dumps([f for f in rows.values() if "description" in f], indent=2)), 60_000
        )


class PersistFindingDismissalsTest(_DbTest):
    def setUp(self):
        super().setUp()
        write_findings(
            self.db, "",
            [_finding("real", "app/login.py"), _finding("bogus", "app/login.py")],
            run_id="r1",
        )
        self.ids = {f["title"]: f["id"] for f in read_findings(self.db, run_id="r1")}

    def test_mixed_verdicts_on_one_file_stamp_only_the_dismissed_id(self):
        from core.graph_loader import _persist_finding_dismissals
        self.install_ctx(target_file="app/login.py", active_node="reviewer_classifier")
        _persist_finding_dismissals("reviewer_classifier", [
            {"finding_id": self.ids["real"], "route": "confirmed", "reason": "solid"},
            {"finding_id": self.ids["bogus"], "route": "false_positive", "reason": "parameterized"},
        ])
        statuses = _statuses_by_title(self.db)
        self.assertEqual(statuses["real"], "reported")
        self.assertEqual(statuses["bogus"], "false_positive")
        # And the dismissal must survive the later campaign-level promotion.
        update_status(self.db, "app/login.py", "r1", "static_confirmed")
        statuses = _statuses_by_title(self.db)
        self.assertEqual(statuses["real"], "static_confirmed")
        self.assertEqual(statuses["bogus"], "false_positive")

    def test_fallback_verdicts_are_routed_but_never_persisted(self):
        from core.graph_loader import _persist_finding_dismissals
        self.install_ctx(target_file="app/login.py", active_node="reviewer_classifier")
        _persist_finding_dismissals("reviewer_classifier", [
            {"finding_id": self.ids["bogus"], "route": "false_positive",
             "reason": "Fallback: schema parse failed"},
        ])
        self.assertEqual(_statuses_by_title(self.db)["bogus"], "reported")

    def test_missing_finding_id_is_skipped(self):
        from core.graph_loader import _persist_finding_dismissals
        self.install_ctx(target_file="app/login.py", active_node="reviewer_classifier")
        _persist_finding_dismissals("reviewer_classifier", [
            {"finding_id": None, "route": "false_positive", "reason": "x"},
        ])
        self.assertEqual(set(_statuses_by_title(self.db).values()), {"reported"})


class FindingsGateTest(_DbTest):
    def test_missing_db_cannot_answer(self):
        from core.graph_loader import campaign_has_findings_to_triage
        self.assertIsNone(
            campaign_has_findings_to_triage(os.path.join(self.tmp, "nope.db"), "r1", "")
        )

    def test_unreadable_db_cannot_answer(self):
        from core.graph_loader import campaign_has_findings_to_triage
        garbage = os.path.join(self.tmp, "garbage.db")
        with open(garbage, "w", encoding="utf-8") as f:
            f.write("this is not sqlite")
        self.assertIsNone(campaign_has_findings_to_triage(garbage, "r1", ""))

    def test_clean_campaign_is_clean(self):
        from core.graph_loader import campaign_has_findings_to_triage
        self.assertIs(campaign_has_findings_to_triage(self.db, "r1", ""), False)

    def test_live_finding_in_scope_requires_triage(self):
        from core.graph_loader import campaign_has_findings_to_triage
        write_findings(self.db, "", [_finding("real", "app/a.py")], run_id="r1")
        self.assertIs(campaign_has_findings_to_triage(self.db, "r1", "app/a.py"), True)

    def test_other_campaigns_findings_do_not_hold_the_gate_open(self):
        from core.graph_loader import campaign_has_findings_to_triage
        write_findings(self.db, "", [_finding("elsewhere", "other/b.py")], run_id="r1")
        self.assertIs(campaign_has_findings_to_triage(self.db, "r1", "app/a.py"), False)

    def test_cross_directory_finding_holds_the_gate_open(self):
        # If the campaign's only finding sits at a sink outside the slice,
        # gating it "clean" would leave a real finding unreviewed forever.
        from core.graph_loader import campaign_has_findings_to_triage
        write_findings(
            self.db, "",
            [_finding("cross-dir", "server/lib/db.js", code_paths=["app/a.py:10"])],
            run_id="r1",
        )
        self.assertIs(campaign_has_findings_to_triage(self.db, "r1", "app/a.py"), True)

    def test_fully_dismissed_campaign_is_clean(self):
        from core.graph_loader import campaign_has_findings_to_triage
        write_findings(self.db, "", [_finding("fp", "app/a.py")], run_id="r1")
        ids = {f["title"]: f["id"] for f in read_findings(self.db, run_id="r1")}
        update_finding_status_by_id(self.db, ids["fp"], "r1", "false_positive")
        self.assertIs(campaign_has_findings_to_triage(self.db, "r1", "app/a.py"), False)


class WorkflowGateTopologyTest(unittest.TestCase):
    """The shipped workflow must route clean campaigns around triage."""

    @classmethod
    def setUpClass(cls):
        import json
        wf_path = Path(_REF_ROOT) / "workflow.json"
        with open(wf_path, "r", encoding="utf-8") as f:
            cls.wf = json.load(f)
        cls.edges = {(e["from"], e.get("on", "")): e["to"] for e in cls.wf["edges"]}

    def test_gate_sits_between_researcher_and_deduplicator(self):
        self.assertEqual(self.edges[("researcher", "")], "findings_gate")
        self.assertEqual(self.edges[("findings_gate", "__DEFAULT__")], "deduplicator")

    def test_clean_route_short_circuits_to_reporter(self):
        self.assertEqual(self.edges[("findings_gate", "clean")], "reporter")

    def test_default_route_is_the_fail_safe(self):
        # Only an explicit "clean" verdict may skip stages; anything else,
        # including gate errors, must continue the full pipeline.
        gate = next(n for n in self.wf["nodes"] if n["id"] == "findings_gate")
        self.assertEqual(gate["type"], "classifier")
        self.assertEqual(gate["routes"], ["clean"])


class SecurityGuidanceScopingTest(_DbTest):
    """Threat models from single-file scans must not leak into other files' guidance.

    A shared knowledge.db accumulates one campaign per edited file. Before the
    fix, every campaign's threat model was stored repo-wide (resource = ""), so
    `mantis_security_guidance("routes/search.ts")` returned the login.ts threat
    model. These tests pin the writer (resource tagging) and the reader
    (file-scoped rows outrank repo-wide ones), plus the repo-wide fail-safe.
    """

    _TM = "# Threat Model\n\nAuthentication Subsystem (login.ts): credential handling.\n"
    _TM_SEARCH = "# Threat Model\n\nProduct Search: user-controlled criteria reaches SQL.\n"

    def setUp(self):
        super().setUp()
        from core.database import record_artifact  # local: not in module header

        self.record_artifact = record_artifact
        os.makedirs(os.path.join(self.tmp, "routes"), exist_ok=True)
        self.login = os.path.join(self.tmp, "routes", "login.ts")
        self.search = os.path.join(self.tmp, "routes", "search.ts")
        for p in (self.login, self.search):
            with open(p, "w", encoding="utf-8") as f:
                f.write("export {}\n")

    def _record_tm(self, run_id, resource, text):
        # jail_dir = repo root, as in `--path-root <repo>` scans, so canonical
        # spellings match what the MCP server queries ("routes/login.ts").
        self.install_ctx(run_id=run_id)
        self.record_artifact(
            self.db, run_id, "threat_model", "workspace/kb/THREAT_MODEL.md",
            text, metadata={"resource": resource, "agent_authored": True},
        )

    def _guidance_tm(self, filepath):
        from core.database import query_security_guidance

        self.install_ctx(run_id="query")
        return query_security_guidance(self.db, filepath=filepath, full=True)[
            "guidance_summary"
        ]

    def test_single_file_scan_tags_threat_model_with_its_file(self):
        from core.database import read_okf_concepts

        self._record_tm("run-login", self.login, self._TM)
        rows = [c for c in read_okf_concepts(self.db) if c["type"] == "Threat Model"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["resource"], "routes/login.ts")

    def test_repo_scan_threat_model_stays_repo_wide(self):
        from core.database import read_okf_concepts

        self._record_tm("run-repo", self.tmp, self._TM)
        rows = [c for c in read_okf_concepts(self.db) if c["type"] == "Threat Model"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["resource"], "")

    def test_other_files_guidance_does_not_inherit_scoped_threat_model(self):
        self._record_tm("run-login", self.login, self._TM)
        self._record_tm("run-search", self.search, self._TM_SEARCH)
        summary = self._guidance_tm("routes/search.ts")
        self.assertIn("Product Search", summary)
        self.assertNotIn("Authentication Subsystem", summary)

    def test_scoped_rows_outrank_legacy_repo_wide_rows(self):
        # Legacy row: written before the fix, repo-wide despite describing login.
        self._record_tm("run-legacy", self.tmp, self._TM)
        self._record_tm("run-search", self.search, self._TM_SEARCH)
        summary = self._guidance_tm("routes/search.ts")
        self.assertIn("Product Search", summary)
        self.assertNotIn("Authentication Subsystem", summary)

    def test_file_without_scoped_rows_still_gets_repo_wide_fallback(self):
        # Fail-safe: a file nobody scanned yet inherits repo-wide guidance
        # rather than none at all.
        self._record_tm("run-legacy", self.tmp, self._TM)
        summary = self._guidance_tm("routes/search.ts")
        self.assertIn("Authentication Subsystem", summary)

    def test_unscanned_file_does_not_inherit_scoped_artifact_fallback(self):
        # Only login.ts was ever scanned; its concept row is file-scoped, so
        # guidance for an unscanned file falls through to the raw
        # campaign_artifacts fallback -- which must not serve another file's
        # threat model either.
        self._record_tm("run-login", self.login, self._TM)
        summary = self._guidance_tm("routes/unscanned.ts")
        self.assertNotIn("Authentication Subsystem", summary)

    def test_scanned_file_still_gets_own_artifact_fallback(self):
        # A non-markdown threat model artifact (e.g. the structured JSON the
        # record_threat_model tool writes) never produces a concept row, so
        # the file's own guidance must reach it through the fallback.
        self.install_ctx(run_id="run-login")
        self.record_artifact(
            self.db, "run-login", "threat_model",
            "workspace/.structured/threat_model.json",
            "Authentication Subsystem (login.ts): credential handling.",
            metadata={"resource": self.login, "agent_authored": True},
        )
        self.assertIn(
            "Authentication Subsystem", self._guidance_tm("routes/login.ts"))
        self.assertNotIn(
            "Authentication Subsystem", self._guidance_tm("routes/search.ts"))

    def test_unscanned_file_accepts_repo_wide_artifact_fallback(self):
        self.install_ctx(run_id="run-repo")
        self.record_artifact(
            self.db, "run-repo", "threat_model",
            "workspace/.structured/threat_model.json",
            "Repo-wide threat perimeter.",
            metadata={"resource": self.tmp, "agent_authored": True},
        )
        self.assertIn(
            "Repo-wide threat perimeter", self._guidance_tm("routes/search.ts"))

    def test_same_run_sweep_keeps_both_files_threat_models(self):
        from core.database import read_okf_concepts

        # One main.py sweep shares a run_id across files; the second file's
        # frontmatter-less THREAT_MODEL.md must not delete the first file's
        # concept row.
        self.install_ctx(run_id="sweep")
        self.record_artifact(
            self.db, "sweep", "threat_model", "workspace/kb/THREAT_MODEL.md",
            self._TM, metadata={"resource": self.login, "agent_authored": True},
        )
        self.record_artifact(
            self.db, "sweep", "threat_model", "workspace/kb/THREAT_MODEL.md",
            self._TM_SEARCH, metadata={"resource": self.search, "agent_authored": True},
        )
        rows = [c for c in read_okf_concepts(self.db) if c["type"] == "Threat Model"]
        self.assertEqual(
            sorted(r["resource"] for r in rows),
            ["routes/login.ts", "routes/search.ts"],
        )
        self.assertIn("Authentication Subsystem", self._guidance_tm("routes/login.ts"))
        self.assertNotIn("Product Search", self._guidance_tm("routes/login.ts"))
        self.assertIn("Product Search", self._guidance_tm("routes/search.ts"))


class CrossCampaignMutationIsolationTest(_DbTest):
    """Per-id dismissals, dedupe merges, explicit-id rewrites, and calibration
    updates must stay within the active campaign's scope."""

    def setUp(self):
        super().setUp()
        write_findings(
            self.db, "app/a.py",
            [
                _finding("camp-a-primary", "app/a.py", description="desc a1"),
                _finding("camp-a-dup", "app/a.py", description="desc a2"),
                _finding("camp-a-cross", "shared/sink.py", description="desc cross"),
            ],
            run_id="r1",
        )
        write_findings(
            self.db, "other/b.py",
            [
                _finding("camp-b-primary", "other/b.py", description="desc b1"),
                _finding("camp-b-dup", "other/b.py", description="desc b2"),
            ],
            run_id="r1",
        )
        self.ids = {f["title"]: f["id"] for f in read_findings(self.db, run_id="r1")}

    def test_classifier_dismissal_cannot_dismiss_other_campaigns_finding(self):
        from core.graph_loader import _persist_finding_dismissals

        self.install_ctx(target_file="other/b.py", active_node="reviewer_classifier")
        _persist_finding_dismissals("reviewer_classifier", [
            {"finding_id": self.ids["camp-a-primary"], "route": "false_positive", "reason": "cross-campaign"},
            {"finding_id": self.ids["camp-b-dup"], "route": "false_positive", "reason": "in-campaign"},
        ])
        statuses = _statuses_by_title(self.db)
        self.assertEqual(statuses["camp-a-primary"], "reported")
        self.assertEqual(statuses["camp-b-dup"], "false_positive")

        # Campaign A can still dismiss its own cross-directory finding via ownership.
        self.install_ctx(target_file="app/a.py", active_node="reviewer_classifier")
        _persist_finding_dismissals("reviewer_classifier", [
            {"finding_id": self.ids["camp-a-cross"], "route": "non_viable", "reason": "owned"},
        ])
        self.assertEqual(_statuses_by_title(self.db)["camp-a-cross"], "non_viable")

    def test_dedupe_findings_cannot_merge_other_campaigns_findings(self):
        from tools.research_tools import dedupe_findings

        self.install_ctx(target_file="other/b.py", active_node="deduplicator")
        dedupe_findings(
            primary_title="camp-b-primary",
            duplicate_titles=["camp-a-dup", "camp-b-dup"],
            duplicate_ids=[self.ids["camp-a-primary"]],
            reason="same bug",
        )
        statuses = _statuses_by_title(self.db)
        self.assertEqual(statuses["camp-a-primary"], "reported")
        self.assertEqual(statuses["camp-a-dup"], "reported")
        self.assertEqual(statuses["camp-b-dup"], "duplicate_merged")
        self.assertEqual(statuses["camp-b-primary"], "reported")

    def test_report_findings_explicit_id_cannot_overwrite_other_campaign(self):
        from tools.research_tools import report_findings

        self.install_ctx(target_file="other/b.py", active_node="researcher")
        report_findings([{
            "id": self.ids["camp-a-primary"],
            "title": "hijacked-title",
            "filepath": "other/b.py",
            "severity": "LOW",
            "description": "hijacked description",
        }])
        by_id = {f["id"]: f for f in read_findings(self.db, run_id="r1")}
        self.assertEqual(by_id[self.ids["camp-a-primary"]]["title"], "camp-a-primary")
        self.assertEqual(by_id[self.ids["camp-a-primary"]]["filepath"], "app/a.py")

    def test_calibrate_finding_cannot_recalibrate_other_campaign(self):
        from tools.research_tools import calibrate_finding

        self.install_ctx(target_file="other/b.py", active_node="calibrator")
        calibrate_finding(
            finding_id=self.ids["camp-a-primary"],
            mantis_risk_score=1.5,
            impact_score=1,
            likelihood_score=1,
            priority="LOW",
        )
        calibrate_finding(
            finding_id=self.ids["camp-b-primary"],
            mantis_risk_score=8.5,
            impact_score=5,
            likelihood_score=4,
            priority="CRITICAL",
        )
        by_id = {f["id"]: f for f in read_findings(self.db, run_id="r1")}
        self.assertIsNone(by_id[self.ids["camp-a-primary"]]["mantis_risk_score"])
        self.assertEqual(by_id[self.ids["camp-b-primary"]]["mantis_risk_score"], 8.5)


class CrossTargetSharedDbIsolationTest(_DbTest):
    """A shared knowledge.db must isolate PoCs, regression checks, lineage history,
    and security guidance across distinct target repositories."""

    def setUp(self):
        super().setUp()
        import asyncio
        from core.database import record_artifact, record_learning

        self._asyncio = asyncio
        self.repo_a = os.path.join(self.tmp, "repo_a")
        self.repo_b = os.path.join(self.tmp, "repo_b")
        os.makedirs(os.path.join(self.repo_a, "app"), exist_ok=True)
        os.makedirs(os.path.join(self.repo_b, "app"), exist_ok=True)
        for repo in (self.repo_a, self.repo_b):
            with open(os.path.join(repo, "app", "auth.py"), "w", encoding="utf-8") as fh:
                fh.write("def login(u): return u\n")

        # Populate Repo A findings, PoC, threat model, FP, recurrent lineage, and learning.
        self._install_repo_ctx(self.repo_a, "run-a-1")
        write_findings(
            self.db,
            "app/auth.py",
            [
                _finding("RepoA-SQLi", "app/auth.py", description="repo A secret sqli"),
                {
                    **_finding("RepoA-FP", "app/auth.py", description="repo A benign pattern"),
                    "status": "false_positive",
                },
            ],
            run_id="run-a-1",
        )
        a_rows = read_findings(self.db, run_id="run-a-1")
        self.repo_a_sqli_id = next(f["id"] for f in a_rows if f["title"] == "RepoA-SQLi")
        self.repo_a_lineage = next(f["lineage_id"] for f in a_rows if f["title"] == "RepoA-SQLi")
        record_artifact(
            self.db,
            "run-a-1",
            "poc",
            f"workspace/repro_{self.repo_a_sqli_id}.py",
            "print('REPO_A_SECRET_POC_TOKEN')\n",
        )
        record_artifact(
            self.db,
            "run-a-1",
            "threat_model",
            "workspace/kb/THREAT_MODEL.md",
            "# Threat Model\n\nRepoA Confidential Payments Core.\n",
            metadata={"resource": self.repo_a, "agent_authored": True},
        )
        record_learning(self.db, "run-a-1", "auth", "RepoA-only trajectory rule")

        # Second Repo A run so RepoA-SQLi becomes a recurrent lineage inside Repo A.
        self._install_repo_ctx(self.repo_a, "run-a-2")
        write_findings(
            self.db,
            "app/auth.py",
            [{
                **_finding("RepoA-SQLi", "app/auth.py", description="repo A secret sqli again"),
                "lineage_id": self.repo_a_lineage,
            }],
            run_id="run-a-2",
        )

        # Populate Repo B finding on the exact same relative path `app/auth.py`.
        self._install_repo_ctx(self.repo_b, "run-b-1")
        write_findings(
            self.db,
            "app/auth.py",
            [_finding("RepoB-XSS", "app/auth.py", description="repo B reflected xss")],
            run_id="run-b-1",
        )
        b_rows = read_findings(self.db, run_id="run-b-1")
        self.repo_b_xss_id = b_rows[0]["id"]
        record_artifact(
            self.db,
            "run-b-1",
            "poc",
            f"workspace/repro_{self.repo_b_xss_id}.py",
            "print('REPO_B_OWN_POC')\n",
        )

    def _install_repo_ctx(self, repo_root: str, run_id: str, target_file: str = "app/auth.py"):
        token = current_run_context.set(RunContext(
            jail_dir=repo_root,
            path_root=repo_root,
            db_path=self.db,
            target_file=target_file,
            run_id=run_id,
        ))
        self.addCleanup(current_run_context.reset, token)

    def test_get_prior_poc_and_regression_check_refuse_cross_target_findings(self):
        from core.database import prior_findings_touching
        from tools.research_tools import get_prior_poc, record_regression_check

        # Active in Repo B (`run-b-2`): Repo A's PoC and regression check must be refused.
        self._install_repo_ctx(self.repo_b, "run-b-2")
        poc_err = self._asyncio.run(get_prior_poc(self.repo_a_sqli_id))
        self.assertIn("different target repository", poc_err)
        self.assertNotIn("REPO_A_SECRET_POC_TOKEN", poc_err)

        reg_err = record_regression_check(self.repo_a_sqli_id, "fixed", "not in repo B")
        self.assertIn("different target repository", reg_err)

        # Same-target prior PoC in Repo B still succeeds.
        poc_ok = self._asyncio.run(get_prior_poc(self.repo_b_xss_id))
        self.assertTrue(poc_ok.startswith("SUCCESS:"), poc_ok)
        self.assertIn("REPO_B_OWN_POC", poc_ok)

        # prior_findings_touching in Repo B sees only Repo B's open prior finding.
        touching_b = prior_findings_touching(self.db, "run-b-2", ["app/auth.py"])
        self.assertEqual([f["title"] for f in touching_b], ["RepoB-XSS"])

    def test_query_lineage_and_security_guidance_do_not_leak_across_targets(self):
        from tools.research_tools import get_security_guidance, query_lineage

        # Active in Repo B (`run-b-2`): querying `app/auth.py` or Repo A's lineage_id must not leak Repo A.
        self._install_repo_ctx(self.repo_b, "run-b-2")
        lin_fp_b = query_lineage(filepath="app/auth.py")
        self.assertIn("RepoB-XSS", lin_fp_b)
        self.assertNotIn("RepoA-SQLi", lin_fp_b)

        lin_id_a_from_b = query_lineage(lineage_id=self.repo_a_lineage)
        self.assertTrue(lin_id_a_from_b.startswith("NO_DATA:"), lin_id_a_from_b)

        guidance_b = get_security_guidance("app/auth.py")
        self.assertIn("RepoB-XSS", guidance_b)
        self.assertNotIn("RepoA-SQLi", guidance_b)
        self.assertNotIn("RepoA-FP", guidance_b)
        self.assertNotIn("RepoA Confidential Payments Core", guidance_b)
        self.assertNotIn("RepoA-only trajectory rule", guidance_b)
        self.assertNotIn(self.repo_a_lineage, guidance_b)

        # Switching back to Repo A (`run-a-3`) restores visibility of Repo A's history and hides Repo B.
        self._install_repo_ctx(self.repo_a, "run-a-3")
        guidance_a = get_security_guidance("app/auth.py")
        self.assertIn("RepoA-SQLi", guidance_a)
        self.assertIn("RepoA-FP", guidance_a)
        self.assertIn("RepoA-only trajectory rule", guidance_a)
        self.assertNotIn("RepoB-XSS", guidance_a)

    def test_standalone_cli_and_mcp_queries_isolate_absolute_and_uncreated_paths(self):
        import shutil
        from core.database import query_historical_lineage, query_security_guidance
        from scripts import advise, mcp_server

        # Clear active RunContext to simulate standalone CLI (`advise.py`) and MCP server calls.
        tok = current_run_context.set(None)
        self.addCleanup(current_run_context.reset, tok)

        repo_c = os.path.join(self.tmp, "repo_c_empty")
        os.makedirs(repo_c, exist_ok=True)
        uncreated_c = os.path.join(repo_c, "app", "auth.py")
        abs_b_auth = os.path.join(self.repo_b, "app", "auth.py")

        # 1. Absolute file query into Repo B outside RunContext preserves repo-relative filepath
        #    and never leaks Repo A's findings, threat model, FPs, or learnings.
        g_b = query_security_guidance(self.db, abs_b_auth)
        self.assertEqual(g_b["filepath"], "app/auth.py")
        self.assertEqual([f["title"] for f in g_b["confirmed_vulnerabilities"]], ["RepoB-XSS"])
        self.assertEqual(g_b["false_positives"], [])
        self.assertEqual(g_b["learned_invariants"], [])
        self.assertNotIn("RepoA Confidential Payments Core", g_b["guidance_summary"])

        # 2. Uncreated file inside a third repository (`repo_c_empty`) does NOT fall back to
        #    whole-DB unanchored leakage in either core.database or advise.py standalone helpers.
        g_c = query_security_guidance(self.db, uncreated_c)
        self.assertEqual(g_c["filepath"], "app/auth.py")
        self.assertEqual(g_c["confirmed_vulnerabilities"], [])
        self.assertEqual(g_c["threat_model"], "")
        self.assertEqual(g_c["learned_invariants"], [])

        adv_c = advise.query_guidance_standalone(self.db, uncreated_c)
        self.assertEqual(adv_c["confirmed_vulnerabilities"], [])
        self.assertEqual(advise.query_lineage_standalone(self.db, filepath=uncreated_c), [])
        self.assertEqual(query_historical_lineage(self.db, filepath=uncreated_c), [])
        rem_c = advise.query_remediation_standalone(self.db, uncreated_c)
        self.assertIn("error", rem_c)

        # 3. MCP server pointing at a shared state directory scopes findings, check_change,
        #    and security_guidance strictly to `state.repo`.
        mcp_home = os.path.join(self.tmp, "shared_mcp_state")
        os.makedirs(mcp_home, exist_ok=True)
        shutil.copy2(self.db, os.path.join(mcp_home, "knowledge.db"))
        state_c = mcp_server.MantisState(repo_c, home=mcp_home)
        self.assertEqual(mcp_server.get_findings(state_c)["findings"], [])
        mcp_g_c = mcp_server.security_guidance(state_c, "app/auth.py")
        self.assertEqual(mcp_g_c["confirmed_vulnerabilities"], [])
        gate_c = mcp_server.check_change(state_c, files=["app/auth.py"], include_coverage=False)
        self.assertEqual(gate_c["verdict"], "PASS")


class DirectorySliceScopingTest(unittest.IsolatedAsyncioTestCase):
    """Cross-functional directory slices default list_files('') to their slice
    and require in-slice source reads before crediting coverage."""

    async def test_cross_functional_slice_defaults_list_files_and_gates_coverage_reads(self):
        import json
        from core.budget import BudgetConfig, BudgetController
        from core.environments.static_env import StaticOnlyEnvironment
        from main import _is_in_scope_code_read, _render_slice_scope_directive
        from tools.research_tools import list_files

        with tempfile.TemporaryDirectory() as td:
            root = os.path.realpath(td)
            svc_a = os.path.join(root, "aaa_repo_a")
            svc_b = os.path.join(root, "zzz_service_b")
            os.makedirs(svc_a)
            os.makedirs(svc_b)
            Path(os.path.join(svc_a, "noise.py")).write_text("x = 1\n")
            Path(os.path.join(svc_b, "billing.py")).write_text("y = 2\n")

            ctx = RunContext(
                jail_dir=root,
                db_path="",
                target_file=svc_b,
                group_targets=(svc_b,),
                scan_mode="cross-functional",
                sandbox=StaticOnlyEnvironment(target_path=root),
            )
            tok = current_run_context.set(ctx)
            try:
                default_list = json.loads(await list_files(""))
                self.assertEqual(default_list, ["zzz_service_b/billing.py"])
                root_list = json.loads(await list_files("."))
                self.assertEqual(root_list, ["aaa_repo_a/noise.py", "zzz_service_b/billing.py"])
            finally:
                current_run_context.reset(tok)

            directive = _render_slice_scope_directive(svc_b, {"targets": [svc_b]}, root)
            self.assertIn("'zzz_service_b/'", directive)

            ctrl = BudgetController(BudgetConfig(), run_id="r")
            # Workspace artifact read: never counts as source examination
            ctrl.record_tool_call(
                "researcher",
                "read_file",
                in_scope=_is_in_scope_code_read(ctx, "read_file", {"filepath": "workspace/plan.json"}),
            )
            self.assertEqual(ctrl.audit_code_reads, 0)
            # Out-of-slice sibling read: allowed for caller/callee context, does not stamp svc_b covered
            ctrl.record_tool_call(
                "researcher",
                "read_file",
                in_scope=_is_in_scope_code_read(ctx, "read_file", {"filepath": "aaa_repo_a/noise.py"}),
            )
            self.assertEqual(ctrl.audit_code_reads, 0)
            # In-slice source read: credits coverage
            ctrl.record_tool_call(
                "researcher",
                "read_file",
                in_scope=_is_in_scope_code_read(ctx, "read_file", {"filepath": "zzz_service_b/billing.py"}),
            )
            self.assertEqual(ctrl.audit_code_reads, 1)


if __name__ == "__main__":
    unittest.main()

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

"""Regression tests for three workstreams:

P6  -- Per-finding review verdicts (core.config.FindingVerdict /
       ExtendedReviewVerdict; graph_loader._coerce_finding_verdicts /
       _persist_finding_dismissals / _derive_campaign_route and the
       classifier wiring). One campaign-level ReviewVerdict used to judge 14
       independent findings at once; these tests pin the per-finding
       persistence rules, the conservative same-filepath guards, the
       "Fallback:" never-learn contract, and the INV-6 fail-safe (empty
       finding_verdicts == exact pre-P6 behavior).

P4  -- Success-only coverage stamps (graph_loader._make_completion_stamp_callback,
       cfg["on_enter_status"] exported empty). A stamp used to fire at node
       ENTRY, so a crashed campaign had already marked its target scanned.
       These tests pin: the entry-stamp map main.py consumes is empty, the
       stamp rides after_agent_callback (which ADK skips when the node body
       raises), the INV-1 sandbox_executed gate for dynamic statuses, and
       best-effort persistence.

R4 + P4-sentinel -- Recall target scoping at path-component boundaries
       (core.memory._canonicalize_for_match / _matches_target / recall) and
       the reached-sink evidence chokepoint (tools.sandbox_tools
       ._note_dynamic_evidence and run_sandbox's string-transport branch).
       Substring matching used to hand `lib` the history of `librandom/`;
       the sandbox_executed flag used to be set by any command whose exit
       code was not 127.

Run with:
    GOOGLE_CLOUD_PROJECT=your-project MANTIS_NEUTER_MATRIX=1 PYTHONPATH=reference \
        reference/.venv/bin/python3 -m unittest reference.tests.test_verdicts_recall_sentinel

No network, no real LLM calls: everything is driven through classifier
callables (node.__pydantic_private__["_func"]), fake sandboxes/contexts, and
direct sqlite3 assertions.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import types as _pytypes
import unittest
from pathlib import Path
from unittest.mock import patch

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

import core.graph_loader as gl
from core.config import ExtendedReviewVerdict, FindingVerdict
from core.context import RunContext, current_run_context
from core.database import init_db, write_findings
from core.memory import _canonicalize_for_match, _matches_target, recall
from core.schemas import ReviewVerdict
from tools import sandbox_tools as st
from tools.sandbox_tools import MANTIS_SENTINEL_TOKEN, run_sandbox


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


_seed_counter = 0


def _seed_finding(db_path, filepath, run_id="r_p6", status="reported"):
    """Inserts one findings row directly and returns its id.

    Titles are made unique per insert: the findings table carries
    UNIQUE(filepath, title, description, line_numbers, run_id), and several
    tests deliberately seed two findings at the SAME filepath.
    """
    global _seed_counter
    _seed_counter += 1
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO findings (run_id, filepath, title, severity, description, status) "
            "VALUES (?, ?, ?, 'HIGH', 'd', ?)",
            (run_id, filepath, f"T{_seed_counter}", status),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def _status_of(db_path, filepath):
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT status FROM findings WHERE filepath = ?", (filepath,)
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def _all_statuses(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return {
            fp: status
            for fp, status in conn.execute("SELECT filepath, status FROM findings")
        }
    finally:
        conn.close()


class _Ctx:
    """Fake ADK node context for classifier callables (TestStatusIntegrity pattern)."""

    state: dict = {}

    def __init__(self):
        self.state = {}


# ===========================================================================
# P6-1: wire compatibility of ExtendedReviewVerdict
# ===========================================================================


class TestExtendedVerdictWireCompat(unittest.TestCase):
    """INV-6: every wire-format-valid strict ReviewVerdict must remain valid
    against ExtendedReviewVerdict, with finding_verdicts defaulting to [].

    If this breaks, ADK's response re-validation (model_validate_json against
    the bound schema) rejects every old-format reviewer response, and each
    review stage dies with a runtime validation error instead of routing.
    """

    def test_strict_review_verdict_json_validates_with_empty_finding_verdicts(self):
        strict_json = ReviewVerdict(route="confirmed", reason="ok").model_dump_json()
        extended = ExtendedReviewVerdict.model_validate_json(strict_json)
        self.assertEqual(extended.route, "confirmed")
        self.assertEqual(extended.reason, "ok")
        self.assertEqual(extended.finding_verdicts, [],
                         "Absent finding_verdicts must default to [] -- the "
                         "empty list IS the pre-P6 fail-safe contract.")

    def test_extended_verdict_round_trips_finding_verdicts(self):
        payload = {
            "route": "false_positive",
            "reason": "summary",
            "finding_verdicts": [
                {"finding_id": 3, "route": "false_positive", "reason": "nah"}
            ],
        }
        extended = ExtendedReviewVerdict.model_validate(payload)
        self.assertEqual(len(extended.finding_verdicts), 1)
        self.assertEqual(extended.finding_verdicts[0].finding_id, 3)

    def test_finding_verdict_tolerates_extra_fields(self):
        """FindingVerdict is extra='ignore' by design: one malformed or
        over-decorated entry must never invalidate its 13 siblings."""
        fv = FindingVerdict.model_validate(
            {"finding_id": 1, "route": "confirmed", "reason": "", "confidence": 0.9}
        )
        self.assertEqual(fv.finding_id, 1)

    def test_shipped_reviewer_node_binds_extended_verdict_without_fork_from(self):
        """Regression test: shipped workflow.json (shared-prefix audit_stem) and
        standalone non-prefix_group reviewer nodes BOTH bind ExtendedReviewVerdict
        and carry the PER-FINDING VERDICTS instruction contract."""
        wf_path = Path(_REF_ROOT) / "workflow.json"
        wf, _cfg = gl.load_workflow_from_json(str(wf_path), load_local=False)
        reviewer_agent = None
        for edge in wf.edges:
            for n in (edge.from_node, edge.to_node):
                agent = getattr(n, "agent", n)
                if getattr(agent, "name", None) == "reviewer":
                    reviewer_agent = agent
                    break
        self.assertIsNotNone(reviewer_agent)
        # Shipped workflow.json places reviewer in prefix_group="audit_stem", so
        # ExtendedReviewVerdict is bound via model._output_schema_override (keeping
        # ADK's tool list free of stage-mutating set_model_response) and PER-FINDING
        # VERDICTS rides in u_reviewer's stage_role_prompt closure.
        self.assertIsNone(reviewer_agent.output_schema)
        self.assertIs(reviewer_agent.model._output_schema_override, ExtendedReviewVerdict)
        closure_texts = [
            c.cell_contents
            for cb in (reviewer_agent.before_model_callback or [])
            for c in (getattr(cb, "__closure__", None) or ())
            if isinstance(getattr(c, "cell_contents", None), str)
        ]
        self.assertTrue(
            any("PER-FINDING VERDICTS:" in t for t in closure_texts),
            "PER-FINDING VERDICTS missing from prefix_group reviewer stage_role_prompt",
        )

        # Also verify a non-prefix_group reviewer without fork_from binds output_schema directly.
        with tempfile.TemporaryDirectory() as td:
            raw = json.loads(wf_path.read_text(encoding="utf-8"))
            for nd in raw["nodes"]:
                nd.pop("prefix_group", None)
                nd.pop("fork_from", None)
            plain_p = Path(td) / "plain_wf.json"
            plain_p.write_text(json.dumps(raw), encoding="utf-8")
            wf_plain, _ = gl.load_workflow_from_json(str(plain_p), load_local=False)
            plain_rev = next(
                getattr(n, "agent", n)
                for e in wf_plain.edges
                for n in (e.from_node, e.to_node)
                if getattr(getattr(n, "agent", n), "name", None) == "reviewer"
            )
            self.assertIs(plain_rev.output_schema, ExtendedReviewVerdict)
            self.assertIn("PER-FINDING VERDICTS:", plain_rev.instruction(None))


# ===========================================================================
# P6-2: _coerce_finding_verdicts normalization
# ===========================================================================


class TestCoerceFindingVerdicts(unittest.TestCase):
    """The classifier receives whichever form survived the output_key /
    session-state round-trip: the pydantic object, its dict dump, or parsed
    JSON. All three must normalize identically, and a malformed entry must
    be dropped without killing its well-formed siblings.
    """

    def test_pydantic_object_form_normalizes(self):
        verdict = ExtendedReviewVerdict(
            route="confirmed",
            reason="r",
            finding_verdicts=[FindingVerdict(finding_id=7, route="CONFIRMED", reason="x")],
        )
        entries = gl._coerce_finding_verdicts(verdict)
        self.assertEqual(
            entries, [{"finding_id": 7, "route": "confirmed", "reason": "x"}]
        )

    def test_dict_form_normalizes(self):
        entries = gl._coerce_finding_verdicts(
            {
                "route": "confirmed",
                "reason": "r",
                "finding_verdicts": [
                    {"finding_id": "12", "route": " False_Positive ", "reason": None}
                ],
            }
        )
        # finding_id arrives as a numeric string (JSON round-trips can
        # stringify ints); int() coercion must accept it. Route is lowercased
        # and stripped; None reason becomes "".
        self.assertEqual(
            entries, [{"finding_id": 12, "route": "false_positive", "reason": ""}]
        )

    def test_json_string_form_normalizes(self):
        """The parsed model JSON (what json.loads yields from the model's raw
        response text) is the third transport form."""
        raw = json.dumps(
            {
                "route": "confirmed",
                "reason": "r",
                "finding_verdicts": [
                    {"finding_id": 5, "route": "non_viable", "reason": "dead code"}
                ],
            }
        )
        entries = gl._coerce_finding_verdicts(json.loads(raw))
        self.assertEqual(
            entries, [{"finding_id": 5, "route": "non_viable", "reason": "dead code"}]
        )

    def test_malformed_entries_dropped_without_killing_siblings(self):
        entries = gl._coerce_finding_verdicts(
            {
                "route": "confirmed",
                "reason": "r",
                "finding_verdicts": [
                    {"finding_id": 1, "route": "confirmed", "reason": "good"},
                    {"finding_id": 2},                      # missing route: dropped
                    {"finding_id": 3, "route": "", "reason": "empty"},   # blank route: dropped
                    {"finding_id": 4, "route": None, "reason": "none"},  # None route: dropped
                    # Non-int id: KEPT for aggregate routing, but finding_id
                    # normalizes to None so persistence will skip it.
                    {"finding_id": "banana", "route": "false_positive", "reason": "b"},
                    {"finding_id": 6, "route": "FALSE_POSITIVE", "reason": "sib"},
                ],
            }
        )
        self.assertEqual(len(entries), 3, "Exactly the three usable entries survive.")
        self.assertEqual(entries[0], {"finding_id": 1, "route": "confirmed", "reason": "good"})
        self.assertEqual(entries[1], {"finding_id": None, "route": "false_positive", "reason": "b"})
        self.assertEqual(entries[2], {"finding_id": 6, "route": "false_positive", "reason": "sib"})

    def test_absent_empty_or_unusable_field_yields_empty_list(self):
        """[] is the INV-6 fail-safe: campaign-level behavior, unchanged."""
        self.assertEqual(gl._coerce_finding_verdicts({"route": "confirmed", "reason": "r"}), [])
        self.assertEqual(
            gl._coerce_finding_verdicts(
                {"route": "confirmed", "reason": "r", "finding_verdicts": []}
            ),
            [],
        )
        self.assertEqual(
            gl._coerce_finding_verdicts(
                {"route": "confirmed", "reason": "r", "finding_verdicts": "not-a-list"}
            ),
            [],
        )
        self.assertEqual(gl._coerce_finding_verdicts("just a string"), [])
        self.assertEqual(gl._coerce_finding_verdicts(None), [])

    def test_routes_are_lowercased(self):
        entries = gl._coerce_finding_verdicts(
            {
                "route": "confirmed",
                "reason": "r",
                "finding_verdicts": [
                    {"finding_id": 1, "route": "CONFIRMED", "reason": ""},
                    {"finding_id": 2, "route": "Non_Viable", "reason": ""},
                ],
            }
        )
        self.assertEqual([e["route"] for e in entries], ["confirmed", "non_viable"],
                         "Statuses are lowercase everywhere in the pipeline; "
                         "coercion is the single normalization point.")


# ===========================================================================
# P6-3: _derive_campaign_route aggregation
# ===========================================================================


class TestDeriveCampaignRoute(unittest.TestCase):
    """The campaign route is DERIVED from per-finding judgments. Any promoted
    finding routes forward (its dismissed siblings were already persisted
    individually); an all-dismissed set routes to the modal dismissal.
    """

    @staticmethod
    def _e(route, fid=1, reason=""):
        return {"finding_id": fid, "route": route, "reason": reason}

    def test_any_promoted_finding_routes_campaign_forward(self):
        entries = [
            self._e("false_positive", 1),
            self._e("confirmed", 2),
            self._e("non_viable", 3),
        ]
        self.assertEqual(gl._derive_campaign_route(entries), "confirmed",
                         "One live vulnerability must carry the campaign to "
                         "the downstream stages; dismissed siblings were "
                         "recorded individually and lose nothing.")

    def test_all_dismissed_routes_to_modal_dismissal(self):
        entries = [self._e("false_positive", i) for i in range(13)] + [
            self._e("non_viable", 99)
        ]
        self.assertEqual(gl._derive_campaign_route(entries), "false_positive",
                         "A 13-fp / 1-nv split reads as the false_positive "
                         "campaign it substantively is.")

    def test_tie_breaks_to_first_seen_dismissal(self):
        entries = [
            self._e("non_viable", 1),
            self._e("false_positive", 2),
            self._e("false_positive", 3),
            self._e("non_viable", 4),
        ]
        self.assertEqual(gl._derive_campaign_route(entries), "non_viable",
                         "2-2 tie must break to the first-seen route.")

    def test_unknown_promotion_route_is_returned_verbatim(self):
        """A non-dismissal route is 'promoted' by definition of the aggregate;
        the classifier's own declared-routes check handles vocabulary."""
        entries = [self._e("false_positive", 1), self._e("weird_route", 2)]
        self.assertEqual(gl._derive_campaign_route(entries), "weird_route")


# ===========================================================================
# P6-4..8: end-to-end through the classifier callable
# ===========================================================================


class TestClassifierPerFindingVerdicts(unittest.TestCase):
    """Drives create_classifier's private callable exactly the way the graph
    does (TestStatusIntegrity pattern) and asserts DB effects directly.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_test_p6_cls_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = os.path.join(self.tmp, "p6.db")
        init_db(self.db)

    def _run_classifier(self, node_input, target_file="", run_id="r_p6",
                        db_path=None, routes=("confirmed",)):
        node = gl.create_classifier("reviewer_classifier", list(routes))
        fn = node.__pydantic_private__["_func"]
        token = current_run_context.set(RunContext(
            jail_dir=self.tmp,
            db_path=db_path if db_path is not None else self.db,
            target_file=target_file,
            run_id=run_id,
        ))
        try:
            return asyncio.run(fn(_Ctx(), node_input))
        finally:
            current_run_context.reset(token)

    # -------------------------------------------------- 4: mixed, distinct paths

    def test_mixed_verdicts_distinct_paths_stamp_dismissed_only_and_route_forward(self):
        """Dismissed findings' paths get stamped (lowercase), the promoted
        finding's path is untouched, and the campaign routes forward. If this
        breaks, either dismissals stop being learned across runs (empty FP
        set forever) or a promotion gets erased by its siblings' dismissals.
        """
        id_a = _seed_finding(self.db, "a.py")
        id_b = _seed_finding(self.db, "b.py")
        id_c = _seed_finding(self.db, "c.py")

        event = self._run_classifier({
            "route": "false_positive",       # top-level summary is OVERRIDDEN
            "reason": "summary",
            "finding_verdicts": [
                {"finding_id": id_a, "route": "CONFIRMED", "reason": "real"},
                {"finding_id": id_b, "route": "FALSE_POSITIVE", "reason": "nah"},
                {"finding_id": id_c, "route": "non_viable", "reason": "dead"},
            ],
        })

        self.assertEqual(_status_of(self.db, "a.py"), "confirmed",
                         "The promoted finding's path must be stamped "
                         "confirmed and never dismissed by sibling dismissals.")
        self.assertEqual(_status_of(self.db, "b.py"), "false_positive",
                         "Dismissal must persist, lowercase.")
        self.assertEqual(_status_of(self.db, "c.py"), "non_viable",
                         "Each dismissal persists under its own route.")
        self.assertEqual(event.actions.route, "confirmed",
                         "Any promoted finding routes the campaign forward, "
                         "overriding the top-level dismissal summary.")

    # -------------------------------------------------- 5: same-filepath guards

    def test_split_verdicts_at_same_filepath_stamp_only_the_dismissed_id(self):
        """Dismissals address the finding id, not the filepath, so a
        dismissal at a path that also hosts a promoted finding stamps
        exactly the dismissed row. The promotion is untouched, and the
        dismissed row's terminal status protects it from being laundered
        into static_confirmed by a later filepath-wide stamp."""
        id_a = _seed_finding(self.db, "x.py")
        id_b = _seed_finding(self.db, "x.py")

        self._run_classifier({
            "route": "confirmed",
            "reason": "summary",
            "finding_verdicts": [
                {"finding_id": id_a, "route": "confirmed", "reason": "real"},
                {"finding_id": id_b, "route": "false_positive", "reason": "nah"},
            ],
        })

        conn = sqlite3.connect(self.db)
        try:
            rows = dict(conn.execute(
                "SELECT id, status FROM findings WHERE filepath = 'x.py'"
            ).fetchall())
        finally:
            conn.close()
        self.assertEqual(rows[id_a], "confirmed",
                         "The promoted finding must be stamped confirmed and "
                         "never touched by a sibling's dismissal.")
        self.assertEqual(rows[id_b], "false_positive",
                         "The dismissed finding must be stamped even when a "
                         "promoted sibling shares its path.")

    def test_unreviewed_sibling_at_same_filepath_is_never_stamped(self):
        """A sibling the reviewer never ruled on cannot be dismissed by mere
        proximity: the stamp lands on the reviewed finding's id and nowhere
        else."""
        id_a = _seed_finding(self.db, "y.py")
        id_b = _seed_finding(self.db, "y.py")  # active sibling with NO verdict

        self._run_classifier({
            "route": "false_positive",
            "reason": "summary",
            "finding_verdicts": [
                {"finding_id": id_a, "route": "false_positive", "reason": "nah"},
            ],
        })

        conn = sqlite3.connect(self.db)
        try:
            rows = dict(conn.execute(
                "SELECT id, status FROM findings WHERE filepath = 'y.py'"
            ).fetchall())
        finally:
            conn.close()
        self.assertEqual(rows[id_a], "false_positive",
                         "The reviewed finding must be stamped.")
        self.assertEqual(rows[id_b], "reported",
                         "An unreviewed sibling must stay untouched.")

    def test_fully_covered_filepath_is_stamped(self):
        """When every finding at the path carries a dismissal entry, every
        row is stamped -- one stamp per reviewed finding id."""
        id_a = _seed_finding(self.db, "z.py")
        id_b = _seed_finding(self.db, "z.py")

        self._run_classifier({
            "route": "false_positive",
            "reason": "summary",
            "finding_verdicts": [
                {"finding_id": id_a, "route": "false_positive", "reason": "a"},
                {"finding_id": id_b, "route": "false_positive", "reason": "b"},
            ],
        })

        conn = sqlite3.connect(self.db)
        try:
            rows = conn.execute(
                "SELECT status FROM findings WHERE filepath = 'z.py'"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual([r[0] for r in rows], ["false_positive", "false_positive"])

    def test_protected_sibling_does_not_block_coverage(self):
        """A sibling already in a terminal status (e.g. dynamic_confirmed)
        cannot be altered by a dismissal stamp, so it must not count as
        'active' when deciding coverage -- and the monotonic guard in
        update_status, not this code, keeps it from being overwritten."""
        id_a = _seed_finding(self.db, "w.py")
        _seed_finding(self.db, "w.py", status="dynamic_confirmed")

        self._run_classifier({
            "route": "false_positive",
            "reason": "summary",
            "finding_verdicts": [
                {"finding_id": id_a, "route": "false_positive", "reason": "nah"},
            ],
        })

        conn = sqlite3.connect(self.db)
        try:
            rows = dict(conn.execute(
                "SELECT id, status FROM findings WHERE filepath = 'w.py'"
            ).fetchall())
        finally:
            conn.close()
        self.assertEqual(rows[id_a], "false_positive",
                         "The reviewed finding must be stamped.")
        self.assertIn("dynamic_confirmed", rows.values(),
                      "Dynamic proof must never be erased by a dismissal.")

    # -------------------------------------------------- 6: Fallback contract

    def test_fallback_reason_per_finding_is_routed_but_never_persisted(self):
        """A 'Fallback:' verdict is harness-synthesized from garbage or
        safety-blocked output -- no review happened. Persisting it at EITHER
        granularity would teach every future run that a real reviewer
        dismissed the finding."""
        id_a = _seed_finding(self.db, "fb1.py")
        id_b = _seed_finding(self.db, "fb2.py")

        event = self._run_classifier({
            "route": "false_positive",
            "reason": "Fallback: model refused",
            "finding_verdicts": [
                {"finding_id": id_a, "route": "false_positive",
                 "reason": "Fallback: model refused"},
                {"finding_id": id_b, "route": "false_positive",
                 "reason": "  Fallback: whitespace-prefixed too"},
            ],
        })

        self.assertEqual(_status_of(self.db, "fb1.py"), "reported",
                         "A synthesized per-finding dismissal was learned as fact.")
        self.assertEqual(_status_of(self.db, "fb2.py"), "reported")
        # Routing still proceeds (fail-closed leaves the promotion path, the
        # graph must not stall): route derives to the modal dismissal, which
        # is undeclared here, so the event takes the default route.
        self.assertIsNotNone(event)

    def test_mixed_fallback_and_genuine_dismissals_persist_only_the_genuine(self):
        id_a = _seed_finding(self.db, "gen.py")
        id_b = _seed_finding(self.db, "synth.py")

        self._run_classifier({
            "route": "false_positive",
            "reason": "summary",
            "finding_verdicts": [
                {"finding_id": id_a, "route": "false_positive", "reason": "reviewed"},
                {"finding_id": id_b, "route": "false_positive",
                 "reason": "Fallback: refusal"},
            ],
        })

        self.assertEqual(_status_of(self.db, "gen.py"), "false_positive")
        self.assertEqual(_status_of(self.db, "synth.py"), "reported",
                         "The synthesized sibling must not ride along with "
                         "the genuine dismissal.")

    # -------------------------------------------------- 7: INV-6 empty list

    def test_empty_finding_verdicts_falls_back_to_campaign_level_persistence(self):
        """finding_verdicts == [] must be EXACTLY pre-P6: the campaign-level
        _persist_dismissal_verdict path fires and stamps the campaign target
        subtree, observable as the same DB effect the old code produced."""
        _seed_finding(self.db, "app.py")
        _seed_finding(self.db, "elsewhere.py")

        event = self._run_classifier(
            {"route": "false_positive", "reason": "Sink unreachable.",
             "finding_verdicts": []},
            target_file="app.py",
        )

        self.assertEqual(_status_of(self.db, "app.py"), "false_positive",
                         "Pre-P6 campaign-level dismissal persistence must "
                         "fire when the per-finding list is empty.")
        self.assertEqual(_status_of(self.db, "elsewhere.py"), "reported",
                         "The campaign stamp is scoped to the campaign "
                         "target, never the whole run.")
        self.assertIsNotNone(event)

    def test_absent_finding_verdicts_behaves_identically_to_empty(self):
        _seed_finding(self.db, "app.py")
        self._run_classifier(
            {"route": "false_positive", "reason": "Sink unreachable."},
            target_file="app.py",
        )
        self.assertEqual(_status_of(self.db, "app.py"), "false_positive")

    # -------------------------------------------------- 8: broken DB survival

    def test_unwritable_db_during_per_finding_persistence_does_not_kill_routing(self):
        """Persistence is best-effort by design: a broken database must never
        break routing. If this raises, one DB hiccup kills the campaign."""
        event = self._run_classifier(
            {
                "route": "false_positive",
                "reason": "summary",
                "finding_verdicts": [
                    {"finding_id": 1, "route": "false_positive", "reason": "x"},
                ],
            },
            db_path=os.path.join(self.tmp, "no", "such", "dir.db"),
        )
        self.assertIsNotNone(event, "A DB failure broke classifier routing.")

    def test_json_string_node_input_with_finding_verdicts_routes_and_persists(self):
        """The classifier's string branch (json.loads of raw response text)
        must reach the same per-finding pipeline as the dict form."""
        id_a = _seed_finding(self.db, "s1.py")
        id_b = _seed_finding(self.db, "s2.py")

        raw = json.dumps({
            "route": "false_positive",
            "reason": "summary",
            "finding_verdicts": [
                {"finding_id": id_a, "route": "confirmed", "reason": "real"},
                {"finding_id": id_b, "route": "false_positive", "reason": "nah"},
            ],
        })
        event = self._run_classifier(raw)

        self.assertEqual(_status_of(self.db, "s1.py"), "confirmed")
        self.assertEqual(_status_of(self.db, "s2.py"), "false_positive")
        self.assertEqual(event.actions.route, "confirmed")


# ===========================================================================
# P4-stamps: success-only coverage stamps
# ===========================================================================


class TestSuccessOnlyCoverageStamps(unittest.TestCase):
    """Coverage stamps moved from node ENTRY (main.py's status_map loop) to
    each stamped agent's after_agent_callback. A crashed campaign must not
    stamp its target as covered/scanned.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_test_p4_stamp_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = os.path.join(self.tmp, "p4.db")
        init_db(self.db)

    def _set_ctx(self, **overrides):
        kwargs = dict(jail_dir=self.tmp, db_path=self.db,
                      target_file="app.py", run_id="r_p4")
        kwargs.update(overrides)
        rc = RunContext(**kwargs)
        token = current_run_context.set(rc)
        self.addCleanup(current_run_context.reset, token)
        return rc

    # -------------------------------------------------- 9: loader export

    def test_loader_exports_empty_on_enter_status_map(self):
        """main.py consumes cfg['on_enter_status'] and stamps at node ENTRY --
        the exact behavior that let a crashed campaign mark its target
        scanned. The map the loader hands it must therefore be empty (the key
        stays present: it is part of the config contract main.py reads
        unconditionally)."""
        wf_path = Path(_REF_ROOT) / "workflow.json"
        # load_local=False: a developer's workflow.local.json overlay must not
        # leak into this assertion.
        _wf, cfg = gl.load_workflow_from_json(str(wf_path), load_local=False)
        self.assertIn("on_enter_status", cfg,
                      "The key itself is contract: main.py reads it "
                      "unconditionally.")
        self.assertEqual(cfg["on_enter_status"], {},
                         "A non-empty map re-arms the entry-time stamp in "
                         "main.py and double-fires with the completion "
                         "callback.")

    # -------------------------------------------------- 10: callback behavior

    def test_clean_completion_stamps_exactly_once(self):
        _seed_finding(self.db, "app.py", run_id="r_p4")
        self._set_ctx()
        cb = gl._make_completion_stamp_callback("reproducer", "static_confirmed")

        calls = []
        import core.database as db_mod
        real_update = db_mod.update_status

        def counting_update(*a, **kw):
            calls.append(a)
            return real_update(*a, **kw)

        with patch.object(db_mod, "update_status", counting_update):
            result = cb(callback_context=object())

        self.assertIsNone(result, "The callback is a pure side effect and "
                                  "must not alter the event stream.")
        self.assertEqual(len(calls), 1, "Exactly one stamp per completion.")
        self.assertEqual(_status_of(self.db, "app.py"), "static_confirmed")

    def test_dynamic_status_without_sandbox_executed_is_skipped(self):
        """INV-1: a node that never reached a sandbox cannot claim dynamic
        proof. The ctx.sandbox_executed gate main.py applied at entry time
        must be preserved verbatim in the completion callback."""
        _seed_finding(self.db, "app.py", run_id="r_p4")
        self._set_ctx(sandbox_executed=False)
        cb = gl._make_completion_stamp_callback("patcher", "dynamic_confirmed")

        self.assertIsNone(cb(callback_context=object()))
        self.assertEqual(_status_of(self.db, "app.py"), "reported",
                         "dynamic_confirmed was stamped without any "
                         "reached-sink evidence (INV-1 violation).")

    def test_dynamic_status_with_sandbox_executed_stamps(self):
        """Positive control for the INV-1 gate."""
        _seed_finding(self.db, "app.py", run_id="r_p4")
        self._set_ctx(sandbox_executed=True)
        cb = gl._make_completion_stamp_callback("patcher", "dynamic_confirmed")
        cb(callback_context=object())
        self.assertEqual(_status_of(self.db, "app.py"), "dynamic_confirmed")

    def test_update_status_raising_does_not_propagate(self):
        """Persistence stays best-effort: a DB hiccup must not kill the
        campaign, and the callback must still return None."""
        self._set_ctx()
        cb = gl._make_completion_stamp_callback("reproducer", "static_confirmed")

        import core.database as db_mod

        def exploding_update(*a, **kw):
            raise sqlite3.OperationalError("disk I/O error")

        with patch.object(db_mod, "update_status", exploding_update):
            try:
                result = cb(callback_context=object())
            except Exception as exc:  # pragma: no cover - the failure being pinned
                self.fail(f"Completion-stamp callback propagated: {exc}")
        self.assertIsNone(result)

    def test_missing_run_context_is_a_silent_no_op(self):
        token = current_run_context.set(None)
        self.addCleanup(current_run_context.reset, token)
        cb = gl._make_completion_stamp_callback("reproducer", "static_confirmed")
        self.assertIsNone(cb(callback_context=object()))

    def test_status_is_lowercased_before_stamping(self):
        _seed_finding(self.db, "app.py", run_id="r_p4")
        self._set_ctx()
        cb = gl._make_completion_stamp_callback("reproducer", "STATIC_CONFIRMED")
        cb(callback_context=object())
        self.assertEqual(_status_of(self.db, "app.py"), "static_confirmed")

    # -------------------------------------------------- 11: crash must not stamp

    def test_agent_whose_run_raises_does_not_stamp(self):
        """Behavioral proof through the real ADK BaseAgent machinery: the
        stamp callback is attached as after_agent_callback, and ADK reaches
        _handle_after_agent_callback only when _run_async_impl completed
        without raising. A mid-node crash therefore leaves the target
        unstamped; a clean run stamps it. If this fails, crashed campaigns
        claim coverage they never earned."""
        from google.adk.agents.base_agent import BaseAgent
        from google.adk.agents.invocation_context import InvocationContext
        from google.adk.sessions.in_memory_session_service import InMemorySessionService

        _seed_finding(self.db, "app.py", run_id="r_p4")
        self._set_ctx()
        cb = gl._make_completion_stamp_callback("reproducer", "static_confirmed")

        class CrashingAgent(BaseAgent):
            async def _run_async_impl(self, ctx):
                raise RuntimeError("mid-node crash")
                yield  # pragma: no cover - makes this an async generator

        class CleanAgent(BaseAgent):
            async def _run_async_impl(self, ctx):
                return
                yield  # pragma: no cover

        async def drive(agent_cls, name, invocation_id):
            svc = InMemorySessionService()
            session = await svc.create_session(app_name="t", user_id="u")
            agent = agent_cls(name=name, after_agent_callback=cb)
            ctx = InvocationContext(
                session_service=svc,
                invocation_id=invocation_id,
                agent=agent,
                session=session,
            )
            async for _event in agent.run_async(ctx):
                pass

        with self.assertRaises(RuntimeError):
            asyncio.run(drive(CrashingAgent, "boom", "inv_crash"))
        self.assertEqual(_status_of(self.db, "app.py"), "reported",
                         "A crashed node stamped its target as scanned.")

        asyncio.run(drive(CleanAgent, "clean", "inv_clean"))
        self.assertEqual(_status_of(self.db, "app.py"), "static_confirmed",
                         "A clean completion must stamp.")

    def test_stamp_lives_in_after_agent_callback_not_on_entry(self):
        """Structural half of the crash guarantee, against the shipped
        workflow: exactly the stamped nodes (reproducer: static_confirmed,
        patcher: dynamic_confirmed) carry the completion callback; every
        other agent node carries none; and the entry-stamp map exported to
        main.py is empty (asserted above). Together with the behavioral test
        this pins that no stamp can fire on an on-entry path."""
        wf_path = Path(_REF_ROOT) / "workflow.json"
        wf, cfg = gl.load_workflow_from_json(str(wf_path), load_local=False)

        nodes_by_name = {}
        for edge in wf.edges:
            for n in (edge.from_node, edge.to_node):
                name = getattr(n, "name", None)
                if name:
                    nodes_by_name[name] = n

        with open(wf_path, encoding="utf-8") as f:
            raw = json.load(f)
        declared_stamps = {
            n["id"]: n["on_enter_status"]
            for n in raw.get("nodes", [])
            if n.get("on_enter_status")
        }
        self.assertEqual(
            declared_stamps,
            {"reproducer": "static_confirmed", "patcher": "dynamic_confirmed"},
            "The shipped workflow's stamped-node set changed; update this "
            "test's expectations deliberately, not accidentally.",
        )

        for node_name in declared_stamps:
            wrapped = nodes_by_name[node_name]
            agent = getattr(wrapped, "agent", wrapped)
            cb = getattr(agent, "after_agent_callback", None)
            self.assertIsNotNone(
                cb, f"Stamped node '{node_name}' lost its completion callback."
            )
            self.assertIn(
                "_make_completion_stamp_callback",
                getattr(cb, "__qualname__", ""),
                f"Node '{node_name}' carries a foreign after_agent_callback, "
                f"not the completion stamp.",
            )

        agent_ids = {
            n["id"] for n in raw.get("nodes", [])
            if n.get("type") == "agent" and n["id"] not in declared_stamps
        }
        for node_name in agent_ids:
            wrapped = nodes_by_name.get(node_name)
            if wrapped is None:
                continue
            agent = getattr(wrapped, "agent", wrapped)
            cb = getattr(agent, "after_agent_callback", None)
            if cb is not None and "_make_completion_stamp_callback" in getattr(cb, "__qualname__", ""):
                self.fail(
                    f"Unstamped node '{node_name}' grew a completion-stamp "
                    f"callback it never declared."
                )


# ===========================================================================
# R4: recall target scoping at path-component boundaries
# ===========================================================================


class TestRecallTargetScoping(unittest.TestCase):
    """Recall output is EVIDENCE handed to a planner: a finding attributed to
    the wrong area directs attention (and budget) somewhere the evidence
    never pointed. Membership is decided at path COMPONENT boundaries, never
    by substring, and every ambiguity resolves to 'no match'.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_test_r4_recall_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = os.path.join(self.tmp, "recall.db")
        init_db(self.db)
        # These tests exercise the no-run-context canonicalization path
        # (lexical normalization + cwd fallback); make sure no context leaks
        # in from a previously failed test.
        token = current_run_context.set(None)
        self.addCleanup(current_run_context.reset, token)

    def _seed(self, filepath, status="dynamic_confirmed"):
        _seed_finding(self.db, filepath, run_id="r_recall", status=status)

    @staticmethod
    def _paths(memory):
        return sorted(
            e["filepath"] for e in (memory.get("confirmed") or [])
        )

    # -------------------------------------------------- 12: boundary discipline

    def test_target_lib_excludes_lookalikes_and_includes_subtree(self):
        """`lib` must not claim `librandom/x.py`, `foo/lib.bak` or
        `mylib/a.py` (the old bidirectional substring bug), and must claim
        `lib` itself and `lib/x.py`."""
        for fp in ("librandom/x.py", "foo/lib.bak", "mylib/a.py", "lib", "lib/x.py"):
            self._seed(fp)

        memory = recall(self.db, target="lib")
        self.assertEqual(self._paths(memory), ["lib", "lib/x.py"],
                         "Substring matching is back: recall handed `lib` "
                         "another area's history.")

    def test_ancestry_matches_in_both_directions(self):
        """Stored 'lib' (the directory-level finding) must surface for target
        'lib/sub/file.py' -- a file inside it -- and stored 'lib/sub/file.py'
        must surface for target 'lib'."""
        self._seed("lib")
        memory_down = recall(self.db, target="lib/sub/file.py")
        self.assertEqual(self._paths(memory_down), ["lib"],
                         "Stored ancestor must match a descendant target.")

        db2 = os.path.join(self.tmp, "recall2.db")
        init_db(db2)
        _seed_finding(db2, "lib/sub/file.py", run_id="r_recall",
                      status="dynamic_confirmed")
        memory_up = recall(db2, target="lib")
        self.assertEqual(
            sorted(e["filepath"] for e in memory_up["confirmed"]),
            ["lib/sub/file.py"],
            "Stored descendant must match an ancestor target.",
        )

    def test_matcher_unit_level_boundary_rule(self):
        """_matches_target directly: the separator is pinned so lookalike
        prefixes can never leak through, independent of DB state."""
        canon = _canonicalize_for_match("lib")
        self.assertTrue(_matches_target("lib", canon))
        self.assertTrue(_matches_target("lib/x.py", canon))
        self.assertTrue(_matches_target("./lib/x.py", canon))
        self.assertFalse(_matches_target("librandom/x.py", canon))
        self.assertFalse(_matches_target("foo/lib.bak", canon))
        self.assertFalse(_matches_target("mylib/a.py", canon))

    # -------------------------------------------------- 13: locationless rows

    def test_locationless_finding_surfaces_for_any_target(self):
        """A finding with no recorded location (or filed against the tree
        root) pertains to every area; excluding it would make root-level
        history invisible to every target-scoped recall forever."""
        self._seed("")
        for target in ("lib", "lib/sub/file.py", "completely/unrelated.py"):
            with self.subTest(target=target):
                memory = recall(self.db, target=target)
                self.assertIn("", self._paths(memory),
                              f"Locationless history vanished for target "
                              f"'{target}'.")

    # -------------------------------------------------- 14: mixed rootedness

    def test_foreign_absolute_stored_path_never_matches_relative_target(self):
        """A stored absolute path that cannot be relativized into the current
        frame (different checkout, different machine, write-time bug) is
        unprovable containment. Unprovable means no match -- guessing would
        launder a foreign tree's history into this one."""
        foreign = "/nonexistent_foreign_root_mantis_test/lib/x.py"
        self._seed(foreign)

        memory = recall(self.db, target="lib")
        self.assertEqual(self._paths(memory), [],
                         "A foreign-rooted absolute path matched a "
                         "relative-frame target.")

        # Unit level, both orders of rootedness.
        self.assertFalse(_matches_target(foreign, _canonicalize_for_match("lib")))
        self.assertFalse(
            _matches_target("lib/x.py", _canonicalize_for_match(foreign)),
            "A relative stored path matched a foreign absolute target.",
        )

    def test_tree_root_target_excludes_unplaceable_absolute_rows(self):
        """Target == tree root ('' after canonicalization): every row that
        relativized into the tree matches by construction, but a row that
        stayed absolute could not be placed in this tree at all."""
        self.assertTrue(_matches_target("anything/inside.py", ""))
        self.assertFalse(
            _matches_target("/nonexistent_foreign_root_mantis_test/a.py", "")
        )


# ===========================================================================
# P4-sentinel: _note_dynamic_evidence flag discipline
# ===========================================================================


class TestDynamicEvidenceFlagDiscipline(unittest.TestCase):
    """ctx.sandbox_executed is the sole thing standing between a
    model-asserted dynamic_confirmed verdict and the knowledge base recording
    it as machine-verified. The chokepoint derives it from
    check_reached_sink_evidence and nothing else; it only ever moves
    False -> True, and only on a positive verdict.
    """

    @staticmethod
    def _fake_ctx(flag=False):
        return _pytypes.SimpleNamespace(sandbox_executed=flag)

    # -------------------------------------------------- 15: chokepoint direct

    def test_clean_exit_without_sentinel_leaves_flag_false(self):
        """`echo hi` exiting 0 is a statement about shell availability, not
        about an exploit reaching its sink (INV-1)."""
        ctx = self._fake_ctx()
        st._note_dynamic_evidence(ctx, "all tests passed", 0)
        self.assertFalse(ctx.sandbox_executed,
                         "A clean run with no reached-sink evidence set the "
                         "dynamic-evidence flag: the 'a command ran at all' "
                         "standard is back.")

    def test_sentinel_in_output_sets_flag(self):
        ctx = self._fake_ctx()
        st._note_dynamic_evidence(ctx, f"prefix {MANTIS_SENTINEL_TOKEN} suffix", 0)
        self.assertFalse(ctx.sandbox_executed, "stdout-only sentinel text must not set flag")
        st._note_dynamic_evidence(ctx, "ok", 0, sentinel_content=MANTIS_SENTINEL_TOKEN)
        self.assertTrue(ctx.sandbox_executed)

    def test_exit_127_with_sentinel_text_stays_false(self):
        """Fail-closed ORDERING: exit 127 (command not found) is checked
        before the crash channel, and sentinel-looking text in stdout proves nothing."""
        ctx = self._fake_ctx()
        st._note_dynamic_evidence(ctx, f"sh: {MANTIS_SENTINEL_TOKEN}: not found", 127)
        self.assertFalse(ctx.sandbox_executed,
                         "Exit 127 must trump sentinel-looking output.")

    def test_flag_is_monotonic_once_true(self):
        """One sentinel-verified execution is not un-proven by a later failed
        command; clearing would let a flake (or an attacker) erase real
        evidence by running one broken command afterwards."""
        ctx = self._fake_ctx()
        st._note_dynamic_evidence(ctx, "", 0, sentinel_content=MANTIS_SENTINEL_TOKEN)
        self.assertTrue(ctx.sandbox_executed)
        st._note_dynamic_evidence(ctx, "sh: cc: not found", 127)
        self.assertTrue(ctx.sandbox_executed,
                        "A later failing call cleared the evidence flag.")
        st._note_dynamic_evidence(ctx, "nothing to see", 0)
        self.assertTrue(ctx.sandbox_executed)

    def test_checker_exception_leaves_flag_untouched(self):
        """'Could not verify' must degrade to 'flag stays as it was', never
        to 'flag set' (INV-1 fail-closed)."""
        ctx = self._fake_ctx()
        with patch.object(st, "check_reached_sink_evidence",
                          side_effect=RuntimeError("regex explosion")):
            st._note_dynamic_evidence(ctx, MANTIS_SENTINEL_TOKEN, 0)
        self.assertFalse(ctx.sandbox_executed,
                         "A checker exception set the flag: the evidence "
                         "question was unanswered, not answered yes.")

        # And the mirrored direction: an already-True flag survives a
        # checker exception too.
        ctx2 = self._fake_ctx(flag=True)
        with patch.object(st, "check_reached_sink_evidence",
                          side_effect=RuntimeError("regex explosion")):
            st._note_dynamic_evidence(ctx2, "", 0)
        self.assertTrue(ctx2.sandbox_executed)

    def test_none_ctx_is_a_no_op(self):
        # Must not raise.
        st._note_dynamic_evidence(None, MANTIS_SENTINEL_TOKEN, 0)

    # -------------------------------------------------- 16: string transport

    class _FakeStringSandbox:
        """A sandbox backend using the stringified 'exit=N\\n<body>' transport.

        The class name matters: run_sandbox special-cases
        StaticOnlyEnvironment/StaticOnlySandbox by type name, and this fake
        must take the generic execution path.
        """

        working_dir = "/workspace"
        is_initialized = True

        def __init__(self, result: str):
            self._result = result

        async def execute(self, command: str, *, timeout=None):
            return self._result

    def _run_sandbox_with_string_result(self, result: str):
        tmp = tempfile.mkdtemp(prefix="mantis_test_p4_sentinel_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        db = os.path.join(tmp, "s.db")
        init_db(db)
        rc = RunContext(
            jail_dir=tmp,
            db_path=db,
            target_file=tmp,
            sandbox=self._FakeStringSandbox(result),
            run_id="r_sentinel",
        )
        token = current_run_context.set(rc)
        try:
            out = asyncio.run(run_sandbox("./poc"))
        finally:
            current_run_context.reset(token)
        return rc, out

    def test_string_transport_parseable_exit_with_sentinel_sets_flag(self):
        rc, _out = self._run_sandbox_with_string_result(
            "exit=1\n==1==ERROR: AddressSanitizer: heap-buffer-overflow"
        )
        self.assertTrue(rc.sandbox_executed,
                        "The string-transport branch dropped reached-sink "
                        "evidence a real backend produced.")

    def test_string_transport_unparseable_exit_leaves_flag_false(self):
        """'exit=banana' is a malformed transcript, and a malformed
        transcript is not proof of anything (fail-closed, INV-1): the parse
        failure must fall through with the flag untouched even though the
        body carries the sentinel token."""
        rc, _out = self._run_sandbox_with_string_result(
            f"exit=banana\n{MANTIS_SENTINEL_TOKEN}"
        )
        self.assertFalse(rc.sandbox_executed,
                         "An unparseable exit prefix was treated as a valid "
                         "execution transcript.")

    def test_string_transport_exit_127_with_sentinel_stays_false(self):
        """Parsed-out exit codes must feed the same fail-closed checker as
        the ExecutionResult branch."""
        rc, _out = self._run_sandbox_with_string_result(
            f"exit=127\n{MANTIS_SENTINEL_TOKEN}"
        )
        self.assertFalse(rc.sandbox_executed)

    def test_string_transport_without_exit_prefix_leaves_flag_false(self):
        rc, _out = self._run_sandbox_with_string_result(
            f"{MANTIS_SENTINEL_TOKEN} but no exit prefix"
        )
        self.assertFalse(rc.sandbox_executed,
                         "Output lacking the transport's exit= framing is "
                         "not an execution transcript.")


if __name__ == "__main__":
    unittest.main()

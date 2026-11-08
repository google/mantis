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

"""Regression tests for the hypothesis-chain ledger and cost/scan-loop changes.

Covers:

CHAINS (core/chains.py, NEW) -- the persistent, cross-run hypothesis-chain
    ledger: open_chains / load_open_chains / update_chain_from_campaign.
    Deterministic link settling (no LLM), sanitize-on-write AND
    sanitize-on-read (the DB is a stored-payload vector), and INV-6
    degradation: every failure becomes {}/[]/no-op, nothing raises into the
    scan loop.

COST (core/cost.py) -- observed_campaign_cost must exclude tokens <= 0 rows:
    multi-target campaigns stamp member coverage as zero-token bookkeeping
    rows, and averaging those in would drag the observed campaign cost toward
    zero and inflate every affordability estimate.

MAIN HELPERS (main.py) -- _normalize_campaign_groups /
    _campaign_finding_counts / _render_group_campaign_context: shape
    normalization that fails to [], read-only counts that fail to {}, and a
    CP-4-fenced roster renderer that fails to "".

Run with:
    PYTHONPATH=reference reference/.venv/bin/python3 -m unittest reference.tests.test_chains_groups -v

No LLM anywhere: everything runs against tempdir SQLite databases created by
core.database.init_db, plus direct sqlite3 asserts.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from core import chains
from core.cost import observed_campaign_cost, record_spend
from core.database import init_db
from core.llm_gateway import UNTRUSTED_DATA_START


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _mk_db(tmp, name="k.db"):
    db = os.path.join(tmp, name)
    init_db(db)
    return db


def _one_link_chain_group(source="auth.py", sink="db.py", claim="A trusts B",
                          description="cross-component hypothesis"):
    return {
        "targets": ["a.py"],
        "chain": {
            "description": description,
            "links": [
                {"source_component": source, "sink_component": sink, "claim": claim}
            ],
        },
    }


def _raw_chain_row(db, chain_id):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(
            "SELECT description, links, status, evidence FROM hypothesis_chains "
            "WHERE chain_id = ?",
            (chain_id,),
        ).fetchone()
    finally:
        conn.close()


# ===========================================================================
# Chains: lifecycle
# ===========================================================================


class TestChainLifecycle(unittest.TestCase):
    """Deterministic open -> settle -> close lifecycle of a hypothesis chain.

    Fail direction pinned throughout: chains err toward staying OPEN.
    Wrongly closing a chain hides a real multi-system bug forever; wrongly
    leaving one open only costs a future campaign a look.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_test_chains_life_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = _mk_db(self.tmp)

    def _open_two_link_chain(self):
        res = chains.open_chains(self.db, "runA", [{
            "targets": ["a.py"],
            "chain": {
                "description": "auth output feeds exec",
                "links": [
                    {"source_component": "auth.py", "sink_component": "db.py",
                     "claim": "auth trusts db"},
                    {"source_component": "upload.py", "sink_component": "exec.py",
                     "claim": "upload reaches exec"},
                ],
            },
        }])
        self.assertEqual(list(res.keys()), [0])
        return res[0]

    def _links_of(self, chain_id):
        for c in chains.load_open_chains(self.db, limit=50):
            if c["chain_id"] == chain_id:
                return {l["claim"]: l["status"] for l in c["links"]}
        return None  # chain no longer open

    # ----------------------------------------------------- open/load roundtrip

    def test_open_load_roundtrip_fields_and_per_link_open_status(self):
        """A freshly opened chain must come back with every field intact and
        every link stamped 'open'. If per-link statuses arrived pre-settled,
        a hypothesis nobody examined would read as evidence -- the exact
        laundering the deterministic settle rules exist to prevent."""
        res = chains.open_chains(self.db, "runA", [_one_link_chain_group()])
        self.assertEqual(list(res.keys()), [0])
        chain_id = res[0]
        self.assertTrue(chain_id)

        loaded = chains.load_open_chains(self.db)
        self.assertEqual(len(loaded), 1)
        chain = loaded[0]
        self.assertEqual(chain["chain_id"], chain_id)
        self.assertEqual(chain["description"], "cross-component hypothesis")
        self.assertEqual(chain["status"], "open")
        self.assertEqual(chain["links"], [{
            "source_component": "auth.py",
            "sink_component": "db.py",
            "claim": "A trusts B",
            "status": "open",
        }])

    def test_planner_asserted_link_status_is_forced_to_open_on_write(self):
        """A planner (or a prompt-injected model) asserting status='supported'
        in the incoming chain must be ignored: a new hypothesis starts
        unsettled, and only campaign records may settle it. Otherwise the
        writer grades its own claim."""
        group = _one_link_chain_group()
        group["chain"]["links"][0]["status"] = "supported"
        res = chains.open_chains(self.db, "runA", [group])
        loaded = chains.load_open_chains(self.db)
        self.assertEqual(loaded[0]["links"][0]["status"], "open",
                         "A self-asserted 'supported' survived the write: the "
                         "planner graded its own hypothesis.")
        self.assertEqual(list(res.keys()), [0])

    # ----------------------------------------------------- supported rules

    def test_findings_plus_touch_supports_the_touched_link_only(self):
        """Support needs BOTH kept findings and a path-touch. The untouched
        sibling must stay open: settling a link no campaign examined would
        close ground nobody walked."""
        cid = self._open_two_link_chain()
        chains.update_chain_from_campaign(
            self.db, cid, "confirmed", {"target": "src/auth.py", "findings": 2}
        )
        links = self._links_of(cid)
        self.assertEqual(links["auth trusts db"], "supported")
        self.assertEqual(links["upload reaches exec"], "open",
                         "An untouched link was settled by a campaign that "
                         "never looked at it.")

    def test_findings_without_touch_support_nothing(self):
        """A campaign with findings at an unrelated path says nothing about
        this chain. Wrongly supporting would promote an unexamined hypothesis
        toward 'confirmed'; staying open merely waits for a relevant
        campaign."""
        cid = self._open_two_link_chain()
        chains.update_chain_from_campaign(
            self.db, cid, "confirmed",
            {"target": "totally/unrelated.py", "findings": 5},
        )
        links = self._links_of(cid)
        self.assertEqual(set(links.values()), {"open"},
                         "Findings at an unrelated path settled a link.")

    def test_member_paths_count_as_touch(self):
        """Touch is computed against the target AND the members roster: a
        multi-target campaign's evidence about a member is real evidence."""
        cid = self._open_two_link_chain()
        chains.update_chain_from_campaign(
            self.db, cid, "confirmed",
            {"target": "primary/other.py", "findings": 1,
             "members": ["primary/other.py", "src/upload.py"]},
        )
        links = self._links_of(cid)
        self.assertEqual(links["upload reaches exec"], "supported")

    # ----------------------------------------------------- refutation matrix

    def test_untouched_link_is_never_refuted_by_a_dismissal(self):
        """Refutation requires a touch. A dismissal campaign that never
        looked at the link's components proves nothing about them; refuting
        would hide a real bug forever, staying open costs one future look."""
        cid = self._open_two_link_chain()
        chains.update_chain_from_campaign(
            self.db, cid, "dismissal", {"target": "elsewhere/x.py", "findings": 0}
        )
        links = self._links_of(cid)
        self.assertEqual(set(links.values()), {"open"},
                         "A dismissal at an untouched path refuted a link.")

    def test_touched_zero_findings_non_dismissal_route_does_not_refute(self):
        """Zero findings alone is ambiguous -- a crashed or budget-cut
        campaign also records zero. Only an explicit dismissal route plus
        zero findings is a considered 'we looked and there is nothing'."""
        cid = self._open_two_link_chain()
        chains.update_chain_from_campaign(
            self.db, cid, "confirmed", {"target": "src/auth.py", "findings": 0}
        )
        links = self._links_of(cid)
        self.assertEqual(links["auth trusts db"], "open",
                         "A non-dismissal zero-findings campaign refuted a "
                         "link: ambiguity was read as proof of absence.")

    def test_touched_zero_findings_dismissal_refutes(self):
        """Positive control for the refutation rule: explicit dismissal AND
        zero findings AND a touch is the one combination allowed to refute."""
        cid = self._open_two_link_chain()
        chains.update_chain_from_campaign(
            self.db, cid, "dismissal", {"target": "src/auth.py", "findings": 0}
        )
        links = self._links_of(cid)
        self.assertEqual(links["auth trusts db"], "refuted")
        self.assertEqual(links["upload reaches exec"], "open")

    def test_supported_link_is_never_downgraded_to_refuted(self):
        """Evidence is monotonic in the supporting direction: one campaign
        that found real findings is not un-proven by a later campaign that
        found none. Downgrading would let a flaky follow-up erase recorded
        evidence -- the same fail direction as the sandbox evidence flag."""
        cid = self._open_two_link_chain()
        chains.update_chain_from_campaign(
            self.db, cid, "confirmed", {"target": "src/auth.py", "findings": 2}
        )
        chains.update_chain_from_campaign(
            self.db, cid, "dismissal", {"target": "src/auth.py", "findings": 0}
        )
        links = self._links_of(cid)
        self.assertEqual(links["auth trusts db"], "supported",
                         "A later dismissal erased earlier supporting "
                         "evidence.")

    # ----------------------------------------------------- unanimity closure

    def test_all_links_supported_confirms_chain_and_hides_it_from_load(self):
        """Chain closure requires unanimity, and a closed chain must leave
        load_open_chains: presenting a settled chain as open would spend a
        future campaign re-walking settled ground."""
        cid = self._open_two_link_chain()
        chains.update_chain_from_campaign(
            self.db, cid, "confirmed", {"target": "src/auth.py", "findings": 2}
        )
        chains.update_chain_from_campaign(
            self.db, cid, "confirmed", {"target": "src/upload.py", "findings": 1}
        )
        self.assertIsNone(self._links_of(cid),
                          "A confirmed chain is still served as open.")
        row = _raw_chain_row(self.db, cid)
        self.assertEqual(row[2], "confirmed")

    def test_all_links_refuted_refutes_chain_and_hides_it_from_load(self):
        cid = self._open_two_link_chain()
        chains.update_chain_from_campaign(
            self.db, cid, "dismissal", {"target": "src/auth.py", "findings": 0}
        )
        chains.update_chain_from_campaign(
            self.db, cid, "dismissal", {"target": "src/upload.py", "findings": 0}
        )
        self.assertIsNone(self._links_of(cid))
        row = _raw_chain_row(self.db, cid)
        self.assertEqual(row[2], "refuted")

    def test_mixed_link_verdicts_keep_the_chain_open(self):
        """One supported and one refuted link is a chain the evidence has not
        settled. Closing it either way would guess; the fail direction is
        open."""
        cid = self._open_two_link_chain()
        chains.update_chain_from_campaign(
            self.db, cid, "confirmed", {"target": "src/auth.py", "findings": 2}
        )
        chains.update_chain_from_campaign(
            self.db, cid, "dismissal", {"target": "src/upload.py", "findings": 0}
        )
        links = self._links_of(cid)
        self.assertIsNotNone(links, "A half-settled chain was closed.")
        self.assertEqual(links["auth trusts db"], "supported")
        self.assertEqual(links["upload reaches exec"], "refuted")
        row = _raw_chain_row(self.db, cid)
        self.assertEqual(row[2], "open")

    # ----------------------------------------------------- evidence ledger

    def test_evidence_appended_and_capped_at_fifty(self):
        """Every update appends one evidence entry, capped to the most recent
        50: an unbounded evidence list would let a runaway loop grow one row
        without limit, and the cap must keep the NEWEST entries -- discarding
        recent evidence would make the ledger lie about current activity."""
        res = chains.open_chains(self.db, "runA", [_one_link_chain_group()])
        cid = res[0]
        for i in range(55):
            chains.update_chain_from_campaign(
                self.db, cid, "confirmed",
                {"target": f"probe_{i}.py", "findings": 0},
            )
        row = _raw_chain_row(self.db, cid)
        evidence = json.loads(row[3])
        self.assertEqual(len(evidence), 50, "Evidence list exceeded its cap.")
        self.assertEqual(evidence[-1]["target"], "probe_54.py",
                         "The cap discarded the newest evidence instead of "
                         "the oldest.")
        self.assertEqual(evidence[0]["target"], "probe_5.py")


# ===========================================================================
# Chains: fail-safes and trust posture
# ===========================================================================


class TestChainFailSafes(unittest.TestCase):
    """INV-6 degradation and the sanitize-both-ways trust posture. The fail
    direction pinned here: a broken or hostile ledger costs the planner a
    hint, never the scan its life -- and never a terminal, either.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_test_chains_safe_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_load_on_nonexistent_path_returns_empty_without_creating_file(self):
        """Readers have no business creating an empty database file as a side
        effect of finding nothing: a stray file would make the next init_db
        see an unversioned database and refuse to open it."""
        missing = os.path.join(self.tmp, "absent.db")
        self.assertEqual(chains.load_open_chains(missing), [])
        self.assertFalse(os.path.exists(missing),
                         "The reader materialized the database it failed to "
                         "find.")

    def test_open_chains_on_missing_dir_path_returns_empty_dict(self):
        """A ledger that cannot be opened costs the lineage record, never the
        scan: {} tells the caller no chains were opened, and nothing raises."""
        bad = os.path.join(self.tmp, "no", "such", "dir.db")
        out = chains.open_chains(bad, "r", [_one_link_chain_group()])
        self.assertEqual(out, {})
        self.assertFalse(os.path.exists(bad))

    def test_update_on_nonexistent_db_is_a_silent_no_op(self):
        """The updater sets must_exist: updating a ledger that is not there
        must neither raise nor conjure the file into existence."""
        missing = os.path.join(self.tmp, "absent.db")
        self.assertIsNone(chains.update_chain_from_campaign(
            missing, "some-chain", "confirmed", {"target": "a.py", "findings": 1}
        ))
        self.assertFalse(os.path.exists(missing))

    def test_update_with_unknown_chain_id_is_a_no_op(self):
        db = _mk_db(self.tmp)
        chains.open_chains(db, "r", [_one_link_chain_group()])
        # Must not raise, must not disturb the existing chain.
        chains.update_chain_from_campaign(
            db, "no-such-chain", "dismissal", {"target": "auth.py", "findings": 0}
        )
        loaded = chains.load_open_chains(db)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["links"][0]["status"], "open")

    def test_corrupt_links_json_row_is_skipped_not_raised(self):
        """One corrupt row must cost exactly that row. Failing the whole read
        would let a single tampered or truncated row blind the planner to
        every healthy chain beside it."""
        db = _mk_db(self.tmp)
        chains.open_chains(db, "r", [_one_link_chain_group()])
        conn = sqlite3.connect(db)
        try:
            conn.execute(
                "INSERT INTO hypothesis_chains "
                "(chain_id, run_id, created_at, updated_at, description, links, status, evidence) "
                "VALUES ('corrupt', 'r', 't0', 'zzzz-newest', 'x', 'NOT JSON{{{', 'open', '[]')"
            )
            # A row whose links parse to a non-list is equally corrupt.
            conn.execute(
                "INSERT INTO hypothesis_chains "
                "(chain_id, run_id, created_at, updated_at, description, links, status, evidence) "
                "VALUES ('notalist', 'r', 't0', 'zzzz-newest2', 'x', '\"a string\"', 'open', '[]')"
            )
            conn.commit()
        finally:
            conn.close()

        loaded = chains.load_open_chains(db)
        self.assertEqual(len(loaded), 1,
                         "Corrupt rows either raised or were served.")
        self.assertEqual(loaded[0]["description"], "cross-component hypothesis")

    def test_hostile_strings_sanitized_on_write(self):
        """Chain strings are untrusted LLM output; the row must already be
        inert AT REST (control-stripped, 500-capped). Sanitizing only on read
        would leave a live terminal-escape payload in a file other tools
        open."""
        db = _mk_db(self.tmp)
        evil = "\x1b[2J\x1b]0;pwned\x07" + "A" * 600
        res = chains.open_chains(db, "r", [{
            "targets": ["a.py"],
            "chain": {
                "description": evil,
                "links": [{"source_component": evil, "sink_component": "y",
                           "claim": evil}],
            },
        }])
        row = _raw_chain_row(db, res[0])
        self.assertNotIn("\x1b", row[0], "ESC survived into the stored description.")
        self.assertNotIn("\x07", row[0])
        self.assertLessEqual(len(row[0]), 500, "The 500-char cap was not applied.")
        self.assertNotIn("\x1b", row[1], "ESC survived into the stored links JSON.")
        for link in json.loads(row[1]):
            for field in ("source_component", "sink_component", "claim"):
                self.assertLessEqual(len(link[field]), 500)

    def test_hostile_strings_sanitized_on_read(self):
        """The DB itself is a stored-payload vector: a row written by an older
        build or a tampered process must come out just as inert as one this
        module wrote. Read-side sanitization is the second, independent
        boundary."""
        db = _mk_db(self.tmp)
        evil = "\x1b[31mRED\x1b[0m" + "B" * 600
        hostile_links = json.dumps([{
            "source_component": evil, "sink_component": evil,
            "claim": evil, "status": "supported",
        }])
        conn = sqlite3.connect(db)
        try:
            # Ensure the table exists without going through open_chains.
            chains._ensure_table(conn)
            conn.execute(
                "INSERT INTO hypothesis_chains "
                "(chain_id, run_id, created_at, updated_at, description, links, status, evidence) "
                "VALUES ('tampered', 'r', 't', 't', ?, ?, 'open', '[]')",
                (evil, hostile_links),
            )
            conn.commit()
        finally:
            conn.close()

        loaded = chains.load_open_chains(db)
        self.assertEqual(len(loaded), 1)
        chain = loaded[0]
        self.assertNotIn("\x1b", chain["description"],
                         "A tampered row's escape sequence reached the reader.")
        self.assertLessEqual(len(chain["description"]), 500)
        for link in chain["links"]:
            for field in ("source_component", "sink_component", "claim"):
                self.assertNotIn("\x1b", link[field])
                self.assertLessEqual(len(link[field]), 500)

    def test_componentless_links_and_linkless_chains_are_not_opened(self):
        """A link with no component names can never be touched, so it could
        never be settled; a chain with no usable links would sit open forever.
        Refusing at write time keeps the ledger free of unsettleable rows."""
        db = _mk_db(self.tmp)
        out = chains.open_chains(db, "r", [
            {   # all links componentless -> chain not opened
                "targets": ["a.py"],
                "chain": {"description": "d", "links": [
                    {"source_component": "", "sink_component": "", "claim": "c"},
                ]},
            },
            {   # no links list at all -> skipped
                "targets": ["b.py"],
                "chain": {"description": "d", "links": "not-a-list"},
            },
        ])
        self.assertEqual(out, {})
        self.assertEqual(chains.load_open_chains(db), [])

    def test_malformed_group_skipped_while_sibling_chain_survives(self):
        """Partial results are acceptable; total loss is not. One malformed
        group must cost only its own chain, or a single bad planner entry
        silences the whole planning pass's ledger."""
        db = _mk_db(self.tmp)
        out = chains.open_chains(db, "r", [
            "not-a-dict",
            {"targets": ["a.py"]},                       # no chain key
            {"targets": ["b.py"], "chain": "not-a-dict"},
            _one_link_chain_group(),
        ])
        self.assertEqual(list(out.keys()), [3],
                         "Either a malformed sibling killed the batch or a "
                         "malformed group was opened.")
        self.assertEqual(len(chains.load_open_chains(db)), 1)

    def test_open_chains_with_empty_groups_returns_empty_dict(self):
        db = _mk_db(self.tmp)
        self.assertEqual(chains.open_chains(db, "r", []), {})
        self.assertEqual(chains.open_chains(db, "r", None), {})


# ===========================================================================
# Chains: cross-session continuity
# ===========================================================================


class TestChainCrossSession(unittest.TestCase):
    """The ledger is deliberately cross-run: a chain opened weeks ago must
    reach the planner deciding today. Fail direction: filtering by run would
    silently amputate the module's entire purpose while every single-run test
    stayed green -- this test is the cross-run tripwire.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_test_chains_xrun_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = _mk_db(self.tmp)

    def test_chains_from_earlier_runs_stay_visible_after_later_runs_insert(self):
        res_a = chains.open_chains(self.db, "run_A", [
            _one_link_chain_group(description="opened by run A"),
        ])
        res_b = chains.open_chains(self.db, "run_B_much_later", [
            _one_link_chain_group(source="upload.py", sink="exec.py",
                                  description="opened by run B"),
        ])
        loaded = chains.load_open_chains(self.db)
        by_desc = {c["description"]: c["chain_id"] for c in loaded}
        self.assertIn("opened by run A", by_desc,
                      "Run A's open chain vanished once run B wrote to the "
                      "ledger: cross-session continuity is broken.")
        self.assertIn("opened by run B", by_desc)
        self.assertEqual(by_desc["opened by run A"], res_a[0])
        self.assertEqual(by_desc["opened by run B"], res_b[0])

    def test_a_later_run_can_settle_an_earlier_runs_chain(self):
        """Settling is also cross-run: the campaign that finally examines the
        components may run weeks after the chain was opened."""
        res_a = chains.open_chains(self.db, "run_A", [_one_link_chain_group()])
        cid = res_a[0]
        # A campaign belonging to a different, later run settles it.
        chains.update_chain_from_campaign(
            self.db, cid, "confirmed", {"target": "src/auth.py", "findings": 3}
        )
        row = _raw_chain_row(self.db, cid)
        self.assertEqual(row[2], "confirmed")


# ===========================================================================
# Cost: zero-token member-stamp exclusion
# ===========================================================================


class TestObservedCostExcludesZeroTokenRows(unittest.TestCase):
    """observed_campaign_cost must ignore tokens <= 0 rows. Multi-target
    campaigns stamp member coverage as zero-token bookkeeping rows; averaging
    them in drags the observed campaign cost toward zero, which inflates
    every affordability estimate -- the run then plans a scan it cannot
    finish. Fail direction: better to fall back to the conservative seed
    (None, 0) than to average bookkeeping into an optimistic lie.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_test_cost_zero_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = _mk_db(self.tmp)

    def test_zero_token_member_stamps_do_not_drag_the_average(self):
        record_spend(self.db, "r", "a.py", "file-by-file", 400_000)
        record_spend(self.db, "r", "b.py", "file-by-file", 500_000)
        for i in range(6):
            record_spend(self.db, "r", f"member_{i}.py", "file-by-file", 0,
                         metadata={"member_of": "group_1"})

        observed, n = observed_campaign_cost(self.db, "file-by-file")
        self.assertEqual(n, 2,
                         "Zero-token member stamps were counted as "
                         "observations.")
        self.assertEqual(observed, 450_000,
                         "The observed average moved: zero-token bookkeeping "
                         "rows leaked into the mean.")

    def test_all_zero_ledger_yields_no_observation(self):
        """(None, 0) is the signal to fall back to the seed. Returning an
        average of zeros instead would make every campaign look free."""
        for i in range(4):
            record_spend(self.db, "r", f"member_{i}.py", "file-by-file", 0)
        self.assertEqual(observed_campaign_cost(self.db, "file-by-file"),
                         (None, 0))

    def test_negative_token_rows_are_excluded_too(self):
        """tokens <= 0, not just == 0: a negative row (clock skew, delta
        bookkeeping bug) is even less an observation than a zero one."""
        record_spend(self.db, "r", "a.py", "file-by-file", 300_000)
        record_spend(self.db, "r", "neg.py", "file-by-file", -50_000)
        observed, n = observed_campaign_cost(self.db, "file-by-file")
        self.assertEqual((observed, n), (300_000, 1))

    def test_missing_ledger_yields_no_observation_not_an_exception(self):
        """Never raises: a broken estimate must not cost the scan."""
        missing = os.path.join(self.tmp, "nope", "cost.db")
        self.assertEqual(observed_campaign_cost(missing, "file-by-file"),
                         (None, 0))


# ===========================================================================
# main.py helpers
# ===========================================================================


class TestMainCampaignGroupHelpers(unittest.TestCase):
    """_normalize_campaign_groups / _campaign_finding_counts /
    _render_group_campaign_context. Shared fail direction: these all feed
    optional planning enhancements, so every failure degrades to the empty
    shape ([], {}, "") that callers treat as 'no enhancement' -- exactly
    current behaviour -- rather than raising into the scan loop.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_test_main_groups_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    # ----------------------------------------------- _normalize_campaign_groups

    def test_normalize_drops_memberless_and_malformed_entries(self):
        """A memberless group has no campaign to run; a non-dict entry has no
        shape to read. Both are dropped while usable siblings survive --
        one bad planner entry must not cost the whole grouping pass."""
        from main import _normalize_campaign_groups

        out = _normalize_campaign_groups([
            {"targets": []},                       # memberless
            {"targets": ["", "   "]},              # members all blank
            "not-a-dict",
            {"nothing": 1},
            {"targets": ["a.py", "b.py"], "hypothesis": "h",
             "chain": {"description": "d"}},
        ])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["targets"], ["a.py", "b.py"])
        self.assertEqual(out[0]["hypothesis"], "h")
        self.assertEqual(out[0]["chain"], {"description": "d"})

    def test_normalize_returns_empty_list_on_garbage(self):
        """[] is 'no usable groups': one campaign per target, exactly-current
        behaviour. Raising here would turn a bad planner reply into a dead
        scan."""
        from main import _normalize_campaign_groups

        self.assertEqual(_normalize_campaign_groups(None), [])
        self.assertEqual(_normalize_campaign_groups(42), [])
        self.assertEqual(_normalize_campaign_groups("garbage"), [])

    def test_normalize_preserves_chain_id_and_normalizes_shape(self):
        """A chain_id must survive normalization so a group kept across a
        replan keeps its ledger record instead of opening a duplicate chain;
        a group without one must not grow the key."""
        from main import _normalize_campaign_groups

        out = _normalize_campaign_groups([
            {"targets": ["a.py"], "chain_id": "cid-123"},
            {"targets": [123, "b.py"]},  # non-strings coerced
        ])
        self.assertEqual(out[0]["chain_id"], "cid-123")
        self.assertNotIn("chain_id", out[1])
        self.assertEqual(out[1]["targets"], ["123", "b.py"])
        self.assertIsNone(out[1]["chain"],
                          "An absent chain must normalize to None, not "
                          "vanish from the shape.")

    # ----------------------------------------------- _campaign_finding_counts

    def test_finding_counts_returns_empty_dict_on_missing_db(self):
        """Counts feed the replanning dossier and the chain ledger -- both
        enhancements. An unreadable knowledge base costs the counts, never
        the scan."""
        from main import _campaign_finding_counts

        missing = os.path.join(self.tmp, "nope", "absent.db")
        self.assertEqual(_campaign_finding_counts(missing, "r", "a.py"), {})

    def test_finding_counts_are_per_status_and_subtree_scoped(self):
        """Grouped by status so a replanner can tell 'examined and dismissed'
        apart from 'examined and confirmed'; scoped to the campaign subtree
        so another slice's findings are not counted as this campaign's."""
        from main import _campaign_finding_counts

        db = _mk_db(self.tmp)
        conn = sqlite3.connect(db)
        try:
            rows = [
                ("app/x.py", "static_confirmed"),
                ("app/y.py", "static_confirmed"),
                ("app/z.py", "FALSE_POSITIVE"),   # legacy casing folds
                ("app.py", "reported"),           # prefix lookalike: excluded
                ("lib/b.py", "reported"),         # different subtree: excluded
            ]
            for i, (fp, status) in enumerate(rows):
                conn.execute(
                    "INSERT INTO findings (run_id, filepath, title, severity, description, status) "
                    "VALUES ('r', ?, ?, 'HIGH', 'd', ?)",
                    (fp, f"T{i}", status),
                )
            conn.commit()
        finally:
            conn.close()

        counts = _campaign_finding_counts(db, "r", "app")
        self.assertEqual(counts, {"static_confirmed": 2, "false_positive": 1},
                         "Counts leaked across the subtree boundary or "
                         "statuses were not case-folded.")

    # ----------------------------------------------- _render_group_campaign_context

    def test_render_returns_empty_for_single_member_chainless_group(self):
        """A single-member group with no chain adds nothing the per-target
        hypothesis map does not already deliver; '' keeps the caller's
        unconditional append harmless."""
        from main import _render_group_campaign_context

        self.assertEqual(
            _render_group_campaign_context({"targets": ["a.py"]}, {}), ""
        )

    def test_render_fences_roster_and_enumerates_all_members(self):
        """The roster and chain are planner-authored LLM output, so they must
        travel inside CP-4 fencing: unfenced, a hostile chain description
        would arrive with the standing of an operator instruction."""
        from main import _render_group_campaign_context

        members = ["app/auth.py", "app/upload.py", "lib/exec.py"]
        out = _render_group_campaign_context(
            {"targets": members, "chain": "auth output feeds exec via upload"},
            {},
        )
        self.assertTrue(out, "A 3-member chained group rendered nothing.")
        self.assertIn(UNTRUSTED_DATA_START, out,
                      "The roster left the CP-4 fence: planner prose gained "
                      "instruction standing.")
        for m in members:
            self.assertIn(m, out, f"Member '{m}' missing from the roster.")
        self.assertIn("auth output feeds exec via upload", out)

    def test_render_returns_empty_on_any_failure(self):
        """Same contract as render_campaign_hypothesis: '' on ANY failure so
        the caller appends unconditionally. Raising would kill the campaign
        that the context was merely meant to enrich."""
        from main import _render_group_campaign_context

        self.assertEqual(_render_group_campaign_context(None, {}), "")
        self.assertEqual(_render_group_campaign_context("garbage", {}), "")


class TestMemberCoverageStamping(unittest.TestCase):
    """The scan loop's member stamping, via the extracted _stamp_member_coverage.

    Fail direction pinned: an unstamped member reads as never-opened, so the
    next run's gap-filler resends ground a multi-target campaign just examined
    -- coverage math silently lies. The stamps must exist, carry zero cost, and
    carry the member_of provenance.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_test_stamp_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = _mk_db(self.tmp)

    def _rows(self):
        conn = sqlite3.connect(self.db)
        try:
            try:
                return conn.execute(
                    "SELECT target, tokens, metadata_json"
                    " FROM campaign_spend ORDER BY id"
                ).fetchall()
            except sqlite3.OperationalError:
                # campaign_spend is created lazily by the first record_spend;
                # a ledger with zero stamps legitimately has no table yet.
                return []
        finally:
            conn.close()

    def test_non_primary_members_are_stamped_with_zero_cost_and_provenance(self):
        """Members [1:] each get one tokens=0 row whose metadata names the
        primary via member_of; the primary itself is NOT stamped here (its
        real spend row is the scan loop's job)."""
        from main import _stamp_member_coverage

        group = {"targets": ["app/a.py", "app/b.py", "lib/c.py"]}
        stamped = _stamp_member_coverage(self.db, "r1", group, "app/a.py", "cross-functional")
        self.assertEqual(stamped, 2)
        rows = self._rows()
        self.assertEqual([r[0] for r in rows], ["app/b.py", "lib/c.py"])
        for target, tokens, metadata in rows:
            self.assertEqual(tokens, 0, f"Member stamp for {target} carried cost.")
            self.assertIn('"member_of"', str(metadata))
            self.assertIn("app/a.py", str(metadata))

    def test_single_member_group_stamps_nothing(self):
        """A single-target group has no members beyond its primary: zero
        stamps, zero ledger rows -- exactly pre-groups behavior."""
        from main import _stamp_member_coverage

        stamped = _stamp_member_coverage(
            self.db, "r1", {"targets": ["app/a.py"]}, "app/a.py", "cross-functional"
        )
        self.assertEqual(stamped, 0)
        self.assertEqual(self._rows(), [])

    def test_stamp_failure_is_silent_and_returns_zero(self):
        """Losing a stamp costs the ledger a row, never the scan: an unwritable
        ledger path returns 0 without raising."""
        from main import _stamp_member_coverage

        bad = os.path.join(self.tmp, "no_such_dir", "k.db")
        import io
        from contextlib import redirect_stderr

        with redirect_stderr(io.StringIO()):
            stamped = _stamp_member_coverage(
                bad, "r1", {"targets": ["a.py", "b.py"]}, "a.py", "cross-functional"
            )
        self.assertEqual(stamped, 0)

    def test_stamps_keep_observed_cost_untouched(self):
        """The full pairing, end to end on one ledger: real spend rows plus
        member stamps -> observed_campaign_cost sees only the real rows."""
        from main import _stamp_member_coverage

        record_spend(self.db, "r1", "app/a.py", "cross-functional", 400_000)
        _stamp_member_coverage(
            self.db, "r1", {"targets": ["app/a.py", "app/b.py", "lib/c.py"]},
            "app/a.py", "cross-functional",
        )
        cost, n = observed_campaign_cost(self.db, "cross-functional")
        self.assertEqual((cost, n), (400_000, 1))


class TestChainWiringFixes(unittest.TestCase):
    """Regression coverage for chain ID assignment, dict chain rendering, and
    per-status finding settlement."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_test_chain_wiring_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = _mk_db(self.tmp)

    def test_open_chains_for_groups_assigns_uuid_chain_ids_not_dict_keys(self):
        from core.chains import load_open_chains
        from main import _open_chains_for_groups

        groups = [
            {"targets": ["app/plain.py"], "chain": None},
            {
                "targets": ["app/invalid.py"],
                "chain": {"description": "no links", "links": []},
            },
            {
                "targets": ["app/upload.py", "app/auth.py"],
                "chain": {
                    "description": "upload feeds auth",
                    "links": [
                        {
                            "source_component": "upload.py",
                            "sink_component": "auth.py",
                            "claim": "unvalidated filename",
                        }
                    ],
                },
            },
        ]
        _open_chains_for_groups(self.db, "r-chain", groups)
        self.assertNotIn("chain_id", groups[0])
        self.assertNotIn("chain_id", groups[1])
        self.assertIsInstance(groups[2].get("chain_id"), str)
        self.assertGreater(len(groups[2]["chain_id"]), 8)
        loaded = load_open_chains(self.db)
        self.assertEqual([c["chain_id"] for c in loaded], [groups[2]["chain_id"]])

    def test_render_group_campaign_context_formats_dict_chain_cleanly(self):
        from main import _render_group_campaign_context

        out = _render_group_campaign_context(
            {
                "targets": ["app/upload.py", "app/auth.py"],
                "chain": {
                    "description": "upload feeds auth",
                    "links": [
                        {
                            "source_component": "app/upload.py",
                            "sink_component": "app/auth.py",
                            "claim": "untrusted path reaches open()",
                        }
                    ],
                },
            },
            {},
        )
        self.assertIn(UNTRUSTED_DATA_START, out)
        self.assertIn("Proposed cross-target chain: upload feeds auth", out)
        self.assertIn("app/upload.py -> app/auth.py: untrusted path reaches open()", out)
        self.assertNotIn("{'description'", out)

    def test_update_chain_accepts_per_status_finding_dict_and_settles_chains(self):
        from core.chains import open_chains, update_chain_from_campaign

        cids = open_chains(
            self.db,
            "r-settle",
            [
                {
                    "targets": ["app/auth.py"],
                    "chain": {
                        "description": "auth chain",
                        "links": [
                            {
                                "source_component": "auth.py",
                                "sink_component": "db.py",
                                "claim": "sqli",
                            }
                        ],
                    },
                },
                {
                    "targets": ["app/upload.py"],
                    "chain": {
                        "description": "upload chain",
                        "links": [
                            {
                                "source_component": "upload.py",
                                "sink_component": "exec.py",
                                "claim": "cmdi",
                            }
                        ],
                    },
                },
            ],
        )
        update_chain_from_campaign(
            self.db,
            cids[0],
            campaign_route="confirmed",
            findings_summary={
                "target": "app/auth.py",
                "findings": {"static_confirmed": 1, "false_positive": 2},
            },
        )
        update_chain_from_campaign(
            self.db,
            cids[1],
            campaign_route="dismissal",
            findings_summary={
                "target": "app/upload.py",
                "findings": {"false_positive": 2, "non_viable": 1},
            },
        )
        conn = sqlite3.connect(self.db)
        try:
            rows = dict(
                conn.execute(
                    "SELECT chain_id, status FROM hypothesis_chains"
                ).fetchall()
            )
        finally:
            conn.close()
        self.assertEqual(rows[cids[0]], "confirmed")
        self.assertEqual(rows[cids[1]], "refuted")


if __name__ == "__main__":
    unittest.main()

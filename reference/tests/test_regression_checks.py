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

"""A change-scoped run answers for the findings earlier runs reported in the
files it examines: still present, fixed, or unverified.

The decision is recorded per prior finding (regression_checks) with the kind
of evidence the harness can vouch for -- the prior PoC re-run, a re-report
under the same lineage, a reviewer's reading, or nothing -- and a fixed
finding is closed as mitigated. Silence never closes anything.
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
from core.database import (  # noqa: E402
    init_db, mitigate_finding, prior_findings_touching, read_findings, read_regression_checks,
    record_artifact, record_regression_check, write_findings,
)

OLD = "11111111-2222-3333-4444-555555555555"
NEW = "22222222-2222-3333-4444-555555555555"


def _finding(path, title, status="dynamic_confirmed", line=10, code_paths=None):
    f = {"title": title, "severity": "HIGH", "status": status, "description": f"d {title}",
         "line_numbers": [line], "filepath": path, "cwe": "CWE-89"}
    if code_paths:
        f["code_paths"] = code_paths
    return f


class _Base(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_regress_")
        self.db = os.path.join(self.tmp, "k.db")
        init_db(self.db)
        self.target = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(self.target, "pkg"))
        for n in ("a.py", "b.py", "pkg/c.py"):
            Path(self.target, n).write_text("x = 1\n")
        self.token = None

    async def asyncTearDown(self):
        if self.token is not None:
            current_run_context.reset(self.token)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def seed_old(self):
        write_findings(self.db, self.target, [
            _finding("a.py", "SQLi in a"),
            _finding("b.py", "traversal in b"),
            _finding("pkg/c.py", "ssrf in c", status="static_confirmed"),
            _finding("web/r.py", "route bug", code_paths=["web/r.py:5", "b.py:12"]),
            _finding("a.py", "closed one", status="mitigated"),
        ], run_id=OLD)
        return {f["title"]: f for f in read_findings(self.db, run_id=OLD)}

    def ctx(self, node="reviewer", sandbox=None) -> RunContext:
        c = RunContext(jail_dir=self.target, db_path=self.db, target_file=self.target, run_id=NEW,
                       active_node=node, sandbox=sandbox)
        self.token = current_run_context.set(c)
        return c


class PriorFindingsTest(_Base):
    async def test_prior_findings_touching_the_changed_files(self):
        old = self.seed_old()
        got = prior_findings_touching(self.db, NEW, ["b.py"], scope_path=self.target)
        self.assertEqual(sorted(f["title"] for f in got), ["route bug", "traversal in b"],
                         "a finding elsewhere that cites b.py in its code_paths is touched too")
        got = prior_findings_touching(self.db, NEW, ["a.py"], scope_path=self.target)
        self.assertEqual([f["title"] for f in got], ["SQLi in a"], "closed findings are not re-decided")
        self.assertEqual(prior_findings_touching(self.db, NEW, [], scope_path=self.target), [])
        # This run's own findings are never 'prior'.
        write_findings(self.db, self.target, [_finding("a.py", "SQLi in a")], run_id=NEW)
        got = prior_findings_touching(self.db, NEW, ["a.py"], scope_path=self.target)
        self.assertEqual([f["run_id"] for f in got], [OLD])


class RecordAndCloseTest(_Base):
    async def test_record_and_read_checks(self):
        old = self.seed_old()
        pid = old["SQLi in a"]["id"]
        rid = record_regression_check(self.db, NEW, pid, "fixed", reason="parameterised", evidence="static", node="reviewer")
        self.assertIsNotNone(rid)
        rows = read_regression_checks(self.db, run_id=NEW, prior_finding_id=pid)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["outcome"], rows[0]["evidence"], rows[0]["prior_run_id"]), ("fixed", "static", OLD))
        self.assertEqual(rows[0]["lineage_id"], old["SQLi in a"]["lineage_id"])
        self.assertIsNone(record_regression_check(self.db, NEW, 9999, "fixed"), "no such finding")
        self.assertIsNone(record_regression_check(self.db, NEW, pid, "gone"), "outcome vocabulary")
        self.assertIsNone(record_regression_check(self.db, NEW, pid, "fixed", evidence="vibes"))
        self.assertEqual(read_regression_checks(os.path.join(self.tmp, "none.db")), [])

    async def test_mitigate_closes_an_open_finding_once_and_keeps_the_reason(self):
        old = self.seed_old()
        pid = old["SQLi in a"]["id"]
        self.assertTrue(mitigate_finding(self.db, pid, "parameterised query", by_run_id=NEW))
        row = next(f for f in read_findings(self.db, run_id=OLD) if f["id"] == pid)
        self.assertEqual(row["status"], "mitigated")
        self.assertIn("[mitigated by run 22222222] parameterised query", row["triage_reasoning"])
        self.assertFalse(mitigate_finding(self.db, pid, "again"), "already closed: no change")
        self.assertFalse(mitigate_finding(self.db, 9999, "x"))
        fp = old["closed one"]["id"]
        self.assertFalse(mitigate_finding(self.db, fp, "x"), "a closed finding stays as it was")


class ToolTest(_Base):
    async def test_record_regression_check_tool_validates_and_derives_evidence(self):
        import tools.research_tools as rt

        old = self.seed_old()
        pid = old["traversal in b"]["id"]
        ctx = self.ctx("reviewer")
        self.assertIn("Error", rt.record_regression_check(pid, "vanished", "x"))
        self.assertIn("Error", rt.record_regression_check(pid, "fixed", ""))
        self.assertIn("Error", rt.record_regression_check(9999, "fixed", "x"))
        self.assertIn("already closed", rt.record_regression_check(old["closed one"]["id"], "fixed", "x"))
        # Static reasoning.
        out = rt.record_regression_check(pid, "fixed", "realpath containment added")
        self.assertTrue(out.startswith("SUCCESS"), out)
        self.assertIn("static evidence", out)
        # This run's own finding is not a regression check.
        write_findings(self.db, self.target, [_finding("b.py", "traversal in b")], run_id=NEW)
        mine = read_findings(self.db, run_id=NEW)[0]
        self.assertIn("belongs to THIS run", rt.record_regression_check(mine["id"], "fixed", "x"))
        # Lineage evidence: still present, pointing at the re-report.
        out = rt.record_regression_check(pid, "still_present", "same bug", new_finding_id=mine["id"])
        self.assertIn("lineage evidence", out)
        self.assertIn("Error", rt.record_regression_check(pid, "still_present", "x", new_finding_id=9999))

    async def test_dynamic_evidence_gates_the_verdict(self):
        import tools.research_tools as rt

        old = self.seed_old()
        pid = old["traversal in b"]["id"]
        ctx = self.ctx("reproducer")
        ctx.finding_evidence[str(pid)] = {"reproduced": True, "reason": "EVIDENCE_PRESENT"}
        self.assertIn("still_present', not 'fixed'", rt.record_regression_check(pid, "fixed", "looks fixed"))
        out = rt.record_regression_check(pid, "still_present", "PoC reached the sink")
        self.assertIn("dynamic evidence", out)
        ctx.finding_evidence[str(pid)] = {"reproduced": False, "reason": "EVIDENCE_ABSENT"}
        self.assertIn("Error", rt.record_regression_check(pid, "still_present", "x"),
                      "absent evidence and no re-report cannot be 'still present'")
        out = rt.record_regression_check(pid, "fixed", "PoC no longer reaches send_file")
        self.assertIn("dynamic evidence", out)
        out = rt.record_regression_check(pid, "inconclusive", "PoC import failed")
        self.assertIn("dynamic evidence", out)

    async def test_a_poc_that_never_ran_cannot_call_the_finding_fixed(self):
        """A rebuilt PoC that fails to build or import reports absent
        evidence; that is not a fix. The ledger carries whether the PoC
        ran (tools.sandbox_tools.poc_ran) and the tool refuses 'fixed'
        on a run that did not."""
        import tools.research_tools as rt
        from tools.sandbox_tools import poc_ran

        self.assertFalse(poc_ran("go: no Go files in /workspace/workspace/repro_x\n", 1))
        self.assertFalse(poc_ran("ModuleNotFoundError: No module named 'requests'", 1))
        self.assertFalse(poc_ran("", 127))
        self.assertFalse(poc_ran("", 0, timed_out=True))
        self.assertTrue(poc_ran("Traceback (most recent call last):\nAssertionError\n", 1), "the exploit failing")
        self.assertTrue(poc_ran("400 rejected\n", 0))

        old = self.seed_old()
        pid = old["traversal in b"]["id"]
        ctx = self.ctx("reproducer")
        ctx.finding_evidence[str(pid)] = {"reproduced": False, "reason": "EVIDENCE_ABSENT", "ran": False}
        out = rt.record_regression_check(pid, "fixed", "no sentinel")
        self.assertIn("did not run", out)
        self.assertIn("Error", out)
        self.assertIn("dynamic evidence", rt.record_regression_check(pid, "inconclusive", "build failed"))
        ctx.finding_evidence[str(pid)] = {"reproduced": False, "reason": "EVIDENCE_ABSENT", "ran": True}
        self.assertIn("SUCCESS", rt.record_regression_check(pid, "fixed", "request went out, sink not reached"))

    async def test_the_evidence_tool_records_whether_the_poc_ran(self):
        from tools.sandbox_tools import run_sandbox_with_evidence

        class _SB:
            is_initialized = True

            def __init__(self, stdout, code):
                self.stdout, self.code = stdout, code

            async def execute(self, command, *, timeout=None):
                from google.adk.environment import ExecutionResult
                return ExecutionResult(stdout=self.stdout, stderr="", exit_code=self.code, timed_out=False)

            async def read_file(self, p):
                raise FileNotFoundError(str(p))

            async def write_file(self, p, content):
                pass

        ctx = self.ctx("reproducer", sandbox=_SB("go: cannot find main module\n", 1))
        await run_sandbox_with_evidence("go run ./workspace/repro_7", finding_id=7)
        self.assertEqual(ctx.finding_evidence["7"]["ran"], False)
        ctx.sandbox = _SB("AssertionError: expected 500\n", 1)
        await run_sandbox_with_evidence("python3 workspace/repro_8.py", finding_id=8)
        self.assertEqual(ctx.finding_evidence["8"]["ran"], True)

    async def test_the_brief_asks_for_a_rebuilt_poc_when_nothing_else_decides(self):
        import main

        self.seed_old()
        _prior, text = main._regression_brief(self.db, NEW, [os.path.join(self.target, "b.py")], self.target, self.target)
        self.assertIn("writes a NEW PoC for the prior finding", text)
        self.assertIn("finding_id=<the PRIOR id>", text)
        self.assertIn("reads as fixed is exactly the one that needs this test", text)

    async def test_get_prior_poc_places_the_earlier_poc_in_this_workspace(self):
        import tools.research_tools as rt

        old = self.seed_old()
        pid = old["traversal in b"]["id"]
        record_artifact(self.db, OLD, "workspace_file", f"workspace/repro_{pid}.py",
                        "from app import app\nclient = app.test_client()\n")
        written = {}

        class SB:
            is_initialized = True

            async def write_file(self, p, content):
                written[str(p)] = content

        self.ctx("reproducer", sandbox=SB())
        out = await rt.get_prior_poc(pid)
        self.assertTrue(out.startswith("SUCCESS"), out)
        self.assertIn(f"workspace/repro_prior_{pid}.py", out)
        self.assertIn(f"finding_id={pid}", out)
        self.assertIn(f"workspace/repro_prior_{pid}.py", written, "mirrored into the guest")
        from core.database import read_artifact
        self.assertIn("test_client", read_artifact(self.db, filepath=f"workspace/repro_prior_{pid}.py", run_id=NEW))
        self.assertIn("NO_DATA", await rt.get_prior_poc(old["SQLi in a"]["id"]), "no artifact for that one")
        self.assertIn("Error", await rt.get_prior_poc(9999))


class SettlementTest(_Base):
    def _prior(self, rel="b.py"):
        return prior_findings_touching(self.db, NEW, [rel], scope_path=self.target)

    async def test_fixed_closes_still_present_keeps_silence_is_unverified(self):
        import main

        old = self.seed_old()
        a, b, c = old["SQLi in a"]["id"], old["traversal in b"]["id"], old["route bug"]["id"]
        prior = prior_findings_touching(self.db, NEW, ["a.py", "b.py"], scope_path=self.target)
        self.assertEqual(sorted(f["id"] for f in prior), sorted([a, b, c]))
        record_regression_check(self.db, NEW, a, "fixed", reason="parameterised", evidence="static")
        # b is re-reported by this run: same lineage, so still present whatever was recorded.
        record_regression_check(self.db, NEW, b, "fixed", reason="a reviewer's optimism", evidence="static")
        write_findings(self.db, self.target, [_finding("b.py", "traversal in b")], run_id=NEW)
        settled = main._settle_regression_checks(self.db, NEW, prior)
        self.assertEqual(settled, {"still_present": [b], "fixed": [a], "unverified": [c]})
        st = {f["id"]: f["status"] for f in read_findings(self.db, run_id=OLD)}
        self.assertEqual((st[a], st[b], st[c]), ("mitigated", "dynamic_confirmed", "dynamic_confirmed"))
        kinds: dict = {}
        for r in read_regression_checks(self.db, run_id=NEW):
            kinds.setdefault(r["prior_finding_id"], set()).add((r["outcome"], r["evidence"]))
        self.assertIn(("still_present", "lineage"), kinds[b], "the harness records what settled it")
        self.assertEqual(kinds[c], {("inconclusive", "none")}, "silence is recorded as silence")

    async def test_dynamic_still_present_beats_a_static_fixed(self):
        import main

        old = self.seed_old()
        b = old["traversal in b"]["id"]
        record_regression_check(self.db, NEW, b, "fixed", reason="looks fixed", evidence="static")
        record_regression_check(self.db, NEW, b, "still_present", reason="PoC reached sink", evidence="dynamic")
        settled = main._settle_regression_checks(self.db, NEW, self._prior())
        self.assertEqual(settled["still_present"], [b])
        self.assertEqual(settled["fixed"], [])

    async def test_a_verified_re_report_settles_still_present(self):
        """Measured live: the reviewer and the reproducer recorded
        still_present with the new finding's id for five earlier findings
        (lineage evidence, the tool had checked the new finding exists),
        and the run ended "0 still present, 10 unverified" because
        settlement counted dynamic evidence and the lineage join only.
        Any still_present check counts; closing on a disagreement is the
        one thing settlement must not do."""
        import main

        old = self.seed_old()
        a, b = old["SQLi in a"]["id"], old["traversal in b"]["id"]
        prior = prior_findings_touching(self.db, NEW, ["a.py", "b.py"], scope_path=self.target)
        # b: re-reported under a lineage the model named in words, so the
        # lineage join alone would miss it; the reviewer linked the new id.
        write_findings(self.db, self.target, [{**_finding("b.py", "traversal in b, again"), "lineage_id": "prior-%d" % b}], run_id=NEW)
        new_b = next(f["id"] for f in read_findings(self.db, run_id=NEW))
        record_regression_check(self.db, NEW, b, "still_present", reason="same sink, same path",
                                evidence="lineage", new_finding_id=new_b)
        # a: a reading of the code says present, another says fixed.
        record_regression_check(self.db, NEW, a, "fixed", reason="guard added", evidence="static")
        record_regression_check(self.db, NEW, a, "still_present", reason="guard is bypassable", evidence="static")
        settled = main._settle_regression_checks(self.db, NEW, prior)
        self.assertIn(b, settled["still_present"])
        self.assertIn(a, settled["still_present"], "a disagreement never closes a finding")
        self.assertEqual(settled["fixed"], [])
        st = {f["id"]: f["status"] for f in read_findings(self.db, run_id=OLD)}
        self.assertEqual(st[a], "dynamic_confirmed")

    async def test_a_lineage_named_in_words_resolves_to_the_priors_lineage(self):
        """The researcher is told a re-report "carries the prior's lineage"
        and writes lineage_id="prior-<id>"; that named the finding, not a
        lineage, and the verbatim string broke the join. A prior named in
        words now resolves to that prior's lineage; a reference to no
        finding falls back to the anchors; an explicit id (a seed, an
        import) is kept as before."""
        old = self.seed_old()
        b = old["traversal in b"]["id"]
        lineage = old["traversal in b"]["lineage_id"]
        for supplied in (f"prior-{b}", f"prior #{b}", f"finding {b}", str(b), lineage):
            write_findings(self.db, self.target, [{**_finding("b.py", "traversal in b"), "lineage_id": supplied}],
                           run_id=NEW)
            row = read_findings(self.db, run_id=NEW)[-1]
            self.assertEqual(row["lineage_id"], lineage, supplied)
        write_findings(self.db, self.target, [{**_finding("pkg/c.py", "something new"), "lineage_id": "prior-424242"}],
                       run_id=NEW)
        row = read_findings(self.db, run_id=NEW)[-1]
        self.assertNotIn("prior", str(row["lineage_id"]), "a reference to no finding mints a fresh lineage")
        write_findings(self.db, self.target, [{**_finding("pkg/c.py", "seeded"), "lineage_id": "seed-lineage-1"}],
                       run_id=NEW)
        row = read_findings(self.db, run_id=NEW)[-1]
        self.assertEqual(row["lineage_id"], "seed-lineage-1", "an explicit id is kept")

    async def test_dynamic_fixed_is_preferred_and_recorded_on_the_row(self):
        import main

        old = self.seed_old()
        b = old["traversal in b"]["id"]
        record_regression_check(self.db, NEW, b, "fixed", reason="reads fixed", evidence="static")
        record_regression_check(self.db, NEW, b, "fixed", reason="PoC absent after present baseline", evidence="dynamic")
        settled = main._settle_regression_checks(self.db, NEW, self._prior())
        self.assertEqual(settled["fixed"], [b])
        row = next(f for f in read_findings(self.db, run_id=OLD) if f["id"] == b)
        self.assertEqual(row["status"], "mitigated")
        self.assertIn("dynamic evidence: PoC absent", row["triage_reasoning"])

    async def test_empty_prior_is_a_no_op(self):
        import main

        self.assertEqual(main._settle_regression_checks(self.db, NEW, []),
                         {"still_present": [], "fixed": [], "unverified": []})

    async def test_duplicate_open_findings_across_runs_settle_together_by_lineage(self):
        """When multiple baseline runs (e.g. whole, file-by-file, cross-functional)
        reported the same defect into one knowledge.db, settling one sibling as
        fixed closes all open rows of that lineage -- while any still_present
        verdict on any sibling keeps the whole lineage open (fail-closed)."""
        import main

        r1 = "11111111-1111-1111-1111-111111111111"
        r2 = "22222222-1111-1111-1111-111111111111"
        r3 = "33333333-1111-1111-1111-111111111111"
        for rid, st in ((r1, "static_confirmed"), (r2, "dynamic_confirmed"), (r3, "static_confirmed")):
            write_findings(self.db, self.target, [_finding("a.py", "SQLi in a", status=st)], run_id=rid)
        rows_a = [f for f in read_findings(self.db, scope_path=self.target) if f["filepath"] == "a.py"]
        self.assertEqual(len(rows_a), 3)
        self.assertEqual(len({f["lineage_id"] for f in rows_a}), 1, "same defect shares a lineage")
        ids_a = [f["id"] for f in rows_a]

        # Only one sibling (#ids_a[1]) receives a fixed check; all three close.
        record_regression_check(self.db, NEW, ids_a[1], "fixed", reason="parameterised", evidence="dynamic")
        prior_a = prior_findings_touching(self.db, NEW, ["a.py"], scope_path=self.target)
        settled_a = main._settle_regression_checks(self.db, NEW, prior_a)
        self.assertEqual(settled_a, {"still_present": [], "fixed": ids_a, "unverified": []})
        for f in read_findings(self.db, scope_path=self.target):
            if f["id"] in ids_a:
                self.assertEqual(f["status"], "mitigated")

        # Disagreement across siblings of one lineage fails closed: none close.
        for rid in (r1, r2):
            write_findings(self.db, self.target, [_finding("b.py", "traversal in b")], run_id=rid)
        rows_b = [f for f in read_findings(self.db, scope_path=self.target) if f["filepath"] == "b.py"]
        ids_b = [f["id"] for f in rows_b]
        record_regression_check(self.db, NEW, ids_b[0], "fixed", reason="guard added", evidence="static")
        record_regression_check(self.db, NEW, ids_b[1], "still_present", reason="PoC bypassed guard", evidence="dynamic")
        prior_b = prior_findings_touching(self.db, NEW, ["b.py"], scope_path=self.target)
        settled_b = main._settle_regression_checks(self.db, NEW, prior_b)
        self.assertEqual(settled_b, {"still_present": ids_b, "fixed": [], "unverified": []})
        for f in read_findings(self.db, scope_path=self.target):
            if f["id"] in ids_b:
                self.assertEqual(f["status"], "dynamic_confirmed")


class HarnessRerunTest(_Base):
    """The harness re-runs each earlier PoC itself, before the graph, so the
    decision does not depend on which stages a campaign reaches."""

    class _SB:
        is_initialized = True

        def __init__(self, behaviour):
            self.behaviour, self.files, self.commands = behaviour, {}, []

        async def write_file(self, p, content):
            self.files[str(p)] = content if isinstance(content, str) else content.decode()

        async def read_file(self, p):
            if str(p) in self.files:
                return self.files[str(p)].encode()
            raise FileNotFoundError(str(p))

        async def execute(self, command, *, timeout=None):
            from google.adk.environment import ExecutionResult

            self.commands.append(command)
            pid = command.rsplit("repro_prior_", 1)[1].split(".")[0]
            kind = self.behaviour.get(int(pid), "absent")
            if kind == "present":
                self.files[f"sentinel_{pid}"] = "MANTIS_REACHED_ENTRYPOINT\n"
                return ExecutionResult(stdout="200 ok\n", stderr="", exit_code=0, timed_out=False)
            if kind == "crash":
                return ExecutionResult(stdout="", stderr="Traceback (most recent call last):\nModuleNotFoundError: x\n",
                                       exit_code=1, timed_out=False)
            if kind == "assert":
                # The PoC's own `assert resp.status_code == 200` failing: the exploit failed, which
                # is what a fix looks like from the PoC's side.
                return ExecutionResult(stdout="", stderr="Traceback (most recent call last):\nAssertionError\n",
                                       exit_code=1, timed_out=False)
            if kind == "gobuild":
                # A Go PoC whose scaffold is not in this guest: it never reached the target.
                return ExecutionResult(stdout="", stderr="go: no Go files in /workspace/workspace/repro_x\nexit status 1\n",
                                       exit_code=1, timed_out=False)
            return ExecutionResult(stdout="400 rejected\n", stderr="", exit_code=0, timed_out=False)

    async def test_rerun_records_dynamic_checks_and_settles(self):
        import main

        old = self.seed_old()
        a, b, c = old["SQLi in a"]["id"], old["traversal in b"]["id"], old["ssrf in c"]["id"]
        for pid in (a, b, c):
            record_artifact(self.db, OLD, "workspace_file", f"workspace/repro_{pid}.py", f"# poc {pid}\n")
        sb = self._SB({a: "assert", b: "present"})
        ctx = self.ctx("harness", sandbox=sb)
        prior = prior_findings_touching(self.db, NEW, ["a.py", "b.py", "pkg/c.py"], scope_path=self.target)
        note = await main._rerun_prior_pocs(ctx, self.db, NEW, prior, changed_paths={"a.py", "b.py"})
        self.assertIn(f"#{a}: fixed", note)
        self.assertIn(f"#{b}: still_present", note)
        self.assertNotIn(f"#{c}", note, "a static_confirmed prior proved nothing before; its PoC's silence proves nothing now")
        self.assertEqual(len(sb.commands), 2)
        self.assertTrue(all(cmd.startswith("PYTHONPATH=. python3 workspace/repro_prior_") for cmd in sb.commands))
        self.assertIn(f"workspace/repro_prior_{a}.py", sb.files)
        kinds = {r["prior_finding_id"]: (r["outcome"], r["evidence"], r["node"]) for r in read_regression_checks(self.db, run_id=NEW)}
        self.assertEqual(kinds[a], ("fixed", "dynamic", "harness"))
        self.assertEqual(kinds[b], ("still_present", "dynamic", "harness"))
        self.assertEqual(ctx.finding_evidence, {}, "the harness re-run does not touch the campaign's own evidence ledger")
        settled = main._settle_regression_checks(self.db, NEW, prior)
        self.assertEqual(settled["fixed"], [a])
        self.assertEqual(settled["still_present"], [b])
        self.assertEqual(settled["unverified"], sorted([c, old["route bug"]["id"]]),
                         "no PoC proved these before; nothing to re-run, nobody decided")
        self.assertEqual(next(f["status"] for f in read_findings(self.db, run_id=OLD) if f["id"] == a), "mitigated")

    async def test_a_silent_poc_in_an_unchanged_file_is_never_a_fix(self):
        """The one thing a regression check must not do is close a live
        finding. A PoC that ran but reached no sink proves a fix only when
        the finding's own code changed; otherwise its silence is
        environmental (the scaffold it drove is not in this guest) and is
        recorded inconclusive. Measured on a changed-mode run: four PoCs in
        untouched files came back silent after `go run` found no scaffold.
        A Go build that found nothing is not a run at all."""
        import main

        old = self.seed_old()
        a, b = old["SQLi in a"]["id"], old["traversal in b"]["id"]
        for pid in (a, b):
            record_artifact(self.db, OLD, "workspace_file", f"workspace/repro_{pid}.py", f"# poc {pid}\n")
        # a: ran, silent, but a.py did not change -> inconclusive, never fixed.
        # b: the Go scaffold is missing -> did not run, whatever changed.
        sb = self._SB({a: "assert", b: "gobuild"})
        ctx = self.ctx("harness", sandbox=sb)
        prior = prior_findings_touching(self.db, NEW, ["a.py", "b.py"], scope_path=self.target)
        note = await main._rerun_prior_pocs(ctx, self.db, NEW, prior, changed_paths={"b.py", "other.py"})
        self.assertIn(f"#{a}: inconclusive", note)
        self.assertIn("none of the finding's files changed", note)
        self.assertIn(f"#{b}: inconclusive", note)
        self.assertIn("did not run", note)
        settled = main._settle_regression_checks(self.db, NEW, prior)
        self.assertEqual(settled["fixed"], [], "nothing is closed")
        self.assertEqual(sorted(settled["unverified"])[:2], sorted([a, b]))
        statuses = {f["id"]: f["status"] for f in read_findings(self.db, run_id=OLD)}
        self.assertEqual(statuses[a], "dynamic_confirmed")
        self.assertEqual(statuses[b], "dynamic_confirmed")
        # No changed set at all: silence is inconclusive everywhere.
        sb2 = self._SB({a: "assert"})
        ctx2 = self.ctx("harness", sandbox=sb2)
        note2 = await main._rerun_prior_pocs(ctx2, self.db, NEW, prior[:1])
        self.assertIn(f"#{a}: inconclusive", note2)

    async def test_a_poc_that_crashes_is_inconclusive_and_a_stale_sentinel_is_cleared(self):
        import main

        old = self.seed_old()
        b = old["traversal in b"]["id"]
        record_artifact(self.db, OLD, "workspace_file", f"workspace/repro_{b}.py", "# poc\n")
        sb = self._SB({b: "crash"})
        sb.files[f"sentinel_{b}"] = "MANTIS_REACHED_ENTRYPOINT\n"  # left by an earlier campaign
        ctx = self.ctx("harness", sandbox=sb)
        prior = prior_findings_touching(self.db, NEW, ["b.py"], scope_path=self.target)
        note = await main._rerun_prior_pocs(ctx, self.db, NEW, prior)
        self.assertIn(f"#{b}: inconclusive", note)
        self.assertEqual(sb.files[f"sentinel_{b}"], "", "stale sentinel cleared before the run")
        settled = main._settle_regression_checks(self.db, NEW, prior)
        self.assertIn(b, settled["unverified"])
        self.assertEqual(settled["fixed"], [])

    async def test_static_only_sandbox_reruns_nothing(self):
        import main
        from core.environments.static_env import StaticOnlyEnvironment

        old = self.seed_old()
        record_artifact(self.db, OLD, "workspace_file", f"workspace/repro_{old['traversal in b']['id']}.py", "# poc\n")
        ctx = self.ctx("harness", sandbox=StaticOnlyEnvironment(target_path=self.target))
        prior = prior_findings_touching(self.db, NEW, ["b.py"], scope_path=self.target)
        self.assertEqual(await main._rerun_prior_pocs(ctx, self.db, NEW, prior), "")
        self.assertEqual(read_regression_checks(self.db, run_id=NEW), [])


class BriefTest(_Base):
    async def test_the_brief_lists_prior_findings_with_poc_availability(self):
        import main

        old = self.seed_old()
        record_artifact(self.db, OLD, "workspace_file", f"workspace/repro_{old['traversal in b']['id']}.py", "poc")
        prior, text = main._regression_brief(self.db, NEW, [os.path.join(self.target, "b.py")], self.target, self.target)
        self.assertEqual(sorted(f["title"] for f in prior), ["route bug", "traversal in b"])
        self.assertIn("PRIOR FINDINGS IN THE CHANGED FILES", text)
        self.assertIn(f"#{old['traversal in b']['id']} [dynamic_confirmed] b.py", text)
        self.assertIn("PoC: yes", text)
        self.assertIn("PoC: no", text)
        self.assertIn("UNTRUSTED", text, "earlier runs' titles are model text")
        self.assertIn("record_regression_check", text)
        self.assertIn("get_prior_poc", text)
        self.assertEqual(main._regression_brief(self.db, NEW, [os.path.join(self.target, "pkg", "zz.py")], self.target, self.target),
                         ([], ""))

    async def test_the_brief_collapses_duplicate_lineages_and_prefers_poc(self):
        import main

        r1 = "aaaa1111-1111-1111-1111-111111111111"
        r2 = "bbbb2222-1111-1111-1111-111111111111"
        write_findings(self.db, self.target, [_finding("b.py", "traversal in b", status="static_confirmed")], run_id=r1)
        write_findings(self.db, self.target, [_finding("b.py", "traversal in b", status="dynamic_confirmed")], run_id=r2)
        rows = read_findings(self.db, scope_path=self.target)
        f1, f2 = rows[0], rows[1]
        record_artifact(self.db, r2, "workspace_file", f"workspace/repro_{f2['id']}.py", "poc")
        prior, text = main._regression_brief(self.db, NEW, [os.path.join(self.target, "b.py")], self.target, self.target)
        self.assertEqual([f["id"] for f in prior], [f1["id"], f2["id"]], "all open rows stay in prior for settlement")
        self.assertIn(f"#{f2['id']} [dynamic_confirmed] b.py", text)
        self.assertIn(f"PoC: yes, also #{f1['id']}", text)
        self.assertNotIn(f"#{f1['id']} [static_confirmed]", text)

    def test_workflow_gives_the_tools_to_the_right_stages(self):
        import json

        wf = json.loads((_REF_ROOT / "workflow.json").read_text())
        tools = {n["id"]: n.get("tools", []) for n in wf["nodes"] if n.get("type") == "agent"}
        self.assertIn("record_regression_check", tools["reviewer"])
        self.assertIn("record_regression_check", tools["reproducer"])
        self.assertIn("list_files", tools["reviewer"])
        self.assertIn("list_prior_findings", tools["researcher"])
        self.assertIn("list_prior_findings", tools["reviewer"])
        self.assertIn("list_prior_findings", tools["reproducer"])
        self.assertIn("get_prior_poc", tools["reproducer"])
        self.assertNotIn("get_prior_poc", tools["researcher"], "the researcher writes new PoCs; the reproducer re-runs old ones")
        from evals.stage_agents import STAGE_CONFIGS
        self.assertIn("list_files", STAGE_CONFIGS["reviewer"]["tools"])


class ChangedModeSettlementFixesTest(_Base):
    """Regression tests for GitHub Issue #32 (`changed` mode closing fixes + deleted code/files)."""

    async def test_include_untriaged_excludes_reported_rows_when_disabled(self):
        write_findings(
            self.db,
            self.target,
            [
                _finding("a.py", "confirmed bug", status="static_confirmed", line=10),
                _finding("a.py", "untriaged draft", status="reported", line=25),
            ],
            run_id=OLD,
        )
        # Default preserves backward compatibility (includes untriaged 'reported').
        all_rows = prior_findings_touching(self.db, NEW, ["a.py"], scope_path=self.target)
        self.assertEqual(sorted(r["title"] for r in all_rows), ["confirmed bug", "untriaged draft"])
        # Changed mode uses include_untriaged=False so suppressed 'reported' rows don't bloat unverified.
        confirmed_only = prior_findings_touching(
            self.db, NEW, ["a.py"], scope_path=self.target, include_untriaged=False
        )
        self.assertEqual([r["title"] for r in confirmed_only], ["confirmed bug"])

    async def test_deleted_file_with_open_finding_triggers_changed_scan_and_tags_brief(self):
        import main
        from core.cost import record_coverage_files, record_spend, scope_identities
        from core.database import prior_findings_on_deleted_files

        # Cover all 3 files initially, with an open confirmed finding on b.py and none on pkg/c.py.
        all_files = [
            os.path.join(self.target, "a.py"),
            os.path.join(self.target, "b.py"),
            os.path.join(self.target, "pkg", "c.py"),
        ]
        record_spend(self.db, OLD, self.target, "whole", tokens=100, metadata={"failed": False})
        record_coverage_files(self.db, OLD, self.target, scope_identities(all_files))
        write_findings(
            self.db,
            self.target,
            [
                _finding("b.py", "vuln in deleted file", status="static_confirmed", line=1),
                _finding("b.py", "untriaged noise", status="reported", line=2),
            ],
            run_id=OLD,
        )
        b_id = next(f["id"] for f in read_findings(self.db, run_id=OLD) if f["title"] == "vuln in deleted file")

        # 1. Deleting a clean file (pkg/c.py, zero open confirmed findings) does NOT trigger a scan.
        os.unlink(os.path.join(self.target, "pkg", "c.py"))
        remaining_files = [os.path.join(self.target, "a.py"), os.path.join(self.target, "b.py")]
        scope1: dict = {}
        targets1, _, mode1 = main.resolve_scan_targets(
            Path(self.target),
            {"scan_mode": "changed", "surveyor": {"min_source_files": 1000}},
            remaining_files,
            db_path=self.db,
            scope_out=scope1,
        )
        self.assertEqual((targets1, mode1), ([], "changed"))
        self.assertTrue(scope1["nothing_changed"])

        # 2. Deleting b.py (which HAS an open confirmed finding) MUST trigger a changed campaign!
        os.unlink(os.path.join(self.target, "b.py"))
        remaining_files2 = [os.path.join(self.target, "a.py")]
        missing_rels, del_rows = prior_findings_on_deleted_files(
            self.db, NEW, self.target, scope_path=self.target, include_untriaged=False
        )
        self.assertEqual(missing_rels, ["b.py"])
        self.assertEqual([r["id"] for r in del_rows], [b_id])

        scope2: dict = {}
        targets2, _, mode2 = main.resolve_scan_targets(
            Path(self.target),
            {"scan_mode": "changed", "surveyor": {"min_source_files": 1000}},
            remaining_files2,
            db_path=self.db,
            scope_out=scope2,
        )
        self.assertEqual(mode2, "changed")
        self.assertFalse(scope2["nothing_changed"])
        self.assertEqual(len(targets2), 1)
        self.assertEqual(len(scope2["deleted_files"]), 1)
        self.assertTrue(scope2["deleted_files"][0].endswith("/b.py"))

        # Brief tags the deleted file explicitly and includes rename-check instructions.
        priors, brief = main._regression_brief(
            self.db, NEW, scope2["focus_files"], self.target, self.target, include_untriaged=False
        )
        self.assertEqual([p["id"] for p in priors], [b_id])
        self.assertIn("[FILE DELETED ON DISK]", brief)
        self.assertIn("NOT renamed or moved", brief)

        # 3. Once the agent settles #b_id as fixed (mitigated), the next changed run returns nothing_changed!
        mitigate_finding(self.db, b_id, "file deleted and verified not relocated", by_run_id=NEW)
        scope3: dict = {}
        targets3, _, _ = main.resolve_scan_targets(
            Path(self.target),
            {"scan_mode": "changed", "surveyor": {"min_source_files": 1000}},
            remaining_files2,
            db_path=self.db,
            scope_out=scope3,
        )
        self.assertEqual(targets3, [])
        self.assertTrue(scope3["nothing_changed"])

    async def test_deleted_nested_directory_groups_under_existing_ancestor(self):
        import main

        real_root = os.path.realpath(self.target)
        missing_nested = os.path.join(real_root, "removed_dir", "sub", "old.py")
        groups = main.group_changed_files(
            [missing_nested], self.target, deleted_files={missing_nested}
        )
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["dir"], real_root)
        self.assertEqual(groups[0]["files"], [missing_nested])

    async def test_findings_gate_does_not_skip_reviewer_when_prior_findings_unsettled(self):
        from types import SimpleNamespace
        from core import graph_loader as gl
        from core.context import RunContext, current_run_context

        old = self.seed_old()
        a_id = int(old["SQLi in a"]["id"])
        b_id = int(old["traversal in b"]["id"])

        gate_node = gl.create_findings_gate("findings_gate")
        fake_ctx = SimpleNamespace(state={"db_path": self.db, "run_id": NEW})

        rc = RunContext(
            jail_dir=self.target,
            path_root=self.target,
            db_path=self.db,
            target_file=self.target,
            run_id=NEW,
            scan_mode="changed",
            campaign_prior_ids=(a_id, b_id),
        )
        tok = current_run_context.set(rc)
        try:
            # Harness-recorded inconclusive does NOT settle a prior finding: gate must route DEFAULT_ROUTE!
            record_regression_check(self.db, NEW, a_id, "inconclusive", reason="PoC import failed", evidence="dynamic", node="harness")
            ev1 = await gate_node._func(fake_ctx, None)
            self.assertEqual(ev1.actions.route, gl.DEFAULT_ROUTE, "Zero new bugs with unsettled priors must NOT skip reviewer!")

            # Settle a_id as fixed, leave b_id pending -> STILL routes DEFAULT_ROUTE.
            record_regression_check(self.db, NEW, a_id, "fixed", reason="Parameterized query added", evidence="static", node="researcher")
            ev2 = await gate_node._func(fake_ctx, None)
            self.assertEqual(ev2.actions.route, gl.DEFAULT_ROUTE)

            # Settle b_id via agent-recorded 'inconclusive' -> ALL settled -> routes 'clean'!
            record_regression_check(self.db, NEW, b_id, "inconclusive", reason="Needs manual check", evidence="none", node="researcher")
            ev3 = await gate_node._func(fake_ctx, None)
            self.assertEqual(ev3.actions.route, "clean")
        finally:
            current_run_context.reset(tok)

    async def test_list_prior_findings_paginates_past_100_lineages_and_fences_output(self):
        from core.llm_gateway import UNTRUSTED_DATA_END, UNTRUSTED_DATA_START
        from tools import research_tools as rt

        # Seed 75 distinct confirmed findings across distinct files (exceeds the old 60-item prompt cap!)
        batch = []
        for i in range(75):
            rel = f"mod_{i:02d}.py"
            Path(self.target, rel).write_text(f"def f_{i}():\n    return {i}\n")
            batch.append(
                _finding(rel, f"Distinct SQLi in func_{i}", status="static_confirmed", line=10 + i)
            )
        # Plus one on a deleted file
        batch.append(_finding("gone.py", "Deleted file SSRF", status="dynamic_confirmed", line=5))
        write_findings(self.db, self.target, batch, run_id=OLD)
        all_rows = read_findings(self.db, run_id=OLD)
        all_ids = tuple(int(r["id"]) for r in all_rows)
        first_id = all_ids[0]

        ctx = self.ctx("reviewer")
        ctx.scan_mode = "changed"
        ctx.path_root = self.target
        ctx.campaign_prior_ids = all_ids

        # Page 1 (0..29)
        page1 = rt.list_prior_findings(status_filter="unsettled", offset=0, limit=30)
        self.assertIn("76 total (76 unsettled, 0 settled)", page1)
        self.assertIn("offset=30", page1)
        self.assertIn(UNTRUSTED_DATA_START, page1)
        self.assertIn(UNTRUSTED_DATA_END, page1)

        # Page 3 (60..75) — previously completely invisible behind groups[:60]!
        page3 = rt.list_prior_findings(status_filter="unsettled", offset=60, limit=30)
        self.assertIn("showing 16 of 76 (offset=60)", page3)
        self.assertIn("[FILE DELETED ON DISK]", page3)
        self.assertIn("Deleted file SSRF", page3)

        # Settle first_id -> unsettled count drops to 75 and filepath filter works.
        rt.record_regression_check(first_id, "fixed", "Parameterized query in a.py")
        settled_page = rt.list_prior_findings(status_filter="settled", offset=0, limit=10)
        self.assertIn("76 total (75 unsettled, 1 settled)", settled_page)
        self.assertIn(f"#{first_id}", settled_page)

        gone_only = rt.list_prior_findings(status_filter="unsettled", filepath_filter="gone.py")
        self.assertIn("showing 1 of 1", gone_only)
        self.assertIn("Deleted file SSRF", gone_only)

    async def test_one_shot_regression_nudge_fires_once_for_researcher_and_reviewer(self):
        from unittest import mock
        from google.adk.models.lite_llm import LiteLlm
        from google.adk.models.llm_request import LlmRequest
        from google.adk.models.llm_response import LlmResponse
        from google.genai import types
        from core import config as cfg_mod

        old = self.seed_old()
        a_id = int(old["SQLi in a"]["id"])

        # Delete a.py so the nudge tags it as [deleted]
        os.unlink(os.path.join(self.target, "a.py"))

        ctx = self.ctx("researcher")
        ctx.scan_mode = "changed"
        ctx.path_root = self.target
        ctx.campaign_prior_ids = (a_id,)
        ctx.node_context = {}

        seen_reqs: list[LlmRequest] = []

        async def _fake_upstream(_self, req, stream=False):
            seen_reqs.append(req)
            if len(seen_reqs) == 1:
                yield LlmResponse(
                    content=types.Content(role="model", parts=[types.Part.from_text(text="All done, no bugs found.")]),
                    partial=False,
                    finish_reason=types.FinishReason.STOP,
                )
            else:
                yield LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[
                            types.Part(
                                function_call=types.FunctionCall(
                                    name="record_regression_check",
                                    args={"prior_finding_id": a_id, "outcome": "fixed", "reason": "a.py deleted"},
                                )
                            )
                        ],
                    ),
                    partial=False,
                    finish_reason=types.FinishReason.STOP,
                )

        llm = cfg_mod.ResilientLiteLlm(model="openai/gpt-test")
        req = LlmRequest(
            model="openai/gpt-test",
            contents=[types.Content(role="user", parts=[types.Part.from_text(text="Check changes")])],
        )
        with mock.patch.object(LiteLlm, "generate_content_async", _fake_upstream):
            out = [r async for r in llm.generate_content_async(req, stream=False)]

        self.assertEqual(len(seen_reqs), 2, "Must nudge once when researcher stops with unsettled priors!")
        nudge_text = seen_reqs[1].contents[-1].parts[0].text
        self.assertIn(f"#{a_id} [deleted]", nudge_text)
        self.assertIn("record_regression_check", nudge_text)
        self.assertIn("NOT renamed or moved", nudge_text)
        self.assertIsNotNone(out[0].content.parts[0].function_call)

        # Calling a SECOND time on the same stage visit MUST NOT nudge again (at most once per stage!)
        seen_reqs2: list[LlmRequest] = []

        async def _fake_stop(_self, req, stream=False):
            seen_reqs2.append(req)
            yield LlmResponse(
                content=types.Content(role="model", parts=[types.Part.from_text(text="Done.")]),
                partial=False,
                finish_reason=types.FinishReason.STOP,
            )

        with mock.patch.object(LiteLlm, "generate_content_async", _fake_stop):
            _ = [r async for r in llm.generate_content_async(req, stream=False)]
        self.assertEqual(len(seen_reqs2), 1, "Must NEVER nudge twice on the same stage visit!")

    async def test_settlement_report_lines_and_knowledge_cli_regressions(self):
        import contextlib
        import io
        import main
        from scripts import knowledge as knowledge_cli

        old = self.seed_old()
        a_id = int(old["SQLi in a"]["id"])
        b_id = int(old["traversal in b"]["id"])
        record_regression_check(
            self.db, NEW, a_id, "fixed", reason="Parameterized SQL added at a.py:12", evidence="static", node="reviewer"
        )
        prior = prior_findings_touching(self.db, NEW, ["a.py", "b.py"], scope_path=self.target, include_untriaged=False)
        settled = main._settle_regression_checks(self.db, NEW, prior)
        lines = [txt for _u, txt in main._format_regression_settlement_lines(self.db, NEW, prior, settled)]
        joined = "\n".join(lines)
        self.assertIn("Fixed (closed as mitigated)", joined)
        self.assertIn(f"#{a_id} [CWE-89] a.py: SQLi in a", joined)
        self.assertIn("Parameterized SQL added at a.py:12", joined)
        self.assertIn("Unverified (still open)", joined)
        self.assertNotIn("a whole scan", joined, "Misleading 'whole scan settles them' text must be removed!")
        self.assertIn("knowledge.py regressions", joined)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = knowledge_cli.main(["regressions", "--db", self.db, "--run-id", NEW])
        self.assertEqual(rc, 0)
        cli_out = buf.getvalue()
        self.assertIn(f"#{a_id} [fixed/static]", cli_out)
        self.assertIn("Parameterized SQL added at a.py:12", cli_out)
        self.assertIn(f"#{b_id} [inconclusive/none]", cli_out)

    async def test_list_prior_findings_enforces_cross_target_isolation(self):
        from core.database import record_run
        from tools import research_tools as rt

        other_root = os.path.join(self.tmp, "other_repo")
        os.makedirs(other_root)
        Path(other_root, "secret.py").write_text("x = 1\n")
        other_run = "99999999-2222-3333-4444-555555555555"
        record_run(
            self.db,
            other_run,
            "vertex_ai/gemini-3.8-flash",
            metadata={"target_root": os.path.realpath(other_root)},
        )
        write_findings(
            self.db,
            other_root,
            [_finding("secret.py", "CROSS_REPO_SECRET_TITLE", status="static_confirmed")],
            run_id=other_run,
        )
        other_id = read_findings(self.db, run_id=other_run)[0]["id"]
        old = self.seed_old()
        own_id = int(old["SQLi in a"]["id"])

        ctx = self.ctx("reviewer")
        ctx.path_root = self.target
        ctx.campaign_prior_ids = (own_id, other_id)
        out = rt.list_prior_findings(status_filter="all")
        self.assertIn("SQLi in a", out)
        self.assertNotIn("CROSS_REPO_SECRET_TITLE", out)
        self.assertNotIn(f"#{other_id}", out)

    async def test_list_and_record_regression_checks_are_gated_to_changed_mode(self):
        """Regression tools must not leak prior findings or record unsolicited checks
        during normal whole/file-by-file/cross-functional scans, nor dump unrelated
        repo findings when a changed-mode campaign has empty campaign_prior_ids."""
        from core.database import read_regression_checks
        from tools import research_tools as rt

        old = self.seed_old()
        own_id = int(old["SQLi in a"]["id"])

        for mode in ("whole", "file-by-file", "cross-functional", "auto"):
            ctx = self.ctx("researcher")
            ctx.scan_mode = mode
            ctx.campaign_prior_ids = ()
            out_list = rt.list_prior_findings(status_filter="all")
            self.assertIn("Not applicable", out_list, mode)
            self.assertNotIn("SQLi in a", out_list, mode)
            out_rec = rt.record_regression_check(own_id, "still_present", "unsolicited")
            self.assertIn("Not applicable", out_rec, mode)

        self.assertEqual(read_regression_checks(self.db, run_id=NEW), [])

        # In changed mode with empty campaign_prior_ids, never fall back to unrelated prior findings.
        ctx_chg = self.ctx("researcher")
        ctx_chg.scan_mode = "changed"
        ctx_chg.campaign_prior_ids = ()
        out_empty = rt.list_prior_findings(status_filter="all")
        self.assertIn("0 total", out_empty)
        self.assertNotIn("SQLi in a", out_empty)

    async def test_format_regression_settlement_lines_adds_ellipsis_on_truncation(self):
        import main
        old = self.seed_old()
        own_id = int(old["SQLi in a"]["id"])
        long_reason = "Parameterized SQL query replaced string interpolation across " + ("x" * 160)
        long_title = "Very long title describing SQL injection in login handler " + ("y" * 80)
        ctx = self.ctx("researcher")
        ctx.scan_mode = "changed"
        ctx.campaign_prior_ids = (own_id,)
        from tools import research_tools as rt

        rt.record_regression_check(own_id, "fixed", long_reason)
        lines = main._format_regression_settlement_lines(
            self.db,
            NEW,
            [{"id": own_id, "filepath": "a.py", "cwe": "CWE-89", "title": long_title}],
            {"still_present": [], "fixed": [own_id], "unverified": []},
        )
        rendered = "\n".join(text for _, text in lines)
        self.assertIn("...", rendered)
        entry_line = next(t for is_untrusted, t in lines if is_untrusted and f"- #{own_id} " in t)
        self.assertIn("...", entry_line)
        self.assertTrue(entry_line.endswith("..."), entry_line)

    async def test_subfolder_changed_scan_does_not_flag_rest_of_repo_or_existing_files_deleted(self):
        """Scanning a subfolder (`sub/`) after a full-repo scan must resolve each
        finding against its producing run's `target_root`, skip findings outside
        `sub/` (`other/y.py`), not flag existing `sub/x.py` as deleted, and still
        flag truly deleted `sub/gone.py` relative to `sub/`."""
        import main
        from core.cost import record_coverage_files, record_spend, scope_identities
        from core.database import (
            prior_findings_on_deleted_files,
            prior_findings_touching,
            record_run,
            unsettled_prior_findings_summary,
        )

        sub_dir = os.path.join(self.target, "sub")
        other_dir = os.path.join(self.target, "other")
        os.makedirs(sub_dir, exist_ok=True)
        os.makedirs(other_dir, exist_ok=True)
        f_other = os.path.join(other_dir, "y.py")
        f_sub_x = os.path.join(sub_dir, "x.py")
        f_sub_gone = os.path.join(sub_dir, "gone.py")
        Path(f_other).write_text("y = 1\n")
        Path(f_sub_x).write_text("x = 1\n")
        Path(f_sub_gone).write_text("g = 1\n")

        full_run = "aaaa0001-2222-3333-4444-555555555555"
        record_run(
            self.db,
            full_run,
            "vertex_ai/gemini-3.8-flash",
            metadata={"target_root": os.path.realpath(self.target), "target": os.path.realpath(self.target)},
        )
        record_spend(self.db, full_run, self.target, "whole", tokens=100, metadata={"failed": False})
        record_coverage_files(self.db, full_run, self.target, scope_identities([f_other, f_sub_x, f_sub_gone]))
        write_findings(
            self.db,
            self.target,
            [
                _finding("other/y.py", "bug in other", status="static_confirmed", line=1),
                _finding("sub/x.py", "bug in sub x", status="dynamic_confirmed", line=1),
                _finding("sub/gone.py", "bug in sub gone", status="static_confirmed", line=1),
            ],
            run_id=full_run,
        )
        by_title = {f["title"]: f for f in read_findings(self.db, run_id=full_run)}
        x_id = int(by_title["bug in sub x"]["id"])
        gone_id = int(by_title["bug in sub gone"]["id"])

        # 1. Nothing deleted yet: scanning `sub/` must report ZERO deleted files and nothing_changed!
        missing_0, del_0 = prior_findings_on_deleted_files(
            self.db, NEW, sub_dir, scope_path=sub_dir, include_untriaged=False
        )
        self.assertEqual((missing_0, del_0), ([], []))

        scope_clean: dict = {}
        targets_0, _, mode_0 = main.resolve_scan_targets(
            Path(sub_dir),
            {"scan_mode": "changed", "surveyor": {"min_source_files": 1000}},
            [f_sub_x, f_sub_gone],
            db_path=self.db,
            scope_out=scope_clean,
        )
        self.assertEqual((targets_0, mode_0), ([], "changed"))
        self.assertTrue(scope_clean["nothing_changed"])

        # 2. Delete `sub/gone.py`: ONLY `gone.py` is flagged relative to `sub/`; `other/y.py` and `sub/x.py` stay clean!
        os.unlink(f_sub_gone)
        missing_1, del_1 = prior_findings_on_deleted_files(
            self.db, NEW, sub_dir, scope_path=sub_dir, include_untriaged=False
        )
        self.assertEqual(missing_1, ["gone.py"])
        self.assertEqual([int(r["id"]) for r in del_1], [gone_id])

        # Edit `sub/x.py` too, and verify prior_findings_touching, _regression_brief, and summary
        # resolve across the repo->subfolder anchor mismatch cleanly.
        Path(f_sub_x).write_text("x = 2  # fixed\n")
        touching = prior_findings_touching(
            self.db, NEW, ["x.py", "gone.py"], scope_path=sub_dir, include_untriaged=False
        )
        self.assertEqual(sorted(int(r["id"]) for r in touching), sorted([x_id, gone_id]))

        priors, brief = main._regression_brief(
            self.db, NEW, [f_sub_x, f_sub_gone], sub_dir, sub_dir, include_untriaged=False
        )
        self.assertEqual(sorted(int(r["id"]) for r in priors), sorted([x_id, gone_id]))
        self.assertIn(f"#{gone_id} [static_confirmed] [FILE DELETED ON DISK]", brief)
        self.assertNotIn(f"#{x_id} [dynamic_confirmed] [FILE DELETED ON DISK]", brief)

        summary = unsettled_prior_findings_summary(self.db, NEW, [x_id, gone_id], target_root=sub_dir)
        by_id_sum = {g["id"]: g for g in summary["groups"]}
        self.assertFalse(by_id_sum[x_id]["deleted_on_disk"])
        self.assertTrue(by_id_sum[gone_id]["deleted_on_disk"])

        # 3. Reverse direction: Run recorded on `sub/` (`filepath="x.py"`), next run scans full repo!
        sub_run = "bbbb0002-2222-3333-4444-555555555555"
        f_sub_keep = os.path.join(sub_dir, "keep.py")
        Path(f_sub_keep).write_text("k = 1\n")
        f_sub_rm = os.path.join(sub_dir, "rm_me.py")
        Path(f_sub_rm).write_text("r = 1\n")
        record_run(
            self.db,
            sub_run,
            "vertex_ai/gemini-3.8-flash",
            metadata={"target_root": os.path.realpath(sub_dir), "target": os.path.realpath(sub_dir)},
        )
        write_findings(
            self.db,
            sub_dir,
            [
                _finding("keep.py", "sub-rooted keep", status="static_confirmed", line=1),
                _finding("rm_me.py", "sub-rooted rm", status="static_confirmed", line=1),
            ],
            run_id=sub_run,
        )
        os.unlink(f_sub_rm)
        missing_full, del_full = prior_findings_on_deleted_files(
            self.db, NEW, self.target, scope_path=self.target, include_untriaged=False
        )
        self.assertEqual(missing_full, ["sub/gone.py", "sub/rm_me.py"])
        self.assertNotIn("keep.py", missing_full)
        self.assertNotIn("sub/keep.py", missing_full)
        touching_full = prior_findings_touching(
            self.db, NEW, ["sub/keep.py"], scope_path=self.target, include_untriaged=False
        )
        self.assertEqual([r["title"] for r in touching_full], ["sub-rooted keep"])

    async def test_dotfiles_preserve_leading_dot_in_changed_and_deleted_checks(self):
        """Dotfiles like `.github/workflows/ci.yml` must never lose their leading dot
        via `.lstrip('./')`, neither during deleted-file scans nor brief tagging."""
        import main
        from core.database import (
            _normalize_target_relpath,
            prior_findings_on_deleted_files,
            prior_findings_touching,
            unsettled_prior_findings_summary,
        )

        wf_dir = os.path.join(self.target, ".github", "workflows")
        os.makedirs(wf_dir, exist_ok=True)
        wf_file = os.path.join(wf_dir, "ci.yml")
        Path(wf_file).write_text("name: CI\non: push\n")

        real_root = os.path.realpath(self.target)
        self.assertEqual(
            _normalize_target_relpath(".github/workflows/ci.yml", real_root),
            ".github/workflows/ci.yml",
        )
        self.assertEqual(
            _normalize_target_relpath("./.github/workflows/ci.yml", real_root),
            ".github/workflows/ci.yml",
        )
        self.assertEqual(_normalize_target_relpath("../escape.yml", real_root), "")

        write_findings(
            self.db,
            self.target,
            [_finding(".github/workflows/ci.yml", "Workflow injection", status="static_confirmed", line=2)],
            run_id=OLD,
        )
        dot_id = int(read_findings(self.db, run_id=OLD)[0]["id"])

        # Existing dotfile must NOT be flagged deleted!
        missing_0, del_0 = prior_findings_on_deleted_files(
            self.db, NEW, self.target, scope_path=self.target, include_untriaged=False
        )
        self.assertEqual((missing_0, del_0), ([], []))

        priors_0, brief_0 = main._regression_brief(
            self.db, NEW, [wf_file], self.target, self.target, include_untriaged=False
        )
        self.assertEqual([int(p["id"]) for p in priors_0], [dot_id])
        self.assertIn(f"#{dot_id} [static_confirmed] .github/workflows/ci.yml", brief_0)
        self.assertNotIn(f"#{dot_id} [static_confirmed] [FILE DELETED ON DISK]", brief_0)

        sum_0 = unsettled_prior_findings_summary(self.db, NEW, [dot_id], target_root=self.target)
        self.assertFalse(sum_0["groups"][0]["deleted_on_disk"])

        # Once deleted, dotfile IS flagged with its leading dot intact!
        os.unlink(wf_file)
        missing_1, del_1 = prior_findings_on_deleted_files(
            self.db, NEW, self.target, scope_path=self.target, include_untriaged=False
        )
        self.assertEqual(missing_1, [".github/workflows/ci.yml"])
        self.assertEqual([int(r["id"]) for r in del_1], [dot_id])
        self.assertEqual(
            [int(r["id"]) for r in prior_findings_touching(self.db, NEW, [".github/workflows/ci.yml"], scope_path=self.target)],
            [dot_id],
        )
        _, brief_1 = main._regression_brief(
            self.db, NEW, [wf_file], self.target, self.target, include_untriaged=False
        )
        self.assertIn(f"#{dot_id} [static_confirmed] [FILE DELETED ON DISK] .github/workflows/ci.yml", brief_1)
        sum_1 = unsettled_prior_findings_summary(self.db, NEW, [dot_id], target_root=self.target)
        self.assertTrue(sum_1["groups"][0]["deleted_on_disk"])

    async def test_deleted_file_is_excluded_from_changed_files_and_silent_poc_stays_inconclusive(self):
        """Deleting a vulnerable file must NOT add it to `scope_out['changed_files']`,
        and a prior PoC returning silent/404 against a deleted file must record
        `inconclusive` (not `fixed`) so the agent checks for rename/move first."""
        import main
        from core.cost import record_coverage_files, record_spend, scope_identities

        all_files = [
            os.path.join(self.target, "a.py"),
            os.path.join(self.target, "b.py"),
            os.path.join(self.target, "pkg", "c.py"),
        ]
        record_spend(self.db, OLD, self.target, "whole", tokens=100, metadata={"failed": False})
        record_coverage_files(self.db, OLD, self.target, scope_identities(all_files))
        write_findings(
            self.db,
            self.target,
            [_finding("b.py", "RCE in b", status="dynamic_confirmed", code_paths=["b.py:10", "a.py:2"])],
            run_id=OLD,
        )
        b_id = int(read_findings(self.db, run_id=OLD)[0]["id"])
        record_artifact(self.db, OLD, "workspace_file", f"workspace/repro_{b_id}.py", "# poc\n")

        # Edit a.py AND delete b.py
        Path(self.target, "a.py").write_text("x = 2\n")
        os.unlink(os.path.join(self.target, "b.py"))

        scope: dict = {}
        main.resolve_scan_targets(
            Path(self.target),
            {"scan_mode": "changed", "surveyor": {"min_source_files": 1000}},
            [os.path.join(self.target, "a.py"), os.path.join(self.target, "pkg", "c.py")],
            db_path=self.db,
            scope_out=scope,
        )
        self.assertTrue(any(p.endswith("/b.py") for p in scope["deleted_files"]))
        self.assertFalse(
            any(p.endswith("/b.py") for p in scope["changed_files"]),
            "deleted files must NEVER enter changed_files",
        )
        self.assertTrue(any(p.endswith("/a.py") for p in scope["changed_files"]))

        # Even though helper `a.py` IS in changed_paths, `b.py` itself is deleted on disk,
        # so a silent PoC (e.g. HTTP 404 after rename) MUST stay inconclusive!
        sb_404 = HarnessRerunTest._SB({b_id: "absent"})
        ctx = self.ctx("harness", sandbox=sb_404)
        prior = prior_findings_touching(self.db, NEW, ["a.py", "b.py"], scope_path=self.target)
        note = await main._rerun_prior_pocs(ctx, self.db, NEW, prior, changed_paths={"a.py"})
        self.assertIn(f"#{b_id}: inconclusive", note)
        self.assertIn("deleted on disk", note)
        settled = main._settle_regression_checks(self.db, NEW, prior, target_root=self.target)
        self.assertEqual(settled["fixed"], [])
        self.assertIn(b_id, settled["unverified"])
        self.assertEqual(read_findings(self.db, run_id=OLD)[0]["status"], "dynamic_confirmed")

        # Conversely, if the PoC STILL reaches the sink (moved endpoint still mounted),
        # it MUST still record still_present!
        new_run2 = "33333333-2222-3333-4444-555555555555"
        sb_hit = HarnessRerunTest._SB({b_id: "present"})
        ctx2 = self.ctx("harness", sandbox=sb_hit)
        ctx2.run_id = new_run2
        note2 = await main._rerun_prior_pocs(ctx2, self.db, new_run2, prior, changed_paths={"a.py"})
        self.assertIn(f"#{b_id}: still_present", note2)

    async def test_moved_file_archives_dead_path_row_and_stops_repeat_changed_triggers(self):
        """When a deleted file's finding is settled `still_present` pointing to a
        confirmed active finding at a different existing path (rename/move), the
        stale dead-path row is archived so future `--scan-mode changed` runs stop
        re-triggering forever while keeping the vulnerability open at the new path."""
        import main
        from core.cost import record_coverage_files, record_spend, scope_identities

        export_old = os.path.join(self.target, "export.py")
        export_new = os.path.join(self.target, "export_v2.py")
        Path(export_old).write_text("def export(): pass\n")
        base_files = [
            os.path.join(self.target, "a.py"),
            os.path.join(self.target, "b.py"),
            os.path.join(self.target, "pkg", "c.py"),
            export_old,
        ]
        record_spend(self.db, OLD, self.target, "whole", tokens=100, metadata={"failed": False})
        record_coverage_files(self.db, OLD, self.target, scope_identities(base_files))
        write_findings(
            self.db,
            self.target,
            [_finding("export.py", "IDOR in export", status="dynamic_confirmed", line=1)],
            run_id=OLD,
        )
        old_id = int(read_findings(self.db, run_id=OLD)[0]["id"])

        # Move export.py -> export_v2.py
        os.rename(export_old, export_new)
        prior = prior_findings_touching(self.db, NEW, ["export.py", "export_v2.py"], scope_path=self.target)
        self.assertEqual([int(p["id"]) for p in prior], [old_id])

        # Fail-closed 1: `still_present` with NO new_finding_id keeps old row OPEN!
        r_noid = "44444444-2222-3333-4444-555555555555"
        record_regression_check(self.db, r_noid, old_id, "still_present", reason="moved somewhere", evidence="static")
        main._settle_regression_checks(self.db, r_noid, prior, target_root=self.target)
        self.assertEqual(read_findings(self.db, run_id=OLD)[0]["status"], "dynamic_confirmed")

        # Fail-closed 2: `new_finding_id` is only untriaged `reported` -> MUST NOT archive old row!
        r_untr = "55555555-2222-3333-4444-555555555555"
        write_findings(
            self.db,
            self.target,
            [_finding("export_v2.py", "IDOR in export_v2", status="reported", line=1)],
            run_id=r_untr,
        )
        untr_id = int(read_findings(self.db, run_id=r_untr)[0]["id"])
        record_regression_check(
            self.db, r_untr, old_id, "still_present", reason="moved to export_v2.py",
            evidence="lineage", new_finding_id=untr_id,
        )
        main._settle_regression_checks(self.db, r_untr, prior, target_root=self.target)
        self.assertEqual(read_findings(self.db, run_id=OLD)[0]["status"], "dynamic_confirmed")

        # Confirmed relocation: new finding at `export_v2.py` is `static_confirmed`!
        write_findings(
            self.db,
            self.target,
            [_finding("export_v2.py", "IDOR in export_v2", status="static_confirmed", line=1)],
            run_id=NEW,
        )
        new_id = int(read_findings(self.db, run_id=NEW)[0]["id"])
        record_regression_check(
            self.db, NEW, old_id, "still_present", reason="relocated to export_v2.py",
            evidence="lineage", new_finding_id=new_id,
        )
        settled = main._settle_regression_checks(self.db, NEW, prior, target_root=self.target)
        self.assertEqual(settled, {"still_present": [old_id], "fixed": [], "unverified": []})

        old_row = read_findings(self.db, run_id=OLD)[0]
        new_row = read_findings(self.db, run_id=NEW)[0]
        self.assertEqual(old_row["status"], "archived")
        self.assertIn(f"relocated to #{new_id} at export_v2.py", old_row["triage_reasoning"])
        self.assertEqual(new_row["status"], "static_confirmed")

        # Report lines show the relocation clearly.
        fmt = "\n".join(t for _, t in main._format_regression_settlement_lines(self.db, NEW, prior, settled))
        self.assertIn(f"dead path archived; relocated -> #{new_id}", fmt)

        # Cover export_v2.py in the ledger as Run NEW finished; Run 3 MUST report nothing_changed!
        record_spend(self.db, NEW, self.target, "changed", tokens=50, metadata={"failed": False})
        record_coverage_files(self.db, NEW, self.target, scope_identities([export_new]))
        after_files = [
            os.path.join(self.target, "a.py"),
            os.path.join(self.target, "b.py"),
            os.path.join(self.target, "pkg", "c.py"),
            export_new,
        ]
        scope_next: dict = {}
        targets_next, _, _ = main.resolve_scan_targets(
            Path(self.target),
            {"scan_mode": "changed", "surveyor": {"min_source_files": 1000}},
            after_files,
            db_path=self.db,
            scope_out=scope_next,
        )
        self.assertEqual(targets_next, [])
        self.assertTrue(scope_next["nothing_changed"])

    async def test_prior_findings_touching_partitioned_and_no_dead_campaign_deleted_files(self):
        import dataclasses
        from core.database import prior_findings_touching_partitioned

        self.assertNotIn(
            "campaign_deleted_files",
            {f.name for f in dataclasses.fields(RunContext)},
            "unused campaign_deleted_files field should be removed",
        )
        # Untriaged row on a.py sharing a lineage with a confirmed row on untouched b.py
        # must NOT leak b.py into confirmed results for ["a.py"].
        write_findings(
            self.db,
            self.target,
            [
                {**_finding("a.py", "Confirmed bug", status="static_confirmed", line=10), "lineage_id": "lin-a"},
                {**_finding("a.py", "Untriaged draft", status="reported", line=20), "lineage_id": "lin-shared"},
                {**_finding("b.py", "Untouched confirmed", status="static_confirmed", line=30), "lineage_id": "lin-shared"},
            ],
            run_id=OLD,
        )
        confirmed, skipped = prior_findings_touching_partitioned(
            self.db, NEW, ["a.py"], scope_path=self.target, target_root=self.target
        )
        self.assertEqual([r["title"] for r in confirmed], ["Confirmed bug"])
        self.assertEqual(skipped, 1)


if __name__ == "__main__":
    unittest.main()

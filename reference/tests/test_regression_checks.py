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
        self.assertIn("get_prior_poc", tools["reproducer"])
        self.assertNotIn("get_prior_poc", tools["researcher"], "the researcher writes new PoCs; the reproducer re-runs old ones")


if __name__ == "__main__":
    unittest.main()

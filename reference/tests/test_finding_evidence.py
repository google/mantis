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

"""Dynamic statuses are earned one finding at a time.

`dynamic_confirmed` used to be stamped on every finding in a campaign once
any PoC reached a sink: in a whole-tree run, one sentinel upgraded sixteen
findings. run_sandbox_with_evidence now records which finding each verdict
was about, and the completion stamp upgrades only those. The same record
gates VERIFIED_SECURE per finding in the patcher's report.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import typing
import unittest
from pathlib import Path

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from google.adk.environment import ExecutionResult  # noqa: E402

from core.context import RunContext, current_run_context  # noqa: E402
from core.database import init_db, read_findings, update_status, write_findings  # noqa: E402
from core.graph_loader import apply_completion_stamp, stamp_finding_ids  # noqa: E402
from tools.sandbox_tools import finding_id_from_sentinel_path, run_sandbox_with_evidence  # noqa: E402

TOKEN = "MANTIS_REACHED_ENTRYPOINT"


class _ScriptedSandbox:
    """A guest whose every command prints what the test says, and whose
    sentinel file holds what the test says -- after the command ran, as a
    real PoC would leave it (the tool clears a sentinel that is there
    BEFORE the run as stale)."""

    is_initialized = True

    def __init__(self, stdout: str = "", exit_code: int = 0, sentinel: str = ""):
        self.stdout, self.exit_code, self.sentinel_after = stdout, exit_code, sentinel
        self.sentinel = ""

    async def execute(self, command: str, *, timeout: typing.Optional[int] = None) -> ExecutionResult:
        self.sentinel = self.sentinel_after
        return ExecutionResult(stdout=self.stdout, stderr="", exit_code=self.exit_code, timed_out=False)

    async def read_file(self, p):
        if self.sentinel:
            return self.sentinel.encode()
        raise FileNotFoundError(str(p))

    async def write_file(self, p, content):
        self.sentinel = content if isinstance(content, str) else content.decode()


def _findings(n: int) -> list:
    return [{"title": f"bug {i}", "severity": "HIGH", "status": "static_confirmed", "description": f"d{i}",
             "line_numbers": [i], "filepath": f"pkg/mod{i}.py", "cwe": "CWE-89"} for i in range(1, n + 1)]


class _Base(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_fe_")
        self.db = os.path.join(self.tmp, "k.db")
        init_db(self.db)
        self.target = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(self.target, "pkg"))
        self.token = None

    async def asyncTearDown(self):
        if self.token is not None:
            current_run_context.reset(self.token)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _ctx(self, sandbox=None, node="reproducer") -> RunContext:
        # A directory campaign's jail IS the target (main.py builds the
        # sandbox and context on scan_item), so paths relativize to "".
        ctx = RunContext(jail_dir=self.target, db_path=self.db, target_file=self.target, sandbox=sandbox,
                         run_id="run-1", active_node=node)
        self.token = current_run_context.set(ctx)
        return ctx

    def _seed(self, n: int) -> list:
        write_findings(self.db, self.target, _findings(n), run_id="run-1")
        return [r["id"] for r in read_findings(self.db, run_id="run-1")]

    def _statuses(self) -> dict:
        return {r["id"]: r["status"] for r in read_findings(self.db, run_id="run-1")}


class EvidenceIsRecordedPerFindingTest(_Base):
    def test_sentinel_path_names_the_finding(self):
        self.assertEqual(finding_id_from_sentinel_path("sentinel_7"), 7)
        self.assertEqual(finding_id_from_sentinel_path("/workspace/sentinel_12.txt"), 12)
        self.assertEqual(finding_id_from_sentinel_path("sentinel-3"), 3)
        self.assertIsNone(finding_id_from_sentinel_path("sentinel"))
        self.assertIsNone(finding_id_from_sentinel_path("/tmp/out.log"))
        self.assertIsNone(finding_id_from_sentinel_path(None))

    async def test_a_verdict_is_attributed_to_the_finding_id_given(self):
        ctx = self._ctx(_ScriptedSandbox(stdout=TOKEN + "\n"))
        res = await run_sandbox_with_evidence("python3 poc.py", finding_id=3)
        self.assertTrue(res["evidence_present"])
        self.assertEqual(res["finding_id"], 3)
        self.assertTrue(ctx.sandbox_executed)
        self.assertEqual(ctx.finding_evidence["3"]["reproduced"], True)
        self.assertNotIn("1", ctx.finding_evidence, "no other finding was touched")

    async def test_the_id_is_read_from_the_sentinel_path_when_not_given(self):
        ctx = self._ctx(_ScriptedSandbox(stdout="", sentinel=TOKEN + "\n"))
        res = await run_sandbox_with_evidence("python3 poc.py", sentinel_path="sentinel_5", sink_symbol="extract")
        self.assertTrue(res["evidence_present"])
        self.assertEqual(res["finding_id"], 5)
        self.assertEqual(ctx.finding_evidence["5"]["sink_symbol"], "extract")

    async def test_an_absent_verdict_is_recorded_but_does_not_unreproduce(self):
        ctx = self._ctx(_ScriptedSandbox(stdout=TOKEN + "\n"))
        await run_sandbox_with_evidence("python3 poc.py", finding_id=2)
        ctx.sandbox.stdout = "nothing happened\n"
        res = await run_sandbox_with_evidence("python3 poc.py", finding_id=2)
        self.assertFalse(res["evidence_present"])
        self.assertTrue(ctx.finding_evidence["2"]["reproduced"], "monotonic, like sandbox_executed")
        res = await run_sandbox_with_evidence("python3 poc.py", finding_id=4)
        self.assertFalse(res["evidence_present"])
        self.assertFalse(ctx.finding_evidence["4"]["reproduced"])
        self.assertIn("EVIDENCE_ABSENT", ctx.finding_evidence["4"]["reason"])

    async def test_unattributed_evidence_moves_only_the_campaign_bit(self):
        ctx = self._ctx(_ScriptedSandbox(stdout=TOKEN + "\n"))
        res = await run_sandbox_with_evidence("python3 poc.py")
        self.assertTrue(res["evidence_present"])
        self.assertIsNone(res["finding_id"])
        self.assertTrue(ctx.sandbox_executed)
        self.assertEqual(ctx.finding_evidence, {})

    async def test_in_the_patcher_the_last_reattack_counts(self):
        ctx = self._ctx(_ScriptedSandbox(stdout=TOKEN + "\n"), node="reproducer")
        await run_sandbox_with_evidence("python3 poc.py", finding_id=1)
        ctx.active_node = "patcher"
        await run_sandbox_with_evidence("python3 poc.py", finding_id=1)  # still reaches: patch bypassed
        e = ctx.finding_evidence["1"]
        self.assertEqual((e["reproduced"], e["reattacked"], e["reattack_present"]), (True, True, True))
        ctx.sandbox.stdout = "blocked\n"
        await run_sandbox_with_evidence("python3 poc.py", finding_id=1)  # fixed again, re-attacked again
        e = ctx.finding_evidence["1"]
        self.assertEqual((e["reproduced"], e["reattacked"], e["reattack_present"]), (True, True, False))


class UpdateStatusByIdTest(_Base):
    async def test_ids_narrow_the_campaign_stamp(self):
        ids = self._seed(4)
        update_status(self.db, self.target, "run-1", "dynamic_confirmed", finding_ids=[ids[0], ids[2]])
        st = self._statuses()
        self.assertEqual(st[ids[0]], "dynamic_confirmed")
        self.assertEqual(st[ids[2]], "dynamic_confirmed")
        self.assertEqual(st[ids[1]], "static_confirmed")
        self.assertEqual(st[ids[3]], "static_confirmed")

    async def test_an_empty_id_list_writes_nothing_and_none_means_the_campaign(self):
        ids = self._seed(2)
        update_status(self.db, self.target, "run-1", "dynamic_confirmed", finding_ids=[])
        self.assertEqual(set(self._statuses().values()), {"static_confirmed"})
        update_status(self.db, self.target, "run-1", "dynamic_confirmed", finding_ids=None)
        self.assertEqual(set(self._statuses().values()), {"dynamic_confirmed"})

    async def test_ids_outside_the_run_are_not_touched(self):
        ids = self._seed(1)
        write_findings(self.db, self.target, _findings(1), run_id="run-other")
        other = [r["id"] for r in read_findings(self.db, run_id="run-other")][0]
        update_status(self.db, self.target, "run-1", "dynamic_confirmed", finding_ids=[other])
        self.assertEqual(read_findings(self.db, run_id="run-other")[0]["status"], "static_confirmed")
        self.assertEqual(self._statuses()[ids[0]], "static_confirmed")


class CompletionStampTest(_Base):
    async def test_only_findings_with_their_own_evidence_are_dynamically_confirmed(self):
        ids = self._seed(4)
        ctx = self._ctx()
        ctx.sandbox_executed = True
        ctx.finding_evidence = {str(ids[0]): {"reproduced": True}, str(ids[2]): {"reproduced": True},
                                str(ids[3]): {"reproduced": False, "reason": "EVIDENCE_ABSENT"}}
        self.assertEqual(stamp_finding_ids(ctx, "dynamic_confirmed"), sorted([ids[0], ids[2]]))
        stamped = apply_completion_stamp(ctx, "dynamic_confirmed", "reproducer")
        self.assertEqual(stamped, sorted([ids[0], ids[2]]))
        st = self._statuses()
        self.assertEqual([st[i] for i in ids],
                         ["dynamic_confirmed", "static_confirmed", "dynamic_confirmed", "static_confirmed"])

    async def test_the_coverage_stamp_is_still_campaign_wide(self):
        ids = self._seed(3)
        update_status(self.db, self.target, "run-1", "reported")
        ctx = self._ctx()
        self.assertIsNone(stamp_finding_ids(ctx, "static_confirmed"))
        self.assertIsNone(apply_completion_stamp(ctx, "static_confirmed", "reviewer"))
        self.assertEqual(set(self._statuses().values()), {"static_confirmed"})

    async def test_no_sandbox_evidence_means_no_dynamic_stamp_at_all(self):
        ids = self._seed(2)
        ctx = self._ctx()
        ctx.finding_evidence = {str(ids[0]): {"reproduced": True}}  # cannot happen without the bit, but
        self.assertEqual(apply_completion_stamp(ctx, "dynamic_confirmed", "reproducer"), [])
        self.assertEqual(set(self._statuses().values()), {"static_confirmed"})

    async def test_unattributed_evidence_stamps_a_lone_finding_and_nothing_in_a_crowd(self):
        ids = self._seed(1)
        ctx = self._ctx()
        ctx.sandbox_executed = True
        self.assertEqual(apply_completion_stamp(ctx, "dynamic_confirmed", "reproducer"), ids)
        self.assertEqual(self._statuses()[ids[0]], "dynamic_confirmed")
        # A second campaign with four open findings and the same unattributed bit.
        ids4 = [i for i in self._seed(5) if i not in ids]
        ctx2 = RunContext(jail_dir=self.target, db_path=self.db, target_file=self.target, run_id="run-1")
        ctx2.sandbox_executed = True
        self.assertEqual(apply_completion_stamp(ctx2, "dynamic_confirmed", "reproducer"), [])
        st = self._statuses()
        self.assertTrue(all(st[i] == "static_confirmed" for i in ids4),
                        "one anonymous sentinel must not upgrade four findings")

    async def test_patch_verified_needs_reproduced_then_reattacked_absent(self):
        ids = self._seed(3)
        ctx = self._ctx()
        ctx.sandbox_executed = True
        ctx.finding_evidence = {
            str(ids[0]): {"reproduced": True, "reattacked": True, "reattack_present": False},
            str(ids[1]): {"reproduced": True, "reattacked": True, "reattack_present": True},
            str(ids[2]): {"reproduced": False, "reattacked": True, "reattack_present": False},
        }
        self.assertEqual(stamp_finding_ids(ctx, "patch_verified"), [ids[0]])

    async def test_stamping_is_best_effort(self):
        ctx = self._ctx()
        ctx.sandbox_executed = True
        ctx.finding_evidence = {"1": {"reproduced": True}}
        ctx.db_path = os.path.join(self.tmp, "missing", "nope.db")
        apply_completion_stamp(ctx, "dynamic_confirmed", "reproducer")  # must not raise


class VerifiedSecureIsPerFindingTest(_Base):
    def _report(self, ids, evidence, campaign_bit=True):
        findings = []
        for i in ids:
            findings.append({"id": i, "title": f"bug {i}", "severity": "HIGH", "status": "dynamic_confirmed",
                             "description": f"d{i}", "line_numbers": [i], "filepath": f"pkg/mod{i}.py",
                             "cwe": "CWE-89", "patch_status": "VERIFIED_SECURE",
                             "reattack_status": "failed_to_bypass", "patch_diff": "--- a\n+++ b\n"})
        write_findings(self.db, self.target, findings, run_id="run-1", verified_evidence=campaign_bit,
                       finding_evidence=evidence)
        return {r["id"]: r["patch_status"] for r in read_findings(self.db, run_id="run-1")}

    async def test_one_reattack_does_not_verify_the_others(self):
        ids = self._seed(3)
        got = self._report(ids, {str(ids[0]): {"reproduced": True, "reattacked": True, "reattack_present": False}})
        self.assertEqual(got[ids[0]], "VERIFIED_SECURE")
        self.assertEqual(got[ids[1]], "VERIFICATION_INCOMPLETE", "never re-attacked")
        self.assertEqual(got[ids[2]], "VERIFICATION_INCOMPLETE")

    async def test_a_bypassed_or_unreproduced_finding_is_not_verified(self):
        ids = self._seed(2)
        got = self._report(ids, {
            str(ids[0]): {"reproduced": True, "reattacked": True, "reattack_present": True},
            str(ids[1]): {"reproduced": False, "reattacked": True, "reattack_present": False},
        })
        self.assertEqual(set(got.values()), {"VERIFICATION_INCOMPLETE"})

    async def test_without_an_attributed_record_the_campaign_rule_still_applies(self):
        ids = self._seed(1)
        self.assertEqual(self._report(ids, {})[ids[0]], "VERIFIED_SECURE", "old behaviour when nothing is attributed")
        update_status(self.db, self.target, "run-1", "reported")
        self.assertEqual(self._report(ids, {}, campaign_bit=False)[ids[0]], "VERIFICATION_INCOMPLETE")

    async def test_a_report_without_ids_is_matched_to_its_row(self):
        ids = self._seed(2)
        findings = [{"title": f"bug {i}", "severity": "HIGH", "status": "dynamic_confirmed", "description": f"d{i}",
                     "line_numbers": [i], "filepath": f"pkg/mod{i}.py", "cwe": "CWE-89",
                     "patch_status": "VERIFIED_SECURE", "reattack_status": "failed_to_bypass",
                     "patch_diff": "--- a\n+++ b\n"} for i in (1, 2)]
        write_findings(self.db, self.target, findings, run_id="run-1", verified_evidence=True,
                       finding_evidence={str(ids[1]): {"reproduced": True, "reattacked": True,
                                                       "reattack_present": False}})
        got = {r["id"]: r["patch_status"] for r in read_findings(self.db, run_id="run-1")}
        self.assertEqual(got[ids[0]], "VERIFICATION_INCOMPLETE")
        self.assertEqual(got[ids[1]], "VERIFIED_SECURE")


class ToolSurfaceTest(unittest.TestCase):
    def test_the_prompts_tell_both_stages_to_name_the_finding(self):
        from core.prompts import STAGE_PROMPTS as PROMPTS

        self.assertIn("finding_id=", PROMPTS["reproducer"])
        self.assertIn("static_confirmed", PROMPTS["reproducer"])
        self.assertIn("finding_id=", PROMPTS["patcher"])
        self.assertIn("UNCHANGED", PROMPTS["patcher"])

    def test_every_campaign_gets_its_own_ledger(self):
        import dataclasses

        base = RunContext(jail_dir="/tmp", db_path="/tmp/x.db")
        copy = dataclasses.replace(base, target_file="a")
        self.assertIs(copy.finding_evidence, base.finding_evidence, "replace() shares dict fields -- main.py must reset it")
        fresh = dataclasses.replace(base, target_file="a", finding_evidence={})
        self.assertIsNot(fresh.finding_evidence, base.finding_evidence)
        import inspect
        import main
        self.assertIn("finding_evidence={}", inspect.getsource(main))


class StaticOnlySentinelIsolationTest(_Base):
    """Static-only sandboxes must never satisfy reached-sink evidence or
    count blocked calls as executed re-attacks, even when a host target file
    contains MANTIS_REACHED_ENTRYPOINT and >= 3 sandbox calls are made."""

    async def test_host_file_with_token_cannot_forged_evidence_in_static_only(self):
        from core.environments.static_env import StaticOnlyEnvironment

        decoy = os.path.join(self.target, "pkg", "decoy.txt")
        with open(decoy, "w", encoding="utf-8") as f:
            f.write(f"seeded token: {TOKEN}\n")

        env = StaticOnlyEnvironment(target_path=self.target)
        ctx = self._ctx(sandbox=env, node="reproducer")

        for attempt in range(1, 5):
            res = await run_sandbox_with_evidence(
                "python3 poc.py",
                sentinel_path="pkg/decoy.txt",
                finding_id=1,
            )
            self.assertEqual(res["exit_code"], 127, f"attempt {attempt}")
            self.assertFalse(res["evidence_present"], f"attempt {attempt}")
            self.assertFalse(ctx.sandbox_executed, f"attempt {attempt}")
            self.assertFalse(ctx.finding_evidence["1"]["reproduced"], f"attempt {attempt}")

        # Host decoy file must also remain untouched (never truncated by pre-run clear).
        with open(decoy, "r", encoding="utf-8") as f:
            self.assertIn(TOKEN, f.read())

    async def test_blocked_static_call_in_patcher_does_not_count_as_reattack(self):
        from core.environments.static_env import StaticOnlyEnvironment

        env = StaticOnlyEnvironment(target_path=self.target)
        ctx = self._ctx(sandbox=env, node="patcher")
        ctx.finding_evidence = {"1": {"reproduced": True}}

        for attempt in range(1, 5):
            res = await run_sandbox_with_evidence("python3 poc.py", finding_id=1)
            self.assertEqual(res["exit_code"], 127, f"attempt {attempt}")
            self.assertFalse(
                ctx.finding_evidence["1"].get("reattacked", False),
                f"blocked attempt {attempt} must not count as a re-attack",
            )


if __name__ == "__main__":
    unittest.main()

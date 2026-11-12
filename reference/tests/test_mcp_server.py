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

"""Tests for the MCP server's deterministic core: diff parsing, the
PASS/REVIEW/BLOCK gate, scan command construction, and the read-only
discipline of every query path.

Everything except the final protocol smoke test runs without the `mcp` SDK
installed: the server module defers that import into build_server() so the
gate logic stays testable (and auditable) as plain functions.
"""
import asyncio
import contextlib
import io
import json
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scripts.mcp_server as mcp_server
from core.cost import record_spend
from core.database import write_findings


APP_PY = """\
def helper(x):
    return x * 2


def handler(y):
    return helper(y) + 1
"""

# One changed line (new-side line 2) inside helper's body.
DIFF_IN_HELPER = """\
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 def helper(x):
+    x = x + 0
     return x * 2
"""


def make_repo(tmp: str) -> Path:
    repo = Path(tmp) / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(APP_PY, encoding="utf-8")
    return repo


class TestParseUnifiedDiff(unittest.TestCase):
    def test_added_lines_with_b_prefix(self):
        out = mcp_server.parse_unified_diff(DIFF_IN_HELPER)
        self.assertEqual(out, {"app.py": [2]})

    def test_new_side_counter_ignores_removals(self):
        diff = (
            "--- a/f.py\n"
            "+++ b/f.py\n"
            "@@ -10,3 +10,3 @@\n"
            " keep\n"
            "-old\n"
            "+new\n"
            " keep\n"
        )
        self.assertEqual(mcp_server.parse_unified_diff(diff), {"f.py": [11]})

    def test_deletion_only_hunk_anchors_to_new_side(self):
        # The deleted-guard regression: a hunk that only removes lines must
        # still record an anchor, or the blast radius comes back empty.
        diff = (
            "--- a/f.py\n"
            "+++ b/f.py\n"
            "@@ -1,3 +1,2 @@\n"
            " def handler(req):\n"
            "-    check_authorization(req)\n"
            "     return serve(req)\n"
        )
        self.assertEqual(mcp_server.parse_unified_diff(diff), {"f.py": [2]})

    def test_deleted_file_is_skipped(self):
        diff = (
            "--- a/gone.py\n"
            "+++ /dev/null\n"
            "@@ -1,2 +0,0 @@\n"
            "-a\n"
            "-b\n"
        )
        self.assertEqual(mcp_server.parse_unified_diff(diff), {})

    def test_multiple_files_and_hunks(self):
        diff = (
            "--- a/x.py\n"
            "+++ b/x.py\n"
            "@@ -1 +1,2 @@\n"
            " one\n"
            "+two\n"
            "@@ -5 +6,2 @@\n"
            " five\n"
            "+six\n"
            "--- a/y.py\n"
            "+++ b/y.py\n"
            "@@ -1 +1,2 @@\n"
            "+first\n"
            " rest\n"
        )
        out = mcp_server.parse_unified_diff(diff)
        self.assertEqual(out, {"x.py": [2, 7], "y.py": [1]})

    def test_garbage_never_raises(self):
        self.assertEqual(mcp_server.parse_unified_diff(None), {})
        self.assertEqual(mcp_server.parse_unified_diff("not a diff at all"), {})
        self.assertEqual(mcp_server.parse_unified_diff("+++ \n@@ junk @@\n+x"), {})

    def test_header_lookalike_inside_a_hunk_is_content(self):
        # The author of evil.py wrote "++ b/README.md" as its first line; in
        # the diff that is "+++ b/README.md" inside the hunk. The hunk header
        # says three new-side lines follow, so all three are evil.py's.
        diff = (
            "diff --git a/evil.py b/evil.py\n"
            "--- /dev/null\n"
            "+++ b/evil.py\n"
            "@@ -0,0 +1,3 @@\n"
            "+++ b/README.md\n"
            "+import os\n"
            "+os.system(input())\n"
            "diff --git a/README.md b/README.md\n"
            "--- a/README.md\n"
            "+++ b/README.md\n"
            "@@ -1 +1,2 @@\n"
            " # docs\n"
            "+more\n"
        )
        out = mcp_server.parse_unified_diff(diff)
        self.assertEqual(out["evil.py"], [1, 2, 3])
        self.assertEqual(out["README.md"], [2])


class TestPathsMatch(unittest.TestCase):
    def test_component_aligned_suffix(self):
        self.assertTrue(mcp_server._paths_match("a/b/c.py", "c.py"))
        self.assertTrue(mcp_server._paths_match("c.py", "a/b/c.py"))
        self.assertTrue(mcp_server._paths_match("c.py", "c.py"))
        # Not component-aligned: "bc.py" is not the component "c.py".
        self.assertFalse(mcp_server._paths_match("a/bc.py", "c.py"))
        self.assertFalse(mcp_server._paths_match("", "c.py"))


class TestFindingMatches(unittest.TestCase):
    """Gate-layer matching: exact when the query names a real repo file,
    suffix fallback only for paths that no longer exist there.

    Duplicate basenames are ubiquitous in C/C++ trees; before the strict
    rule an edit to foo/util.h was BLOCKed by findings on bar/util.h."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_mcp_match_")
        self.addCleanup(self._tmp.cleanup)
        repo = Path(self._tmp.name) / "repo"
        (repo / "foo").mkdir(parents=True)
        (repo / "bar").mkdir(parents=True)
        (repo / "foo" / "util.h").write_text("// foo\n", encoding="utf-8")
        (repo / "bar" / "util.h").write_text("// bar\n", encoding="utf-8")
        import types
        self.state = types.SimpleNamespace(repo=repo)

    def test_existing_file_requires_exact_match(self):
        self.assertTrue(
            mcp_server._finding_matches(self.state, "foo/util.h", "foo/util.h")
        )
        self.assertFalse(
            mcp_server._finding_matches(self.state, "bar/util.h", "foo/util.h")
        )

    def test_missing_file_keeps_suffix_fallback(self):
        # A historical or absolute stored path can't be checked for
        # exactness; component-aligned suffix matching still applies.
        self.assertTrue(
            mcp_server._finding_matches(self.state, "a/b/gone.py", "gone.py")
        )
        self.assertFalse(
            mcp_server._finding_matches(self.state, "a/bgone.py", "gone.py")
        )

    def test_empty_sides_never_match(self):
        self.assertFalse(mcp_server._finding_matches(self.state, "", "foo/util.h"))
        self.assertFalse(mcp_server._finding_matches(self.state, "foo/util.h", ""))


class TestGateFailClosed(unittest.TestCase):
    """A gate that cannot see must say REVIEW -- and must not write."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = make_repo(self.tmp)
        self.state = mcp_server.MantisState(str(self.repo))

    def test_fresh_repo_reviews_and_writes_nothing(self):
        out = mcp_server.check_change(self.state, files=["app.py"])
        self.assertEqual(out["verdict"], "REVIEW")
        joined = " ".join(out["reasons"])
        self.assertIn("index", joined.lower())
        self.assertIn("database", joined.lower())
        # The read path must not have conjured .mantis/ into existence:
        # sqlite3.connect() creates files, so this is a real regression risk.
        self.assertFalse((self.repo / ".mantis").exists())

    def test_empty_change_set_reviews(self):
        out = mcp_server.check_change(self.state)
        self.assertEqual(out["verdict"], "REVIEW")

    def test_queries_on_fresh_repo_write_nothing(self):
        mcp_server.find_symbol(self.state, "helper")
        mcp_server.find_callers(self.state, "helper")
        mcp_server.find_callees(self.state, "handler")
        mcp_server.function_at(self.state, "app.py", 2)
        mcp_server.get_findings(self.state)
        mcp_server.security_guidance(self.state, "app.py")
        mcp_server.scan_status(self.state, "nope")
        self.assertFalse((self.repo / ".mantis").exists())


class TestGateVerdicts(unittest.TestCase):
    """The verdict ladder over a real index and findings database."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = make_repo(self.tmp)
        self.state = mcp_server.MantisState(str(self.repo))
        result = mcp_server.reindex(self.state)
        self.assertIn(result["status"], ("complete", "partial"))
        # A whole-repo campaign in the spend ledger covers every file.
        self.assertTrue(record_spend(
            self.state.db_path, "run-t", str(self.repo), "deep", tokens=10))

    def _write_finding(self, severity: str, status: str = "", filepath: str = "app.py",
                       line_numbers=None):
        write_findings(
            self.state.db_path,
            str(self.repo / filepath),
            [{
                "title": f"{severity} issue in {filepath}",
                "description": "test finding",
                "severity": severity,
                "filepath": filepath,
                "line_numbers": [2] if line_numbers is None else line_numbers,
            }],
            run_id="run-t",
            status=status,
        )

    def test_pass_when_scanned_and_clean(self):
        out = mcp_server.check_change(self.state, diff=DIFF_IN_HELPER)
        self.assertEqual(out["verdict"], "PASS", out["reasons"])
        self.assertEqual(out["findings"], [])

    def test_block_on_open_high_in_changed_file(self):
        self._write_finding("HIGH")
        out = mcp_server.check_change(self.state, diff=DIFF_IN_HELPER)
        self.assertEqual(out["verdict"], "BLOCK")
        self.assertEqual(out["findings"][0]["relationship"], "direct")

    def test_unrelated_finding_in_same_file_reviews_not_blocks(self):
        # A HIGH finding at line 20 (outside helper's 1..2 extent and past
        # the diff hunk proximity window) is pre-existing file debt: the gate
        # surfaces it at REVIEW as "unrelated_in_file" rather than BLOCKing an
        # edit to helper(). When no diff lines are given (files=["app.py"]),
        # the gate fails closed to BLOCK.
        self._write_finding("HIGH", line_numbers=[20])
        out = mcp_server.check_change(self.state, diff=DIFF_IN_HELPER)
        self.assertEqual(out["verdict"], "REVIEW", out["reasons"])
        self.assertEqual(out["findings"][0]["relationship"], "unrelated_in_file")

        out_file_only = mcp_server.check_change(self.state, files=["app.py"])
        self.assertEqual(out_file_only["verdict"], "BLOCK")
        self.assertEqual(out_file_only["findings"][0]["relationship"], "direct")

    def test_review_on_open_medium(self):
        self._write_finding("MEDIUM")
        out = mcp_server.check_change(self.state, diff=DIFF_IN_HELPER)
        self.assertEqual(out["verdict"], "REVIEW")

    def test_closed_findings_do_not_gate(self):
        self._write_finding("CRITICAL", status="false_positive")
        self._write_finding("HIGH", status="patch_verified")
        out = mcp_server.check_change(self.state, diff=DIFF_IN_HELPER)
        self.assertEqual(out["verdict"], "PASS", out["reasons"])

    def test_review_on_never_scanned_file(self):
        (self.repo / "new_module.py").write_text("x = 1\n", encoding="utf-8")
        # Our state has a whole-repo spend row, so the ancestor rule covers
        # even a brand-new file: deterministic gate PASS, and the parallel
        # scan_change audit is what inspects the new content.
        out = mcp_server.check_change(self.state, files=["new_module.py"])
        self.assertEqual(out["verdict"], "PASS", out["reasons"])

        narrow = mcp_server.MantisState(str(self.repo))
        narrow_home = Path(self.tmp) / "narrow"
        narrow_home.mkdir()
        narrow.home = narrow_home
        narrow.db_path = str(narrow_home / "knowledge.db")
        from core.database import init_db
        init_db(narrow.db_path)
        record_spend(narrow.db_path, "run-n", str(self.repo / "app.py"),
                     "deep", tokens=5)
        out = mcp_server.check_change(narrow, files=["new_module.py"])
        self.assertEqual(out["verdict"], "REVIEW")
        self.assertTrue(any("never been scanned" in r for r in out["reasons"]))

    def test_blast_radius_names_function_and_callers(self):
        out = mcp_server.check_change(self.state, diff=DIFF_IN_HELPER)
        self.assertTrue(out["blast_radius"], "expected an enclosing function")
        entry = out["blast_radius"][0]
        self.assertIn("helper", str(entry["function"]))
        callers = {str(c["caller"]) for c in entry["callers"]}
        self.assertTrue(any("handler" in c for c in callers), callers)

    def test_deletion_only_diff_still_has_blast_radius(self):
        # Deleting a line from helper's body, adding nothing: the gate must
        # still anchor the change inside helper and walk to its callers.
        diff = (
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,2 +1,1 @@\n"
            " def helper(x):\n"
            "-    return x * 2\n"
        )
        out = mcp_server.check_change(self.state, diff=diff)
        self.assertTrue(out["blast_radius"], "deletion-only diff lost its radius")
        self.assertIn("helper", str(out["blast_radius"][0]["function"]))

    def test_caller_radius_finding_reviews_not_blocks(self):
        # util.py calls the changed function, and carries an open HIGH
        # finding: the gate must surface it as caller_radius and hold at
        # REVIEW -- BLOCK is reserved for findings in the change itself.
        (self.repo / "util.py").write_text(
            "from app import helper\n\n\ndef use(v):\n    return helper(v)\n",
            encoding="utf-8",
        )
        mcp_server.reindex(self.state)
        self._write_finding("HIGH", filepath="util.py")
        out = mcp_server.check_change(self.state, diff=DIFF_IN_HELPER)
        self.assertEqual(out["verdict"], "REVIEW", out["reasons"])
        self.assertIn("caller_radius",
                      {f["relationship"] for f in out["findings"]})

    def test_resolve_mitigated_closes_the_loop(self):
        self._write_finding("HIGH")
        out = mcp_server.check_change(self.state, diff=DIFF_IN_HELPER)
        self.assertEqual(out["verdict"], "BLOCK")
        fid = out["findings"][0]["id"]
        res = mcp_server.resolve_finding(
            self.state, fid, "mitigated", "parameterized the query")
        self.assertTrue(res["applied"], res)
        out = mcp_server.check_change(self.state, diff=DIFF_IN_HELPER)
        self.assertEqual(out["verdict"], "PASS", out["reasons"])
        audit = (self.state.home / "resolutions.log").read_text(encoding="utf-8")
        self.assertIn("parameterized the query", audit)

    def test_dismissal_cannot_erase_machine_evidence(self):
        self._write_finding("HIGH", status="dynamic_confirmed")
        fid = mcp_server.get_findings(self.state)["findings"][0]["id"]
        res = mcp_server.resolve_finding(
            self.state, fid, "false_positive", "I disagree")
        self.assertFalse(res["applied"], res)
        self.assertEqual(res["new_status"].lower(), "dynamic_confirmed")
        self.assertIn("machine-verified", res["note"])
        # A fix is not a dismissal: mitigated IS allowed over machine proof.
        res = mcp_server.resolve_finding(
            self.state, fid, "mitigated", "fixed and deployed")
        self.assertTrue(res["applied"], res)

    def test_terminal_refusal_note_names_the_status_not_the_machine(self):
        """Re-closing an already-dismissed finding is refused because the
        row is terminal -- the note must say that, not blame machine
        evidence that was never there."""
        self._write_finding("HIGH")
        fid = mcp_server.get_findings(self.state)["findings"][0]["id"]
        self.assertTrue(mcp_server.resolve_finding(
            self.state, fid, "false_positive", "wrong file entirely")["applied"])
        res = mcp_server.resolve_finding(
            self.state, fid, "mitigated", "changed my mind, I fixed it")
        self.assertFalse(res["applied"], res)
        self.assertIn("false_positive", res["note"])
        self.assertNotIn("machine-verified", res["note"])

    def test_resolve_rejects_dishonest_or_empty_input(self):
        self._write_finding("HIGH")
        fid = mcp_server.get_findings(self.state)["findings"][0]["id"]
        # Machine labels are not available to the operator surface.
        self.assertIn("error", mcp_server.resolve_finding(
            self.state, fid, "patch_verified", "trust me"))
        self.assertIn("error", mcp_server.resolve_finding(
            self.state, fid, "mitigated", "   "))
        self.assertIn("error", mcp_server.resolve_finding(
            self.state, 99999, "mitigated", "no such finding"))


class TestPathContainment(unittest.TestCase):
    """Paths that do not resolve inside the repo are refused, loudly."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = make_repo(self.tmp)
        self.state = mcp_server.MantisState(str(self.repo))

    def test_rel_refuses_traversals_and_outside_paths(self):
        self.assertEqual(self.state.rel("../outside.py"), "")
        self.assertEqual(self.state.rel("a/../../outside.py"), "")
        self.assertEqual(self.state.rel("/etc/passwd"), "")
        self.assertEqual(self.state.rel(str(Path(self.tmp) / "x.py")), "")
        # In-repo spellings still resolve.
        self.assertEqual(self.state.rel("app.py"), "app.py")
        self.assertEqual(self.state.rel("./app.py"), "app.py")
        self.assertEqual(self.state.rel(str(self.repo / "app.py")), "app.py")

    def test_scan_change_refuses_existing_files_outside_repo(self):
        outside = Path(self.tmp) / "outside.py"
        outside.write_text("x = 1\n", encoding="utf-8")
        out = mcp_server.scan_change(
            self.state, ["../outside.py", str(outside)])
        self.assertIn("error", out)
        self.assertFalse((self.repo / ".mantis").exists())

    def test_scan_change_refuses_symlink_escape(self):
        secret = Path(self.tmp) / "secret.py"
        secret.write_text("x = 1\n", encoding="utf-8")
        (self.repo / "link.py").symlink_to(secret)
        out = mcp_server.scan_change(self.state, ["link.py"])
        self.assertIn("error", out)

    def test_check_change_names_outside_paths(self):
        out = mcp_server.check_change(
            self.state, files=["../outside.py", "app.py"])
        self.assertEqual(out["verdict"], "REVIEW")
        self.assertTrue(
            any("outside this repository" in r for r in out["reasons"]),
            out["reasons"])


class TestScanCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = make_repo(self.tmp)
        self.state = mcp_server.MantisState(str(self.repo))

    def test_scan_cmd_shape(self):
        cmd = mcp_server._scan_cmd(self.state, "/t/app.py", 99, "some-model")
        self.assertEqual(cmd[0], sys.executable)
        self.assertTrue(cmd[1].endswith("main.py"))
        self.assertEqual(cmd[2], "/t/app.py")
        self.assertIn("--db", cmd)
        self.assertIn("--yes", cmd)
        # The anchor that keeps stored finding paths repo-relative instead of
        # bare basenames, which same-named files could cross-match.
        self.assertEqual(cmd[cmd.index("--path-root") + 1], str(self.state.repo))
        self.assertEqual(cmd[cmd.index("--max-llm-calls") + 1], "99")
        self.assertEqual(cmd[cmd.index("--model") + 1], "some-model")

    def test_scan_cmd_omits_optionals(self):
        cmd = mcp_server._scan_cmd(self.state, "/t/app.py", 0, "")
        self.assertNotIn("--max-llm-calls", cmd)
        self.assertNotIn("--model", cmd)

    def test_scan_change_rejects_nonexistent_files(self):
        out = mcp_server.scan_change(self.state, ["missing.py"])
        self.assertIn("error", out)
        self.assertFalse((self.repo / ".mantis").exists())


class TestScanIndexRestore(unittest.TestCase):
    """A finished scan must leave the shared catalog repo-rooted.

    The pipeline subprocess scans ONE file as its target and rebuilds the
    shared structural index rooted there, so repo-rooted paths stop
    resolving and the gate's blast radius goes blind (found dogfooding:
    callers vanished after the first background scan).
    """

    def test_repo_rooted_index_restored_after_scan(self):
        from unittest import mock

        from core.structural_index import build_structural_index

        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        repo = make_repo(tmp)
        sub = repo / "sub"
        sub.mkdir()
        (sub / "mod.py").write_text("def inner():\n    return 1\n",
                                    encoding="utf-8")
        state = mcp_server.MantisState(str(repo))
        mcp_server.reindex(state)
        self.assertTrue(
            state.index().enclosing_symbol("app.py", 2).get("found"))

        # What the pipeline subprocess does: re-root the shared catalog at
        # its own (narrower) target.
        build_structural_index(str(sub), state.state_dir())
        self.assertFalse(
            state.index().enclosing_symbol("app.py", 2).get("found"))

        # A scan whose subprocess is a no-op: only the restore acts.
        with mock.patch.object(
                mcp_server, "_scan_cmd",
                lambda *a, **k: [sys.executable, "-c", "pass"]):
            out = mcp_server.scan_change(state, ["app.py"])
            self.assertIn("scan_id", out)
            deadline = time.time() + 30
            status = {}
            while time.time() < deadline:
                status = mcp_server.scan_status(state, out["scan_id"])
                if status.get("status") in ("done", "finished_with_errors"):
                    break
                time.sleep(0.2)
        self.assertEqual(status.get("status"), "done", status)
        self.assertTrue(status.get("index_restored"), status)
        self.assertTrue(
            state.index().enclosing_symbol("app.py", 2).get("found"))


class TestReindexPin(unittest.TestCase):
    """reindex pins a clean git checkout to HEAD, so a repeat is a reuse."""

    def setUp(self):
        import subprocess

        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.repo = make_repo(tmp)
        (self.repo / "sub").mkdir()
        (self.repo / "sub" / "mod.py").write_text("def inner():\n    return 1\n", encoding="utf-8")
        for args in (["init", "-q"], ["config", "user.email", "t@example.com"],
                     ["config", "user.name", "t"], ["add", "-A"], ["commit", "-q", "-m", "c"]):
            subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True)
        self.state = mcp_server.MantisState(str(self.repo), home=str(Path(tmp) / "state"))

    def _writes(self):
        from unittest import mock

        import core.structural_index as sidx

        real = sidx._write_catalog
        calls = []
        return calls, mock.patch.object(
            sidx, "_write_catalog", lambda *a, **k: (calls.append(1), real(*a, **k)))

    def test_repeat_reindex_of_a_clean_checkout_reuses_the_catalog(self):
        calls, patch = self._writes()
        with patch:
            first = mcp_server.reindex(self.state)
            second = mcp_server.reindex(self.state)
        self.assertEqual(first["status"], "complete")
        self.assertEqual(second["status"], "complete")
        self.assertEqual(len(calls), 1, "the second reindex at the same commit rebuilt the catalog")

    def test_catalog_re_rooted_at_the_same_commit_is_still_restored(self):
        from core.structural_index import build_structural_index

        mcp_server.reindex(self.state)
        build_structural_index(str(self.repo / "sub"), self.state.state_dir())
        self.assertFalse(self.state.index().enclosing_symbol("app.py", 2).get("found"))
        mcp_server.reindex(self.state)
        self.assertTrue(self.state.index().enclosing_symbol("app.py", 2).get("found"))


class TestScanStatusLabels(unittest.TestCase):
    """Pipeline exit 2 is a graceful budget pause, not a failure."""

    def _scan_with_exit(self, code: int) -> dict:
        from unittest import mock

        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        repo = make_repo(tmp)
        state = mcp_server.MantisState(str(repo))
        mcp_server.reindex(state)
        with mock.patch.object(
                mcp_server, "_scan_cmd",
                lambda *a, **k: [sys.executable, "-c",
                                 f"import sys; sys.exit({code})"]):
            out = mcp_server.scan_change(state, ["app.py"])
            deadline = time.time() + 30
            status = {}
            while time.time() < deadline:
                status = mcp_server.scan_status(state, out["scan_id"])
                if status.get("status") != "running":
                    break
                time.sleep(0.2)
        return status

    def test_exit_2_is_paused_not_an_error(self):
        status = self._scan_with_exit(2)
        self.assertEqual(status.get("status"), "paused_at_budget", status)

    def test_other_nonzero_exits_are_errors(self):
        status = self._scan_with_exit(1)
        self.assertEqual(status.get("status"), "finished_with_errors", status)

    def test_wait_seconds_blocks_until_scan_completes(self):
        from unittest import mock

        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        repo = make_repo(tmp)
        state = mcp_server.MantisState(str(repo))
        mcp_server.reindex(state)
        with mock.patch.object(
                mcp_server, "_scan_cmd",
                lambda *a, **k: [sys.executable, "-c",
                                 "import time; time.sleep(0.1)"]):
            out = mcp_server.scan_change(state, ["app.py"])
            status = mcp_server.scan_status(state, out["scan_id"], wait_seconds=10)
        self.assertEqual(status.get("status"), "done", status)


class TestCheckCli(unittest.TestCase):
    """The one-shot --check mode that serves pre-commit hooks and CI."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = make_repo(self.tmp)

    def _run_check(self, argv, stdin_text=""):
        buf = io.StringIO()
        old_stdin = sys.stdin
        try:
            sys.stdin = io.StringIO(stdin_text)
            with contextlib.redirect_stdout(buf):
                rc = mcp_server.main(argv)
        finally:
            sys.stdin = old_stdin
        return rc, buf.getvalue()

    def test_fresh_repo_reviews_with_exit_1_and_writes_nothing(self):
        rc, out = self._run_check(["--repo", str(self.repo), "--check"],
                                  stdin_text=DIFF_IN_HELPER)
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "REVIEW")
        self.assertFalse((self.repo / ".mantis").exists())

    def test_files_flag_without_diff(self):
        rc, out = self._run_check(
            ["--repo", str(self.repo), "--check", "--files", "app.py"])
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out)["verdict"], "REVIEW")

    def test_bad_repo_exits_3_not_a_verdict_code(self):
        rc, _ = self._run_check(
            ["--repo", str(self.repo / "nope"), "--check"])
        self.assertEqual(rc, 3)


class TestMcpProtocol(unittest.TestCase):
    """Smoke test over the pinned MCP SDK."""

    def test_tools_registered(self):
        import mcp  # noqa: F401

        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        state = mcp_server.MantisState(str(make_repo(tmp)))
        srv = mcp_server.build_server(state)
        tools = asyncio.run(srv.list_tools())
        names = {t.name for t in tools}
        expected = {
            "mantis_check_change", "mantis_scan_change", "mantis_scan_status",
            "mantis_reindex", "mantis_find_symbol", "mantis_find_callers",
            "mantis_find_callees", "mantis_function_at", "mantis_get_findings",
            "mantis_security_guidance", "mantis_resolve_finding",
        }
        self.assertEqual(expected - names, set(), f"missing tools: {expected - names}")


if __name__ == "__main__":
    unittest.main()

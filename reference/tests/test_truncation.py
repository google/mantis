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

"""Truncation is the harness's: one marker, a floor on verdict-stage limits,
and a fail-closed reading of a cut sandbox trace.

A tool output cut without saying so is read as the whole observation, and a
verdict drawn from where the cut fell is a verdict drawn from the harness.
These tests pin the three things that stop that: every cut goes through
core.truncation and announces itself in one shape; the limits on outputs the
reviewer, critic, reproducer and patcher read are never below 10,000 chars;
and check_reached_sink_evidence never reads "sentinel not in a cut trace" as
"sentinel absent" (INV-1 fails closed with a reason that says why).
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from core.context import RunContext, current_run_context
from core.llm_gateway import UNTRUSTED_DATA_END, UNTRUSTED_DATA_START
from core.truncation import (
    DEFAULT_ADVICE,
    TRUNCATION_MARKER_PREFIX,
    is_truncation_marker_present,
    split_truncation,
    truncate_with_marker,
    truncation_marker,
)
from tools import sandbox_tools
from tools.sandbox_tools import (
    EVIDENCE_TRUNCATED_PREFIX,
    MANTIS_SENTINEL_TOKEN,
    check_reached_sink_evidence,
)

VERDICT_FLOOR = 10_000


# ---------------------------------------------------------------------------
# The helper
# ---------------------------------------------------------------------------


class TruncationHelperTest(unittest.TestCase):
    def test_text_within_limit_is_returned_unchanged(self):
        for text in ("", "abc", "x" * 100):
            with self.subTest(text=text[:5]):
                self.assertEqual(truncate_with_marker(text, 100), text)
                self.assertEqual(split_truncation(text, 100), (text, ""))
                self.assertFalse(is_truncation_marker_present(truncate_with_marker(text, 100)))

    def test_marker_has_the_one_exact_shape(self):
        out = truncate_with_marker("a" * 25, 10, what="file 'x.c'")
        expected = (
            "a" * 10
            + "\n[MANTIS TRUNCATION: file 'x.c' cut by the harness after 10 of 25 chars "
            "(15 omitted). This cut is the harness's, not the target's: re-read with "
            "start_line/end_line, get_function_boundary, or a narrower command before "
            "drawing any conclusion from the boundary.]"
        )
        self.assertEqual(out, expected)
        self.assertTrue(out.startswith("a" * 10 + "\n" + TRUNCATION_MARKER_PREFIX))
        self.assertTrue(is_truncation_marker_present(out))

    def test_omitted_count_is_total_minus_limit(self):
        for total, limit in ((11, 10), (1000, 10), (VERDICT_FLOOR + 1, VERDICT_FLOOR)):
            with self.subTest(total=total, limit=limit):
                out = truncate_with_marker("z" * total, limit)
                self.assertEqual(len(out.split("\n", 1)[0]), limit)
                self.assertIn(f"after {limit} of {total} chars ({total - limit} omitted)", out)

    def test_default_what_is_output(self):
        self.assertIn("output cut by the harness", truncate_with_marker("q" * 5, 2))

    def test_marker_builder_supports_other_units_in_the_same_shape(self):
        m = truncation_marker("listing under 'src'", 1000, 3000, unit="entries", advice="walk a subtree.")
        self.assertTrue(m.startswith(TRUNCATION_MARKER_PREFIX))
        self.assertIn("cut by the harness after 1000 of 3000 entries (2000 omitted)", m)
        self.assertIn("This cut is the harness's, not the target's: walk a subtree.]", m)
        self.assertNotIn(DEFAULT_ADVICE, m)

    def test_never_raises_on_hostile_inputs(self):
        self.assertEqual(truncate_with_marker(None, 10), "")
        self.assertEqual(truncate_with_marker(12345, 10), "12345")
        self.assertTrue(truncate_with_marker("abc", -1).startswith("\n" + TRUNCATION_MARKER_PREFIX))
        self.assertTrue(truncate_with_marker("abc", "bogus").startswith("\n" + TRUNCATION_MARKER_PREFIX))
        self.assertFalse(is_truncation_marker_present(None))
        self.assertFalse(is_truncation_marker_present(""))
        self.assertTrue(is_truncation_marker_present({"k": TRUNCATION_MARKER_PREFIX}))

    def test_presence_check_is_the_prefix(self):
        self.assertTrue(is_truncation_marker_present(f"noise {TRUNCATION_MARKER_PREFIX} x]"))
        self.assertFalse(is_truncation_marker_present("[TRUNCATED: old style]"))


# ---------------------------------------------------------------------------
# Limits on what the verdict stages read
# ---------------------------------------------------------------------------


class VerdictStageLimitsTest(unittest.TestCase):
    """Below 10k chars a cut can hide the very guard the reader is looking for."""

    def test_read_file_and_git_limit(self):
        import tools.research_tools as rt
        self.assertGreaterEqual(rt.MAX_READ_SIZE, VERDICT_FLOOR)

    def test_function_boundary_limit(self):
        import tools.structural_tools as st
        self.assertGreaterEqual(st.MAX_SNIPPET_BYTES, VERDICT_FLOOR)

    def test_every_sandbox_backend_output_cap(self):
        from core.environments import gce_env, gvisor_env, microsandbox_env
        for mod in (gce_env, gvisor_env, microsandbox_env):
            with self.subTest(backend=mod.__name__):
                self.assertGreaterEqual(mod.MAX_OUTPUT, VERDICT_FLOOR)

    def test_no_ad_hoc_truncation_text_remains_in_tool_or_sandbox_code(self):
        """Every cut announces itself through the shared marker, not a local string."""
        root = Path(_REF_ROOT)
        offenders = []
        for rel in ("tools", "core/environments"):
            for py in sorted((root / rel).glob("*.py")):
                src = py.read_text(encoding="utf-8")
                if "[TRUNCATED" in src:
                    offenders.append(str(py.relative_to(root)))
                # A bare slice to a literal cap on a stream the model reads.
                if re.search(r"\[:\s*16000\s*\]", src):
                    offenders.append(f"{py.relative_to(root)} (bare [:16000] slice)")
        self.assertEqual(offenders, [])


# ---------------------------------------------------------------------------
# The tool sites
# ---------------------------------------------------------------------------


class ReadFileMarkerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import tools.research_tools as rt
        from core.database import init_db
        from core.sandbox import build_sandbox
        self.rt = rt
        self.tmp = tempfile.mkdtemp(prefix="mantis_trunc_read_")
        self.jail = Path(self.tmp)
        self.body = "".join(f"line {i:05d}: int guard = x < len;\n" for i in range(1, 400))
        (self.jail / "big.c").write_text(self.body, encoding="utf-8")
        db = str(self.jail / "knowledge.db")
        init_db(db)
        ctx = RunContext(
            jail_dir=str(self.jail), db_path=db, target_file=str(self.jail),
            sandbox=build_sandbox({"type": "static-only", "options": {}}, str(self.jail)),
            run_id="trunc_read",
        )
        self.tok = current_run_context.set(ctx)

    async def asyncTearDown(self):
        current_run_context.reset(self.tok)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_untouched_when_under_the_limit(self):
        out = await self.rt.read_file("big.c")
        self.assertFalse(is_truncation_marker_present(out))
        self.assertIn("line 00399", out)

    async def test_cut_is_announced_outside_the_untrusted_fence(self):
        limit = 500
        numbered_body = "".join(
            f"{i}: line {i:05d}: int guard = x < len;\n" for i in range(1, 400)
        )
        with patch.object(self.rt, "MAX_READ_SIZE", limit):
            out = await self.rt.read_file("big.c")
        self.assertTrue(is_truncation_marker_present(out))
        self.assertIn(f"file 'big.c' cut by the harness after {limit} of {len(numbered_body)} chars", out)
        self.assertNotIn("[TRUNCATED", out)
        # Harness bookkeeping sits after the fence, like the range header and
        # the large-read note: a hostile file cannot forge its position.
        self.assertGreater(out.index(TRUNCATION_MARKER_PREFIX), out.index(UNTRUSTED_DATA_END))
        # Exactly `limit` chars of the numbered source survive inside the fence.
        inside = out[out.index(UNTRUSTED_DATA_START):out.index(UNTRUSTED_DATA_END)]
        inside_body = inside.split("\n", 1)[1].rstrip("\n")
        self.assertEqual(inside_body, numbered_body[:limit])

    async def test_ranged_read_is_cut_by_the_same_rule(self):
        with patch.object(self.rt, "MAX_READ_SIZE", 40):
            out = await self.rt.read_file("big.c", start_line=1, end_line=5)
        self.assertTrue(out.startswith("[big.c: lines 1-5 of 399]"))
        self.assertTrue(is_truncation_marker_present(out))
        self.assertGreater(out.index(TRUNCATION_MARKER_PREFIX), out.index(UNTRUSTED_DATA_END))


class GitOutputMarkerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import subprocess
        import tools.research_tools as rt
        self.rt = rt
        self.tmp = tempfile.mkdtemp(prefix="mantis_trunc_git_")
        self.repo = Path(os.path.realpath(self.tmp))
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t",
                   GIT_COMMITTER_EMAIL="t@x", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True, env=env)
        (self.repo / "a.c").write_text("int a;\n" * 200)
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True, env=env)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-q", "-m", "one"], check=True, env=env)
        (self.repo / "a.c").write_text("int b;\n" * 200)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-q", "-am", "two"], check=True, env=env)
        ctx = RunContext(jail_dir=str(self.repo), db_path=str(self.repo / "k.db"),
                         target_file=str(self.repo), run_id="trunc_git")
        self.tok = current_run_context.set(ctx)

    async def asyncTearDown(self):
        current_run_context.reset(self.tok)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_git_diff_and_log_announce_the_cut_outside_the_fence(self):
        with patch.object(self.rt, "MAX_READ_SIZE", 64):
            diff = await self.rt.get_git_diff()
            log = await self.rt.get_git_log()
        for label, out in (("diff", diff), ("log", log)):
            with self.subTest(tool=label):
                self.assertTrue(is_truncation_marker_present(out), out[:200])
                self.assertNotIn("[TRUNCATED", out)
                self.assertGreater(out.index(TRUNCATION_MARKER_PREFIX), out.index(UNTRUSTED_DATA_END))
        self.assertIn("git diff for 'HEAD' cut by the harness after 64 of", diff)
        self.assertIn("git log for 'repo' cut by the harness after 64 of", log)


class ListFilesHintTest(unittest.IsolatedAsyncioTestCase):
    async def test_structured_contract_kept_and_hint_carries_the_marker(self):
        import json
        import tools.research_tools as rt
        entries = [f"src/f{i}.c" for i in range(30)]
        with patch.object(rt, "MAX_LIST_ENTRIES", 10):
            raw = rt._bounded_listing(entries, "src")
        payload = json.loads(raw)
        self.assertTrue(payload["truncated"])
        self.assertEqual(payload["shown"], 10)
        self.assertEqual(payload["total"], 30)
        self.assertEqual(len(payload["entries"]), 10)
        self.assertTrue(payload["hint"].startswith(TRUNCATION_MARKER_PREFIX))
        self.assertIn("after 10 of 30 entries (20 omitted)", payload["hint"])
        self.assertIn("narrower", payload["hint"])


class FunctionBoundaryMarkerTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        import tree_sitter  # noqa: F401
        from core.structural_index import build_structural_index, state_dir_for_db

        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_trunc_boundary_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(os.path.realpath(self._tmp.name))
        self.code = self.tmp / "code"
        self.code.mkdir()
        body = "\n".join(f"    x = x + {i}" for i in range(400))
        self.src = f"def big(x):\n{body}\n    return x\n"
        (self.code / "big.py").write_text(self.src)
        self.db = str(self.tmp / "knowledge.db")
        Path(self.db).touch()
        build_structural_index(str(self.code), state_dir_for_db(self.db), "snap")
        tok = current_run_context.set(RunContext(jail_dir=str(self.code), db_path=self.db,
                                                 target_file="", run_id="r"))
        self.addCleanup(current_run_context.reset, tok)

    async def test_boundary_cut_is_announced_outside_the_fence(self):
        import tools.structural_tools as st
        full = await st.get_function_boundary("big.py", 5)
        self.assertNotIn("Structural index unavailable", full)
        self.assertNotIn("No indexed function", full)
        self.assertFalse(is_truncation_marker_present(full))
        with patch.object(st, "MAX_SNIPPET_BYTES", 200):
            out = await st.get_function_boundary("big.py", 5)
        self.assertTrue(is_truncation_marker_present(out))
        self.assertIn("function body big.py:", out)
        self.assertIn("cut by the harness after 200 of", out)
        self.assertNotIn("[TRUNCATED", out)
        self.assertGreater(out.index(TRUNCATION_MARKER_PREFIX), out.index(UNTRUSTED_DATA_END))


class SandboxBackendMarkerTest(unittest.IsolatedAsyncioTestCase):
    """The environments are where a sandbox trace is cut; the cut must be announced there."""

    async def test_gce_execute_announces_a_cut_stream(self):
        from core.environments import gce_env
        env = gce_env.GceEnvironment(project="p", gcloud_bin="/bin/true")
        env._ensure = AsyncMock(return_value=None)
        long_out = "o" * (gce_env.MAX_OUTPUT + 500)
        long_err = "e" * (gce_env.MAX_OUTPUT + 7)
        with patch("subprocess.run", return_value=MagicMock(returncode=3, stdout=long_out, stderr=long_err)):
            res = await env.execute("./poc")
        self.assertEqual(res.exit_code, 3)
        self.assertTrue(res.stdout.startswith("o" * gce_env.MAX_OUTPUT + "\n" + TRUNCATION_MARKER_PREFIX))
        self.assertIn(f"sandbox stdout cut by the harness after {gce_env.MAX_OUTPUT} of {len(long_out)} chars (500 omitted)", res.stdout)
        self.assertIn(f"sandbox stderr cut by the harness after {gce_env.MAX_OUTPUT} of {len(long_err)} chars (7 omitted)", res.stderr)
        with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="short", stderr="")):
            res = await env.execute("./poc")
        self.assertEqual((res.stdout, res.stderr), ("short", ""))

    async def test_gvisor_execute_and_apply_patch_announce_a_cut_stream(self):
        from core.environments import gvisor_env
        with patch("shutil.which", return_value="/usr/bin/docker"):
            env = gvisor_env.GvisorEnvironment(container_tool="docker")
        env._ensure = AsyncMock(return_value=None)
        long_out = "o" * (gvisor_env.MAX_OUTPUT + 1)
        with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=long_out, stderr="")):
            res = await env.execute("./poc")
        self.assertIn(f"sandbox stdout cut by the harness after {gvisor_env.MAX_OUTPUT} of {len(long_out)} chars (1 omitted)", res.stdout)
        self.assertEqual(res.stderr, "")
        with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=long_out, stderr="")):
            out = await env.apply_patch("--- a\n+++ b\n")
        self.assertTrue(out.startswith("exit=0\n" + "o" * gvisor_env.MAX_OUTPUT + "\n" + TRUNCATION_MARKER_PREFIX))
        self.assertIn("patch output cut by the harness", out)

    async def test_microsandbox_execute_announces_a_cut_stream(self):
        from core.environments import microsandbox_env
        env = microsandbox_env.MicrosandboxEnvironment.__new__(microsandbox_env.MicrosandboxEnvironment)
        env._workdir = Path("/workspace")
        env.timeout = 5
        long_out = "o" * (microsandbox_env.MAX_OUTPUT + 9)
        shell_result = MagicMock(stdout_text=long_out, stderr_text="", exit_code=0)
        fake_sb = MagicMock()
        fake_sb.shell = AsyncMock(return_value=shell_result)
        env._ensure = AsyncMock(return_value=fake_sb)
        res = await env.execute("./poc")
        self.assertIn(f"sandbox stdout cut by the harness after {microsandbox_env.MAX_OUTPUT} of {len(long_out)} chars (9 omitted)", res.stdout)


# ---------------------------------------------------------------------------
# INV-1: a cut trace verifies nothing, and says so
# ---------------------------------------------------------------------------


def _cut(text: str, limit: int = 50) -> str:
    return truncate_with_marker(text, limit, what="sandbox stdout")


class EvidenceCheckerTruncationTest(unittest.TestCase):
    def test_no_sentinel_in_a_cut_trace_is_truncated_not_absent(self):
        out = _cut("harness starting\n" + "noise\n" * 100)
        present, reason = check_reached_sink_evidence(out, exit_code=0)
        self.assertFalse(present)
        self.assertTrue(reason.startswith(EVIDENCE_TRUNCATED_PREFIX + ":"), reason)
        self.assertNotIn("EVIDENCE_ABSENT", reason)
        self.assertIn("cut by the harness before the sentinel could be confirmed", reason)

    def test_no_sentinel_in_a_whole_trace_is_still_absent(self):
        present, reason = check_reached_sink_evidence("harness starting\nnoise\n", exit_code=0)
        self.assertFalse(present)
        self.assertTrue(reason.startswith("EVIDENCE_ABSENT:"), reason)
        self.assertNotIn(EVIDENCE_TRUNCATED_PREFIX, reason)

    def test_sentinel_that_survived_the_cut_still_counts(self):
        out = _cut("==1==ERROR: AddressSanitizer: heap-buffer-overflow\n" + "noise\n" * 100)
        present, reason = check_reached_sink_evidence(out, exit_code=1)
        self.assertTrue(present, reason)
        self.assertIn("EVIDENCE_PRESENT", reason)

    def test_sidecar_sentinel_beats_a_cut_trace(self):
        out = _cut("noise\n" * 100)
        present, reason = check_reached_sink_evidence(out, 0, sentinel_content=MANTIS_SENTINEL_TOKEN)
        self.assertTrue(present, reason)

    def test_crash_naming_the_sink_inside_the_kept_part_still_counts(self):
        asan = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n#0 0x4a1 in parse_header src/p.c:9\n"
        out = truncate_with_marker(asan + "tail\n" * 100, len(asan) + 10, what="sandbox stderr")
        present, reason = check_reached_sink_evidence(out, 1, sink_symbol="parse_header")
        self.assertTrue(present, reason)

    def test_crash_whose_sink_frame_may_be_in_the_cut_is_truncated_not_absent(self):
        asan = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n#0 0x4a1 in other_fn src/o.c:1\n"
        out = truncate_with_marker(asan + "#1 ...\n" * 100, len(asan) + 3, what="sandbox stderr")
        present, reason = check_reached_sink_evidence(out, 1, sink_symbol="parse_header")
        self.assertFalse(present)
        self.assertTrue(reason.startswith(EVIDENCE_TRUNCATED_PREFIX + ":"), reason)
        self.assertIn("no backtrace frame names target sink 'parse_header'", reason)

    def test_definitive_failures_are_not_relabelled(self):
        # Exit 127 and an unavailable sandbox are facts about the run, not
        # about the trace's completeness; their reasons stay what they were.
        present, reason = check_reached_sink_evidence(_cut("sh: poc: command not found\n" * 20), 127)
        self.assertFalse(present)
        self.assertIn("exit code 127", reason)
        present, reason = check_reached_sink_evidence("SANDBOX-UNAVAILABLE " + _cut("x" * 100), 0)
        self.assertFalse(present)
        self.assertIn("sandbox environment unavailable", reason)

    def test_a_forged_marker_cannot_manufacture_evidence(self):
        # A target printing the marker text gets, at most, "not verified":
        # the rule only ever turns a negative into a differently worded negative.
        forged = f"{TRUNCATION_MARKER_PREFIX} fake] all good"
        present, reason = check_reached_sink_evidence(forged, 0, sink_symbol="sink")
        self.assertFalse(present)
        present, reason = check_reached_sink_evidence(forged, 0, sentinel_content="")
        self.assertFalse(present)


class _FakeSandbox:
    def __init__(self, stdout: str, stderr: str = "", exit_code: int = 0, files=None, post_files=None):
        from google.adk.environment import ExecutionResult
        self._res = ExecutionResult(stdout=stdout, stderr=stderr, exit_code=exit_code, timed_out=False)
        self.files = dict(files or {})   # guest path -> bytes
        self._post_files = dict(post_files or {})
        self.writes = []

    async def execute(self, command):
        self.files.update(self._post_files)
        return self._res

    async def read_file(self, path):
        key = str(path)
        if key in self.files:
            return self.files[key]
        raise FileNotFoundError(path)

    async def write_file(self, path, content):
        data = content.encode("utf-8") if isinstance(content, str) else content
        self.files[str(path)] = data
        self.writes.append((str(path), data))


class StaleSentinelTest(unittest.IsolatedAsyncioTestCase):
    """A sentinel left by an earlier attempt must not satisfy this one -- and clearing it
    must not become a way to blank whatever file the model names."""

    def _ctx(self, sandbox):
        self.tmp = tempfile.mkdtemp(prefix="mantis_sentinel_")
        ctx = RunContext(jail_dir=self.tmp, db_path=str(Path(self.tmp) / "k.db"), target_file="", run_id="s")
        ctx.sandbox = sandbox
        ctx.active_node = "reproducer"
        tok = current_run_context.set(ctx)
        self.addCleanup(current_run_context.reset, tok)
        return ctx

    async def test_a_stale_sentinel_is_cleared_before_the_run(self):
        sb = _FakeSandbox(stdout="exit=1\npayload rejected\n", files={"sentinel_7": b"MANTIS_REACHED_ENTRYPOINT\n"})
        self._ctx(sb)
        res = await sandbox_tools.run_sandbox_with_evidence("python3 poc.py", sentinel_path="sentinel_7", sink_symbol="sink")
        self.assertFalse(res["evidence_present"], "last attempt's sentinel did not prove this attempt")
        self.assertEqual(sb.writes, [("sentinel_7", b"")])

    async def test_a_file_that_is_not_a_sentinel_is_left_alone(self):
        app = b"from flask import Flask\napp = Flask(__name__)\n"
        sb = _FakeSandbox(stdout="exit=0\nok\n", files={"app.py": app})
        self._ctx(sb)
        res = await sandbox_tools.run_sandbox_with_evidence("python3 poc.py", sentinel_path="app.py", sink_symbol="sink")
        self.assertEqual(sb.writes, [], "a model-named path that is not a stale sentinel is never written")
        self.assertEqual(sb.files["app.py"], app)
        self.assertFalse(res["evidence_present"])

    async def test_a_missing_sentinel_path_is_fine(self):
        sb = _FakeSandbox(stdout="exit=0\nMANTIS_REACHED_ENTRYPOINT\n")
        self._ctx(sb)
        res = await sandbox_tools.run_sandbox_with_evidence("python3 poc.py", sentinel_path="sentinel_9", sink_symbol="sink")
        self.assertEqual(sb.writes, [])
        self.assertFalse(res["evidence_present"], "stdout token without sidecar file must not forge proof")


class RunSandboxWithEvidenceTruncationTest(unittest.IsolatedAsyncioTestCase):
    def _ctx(self, sandbox):
        self.tmp = tempfile.mkdtemp(prefix="mantis_trunc_sbx_")
        ctx = RunContext(jail_dir=self.tmp, db_path=str(Path(self.tmp) / "k.db"), target_file="", run_id="s")
        ctx.sandbox = sandbox
        ctx.active_node = "reproducer"
        tok = current_run_context.set(ctx)
        self.addCleanup(current_run_context.reset, tok)
        return ctx

    async def test_cut_trace_without_sentinel_is_not_verified_and_flag_stays_down(self):
        cut = truncate_with_marker("poc running\n" * 2000, 16000, what="sandbox stdout")
        ctx = self._ctx(_FakeSandbox(stdout=cut))
        res = await sandbox_tools.run_sandbox_with_evidence("python3 poc.py", sink_symbol="sink")
        self.assertFalse(res["evidence_present"])
        self.assertTrue(res["evidence_reason"].startswith(EVIDENCE_TRUNCATED_PREFIX + ":"), res["evidence_reason"])
        self.assertFalse(getattr(ctx, "sandbox_executed", False))
        # The marker reaches the model inside the tool response, so the
        # prompt rule has something to point at.
        self.assertTrue(is_truncation_marker_present(res["raw"]))

    async def test_cut_trace_with_sentinel_in_the_kept_part_is_verified(self):
        cut = truncate_with_marker("poc running\n" * 2000, 16000, what="sandbox stdout")
        ctx = self._ctx(
            _FakeSandbox(
                stdout=cut,
                post_files={".mantis_reached_sentinel": f"{MANTIS_SENTINEL_TOKEN}\n".encode("utf-8")},
            )
        )
        res = await sandbox_tools.run_sandbox_with_evidence("python3 poc.py", sink_symbol="sink")
        self.assertTrue(res["evidence_present"], res["evidence_reason"])
        self.assertTrue(ctx.sandbox_executed)

    async def test_whole_trace_without_sentinel_is_absent_as_before(self):
        ctx = self._ctx(_FakeSandbox(stdout="poc running\n"))
        res = await sandbox_tools.run_sandbox_with_evidence("python3 poc.py", sink_symbol="sink")
        self.assertFalse(res["evidence_present"])
        self.assertTrue(res["evidence_reason"].startswith("EVIDENCE_ABSENT:"), res["evidence_reason"])
        self.assertFalse(getattr(ctx, "sandbox_executed", False))


# ---------------------------------------------------------------------------
# The verdict stages are told
# ---------------------------------------------------------------------------


class VerdictStagePromptRuleTest(unittest.TestCase):
    def test_each_verdict_stage_prompt_names_the_marker_and_the_rule(self):
        from core.prompts import STAGE_PROMPTS, TRUNCATION_RULE
        self.assertIn(TRUNCATION_MARKER_PREFIX.rstrip(":"), TRUNCATION_RULE)
        for stage in ("reviewer", "critic", "reproducer", "patcher"):
            with self.subTest(stage=stage):
                prompt = STAGE_PROMPTS[stage]
                self.assertIn("[MANTIS TRUNCATION: ...]", prompt)
                self.assertIn("harness cutting the observation", prompt)
                self.assertIn("never treat the cut boundary as evidence", prompt)
                self.assertIn("start_line/end_line or get_function_boundary", prompt)
                self.assertEqual(prompt.count("[MANTIS TRUNCATION: ...]"), 1, "one sentence, stated once")

    def test_rule_is_one_sentence_with_no_fences_or_shell(self):
        from core.prompts import TRUNCATION_RULE
        self.assertNotIn("```", TRUNCATION_RULE)
        self.assertNotIn("$ ", TRUNCATION_RULE)
        self.assertEqual(TRUNCATION_RULE.strip().count("\n"), 0)


if __name__ == "__main__":
    unittest.main()

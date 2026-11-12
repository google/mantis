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

"""A PoC is re-runnable from what its run stored.

Live, the wrapper `workspace/repro_<id>.py` was persisted and its harness
was not: a Go program under `workspace/repro_<id>/` (persisted, never
restored) or a `_test.go` written into the package inside the guest (never
persisted). A later run re-ran a wrapper with nothing to build. Now the
files a PoC leaves in the target tree are kept when its evidence lands, and
every companion is restored before the wrapper is re-run.
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
from core.database import init_db, read_artifact, read_artifacts_like, record_artifact, write_findings  # noqa: E402
from core.poc_scaffold import (  # noqa: E402
    MAX_SCAFFOLD_FILES, STAGING_MARKER, capture_poc_scaffold, find_new_files_command,
    prior_poc_companions, restore_poc_companions, safe_target_relpath, scaffold_artifact_path,
)
from tools.sandbox_tools import run_sandbox_with_evidence  # noqa: E402

TOKEN = "MANTIS_REACHED_ENTRYPOINT"
OLD, NEW = "run-old", "run-new"


class _Guest:
    """A guest with a file table. `find` lists the files the test marks as
    created after staging; every other command prints what the test says."""

    is_initialized = True

    def __init__(self, files: dict | None = None, created: list | None = None,
                 stdout: str = "", exit_code: int = 0, target_path: str = "",
                 post_files: dict | None = None):
        self.files = dict(files or {})
        self.post_files = dict(post_files or {})
        self.created = list(created or [])
        self.stdout, self.exit_code = stdout, exit_code
        self.commands: list = []
        self.target_path = target_path

    async def execute(self, command: str, *, timeout: typing.Optional[int] = None) -> ExecutionResult:
        self.commands.append(command)
        if command.startswith(f"test -e {STAGING_MARKER} && find"):
            if STAGING_MARKER not in self.files:
                return ExecutionResult(stdout="", stderr="", exit_code=1, timed_out=False)
            return ExecutionResult(stdout="".join(f"./{p}\n" for p in self.created), stderr="",
                                   exit_code=0, timed_out=False)
        self.files.update(self.post_files)
        return ExecutionResult(stdout=self.stdout, stderr="", exit_code=self.exit_code, timed_out=False)

    async def read_file(self, p):
        key = str(p)
        if key in self.files:
            v = self.files[key]
            return v if isinstance(v, bytes) else v.encode()
        raise FileNotFoundError(key)

    async def write_file(self, p, content):
        self.files[str(p)] = content if isinstance(content, (str, bytes)) else str(content)


class PathSafetyTest(unittest.TestCase):
    def test_only_paths_inside_the_tree_pass(self):
        self.assertEqual(safe_target_relpath("./cmd/x/repro_test.go"), "cmd/x/repro_test.go")
        self.assertEqual(safe_target_relpath("a//b/../c.go"), "a/c.go")
        for bad in ("", "/etc/passwd", "../x", "a/../../x", "..", "workspace/r.py", "workspace",
                    STAGING_MARKER, "a\nb", "a\x00b"):
            self.assertIsNone(safe_target_relpath(bad), bad)

    def test_the_guest_listing_is_posix_find_behind_the_marker(self):
        cmd = find_new_files_command()
        self.assertTrue(cmd.startswith(f"test -e {STAGING_MARKER} && find . "))
        for frag in ("-prune", f"-newer {STAGING_MARKER}", "-type f", "-size -", "-path ./workspace",
                     "-name .git", "-name node_modules", "| head -n"):
            self.assertIn(frag, cmd)
        self.assertNotIn("-printf", cmd, "busybox find has no -printf")


class CaptureTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_scaf_")
        self.host = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(self.host, "cmd", "x"))
        Path(self.host, "cmd", "x", "main.go").write_text("package main\n")
        self.kept: list = []

    async def asyncTearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _persist(self, artifact_path, content, rel):
        self.kept.append((artifact_path, content, rel))

    async def test_new_text_files_are_kept_under_the_finding(self):
        guest = _Guest(
            files={STAGING_MARKER: "", "cmd/x/repro16_test.go": "package main\n// harness\n",
                   "cmd/x/main.go": "package main\n// edited by the poc\n",
                   "cmd/x/repro16.test": b"\x7fELF\x02\x01\x01\x00binary", "big.txt": "x" * (300 * 1024)},
            created=["cmd/x/repro16_test.go", "cmd/x/main.go", "cmd/x/repro16.test", "big.txt",
                     "../escape.go", "workspace/already.py"],
        )
        kept = await capture_poc_scaffold(guest, 16, self._persist, host_root=self.host)
        self.assertEqual(kept, ["cmd/x/repro16_test.go"])
        self.assertEqual([k[0] for k in self.kept], [scaffold_artifact_path(16, "cmd/x/repro16_test.go")])
        self.assertEqual(self.kept[0][1], "package main\n// harness\n")
        self.assertEqual(self.kept[0][2], "cmd/x/repro16_test.go")

    async def test_nothing_is_kept_without_the_marker(self):
        guest = _Guest(files={"cmd/x/new.go": "x"}, created=["cmd/x/new.go"])
        self.assertEqual(await capture_poc_scaffold(guest, 1, self._persist), [])
        self.assertEqual(self.kept, [])

    async def test_the_count_is_capped(self):
        names = [f"gen/f{i}.go" for i in range(MAX_SCAFFOLD_FILES + 20)]
        guest = _Guest(files={STAGING_MARKER: "", **{n: "package gen\n" for n in names}}, created=names)
        kept = await capture_poc_scaffold(guest, 2, self._persist)
        self.assertEqual(len(kept), MAX_SCAFFOLD_FILES)

    async def test_a_persist_failure_costs_that_file_only(self):
        def flaky(artifact_path, content, rel):
            if rel.endswith("b.go"):
                raise RuntimeError("disk")
            self.kept.append((artifact_path, content, rel))
        guest = _Guest(files={STAGING_MARKER: "", "a.go": "a", "b.go": "b", "c.go": "c"},
                       created=["a.go", "b.go", "c.go"])
        self.assertEqual(await capture_poc_scaffold(guest, 3, flaky), ["a.go", "c.go"])


class _DbBase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_scaf_db_")
        self.db = os.path.join(self.tmp, "k.db")
        init_db(self.db)
        self.target = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(self.target, "pkg"))
        self.token = None

    async def asyncTearDown(self):
        if self.token is not None:
            current_run_context.reset(self.token)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _ctx(self, sandbox=None, node="reproducer", run_id=NEW) -> RunContext:
        ctx = RunContext(jail_dir=self.target, db_path=self.db, target_file=self.target, sandbox=sandbox,
                         run_id=run_id, active_node=node, finding_evidence={})
        self.token = current_run_context.set(ctx)
        return ctx

    def _seed_prior(self, fid: int = 7):
        """An earlier run's wrapper and companions for finding `fid`, plus
        rows that must NOT travel with it."""
        record_artifact(self.db, OLD, "workspace_file", f"workspace/repro_{fid}.py", "# wrapper\n")
        record_artifact(self.db, OLD, "workspace_file", f"workspace/repro_{fid}/main.go", "package main\n")
        record_artifact(self.db, OLD, "workspace_file", f"workspace/zz_repro_{fid}_test.go", "package pkg\n")
        record_artifact(self.db, OLD, "workspace_file", scaffold_artifact_path(fid, "pkg/repro_test.go"),
                        "package pkg // in-tree harness\n")
        record_artifact(self.db, OLD, "workspace_file", scaffold_artifact_path(fid, "pkg/exists.go"),
                        "package pkg // the tree has grown one here\n")
        record_artifact(self.db, OLD, "workspace_file", f"workspace/repro_{fid}/_target/../../../etc/cron.d/x",
                        "evil\n")
        record_artifact(self.db, OLD, "workspace_file", f"workspace/repro_{fid}0.py", "# finding 70's wrapper\n")
        record_artifact(self.db, OLD, "workspace_file", f"workspace/findings/{fid}.json", "{}")
        record_artifact(self.db, OLD, "workspace_file", f"workspace/exploit_chain_{fid}.md", "chain")
        record_artifact(self.db, "run-other", "workspace_file", f"workspace/repro_{fid}/other.go", "not this run\n")


class CompanionLookupTest(_DbBase):
    async def test_read_artifacts_like_returns_the_newest_row_per_path(self):
        record_artifact(self.db, OLD, "workspace_file", "workspace/repro_1/a.go", "v1")
        record_artifact(self.db, OLD, "workspace_file", "workspace/repro_1/a.go", "v2")
        record_artifact(self.db, OLD, "plan", "workspace/repro_1/plan", "p")
        rows = read_artifacts_like(self.db, OLD, "%repro\\_1%", artifact_type="workspace_file")
        self.assertEqual([(r["filepath"], r["content"]) for r in rows], [("workspace/repro_1/a.go", "v2")])

    async def test_companions_are_the_findings_own_files_minus_the_wrapper(self):
        self._seed_prior(7)
        got = dict(prior_poc_companions(self.db, OLD, 7))
        self.assertEqual(set(got), {
            "workspace/repro_7/main.go", "workspace/zz_repro_7_test.go",
            "pkg/repro_test.go", "pkg/exists.go",
        })
        self.assertEqual(got["pkg/repro_test.go"], "package pkg // in-tree harness\n")
        self.assertNotIn("workspace/repro_7.py", got, "the wrapper is placed by the caller, renamed")
        self.assertNotIn("workspace/repro_70.py", got, "repro_70 is another finding")
        self.assertFalse(any("etc/cron.d" in k or ".." in k for k in got), "nothing may leave the tree")

    async def test_restore_writes_companions_and_leaves_grown_files_alone(self):
        self._seed_prior(7)
        guest = _Guest(files={STAGING_MARKER: "", "pkg/exists.go": "package pkg // current code\n"})
        restored, skipped = await restore_poc_companions(guest, self.db, OLD, 7)
        self.assertEqual(sorted(restored), ["pkg/repro_test.go", "workspace/repro_7/main.go",
                                            "workspace/zz_repro_7_test.go"])
        self.assertEqual(skipped, ["pkg/exists.go"])
        self.assertEqual(guest.files["pkg/exists.go"], "package pkg // current code\n",
                         "a scaffold never stands in for a file the code now has")
        self.assertEqual(guest.files["pkg/repro_test.go"], "package pkg // in-tree harness\n")
        self.assertEqual(guest.files["workspace/repro_7/main.go"], "package main\n")

    async def test_a_prior_run_with_only_a_wrapper_restores_nothing(self):
        record_artifact(self.db, OLD, "workspace_file", "workspace/repro_9.py", "# wrapper\n")
        guest = _Guest(files={STAGING_MARKER: ""})
        self.assertEqual(await restore_poc_companions(guest, self.db, OLD, 9), ([], []))


class EvidenceKeepsTheScaffoldTest(_DbBase):
    """run_sandbox_with_evidence stores the PoC's in-tree files when the
    evidence lands -- and only then, and not in the patcher."""

    def _guest(self, stdout="ok\n", sentinel: str = TOKEN + "\n"):
        post = {"sentinel_12": sentinel} if sentinel else {}
        return _Guest(files={STAGING_MARKER: "", "pkg/repro12_test.go": "package pkg\n",
                             "pkg/mod1.py": "edited\n"},
                      created=["pkg/repro12_test.go", "pkg/mod1.py", "sentinel_12"],
                      stdout=stdout, target_path=self.target, post_files=post)

    async def test_evidence_present_persists_new_tree_files_under_the_finding(self):
        Path(self.target, "pkg", "mod1.py").write_text("original\n")
        ctx = self._ctx(self._guest())
        res = await run_sandbox_with_evidence("python3 workspace/repro_12.py", finding_id=12)
        self.assertTrue(res["evidence_present"])
        self.assertEqual(res["scaffold_files_kept"], ["pkg/repro12_test.go"])
        art = read_artifact(self.db, filepath=scaffold_artifact_path(12, "pkg/repro12_test.go"), run_id=NEW)
        self.assertEqual(art, "package pkg\n")
        self.assertIsNone(read_artifact(self.db, filepath=scaffold_artifact_path(12, "pkg/mod1.py"), run_id=NEW),
                          "a host file the PoC edited is a patch, not a scaffold")
        self.assertIsNone(read_artifact(self.db, filepath=scaffold_artifact_path(12, "sentinel_12"), run_id=NEW),
                          "sidecar sentinel must never be captured as a reusable PoC scaffold")
        self.assertTrue(ctx.finding_evidence["12"]["reproduced"])

    async def test_evidence_absent_keeps_nothing(self):
        self._ctx(self._guest(stdout=TOKEN + "\n", sentinel=""))
        res = await run_sandbox_with_evidence("python3 workspace/repro_12.py", finding_id=12)
        self.assertFalse(res["evidence_present"])
        self.assertEqual(res["scaffold_files_kept"], [])
        self.assertEqual(read_artifacts_like(self.db, NEW, "%repro\\_12%"), [])

    async def test_the_patcher_keeps_nothing(self):
        self._ctx(self._guest(), node="patcher")
        res = await run_sandbox_with_evidence("python3 workspace/repro_12.py", finding_id=12)
        self.assertTrue(res["evidence_present"])
        self.assertEqual(res["scaffold_files_kept"], [])
        self.assertEqual(read_artifacts_like(self.db, NEW, "%repro\\_12%"), [])

    async def test_the_whole_loop_restores_what_capture_kept(self):
        """Capture in run A, restore in run B: the in-tree harness comes
        back at its path, the wrapper at repro_prior_<id>."""
        import main

        write_findings(self.db, self.target, [{"title": "bug", "severity": "HIGH", "status": "dynamic_confirmed",
                                               "description": "d", "line_numbers": [1], "filepath": "pkg/mod1.py",
                                               "cwe": "CWE-89"}], run_id=OLD)
        from core.database import read_findings
        fid = read_findings(self.db, run_id=OLD)[0]["id"]
        # Run A: the reproducer wrote the wrapper (workspace, persisted) and
        # a harness into the package (guest only), then the evidence landed.
        record_artifact(self.db, OLD, "workspace_file", f"workspace/repro_{fid}.py", "# wrapper\n")
        self._ctx(_Guest(files={STAGING_MARKER: "", f"pkg/repro{fid}_test.go": "package pkg // harness\n"},
                         created=[f"pkg/repro{fid}_test.go"], stdout="ok\n", target_path=self.target,
                         post_files={f"sentinel_{fid}": TOKEN + "\n"}),
                  run_id=OLD)
        await run_sandbox_with_evidence("go test ./pkg/", finding_id=fid)
        current_run_context.reset(self.token)
        self.token = None
        # Run B: a fresh guest. The harness re-runs the PoC before the graph.
        guest = _Guest(files={STAGING_MARKER: ""}, stdout="ok\n")
        ctx = self._ctx(guest, node="harness")
        prior = [{"id": fid, "run_id": OLD, "status": "dynamic_confirmed", "filepath": "pkg/mod1.py"}]
        await main._rerun_prior_pocs(ctx, self.db, NEW, prior, changed_paths=set())
        self.assertEqual(guest.files[f"pkg/repro{fid}_test.go"], "package pkg // harness\n",
                         "the harness is back where the wrapper expects it")
        self.assertIn(f"workspace/repro_prior_{fid}.py", guest.files)
        order = [c for c in guest.commands if "repro_prior_" in c]
        self.assertEqual(len(order), 1)


class StagingMarkerTest(unittest.TestCase):
    """The marker is what makes "newer than staging" answerable. The
    microVM environment drops it once the target is copied in."""

    def test_microsandbox_drops_the_marker_after_staging(self):
        import asyncio
        from unittest import mock

        from core.environments import microsandbox_env as M

        tmp = tempfile.mkdtemp(prefix="mantis_scaf_env_")
        try:
            Path(tmp, "a.go").write_text("package a\n")
            env = M.MicrosandboxEnvironment.__new__(M.MicrosandboxEnvironment)
            env.target_path = tmp
            env.image = "mantis-sandbox:latest"
            env.timeout = 30.0
            env.memory = None
            env.cpus = None
            env._workdir = Path("/workspace")
            env._sb = None
            env._name = None
            env._stage_error = None
            env.is_initialized = False
            events: list = []

            class _Fs:
                async def mkdir(self, path):
                    events.append(("mkdir", str(path)))

                async def copy_from_host(self, src, dest):
                    events.append(("copy", str(dest)))

                async def write(self, path, data):
                    events.append(("write", str(path)))

            class _Sb:
                fs = _Fs()

            async def fake_create(name, **kwargs):
                return _Sb()

            with mock.patch.object(M.MsbSandbox, "create", side_effect=fake_create):
                asyncio.run(env.initialize())
            self.assertIn(("copy", "/workspace/a.go"), events)
            self.assertEqual(events[-1], ("write", f"/workspace/{STAGING_MARKER}"),
                             "the marker is the last thing written: everything staged is older")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

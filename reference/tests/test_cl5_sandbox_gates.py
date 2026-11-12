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

"""Regression tests for dynamic sandbox evidence gates, split-plane isolation,
remote transport/telemetry safety, and guest boot failure handling."""

from __future__ import annotations

import asyncio
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest import IsolatedAsyncioTestCase, mock
import unittest

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from google.adk.environment import ExecutionResult

from core.budget import BudgetConfig, BudgetController
from core.context import RunContext, current_run_context
from core.database import init_db, read_findings
from core.environments.base import BaseEnvironment
from core.environments.gce_env import GceEnvironment
from core.environments.gvisor_env import GvisorEnvironment
from core.environments.microsandbox_env import MicrosandboxEnvironment
import core.environments.microsandbox_env as msb_mod
from core.environments.remote_env import RemoteTargetEnvironment
from tools.research_tools import list_files as tool_list_files
from tools.research_tools import read_file as tool_read_file
from tools.research_tools import record_patch
from tools.sandbox_tools import (
    MANTIS_SENTINEL_TOKEN,
    _guest_file_reader,
    apply_patch,
    check_reached_sink_evidence,
    poc_ran,
    run_sandbox,
    run_sandbox_with_evidence,
)


def _insert_confirmed_finding(db_path: str, run_id: str, title: str, filepath: str = "app.py") -> int:
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)").fetchall()}
        row_data = {
            "run_id": run_id,
            "filepath": filepath,
            "title": title,
            "description": "eval(x)",
            "vulnerability_class": "Code Injection",
            "severity": "HIGH",
            "confidence": "HIGH",
            "status": "dynamic_confirmed",
            "evidence_tier": "dynamic_confirmed",
            "campaign": filepath,
            "scope_path": filepath,
        }
        row_data = {k: v for k, v in row_data.items() if k in cols}
        keys = list(row_data.keys())
        cur = conn.execute(
            f"INSERT INTO findings ({', '.join(keys)}) VALUES ({', '.join('?' for _ in keys)})",
            [row_data[k] for k in keys],
        )
        conn.commit()
        return int(cur.lastrowid)


class _StubDynamicEnv(BaseEnvironment):
    """Minimal in-memory BaseEnvironment double for deterministic gate testing."""

    def __init__(self, exec_fn, files=None, read_err=None):
        super().__init__()
        self._exec_fn = exec_fn
        self._files = dict(files or {})
        self._read_err = read_err
        self.is_initialized = True
        self.last_env = None

    @property
    def working_dir(self) -> Path:
        return Path("/workspace")

    async def initialize(self) -> None:
        self.is_initialized = True

    async def close(self) -> None:
        pass

    async def execute(self, command: str, *, timeout=None) -> ExecutionResult:
        self.last_env = self._consume_exec_env() if hasattr(self, "_consume_exec_env") else None
        return await self._exec_fn(command, timeout, self.last_env, self._files)

    async def read_file(self, path: Path) -> bytes:
        if self._read_err is not None:
            raise self._read_err
        key = str(path)
        if key not in self._files:
            raise FileNotFoundError(key)
        val = self._files[key]
        return val.encode("utf-8") if isinstance(val, str) else bytes(val)

    async def write_file(self, path: Path, content) -> None:
        self._files[str(path)] = content.encode("utf-8") if isinstance(content, str) else bytes(content)

    async def list_files(self, directory: str = ""):
        if self._read_err is not None:
            raise self._read_err
        return sorted(self._files.keys())

    async def apply_patch(self, diff: str) -> str:
        return "exit=0\npatched"

    async def preflight(self) -> None:
        pass


class SandboxGateInvariantsTest(IsolatedAsyncioTestCase):
    """Tests for sandbox-local-2, sandbox-local-10, sandbox-remote-1, sandbox-remote-4,
    sandbox-local-4, and sandbox-local-9."""

    async def test_echoed_sentinel_in_stdout_rejected_while_guest_sidecar_confirms(self):
        async def exec_echo_400(cmd, timeout, env_vars, files):
            return ExecutionResult(
                stdout='HTTP/1.1 400 Bad Request\n{"error":"invalid path /api/MANTIS_REACHED_ENTRYPOINT"}',
                stderr="",
                exit_code=0,
                timed_out=False,
            )

        sb = _StubDynamicEnv(exec_echo_400)
        ctx = RunContext(jail_dir="/tmp", db_path="", active_node="reproducer", sandbox=sb)
        tok = current_run_context.set(ctx)
        try:
            res = await run_sandbox_with_evidence("python3 poc.py", sentinel_path="sentinel_1", finding_id=1)
            self.assertFalse(res["evidence_present"])
            self.assertFalse(ctx.sandbox_executed)
            self.assertFalse(ctx.finding_evidence["1"]["reproduced"])

            # Now write the nonce-bound sentinel to the defaulted sentinel_1 file inside guest
            async def exec_real_hit(cmd, timeout, env_vars, files):
                s_file = (env_vars or {}).get("MANTIS_SENTINEL_FILE", "sentinel_1")
                nonce = (env_vars or {}).get("MANTIS_SENTINEL_NONCE", "")
                token_line = f"{MANTIS_SENTINEL_TOKEN}:{nonce}\n" if nonce else f"{MANTIS_SENTINEL_TOKEN}\n"
                files[s_file] = token_line.encode("utf-8")
                return ExecutionResult(stdout="200 OK\n", stderr="", exit_code=0, timed_out=False)

            sb._exec_fn = exec_real_hit
            res_hit = await run_sandbox_with_evidence("python3 poc.py", finding_id=1)
            self.assertTrue(res_hit["evidence_present"], res_hit)
            self.assertTrue(ctx.sandbox_executed)
            self.assertTrue(ctx.finding_evidence["1"]["reproduced"])
        finally:
            current_run_context.reset(tok)

    async def test_echoed_sentinel_in_patcher_stderr_does_not_fail_valid_patch(self):
        with tempfile.TemporaryDirectory() as td:
            db_p = str(Path(td) / "k.db")
            fid = _insert_confirmed_finding(db_p, "r1", "Code Injection")

            async def exec_patched_reject(cmd, timeout, env_vars, files):
                return ExecutionResult(
                    stdout="",
                    stderr="ValueError: invalid identifier 'MANTIS_REACHED_ENTRYPOINT'",
                    exit_code=1,
                    timed_out=False,
                )

            sb = _StubDynamicEnv(exec_patched_reject)
            ctx = RunContext(
                jail_dir=td,
                db_path=db_p,
                run_id="r1",
                target_file="app.py",
                active_node="patcher",
                sandbox=sb,
                sandbox_executed=True,
            )
            ctx.finding_evidence[str(fid)] = {
                "reproduced": True,
                "reattacked": False,
                "reattack_present": False,
                "sink_symbol": "",
                "reason": "",
            }
            tok = current_run_context.set(ctx)
            try:
                res = await run_sandbox_with_evidence(
                    "python3 poc.py", sentinel_path=f"sentinel_{fid}", finding_id=fid
                )
                self.assertFalse(res["evidence_present"])
                patch_out = record_patch(
                    finding_id=fid,
                    patch_diff="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-eval(x)\n+int(x)\n",
                    reattack_status="failed_to_bypass",
                    remediation="replaced eval with int",
                )
                self.assertIn("VERIFIED_SECURE", patch_out)
                saved = [f for f in read_findings(db_p, run_id="r1") if f["id"] == fid][0]
                self.assertEqual(saved["patch_status"], "VERIFIED_SECURE")
                self.assertEqual(saved["status"], "patch_verified")
            finally:
                current_run_context.reset(tok)

    async def test_non_repro_node_bare_run_sandbox_does_not_set_sandbox_executed(self):
        async def exec_cat_crash(cmd, timeout, env_vars, files):
            return ExecutionResult(
                stdout="==1==ERROR: AddressSanitizer: heap-buffer-overflow\n",
                stderr="",
                exit_code=1,
                timed_out=False,
            )

        ctx = RunContext(
            jail_dir="/tmp",
            db_path="",
            active_node="researcher",
            sandbox=_StubDynamicEnv(exec_cat_crash),
        )
        tok = current_run_context.set(ctx)
        try:
            await run_sandbox("cat crash.log")
            self.assertFalse(ctx.sandbox_executed)
        finally:
            current_run_context.reset(tok)

    async def test_unstarted_gce_and_gvisor_read_guest_file_never_reads_host_checkout(self):
        with tempfile.TemporaryDirectory() as td:
            planted = Path(td) / "sentinel_77"
            planted.write_text(f"{MANTIS_SENTINEL_TOKEN}\n", encoding="utf-8")

            gce = GceEnvironment.__new__(GceEnvironment)
            gce.target_path = td
            gce._workdir = Path("/workspace")
            gce._started = False
            gce.is_initialized = False

            gv = GvisorEnvironment.__new__(GvisorEnvironment)
            gv.target_path = td
            gv._workdir = Path("/workspace")
            gv._started = False
            gv.is_initialized = False

            for env in (gce, gv):
                reader = _guest_file_reader(env)
                with self.assertRaises(FileNotFoundError):
                    await reader(Path("sentinel_77"))

    def test_sidecar_precedes_enoent_and_launcher_anchored_poc_ran_and_go_rust_panics(self):
        # Sidecar sentinel written before post-sink ENOENT still counts as reached-sink proof
        ok1, _ = check_reached_sink_evidence(
            "FileNotFoundError: [Errno 2] No such file or directory",
            1,
            sentinel_content=MANTIS_SENTINEL_TOKEN,
        )
        ok127, _ = check_reached_sink_evidence(
            "sh: 1: post_hook: No such file or directory",
            127,
            sentinel_content=MANTIS_SENTINEL_TOKEN,
        )
        self.assertTrue(ok1)
        self.assertTrue(ok127)

        # Patched target raising FileNotFoundError or ast.literal_eval SyntaxError inside a real
        # staged target file (verified via _host_has) counts as poc_ran=True, whereas frames in
        # PoC scripts themselves (outside staged tree or invoked by command) remain False.
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "app.py").write_text("def run_cmd(x):\n    pass\n", encoding="utf-8")
            (Path(td) / "exploit.py").write_text("import missing_dep\n", encoding="utf-8")
            self.assertTrue(
                poc_ran(
                    'Traceback (most recent call last):\n'
                    '  File "workspace/repro_1.py", line 4, in <module>\n'
                    '  File "/workspace/app.py", line 14, in run_cmd\n'
                    "FileNotFoundError: [Errno 2] No such file or directory: 'id; touch /tmp/x'",
                    1,
                    command="python3 workspace/repro_1.py",
                    jail_dir=td,
                    workdir="/workspace",
                )
            )
            self.assertTrue(
                poc_ran(
                    'Traceback (most recent call last):\n'
                    '  File "workspace/repro_1.py", line 4, in <module>\n'
                    '  File "/workspace/app.py", line 9, in parse_expr\n'
                    '  File "<unknown>", line 1\n'
                    "SyntaxError: invalid syntax",
                    1,
                    command="python3 workspace/repro_1.py",
                    jail_dir=td,
                    workdir="/workspace",
                )
            )
            # Negative cases: PoC script frames, cd failures, Go stat/open missing files
            self.assertFalse(
                poc_ran(
                    'Traceback (most recent call last):\n'
                    '  File "/app/poc_3.py", line 1, in <module>\n'
                    "ModuleNotFoundError: No module named 'requests'",
                    1,
                    command="python3 /app/poc_3.py",
                    jail_dir=td,
                    workdir="/workspace",
                )
            )
            self.assertFalse(
                poc_ran(
                    'Traceback (most recent call last):\n'
                    '  File "/workspace/target/poc.py", line 2\n'
                    "SyntaxError: invalid syntax",
                    1,
                    command="python3 /workspace/target/poc.py",
                    jail_dir=td,
                    workdir="/workspace",
                )
            )
            self.assertFalse(
                poc_ran(
                    'Traceback (most recent call last):\n'
                    '  File "exploit.py", line 1, in <module>\n'
                    "ImportError: cannot import name 'foo'",
                    1,
                    command="python3 exploit.py",
                    jail_dir=td,
                    workdir="/workspace",
                )
            )
            self.assertFalse(
                poc_ran(
                    "bash: line 1: cd: workspace/repro_3: No such file or directory",
                    1,
                    command="cd workspace/repro_3 && python3 poc.py",
                    jail_dir=td,
                    workdir="/workspace",
                )
            )
            self.assertFalse(
                poc_ran(
                    "sh: 1: cd: can't cd to workspace/repro_3",
                    2,
                    command="cd workspace/repro_3 && python3 poc.py",
                    jail_dir=td,
                    workdir="/workspace",
                )
            )
            self.assertFalse(
                poc_ran(
                    "stat poc.go: no such file or directory",
                    1,
                    command="go run poc.go",
                    jail_dir=td,
                    workdir="/workspace",
                )
            )
            self.assertFalse(
                poc_ran(
                    "open cmd/poc.go: no such file or directory",
                    1,
                    command="go run cmd/poc.go",
                    jail_dir=td,
                    workdir="/workspace",
                )
            )

        # Frameless or launcher/harness setup failures remain False
        self.assertFalse(poc_ran("ModuleNotFoundError: No module named 'requests'", 1))
        self.assertFalse(poc_ran("sh: 1: pytest: command not found", 127))
        self.assertFalse(
            poc_ran(
                "python3: can't open file '/workspace/workspace/repro_1.py': [Errno 2] No such file or directory",
                2,
            )
        )
        # Guest target exiting 255 via sys.exit(-1) without SANDBOX-ERROR is a real run
        self.assertTrue(poc_ran("input rejected\n", 255))

        # Go panic backtrace corroboration (exit 2) — requires goroutine header + .go:line frame
        go_trace = (
            "panic: runtime error: index out of range [3] with length 0\n\n"
            "goroutine 1 [running]:\n"
            "example.com/pkg/parser.ParseHeader({0xc0000140c0, 0x0, 0x0})\n"
            "\t/workspace/pkg/parser/header.go:42 +0x45\n"
            "main.main()\n"
            "\t/workspace/cmd/server/main.go:12 +0x25\n"
        )
        self.assertTrue(check_reached_sink_evidence(go_trace, 2, sink_symbol="ParseHeader")[0])
        self.assertFalse(check_reached_sink_evidence(go_trace, 2, sink_symbol="UnrelatedSink")[0])
        self.assertFalse(
            check_reached_sink_evidence("panic: boom\n\n1: run_query\n", 2, sink_symbol="run_query")[0]
        )
        self.assertFalse(
            check_reached_sink_evidence(
                "panic: boom\nmain.run_query()\n\t/workspace/main.go:10\n",
                2,
                sink_symbol="run_query",
            )[0]
        )

        # Rust panic backtrace corroboration — requires exit 101 + panic header + stack backtrace:
        rust_trace = (
            "thread 'main' panicked at src/parser.rs:10:5:\n"
            "index out of bounds: the len is 0 but the index is 3\n"
            "stack backtrace:\n"
            "   0: rust_begin_unwind\n"
            "   1: core::panicking::panic_bounds_check\n"
            "   2: target_crate::parser::parse_frame\n"
            "             at ./src/parser.rs:10:5\n"
        )
        self.assertTrue(check_reached_sink_evidence(rust_trace, 101, sink_symbol="parse_frame")[0])
        self.assertFalse(check_reached_sink_evidence(rust_trace, 101, sink_symbol="other_fn")[0])
        self.assertFalse(
            check_reached_sink_evidence(
                "thread 'main' panicked at src/x.rs:1:1:\nboom\n   3: run_query\n",
                1,
                sink_symbol="run_query",
            )[0]
        )
        self.assertFalse(
            check_reached_sink_evidence(
                "thread 'main' panicked at src/x.rs:1:1:\nboom\n   3: run_query\n",
                101,
                sink_symbol="run_query",
            )[0]
        )
        self.assertFalse(
            check_reached_sink_evidence(
                "thread 'main' panicked at src/x.rs:1:1:\nboom\nstack backtrace:\n   3: run_query\n",
                1,
                sink_symbol="run_query",
            )[0]
        )

    async def test_reattack_timeout_and_ssh_error_fail_closed_and_apply_patch_invalidates(self):
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            local_src, remote_wd = td_p / "src", td_p / "remote"
            local_src.mkdir()
            remote_wd.mkdir()
            (local_src / "app.py").write_text("def handle(x):\n    return eval(x)\n", encoding="utf-8")
            (remote_wd / "app.py").write_text("def handle(x):\n    return eval(x)\n", encoding="utf-8")

            db_p = str(td_p / "remote.db")
            fid_timeout = _insert_confirmed_finding(db_p, "r1", "Timeout Reattack")
            fid_ssh = _insert_confirmed_finding(db_p, "r1", "SSH 255 Reattack")
            fid_stale = _insert_confirmed_finding(db_p, "r1", "Stale Patch Reattack")

            rem_env = RemoteTargetEnvironment(
                str(local_src),
                transport="exec",
                workdir=str(remote_wd),
                exec_argv=["/bin/sh", "-c"],
                timeout_seconds=1,
            )
            ctx = RunContext(
                jail_dir=str(local_src),
                db_path=db_p,
                run_id="r1",
                target_file="app.py",
                active_node="patcher",
                sandbox=rem_env,
                sandbox_executed=True,
            )
            for fid in (fid_timeout, fid_ssh, fid_stale):
                ctx.finding_evidence[str(fid)] = {
                    "reproduced": True,
                    "reattacked": False,
                    "reattack_present": False,
                    "sink_symbol": "",
                    "reason": "",
                }
            tok = current_run_context.set(ctx)
            try:
                # 1. Re-attack #1 bypasses patch (writes sidecar sentinel); Re-attack #2 times out -> stays VERIFICATION_FAILED!
                await run_sandbox_with_evidence(
                    f"printf '%s\\n' '{MANTIS_SENTINEL_TOKEN}' > sentinel_{fid_timeout}",
                    sentinel_path=f"sentinel_{fid_timeout}",
                    finding_id=fid_timeout,
                )
                self.assertTrue(ctx.finding_evidence[str(fid_timeout)]["reattack_present"])
                await run_sandbox_with_evidence("sleep 3", finding_id=fid_timeout)
                self.assertTrue(ctx.finding_evidence[str(fid_timeout)]["reattack_present"])
                out_t = record_patch(
                    finding_id=fid_timeout,
                    patch_diff="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-a\n+b\n",
                    reattack_status="failed_to_bypass",
                )
                self.assertIn("VERIFICATION_FAILED", out_t)

                # 2. Clean re-attack followed by apply_patch invalidates prior reattacked state until re-run!
                await run_sandbox_with_evidence("true", finding_id=fid_stale)
                self.assertTrue(ctx.finding_evidence[str(fid_stale)]["reattacked"])
                await apply_patch(
                    "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n def handle(x):\n-    return eval(x)\n+    return int(x)\n"
                )
                self.assertFalse(ctx.finding_evidence[str(fid_stale)]["reattacked"])
                out_stale = record_patch(
                    finding_id=fid_stale,
                    patch_diff="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-a\n+b\n",
                    reattack_status="failed_to_bypass",
                )
                self.assertIn("VERIFICATION_INCOMPLETE", out_stale)
            finally:
                current_run_context.reset(tok)
                await rem_env.close()

            # 3. SSH exit 255 transport failure emits SANDBOX-ERROR and never certifies VERIFIED_SECURE
            async def fake_ssh_255(cmd, timeout, env_vars, files):
                return ExecutionResult(
                    stdout="",
                    stderr="SANDBOX-ERROR: SSH transport failed (exit=255): ssh: connect to host 10.0.0.5 port 22: Connection timed out",
                    exit_code=255,
                    timed_out=False,
                )

            ctx_ssh = RunContext(
                jail_dir=str(local_src),
                db_path=db_p,
                run_id="r1",
                target_file="app.py",
                active_node="patcher",
                sandbox=_StubDynamicEnv(fake_ssh_255),
                sandbox_executed=True,
            )
            ctx_ssh.finding_evidence[str(fid_ssh)] = {
                "reproduced": True,
                "reattacked": False,
                "reattack_present": False,
                "sink_symbol": "",
                "reason": "",
            }
            tok2 = current_run_context.set(ctx_ssh)
            try:
                await run_sandbox_with_evidence("python3 poc.py", finding_id=fid_ssh)
                out_ssh = record_patch(
                    finding_id=fid_ssh,
                    patch_diff="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-a\n+b\n",
                    reattack_status="failed_to_bypass",
                )
                self.assertIn("VERIFICATION_INCOMPLETE", out_ssh)
            finally:
                current_run_context.reset(tok2)

            rows = {f["id"]: f for f in read_findings(db_p, run_id="r1")}
            self.assertEqual(rows[fid_timeout]["patch_status"], "VERIFICATION_FAILED")
            self.assertEqual(rows[fid_ssh]["patch_status"], "VERIFICATION_INCOMPLETE")
            self.assertNotEqual(rows[fid_ssh]["status"], "patch_verified")

    async def test_unscoped_log_cmd_stripped_for_gates_and_log_file_delta_captures_new_crash(self):
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            local_src, remote_wd = td_p / "src", td_p / "remote"
            local_src.mkdir()
            remote_wd.mkdir()
            (local_src / "app.py").write_text("x = 1\n", encoding="utf-8")
            (remote_wd / "app.py").write_text("x = 1\n", encoding="utf-8")
            log_file = remote_wd / "service.log"
            log_file.write_text(
                "==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014\n",
                encoding="utf-8",
            )
            db_p = str(td_p / "log.db")
            fid = _insert_confirmed_finding(db_p, "r1", "LogCmd Patch")

            rem_log = RemoteTargetEnvironment(
                str(local_src),
                transport="exec",
                workdir=str(remote_wd),
                exec_argv=["/bin/sh", "-c"],
                log_cmd=f"tail -n 100 {log_file}",
                timeout_seconds=5,
            )
            # Direct execute() preserves [REMOTE TARGET TELEMETRY] for operator/LLM debugging
            direct = await rem_log.execute("echo poc-ran")
            self.assertIn("[REMOTE TARGET TELEMETRY]", direct.stdout)

            # Reproducer no-op is NOT fooled by stale ASan line in unscoped log_cmd
            ctx_r = RunContext(
                jail_dir=str(local_src), db_path=db_p, run_id="r1", target_file="app.py",
                active_node="reproducer", sandbox=rem_log,
            )
            tok = current_run_context.set(ctx_r)
            try:
                v_res = await run_sandbox_with_evidence("true", finding_id=999)
                self.assertFalse(v_res["evidence_present"])
            finally:
                current_run_context.reset(tok)

            # Patcher clean re-attack succeeds as VERIFIED_SECURE despite stale ASan line in log_cmd
            ctx_p = RunContext(
                jail_dir=str(local_src), db_path=db_p, run_id="r1", target_file="app.py",
                active_node="patcher", sandbox=rem_log, sandbox_executed=True,
            )
            ctx_p.finding_evidence[str(fid)] = {
                "reproduced": True, "reattacked": False, "reattack_present": False, "sink_symbol": "", "reason": ""
            }
            tok = current_run_context.set(ctx_p)
            try:
                await run_sandbox_with_evidence("true", finding_id=fid)
                p_out = record_patch(
                    finding_id=fid,
                    patch_diff="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-a\n+b\n",
                    reattack_status="failed_to_bypass",
                )
                self.assertIn("VERIFIED_SECURE", p_out)
            finally:
                current_run_context.reset(tok)
                await rem_log.close()

            # Cursor-scoped log_file delta ignores pre-existing crash and detects fresh crash appended during execute()
            rem_delta = RemoteTargetEnvironment(
                str(local_src),
                transport="exec",
                workdir=str(remote_wd),
                exec_argv=["/bin/sh", "-c"],
                log_file=str(log_file),
                timeout_seconds=5,
            )
            ctx_d = RunContext(
                jail_dir=str(local_src), db_path=db_p, run_id="r1", target_file="app.py",
                active_node="reproducer", sandbox=rem_delta,
            )
            tok = current_run_context.set(ctx_d)
            try:
                noop_delta = await run_sandbox_with_evidence("true", finding_id=888)
                self.assertFalse(noop_delta["evidence_present"])

                fresh_crash = await run_sandbox_with_evidence(
                    f"printf '==99==ERROR: AddressSanitizer: use-after-free\\n' >> {log_file}",
                    finding_id=888,
                )
                self.assertTrue(fresh_crash["evidence_present"], fresh_crash)
            finally:
                current_run_context.reset(tok)
                await rem_delta.close()

    async def test_boot_stage_failures_surface_sandbox_error_clean_container_and_lock_msb(self):
        # 1. Broken dynamic sandbox surfaces SANDBOX-ERROR: on read_file & list_files
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "vuln.py").write_text("x = 1\n", encoding="utf-8")

            async def dummy_exec(cmd, timeout, env_vars, files):
                return ExecutionResult(stdout="", stderr="", exit_code=0, timed_out=False)

            broken = _StubDynamicEnv(dummy_exec, read_err=RuntimeError("docker run failed: runtime runsc not found"))
            ctx = RunContext(jail_dir=td, db_path="", active_node="researcher", sandbox=broken)
            tok = current_run_context.set(ctx)
            try:
                rf = await tool_read_file("vuln.py")
                lf = await tool_list_files("")
                self.assertTrue(rf.startswith("SANDBOX-ERROR:"), rf)
                self.assertTrue(lf.startswith("SANDBOX-ERROR:"), lf)
            finally:
                current_run_context.reset(tok)

        # 2. GvisorEnvironment cleans up created container if staging raises before _started = True
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "vuln.py").write_text("x = 1\n", encoding="utf-8")
            gv = GvisorEnvironment.__new__(GvisorEnvironment)
            gv.target_path = td
            gv.image = "mantis-sandbox:latest"
            gv.runtime = "runsc"
            gv.timeout = 10
            gv._workdir = Path("/workspace")
            gv.tool = "docker"
            gv.container_name = "mantis-gv-stageleaktest"
            gv._started = False
            gv.is_initialized = False
            gv._lock = asyncio.Lock()

            seen_cmds = []

            def fake_run_cmd(argv, stdin=None, timeout=None):
                seen_cmds.append(list(argv))
                return 0, ""

            gv._run_cmd = fake_run_cmd
            with mock.patch("core.environments.staging.stage_to_directory", side_effect=RuntimeError("staging budget exceeded")):
                with self.assertRaises(RuntimeError):
                    await gv._ensure()
            self.assertTrue(
                any(cmd[:3] == ["docker", "rm", "-f"] and "mantis-gv-stageleaktest" in cmd for cmd in seen_cmds),
                f"Expected docker rm -f on staging failure; saw {seen_cmds}",
            )

        # 3. MicrosandboxEnvironment._ensure() serializes concurrent callers with asyncio.Lock (1 VM booted)
        created_vms = []

        class _FakeFs:
            async def mkdir(self, p):
                pass

            async def copy_from_host(self, s, d):
                pass

            async def write(self, p, data):
                pass

        class _FakeSb:
            def __init__(self, name):
                self.name = name
                self.fs = _FakeFs()
                self.stopped = False

            async def shell(self, cmd, cwd=None, timeout=None):
                class _O:
                    stdout_text = ""
                    stderr_text = ""
                    exit_code = 0

                return _O()

            async def stop(self, timeout=None):
                self.stopped = True

            async def destroy(self, force=False, timeout=None):
                pass

        async def fake_create(**kw):
            await asyncio.sleep(0.04)
            vm = _FakeSb(kw.get("name", "vm"))
            created_vms.append(vm)
            return vm

        async def fake_remove(name):
            pass

        with (
            mock.patch.object(msb_mod.MsbSandbox, "create", side_effect=fake_create),
            mock.patch.object(msb_mod.MsbSandbox, "remove", side_effect=fake_remove),
            mock.patch.object(msb_mod, "verify_network_none_policy", return_value=None),
        ):
            menv = MicrosandboxEnvironment.__new__(MicrosandboxEnvironment)
            menv.target_path = ""
            menv.image = "mantis-sandbox:latest"
            menv.timeout = 30.0
            menv.memory = None
            menv.cpus = None
            menv._workdir = Path("/workspace")
            menv._sb = None
            menv._name = None
            menv._stage_error = None
            menv.is_initialized = False
            await asyncio.gather(menv._ensure(), menv._ensure())
            self.assertEqual(len(created_vms), 1)
            await menv.close()

    async def test_drive_campaign_credits_audit_code_reads_only_on_non_error_responses(self):
        import main as main_mod

        class _Part:
            def __init__(self, function_call=None, function_response=None):
                self.text = None
                self.function_call = function_call
                self.function_response = function_response

        class _FC:
            def __init__(self, cid, name, args):
                self.id = cid
                self.name = name
                self.args = args

        class _FR:
            def __init__(self, fid, name, response):
                self.id = fid
                self.name = name
                self.response = response

        class _Content:
            def __init__(self, parts):
                self.parts = parts

        class _NodeInfo:
            def __init__(self, path):
                self.path = path

        class _Event:
            def __init__(self, node_path, parts):
                self.author = node_path
                self.node_info = _NodeInfo(node_path)
                self.partial = False
                self.error_code = None
                self.usage_metadata = None
                self.actions = None
                self.content = _Content(parts)

        class _FakeRunner:
            def __init__(self, events):
                self._events = events

            async def run_async(self, **kw):
                for ev in self._events:
                    yield ev

        with tempfile.TemporaryDirectory() as td:
            vuln = Path(td) / "vuln.py"
            vuln.write_text("x = 1\n", encoding="utf-8")

            # Case 1: SANDBOX-ERROR on read_file -> task fails and audit_code_reads stays 0
            ctrl_fail = BudgetController(config=BudgetConfig(), run_id="r_fail")
            events_fail = [
                _Event("researcher", [_Part(function_call=_FC("c1", "read_file", {"filepath": "vuln.py"}))]),
                _Event(
                    "researcher",
                    [_Part(function_response=_FR("c1", "read_file", {"result": "SANDBOX-ERROR: container dead"}))],
                ),
            ]
            ctx_fail = RunContext(jail_dir=td, db_path="", target_file=td, run_id="r_fail")
            tok1 = current_run_context.set(ctx_fail)
            try:
                failed = await main_mod._drive_campaign(
                    _FakeRunner(events_fail),
                    "sess_fail",
                    None,
                    None,
                    filepath=td,
                    run_id="r_fail",
                    db_path="",
                    status_map=None,
                    budget_controller=ctrl_fail,
                    transcript=None,
                )
            finally:
                current_run_context.reset(tok1)
            self.assertTrue(failed)
            self.assertEqual(ctrl_fail.audit_code_reads, 0)

            # Case 2: Successful fenced read_file -> task succeeds and audit_code_reads == 1
            ctrl_ok = BudgetController(config=BudgetConfig(), run_id="r_ok")
            events_ok = [
                _Event("researcher", [_Part(function_call=_FC("c2", "read_file", {"filepath": "vuln.py"}))]),
                _Event(
                    "researcher",
                    [
                        _Part(
                            function_response=_FR(
                                "c2",
                                "read_file",
                                {"result": "<<<UNTRUSTED_SOURCE_CODE_DATA_START>>>\nx = 1\n<<<UNTRUSTED_SOURCE_CODE_DATA_END>>>"},
                            )
                        )
                    ],
                ),
            ]
            ctx_ok = RunContext(jail_dir=td, db_path="", target_file=td, run_id="r_ok")
            tok2 = current_run_context.set(ctx_ok)
            try:
                failed_ok = await main_mod._drive_campaign(
                    _FakeRunner(events_ok),
                    "sess_ok",
                    None,
                    None,
                    filepath=td,
                    run_id="r_ok",
                    db_path="",
                    status_map=None,
                    budget_controller=ctrl_ok,
                    transcript=None,
                )
            finally:
                current_run_context.reset(tok2)
            self.assertFalse(failed_ok)
            self.assertEqual(ctrl_ok.audit_code_reads, 1)


if __name__ == "__main__":
    unittest.main()

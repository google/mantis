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

"""Hermetic unit tests for split-plane RemoteTargetEnvironment (INV-1, INV-2, INV-4)."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from core.context import RunContext, current_run_context
from core.environments import build_environment
from core.environments import remote_env
from core.environments.remote_env import RemoteTargetEnvironment
from core.synthesizer import ResearchGraphSynthesizer, clamp_sandbox_to_ceiling
from tools.sandbox_tools import MANTIS_SENTINEL_TOKEN, run_sandbox_with_evidence


class RemoteTargetEnvironmentTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp_local = tempfile.TemporaryDirectory(prefix="mantis_remote_local_")
        self._tmp_remote = tempfile.TemporaryDirectory(prefix="mantis_remote_guest_")
        self.addCleanup(self._tmp_local.cleanup)
        self.addCleanup(self._tmp_remote.cleanup)
        self.local_dir = Path(os.path.realpath(self._tmp_local.name))
        self.remote_dir = Path(os.path.realpath(self._tmp_remote.name))

        # Populate local checkout and remote target workdir independently
        (self.local_dir / "service.py").write_text("def handle(x):\n    return x\n", encoding="utf-8")
        (self.remote_dir / "service.py").write_text("def handle(x):\n    return x\n", encoding="utf-8")

    def _make_exec_env(self, **extra) -> RemoteTargetEnvironment:
        return build_environment(
            {
                "type": "remote",
                "options": {
                    "transport": "exec",
                    "exec_argv": ["/bin/sh", "-c"],
                    "workdir": str(self.remote_dir),
                    **extra,
                },
            },
            target_path=str(self.local_dir),
        )

    async def test_split_plane_preserves_host_immutability_inv4(self):
        env = self._make_exec_env()
        await env.preflight()
        await env.initialize()

        # Static plane reads local checkout
        files = await env.list_files("")
        self.assertEqual(files, ["service.py"])
        self.assertEqual(
            await env.read_file("service.py"),
            b"def handle(x):\n    return x\n",
        )

        # Dynamic plane writes and patches ONLY on the remote target, leaving local_dir untouched
        await env.write_file("workspace/repro_1.py", "print('MANTIS_REACHED_ENTRYPOINT')\n")
        self.assertFalse((self.local_dir / "workspace" / "repro_1.py").exists())
        self.assertTrue((self.remote_dir / "workspace" / "repro_1.py").exists())

        diff = (
            "--- a/service.py\n"
            "+++ b/service.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def handle(x):\n"
            "-    return x\n"
            "+    return str(x)\n"
        )
        patch_res = await env.apply_patch(diff)
        self.assertTrue(patch_res.startswith("exit=0"), patch_res)
        self.assertEqual(
            (self.local_dir / "service.py").read_text(encoding="utf-8"),
            "def handle(x):\n    return x\n",
            "local source checkout must never be mutated by remote apply_patch",
        )
        self.assertEqual(
            (self.remote_dir / "service.py").read_text(encoding="utf-8"),
            "def handle(x):\n    return str(x)\n",
        )
        await env.close()

    async def test_planted_local_sentinel_cannot_spoof_remote_dynamic_evidence_inv1(self):
        # Plant a fake sentinel file inside the local audited repository checkout
        (self.local_dir / "sentinel_77").write_text(f"{MANTIS_SENTINEL_TOKEN}\n", encoding="utf-8")

        env = self._make_exec_env()
        ctx = RunContext(
            db_path=str(self.local_dir / "unused.db"),
            run_id="run-remote-test",
            target_file="service.py",
            jail_dir=str(self.local_dir),
            sandbox=env,
        )
        token = current_run_context.set(ctx)
        try:
            # 1. Command does NOT write sentinel on remote target -> MUST fail closed despite local sentinel_77
            res_spoof = await run_sandbox_with_evidence(
                "python3 -c 'print(123)'",
                sentinel_path="sentinel_77",
                finding_id=77,
            )
            self.assertFalse(
                res_spoof["evidence_present"],
                "local checkout file must never satisfy dynamic sentinel verification",
            )
            # Planted local file was also never truncated/mutated on host
            self.assertIn(
                MANTIS_SENTINEL_TOKEN,
                (self.local_dir / "sentinel_77").read_text(encoding="utf-8"),
            )

            # 2. Command genuinely writes sentinel on remote target -> evidence_present=True
            res_real = await run_sandbox_with_evidence(
                f"printf '%s\\n' '{MANTIS_SENTINEL_TOKEN}' > sentinel_77",
                sentinel_path="sentinel_77",
                finding_id=77,
            )
            self.assertTrue(res_real["evidence_present"], res_real)
        finally:
            current_run_context.reset(token)
            await env.close()

    async def test_rebuild_log_and_reset_hooks_execute_deterministically(self):
        env = self._make_exec_env(
            rebuild_cmd="printf 'rebuilt-ok\\n' > rebuilt.marker",
            log_cmd="printf 'daemon-log: %s\\n' 'MANTIS_REACHED_ENTRYPOINT'",
            reset_cmd="rm -f rebuilt.marker transient.txt",
        )
        (self.remote_dir / "transient.txt").write_text("stale", encoding="utf-8")

        # initialize() runs reset_cmd before staging marker
        await env.initialize()
        self.assertFalse((self.remote_dir / "transient.txt").exists())

        # execute() appends bounded log_cmd telemetry
        exec_res = await env.execute("echo poc-ran")
        self.assertEqual(exec_res.exit_code, 0)
        self.assertIn("poc-ran", exec_res.stdout)
        self.assertIn("[REMOTE TARGET TELEMETRY]", exec_res.stdout)
        self.assertIn("daemon-log: MANTIS_REACHED_ENTRYPOINT", exec_res.stdout)

        # apply_patch() triggers rebuild_cmd
        diff = (
            "--- a/service.py\n"
            "+++ b/service.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def handle(x):\n"
            "-    return x\n"
            "+    return int(x)\n"
        )
        patch_out = await env.apply_patch(diff)
        self.assertTrue(patch_out.startswith("exit=0"), patch_out)
        self.assertTrue((self.remote_dir / "rebuilt.marker").exists())

        # Failing rebuild_cmd surfaces non-zero exit to patcher
        env_fail = self._make_exec_env(rebuild_cmd="echo 'compile error' >&2; exit 2")
        diff2 = (
            "--- a/service.py\n"
            "+++ b/service.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def handle(x):\n"
            "-    return int(x)\n"
            "+    return float(x)\n"
        )
        fail_out = await env_fail.apply_patch(diff2)
        self.assertTrue(fail_out.startswith("exit=2"), fail_out)
        self.assertIn("[PATCH APPLIED; REBUILD FAILED]", fail_out)
        self.assertIn("compile error", fail_out)

        # close() resets remote target state
        await env.close()
        self.assertFalse((self.remote_dir / "rebuilt.marker").exists())

    async def test_ssh_and_container_transport_hardening_and_read_bounds(self):
        # Reject insecure SSH host key policy or option-injected host/container names
        with self.assertRaises(ValueError):
            RemoteTargetEnvironment(host="10.0.0.5", strict_host_key_checking="no")
        with self.assertRaises(ValueError):
            RemoteTargetEnvironment(host="-oProxyCommand=evil")
        with self.assertRaises(ValueError):
            RemoteTargetEnvironment(container="--privileged")
        with self.assertRaises(ValueError):
            RemoteTargetEnvironment(container="app", container_tool="kubectl")

        ssh_env = RemoteTargetEnvironment(
            target_path=str(self.local_dir),
            host="10.10.0.5",
            ssh_user="auditor",
            port=2222,
            strict_host_key_checking="accept-new",
            workdir="/opt/app",
        )
        argv = ssh_env._build_transport_argv("id")
        self.assertIn("-oBatchMode=yes", argv)
        self.assertIn("-oForwardAgent=no", argv)
        self.assertIn("-oClearAllForwardings=yes", argv)
        self.assertIn("-oPermitLocalCommand=no", argv)
        self.assertIn("-oStrictHostKeyChecking=accept-new", argv)
        self.assertIn("--", argv)
        self.assertEqual(argv[argv.index("--") + 1], "auditor@10.10.0.5")

        # Guest file size ceiling & path confinement
        exec_env = self._make_exec_env()
        await exec_env.initialize()
        with self.assertRaises(PermissionError):
            await exec_env.write_file("../escape.txt", "nope")
        (self.remote_dir / "big.bin").write_bytes(b"A" * 2048)
        with (
            mock.patch.object(remote_env, "MAX_GUEST_FILE_BYTES", 512),
            mock.patch.object(remote_env, "_MAX_B64_GUEST_FILE_BYTES", 800),
        ):
            with self.assertRaises(ValueError) as ctx_cap:
                await exec_env.read_guest_file("big.bin")
        self.assertIn("exceeds maximum sandbox read size", str(ctx_cap.exception))
        await exec_env.close()

    def test_synthesizer_never_auto_selects_remote_without_operator_override(self):
        # Clamp treats 'remote' above every non-remote ceiling
        clamped, did_clamp = clamp_sandbox_to_ceiling("remote", "gce")
        self.assertEqual((clamped, did_clamp), ("gce", True))
        kept, did_clamp_same = clamp_sandbox_to_ceiling("remote", "remote")
        self.assertEqual((kept, did_clamp_same), ("remote", False))

        synth = ResearchGraphSynthesizer()
        raw_spec = {
            "name": "remote_escalation_attempt",
            "config": {"sandbox": {"type": "remote"}},
            "nodes": [
                {"id": "researcher", "type": "agent", "skill": "mantis-researcher", "tools": ["read_file", "report_findings"]},
            ],
            "edges": [{"from": "START", "to": "researcher"}],
        }
        spec_clamped = synth.sanitize_and_validate_spec(
            raw_spec,
            objective="Audit web API endpoints",
            sandbox_type=None,
        )
        self.assertNotEqual(spec_clamped.config.sandbox.type, "remote")

        spec_explicit = synth.sanitize_and_validate_spec(
            raw_spec,
            objective="Audit web API endpoints",
            sandbox_type="remote",
        )
        self.assertEqual(spec_explicit.config.sandbox.type, "remote")


if __name__ == "__main__":
    unittest.main()

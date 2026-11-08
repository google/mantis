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

"""The guest the reproducer runs PoCs in has no network and no host mounts.

The reproducer deliberately executes attacker payloads: command injection,
SSRF to attacker-chosen URLs, path traversal, deserialisation. Those are
only safe to run because the microVM is created with egress and ingress
denied and nothing from the host mounted in. This pins that creation call so
a refactor cannot quietly hand the guest a NAT uplink or a bind mount.
"""

from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from unittest import mock

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))


class _FakeFs:
    def __init__(self):
        self.dirs: list[str] = []

    async def mkdir(self, path):
        self.dirs.append(str(path))


class _FakeSandbox:
    def __init__(self):
        self.fs = _FakeFs()


class MicrosandboxCreationTest(unittest.TestCase):
    def _create_kwargs(self) -> dict:
        from core.environments import microsandbox_env as M

        env = M.MicrosandboxEnvironment.__new__(M.MicrosandboxEnvironment)
        env.target_path = ""
        env.image = "mantis-sandbox:latest"
        env.timeout = 30.0
        env.memory = None
        env.cpus = None
        env._workdir = Path("/workspace")
        env._sb = None
        env._name = None
        env._stage_error = None
        env.is_initialized = False

        seen: dict = {}

        async def fake_create(name, **kwargs):
            seen["name"] = name
            seen.update(kwargs)
            return _FakeSandbox()

        with mock.patch.object(M.MsbSandbox, "create", side_effect=fake_create):
            asyncio.run(env.initialize())
        return seen

    def test_the_guest_is_created_with_all_network_denied(self):
        from microsandbox.types import Action, Network

        kwargs = self._create_kwargs()
        self.assertIn("network", kwargs, "the sandbox is created without saying what network it gets")
        net = kwargs["network"]
        self.assertEqual(net, Network.none())
        self.assertEqual(net.policy.default_egress, Action.DENY)
        self.assertEqual(net.policy.default_ingress, Action.DENY)
        self.assertEqual(net.policy.rules, ())
        self.assertEqual(dict(net.ports), {}, "no port of the guest is published to the host")

    def test_the_guest_gets_no_host_mounts_or_environment(self):
        kwargs = self._create_kwargs()
        for key in ("volumes", "mounts", "env", "environment", "privileged"):
            self.assertNotIn(key, kwargs, f"{key!r} would reach into the host from the guest")
        self.assertEqual(kwargs.get("pull_policy"), __import__("microsandbox").PullPolicy.NEVER,
                         "a run must not fetch images; the operator pulls what the guest runs")
        self.assertTrue(str(kwargs["name"]).startswith("mantis-msb-"))

    def test_sizing_is_optional_and_bounded(self):
        from core.environments import microsandbox_env as M

        env = M.MicrosandboxEnvironment.__new__(M.MicrosandboxEnvironment)
        with mock.patch.object(M.os, "access", return_value=True):
            M.MicrosandboxEnvironment.__init__(env, target_path="", memory=4096, cpus=4)
        self.assertEqual((env.memory, env.cpus), (4096, 4))
        with mock.patch.object(M.os, "access", return_value=True):
            M.MicrosandboxEnvironment.__init__(env, target_path="", memory=10**9, cpus=10**3)
        self.assertEqual((env.memory, env.cpus), (16384, 16), "a workflow file cannot ask one VM for the host")
        with mock.patch.object(M.os, "access", return_value=True):
            M.MicrosandboxEnvironment.__init__(env, target_path="")
        self.assertEqual((env.memory, env.cpus), (None, None), "defaults stay the runtime's")
        env.memory, env.cpus = 2048, 2
        env._sb = None; env._name = None; env._stage_error = None; env.is_initialized = False
        env._workdir = Path("/workspace")
        seen: dict = {}

        async def fake_create(name, **kwargs):
            seen.update(kwargs)
            return _FakeSandbox()

        with mock.patch.object(M.MsbSandbox, "create", side_effect=fake_create):
            asyncio.run(env.initialize())
        self.assertEqual((seen.get("memory"), seen.get("cpus")), (2048, 2))
        self.assertEqual(seen["network"], __import__("microsandbox.types", fromlist=["Network"]).Network.none(),
                         "sizing never changes the network")

    def test_the_source_says_the_same_thing(self):
        """A second, independent witness: the literal call site. If someone
        routes creation through a helper the test above still holds; this one
        catches a network argument that is computed rather than written."""
        import inspect

        from core.environments import microsandbox_env as M

        src = inspect.getsource(M.MicrosandboxEnvironment._ensure)
        self.assertIn("network=Network.none()", src)


class BoundedGuestStreamTest(unittest.IsolatedAsyncioTestCase):
    """Host memory stays bounded even when a guest emits unbounded stdout or files."""

    def test_run_bounded_subprocess_caps_buffered_bytes_and_preserves_total(self):
        from core.environments.base import format_bounded_output, run_bounded_subprocess
        from core.truncation import TRUNCATION_MARKER_PREFIX

        res = run_bounded_subprocess(
            [sys.executable, "-c", "import sys; sys.stdout.write('A' * 300000)"],
            timeout=10.0,
            max_stdout_bytes=65536,
            max_stderr_bytes=4096,
        )
        self.assertEqual(res.returncode, 0)
        self.assertFalse(res.timed_out)
        self.assertTrue(res.stdout_overflowed)
        self.assertEqual(len(res.stdout), 65536)
        self.assertEqual(res.stdout_total_bytes, 300000)

        formatted = format_bounded_output(
            res.stdout, res.stdout_total_bytes, 16000, what="sandbox stdout"
        )
        self.assertTrue(formatted.startswith("A" * 16000 + "\n" + TRUNCATION_MARKER_PREFIX))
        self.assertIn("after 16000 of 300000 chars", formatted)

    def test_run_bounded_subprocess_kills_early_on_overflow_when_requested(self):
        from core.environments.base import run_bounded_subprocess

        res = run_bounded_subprocess(
            [
                sys.executable,
                "-c",
                "import sys\nwhile True:\n    sys.stdout.buffer.write(b'X' * 65536)\n",
            ],
            timeout=10.0,
            max_stdout_bytes=131072,
            max_stderr_bytes=4096,
            kill_on_stdout_overflow=True,
        )
        self.assertTrue(res.stdout_overflowed)
        self.assertEqual(len(res.stdout), 131072)

    async def test_gvisor_and_gce_read_file_reject_oversized_guest_files(self):
        import base64
        from core.environments import gce_env, gvisor_env

        with mock.patch("shutil.which", return_value="/usr/bin/docker"):
            gv = gvisor_env.GvisorEnvironment(container_tool="docker")
        gv._ensure = mock.AsyncMock(return_value=None)

        with mock.patch.object(gvisor_env, "MAX_GUEST_FILE_BYTES", 1024):
            with mock.patch(
                "subprocess.run",
                return_value=mock.MagicMock(returncode=0, stdout=b"Z" * 2048, stderr=b""),
            ):
                with self.assertRaises(ValueError) as ctx:
                    await gv.read_file("huge.bin")
        self.assertIn("exceeds maximum sandbox read size", str(ctx.exception))

        gce = gce_env.GceEnvironment(project="proj", gcloud_bin="/bin/true")
        gce._ensure = mock.AsyncMock(return_value=None)
        oversized_b64 = base64.b64encode(b"Y" * 2048)
        with (
            mock.patch.object(gce_env, "MAX_GUEST_FILE_BYTES", 1024),
            mock.patch.object(gce_env, "_MAX_B64_GUEST_FILE_BYTES", 1400),
            mock.patch(
                "subprocess.run",
                return_value=mock.MagicMock(returncode=0, stdout=oversized_b64, stderr=b""),
            ),
        ):
            with self.assertRaises(ValueError) as ctx2:
                await gce.read_file("huge.bin")
        self.assertIn("exceeds maximum sandbox read size", str(ctx2.exception))


if __name__ == "__main__":
    unittest.main()

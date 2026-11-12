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

"""Regression tests for CL 1 launch & wire portability fixes:

- ci-pr-scan-1: `PYTHONSAFEPATH=1 python3 -P reference/main.py --help` bootstrap
- campaign-drive-3: subdirectory-aware, byte-safe git `discover_files` & UTF-16 BOM check
- config-resolution-1: off-Vertex stage model inheritance, `fast_model`, and multi-model preflight
- gap-provider-wire-portability-1: stripping empty `cache_control_injection_points` before wire send
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
os.environ.setdefault("LITELLM_MODE", "PRODUCTION")

import httpx  # noqa: E402
from google.adk.agents.context_cache_config import ContextCacheConfig  # noqa: E402
from google.adk.models.llm_request import LlmRequest  # noqa: E402
from google.genai import types  # noqa: E402


class TestPythonSafePathBootstrap(unittest.TestCase):
    """ci-pr-scan-1: `main.py` must import `core.*` cleanly under `PYTHONSAFEPATH=1` / `-P`."""

    def test_main_help_succeeds_under_pythonsafepath_and_dash_p(self):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["PYTHONSAFEPATH"] = "1"
        proc = subprocess.run(
            [sys.executable, "-P", str(_REF_ROOT / "main.py"), "--help"],
            cwd=tempfile.gettempdir(),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"main.py --help failed under PYTHONSAFEPATH=1 -P:\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}",
        )
        self.assertIn("usage:", proc.stdout.lower())


class TestSubdirAndByteSafeDiscovery(unittest.TestCase):
    """campaign-drive-3: subdirectory git discovery, non-UTF-8 byte resilience, and UTF-16 BOM."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_cl1_disc_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _git(self, repo: Path, *args: str) -> None:
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)

    def test_git_subdirectory_discovers_tracked_dotfiles_and_honors_gitignore(self):
        import main as main_mod

        repo = Path(self.tmp) / "git_repo"
        repo.mkdir()
        self._git(repo, "init", "-q", "-b", "main")
        self._git(repo, "config", "user.name", "Test")
        self._git(repo, "config", "user.email", "test@example.com")
        (repo / ".gitignore").write_text("*.ignored.log\n", encoding="utf-8")

        sub_dir = repo / "packages" / "auth"
        sub_dir.mkdir(parents=True)
        (sub_dir / ".env.example").write_text("API_KEY=placeholder\n", encoding="utf-8")
        (sub_dir / "index.ts").write_text("export const auth = true;\n", encoding="utf-8")
        (sub_dir / "debug.ignored.log").write_text("noise\n", encoding="utf-8")

        self._git(repo, "add", ".gitignore", "packages/auth/.env.example", "packages/auth/index.ts")
        self._git(repo, "commit", "-q", "-m", "init")

        discovered = main_mod.discover_files(sub_dir)
        self.assertIn(str(sub_dir / ".env.example"), discovered)
        self.assertIn(str(sub_dir / "index.ts"), discovered)
        self.assertNotIn(str(sub_dir / "debug.ignored.log"), discovered)

    def test_non_utf8_filename_in_git_repo_does_not_crash_or_expose_gitignored(self):
        import main as main_mod

        repo = Path(self.tmp) / "latin1_repo"
        repo.mkdir()
        self._git(repo, "init", "-q", "-b", "main")
        self._git(repo, "config", "user.name", "Test")
        self._git(repo, "config", "user.email", "test@example.com")
        (repo / ".gitignore").write_text("secret.ignored.txt\n", encoding="utf-8")
        (repo / "good.py").write_text("x = 1\n", encoding="utf-8")
        (repo / "secret.ignored.txt").write_text("do not scan\n", encoding="utf-8")

        raw_bad_path = os.fsencode(str(repo)) + b"/bad_\xff_name.py"
        try:
            with open(raw_bad_path, "wb") as fh:
                fh.write(b"y = 2\n")
        except OSError:
            self.skipTest("Filesystem rejected non-UTF-8 filename")

        self._git(repo, "add", "-A")
        discovered = main_mod.discover_files(repo)
        self.assertIn(str(repo / "good.py"), discovered)
        self.assertNotIn(str(repo / "secret.ignored.txt"), discovered)

    def test_utf16_bom_source_is_not_treated_as_binary(self):
        import main as main_mod

        utf16_file = Path(self.tmp) / "Program.cs"
        utf16_file.write_bytes("namespace App { class Program {} }\r\n".encode("utf-16"))
        self.assertFalse(main_mod.is_binary_file(utf16_file))

        elf_file = Path(self.tmp) / "bin.o"
        elf_file.write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00")
        self.assertTrue(main_mod.is_binary_file(elf_file))

    def test_git_submodule_dir_entry_expands_and_walk_skips_venv_and_node_modules_but_keeps_vendor(self):
        import main as main_mod

        # 1. Non-git directory walk: skips node_modules, pyvenv.cfg venvs, CACHEDIR.TAG, keeps vendor/
        plain = Path(self.tmp) / "plain_tree"
        (plain / "src").mkdir(parents=True)
        (plain / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
        (plain / "vendor" / "lib").mkdir(parents=True)
        (plain / "vendor" / "lib" / "vendored.py").write_text("v = 1\n", encoding="utf-8")
        (plain / "node_modules" / "pkg").mkdir(parents=True)
        (plain / "node_modules" / "pkg" / "index.js").write_text("module.exports = {};\n", encoding="utf-8")
        (plain / "custom_venv" / "lib").mkdir(parents=True)
        (plain / "custom_venv" / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
        (plain / "custom_venv" / "lib" / "site.py").write_text("s = 1\n", encoding="utf-8")
        (plain / "build_cache").mkdir(parents=True)
        (plain / "build_cache" / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n", encoding="utf-8")
        (plain / "build_cache" / "cached.py").write_text("c = 1\n", encoding="utf-8")

        walked = main_mod.discover_files(plain)
        self.assertIn(str(plain / "src" / "app.py"), walked)
        self.assertIn(str(plain / "vendor" / "lib" / "vendored.py"), walked)
        self.assertNotIn(str(plain / "node_modules" / "pkg" / "index.js"), walked)
        self.assertNotIn(str(plain / "custom_venv" / "pyvenv.cfg"), walked)
        self.assertNotIn(str(plain / "custom_venv" / "lib" / "site.py"), walked)
        self.assertNotIn(str(plain / "build_cache" / "cached.py"), walked)

        # 2. Nested git repo (untracked submodule-style directory emitted as `submod/` by ls-files)
        outer = Path(self.tmp) / "outer_repo"
        outer.mkdir()
        self._git(outer, "init", "-q", "-b", "main")
        self._git(outer, "config", "user.name", "Test")
        self._git(outer, "config", "user.email", "test@example.com")
        (outer / "root.py").write_text("r = 1\n", encoding="utf-8")
        self._git(outer, "add", "root.py")
        self._git(outer, "commit", "-q", "-m", "root")

        nested = outer / "third_party" / "submod"
        nested.mkdir(parents=True)
        self._git(nested, "init", "-q", "-b", "main")
        (nested / "sub.c").write_text("int sub(void) { return 0; }\n", encoding="utf-8")

        outer_disc = main_mod.discover_files(outer)
        self.assertIn(str(outer / "root.py"), outer_disc)
        self.assertIn(str(nested / "sub.c"), outer_disc)

    def test_path_root_ceiling_stops_upward_git_traversal(self):
        import main as main_mod

        outer = Path(self.tmp) / "outer_ceiling_repo"
        outer.mkdir()
        self._git(outer, "init", "-q", "-b", "main")
        self._git(outer, "config", "user.name", "Test")
        self._git(outer, "config", "user.email", "test@example.com")
        (outer / ".gitignore").write_text("*.ignored_by_outer.py\n", encoding="utf-8")
        self._git(outer, "add", ".gitignore")
        self._git(outer, "commit", "-q", "-m", "init")

        ceiling = outer / "isolated_workspace"
        sub = ceiling / "pkg"
        sub.mkdir(parents=True)
        (sub / "app.py").write_text("x = 1\n", encoding="utf-8")
        (sub / "local.ignored_by_outer.py").write_text("y = 2\n", encoding="utf-8")

        # Without path_root ceiling, outer repo's .gitignore applies.
        unbounded = main_mod.discover_files(sub)
        self.assertIn(str(sub / "app.py"), unbounded)
        self.assertNotIn(str(sub / "local.ignored_by_outer.py"), unbounded)

        # With path_root=ceiling, upward git walk stops at ceiling and falls back to safe walk.
        bounded = main_mod.discover_files(sub, path_root=ceiling)
        self.assertIn(str(sub / "app.py"), bounded)
        self.assertIn(str(sub / "local.ignored_by_outer.py"), bounded)


class TestStageModelInheritanceAndPreflight(unittest.TestCase):
    """config-resolution-1: persisted non-Vertex model reaches all stages; preflight checks all models."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_cl1_cfg_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _clean_provider_env(self) -> dict[str, str]:
        keep = {
            k: v
            for k, v in os.environ.items()
            if k
            not in (
                "VERTEXAI_PROJECT",
                "GOOGLE_CLOUD_PROJECT",
                "MANTIS_MODEL",
                "MODEL_ID",
                "GEMINI_API_KEY",
                "GOOGLE_API_KEY",
                "ANTHROPIC_API_KEY",
            )
        }
        keep["OPENAI_API_KEY"] = "sk-test-only"
        return keep

    def test_shipped_workflow_with_local_openai_model_has_zero_vertex_nodes(self):
        from core.graph_loader import load_workflow_from_json

        wf_copy = Path(self.tmp) / "workflow.json"
        shutil.copyfile(_REF_ROOT / "workflow.json", wf_copy)
        local_overlay = Path(self.tmp) / "workflow.local.json"
        local_overlay.write_text(
            json.dumps({"config": {"default_model": "openai/gpt-4o"}}),
            encoding="utf-8",
        )

        with mock.patch.dict(os.environ, self._clean_provider_env(), clear=True):
            wf_obj, cfg = load_workflow_from_json(str(wf_copy), load_local=True)

        edges = set()
        agent_models: dict[str, str] = {}
        for edge in wf_obj.edges:
            fn = getattr(edge.from_node, "name", None)
            tn = getattr(edge.to_node, "name", None)
            if fn and tn:
                edges.add((fn, tn))
            for node in (edge.from_node, edge.to_node):
                ag = getattr(node, "agent", node)
                name = getattr(ag, "name", None)
                if name and hasattr(ag, "model") and ag.model is not None:
                    agent_models[name] = getattr(ag.model, "model", "")

        self.assertIn(("history", "structural_index"), edges)
        self.assertIn("history", agent_models)
        self.assertIn("deduplicator", agent_models)
        for stage, resolved in agent_models.items():
            self.assertEqual(
                resolved,
                "openai/gpt-4o",
                f"Stage '{stage}' stayed pinned to '{resolved}' instead of inheriting openai/gpt-4o",
            )
        self.assertEqual(cfg.get("resolved_node_models"), ["openai/gpt-4o"])

    def test_fast_model_routes_fast_tier_stages_and_preflight_catches_missing_secondary_creds(self):
        from core.graph_loader import load_workflow_from_json
        from scripts.configure import run_preflight_checks

        wf_copy = Path(self.tmp) / "workflow.json"
        shutil.copyfile(_REF_ROOT / "workflow.json", wf_copy)
        local_overlay = Path(self.tmp) / "workflow.local.json"
        local_overlay.write_text(
            json.dumps(
                {
                    "config": {
                        "default_model": "openai/gpt-4o",
                        "fast_model": "anthropic/claude-haiku-4-5",
                    }
                }
            ),
            encoding="utf-8",
        )

        with mock.patch.dict(os.environ, self._clean_provider_env(), clear=True):
            wf_obj, cfg = load_workflow_from_json(str(wf_copy), load_local=True)
            agent_models = {}
            for edge in wf_obj.edges:
                for node in (edge.from_node, edge.to_node):
                    ag = getattr(node, "agent", node)
                    name = getattr(ag, "name", None)
                    if name and hasattr(ag, "model") and ag.model is not None:
                        agent_models[name] = getattr(ag.model, "model", "")

            self.assertEqual(agent_models["history"], "anthropic/claude-haiku-4-5")
            self.assertEqual(agent_models["deduplicator"], "anthropic/claude-haiku-4-5")
            self.assertEqual(agent_models["researcher"], "openai/gpt-4o")

            # Preflight must fail because fast_model uses anthropic/* while ANTHROPIC_API_KEY is unset!
            ok, msgs = run_preflight_checks(cfg)
            self.assertFalse(ok, f"Preflight unexpectedly passed missing secondary model creds: {msgs}")
            self.assertTrue(any("ANTHROPIC_API_KEY" in m for m in msgs), msgs)

    def test_default_vertex_config_preserves_flash_lite_fast_tier_and_fingerprint(self):
        from core.graph_loader import load_workflow_from_json

        env = self._clean_provider_env()
        env["VERTEXAI_PROJECT"] = "example-project"
        with mock.patch.dict(os.environ, env, clear=True):
            wf_obj, cfg = load_workflow_from_json(str(_REF_ROOT / "workflow.json"), load_local=False)

        agent_models: dict[str, str] = {}
        for edge in wf_obj.edges:
            for node in (edge.from_node, edge.to_node):
                ag = getattr(node, "agent", node)
                name = getattr(ag, "name", None)
                if name and hasattr(ag, "model") and ag.model is not None:
                    agent_models[name] = getattr(ag.model, "model", "")

        self.assertEqual(agent_models["history"], "vertex_ai/gemini-3.5-flash-lite")
        self.assertEqual(agent_models["deduplicator"], "vertex_ai/gemini-3.5-flash-lite")
        self.assertEqual(agent_models["researcher"], "vertex_ai/gemini-3.8-flash")
        self.assertEqual(agent_models["critic"], "vertex_ai/gemini-3.8-flash")
        self.assertEqual(
            cfg.get("resolved_node_models"),
            ["vertex_ai/gemini-3.5-flash-lite", "vertex_ai/gemini-3.8-flash"],
        )
        self.assertTrue(bool(cfg.get("harness_fingerprint")))

    def test_configure_check_clean_passes_on_shipped_workflow(self):
        proc = subprocess.run(
            [sys.executable, str(_REF_ROOT / "scripts" / "configure.py"), "--workflow", str(_REF_ROOT / "workflow.json"), "--check-clean"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


class TestWirePortabilityStripEmptyInjectionPoints(unittest.IsolatedAsyncioTestCase):
    """gap-provider-wire-portability-1: `cache_control_injection_points: []` never reaches the wire."""

    async def _capture_adk_wire(self, model_id: str, extra_env: dict[str, str], *, stream: bool, api_base: str | None = None) -> list[dict]:
        from core.config import ResilientLiteLlm, get_llm_kwargs

        captured_bodies: list[dict] = []

        async def fake_async_send(self_client, request: httpx.Request, **kwargs):
            body = json.loads(request.content.decode("utf-8"))
            captured_bodies.append(body)
            if stream:
                sse = (
                    b'data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m",'
                    b'"choices":[{"index":0,"delta":{"role":"assistant","content":"ok"},"finish_reason":null}]}\n\n'
                    b'data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m",'
                    b'"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],'
                    b'"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}\n\n'
                    b"data: [DONE]\n\n"
                )
                return httpx.Response(
                    200,
                    content=sse,
                    headers={"content-type": "text/event-stream"},
                    request=request,
                )
            return httpx.Response(
                200,
                json={
                    "id": "c1",
                    "object": "chat.completion",
                    "created": 1,
                    "model": model_id,
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
                },
                request=request,
            )

        env = {
            "MANTIS_LLM_MAX_PATIENCE_SECONDS": "0",
            "MANTIS_LLM_RETRY_INITIAL_DELAY": "0",
            "MANTIS_LLM_MIN_OFFSET": "0",
            "MANTIS_LLM_RETRY_MAX_DELAY": "0",
            **extra_env,
        }
        with mock.patch.dict(os.environ, env, clear=False):
            resolved, llm_kwargs = get_llm_kwargs(model_id=model_id, api_base=api_base, reasoning_effort="low")
            # ADK still requires [] in get_llm_kwargs so it does not synthesize Anthropic cache_control blocks.
            self.assertEqual(llm_kwargs.get("cache_control_injection_points"), [])
            llm = ResilientLiteLlm(**llm_kwargs)
            req = LlmRequest(
                model=resolved,
                contents=[types.Content(role="user", parts=[types.Part.from_text(text="ping")])],
                cache_config=ContextCacheConfig(),
            )
            with mock.patch.object(httpx.AsyncClient, "send", fake_async_send), mock.patch(
                "litellm.llms.vertex_ai.vertex_llm_base.VertexBase._ensure_access_token_async",
                return_value=("fake-token", "example-project"),
            ), mock.patch(
                "litellm.llms.vertex_ai.vertex_llm_base.VertexBase._ensure_access_token",
                return_value=("fake-token", "example-project"),
            ):
                responses = [r async for r in llm.generate_content_async(req, stream=stream)]
                self.assertGreaterEqual(len(responses), 1)
        return captured_bodies

    async def test_vertex_glm_maas_and_litellm_proxy_strip_ccip_stream_and_nonstream(self):
        for stream in (False, True):
            with self.subTest(route="vertex_glm_maas", stream=stream):
                bodies = await self._capture_adk_wire(
                    "vertex_ai/openai/zai-org/glm-5.2-maas",
                    {"VERTEXAI_PROJECT": "example-project", "VERTEXAI_LOCATION": "us-central1"},
                    stream=stream,
                )
                self.assertEqual(len(bodies), 1)
                self.assertNotIn("cache_control_injection_points", bodies[0])

            with self.subTest(route="litellm_proxy", stream=stream):
                bodies = await self._capture_adk_wire(
                    "litellm_proxy/gpt-4o",
                    {"LITELLM_PROXY_API_KEY": "sk-proxy-test"},
                    stream=stream,
                    api_base="http://127.0.0.1:4000/v1",
                )
                self.assertEqual(len(bodies), 1)
                self.assertNotIn("cache_control_injection_points", bodies[0])

    def test_sync_completion_and_configure_probe_strip_ccip(self):
        from core.config import ResilientLiteLLMClient, get_llm_kwargs
        from scripts.configure import _probe_llm_reachability

        captured_sync: list[dict] = []

        def fake_sync_send(self_client, request: httpx.Request, **kwargs):
            captured_sync.append(json.loads(request.content.decode("utf-8")))
            return httpx.Response(
                200,
                json={
                    "id": "c1",
                    "object": "chat.completion",
                    "created": 1,
                    "model": "m",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
                },
                request=request,
            )

        with mock.patch.dict(
            os.environ,
            {"VERTEXAI_PROJECT": "example-project", "VERTEXAI_LOCATION": "us-central1"},
            clear=False,
        ), mock.patch.object(httpx.Client, "send", fake_sync_send), mock.patch(
            "litellm.llms.vertex_ai.vertex_llm_base.VertexBase._ensure_access_token",
            return_value=("fake-token", "example-project"),
        ):
            resolved, kw = get_llm_kwargs("vertex_ai/openai/zai-org/glm-5.2-maas")
            ResilientLiteLLMClient().completion(messages=[{"role": "user", "content": "hi"}], **kw)
            ok, _ = _probe_llm_reachability(resolved, kw, prompt="test", max_tokens=16, timeout=5.0)
            self.assertTrue(ok)

        self.assertEqual(len(captured_sync), 2)
        for body in captured_sync:
            self.assertNotIn("cache_control_injection_points", body)


if __name__ == "__main__":
    unittest.main()

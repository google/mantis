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

"""Tests for how get_llm_kwargs shapes a request per provider route.

The pipeline is provider-agnostic underneath (litellm); these pin the few
places the harness adds route-specific behaviour, so a change to one route
cannot silently diverge from another.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from core.config import DEFAULT_MODEL, get_llm_kwargs, normalize_model_id  # noqa: E402

_CATEGORIES = {
    "HARM_CATEGORY_DANGEROUS_CONTENT",
    "HARM_CATEGORY_HATE_SPEECH",
    "HARM_CATEGORY_HARASSMENT",
    "HARM_CATEGORY_SEXUALLY_EXPLICIT",
}

_CRED_VARS = ("GEMINI_API_KEY", "GOOGLE_API_KEY", "VERTEXAI_PROJECT",
              "GOOGLE_CLOUD_PROJECT", "GOOGLE_APPLICATION_CREDENTIALS",
              "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "MANTIS_MODEL", "MODEL_ID",
              "LLM_API_BASE")


def _clean_env(**extra):
    env = {k: v for k, v in os.environ.items() if k not in _CRED_VARS}
    env.update(extra)
    return mock.patch.dict(os.environ, env, clear=True)


def _relaxed(kwargs) -> bool:
    settings = kwargs.get("safety_settings") or []
    return ({s["category"] for s in settings} == _CATEGORIES
            and all(s["threshold"] == "BLOCK_NONE" for s in settings))


class DefaultModelTest(unittest.TestCase):
    def test_default_is_a_supported_gemini_flash(self):
        self.assertEqual(DEFAULT_MODEL, "vertex_ai/gemini-3.8-flash")

    def test_bare_gemini_routes_by_credentials(self):
        with _clean_env(GEMINI_API_KEY="k"):
            self.assertEqual(normalize_model_id("gemini-3.8-flash"), "gemini/gemini-3.8-flash")
        with _clean_env(GOOGLE_API_KEY="k"):
            self.assertEqual(normalize_model_id("gemini-3.8-flash"), "gemini/gemini-3.8-flash")
        with _clean_env(GOOGLE_CLOUD_PROJECT="p"):
            self.assertEqual(normalize_model_id("gemini-3.8-flash"), "vertex_ai/gemini-3.8-flash")


class SafetySettingsPerRouteTest(unittest.TestCase):
    """The category-filter relaxation follows the model, not the route.

    Before this, only the vertex_ai/ branch set safety_settings: the same
    defensive-analysis prompt could be filtered through an API key and pass
    through a project.
    """

    def test_vertex_route_relaxes_filters(self):
        with _clean_env(GOOGLE_CLOUD_PROJECT="p"):
            model, kwargs = get_llm_kwargs(model_id="vertex_ai/gemini-3.8-flash")
        self.assertEqual(model, "vertex_ai/gemini-3.8-flash")
        self.assertTrue(_relaxed(kwargs), kwargs.get("safety_settings"))
        self.assertEqual(kwargs.get("vertex_project"), "p")

    def test_gemini_api_route_relaxes_filters_too(self):
        with _clean_env(GEMINI_API_KEY="k"):
            model, kwargs = get_llm_kwargs(model_id="gemini-3.8-flash")
        self.assertEqual(model, "gemini/gemini-3.8-flash")
        self.assertTrue(_relaxed(kwargs), kwargs.get("safety_settings"))
        self.assertNotIn("vertex_project", kwargs)

    def test_non_gemini_routes_are_untouched(self):
        with _clean_env(ANTHROPIC_API_KEY="k"):
            _, anthropic = get_llm_kwargs(model_id="anthropic/claude-opus-5")
        with _clean_env(OPENAI_API_KEY="k", LLM_API_BASE="http://x/v1"):
            _, openai_compat = get_llm_kwargs(model_id="openai/glm-5.3")
            # A Gemini model served by an OpenAI-compatible gateway takes
            # OpenAI parameters; the Gemini-only one would be rejected there.
            _, gateway_gemini = get_llm_kwargs(model_id="openai/gemini-3.8-flash")
        self.assertNotIn("safety_settings", anthropic)
        self.assertNotIn("safety_settings", openai_compat)
        self.assertNotIn("safety_settings", gateway_gemini)
        self.assertEqual(openai_compat.get("api_base"), "http://x/v1")

    def test_vertex_global_is_only_set_on_vertex(self):
        import litellm

        with mock.patch.object(litellm, "vertex_ai_safety_settings", None, create=True):
            with _clean_env(GEMINI_API_KEY="k"):
                get_llm_kwargs(model_id="gemini/gemini-3.8-flash")
            self.assertIsNone(litellm.vertex_ai_safety_settings)
            with _clean_env(GOOGLE_CLOUD_PROJECT="p"):
                get_llm_kwargs(model_id="vertex_ai/gemini-3.8-flash")
            self.assertIsNotNone(litellm.vertex_ai_safety_settings)


class NonVertexOnboardingConfigureTest(unittest.TestCase):
    """r3-docs-2: configure.py --auto auto-selects gemini/<id> when only
    GEMINI_API_KEY is set, and prints actionable --model guidance (without
    falsely claiming settings were saved) for Anthropic, OpenAI, and --api-base."""

    def _copy_base_workflow(self, tmp_dir: str) -> Path:
        import shutil

        src = Path(_REF_ROOT) / "workflow.json"
        dst = Path(tmp_dir) / "workflow.json"
        shutil.copy2(src, dst)
        return dst

    @staticmethod
    def _offline_caps(**overrides):
        base = {
            "kvm": False,
            "docker": False,
            "podman": False,
            "container_tool": None,
            "runsc": False,
            "gcloud": False,
            "gcp_auth": False,
            "gcp_account": None,
            "gcp_project": None,
            "vertex_project": None,
            "gemini_api_key": False,
            "anthropic_api_key": False,
            "openai_api_key": False,
            "llm_api_base": None,
            "microsandbox_image": None,
            "recommended_sandbox": "static-only",
            "available_sandboxes": ["static-only"],
        }
        base.update(overrides)
        return base

    def test_auto_switches_to_gemini_api_route_when_only_gemini_api_key_is_set(self):
        import contextlib
        import io
        import json
        import tempfile
        from scripts import configure as cfg_mod

        with tempfile.TemporaryDirectory() as td:
            wf_path = self._copy_base_workflow(td)
            local_path = wf_path.with_name("workflow.local.json")
            buf = io.StringIO()
            with (
                _clean_env(GEMINI_API_KEY="ai-studio-key"),
                mock.patch.object(
                    cfg_mod,
                    "detect_capabilities",
                    return_value=self._offline_caps(gemini_api_key=True),
                ),
                mock.patch("sys.argv", ["configure.py", "--workflow", str(wf_path), "--auto"]),
                contextlib.redirect_stdout(buf),
            ):
                rc = cfg_mod.main()
                ok, msgs = cfg_mod.run_preflight_checks(
                    cfg_mod.load_workflow_dict(str(wf_path)).get("config", {}),
                    nodes=cfg_mod.load_workflow_dict(str(wf_path)).get("nodes"),
                )

            self.assertEqual(rc, 0)
            self.assertTrue(local_path.exists(), "workflow.local.json should persist auto-resolved gemini/ model")
            persisted = json.loads(local_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["config"]["default_model"], "gemini/gemini-3.8-flash")
            self.assertTrue(ok, msgs)
            out = buf.getvalue()
            self.assertIn("Auto-configured model: 'gemini/gemini-3.8-flash'", out)
            self.assertIn("Auto-configured Mantis settings saved to", out)

    def test_auto_with_anthropic_or_openai_key_prints_model_hint_and_does_not_claim_save(self):
        import contextlib
        import io
        import tempfile
        from scripts import configure as cfg_mod

        for env_kw, cap_kw, expected_flag in (
            (
                {"ANTHROPIC_API_KEY": "sk-ant-test"},
                {"anthropic_api_key": True},
                "--model anthropic/",
            ),
            (
                {"OPENAI_API_KEY": "sk-openai-test"},
                {"openai_api_key": True},
                "--model openai/",
            ),
        ):
            with self.subTest(provider=expected_flag), tempfile.TemporaryDirectory() as td:
                wf_path = self._copy_base_workflow(td)
                local_path = wf_path.with_name("workflow.local.json")
                buf = io.StringIO()
                with (
                    _clean_env(**env_kw),
                    mock.patch.object(
                        cfg_mod,
                        "detect_capabilities",
                        return_value=self._offline_caps(**cap_kw),
                    ),
                    mock.patch("sys.argv", ["configure.py", "--workflow", str(wf_path), "--auto"]),
                    contextlib.redirect_stdout(buf),
                ):
                    rc = cfg_mod.main()

                self.assertEqual(rc, 0)
                self.assertFalse(local_path.exists())
                out = buf.getvalue()
                self.assertNotIn("Auto-configured Mantis settings saved to", out)
                self.assertIn("did not write", out)
                self.assertIn(expected_flag, out)

                # Runtime get_llm_kwargs also names --model when invoked directly via run.sh/main.py
                with _clean_env(**env_kw), mock.patch("google.auth.default", side_effect=RuntimeError("no adc")):
                    with self.assertRaises(ValueError) as ctx_err:
                        get_llm_kwargs(model_id="vertex_ai/gemini-3.8-flash")
                self.assertIn(expected_flag, str(ctx_err.exception))

    def test_api_base_without_model_names_model_flag_and_auto_with_model_persists(self):
        import contextlib
        import io
        import json
        import tempfile
        from scripts import configure as cfg_mod

        with tempfile.TemporaryDirectory() as td:
            wf_path = self._copy_base_workflow(td)
            local_path = wf_path.with_name("workflow.local.json")
            buf = io.StringIO()
            with (
                _clean_env(),
                mock.patch("google.auth.default", side_effect=RuntimeError("no adc")),
                mock.patch.object(
                    cfg_mod,
                    "detect_capabilities",
                    return_value=self._offline_caps(llm_api_base="http://localhost:8000/v1"),
                ),
                mock.patch(
                    "sys.argv",
                    [
                        "configure.py",
                        "--workflow",
                        str(wf_path),
                        "--api-base",
                        "http://localhost:8000/v1",
                        "--test",
                    ],
                ),
                contextlib.redirect_stdout(buf),
            ):
                rc_bad = cfg_mod.main()
            self.assertEqual(rc_bad, 1)
            self.assertIn("--model openai/<model-id> --api-base http://localhost:8000/v1", buf.getvalue())

            # Passing --auto together with --model persists the explicit non-Vertex model cleanly.
            buf_ok = io.StringIO()
            with (
                _clean_env(ANTHROPIC_API_KEY="sk-ant-ok"),
                mock.patch.object(
                    cfg_mod,
                    "detect_capabilities",
                    return_value=self._offline_caps(anthropic_api_key=True),
                ),
                mock.patch(
                    "sys.argv",
                    [
                        "configure.py",
                        "--workflow",
                        str(wf_path),
                        "--auto",
                        "--model",
                        "anthropic/claude-sonnet-4-5",
                    ],
                ),
                contextlib.redirect_stdout(buf_ok),
            ):
                rc_ok = cfg_mod.main()
                wf_loaded = cfg_mod.load_workflow_dict(str(wf_path))
                ok, msgs = cfg_mod.run_preflight_checks(
                    wf_loaded.get("config", {}),
                    nodes=wf_loaded.get("nodes"),
                )
            self.assertEqual(rc_ok, 0)
            self.assertTrue(ok, msgs)
            persisted = json.loads(local_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["config"]["default_model"], "anthropic/claude-sonnet-4-5")
            self.assertIn("Auto-configured Mantis settings saved to", buf_ok.getvalue())


if __name__ == "__main__":
    unittest.main()

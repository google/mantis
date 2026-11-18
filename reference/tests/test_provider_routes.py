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

    def test_adc_project_prevents_switching_vertex_to_gemini_api(self):
        """[r4-vertex-to-gemini-autoselect]: detect_capabilities reads project from an
        existing local ADC file via load_credentials_from_file() (NEVER google.auth.default())
        so a working Vertex service-account install with GEMINI_API_KEY in env is not
        silently rewritten to gemini/*."""
        import contextlib
        import io
        import json
        import tempfile
        from scripts import configure as cfg_mod

        with tempfile.TemporaryDirectory() as td:
            wf_path = self._copy_base_workflow(td)
            local_path = wf_path.with_name("workflow.local.json")
            sa_path = Path(td) / "sa.json"
            sa_path.write_text(
                json.dumps({"type": "service_account", "project_id": "adc-vertex-proj"}),
                encoding="utf-8",
            )
            with (
                _clean_env(
                    GEMINI_API_KEY="ai-studio-key",
                    GOOGLE_APPLICATION_CREDENTIALS=str(sa_path),
                ),
                mock.patch.object(cfg_mod, "check_microsandbox_virtualization", return_value=(False, "")),
                mock.patch("shutil.which", return_value=None),
                mock.patch(
                    "google.auth.load_credentials_from_file",
                    return_value=(object(), "adc-vertex-proj"),
                ) as load_mock,
                mock.patch(
                    "google.auth.default",
                    side_effect=AssertionError("detect_capabilities must not call google.auth.default()"),
                ),
            ):
                caps = cfg_mod.detect_capabilities()
                self.assertEqual(caps.get("vertex_project"), "adc-vertex-proj")
                load_mock.assert_called_once_with(str(sa_path))
                buf = io.StringIO()
                with (
                    mock.patch.object(
                        cfg_mod,
                        "run_preflight_checks_async",
                        new=mock.AsyncMock(return_value=(True, [])),
                    ),
                    contextlib.redirect_stdout(buf),
                ):
                    # 1. Plain ensure_configured keeps Vertex without rewriting workflow.local.json.
                    cfg_plain = cfg_mod.ensure_configured(
                        workflow_path=str(wf_path),
                        auto=True,
                        save=True,
                        persist_overrides=False,
                    )
                    self.assertEqual(cfg_plain.get("default_model"), "vertex_ai/gemini-3.8-flash")
                    self.assertFalse(local_path.exists(), "must not rewrite workflow.local.json to gemini/*")

                    # 2. With a CLI override (forcing past the early preflight shortcut into
                    # auto-resolution), ADC project still preserves vertex_ai/* and exports
                    # VERTEXAI_PROJECT instead of falling back to gemini/*.
                    cfg = cfg_mod.ensure_configured(
                        workflow_path=str(wf_path),
                        auto=True,
                        overrides={"sandbox": {"type": "static-only", "options": {}}},
                        save=True,
                        persist_overrides=False,
                    )
                self.assertEqual(cfg.get("default_model"), "vertex_ai/gemini-3.8-flash")
                self.assertEqual(os.environ.get("VERTEXAI_PROJECT"), "adc-vertex-proj")
                self.assertFalse(local_path.exists(), "must not rewrite workflow.local.json to gemini/*")

    def test_detect_adc_project_never_probes_metadata_ignores_quota_project_and_skips_on_timeout(self):
        """PR #36 review hardening:
        - Missing ADC file returns immediately without calling google.auth.default/load_credentials_from_file.
        - authorized_user ADC with quota_project_id returns None (never leaks billing project as GCE/Vertex project).
        - external_account JSON is skipped without network/pluggable execution.
        - gcloud TimeoutExpired skips _detect_adc_project and preserves gcp_project_probe_failed=True."""
        import json
        import subprocess
        import tempfile
        from scripts import configure as cfg_mod

        with tempfile.TemporaryDirectory() as td:
            # 1. No ADC file anywhere -> zero google.auth calls (no 12s metadata probe, no gcloud).
            missing_cfg = Path(td) / "empty_gcloud"
            missing_cfg.mkdir()
            with (
                _clean_env(GEMINI_API_KEY="k", CLOUDSDK_CONFIG=str(missing_cfg), HOME=td),
                mock.patch("google.auth.default", side_effect=AssertionError("must not call default()")),
                mock.patch(
                    "google.auth.load_credentials_from_file",
                    side_effect=AssertionError("must not call load_credentials_from_file() when file missing"),
                ),
            ):
                self.assertIsNone(cfg_mod._detect_adc_project())

            # 2. Real authorized_user ADC file with quota_project_id -> returns None (no billing leak, no gcloud).
            user_adc = missing_cfg / "application_default_credentials.json"
            user_adc.write_text(
                json.dumps(
                    {
                        "type": "authorized_user",
                        "client_id": "test-client-id.apps.googleusercontent.com",
                        "client_secret": "test-secret",
                        "refresh_token": "1//test-refresh-token",
                        "quota_project_id": "billing-only-project",
                    }
                ),
                encoding="utf-8",
            )
            with (
                _clean_env(CLOUDSDK_CONFIG=str(missing_cfg), HOME=td),
                mock.patch("google.auth.default", side_effect=AssertionError("must not call default()")),
            ):
                self.assertIsNone(cfg_mod._detect_adc_project())

            # 3. external_account JSON -> skipped without invoking load_credentials_from_file / network.
            ext_adc = Path(td) / "ext.json"
            ext_adc.write_text(
                json.dumps({"type": "external_account", "audience": "//iam.googleapis.com/projects/123"}),
                encoding="utf-8",
            )
            with (
                _clean_env(GOOGLE_APPLICATION_CREDENTIALS=str(ext_adc)),
                mock.patch(
                    "google.auth.load_credentials_from_file",
                    side_effect=AssertionError("must skip external_account without network/exec"),
                ),
            ):
                self.assertIsNone(cfg_mod._detect_adc_project())

            # 4. gcloud probe TimeoutExpired -> skips _detect_adc_project() and keeps gcp_project_probe_failed=True.
            def _fake_run(argv, **kwargs):
                if "auth" in argv:
                    return subprocess.CompletedProcess(argv, 0, stdout="dev@example.com\n", stderr="")
                raise subprocess.TimeoutExpired(argv, timeout=3)

            with (
                _clean_env(GEMINI_API_KEY="k"),
                mock.patch.object(cfg_mod, "check_microsandbox_virtualization", return_value=(False, "")),
                mock.patch("shutil.which", side_effect=lambda name: "/usr/bin/gcloud" if name == "gcloud" else None),
                mock.patch("subprocess.run", side_effect=_fake_run),
                mock.patch.object(
                    cfg_mod,
                    "_detect_adc_project",
                    side_effect=AssertionError("must skip _detect_adc_project when gcloud timed out"),
                ),
            ):
                caps = cfg_mod.detect_capabilities()
            self.assertTrue(caps.get("gcp_project_probe_failed"))
            self.assertIsNone(caps.get("vertex_project"))

    def test_overlay_explicit_helpers_handle_non_dict_config_without_raising(self):
        """Non-dict `config` in workflow.local.json must not raise AttributeError in
        _model_choice_is_explicit / _sandbox_choice_is_explicit."""
        import json
        import tempfile
        from scripts import configure as cfg_mod

        for bad_cfg in ("not-a-dict", [1, 2, 3], 42, True):
            with self.subTest(bad_cfg=bad_cfg), tempfile.TemporaryDirectory() as td:
                wf_path = self._copy_base_workflow(td)
                local_path = wf_path.with_name("workflow.local.json")
                local_path.write_text(json.dumps({"config": bad_cfg}), encoding="utf-8")
                self.assertFalse(cfg_mod._model_choice_is_explicit(str(wf_path)))
                self.assertFalse(cfg_mod._sandbox_choice_is_explicit(str(wf_path)))

    def test_explicit_local_overlay_and_gcloud_timeout_preserve_vertex_model(self):
        """[r4-vertex-to-gemini-autoselect]: Never overwrite an explicit vertex_ai/* model
        pinned in workflow.local.json, and never switch when gcloud project probe timed out."""
        import contextlib
        import io
        import json
        import tempfile
        from scripts import configure as cfg_mod

        # Case 1: workflow.local.json explicitly pins vertex_ai/gemini-3.8-flash.
        with tempfile.TemporaryDirectory() as td:
            wf_path = self._copy_base_workflow(td)
            local_path = wf_path.with_name("workflow.local.json")
            local_payload = {"config": {"default_model": "vertex_ai/gemini-3.8-flash"}}
            local_path.write_text(json.dumps(local_payload), encoding="utf-8")
            buf = io.StringIO()
            with (
                _clean_env(GEMINI_API_KEY="ai-studio-key"),
                mock.patch.object(
                    cfg_mod,
                    "detect_capabilities",
                    return_value=self._offline_caps(gemini_api_key=True),
                ),
                contextlib.redirect_stdout(buf),
            ):
                cfg = cfg_mod.ensure_configured(
                    workflow_path=str(wf_path),
                    auto=True,
                    save=True,
                    persist_overrides=False,
                )
            self.assertEqual(cfg.get("default_model"), "vertex_ai/gemini-3.8-flash")
            self.assertEqual(json.loads(local_path.read_text(encoding="utf-8")), local_payload)
            self.assertIn("Keeping explicit local overlay model", buf.getvalue())

        # Case 2: gcloud probe timed out (`gcp_project_probe_failed=True`).
        with tempfile.TemporaryDirectory() as td:
            wf_path = self._copy_base_workflow(td)
            local_path = wf_path.with_name("workflow.local.json")
            buf = io.StringIO()
            with (
                _clean_env(GEMINI_API_KEY="ai-studio-key"),
                mock.patch.object(
                    cfg_mod,
                    "detect_capabilities",
                    return_value=self._offline_caps(
                        gemini_api_key=True,
                        gcp_project_probe_failed=True,
                    ),
                ),
                contextlib.redirect_stdout(buf),
            ):
                cfg = cfg_mod.ensure_configured(
                    workflow_path=str(wf_path),
                    auto=True,
                    save=True,
                    persist_overrides=False,
                )
            self.assertEqual(cfg.get("default_model"), "vertex_ai/gemini-3.8-flash")
            self.assertFalse(local_path.exists())
            self.assertIn("probe timed out", buf.getvalue())

    def test_gemini_prefix_preflight_requires_api_key_not_gcp_project(self):
        """[r4-gemini-preflight-key]: `gemini/*` routes strictly to AI Studio and must fail
        preflight when only a GCP project is set (no GEMINI_API_KEY/GOOGLE_API_KEY)."""
        from scripts import configure as cfg_mod

        with _clean_env(GOOGLE_CLOUD_PROJECT="my-gcp-project"):
            ok_prefixed, msg_prefixed = cfg_mod._check_single_llm_preflight(
                "gemini/gemini-3.8-flash", {}, probe=False
            )
            self.assertFalse(ok_prefixed, msg_prefixed)
            self.assertIn("GEMINI_API_KEY", msg_prefixed)

            # Bare `gemini-*` routes to Vertex AI when a real GCP project is set.
            ok_bare, msg_bare = cfg_mod._check_single_llm_preflight(
                "gemini-3.8-flash", {}, probe=False
            )
            self.assertTrue(ok_bare, msg_bare)

        with _clean_env(GOOGLE_CLOUD_PROJECT="YOUR_PROJECT_ID"):
            ok_placeholder, _ = cfg_mod._check_single_llm_preflight(
                "gemini-3.8-flash", {}, probe=False
            )
            self.assertFalse(ok_placeholder)

        with _clean_env(GEMINI_API_KEY="ai-studio-key"):
            ok_key, msg_key = cfg_mod._check_single_llm_preflight(
                "gemini/gemini-3.8-flash", {}, probe=False
            )
            self.assertTrue(ok_key, msg_key)

    def test_autoselected_model_persists_when_one_shot_sandbox_override_passed(self):
        """[r4-autoselect-not-saved]: Passing a one-shot CLI `--sandbox` override must still
        persist auto-selected `default_model` while keeping `--sandbox` itself non-sticky."""
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
                    return_value=self._offline_caps(
                        gemini_api_key=True,
                        available_sandboxes=["static-only", "gvisor"],
                    ),
                ),
                mock.patch.object(
                    cfg_mod,
                    "run_preflight_checks_async",
                    new=mock.AsyncMock(return_value=(True, [])),
                ),
                contextlib.redirect_stdout(buf),
            ):
                cfg = cfg_mod.ensure_configured(
                    workflow_path=str(wf_path),
                    auto=True,
                    overrides={"sandbox": {"type": "gvisor", "options": {}}},
                    save=True,
                    persist_overrides=False,
                )
            self.assertEqual(cfg.get("default_model"), "gemini/gemini-3.8-flash")
            self.assertEqual(cfg.get("sandbox", {}).get("type"), "gvisor")
            self.assertTrue(local_path.exists(), "auto-selected model must persist despite one-shot --sandbox")
            persisted = json.loads(local_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["config"].get("default_model"), "gemini/gemini-3.8-flash")
            self.assertNotIn("sandbox", persisted["config"], "one-shot --sandbox must stay non-sticky")


if __name__ == "__main__":
    unittest.main()

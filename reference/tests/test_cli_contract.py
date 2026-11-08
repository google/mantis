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

"""Tests for the CLI contract: one-shot overrides, --save-config opt-in,
--path-root hard-fail, and launcher usage exit codes.

A per-invocation flag must never silently become sticky configuration:
before these rules, `--db /tmp/scratch.db` on one experiment persisted
into workflow.local.json and every later run kept writing findings there,
and a typo'd --model was saved before validation, breaking every
subsequent run. A --path-root that cannot contain the target used to
warn-and-proceed, burning the full budget on an un-rooted catalog.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

SENTINEL_MODEL = "vertex_ai/sentinel-model-for-tests"


class ConfigPersistenceTest(unittest.TestCase):
    """CLI overrides are live for the run but only saved on explicit opt-in."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_cli_contract_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(os.path.realpath(self._tmp.name))
        self.wf = self.tmp / "workflow.json"
        shutil.copyfile(Path(_REF_ROOT) / "workflow.json", self.wf)
        self.local = self.tmp / "workflow.local.json"

    def _run(self, **kwargs):
        from scripts.configure import ensure_configured_async
        return asyncio.run(
            ensure_configured_async(
                workflow_path=str(self.wf),
                auto=True,
                overrides={"default_model": SENTINEL_MODEL},
                **kwargs,
            )
        )

    def _local_text(self) -> str:
        return self.local.read_text(encoding="utf-8") if self.local.exists() else ""

    def test_overrides_are_one_shot_by_default(self):
        before = self.wf.read_bytes()
        cfg = self._run()
        # Live for THIS run...
        self.assertEqual(cfg.get("default_model"), SENTINEL_MODEL)
        # ...but never written to disk without the opt-in.
        self.assertNotIn(SENTINEL_MODEL, self._local_text())
        self.assertEqual(self.wf.read_bytes(), before)

    def test_overrides_persist_with_save_config(self):
        cfg = self._run(persist_overrides=True)
        self.assertEqual(cfg.get("default_model"), SENTINEL_MODEL)
        self.assertIn(SENTINEL_MODEL, self._local_text())
        # The tracked file still never changes; persistence targets the
        # local overlay only.
        self.assertNotIn(
            SENTINEL_MODEL, self.wf.read_text(encoding="utf-8")
        )

    def test_overrides_survive_an_auto_resolution_that_persists(self):
        # First run on a host that can run microsandbox: the tracked
        # static-only floor is promoted and that promotion is persisted.
        # The persisted config is reloaded from disk -- the one-shot
        # override must still be the live one in what comes back.
        caps = {
            "available_sandboxes": ["static-only", "microsandbox"],
            "recommended_sandbox": "microsandbox",
            "microsandbox_image": "mantis-sandbox:latest",
        }
        with patch("scripts.configure.detect_capabilities", return_value=caps):
            cfg = self._run()
        self.assertEqual(cfg.get("default_model"), SENTINEL_MODEL)
        self.assertEqual(cfg.get("sandbox", {}).get("type"), "microsandbox")
        local = json.loads(self._local_text())
        self.assertEqual(local["config"]["sandbox"]["type"], "microsandbox")
        self.assertNotIn(SENTINEL_MODEL, self._local_text())


class PathRootHardFailTest(unittest.TestCase):
    """An impossible --path-root exits 1 before any budget is spent."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_path_root_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(os.path.realpath(self._tmp.name))
        self.target_dir = self.tmp / "repo"
        self.target_dir.mkdir()
        self.target = self.target_dir / "app.py"
        self.target.write_text("def f():\n    return 1\n", encoding="utf-8")
        self.elsewhere = self.tmp / "unrelated"
        self.elsewhere.mkdir()

    def _invoke(self, path_root: str):
        # A dummy OpenAI-compatible endpoint: the launcher's preflight wants a
        # configured model before it hands over to the pipeline, and this test
        # must not depend on credentials being present. Nothing is called;
        # --path-root is rejected before the first LLM turn.
        env = {k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}
        env["OPENAI_API_KEY"] = "dummy"
        return subprocess.run(
            [
                sys.executable,
                str(Path(_REF_ROOT) / "main.py"),
                str(self.target),
                "--path-root", path_root,
                "--db", str(self.tmp / "kb.db"),
                "--model", "openai/nonexistent",
                "--api-base", "http://127.0.0.1:9",
                "--sandbox", "static-only",
                "--no-auto-configure",
            ],
            cwd=str(self.tmp),
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )

    def test_non_ancestor_dir_fails_closed(self):
        res = self._invoke(str(self.elsewhere))
        self.assertEqual(res.returncode, 1, res.stderr[-2000:])
        self.assertIn("--path-root", res.stderr)
        self.assertIn("not an ancestor", res.stderr)

    def test_file_path_root_fails_closed_with_distinct_reason(self):
        res = self._invoke(str(self.target))
        self.assertEqual(res.returncode, 1, res.stderr[-2000:])
        self.assertIn("--path-root", res.stderr)
        self.assertIn("not a directory", res.stderr)


class LauncherUsageExitTest(unittest.TestCase):
    """Usage errors exit 64 (EX_USAGE); exit 2 stays reserved for budget pause."""

    def _parse(self, argv):
        from scripts.launch import build_parser
        parser = build_parser()
        with contextlib.redirect_stderr(io.StringIO()), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                parser.parse_args(argv)
        return ctx.exception.code

    def test_unknown_flag_exits_64(self):
        self.assertEqual(self._parse(["t", "--definitely-not-a-flag"]), 64)

    def test_bad_choice_exits_64(self):
        self.assertEqual(self._parse(["t", "--sandbox", "bogus"]), 64)

    def test_help_still_exits_0(self):
        self.assertEqual(self._parse(["--help"]), 0)


class SaveConfigFlagTest(unittest.TestCase):
    """--save-config exists, defaulting to off."""

    def test_launcher_flag_defaults_off(self):
        from scripts.launch import build_parser
        args = build_parser().parse_args(["target"])
        self.assertFalse(args.save_config)
        args = build_parser().parse_args(["target", "--save-config"])
        self.assertTrue(args.save_config)


class OneParserTest(unittest.TestCase):
    """main.py and run.sh (scripts/launch.py) are the same command line.

    Two parsers drifted twice: --scan-mode and --exclude existed only on
    main.py, --token-budget and --max-time only on the launcher, and the
    pause banner printed a resume command one of them rejected.
    """

    @staticmethod
    def _flags(help_text: str) -> set:
        import re
        return set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", help_text))

    def _help(self, script: str) -> str:
        res = subprocess.run([sys.executable, str(Path(_REF_ROOT) / script), "--help"],
                             capture_output=True, text=True, timeout=120, cwd=_REF_ROOT)
        self.assertEqual(res.returncode, 0, res.stderr[-2000:])
        return res.stdout

    def test_main_has_no_parser_of_its_own(self):
        import main as mantis_main
        self.assertFalse(hasattr(mantis_main, "parse_cli_args"))

    def test_both_entry_points_accept_the_same_flags(self):
        main_flags = self._flags(self._help("main.py"))
        launcher_flags = self._flags(self._help("scripts/launch.py"))
        self.assertEqual(main_flags, launcher_flags)
        for flag in ("--scan-mode", "--yes", "--exclude", "--path-root", "--resume",
                     "--token-budget", "--max-time", "--objective", "--no-context-cache"):
            self.assertIn(flag, main_flags, flag)

    def test_main_usage_errors_exit_64_too(self):
        res = subprocess.run([sys.executable, str(Path(_REF_ROOT) / "main.py"), "t", "--definitely-not-a-flag"],
                             capture_output=True, text=True, timeout=120, cwd=_REF_ROOT)
        self.assertEqual(res.returncode, 64, res.stderr[-500:])


class SandboxDowngradeAndExitCodeTest(unittest.TestCase):
    """MANTIS_ALLOW_SANDBOX_DOWNGRADE=1 propagates static-only into pipeline,
    and exit code 2 is reserved strictly for budget pauses."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_downgrade_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(os.path.realpath(self._tmp.name))
        self.wf = self.tmp / "workflow.json"
        shutil.copyfile(Path(_REF_ROOT) / "workflow.json", self.wf)
        self.local = self.tmp / "workflow.local.json"
        self.local.write_text(
            json.dumps(
                {
                    "config": {
                        "default_model": "openai/nonexistent",
                        "api_base": "http://127.0.0.1:9",
                        "sandbox": {"type": "gvisor", "options": {}},
                    }
                }
            ),
            encoding="utf-8",
        )
        self.target = self.tmp / "app.py"
        self.target.write_text("def f():\n    return 1\n", encoding="utf-8")

    def test_run_launch_invalid_budget_returns_exit_usage_not_2(self):
        from scripts.launch import run_launch

        with contextlib.redirect_stderr(io.StringIO()):
            rc = run_launch(target=str(self.target), max_time="not-a-duration")
        self.assertEqual(rc, 64)

    def test_refuse_silent_downgrade_exits_1_not_2(self):
        from scripts.configure import _refuse_silent_downgrade

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MANTIS_ALLOW_SANDBOX_DOWNGRADE", None)
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as cm:
                    _refuse_silent_downgrade("sandbox unavailable")
        self.assertEqual(cm.exception.code, 1)

    def test_allow_sandbox_downgrade_propagates_static_only_to_pipeline_without_persisting(self):
        from scripts.launch import run_launch

        captured: dict = {}

        async def _fake_pipeline(**kwargs):
            captured.update(kwargs)
            return 0

        caps = {
            "available_sandboxes": ["static-only"],
            "recommended_sandbox": "static-only",
            "microsandbox_image": None,
        }
        env = {k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}
        env["OPENAI_API_KEY"] = "dummy"
        env["MANTIS_ALLOW_SANDBOX_DOWNGRADE"] = "1"
        with patch.dict(os.environ, env, clear=True), \
             patch("scripts.configure.detect_capabilities", return_value=caps), \
             patch("scripts.launch.pipeline", side_effect=_fake_pipeline), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            rc = run_launch(
                target=str(self.target),
                workflow_path=str(self.wf),
                model="openai/override-model",
                assume_yes=True,
            )

        self.assertEqual(rc, 0)
        sb_override = captured.get("sandbox_override")
        self.assertEqual(sb_override, {"type": "static-only", "options": {}})
        # Overlay on disk must still hold 'gvisor' (session-only downgrade).
        disk_overlay = json.loads(self.local.read_text(encoding="utf-8"))
        self.assertEqual(disk_overlay["config"]["sandbox"]["type"], "gvisor")

    def test_pipeline_direct_call_propagates_downgrade_and_runtime_sandbox_error_exits_1(self):
        import main as mantis_main

        caps = {
            "available_sandboxes": ["static-only"],
            "recommended_sandbox": "static-only",
            "microsandbox_image": None,
        }
        env = {k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}
        env["OPENAI_API_KEY"] = "dummy"

        # 1. With MANTIS_ALLOW_SANDBOX_DOWNGRADE=1, pipeline loads static-only
        # instead of reloading gvisor from workflow.local.json (aborted at work
        # plan confirmation so no LLM call is needed).
        env_ok = {**env, "MANTIS_ALLOW_SANDBOX_DOWNGRADE": "1"}
        seen_Configs: list = []
        orig_load = mantis_main.load_workflow_from_json

        def _spy_load(*a, **kw):
            wf, cfg = orig_load(*a, **kw)
            seen_Configs.append(cfg)
            return wf, cfg

        with patch.dict(os.environ, env_ok, clear=True), \
             patch("scripts.configure.detect_capabilities", return_value=caps), \
             patch.object(mantis_main, "load_workflow_from_json", side_effect=_spy_load), \
             patch.object(mantis_main, "_confirm_work_plan", return_value=False), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            rc = asyncio.run(
                mantis_main.pipeline(
                    scan_target=str(self.target),
                    workflow_path=str(self.wf),
                    db_override=str(self.tmp / "k.db"),
                )
            )
        self.assertEqual(rc, 0)
        self.assertEqual(seen_Configs[-1]["sandbox"]["type"], "static-only")

        # 2. If build_sandbox raises RuntimeError at preflight (e.g. auto_configure=False),
        # pipeline returns 1 (fatal error), never 2 (reserved for budget pause).
        with patch.dict(os.environ, env, clear=True), \
             patch.object(mantis_main, "_confirm_work_plan", return_value=True), \
             patch.object(mantis_main, "build_sandbox", side_effect=RuntimeError("boom")), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            rc_err = asyncio.run(
                mantis_main.pipeline(
                    scan_target=str(self.target),
                    workflow_path=str(self.wf),
                    db_override=str(self.tmp / "k2.db"),
                    auto_configure=False,
                )
            )
        self.assertEqual(rc_err, 1)


if __name__ == "__main__":
    unittest.main()

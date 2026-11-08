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

"""The repository's own GitHub hygiene: every workflow pins actions by commit,
declares least-privilege permissions, keeps untrusted context out of run
blocks, and Scorecard is present. Also the refresh's behaviour when the
repository forbids workflows from opening pull requests."""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parent.parent.parent
_WF = _REPO / ".github" / "workflows"
_SHA_PIN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$")


def _steps(spec):
    for job in spec.get("jobs", {}).values():
        for st in job.get("steps", []) or []:
            yield job, st


class WorkflowHygieneTest(unittest.TestCase):
    def setUp(self):
        self.workflows = {p.name: yaml.safe_load(p.read_text(encoding="utf-8")) for p in _WF.glob("*.yml")}
        self.assertLessEqual({"mantis-pr-scan.yml", "mantis-knowledge-refresh.yml", "scorecard.yml"},
                             set(self.workflows), sorted(self.workflows))

    def test_every_action_is_pinned_to_a_commit_with_its_version_noted(self):
        for name, spec in self.workflows.items():
            text = (_WF / name).read_text(encoding="utf-8")
            for _job, st in _steps(spec):
                uses = st.get("uses")
                if not uses or uses.startswith("./"):
                    continue
                self.assertRegex(uses, _SHA_PIN, f"{name}: {uses}")
                line = next(ln for ln in text.splitlines() if uses in ln)
                self.assertRegex(line, r"#\s*v\d", f"{name}: {uses} has no version comment")
        action = yaml.safe_load((_REPO / "action" / "action.yml").read_text(encoding="utf-8"))
        for st in action["runs"]["steps"]:
            if st.get("uses"):
                self.assertRegex(st["uses"], _SHA_PIN, st["uses"])

    def test_permissions_are_declared_and_minimal(self):
        for name, spec in self.workflows.items():
            self.assertIn("permissions", spec, f"{name}: no top-level permissions")
            top = spec["permissions"]
            if top != "read-all":
                self.assertIsInstance(top, dict, name)
                self.assertTrue(set(top.values()) <= {"read", "write"}, (name, top))
                for scope, level in top.items():
                    if level == "write":
                        self.assertEqual(scope, "id-token", f"{name}: top-level write on {scope}")
            for job_name, job in spec["jobs"].items():
                for scope, level in (job.get("permissions") or {}).items():
                    self.assertIn(level, ("read", "write", "none"), (name, job_name, scope))

    def test_no_personal_access_tokens_anywhere(self):
        for name in self.workflows:
            text = (_WF / name).read_text(encoding="utf-8")
            self.assertNotRegex(text, r"secrets\.[A-Z_]*(PAT|PERSONAL)", name)
            self.assertNotIn("repo_token", text, name)

    def test_no_pull_request_target_or_workflow_run_triggers(self):
        for name, spec in self.workflows.items():
            on = spec.get("on") or spec.get(True) or {}
            triggers = set(on.keys()) if isinstance(on, dict) else set(on if isinstance(on, list) else [on])
            self.assertFalse({"pull_request_target", "workflow_run"} & triggers, (name, triggers))

    def test_scorecard_is_present_and_shaped_right(self):
        sc = self.workflows["scorecard.yml"]
        self.assertEqual(sc["permissions"], "read-all")
        job = sc["jobs"]["analysis"]
        self.assertEqual(job["permissions"]["security-events"], "write")
        self.assertEqual(job["permissions"]["id-token"], "write")
        self.assertTrue(any("ossf/scorecard-action@" in (st.get("uses") or "") for st in job["steps"]))
        self.assertTrue(all(st.get("with", {}).get("persist-credentials") is False
                            for st in job["steps"] if "actions/checkout@" in (st.get("uses") or "")))

    def test_untrusted_context_never_reaches_run_directly(self):
        # Attacker-influenced event fields go through env:, never ${{ }} in run:.
        risky = re.compile(r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|commits|head_commit|pages)"
                           r"|github\.head_ref|inputs\.)")
        for name, spec in self.workflows.items():
            for _job, st in _steps(spec):
                run = st.get("run")
                if run:
                    self.assertIsNone(risky.search(run), (name, st.get("name")))


class RefreshOpensPullRequestsPolitelyTest(unittest.TestCase):
    def test_the_refresh_pushes_first_and_falls_back_to_a_link(self):
        spec = yaml.safe_load((_WF / "mantis-knowledge-refresh.yml").read_text(encoding="utf-8"))
        step = next(st for st in spec["jobs"]["refresh"]["steps"]
                    if st.get("name") == "Open a pull request if the knowledge changed")
        run = step["run"]
        self.assertLess(run.index("git -c"), run.index("gh pr create"), "push before the PR call")
        self.assertIn("gh pr view", run)
        self.assertIn("compare/main...", run)
        self.assertIn("::notice", run)
        self.assertIn("GITHUB_STEP_SUMMARY", run)
        # No `set -e` surprise: a refused PR must not fail the step after the push.
        tail = run.split("gh pr create", 1)[1]
        self.assertIn("else", tail)
        self.assertNotIn("exit 1", tail)

    def test_gitignore_allows_staging_mantis_knowledge_while_ignoring_runtime_state(self):
        import subprocess

        ignored = subprocess.run(
            ["git", "check-ignore", "-q", ".mantis/scratch.tmp"],
            cwd=_REPO,
            check=False,
        )
        self.assertEqual(ignored.returncode, 0, "runtime .mantis/* files must remain ignored")
        allowed = subprocess.run(
            ["git", "check-ignore", "-q", ".mantis/knowledge/manifest.json"],
            cwd=_REPO,
            check=False,
        )
        self.assertEqual(
            allowed.returncode,
            1,
            ".mantis/knowledge/ must not be gitignored so mantis-knowledge-refresh.yml can stage it",
        )

    def test_readme_builtin_tool_count_matches_registry(self):
        ref_root = str(_REPO / "reference")
        if ref_root not in sys.path:
            sys.path.insert(0, ref_root)
        from tools import TOOLS

        readme = (_REPO / "reference" / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"The {len(TOOLS)} built-in tools", readme)
        self.assertIn(f"The built-in {len(TOOLS)}", readme)


if __name__ == "__main__":
    unittest.main()

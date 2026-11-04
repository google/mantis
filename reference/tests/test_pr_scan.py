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

"""Tests for the pull-request scan driver behind the GitHub Action.

Nothing here reaches a model. The pipeline subprocess is replaced by a
python one-liner that writes the same spend rows and findings the real
scan would, so the gate, the fail-closed floors, the exit codes, and the
annotation rendering are exercised against a real git repository, a real
structural index, and a real findings database.
"""
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
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scripts.pr_scan as pr_scan  # noqa: E402


BASE_APP = """\
def helper(x):
    return x * 2


def handler(y):
    return helper(y) + 1
"""

# One added line (new-side line 2) inside helper's body.
HEAD_APP = """\
def helper(x):
    x = x + 0
    return x * 2


def handler(y):
    return helper(y) + 1
"""


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def make_pr_repo(tmp: str) -> tuple:
    """A repository with a base commit and a head commit that edits app.py,
    adds new.py and README.md, and deletes gone.py. Returns (repo, base_sha)."""
    repo = Path(tmp) / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    (repo / "app.py").write_text(BASE_APP, encoding="utf-8")
    (repo / "gone.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "app.py").write_text(HEAD_APP, encoding="utf-8")
    (repo / "new.py").write_text("def fresh():\n    return 1\n", encoding="utf-8")
    (repo / "README.md").write_text("# docs\n", encoding="utf-8")
    (repo / "gone.py").unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "head")
    return repo, base


# The stand-in for the pipeline: records the spend row the coverage ledger
# needs, optionally writes one finding, writes the spend report the driver
# asked for (unless told to leave none, as a killed process would), then
# exits with the given code. The driver's extra flags land in sys.argv.
_FAKE_SCAN = """\
import json, sys
sys.path.insert(0, {ref_root!r})
from core.cost import record_spend
from core.database import record_run, write_findings
argv = sys.argv[1:]
# The real _scan_cmd puts --model on the command line; this stand-in replaces
# _scan_cmd, so the model arrives through the template instead.
model = {model!r} or (argv[argv.index("--model") + 1] if "--model" in argv else "")
run = "run-pr-" + model.replace("/", "_") if model else "run-pr"
record_run({db!r}, run, model)
record_spend({db!r}, run, {target!r}, "deep", tokens=5)
finding = {finding!r}
if finding:
    write_findings({db!r}, {target!r}, [finding], run_id=run, status="")
if "--spend-report" in argv and not {no_report!r}:
    path = argv[argv.index("--spend-report") + 1]
    granted = int(argv[argv.index("--max-tokens") + 1]) if "--max-tokens" in argv else 0
    spent = {tokens!r} if {tokens!r} is not None else 1000
    cached = {cached!r}
    json.dump({{"run_id": "run-pr", "tokens": spent, "fresh_tokens": spent - cached,
               "cached_tokens": cached, "cache_discount": 1.0, "llm_calls": 3,
               "graph_steps": 4, "elapsed_seconds": 0.5, "max_tokens": granted,
               "max_llm_calls": 1, "pause_trigger": {pause_trigger!r},
               "nodes": {nodes!r}, "exit_code": {code}}}, open(path, "w"))
sys.exit({code})
"""

# The graph a finished single-file run walks; a run that stops early reports a prefix.
FULL_GRAPH = ["history", "structural_index", "architect", "threat_modeler", "planner",
              "researcher", "findings_gate", "reporter"]


def fake_scan(finding=None, code=0, tokens=None, cached=0, pause_trigger="",
              no_report=False, nodes=None):
    if nodes is None:
        nodes = FULL_GRAPH if code == 0 else FULL_GRAPH[:FULL_GRAPH.index("researcher") + 1]

    def _cmd(state, target, max_llm_calls, model):
        return [sys.executable, "-c", _FAKE_SCAN.format(
            ref_root=str(pr_scan._REF_ROOT), db=state.db_path, target=target,
            finding=finding, code=code, tokens=tokens, cached=cached,
            pause_trigger=pause_trigger, no_report=no_report, nodes=list(nodes),
            model=str(model or ""))]
    return _cmd


class DriverCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_pr_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo, self.base = make_pr_repo(self.tmp)
        self.out_json = Path(self.tmp) / "out" / "report.json"
        self.summary = Path(self.tmp) / "summary.md"
        self.gh_out = Path(self.tmp) / "gh_output"
        self.state_root = Path(self.tmp) / "state"
        self.env = {**os.environ, "GEMINI_API_KEY": "test-key"}

    def run_main(self, *extra, env=None, scan=None, daily=("--daily-token-budget", "0")):
        argv = ["--repo", str(self.repo), "--base", self.base,
                "--output-json", str(self.out_json),
                "--summary", str(self.summary),
                "--github-output", str(self.gh_out),
                "--state-dir", str(self.state_root),
                "--max-llm-calls", "1", *daily, *extra]
        buf = io.StringIO()
        cm = (mock.patch.object(pr_scan, "_scan_cmd", scan)
              if scan is not None else contextlib.nullcontext())
        with cm, contextlib.redirect_stdout(buf):
            rc = pr_scan.main(argv, env=self.env if env is None else env)
        return rc, buf.getvalue()

    def report(self):
        return json.loads(self.out_json.read_text(encoding="utf-8"))

    def commit_pr(self, files):
        """Adds another commit on top of HEAD with the given {path: content}
        (content None = symlink to the value in `links`), for adversarial
        pull-request shapes."""
        for rel, content in files.items():
            p = self.repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, tuple) and content[0] == "symlink":
                if p.exists() or p.is_symlink():
                    p.unlink()
                p.symlink_to(content[1])
            else:
                p.write_text(content, encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "adversarial")

    def scan_log(self):
        logs = list(self.state_root.glob("mantis-pr-scan-*/pr_scan.log"))
        self.assertEqual(len(logs), 1, logs)
        return logs[0].read_text(encoding="utf-8")


class TestChangeSet(DriverCase):
    def test_covers_edits_and_additions_and_reports_deletions(self):
        changed, diff, moves = pr_scan.pr_changes(self.repo, self.base)
        self.assertEqual(changed["app.py"], [2])
        self.assertIn("new.py", changed)
        self.assertIn("README.md", changed)
        self.assertNotIn("gone.py", changed, "nothing to scan in a deleted file")
        self.assertEqual(moves, {"renamed": {}, "deleted": ["gone.py"]},
                         "but the gate is told, so findings it knew there are not forgotten")
        self.assertIn("+++ b/app.py", diff)

    def test_a_rename_is_reported_as_old_to_new(self):
        (self.repo / "lib").mkdir()
        _git(self.repo, "mv", "app.py", "lib/app_v2.py")
        _git(self.repo, "commit", "-q", "-m", "move")
        changed, _diff, moves = pr_scan.pr_changes(self.repo, self.base)
        self.assertIn("lib/app_v2.py", changed)
        self.assertNotIn("app.py", changed)
        self.assertEqual(moves["renamed"], {"app.py": "lib/app_v2.py"})
        self.assertEqual(moves["deleted"], ["gone.py"])

    def test_a_type_change_is_a_change(self):
        # A symlink on the base that becomes a regular file with content on
        # the head is status T. It is scanned and gated like a modification.
        (self.repo / "link.py").symlink_to("new.py")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "link")
        base2 = _git(self.repo, "rev-parse", "HEAD")
        (self.repo / "link.py").unlink()
        (self.repo / "link.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "unlink")
        changed, _diff, _moves = pr_scan.pr_changes(self.repo, base2)
        self.assertIn("link.py", changed)

    def test_missing_or_unknown_base_is_infrastructure(self):
        with self.assertRaises(pr_scan.InfraError):
            pr_scan.pr_changes(self.repo, "")
        with self.assertRaises(pr_scan.InfraError):
            pr_scan.pr_changes(self.repo, "0" * 40)

    def test_revisions_are_validated_before_reaching_git(self):
        # A base or head is a SHA (or HEAD). Anything else -- in particular
        # anything that could be read as a git option -- is refused up front.
        for bad in ("--upload-pack=touch /tmp/pwned", "-", "main", "HEAD~1", "abc"):
            with self.subTest(base=bad), self.assertRaises(pr_scan.InfraError):
                pr_scan.pr_changes(self.repo, bad)
        with self.assertRaises(pr_scan.InfraError):
            pr_scan.pr_changes(self.repo, self.base, head="--output=/tmp/x")
        self.assertIn("app.py", pr_scan.pr_changes(self.repo, self.base, head="HEAD")[0])

    def test_gitattributes_cannot_hide_a_changed_file(self):
        # `evil.py -diff` makes git render the file as "Binary files differ"
        # with no +++ header or hunks. The file must still be in the change
        # set (line-less), so it is scanned and gated fail-closed.
        self.commit_pr({".gitattributes": "evil.py -diff\n",
                        "evil.py": "import os\nos.system(input())\n"})
        changed, diff, _ = pr_scan.pr_changes(self.repo, self.base)
        self.assertIn("evil.py", changed)
        self.assertEqual(changed["evil.py"], [])
        self.assertNotIn("+++ b/evil.py", diff)

    def test_binary_detection_cannot_hide_a_changed_file(self):
        self.commit_pr({"blob.py": "x = 1\n\x00\nimport os\n"})
        changed, _, _ = pr_scan.pr_changes(self.repo, self.base)
        self.assertIn("blob.py", changed)

    def test_content_that_looks_like_a_diff_header_does_not_rename_the_section(self):
        # A new file whose first line is "++ b/README.md" appears in the diff
        # as "+++ b/README.md" inside the hunk. It is content, not a header.
        self.commit_pr({"evil.py": "++ b/README.md\nimport os\nos.system(input())\n"})
        changed, diff, _ = pr_scan.pr_changes(self.repo, self.base)
        self.assertEqual(changed["evil.py"], [1, 2, 3])
        self.assertEqual(changed["README.md"], [1])  # README's own one-line change only
        kept = pr_scan.filter_diff(diff, {"evil.py", "app.py", "new.py"})
        self.assertIn("++ b/README.md\n", kept)       # the content line survives
        self.assertNotIn("+++ b/README.md\n@@", kept)  # README's real section is gone
        self.assertEqual(pr_scan.parse_unified_diff(kept)["evil.py"], [1, 2, 3])


class TestIgnoreAndFilter(unittest.TestCase):
    def test_default_patterns_cover_docs_and_images(self):
        pats = pr_scan.parse_ignore(None)
        self.assertTrue(pr_scan.is_ignored("docs/guide.md", pats))
        self.assertTrue(pr_scan.is_ignored("img/logo.png", pats))
        self.assertFalse(pr_scan.is_ignored("src/app.py", pats))
        self.assertFalse(pr_scan.is_ignored("Dockerfile", pats))
        # Dependency manifests and lockfiles are supply-chain changes: scanned.
        for manifest in ("requirements.txt", "constraints.txt", "go.sum", "yarn.lock",
                         "Cargo.lock", "Gemfile.lock", "CMakeLists.txt"):
            self.assertFalse(pr_scan.is_ignored(manifest, pats), manifest)

    def test_explicit_patterns_replace_defaults(self):
        pats = pr_scan.parse_ignore("vendor/*, *.gen.go")
        self.assertTrue(pr_scan.is_ignored("vendor/x.py", pats))
        self.assertTrue(pr_scan.is_ignored("a/b/types.gen.go", pats))
        self.assertFalse(pr_scan.is_ignored("README.md", pats))
        self.assertEqual(pr_scan.parse_ignore(""), [])

    def test_filter_diff_drops_whole_sections(self):
        diff = (
            "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1 +1,2 @@\n one\n+two\n"
            "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n"
            "@@ -1 +1,2 @@\n a\n+b\n"
        )
        kept = pr_scan.filter_diff(diff, {"x.py"})
        self.assertIn("+++ b/x.py", kept)
        self.assertNotIn("README.md", kept)
        self.assertEqual(pr_scan.parse_unified_diff(kept), {"x.py": [2]})


class TestPreflightAndCommand(unittest.TestCase):
    _BASE_ENV = {"PATH": os.environ.get("PATH", "")}

    def _preflight(self, env, model="", api_base=""):
        # The host may hold real Google credentials; the preflight must only
        # see the environment a runner would have, so ADC is forced absent.
        with mock.patch("google.auth.default", side_effect=Exception("no ADC")):
            return pr_scan.credential_preflight({**self._BASE_ENV, **env},
                                                api_base=api_base, model=model)

    def test_gemini_api_route_needs_its_key(self):
        self.assertIsNone(self._preflight({"GEMINI_API_KEY": "k"}, "gemini/gemini-3.8-flash"))
        reason = self._preflight({}, "gemini/gemini-3.8-flash")
        self.assertIn("GEMINI_API_KEY", reason)

    def test_anthropic_route_needs_its_key(self):
        self.assertIsNone(self._preflight({"ANTHROPIC_API_KEY": "k"}, "anthropic/claude-opus-5"))
        reason = self._preflight({}, "anthropic/claude-opus-5")
        self.assertIn("ANTHROPIC_API_KEY", reason)

    def test_openai_compatible_endpoint_skips_the_check(self):
        self.assertIsNone(self._preflight({}, "openai/glm-5.3", api_base="http://x/v1"))
        reason = self._preflight({}, "openai/glm-5.3")
        self.assertIn("OPENAI_API_KEY", reason)

    def test_vertex_route_refuses_an_api_base_off_google(self):
        # The Agent Platform route sends the job's Google credential as a
        # bearer token to api_base. An api_base on another host would hand
        # that credential to whoever runs it.
        reason = self._preflight({"GOOGLE_CLOUD_PROJECT": "p"}, "vertex_ai/gemini-3.8-flash",
                                 api_base="https://evil.example/v1")
        self.assertIn("googleapis.com", reason)
        self.assertIn("credential", reason)
        self.assertIsNone(self._preflight({"GOOGLE_CLOUD_PROJECT": "p"}, "vertex_ai/gemini-3.8-flash",
                                          api_base="https://us-central1-aiplatform.googleapis.com"))
        self.assertIsNone(self._preflight({"GOOGLE_CLOUD_PROJECT": "p"}, "vertex_ai/gemini-3.8-flash",
                                          api_base="https://aiplatform.googleapis.com/v1"))
        # Look-alikes are not Google.
        for host in ("https://googleapis.com.evil.example", "https://evilgoogleapis.com",
                     "https://user@googleapis.com@evil.example/", "not a url"):
            self.assertIsNotNone(self._preflight({"GOOGLE_CLOUD_PROJECT": "p"},
                                                 "vertex_ai/gemini-3.8-flash", api_base=host), host)

    def test_vertex_route_needs_a_project(self):
        self.assertIsNone(self._preflight({"GOOGLE_CLOUD_PROJECT": "p"}, "vertex_ai/gemini-3.8-flash"))
        self.assertIsNone(self._preflight({"VERTEXAI_PROJECT": "p"}, "vertex_ai/claude-opus-5"))
        reason = self._preflight({}, "vertex_ai/claude-opus-5")
        self.assertIn("GOOGLE_CLOUD_PROJECT", reason)

    def test_bare_names_route_by_credentials(self):
        # A bare gemini-* id goes to the Gemini API when its key is present and
        # to Vertex otherwise, exactly as the pipeline resolves it.
        self.assertIsNone(self._preflight({"GEMINI_API_KEY": "k"}, "gemini-3.8-flash"))
        self.assertIsNone(self._preflight({"GOOGLE_CLOUD_PROJECT": "p"}, "gemini-3.8-flash"))
        reason = self._preflight({}, "gemini-3.8-flash")
        self.assertIsNotNone(reason)

    def test_preflight_leaves_the_process_environment_alone(self):
        before = dict(os.environ)
        self._preflight({"ANTHROPIC_API_KEY": "k"}, "anthropic/claude-opus-5")
        self.assertEqual(dict(os.environ), before)

    def test_scan_command_pins_static_sandbox(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        state = pr_scan.MantisState(tmp)
        cmd = pr_scan.scan_command(state, "a.py", 7, "some-model", api_base="http://x/v1")
        self.assertEqual(cmd[cmd.index("--sandbox") + 1], "static-only")
        self.assertEqual(cmd[cmd.index("--path-root") + 1], str(state.repo))
        self.assertEqual(cmd[cmd.index("--max-llm-calls") + 1], "7")
        self.assertEqual(cmd[cmd.index("--model") + 1], "some-model")
        self.assertEqual(cmd[cmd.index("--api-base") + 1], "http://x/v1")
        self.assertIn("--yes", cmd)


class TestRepoRootTarget(unittest.IsolatedAsyncioTestCase):
    """Each changed file is scanned with the repository as the target and the
    file as the run's one changed file, so the campaign can read the code
    around it in other packages. The MCP scan_change path keeps its file
    target."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_pr_root_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = Path(self.tmp, "repo").resolve()
        (self.repo / "cmd" / "a").mkdir(parents=True)
        (self.repo / "internal" / "b").mkdir(parents=True)
        (self.repo / "cmd" / "a" / "main.go").write_text("package main\n", encoding="utf-8")
        (self.repo / "internal" / "b" / "policy.go").write_text("package b // POLICY-B\n", encoding="utf-8")
        self.state = pr_scan.MantisState(str(self.repo))

    @staticmethod
    def _argv(cmd):
        from scripts.launch import build_parser

        return build_parser().parse_args(cmd[2:])

    def test_scan_command_targets_the_repo_with_the_file_listed(self):
        cmd = pr_scan.scan_command(self.state, "cmd/a/main.go", 7, "m")
        args = self._argv(cmd)
        self.assertEqual(args.target, str(self.repo))
        self.assertEqual(args.scan_mode, "changed")
        self.assertEqual(args.changed_files, ["cmd/a/main.go"])
        self.assertEqual(args.path_root, str(self.repo))
        self.assertEqual(args.sandbox, "static-only")
        # A pull-request file named like a flag is still a value.
        self.assertEqual(self._argv(pr_scan.scan_command(self.state, "-x.py", 7, "m")).changed_files, ["-x.py"])

    def test_the_mcp_scan_command_is_unchanged(self):
        cmd = pr_scan._scan_cmd(self.state, str(self.repo / "cmd" / "a" / "main.go"), 7, "m")
        self.assertEqual(cmd[2], str(self.repo / "cmd" / "a" / "main.go"))
        self.assertNotIn("--scan-mode", cmd)
        self.assertFalse(any(c.startswith("--changed-files") for c in cmd))

    async def test_a_scan_reads_across_packages(self):
        """Counterfactual for the file target: pr_scan's own argv, resolved the
        way the pipeline resolves it (main.py: targets, jail at the target
        root, target_file the campaign), then read_file on a file in another
        package. With a file target the jail is the file's directory and the
        single-file gate refuses the read."""
        import main
        from core.context import RunContext, current_run_context
        from core.sandbox import build_sandbox
        import tools.research_tools as rt

        args = self._argv(pr_scan.scan_command(self.state, "cmd/a/main.go", 7, "m"))
        target = Path(args.target)
        discovered = main.discover_files(target)
        listed = None
        if args.changed_files is not None:
            listed, outside, _not_source = main._listed_changed_files(target, args.changed_files, discovered)
            self.assertEqual(outside, [])
        config = {"scan_mode": args.scan_mode or "auto", "surveyor": {"min_source_files": 1000}}
        targets, _astm, mode = main.resolve_scan_targets(
            target, config, discovered, db_path="", scope_out={}, changed_files_override=listed)
        scan_item = targets[0]
        jail_dir = str(target.parent) if target.is_file() else str(target)
        sandbox = build_sandbox({"type": "static-only"}, str(target) if target.is_dir() else scan_item)
        ctx = RunContext(jail_dir=jail_dir, db_path="", target_file=scan_item, run_id="run-pr",
                         sandbox=sandbox, active_node="researcher")
        token = current_run_context.set(ctx)
        try:
            out = await rt.read_file("internal/b/policy.go")
            own = await rt.read_file("cmd/a/main.go")
        finally:
            current_run_context.reset(token)
        self.assertNotIn("Permission denied", out)
        self.assertIn("POLICY-B", out)
        self.assertIn("package main", own)
        self.assertEqual(mode, "changed")
        self.assertEqual(scan_item, str(self.repo / "cmd" / "a"), "the campaign is the file's own directory")


class TestSelection(DriverCase):
    def test_cap_is_deterministic_and_names_the_rest(self):
        state = pr_scan.MantisState(str(self.repo))
        changed = {"app.py": [2], "new.py": [1], "zzz/outside/../../etc": []}
        rels, skipped = pr_scan.select_scan_files(state, changed, 1)
        self.assertEqual(rels, ["app.py"])
        self.assertEqual(skipped, ["new.py"])
        rels, skipped = pr_scan.select_scan_files(state, changed, 0)
        self.assertEqual((rels, skipped), (["app.py", "new.py"], []))


class TestAnnotations(unittest.TestCase):
    def test_escaping_blocks_command_smuggling(self):
        line = pr_scan.annotation(
            "warning", "a\nb::error::pwned %", file="p,q:r.py", line=3, title="t:1,2")
        self.assertTrue(line.startswith("::warning file=p%2Cq%3Ar.py,line=3,title=t%3A1%2C2::"))
        self.assertIn("a%0Ab::error::pwned %25", line)
        # One physical line: a title or message cannot start a second command.
        self.assertEqual(line.count("\n"), 0)

    def _report(self, findings, fail_on="none"):
        return {"verdict": "REVIEW", "findings": findings, "fail_on": fail_on,
                "scan": {"results": [], "skipped": []}}

    def test_levels_follow_relationship_and_fail_on(self):
        hi = {"title": "sqli", "severity": "HIGH", "status": "reported",
              "filepath": "a.py", "line_numbers": [4]}
        direct = dict(hi, relationship="direct")
        elsewhere = dict(hi, relationship="unrelated_in_file")
        caller = dict(hi, relationship="caller_radius")
        lines = pr_scan.render_annotations(self._report([direct, elsewhere, caller]))
        self.assertTrue(lines[0].startswith("::warning file=a.py,line=4"))
        self.assertTrue(lines[1].startswith("::notice "))
        self.assertTrue(lines[2].startswith("::notice "))
        strict = pr_scan.render_annotations(self._report([direct], fail_on="block"))
        self.assertTrue(strict[0].startswith("::error file=a.py,line=4"))

    def test_per_level_cap_points_to_summary(self):
        many = [{"title": f"f{i}", "severity": "MEDIUM", "status": "reported",
                 "filepath": "a.py", "line_numbers": [i + 1], "relationship": "direct"}
                for i in range(13)]
        lines = pr_scan.render_annotations(self._report(many))
        warnings = [l for l in lines if l.startswith("::warning")]
        self.assertEqual(len(warnings), pr_scan.MAX_ANNOTATIONS_PER_LEVEL + 1)
        self.assertIn("3 more warning-level", warnings[-1])


class TestEndToEnd(DriverCase):
    """main() over a real repo with the pipeline subprocess stood in for."""

    def test_clean_scan_passes_and_writes_everything(self):
        rc, out = self.run_main(scan=fake_scan())
        self.assertEqual(rc, pr_scan.EXIT_OK, out)
        rep = self.report()
        self.assertEqual(rep["verdict"], "PASS", rep["reasons"])
        self.assertEqual(rep["findings"], [])
        self.assertEqual(sorted(rep["scan"]["files"]), ["app.py", "new.py"])
        self.assertEqual(rep["ignored"], ["README.md"])
        self.assertTrue(all(r["status"] == "done" for r in rep["scan"]["results"]))
        self.assertNotIn("::warning", out)
        self.assertNotIn("::error", out)
        self.assertIn("verdict=PASS", self.gh_out.read_text(encoding="utf-8"))
        summary = self.summary.read_text(encoding="utf-8")
        self.assertIn("Mantis PR scan: PASS", summary)
        self.assertIn("`README.md`", summary)
        # The blast radius saw the edit inside helper(): the index was
        # restored to repo-rooted after the per-file scans.
        self.assertTrue(any("helper" in str(b.get("function")) for b in rep["blast_radius"]),
                        rep["blast_radius"])

    def test_direct_high_finding_is_advisory_by_default_and_fails_on_block(self):
        finding = {"title": "Injection in helper", "description": "d",
                   "severity": "HIGH", "filepath": "app.py", "line_numbers": [2]}
        rc, out = self.run_main(scan=fake_scan(finding))
        self.assertEqual(rc, pr_scan.EXIT_OK)
        rep = self.report()
        self.assertEqual(rep["verdict"], "BLOCK")
        self.assertEqual(rep["findings"][0]["relationship"], "direct")
        self.assertIn("::warning file=app.py,line=2,title=Mantis%3A HIGH::", out)
        self.assertNotIn("::error", out)

        rc, out = self.run_main("--fail-on", "block", scan=fake_scan(finding))
        self.assertEqual(rc, pr_scan.EXIT_FAILED_GATE)
        self.assertIn("::error file=app.py,line=2", out)

    def test_same_file_debt_outside_change_is_review_not_block(self):
        # handler() lives at lines 6-7 of HEAD_APP: outside helper's span and
        # past the +/-3 window around changed line 2.
        finding = {"title": "Old debt in handler", "description": "d",
                   "severity": "CRITICAL", "filepath": "app.py", "line_numbers": [7]}
        rc, out = self.run_main("--fail-on", "block", scan=fake_scan(finding))
        self.assertEqual(rc, pr_scan.EXIT_OK, out)
        rep = self.report()
        self.assertEqual(rep["verdict"], "REVIEW")
        self.assertEqual(rep["findings"][0]["relationship"], "unrelated_in_file")
        self.assertIn("::notice ", out)

    def test_failed_scan_is_a_coverage_gap_that_fails_only_when_asked(self):
        rc, out = self.run_main(scan=fake_scan(code=1))
        self.assertEqual(rc, pr_scan.EXIT_OK)
        rep = self.report()
        self.assertEqual(rep["verdict"], "REVIEW", "a person should know")
        self.assertEqual(rep["findings_verdict"], "PASS", "the findings said nothing")
        self.assertEqual(rep["coverage"]["status"], "none")
        self.assertTrue(any("finished with errors" in r for r in rep["reasons"]), rep["reasons"])
        self.assertIn("title=Mantis%3A unscanned", out)
        self.assertIn("fail-closed` is off", self.summary.read_text(encoding="utf-8"))
        # fail-on judges findings only: a broken scanner does not fail the job.
        rc, _ = self.run_main("--fail-on", "review", scan=fake_scan(code=1))
        self.assertEqual(rc, pr_scan.EXIT_OK)
        rc, _ = self.run_main("--fail-on", "block", scan=fake_scan(code=1))
        self.assertEqual(rc, pr_scan.EXIT_OK)
        # fail-closed judges coverage, whatever fail-on says.
        rc, _ = self.run_main("--fail-closed", scan=fake_scan(code=1))
        self.assertEqual(rc, pr_scan.EXIT_FAILED_GATE)
        self.assertTrue(self.report()["fail_closed"])
        self.assertIn("fail-closed` is on", self.summary.read_text(encoding="utf-8"))

    def test_a_real_review_finding_still_fails_under_fail_on_review(self):
        low = {"title": "Weak hash", "severity": "LOW", "status": "confirmed",
               "description": "md5", "filepath": "app.py", "line_numbers": [2], "cwe": "CWE-328"}
        rc, _ = self.run_main("--fail-on", "review", scan=fake_scan(finding=low))
        self.assertEqual(rc, pr_scan.EXIT_FAILED_GATE)
        rep = self.report()
        self.assertEqual(rep["findings_verdict"], "REVIEW")
        self.assertEqual(rep["coverage"]["status"], "complete")
        rc, _ = self.run_main("--fail-on", "block", scan=fake_scan(finding=low))
        self.assertEqual(rc, pr_scan.EXIT_OK)

    def test_budget_pause_is_partial_coverage_not_a_failure(self):
        # The pipeline exits 2 when it hits a ceiling: findings so far are
        # stored, nothing broke, but the file is not fully audited. That is
        # REVIEW with a reason naming the ceiling it hit -- not an error, and
        # not a PASS. The trigger comes from the pipeline's own spend report,
        # never from the log.
        rc, out = self.run_main("--fail-on", "block",
                                scan=fake_scan(code=2, pause_trigger="llm_calls_limit"))
        rep = self.report()
        self.assertTrue(all(r["status"] == "paused_at_budget" for r in rep["scan"]["results"]))
        self.assertEqual(rep["verdict"], "REVIEW", rep["reasons"])
        self.assertEqual(rep["coverage"]["status"], "none")
        self.assertTrue(any("LLM call ceiling" in r for r in rep["reasons"]), rep["reasons"])
        self.assertTrue(any("max-llm-calls" in a for a in rep["next_actions"]))
        self.assertNotIn("unscanned", out)
        self.assertEqual(rc, pr_scan.EXIT_OK)
        rc, _ = self.run_main("--fail-on", "review",
                              scan=fake_scan(code=2, pause_trigger="token_budget"))
        rep = self.report()
        self.assertTrue(any("run token budget" in r for r in rep["reasons"]), rep["reasons"])
        self.assertTrue(any("max-tokens" in a for a in rep["next_actions"]))
        self.assertEqual(rc, pr_scan.EXIT_OK, "partial coverage is not a finding")
        rc, _ = self.run_main("--fail-closed",
                              scan=fake_scan(code=2, pause_trigger="token_budget"))
        self.assertEqual(rc, pr_scan.EXIT_FAILED_GATE)
        # No account at all (the process died after deciding to pause): the
        # reason stays honest about not knowing which ceiling.
        rc, _ = self.run_main(scan=fake_scan(code=2, no_report=True))
        rep = self.report()
        self.assertTrue(any("a pipeline ceiling" in r for r in rep["reasons"]), rep["reasons"])
        # An account with no trigger is the pipeline's other exit 2, a
        # configuration error before any campaign ran: a failed scan.
        rc, _ = self.run_main(scan=fake_scan(code=2, pause_trigger=""))
        rep = self.report()
        self.assertTrue(all(r["status"] == "finished_with_errors" for r in rep["scan"]["results"]))
        self.assertEqual(rep["verdict"], "REVIEW")

    def test_timeout_floors_review(self):
        sleeper = lambda *a, **k: [sys.executable, "-c", "import time; time.sleep(5)"]
        rc, _ = self.run_main("--per-file-timeout", "0.5", "--max-files", "1", scan=sleeper)
        rep = self.report()
        self.assertEqual(rep["scan"]["results"][0]["status"], "timed_out")
        self.assertEqual(rep["verdict"], "REVIEW")
        self.assertEqual(rc, pr_scan.EXIT_OK)

    def test_max_files_cap_names_the_unscanned(self):
        rc, out = self.run_main("--max-files", "1", scan=fake_scan())
        rep = self.report()
        self.assertEqual(rep["scan"]["files"], ["app.py"])
        self.assertEqual(rep["scan"]["skipped"], ["new.py"])
        self.assertEqual(rep["verdict"], "REVIEW")
        self.assertTrue(any("new.py" in r for r in rep["reasons"]))
        self.assertIn("max-files cap", out)

    def test_all_ignored_passes_without_scanning(self):
        rc, out = self.run_main("--ignore", "*.py,*.md", scan=fake_scan())
        rep = self.report()
        self.assertEqual(rc, pr_scan.EXIT_OK)
        self.assertEqual(rep["verdict"], "PASS")
        self.assertEqual(rep["scan"]["results"], [])
        self.assertEqual(sorted(rep["ignored"]), ["README.md", "app.py", "new.py"])

    def test_missing_credentials_is_a_setup_failure_and_writes_nothing(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("ANTHROPIC_API_KEY", "GOOGLE_CLOUD_PROJECT", "VERTEXAI_PROJECT")}
        with mock.patch("google.auth.default", side_effect=Exception("no ADC")):
            rc, out = self.run_main("--model", "anthropic/claude-opus-5", env=env)
        self.assertEqual(rc, pr_scan.EXIT_OK, "fail-open: a setup failure does not fail the job")
        self.assertIn("::warning title=Mantis%3A cannot scan::", out)
        self.assertIn("ANTHROPIC_API_KEY", out)
        self.assertFalse((self.repo / ".mantis").exists())
        self.assertFalse(self.state_root.exists())
        self.assertFalse(self.out_json.exists())
        self.assertIn("not run", self.summary.read_text(encoding="utf-8"))
        self.assertIn("verdict=NOT_RUN", self.gh_out.read_text(encoding="utf-8"))
        with mock.patch("google.auth.default", side_effect=Exception("no ADC")):
            rc, out = self.run_main("--model", "anthropic/claude-opus-5", "--fail-closed", env=env)
        self.assertEqual(rc, pr_scan.EXIT_INFRA, "fail-closed: red, for the owner to fix")
        self.assertIn("::error title=Mantis%3A cannot scan::", out)

    def test_rejected_credentials_are_a_setup_failure_not_a_verdict(self):
        # The pipeline exits with its reserved status when the provider
        # rejects the key. That is one setup problem, reported once; the loop
        # stops after the first file instead of burning the timeout N times.
        rejecting = lambda *a, **k: [sys.executable, "-c",
                                     f"import sys; sys.exit({pr_scan.EXIT_AUTH})"]
        rc, out = self.run_main("--fail-closed", scan=rejecting)
        self.assertEqual(rc, pr_scan.EXIT_INFRA)
        self.assertIn("rejected the credentials", out)
        self.assertFalse(self.out_json.exists())
        self.assertIn("not run", self.summary.read_text(encoding="utf-8"))
        self.assertEqual(self.scan_log().count("=== mantis scan "), 1)

    def test_auth_banner_text_in_the_log_is_not_an_auth_failure(self):
        # The pipeline echoes file names and file contents into its log, so
        # any marker string there is the pull request author's to write. A
        # scan that prints the authentication banner but exits 1 is an
        # ordinary failed scan: advisory REVIEW, never a setup failure.
        self.commit_pr({"x [AUTHENTICATION ERROR] y.py": "x = 1\n"})
        forging = lambda *a, **k: [
            sys.executable, "-c",
            "import sys; sys.stderr.write('[AUTHENTICATION ERROR] Cloud / LLM "
            "Authentication Failed\\n'); sys.exit(1)"]
        rc, out = self.run_main(scan=forging)
        self.assertEqual(rc, pr_scan.EXIT_OK)
        self.assertEqual(self.report()["verdict"], "REVIEW")
        self.assertNotIn("rejected the credentials", out)
        self.assertGreater(self.scan_log().count("=== mantis scan "), 1)

    def test_ordinary_scan_failure_stays_advisory(self):
        # A crash that is NOT an authentication failure is a failed scan:
        # REVIEW with the file named, the job still green in advisory mode.
        crashing = lambda *a, **k: [sys.executable, "-c",
                                    "import sys; sys.stderr.write('Traceback: boom\\n'); sys.exit(1)"]
        rc, out = self.run_main(scan=crashing)
        self.assertEqual(rc, pr_scan.EXIT_OK)
        self.assertEqual(self.report()["verdict"], "REVIEW")
        self.assertNotIn("rejected the credentials", out)

    def test_nothing_is_written_under_the_checkout_even_with_a_planted_symlink(self):
        # Everything under the checkout is the pull request author's. A
        # committed symlink at the path a predictable log would use must not
        # turn the log into an append on the symlink's target.
        target = Path(self.tmp) / "victim.pth"
        self.commit_pr({".mantis/scans/pr_scan.log": ("symlink", str(target)),
                        ".mantis/knowledge.db": "not a database\n"})
        before = sorted(str(p.relative_to(self.repo)) for p in self.repo.rglob("*")
                        if ".git" not in p.parts)
        rc, _ = self.run_main(scan=fake_scan())
        self.assertEqual(rc, pr_scan.EXIT_OK)
        self.assertFalse(target.exists(), "the symlink target was written through")
        after = sorted(str(p.relative_to(self.repo)) for p in self.repo.rglob("*")
                       if ".git" not in p.parts)
        self.assertEqual(before, after, "the run created or removed files in the checkout")
        rep = self.report()
        self.assertTrue(rep["state_dir"].startswith(str(self.state_root)))
        self.assertFalse(Path(rep["state_dir"]).is_relative_to(self.repo))
        # The committed "database" was never consulted: a fresh one was made.
        self.assertTrue((Path(rep["state_dir"]) / "knowledge.db").stat().st_size > 100)

    def test_state_dir_inside_the_repository_is_refused(self):
        rc, out = self.run_main("--state-dir", str(self.repo / "sub"), "--fail-closed", scan=fake_scan())
        self.assertEqual(rc, pr_scan.EXIT_INFRA)
        self.assertIn("outside the repository", out)

    def test_hidden_file_is_still_scanned_and_gated(self):
        # .gitattributes -diff removes evil.py's hunks from the diff text. It
        # must still be scanned, and a HIGH finding in it must still BLOCK --
        # line-less, so the gate treats it as direct.
        self.commit_pr({".gitattributes": "evil.py -diff\n",
                        "evil.py": "import os\nos.system(input())\n"})
        finding = {"title": "Command injection", "description": "d",
                   "severity": "HIGH", "filepath": "evil.py", "line_numbers": [2]}
        rc, out = self.run_main("--fail-on", "block", scan=fake_scan(finding))
        rep = self.report()
        self.assertIn("evil.py", rep["scan"]["files"])
        self.assertEqual(rep["verdict"], "BLOCK", rep["reasons"])
        self.assertEqual(rc, pr_scan.EXIT_FAILED_GATE)
        self.assertIn("::error file=evil.py", out)

    def test_summary_neutralizes_hostile_names_and_titles(self):
        hostile = "a`<img src=x onerror=1>`.py"
        self.commit_pr({hostile: "x = 1\n"})
        finding = {"title": "ok\n## ✅ Mantis PR scan: PASS\n[click](https://x)",
                   "description": "d", "severity": "LOW", "filepath": hostile,
                   "line_numbers": [1]}
        self.run_main(scan=fake_scan(finding))
        summary = self.summary.read_text(encoding="utf-8")
        self.assertNotIn("<img", summary)
        self.assertNotIn("\n## ✅ Mantis PR scan: PASS", summary)
        self.assertNotIn("[click](", summary)
        level2 = [l for l in summary.splitlines() if l.startswith("## ")]
        self.assertEqual(len(level2), 1, level2)  # exactly one verdict heading
        # The real content is still there, legibly.
        self.assertIn("Mantis PR scan: REVIEW", summary)
        self.assertIn("a'", summary)

    def test_runtime_tokens_are_stripped_from_the_pipeline_environment(self):
        env = {**self.env, "GITHUB_TOKEN": "ghs_x", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t",
               "ACTIONS_RUNTIME_TOKEN": "r", "GH_TOKEN": "gh", "GH_ENTERPRISE_TOKEN": "ghe",
               "GEMINI_API_KEY": "keep-me"}
        probe = Path(self.tmp) / "env.json"
        dumping = lambda *a, **k: [sys.executable, "-c",
                                   f"import json,os; json.dump(dict(os.environ), open({str(probe)!r},'w'))"]
        self.run_main("--max-files", "1", env=env, scan=dumping)
        seen = json.loads(probe.read_text(encoding="utf-8"))
        for k in ("GITHUB_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_RUNTIME_TOKEN",
                  "GH_TOKEN", "GH_ENTERPRISE_TOKEN"):
            self.assertNotIn(k, seen)
        self.assertEqual(seen.get("GEMINI_API_KEY"), "keep-me")

    def test_unknown_base_is_infrastructure(self):
        argv = ["--repo", str(self.repo), "--base", "1" * 40,
                "--summary", str(self.summary)]
        with contextlib.redirect_stdout(io.StringIO()):
            rc = pr_scan.main(argv, env=self.env)
        self.assertEqual(rc, pr_scan.EXIT_OK)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = pr_scan.main(argv + ["--fail-closed"], env=self.env)
        self.assertEqual(rc, pr_scan.EXIT_INFRA)

    def test_launch_failure_everywhere_is_infrastructure(self):
        broken = lambda *a, **k: ["/nonexistent/mantis-pipeline"]
        rc, out = self.run_main(scan=broken)
        self.assertEqual(rc, pr_scan.EXIT_OK)
        self.assertIn("failed to launch", out)
        rc, out = self.run_main("--fail-closed", scan=broken)
        self.assertEqual(rc, pr_scan.EXIT_INFRA)


class TestTimeoutFollowsProgress(DriverCase):
    """A scan still writing at its timeout is slow, not hung: it runs on,
    within bounds. A silent one is killed at its timeout, as before."""

    def test_a_scan_still_writing_at_its_timeout_finishes(self):
        writer = lambda *a, **k: [sys.executable, "-u", "-c",
                                  "import time\nfor i in range(26):\n"
                                  "    print('turn', i, flush=True)\n    time.sleep(0.1)\n"]
        self.run_main("--per-file-timeout", "2", "--max-files", "1", scan=writer)
        r = self.report()["scan"]["results"][0]
        log = self.scan_log()
        self.assertEqual(r["status"], "done", log[-800:])
        self.assertIn("still working at 2s", log)
        self.assertNotIn("timed out", log)

    def test_a_scan_that_never_stops_writing_still_ends(self):
        forever = lambda *a, **k: [sys.executable, "-u", "-c",
                                   "import time\nwhile True:\n"
                                   "    print('x', flush=True)\n    time.sleep(0.05)\n"]
        self.run_main("--per-file-timeout", "0.5", "--max-files", "1", scan=forever)
        self.assertEqual(self.report()["scan"]["results"][0]["status"], "timed_out")
        self.assertIn("(its limit)", self.scan_log())

    def test_a_wait_that_fails_kills_the_scan_and_is_charged_as_a_timeout(self):
        sleeper = lambda *a, **k: [sys.executable, "-c", "import time; time.sleep(30)"]
        with mock.patch.object(pr_scan, "wait_for_scan", side_effect=RuntimeError("boom")):
            self.run_main("--per-file-timeout", "60", "--max-files", "1",
                          "--max-tokens", "300000", scan=sleeper)
        r = self.report()["scan"]["results"][0]
        self.assertEqual((r["status"], r["tokens"]), ("timed_out", 300_000))
        self.assertLess(r["seconds"], 15, "the scan was left running, not killed")
        self.assertIn("scan abandoned: RuntimeError('boom')", self.scan_log())


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class _FakeProc:
    """Ends at `ends_at` on the fake clock (None: never); each wait that
    does not reach it advances the clock by its timeout."""

    def __init__(self, clock, ends_at=None):
        self.clock, self.ends_at, self.killed = clock, ends_at, False

    def wait(self, timeout=None):
        if self.killed:
            return -9
        if self.ends_at is not None and (timeout is None or self.clock.t + timeout >= self.ends_at):
            self.clock.t = max(self.clock.t, self.ends_at)
            return 0
        if timeout is None:
            raise AssertionError("would wait forever")
        self.clock.t += timeout
        raise subprocess.TimeoutExpired("scan", timeout)

    def kill(self):
        self.killed = True


class TestWaitForScan(unittest.TestCase):
    """wait_for_scan on a fake clock: timeout 100, stall window 20, cap 200."""

    def wait(self, ends_at=None, writes_until=0.0, timeout=100.0, stall=20.0):
        clock = _Clock()
        proc = _FakeProc(clock, ends_at)
        code = pr_scan.wait_for_scan(proc, timeout, lambda: int(min(clock.t, writes_until) * 10),
                                     clock=clock, stall_seconds=stall, extension_factor=2.0)
        return code, clock.t, proc.killed

    def test_a_scan_that_ends_in_time_is_untouched(self):
        self.assertEqual(self.wait(ends_at=60), (0, 60, False))

    def test_a_silent_scan_is_killed_at_its_timeout(self):
        code, t, killed = self.wait(writes_until=0)
        self.assertEqual((code, killed), (None, True))
        self.assertGreaterEqual(t, 100)
        self.assertLess(t, 106)

    def test_a_scan_that_went_silent_well_before_its_timeout_gets_no_extension(self):
        code, t, _ = self.wait(writes_until=50)
        self.assertIsNone(code)
        self.assertLess(t, 106)

    def test_a_scan_writing_past_its_timeout_finishes(self):
        self.assertEqual(self.wait(ends_at=160, writes_until=150), (0, 160, False))

    def test_a_scan_that_falls_silent_past_its_timeout_is_killed_after_the_stall_window(self):
        code, t, killed = self.wait(writes_until=130)
        self.assertEqual((code, killed), (None, True))
        self.assertGreaterEqual(t, 150)
        self.assertLess(t, 156)

    def test_a_scan_that_never_falls_silent_is_killed_at_the_cap(self):
        code, t, killed = self.wait(writes_until=10_000)
        self.assertEqual((code, killed), (None, True))
        self.assertAlmostEqual(t, 200, delta=0.1)

    def test_the_stall_window_is_never_longer_than_the_timeout(self):
        code, t, _ = self.wait(writes_until=0, timeout=5, stall=900)
        self.assertIsNone(code)
        self.assertLess(t, 6.5)

    def test_no_timeout_waits_for_the_scan(self):
        self.assertEqual(self.wait(ends_at=1e9, timeout=0), (0, 1e9, False))


class TestKnownFindingsFollowFiles(DriverCase):
    """A finding the database knows at a path is not lost when the path moves."""

    def seed_known(self, rel, title="Command injection", severity="HIGH", line=2):
        # A finding recorded by an earlier run (a different run id, as an
        # imported one would be), at the path the base commit has.
        from core.database import init_db, write_findings

        self.state_root.mkdir(parents=True, exist_ok=True)
        self._seed = {"title": title, "description": "d", "severity": severity,
                      "filepath": rel, "line_numbers": [line], "cwe": "CWE-78"}
        self._seed_rel = rel

    def run_with_seed(self, *extra, scan=None):
        # The driver makes a fresh database per run, so the seed is written
        # by the fake scan's first invocation into that database; the finding
        # keeps the OLD path, as an imported finding would.
        seed = dict(self._seed)
        seed_db = []

        def seeding(state, target, max_llm_calls, model):
            if not seed_db:
                from core.database import write_findings
                write_findings(state.db_path, seed["filepath"], [seed], run_id="run-base", status="")
                seed_db.append(state.db_path)
            return (scan or fake_scan())(state, target, max_llm_calls, model)

        return self.run_main(*extra, scan=seeding)

    def test_a_rename_carries_the_finding_and_blocks(self):
        (self.repo / "lib").mkdir()
        _git(self.repo, "mv", "app.py", "lib/app_v2.py")
        _git(self.repo, "commit", "-q", "-m", "move")
        self.seed_known("app.py")
        rc, out = self.run_with_seed("--fail-on", "block")
        rep = self.report()
        self.assertEqual(rep["findings_verdict"], "BLOCK", rep["reasons"])
        self.assertEqual(rc, pr_scan.EXIT_FAILED_GATE)
        self.assertTrue(any("renamed from app.py" in r for r in rep["reasons"]), rep["reasons"])
        hit = next(f for f in rep["findings"] if f["title"] == "Command injection")
        self.assertEqual(hit["filepath"], "lib/app_v2.py")
        self.assertEqual(hit["renamed_from"], "app.py")
        self.assertEqual(hit["relationship"], "direct")
        self.assertEqual(rep["renamed"], {"app.py": "lib/app_v2.py"})

    def test_a_deleted_file_with_a_finding_is_a_review(self):
        # gone.py is deleted between base and head in the fixture.
        self.seed_known("gone.py", title="Hardcoded secret", severity="HIGH")
        rc, _ = self.run_with_seed("--fail-on", "review")
        rep = self.report()
        self.assertEqual(rep["findings_verdict"], "REVIEW", rep["reasons"])
        self.assertTrue(any("gone.py" in r and "deletes" in r for r in rep["reasons"]), rep["reasons"])
        self.assertEqual(rep["deleted"], ["gone.py"])
        self.assertEqual(rc, pr_scan.EXIT_FAILED_GATE)
        rc, _ = self.run_with_seed("--fail-on", "block")
        self.assertEqual(rc, pr_scan.EXIT_OK, "a deletion is a question, not a BLOCK")

    def test_an_unrelated_rename_is_not_blamed(self):
        (self.repo / "lib").mkdir()
        _git(self.repo, "mv", "new.py", "lib/other.py")
        _git(self.repo, "commit", "-q", "-m", "move")
        self.seed_known("app.py")  # app.py is modified, not renamed: direct on its own
        rc, _ = self.run_with_seed()
        rep = self.report()
        hit = next(f for f in rep["findings"] if f["title"] == "Command injection")
        self.assertEqual(hit["filepath"], "app.py")
        self.assertNotIn("renamed_from", hit)


class TestOutputHygiene(DriverCase):
    def test_html_in_a_title_is_encoded_in_the_summary(self):
        finding = {"title": "<h1>PASS</h1><a href=\"https://evil\">x</a> & <details>",
                   "description": "d", "severity": "HIGH", "filepath": "app.py",
                   "line_numbers": [2]}
        self.run_main(scan=fake_scan(finding))
        text = self.summary.read_text(encoding="utf-8")
        self.assertNotIn("<h1>", text)
        self.assertNotIn("<a href", text)
        self.assertNotIn("<details>", text)
        self.assertIn("&lt;h1&gt;", text)
        self.assertIn("&amp;", text)
        # The JSON report went through the egress scrubber too.
        rep = self.report()
        self.assertIsInstance(rep["findings"][0]["title"], str)

    def test_the_credentials_file_is_never_a_scan_target(self):
        # google-github-actions/auth drops gha-creds-<random>.json into the
        # checkout, untracked. The driver's file selection is the diff, so it
        # never sees it; the pipeline's own discovery must not either.
        import main as pipeline_main

        (self.repo / "gha-creds-abc123.json").write_text('{"type": "external_account"}', encoding="utf-8")
        found = pipeline_main.discover_files(self.repo)
        self.assertFalse(any(f.endswith("gha-creds-abc123.json") for f in found), found)
        self.assertTrue(any(f.endswith("app.py") for f in found))


class TestActionDefinition(unittest.TestCase):
    """What action.yml must do before the driver gets a say."""

    def setUp(self):
        self.text = (pr_scan._REF_ROOT.parent / "action" / "action.yml").read_text(encoding="utf-8")

    def test_steps_run_from_the_action_directory_with_a_safe_path(self):
        # A composite step's default cwd is the pull-request checkout, and
        # `python -m` puts the cwd first on sys.path: a pip/__init__.py in
        # the pull request would be what `python -m pip` imports.
        import yaml

        spec = yaml.safe_load(self.text)
        steps = [st for st in spec["runs"]["steps"] if "run" in st]
        self.assertGreaterEqual(len(steps), 3)
        for st in steps:
            self.assertEqual(st.get("working-directory"), "${{ github.action_path }}", st.get("name"))
        install = next(st for st in steps if "pip install" in st["run"])
        self.assertEqual(install["env"]["PYTHONSAFEPATH"], "1")
        self.assertIn("python -P -m pip", install["run"])
        self.assertIn("--require-hashes", install["run"])
        scan = next(st for st in steps if "pr_scan.py" in st["run"])
        self.assertEqual(scan["env"]["PYTHONSAFEPATH"], "1")
        self.assertEqual(scan["env"]["LITELLM_MODE"], "PRODUCTION")

    def test_the_credentials_file_is_moved_out_of_the_checkout_before_the_scan(self):
        import yaml

        spec = yaml.safe_load(self.text)
        names = [st.get("name") for st in spec["runs"]["steps"]]
        move = names.index("Move the credential out of the checkout")
        scan = names.index("Scan the pull request")
        self.assertLess(move, scan)
        body = spec["runs"]["steps"][move]["run"]
        for needle in ("$GITHUB_WORKSPACE", "$RUNNER_TEMP", "GOOGLE_APPLICATION_CREDENTIALS=",
                       "GOOGLE_GHA_CREDS_PATH=", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=", "rm -f"):
            self.assertIn(needle, body, needle)

    def test_fail_closed_is_an_input_defaulting_off(self):
        import yaml

        spec = yaml.safe_load(self.text)
        self.assertEqual(spec["inputs"]["fail-closed"]["default"], "false")
        self.assertIn("--fail-closed", self.text)
        self.assertIn("MANTIS_ACTION_FAIL_CLOSED", self.text)


class TestManyModels(DriverCase):
    def test_models_scan_every_file_under_every_model(self):
        rc, out = self.run_main("--models", "vertex_ai/a-model, vertex_ai/b-model", scan=fake_scan())
        rep = self.report()
        jobs = sorted((r["file"], r["model"]) for r in rep["scan"]["results"])
        self.assertEqual(jobs, [("app.py", "vertex_ai/a-model"), ("app.py", "vertex_ai/b-model"),
                                ("new.py", "vertex_ai/a-model"), ("new.py", "vertex_ai/b-model")])
        self.assertEqual(rep["coverage"]["status"], "complete")
        self.assertEqual(rc, pr_scan.EXIT_OK)
        text = self.summary.read_text(encoding="utf-8")
        self.assertIn("| File | Model | Result |", text)
        self.assertIn("vertex_ai/b-model", text)
        from core.database import run_models
        self.assertEqual(sorted(set(run_models(Path(rep["state_dir"], "knowledge.db").as_posix()).values())),
                         ["vertex_ai/a-model", "vertex_ai/b-model"])

    def test_the_budget_is_shared_over_all_the_jobs(self):
        floor = pr_scan.MIN_SCAN_ALLOWANCE
        # Four jobs; each spends its share plus a little, so the last is not launched.
        rc, out = self.run_main("--models", "m1,m2", "--max-tokens", str(4 * floor),
                                scan=fake_scan(tokens=floor + 20_000))
        rep = self.report()
        statuses = [(r["file"], r["model"], r["status"]) for r in rep["scan"]["results"]]
        # Carry-over shares: one job's overshoot narrows the next job's share
        # below the floor, so some job is not launched, whichever model it
        # belongs to, and the run as a whole stays inside its budget.
        self.assertIn("over_budget", {st[2] for st in statuses}, statuses)
        self.assertLessEqual(sum(int(r["tokens"]) for r in rep["scan"]["results"]), 4 * floor)
        self.assertEqual(rep["coverage"]["status"], "partial")

    def test_one_model_failing_is_a_gap_for_that_model_only(self):
        calls = []

        def flaky(state, target, max_llm_calls, model):
            calls.append(model)
            return fake_scan(code=1 if model == "bad" else 0)(state, target, max_llm_calls, model)

        rc, out = self.run_main("--models", "good,bad", scan=flaky)
        rep = self.report()
        bad = [r for r in rep["scan"]["results"] if r["model"] == "bad"]
        self.assertTrue(all(r["status"] == "finished_with_errors" for r in bad))
        self.assertEqual(rep["coverage"]["status"], "partial")
        self.assertEqual(sorted({u["file"] for u in rep["coverage"]["unaudited"]}), ["app.py", "new.py"])
        self.assertEqual(rc, pr_scan.EXIT_OK)


class TestSpendArithmetic(unittest.TestCase):
    """The pure functions the run budget is made of."""

    def test_allowance_is_an_equal_share_of_what_is_left(self):
        self.assertEqual(pr_scan.allowance(1_000_000, 0, 4), 250_000)
        self.assertEqual(pr_scan.allowance(1_000_000, 100_000, 3), 300_000)  # carry-over
        self.assertEqual(pr_scan.allowance(1_000_000, 1_000_000, 2), 0)
        self.assertEqual(pr_scan.allowance(1_000_000, 1_500_000, 2), 0)      # never negative
        self.assertEqual(pr_scan.allowance(0, 0, 5), 0)                      # no budget
        self.assertEqual(pr_scan.allowance(100, 0, 0), 0)

    def test_charge_prefers_the_raw_count_and_defaults_to_the_grant(self):
        acct = {"tokens": 900, "fresh_tokens": 500, "cached_tokens": 400, "llm_calls": 2,
                "pause_trigger": ""}
        self.assertEqual(pr_scan.charge(acct, 10_000), 900)
        # A discounted figure larger than fresh+cached (a child run with a
        # different discount) is still honoured: the larger of the two.
        acct["tokens"] = 1_200
        self.assertEqual(pr_scan.charge(acct, 10_000), 1_200)
        self.assertEqual(pr_scan.charge(None, 10_000), 10_000)

    def test_spend_report_parsing_is_strict(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        p = Path(tmp) / "s.json"
        self.assertIsNone(pr_scan.read_spend_report(p))
        p.write_text("not json", encoding="utf-8")
        self.assertIsNone(pr_scan.read_spend_report(p))
        p.write_text("[1,2]", encoding="utf-8")
        self.assertIsNone(pr_scan.read_spend_report(p))
        p.write_text(json.dumps({"tokens": -5, "fresh_tokens": "x", "cached_tokens": True,
                                 "llm_calls": 2.0, "pause_trigger": None}), encoding="utf-8")
        acct = pr_scan.read_spend_report(p)
        self.assertEqual(acct, {"tokens": 0, "fresh_tokens": 0, "cached_tokens": 0,
                                "llm_calls": 2, "pause_trigger": "", "nodes": []})
        p.write_text(json.dumps({"tokens": 1, "nodes": ["researcher", 3, "reviewer"]}), encoding="utf-8")
        self.assertEqual(pr_scan.read_spend_report(p)["nodes"], ["researcher", "reviewer"])
        self.assertTrue(pr_scan.researcher_finished(["planner", "researcher", "findings_gate"]))
        self.assertFalse(pr_scan.researcher_finished(["planner", "researcher"]))
        self.assertFalse(pr_scan.researcher_finished(["planner"]))
        self.assertFalse(pr_scan.researcher_finished([]))

    def test_scan_command_carries_the_grant_at_full_price(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        state = pr_scan.MantisState(tmp)
        cmd = pr_scan.scan_command(state, "a.py", 7, "m", max_tokens=12_345,
                                   spend_report="/tmp/x.json")
        self.assertEqual(cmd[cmd.index("--max-tokens") + 1], "12345")
        self.assertEqual(cmd[cmd.index("--cache-discount") + 1], "1")
        self.assertEqual(cmd[cmd.index("--spend-report") + 1], "/tmp/x.json")
        cmd = pr_scan.scan_command(state, "a.py", 7, "m", max_tokens=0)
        self.assertNotIn("--max-tokens", cmd)
        self.assertEqual(cmd[cmd.index("--cache-discount") + 1], "1",
                         "no run budget still means every token at full price")


class TestRunBudget(DriverCase):
    """The run budget end to end, with the pipeline stood in for. The PR
    fixture has two scannable files, app.py then new.py."""

    def results(self):
        return {r["file"]: r for r in self.report()["scan"]["results"]}

    def test_shares_are_equal_with_carry_over_and_charged_from_the_account(self):
        rc, _ = self.run_main("--max-tokens", "1000000", scan=fake_scan(tokens=100_000))
        res = self.results()
        self.assertEqual(res["app.py"]["granted"], 500_000)
        self.assertEqual(res["app.py"]["tokens"], 100_000)
        # new.py gets everything left, not its original half.
        self.assertEqual(res["new.py"]["granted"], 900_000)
        usage = self.report()["usage"]
        self.assertEqual(usage, {"tokens": 200_000, "llm_calls": 6, "max_tokens": 1_000_000,
                                 "files_scanned": 2, "files_over_budget": 0})
        self.assertEqual(self.report()["verdict"], "PASS")
        self.assertEqual(rc, pr_scan.EXIT_OK)
        self.assertIn("Model usage: 200,000 tokens of a 1,000,000 budget, 6 calls",
                      self.summary.read_text(encoding="utf-8"))

    def test_a_file_the_budget_cannot_reach_is_not_launched_and_floors_review(self):
        # The budget is checked after each call, so a scan can overshoot its
        # share by one call. Here the first scan does, leaving less than the
        # floor for the second file: that file is never launched (no
        # process, no spend), reported over budget, and the verdict is REVIEW
        # naming it.
        probe = Path(self.tmp) / "launched.txt"
        floor = pr_scan.MIN_SCAN_ALLOWANCE
        inner = fake_scan(tokens=floor + 5_000)

        def counting(state, target, max_llm_calls, model):
            with open(probe, "a") as fh:
                fh.write(target + "\n")
            return inner(state, target, max_llm_calls, model)

        rc, out = self.run_main("--max-tokens", str(2 * floor), scan=counting)
        res = self.results()
        self.assertEqual(res["app.py"]["status"], "done")
        self.assertEqual(res["app.py"]["granted"], floor)
        self.assertEqual(res["app.py"]["tokens"], floor + 5_000)
        self.assertEqual(res["new.py"]["status"], "over_budget")
        self.assertEqual(res["new.py"]["granted"], floor - 5_000)
        self.assertEqual(res["new.py"]["tokens"], 0)
        self.assertEqual(probe.read_text().count("\n"), 1, "new.py must not be launched")
        rep = self.report()
        self.assertEqual(rep["verdict"], "REVIEW")
        self.assertEqual(rep["coverage"]["status"], "partial")
        self.assertEqual([u["file"] for u in rep["coverage"]["unaudited"]], ["new.py"])
        self.assertTrue(any("run token budget was spent" in r and "new.py" in r
                            for r in rep["reasons"]), rep["reasons"])
        self.assertTrue(any("max-tokens" in a for a in rep["next_actions"]))
        self.assertEqual(rep["scan"]["over_budget"], ["new.py"])
        self.assertIn("::warning title=Mantis%3A unscanned::1 changed file(s) not scanned "
                      "(token budget spent)", out)
        self.assertIn("Not scanned (token budget spent): `new.py`",
                      self.summary.read_text(encoding="utf-8"))
        self.assertEqual(rc, pr_scan.EXIT_OK)
        rc, _ = self.run_main("--fail-on", "review", "--max-tokens", str(2 * floor), scan=inner)
        self.assertEqual(rc, pr_scan.EXIT_OK, "an unscanned file is coverage, not a finding")
        rc, _ = self.run_main("--fail-closed", "--max-tokens", str(2 * floor), scan=inner)
        self.assertEqual(rc, pr_scan.EXIT_FAILED_GATE)

    def test_a_scan_that_leaves_no_account_is_charged_its_whole_share(self):
        # Killed (timeout) or crashed before writing its report: the driver
        # cannot know what it spent, so it assumes all of it. Here the first
        # scan leaves nothing, so the second file's share is what remains of
        # the budget after the first's full grant, not after its real spend.
        calls = {"n": 0}
        silent = fake_scan(no_report=True)
        chatty = fake_scan(tokens=10)

        def alternating(state, target, max_llm_calls, model):
            calls["n"] += 1
            return (silent if calls["n"] == 1 else chatty)(state, target, max_llm_calls, model)

        self.run_main("--max-tokens", "1000000", scan=alternating)
        res = self.results()
        self.assertEqual(res["app.py"]["tokens"], 500_000)
        self.assertIsNone(res["app.py"]["llm_calls"])
        self.assertEqual(res["new.py"]["granted"], 500_000)
        usage = self.report()["usage"]
        self.assertEqual(usage["tokens"], 500_010)
        self.assertIsNone(usage["llm_calls"], "a sum with a hole in it is not a count")
        self.assertIn("| ? |", self.summary.read_text(encoding="utf-8"))

    def test_timeout_is_charged_in_full(self):
        sleeper = lambda *a, **k: [sys.executable, "-c", "import time; time.sleep(5)"]
        self.run_main("--per-file-timeout", "0.5", "--max-files", "1", "--max-tokens", "300000",
                      scan=sleeper)
        r = self.report()["scan"]["results"][0]
        self.assertEqual(r["status"], "timed_out")
        self.assertEqual(r["tokens"], 300_000)

    def test_a_launch_failure_costs_nothing(self):
        broken = lambda *a, **k: ["/nonexistent/mantis-pipeline"]
        self.run_main("--max-tokens", "1000000", scan=broken)
        # Every scan failed to launch: a setup failure, no report is written,
        # but the summary must not claim spend either.
        self.assertFalse(self.out_json.exists())

    def test_cached_tokens_are_charged_at_full_price(self):
        self.run_main("--max-tokens", "1000000", scan=fake_scan(tokens=1_000, cached=900))
        res = self.results()
        self.assertEqual(res["app.py"]["tokens"], 1_000)

    def test_no_run_budget_keeps_the_pipeline_ceiling_and_still_reports(self):
        rc, _ = self.run_main("--max-tokens", "0", scan=fake_scan(tokens=777))
        res = self.results()
        self.assertEqual(res["app.py"]["granted"], 0)
        self.assertEqual(res["app.py"]["tokens"], 777)
        usage = self.report()["usage"]
        self.assertEqual(usage["max_tokens"], 0)
        self.assertEqual(usage["tokens"], 1_554)
        self.assertIn("(no run budget)", self.summary.read_text(encoding="utf-8"))
        self.assertEqual(rc, pr_scan.EXIT_OK)

    def test_children_get_the_input_cap_and_the_grant(self):
        probe = Path(self.tmp) / "child.json"
        dumping = lambda *a, **k: [
            sys.executable, "-c",
            f"import json,os,sys; json.dump({{'env': dict(os.environ), 'argv': sys.argv}}, "
            f"open({str(probe)!r},'w'))"]
        self.run_main("--max-files", "1", "--max-tokens", "640000", "--max-input-tokens",
                      "4096", scan=dumping)
        seen = json.loads(probe.read_text(encoding="utf-8"))
        self.assertEqual(seen["env"].get("MANTIS_MAX_INPUT_TOKENS"), "4096")
        argv = seen["argv"]
        self.assertEqual(argv[argv.index("--max-tokens") + 1], "640000")
        self.assertEqual(argv[argv.index("--cache-discount") + 1], "1")
        spend = Path(argv[argv.index("--spend-report") + 1])
        self.assertTrue(str(spend).startswith(str(self.state_root)))
        self.assertFalse(str(spend).startswith(str(self.repo)))
        # 0 removes the cap from the child's environment even if the runner had one.
        self.run_main("--max-files", "1", "--max-input-tokens", "0",
                      env={**self.env, "MANTIS_MAX_INPUT_TOKENS": "99"}, scan=dumping)
        seen = json.loads(probe.read_text(encoding="utf-8"))
        self.assertNotIn("MANTIS_MAX_INPUT_TOKENS", seen["env"])

    def test_bad_budget_values_are_setup_errors(self):
        rc, out = self.run_main("--max-tokens", "lots", "--fail-closed", scan=fake_scan())
        self.assertEqual(rc, pr_scan.EXIT_INFRA)
        self.assertIn("max-tokens", out)
        rc, _ = self.run_main("--max-input-tokens", "-1", "--fail-closed", scan=fake_scan())
        self.assertEqual(rc, pr_scan.EXIT_INFRA)

    def test_defaults_are_the_documented_ones(self):
        args = pr_scan.parse_args([])
        self.assertEqual(args.max_tokens, str(pr_scan.DEFAULT_MAX_TOKENS))
        self.assertEqual(args.max_input_tokens, pr_scan.DEFAULT_MAX_INPUT_TOKENS)
        self.assertEqual(args.daily_token_budget, str(pr_scan.DEFAULT_DAILY_TOKEN_BUDGET))
        self.assertGreater(pr_scan.DEFAULT_MAX_TOKENS, 0)
        self.assertGreater(pr_scan.DEFAULT_MAX_INPUT_TOKENS, 0)
        self.assertGreater(pr_scan.DEFAULT_DAILY_TOKEN_BUDGET, pr_scan.DEFAULT_MAX_TOKENS)


class _FakeResponse:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class _FakeSession:
    def __init__(self, status=200, body=None, raise_exc=None):
        self.calls = []
        self._resp = _FakeResponse(status, body if body is not None else {})
        self._raise = raise_exc

    def get(self, url, params=None, timeout=None):
        self.calls.append((url, dict(params or {}), timeout))
        if self._raise:
            raise self._raise
        return self._resp


class TestDailyMeter(unittest.TestCase):
    """Reading the platform's token meter: one request, strict parsing,
    actionable refusals."""

    ENV = {"GOOGLE_CLOUD_PROJECT": "p-1"}

    def test_sums_every_point_of_every_series(self):
        body = {"timeSeries": [
            {"metric": {"labels": {"type": "input"}}, "points": [{"value": {"int64Value": "1200"}}]},
            {"metric": {"labels": {"type": "output"}}, "points": [{"value": {"int64Value": "34"}},
                                                                  {"value": {"doubleValue": 6.0}}]},
        ]}
        s = _FakeSession(body=body)
        self.assertEqual(pr_scan.tokens_served_today(self.ENV, now=1_700_000_000, session=s), 1240)
        url, params, timeout = s.calls[0]
        self.assertEqual(url, "https://monitoring.googleapis.com/v3/projects/p-1/timeSeries")
        self.assertIn(pr_scan.TOKEN_COUNT_METRIC, params["filter"])
        self.assertEqual(params["interval.endTime"], "2023-11-14T22:13:20Z")
        self.assertEqual(params["interval.startTime"], "2023-11-13T22:13:20Z")
        self.assertEqual(params["aggregation.alignmentPeriod"], "86400s")
        self.assertEqual(params["aggregation.perSeriesAligner"], "ALIGN_SUM")
        self.assertEqual(params["aggregation.crossSeriesReducer"], "REDUCE_SUM")
        self.assertEqual(timeout, 30)

    def test_empty_series_is_zero_not_an_error(self):
        self.assertEqual(pr_scan.tokens_served_today(self.ENV, session=_FakeSession(body={})), 0)

    def test_refusals_are_named(self):
        with self.assertRaises(pr_scan.DailyMeterUnavailable) as c:
            pr_scan.tokens_served_today({}, session=_FakeSession())
        self.assertIn("GOOGLE_CLOUD_PROJECT", str(c.exception))
        with self.assertRaises(pr_scan.DailyMeterUnavailable) as c:
            pr_scan.tokens_served_today(self.ENV, session=_FakeSession(status=403))
        self.assertIn("roles/monitoring.viewer", str(c.exception))
        with self.assertRaises(pr_scan.DailyMeterUnavailable):
            pr_scan.tokens_served_today(self.ENV, session=_FakeSession(status=500))
        with self.assertRaises(pr_scan.DailyMeterUnavailable):
            pr_scan.tokens_served_today(self.ENV, session=_FakeSession(raise_exc=OSError("net")))
        with self.assertRaises(pr_scan.DailyMeterUnavailable):
            pr_scan.tokens_served_today(self.ENV, session=_FakeSession(body=ValueError("x")))
        with self.assertRaises(pr_scan.DailyMeterUnavailable):
            pr_scan.tokens_served_today(
                self.ENV, session=_FakeSession(body={"timeSeries": [{"points": [{"value": {"int64Value": "x"}}]}]}))

    def test_run_budget_for_today(self):
        f = pr_scan.run_budget_for_today
        self.assertEqual(f(4_000_000, 0, 0), 4_000_000)          # no daily budget
        self.assertEqual(f(0, 0, 0), 0)                          # no budgets at all
        self.assertEqual(f(4_000_000, 100_000_000, 1_000_000), 4_000_000)
        self.assertEqual(f(4_000_000, 100_000_000, 97_500_000), 2_500_000)  # cut to what is left
        self.assertEqual(f(4_000_000, 100_000_000, 100_000_000), 0)
        self.assertEqual(f(4_000_000, 100_000_000, 250_000_000), 0)        # never negative
        self.assertEqual(f(0, 100_000_000, 40_000_000), 60_000_000)        # daily alone bounds


def _knowledge_files(status="confirmed", severity="HIGH", line=2):
    """A minimal valid knowledge export: one finding on app.py and a threat model."""
    finding = {"lineage_id": "lin-app-1", "signature": "sig-app-1", "filepath": "app.py",
               "line_numbers": [line], "title": "Known issue in helper", "severity": severity,
               "status": status, "description": "Recorded by an earlier full scan.", "cwe": "CWE-20",
               "code_paths": ["app.py:2"], "run_id": "full-scan-1"}
    return {
        ".mantis/knowledge/manifest.json": json.dumps({"schema_version": 1, "generator": "mantis"}),
        ".mantis/knowledge/findings.jsonl": json.dumps(finding) + "\n",
        ".mantis/knowledge/threat_model.md": "# Threat model\n\n- helper() takes caller input\n",
        ".mantis/knowledge/threat_model.json": json.dumps({"threats": [{"title": "caller input in helper"}]}),
        ".mantis/knowledge/coverage.json": json.dumps({"schema_version": 1, "runs": [
            {"run_id": "full-scan-1", "snapshot_id": "s1", "examined": ["app.py"]}],
            "scanned": [{"path": "app.py", "scan_mode": "file-by-file", "last_run_id": "full-scan-1"}]}),
    }


def _knowledge_files_with_model(model, **kw):
    """The same export, version 2, with the finder's model on record."""
    files = _knowledge_files(**kw)
    manifest = json.loads(files[".mantis/knowledge/manifest.json"])
    manifest["schema_version"] = 2
    files[".mantis/knowledge/manifest.json"] = json.dumps(manifest)
    files[".mantis/knowledge/runs.jsonl"] = json.dumps({"run_id": "full-scan-1", "model": model}) + "\n"
    return files


class KnowledgeCase(DriverCase):
    """The fixture's BASE commit carries a knowledge export; HEAD is the usual
    PR on top (app.py edited at line 2, new.py added)."""

    knowledge_model = ""

    def setUp(self):
        super().setUp()
        # Rewrite history: knowledge in the base, then the same PR on top.
        files = (_knowledge_files_with_model(self.knowledge_model) if self.knowledge_model
                 else _knowledge_files())
        _git(self.repo, "checkout", "-q", self.base)
        for rel, body in files.items():
            p = self.repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "base with knowledge")
        self.base = _git(self.repo, "rev-parse", "HEAD")
        (self.repo / "app.py").write_text(HEAD_APP, encoding="utf-8")
        (self.repo / "new.py").write_text("def fresh():\n    return 1\n", encoding="utf-8")
        (self.repo / "README.md").write_text("# docs\n", encoding="utf-8")
        (self.repo / "gone.py").unlink()
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "head")
        _git(self.repo, "checkout", "-q", "-B", "main")


class TestKnowledgeInTheRun(KnowledgeCase):
    def test_base_knowledge_feeds_the_gate_and_the_scans(self):
        probe = Path(self.tmp) / "child.json"
        dumping = lambda *a, **k: [sys.executable, "-c",
                                   f"import json,sys; json.dump(sys.argv, open({str(probe)!r},'w'))"]
        rc, out = self.run_main("--fail-on", "block", scan=dumping)
        rep = self.report()
        # INV-3 at the gate: the known HIGH finding sits on the changed line.
        self.assertEqual(rep["verdict"], "BLOCK", rep["reasons"])
        self.assertTrue(any("Known issue in helper" in r for r in rep["reasons"]), rep["reasons"])
        self.assertEqual(rc, pr_scan.EXIT_FAILED_GATE)
        kn = rep["knowledge"]
        self.assertTrue(kn["source"].startswith("base commit"))
        self.assertEqual(kn["imported"]["findings"], 1)
        self.assertTrue(kn["imported"]["threat_model"])
        self.assertEqual(kn["changed"], [])
        self.assertEqual(kn["error"], "")
        # app.py was covered by the full scan: no "never been scanned" for it.
        self.assertFalse(any("'app.py' has never been scanned" in r for r in rep["reasons"]), rep["reasons"])
        # Children import the same extracted copy, which lives in the state dir, not the checkout.
        argv = json.loads(probe.read_text())
        kdir = argv[argv.index("--import-knowledge") + 1]
        self.assertTrue(kdir.startswith(str(self.state_root)), kdir)
        self.assertFalse(kdir.startswith(str(self.repo)))
        self.assertTrue((Path(kdir) / "findings.jsonl").exists())
        self.assertIn("### Knowledge", self.summary.read_text())
        self.assertIn("1 known finding(s)", self.summary.read_text())

    def test_the_pull_requests_edits_to_knowledge_are_not_trusted_and_are_flagged(self):
        # The PR marks the finding a false positive and deletes the threat
        # model. The gate still blocks on the base's version; the edits are a
        # REVIEW reason and annotations, and the files are never scanned.
        probe = Path(self.tmp) / "launched.txt"

        def counting(state, target, max_llm_calls, model):
            with open(probe, "a") as fh:
                fh.write(target + "\n")
            return fake_scan()(state, target, max_llm_calls, model)

        files = _knowledge_files(status="false_positive")
        self.commit_pr({".mantis/knowledge/findings.jsonl": files[".mantis/knowledge/findings.jsonl"]})
        (self.repo / ".mantis/knowledge/threat_model.md").unlink()
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "tamper")
        rc, out = self.run_main("--ignore", "", scan=counting)  # even with nothing ignored
        rep = self.report()
        self.assertEqual(rep["verdict"], "BLOCK", rep["reasons"])
        self.assertEqual(sorted(rep["knowledge"]["changed"]),
                         ["D .mantis/knowledge/threat_model.md", "M .mantis/knowledge/findings.jsonl"])
        self.assertTrue(any("changes Mantis's knowledge" in r for r in rep["reasons"]), rep["reasons"])
        self.assertIn("::warning file=.mantis/knowledge/findings.jsonl,title=Mantis%3A knowledge changed::", out)
        self.assertIn("::warning title=Mantis%3A knowledge changed::This pull request changes Mantis's "
                      "knowledge (D .mantis/knowledge/threat_model.md)", out)
        launched = probe.read_text()
        self.assertNotIn(".mantis", launched, "knowledge files are never scanned")
        self.assertIn("Changed by this pull request", self.summary.read_text())

    def test_a_knowledge_only_pull_request_is_review_not_pass(self):
        self.commit_pr({".mantis/knowledge/learnings.jsonl": json.dumps({"category": "x", "learning": "y"}) + "\n"})
        # Make it knowledge-only: revert the code and README changes.
        _git(self.repo, "checkout", "-q", self.base, "--", "app.py")
        for extra in ("new.py", "README.md"):
            (self.repo / extra).unlink()
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "knowledge only")
        rc, out = self.run_main("--fail-on", "review", scan=fake_scan())
        rep = self.report()
        self.assertEqual(rep["verdict"], "REVIEW", rep["reasons"])
        self.assertTrue(any("changes Mantis's knowledge" in r for r in rep["reasons"]))
        self.assertEqual(rc, pr_scan.EXIT_FAILED_GATE)

    def test_knowledge_added_by_the_pull_request_is_not_imported(self):
        # Base without knowledge, PR adds it: nothing is read, the addition is flagged.
        _git(self.repo, "checkout", "-q", "main~2")  # the original knowledge-free base
        base = _git(self.repo, "rev-parse", "HEAD")
        _git(self.repo, "checkout", "-q", "-B", "pr")
        for rel, body in _knowledge_files().items():
            p = self.repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
        (self.repo / "app.py").write_text(HEAD_APP, encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "pr adds knowledge")
        self.base = base
        rc, _ = self.run_main(scan=fake_scan())
        rep = self.report()
        self.assertIsNone(rep["knowledge"]["source"])
        self.assertIsNone(rep["knowledge"]["imported"])
        self.assertTrue(all(c.startswith("A ") for c in rep["knowledge"]["changed"]), rep["knowledge"])
        self.assertNotEqual(rep["verdict"], "BLOCK")
        self.assertIn("in the base commit; the scan started from nothing", self.summary.read_text())

    def test_unreadable_base_knowledge_is_review_not_a_setup_failure(self):
        _git(self.repo, "checkout", "-q", self.base)
        (self.repo / ".mantis/knowledge/manifest.json").write_text(json.dumps({"schema_version": 99}))
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "broken manifest")
        self.base = _git(self.repo, "rev-parse", "HEAD")
        (self.repo / "app.py").write_text(HEAD_APP, encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "head")
        _git(self.repo, "checkout", "-q", "-B", "main")
        rc, _ = self.run_main(scan=fake_scan())
        rep = self.report()
        self.assertIn("schema_version", rep["knowledge"]["error"])
        self.assertTrue(any("could not be read" in r for r in rep["reasons"]), rep["reasons"])
        self.assertEqual(rep["verdict"], "REVIEW")
        self.assertEqual(rc, pr_scan.EXIT_OK)


class TestKnowledgeRefresh(KnowledgeCase):
    """--export-knowledge: the trusted post-merge refresh. The base knows a
    HIGH finding at app.py:2; the PR rewrites line 2."""

    def refresh(self, *extra, scan):
        out_dir = Path(self.tmp) / "export"
        rc, out = self.run_main("--export-knowledge", str(out_dir), *extra, scan=scan)
        return rc, out, out_dir

    def test_rewritten_and_not_refound_is_archived_and_exported(self):
        # The rescan of app.py completes and reports nothing: the known finding's
        # line was rewritten, so it is archived, not left open and not dropped.
        rc, out, out_dir = self.refresh(scan=fake_scan())
        rep = self.report()
        archived = rep["knowledge"]["archived"]
        self.assertEqual([a["lineage_id"] for a in archived], ["lin-app-1"])
        self.assertNotEqual(rep["verdict"], "BLOCK", rep["reasons"])
        # Still surfaced: as an archived notice on the touched file, not a verdict.
        rels = {f["lineage_id"]: f["relationship"] for f in rep["findings"] if f.get("lineage_id")}
        self.assertEqual(rels.get("lin-app-1"), "archived")
        self.assertIn("::notice file=app.py,line=2,title=Mantis%3A HIGH::Known issue in helper [HIGH, archived] "
                      "archived: found here before", out)
        self.assertIn("Archived by this refresh (1)", self.summary.read_text())
        # The export carries the archived row with the reason, and the head.
        recs = [json.loads(l) for l in (out_dir / "findings.jsonl").read_text().splitlines()]
        row = next(r for r in recs if r["lineage_id"] == "lin-app-1")
        self.assertEqual(row["status"], "archived")
        self.assertIn("archived by knowledge refresh", row["triage_reasoning"])
        self.assertIn("check again", row["triage_reasoning"])
        manifest = json.loads((out_dir / "manifest.json").read_text())
        self.assertEqual(manifest["head"], _git(self.repo, "rev-parse", "HEAD"))
        self.assertIn("Knowledge written to", self.summary.read_text())
        # Coverage advanced to the files this refresh scanned.
        cov = json.loads((out_dir / "coverage.json").read_text())
        self.assertIn("app.py", [s["path"] for s in cov["scanned"]])

    def test_refound_lineage_stays_open(self):
        refound = {"title": "Known issue in helper", "severity": "HIGH", "status": "confirmed",
                   "description": "Still here.", "line_numbers": [2], "filepath": "app.py",
                   "lineage_id": "lin-app-1", "signature": "sig-app-1", "cwe": "CWE-20"}
        rc, out, out_dir = self.refresh("--fail-on", "block", scan=fake_scan(finding=refound))
        rep = self.report()
        self.assertEqual(rep["knowledge"]["archived"], [])
        self.assertEqual(rep["verdict"], "BLOCK")
        recs = [json.loads(l) for l in (out_dir / "findings.jsonl").read_text().splitlines()]
        self.assertEqual([r["status"] for r in recs if r["lineage_id"] == "lin-app-1"], ["confirmed"])

    def test_untouched_lines_failed_scans_and_dismissals_are_left_alone(self):
        # Finding at line 40, nowhere near the change: open stays open.
        far = _knowledge_files(line=40)
        _git(self.repo, "checkout", "-q", self.base)
        (self.repo / ".mantis/knowledge/findings.jsonl").write_text(far[".mantis/knowledge/findings.jsonl"])
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "base far")
        self.base = _git(self.repo, "rev-parse", "HEAD")
        (self.repo / "app.py").write_text(HEAD_APP, encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "head")
        _git(self.repo, "checkout", "-q", "-B", "main")
        rc, out, out_dir = self.refresh(scan=fake_scan())
        self.assertEqual(self.report()["knowledge"]["archived"], [])

    def test_archiving_needs_the_researcher_to_have_finished_not_the_run(self):
        # Paused in review, after the researcher reported: the file was examined.
        paused_late = fake_scan(code=2, pause_trigger="llm_calls_limit",
                                nodes=FULL_GRAPH[:FULL_GRAPH.index("findings_gate") + 1] + ["deduplicator", "reviewer"])
        rc, out, out_dir = self.refresh(scan=paused_late)
        self.assertEqual([a["lineage_id"] for a in self.report()["knowledge"]["archived"]], ["lin-app-1"])
        # Paused or failed inside the researcher: nobody finished looking; nothing archived.
        for early in (fake_scan(code=2, pause_trigger="token_budget", nodes=FULL_GRAPH[:6]),
                      fake_scan(code=1, nodes=FULL_GRAPH[:6]),
                      fake_scan(code=2, pause_trigger="llm_calls_limit", no_report=True)):
            rc, out, out_dir = self.refresh(scan=early)
            self.assertEqual(self.report()["knowledge"]["archived"], [], self.report()["scan"]["results"])
        # A finished run from a pipeline that reports no nodes still counts.
        rc, out, out_dir = self.refresh(scan=fake_scan(nodes=[]))
        self.assertEqual([a["lineage_id"] for a in self.report()["knowledge"]["archived"]], ["lin-app-1"])

    def test_a_pull_request_scan_never_archives(self):
        # Same change, no --export-knowledge: the imported finding stays open
        # on the rewritten line and the gate blocks. Fail closed at PR time.
        rc, out = self.run_main("--fail-on", "block", scan=fake_scan())
        rep = self.report()
        self.assertNotIn("archived", rep["knowledge"])
        self.assertEqual(rep["verdict"], "BLOCK", rep["reasons"])

    def test_radius_adds_caller_files_after_the_change(self):
        # helper() is called by handler() in the same file; add a caller in
        # another file so the radius has somewhere to go.
        (self.repo / "caller.py").write_text("from app import helper\n\ndef use():\n    return helper(1)\n")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "add caller")
        # The PR touches app.py only.
        self.base = _git(self.repo, "rev-parse", "HEAD")
        (self.repo / "app.py").write_text(HEAD_APP.replace("x + 0", "x + 1"), encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "touch helper")
        probe = Path(self.tmp) / "launched.txt"
        real_scan_command = pr_scan.scan_command

        def counting(state, rel_fp, *args, **kwargs):
            with open(probe, "a") as fh:
                fh.write(rel_fp + "\n")
            return real_scan_command(state, rel_fp, *args, **kwargs)

        with mock.patch.object(pr_scan, "scan_command", counting):
            self.run_main("--radius", "1", scan=fake_scan())
        launched = probe.read_text().split()
        self.assertEqual(launched[0], "app.py")
        self.assertIn("caller.py", launched, f"index should name caller.py as a caller: {launched}")


class TestClosingIndex(DriverCase):
    """The scans already leave a repo-rooted catalog; the driver does not
    rebuild it after them, and still builds one when there is none."""

    def counted(self):
        import core.structural_index as sidx

        calls = {"reindex": 0, "write": 0}
        real_reindex, real_write = pr_scan.reindex, sidx._write_catalog

        def reindex(state):
            calls["reindex"] += 1
            return real_reindex(state)

        def write(*a, **k):
            calls["write"] += 1
            return real_write(*a, **k)

        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(pr_scan, "reindex", reindex))
        stack.enter_context(mock.patch.object(sidx, "_write_catalog", write))
        return calls, stack

    def test_repo_rooted_catalog_is_not_rebuilt_after_the_scans(self):
        # Untracked, so the checkout cannot be pinned: without the skip the
        # closing reindex would re-resolve the whole catalog.
        (self.repo / "scratch.txt").write_text("x\n", encoding="utf-8")
        calls, stack = self.counted()
        with stack:
            self.run_main("--radius", "1", scan=fake_scan())
        self.assertEqual(calls, {"reindex": 1, "write": 1})
        self.assertTrue(self.report()["blast_radius"], "the gate lost the index")

    def test_without_a_catalog_the_driver_still_builds_one_for_the_gate(self):
        calls, stack = self.counted()
        with stack:
            self.run_main(scan=fake_scan())
        self.assertEqual(calls["reindex"], 1)
        self.assertTrue(self.report()["blast_radius"], "the gate lost the index")

    def test_a_catalog_rooted_elsewhere_is_not_repo_rooted(self):
        from core.structural_index import build_structural_index
        from scripts.mcp_server import MantisState

        state = MantisState(str(self.repo))
        state.home = self.state_root
        state.db_path = str(self.state_root / "knowledge.db")
        self.assertFalse(pr_scan.index_is_repo_rooted(state))
        (self.repo / "sub").mkdir()
        (self.repo / "sub" / "m.py").write_text("def f():\n    return 1\n", encoding="utf-8")
        build_structural_index(str(self.repo / "sub"), state.state_dir())
        self.assertFalse(pr_scan.index_is_repo_rooted(state))
        build_structural_index(str(self.repo), state.state_dir())
        self.assertTrue(pr_scan.index_is_repo_rooted(state))


class TestDailyBudgetInTheRun(DriverCase):
    """The daily budget end to end, with the meter stubbed."""

    def with_meter(self, used):
        return mock.patch.object(pr_scan, "tokens_served_today", lambda env, **kw: used)

    def test_the_meter_is_read_again_before_each_file(self):
        # Two runs start inside the meter's lag and both see the day nearly
        # unspent. Here the meter jumps after the first file (a sibling run's
        # spend became visible): the second file is not launched.
        readings = iter([1_000_000, 99_950_000, 99_950_000])
        probe = Path(self.tmp) / "launched.txt"

        def counting(state, target, max_llm_calls, model):
            with open(probe, "a") as fh:
                fh.write(target + "\n")
            return fake_scan(tokens=10_000)(state, target, max_llm_calls, model)

        with mock.patch.object(pr_scan, "tokens_served_today", lambda env, **kw: next(readings)):
            rc, _ = self.run_main("--max-tokens", "4M", scan=counting,
                                  daily=("--daily-token-budget", "100M"))
        rep = self.report()
        res = {r["file"]: r for r in rep["scan"]["results"]}
        self.assertEqual(res["app.py"]["status"], "done")
        self.assertEqual(res["new.py"]["status"], "over_budget", res)
        self.assertEqual(probe.read_text().count("\n"), 1)
        self.assertEqual(rep["coverage"]["status"], "partial")
        self.assertEqual(rc, pr_scan.EXIT_OK)

    def test_a_spent_day_launches_nothing_and_floors_review(self):
        probe = Path(self.tmp) / "launched.txt"

        def counting(state, target, max_llm_calls, model):
            probe.write_text("launched")
            return fake_scan()(state, target, max_llm_calls, model)

        with self.with_meter(100_000_000):
            rc, out = self.run_main("--max-tokens", "4M", scan=counting,
                                    daily=("--daily-token-budget", "100M"))
        self.assertFalse(probe.exists(), "nothing may be launched on a spent day")
        rep = self.report()
        self.assertEqual(rep["verdict"], "REVIEW")
        self.assertEqual(sorted(rep["scan"]["over_budget"]), ["app.py", "new.py"])
        self.assertTrue(any("daily token budget is spent" in r for r in rep["reasons"]), rep["reasons"])
        self.assertTrue(any("daily-token-budget" in a for a in rep["next_actions"]))
        self.assertEqual(rep["usage"]["daily"],
                         {"budget": 100_000_000, "used_before_run": 100_000_000, "run_budget": 0})
        self.assertEqual(rep["usage"]["tokens"], 0)
        self.assertIn("Daily budget: 100,000,000 of 100,000,000", self.summary.read_text())
        self.assertIn("the daily budget left nothing for this run", self.summary.read_text())
        self.assertNotIn("(no run budget)", self.summary.read_text())
        self.assertIn("(token budget spent)", out)
        self.assertEqual(rc, pr_scan.EXIT_OK)

    def test_what_is_left_of_the_day_caps_the_run(self):
        with self.with_meter(99_000_000):
            self.run_main("--max-tokens", "4M", scan=fake_scan(tokens=10),
                          daily=("--daily-token-budget", "100M"))
        rep = self.report()
        self.assertEqual(rep["usage"]["max_tokens"], 1_000_000)
        self.assertEqual(rep["usage"]["daily"]["run_budget"], 1_000_000)
        self.assertEqual(rep["scan"]["results"][0]["granted"], 500_000)
        self.assertEqual(rep["verdict"], "PASS")
        self.assertIn("1,000,000 were left for it", self.summary.read_text())

    def test_an_ordinary_day_leaves_the_run_budget_alone(self):
        with self.with_meter(3_000_000):
            self.run_main("--max-tokens", "4M", scan=fake_scan(tokens=10),
                          daily=("--daily-token-budget", "100M"))
        rep = self.report()
        self.assertEqual(rep["usage"]["max_tokens"], 4_000_000)
        self.assertEqual(rep["verdict"], "PASS")

    def test_an_unreadable_meter_is_a_setup_failure_when_a_budget_is_set(self):
        def refuse(env, **kw):
            raise pr_scan.DailyMeterUnavailable("grant roles/monitoring.viewer")

        with mock.patch.object(pr_scan, "tokens_served_today", refuse):
            rc, out = self.run_main("--fail-closed", scan=fake_scan(),
                                    daily=("--daily-token-budget", "100M"))
        self.assertEqual(rc, pr_scan.EXIT_INFRA)
        self.assertIn("roles/monitoring.viewer", out)
        self.assertFalse(self.out_json.exists())
        with mock.patch.object(pr_scan, "tokens_served_today", refuse):
            rc, out = self.run_main(scan=fake_scan(), daily=("--daily-token-budget", "100M"))
        self.assertEqual(rc, pr_scan.EXIT_OK, "fail-open by default")
        self.assertFalse(self.out_json.exists())
        # Disabled explicitly: the meter is never consulted.
        with mock.patch.object(pr_scan, "tokens_served_today", refuse):
            rc, _ = self.run_main(scan=fake_scan(), daily=("--daily-token-budget", "0"))
        self.assertEqual(rc, pr_scan.EXIT_OK)

    def test_daily_budget_alone_bounds_an_unbounded_run(self):
        with self.with_meter(99_900_000):
            self.run_main("--max-tokens", "0", scan=fake_scan(tokens=10),
                          daily=("--daily-token-budget", "100M"))
        rep = self.report()
        self.assertEqual(rep["usage"]["max_tokens"], 100_000)
        self.assertEqual(rep["scan"]["results"][0]["granted"], 50_000)


class TestArchivingByFinder(KnowledgeCase):
    knowledge_model = "vertex_ai/finder"

    def refresh(self, *extra, scan):
        out_dir = Path(self.tmp) / "export"
        rc, out = self.run_main("--export-knowledge", str(out_dir), *extra, scan=scan)
        return rc, out, out_dir

    def test_a_different_model_cannot_shelve_the_finding(self):
        # The base finding was found by one model; the refresh runs a second
        # only, which rescans the rewritten line and reports nothing. Left open.
        rc, out, out_dir = self.refresh("--models", "vertex_ai/second", scan=fake_scan())
        rep = self.report()
        self.assertEqual(rep["knowledge"]["archived"], [])
        kept = rep["knowledge"]["kept_open"]
        self.assertEqual([k["lineage_id"] for k in kept], ["lin-app-1"])
        self.assertEqual(kept[0]["found_by"], "vertex_ai/finder")
        self.assertEqual(kept[0]["not_refound_by"], ["vertex_ai/second"])
        self.assertIn("Left open (1)", self.summary.read_text(encoding="utf-8"))
        recs = [json.loads(l) for l in (out_dir / "findings.jsonl").read_text().splitlines()]
        row = next(r for r in recs if r["lineage_id"] == "lin-app-1")
        self.assertEqual(row["status"], "confirmed")
        self.assertEqual(row["model"], "vertex_ai/finder", "the export keeps the finder")
        # And the gate still treats it as open: BLOCK under block.
        self.assertEqual(rep["findings_verdict"], "BLOCK", rep["reasons"])

    def test_the_finder_itself_shelves_it(self):
        rc, out, out_dir = self.refresh("--models", "vertex_ai/second,vertex_ai/finder",
                                        scan=fake_scan())
        rep = self.report()
        self.assertEqual([a["lineage_id"] for a in rep["knowledge"]["archived"]], ["lin-app-1"])
        self.assertNotIn("kept_open", rep["knowledge"])
        runs = {json.loads(l)["run_id"]: json.loads(l)["model"]
                for l in (out_dir / "runs.jsonl").read_text().splitlines()}
        self.assertEqual(runs["full-scan-1"], "vertex_ai/finder", "imported provenance survives the export")
        self.assertIn("vertex_ai/second", runs.values())
        cov = json.loads((out_dir / "coverage.json").read_text())
        by_model = {}
        for e in cov["scanned"]:
            by_model.setdefault(e["model"], set()).add(e["path"])
        # Coverage is the campaign's: app.py sits at the root, so its
        # campaign is the repository (main.group_changed_files), per model.
        self.assertIn(".", by_model["vertex_ai/second"])
        self.assertIn(".", by_model["vertex_ai/finder"])

    def test_a_finding_of_unknown_model_is_shelved_by_anyone(self):
        # Version-1 knowledge names no model: the old rule applies.
        files = _knowledge_files()
        _git(self.repo, "checkout", "-q", self.base)
        (self.repo / ".mantis/knowledge/runs.jsonl").unlink()
        (self.repo / ".mantis/knowledge/manifest.json").write_text(files[".mantis/knowledge/manifest.json"])
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "base v1")
        self.base = _git(self.repo, "rev-parse", "HEAD")
        (self.repo / "app.py").write_text(HEAD_APP, encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "head")
        _git(self.repo, "checkout", "-q", "-B", "main")
        rc, out, out_dir = self.refresh("--models", "vertex_ai/second", scan=fake_scan())
        self.assertEqual([a["lineage_id"] for a in self.report()["knowledge"]["archived"]], ["lin-app-1"])


# The stand-in for a one-process pipeline run: every listed file arrives as a
# --changed-files flag; it writes the spend report the real pipeline does,
# with a per-campaign block (files absolute, as main.py lists them) taken
# from `plan` {rel: {status, tokens, cached, calls, nodes, trigger}}. A file
# the plan does not name gets no campaign. `then_sleep` rewrites the report
# after the campaigns and sleeps, as a run killed after them would.
_FAKE_ONE_PROCESS = """\
import json, sys, time
sys.path.insert(0, {ref_root!r})
from core.cost import record_spend
from core.database import record_run
argv = sys.argv[1:]
listed = [a.split("=", 1)[1] for a in argv if a.startswith("--changed-files=")]
with open({probe!r}, "a") as fh:
    fh.write(json.dumps(argv) + "\\n")
record_run({db!r}, "run-pr", "")
plan = {plan!r}
campaigns = []
for rel in listed:
    p = plan.get(rel)
    if p is None:
        continue
    record_spend({db!r}, "run-pr", {repo!r} + "/" + rel, "changed", tokens=5)
    campaigns.append({{"target": {repo!r} + "/" + rel, "files": [{repo!r} + "/" + rel],
                      "status": p["status"], "pause_trigger": p.get("trigger", ""),
                      "tokens": p["tokens"], "fresh_tokens": p["tokens"] - p.get("cached", 0),
                      "cached_tokens": p.get("cached", 0), "llm_calls": p["calls"],
                      "elapsed_seconds": 1.5, "nodes": p["nodes"]}})
total = sum(c["fresh_tokens"] + c["cached_tokens"] for c in campaigns) + {extra_tokens!r}
calls = sum(c["llm_calls"] for c in campaigns)
path = argv[argv.index("--spend-report") + 1]
report = {{"run_id": "run-pr", "tokens": total, "fresh_tokens": total, "cached_tokens": 0,
          "llm_calls": calls, "pause_trigger": {trigger!r}, "nodes": ["history"],
          "exit_code": None, "campaigns": campaigns}}
if {old_pipeline!r}:
    report.pop("campaigns")
json.dump(report, open(path, "w"))
if {then_sleep!r}:
    time.sleep(30)
sys.exit({code})
"""

_PLAN_DONE = {"status": "done", "tokens": 300_000, "cached": 200_000, "calls": 30, "nodes": FULL_GRAPH}
_PLAN_CAPPED = {"status": "paused", "trigger": "campaign_tokens", "tokens": 450_001, "calls": 12,
                "nodes": ["history", "structural_index", "architect"]}


def fake_one_process(probe, plan, code=0, trigger="", old_pipeline=False, then_sleep=False,
                     extra_tokens=0):
    def _cmd(state, target, max_llm_calls, model):
        return [sys.executable, "-c", _FAKE_ONE_PROCESS.format(
            ref_root=str(pr_scan._REF_ROOT), db=state.db_path, repo=str(state.repo),
            probe=str(probe), plan=plan, code=code, trigger=trigger,
            old_pipeline=old_pipeline, then_sleep=then_sleep, extra_tokens=extra_tokens)]
    return _cmd


class TestOneProcess(DriverCase):
    """--one-process: one pipeline run for the pull request's files, each
    file's status, tokens and examined flag taken from its own campaign."""

    def setUp(self):
        super().setUp()
        # A third changed file in a directory: app.py and new.py at the root
        # are then their own single-file campaigns (main.group_changed_files).
        self.commit_pr({"pkg/lib.py": "def lib(v):\n    return v\n"})
        self.probe = Path(self.tmp) / "argv.jsonl"

    def launches(self):
        return [json.loads(l) for l in self.probe.read_text().splitlines()]

    def results(self):
        return {r["file"]: r for r in self.report()["scan"]["results"]}

    def test_each_file_takes_its_own_campaigns_outcome(self):
        plan = {"app.py": _PLAN_DONE, "new.py": _PLAN_CAPPED, "pkg/lib.py": _PLAN_DONE}
        rc, _ = self.run_main("--one-process", "--max-tokens", "1500000",
                              scan=fake_one_process(self.probe, plan, code=1))
        launches = self.launches()
        self.assertEqual(len(launches), 1, "one pipeline run for every file")
        argv = launches[0]
        self.assertEqual([a for a in argv if a.startswith("--changed-files=")],
                         ["--changed-files=app.py", "--changed-files=new.py", "--changed-files=pkg/lib.py"])
        self.assertEqual(argv[argv.index("--max-tokens") + 1], "1500000")
        self.assertEqual(argv[argv.index("--max-campaign-tokens") + 1], "500000",
                         "an equal share per campaign, so one file cannot spend the others'")
        res = self.results()
        self.assertEqual(res["app.py"]["status"], "done")
        self.assertEqual(res["pkg/lib.py"]["status"], "done")
        self.assertEqual(res["new.py"]["status"], "paused_at_budget",
                         "only the campaign over its share stops; the others finish")
        self.assertEqual(res["new.py"]["pause_trigger"], "campaign_tokens")
        self.assertEqual([res[f]["tokens"] for f in ("app.py", "new.py", "pkg/lib.py")],
                         [300_000, 450_001, 300_000], "cached tokens at full price, per campaign")
        self.assertEqual([res[f]["llm_calls"] for f in ("app.py", "new.py", "pkg/lib.py")], [30, 12, 30])
        self.assertEqual([res[f]["examined"] for f in ("app.py", "new.py", "pkg/lib.py")],
                         [True, False, True], "examined from each campaign's own nodes")
        self.assertEqual(self.report()["usage"]["tokens"], 1_050_001)
        rep = self.report()
        self.assertEqual([u["file"] for u in rep["coverage"]["unaudited"]], ["new.py"])
        self.assertTrue(any("new.py" in r and "share of the run token budget" in r for r in rep["reasons"]),
                        rep["reasons"])
        self.assertEqual(rep["coverage"]["status"], "partial")
        self.assertEqual(rc, pr_scan.EXIT_OK)

    def test_a_file_the_run_made_no_campaign_of_is_not_audited(self):
        # The run finished but listed new.py in no campaign (e.g. not source
        # there): never "done" on the run's exit code alone. The charge the
        # campaigns do not account for lands on it.
        plan = {"app.py": _PLAN_DONE, "pkg/lib.py": _PLAN_DONE}
        self.run_main("--one-process", "--max-tokens", "3M",
                      scan=fake_one_process(self.probe, plan, extra_tokens=7))
        res = self.results()
        self.assertEqual(res["new.py"]["status"], "finished_with_errors")
        self.assertEqual(res["new.py"]["tokens"], 7)
        self.assertEqual(self.report()["usage"]["tokens"], 600_007)

    def test_a_killed_run_keeps_the_campaigns_that_finished(self):
        plan = {"app.py": _PLAN_DONE}
        self.run_main("--one-process", "--max-tokens", "3M", "--per-file-timeout", "1",
                      scan=fake_one_process(self.probe, plan, then_sleep=True))
        res = self.results()
        self.assertEqual(res["app.py"]["status"], "done", "its account was written before the kill")
        self.assertEqual(res["new.py"]["status"], "timed_out")
        self.assertEqual(res["pkg/lib.py"]["status"], "timed_out")
        self.assertEqual(self.report()["usage"]["tokens"], 3_000_000,
                         "a killed run is charged its whole grant")
        self.assertIn("timed out after 3s", self.scan_log(), "the timeout is the files'")

    def test_an_older_pipeline_without_campaigns_gives_every_file_the_runs_outcome(self):
        plan = {"app.py": _PLAN_DONE, "new.py": _PLAN_DONE, "pkg/lib.py": _PLAN_DONE}
        self.run_main("--one-process", "--max-tokens", "3M",
                      scan=fake_one_process(self.probe, plan, old_pipeline=True))
        res = self.results()
        self.assertEqual({r["status"] for r in res.values()}, {"done"})
        self.assertEqual({r["examined"] for r in res.values()}, {False},
                         "merged run nodes cannot say which file was examined")
        self.assertEqual(self.report()["usage"]["tokens"], 900_000)

    def test_a_run_paused_before_a_campaign_leaves_that_file_paused(self):
        plan = {"app.py": _PLAN_DONE}
        self.run_main("--one-process", "--max-tokens", "3M",
                      scan=fake_one_process(self.probe, plan, code=2, trigger="token_budget"))
        res = self.results()
        self.assertEqual(res["app.py"]["status"], "done")
        self.assertEqual(res["new.py"]["status"], "paused_at_budget")
        self.assertEqual(res["new.py"]["pause_trigger"], "token_budget")

    def test_campaigns_below_the_floor_are_not_launched(self):
        floor = pr_scan.MIN_SCAN_ALLOWANCE
        plan = {"app.py": _PLAN_DONE, "new.py": _PLAN_DONE, "pkg/lib.py": _PLAN_DONE}
        self.run_main("--one-process", "--max-tokens", str(2 * floor),
                      scan=fake_one_process(self.probe, plan))
        argv = self.launches()[0]
        self.assertEqual([a for a in argv if a.startswith("--changed-files=")],
                         ["--changed-files=app.py", "--changed-files=new.py"])
        self.assertEqual(argv[argv.index("--max-campaign-tokens") + 1], str(floor))
        self.assertEqual(self.results()["pkg/lib.py"]["status"], "over_budget")
        self.assertEqual(self.report()["scan"]["over_budget"], ["pkg/lib.py"])

    def test_one_campaign_needs_no_share_and_files_in_one_directory_share_it(self):
        state = pr_scan.MantisState(str(self.repo))
        self.commit_pr({"pkg/more.py": "def more():\n    return 2\n"})
        self.assertEqual(pr_scan.campaign_groups(state, ["app.py", "pkg/lib.py", "new.py", "pkg/more.py"]),
                         [["app.py"], ["pkg/lib.py", "pkg/more.py"], ["new.py"]])
        self.assertEqual(pr_scan.campaign_groups(state, ["app.py", "new.py"]), [["app.py", "new.py"]],
                         "root files alone are the one root campaign")
        cmd = pr_scan.scan_command(state, ["app.py", "new.py"], 7, "m", max_tokens=10)
        self.assertNotIn("--max-campaign-tokens", cmd)

    def test_the_mcp_scan_command_is_unchanged_in_one_process_mode(self):
        state = pr_scan.MantisState(str(self.repo))
        base = pr_scan._scan_cmd(state, str(self.repo / "app.py"), 7, "m")
        self.assertEqual(base[2], str(self.repo / "app.py"))
        self.assertNotIn("--scan-mode", base)
        self.assertFalse(any(c.startswith("--changed-files") for c in base))
        cmd = pr_scan.scan_command(state, ["app.py", "-x.py"], 7, "m", max_campaign_tokens=5)
        head = pr_scan._scan_cmd(state, str(self.repo), 7, "m")
        self.assertEqual(cmd[:len(head)], head, "the driver only appends to scan_change's command")
        from scripts.launch import build_parser

        args = build_parser().parse_args(cmd[2:])
        self.assertEqual(args.changed_files, ["app.py", "-x.py"])
        self.assertEqual(args.max_campaign_tokens, "5")

    def test_per_file_mode_is_the_default(self):
        self.assertFalse(pr_scan.parse_args([]).one_process)
        self.run_main("--max-tokens", "1000000", scan=fake_scan(tokens=10))
        self.assertEqual(len(self.report()["scan"]["results"]), 3)
        self.assertEqual(self.report()["usage"]["tokens"], 30)


class TestOneProcessResults(unittest.TestCase):
    """The pure mapping from a run's spend report to per-file results."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.state = pr_scan.MantisState(self.tmp)
        for rel in ("a/x.py", "a/y.py", "b/z.py"):
            p = Path(self.tmp, rel)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x = 1\n")

    def test_a_campaigns_spend_is_shared_by_its_files_and_sums_to_the_charge(self):
        acct = {"tokens": 1_001, "fresh_tokens": 1_001, "cached_tokens": 0, "llm_calls": 7,
                "pause_trigger": "", "nodes": [],
                "campaigns": [{"files": [f"{self.state.repo}/a/x.py", f"{self.state.repo}/a/y.py"],
                               "status": "done", "pause_trigger": "", "tokens": 1_001,
                               "fresh_tokens": 1_001, "cached_tokens": 0, "llm_calls": 7,
                               "elapsed_seconds": 2.0, "nodes": FULL_GRAPH}]}
        res = pr_scan.one_process_results(self.state, ["a/x.py", "a/y.py", "b/z.py"], "m", 1, acct,
                                          cost=1_500, granted=500, seconds=9.0)
        by = {r["file"]: r for r in res}
        self.assertEqual([by[f]["tokens"] for f in ("a/x.py", "a/y.py", "b/z.py")], [501, 500, 499])
        self.assertEqual(sum(r["tokens"] for r in res), 1_500)
        self.assertEqual([by[f]["llm_calls"] for f in ("a/x.py", "a/y.py", "b/z.py")], [4, 3, 0])
        self.assertEqual(by["b/z.py"]["status"], "finished_with_errors")
        self.assertTrue(by["a/x.py"]["examined"] and by["a/y.py"]["examined"])

    def test_no_account_is_charged_in_full_and_counts_nothing(self):
        res = pr_scan.one_process_results(self.state, ["a/x.py", "b/z.py"], "m", None, None,
                                          cost=1_000, granted=500, seconds=3.0)
        self.assertEqual([r["status"] for r in res], ["timed_out", "timed_out"])
        self.assertEqual([r["tokens"] for r in res], [500, 500])
        self.assertEqual([r["llm_calls"] for r in res], [None, None])
        self.assertEqual(pr_scan.charge_for(None, None, 1_000), 1_000)
        self.assertEqual(pr_scan.charge_for(None, {"tokens": 10, "fresh_tokens": 10, "cached_tokens": 0}, 1_000),
                         1_000, "a killed run's partial account does not lower its charge")
        self.assertEqual(pr_scan.charge_for(-1, None, 1_000), 0)

    def test_rejected_credentials_reach_the_caller(self):
        acct = {"tokens": 0, "fresh_tokens": 0, "cached_tokens": 0, "llm_calls": 0,
                "pause_trigger": "", "nodes": [], "campaigns": []}
        res = pr_scan.one_process_results(self.state, ["a/x.py"], "m", pr_scan.EXIT_AUTH, acct,
                                          cost=0, granted=0, seconds=1.0)
        self.assertEqual(res[0]["status"], "credentials_rejected")


if __name__ == "__main__":
    unittest.main()

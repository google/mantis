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

"""Phase-2 CL 3 regression tests:
- research-tools-2: LLM citation formats & partial-batch report_findings persistence
- research-tools-7: \\n-only line splitting & source-only line numbering in read_file / get_function_boundary
- gap-non-utf8-and-awkward-inputs-1: bytes-mode git execution surviving Latin-1 / binary output
- Subdirectory git-tool support: list_files, get_git_log, get_git_diff on nested repo targets
- structural-index-1, 2, 3, 4 & gap-degraded-structural-index-1..3: decorators/attributes,
  tiered indexing priority, target-scoped catalog isolation, SQL filepath pushdown, parser warnings
- planner-surveyor-4: sink noise removal, real command sinks, and <= 5 per-file sink cap
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from core.checklist import build_slice_audit_checklist  # noqa: E402
from core.context import RunContext, current_run_context  # noqa: E402
from core.database import init_db, read_findings  # noqa: E402
from core.environments.static_env import StaticOnlyEnvironment  # noqa: E402
from core.llm_gateway import UNTRUSTED_DATA_END, UNTRUSTED_DATA_START  # noqa: E402
import core.structural_index as sidx  # noqa: E402
from core.structural_index import build_structural_index, state_dir_for_db  # noqa: E402
import tools.research_tools as rt  # noqa: E402
import tools.structural_tools as st  # noqa: E402


def _git(repo: Path, *args: str, env: dict[str, str] | None = None) -> None:
    run_env = dict(os.environ)
    run_env["GIT_CONFIG_NOSYSTEM"] = "1"
    run_env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    run_env.setdefault("GIT_AUTHOR_NAME", "Tester")
    run_env.setdefault("GIT_AUTHOR_EMAIL", "tester@example.com")
    run_env.setdefault("GIT_COMMITTER_NAME", "Tester")
    run_env.setdefault("GIT_COMMITTER_EMAIL", "tester@example.com")
    if env:
        run_env.update(env)
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        env=run_env,
    )


class TestP2ResearchToolsCitationsAndReads(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="mantis_p2_rt_")))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = self.tmp / "repo"
        (self.repo / "routes").mkdir(parents=True)
        (self.repo / "pkg").mkdir(parents=True)
        (self.repo / "app.py").write_text(
            "def helper(x):\n"
            "    return x\n"
            "def handle_login(req):\n"
            "    return helper(req)\n",
            encoding="utf-8",
        )
        (self.repo / "auth.cpp").write_text(
            "class Auth {\n"
            "  bool Auth::login(const char* u) { return true; }\n"
            "};\n",
            encoding="utf-8",
        )
        (self.repo / "routes" / "api.py").write_text(
            "def fetch_user(uid):\n"
            "    return {'id': uid, 'role': 'member'}\n",
            encoding="utf-8",
        )
        (self.repo / "pkg" / "mod.rs").write_text(
            "pub fn handle_req() -> i32 {\n"
            "    42\n"
            "}\n",
            encoding="utf-8",
        )
        self.db = str(self.tmp / "knowledge.db")
        init_db(self.db)
        self.ctx = RunContext(
            jail_dir=str(self.repo),
            db_path=self.db,
            target_file=str(self.repo),
            sandbox=StaticOnlyEnvironment(target_path=str(self.repo)),
            run_id="r_p2_rt",
        )
        self._tok = current_run_context.set(self.ctx)
        self.addCleanup(current_run_context.reset, self._tok)

    def test_report_findings_accepts_llm_citation_formats(self):
        res = rt.report_findings(
            {
                "findings": [
                    {
                        "title": "CppScopeResolution",
                        "filepath": "auth.cpp",
                        "severity": "HIGH",
                        "description": "Bypass in Auth::login",
                        "line_numbers": [2],
                        "code_paths": ["auth.cpp:Auth::login", "auth.cpp:L2"],
                    },
                    {
                        "title": "LineRangeAndColAndQualified",
                        "filepath": "routes/api.py",
                        "severity": "MEDIUM",
                        "description": "IDOR in fetch_user",
                        "line_numbers": [1, 2],
                        "code_paths": [
                            "routes/api.py:L1-L2",
                            "routes/api.py:1-2",
                            "routes/api.py:2:28",
                            "routes/api.py:api.fetch_user",
                        ],
                    },
                    {
                        "title": "RustThreePartQualified",
                        "filepath": "pkg/mod.rs",
                        "severity": "LOW",
                        "description": "Unchecked request in handle_req",
                        "line_numbers": [1],
                        "code_paths": ["pkg/mod.rs:L1:impl::handle_req"],
                    },
                ]
            }
        )
        self.assertTrue(res.startswith("SUCCESS"), res)
        saved = read_findings(self.db, run_id="r_p2_rt")
        self.assertEqual(len(saved), 3)

    def test_report_findings_partial_batch_persists_valid_and_reports_rejected(self):
        res = rt.report_findings(
            {
                "findings": [
                    {
                        "title": "ValidFinding1",
                        "filepath": "app.py",
                        "severity": "HIGH",
                        "description": "d1",
                        "line_numbers": [2],
                        "code_paths": ["app.py:L2"],
                    },
                    {
                        "title": "ValidFinding2",
                        "filepath": "app.py",
                        "severity": "MEDIUM",
                        "description": "d2",
                        "line_numbers": [3],
                        "code_paths": ["app.py:handle_login"],
                    },
                    {
                        "title": "InvalidMiddleFinding",
                        "filepath": "app.py",
                        "severity": "LOW",
                        "description": "hallucinated line and symbol",
                        "line_numbers": [999],
                        "code_paths": ["app.py:totally_missing_fn_xyz"],
                    },
                    {
                        "title": "ValidFinding4",
                        "filepath": "auth.cpp",
                        "severity": "HIGH",
                        "description": "d4",
                        "line_numbers": [2],
                        "code_paths": ["auth.cpp:Auth::login"],
                    },
                    {
                        "title": "ValidFinding5",
                        "filepath": "routes/api.py",
                        "severity": "MEDIUM",
                        "description": "d5",
                        "line_numbers": [2],
                        "code_paths": ["routes/api.py:1-2"],
                    },
                ]
            }
        )
        self.assertTrue(res.startswith("PARTIAL SUCCESS"), res)
        self.assertIn("Saved 4", res)
        self.assertIn("InvalidMiddleFinding", res)
        self.assertIn("totally_missing_fn_xyz", res)

        saved = read_findings(self.db, run_id="r_p2_rt")
        titles = {r["title"] for r in saved}
        self.assertEqual(
            titles,
            {"ValidFinding1", "ValidFinding2", "ValidFinding4", "ValidFinding5"},
        )

    async def test_read_file_and_boundary_newline_only_and_line_numbers_source_only(self):
        weird = self.repo / "weird.py"
        weird.write_text(
            "# banner \x0c formfeed \x0c two \u2028 unicode_ls\n"
            "def check_guard(x):\n"
            "    if not x:\n"
            "        raise ValueError('denied')\n"
            "    return 'secret_ok'\n",
            encoding="utf-8",
        )
        build_structural_index(str(self.repo), state_dir_for_db(self.db), "unknown")

        out = await rt.read_file("weird.py", start_line=2, end_line=5)
        self.assertTrue(out.startswith("[weird.py: lines 2-5 of 5]\n"), out)
        inside = out[out.index(UNTRUSTED_DATA_START) : out.index(UNTRUSTED_DATA_END)]
        self.assertIn("2: def check_guard(x):\n", inside)
        self.assertIn("5:     return 'secret_ok'", inside)

        boundary = await st.get_function_boundary("weird.py", 2)
        self.assertIn("2: def check_guard(x):", boundary)
        self.assertIn("5:     return 'secret_ok'", boundary)

        # Virtual workspace / DB reads MUST stay completely unnumbered
        await rt.write_file("workspace/kb/THREAT_MODEL.md", "# Threat\nLine two")
        tm_doc = await rt.read_file("workspace/kb/THREAT_MODEL.md")
        self.assertEqual(tm_doc, "# Threat\nLine two")

        rt.record_summary({"overview": "Clean summary", "key_modules": ["app"]})
        sum_doc = await rt.read_file("mantis-summary.md")
        self.assertNotIn("1: ", sum_doc)
        self.assertIn("Clean summary", sum_doc)


class TestP2GitBytesAndSubdirectoryTargets(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="mantis_p2_git_")))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = str(self.tmp / "knowledge.db")
        init_db(self.db)

    async def test_git_tools_bytes_mode_survives_latin1_and_binary_output(self):
        repo = self.tmp / "latin1_repo"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        (repo / "legacy.c").write_bytes(b"/* Author: J\xf6rg \xe9 */\nint v = 1;\n")
        _git(repo, "add", "legacy.c")
        _git(repo, "commit", "-q", "-m", "init legacy")

        (repo / "legacy.c").write_bytes(b"/* Author: J\xf6rg \xe9 \xff */\nint v = 2;\n")
        _git(repo, "add", "legacy.c")
        # Commit message & author containing raw Latin-1 bytes via commit-tree
        tree = subprocess.check_output(["git", "-C", str(repo), "write-tree"]).strip()
        parent = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"]).strip()
        commit_env = dict(os.environ)
        commit_env["GIT_CONFIG_NOSYSTEM"] = "1"
        commit_env["GIT_CONFIG_GLOBAL"] = "/dev/null"
        new_head = subprocess.run(
            ["git", "-C", str(repo), "commit-tree", tree.decode(), "-p", parent.decode()],
            input=b"Fix caf\xe9 parser \xf6\xff\n",
            capture_output=True,
            check=True,
            env=commit_env,
        ).stdout.strip()
        subprocess.run(
            ["git", "-C", str(repo), "update-ref", "HEAD", new_head.decode()],
            check=True,
            env=commit_env,
        )

        ctx = RunContext(
            jail_dir=str(repo),
            db_path=self.db,
            target_file=str(repo),
            run_id="r_latin1",
        )
        tok = current_run_context.set(ctx)
        try:
            raw_log, ok = rt._run_safe_git_command(["log", "-n2"], repo)
            self.assertTrue(ok, raw_log)
            log_out = await rt.get_git_log(max_commits=5)
            diff_out = await rt.get_git_diff()
            self.assertIn("UNTRUSTED_SOURCE_CODE_DATA_START", log_out)
            self.assertIn("UNTRUSTED_SOURCE_CODE_DATA_START", diff_out)
            self.assertIn("int v = 2;", diff_out)
        finally:
            current_run_context.reset(tok)

    async def test_subdirectory_git_target_hides_gitignored_and_scopes_log_and_diff_safely(self):
        repo = self.tmp / "monorepo"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        (repo / ".gitignore").write_text("build/\n*.ignored.txt\n.env\n", encoding="utf-8")
        (repo / "outside_secret.py").write_text("OUTSIDE_V1 = 1\n", encoding="utf-8")
        sub = repo / "packages" / "sub"
        sub.mkdir(parents=True)
        (sub / "app.py").write_text("def sub_v1():\n    return 1\n", encoding="utf-8")
        _git(repo, "add", ".gitignore", "outside_secret.py", "packages/sub/app.py")
        _git(repo, "commit", "-q", "-m", "INITIAL_MONOREPO_COMMIT")

        # Commit 2: outside-only commit (must NOT show in sub's git log)
        (repo / "outside_secret.py").write_text("OUTSIDE_V2 = 2\n", encoding="utf-8")
        _git(repo, "add", "outside_secret.py")
        _git(repo, "commit", "-q", "-m", "OUTSIDE_COMMIT_ONLY")

        # Commit 3: touches both outside_secret.py and packages/sub/app.py
        (repo / "outside_secret.py").write_text("OUTSIDE_HUNK_SECRET = 999\n", encoding="utf-8")
        (sub / "app.py").write_text("def sub_v2():\n    return 2\n", encoding="utf-8")
        _git(repo, "add", "outside_secret.py", "packages/sub/app.py")
        _git(repo, "commit", "-q", "-m", "SUBDIR_AUTH_FIX")

        # Create gitignored artifacts + untracked source inside sub
        (sub / "build").mkdir()
        (sub / "build" / "bundle.js").write_text("ignored build output\n", encoding="utf-8")
        (sub / "debug.ignored.txt").write_text("ignored debug log\n", encoding="utf-8")
        (sub / ".env").write_text("API_SECRET=topsecret\n", encoding="utf-8")
        (sub / "helper.py").write_text("def helper():\n    return 3\n", encoding="utf-8")

        for sandbox in (StaticOnlyEnvironment(target_path=str(sub)), None):
            ctx = RunContext(
                jail_dir=str(sub),
                db_path=self.db,
                target_file=str(sub),
                sandbox=sandbox,
                run_id="r_subdir",
            )
            tok = current_run_context.set(ctx)
            try:
                listed = json.loads(await rt.list_files(""))
                self.assertEqual(listed, ["app.py", "helper.py"])

                log_out = await rt.get_git_log(max_commits=10)
                self.assertNotIn("not a git repository", log_out.lower())
                self.assertIn("SUBDIR_AUTH_FIX", log_out)
                self.assertNotIn("OUTSIDE_COMMIT_ONLY", log_out)

                diff_out = await rt.get_git_diff()
                self.assertIn("def sub_v2():", diff_out)
                self.assertNotIn("OUTSIDE_HUNK_SECRET", diff_out)

                # Path traversal outside sub in get_git_log / get_git_diff stays denied
                escape_log = await rt.get_git_log(path="../outside_secret.py")
                self.assertIn("Permission denied", escape_log)
            finally:
                current_run_context.reset(tok)

        # Symlink escape from outside directory into repo/packages/sub must NOT grant git access
        escape_parent = self.tmp / "escape_holder"
        escape_parent.mkdir()
        sym_sub = escape_parent / "linked_sub"
        sym_sub.symlink_to(sub)
        sym_ctx = RunContext(
            jail_dir=str(sym_sub),
            db_path=self.db,
            target_file=str(sym_sub),
            sandbox=StaticOnlyEnvironment(target_path=str(sym_sub)),
            run_id="r_sym_sub",
        )
        tok_sym = current_run_context.set(sym_ctx)
        try:
            sym_list = await rt.list_files("")
            self.assertIn("Permission denied", sym_list)
        finally:
            current_run_context.reset(tok_sym)


class TestP2StructuralIndexAndChecklist(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="mantis_p2_sidx_")))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    async def test_structural_index_includes_decorators_and_attributes_across_languages(self):
        self.assertGreaterEqual(getattr(sidx, "_EXTRACTOR_SCHEMA_VERSION", 0), 2)
        repo = self.tmp / "dec_repo"
        repo.mkdir()
        (repo / "app.py").write_text(
            "@login_required\n"
            "@app.route('/admin')\n"
            "def export_users():\n"
            "    return 'ok'\n",
            encoding="utf-8",
        )
        (repo / "ctrl.ts").write_text(
            "class AdminCtrl {\n"
            "  @UseGuards(Auth)\n"
            "  @Get('/admin')\n"
            "  exportUsers() {\n"
            "    return 1;\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        (repo / "srv.rs").write_text(
            "#[allow(dead_code)]\n"
            "#[get(\"/admin\")]\n"
            "pub fn admin_panel() -> i32 {\n"
            "    1\n"
            "}\n",
            encoding="utf-8",
        )
        (repo / "AuthController.cs").write_text(
            "class AuthController {\n"
            "    [Authorize]\n"
            "    [HttpGet(\"/admin\")]\n"
            "    public int Panel() {\n"
            "        return 1;\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        db = str(self.tmp / "dec.db")
        init_db(db)
        build_structural_index(str(repo), state_dir_for_db(db, str(repo)), "unknown")

        ctx = RunContext(
            jail_dir=str(repo),
            db_path=db,
            target_file=str(repo),
            run_id="r_dec",
        )
        tok = current_run_context.set(ctx)
        try:
            py_b1 = await st.get_function_boundary("app.py", 1)
            py_b3 = await st.get_function_boundary("app.py", 3)
            self.assertIn("@login_required", py_b1)
            self.assertIn("@app.route('/admin')", py_b3)

            ts_b = await st.get_function_boundary("ctrl.ts", 2)
            self.assertIn("@UseGuards(Auth)", ts_b)
            self.assertIn("@Get('/admin')", ts_b)

            rs_b = await st.get_function_boundary("srv.rs", 1)
            self.assertIn("#[allow(dead_code)]", rs_b)
            self.assertIn('#[get("/admin")]', rs_b)

            cs_b = await st.get_function_boundary("AuthController.cs", 2)
            self.assertIn("[Authorize]", cs_b)
            self.assertIn('[HttpGet("/admin")]', cs_b)

            checklist = build_slice_audit_checklist(ctx)
            self.assertIn("export_users", checklist)
        finally:
            current_run_context.reset(tok)

    def test_structural_index_prioritizes_first_party_tiers_before_cap(self):
        repo = self.tmp / "tiered_repo"
        (repo / "a_vendor" / "third_party").mkdir(parents=True)
        (repo / "b_tests").mkdir(parents=True)
        (repo / "z_src").mkdir(parents=True)

        for i in range(4):
            (repo / "a_vendor" / "third_party" / f"v{i}.py").write_text(f"def vend_{i}():\n    return {i}\n")
        for i in range(3):
            (repo / "b_tests" / f"test_u{i}.py").write_text(f"def test_fn_{i}():\n    return {i}\n")
        (repo / "z_src" / "core_a.py").write_text("def prod_a():\n    return 1\n")
        (repo / "z_src" / "core_b.py").write_text("def prod_b():\n    return 2\n")

        state = self.tmp / "tier_state"
        with mock.patch.object(sidx, "MAX_UNITS", 4):
            res = build_structural_index(str(repo), str(state), "unknown")

        self.assertEqual(res["status"], "partial")
        self.assertTrue(res["truncated"])
        idx = sidx.StructuralIndex(str(state))
        self.assertEqual(idx.resolve_symbol("prod_a")["total"], 1)
        self.assertEqual(idx.resolve_symbol("prod_b")["total"], 1)
        self.assertEqual(idx.resolve_symbol("vend_0")["total"], 0)

    def test_structural_index_target_scoping_blocks_cross_repo_leak_on_shared_db(self):
        repo_a = self.tmp / "repo_a"
        repo_b = self.tmp / "repo_b"
        repo_a.mkdir()
        repo_b.mkdir()
        (repo_a / "secret_a.py").write_text("def only_in_repo_a():\n    return 'a'\n")
        (repo_b / "app_b.py").write_text("def only_in_repo_b():\n    return 'b'\n")

        shared_db = str(self.tmp / "shared_knowledge.db")
        init_db(shared_db)

        # Build repo_a via legacy 1-arg state_dir_for_db (simulating graph_loader)
        build_structural_index(str(repo_a), state_dir_for_db(shared_db), "snap_a")

        # Switch RunContext to unindexed repo_b on the SAME shared_db
        ctx_b = RunContext(
            jail_dir=str(repo_b),
            db_path=shared_db,
            target_file=str(repo_b),
            run_id="r_b",
        )
        tok_b = current_run_context.set(ctx_b)
        try:
            leaked = st.find_symbol("only_in_repo_a")
            self.assertIn("unavailable", leaked.lower())
            self.assertNotIn("secret_a.py", leaked)
        finally:
            current_run_context.reset(tok_b)

        # Now index repo_b on the same shared_db; switching back to repo_a still serves repo_a!
        build_structural_index(str(repo_b), state_dir_for_db(shared_db), "snap_b")
        ctx_a = RunContext(
            jail_dir=str(repo_a),
            db_path=shared_db,
            target_file=str(repo_a),
            run_id="r_a",
        )
        tok_a = current_run_context.set(ctx_a)
        try:
            sym_a = st.find_symbol("only_in_repo_a")
            self.assertIn("secret_a.py", sym_a)
            sym_b_from_a = st.find_symbol("only_in_repo_b")
            self.assertNotIn("app_b.py", sym_b_from_a)
        finally:
            current_run_context.reset(tok_a)

    def test_resolve_symbol_pushes_filepath_filter_into_sql_before_limit(self):
        repo = self.tmp / "many_syms"
        repo.mkdir()
        for i in range(30):
            (repo / f"f{i:02d}.py").write_text("def handle():\n    return 1\n")
        (repo / "caller.py").write_text("import f27\ndef entry():\n    return f27.handle()\n")

        db = str(self.tmp / "many.db")
        init_db(db)
        build_structural_index(str(repo), state_dir_for_db(db, str(repo)), "unknown")

        ctx = RunContext(
            jail_dir=str(repo),
            db_path=db,
            target_file=str(repo),
            run_id="r_many",
        )
        tok = current_run_context.set(ctx)
        try:
            out = st.find_callers("handle", filepath="f27.py")
            self.assertNotIn("No definition of 'handle'", out)
            self.assertIn("caller.py", out)
        finally:
            current_run_context.reset(tok)

    def test_load_parser_logs_warning_once_and_single_file_unavailable_message(self):
        fake_mod = mock.MagicMock()
        fake_mod.get_parser.side_effect = RuntimeError("synthetic grammar failure")
        if hasattr(sidx, "_FAILED_PARSERS"):
            sidx._FAILED_PARSERS.clear()
        with mock.patch.dict(sys.modules, {"tree_sitter_language_pack": fake_mod}):
            with self.assertLogs("core.structural_index", level="WARNING") as cm:
                self.assertIsNone(sidx._load_parser("synthetic_broken_lang"))
                self.assertIsNone(sidx._load_parser("synthetic_broken_lang"))
        self.assertEqual(len(cm.output), 1)
        self.assertIn("synthetic_broken_lang", cm.output[0])

        # Single-file campaign with unavailable index gives accurate single-file guidance
        repo = self.tmp / "single_unavail"
        repo.mkdir()
        target = repo / "app.py"
        target.write_text("x = 1\n")
        empty_db = str(self.tmp / "no_idx.db")
        init_db(empty_db)
        ctx = RunContext(
            jail_dir=str(repo),
            db_path=empty_db,
            target_file=str(target),
            run_id="r_single_unavail",
        )
        tok = current_run_context.set(ctx)
        try:
            msg = st.find_symbol("x")
            self.assertIn("unavailable", msg.lower())
            self.assertIn("read_file", msg)
            self.assertNotIn("changes nothing about what you can read", msg)
        finally:
            current_run_context.reset(tok)

    def test_checklist_removes_noisy_sinks_adds_cmd_sinks_and_caps_per_file(self):
        repo = self.tmp / "checklist_repo"
        repo.mkdir()
        benign_lines = ["import json, re", "def parse_cfg(raw, db):"]
        for i in range(20):
            benign_lines.append(f"    j{i} = json.loads(raw)")
            benign_lines.append(f"    r{i} = re.compile('^a{i}$')")
        for i in range(12):
            benign_lines.append(f"    db.execute('SELECT {i}')")
        (repo / "a_benign_flood.py").write_text("\n".join(benign_lines) + "\n", encoding="utf-8")

        (repo / "z_cmd_sinks.py").write_text(
            "import os, subprocess\n"
            "def run_ops(cmd):\n"
            "    subprocess.run(cmd, shell=True)\n"
            "    subprocess.call(cmd, shell=True)\n"
            "    subprocess.Popen(cmd, shell=True)\n"
            "    os.system(cmd)\n",
            encoding="utf-8",
        )
        (repo / "runner.go").write_text(
            "package main\n"
            "import \"os/exec\"\n"
            "func runCmd(arg string) {\n"
            "    exec.Command(\"sh\", \"-c\", arg)\n"
            "}\n",
            encoding="utf-8",
        )

        db = str(self.tmp / "chk.db")
        init_db(db)
        build_structural_index(str(repo), state_dir_for_db(db, str(repo)), "unknown")

        ctx = RunContext(
            jail_dir=str(repo),
            db_path=db,
            target_file=str(repo),
            run_id="r_chk",
        )
        checklist = build_slice_audit_checklist(ctx)
        self.assertNotIn("-> loads()", checklist)
        self.assertNotIn("-> compile()", checklist)
        flood_bullets = [
            ln for ln in checklist.splitlines() if "a_benign_flood.py:" in ln
        ]
        self.assertLessEqual(len(flood_bullets), 5, flood_bullets)
        self.assertGreaterEqual(len(flood_bullets), 1)
        self.assertIn("z_cmd_sinks.py:3 -> run()", checklist)
        self.assertIn("z_cmd_sinks.py:4 -> call()", checklist)
        self.assertIn("z_cmd_sinks.py:5 -> Popen()", checklist)
        self.assertIn("z_cmd_sinks.py:6 -> system()", checklist)
        self.assertIn("runner.go:4 -> Command()", checklist)


if __name__ == "__main__":
    unittest.main()

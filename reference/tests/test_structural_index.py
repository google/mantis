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

"""Tests for the deterministic structural index, its tools, and interception.

The index is a navigation hint built by tree-sitter, published atomically
next to the campaign database. These tests pin the four properties the
rest of the harness relies on: fail-safe degradation (INV-6: no parser, no
index, unreadable state all cost nothing but the hints), snapshot reuse
semantics, refusal to guess on ambiguity, and the same jail and
untrusted-content treatment as read_file. No LLM calls.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from core.context import RunContext, current_run_context
from core.structural_index import (
    _AMBIENT_RECEIVERS,
    MAX_FILE_BYTES,
    StructuralIndex,
    _CandidateLookup,
    _language_for,
    _load_parser,
    _resolve_callee_id,
    build_structural_index,
    extract_unit,
    git_snapshot_id,
    state_dir_for_db,
)

AUTH_PY = '''\
def check_password(pw):
    return pw == "x"

def login(user, pw):
    if check_password(pw):
        return True
    return False

def outer():
    def inner():
        return 1
    return inner()

class Session:
    def refresh(self):
        return login("u", "p")
'''

DB_PY = '''\
def helper():
    return 1

def query():
    return helper()
'''

UTIL_JS = '''\
function helper(n) { return n; }
function run() { return helper(2); }
'''


def _write_fixture(code: Path):
    (code / "app").mkdir(parents=True)
    (code / "lib").mkdir(parents=True)
    (code / "app" / "auth.py").write_text(AUTH_PY)
    (code / "app" / "db.py").write_text(DB_PY)
    (code / "lib" / "util.js").write_text(UTIL_JS)
    (code / "README.md").write_text("# docs\n")


CPP_WIDGET_CC = '''\
class Widget {
 public:
  Widget& assign(const Widget& other);
  bool operator==(const Widget& other) const { return true; }
  ~Widget() {}
  operator bool() const { return true; }
  int& ref_count() { return count_; }
 private:
  int count_;
};

Widget& Widget::assign(const Widget& other) { return *this; }
'''


class CppDeclaratorNamingTest(unittest.TestCase):
    """C++ members behind field-less declarator wrappers get real names.

    `T& f()` must mint f (cpp reference_declarator exposes no fields, so
    the chain walker previously fell back to the return type), operators
    and destructors are name terminals, and conversion operators follow
    ctags semantics ("operator <type>").
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_sidx_cpp_")
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(os.path.realpath(self._tmp.name))
        code = tmp / "code"
        code.mkdir()
        (code / "widget.cc").write_text(CPP_WIDGET_CC)
        res = build_structural_index(str(code), str(tmp / "state"), "snapcpp")
        if res["status"] != "complete":
            self.skipTest("cpp grammar unavailable in this environment")
        self.idx = StructuralIndex(str(tmp / "state"))

    def _only(self, name):
        res = self.idx.resolve_symbol(name)
        self.assertEqual(res["total"], 1, f"{name!r} should resolve uniquely")
        return res["results"][0]

    def test_reference_return_members_keep_their_names(self):
        self.assertEqual(
            self._only("ref_count")["qualified_name"], "Widget.ref_count"
        )
        self.assertEqual(self._only("assign")["name"], "assign")

    def test_return_type_does_not_pollute_class_lookups(self):
        self.assertEqual(self._only("Widget")["kind"], "class")

    def test_operators_destructors_and_conversions_are_minted(self):
        self.assertEqual(
            self._only("operator==")["qualified_name"], "Widget.operator=="
        )
        self.assertEqual(
            self._only("~Widget")["qualified_name"], "Widget.~Widget"
        )
        self.assertEqual(
            self._only("operator bool")["qualified_name"],
            "Widget.operator bool",
        )


class BuildTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_sidx_build_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(os.path.realpath(self._tmp.name))
        self.code = self.tmp / "code"
        self.state = self.tmp / "state"
        _write_fixture(self.code)

    def test_build_is_complete_and_catalog_queryable(self):
        res = build_structural_index(str(self.code), str(self.state), "snap1")
        self.assertEqual(res["status"], "complete")
        self.assertEqual(res["coverage"]["total_files"], 3)  # README not source
        self.assertEqual(res["coverage"]["indexed_files"], 3)
        idx = StructuralIndex(str(self.state))
        self.assertTrue(idx.available())
        login = idx.resolve_symbol("login")
        self.assertEqual(login["total"], 1)
        self.assertEqual(login["results"][0]["file_path"], "app/auth.py")

    def test_unique_name_resolves_direct_ambiguous_stays_unresolved(self):
        build_structural_index(str(self.code), str(self.state), "snap1")
        idx = StructuralIndex(str(self.state))
        login = idx.resolve_symbol("login")["results"][0]
        callees = idx.find_callees(login)["results"]
        kinds = {e["callee_name"]: e["edge_kind"] for e in callees}
        # check_password is unique in the catalog -> direct.
        self.assertEqual(kinds.get("check_password"), "direct")
        # helper is defined in app/db.py AND lib/util.js: a guess between
        # them would fabricate evidence, so the edge stays unresolved.
        query = idx.resolve_symbol("query")["results"][0]
        q_callees = idx.find_callees(query)["results"]
        self.assertEqual(q_callees[0]["callee_name"], "helper")
        self.assertEqual(q_callees[0]["edge_kind"], "unresolved")

    def test_callers_include_unresolved_name_matches(self):
        build_structural_index(str(self.code), str(self.state), "snap1")
        idx = StructuralIndex(str(self.state))
        helper_py = [
            r for r in idx.resolve_symbol("helper")["results"]
            if r["file_path"] == "app/db.py"
        ][0]
        callers = idx.find_callers(helper_py)["results"]
        # Both the python and js call sites surface: dropping the
        # name-only matches would silently narrow the audit set.
        files = {c["file_path"] for c in callers}
        self.assertIn("app/db.py", files)
        self.assertIn("lib/util.js", files)

    def test_qualified_call_does_not_misresolve_to_unrelated_class_method(self):
        # Dogfood regression: routes/login.ts calls `UserModel.findAll(...)` and
        # `console.log(...)`, while the only `findAll` and `log` definitions in
        # the catalog belong to `RecycleComponent` and `AuditLogger`. Neither
        # call may resolve as a 'direct' edge to the unrelated class.
        (self.code / "app" / "components.py").write_text(
            "class RecycleComponent:\n"
            "    def findAll(self):\n"
            "        return []\n\n"
            "class AuditLogger:\n"
            "    def log(self, msg):\n"
            "        return msg\n\n"
            "def route_login():\n"
            "    console.log('hi')\n"
            "    return UserModel.findAll()\n"
        )
        build_structural_index(str(self.code), str(self.state), "snap_qual1")
        idx = StructuralIndex(str(self.state))
        route = idx.resolve_symbol("route_login")["results"][0]
        callees = {
            e["callee_name"]: e["edge_kind"]
            for e in idx.find_callees(route)["results"]
        }
        self.assertEqual(callees.get("findAll"), "unresolved", callees)
        self.assertEqual(callees.get("log"), "unresolved", callees)

    def test_qualified_call_disambiguates_same_named_methods(self):
        (self.code / "app" / "tokens.py").write_text(
            "class Token:\n"
            "    def refresh(self):\n"
            "        return 't'\n\n"
            "def rotate():\n"
            "    return Session.refresh()\n"
        )
        build_structural_index(str(self.code), str(self.state), "snap_qual2")
        idx = StructuralIndex(str(self.state))
        rotate = idx.resolve_symbol("rotate")["results"][0]
        edges = idx.find_callees(rotate)["results"]
        self.assertEqual(len(edges), 1, edges)
        self.assertEqual(edges[0]["edge_kind"], "direct", edges)
        self.assertEqual(edges[0]["callee"], "Session.refresh", edges)

    def test_snapshot_match_reuses_published_index(self):
        build_structural_index(str(self.code), str(self.state), "snap1")
        res2 = build_structural_index(str(self.code), str(self.state), "snap1")
        self.assertTrue(res2.get("reused"))

    def test_unknown_snapshot_always_rebuilds_with_unit_cache(self):
        res1 = build_structural_index(str(self.code), str(self.state), "unknown")
        self.assertFalse(res1.get("reused", False))
        res2 = build_structural_index(str(self.code), str(self.state), "unknown")
        # Rebuilt (not a manifest reuse), but every unit came from cache.
        self.assertFalse(res2.get("reused", False))
        self.assertEqual(res2["units"]["reused"], res2["units"]["total"])

    def test_renamed_file_is_not_replayed_from_cache(self):
        build_structural_index(str(self.code), str(self.state), "snap1")
        os.rename(self.code / "app" / "db.py", self.code / "app" / "db2.py")
        res = build_structural_index(str(self.code), str(self.state), "snap2")
        self.assertEqual(res["status"], "complete")
        idx = StructuralIndex(str(self.state))
        paths = {r["file_path"] for r in idx.resolve_symbol("query")["results"]}
        self.assertEqual(paths, {"app/db2.py"})

    def test_manifest_commit_is_atomic(self):
        build_structural_index(str(self.code), str(self.state), "snap1")
        self.assertTrue((self.state / "manifest.json").exists())
        self.assertFalse((self.state / "tmp" / "manifest.json").exists())
        self.assertFalse((self.state / "tmp" / "catalog.sqlite.tmp").exists())

    def test_catalog_boundaries_cover_functions_and_methods_only(self):
        build_structural_index(str(self.code), str(self.state), "snap1")
        conn = sqlite3.connect(str(self.state / "catalog.sqlite"))
        try:
            kinds = {
                row[0] for row in conn.execute(
                    "SELECT DISTINCT s.kind FROM function_boundaries b"
                    " JOIN symbols s ON s.symbol_id = b.symbol_id"
                )
            }
        finally:
            conn.close()
        self.assertTrue(kinds.issubset({"function", "method"}), kinds)

    def test_oversized_file_is_skipped_and_status_partial(self):
        (self.code / "big.py").write_text("x = 1\n" * (MAX_FILE_BYTES // 6 + 10))
        res = build_structural_index(str(self.code), str(self.state), "snap1")
        self.assertEqual(res["status"], "partial")
        idx = StructuralIndex(str(self.state))
        self.assertEqual(idx.file_coverage("big.py")["status"], "skipped_too_large")

    def test_missing_parser_degrades_to_empty_without_raising(self):
        # INV-6: mask the language pack so every parser load fails. A fresh
        # state dir guarantees no unit-cache path can mask the degradation.
        masked = types.ModuleType("tree_sitter_language_pack")
        real = sys.modules.get("tree_sitter_language_pack")
        sys.modules["tree_sitter_language_pack"] = masked
        try:
            res = build_structural_index(str(self.code), str(self.state), "snap1")
        finally:
            if real is not None:
                sys.modules["tree_sitter_language_pack"] = real
            else:
                sys.modules.pop("tree_sitter_language_pack", None)
        self.assertEqual(res["status"], "empty")
        self.assertFalse(StructuralIndex(str(self.state)).available())

    def test_unwritable_state_dir_returns_failed_without_raising(self):
        blocker = self.tmp / "blocker"
        blocker.write_text("not a directory")
        res = build_structural_index(str(self.code), str(blocker / "state"), "snap1")
        self.assertEqual(res["status"], "failed")

    def test_empty_target_is_empty_not_an_error(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        res = build_structural_index(str(empty), str(self.state), "snap1")
        self.assertEqual(res["status"], "empty")


class QueryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="mantis_sidx_query_")
        tmp = Path(os.path.realpath(cls._tmp.name))
        cls.code = tmp / "code"
        cls.state = tmp / "state"
        _write_fixture(cls.code)
        build_structural_index(str(cls.code), str(cls.state), "snapq")
        cls.idx = StructuralIndex(str(cls.state))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_ambiguity_is_reported_not_resolved(self):
        res = self.idx.resolve_symbol("helper")
        self.assertEqual(res["total"], 2)
        self.assertTrue(res["ambiguous"])

    def test_pagination_is_stable(self):
        first = self.idx.resolve_symbol("helper", limit=1, offset=0)["results"]
        second = self.idx.resolve_symbol("helper", limit=1, offset=1)["results"]
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertNotEqual(first[0]["symbol_id"], second[0]["symbol_id"])

    def test_boundary_returns_innermost_enclosing_function(self):
        inner_line = AUTH_PY.splitlines().index("        return 1") + 1
        res = self.idx.get_function_boundary("app/auth.py", inner_line)
        self.assertTrue(res["found"])
        self.assertEqual(res["qualified_name"], "outer.inner")

    def test_boundary_miss_carries_partition_status(self):
        res = self.idx.get_function_boundary("app/auth.py", 9999)
        self.assertFalse(res["found"])
        self.assertIn(res["coverage"]["partition_status"], ("complete", "partial"))

    def test_unknown_symbol_is_empty_with_partition_status(self):
        res = self.idx.resolve_symbol("no_such_symbol_zzz")
        self.assertEqual(res["results"], [])
        self.assertIn("partition_status", res["coverage"])

    def test_unenumerated_file_coverage_says_so(self):
        self.assertEqual(
            self.idx.file_coverage("README.md")["status"], "not_enumerated"
        )


class ToolsTest(unittest.IsolatedAsyncioTestCase):
    """The four research tools over the index: wrapped output, refusal on
    ambiguity, jail containment, and fail-safe degradation."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_sidx_tools_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(os.path.realpath(self._tmp.name))
        self.code = self.tmp / "code"
        _write_fixture(self.code)
        self.db = str(self.tmp / "knowledge.db")
        Path(self.db).touch()
        build_structural_index(
            str(self.code), state_dir_for_db(self.db), "snapt"
        )
        self.install_ctx()

    def install_ctx(self, **overrides):
        kwargs = dict(
            jail_dir=str(self.code),
            db_path=self.db,
            target_file="",
            run_id="r1",
        )
        kwargs.update(overrides)
        token = current_run_context.set(RunContext(**kwargs))
        self.addCleanup(current_run_context.reset, token)

    def test_find_symbol_output_is_wrapped(self):
        from core.llm_gateway import UNTRUSTED_DATA_START
        from tools.structural_tools import find_symbol
        out = find_symbol("login")
        self.assertIn(UNTRUSTED_DATA_START, out)
        self.assertIn("app/auth.py", out)

    def test_missing_symbol_is_a_hint_not_a_verdict(self):
        from tools.structural_tools import find_symbol
        out = find_symbol("no_such_symbol_zzz")
        self.assertIn("No definition", out)
        self.assertIn("read_file", out)

    def test_ambiguous_symbol_refuses_with_candidates(self):
        from tools.structural_tools import find_callers
        out = find_callers("helper")
        self.assertIn("ambiguous", out)
        self.assertIn("filepath", out)
        self.assertIn("app/db.py", out)
        self.assertIn("lib/util.js", out)

    def test_filepath_argument_narrows_ambiguity(self):
        from tools.structural_tools import find_callers
        out = find_callers("helper", filepath="app/db.py")
        self.assertIn("call site(s)", out)

    def test_filepath_suffix_narrows_ambiguity(self):
        # 'db.py' is not how the catalog spells it, but only one candidate
        # ends with '/db.py', so the suffix resolves instead of refusing.
        from tools.structural_tools import find_callers
        out = find_callers("helper", filepath="db.py")
        self.assertIn("call site(s)", out)
        self.assertIn("app/db.py", out)

    def test_exact_filepath_beats_suffix(self):
        # A top-level db.py makes 'db.py' both an exact match and a suffix
        # of app/db.py; the exact match must win, not read as ambiguous.
        (self.code / "db.py").write_text("def helper():\n    return 2\n")
        build_structural_index(
            str(self.code), state_dir_for_db(self.db), "snapt4"
        )
        from tools.structural_tools import find_callers
        out = find_callers("helper", filepath="db.py")
        self.assertNotIn("ambiguous", out)
        self.assertIn("call site(s)", out)

    def test_ambiguous_filepath_suffix_refused(self):
        (self.code / "app" / "sub").mkdir()
        (self.code / "lib" / "sub").mkdir()
        (self.code / "app" / "sub" / "dup.py").write_text("def dupfn():\n    return 1\n")
        (self.code / "lib" / "sub" / "dup.py").write_text("def dupfn():\n    return 2\n")
        build_structural_index(
            str(self.code), state_dir_for_db(self.db), "snapt5"
        )
        from tools.structural_tools import find_callers
        out = find_callers("dupfn", filepath="sub/dup.py")
        self.assertIn("ambiguous", out)

    def test_find_callees_marks_unresolved_edges(self):
        from tools.structural_tools import find_callees
        out = find_callees("query")
        self.assertIn("helper", out)
        self.assertIn("external or not indexed", out)

    def test_zero_callers_carries_reachability_caveat(self):
        # 'run' calls helper but nothing calls 'run': the empty result must
        # prompt a reachability check without inviting blanket dismissal of
        # entrypoints that legitimately have no in-index callers.
        from tools.structural_tools import find_callers
        out = find_callers("run")
        self.assertIn("No recorded callers", out)
        self.assertIn("0 direct call sites", out)
        self.assertIn("route handler", out)

    async def test_boundary_returns_wrapped_source(self):
        from core.llm_gateway import UNTRUSTED_DATA_START
        from tools.structural_tools import get_function_boundary
        line = AUTH_PY.splitlines().index('    return pw == "x"') + 1
        out = await get_function_boundary("app/auth.py", line)
        self.assertIn("check_password", out)
        self.assertIn('return pw == "x"', out)
        self.assertIn(UNTRUSTED_DATA_START, out)

    async def test_boundary_scrubs_secrets(self):
        (self.code / "app" / "leaky.py").write_text(
            'def connect():\n    key = "AKIAIOSFODNN7EXAMPLE"\n    return key\n'
        )
        build_structural_index(
            str(self.code), state_dir_for_db(self.db), "snapt2"
        )
        from tools.structural_tools import get_function_boundary
        out = await get_function_boundary("app/leaky.py", 2)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)
        self.assertIn("[REDACTED_AWS_KEY_ID]", out)

    async def test_single_file_jail_refuses_other_files(self):
        self.install_ctx(target_file=str(self.code / "app" / "auth.py"))
        from tools.structural_tools import get_function_boundary
        out = await get_function_boundary("app/db.py", 2)
        self.assertIn("Permission denied", out)

    async def test_boundary_tolerates_path_suffix(self):
        from tools.structural_tools import get_function_boundary
        line = AUTH_PY.splitlines().index('    return pw == "x"') + 1
        out = await get_function_boundary("auth.py", line)
        self.assertIn("check_password", out)
        self.assertIn("app/auth.py", out)

    async def test_jail_applies_to_suffix_resolved_path(self):
        # 'db.py' suffix-resolves to app/db.py; the jail must judge the
        # resolved path, not the spelling the caller used.
        self.install_ctx(target_file=str(self.code / "app" / "auth.py"))
        from tools.structural_tools import get_function_boundary
        out = await get_function_boundary("db.py", 2)
        self.assertIn("Permission denied", out)

    def test_missing_index_degrades_to_baseline_tools(self):
        other_db = str(self.tmp / "elsewhere" / "k.db")
        os.makedirs(os.path.dirname(other_db))
        Path(other_db).touch()
        self.install_ctx(db_path=other_db)
        from tools.structural_tools import find_symbol
        out = find_symbol("login")
        self.assertIn("read_file", out)
        self.assertIn("unavailable", out.lower())

    def test_no_context_is_an_error_not_a_crash(self):
        token = current_run_context.set(None)
        self.addCleanup(current_run_context.reset, token)
        from tools.structural_tools import find_symbol
        self.assertIn("No active execution context", find_symbol("login"))

    def test_partial_index_results_carry_degradation_note(self):
        (self.code / "app" / "huge.py").write_text("x = 1\n" * (MAX_FILE_BYTES // 6 + 10))
        build_structural_index(
            str(self.code), state_dir_for_db(self.db), "snapt3"
        )
        from tools.structural_tools import find_symbol
        out = find_symbol("login")
        self.assertIn("partial", out)
        self.assertIn("not as proof of absence", out)


class ToolRegistrationTest(unittest.TestCase):
    def test_structural_tools_registered(self):
        import tools
        for name in ("find_symbol", "find_callers", "find_callees",
                     "get_function_boundary"):
            self.assertIn(name, tools.TOOLS)

    def test_eval_structural_toolset_names_match_registry(self):
        import tools
        sys.path.insert(0, str(Path(_REF_ROOT) / "evals"))
        try:
            from research_eval import TOOLSETS
        finally:
            sys.path.pop(0)
        for name in TOOLSETS["structural"]:
            self.assertIn(name, tools.TOOLS, f"eval names unknown tool {name}")


class StructuralIndexNodeTest(unittest.IsolatedAsyncioTestCase):
    """The deterministic graph node and its by-id interception."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_sidx_node_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(os.path.realpath(self._tmp.name))
        self.code = self.tmp / "code"
        _write_fixture(self.code)
        self.db = str(self.tmp / "knowledge.db")
        Path(self.db).touch()

    def install_ctx(self, **overrides):
        kwargs = dict(
            jail_dir=str(self.code),
            db_path=self.db,
            target_file="",
            run_id="r1",
            snapshot_id="snapn",
        )
        kwargs.update(overrides)
        token = current_run_context.set(RunContext(**kwargs))
        self.addCleanup(current_run_context.reset, token)

    async def test_node_builds_catalog_next_to_db(self):
        from core.graph_loader import create_structural_index_node
        self.install_ctx()
        n = create_structural_index_node("structural_index")
        mock_ctx = MagicMock()
        mock_ctx.state = {}
        event = await n._func(mock_ctx, node_input=None)
        self.assertIn("Structural index complete", event.output)
        self.assertTrue(
            (Path(state_dir_for_db(self.db)) / "catalog.sqlite").exists()
        )

    async def test_node_prefers_path_root_over_jail(self):
        """A single-file scan's jail is the file's parent directory;
        indexing it would re-root the shared catalog at a subdirectory and
        cross-directory callers would vanish mid-scan. With path_root in
        the context the catalog must stay repo-rooted.
        """
        from core.graph_loader import create_structural_index_node
        self.install_ctx(
            jail_dir=str(self.code / "app"),
            target_file=str(self.code / "app" / "auth.py"),
            path_root=str(self.code),
        )
        n = create_structural_index_node("structural_index")
        mock_ctx = MagicMock()
        mock_ctx.state = {}
        event = await n._func(mock_ctx, node_input=None)
        self.assertIn("Structural index complete", event.output)
        idx = StructuralIndex(state_dir_for_db(self.db))
        # Repo-rooted paths resolve, including a file OUTSIDE the jail.
        self.assertTrue(idx.enclosing_symbol("app/auth.py", 5).get("found"))
        self.assertTrue(idx.enclosing_symbol("lib/util.js", 2).get("found"))

        # The boundary tool must read source through the SAME repo-rooted
        # catalog: its file_path is path_root-relative while the jail is
        # the slice, so without the rebase the single-file gate silently
        # skips and the sandbox read resolves app/app/auth.py.
        from tools.structural_tools import get_function_boundary
        for spelling in ("auth.py", "app/auth.py"):
            out = await get_function_boundary(spelling, 5)
            self.assertIn("def login", out, out)
        # A catalog row outside the jail is structural context only:
        # refused, never handed to the sandbox.
        out = await get_function_boundary("lib/util.js", 2)
        self.assertIn("Permission denied", out, out)
        self.assertNotIn("function run", out, out)

    async def test_node_without_target_skips_and_routes_on(self):
        from core.graph_loader import create_structural_index_node
        self.install_ctx(jail_dir="")
        n = create_structural_index_node("structural_index")
        mock_ctx = MagicMock()
        mock_ctx.state = {}
        event = await n._func(mock_ctx, node_input=None)
        self.assertIn("skipped", event.output)

    def _spec(self, node_id: str) -> dict:
        return {
            "name": "wf_intercept_test",
            "config": {"default_model": "vertex_ai/gemini-3.8-flash"},
            "nodes": [
                {
                    "id": node_id,
                    "type": "agent",
                    "tools": ["this_tool_does_not_exist"],
                    "system_prompt": "p",
                }
            ],
            "edges": [{"from": "START", "to": node_id}],
        }

    def test_loader_intercepts_structural_index_by_id(self):
        # The node declares a nonexistent tool. A regular agent build fails
        # on it; the interception never builds tools or a model, so loading
        # succeeds. This pins that the stage makes no LLM calls.
        from core.graph_loader import load_workflow_from_json
        good = self.tmp / "wf_good.json"
        good.write_text(json.dumps(self._spec("structural_index")))
        load_workflow_from_json(str(good), load_local=False)

        bad = self.tmp / "wf_bad.json"
        bad.write_text(json.dumps(self._spec("some_other_agent")))
        with self.assertRaises(ValueError):
            load_workflow_from_json(str(bad), load_local=False)


class MacroIndexingTest(unittest.TestCase):
    """C preprocessor definitions are indexed as 'macro' symbols so a
    reviewer can check whether a #define changes the semantics a finding
    relies on (e.g. a macro that discards its argument)."""

    C_FILE = (
        "#define PORT_ZERO 0\n"
        "#define get_port(ctx) (PORT_ZERO)\n"
        "\n"
        "int pick(int *arr) {\n"
        "    return arr[get_port(0)];\n"
        "}\n"
    )

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_sidx_macro_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(os.path.realpath(self._tmp.name))
        self.code = self.tmp / "code"
        (self.code / "src").mkdir(parents=True)
        (self.code / "src" / "port.c").write_text(self.C_FILE)
        self.state = str(self.tmp / "state")
        build_structural_index(str(self.code), self.state, "snapm")

    def test_macros_are_indexed_with_kind_macro(self):
        idx = StructuralIndex(self.state)
        plain = idx.resolve_symbol("PORT_ZERO")
        self.assertEqual(plain["total"], 1)
        self.assertEqual(plain["results"][0]["kind"], "macro")
        fn_like = idx.resolve_symbol("get_port")
        self.assertEqual(fn_like["total"], 1)
        self.assertEqual(fn_like["results"][0]["kind"], "macro")

    def test_macro_line_resolves_as_boundary(self):
        idx = StructuralIndex(self.state)
        res = idx.get_function_boundary("src/port.c", 2)
        self.assertTrue(res["found"])
        self.assertEqual(res["qualified_name"], "get_port")


class LanguageCoverageTest(unittest.TestCase):
    """Definition kinds across all supported grammars.

    Each case pins constructs that used to be invisible (Go types, C/C++
    type specifiers, Rust items, Kotlin functions/objects, TS/JS named
    function values, Java/C#/PHP/Ruby type declarations) AND the gates
    that keep the new mappings from minting fake symbols: C/C++ forward
    declarations, Kotlin/Java/C# variable declarations, and python's
    literal "module" root node.
    """

    def _syms(self, fname: str, src: str) -> dict:
        lang = _language_for(fname)
        parser = _load_parser(lang)
        if parser is None:
            self.skipTest(f"no parser for {lang}")
        unit = extract_unit(fname, src.encode(), lang, parser)
        return {
            s["name"]: s["kind"] for s in unit["symbols"] if s["name"] != "<module>"
        }

    def test_h_headers_use_the_cpp_grammar(self):
        # C++ headers do not parse as C; C headers do parse as C++.
        self.assertEqual(_language_for("include/q.h"), "cpp")

    def test_cpp_specifiers_definitions_only(self):
        syms = self._syms("q.h", (
            "struct Node { int v; };\n"
            "struct Node;\n"           # forward declaration
            "struct Node make();\n"    # type reference in a return type
            "enum Color { RED };\n"
            "union Pack { int i; };\n"
            "template <typename T> class Q { void push(T t); };\n"
        ))
        self.assertEqual(syms.get("Node"), "struct")
        self.assertEqual(syms.get("Color"), "enum")
        self.assertEqual(syms.get("Pack"), "union")
        self.assertEqual(syms.get("Q"), "class")

    def test_go_type_declarations(self):
        syms = self._syms("s.go", (
            "package p\n"
            "type Server struct { port int }\n"
            "type Handler interface { Serve() }\n"
            "type Meters = float64\n"
        ))
        self.assertEqual(syms.get("Server"), "type")
        self.assertEqual(syms.get("Handler"), "type")
        self.assertEqual(syms.get("Meters"), "type")

    def test_rust_items(self):
        syms = self._syms("l.rs", (
            "trait Animal { fn speak(&self); }\n"
            "enum Shape { Circle }\n"
            "union U { i: i32, f: f32 }\n"
            "mod inner { pub fn g() {} }\n"
            "type Meters = f64;\n"
            "macro_rules! my_macro { () => {}; }\n"
        ))
        self.assertEqual(syms.get("Animal"), "interface")
        self.assertEqual(syms.get("Shape"), "enum")
        self.assertEqual(syms.get("U"), "union")
        self.assertEqual(syms.get("inner"), "module")
        self.assertEqual(syms.get("g"), "function")
        self.assertEqual(syms.get("Meters"), "type")
        self.assertEqual(syms.get("my_macro"), "macro")

    def test_kotlin_functions_objects_and_no_val_flood(self):
        syms = self._syms("w.kt", (
            "object Config {\n"
            "    fun load(): Int {\n"
            "        val local = 5\n"
            "        return local\n"
            "    }\n"
            "}\n"
            "val topLevel = 10\n"
            "class Widget {\n"
            "    val member = 1\n"
            "    fun draw() {}\n"
            "}\n"
        ))
        self.assertEqual(syms.get("Config"), "class")
        self.assertEqual(syms.get("load"), "function")
        self.assertEqual(syms.get("Widget"), "class")
        self.assertEqual(syms.get("draw"), "function")
        # val/var declarations must not mint symbols: one per local would
        # drown the catalog in noise.
        for noise in ("local", "topLevel", "member"):
            self.assertNotIn(noise, syms)

    def test_ts_declarations(self):
        syms = self._syms("t.ts", (
            "type Alias = { a: number };\n"
            "abstract class Abs { abstract m(): void; }\n"
            "namespace Ns { export const inner = () => 1; }\n"
            "enum Color { Red }\n"
        ))
        self.assertEqual(syms.get("Alias"), "type")
        self.assertEqual(syms.get("Abs"), "class")
        self.assertEqual(syms.get("Ns"), "module")
        self.assertEqual(syms.get("Color"), "enum")
        self.assertEqual(syms.get("inner"), "function")

    def test_js_named_function_values_only(self):
        syms = self._syms("v.js", (
            "const arrow = (x) => x + 1;\n"
            "const fexpr = function (y) { return y; };\n"
            "function* gen() { yield 1; }\n"
            "const num = 5;\n"
            "setTimeout(() => { console.log(1); }, 10);\n"
        ))
        self.assertEqual(syms.get("arrow"), "function")
        self.assertEqual(syms.get("fexpr"), "function")
        self.assertEqual(syms.get("gen"), "function")
        # Plain initializers and anonymous callbacks stay invisible.
        self.assertNotIn("num", syms)
        self.assertNotIn("setTimeout", syms)

    def test_java_type_declarations_without_declarator_noise(self):
        syms = self._syms("j.java", (
            "enum Status { OK }\n"
            "record PointR(int x, int y) {}\n"
            "@interface Marker { String value(); }\n"
            "class Box {\n"
            "    int size = 5;\n"
            "    void grow() { int step = 1; }\n"
            "}\n"
        ))
        self.assertEqual(syms.get("Status"), "enum")
        self.assertEqual(syms.get("PointR"), "class")
        self.assertEqual(syms.get("Marker"), "interface")
        # Java field/local declarators share the variable_declarator node
        # type with JS but hold no function value: never symbols.
        self.assertNotIn("size", syms)
        self.assertNotIn("step", syms)

    def test_csharp_declarations_without_lambda_noise(self):
        syms = self._syms("c.cs", (
            "struct Vec { public int X; }\n"
            "enum Mode { A }\n"
            "record Rec(int A);\n"
            "class Svc {\n"
            "    public int Count { get; set; }\n"
            "    void Run() { System.Func<int,int> f = x => x; }\n"
            "}\n"
        ))
        self.assertEqual(syms.get("Vec"), "struct")
        self.assertEqual(syms.get("Mode"), "enum")
        self.assertEqual(syms.get("Rec"), "class")
        self.assertEqual(syms.get("Count"), "property")
        self.assertNotIn("f", syms)  # lambda_expression: deliberately not a value type

    def test_php_and_ruby_container_kinds(self):
        php = self._syms("p.php", (
            "<?php\n"
            "trait Greets { public function hi() { return 'hi'; } }\n"
            "enum Suit { case Hearts; }\n"
        ))
        self.assertEqual(php.get("Greets"), "interface")
        self.assertEqual(php.get("Suit"), "enum")
        rb = self._syms("r.rb", "module Helpers\n  def aid\n    1\n  end\nend\n")
        self.assertEqual(rb.get("Helpers"), "module")
        self.assertEqual(rb.get("aid"), "method")

    def test_python_root_module_node_is_not_a_symbol(self):
        # Python's root node type is literally "module". With "module" now
        # in _DEF_KINDS (for ruby), the walk must start below the root or a
        # top-level bare identifier names a phantom symbol that prefixes
        # every qualified name in the file.
        lang = _language_for("a.py")
        parser = _load_parser(lang)
        if parser is None:
            self.skipTest("no python parser")
        unit = extract_unit(
            "a.py", b"import os\nflag\ndef f():\n    return 1\n", lang, parser
        )
        names = {s["name"] for s in unit["symbols"]}
        self.assertEqual(names, {"<module>", "f"})
        f = next(s for s in unit["symbols"] if s["name"] == "f")
        self.assertEqual(f["qualified_name"], "f")  # no phantom prefix


class StateDirKeyingTest(unittest.TestCase):
    """Two campaign databases sharing a directory keep separate catalogs."""

    def test_state_dirs_are_keyed_by_db_filename(self):
        with tempfile.TemporaryDirectory(prefix="mantis_sidx_key_") as tmp:
            alpha = state_dir_for_db(str(Path(tmp) / "alpha.db"))
            beta = state_dir_for_db(str(Path(tmp) / "beta.db"))
            self.assertNotEqual(alpha, beta)
            self.assertEqual(Path(alpha).name, "alpha.structural_index")
            self.assertEqual(Path(beta).name, "beta.structural_index")
            self.assertEqual(Path(alpha).parent, Path(beta).parent)

    def test_sibling_databases_do_not_clobber_each_other(self):
        with tempfile.TemporaryDirectory(prefix="mantis_sidx_key2_") as tmp:
            tmp_path = Path(os.path.realpath(tmp))
            code_a = tmp_path / "a"
            code_b = tmp_path / "b"
            code_a.mkdir()
            code_b.mkdir()
            (code_a / "only_a.py").write_text("def alpha_fn():\n    return 1\n")
            (code_b / "only_b.py").write_text("def beta_fn():\n    return 2\n")
            db_a = str(tmp_path / "alpha.db")
            db_b = str(tmp_path / "beta.db")
            build_structural_index(str(code_a), state_dir_for_db(db_a), "s1")
            build_structural_index(str(code_b), state_dir_for_db(db_b), "s2")
            idx_a = StructuralIndex(state_dir_for_db(db_a))
            idx_b = StructuralIndex(state_dir_for_db(db_b))
            # Before the keyed layout the second build replaced the first:
            # idx_a would serve beta_fn and report its own symbol missing.
            self.assertEqual(idx_a.resolve_symbol("alpha_fn")["total"], 1)
            self.assertEqual(idx_a.resolve_symbol("beta_fn")["total"], 0)
            self.assertEqual(idx_b.resolve_symbol("beta_fn")["total"], 1)
            self.assertEqual(idx_b.resolve_symbol("alpha_fn")["total"], 0)


def _scan_resolve(edge, syms_by_name, sym_by_id):
    """The resolver as it was before _CandidateLookup: a linear scan of the
    name's candidates per edge. The reference the lookup must agree with."""
    callee_name = edge.get("callee_name") or ""
    candidates = syms_by_name.get(callee_name, [])
    if not candidates:
        return None
    qual = (edge.get("qualifier") or "").strip()
    if not qual:
        return candidates[0]["symbol_id"] if len(candidates) == 1 else None
    if qual in ("self", "this", "super", "cls"):
        caller_q = (sym_by_id.get(edge.get("caller_id") or "") or {}).get("qualified_name") or ""
        if "." in caller_q:
            owner = caller_q.rsplit(".", 1)[0]
            same = [c for c in candidates if c.get("qualified_name") == f"{owner}.{callee_name}"]
            if len(same) == 1:
                return same[0]["symbol_id"]
        return candidates[0]["symbol_id"] if len(candidates) == 1 else None
    suffix = f"{qual}.{callee_name}"
    matched = [
        c for c in candidates
        if c.get("qualified_name") == suffix
        or str(c.get("qualified_name") or "").endswith("." + suffix)
        or Path(str(c.get("file_path") or "")).stem == qual
    ]
    if len(matched) == 1:
        return matched[0]["symbol_id"]
    if len(matched) > 1:
        return None
    if qual in _AMBIENT_RECEIVERS or qual[0].isupper():
        return None
    return candidates[0]["symbol_id"] if len(candidates) == 1 else None


class _CountingSym(dict):
    """A symbol row that counts field reads, to bound per-edge work."""

    reads = 0

    def get(self, *a):
        _CountingSym.reads += 1
        return super().get(*a)


class CalleeLookupTest(unittest.TestCase):
    """Qualifier matching goes through per-name tables, not a scan per edge."""

    @staticmethod
    def _catalog(rng, names, per_name):
        owners = ["Session", "Token", "pkg.Session", "a.b.Session", "auth", "db", "x"]
        files = ["app/auth.py", "app/session.go", "lib/db.ts", "vendor/x/token.go",
                 "session", "a/b.tar.gz", ""]
        syms_by_name, sym_by_id = {}, {}
        n = 0
        for name in names:
            for _ in range(rng.randint(1, per_name)):
                n += 1
                owner = rng.choice(owners + [None])
                qn = rng.choice([f"{owner}.{name}" if owner else name, name, None, f"{owner}"])
                sym = {"symbol_id": f"s{n}", "name": name, "qualified_name": qn,
                       "file_path": rng.choice(files + [None])}
                syms_by_name.setdefault(name, []).append(sym)
                sym_by_id[sym["symbol_id"]] = sym
        return syms_by_name, sym_by_id

    def test_lookup_resolves_exactly_like_the_scan(self):
        import random

        rng = random.Random(7)
        names = ["refresh", "login", "String", "Error", "log", "findAll", "a.b"]
        syms_by_name, sym_by_id = self._catalog(rng, names, 40)
        # Unique names too, so the single-candidate branches are exercised.
        for i in range(5):
            sym = {"symbol_id": f"u{i}", "name": f"uniq{i}", "qualified_name": f"M.uniq{i}",
                   "file_path": "m.py"}
            syms_by_name[f"uniq{i}"] = [sym]
            sym_by_id[sym["symbol_id"]] = sym
        quals = ["", "  ", "self", "this", "super", "cls", "Session", "pkg.Session",
                 "b.Session", "a.b.Session", "auth", "session", "token", "db", "console",
                 "json", "UserModel", "s", "x", "a.b", "b.tar"]
        callers = list(sym_by_id) + ["", "missing"]
        lookup = _CandidateLookup(syms_by_name)
        checked = resolved = 0
        for name in names + [f"uniq{i}" for i in range(5)] + ["nope", ""]:
            for qual in quals:
                for caller in callers[:: max(1, len(callers) // 25)]:
                    edge = {"callee_name": name, "qualifier": qual, "caller_id": caller}
                    want = _scan_resolve(edge, syms_by_name, sym_by_id)
                    self.assertEqual(_resolve_callee_id(edge, syms_by_name, sym_by_id, lookup),
                                     want, edge)
                    self.assertEqual(_resolve_callee_id(edge, syms_by_name, sym_by_id), want, edge)
                    checked += 1
                    resolved += want is not None
        # Both outcomes occur, or agreement would prove nothing.
        self.assertGreater(resolved, 50)
        self.assertGreater(checked - resolved, 50)

    def test_per_edge_work_does_not_grow_with_candidates(self):
        # 400 same-named candidates, 300 qualified edges calling the name: a
        # scan reads every candidate on every edge (~360k reads); the shared
        # lookup reads each candidate once, to build its tables.
        cands = [_CountingSym(symbol_id=f"s{i}", name="String", file_path=f"vendor/p{i}/s.go",
                              qualified_name=f"T{i}.String") for i in range(400)]
        syms_by_name = {"String": cands}
        sym_by_id = {c["symbol_id"]: c for c in cands}
        lookup = _CandidateLookup(syms_by_name)
        _CountingSym.reads = 0
        for i in range(300):
            edge = {"callee_name": "String", "qualifier": f"T{i}", "caller_id": "s0"}
            self.assertEqual(_resolve_callee_id(edge, syms_by_name, sym_by_id, lookup), f"s{i}")
            edge = {"callee_name": "String", "qualifier": "self", "caller_id": f"s{i}"}
            self.assertEqual(_resolve_callee_id(edge, syms_by_name, sym_by_id, lookup), f"s{i}")
        self.assertLessEqual(_CountingSym.reads, 3 * len(cands) + 2 * 300)


def _git_repo(path: Path) -> str:
    """Commits the fixture at path as a git repository; returns HEAD."""
    def git(*args):
        return subprocess.run(["git", "-C", str(path), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    git("init", "-q")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    git("add", "-A")
    git("commit", "-q", "-m", "fixture")
    return git("rev-parse", "HEAD")


class SnapshotPinTest(unittest.TestCase):
    """A clean checkout pins the index to HEAD, so a rebuild reuses it."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_sidx_pin_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(os.path.realpath(self._tmp.name))
        self.code = self.tmp / "code"
        _write_fixture(self.code)
        self.head = _git_repo(self.code)
        self.state = self.tmp / "state"

    def test_clean_checkout_pins_to_head(self):
        self.assertEqual(git_snapshot_id(str(self.code)), f"git:{self.head}")

    def test_anything_the_index_would_read_differently_is_unknown(self):
        (self.code / "app" / "db.py").write_text("def helper():\n    return 2\n")
        self.assertEqual(git_snapshot_id(str(self.code)), "unknown")
        subprocess.run(["git", "-C", str(self.code), "checkout", "-q", "--", "."], check=True)
        (self.code / "untracked.py").write_text("x = 1\n")
        self.assertEqual(git_snapshot_id(str(self.code)), "unknown")
        (self.code / "untracked.py").unlink()
        # Ignored files are indexed too, so they unpin as well.
        (self.code / ".gitignore").write_text("build/\n")
        subprocess.run(["git", "-C", str(self.code), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.code), "commit", "-q", "-m", "ignore"], check=True)
        self.assertTrue(git_snapshot_id(str(self.code)).startswith("git:"))
        (self.code / "build").mkdir()
        (self.code / "build" / "gen.py").write_text("x = 1\n")
        self.assertEqual(git_snapshot_id(str(self.code)), "unknown")

    def test_subdirectory_and_non_repository_are_unknown(self):
        self.assertEqual(git_snapshot_id(str(self.code / "app")), "unknown")
        plain = self.tmp / "plain"
        plain.mkdir()
        self.assertEqual(git_snapshot_id(str(plain)), "unknown")
        self.assertEqual(git_snapshot_id(str(self.tmp / "missing")), "unknown")

    def test_pinned_rebuild_reuses_and_another_root_does_not(self):
        snap = git_snapshot_id(str(self.code))
        first = build_structural_index(str(self.code), str(self.state), snap)
        self.assertFalse(first.get("reused", False))
        self.assertEqual(first["code_root"], str(self.code))
        second = build_structural_index(str(self.code), str(self.state), snap)
        self.assertTrue(second.get("reused"))
        # The same pin over a different root is a different catalog.
        other = build_structural_index(str(self.code / "app"), str(self.state), snap)
        self.assertFalse(other.get("reused", False))

    def test_pinned_catalog_of_another_extractor_is_rebuilt(self):
        import core.structural_index as sidx

        snap = git_snapshot_id(str(self.code))
        build_structural_index(str(self.code), str(self.state), snap)
        with mock.patch.object(sidx, "_ts_version", return_value="999.0.0"):
            again = build_structural_index(str(self.code), str(self.state), snap)
        self.assertFalse(again.get("reused", False),
                         "a catalog built by another extractor was reused at the same commit")

    async def _run_node(self):
        from core.graph_loader import create_structural_index_node

        token = current_run_context.set(RunContext(
            jail_dir=str(self.code), db_path=str(self.tmp / "knowledge.db"),
            target_file="", run_id="r1"))
        try:
            mock_ctx = MagicMock()
            mock_ctx.state = {}
            return await create_structural_index_node("structural_index")._func(mock_ctx, None)
        finally:
            current_run_context.reset(token)

    def test_pipeline_node_reuses_the_catalog_of_a_clean_checkout(self):
        import asyncio
        import core.structural_index as sidx

        (self.tmp / "knowledge.db").touch()
        real = sidx._write_catalog
        writes = []
        with mock.patch.object(sidx, "_write_catalog",
                               side_effect=lambda *a, **k: (writes.append(1), real(*a, **k))):
            first = asyncio.run(self._run_node())
            second = asyncio.run(self._run_node())
        self.assertIn("Structural index complete", first.output)
        self.assertIn("Structural index complete", second.output)
        self.assertEqual(len(writes), 1, "the second run over the same commit rebuilt the catalog")
        manifest = json.loads(
            (Path(state_dir_for_db(str(self.tmp / "knowledge.db"))) / "manifest.json").read_text())
        self.assertEqual(manifest["snapshot_id"], f"git:{self.head}")


class WorkflowTopologyTest(unittest.TestCase):
    """The shipped workflow keeps the structural_index node and topology."""

    @classmethod
    def setUpClass(cls):
        with open(Path(_REF_ROOT) / "workflow.json", "r", encoding="utf-8") as f:
            cls.wf = json.load(f)

    def test_structural_index_node_and_edges_unchanged(self):
        node = next(n for n in self.wf["nodes"] if n["id"] == "structural_index")
        self.assertEqual(node["type"], "agent")
        edges = {(e["from"], e["to"]) for e in self.wf["edges"]}
        self.assertIn(("history", "structural_index"), edges)
        self.assertIn(("structural_index", "architect"), edges)


if __name__ == "__main__":
    unittest.main()

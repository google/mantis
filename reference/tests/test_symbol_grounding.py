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

"""Tests for catalog symbol grounding in write_findings (INV-3 lineage).

The lineage anchors hang off the target symbol, and the prose extractor moves
whenever a model rephrases a title -- which mints a fresh lineage for a defect
every earlier run already tracked. Grounding reads the enclosing function from
the structural catalog instead: a measurement of the code, invariant to prose.

Layers:

1. `ground_symbol_in_catalog`: grounds to the enclosing function, tolerates
   path-base differences, refuses ambiguity, and returns "" on every
   degradation (no catalog, no match, bad lines).
2. `write_findings`: the grounded symbol reaches the stable signature, and two
   differently-phrased reports of the same defect keep ONE lineage -- with the
   anti-vacuity twin proving they diverge without a catalog.

Requires the tree-sitter python grammar for the catalog build; tests skip
without it, matching test_cognitive_complexity.
"""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from core.database import (
    compute_stable_signature,
    ground_symbol_in_catalog,
    init_db,
    write_findings,
)
from core.structural_index import (
    _load_parser,
    build_structural_index,
    state_dir_for_db,
)

_HAS_PYTHON_GRAMMAR = _load_parser("python") is not None

_QUERIES_SRC = (
    "def helper_one():\n"
    "    return 1\n"
    "\n"
    "def fetch_rows(q):\n"
    "    q2 = 'SELECT * FROM t WHERE x = ' + q\n"
    "    return run(q2)\n"
)

_VIEWS_SRC = (
    "def render_view(ctx):\n"
    "    if ctx:\n"
    "        return page(ctx)\n"
    "    return none_page()\n"
)

_LIB_QUERIES_SRC = "def list_things():\n    return []\n"


class GroundSymbolInCatalogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _HAS_PYTHON_GRAMMAR:
            raise AssertionError("tree-sitter python grammar unavailable in reference environment")
        cls._tmp = tempfile.TemporaryDirectory(prefix="mantis_grounding_")
        base = Path(cls._tmp.name)
        jail = base / "jail"
        for rel, body in (
            ("app/queries.py", _QUERIES_SRC),
            ("app/views.py", _VIEWS_SRC),
            ("lib/queries.py", _LIB_QUERIES_SRC),
        ):
            path = jail / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        cls.db_path = str(base / "state" / "knowledge.db")
        Path(cls.db_path).parent.mkdir(parents=True, exist_ok=True)
        init_db(cls.db_path)
        manifest = build_structural_index(str(jail), state_dir_for_db(cls.db_path))
        assert manifest.get("status") == "complete", manifest

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_grounds_to_the_enclosing_function(self):
        self.assertEqual(
            ground_symbol_in_catalog(self.db_path, "app/queries.py", "[5]"),
            "fetch_rows",
        )

    def test_first_cited_line_wins(self):
        # Lines 2 and 5 fall in different functions; the first (minimum) is
        # the anchor, matching how line_numbers are already sorted on write.
        self.assertEqual(
            ground_symbol_in_catalog(self.db_path, "app/queries.py", "[5, 2]"),
            "helper_one",
        )

    def test_suffix_path_tolerance_on_unique_basename(self):
        self.assertEqual(
            ground_symbol_in_catalog(self.db_path, "views.py", "[3]"),
            "render_view",
        )

    def test_ambiguous_suffix_is_refused_not_guessed(self):
        # Both app/queries.py and lib/queries.py end with /queries.py; a wrong
        # symbol stamped onto a lineage is worse than no symbol.
        self.assertEqual(
            ground_symbol_in_catalog(self.db_path, "queries.py", "[1]"), ""
        )

    def test_line_outside_any_function_is_empty(self):
        self.assertEqual(
            ground_symbol_in_catalog(self.db_path, "app/queries.py", "[99]"), ""
        )

    def test_degraded_inputs_are_empty(self):
        self.assertEqual(ground_symbol_in_catalog(self.db_path, "", "[5]"), "")
        self.assertEqual(
            ground_symbol_in_catalog(self.db_path, "app/queries.py", "[]"), ""
        )
        self.assertEqual(
            ground_symbol_in_catalog(self.db_path, "app/queries.py", "not json"),
            "",
        )

    def test_no_catalog_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            bare_db = str(Path(tmp) / "knowledge.db")
            init_db(bare_db)
            self.assertEqual(
                ground_symbol_in_catalog(bare_db, "app/queries.py", "[5]"), ""
            )


# Two phrasings of the same defect at app/queries.py:5. Chosen so the prose
# extractor yields DIFFERENT symbols ("string_concat" from the backticks vs the
# sorted-token fallback) and neither phrasing's symbol appears anywhere in the
# other's text -- which defeats lineage anchor 2 and, the symbols being
# non-empty, anchor 3. Without grounding these mint two lineages.
_PHRASING_A = {
    "title": "Tainted SQL assembled via `string_concat`",
    "description": "User text reaches the statement builder unparameterized.",
    "severity": "HIGH",
    "cwe": "CWE-89",
    "filepath": "app/queries.py",
    "line_numbers": [5],
}
_PHRASING_B = {
    "title": "Unparameterized database statement from request text",
    "description": "The handler interpolates caller input into the WHERE clause.",
    "severity": "HIGH",
    "cwe": "CWE-89",
    "filepath": "app/queries.py",
    "line_numbers": [5],
}


def _lineages(db_path: str) -> list:
    conn = sqlite3.connect(db_path)
    try:
        return [
            row[0]
            for row in conn.execute(
                "SELECT lineage_id FROM findings ORDER BY id"
            ).fetchall()
        ]
    finally:
        conn.close()


@unittest.skipUnless(_HAS_PYTHON_GRAMMAR, "tree-sitter python grammar unavailable")
class WriteFindingsGroundingTest(unittest.TestCase):
    def _workspace(self, with_catalog: bool) -> str:
        base = Path(self._tmp.name)
        jail = base / "jail"
        target = jail / "app" / "queries.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_QUERIES_SRC)
        db_path = str(base / "state" / "knowledge.db")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        init_db(db_path)
        if with_catalog:
            manifest = build_structural_index(
                str(jail), state_dir_for_db(db_path)
            )
            assert manifest.get("status") == "complete", manifest
        return db_path

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_grounding_wf_")
        self.addCleanup(self._tmp.cleanup)

    def test_signature_uses_the_grounded_symbol(self):
        db_path = self._workspace(with_catalog=True)
        write_findings(db_path, "app/queries.py", [dict(_PHRASING_A)], run_id="r1")
        conn = sqlite3.connect(db_path)
        try:
            stored = conn.execute("SELECT signature FROM findings").fetchone()[0]
        finally:
            conn.close()
        grounded = compute_stable_signature(
            filepath="app/queries.py",
            title=_PHRASING_A["title"],
            cwe="CWE-89",
            symbol="fetch_rows",
            description=_PHRASING_A["description"],
        )
        prose = compute_stable_signature(
            filepath="app/queries.py",
            title=_PHRASING_A["title"],
            cwe="CWE-89",
            symbol="string_concat",
            description=_PHRASING_A["description"],
        )
        self.assertEqual(stored, grounded)
        self.assertNotEqual(stored, prose)

    def test_rephrased_report_keeps_one_lineage(self):
        db_path = self._workspace(with_catalog=True)
        write_findings(db_path, "app/queries.py", [dict(_PHRASING_A)], run_id="r1")
        write_findings(db_path, "app/queries.py", [dict(_PHRASING_B)], run_id="r2")
        lineages = _lineages(db_path)
        self.assertEqual(len(lineages), 2)
        self.assertEqual(
            lineages[0],
            lineages[1],
            "Same file, same line, same CWE, different prose: with a catalog "
            "this is one tracked defect, not two.",
        )

    def test_without_a_catalog_the_same_rephrasing_splits_lineage(self):
        # Anti-vacuity for the test above, and a record of the exact failure
        # mode grounding exists to close. If this ever starts PASSING with one
        # lineage, the prose anchors learned to merge these and the grounding
        # path should be re-examined for redundancy.
        db_path = self._workspace(with_catalog=False)
        write_findings(db_path, "app/queries.py", [dict(_PHRASING_A)], run_id="r1")
        write_findings(db_path, "app/queries.py", [dict(_PHRASING_B)], run_id="r2")
        lineages = _lineages(db_path)
        self.assertEqual(len(lineages), 2)
        self.assertNotEqual(lineages[0], lineages[1])


class WiringPinTest(unittest.TestCase):
    def test_write_findings_grounds_the_symbol(self):
        source = (Path(_REF_ROOT) / "core" / "database.py").read_text()
        body = source[source.index("\ndef write_findings("):]
        self.assertIn("ground_symbol_in_catalog(", body)


if __name__ == "__main__":
    unittest.main()

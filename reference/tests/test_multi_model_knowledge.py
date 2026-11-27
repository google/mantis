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

"""Knowledge built by more than one model: provenance per record, coverage
per model, archiving by the finder only, and the driver's --models."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from core import knowledge as K  # noqa: E402
from core.cost import record_spend, uncovered_files  # noqa: E402
from core.database import init_db, read_findings, record_learning, record_run, run_models, write_findings  # noqa: E402

OPUS = "vertex_ai/claude-opus-5-5"
FLASH = "vertex_ai/gemini-3.8-flash"


class RunLedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_mm_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = os.path.join(self.tmp, "k.db")
        self.repo = os.path.realpath(os.path.join(self.tmp, "repo"))
        os.makedirs(self.repo)

    def test_a_run_records_its_model_once(self):
        self.assertEqual(run_models(self.db), {}, "no database")
        init_db(self.db)
        self.assertEqual(run_models(self.db), {})
        self.assertTrue(record_run(self.db, "r1", OPUS))
        self.assertTrue(record_run(self.db, "r1", FLASH), "a resumed run is the same run")
        self.assertTrue(record_run(self.db, "r2", FLASH))
        self.assertEqual(run_models(self.db), {"r1": OPUS, "r2": FLASH})
        self.assertFalse(record_run("", "r3", FLASH))
        self.assertFalse(record_run(self.db, "", FLASH))

    def test_the_pipeline_records_the_run_after_it_has_an_id(self):
        """pipeline() must call record_run only once run_id is bound. For a
        while the call sat above the assignment: `run_id` is a local of the
        function, so Python raised UnboundLocalError, the except swallowed
        it as a warning, and the ledger stayed empty for every real run --
        exports and pr_scan then attributed nothing to any model."""
        import ast
        import inspect
        import textwrap

        import main

        tree = ast.parse(textwrap.dedent(inspect.getsource(main.pipeline)))
        assigned: list[int] = []
        recorded: list[int] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "run_id" for t in node.targets
            ):
                assigned.append(node.lineno)
            if isinstance(node, ast.Call):
                name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
                if name == "record_run":
                    recorded.append(node.lineno)
        self.assertTrue(assigned, "pipeline() no longer binds run_id")
        self.assertTrue(recorded, "pipeline() no longer records the run's model")
        for line in recorded:
            self.assertGreater(line, min(assigned),
                               "record_run is called before run_id is bound: the ledger stays empty")

    def test_coverage_is_per_model_when_asked_and_any_model_otherwise(self):
        init_db(self.db)
        a, b, c = (os.path.join(self.repo, n) for n in ("a.py", "b.py", "c.py"))
        record_run(self.db, "r-opus", OPUS)
        record_run(self.db, "r-flash", FLASH)
        record_spend(self.db, "r-opus", a, "file-by-file", tokens=10)
        record_spend(self.db, "r-flash", b, "file-by-file", tokens=10)
        record_spend(self.db, "r-old", c, "file-by-file", tokens=10)  # no runs row: model unknown
        files = [a, b, c]
        self.assertEqual(uncovered_files(self.db, files), [], "any model: everything is covered")
        # c was covered by a run of unknown model: that counts for everyone,
        # so turning on provenance never makes an old knowledge base re-sweep.
        self.assertEqual(uncovered_files(self.db, files, model=OPUS), [b])
        self.assertEqual(uncovered_files(self.db, files, model=FLASH), [a])
        self.assertEqual(uncovered_files(self.db, files, model="vertex_ai/other"), [a, b])
        # A failed campaign covers nothing for its model either.
        record_spend(self.db, "r-opus", b, "file-by-file", tokens=10, metadata={"failed": True})
        self.assertEqual(uncovered_files(self.db, files, model=OPUS), [b])
        # A database with spend rows but no runs table: the old answer.
        other = os.path.join(self.tmp, "legacy.db")
        record_spend(other, "r1", a, "whole", tokens=5)
        self.assertEqual(uncovered_files(other, [a, b]), [b])
        self.assertEqual(uncovered_files(other, [a, b], model=OPUS), [b])


class ExportImportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mantis_mm_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = os.path.join(self.tmp, "k.db")
        self.repo = os.path.realpath(os.path.join(self.tmp, "repo"))
        os.makedirs(os.path.join(self.repo, "src"))
        init_db(self.db)
        record_run(self.db, "r-opus", OPUS)
        record_run(self.db, "r-flash", FLASH)
        write_findings(self.db, "src/app.py", [{
            "title": "SQL injection in get_user", "severity": "HIGH", "status": "confirmed",
            "description": "d", "line_numbers": [7], "cwe": "CWE-89", "filepath": "src/app.py",
        }], run_id="r-opus")
        write_findings(self.db, "src/app.py", [{
            "title": "Weak hash", "severity": "LOW", "status": "confirmed",
            "description": "d", "line_numbers": [20], "cwe": "CWE-328", "filepath": "src/app.py",
        }], run_id="r-flash")
        record_learning(self.db, "r-flash", "codebase", "Queries are hand-built.", tags=["sql"])
        from core.memory import record_coverage
        record_coverage(self.db, "r-opus", self.repo, [os.path.join(self.repo, "src/app.py")])
        record_coverage(self.db, "r-flash", self.repo, [os.path.join(self.repo, "src/app.py"),
                                                        os.path.join(self.repo, "src/util.py")])
        record_spend(self.db, "r-opus", os.path.join(self.repo, "src/app.py"), "file-by-file", tokens=100)
        record_spend(self.db, "r-flash", os.path.join(self.repo, "src/app.py"), "file-by-file", tokens=50)
        record_spend(self.db, "r-flash", os.path.join(self.repo, "src/util.py"), "file-by-file", tokens=50)
        self.export = os.path.join(self.tmp, "export")

    def test_export_names_the_model_on_every_record(self):
        counts = K.export_knowledge(self.db, self.export, repo_root=self.repo)
        self.assertEqual(counts["models"], [OPUS, FLASH])
        self.assertEqual(counts["runs"], 2)
        manifest = json.loads(Path(self.export, K.MANIFEST).read_text())
        self.assertEqual(manifest["schema_version"], 2)
        self.assertEqual(manifest["models"], [OPUS, FLASH])
        runs = [json.loads(l) for l in Path(self.export, K.RUNS).read_text().splitlines()]
        self.assertEqual({r["run_id"]: r["model"] for r in runs}, {"r-opus": OPUS, "r-flash": FLASH})
        findings = {json.loads(l)["title"]: json.loads(l) for l in Path(self.export, K.FINDINGS).read_text().splitlines()}
        self.assertEqual(findings["SQL injection in get_user"]["model"], OPUS)
        self.assertEqual(findings["Weak hash"]["model"], FLASH)
        learnings = [json.loads(l) for l in Path(self.export, K.LEARNINGS).read_text().splitlines()]
        self.assertEqual(learnings[0]["model"], FLASH)
        cov = json.loads(Path(self.export, K.COVERAGE).read_text())
        self.assertEqual({r["run_id"]: r["model"] for r in cov["runs"]}, {"r-opus": OPUS, "r-flash": FLASH})
        scanned = {(e["path"], e["model"]) for e in cov["scanned"]}
        self.assertEqual(scanned, {("src/app.py", OPUS), ("src/app.py", FLASH), ("src/util.py", FLASH)},
                         "one entry per path per model")

    def test_import_restores_per_model_coverage(self):
        K.export_knowledge(self.db, self.export, repo_root=self.repo)
        fresh = os.path.join(self.tmp, "fresh.db")
        counts = K.import_knowledge(fresh, self.export, run_id="run-new", repo_root=self.repo)
        self.assertEqual(counts["runs"], 2)
        self.assertEqual(counts["coverage_paths"], 3)
        self.assertEqual(run_models(fresh), {"r-opus": OPUS, "r-flash": FLASH})
        app, util, new = (os.path.join(self.repo, p) for p in ("src/app.py", "src/util.py", "src/new.py"))
        self.assertEqual(uncovered_files(fresh, [app, util, new]), [new])
        self.assertEqual(uncovered_files(fresh, [app, util, new], model=OPUS), [util, new])
        self.assertEqual(uncovered_files(fresh, [app, util, new], model=FLASH), [new])
        # Imported findings keep their run, and so their model.
        rows = {r["title"]: r for r in read_findings(fresh)}
        self.assertEqual(run_models(fresh)[rows["SQL injection in get_user"]["run_id"]], OPUS)
        # Importing again adds nothing.
        counts2 = K.import_knowledge(fresh, self.export, run_id="run-new", repo_root=self.repo)
        self.assertEqual(counts2["findings"], 0)
        self.assertEqual(counts2["coverage_paths"], 3)

    def test_a_version_one_export_still_imports_with_unknown_models(self):
        K.export_knowledge(self.db, self.export, repo_root=self.repo)
        manifest = json.loads(Path(self.export, K.MANIFEST).read_text())
        manifest["schema_version"] = 1
        Path(self.export, K.MANIFEST).write_text(json.dumps(manifest))
        Path(self.export, K.RUNS).unlink()
        for name in (K.FINDINGS, K.LEARNINGS):
            lines = [json.loads(l) for l in Path(self.export, name).read_text().splitlines()]
            for rec in lines:
                rec.pop("model", None)
            Path(self.export, name).write_text("".join(json.dumps(r) + "\n" for r in lines))
        cov = json.loads(Path(self.export, K.COVERAGE).read_text())
        for e in cov["runs"] + cov["scanned"]:
            e.pop("model", None)
        Path(self.export, K.COVERAGE).write_text(json.dumps(cov))
        fresh = os.path.join(self.tmp, "fresh.db")
        counts = K.import_knowledge(fresh, self.export, run_id="run-new", repo_root=self.repo)
        self.assertEqual(counts["runs"], 0)
        self.assertEqual(counts["findings"], 2)
        app = os.path.join(self.repo, "src/app.py")
        self.assertEqual(uncovered_files(fresh, [app]), [], "covered by someone")
        self.assertEqual(uncovered_files(fresh, [app], model=OPUS), [],
                         "by nobody we can name, which counts for everyone")


class RefreshWorkflowModelsTest(unittest.TestCase):
    def test_the_workflow_runs_every_model_listed(self):
        import yaml
        path = _REF_ROOT.parent / ".github" / "workflows" / "mantis-knowledge-refresh.yml"
        spec = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.assertIn("MANTIS_MODELS", spec["env"])
        steps = {st.get("name"): st for st in spec["jobs"]["refresh"]["steps"] if st.get("name")}
        self.assertIn("--models", steps["Delta scan of what landed since the last refresh"]["run"])
        sweep = steps["Sweep files no scan has covered"]["run"]
        self.assertIn("for m in $MANTIS_MODELS", sweep)
        self.assertIn('--model "$m"', sweep)
        self.assertIn("import_flag=()", sweep.split("for m in")[1], "the import happens once")

    def test_the_sweep_does_not_swallow_a_failed_scan(self):
        import subprocess
        import tempfile
        import yaml
        path = _REF_ROOT.parent / ".github" / "workflows" / "mantis-knowledge-refresh.yml"
        spec = yaml.safe_load(path.read_text(encoding="utf-8"))
        steps = {st.get("name"): st for st in spec["jobs"]["refresh"]["steps"] if st.get("name")}
        sweep = steps["Sweep files no scan has covered"]["run"]
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp, "python")
            stub.write_text('#!/bin/sh\ncase "$1" in\n  main.py) exit "$SCAN_RC" ;;\n'
                            '  scripts/knowledge.py) echo exported ;;\nesac\n')
            stub.chmod(0o755)
            for scan_rc, step_rc, warns in ((0, 0, False), (2, 0, False), (1, 0, True),
                                            (4, 4, False), (64, 64, False)):
                env = {"PATH": f"{tmp}:/usr/bin:/bin", "SCAN_RC": str(scan_rc),
                       "MANTIS_MODELS": "m1", "GITHUB_WORKSPACE": tmp, "RUNNER_TEMP": tmp}
                p = subprocess.run(["bash", "-eo", "pipefail", "-c", sweep], env=env,
                                   cwd=tmp, capture_output=True, text=True)
                with self.subTest(scan_rc=scan_rc):
                    self.assertEqual(p.returncode, step_rc, p.stderr)
                    self.assertEqual("exported" in p.stdout, step_rc == 0)
                    self.assertEqual("::warning" in p.stdout, warns)


if __name__ == "__main__":
    unittest.main()

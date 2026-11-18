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

"""Regression tests for depth coverage rotation, depth-aware ledger stamping,
reasoning effort precedence, resume fidelity, repo-docs batch injection,
pause-banner boolean flags, and peak risk-score calibration retention."""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from core.budget import BudgetConfig, BudgetController, BudgetExceededError
from core.context import RunContext, current_run_context
from core.cost import (
    changed_files,
    covered_below_depth,
    has_active_file_sweep,
    load_run_plan,
    record_coverage_files,
    record_run_plan,
    record_spend,
    scope_identities,
    uncovered_files,
)
from core.database import init_db, read_risk_scores, record_calibration, record_run
from core.depth import resolve_depth_profile
import core.graph_loader as gl
from core.prompts import INHERITED_STEM_NEUTRALITY_RULE, STAGE_PROMPTS
from core.repo_docs import REPO_DOCS_DIRECTIVE_MARKER
import main as mantis_main
from scripts.launch import build_parser


def _collect_workflow_agents(workflow) -> dict[str, object]:
    found: dict[str, object] = {}
    for edge in workflow.edges:
        for n in (getattr(edge, "from_node", None), getattr(edge, "to_node", None)):
            agent = getattr(n, "agent", n)
            name = getattr(agent, "name", None)
            if name and getattr(agent, "model", None) is not None:
                found[name] = agent
    return found


class DepthCoverageAndRotationTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_depth_rot_")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(os.path.realpath(self._tmp.name))
        self.db = str(self.root / "knowledge.db")
        init_db(self.db)

    def _make_repo(self, name: str, n_active: int, *, n_noise: int = 0) -> tuple[Path, list[str]]:
        repo = self.root / name
        files: list[str] = []
        subsystems = ("auth", "api", "billing", "workers", "frontend")
        for i in range(n_active):
            sub = repo / subsystems[i % len(subsystems)]
            sub.mkdir(parents=True, exist_ok=True)
            fp = sub / f"handler_{i:04d}.py"
            fp.write_text(f"def handle_{i}(req):\n    return req.args.get('x')\n", encoding="utf-8")
            files.append(str(fp))
        if n_noise:
            docs = repo / "docs"
            docs.mkdir(parents=True, exist_ok=True)
            for j in range(n_noise):
                nf = docs / f"guide_{j:03d}.md"
                nf.write_text("# documentation\n", encoding="utf-8")
                files.append(str(nf))
            (repo / "README.md").write_text("# Repo\n", encoding="utf-8")
            (repo / "package-lock.json").write_text("{}\n", encoding="utf-8")
            files.extend([str(repo / "README.md"), str(repo / "package-lock.json")])
        return repo, files

    def test_large_repo_second_default_run_stays_in_depth_batches_and_rotates(self):
        """[r3-impact-1]: A >1000-file repo's second plain `auto` run must NOT flip
        from depth batches into a per-file sweep, and omitted vs explicit --depth 30
        must behave identically."""
        repo, files = self._make_repo("big_repo", n_active=1050, n_noise=20)
        model = "vertex_ai/gemini-3.8-flash"
        record_run(self.db, "run_1", model=model)

        scope1: dict = {}
        with contextlib.redirect_stderr(io.StringIO()):
            targets1, _astm1, mode1 = mantis_main.resolve_scan_targets(
                repo,
                {"depth": 30, "_depth_explicit": False, "default_model": model},
                files,
                precomputed_astm={"slices": []},
                db_path=self.db,
                scope_out=scope1,
            )
        self.assertEqual(mode1, mantis_main.SCAN_MODE_CROSS_FUNCTIONAL)
        groups1 = scope1["depth_groups"]
        self.assertLessEqual(len(groups1), 10)
        covered1 = {f for g in groups1 for f in g["targets"]}
        self.assertGreater(len(covered1), 0)
        self.assertLess(len(covered1), 1050)

        # Record Run 1 depth-batch spend rows + member stamps (exactly as pipeline() does).
        for g in groups1:
            primary = g["targets"][0]
            record_spend(
                self.db,
                "run_1",
                primary,
                mantis_main.SCAN_MODE_CROSS_FUNCTIONAL,
                tokens=10_000,
                metadata={"failed": False, "depth": 30},
            )
            mantis_main._stamp_member_coverage(
                self.db,
                "run_1",
                g,
                primary,
                mantis_main.SCAN_MODE_CROSS_FUNCTIONAL,
                depth=30,
            )

        # Even if ANOTHER repo in the same shared DB ran file-by-file, this repo must not flip.
        other_repo, other_files = self._make_repo("other_repo", n_active=2)
        record_spend(self.db, "run_other", other_files[0], mantis_main.SCAN_MODE_FILE_BY_FILE, tokens=500)
        self.assertFalse(has_active_file_sweep(self.db, files, model=model))

        # Run 2 with omitted --depth (_depth_explicit=False) AND explicit (_depth_explicit=True)
        # must BOTH stay in cross-functional depth batches and rotate onto disjoint uncovered files.
        for explicit in (False, True):
            scope2: dict = {}
            err2 = io.StringIO()
            with contextlib.redirect_stderr(err2):
                targets2, _astm2, mode2 = mantis_main.resolve_scan_targets(
                    repo,
                    {"depth": 30, "_depth_explicit": explicit, "default_model": model},
                    files,
                    precomputed_astm={"slices": []},
                    db_path=self.db,
                    scope_out=scope2,
                )
            self.assertEqual(mode2, mantis_main.SCAN_MODE_CROSS_FUNCTIONAL, f"explicit={explicit}")
            self.assertTrue(scope2.get("depth_rotated"), err2.getvalue())
            groups2 = scope2["depth_groups"]
            self.assertLessEqual(len(groups2), 10)
            covered2 = {f for g in groups2 for f in g["targets"]}
            self.assertTrue(covered1.isdisjoint(covered2), "Run 2 must rotate to uncovered files")
            self.assertFalse(any(f.endswith((".md", "package-lock.json")) for f in covered2))
            self.assertEqual(len(targets2), len(groups2))

    def test_mid_size_repo_rotates_to_full_coverage_and_avoids_29_30_cliff(self):
        """[r3-depth-1]: 35-file repo stays whole at depth 30 (no 29/30 cliff), and an
        80-file repo rotates across uncovered active files until 100% covered."""
        small_repo, small_files = self._make_repo("small_35", n_active=35)
        self.assertEqual(resolve_depth_profile(30).whole_file_limit, 40)
        with contextlib.redirect_stderr(io.StringIO()):
            targets_s, _a, mode_s = mantis_main.resolve_scan_targets(
                small_repo, {"depth": 30}, small_files, precomputed_astm={"slices": []}
            )
        self.assertEqual(mode_s, mantis_main.SCAN_MODE_WHOLE)
        self.assertEqual(targets_s, [str(small_repo)])

        repo, files = self._make_repo("mid_80", n_active=80, n_noise=5)
        model = "vertex_ai/gemini-3.8-flash"
        seen: set[str] = set()
        for run_idx in range(1, 6):
            rid = f"rot_{run_idx}"
            record_run(self.db, rid, model=model)
            scope: dict = {}
            with contextlib.redirect_stderr(io.StringIO()):
                _t, _a, mode = mantis_main.resolve_scan_targets(
                    repo,
                    {"depth": 30, "default_model": model},
                    files,
                    precomputed_astm={"slices": []},
                    db_path=self.db,
                    scope_out=scope,
                )
            self.assertEqual(mode, mantis_main.SCAN_MODE_CROSS_FUNCTIONAL)
            groups = scope["depth_groups"]
            batch_files = {f for g in groups for f in g["targets"]}
            if len(seen) < 80:
                self.assertTrue(seen.isdisjoint(batch_files), f"run {run_idx} rescanned already-covered files")
            seen |= batch_files
            for g in groups:
                record_spend(
                    self.db,
                    rid,
                    g["targets"][0],
                    mantis_main.SCAN_MODE_CROSS_FUNCTIONAL,
                    tokens=5_000,
                    metadata={"failed": False, "depth": 30},
                )
                mantis_main._stamp_member_coverage(
                    self.db,
                    rid,
                    g,
                    g["targets"][0],
                    mantis_main.SCAN_MODE_CROSS_FUNCTIONAL,
                    depth=30,
                )
            if len(seen) == 80:
                break

        self.assertEqual(len(seen), 80, "Repeat depth-30 runs should cover all 80 active files in <=5 runs")

        # Once all 80 active files are covered, another run falls back to full repo (NOT noise files!).
        scope_after: dict = {}
        err_after = io.StringIO()
        with contextlib.redirect_stderr(err_after):
            _t, _a, mode_after = mantis_main.resolve_scan_targets(
                repo,
                {"depth": 30, "default_model": model},
                files,
                precomputed_astm={"slices": []},
                db_path=self.db,
                scope_out=scope_after,
            )
        self.assertEqual(mode_after, mantis_main.SCAN_MODE_CROSS_FUNCTIONAL)
        self.assertFalse(scope_after.get("depth_rotated"))
        self.assertIn("already covered at depth >= 30", err_after.getvalue())
        after_files = {f for g in scope_after["depth_groups"] for f in g["targets"]}
        self.assertFalse(any(f.endswith((".md", "package-lock.json")) for f in after_files))

    def test_depth_10_on_large_repo_batches_instead_of_root_stamping_and_min_depth_semantics(self):
        """[r3-depth-6]: Depth 1..10 on >1000 active files plans 1 bounded 40-file batch,
        depth is honored by uncovered_files(min_depth=...), legacy NULL-depth rows keep
        counting (INV-6), and --scan-mode uncovered reports lower-depth coverage."""
        big_repo, big_files = self._make_repo("huge_1050", n_active=1050)
        scope10: dict = {}
        with contextlib.redirect_stderr(io.StringIO()):
            targets10, _a10, mode10 = mantis_main.resolve_scan_targets(
                big_repo,
                {"depth": 10},
                big_files,
                precomputed_astm={"slices": []},
                scope_out=scope10,
            )
        self.assertEqual(mode10, mantis_main.SCAN_MODE_CROSS_FUNCTIONAL)
        self.assertEqual(len(targets10), 1)
        self.assertEqual(len(scope10["depth_groups"]), 1)
        self.assertLessEqual(len(scope10["depth_groups"][0]["targets"]), 40)

        # Now test depth-aware coverage on a 50-file repo scanned whole at depth 10.
        repo50, files50 = self._make_repo("repo_50", n_active=50)
        model = "vertex_ai/gemini-3.8-flash"
        record_run(self.db, "r_shallow", model=model)
        record_spend(
            self.db,
            "r_shallow",
            str(repo50),
            mantis_main.SCAN_MODE_WHOLE,
            tokens=5_000,
            metadata={"failed": False, "depth": 10},
        )
        # Depth 10 satisfies min_depth=10 and min_depth=None, but NOT min_depth=30!
        self.assertEqual(uncovered_files(self.db, files50, model=model, min_depth=None), [])
        self.assertEqual(uncovered_files(self.db, files50, model=model, min_depth=10), [])
        self.assertEqual(len(uncovered_files(self.db, files50, model=model, min_depth=30)), 50)
        below = covered_below_depth(self.db, files50, min_depth=30, model=model)
        self.assertEqual(len(below["files"]), 50)
        self.assertEqual(below["max_depth"], 10)

        # --scan-mode uncovered without explicit depth notices lower-depth coverage.
        err_imp = io.StringIO()
        with contextlib.redirect_stderr(err_imp):
            t_imp, _a, m_imp = mantis_main.resolve_scan_targets(
                repo50,
                {"scan_mode": mantis_main.SCAN_MODE_UNCOVERED, "depth": 30, "_depth_explicit": False, "default_model": model},
                files50,
                db_path=self.db,
            )
        self.assertEqual(t_imp, [])
        self.assertEqual(m_imp, mantis_main.SCAN_MODE_UNCOVERED)
        self.assertIn("lower depth", err_imp.getvalue())
        self.assertIn("max recorded depth 10 < 30", err_imp.getvalue())

        # --scan-mode uncovered WITH explicit --depth 50 re-includes all 50 shallow files.
        err_exp = io.StringIO()
        with contextlib.redirect_stderr(err_exp):
            t_exp, _a, m_exp = mantis_main.resolve_scan_targets(
                repo50,
                {"scan_mode": mantis_main.SCAN_MODE_UNCOVERED, "depth": 50, "_depth_explicit": True, "default_model": model},
                files50,
                db_path=self.db,
            )
        self.assertEqual(m_exp, mantis_main.SCAN_MODE_FILE_BY_FILE)
        self.assertEqual(len(t_exp), 50)
        self.assertIn("depth < 50", err_exp.getvalue())

        # INV-6: legacy row with NO recorded depth still counts as covered at any min_depth.
        record_spend(
            self.db,
            "r_legacy",
            files50[0],
            mantis_main.SCAN_MODE_FILE_BY_FILE,
            tokens=1_000,
            metadata={"failed": False},
        )
        uncov_at_100 = uncovered_files(self.db, files50, model=model, min_depth=100)
        self.assertNotIn(files50[0], uncov_at_100)
        self.assertEqual(len(uncov_at_100), 49)

    def test_legacy_auto_per_file_sweep_excludes_doc_and_lock_noise(self):
        """[planner-surveyor-1]: When legacy non-depth `auto` selects file-by-file,
        pure docs/lockfiles/CSS noise are filtered out rather than swept per file."""
        repo, files = self._make_repo("noisy_legacy", n_active=10, n_noise=5)
        virgin_db = str(self.root / "virgin_legacy.db")
        with contextlib.redirect_stderr(io.StringIO()):
            targets, _a, mode = mantis_main.resolve_scan_targets(
                repo,
                {"surveyor": {"min_source_files": 5}},
                files,
                db_path=virgin_db,
            )
        self.assertEqual(mode, mantis_main.SCAN_MODE_FILE_BY_FILE)
        self.assertEqual(len(targets), 10)
        self.assertTrue(all(f.endswith(".py") for f in targets))


class DepthEffortPrecedenceAndResumeFidelityTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_depth_eff_")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(os.path.realpath(self._tmp.name))
        self.wf_base = _REF_ROOT / "workflow.json"

    def test_depth_effort_applies_to_audit_stem_only_and_respects_operator_precedence(self):
        """[r3-depth-2]: Depth effort applies to audit_stem prefix_group without flattening
        non-stem nodes, and yields to CLI > REASONING_EFFORT > workflow.local.json."""
        wf_dir = self.root / "wf"
        wf_dir.mkdir()
        wf_copy = wf_dir / "workflow.json"
        wf_copy.write_text(self.wf_base.read_text(encoding="utf-8"), encoding="utf-8")

        base_env = {"OPENAI_API_KEY": "dummy", "MANTIS_LLM_STREAM": "0"}

        # 1. Depth effort alone ("high"): audit_stem becomes "high", non-stem deduplicator stays "low",
        #    calibrator/reflector stay "medium", and _cli_reasoning_effort is NOT set.
        with patch.dict(os.environ, base_env, clear=True):
            wf_depth, cfg_depth = gl.load_workflow_from_json(
                str(wf_copy),
                model_override="openai/gpt-5",
                load_local=False,
                depth_reasoning_effort="high",
            )
        agents_depth = _collect_workflow_agents(wf_depth)
        for stem_id in ("architect", "threat_modeler", "planner", "explorer", "researcher", "reviewer", "critic"):
            self.assertEqual(agents_depth[stem_id].model._additional_args.get("reasoning_effort"), "high", stem_id)
        self.assertEqual(agents_depth["deduplicator"].model._additional_args.get("reasoning_effort"), "low")
        self.assertEqual(agents_depth["reflector"].model._additional_args.get("reasoning_effort"), "medium")
        self.assertNotIn("_cli_reasoning_effort", cfg_depth)
        self.assertEqual(cfg_depth.get("_effective_stem_reasoning_effort"), "high")

        # 2. workflow.local.json beats depth_reasoning_effort.
        (wf_dir / "workflow.local.json").write_text(
            json.dumps({"config": {"reasoning_effort": "low"}}),
            encoding="utf-8",
        )
        with patch.dict(os.environ, base_env, clear=True):
            wf_local, cfg_local = gl.load_workflow_from_json(
                str(wf_copy),
                model_override="openai/gpt-5",
                load_local=True,
                depth_reasoning_effort="high",
            )
        agents_local = _collect_workflow_agents(wf_local)
        self.assertEqual(agents_local["researcher"].model._additional_args.get("reasoning_effort"), "low")
        self.assertEqual(agents_local["patcher"].model._additional_args.get("reasoning_effort"), "low")
        self.assertEqual(cfg_local.get("_effective_stem_reasoning_effort"), "low")

        # 3. REASONING_EFFORT env beats workflow.local.json and depth_reasoning_effort.
        with patch.dict(os.environ, {**base_env, "REASONING_EFFORT": "medium"}, clear=True):
            wf_env, cfg_env = gl.load_workflow_from_json(
                str(wf_copy),
                model_override="openai/gpt-5",
                load_local=True,
                depth_reasoning_effort="high",
            )
        agents_env = _collect_workflow_agents(wf_env)
        self.assertEqual(agents_env["researcher"].model._additional_args.get("reasoning_effort"), "medium")
        self.assertEqual(cfg_env.get("_effective_stem_reasoning_effort"), "medium")

        # 4. CLI reasoning_effort_override beats env, local, and depth.
        with patch.dict(os.environ, {**base_env, "REASONING_EFFORT": "medium"}, clear=True):
            wf_cli, cfg_cli = gl.load_workflow_from_json(
                str(wf_copy),
                model_override="openai/gpt-5",
                reasoning_effort_override="high",
                load_local=True,
                depth_reasoning_effort="low",
            )
        agents_cli = _collect_workflow_agents(wf_cli)
        self.assertEqual(agents_cli["researcher"].model._additional_args.get("reasoning_effort"), "high")
        self.assertEqual(agents_cli["deduplicator"].model._additional_args.get("reasoning_effort"), "high")
        self.assertEqual(cfg_cli.get("_cli_reasoning_effort"), "high")

    def test_resume_restores_depth_effort_preserves_explicit_passes_1_and_parallel_workers(self):
        """[r3-depth-3] + [r3-depth-2]: Bare --resume restores depth reasoning effort onto
        the reloaded graph, keeps explicit --passes 1 on depth >= 75, passes depth effort to
        extra --parallel workers, and notices an explicit --resume --depth override."""
        repo = self.root / "resume_repo"
        repo.mkdir()
        f1 = repo / "a.py"
        f2 = repo / "b.py"
        f1.write_text("def a(): return 1\n", encoding="utf-8")
        f2.write_text("def b(): return 2\n", encoding="utf-8")
        db = str(self.root / "resume.db")
        init_db(db)

        env = {"OPENAI_API_KEY": "dummy", "MANTIS_LLM_STREAM": "0"}

        # Run 1: --depth 90 --passes 1 --scan-mode file-by-file, paused on second file.
        run1_calls: list[str] = []
        paused_run_id: list[str] = []

        async def _pause_on_second(_runner, _ss, filepath, rid, **kw):
            run1_calls.append(filepath)
            paused_run_id.append(rid)
            if len(run1_calls) == 1:
                kw["budget_controller"].audit_code_reads += 1
                return False
            raise BudgetExceededError("max_tokens", 1000, 1000, rid)

        out1, err1 = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, env, clear=True), \
             patch.object(mantis_main, "execute_sub_task", side_effect=_pause_on_second), \
             contextlib.redirect_stdout(out1), \
             contextlib.redirect_stderr(err1):
            rc1 = asyncio.run(
                mantis_main.pipeline(
                    scan_target=str(repo),
                    db_override=db,
                    model_override="openai/gpt-5",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    scan_mode_override="file-by-file",
                    auto_configure=False,
                    load_local=False,
                    assume_yes=True,
                    depth=90,
                    passes=1,
                    passes_explicit=True,
                    no_memory=True,
                )
            )
        self.assertEqual(rc1, 2, out1.getvalue() + err1.getvalue())
        rid = paused_run_id[0]
        # Pause banner must include --passes 1 and clean --no-memory (no 'True'!).
        self.assertIn("--passes 1", out1.getvalue())
        self.assertIn("--no-memory", out1.getvalue())
        self.assertNotIn("--no-memory True", out1.getvalue())

        # Persisted plan must retain passes=1, passes_explicit=True, depth=90.
        loaded = load_run_plan(db, rid, str(repo))
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["depth"], 90)
        self.assertEqual(loaded["passes"], 1)
        self.assertTrue(loaded.get("passes_explicit"))

        # Run 2: bare --resume (depth=None, passes=1, passes_explicit=False) with --parallel 2.
        # Must restore depth=90, reload workflow with depth_reasoning_effort='max', pass
        # depth_reasoning_effort='max' to worker 2, and run only 1 pass (NOT 2!).
        loaded_efforts: list[object] = []
        real_loader = mantis_main.load_workflow_from_json

        def _spy_loader(*args, **kwargs):
            loaded_efforts.append(kwargs.get("depth_reasoning_effort"))
            return real_loader(*args, **kwargs)

        resumed_passes: list[tuple[str, int, int]] = []

        async def _finish_resume(_runner, _ss, filepath, _rid, **kw):
            ctx = current_run_context.get()
            resumed_passes.append((filepath, ctx.depth, ctx.pass_index))
            kw["budget_controller"].audit_code_reads += 1
            return False

        out2, err2 = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, env, clear=True), \
             patch.object(mantis_main, "load_workflow_from_json", side_effect=_spy_loader), \
             patch.object(mantis_main, "execute_sub_task", side_effect=_finish_resume), \
             contextlib.redirect_stdout(out2), \
             contextlib.redirect_stderr(err2):
            rc2 = asyncio.run(
                mantis_main.pipeline(
                    scan_target=str(repo),
                    db_override=db,
                    model_override="openai/gpt-5",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    auto_configure=False,
                    load_local=False,
                    assume_yes=True,
                    resume_run_id=rid,
                    parallel=2,
                )
            )
        self.assertEqual(rc2, 0, out2.getvalue() + err2.getvalue())
        # Initial load (depth 30 -> None), reload after saved_plan depth 90 ('max'), and worker 2 ('max')
        # (worker_count = min(2, 1) = 1 since only 1 target remains; verify reloaded graph got 'max').
        self.assertIn("max", loaded_efforts)
        self.assertEqual(len(resumed_passes), 1)
        self.assertEqual(resumed_passes[0][1], 90)
        self.assertEqual(resumed_passes[0][2], 1)
        self.assertIn("effort=max", out2.getvalue())

        # Verify extra --parallel worker receives depth_reasoning_effort when >=2 campaigns run.
        par_efforts: list[object] = []

        def _spy_par_loader(*args, **kwargs):
            par_efforts.append(kwargs.get("depth_reasoning_effort"))
            return real_loader(*args, **kwargs)

        async def _noop_exec(_runner, _ss, _fp, _rid, **kw):
            kw["budget_controller"].audit_code_reads += 1
            return False

        with patch.dict(os.environ, env, clear=True), \
             patch.object(mantis_main, "load_workflow_from_json", side_effect=_spy_par_loader), \
             patch.object(mantis_main, "execute_sub_task", side_effect=_noop_exec), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            rc_par = asyncio.run(
                mantis_main.pipeline(
                    scan_target=str(repo),
                    db_override=str(self.root / "par.db"),
                    model_override="openai/gpt-5",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    scan_mode_override="file-by-file",
                    auto_configure=False,
                    load_local=False,
                    assume_yes=True,
                    depth=65,
                    parallel=2,
                )
            )
        self.assertEqual(rc_par, 0)
        self.assertEqual(par_efforts, ["high", "high"])

        # Verify explicit --resume --depth M differing from saved depth emits a notice.
        db_ov = str(self.root / "override_depth.db")
        init_db(db_ov)
        record_run(db_ov, "r_ov", model="openai/gpt-5", metadata={"target": str(repo), "target_root": str(repo)})
        record_run_plan(db_ov, "r_ov", targets=[str(f1)], target_root=str(repo), depth=65)
        err_ov = io.StringIO()
        with patch.dict(os.environ, env, clear=True), \
             patch.object(mantis_main, "execute_sub_task", side_effect=_noop_exec), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(err_ov):
            rc_ov = asyncio.run(
                mantis_main.pipeline(
                    scan_target=str(repo),
                    db_override=db_ov,
                    model_override="openai/gpt-5",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    auto_configure=False,
                    load_local=False,
                    assume_yes=True,
                    resume_run_id="r_ov",
                    depth=15,
                )
            )
        self.assertEqual(rc_ov, 0)
        self.assertIn("Applying explicit --depth 15 over recorded depth 65", err_ov.getvalue())


class RepoDocsBatchAndLiveSmokeFixesTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_docs_smoke_")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(os.path.realpath(self._tmp.name))
        self.db = str(self.root / "knowledge.db")
        init_db(self.db)

    def test_repo_docs_injected_on_depth_batch_campaigns_and_judge_neutrality_rule_present(self):
        """[r3-repo-docs-2] & [r3-repo-docs-1]: Multi-file depth batches (using group_targets)
        MUST receive REPO_DOCS_DIRECTIVE_MARKER on architect/threat_modeler, while true
        single-file campaigns do not; reviewer/critic/reproducer carry the neutrality rule."""
        from google.adk.models import LlmRequest

        repo = self.root / "batched_repo"
        repo.mkdir()
        (repo / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
        (repo / "README.md").write_text("# App\n", encoding="utf-8")
        f1 = repo / "a.py"
        f2 = repo / "b.py"
        f1.write_text("x = 1\n", encoding="utf-8")
        f2.write_text("y = 2\n", encoding="utf-8")

        batch_ctx = RunContext(
            jail_dir=str(repo),
            db_path=self.db,
            target_file=str(f1),
            group_targets=(str(f1), str(f2)),
            scan_mode="cross-functional",
            run_id="r_batch_docs",
        )
        tok = current_run_context.set(batch_ctx)
        self.addCleanup(current_run_context.reset, tok)

        for stage in ("architect", "threat_modeler"):
            req = LlmRequest()
            req.config.system_instruction = "base"
            gl._make_campaign_directive_before_model_callback(stage)(None, req)
            self.assertIn(REPO_DOCS_DIRECTIVE_MARKER, str(req.config.system_instruction), stage)
            self.assertIn("SECURITY.md", str(req.config.system_instruction), stage)

        for judge in ("reviewer", "critic"):
            self.assertIn(INHERITED_STEM_NEUTRALITY_RULE.strip(), STAGE_PROMPTS[judge], judge)

        # All three forked judge stages (reviewer, critic, reproducer) receive the neutrality
        # rule in their compiled prefix-group stage assignment prompt while STAGE_PROMPTS
        # stays safely below MAX_NODE_SYSTEM_PROMPT_CHARS / 2.
        from types import SimpleNamespace
        from google.genai import types as genai_types

        wf, _cfg = gl.load_workflow_from_json(
            str(_REF_ROOT / "workflow.json"),
            model_override="openai/gpt-5",
            load_local=False,
        )
        agents = _collect_workflow_agents(wf)

        import inspect

        async def _run_callbacks(cb, cb_ctx, req):
            fns = cb if isinstance(cb, list) else ([cb] if cb is not None else [])
            for fn in fns:
                res = fn(cb_ctx, req)
                if inspect.isawaitable(res):
                    await res

        for judge in ("reviewer", "critic", "reproducer"):
            self.assertIn(judge, agents, f"missing compiled agent {judge}")
            req = LlmRequest(
                contents=[genai_types.Content(role="user", parts=[genai_types.Part(text="seed")])]
            )
            cb_ctx = SimpleNamespace(
                session=SimpleNamespace(events=[], state={}),
                invocation_id="inv-neutrality",
            )
            asyncio.run(_run_callbacks(agents[judge].before_model_callback, cb_ctx, req))
            rendered = "\n".join(
                getattr(p, "text", "") or ""
                for c in (req.contents or [])
                for p in (getattr(c, "parts", None) or [])
            )
            self.assertIn(INHERITED_STEM_NEUTRALITY_RULE.strip(), rendered, judge)

    def test_format_pause_banner_renders_boolean_flags_without_value_tokens(self):
        """Bonus live-run bug #1: boolean resume_flags (`--no-memory: True`) must render as
        bare flags parseable by launch.py argparse, never `--no-memory True`."""
        ctrl = BudgetController(config=BudgetConfig(max_llm_calls=4), run_id="run-flag-test")
        banner = ctrl.format_pause_banner(
            trigger="max_llm_calls",
            target=str(self.root),
            resume_flags={
                "--db": self.db,
                "--model": "vertex_ai/gemini-3.8-flash",
                "--no-memory": True,
                "--flex": True,
                "--intra-run-learning": False,
                "--depth": 1,
                "--passes": 1,
            },
        )
        self.assertIn("--no-memory", banner)
        self.assertNotIn("--no-memory True", banner)
        self.assertIn("--flex", banner)
        self.assertNotIn("--flex True", banner)
        self.assertNotIn("--intra-run-learning", banner)
        self.assertIn("--depth 1", banner)
        self.assertIn("--passes 1", banner)

        # Extract the resume command line from the banner and verify launch.py parses it!
        cmd_line = next(line.strip() for line in banner.splitlines() if "--resume run-flag-test" in line)
        tokens = shlex.split(cmd_line)
        # Drop launcher path (`.../run.sh` or `python3 .../launch.py`)
        argv = tokens[2:] if tokens[0] == "python3" else tokens[1:]
        parsed = build_parser().parse_args(argv)
        self.assertTrue(parsed.no_memory)
        self.assertTrue(parsed.flex)
        self.assertEqual(parsed.depth, 1)
        self.assertEqual(parsed.passes, 1)
        self.assertEqual(parsed.resume, "run-flag-test")

    def test_record_calibration_retains_peak_risk_score_per_file_and_run(self):
        """Bonus live-run bug #2: calibrating multiple findings in the same file during a
        run must keep the peak (highest) score instead of overwriting 10.0 with 8.0."""
        fp = str(self.root / "app.py")
        record_calibration(self.db, fp, 10.0, "Critical RCE", run_id="r1")
        record_calibration(self.db, fp, 8.0, "High path traversal", run_id="r1")
        rows = read_risk_scores(self.db, filepath=fp, run_id="r1")
        self.assertEqual(len(rows), 1)
        self.assertAlmostEqual(rows[0]["score"], 10.0)
        self.assertEqual(rows[0]["reasoning"], "Critical RCE")

        # Higher subsequent score DOES upgrade the file score.
        record_calibration(self.db, fp, 6.5, "Medium issue", run_id="r2")
        record_calibration(self.db, fp, 9.5, "Critical auth bypass", run_id="r2")
        rows2 = read_risk_scores(self.db, filepath=fp, run_id="r2")
        self.assertEqual(len(rows2), 1)
        self.assertAlmostEqual(rows2[0]["score"], 9.5)
        self.assertEqual(rows2[0]["reasoning"], "Critical auth bypass")

    def test_shallow_scan_does_not_hide_file_edit_from_deeper_runs(self):
        """[r4-depth-change-detection]: A --depth 5 triage after an edit must not hide
        the edited file from a subsequent --depth 30 scan."""
        repo = self.root / "depth_change_repo"
        repo.mkdir()
        a = repo / "a.py"
        b = repo / "b.py"
        a.write_text("def a(): return 1\n", encoding="utf-8")
        b.write_text("def b(): return 1\n", encoding="utf-8")
        files = [str(a), str(b)]
        model = "vertex_ai/gemini-3.8-flash"

        # Run 1 at depth 30 covers the repo with v1 hashes.
        record_run(self.db, "run_d30", model=model)
        record_spend(
            self.db, "run_d30", str(repo), mantis_main.SCAN_MODE_WHOLE,
            tokens=5000, metadata={"failed": False, "depth": 30},
        )
        record_coverage_files(self.db, "run_d30", str(repo), scope_identities(files))
        self.assertEqual(uncovered_files(self.db, files, model=model, min_depth=30), [])

        # Edit a.py -> v2 (different size so mtime/size cache never collides).
        a.write_text("def a():\n    return 2 + 2  # edited\n", encoding="utf-8")

        # Run 2 at depth 5 records the new v2 hash.
        record_run(self.db, "run_d5", model=model)
        record_spend(
            self.db, "run_d5", str(repo), mantis_main.SCAN_MODE_WHOLE,
            tokens=1000, metadata={"failed": False, "depth": 5},
        )
        record_coverage_files(self.db, "run_d5", str(repo), scope_identities(files))

        # At min_depth=5 (or None), a.py is covered as v2.
        self.assertEqual(uncovered_files(self.db, files, model=model, min_depth=5), [])
        self.assertEqual(uncovered_files(self.db, files, model=model, min_depth=None), [])
        self.assertEqual(changed_files(self.db, files, model=model), {"files": []})

        # At min_depth=30, the depth-5 row must NOT hide the edit to a.py!
        self.assertEqual(uncovered_files(self.db, files, model=model, min_depth=30), [str(a)])
        self.assertEqual(
            changed_files(self.db, files, model=model, min_depth=30),
            {"files": [str(a)]},
        )

    def test_mixed_depth_resume_under_one_run_id_and_legacy_null_depth_rows(self):
        """[r4-depth-change-detection]: Filtering by (run_id, campaign_target) separates
        mixed-depth campaigns resumed under ONE run_id, while preserving legacy depth-less
        (INV-6) and imported coverage rows."""
        repo = self.root / "mixed_resume_repo"
        dir_a = repo / "dirA"
        dir_b = repo / "dirB"
        dir_c = repo / "dirC"
        for d in (dir_a, dir_b, dir_c):
            d.mkdir(parents=True)
        fa = dir_a / "a.py"
        fb = dir_b / "b.py"
        fc = dir_c / "c.py"
        fa.write_text("x = 1\n", encoding="utf-8")
        fb.write_text("y = 1\n", encoding="utf-8")
        fc.write_text("z = 1\n", encoding="utf-8")
        model = "vertex_ai/gemini-3.8-flash"

        # Baseline depth-30 run covers dirA and dirB; legacy depth-less import covers dirC.
        record_run(self.db, "run_base", model=model)
        record_spend(self.db, "run_base", str(dir_a), "cross-functional", tokens=4000, metadata={"depth": 30})
        record_coverage_files(self.db, "run_base", str(dir_a), scope_identities([str(fa)]))
        record_spend(self.db, "run_base", str(dir_b), "cross-functional", tokens=4000, metadata={"depth": 30})
        record_coverage_files(self.db, "run_base", str(dir_b), scope_identities([str(fb)]))

        # Imported legacy row: campaign_spend has per-file target with NO depth,
        # while coverage_files records campaign_target=str(repo) (knowledge.py shape).
        record_run(self.db, "run_imported", model=model)
        record_spend(self.db, "run_imported", str(fc), "whole", tokens=0, metadata={"imported": True})
        record_coverage_files(self.db, "run_imported", str(repo), scope_identities([str(fc)]))

        # Edit a.py and b.py.
        fa.write_text("x = 2  # modified\n", encoding="utf-8")
        fb.write_text("y = 2  # modified\n", encoding="utf-8")

        # ONE resumed run_id ("run_mixed") scans dirA at depth=30, then resumes dirB at depth=5!
        record_run(self.db, "run_mixed", model=model)
        record_spend(self.db, "run_mixed", str(dir_a), "cross-functional", tokens=4000, metadata={"depth": 30})
        record_coverage_files(self.db, "run_mixed", str(dir_a), scope_identities([str(fa)]))
        record_spend(self.db, "run_mixed", str(dir_b), "cross-functional", tokens=1000, metadata={"depth": 5})
        record_coverage_files(self.db, "run_mixed", str(dir_b), scope_identities([str(fb)]))

        # Under min_depth=30:
        # - dirA/a.py was re-scanned at depth 30 -> covered.
        # - dirB/b.py was only re-scanned at depth 5 (under the SAME run_id!) -> still uncovered!
        # - dirC/c.py has legacy NULL depth (INV-6) -> still covered even at min_depth=100!
        self.assertEqual(
            uncovered_files(self.db, [str(fa), str(fb), str(fc)], model=model, min_depth=30),
            [str(fb)],
        )
        # If legacy c.py is later edited, min_depth=100 still sees the change against the imported row.
        fc.write_text("z = 999  # edited legacy\n", encoding="utf-8")
        self.assertEqual(
            uncovered_files(self.db, [str(fc)], model=model, min_depth=100),
            [str(fc)],
        )

    def test_has_active_file_sweep_scopes_to_newest_coverage_earning_run(self):
        """[r4-sticky-file-sweep]: One historical per-file campaign must not permanently lock
        future default runs into file-by-file sweeps once a newer batch/whole run supersedes it."""
        repo = self.root / "large_sticky_repo"
        repo.mkdir()
        files = []
        for i in range(1050):
            p = repo / f"mod_{i:04d}.py"
            p.write_text(f"def f_{i}(): return {i}\n", encoding="utf-8")
            files.append(str(p))
        other_repo = self.root / "other_sticky_repo"
        other_repo.mkdir()
        other_files = []
        for i in range(3):
            p = other_repo / f"o_{i}.py"
            p.write_text(f"def o_{i}(): return {i}\n", encoding="utf-8")
            other_files.append(str(p))
        model = "vertex_ai/gemini-3.8-flash"

        # 1. Start with a paused file-by-file (or --scan-mode uncovered) sweep -> active.
        record_run(self.db, "r1_sweep", model=model)
        record_spend(
            self.db, "r1_sweep", files[0], mantis_main.SCAN_MODE_FILE_BY_FILE,
            tokens=2000, metadata={"failed": False, "depth": 30},
        )
        self.assertTrue(has_active_file_sweep(self.db, files, model=model))

        # 2. A FAILED cross-functional run does not supersede the sweep.
        record_run(self.db, "r2_failed", model=model)
        record_spend(
            self.db, "r2_failed", files[1], mantis_main.SCAN_MODE_CROSS_FUNCTIONAL,
            tokens=2000, metadata={"failed": True, "depth": 30},
        )
        self.assertTrue(has_active_file_sweep(self.db, files, model=model))

        # 3. A completed cross-functional batch run supersedes the old file sweep.
        record_run(self.db, "r3_batch", model=model)
        record_spend(
            self.db, "r3_batch", files[2], mantis_main.SCAN_MODE_CROSS_FUNCTIONAL,
            tokens=10_000, metadata={"failed": False, "depth": 30},
        )
        self.assertFalse(has_active_file_sweep(self.db, files, model=model))

        # 4. A newer file-by-file run on an UNRELATED repo must not flip this repo back.
        record_run(self.db, "r4_other", model=model)
        record_spend(
            self.db, "r4_other", other_files[0], mantis_main.SCAN_MODE_FILE_BY_FILE,
            tokens=2000, metadata={"failed": False, "depth": 30},
        )
        self.assertFalse(has_active_file_sweep(self.db, files, model=model))

        # End-to-end: plain `auto` on the >1000-file repo stays in depth batches!
        scope: dict = {}
        with contextlib.redirect_stderr(io.StringIO()):
            _t, _a, mode = mantis_main.resolve_scan_targets(
                repo,
                {"depth": 30, "default_model": model},
                files,
                precomputed_astm={"slices": []},
                db_path=self.db,
                scope_out=scope,
            )
        self.assertEqual(mode, mantis_main.SCAN_MODE_CROSS_FUNCTIONAL)

        # 5. Starting a new file-by-file run on THIS repo activates sweep continuation again.
        record_run(self.db, "r5_new_sweep", model=model)
        record_spend(
            self.db, "r5_new_sweep", files[3], mantis_main.SCAN_MODE_FILE_BY_FILE,
            tokens=2000, metadata={"failed": False, "depth": 30},
        )
        self.assertTrue(has_active_file_sweep(self.db, files, model=model))

    def test_has_active_file_sweep_ignores_changed_and_narrow_subdir_runs(self):
        """A small `--scan-mode changed` run or narrow subdirectory scan (e.g. `lib/`)
        must neither terminate an active repo-wide file-by-file sweep nor lock the
        entire repository into per-file sweeps."""
        repo = self.root / "scoped_sweep_repo"
        src_dir = repo / "src"
        lib_dir = repo / "lib"
        src_dir.mkdir(parents=True)
        lib_dir.mkdir(parents=True)
        src_file = src_dir / "main.py"
        lib_file = lib_dir / "util.py"
        src_file.write_text("x = 1\n", encoding="utf-8")
        lib_file.write_text("y = 1\n", encoding="utf-8")
        files = [str(src_file), str(lib_file)]
        model = "vertex_ai/gemini-3.8-flash"

        # 1. Start a repo-wide file-by-file sweep -> active.
        record_run(
            self.db, "r_full_sweep", model=model,
            metadata={"target": str(repo), "target_root": str(repo)},
        )
        record_spend(
            self.db, "r_full_sweep", str(src_file), mantis_main.SCAN_MODE_FILE_BY_FILE,
            tokens=2000, metadata={"failed": False, "depth": 30},
        )
        self.assertTrue(has_active_file_sweep(self.db, files, model=model))

        # 2. A newer `--scan-mode changed` run on lib/ (or even repo root) must NOT end it.
        record_run(
            self.db, "r_chg_lib", model=model,
            metadata={"target": str(repo), "target_root": str(repo)},
        )
        record_spend(
            self.db, "r_chg_lib", str(lib_dir), mantis_main.SCAN_MODE_CHANGED,
            tokens=1500, metadata={"failed": False, "depth": 30},
        )
        self.assertTrue(has_active_file_sweep(self.db, files, model=model))
        record_spend(
            self.db, "r_chg_lib", str(repo), mantis_main.SCAN_MODE_CHANGED,
            tokens=1500, metadata={"failed": False, "depth": 30},
        )
        self.assertTrue(has_active_file_sweep(self.db, files, model=model))

        # 3. A newer narrow `whole` scan strictly on lib/ (or lib/util.py) must NOT end it.
        record_run(
            self.db, "r_whole_lib", model=model,
            metadata={"target": str(lib_dir), "target_root": str(repo)},
        )
        record_spend(
            self.db, "r_whole_lib", str(lib_dir), mantis_main.SCAN_MODE_WHOLE,
            tokens=1500, metadata={"failed": False, "depth": 30},
        )
        self.assertTrue(has_active_file_sweep(self.db, files, model=model))

        # Even a legacy `whole` row lacking `runs.metadata_json.target` (only `target_root`) on lib/ must NOT end it.
        record_run(
            self.db, "r_whole_lib_legacy", model=model,
            metadata={"target_root": str(repo)},
        )
        record_spend(
            self.db, "r_whole_lib_legacy", str(lib_dir), mantis_main.SCAN_MODE_WHOLE,
            tokens=1500, metadata={"failed": False, "depth": 30},
        )
        self.assertTrue(has_active_file_sweep(self.db, files, model=model))

        # 4. A newer narrow `cross-functional` run targeting ONLY lib/ must NOT end it.
        record_run(
            self.db, "r_cf_lib", model=model,
            metadata={"target": str(lib_dir), "target_root": str(repo)},
        )
        record_spend(
            self.db, "r_cf_lib", str(lib_file), mantis_main.SCAN_MODE_CROSS_FUNCTIONAL,
            tokens=3000, metadata={"failed": False, "depth": 30},
        )
        self.assertTrue(has_active_file_sweep(self.db, files, model=model))

        # 5. A FULL-REPO `whole` run on `repo` DOES end the sweep!
        record_run(
            self.db, "r_whole_repo", model=model,
            metadata={"target": str(repo), "target_root": str(repo)},
        )
        record_spend(
            self.db, "r_whole_repo", str(repo), mantis_main.SCAN_MODE_WHOLE,
            tokens=8000, metadata={"failed": False, "depth": 30},
        )
        self.assertFalse(has_active_file_sweep(self.db, files, model=model))

        # 6. A narrow `file-by-file` run targeting ONLY lib/ must NOT activate a repo-wide sweep!
        record_run(
            self.db, "r_sweep_lib_only", model=model,
            metadata={"target": str(lib_dir), "target_root": str(repo)},
        )
        record_spend(
            self.db, "r_sweep_lib_only", str(lib_file), mantis_main.SCAN_MODE_FILE_BY_FILE,
            tokens=1500, metadata={"failed": False, "depth": 30},
        )
        self.assertFalse(has_active_file_sweep(self.db, files, model=model))


if __name__ == "__main__":
    unittest.main()

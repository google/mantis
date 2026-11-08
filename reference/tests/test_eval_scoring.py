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

"""Unit tests for eval scoring honesty in run_eval (issue #8).

A model that never answers (dead key, quota, timeout) must not be scored as a
correct rejector: no-verdict cases get their own bucket and are never TN,
precision is undefined (None) rather than 1.0 when there are no positive
predictions, and the calibrator does not invent a 5.0 score for findings that
were never scored. Operational metrics stay harsh: a real finding that gets no
verdict is still a fatal drop.
"""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

import json

import evals.run_eval as run_eval

_EVALS_DIR = Path(_REF_ROOT) / "evals"
_REVIEW_DS = _EVALS_DIR / "review_dataset.json"
_CRITIC_DS = _EVALS_DIR / "critic_dataset.json"
_CALIBRATE_DS = _EVALS_DIR / "calibrate_dataset.json"


async def _dead_run_async(self, *args, **kwargs):
    """Simulates a model/API that always fails: raises before any event."""
    raise RuntimeError("simulated model failure")
    yield  # pragma: no cover - makes this an async generator function


def _event(text):
    return SimpleNamespace(content=SimpleNamespace(parts=[SimpleNamespace(text=text)]))


def _route_oracle(title_to_route, fail_routes=()):
    """run_async stub answering the ground-truth route per case (by prompt title).

    Routes listed in fail_routes raise instead, simulating a model that only
    fails on those cases.
    """

    async def oracle(self, *args, **kwargs):
        prompt = kwargs["new_message"].parts[0].text
        route = next(r for t, r in title_to_route.items() if t in prompt)
        if route in fail_routes:
            raise RuntimeError("simulated failure on this case")
        yield _event(f'{{"route": "{route}"}}')

    return oracle


def _title_routes(dataset_path):
    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {c["finding"]["title"]: c["ground_truth"]["expected_route"] for c in data["cases"]}


class TestEvalScoring(unittest.IsolatedAsyncioTestCase):

    # ------------------------------------------------------------------
    # Dead model: must be visibly broken, not a perfect filter.
    # ------------------------------------------------------------------

    async def test_dead_model_reviewer_scores_no_true_negatives(self):
        with patch.object(run_eval.Runner, "run_async", _dead_run_async):
            res = await run_eval.eval_reviewer("test-model", "low", _REVIEW_DS)
        self.assertEqual(res["tp"], 0)
        self.assertEqual(res["fp"], 0)
        self.assertEqual(res["tn"], 0)
        self.assertEqual(res["fn"], 0)
        self.assertEqual(res["no_verdict"], 6)
        self.assertEqual(res["errors"], 6)
        self.assertIsNone(res["precision"])
        self.assertEqual(res["recall"], 0.0)
        self.assertEqual(res["noise_admitted"], 0)
        # Operationally the two real findings were still dropped.
        self.assertEqual(res["fatal_drops"], 2)
        self.assertAlmostEqual(res["safety"], 4 / 6)

    async def test_dead_model_critic_scores_no_true_negatives(self):
        with patch.object(run_eval.Runner, "run_async", _dead_run_async):
            res = await run_eval.eval_critic("test-model", "low", _CRITIC_DS)
        self.assertEqual(res["tn"], 0)
        self.assertEqual(res["no_verdict"], 4)
        self.assertEqual(res["errors"], 4)
        self.assertIsNone(res["precision"])
        self.assertEqual(res["recall"], 0.0)

    async def test_dead_model_calibrator_reports_unscored_not_mae(self):
        with patch.object(run_eval.Runner, "run_async", _dead_run_async):
            res = await run_eval.eval_calibrator("test-model", "low", _CALIBRATE_DS)
        self.assertIsNone(res["mae"])
        self.assertEqual(res["unscored"], 3)
        self.assertEqual(res["errors"], 1)
        self.assertEqual(res["priority_accuracy"], 0.0)

    # ------------------------------------------------------------------
    # Partially dead model: silence on positives is fatal, not neutral.
    # ------------------------------------------------------------------

    async def test_reviewer_silence_on_positives_still_counts_as_fatal_drop(self):
        routes = _title_routes(_REVIEW_DS)
        oracle = _route_oracle(routes, fail_routes=("confirmed",))
        with patch.object(run_eval.Runner, "run_async", oracle):
            res = await run_eval.eval_reviewer("test-model", "low", _REVIEW_DS)
        self.assertEqual(res["tn"], 4)
        self.assertEqual(res["no_verdict"], 2)
        self.assertEqual(res["errors"], 2)
        # No positive predictions were made, so precision is undefined --
        # not 1.0 -- even though the negatives were all handled correctly.
        self.assertIsNone(res["precision"])
        self.assertEqual(res["recall"], 0.0)
        self.assertEqual(res["fatal_drops"], 2)
        self.assertAlmostEqual(res["safety"], 4 / 6)

    # ------------------------------------------------------------------
    # Healthy and noisy models: real verdicts still score normally.
    # ------------------------------------------------------------------

    async def test_reviewer_perfect_model_scores_perfectly(self):
        routes = _title_routes(_REVIEW_DS)
        with patch.object(run_eval.Runner, "run_async", _route_oracle(routes)):
            res = await run_eval.eval_reviewer("test-model", "low", _REVIEW_DS)
        self.assertEqual(res["tp"], 2)
        self.assertEqual(res["tn"], 4)
        self.assertEqual(res["no_verdict"], 0)
        self.assertEqual(res["errors"], 0)
        self.assertEqual(res["precision"], 1.0)
        self.assertEqual(res["recall"], 1.0)
        self.assertEqual(res["fatal_drops"], 0)
        self.assertEqual(res["safety"], 1.0)

    async def test_reviewer_confirm_everything_model_pays_in_precision(self):
        routes = _title_routes(_REVIEW_DS)
        all_confirmed = {t: "confirmed" for t in routes}
        with patch.object(run_eval.Runner, "run_async", _route_oracle(all_confirmed)):
            res = await run_eval.eval_reviewer("test-model", "low", _REVIEW_DS)
        self.assertEqual(res["tp"], 2)
        self.assertEqual(res["fp"], 4)
        self.assertEqual(res["tn"], 0)
        self.assertEqual(res["no_verdict"], 0)
        self.assertAlmostEqual(res["precision"], 2 / 6)
        self.assertEqual(res["noise_admitted"], 4)

    # ------------------------------------------------------------------
    # score_dedup_partition: undefined precision without merge evidence.
    # ------------------------------------------------------------------

    def test_dedup_precision_undefined_when_nothing_merged(self):
        gt = {
            "findings": [
                {"id": 1, "title": "A"},
                {"id": 2, "title": "A-dup"},
                {"id": 3, "title": "B"},
            ],
            "ground_truth_clusters": {
                "c1": {"finding_ids": [1, 2], "relation": "DUPLICATE"},
                "c2": {"finding_ids": [3], "relation": "DISTINCT"},
            },
        }
        res = run_eval.score_dedup_partition([], gt)
        self.assertEqual(res["tp"], 0)
        self.assertEqual(res["fn"], 1)
        self.assertEqual(res["tn"], 1)
        self.assertIsNone(res["precision"])
        self.assertIsNone(res["f1"])
        self.assertEqual(res["recall"], 0.0)

    def test_dedup_real_merge_still_scores_defined_precision(self):
        gt = {
            "findings": [
                {"id": 1, "title": "A"},
                {"id": 2, "title": "A-dup"},
                {"id": 3, "title": "B"},
            ],
            "ground_truth_clusters": {
                "c1": {"finding_ids": [1, 2], "relation": "DUPLICATE"},
                "c2": {"finding_ids": [3], "relation": "DISTINCT"},
            },
        }
        db = [
            {"title": "A", "status": "active"},
            {"title": "A-dup", "status": "duplicate_merged"},
            {"title": "B", "status": "active"},
        ]
        res = run_eval.score_dedup_partition(db, gt)
        self.assertEqual(res["tp"], 1)
        self.assertEqual(res["precision"], 1.0)
        self.assertEqual(res["recall"], 1.0)
        self.assertEqual(res["f1"], 1.0)


class TestStageAgentAlignment(unittest.TestCase):

    def test_reviewer_stage_agent_uses_production_prompt_guard_and_extended_schema(self):
        from core.config import ExtendedReviewVerdict
        from core.llm_gateway import UNTRUSTED_CODE_AUDIT_GUARD
        from core.prompts import get_stage_prompt
        from evals.stage_agents import build_stage_agent

        agent = build_stage_agent("reviewer", model_id="test-model", reasoning_effort="low")
        self.assertIs(agent.output_schema, ExtendedReviewVerdict)
        rendered = agent.instruction(None)
        self.assertIn(get_stage_prompt("reviewer", "mantis-review"), rendered)
        self.assertIn(UNTRUSTED_CODE_AUDIT_GUARD.strip(), rendered)
        self.assertIn("CRITICAL TERMINATION CONTRACT:", rendered)
        self.assertIn("PER-FINDING VERDICTS:", rendered)

    def test_patcher_stage_agent_uses_production_prompt_and_record_patch_tools(self):
        from core.prompts import get_stage_prompt
        from evals.stage_agents import build_stage_agent

        agent = build_stage_agent("patcher", model_id="test-model", reasoning_effort="low")
        tool_names = {getattr(t, "__name__", str(t)) for t in agent.tools}
        self.assertIn("record_patch", tool_names)
        self.assertIn("run_sandbox_with_evidence", tool_names)
        rendered = agent.instruction(None)
        self.assertIn(get_stage_prompt("patcher", "mantis-coder"), rendered)

    def test_stage_configs_toolsets_match_shipped_workflow(self):
        from evals.stage_agents import STAGE_CONFIGS

        wf = json.loads((Path(_REF_ROOT) / "workflow.json").read_text(encoding="utf-8"))
        wf_tools = {n["id"]: n["tools"] for n in wf["nodes"] if n.get("type") == "agent"}
        for stage, cfg in STAGE_CONFIGS.items():
            self.assertEqual(cfg["tools"], wf_tools[stage], f"tool drift on stage '{stage}'")


class TestEvalToolContextVisibility(unittest.IsolatedAsyncioTestCase):
    """Regression tests ensuring run_eval seeds findings under the active eval run_id and scope."""

    async def test_eval_calibrator_tools_see_and_update_seeded_findings(self):
        from tools.research_tools import calibrate_finding, get_findings

        async def _tool_driving_calibrator(runner_self, *args, **kwargs):
            raw = get_findings()
            self.assertNotIn("NO_DATA:", raw)
            # Extract JSON array inside untrusted fence
            start = raw.find("[")
            end = raw.rfind("]")
            rows = json.loads(raw[start : end + 1])
            self.assertEqual(len(rows), 3)
            for row in rows:
                out = calibrate_finding(
                    finding_id=row["id"],
                    mantis_risk_score=9.5,
                    impact_score=5,
                    likelihood_score=5,
                    priority="CRITICAL",
                )
                self.assertIn("SUCCESS:", out)
            yield _event("done")

        with patch.object(run_eval.Runner, "run_async", _tool_driving_calibrator):
            res = await run_eval.eval_calibrator("test-model", "low", _CALIBRATE_DS)
        self.assertEqual(res["errors"], 0)
        self.assertEqual(res["unscored"], 0)
        self.assertIsNotNone(res["mae"])

    async def test_eval_deduplicator_tools_see_and_merge_seeded_findings(self):
        from tools.research_tools import dedupe_findings, get_findings

        syn_ds = _EVALS_DIR / "synthetic_dataset.json"

        async def _tool_driving_deduper(runner_self, *args, **kwargs):
            raw = get_findings()
            self.assertNotIn("NO_DATA:", raw)
            start = raw.find("[")
            end = raw.rfind("]")
            rows = json.loads(raw[start : end + 1])
            self.assertGreaterEqual(len(rows), 2)
            out = dedupe_findings(
                primary_title=rows[0]["title"],
                duplicate_titles=[rows[1]["title"]],
                reason="same root cause",
            )
            self.assertIn("Deduplicated 1 finding", out)
            yield _event("done")

        with patch.object(run_eval.Runner, "run_async", _tool_driving_deduper):
            res = await run_eval.eval_deduplicator("test-model", "low", syn_ds)
        self.assertEqual(res["schema_errors"], 0)
        self.assertGreaterEqual(res["tp"], 1)

    async def test_eval_reviewer_isolates_per_case_findings_and_parses_compact_json(self):
        from tools.research_tools import get_findings

        routes = _title_routes(_REVIEW_DS)

        async def _case_checking_reviewer(runner_self, *args, **kwargs):
            raw = get_findings()
            self.assertNotIn("NO_DATA:", raw)
            start = raw.find("[")
            end = raw.rfind("]")
            rows = json.loads(raw[start : end + 1])
            self.assertEqual(len(rows), 1, "each reviewer eval case must see only its own finding")
            route = routes[rows[0]["title"]]
            yield _event(f'{{"route":"{route}","reason":"ok"}}')

        with patch.object(run_eval.Runner, "run_async", _case_checking_reviewer):
            res = await run_eval.eval_reviewer("test-model", "low", _REVIEW_DS)
        self.assertEqual(res["tp"], 2)
        self.assertEqual(res["tn"], 4)
        self.assertEqual(res["no_verdict"], 0)


if __name__ == "__main__":
    unittest.main()

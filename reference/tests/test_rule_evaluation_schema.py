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
"""Rule evaluations accepted by core/schemas.py and schema.json agree."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

import jsonschema
from pydantic import ValidationError

from core.schemas import CalibrationRuleEvaluationSchema, TriageRuleEvaluationSchema

_DEFS = json.loads((_REF_ROOT.parent / "schema.json").read_text(encoding="utf-8"))["$defs"]


class RuleEvaluationSchemaTest(unittest.TestCase):
    def test_either_form_is_accepted_and_stays_valid_json(self):
        cases = (
            (TriageRuleEvaluationSchema, "triage_rule_evaluation", {"outcome": "PASS"}),
            (TriageRuleEvaluationSchema, "triage_rule_evaluation", {"passes": True}),
            (CalibrationRuleEvaluationSchema, "calibration_rule_evaluation", {"outcome": "DOES_NOT_APPLY"}),
            (CalibrationRuleEvaluationSchema, "calibration_rule_evaluation", {"fires": False}),
        )
        for model, name, data in cases:
            with self.subTest(name=name, data=data):
                dumped = model.model_validate(data).model_dump()
                jsonschema.validate(dumped, {"$ref": f"#/$defs/{name}", "$defs": _DEFS})

    def test_a_verdict_is_still_required(self):
        for model in (TriageRuleEvaluationSchema, CalibrationRuleEvaluationSchema):
            with self.subTest(model=model.__name__), self.assertRaises(ValidationError):
                model.model_validate({"reason": "x"})


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""
Mantis Dynamic Schema Code Generator
Parses schema.json ($defs, properties, types, enums, required fields, and constraints)
and dynamically generates reference/core/schemas.py with strongly-typed Pydantic V2 models.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Set

SCHEMA_JSON_PATH = Path(__file__).resolve().parent.parent.parent / "schema.json"
TARGET_OUTPUT_PATH = Path(__file__).resolve().parent.parent / "core" / "schemas.py"


def schema_name_to_class_name(name: str) -> str:
    """Converts a schema def name (e.g. 'finding', 'learning_entry') to PascalCase 'FindingSchema'."""
    parts = name.replace("-", "_").split("_")
    return "".join(p.capitalize() for p in parts) + "Schema"


def resolve_type_annotation(prop_name: str, prop: Dict[str, Any], defs: Dict[str, Any]) -> str:
    """Translates a JSON Schema property object dynamically into a Python type annotation."""
    if "$ref" in prop:
        ref_key = prop["$ref"].split("/")[-1]
        if ref_key == "uuid":
            return "str"
        if ref_key == "calibration_outcome":
            return "Literal['APPLIES', 'DOES_NOT_APPLY', 'UNKNOWN']"
        return schema_name_to_class_name(ref_key)

    if "enum" in prop:
        raw_vals = [v for v in prop["enum"] if v is not None and v != "null"]
        if prop_name == "severity":
            enum_vals = sorted(list(set(v.upper() for v in raw_vals)))
        else:
            enum_vals = raw_vals
        literals = ", ".join(f'"{v}"' for v in enum_vals)
        return f"Literal[{literals}]" if literals else "str"

    prop_type = prop.get("type")
    if isinstance(prop_type, list):
        non_null = [t for t in prop_type if t != "null"]
        if len(non_null) == 1:
            prop_type = non_null[0]
        else:
            resolved_types = [resolve_type_annotation(prop_name, {"type": t}, defs) for t in non_null]
            return f"Union[{', '.join(resolved_types)}]"

    if prop_type == "string":
        return "str"
    elif prop_type == "integer":
        return "int"
    elif prop_type == "number":
        return "float"
    elif prop_type == "boolean":
        return "bool"
    elif prop_type == "array":
        items = prop.get("items", {})
        if items:
            item_type = resolve_type_annotation(f"{prop_name}_item", items, defs)
            return f"List[{item_type}]"
        return "List[Any]"
    elif prop_type == "object":
        return "Dict[str, Any]"
    elif "oneOf" in prop or "anyOf" in prop:
        variants = prop.get("oneOf") or prop.get("anyOf", [])
        types = [resolve_type_annotation(prop_name, v, defs) for v in variants]
        return f"Union[{', '.join(types)}]"

    return "Any"


def extract_all_properties(def_schema: Dict[str, Any]) -> tuple[Dict[str, Any], Set[str]]:
    """Extracts properties and required fields across direct properties, oneOf, anyOf, and allOf variants."""
    properties = dict(def_schema.get("properties", {}))
    required_fields = set(def_schema.get("required", []))

    for key in ("oneOf", "anyOf", "allOf"):
        if key in def_schema:
            for variant in def_schema[key]:
                if isinstance(variant, dict):
                    v_props = variant.get("properties", {})
                    for pk, pv in v_props.items():
                        if pk not in properties:
                            properties[pk] = pv
                    for req in variant.get("required", []):
                        required_fields.add(req)

    return properties, required_fields


def generate_class_from_def(name: str, def_schema: Dict[str, Any], defs: Dict[str, Any]) -> List[str]:
    """Dynamically converts a single $defs entry from schema.json into a Pydantic V2 model."""
    class_name = schema_name_to_class_name(name)
    raw_doc = def_schema.get("description") or def_schema.get("title") or f"Schema for {name}"
    docstring_clean = raw_doc.split("\n")[0][:100].replace('\\', '\\\\').replace('"', '\\"')

    allow_extra = def_schema.get("additionalProperties", True)
    extra_mode = "allow" if allow_extra else "forbid"

    lines = [
        f"class {class_name}(BaseModel):",
        f'    """{docstring_clean}"""',
        f'    model_config = ConfigDict(extra="{extra_mode}")',
    ]

    properties, required_fields = extract_all_properties(def_schema)

    for prop_name, prop_def in properties.items():
        py_type = resolve_type_annotation(prop_name, prop_def, defs)
        is_required = prop_name in required_fields and name not in ("learning_entry", "finding")
        field_args = []

        # Aliases and Python reserved keyword handling
        if prop_name == "pass":
            field_name = "pass_num"
            field_args.append("validation_alias=AliasChoices('pass', 'pass_num')")
        elif prop_name == "pass_number":
            field_name = "pass_number"
            field_args.append("validation_alias=AliasChoices('pass', 'pass_number')")
        elif prop_name == "mitigation":
            field_name = "mitigation"
            field_args.append("validation_alias=AliasChoices('mitigation', 'remediation')")
        elif prop_name == "learning":
            field_name = "learning"
            field_args.append("validation_alias=AliasChoices('learning', 'insight')")
        elif prop_name == "insight":
            field_name = "insight"
            field_args.append("validation_alias=AliasChoices('insight', 'learning')")
        else:
            field_name = prop_name

        # Documentation description
        if "description" in prop_def:
            desc_short = prop_def["description"].split("\n")[0].replace('"', '\\"')[:80]
            field_args.append(f'description="{desc_short}"')

        # Constraints
        if "minLength" in prop_def:
            field_args.append(f"min_length={prop_def['minLength']}")
        if "maxLength" in prop_def:
            field_args.append(f"max_length={prop_def['maxLength']}")

        # Defaults
        if not is_required:
            if py_type.startswith("List"):
                field_args.insert(0, "default_factory=list")
                py_type = f"Optional[{py_type}]"
            elif py_type == "str":
                field_args.insert(0, 'default=""')
                py_type = "Optional[str]"
            elif py_type == "int":
                field_args.insert(0, "default=None")
                py_type = "Optional[int]"
            elif py_type == "bool":
                field_args.insert(0, "default=False")
                py_type = "Optional[bool]"
            elif py_type == "Dict[str, Any]":
                field_args.insert(0, "default=None")
                py_type = "Optional[Dict[str, Any]]"
            else:
                field_args.insert(0, "default=None")
                py_type = f"Optional[{py_type}]"

        args_str = ", ".join(field_args)
        lines.append(f"    {field_name}: {py_type} = Field({args_str})")

    # Ensure canonical tool integration fields exist on finding
    if name == "finding":
        if "filepath" not in properties:
            lines.append("    filepath: Optional[str] = Field(default=None, description=\"Relative file path where flaw is located\")")
        if "remediation" not in properties:
            lines.append("    remediation: Optional[str] = Field(default='', validation_alias=AliasChoices('remediation', 'mitigation'), description=\"Fix instructions\")")
        if "line_numbers" not in properties:
            lines.append("    line_numbers: Optional[List[int]] = Field(default=None, description=\"Line numbers where flaw occurs\")")
        if "score" not in properties:
            lines.append("    score: Optional[int] = Field(default=None, description=\"Calibrated risk score (0-100)\")")
        if "reasoning" not in properties:
            lines.append("    reasoning: Optional[str] = Field(default=None, description=\"Justification for score or verdict\")")

        # Validator for uppercase severity
        lines.extend([
            "",
            "    @field_validator('severity', mode='before')",
            "    @classmethod",
            "    def normalize_severity(cls, v: Any) -> str:",
            "        if isinstance(v, str):",
            "            return v.upper()",
            "        return v",
        ])

    # Ensure canonical tool integration fields exist on learning_entry
    if name == "learning_entry":
        if "category" not in properties:
            lines.append('    category: Optional[str] = Field(default="", description="Category of learning.")')
        if "learning" not in properties:
            lines.append("    learning: Optional[str] = Field(default=None, validation_alias=AliasChoices('learning', 'insight'), description=\"Concrete lesson learned.\")")
        if "tags" not in properties:
            lines.append('    tags: Optional[List[str]] = Field(default_factory=list, description="Keywords and tags for indexing.")')

    # Ensure loop_pass & max_passes exist on state
    if name == "state":
        if "loop_pass" not in properties:
            lines.append('    loop_pass: Optional[int] = Field(default=None, description="The current pass number in the campaign loop (starts at 1).")')
        if "max_passes" not in properties:
            lines.append('    max_passes: Optional[int] = Field(default=None, description="The maximum number of passes allowed before the orchestrator halts.")')

    lines.append("")
    return lines


def generate_pydantic_code(schema_data: Dict[str, Any]) -> str:
    """Reads schema_data ($defs) from schema.json and dynamically builds Python Pydantic code."""
    defs = schema_data.get("$defs", {})

    code_lines = [
        '"""',
        "# AUTO-GENERATED DYNAMICALLY FROM schema.json - DO NOT EDIT DIRECTLY.",
        "# To regenerate, run: python3 reference/scripts/generate_schemas.py",
        '"""',
        "",
        "from __future__ import annotations",
        "from typing import Any, Dict, List, Literal, Optional, Union",
        "from pydantic import BaseModel, Field, ConfigDict, AliasChoices, field_validator",
        "",
        "# ---------------------------------------------------------------------------",
        "# Canonical Models (Generated Dynamically by Inspecting schema.json $defs)",
        "# ---------------------------------------------------------------------------",
        "",
    ]

    # Order of definition to ensure proper dependency resolution
    def_order = [
        "history_entry",
        "triage_rule_evaluation",
        "triage_checklist",
        "calibration_rule_evaluation",
        "calibration_checklist",
        "finding",
        "learning_entry",
        "state",
        "tx_log_entry",
        "execution_log_entry",
    ]

    for def_key in def_order:
        if def_key in defs:
            code_lines.extend(generate_class_from_def(def_key, defs[def_key], defs))

    # Dynamic schema evolution: iterate over any additional definitions in $defs
    for def_key, def_val in defs.items():
        if def_key not in def_order and def_key not in ("plan", "uuid", "calibration_outcome", "repro_attempts") and isinstance(def_val, dict):
            code_lines.extend(generate_class_from_def(def_key, def_val, defs))

    # Generate InvestigationTargetSchema & PlanSchema from $defs/plan
    plan_def = defs.get("plan", {})
    inv_def = plan_def.get("properties", {}).get("investigations", {}).get("items", {})
    if inv_def or "plan" in defs:
        code_lines.extend([
            "class InvestigationTargetSchema(BaseModel):",
            '    """Targeted audit focus within a review plan (from schema.json #/$defs/plan)."""',
            '    model_config = ConfigDict(extra="allow")',
            "    title: str = Field(description='Title of planned investigation')",
            "    target_files: List[str] = Field(description='Files targeted for review')",
            "    focus_areas: Optional[List[str]] = Field(default_factory=list, description='Security focus areas')",
            "    kb_references: Optional[List[str]] = Field(default_factory=list, description='KB documentation files')",
            "    question: Optional[str] = Field(default='', description='Prompting question for researcher')",
            "",
            "class PlanSchema(BaseModel):",
            '    """Strategic campaign plan (from schema.json #/$defs/plan)."""',
            '    model_config = ConfigDict(extra="allow")',
            "    pass_number: Optional[int] = Field(default=1, validation_alias=AliasChoices('pass', 'pass_number'))",
            "    investigations: List[InvestigationTargetSchema] = Field(description='Targeted investigations')",
            "    focus_areas: Optional[List[str]] = Field(default_factory=list, description='Focus areas')",
            "    rationale: Optional[str] = Field(default='', description='Strategic rationale')",
            "",
        ])

    # Canonical Aliases
    code_lines.extend([
        "# ---------------------------------------------------------------------------",
        "# Canonical Type Aliases (Connecting Pipeline Tools to Canonical Schemas)",
        "# ---------------------------------------------------------------------------",
        "",
        "VulnerabilityFinding = FindingSchema",
        "InvestigationTarget = InvestigationTargetSchema",
        "ReviewPlan = PlanSchema",
        "LearningEntry = LearningEntrySchema",
        "",
        "# ---------------------------------------------------------------------------",
        "# Workflow Verdicts, Reporting & Domain Tool Schemas",
        "# ---------------------------------------------------------------------------",
        "",
        "class VulnerabilityReport(BaseModel):",
        '    """Structured report returned by the researcher stage containing canonical FindingSchema objects."""',
        '    model_config = ConfigDict(extra="forbid")',
        "    findings: List[FindingSchema] = Field(",
        "        default_factory=list,",
        "        validation_alias=AliasChoices('findings', 'vulnerabilities'),",
        "        description='A list of all vulnerabilities found in the target. Empty if none found.'",
        "    )",
        "",
        "class ReviewVerdict(BaseModel):",
        '    """Structured verdict for reviewer classifier routing."""',
        '    model_config = ConfigDict(extra="forbid")',
        "    route: Literal['confirmed', 'false_positive']",
        "    reason: str = Field(description='One sentence justifying the verdict.')",
        "",
        "class CriticVerdict(BaseModel):",
        '    """Structured verdict for critic classifier routing."""',
        '    model_config = ConfigDict(extra="forbid")',
        "    route: Literal['viable', 'non_viable']",
        "    reason: str = Field(description='One sentence justifying the exploit viability verdict.')",
        "",
        "class ReproVerdict(BaseModel):",
        '    """Structured verdict for reproducer classifier routing."""',
        '    model_config = ConfigDict(extra="ignore")',
        "    route: Literal['success', 'failed_repro']",
        "    reason: str = Field(description='One sentence describing what was executed and observed.')",
        "",
        "class ThreatModel(BaseModel):",
        '    """Threat model artifact from /mantis-threat-model."""',
        '    model_config = ConfigDict(extra="ignore")',
        "    threat_actors: List[str] = Field(default_factory=list, description='Identified adversary profiles and positions')",
        "    trust_boundaries: List[str] = Field(default_factory=list, description='System boundaries where untrusted input enters')",
        "    entry_points: List[str] = Field(default_factory=list, description='Public or internal endpoints exposed to input')",
        "    key_risks: List[str] = Field(default_factory=list, description='Primary business or security risks identified')",
        "",
        "class CodebaseSummary(BaseModel):",
        '    """Codebase summary from /mantis-summarize."""',
        '    model_config = ConfigDict(extra="ignore")',
        '    overview: str = Field(default="", description=\'Executive summary of the codebase purpose and architecture\', validation_alias=AliasChoices(\'overview\', \'summary\', \'description\'))',
        "    key_modules: List[Union[str, Dict[str, Any]]] = Field(default_factory=list, description='Core system components and directories')",
        "    tech_stack: List[str] = Field(default_factory=list, description='Languages, frameworks, and database dependencies')",
        "",
        "class ExploitChain(BaseModel):",
        '    """Multi-stage exploit chain from /mantis-chain."""',
        '    model_config = ConfigDict(extra="ignore")',
        "    chain_title: str = Field(description='Descriptive title of the composite attack chain')",
        "    finding_titles: List[str] = Field(description='Titles or IDs of the chained findings')",
        "    attack_path: str = Field(description='Step-by-step progression of the chained exploit')",
        "    combined_impact: str = Field(description='Composite impact achieved through the chain')",
        "",
        "class ExecutiveReport(BaseModel):",
        '    """Final executive review packet compiled by /mantis-report."""',
        '    model_config = ConfigDict(extra="ignore")',
        "    executive_summary: str = Field(description='High level executive summary of findings and risk posture')",
        "    critical_findings_count: int = Field(default=0, description='Total critical findings recorded')",
        "    recommendations: List[str] = Field(default_factory=list, description='Prioritized remediation actions')",
        "",
        "# Schema.json helper registry",
        "SCHEMA_DEFINITIONS = {",
        "    'finding': FindingSchema,",
        "    'plan': PlanSchema,",
        "    'learning_entry': LearningEntrySchema,",
        "    'state': StateSchema,",
        "    'triage_checklist': TriageChecklistSchema,",
        "    'calibration_checklist': CalibrationChecklistSchema,",
        "}",
        "",
    ])

    return "\n".join(code_lines)


def main():
    if not SCHEMA_JSON_PATH.exists():
        raise FileNotFoundError(f"schema.json not found at {SCHEMA_JSON_PATH}")

    with open(SCHEMA_JSON_PATH, "r", encoding="utf-8") as f:
        schema_data = json.load(f)

    generated_code = generate_pydantic_code(schema_data)

    TARGET_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(TARGET_OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(generated_code)

    print(f"✅ Generated {TARGET_OUTPUT_PATH} from {SCHEMA_JSON_PATH}")


if __name__ == "__main__":
    main()

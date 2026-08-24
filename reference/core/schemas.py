"""
# AUTO-GENERATED DYNAMICALLY FROM schema.json - DO NOT EDIT DIRECTLY.
# To regenerate, run: python3 reference/scripts/generate_schemas.py
"""

from __future__ import annotations
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, Field, ConfigDict, AliasChoices, field_validator

# ---------------------------------------------------------------------------
# Canonical Models (Generated Dynamically by Inspecting schema.json $defs)
# ---------------------------------------------------------------------------

class HistoryEntrySchema(BaseModel):
    """History Entry Schema"""
    model_config = ConfigDict(extra="allow")
    stage: str = Field()
    action: str = Field()
    details: str = Field()
    pass_number: int = Field(validation_alias=AliasChoices('pass', 'pass_number'), description="The sequential pass number of the pipeline loop.")
    timestamp: str = Field(description="ISO 8601 timestamp of when the history entry was recorded.")
    snapshot: Optional[str] = Field(default="", description="The SNAPSHOT_ID (SNAPSHOT_ID ladder, top-level description) this history action ")

class TriageRuleEvaluationSchema(BaseModel):
    """Schema for triage_rule_evaluation"""
    model_config = ConfigDict(extra="forbid")
    passes: bool = Field(description="DEPRECATED: True if the finding satisfies this validity constraint.")
    outcome: Literal["PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"] = Field(description="The evaluation outcome of the constraint.")
    reason: Optional[str] = Field(default="", description="The reasoning for the evaluation.")

class TriageChecklistSchema(BaseModel):
    """Triage Checklist (13 Negative Constraints)"""
    model_config = ConfigDict(extra="forbid")
    ignore_hypothetical_misuse: TriageRuleEvaluationSchema = Field()
    ignore_missing_hygiene: TriageRuleEvaluationSchema = Field()
    require_strict_reproducibility: TriageRuleEvaluationSchema = Field()
    avoid_pedantic_linting: TriageRuleEvaluationSchema = Field()
    no_security_flaw_stretching: TriageRuleEvaluationSchema = Field()
    evaluate_questionable_file_paths: TriageRuleEvaluationSchema = Field()
    ignore_resource_exhaustion_dos: TriageRuleEvaluationSchema = Field()
    intrinsic_security_flaws: TriageRuleEvaluationSchema = Field()
    verify_mitigations_pragmatically: TriageRuleEvaluationSchema = Field()
    refine_code_paths_strictly: TriageRuleEvaluationSchema = Field()
    ignore_simd_vector_padding: TriageRuleEvaluationSchema = Field()
    ensure_source_code_coherence: TriageRuleEvaluationSchema = Field()
    verify_attacker_control_of_source: TriageRuleEvaluationSchema = Field()

class CalibrationRuleEvaluationSchema(BaseModel):
    """Schema for calibration_rule_evaluation"""
    model_config = ConfigDict(extra="forbid")
    fires: bool = Field(description="DEPRECATED: True if this sanity cap rule applies (fires) to this finding.")
    outcome: Literal['APPLIES', 'DOES_NOT_APPLY', 'UNKNOWN'] = Field()
    reason: Optional[str] = Field(default="")

class CalibrationChecklistSchema(BaseModel):
    """Calibration Checklist (Sanity Caps)"""
    model_config = ConfigDict(extra="forbid")
    repro_failure: CalibrationRuleEvaluationSchema = Field()
    unreachable_inputs: CalibrationRuleEvaluationSchema = Field()
    third_party_reachability: CalibrationRuleEvaluationSchema = Field()
    minor_config_hygiene: CalibrationRuleEvaluationSchema = Field()
    non_security_critical: CalibrationRuleEvaluationSchema = Field()
    vague_code_paths: CalibrationRuleEvaluationSchema = Field()
    unreliable_triggers: CalibrationRuleEvaluationSchema = Field()
    prerequisite_shell: CalibrationRuleEvaluationSchema = Field()
    physical_long_term: CalibrationRuleEvaluationSchema = Field()
    trusted_controller_zero_delta: CalibrationRuleEvaluationSchema = Field()
    standard_host_attacks: CalibrationRuleEvaluationSchema = Field()
    static_confirmation: CalibrationRuleEvaluationSchema = Field()
    strict_xss: CalibrationRuleEvaluationSchema = Field()
    internal_nested: CalibrationRuleEvaluationSchema = Field()
    probabilistic_llm: CalibrationRuleEvaluationSchema = Field()
    supply_chain_prerequisites: CalibrationRuleEvaluationSchema = Field()
    non_default_config: CalibrationRuleEvaluationSchema = Field()
    confidential_computing_host: CalibrationRuleEvaluationSchema = Field()
    trusted_controller_critical_bypass: CalibrationRuleEvaluationSchema = Field()
    local_attack_vector: CalibrationRuleEvaluationSchema = Field()
    self_contained_blast: CalibrationRuleEvaluationSchema = Field()
    rarely_exposed: CalibrationRuleEvaluationSchema = Field()
    equivalent_primitives: CalibrationRuleEvaluationSchema = Field()
    documented_insecure_config: CalibrationRuleEvaluationSchema = Field()
    physical_temporary: CalibrationRuleEvaluationSchema = Field()
    high_privilege_external: CalibrationRuleEvaluationSchema = Field()
    trusted_controller_standard_bypass: CalibrationRuleEvaluationSchema = Field()

class FindingSchema(BaseModel):
    """The finding object (workspace/findings/<uuid>.json) is the core state unit for a discovered vulnerab"""
    model_config = ConfigDict(extra="allow")
    id: Optional[str] = Field(default="", description="Unique identifier matching the filename.")
    title: Optional[str] = Field(default="", description="A concise summary of the vulnerability. For exploit chains, must explicitly cont")
    description: Optional[str] = Field(default="", description="Detailed explanation of the flaw and its mechanism.")
    code_paths: Optional[List[str]] = Field(default_factory=list, description="Exact locations of the flaw (e.g., 'src/auth.c:145'). For exploit chains, the un")
    impact: Optional[str] = Field(default="", description="The potential consequence of the vulnerability.")
    severity: Optional[Literal["CRITICAL", "HIGH", "LOW", "MEDIUM"]] = Field(default=None, description="Initial severity estimate.")
    privileges_required: Optional[Literal["NONE", "LOW", "HIGH"]] = Field(default=None, description="Privilege level needed to exploit.")
    attacker_position: Optional[Literal["EXTERNAL", "INTERNAL_NETWORK", "IN_CLUSTER", "LOCAL", "HOST_SYSTEM", "SUPPLY_CHAIN", "PHYSICAL_TEMPORARY", "PHYSICAL_LONG_TERM"]] = Field(default=None, description="The starting position of the attacker required to exploit.")
    user_interaction: Optional[Literal["NONE", "REQUIRED"]] = Field(default=None, description="Whether user interaction is required.")
    mitigation: Optional[str] = Field(default="", validation_alias=AliasChoices('mitigation', 'remediation'), description="Recommended corrective modification.")
    history: Optional[List[HistoryEntrySchema]] = Field(default_factory=list, description="Chronological log of actions taken on this finding. For exploit chains, must inc")
    status: Optional[Literal["VALID", "FALSE_POSITIVE", "PROVISIONALLY_VALID", "NEEDS_RESEARCH", "DUPLICATE"]] = Field(default=None, description="The validity of the finding.")
    duplicate_of: Optional[str] = Field(default="", description="If status is DUPLICATE, the UUID of the primary finding this is a duplicate of.")
    reasoning: Optional[str] = Field(default="", description="The reviewer's independent rationale for the status.")
    repro_hints: Optional[str] = Field(default="", description="Instructions for triggering the bug, reached-sink evidence channels, and executi")
    production_viability: Optional[Literal["VIABLE", "NON_VIABLE", "SAMPLE_OR_TEST", "CONDITIONAL_VIABLE"]] = Field(default=None, description="Whether the bug is triggerable in a release build.")
    critic_reasoning: Optional[str] = Field(default="", description="Rationale for viability (e.g., 'Not protected by allocator padding').")
    repro_status: Optional[Literal["reproduced", "statically_confirmed", "not_attempted", "failed_to_reproduce"]] = Field(default=None, description="The outcome of the reproduction attempt. Enum is UNCHANGED. Reached-Sink Evidenc")
    repro_file_path: Optional[str] = Field(default="", description="Path to the generated PoC script or payload.")
    run_command: Optional[str] = Field(default="", description="The exact command used to execute the PoC.")
    repro_output: Optional[str] = Field(default="", description="Standard output and error from the sandbox run.")
    patch_status: Optional[Literal["VERIFIED_SECURE", "MITIGATION_PROPOSED", "VERIFICATION_INCOMPLETE", "VERIFICATION_FAILED", "ERROR"]] = Field(default=None, description="The outcome of the patching and re-attack attempts.")
    patch_diff: Optional[str] = Field(default="", description="The unified diff of the verified fix, or mitigation recommendation.")
    reattack_status: Optional[Literal["bypassed_patch", "failed_to_bypass", "inconclusive_baseline_changed"]] = Field(default=None, description="The outcome of the variant-hunting re-attack. `failed_to_bypass` requires a non-")
    reattack_file_path: Optional[str] = Field(default="", description="Path to the newly generated re-attack script.")
    reattack_run_command: Optional[str] = Field(default="", description="The exact execution command used for the re-attack.")
    reattack_output: Optional[str] = Field(default="", description="Standard output and error from the re-attack run.")
    reattack_variants: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="Variant inputs attempted during the variant-hunting re-attack. Each entry record")
    impact_score: Optional[int] = Field(default=None, description="Calculated technical impact (1-5) on CIA triad.")
    likelihood_score: Optional[int] = Field(default=None, description="Probability of occurrence (1-5) based on proven exploitability.")
    availability_tier: Optional[Literal["CRITICAL", "STANDARD", "LOW_CRITICALITY"]] = Field(default=None, description="Availability criticality of the component if availability impact exists.")
    inferred_exposure: Optional[Literal["EXPOSED", "INTERNAL", "PRIVILEGED"]] = Field(default=None, description="Resolved network/trust exposure tier based on threat model.")
    mantis_risk_score: Optional[float] = Field(default=None, description="Final calculated risk score (Hazard = (Impact + Likelihood) * Multiplier).")
    priority: Optional[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]] = Field(default=None, description="Qualitative priority bucket.")
    sanity_triage_applied: Optional[str] = Field(default="", description="Semicolon-separated list of sanity triage caps and downgrades that fired.")
    triage_checklist: Optional[TriageChecklistSchema] = Field(default=None)
    calibration_checklist: Optional[CalibrationChecklistSchema] = Field(default=None)
    outrage_commentary: Optional[str] = Field(default="", description="Reasoning about the outrage factor (Risk = Hazard + Outrage).")
    executive_summary: Optional[str] = Field(default="", description="High-level summary of the risk for stakeholders.")
    constituent_findings: Optional[List[str]] = Field(default_factory=list, description="Array of finding UUIDs that constitute this exploit chain finding.")
    discovery_commit: Optional[str] = Field(default="", description="The SNAPSHOT_ID (see the SNAPSHOT_ID ladder in the top-level description) of the")
    repro_snapshot_id: Optional[str] = Field(default="", description="The SNAPSHOT_ID the reproduction attempt (repro_status / repro_file_path / repro")
    reattack_snapshot_id: Optional[str] = Field(default="", description="The SNAPSHOT_ID the re-attack (reattack_status / reattack_output) was executed a")
    patch_base_snapshot: Optional[str] = Field(default="", description="The SNAPSHOT_ID of the snapshot the patch_diff was generated and verified agains")
    possible_duplicate_of: Optional[str] = Field(default="", description="UUID of a finding this one MIGHT duplicate but which could NOT be confirmed as a")
    cwe: Optional[str] = Field(default="", description="CWE identifier for this vulnerability (e.g. 'CWE-787'). Optional and backward-co")
    signature: Optional[str] = Field(default="", description="Deterministic stable signature of this finding's content identity, computed once")
    lineage_id: Optional[str] = Field(default="", description="Lineage identifier linking findings that represent the same underlying bug acros")
    sast_provenance: Optional[Dict[str, Any]] = Field(default=None, description="Provenance metadata for findings seeded by external SAST tools via the SAST seed")
    filepath: Optional[str] = Field(default=None, description="Relative file path where flaw is located")
    remediation: Optional[str] = Field(default='', validation_alias=AliasChoices('remediation', 'mitigation'), description="Fix instructions")
    line_numbers: Optional[List[int]] = Field(default=None, description="Line numbers where flaw occurs")
    score: Optional[int] = Field(default=None, description="Calibrated risk score (0-100)")

    @field_validator('severity', mode='before')
    @classmethod
    def normalize_severity(cls, v: Any) -> str:
        if isinstance(v, str):
            return v.upper()
        return v

class LearningEntrySchema(BaseModel):
    """Schema for a single JSON line in workspace/learnings.jsonl (ephemeral inbox) or workspace/historical"""
    model_config = ConfigDict(extra="allow")
    type: Optional[Literal["trajectory_insight"]] = Field(default=None)
    action: Optional[Literal["add", "update", "remove"]] = Field(default=None)
    target_entity: Optional[str] = Field(default="", description="Target component or file (e.g., 'auth_module.py').")
    insight: Optional[str] = Field(default="", validation_alias=AliasChoices('insight', 'learning'), description="Description of the insight.")
    source_stage: Optional[str] = Field(default="", description="Stage that produced the insight.")
    snapshot: Optional[str] = Field(default="", description="The SNAPSHOT_ID (SNAPSHOT_ID ladder) this insight was observed against; stamped ")
    title: Optional[str] = Field(default="", description="Finding title.")
    code_paths: Optional[List[str]] = Field(default_factory=list)
    status: Optional[Literal["VIABLE", "NON_VIABLE", "SAMPLE_OR_TEST", "CONDITIONAL_VIABLE", "FALSE_POSITIVE", "NEEDS_RESEARCH", "VERIFIED_SECURE", "MITIGATION_PROPOSED", "VERIFICATION_INCOMPLETE", "VERIFICATION_FAILED", "ERROR"]] = Field(default=None)
    patch_base_snapshot: Optional[str] = Field(default="", description="The SNAPSHOT_ID the patch was verified against; written by mantis-patch (or omit")
    revision_id: Optional[str] = Field(default="")
    description: Optional[str] = Field(default="")
    vuln_type: Optional[str] = Field(default="")
    mitigation_diff: Optional[str] = Field(default="")
    cve: Optional[str] = Field(default="")
    history: Optional[List[HistoryEntrySchema]] = Field(default_factory=list)
    category: Optional[str] = Field(default="", description="Category of learning.")
    learning: Optional[str] = Field(default=None, validation_alias=AliasChoices('learning', 'insight'), description="Concrete lesson learned.")
    tags: Optional[List[str]] = Field(default_factory=list, description="Keywords and tags for indexing.")

class StateSchema(BaseModel):
    """The mantis state file (workspace/.mantis_state.json) tracks the loop context across rounds."""
    model_config = ConfigDict(extra="allow")
    pass_number: int = Field(validation_alias=AliasChoices('pass', 'pass_number'), description="The current sequential pass number of the pipeline.")
    last_updated: str = Field(description="ISO 8601 timestamp of when the state was last updated.")
    vcs_info: Optional[Dict[str, Any]] = Field(default=None, description="Information about the target version control system state.")
    active_snapshot: Optional[Dict[str, Any]] = Field(default=None, description="The immutable pinned snapshot the CURRENT pass reads through. Written by the orc")
    snapshot_history: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="APPEND-ONLY log of one entry per pinned pass, in pass order. The orchestrator ap")
    kb_snapshot_id: Optional[str] = Field(default="", description="The SNAPSHOT_ID the knowledge base (workspace/kb: architecture, threat model, su")
    changed_files: Optional[List[str]] = Field(default_factory=list, description="Efficiency HINT only: repo-relative paths that changed between the previous pinn")
    changed_files_status: Optional[Literal["COMPUTED", "UNKNOWN"]] = Field(default=None, description="Whether changed_files is a trustworthy diff (COMPUTED) or could not be computed ")
    changed_files_pass: Optional[int] = Field(default=None, description="The pass_number when changed_files/changed_files_status were last computed. Cons")
    loop_pass: Optional[int] = Field(default=None, description="The current pass number in the campaign loop (starts at 1).")
    max_passes: Optional[int] = Field(default=None, description="The maximum number of passes allowed before the orchestrator halts.")

class TxLogEntrySchema(BaseModel):
    """Deduplicator Transaction Log Entry Schema"""
    model_config = ConfigDict(extra="allow")
    timestamp: str = Field()
    action: str = Field()
    primary_uuid: Union[str, Any] = Field(description="The UUID of the primary finding, or null if the action is loop_filter.")
    moved_uuid: str = Field()

class ExecutionLogEntrySchema(BaseModel):
    """Execution Log Entry Schema"""
    model_config = ConfigDict(extra="allow")
    step_index: int = Field()
    source: str = Field()
    type: str = Field()
    status: str = Field()
    created_at: Optional[str] = Field(default="")
    thinking: Optional[str] = Field(default="")
    content: Optional[str] = Field(default="")
    tool_calls: Optional[List[Dict[str, Any]]] = Field(default_factory=list)

class InvestigationTargetSchema(BaseModel):
    """Targeted audit focus within a review plan (from schema.json #/$defs/plan)."""
    model_config = ConfigDict(extra="allow")
    title: str = Field(description='Title of planned investigation')
    target_files: List[str] = Field(description='Files targeted for review')
    focus_areas: Optional[List[str]] = Field(default_factory=list, description='Security focus areas')
    kb_references: Optional[List[str]] = Field(default_factory=list, description='KB documentation files')
    question: Optional[str] = Field(default='', description='Prompting question for researcher')

class PlanSchema(BaseModel):
    """Strategic campaign plan (from schema.json #/$defs/plan)."""
    model_config = ConfigDict(extra="allow")
    pass_number: Optional[int] = Field(default=1, validation_alias=AliasChoices('pass', 'pass_number'))
    investigations: List[InvestigationTargetSchema] = Field(description='Targeted investigations')
    focus_areas: Optional[List[str]] = Field(default_factory=list, description='Focus areas')
    rationale: Optional[str] = Field(default='', description='Strategic rationale')

# ---------------------------------------------------------------------------
# Canonical Type Aliases (Connecting Pipeline Tools to Canonical Schemas)
# ---------------------------------------------------------------------------

VulnerabilityFinding = FindingSchema
InvestigationTarget = InvestigationTargetSchema
ReviewPlan = PlanSchema
LearningEntry = LearningEntrySchema

# ---------------------------------------------------------------------------
# Workflow Verdicts, Reporting & Domain Tool Schemas
# ---------------------------------------------------------------------------

class VulnerabilityReport(BaseModel):
    """Structured report returned by the researcher stage containing canonical FindingSchema objects."""
    model_config = ConfigDict(extra="forbid")
    findings: List[FindingSchema] = Field(
        default_factory=list,
        validation_alias=AliasChoices('findings', 'vulnerabilities'),
        description='A list of all vulnerabilities found in the target. Empty if none found.'
    )

class ReviewVerdict(BaseModel):
    """Structured verdict for reviewer classifier routing."""
    model_config = ConfigDict(extra="forbid")
    route: Literal['confirmed', 'false_positive']
    reason: str = Field(description='One sentence justifying the verdict.')

class CriticVerdict(BaseModel):
    """Structured verdict for critic classifier routing."""
    model_config = ConfigDict(extra="forbid")
    route: Literal['viable', 'non_viable']
    reason: str = Field(description='One sentence justifying the exploit viability verdict.')

class ReproVerdict(BaseModel):
    """Structured verdict for reproducer classifier routing."""
    model_config = ConfigDict(extra="ignore")
    route: Literal['success', 'failed_repro']
    reason: str = Field(description='One sentence describing what was executed and observed.')

class ThreatModel(BaseModel):
    """Threat model artifact from /mantis-threat-model."""
    model_config = ConfigDict(extra="ignore")
    threat_actors: List[str] = Field(default_factory=list, description='Identified adversary profiles and positions')
    trust_boundaries: List[str] = Field(default_factory=list, description='System boundaries where untrusted input enters')
    entry_points: List[str] = Field(default_factory=list, description='Public or internal endpoints exposed to input')
    key_risks: List[str] = Field(default_factory=list, description='Primary business or security risks identified')

class CodebaseSummary(BaseModel):
    """Codebase summary from /mantis-summarize."""
    model_config = ConfigDict(extra="ignore")
    overview: str = Field(default="", description='Executive summary of the codebase purpose and architecture', validation_alias=AliasChoices('overview', 'summary', 'description'))
    key_modules: List[Union[str, Dict[str, Any]]] = Field(default_factory=list, description='Core system components and directories')
    tech_stack: List[str] = Field(default_factory=list, description='Languages, frameworks, and database dependencies')

class ExploitChain(BaseModel):
    """Multi-stage exploit chain from /mantis-chain."""
    model_config = ConfigDict(extra="ignore")
    chain_title: str = Field(description='Descriptive title of the composite attack chain')
    finding_titles: List[str] = Field(description='Titles or IDs of the chained findings')
    attack_path: str = Field(description='Step-by-step progression of the chained exploit')
    combined_impact: str = Field(description='Composite impact achieved through the chain')

class ExecutiveReport(BaseModel):
    """Final executive review packet compiled by /mantis-report."""
    model_config = ConfigDict(extra="ignore")
    executive_summary: str = Field(description='High level executive summary of findings and risk posture')
    critical_findings_count: int = Field(default=0, description='Total critical findings recorded')
    recommendations: List[str] = Field(default_factory=list, description='Prioritized remediation actions')

# Schema.json helper registry
SCHEMA_DEFINITIONS = {
    'finding': FindingSchema,
    'plan': PlanSchema,
    'learning_entry': LearningEntrySchema,
    'state': StateSchema,
    'triage_checklist': TriageChecklistSchema,
    'calibration_checklist': CalibrationChecklistSchema,
}

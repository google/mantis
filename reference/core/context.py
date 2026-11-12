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

import contextvars
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class RunContext:
    jail_dir: str
    db_path: str
    target_file: str = ""
    sandbox: object = None
    run_id: str = ""
    sandbox_executed: bool = False
    snapshot_id: str = ""
    budget_controller: object = None
    static_sandbox_attempts: int = 0
    active_node: str = ""
    # The scan mode this run was launched with ("whole", "file-by-file",
    # "cross-functional"). Empty when the caller predates the field; every
    # consumer must treat empty as "unknown" and fall back to per-campaign
    # behavior (INV-6).
    scan_mode: str = ""
    # The directory finding filepaths should be stored relative to -- the
    # enclosing repository when a scan targets a single file inside one.
    # A file-sized target cannot know its own repository; only the caller
    # does. Empty means "unknown": canonicalization falls back to the
    # jail-anchored behavior that predates the field (INV-6).
    path_root: str = ""
    # Operator exclusions (core.exclusions), relative to the target: what the
    # run does not scan and does not list. Empty means none (INV-6).
    exclude: tuple = ()
    # The model this run uses (resolved id). Empty when unknown.
    model: str = ""
    # Identity of the harness configuration this run executes (node ids,
    # tools, models, prompts, sandbox tier; core.graph_loader
    # .compute_harness_fingerprint). Stamped on every coverage row so a later
    # run can tell "covered" from "covered by THIS harness". Empty means
    # unknown: rows are written without one and never reported stale (INV-6).
    harness_fingerprint: str = ""
    # Per-file un-windowed read_file call counters for tool-loop steering.
    read_file_counts: dict[str, int] = field(default_factory=dict)
    # Reached-sink evidence per FINDING, keyed by the finding's database id as
    # a string. `sandbox_executed` above says "some PoC in this campaign
    # reached a sink"; this says which. Each entry: {"reproduced": bool (a
    # reproducer-stage run of this finding's PoC had evidence), "reattacked":
    # bool (a patcher-stage run was made), "reattack_present": bool (the
    # last re-attack still reached the sink), "sink_symbol": str, "reason":
    # str (the last evidence_reason)}. Written only by
    # tools.sandbox_tools.run_sandbox_with_evidence; read by the completion
    # stamp, which upgrades only the findings named here. Empty means no
    # evidence was attributed to any finding.
    finding_evidence: dict[str, dict] = field(default_factory=dict)
    # Each stage's working-context budget, keyed by node id: {"tokens": the
    # last request's estimated size, "limit": the model's window, "restarts":
    # how often the stage was restarted with a fresh context}. Written by the
    # node context ceiling before every model call; read by the after-tool
    # guard, which sizes each NEW tool result to the headroom left. Per
    # campaign, like the evidence ledger: with --parallel the same callbacks
    # serve every campaign in flight.
    node_context: dict[str, dict] = field(default_factory=dict)
    # Operator-side text every agent node of this campaign must see: what
    # the campaign is about when that is narrower than its target (a
    # change-scoped run). Nodes run with include_contents="none", so only
    # the first node sees the seed message; this is appended to each node's
    # instructions instead (core.graph_loader). Empty means no directive.
    campaign_directive: str = ""
    # Data-side context for the stages that decide where to look (the
    # slice briefing, what earlier runs found here, cross-area leads, the
    # coverage note, the survey's focus): the blocks main.py also places in
    # the seed message, which only the first node reads. Appended, bounded,
    # to the instructions of the architect, threat modeler, planner,
    # researchers, reviewer and critic (core.graph_loader.CONTEXT_STAGES).
    # Each block carries its own fencing. Empty means none.
    campaign_context: str = ""
    # Number of concurrent campaign workers active in this pipeline invocation
    # (1 = sequential default). Used to line-buffer and prefix console output
    # so concurrent campaigns do not interleave mid-word.
    parallel_workers: int = 1
    # Optional run-scoped prefix-reuse ledger shared across worker Workflow
    # instances inside one pipeline() call; None falls back to per-callback dict.
    shared_prefix_runs: Optional[dict[str, dict[str, str]]] = None
    # All directory/file targets grouped into this campaign (primary + secondaries).
    group_targets: tuple = ()
    # Lazily computed deterministic AST/lexical sink & entrypoint checklist for
    # planner and researcher stages (None = not yet computed, "" = none found).
    audit_checklist: Optional[str] = None
    # Multi-pass audit tracking (1-indexed; >1 = independent blind repeat pass).
    pass_index: int = 1
    artifact_resource: str = ""
    reported_in_pass: bool = False
    # True on multi-campaign runs so per-campaign reporter defers to the single
    # post-run consolidated report pass.
    defer_reporter: bool = False
    # Finding IDs explicitly promoted by the most recent per-finding classifier
    # stage in this campaign/pass (None = no classifier has narrowed the cohort yet).
    promoted_finding_ids: Optional[set[int]] = None
    # Count of synthesized Fallback: verdict turns observed in this campaign.
    verdict_fallbacks: int = 0
    # Mid-invocation --resume accounting.
    pre_pause_tokens: int = 0
    resumed_mid_invocation: bool = False
    # Cross-run memory policy controls (--no-memory / --intra-run-learning).
    enable_memory: bool = True
    intra_run_learning: bool = False
    freeze_memory_to_prior_runs: bool = False

current_run_context: contextvars.ContextVar[Optional[RunContext]] = contextvars.ContextVar(
    "current_run_context", default=None
)


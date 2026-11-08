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

from .research_tools import (
    read_file,
    write_file,
    list_files,
    report_findings,
    get_findings,
    score_risk,
    record_plan,
    get_plan,
    record_threat_model,
    get_threat_model,
    record_summary,
    get_summary,
    record_exploit_chain,
    record_learning,
    dedupe_findings,
    record_patch,
    generate_report,
    calibrate_finding,
    get_security_guidance,
    query_lineage,
    record_regression_check,
    get_prior_poc,
    get_git_log,
    get_git_diff,
    detect_vcs_info,
)
from .sandbox_tools import (
    run_sandbox,
    apply_patch,
    run_sandbox_with_evidence,
    check_reached_sink_evidence,
)
from .structural_tools import (
    find_symbol,
    find_callers,
    find_callees,
    get_function_boundary,
)

TOOLS: dict[str, object] = {
    "read_file": read_file,
    "write_file": write_file,
    "list_files": list_files,
    "get_git_log": get_git_log,
    "get_git_diff": get_git_diff,
    "report_findings": report_findings,
    "get_findings": get_findings,
    "score_risk": score_risk,
    "calibrate_finding": calibrate_finding,
    "record_plan": record_plan,
    "get_plan": get_plan,
    "record_threat_model": record_threat_model,
    "get_threat_model": get_threat_model,
    "record_summary": record_summary,
    "get_summary": get_summary,
    "record_exploit_chain": record_exploit_chain,
    "record_learning": record_learning,
    "dedupe_findings": dedupe_findings,
    "record_patch": record_patch,
    "generate_report": generate_report,
    "run_sandbox": run_sandbox,
    "apply_patch": apply_patch,
    "run_sandbox_with_evidence": run_sandbox_with_evidence,
    "get_security_guidance": get_security_guidance,
    "query_lineage": query_lineage,
    "record_regression_check": record_regression_check,
    "get_prior_poc": get_prior_poc,
    "find_symbol": find_symbol,
    "find_callers": find_callers,
    "find_callees": find_callees,
    "get_function_boundary": get_function_boundary,
}

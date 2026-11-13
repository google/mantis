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

"""Writes the run's findings as SARIF 2.1.0.

WHY THIS EXISTS
---------------
Until now the only way out of Mantis was the SQLite knowledge base. That is fine
for Mantis talking to itself and useless for everything else: a deployment that
wants findings in GitHub code scanning, an internal dashboard, or a ticket queue
has to read our schema and write a converter. SARIF is the standard interchange
format for exactly this, so the converter should be ours and written once.

This is EMISSION, which is the opposite trade-off from ingestion.
`mantis-pipeline-adapter` argues against SARIF for reading other tools' output,
and it is right: every scanner emits a different subset, so the parser absorbs
all of that variance. Emitting inverts it. We control what we produce and the
consumer needs no custom parser.

THE PATH PROBLEM, WHICH IS BOTH A LEAK AND A BUG
------------------------------------------------
`canonical_filepath` falls back to returning an ABSOLUTE path when it cannot
relativize one. That is reasonable for a local SQLite row and wrong here: a
SARIF file is meant to be uploaded, and `/Users/someone/work/secret-project/...`
discloses the host layout and the project name to whoever reads it.

It is also, independently, the single most common cause of SARIF that appears to
work: GitHub accepts a file with absolute URIs and then displays nothing,
because it cannot match the path against the repository tree. There is no error.

So this module RE-DERIVES every path from the scan root instead of trusting the
stored value, and a finding whose path cannot be made relative is dropped with a
counted, reported reason -- never emitted absolute, never dropped silently.

WHAT SARIF CANNOT SAY, AND WHY THAT MATTERS HERE
------------------------------------------------
SARIF has no field for "this finding is unverified". Every entry is a `result`
with a `level`. A finding nobody reproduced and a finding with a working
proof-of-concept are the same shape.

Mantis spends its entire design keeping that distinction (INV-1, the evidence
tiers, the reproduction gate). Flattening it on the way out would undo that at
the last step, so the verification state is written into `message.text` -- where
a human sees it without knowing our internals -- as well as into the property
bag for machines.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

TOOL_NAME = "Mantis"
TOOL_INFORMATION_URI = "https://github.com/google/mantis"

# The complete SARIF level vocabulary. There are four, all lowercase; "critical",
# "info" and "HIGH" are not among them and are the classic rejection cause.
_LEVELS = ("none", "note", "warning", "error")

# Mantis severity -> (SARIF level, representative 0-10 score).
#
# The score is only a fallback for when `mantis_risk_score` is absent. It is the
# BOTTOM of each CVSS band rather than the middle: the band is all we actually know,
# and picking the middle would invent precision we do not have, in the direction of
# overstating. A reader comparing two findings should not be misled by a number we
# made up.
_SEVERITY_MAP = {
    "CRITICAL": ("error", 9.0),
    "HIGH": ("error", 7.0),
    "MEDIUM": ("warning", 4.0),
    "LOW": ("note", 0.1),
}
_DEFAULT_SEVERITY = ("warning", 4.0)

# Suppression is decided by `core.database.is_suppressed`, not by a copy of the
# vocabulary kept here. A second list would be one more place to forget when a status
# is added, and the failure is silent in the worst direction: a finding the reviewer
# dismissed presented to an outside system as a live alert.

# How much confidence the pipeline actually established, in plain words. SARIF has
# no vocabulary for this, so it goes in the message where a human will see it.
_VERIFICATION_NOTE = {
    "VERIFIED_SECURE": "verified: the proposed patch withstood re-attack",
    "MITIGATION_PROPOSED": "unverified: a patch is proposed but was not confirmed",
    "VERIFICATION_INCOMPLETE": "unverified: verification did not complete",
    "VERIFICATION_FAILED": "unverified: verification was attempted and failed",
}


class SarifExportError(ValueError):
    """The SARIF document could not be produced as specified."""


def _relative_uri(filepath: str, scan_root: str) -> Optional[str]:
    """Returns a repo-relative, percent-encoded URI, or None if it cannot be one.

    None is a refusal, not an error to paper over. Emitting an absolute path here
    would leak the host layout, and emitting a `..` path produces a file GitHub
    silently ignores. The caller counts and reports the refusals.
    """
    raw = str(filepath or "").strip().replace("\\", "/")
    if not raw:
        return None
    if raw.startswith("file://"):
        raw = raw[7:]

    if os.path.isabs(raw):
        if not scan_root:
            return None
        try:
            rel = os.path.relpath(raw, scan_root).replace("\\", "/")
        except (ValueError, OSError):
            return None
    else:
        rel = raw

    while rel.startswith("./"):
        rel = rel[2:]
    rel = posixpath.normpath(rel)

    # `normpath` resolves interior traversal but cannot fix a path that genuinely
    # escapes the root, and "." means the root itself, which is not a file.
    if rel in (".", "", "/") or rel.startswith("..") or rel.startswith("/"):
        return None

    # Encode everything a path segment may not hold, but never the separator.
    return quote(rel, safe="/")


def _first_line(line_numbers: Any) -> int:
    """SARIF regions are 1-based; 0 or negative is schema-invalid.

    Findings routinely carry no line at all, so this defaults to 1 rather than
    dropping the finding: "somewhere in this file" is still worth reporting, and
    a missing region would be a worse lie than an imprecise one.
    """
    candidates: List[Any] = []
    if isinstance(line_numbers, list):
        candidates = line_numbers
    elif isinstance(line_numbers, (int, float, str)):
        candidates = [line_numbers]

    for value in candidates:
        try:
            line = int(value)
        except (TypeError, ValueError):
            continue
        if line >= 1:
            return line
    return 1


def _security_severity(finding: Dict[str, Any], fallback: float) -> str:
    """Returns the GitHub `security-severity` value.

    A STRING holding a 0-10 decimal. Emitting a JSON number here is one of the
    most common silent failures: the upload succeeds and the severity is simply
    never assigned.
    """
    raw = finding.get("mantis_risk_score")
    try:
        score = float(raw)
    except (TypeError, ValueError):
        score = fallback
    # NaN fails `score == score`; it would also make the JSON unparseable.
    if score != score or score in (float("inf"), float("-inf")):
        score = fallback
    return f"{max(0.0, min(10.0, score)):.1f}"


def _rule_id(finding: Dict[str, Any]) -> str:
    """Groups findings by weakness class so a consumer can triage by kind.

    CWE when present, because that is the shared vocabulary; otherwise a single
    generic bucket. Inventing a rule id per finding title would defeat grouping
    entirely -- every alert would be its own rule.
    """
    cwe = str(finding.get("cwe") or "").strip().upper()
    if cwe.startswith("CWE-") and cwe[4:].isdigit():
        return cwe
    return "MANTIS-FINDING"


def _message_text(finding: Dict[str, Any]) -> str:
    # Title and description are model-written from target content: the one
    # egress path that skipped the sanitizer every other export applies.
    # sanitize_egress_text strips terminal control sequences and scrubs
    # credentials the model quoted; the bracket rewrite keeps a description
    # from forging the verification note that follows it.
    from core.database import is_untriaged
    from core.llm_gateway import sanitize_egress_text

    title = sanitize_egress_text(str(finding.get("title") or "Unnamed finding")).strip()
    description = sanitize_egress_text(str(finding.get("description") or "")).strip()
    title = _MANTIS_NOTE_LOOKALIKE.sub("(", title)
    description = _MANTIS_NOTE_LOOKALIKE.sub("(", description)

    status = str(finding.get("status") or "").strip()
    status_low = status.lower()
    patch_status = str(finding.get("patch_status") or "").strip().upper()

    # patch_status is trusted here because write_findings keeps
    # VERIFIED_SECURE only when the harness itself recorded reached-sink
    # evidence for the run (verified_evidence); the export adds no gate.
    if is_untriaged(status):
        note = "untriaged: review did not complete; requires manual review"
    elif patch_status == "VERIFIED_SECURE":
        note = _VERIFICATION_NOTE["VERIFIED_SECURE"]
    elif status_low in ("dynamic_confirmed", "reproduced") or (
        status_low == "patch_verified" and patch_status != "VERIFIED_SECURE"
    ):
        if patch_status == "MITIGATION_PROPOSED":
            patch_clause = "a patch is proposed but was not confirmed"
        elif patch_status == "VERIFICATION_INCOMPLETE":
            patch_clause = "patch verification did not complete"
        elif patch_status == "VERIFICATION_FAILED":
            patch_clause = "patch verification was attempted and failed"
        else:
            patch_clause = "no verified patch recorded"
        note = f"reproduced: reached-sink evidence recorded; {patch_clause}"
    else:
        note = _VERIFICATION_NOTE.get(patch_status)
        if note is None:
            # No patch verification ran. Say so rather than staying silent: silence
            # reads as confidence, and this is the most common case.
            note = "unverified: no reproduction or patch verification is recorded"

    parts = [title]
    if description:
        parts.append(description)
    parts.append(f"[Mantis {note}. Triage status: {status or 'unknown'}.]")
    return "\n\n".join(parts)


_MANTIS_NOTE_LOOKALIKE = re.compile(r"\[(?=Mantis\b)")


def _fingerprint(finding: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Stable identity across runs, so an alert survives a refactor.

    Reuses the lineage id Mantis already maintains for INV-3 regression tracking.
    That makes the consumer's notion of "the same finding" agree with ours,
    instead of the consumer guessing from path plus surrounding text and closing
    an alert every time the code moves.
    """
    for key in ("lineage_id", "signature"):
        value = str(finding.get(key) or "").strip()
        if value:
            # Values MUST be strings; a number fails schema validation.
            return {f"mantis/{key}/v1": value}
    return None


def build_sarif(
    findings: List[Dict[str, Any]],
    scan_root: str = "",
    tool_version: str = "",
    include_suppressed: bool = False,
    run_properties: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    """Builds a SARIF 2.1.0 document. Returns `(document, skipped_reasons)`.

    Skips are returned rather than logged and forgotten. A finding missing from
    an export is indistinguishable from a finding that was never made, so the
    caller reports the count -- the same reason a misconfigured evidence source
    stops the run instead of being dropped.
    """
    rules: List[Dict[str, Any]] = []
    rule_index: Dict[str, int] = {}
    rule_max_level: Dict[str, str] = {}
    rule_max_score: Dict[str, float] = {}
    results: List[Dict[str, Any]] = []
    skipped: List[str] = []
    untriaged_omitted = 0

    from core.database import is_suppressed, is_untriaged

    for finding in findings or []:
        status = str(finding.get("status") or "")
        if not include_suppressed and is_untriaged(status):
            untriaged_omitted += 1
        if not include_suppressed and is_suppressed(status):
            continue

        uri = _relative_uri(finding.get("filepath", ""), scan_root)
        if uri is None:
            skipped.append(
                f"{finding.get('title') or 'untitled'}: path "
                f"{finding.get('filepath')!r} is not inside the scan root, so it "
                f"cannot be written as a relative URI"
            )
            continue

        severity = str(finding.get("severity") or "").strip().upper()
        level, fallback_score = _SEVERITY_MAP.get(severity, _DEFAULT_SEVERITY)
        score = _security_severity(finding, fallback_score)
        untriaged_entry = bool(include_suppressed and is_untriaged(status))
        result_level = "note" if untriaged_entry else level

        rid = _rule_id(finding)
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            tags = ["security"]
            if rid.startswith("CWE-"):
                tags.append(f"external/cwe/{rid.lower()}")
            rules.append({
                "id": rid,
                "shortDescription": {
                    "text": (
                        f"{rid}: weakness class reported by Mantis"
                        if rid.startswith("CWE-")
                        else "Finding reported by Mantis without a CWE classification"
                    )
                },
                "defaultConfiguration": {"level": result_level},
                "properties": {"security-severity": score, "tags": tags},
            })
            rule_max_level[rid] = result_level
            try:
                rule_max_score[rid] = float(score)
            except ValueError:
                rule_max_score[rid] = fallback_score
        else:
            if _LEVELS.index(result_level) > _LEVELS.index(rule_max_level[rid]):
                rule_max_level[rid] = result_level
            try:
                s_val = float(score)
            except ValueError:
                s_val = fallback_score
            if s_val > rule_max_score[rid]:
                rule_max_score[rid] = s_val

        props: Dict[str, Any] = {
            "security-severity": score,
            "mantis-status": status or "unknown",
            "mantis-patch-status": str(finding.get("patch_status") or "") or "none",
        }
        if untriaged_entry:
            props["mantis/triage"] = "untriaged"

        result: Dict[str, Any] = {
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": result_level,
            "message": {"text": _message_text(finding)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": _first_line(finding.get("line_numbers"))},
                }
            }],
            "properties": props,
        }
        fingerprints = _fingerprint(finding)
        if fingerprints:
            result["partialFingerprints"] = fingerprints
        results.append(result)

    # Pass 2: stamp max defaultConfiguration.level and security-severity per rule.
    for rid, idx in rule_index.items():
        rules[idx]["defaultConfiguration"]["level"] = rule_max_level[rid]
        if isinstance(rules[idx]["properties"].get("security-severity"), str):
            rules[idx]["properties"]["security-severity"] = f"{rule_max_score[rid]:.1f}"

    driver: Dict[str, Any] = {
        "name": TOOL_NAME,
        "informationUri": TOOL_INFORMATION_URI,
        "rules": rules,
    }
    if tool_version:
        driver["version"] = str(tool_version)

    run_props: Dict[str, Any] = {"untriaged_omitted": untriaged_omitted}
    if isinstance(run_properties, dict):
        for k, v in run_properties.items():
            run_props[str(k)] = v

    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        # Deliberately no `originalUriBaseIds`. The conventional `%SRCROOT%` entry
        # holds an absolute host path, which would reintroduce exactly the
        # disclosure `_relative_uri` exists to prevent. A plain relative URI is
        # already interpreted against the repository root.
        "runs": [{"tool": {"driver": driver}, "results": results, "properties": run_props}],
    }
    return document, skipped


def validate_sarif(document: Dict[str, Any]) -> List[str]:
    """Checks the invariants that cause rejection or silent data loss.

    Not a schema validator, and it must not be mistaken for one. It covers the
    specific mistakes that produce a file which looks correct locally and then
    fails, or worse, uploads cleanly and displays nothing.
    """
    problems: List[str] = []

    if document.get("version") != SARIF_VERSION:
        problems.append(
            f"version must be the string {SARIF_VERSION!r}, got "
            f"{document.get('version')!r}"
        )

    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        problems.append("runs must be a non-empty list")
        return problems

    for run in runs:
        driver = (run.get("tool") or {}).get("driver") or {}
        if not driver.get("name"):
            problems.append("tool.driver.name is required")

        rules = driver.get("rules") or []
        ids = [r.get("id") for r in rules]
        if len(ids) != len(set(ids)):
            problems.append("tool.driver.rules contains duplicate ids")

        for result in run.get("results") or []:
            rid = result.get("ruleId")
            if rid not in ids:
                problems.append(f"result ruleId {rid!r} is not a declared rule")
            index = result.get("ruleIndex")
            if index is not None:
                if not isinstance(index, int) or not 0 <= index < len(ids):
                    problems.append(f"ruleIndex {index!r} is out of range")
                elif ids[index] != rid:
                    problems.append(
                        f"ruleIndex {index} points at {ids[index]!r} but ruleId is {rid!r}"
                    )

            if result.get("level") not in _LEVELS:
                problems.append(
                    f"level {result.get('level')!r} is not one of {list(_LEVELS)}"
                )
            if not (result.get("message") or {}).get("text"):
                problems.append("result.message.text is required")

            for key, value in (result.get("partialFingerprints") or {}).items():
                if not isinstance(value, str):
                    problems.append(
                        f"partialFingerprints[{key!r}] must be a string, got "
                        f"{type(value).__name__}"
                    )

            for bag in (result.get("properties"), *(
                [r.get("properties") for r in rules]
            )):
                score = (bag or {}).get("security-severity")
                if score is None:
                    continue
                if not isinstance(score, str):
                    problems.append(
                        f"security-severity must be a string, got "
                        f"{type(score).__name__} ({score!r})"
                    )
                else:
                    try:
                        if not 0.0 <= float(score) <= 10.0:
                            problems.append(f"security-severity {score!r} is outside 0-10")
                    except ValueError:
                        problems.append(f"security-severity {score!r} is not a number")

            for location in result.get("locations") or []:
                physical = location.get("physicalLocation") or {}
                uri = (physical.get("artifactLocation") or {}).get("uri", "")
                if not uri:
                    problems.append("artifactLocation.uri is required")
                elif uri.startswith("/") or uri.startswith("file:") or ".." in uri.split("/"):
                    problems.append(
                        f"uri {uri!r} must be relative and inside the scan root; an "
                        f"absolute path leaks the host layout and is silently "
                        f"ignored by consumers"
                    )
                elif "\\" in uri:
                    problems.append(f"uri {uri!r} contains a backslash; use '/'")

                start = (physical.get("region") or {}).get("startLine")
                if start is not None and (not isinstance(start, int) or start < 1):
                    problems.append(f"region.startLine must be >= 1, got {start!r}")

    return problems


def write_sarif(
    path: str,
    findings: List[Dict[str, Any]],
    scan_root: str = "",
    tool_version: str = "",
    include_suppressed: bool = False,
    run_properties: Optional[Dict[str, Any]] = None,
) -> Tuple[int, List[str]]:
    """Writes validated SARIF to `path`. Returns `(result_count, skipped_reasons)`.

    Validation runs BEFORE the write. A file that fails its own invariants is not
    a partial success -- it is a file whose consumer will either reject it or
    display nothing, and writing it anyway would make the run look successful.

    `include_suppressed` as for build_sarif: for a caller that has already
    selected the findings to present by its own rule.
    """
    document, skipped = build_sarif(
        findings, scan_root=scan_root, tool_version=tool_version,
        include_suppressed=include_suppressed,
        run_properties=run_properties,
    )
    problems = validate_sarif(document)
    if problems:
        raise SarifExportError(
            "Refusing to write invalid SARIF:\n  " + "\n  ".join(problems)
        )

    abs_path = os.path.abspath(path)
    parent = os.path.dirname(abs_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp_path = f"{abs_path}.{os.getpid()}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as handle:
            # allow_nan=False: Python emits bare NaN/Infinity by default, which is not
            # valid JSON. `mantis_risk_score` is a REAL column, so this is reachable.
            json.dump(document, handle, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
        os.replace(tmp_path, abs_path)
    except BaseException:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return len(document["runs"][0]["results"]), skipped

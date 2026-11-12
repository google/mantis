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

"""Diversification metrics: does this audit look like it actually searched?

WHY THIS EXISTS
---------------
There is no ground truth and there never will be. Mantis will be run on monorepos we
never see, by people who will not tell us when it missed something. We cannot measure
recall, so the honest alternative is to make the run describe its own shape and let a
human judge whether that shape is plausible.

The specific failure this is aimed at is the one that looks most like success: a run
that reports twenty findings which are really the same finding twenty times. Twenty
instances of "unvalidated input" in twenty files, all from one area, all the same
weakness class, is one observation with a large count -- and it is indistinguishable
from thorough work if you only read the total.

WHAT IT MEASURES
----------------
Four things, each a plain count or ratio over validated/structural fields:

  * SPREAD    -- how many distinct areas produced findings, against how many were
                 examined. Low spread with high counts means one area dominated.
  * VARIETY   -- how many distinct weakness classes. One CWE across everything is a
                 single observation repeated.
  * DEPTH     -- how many findings survived review rather than being dismissed. A high
                 dismissal rate means the run was generating noise.
  * SILENCE   -- how many examined areas produced nothing at all. Not a defect on its
                 own, but the number a reader needs to interpret everything else.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not score the run, grade it, or gate anything on the result. There is no
threshold at which a run is declared bad, because no such threshold is knowable: a
repository with one real defect SHOULD produce one finding in one area, and a metric
that called that failure would be worse than no metric. It reports the shape and says
what the shape could mean, in both directions. The reader decides.

It also never modifies a finding. Nothing here can change severity, status, or whether
something is reported -- it is strictly an observation about the set as a whole.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Statuses meaning "a reviewer looked at this and rejected it". Mirrors
# `memory._STATUSES_DISMISSED` plus the deduplicator's own outcome, which is a rejection
# of a duplicate rather than of a claim.
_REJECTED = frozenset({
    "false_positive", "non_viable", "sample_or_test", "duplicate_merged",
})

# Statuses meaning "nobody has ruled on this yet". `reported` is the schema default for
# every newly written finding (database.py), so a run whose triage never executed -- cut
# short by budget, or crashed -- leaves everything sitting here.
#
# This MUST stay separate from _REJECTED. Counting the default as a rejection made the
# report say "100% of findings were rejected at review; the reviewers are working" about
# a run in which no reviewer ran at all. An unreviewed claim is not a dismissed one, and
# conflating them invents a quality signal out of the absence of one.
_UNREVIEWED = frozenset({"reported"})


def _area_of(filepath: Any) -> str:
    """The directory a finding sits in, which is the unit 'spread' counts.

    Findings are per-file; counting distinct FILES would report high spread for twenty
    findings in one directory, which is exactly the concentration this is meant to
    expose. For the same reason root-level files collapse to a single area rather than
    each becoming its own.
    """
    path = str(filepath or "").replace("\\", "/").rstrip("/")
    if not path:
        return ""
    cut = path.rfind("/")
    if cut > 0:
        return path[:cut]
    # "a.py" -> "." and "/a.py" -> "/": both are one area, not one area per file.
    return "/" if cut == 0 else "."



def _produced_something(examined_item: str, finding_paths: List[str]) -> bool:
    """Did this scan target yield any finding?

    `examined_areas` holds whatever the run scanned, and that is NOT one granularity:
    file-by-file mode appends individual FILES while cross-functional mode appends DIRECTORIES.
    Findings are always per-file. Comparing the two by count reported "19 of 20 produced
    nothing" for a run in which every single file produced a finding.

    So match by containment instead: a target counts as productive if any finding sits
    at it or beneath it.
    """
    item = str(examined_item or "").replace("\\", "/").strip().rstrip("/")
    if not item:
        return False
    prefix = item + "/"
    for path in finding_paths:
        if path == item or path.startswith(prefix) or item.endswith("/" + path):
            return True
    return False


def measure(
    findings: List[Dict[str, Any]],
    examined_areas: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Describes the shape of what this run produced.

    `examined_areas` is what the run actually examined -- needed because the interesting
    quantity is findings-per-examined-target, and the findings alone cannot say how much
    ground was walked to produce them.

    Never raises (INV-6).
    """
    empty: Dict[str, Any] = {"available": False}
    try:
        rows = [f for f in (findings or []) if isinstance(f, dict)]
        examined = [str(a) for a in (examined_areas or []) if str(a or "").strip()]
        if not rows and not examined:
            return empty

        def _status(f: Dict[str, Any]) -> str:
            return str(f.get("status") or "").strip().lower()

        # Closed prior-run/regression rows (mitigated, archived) are neither live
        # claims nor triage rejections of this run.
        rows = [f for f in rows if _status(f) not in ("mitigated", "archived")]

        # Three outcomes, not two. A finding still sitting at the schema default has not
        # been rejected -- nobody has looked at it yet.
        rejected_rows = [f for f in rows if _status(f) in _REJECTED]
        kept = [f for f in rows if _status(f) not in _REJECTED]
        unreviewed = [f for f in kept if _status(f) in _UNREVIEWED]
        rejected = len(rejected_rows)

        # Shape is measured over everything still standing, unreviewed included: those
        # are claims that have not been knocked down, and excluding them would make a
        # run whose triage never executed report no shape at all.
        areas_with_findings = {_area_of(f.get("filepath")) for f in kept}
        areas_with_findings.discard("")

        weaknesses = {str(f.get("cwe") or "").strip() for f in kept}
        weaknesses.discard("")

        severities: Dict[str, int] = {}
        for f in kept:
            sev = str(f.get("severity") or "unspecified").strip().lower()
            severities[sev] = severities.get(sev, 0) + 1

        # Concentration: the share of surviving findings in the single busiest area.
        # 1.0 means everything came from one place.
        per_area: Dict[str, int] = {}
        for f in kept:
            area = _area_of(f.get("filepath"))
            if area:
                per_area[area] = per_area.get(area, 0) + 1
        busiest = max(per_area.values()) if per_area else 0
        concentration = (busiest / len(kept)) if kept else 0.0

        finding_paths = []
        for f in kept:
            p = str(f.get("filepath") or "").replace("\\", "/").strip().rstrip("/")
            if p:
                finding_paths.append(p)
        silent = sum(1 for item in examined if not _produced_something(item, finding_paths))

        # Denominator is what was actually REVIEWED. Dividing by every raised finding
        # would report a 100% rejection rate for a run in which no reviewer ran.
        reviewed = rejected + (len(kept) - len(unreviewed))

        return {
            "available": True,
            "findings_total": len(rows),
            "findings_kept": len(kept),
            "findings_rejected": rejected,
            "findings_unreviewed": len(unreviewed),
            "findings_reviewed": reviewed,
            "rejection_rate": (rejected / reviewed) if reviewed else 0.0,
            "targets_examined": len(examined),
            "areas_with_findings": len(areas_with_findings),
            "silent_targets": silent,
            "distinct_weaknesses": len(weaknesses),
            "severity_spread": severities,
            "concentration": round(concentration, 3),
        }
    except Exception as exc:
        logger.warning("Diversification metrics failed: %s", exc)
        return empty


def render_metrics(metrics: Dict[str, Any]) -> List[str]:
    """Operator-facing lines describing the run's shape.

    Returns a list of plain strings containing no repository-derived bytes -- only
    counts and ratios -- so the caller can print them without CP-4 concerns.

    Every observation is stated with BOTH readings. "One weakness class across nine
    findings" can mean a systemic flaw worth chasing or a single observation counted
    nine times, and this module cannot tell which. Presenting only the pessimistic
    reading would train the reader to ignore it.
    """
    if not isinstance(metrics, dict) or not metrics.get("available"):
        return []

    kept = metrics.get("findings_kept", 0)
    lines = [
        f"{kept} finding(s) kept across {metrics.get('areas_with_findings', 0)} "
        f"area(s); {metrics.get('findings_rejected', 0)} rejected at review.",
    ]

    # Stated plainly, because every ratio below is weaker when triage did not finish.
    unreviewed = metrics.get("findings_unreviewed", 0)
    if unreviewed:
        lines.append(
            f"{unreviewed} finding(s) were never reviewed, so they are counted as "
            f"standing rather than as confirmed. Triage may have been cut short."
        )

    if metrics.get("targets_examined"):
        lines.append(
            f"{metrics['targets_examined']} target(s) examined, "
            f"{metrics.get('silent_targets', 0)} produced nothing."
        )

    if kept >= 3:
        distinct = metrics.get("distinct_weaknesses", 0)
        if distinct <= 1:
            lines.append(
                f"All {kept} findings share one weakness class. That is either a "
                f"systemic flaw worth pursuing everywhere, or one observation counted "
                f"{kept} times -- worth deciding which before acting on the count."
            )
        else:
            lines.append(f"{distinct} distinct weakness class(es) represented.")

        concentration = metrics.get("concentration", 0.0)
        if concentration >= 0.8 and metrics.get("areas_with_findings", 0) >= 1:
            lines.append(
                f"{concentration:.0%} of findings come from a single area. That area "
                f"may genuinely be the weak point, or it may be the only one that was "
                f"examined deeply."
            )

    # Gated on findings actually REVIEWED, not findings raised: the sentence claims the
    # reviewers were working, so it must not appear when they never ran.
    rate = metrics.get("rejection_rate", 0.0)
    if metrics.get("findings_reviewed", 0) >= 5 and rate >= 0.5:
        lines.append(
            f"{rate:.0%} of reviewed findings were rejected. The reviewers are "
            f"working, but a run that mostly produces noise is spending its budget on "
            f"triage rather than analysis."
        )

    return lines

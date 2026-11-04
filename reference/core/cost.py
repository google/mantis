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

"""Campaign cost estimation and the observed-spend ledger.

WHAT THIS IS FOR
    Choosing a scan that should finish inside its token budget, instead of
    discovering at 10,000,000 tokens that the run covered 0.9% of the tree and
    stopped. The budget controller already stops the run safely; what it cannot
    do is tell the operator BEFOREHAND how much of the repository their budget
    actually buys.

WHY THE ARITHMETIC IS SHAPED THIS WAY
    Measured against the real trees before any of this was written:

        chromium    462,079 files, 3.0 GB, ~761,726,208 content tokens
        juice-shop    1,168 files,  14 MB,   ~3,512,671 content tokens

    Holding the 10M ceiling fixed and varying ONLY the assumed per-campaign
    overhead, the number of chromium files a file-by-file scan gets through is:

        5,000 tok/campaign  ->  1,999 files
       20,000 tok/campaign  ->    500 files
       50,000 tok/campaign  ->    200 files

    Those are exactly ceiling/overhead. The file contents contributed NOTHING:
    chromium's median file is 333 tokens against an overhead sixty times larger.

    So this module deliberately does NOT do byte accounting. Summing file sizes
    would be precise about the term that does not matter while guessing at the
    term that does. Cost is modelled as a flat per-campaign figure, and the file
    size is used only to catch the rare file so large it dominates its own
    campaign (chromium's largest is 20 MB, ~5.1M tokens -- half the default
    budget in a single file).

WHY THE DEFAULT IS A SEED AND NOT AN ANSWER
    The dominant term is turns-per-node, and nothing in the system has ever
    recorded it. DEFAULT_CAMPAIGN_TOKENS is therefore an assumption, not a
    measurement, and is marked as such everywhere it surfaces. `record_spend`
    exists so it stops being an assumption: once a deployment has run once,
    `observed_campaign_cost` returns ITS number, and the estimate describes the
    deployment's own workflow, models and repositories rather than ours.

    Accuracy is explicitly not the goal -- "it won't be perfect and we still
    might hit the guardrail, but if it's usually successful that's good enough".
    Every consumer must stay correct when the estimate is wrong, because it will
    be. The budget controller remains the thing that actually stops a run.

WHAT THIS MODULE MUST NEVER DO
    Refuse, cap, or discourage a scan. It reports numbers. The only place its
    output CHOOSES anything is scan_mode=auto, which is already defined as the
    mode that decides on the operator's behalf; every explicit mode runs exactly
    what was asked for and merely states what the budget covers.

RESUMPTION
    Spend is recorded per run_id and NOT carried forward into a resumed run.
    That is intentional and matches the resume contract: `--resume` starts a
    fresh budget so an operator can resume out of the box without recomputing
    anything. See `estimate_scan` and the README.

WHICH HARNESS COVERED IT
    Every row also names the harness configuration that ran the campaign
    (`harness_fingerprint`, from core.graph_loader). "Covered" without that is
    a statement about the past harness: after any upgrade -- a new tool, a
    stronger model, a rewritten stage prompt -- a slice the old configuration
    examined was never examined by the new one, and `--resume` and `auto`
    would skip it forever. `uncovered_files`, `harness_mismatches` and
    `run_ledger` compare the stamp on reuse. By default a mismatch still
    counts as covered and is only REPORTED (the operator decides whether the
    upgrade warrants re-examining what it covers); `--rescan-changed-harness`
    treats it as uncovered. A row with no stamp -- recorded before this
    existed, or imported from an export that did not carry one -- covers for
    every harness, so turning the stamp on re-sweeps nothing (INV-6).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional


def _connect(db_path: str) -> sqlite3.Connection:
    """Knowledge-database connection with the shared busy timeout and journal
    settings (core.database.connect); imported lazily to keep module import
    order free of cycles."""
    from core.database import connect

    return connect(db_path)

# Characters per token. Matches core.config._CHARS_PER_TOKEN and the estimate at
# main.py's token fallback, deliberately: a second, different constant for the same
# quantity would make two parts of the system disagree about what a token costs.
_CHARS_PER_TOKEN = 4

# Seed cost for one campaign, in effective tokens, used until a deployment has
# observed its own. The first derivation multiplied a measured static floor
# (~4,729 tokens of prompts and tool declarations per single-turn pass) by an
# assumed five turns, giving 25k -- and the first live campaign measured
# 437,693: reasoning tokens and multi-turn tool loops dominate real cost, and
# the static floor captured neither. This is that observation, rounded up.
#
# It is still an ASSUMPTION -- one campaign, one model, one repository -- and
# it is used only until record_spend() has real data for this deployment,
# which replaces it after a single completed campaign.
DEFAULT_CAMPAIGN_TOKENS = 500_000

# Fraction of the budget available to campaigns. The remainder covers correlation,
# synthesis and reporting, which run after the scan loop and still have to fit.
_CAMPAIGN_BUDGET_RATIO = 0.85

# A campaign whose target file alone exceeds this share of the per-campaign cost is
# priced on its content instead of the flat rate. Below this, file size is noise
# against prompt overhead and including it adds false precision.
_OVERSIZED_FILE_RATIO = 0.5

# Ignore absurd observations when averaging. A campaign that died in its first
# second and recorded ~0 tokens is not evidence that campaigns are cheap.
_MIN_CREDIBLE_OBSERVATION = 100


class CostLedgerUnavailable(Exception):
    """Raised only by explicit ledger inspection, never by the estimator."""


@dataclass
class ScanEstimate:
    """What a budget buys. Every field is an estimate except `planned_campaigns`."""

    planned_campaigns: int
    affordable_campaigns: int
    cost_per_campaign: int
    spendable_tokens: int
    basis: str  # "observed" | "seeded"
    observations: int = 0
    oversized: list[str] = field(default_factory=list)

    @property
    def fits(self) -> bool:
        return self.affordable_campaigns >= self.planned_campaigns

    @property
    def coverage_fraction(self) -> float:
        if self.planned_campaigns <= 0:
            return 1.0
        return min(1.0, self.affordable_campaigns / self.planned_campaigns)

    def describe(self) -> str:
        """One line, stating numbers and never judging them.

        The basis is always named. An operator told "this budget covers 200 of
        462,079 campaigns" deserves to know whether that came from their own
        previous runs or from our guess, because the two justify very different
        levels of trust.
        """
        basis = (
            f"from {self.observations} observed campaign(s)"
            if self.basis == "observed"
            else "estimated, no observed runs yet"
        )
        if self.fits:
            return (
                f"Budget covers all {self.planned_campaigns:,} campaign(s) "
                f"at ~{self.cost_per_campaign:,} tokens each ({basis})."
            )
        return (
            f"Budget covers ~{self.affordable_campaigns:,} of "
            f"{self.planned_campaigns:,} campaign(s) "
            f"({self.coverage_fraction * 100:.1f}%) at ~{self.cost_per_campaign:,} "
            f"tokens each ({basis}). The run pauses there and resumes with --resume."
        )


def _ensure_table(conn: sqlite3.Connection) -> None:
    """Creates the ledger table.

    Separate from campaign_artifacts on purpose. `list_files` surfaces every
    campaign_artifacts row for a run to the MODEL as a workspace listing, so
    filing cost rows there would inject operational accounting into agent context
    for no analytical benefit -- and grow it linearly in campaign count.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS campaign_spend (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            target TEXT,
            scan_mode TEXT,
            tokens INTEGER,
            llm_calls INTEGER,
            graph_steps INTEGER,
            elapsed_seconds REAL,
            metadata_json TEXT DEFAULT '{}',
            harness_fingerprint TEXT
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_campaign_spend_mode ON campaign_spend(scan_mode)"
    )
    # Columns added after the table first shipped. ALTER guarded by the
    # catalogue, the way core.database grows `findings`: an existing ledger
    # keeps every row (old rows read back as NULL, which every reader treats
    # as "unknown harness" -- INV-6), and a ledger created today gets the
    # column from the CREATE above.
    if not has_fingerprint_column(conn):
        conn.execute("ALTER TABLE campaign_spend ADD COLUMN harness_fingerprint TEXT")
    # What content a completed campaign examined, file by file. The spend
    # row says a target was covered; this says covered AS WHAT, so a later
    # run can tell an unchanged file from one edited since (issue #15). A
    # ledger without this table reads as "content unknown", which covers
    # (INV-6).
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS coverage_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT,
            campaign_target TEXT,
            path TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            size INTEGER,
            mtime_ns INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_coverage_files_path ON coverage_files(path)")


def has_coverage_files_table(conn: sqlite3.Connection) -> bool:
    """Whether this ledger records what content it covered. Readers ask
    rather than migrate, for the reason has_fingerprint_column gives."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'coverage_files'").fetchone()
    return bool(row)


#: Hex digits of SHA-256 kept per file: enough to never collide inside one
#: repository, short enough to export in bulk.
CONTENT_HASH_CHARS = 16


def file_identity(path: str) -> Optional[tuple[str, int, int]]:
    """`(content_hash, size, mtime_ns)` of a regular file, or None when it
    cannot be read. The hash is of the bytes; size and mtime are kept so a
    later check can skip the read when neither moved."""
    try:
        st = os.stat(path)
        if not os.path.isfile(path):
            return None
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()[:CONTENT_HASH_CHARS], int(st.st_size), int(st.st_mtime_ns)
    except (OSError, ValueError):
        return None


def scope_identities(files: Iterable[str]) -> list[tuple[str, str, int, int]]:
    """`(path, content_hash, size, mtime_ns)` for every readable file in
    `files`. Taken at campaign START, since that is the content the campaign
    examines; a file edited while the scan runs is recorded as it was read."""
    out = []
    for f in files:
        ident = file_identity(str(f))
        if ident is not None:
            out.append((str(f), *ident))
    return out


def record_coverage_files(db_path: str, run_id: str, campaign_target: str,
                          identities: Iterable[tuple[str, str, int, int]]) -> int:
    """Records which content a completed campaign covered. Returns rows
    written. Never raises: bookkeeping, like record_spend (INV-6)."""
    rows = [(str(run_id), str(campaign_target), str(p), str(h),
             int(s) if s is not None else None, int(m) if m is not None else None)
            for p, h, s, m in identities if p and h]
    if not db_path or not rows:
        return 0
    conn = None
    try:
        conn = _connect(db_path)
        with conn:
            _ensure_table(conn)
            conn.executemany(
                "INSERT INTO coverage_files (run_id, campaign_target, path, content_hash, size, mtime_ns) "
                "VALUES (?, ?, ?, ?, ?, ?)", rows)
        return len(rows)
    except (sqlite3.Error, OSError, TypeError, ValueError):
        return 0
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass


def _covered_identities(db_path: str, model: str = "", run_id: str = "") -> dict:
    """Every path with recorded content, mapped to the most recent identity
    `((content_hash, size | None, mtime_ns | None),)` it was covered as -- by
    this model and by unknown models when `model` is given (the rule
    _completed_coverage follows), by one run when `run_id` is given. `{}`
    when the ledger records no content.

    Only the latest recorded row per path counts: if a file was scanned at H1,
    fixed and scanned at H2, and later reverted back to H1, comparing against
    all historical hashes would treat the reverted bug as already covered.
    Raises when the ledger exists but cannot be read; callers decide what that
    means."""
    if not db_path or not os.path.exists(db_path):
        return {}
    conn = _connect(db_path)
    try:
        if not has_coverage_files_table(conn):
            return {}
        rows = _content_rows(conn, model, run_id)
    finally:
        conn.close()
    out: dict = {}
    for path, content_hash, size, mtime_ns, _run in rows:
        if path and content_hash:
            out[str(path)] = ((str(content_hash), size, mtime_ns),)
    return out


def _content_rows(conn: sqlite3.Connection, model: str = "", run_id: str = "") -> list:
    """`(path, content_hash, size, mtime_ns, run_id)` rows of coverage_files,
    oldest first (`ORDER BY id ASC`), under the same model rule as
    _completed_coverage."""
    if run_id:
        return conn.execute(
            "SELECT path, content_hash, size, mtime_ns, run_id FROM coverage_files "
            "WHERE run_id = ? ORDER BY id ASC",
            (str(run_id),)).fetchall()
    has_runs = model and conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'runs'").fetchone()
    if has_runs:
        return conn.execute(
            "SELECT c.path, c.content_hash, c.size, c.mtime_ns, c.run_id FROM coverage_files c "
            "LEFT JOIN runs r ON r.run_id = c.run_id "
            "WHERE r.model = ? OR r.model IS NULL OR r.model = '' ORDER BY c.id ASC",
            (str(model),)).fetchall()
    return conn.execute(
        "SELECT path, content_hash, size, mtime_ns, run_id FROM coverage_files ORDER BY id ASC"
    ).fetchall()


def _coverage_runs(db_path: str, model: str = "") -> tuple[dict, set]:
    """`(target -> run ids of completed campaigns over it, run ids that
    recorded content)`, under the model rule of _completed_coverage. Lets a
    reader tell a file that exists under a covered directory but was NOT
    there when the covering campaign ran: that campaign recorded content
    for its files and has none for this one. `({}, set())` when the ledger
    has no table; raises when it cannot be read."""
    if not db_path or not os.path.exists(db_path):
        return {}, set()
    conn = _connect(db_path)
    try:
        try:
            has_runs = model and conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'runs'").fetchone()
            if has_runs:
                rows = conn.execute(
                    "SELECT s.target, s.metadata_json, s.run_id FROM campaign_spend s "
                    "LEFT JOIN runs r ON r.run_id = s.run_id "
                    "WHERE s.target IS NOT NULL AND (r.model = ? OR r.model IS NULL OR r.model = '')",
                    (str(model),)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT target, metadata_json, run_id FROM campaign_spend WHERE target IS NOT NULL"
                ).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc).lower():
                return {}, set()
            raise
        recorded: set = set()
        if has_coverage_files_table(conn):
            recorded = {str(r[4]) for r in _content_rows(conn, model) if r[4]}
    finally:
        conn.close()
    targets: dict = {}
    for target, metadata_json, run in rows:
        t = str(target or "").rstrip("/")
        if t and run and not _row_failed(metadata_json):
            targets.setdefault(t, set()).add(str(run))
    return targets, recorded


def content_changed(path: str, identities: Iterable[tuple]) -> bool:
    """Whether `path` differs now from the most recent identity (`identities[-1]`)
    it was covered as.

    Size and mtime decide without reading when they both still match the
    recorded pair (the git-index rule); otherwise the file is hashed once.
    Comparing only against the latest record ensures a revert back to an
    older, previously scanned commit is seen as a change. A file that cannot
    be read now is not reported as changed -- it is not scannable either, and
    the caller's file list will not contain it.
    """
    ids = list(identities)
    if not ids:
        return False
    h, size, mtime_ns = ids[-1]
    try:
        st = os.stat(path)
    except OSError:
        return False
    if size is not None and mtime_ns is not None and int(size) == st.st_size and int(mtime_ns) == st.st_mtime_ns:
        return False
    ident = file_identity(path)
    if ident is None:
        return False
    return ident[0] != str(h)


def content_recorded_for(db_path: str, files, model: str = "") -> int:
    """How many of `files` the ledger holds content for (for this model).
    Zero on a ledger that predates content recording, which is how a caller
    tells "nothing changed" from "nothing is known". Never raises."""
    try:
        covered = _covered_identities(db_path, model)
    except Exception:
        return 0
    return sum(1 for f in files if str(f) in covered)


def changed_files(db_path: str, files, model: str = "", run_id: str = "") -> Optional[dict]:
    """`{"files": [...]}`: the subset of `files` whose content the ledger
    recorded (for this model, or for one run) and that differs now. None
    when the ledger cannot be read. Files with no recorded content are not
    changed -- they are covered or uncovered, which uncovered_files says."""
    if not db_path:
        return None
    try:
        covered = _covered_identities(db_path, model, run_id=run_id)
        if not covered:
            return {"files": []}
        return {"files": [str(f) for f in files if content_changed(str(f), covered.get(str(f), ()))]}
    except Exception:
        return None


def has_fingerprint_column(conn: sqlite3.Connection) -> bool:
    """Whether this ledger carries `harness_fingerprint`.

    Readers ask rather than migrate: uncovered_files and run_ledger are
    read-only probes that may run against a database this process must not
    write (a shared knowledge base, a read-only mount), so they select the
    column only where it exists and read NULL everywhere else.
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(campaign_spend)").fetchall()}
    return "harness_fingerprint" in cols


def _row_failed(metadata_json: Any) -> bool:
    try:
        meta = json.loads(metadata_json or "{}")
    except (TypeError, ValueError):
        return False
    return isinstance(meta, dict) and bool(meta.get("failed"))


def _completed_coverage(db_path: str, model: str = "") -> Optional[dict]:
    """Every target a completed campaign covered, mapped to the harness
    fingerprints of the rows that covered it (None for a row recorded before
    fingerprints existed, or imported from an export that did not carry one).

    Returns None when the ledger was never written -- no file, no table --
    which is a genuine first run. Raises when the ledger exists and cannot be
    read; the callers decide what an unreadable ledger means to them.

    With `model` given, only rows of that model and rows of no known model
    count, for the reasons uncovered_files gives.
    """
    if not os.path.exists(db_path):
        return None
    conn = _connect(db_path)
    try:
        try:
            fp_col = "s.harness_fingerprint" if has_fingerprint_column(conn) else "NULL"
            has_runs = model and conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'runs'").fetchone()
            if has_runs:
                # Rows of this model, and rows of no known model.
                rows = conn.execute(
                    f"SELECT s.target, s.metadata_json, {fp_col} FROM campaign_spend s "
                    "LEFT JOIN runs r ON r.run_id = s.run_id "
                    "WHERE s.target IS NOT NULL AND (r.model = ? OR r.model IS NULL OR r.model = '')",
                    (str(model),)
                ).fetchall()
            else:
                rows = conn.execute(
                    f"SELECT s.target, s.metadata_json, {fp_col} FROM campaign_spend s "
                    "WHERE s.target IS NOT NULL"
                ).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc).lower():
                return None  # Ledger never written: genuine first run.
            raise
    finally:
        conn.close()
    targets: dict = {}
    for target, metadata_json, fingerprint in rows:
        t = str(target or "").rstrip("/")
        if t and not _row_failed(metadata_json):
            targets.setdefault(t, set()).add(str(fingerprint) if fingerprint else None)
    return targets


def _covering_fingerprints(path: str, targets: dict) -> Optional[set]:
    """The fingerprints of every completed campaign whose target was `path`
    or an ancestor of it; None when nothing covered it.

    Walks UP the directory chain so each check is a set lookup. Comparing
    every file against every target is the quadratic nobody notices until
    chromium's 462,079 files meet a ledger with a few thousand rows. The whole
    chain is walked, not just to the first hit: a file covered by an old
    whole-repository campaign AND by a recent per-file one is covered by both
    harnesses, and the verdict below needs to know that.
    """
    found: Optional[set] = None
    probe = path.rstrip("/")
    while probe:
        if probe in targets:
            found = (found or set()) | targets[probe]
        parent = probe.rsplit("/", 1)[0] if "/" in probe else ""
        if parent == probe:
            break
        probe = parent
    return found


def coverage_verdict(fingerprints: Optional[set], current: str) -> str:
    """'uncovered', 'covered', or 'mismatched' -- covered only by campaigns
    that ran a different harness configuration.

    A row with no fingerprint always counts as covered: it predates the
    stamp, and turning the stamp on must not make an existing knowledge base
    re-sweep itself (INV-6). With no current fingerprint to compare against,
    every covering row counts, as it always did.
    """
    if fingerprints is None:
        return "uncovered"
    if not current or None in fingerprints or current in fingerprints:
        return "covered"
    return "mismatched"


def uncovered_files(
    db_path: str,
    files,
    model: str = "",
    harness_fingerprint: str = "",
    rescan_changed_harness: bool = False,
    rescan_changed_files: bool = True,
) -> Optional[list]:
    """The subset of `files` no recorded campaign has ever covered.

    With `model` given, covered means covered BY THAT MODEL: a file another
    model is known to have scanned is still uncovered for this one.
    Knowledge built by more than one model needs each to see every file,
    and the models differ in what they find. A campaign whose model is
    unknown (recorded before runs were, or imported from an export that
    did not say) counts as coverage for every model, as it always did:
    turning on provenance must not make an existing knowledge base re-sweep
    itself.

    With `harness_fingerprint` given, a file whose covering campaigns ALL
    carry a different, non-NULL fingerprint was examined by another harness
    configuration -- older tools, a weaker model, a previous prompt. By
    default it still counts as covered (the caller reports the count, see
    harness_mismatches, and the operator decides); with
    `rescan_changed_harness` it is uncovered and swept again. A row with no
    fingerprint covers the file for every harness, exactly as a row with no
    model covers it for every model (INV-6).

    A covered file whose CONTENT differs from the most recent version the
    ledger recorded it as (coverage_files; see changed_files) was not examined
    in its present form, and with `rescan_changed_files` -- the default --
    it is uncovered. So is a file under a covered directory that the
    covering campaign recorded no content for while recording it for its
    other files: it was not there when that campaign ran. A file the ledger
    recorded no content for because content was not being recorded (covered
    before this existed, or by an import that did not carry it) is covered
    as it always was (INV-6).

    A file counts as covered when some completed campaign's target was the
    file itself or an ancestor directory of it: scanning `repo/lib` covers
    everything under `lib`, and a whole-repository campaign covers the tree.
    Coverage is what this probe answers -- NOT "was this repository ever
    seen": a codebase whose `lib/` was scanned last month still has every
    file outside `lib/` uncovered, and skipping those silently is exactly
    the hole the caller uses this to close.

    A campaign that FAILED does not cover anything. Its row stays in the
    ledger (it ran the graph and cost real tokens, which the cost estimate
    wants to know), but a crashed scan looked at nothing a later run should
    trust; counting it would make `auto` skip the file forever and would let
    a change gate treat it as audited.

    Returns None when there is no ledger to consult or it cannot be read.
    The distinction is deliberate and load-bearing: a MISSING ledger (no
    file, no table) is a genuine first run and every file is uncovered, but
    an UNREADABLE one (corrupt, locked, permission-denied) is unknowable
    and returns None. The caller sweeps whatever this returns -- one
    campaign per file -- and a broken database must never be the reason a
    run becomes orders of magnitude larger than the operator expected.
    """
    if not db_path:
        return None  # No ledger to consult: coverage is unknowable.
    all_files = [str(f) for f in files]
    try:
        targets = _completed_coverage(db_path, model)
        if targets is None:
            return all_files  # Ledger never written: genuine first run.
        covered_as = _covered_identities(db_path, model) if rescan_changed_files else {}
        target_runs, recording_runs = _coverage_runs(db_path, model) if covered_as else ({}, set())
        current = str(harness_fingerprint or "")
        out = []
        for path in all_files:
            verdict = coverage_verdict(_covering_fingerprints(path, targets), current)
            if verdict == "uncovered" or (verdict == "mismatched" and rescan_changed_harness):
                out.append(path)
            elif covered_as:
                ids = covered_as.get(path)
                if ids:
                    if content_changed(path, ids):
                        out.append(path)
                elif recording_runs:
                    # Covered only by campaigns that recorded content, and
                    # none recorded this file: it did not exist then. If any
                    # covering campaign predates content recording nothing
                    # can be told, and the file is covered (INV-6).
                    covering = _covering_fingerprints(path, target_runs) or set()
                    if covering and covering <= recording_runs:
                        out.append(path)
        return out
    except Exception:
        return None


def harness_mismatches(
    db_path: str,
    files,
    model: str = "",
    harness_fingerprint: str = "",
) -> Optional[dict]:
    """The files in `files` that count as covered ONLY because a different
    harness configuration examined them, as
    `{"files": [...], "fingerprints": {other_fingerprint: file_count}}`.

    These are exactly the files uncovered_files() would add under
    `rescan_changed_harness`; the caller states the count once per run so
    the operator can decide whether the upgrade is worth re-examining them.
    Same model scoping and NULL-fingerprint rule as uncovered_files.

    Returns None when there is nothing to compare -- no ledger path, no
    current fingerprint -- or the ledger cannot be read. Never raises.
    """
    if not db_path or not harness_fingerprint:
        return None
    all_files = [str(f) for f in files]
    try:
        targets = _completed_coverage(db_path, model)
        out: dict = {"files": [], "fingerprints": {}}
        if targets is None:
            return out  # Ledger never written: nothing was covered by anyone.
        current = str(harness_fingerprint)
        for path in all_files:
            covering = _covering_fingerprints(path, targets)
            if coverage_verdict(covering, current) != "mismatched":
                continue
            out["files"].append(path)
            for fp in sorted(covering or ()):
                out["fingerprints"][fp] = out["fingerprints"].get(fp, 0) + 1
        return out
    except Exception:
        return None


def run_ledger(db_path: str, run_id: str) -> Optional[dict]:
    """What one run's campaigns did, as
    `{target: {"failed": bool, "harness_fingerprint": str | None}}`, the
    latest row per target winning (a retried campaign supersedes its failure).
    The fingerprint is None for rows recorded before the stamp existed.

    Returns None when the ledger cannot be read, `{}` when the run has no
    rows: a run that paused inside its first campaign recorded nothing, and
    resuming it means scanning everything, which is what an empty answer
    tells the caller. Never raises.
    """
    if not db_path or not run_id:
        return None
    try:
        if not os.path.exists(db_path):
            return {}
        conn = _connect(db_path)
        try:
            try:
                fp_col = "harness_fingerprint" if has_fingerprint_column(conn) else "NULL"
                rows = conn.execute(
                    f"SELECT target, metadata_json, {fp_col} FROM campaign_spend "
                    "WHERE run_id = ? AND target IS NOT NULL ORDER BY id ASC",
                    (str(run_id),),
                ).fetchall()
            except sqlite3.OperationalError as exc:
                if "no such table" in str(exc).lower():
                    return {}
                raise
        finally:
            conn.close()
        out: dict = {}
        for target, metadata_json, fingerprint in rows:
            t = str(target or "").rstrip("/")
            if t:
                out[t] = {
                    "failed": _row_failed(metadata_json),
                    "harness_fingerprint": str(fingerprint) if fingerprint else None,
                }
        return out
    except Exception:
        return None


def record_run_scan_mode(db_path: str, run_id: str, scan_mode: str) -> bool:
    """Records the resolved scan mode on the `runs` row (`metadata_json`) if not
    already set, so a run that pauses inside its very first campaign (before any
    `campaign_spend` row is written) still knows its mode on `--resume`. Never
    raises (INV-6)."""
    if not db_path or not run_id or not scan_mode or not os.path.exists(db_path):
        return False
    conn = None
    try:
        conn = _connect(db_path)
        with conn:
            has_runs = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'runs'"
            ).fetchone()
            if not has_runs:
                return False
            row = conn.execute(
                "SELECT metadata_json FROM runs WHERE run_id = ?",
                (str(run_id),),
            ).fetchone()
            if row is None:
                return False
            try:
                meta = json.loads(row[0] or "{}")
                if not isinstance(meta, dict):
                    meta = {}
            except ValueError:
                meta = {}
            if meta.get("scan_mode"):
                return True
            meta["scan_mode"] = str(scan_mode)
            conn.execute(
                "UPDATE runs SET metadata_json = ? WHERE run_id = ?",
                (json.dumps(meta), str(run_id)),
            )
        return True
    except (sqlite3.Error, OSError, TypeError, ValueError):
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass


def run_scan_mode(db_path: str, run_id: str) -> str:
    """The scan mode a run's campaigns were recorded under, '' if unknown.

    Checks `campaign_spend` first (latest row wins), falling back to
    `runs.metadata_json` for a run that paused inside its first campaign before
    any spend row was written. A resumed run must plan the way the original
    did: a file-by-file sweep picked up without the flag would otherwise be
    re-resolved as `auto`, which plans one whole-target campaign for a small
    directory and so reruns the wrong thing. Never raises.
    """
    if not db_path or not run_id:
        return ""
    try:
        if not os.path.exists(db_path):
            return ""
        conn = _connect(db_path)
        try:
            try:
                row = conn.execute(
                    "SELECT scan_mode FROM campaign_spend WHERE run_id = ? "
                    "AND scan_mode IS NOT NULL AND scan_mode != '' ORDER BY id DESC LIMIT 1",
                    (str(run_id),),
                ).fetchone()
                if row and row[0]:
                    return str(row[0])
            except sqlite3.OperationalError:
                pass
            try:
                rrow = conn.execute(
                    "SELECT metadata_json FROM runs WHERE run_id = ?",
                    (str(run_id),),
                ).fetchone()
                if rrow and rrow[0]:
                    meta = json.loads(rrow[0])
                    if isinstance(meta, dict) and meta.get("scan_mode"):
                        return str(meta["scan_mode"])
            except (sqlite3.OperationalError, ValueError):
                pass
        finally:
            conn.close()
        return ""
    except Exception:
        return ""


def latest_run_id(db_path: str, target: str = "") -> str:
    """The most recent run recorded in this database, preferring runs whose
    ledger rows fall under `target` so `--resume` in one repository does not
    pick up a run over another. Falls back to the findings table for a run
    that never completed a campaign. '' when there is nothing to resume.
    Never raises.
    """
    if not db_path or not os.path.exists(db_path):
        return ""
    root = os.path.realpath(target) if target else ""
    try:
        conn = _connect(db_path)
        try:
            candidates: list = []
            for sql in (
                "SELECT run_id, target, MAX(timestamp) AS ts FROM campaign_spend "
                "WHERE run_id IS NOT NULL AND run_id != '' GROUP BY run_id",
                "SELECT run_id, '' AS target, MAX(timestamp) AS ts FROM findings "
                "WHERE run_id IS NOT NULL AND run_id != '' GROUP BY run_id",
            ):
                try:
                    candidates += [tuple(r) for r in conn.execute(sql).fetchall()]
                except sqlite3.OperationalError:
                    continue
        finally:
            conn.close()
    except Exception:
        return ""
    if not candidates:
        return ""

    def under_root(t: str) -> bool:
        if not root or not t:
            return not root
        try:
            rt = os.path.realpath(t)
            return rt == root or os.path.commonpath([rt, root]) == root
        except (ValueError, OSError):
            return False

    scoped = [c for c in candidates if under_root(str(c[1] or ""))] or candidates
    scoped.sort(key=lambda c: str(c[2] or ""), reverse=True)
    return str(scoped[0][0])


def record_spend(
    db_path: str,
    run_id: str,
    target: str,
    scan_mode: str,
    tokens: int,
    llm_calls: int = 0,
    graph_steps: int = 0,
    elapsed_seconds: float = 0.0,
    metadata: Optional[dict] = None,
    harness_fingerprint: str = "",
) -> bool:
    """Records what one campaign actually cost. Returns True if stored.

    `harness_fingerprint` names the configuration that ran the campaign
    (core.graph_loader.compute_harness_fingerprint), so a later run can tell
    whether "covered" means covered by the harness it is about to run. Empty
    is stored as NULL -- unknown -- which every reader treats as covering
    for any harness, the same way a row with no model covers for any model.

    Never raises. This is bookkeeping: a scan that found a real vulnerability
    must not fail because the accounting table was unwritable (INV-6).
    """
    if not db_path or tokens is None:
        return False
    conn = None
    try:
        # closing(), not a bare `with`: sqlite3's connection context manager is a
        # TRANSACTION manager that commits or rolls back and leaves the handle open.
        # One leaked descriptor per campaign is 462,079 of them on a chromium sweep.
        conn = _connect(db_path)
        with conn:
            _ensure_table(conn)
            conn.execute(
                """
                INSERT INTO campaign_spend
                    (run_id, target, scan_mode, tokens, llm_calls, graph_steps,
                     elapsed_seconds, metadata_json, harness_fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(run_id),
                    str(target),
                    str(scan_mode),
                    int(tokens),
                    int(llm_calls or 0),
                    int(graph_steps or 0),
                    float(elapsed_seconds or 0.0),
                    json.dumps(metadata or {}),
                    str(harness_fingerprint) if harness_fingerprint else None,
                ),
            )
        return True
    except (sqlite3.Error, OSError, TypeError, ValueError):
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass


def observed_campaign_cost(
    db_path: str, scan_mode: str = "", limit: int = 200
) -> tuple[Optional[int], int]:
    """Mean observed cost of a campaign, as `(tokens, n_observations)`.

    Returns `(None, 0)` when there is nothing credible to average, which is the
    signal to fall back to the seed. Never raises.

    Prefers observations from the SAME scan mode: a file-by-file campaign reads
    one file and a cross-functional campaign ranges over a subsystem, so their
    costs are not drawn from the same population. Falls back to all modes rather
    than to the seed, since a real number from a different mode still beats a
    guess.
    """
    rows: list[Any] = []
    conn = None
    try:
        conn = _connect(db_path)
        with conn:
            _ensure_table(conn)
            cur = conn.cursor()
            # `tokens > 0` is stated alongside the credibility floor, not left to
            # it: multi-target campaigns stamp member coverage as zero-token
            # ledger rows (metadata member_of) purely so uncovered_files() sees
            # them covered. Those rows are bookkeeping, not observations --
            # averaging them in would drag the observed campaign cost toward
            # zero and inflate every affordability estimate. The floor happens
            # to exclude them today, but it is a tunable credibility threshold,
            # and the member-stamp exclusion must not depend on its value.
            if scan_mode:
                cur.execute(
                    "SELECT tokens FROM campaign_spend WHERE scan_mode = ? "
                    "AND tokens > 0 AND tokens >= ? "
                    "ORDER BY id DESC LIMIT ?",
                    (str(scan_mode), _MIN_CREDIBLE_OBSERVATION, int(limit)),
                )
                rows = [r[0] for r in cur.fetchall()]
            if not rows:
                cur.execute(
                    "SELECT tokens FROM campaign_spend WHERE tokens > 0 AND tokens >= ? "
                    "ORDER BY id DESC LIMIT ?",
                    (_MIN_CREDIBLE_OBSERVATION, int(limit)),
                )
                rows = [r[0] for r in cur.fetchall()]
    except (sqlite3.Error, OSError, TypeError, ValueError):
        return (None, 0)
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass

    clean = [
        int(r)
        for r in rows
        if isinstance(r, (int, float)) and r > 0 and r >= _MIN_CREDIBLE_OBSERVATION
    ]
    if not clean:
        return (None, 0)
    return (int(sum(clean) / len(clean)), len(clean))


def estimate_file_tokens(path: str) -> int:
    """Token estimate for a file's contents. 0 if it cannot be sized."""
    try:
        import os

        return int(os.path.getsize(path) // _CHARS_PER_TOKEN)
    except (OSError, TypeError, ValueError):
        return 0


def estimate_scan(
    targets: list[str],
    max_tokens: int,
    db_path: str = "",
    scan_mode: str = "",
) -> ScanEstimate:
    """Estimates how much of `targets` the token budget covers.

    Never raises: a broken estimate must not cost the scan, so every failure path
    degrades to the seeded cost with `basis="seeded"`.

    `max_tokens` is the WHOLE-RUN ceiling. A resumed run starts from zero by
    design, so this describes one process's worth of budget -- which is exactly
    what the operator is deciding about at the moment it is printed.
    """
    planned = len(targets or [])

    observed, n_obs = (None, 0)
    if db_path:
        observed, n_obs = observed_campaign_cost(db_path, scan_mode)

    if observed and observed > 0:
        cost, basis = int(observed), "observed"
    else:
        cost, basis = DEFAULT_CAMPAIGN_TOKENS, "seeded"

    try:
        spendable = int(max(0, int(max_tokens)) * _CAMPAIGN_BUDGET_RATIO)
    except (TypeError, ValueError):
        spendable = 0

    # A ceiling of 0 means the token budget is DISABLED, not that nothing is
    # affordable: without this, `spendable // cost` reads an unlimited budget
    # as "covers ~0 campaigns" -- the exact opposite of what the operator said.
    unbounded = False
    try:
        unbounded = int(max_tokens) <= 0
    except (TypeError, ValueError):
        pass

    # Name the files big enough to distort their own campaign. Rare, but at the
    # extreme a single file is half the default budget, and an operator who is
    # told "200 campaigns" deserves to know one of them is a 20 MB generated blob.
    oversized: list[str] = []
    threshold = cost * _OVERSIZED_FILE_RATIO
    for t in (targets or []):
        ft = estimate_file_tokens(t)
        if ft > threshold:
            oversized.append(t)
        if len(oversized) >= 10:
            break

    if unbounded:
        affordable = planned
    else:
        affordable = spendable // cost if cost > 0 else planned
    return ScanEstimate(
        planned_campaigns=planned,
        affordable_campaigns=int(affordable),
        cost_per_campaign=int(cost),
        spendable_tokens=int(spendable),
        basis=basis,
        observations=int(n_obs),
        oversized=oversized,
    )


# --- Backfilling the content ledger ------------------------------------------------------
#
# Databases from before coverage_files existed hold completed campaigns with
# no record of the content they examined, so a `changed` run cannot tell
# what moved and scans the whole target once to find out. The operator who
# paid for those campaigns should not pay again: the ledger can be filled
# in after the fact, from what the files were when the campaign ran.
#
# What a file was then is known three ways, in order of trust: the commit
# the run recorded (snapshot_id on its artifacts), a commit the operator
# names (--at), or the working tree as it is now (--assume-unchanged: the
# operator asserts nothing was edited since). A commit's content is hashed
# from git, never from the tree, so an edit made since is seen as a change.

_COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")


def run_snapshot_ids(db_path: str) -> dict:
    """`{run_id: snapshot_id}` from the artifacts each run recorded, for runs
    that recorded one. {} when the database has none or cannot be read."""
    if not db_path or not os.path.exists(db_path):
        return {}
    out: dict = {}
    conn = None
    try:
        conn = _connect(db_path)
        rows = conn.execute(
            "SELECT run_id, metadata_json FROM campaign_artifacts WHERE metadata_json LIKE '%snapshot_id%'"
        ).fetchall()
    except sqlite3.Error:
        return {}
    finally:
        if conn is not None:
            conn.close()
    for run_id, meta_json in rows:
        if run_id in out:
            continue
        try:
            meta = json.loads(meta_json or "{}")
        except (TypeError, ValueError):
            continue
        snap = str((meta or {}).get("snapshot_id") or "").strip()
        if snap and _COMMIT_RE.match(snap):
            out[str(run_id)] = snap
    return out


def git_blob_identities(repo_root: str, commit: str, rel_paths: Iterable[str]) -> dict:
    """`{rel_path: (content_hash, size, None)}` for the files that exist at
    `commit`, hashed the way file_identity hashes the working tree (the
    content ledger's own rule), with no mtime: a later check hashes rather
    than trusting a timestamp. Files absent at the commit are left out.
    {} when git is unavailable or the commit unknown. Never raises."""
    import subprocess

    rels = [str(p).replace(os.sep, "/") for p in rel_paths if str(p).strip()]
    if not rels:
        return {}
    try:
        subprocess.run(["git", "-C", repo_root, "cat-file", "-e", f"{commit}^{{commit}}"],
                       check=True, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return {}
    out: dict = {}
    try:
        proc = subprocess.run(
            ["git", "-C", repo_root, "cat-file", "--batch"],
            input="".join(f"{commit}:{rel}\n" for rel in rels).encode("utf-8"),
            capture_output=True, timeout=600,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    data = proc.stdout
    pos = 0
    for rel in rels:
        nl = data.find(b"\n", pos)
        if nl < 0:
            break
        header = data[pos:nl].decode("utf-8", errors="replace")
        pos = nl + 1
        fields = header.split()
        if len(fields) == 3 and fields[1] == "blob":
            size = int(fields[2])
            blob = data[pos:pos + size]
            pos += size + 1  # the trailing newline git adds after each object
            out[rel] = (hashlib.sha256(blob).hexdigest()[:CONTENT_HASH_CHARS], size, None)
        # "<spec> missing" (or a non-blob): absent at this commit; nothing to skip
    return out


def backfill_coverage(db_path: str, target_root: str, discovered_files: Iterable[str],
                      at: Optional[str] = None, assume_unchanged: bool = False,
                      dry_run: bool = False) -> dict:
    """Writes coverage_files rows for every completed campaign under
    `target_root` that has none, from the content its files had when it
    ran. Returns a summary: {"backfilled": [(run_id, target, files, source)],
    "skipped": [(run_id, target, reason)], "rows": n}. Never raises on a
    campaign; a campaign whose content cannot be established is skipped
    with the reason, so the operator can supply --at or decide the tree is
    unchanged. Campaigns that already have content rows are left alone.

    `discovered_files` is the target's source file list (main.discover_files
    with the operator's excludes): a directory campaign covered what that
    list holds under it, as the scan loop records.
    """
    summary: dict = {"backfilled": [], "skipped": [], "rows": 0}
    if not db_path or not os.path.exists(db_path):
        summary["skipped"].append(("", "", "no database"))
        return summary
    root = os.path.realpath(str(target_root))
    files = [os.path.realpath(str(f)) for f in discovered_files or []]
    under_root = [f for f in files if f == root or f.startswith(root + os.sep)]
    snapshots = run_snapshot_ids(db_path)

    conn = _connect(db_path)
    try:
        _ensure_table(conn)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(campaign_spend)").fetchall()}
        if not cols:
            return summary
        rows = conn.execute("SELECT run_id, target, metadata_json FROM campaign_spend ORDER BY id").fetchall()
        have_content = {(str(r[0]), str(r[1])) for r in conn.execute(
            "SELECT DISTINCT run_id, campaign_target FROM coverage_files").fetchall()}
    finally:
        conn.close()

    seen: set = set()
    for run_id, target, meta in rows:
        key = (str(run_id), str(target))
        if key in seen:
            continue
        seen.add(key)
        if _row_failed(meta):
            continue
        real_target = os.path.realpath(str(target))
        if real_target != root and not real_target.startswith(root + os.sep):
            continue
        if key in have_content:
            summary["skipped"].append((run_id, target, "already has content rows"))
            continue
        if os.path.isfile(real_target):
            scope = [real_target]
        else:
            prefix = real_target.rstrip(os.sep) + os.sep
            scope = [f for f in under_root if f.startswith(prefix)]
        if not scope:
            summary["skipped"].append((run_id, target, "no source files under the target now"))
            continue
        rels = [os.path.relpath(f, root) for f in scope]
        commit = str(at or "").strip() or snapshots.get(str(run_id), "")
        identities: list = []
        if commit:
            blobs = git_blob_identities(root, commit, rels)
            if not blobs:
                summary["skipped"].append((run_id, target, f"commit {commit[:12]} not readable from git here"))
                continue
            for f, rel in zip(scope, rels):
                ident = blobs.get(rel.replace(os.sep, "/"))
                if ident is not None:
                    identities.append((f, *ident))
            source = f"commit {commit[:12]}"
        elif assume_unchanged:
            identities = scope_identities(scope)
            source = "working tree (asserted unchanged)"
        else:
            summary["skipped"].append((run_id, target, "no recorded commit; pass --at <commit> or --assume-unchanged"))
            continue
        if not identities:
            summary["skipped"].append((run_id, target, f"none of its files exist at {source}"))
            continue
        if not dry_run:
            summary["rows"] += record_coverage_files(db_path, run_id, target, identities)
        summary["backfilled"].append((run_id, target, len(identities), source))
    return summary

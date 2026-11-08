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

"""Persistent hypothesis-chain ledger for the dynamic planner.

WHAT THIS IS FOR
    A multi-component vulnerability is a claim of the shape "component A trusts
    B's output; B's validation is weak; still needed: reachability from the
    edge". No single campaign settles that claim, and the campaigns that do are
    frequently weeks apart. This module stores those planner-authored
    hypotheses as CHAINS of LINKS in the knowledge database (the
    `hypothesis_chains` table created by `database.init_db`), so a chain opened
    in one run is loaded, extended and eventually settled by later runs. Load
    is deliberately cross-run: `load_open_chains` reads open chains from ALL
    runs, because cross-session continuity is the point.

    Links are settled deterministically -- no LLM touches the verdict.
    `update_chain_from_campaign` compares a finished campaign's target paths
    and findings count against each link's named components and flips link
    status by fixed rules (documented on the function). The planner writes the
    hypothesis; the campaign record confirms or refutes it.

TRUST POSTURE
    Every string in a chain originated from an LLM and then sat in a database
    that earlier (possibly prompt-injected) runs could write. Chain content is
    therefore UNTRUSTED both on the way in and -- because the DB itself is a
    stored-payload vector -- on the way out: every string is length-capped and
    stripped of terminal control sequences at both boundaries, and nothing in
    a chain is ever interpreted as an instruction, a path to open, or a
    capability. Chains direct attention, exactly like recall in `core.memory`;
    they never widen tools, sandbox, or trust.

DEGRADATION (INV-6)
    Nothing here may raise into the scan loop. Every reader tolerates a
    missing file, missing table, or corrupt row by returning empty; every
    writer tolerates failure by doing nothing. A broken chain ledger costs the
    planner a hint; it must never cost the scan.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional


def _shared_connect(db_path: str) -> sqlite3.Connection:
    """Knowledge-database connection with the shared busy timeout and journal
    settings (core.database.connect); imported lazily to keep module import
    order free of cycles."""
    from core.database import connect

    return connect(db_path)

# SECURITY (INV-4): database paths are anchored and symlink-refused before they
# are opened. If the resolver cannot be imported, this module fails CLOSED --
# every function becomes a no-op -- rather than opening an unanchored path.
try:
    from core.paths import resolve_db_path as _resolve_db_path
except Exception:  # pragma: no cover - packaging failure degrades to no-op
    _resolve_db_path = None

# Chain strings are untrusted LLM output; strip terminal control sequences with
# the gateway's shared sanitizer. The regex fallback keeps the trust posture
# intact even if the gateway cannot be imported: control characters are removed
# either way, tab and newline survive.
try:
    from core.llm_gateway import strip_terminal_control as _strip_ctl
except Exception:  # pragma: no cover - fallback keeps sanitization fail-safe
    _FALLBACK_CTL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

    def _strip_ctl(text: str) -> str:
        return _FALLBACK_CTL_RE.sub("", str(text or ""))


# Bounds. A chain is a hint for a planner, not an archive: caps keep a hostile
# or runaway writer from growing a row without limit, and keep sanitized output
# small enough that recall never evicts the code under review.
_MAX_FIELD_CHARS = 500
_MAX_LINKS = 20
_MAX_EVIDENCE = 50
_MAX_MEMBER_PATHS = 200

_LINK_FIELDS = ("source_component", "sink_component", "claim")
_LINK_STATUSES = ("open", "supported", "refuted")
_CHAIN_STATUSES = ("open", "confirmed", "refuted")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean(value, limit: int = _MAX_FIELD_CHARS) -> str:
    """Sanitizes one untrusted string: control chars stripped, length capped.

    Applied at BOTH boundaries (write and read), never raises. Order matters:
    control sequences are removed before the cap so truncation cannot leave a
    half-stripped escape introducer at the cut.
    """
    try:
        s = _strip_ctl(str(value if value is not None else ""))
    except Exception:
        return ""
    s = s.strip()
    if len(s) > limit:
        s = s[:limit]
    return s


def _clean_link(raw) -> Optional[dict]:
    """One sanitized link dict from untrusted input, or None if not a dict.

    Unknown keys are dropped rather than carried: a link is exactly its two
    component names, its claim, and its status, and anything else a model or a
    tampered row adds has no reader and therefore no business persisting.
    """
    if not isinstance(raw, dict):
        return None
    link = {k: _clean(raw.get(k)) for k in _LINK_FIELDS}
    status = _clean(raw.get("status"), 32).lower()
    link["status"] = status if status in _LINK_STATUSES else "open"
    return link


def _connect(db_path: str, must_exist: bool = False) -> Optional[sqlite3.Connection]:
    """Opens the ledger, or returns None when it safely cannot.

    `must_exist` is set by readers and by the updater: neither has any business
    creating an empty database file as a side effect of finding nothing.
    """
    if not db_path or _resolve_db_path is None:
        return None
    resolved = _resolve_db_path(db_path)  # raises to the caller's catch-all
    if must_exist and not os.path.exists(resolved):
        return None
    return _shared_connect(resolved)


def _ensure_table(conn: sqlite3.Connection) -> None:
    """Creates the chain table when writing into a DB whose init_db predates it.

    Same shape as database.init_db, IF NOT EXISTS -- a knowledge base built by
    an older build must gain the ledger on first write, not error on it.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS hypothesis_chains (
            chain_id TEXT PRIMARY KEY,
            run_id TEXT,
            created_at TEXT,
            updated_at TEXT,
            description TEXT,
            links TEXT,
            status TEXT DEFAULT 'open',
            evidence TEXT
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_hypothesis_chains_status ON hypothesis_chains(status)"
    )


def _component_touches(component: str, path: str) -> bool:
    """Whether a campaign path plausibly covers a link component.

    Case-insensitive, both directions: the component appears in the path, or
    the path's basename appears in the component. Deliberately looser than the
    component-boundary matching in core.memory: a link names a COMPONENT the
    planner described in prose ("the upload handler", "auth.py"), not a
    validated path, and a missed match here only delays settling a link --
    which is the safe direction (see update_chain_from_campaign).
    Empty strings never match anything.
    """
    c = str(component or "").strip().lower()
    p = str(path or "").strip().lower().replace("\\", "/")
    if not c or not p:
        return False
    if c in p:
        return True
    base = posixpath.basename(p.rstrip("/"))
    return bool(base) and base in c


def open_chains(db_path: str, run_id: str, groups: list[dict]) -> dict[int, str]:
    """Persists the chain hypotheses attached to campaign groups.

    For each group whose `chain` key holds `{description, links: [{
    source_component, sink_component, claim}]}`, inserts one open chain row:
    fresh uuid4 chain_id, every link stamped with per-link status 'open',
    empty evidence, ISO timestamps. Every string is sanitized on the way IN
    (length-capped, control-stripped) -- the row will be read back by a later
    session and must already be inert at rest.

    Returns {group_index: chain_id} for the groups that got chains. A
    malformed group is skipped, not fatal (partial results are acceptable);
    any ledger-level failure returns {}. Never raises (INV-6).
    """
    out: dict[int, str] = {}
    conn = None
    try:
        conn = _connect(db_path)
        if conn is None:
            return {}
        # `with conn`, not bare execute: sqlite3's connection context manager is
        # a TRANSACTION manager (commit/rollback); the handle is closed below.
        with conn:
            _ensure_table(conn)
            now = _now_iso()
            for idx, group in enumerate(groups or []):
                try:
                    if not isinstance(group, dict):
                        continue
                    chain = group.get("chain")
                    if not isinstance(chain, dict):
                        continue
                    raw_links = chain.get("links")
                    if not isinstance(raw_links, list):
                        continue
                    links = []
                    for raw_link in raw_links[:_MAX_LINKS]:
                        link = _clean_link(raw_link)
                        if link is None:
                            continue
                        if not link["source_component"] and not link["sink_component"]:
                            # No component names -> no campaign path can ever
                            # touch this link, so it could never be settled.
                            continue
                        link["status"] = "open"  # a new hypothesis starts unsettled
                        links.append(link)
                    if not links:
                        continue  # a chain with no links can never be settled
                    chain_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO hypothesis_chains
                            (chain_id, run_id, created_at, updated_at,
                             description, links, status, evidence)
                        VALUES (?, ?, ?, ?, ?, ?, 'open', '[]')
                        """,
                        (
                            chain_id,
                            _clean(run_id, 128),
                            now,
                            now,
                            _clean(chain.get("description")),
                            json.dumps(links),
                        ),
                    )
                    out[idx] = chain_id
                except Exception:
                    continue  # this group's chain is lost; the others are not
        return out
    except Exception:
        return {}
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass


def load_open_chains(db_path: str, limit: int = 20) -> list[dict]:
    """Open chains from ALL runs, newest activity first.

    Cross-run on purpose: the ledger exists precisely so a chain opened weeks
    ago reaches the planner deciding today. Each returned dict is
    {chain_id, description, links: list[dict], status}, and every string is
    sanitized on the way OUT as well -- the DB is a stored-payload vector, and
    a row written by an older build or a tampered process must come out just
    as inert as one this module wrote.

    Missing file, missing table, or unreadable ledger -> []. A single corrupt
    row is skipped rather than failing the read. Never raises (INV-6).
    """
    try:
        lim = max(1, min(int(limit), 100))
    except (TypeError, ValueError):
        lim = 20
    rows: list = []
    conn = None
    try:
        conn = _connect(db_path, must_exist=True)
        if conn is None:
            return []
        rows = conn.execute(
            "SELECT chain_id, description, links, status FROM hypothesis_chains "
            "WHERE status = 'open' ORDER BY updated_at DESC, rowid DESC LIMIT ?",
            (lim,),
        ).fetchall()
    except Exception:
        return []
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass

    out: list[dict] = []
    for row in rows:
        try:
            parsed = json.loads(row[2] or "[]")
            if not isinstance(parsed, list):
                continue
            links = []
            for raw_link in parsed[:_MAX_LINKS]:
                link = _clean_link(raw_link)
                if link is not None:
                    links.append(link)
            status = _clean(row[3], 32).lower()
            out.append(
                {
                    "chain_id": _clean(row[0], 64),
                    "description": _clean(row[1]),
                    "links": links,
                    "status": status if status in _CHAIN_STATUSES else "open",
                }
            )
        except Exception:
            continue  # one corrupt row must not cost the rest
    return out


def update_chain_from_campaign(
    db_path: str, chain_id: str, campaign_route: str, findings_summary: dict
) -> None:
    """Settles chain links against one finished campaign. Deterministic, no LLM.

    A link is TOUCHED when the campaign's target path (or any 'members' path)
    matches its source or sink component per `_component_touches`. Then:

      * kept/valid findings (`findings_summary['findings']` > 0) -> touched
        links become 'supported';
      * `campaign_route == 'dismissal'` AND zero findings -> touched links
        become 'refuted' (a link already 'supported' by earlier evidence is
        not downgraded);
      * chain status: all links 'supported' -> 'confirmed'; all 'refuted' ->
        'refuted'; anything else stays 'open'.

    The asymmetry is deliberate. Supporting evidence needs actual findings;
    refutation needs BOTH an explicit dismissal route AND zero findings -- a
    campaign that merely never looked at a link (untouched, or routed anywhere
    but dismissal) must never refute it. The fail direction follows: chains
    err toward staying open, because wrongly closing a chain hides a real
    multi-system bug forever, while wrongly leaving one open only costs a
    future campaign.

    Appends an evidence entry {target, route, findings, ts}, capped at the
    most recent 50, and refreshes updated_at. Any failure -> silently does
    nothing. Never raises (INV-6).
    """
    conn = None
    try:
        cid = _clean(chain_id, 64)
        if not cid:
            return None
        summary = findings_summary if isinstance(findings_summary, dict) else {}
        raw_findings = summary.get("findings")
        if isinstance(raw_findings, dict):
            from core.database import is_suppressed

            findings_n = 0
            for st, cnt in raw_findings.items():
                if is_suppressed(st):
                    continue
                try:
                    findings_n += max(0, int(cnt or 0))
                except (TypeError, ValueError):
                    continue
        else:
            try:
                findings_n = max(0, int(raw_findings or 0))
            except (TypeError, ValueError):
                findings_n = 0
        route = _clean(campaign_route, 64).lower()
        paths = [_clean(summary.get("target"))]
        members = summary.get("members")
        if isinstance(members, list):
            for member in members[:_MAX_MEMBER_PATHS]:
                paths.append(_clean(member))
        paths = [p for p in paths if p]

        conn = _connect(db_path, must_exist=True)
        if conn is None:
            return None
        with conn:
            row = conn.execute(
                "SELECT links, evidence FROM hypothesis_chains WHERE chain_id = ?",
                (cid,),
            ).fetchone()
            if row is None:
                return None

            # Re-sanitize on load: this row is as untrusted as any other read.
            try:
                raw_links = json.loads(row[0] or "[]")
            except (TypeError, ValueError):
                raw_links = []
            if not isinstance(raw_links, list):
                raw_links = []
            links = []
            for raw_link in raw_links[:_MAX_LINKS]:
                link = _clean_link(raw_link)
                if link is not None:
                    links.append(link)

            for link in links:
                touched = any(
                    _component_touches(link[field], path)
                    for field in ("source_component", "sink_component")
                    for path in paths
                )
                if not touched:
                    continue
                if findings_n > 0:
                    link["status"] = "supported"
                elif route == "dismissal" and link["status"] != "supported":
                    link["status"] = "refuted"

            if links and all(l["status"] == "supported" for l in links):
                status = "confirmed"
            elif links and all(l["status"] == "refuted" for l in links):
                status = "refuted"
            else:
                status = "open"

            try:
                evidence = json.loads(row[1] or "[]")
            except (TypeError, ValueError):
                evidence = []
            if not isinstance(evidence, list):
                evidence = []
            now = _now_iso()
            evidence.append(
                {
                    "target": paths[0] if paths else "",
                    "route": route,
                    "findings": findings_n,
                    "ts": now,
                }
            )
            evidence = evidence[-_MAX_EVIDENCE:]

            conn.execute(
                "UPDATE hypothesis_chains SET links = ?, evidence = ?, status = ?, "
                "updated_at = ? WHERE chain_id = ?",
                (json.dumps(links), json.dumps(evidence), status, now, cid),
            )
    except Exception:
        return None  # bookkeeping must never cost the scan (INV-6)
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass
    return None

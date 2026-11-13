#!/usr/bin/env python3
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

"""Mantis MCP server: a secure development loop over stdio.

Exposes Mantis's deterministic knowledge -- the tree-sitter structural
index, the persistent findings database, and threat-model-informed security
guidance -- as MCP tools a coding agent calls while editing, plus a
budget-capped scoped scan that runs the full Mantis pipeline over a change
set in the background. The intended loop: edit, call mantis_check_change on
the diff, fix or verify what it raises, and let mantis_scan_change audit
the touched files in parallel; the next check_change sees whatever the scan
found, because both read the same per-repository knowledge database.

Design rules, in force everywhere in this file:

- The server NEVER calls an LLM. Tier-1 tools are deterministic reads over
  the catalog and the findings database; the Tier-2 scan spawns the
  existing pipeline (main.py) as a subprocess that owns its own budget.
- The gate fails CLOSED. A missing index, a missing database, or a file no
  scan has ever covered yields REVIEW with instructions -- never PASS. PASS
  means "every check ran and nothing known intersects this change", not
  "secure".
- Nothing writes into the repository, ever: state lives in a per-repository
  directory outside it (see MantisState), and read-only
  tools write nothing at all: sqlite3.connect() creates files, so every
  read path checks existence before opening.
"""
from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

# Finding statuses that still demand attention. Lowercased for comparison:
# the database folds status casing at the door, but older rows may predate
# that. patch_verified is deliberately absent -- a verified fix is closed.
OPEN_FINDING_STATUSES = {
    "reported",
    "confirmed",
    "viable",
    "reproduced",
    "dynamic_confirmed",
    "static_confirmed",
    "provisionally_valid",
    "valid",
    "needs_research",
}

# Severities (or priorities, when severity is absent) that block the gate.
BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}

# Callers listed per changed function in the blast radius. A cap, not a
# truncation of the analysis: the verdict reflects every edge, the listing
# stays readable.
MAX_CALLERS_SHOWN = 10

# Maximum server-side wait for mantis_scan_status long-polling, so an MCP
# client can block on a running scan without burning agent turns in a poll loop.
MAX_WAIT_SECONDS = 60.0

# Line proximity window around a diff hunk for findings outside any function.
DIFF_LINE_PROXIMITY = 3

# Where per-repository state lives when --state-dir is not given: a directory
# under this path, keyed by the repository. Defaults to <workspace>/mcp.
MCP_STATE_DIR_ENV = "MANTIS_MCP_STATE_DIR"

# Ceilings on what one mantis_scan_change call may start. The caller is the
# operator's own agent, but an agent under prompt injection can call a tool
# in a loop; without these, N calls were N concurrent pipelines each allowed
# any --max-llm-calls the caller named.
MAX_SCAN_LLM_CALLS = 500
MAX_SCAN_FILES = 50
MAX_CONCURRENT_SCANS = 2
MAX_SCAN_WALL_SECONDS = 3600.0

VERDICT_PASS = "PASS"
VERDICT_REVIEW = "REVIEW"
VERDICT_BLOCK = "BLOCK"

_VERDICT_RANK = {VERDICT_PASS: 0, VERDICT_REVIEW: 1, VERDICT_BLOCK: 2}


class MantisState:
    """Per-repo paths and live scan registry for one server process.

    State -- the knowledge database, the structural catalog, scan logs, the
    resolutions audit log -- lives OUTSIDE the repository it describes, in a
    per-repository directory under the Mantis workspace (or under
    MANTIS_MCP_STATE_DIR / --state-dir). The repository is the code under
    audit, and in the general case it is somebody else's: a committed symlink
    at a predictable path under `<repo>/.mantis/` turned every state write
    into a write to any file the server's user could reach, and a committed
    database or catalog was trusted as the server's own memory and could
    hand the change gate a PASS. Keeping state out of the tree closes both.
    """

    def __init__(self, repo_root: str, home: Optional[str] = None):
        self.repo = Path(repo_root).resolve()
        self.home = self._default_home(self.repo, home)
        self.db_path = str(self.home / "knowledge.db")
        self.scans: Dict[str, Dict[str, Any]] = {}
        self._scan_events: Dict[str, threading.Event] = {}
        self._scan_procs: Dict[str, Optional[subprocess.Popen]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _default_home(repo: Path, explicit: Optional[str]) -> Path:
        import hashlib

        from core.paths import workspace_dir

        if explicit:
            return Path(explicit).expanduser().resolve()
        base = os.environ.get(MCP_STATE_DIR_ENV, "").strip()
        root = Path(base).expanduser().resolve() if base else workspace_dir() / "mcp"
        # One directory per repository path, so two checkouts never share a
        # catalog; keyed by hash so the directory name is always a safe one.
        return root / hashlib.sha256(str(repo).encode("utf-8")).hexdigest()[:16]

    def check_home(self) -> str:
        """Why the state directory is unusable, or "" when it is fine.

        Refused: a state directory inside the repository (the repository's
        author could then plant it), or one that is or traverses a symlink.
        """
        try:
            resolved = self.home.resolve()
        except OSError as exc:
            return f"state directory '{self.home}' cannot be resolved: {exc}"
        if resolved == self.repo or self.repo in resolved.parents:
            return (f"state directory '{self.home}' is inside the repository; state must "
                    f"live outside the code under audit (set --state-dir or "
                    f"{MCP_STATE_DIR_ENV}).")
        from core.paths import validate_data_path

        ok, why = validate_data_path(self.home)
        return "" if ok is not None else why

    def ensure_home(self) -> None:
        """Creates the state directory and the knowledge database. Write paths only."""
        problem = self.check_home()
        if problem:
            raise PermissionError(problem)
        self.home.mkdir(parents=True, exist_ok=True)
        if not os.path.exists(self.db_path):
            from core.database import init_db

            init_db(self.db_path)

    def open_log(self, name: str):
        """Append handle on a log under the state directory that must be a
        regular file: a symlink there is refused rather than followed."""
        path = self.home / name
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        return os.fdopen(os.open(str(path), flags, 0o600), "a", encoding="utf-8")

    def db_exists(self) -> bool:
        return os.path.exists(self.db_path)

    def state_dir(self) -> str:
        from core.structural_index import state_dir_for_db

        return state_dir_for_db(self.db_path)

    def index(self):
        from core.structural_index import StructuralIndex

        return StructuralIndex(self.state_dir())

    def rel(self, filepath: str) -> str:
        """Repo-relative form of a path that may arrive absolute or relative.

        Anything that does not resolve inside the repo returns "" -- refused,
        not reinterpreted. The old fallbacks turned /etc/passwd into
        etc/passwd and passed ../escape through verbatim, handing the scan
        tier paths outside the repository it serves.
        """
        clean = str(filepath or "").replace("\\", "/").strip()
        if not clean:
            return ""
        p = Path(clean)
        if p.is_absolute():
            try:
                clean = str(p.resolve().relative_to(self.repo)).replace("\\", "/")
            except (OSError, ValueError):
                return ""
        else:
            clean = clean.removeprefix("./")
        if ".." in Path(clean).parts:
            return ""
        return clean


# --- Tier 1: deterministic reads -------------------------------------------------


def reindex(state: MantisState) -> Dict[str, Any]:
    """Builds or incrementally refreshes the structural index for the repo."""
    from core.structural_index import build_structural_index, git_snapshot_id

    state.ensure_home()
    t0 = time.time()
    manifest = build_structural_index(
        str(state.repo), state.state_dir(), git_snapshot_id(str(state.repo))) or {}
    coverage = manifest.get("coverage") or {}
    return {
        "status": manifest.get("status", "unknown"),
        "files_indexed": coverage.get("indexed_files"),
        "total_files": coverage.get("total_files"),
        "elapsed_seconds": round(time.time() - t0, 2),
        "state_dir": state.state_dir(),
    }


def _resolve_symbol_rows(idx, name: str, filepath: str = "") -> List[Dict[str, Any]]:
    """Catalog rows for a symbol name, filtered by component-aligned path suffix."""
    res = idx.resolve_symbol(name, limit=50)
    rows = res.get("results") or []
    if filepath:
        want = str(filepath).replace("\\", "/").strip("/")
        rows = [
            r for r in rows
            if r.get("file_path") == want or str(r.get("file_path", "")).endswith("/" + want)
            or want.endswith("/" + str(r.get("file_path", "")))
        ]
    return rows


def _unavailable_index_response(idx, *, for_function_at: bool = False) -> Dict[str, Any]:
    if idx.is_legitimately_empty():
        base: Dict[str, Any] = {
            "available": True,
            "empty_repo": True,
            "hint": "Repository has no files in supported tree-sitter languages.",
        }
        if for_function_at:
            base["found"] = False
        else:
            base["results"] = []
        return base
    if idx.failure_reason() == "degraded_empty":
        hint = "Structural index degraded (0 files indexed despite supported source files). Call mantis_reindex."
    else:
        hint = "No structural index. Call mantis_reindex first."
    out: Dict[str, Any] = {"available": False, "hint": hint}
    if for_function_at:
        out["found"] = False
    return out


def find_symbol(state: MantisState, name: str, offset: int = 0) -> Dict[str, Any]:
    idx = state.index()
    if not idx.available():
        res = _unavailable_index_response(idx)
        if res.get("empty_repo"):
            res["total"] = 0
        return res
    out = idx.resolve_symbol(name, limit=20, offset=offset)
    out["available"] = True
    return out


def find_callers(state: MantisState, symbol: str, filepath: str = "") -> Dict[str, Any]:
    idx = state.index()
    if not idx.available():
        res = _unavailable_index_response(idx)
        if res.get("empty_repo"):
            res["resolved"] = False
        return res
    rows = _resolve_symbol_rows(idx, symbol, filepath)
    if not rows:
        return {"available": True, "resolved": False,
                "hint": f"Symbol '{symbol}' not in the catalog."}
    if len({r["symbol_id"] for r in rows}) > 1 and not filepath:
        return {"available": True, "resolved": False, "ambiguous": True,
                "candidates": [
                    {"file_path": r.get("file_path"), "qualified_name": r.get("qualified_name"),
                     "start_line": r.get("start_line")} for r in rows[:10]
                ],
                "hint": "Disambiguate with the filepath argument."}
    out = idx.find_callers(rows[0])
    out.update({"available": True, "resolved": True, "symbol": rows[0].get("qualified_name")})
    return out


def find_callees(state: MantisState, symbol: str, filepath: str = "") -> Dict[str, Any]:
    idx = state.index()
    if not idx.available():
        res = _unavailable_index_response(idx)
        if res.get("empty_repo"):
            res["resolved"] = False
        return res
    rows = _resolve_symbol_rows(idx, symbol, filepath)
    if not rows:
        return {"available": True, "resolved": False,
                "hint": f"Symbol '{symbol}' not in the catalog."}
    out = idx.find_callees(rows[0])
    out.update({"available": True, "resolved": True, "symbol": rows[0].get("qualified_name")})
    return out


def function_at(state: MantisState, filepath: str, line: int) -> Dict[str, Any]:
    idx = state.index()
    if not idx.available():
        return _unavailable_index_response(idx, for_function_at=True)
    out = idx.enclosing_symbol(state.rel(filepath), int(line))
    out["available"] = True
    return out


def _finding_view(f: Dict[str, Any]) -> Dict[str, Any]:
    """The fields a dev-loop consumer needs; drops embeddings and bulk prose."""
    return {
        "id": f.get("id"),
        "title": f.get("title"),
        "severity": f.get("severity"),
        "priority": f.get("priority"),
        "status": f.get("status"),
        "filepath": f.get("filepath"),
        "line_numbers": f.get("line_numbers"),
        "code_paths": f.get("code_paths"),
        "cwe": f.get("cwe"),
        "lineage_id": f.get("lineage_id"),
    }


def get_findings(state: MantisState, filepath: str = "", status: str = "") -> Dict[str, Any]:
    if not state.db_exists():
        return {"findings": [], "hint": "No findings database yet. Run mantis_scan_change."}
    from core.database import read_findings, run_belongs_to_active_target, run_target_roots

    rows = read_findings(state.db_path)
    roots_map = run_target_roots(state.db_path)
    repo_root = str(state.repo)
    rel = state.rel(filepath) if filepath else ""
    out = []
    for f in rows:
        if not run_belongs_to_active_target(
            state.db_path, f.get("run_id"), active_root=repo_root, roots_map=roots_map
        ):
            continue
        if rel and not _finding_matches(state, str(f.get("filepath") or ""), rel):
            continue
        if status and str(f.get("status") or "").lower() != status.lower():
            continue
        out.append(_finding_view(f))
    return {"findings": out, "total": len(out)}


def security_guidance(state: MantisState, filepath: str, full: bool = False) -> Dict[str, Any]:
    if not state.db_exists():
        return {"hint": "No knowledge database yet. Run mantis_scan_change to build one."}
    from core.database import query_security_guidance

    return query_security_guidance(
        state.db_path, state.rel(filepath), full=full, target_root=str(state.repo)
    )


# Operator resolutions. The operator owns the repository and the database;
# withholding a closure tool would not remove the capability, only push it to
# raw sqlite. What the tool preserves is label honesty: machine statuses
# (patch_verified, dynamic_confirmed) stay reserved for the verification
# pipeline, and the database's monotonic guard still refuses a dismissal
# over machine-verified evidence.
RESOLUTION_STATUSES = ("mitigated", "false_positive", "accepted_risk")
_RESOLUTION_ALIASES = {
    "mark_resolved": "mitigated",
    "resolved": "mitigated",
}
_TERMINAL_CLOSED_STATUSES = frozenset({
    "false_positive",
    "mitigated",
    "accepted_risk",
    "duplicate_merged",
    "non_viable",
    "sample_or_test",
    "patch_verified",
})


def _file_sha256(path: Path) -> str:
    try:
        if path.is_file():
            return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        pass
    return ""


def resolve_finding(state: MantisState, finding_id: int, resolution: str,
                    reason: str) -> Dict[str, Any]:
    """Closes one finding with an operator verdict and an audit trail."""
    raw_res = str(resolution or "").strip().lower()
    res = _RESOLUTION_ALIASES.get(raw_res, raw_res)
    if res not in RESOLUTION_STATUSES:
        return {"error": f"resolution must be one of {list(RESOLUTION_STATUSES)}: "
                         "'mitigated' (or 'mark_resolved') means the defect was fixed, "
                         "'false_positive' means the report is wrong, "
                         "'accepted_risk' records an explicit risk acceptance."}
    if not str(reason or "").strip():
        return {"error": "A non-empty reason is required: it is the audit "
                         "trail for overriding the scanner."}
    if not state.db_exists():
        return {"error": "No findings database."}
    try:
        fid = int(finding_id)
    except (TypeError, ValueError):
        return {"error": f"finding_id must be an integer, got {finding_id!r}."}
    from core.database import (
        read_finding_resolutions,
        read_findings,
        record_finding_resolution,
        run_belongs_to_active_target,
        run_target_roots,
        update_finding_status_by_id,
    )

    all_rows = read_findings(state.db_path)

    def row_for(i: int, rows: Optional[List[Dict[str, Any]]] = None):
        for f in (rows if rows is not None else read_findings(state.db_path)):
            if f.get("id") == i:
                return f
        return None

    row = row_for(fid, all_rows)
    if row is None:
        return {"error": f"No finding with id {fid}."}
    old_status = str(row.get("status") or "")
    old_lower = old_status.strip().lower()
    lineage_id = str(row.get("lineage_id") or "").strip()
    roots_map = run_target_roots(state.db_path)
    repo_root = str(state.repo)

    lineage_has_machine_proof = old_lower in ("dynamic_confirmed", "patch_verified")
    if lineage_id and not lineage_has_machine_proof:
        for sib in all_rows:
            if str(sib.get("lineage_id") or "").strip() != lineage_id:
                continue
            if not run_belongs_to_active_target(
                state.db_path, sib.get("run_id"), active_root=repo_root, roots_map=roots_map
            ):
                continue
            if str(sib.get("status") or "").strip().lower() in ("dynamic_confirmed", "patch_verified"):
                lineage_has_machine_proof = True
                break

    preserved_machine_proof = False
    if res == "false_positive" and lineage_has_machine_proof:
        applied = False
        new_status = old_status
    elif old_lower in _TERMINAL_CLOSED_STATUSES:
        applied = False
        new_status = old_status
    elif res == "accepted_risk" and old_lower == "dynamic_confirmed":
        existing_res = read_finding_resolutions(state.db_path, target_root=repo_root)
        prev_res = str((existing_res.get(lineage_id) or {}).get("resolution") or "").strip().lower()
        if not lineage_id or prev_res == "accepted_risk":
            applied = False
            new_status = old_status
        else:
            # Never overwrite machine-verified dynamic_confirmed evidence on the
            # finding row; record the risk acceptance in finding_resolutions only.
            applied = True
            new_status = old_status
            preserved_machine_proof = True
    else:
        update_finding_status_by_id(state.db_path, fid, str(row.get("run_id") or ""), res)
        new_status = str((row_for(fid) or {}).get("status") or "")
        applied = new_status.strip().lower() == res

    if applied and lineage_id:
        for sib in all_rows:
            sib_id = sib.get("id")
            if sib_id == fid or str(sib.get("lineage_id") or "").strip() != lineage_id:
                continue
            if not run_belongs_to_active_target(
                state.db_path, sib.get("run_id"), active_root=repo_root, roots_map=roots_map
            ):
                continue
            sib_status = str(sib.get("status") or "").strip().lower()
            if sib_status in OPEN_FINDING_STATUSES and not (
                res == "accepted_risk" and sib_status == "dynamic_confirmed"
            ):
                update_finding_status_by_id(
                    state.db_path, int(sib_id), str(sib.get("run_id") or ""), res
                )
        rel_fp = state.rel(str(row.get("filepath") or ""))
        file_sha = _file_sha256(state.repo / rel_fp) if rel_fp else ""
        record_finding_resolution(
            state.db_path,
            lineage_id=lineage_id,
            resolution=res,
            reason=str(reason).strip(),
            target_root=repo_root,
            filepath=rel_fp or str(row.get("filepath") or ""),
            resolved_file_sha256=file_sha,
            finding_id=fid,
        )

    with state.open_log("resolutions.log") as fh:
        fh.write(json.dumps({
            "at": time.time(),
            "finding_id": fid,
            "lineage_id": row.get("lineage_id"),
            "title": row.get("title"),
            "old_status": old_status,
            "new_status": new_status,
            "resolution": res,
            "reason": str(reason).strip(),
        }) + "\n")
    out: Dict[str, Any] = {"finding_id": fid, "old_status": old_status,
                           "new_status": new_status, "applied": applied}
    if preserved_machine_proof:
        out["note"] = ("Recorded accepted_risk in finding_resolutions while preserving "
                       "machine-verified 'dynamic_confirmed' status on the finding row.")
    elif not applied:
        if res == "false_positive" and lineage_has_machine_proof:
            out["note"] = ("The monotonic status guard refused the transition: "
                           "a dismissal never overwrites machine-verified "
                           "evidence (dynamic_confirmed, patch_verified).")
        else:
            out["note"] = ("The monotonic status guard refused the transition: "
                           f"'{old_status}' is already a terminal status and "
                           "is preserved.")
    return out


# --- The gate ---------------------------------------------------------------------


_HUNK_RE = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_HUNK_FULL_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _unescape_git_path(raw: str, *, strip_prefix: bool = True) -> str:
    """Normalizes a git diff header path (including C-quoted paths with octals)."""
    text = str(raw or "").strip()
    if not text:
        return ""
    if text.startswith('"'):
        out = bytearray()
        i = 1
        while i < len(text):
            ch = text[i]
            if ch == '"':
                break
            if ch == "\\" and i + 1 < len(text):
                nxt = text[i + 1]
                if nxt in "01234567" and i + 3 < len(text) and all(c in "01234567" for c in text[i + 1:i + 4]):
                    out.append(int(text[i + 1:i + 4], 8))
                    i += 4
                    continue
                esc = {"n": ord("\n"), "t": ord("\t"), "r": ord("\r"), "\\": ord("\\"), '"': ord('"')}.get(nxt)
                if esc is not None:
                    out.append(esc)
                    i += 2
                    continue
            out.extend(ch.encode("utf-8"))
            i += 1
        text = out.decode("utf-8", "replace")
    else:
        text = text.split("\t")[0].strip()
    if text == "/dev/null":
        return "/dev/null"
    if strip_prefix and (text.startswith("a/") or text.startswith("b/")):
        text = text[2:]
    return text


def parse_unified_diff_hunks(diff_text: str) -> Dict[str, List[Dict[str, Any]]]:
    """Parsed hunk descriptors per new-side file path. Never raises."""
    per_file: Dict[str, List[Dict[str, Any]]] = {}
    current = ""
    old_line = 0
    new_line = 0
    old_left = 0
    new_left = 0
    active_hunk: Optional[Dict[str, Any]] = None

    for raw in str(diff_text or "").splitlines():
        in_hunk = old_left > 0 or new_left > 0
        if in_hunk:
            if raw.startswith("\\"):
                continue
            if raw.startswith("+"):
                if active_hunk is not None:
                    active_hunk["added_new"].add(new_line)
                    active_hunk["new_to_old"][new_line] = max(1, old_line)
                new_line += 1
                new_left -= 1
            elif raw.startswith("-"):
                if active_hunk is not None:
                    active_hunk["deleted_old"][old_line] = max(1, new_line)
                old_line += 1
                old_left -= 1
            else:
                if active_hunk is not None:
                    active_hunk["kept_old_to_new"][old_line] = new_line
                    active_hunk["new_to_old"][new_line] = old_line
                old_line += 1
                new_line += 1
                old_left -= 1
                new_left -= 1
            continue
        active_hunk = None
        if raw.startswith("+++ "):
            path = _unescape_git_path(raw[4:], strip_prefix=True)
            current = "" if path in ("", "/dev/null") else path
            if current:
                per_file.setdefault(current, [])
            continue
        m = _HUNK_FULL_RE.match(raw)
        if m:
            o_start = int(m.group(1))
            o_cnt = int(m.group(2)) if m.group(2) is not None else 1
            n_start = int(m.group(3))
            n_cnt = int(m.group(4)) if m.group(4) is not None else 1
            old_line = o_start
            new_line = n_start
            old_left = o_cnt
            new_left = n_cnt
            if current:
                active_hunk = {
                    "old_start": o_start,
                    "old_count": o_cnt,
                    "new_start": n_start,
                    "new_count": n_cnt,
                    "deleted_old": {},
                    "kept_old_to_new": {},
                    "added_new": set(),
                    "new_to_old": {},
                }
                per_file[current].append(active_hunk)
            continue
    for fp in per_file:
        per_file[fp].sort(key=lambda h: (h["old_start"], h["new_start"]))
    return per_file


def translate_line_through_hunks(
    old_line: int, hunks: List[Dict[str, Any]]
) -> Tuple[int, bool]:
    """Maps a pre-diff 1-based line number to `(new_line, directly_modified)`."""
    ln = int(old_line)
    if ln <= 0 or not hunks:
        return max(1, ln), False
    delta = 0
    for h in hunks:
        o_start = int(h["old_start"])
        o_cnt = int(h["old_count"])
        n_start = int(h["new_start"])
        n_cnt = int(h["new_count"])
        if o_cnt == 0:
            # Pure insertion `@@ -k,0 +n_start,n_cnt @@` inserts AFTER old line k.
            if ln <= o_start:
                return max(1, ln + delta), False
            delta += n_cnt
            continue
        o_end = o_start + o_cnt - 1
        if ln < o_start:
            return max(1, ln + delta), False
        if o_start <= ln <= o_end:
            kept = h.get("kept_old_to_new") or {}
            if ln in kept:
                return max(1, int(kept[ln])), False
            deleted = h.get("deleted_old") or {}
            return max(1, int(deleted.get(ln, max(1, n_start)))), True
        delta += n_cnt - o_cnt
    return max(1, ln + delta), False


def _reverse_translate_line_through_hunks(
    new_line: int, hunks: List[Dict[str, Any]]
) -> Tuple[int, bool]:
    """Maps a post-diff 1-based line number back to `(old_line, directly_added_or_deleted)`."""
    ln = int(new_line)
    if ln <= 0 or not hunks:
        return max(1, ln), False
    delta = 0
    for h in hunks:
        o_start = int(h["old_start"])
        o_cnt = int(h["old_count"])
        n_start = int(h["new_start"])
        n_cnt = int(h["new_count"])
        if n_cnt == 0:
            anchor = max(1, n_start)
            if ln < anchor:
                return max(1, ln - delta), False
            if ln == anchor:
                return max(1, o_start), True
            delta -= o_cnt
            continue
        n_end = n_start + n_cnt - 1
        if ln < n_start:
            return max(1, ln - delta), False
        if n_start <= ln <= n_end:
            n2o = h.get("new_to_old") or {}
            added = h.get("added_new") or set()
            if ln in n2o:
                return max(1, int(n2o[ln])), (ln in added)
            return max(1, o_start), True
        delta += n_cnt - o_cnt
    return max(1, ln - delta), False


def parse_diff_moves(diff_text: str) -> Dict[str, Any]:
    """Extracts `{"renamed": {old: new}, "deleted": [old, ...]}` from a unified/git diff.

    Hunk bodies are counted and skipped just like `parse_unified_diff` so file
    contents inside a hunk can never spoof `rename from` or `deleted file mode`.
    """
    renamed: Dict[str, str] = {}
    deleted: List[str] = []
    old_left = 0
    new_left = 0

    sec_rename_from = ""
    sec_rename_to = ""
    sec_deleted_mode = False
    sec_minus = ""
    sec_plus = ""
    sec_git_old = ""

    def _flush_section() -> None:
        nonlocal sec_rename_from, sec_rename_to, sec_deleted_mode, sec_minus, sec_plus, sec_git_old
        if sec_rename_from and sec_rename_to:
            renamed[sec_rename_from] = sec_rename_to
        elif (
            (sec_plus == "/dev/null" and sec_minus and sec_minus != "/dev/null")
            or (sec_deleted_mode and (sec_minus or sec_git_old))
        ):
            victim = sec_minus if (sec_minus and sec_minus != "/dev/null") else sec_git_old
            if victim and victim not in deleted:
                deleted.append(victim)
        sec_rename_from = ""
        sec_rename_to = ""
        sec_deleted_mode = False
        sec_minus = ""
        sec_plus = ""
        sec_git_old = ""

    for raw in str(diff_text or "").splitlines():
        if old_left > 0 or new_left > 0:
            if raw.startswith("\\"):
                continue
            if raw.startswith("+"):
                new_left -= 1
            elif raw.startswith("-"):
                old_left -= 1
            else:
                old_left -= 1
                new_left -= 1
            continue

        if raw.startswith("diff --git "):
            _flush_section()
            rest = raw[len("diff --git "):].strip()
            m_ab = re.match(r"^a/(.+?) b/(.+)$", rest)
            if m_ab:
                sec_git_old = m_ab.group(1)
            continue
        if raw.startswith("rename from "):
            sec_rename_from = _unescape_git_path(raw[len("rename from "):], strip_prefix=False)
            continue
        if raw.startswith("rename to "):
            sec_rename_to = _unescape_git_path(raw[len("rename to "):], strip_prefix=False)
            continue
        if raw.startswith("deleted file mode "):
            sec_deleted_mode = True
            continue
        if raw.startswith("--- "):
            if sec_minus and sec_plus:
                _flush_section()
            sec_minus = _unescape_git_path(raw[4:], strip_prefix=True)
            continue
        if raw.startswith("+++ "):
            sec_plus = _unescape_git_path(raw[4:], strip_prefix=True)
            continue
        m = _HUNK_RE.match(raw)
        if m:
            old_left = int(m.group(1)) if m.group(1) is not None else 1
            new_left = int(m.group(3)) if m.group(3) is not None else 1
            continue

    _flush_section()
    return {"renamed": renamed, "deleted": deleted}


def parse_unified_diff(diff_text: str) -> Dict[str, List[int]]:
    """New-side changed line numbers per file from a unified diff. Never raises.

    File headers are recognized only between hunks. Inside a hunk the
    `@@ -a,b +c,d @@` counts say exactly how many old-side and new-side lines
    follow, and every one of them is content -- including a content line
    that reads `+++ b/other.py`, which the author of the diffed file
    controls. Treating such a line as a header would re-attribute the rest
    of the file's hunks to another path, or to nothing.
    """
    changed: Dict[str, List[int]] = {}
    current = ""
    new_line = 0
    old_left = 0  # old-side lines still owed by the open hunk
    new_left = 0  # new-side lines still owed by the open hunk
    for raw in str(diff_text or "").splitlines():
        in_hunk = old_left > 0 or new_left > 0
        if in_hunk:
            if raw.startswith("\\"):
                continue  # "\ No newline at end of file": not a counted line
            if raw.startswith("+"):
                if current:
                    changed[current].append(new_line)
                new_line += 1
                new_left -= 1
            elif raw.startswith("-"):
                # Old-side line: the new-side counter does not advance, but
                # the deletion itself anchors here -- a hunk that only
                # removes lines (the deleted-guard regression) must still map
                # to its enclosing function, or the blast radius comes back
                # empty.
                if current:
                    changed[current].append(max(1, new_line))
                old_left -= 1
            else:
                new_line += 1
                old_left -= 1
                new_left -= 1
            continue
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            path = path.split("\t")[0]
            if path.startswith("b/"):
                path = path[2:]
            current = "" if path == "/dev/null" else path
            if current:
                changed.setdefault(current, [])
            continue
        m = _HUNK_RE.match(raw)
        if m:
            old_left = int(m.group(1)) if m.group(1) is not None else 1
            new_line = int(m.group(2))
            new_left = int(m.group(3)) if m.group(3) is not None else 1
            continue
    return {f: sorted(set(lines)) for f, lines in changed.items()}


def _paths_match(a: str, b: str) -> bool:
    """Component-aligned equality: exact, or one a path-suffix of the other."""
    a = str(a or "").replace("\\", "/").strip("/")
    b = str(b or "").replace("\\", "/").strip("/")
    if not a or not b:
        return False
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _finding_matches(state, stored: str, query: str) -> bool:
    """Strict matching for the gate layer. Findings store canonical
    root-relative paths, so when `query` names a real file in the repo both
    sides are canonical and only exact equality is a match — otherwise
    duplicate basenames cross-match (an edit to foo/util.h gets BLOCKed by
    findings on bar/util.h; ubiquitous in C/C++ trees). Component-aligned
    suffix matching (_paths_match) stays as the fallback for absolute,
    historical, or deleted paths, where exactness is unknowable."""
    s = str(stored or "").replace("\\", "/").strip("/")
    q = str(query or "").replace("\\", "/").strip("/")
    if not s or not q:
        return False
    try:
        if (state.repo / q).is_file():
            return s == q
    except OSError:
        pass
    return _paths_match(s, q)


def _uncovered(state: MantisState, rel_files: List[str]) -> Optional[List[str]]:
    """Changed files no recorded campaign ever covered, else None if unknowable.

    Delegates to core.cost.uncovered_files, which owns the ancestor-directory
    coverage rule (scanning repo/lib covers lib/anything). The ledger stores
    targets as the pipeline received them, so each file is probed in both its
    absolute and repo-relative spellings and covered if either one is.
    """
    from core.cost import uncovered_files

    abs_map = {rel: str(state.repo / rel) for rel in rel_files}
    probes = list(abs_map.values()) + list(abs_map)
    unc = uncovered_files(state.db_path, probes)
    if unc is None:
        return None
    unc_set = set(unc)
    return [rel for rel, ab in abs_map.items() if ab in unc_set and rel in unc_set]


def _run_covered_file_shas(state: MantisState) -> Dict[Tuple[str, str], str]:
    """Returns `{(run_id, repo_rel_path): content_sha256}` from `coverage_files`, if present."""
    if not state.db_exists():
        return {}
    try:
        from core.database import connect

        conn = connect(state.db_path)
        try:
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='coverage_files'"
            ).fetchone()
            if not row:
                return {}
            rows = conn.execute(
                "SELECT run_id, path, content_hash FROM coverage_files ORDER BY id ASC"
            ).fetchall()
        finally:
            conn.close()
    except Exception:
        return {}
    out: Dict[Tuple[str, str], str] = {}
    for run_id, path, chash in rows:
        if not run_id or not path or not chash:
            continue
        rel = state.rel(str(path))
        if rel:
            out[(str(run_id), rel)] = str(chash)
    return out


def check_change(state: MantisState, files: Optional[List[str]] = None,
                 diff: str = "", renamed: Optional[Dict[str, str]] = None,
                 deleted: Optional[List[str]] = None,
                 include_coverage: bool = True,
                 post_diff_min_id: Optional[int] = None) -> Dict[str, Any]:
    """The deterministic gate: what Mantis knows about this change, as a verdict.

    BLOCK  -- an open HIGH/CRITICAL finding intersects the change.
    REVIEW -- something demands human/agent attention: open findings of any
              severity touch the change or its callers, a changed file has
              never been scanned, or the index/database needed to decide is
              missing (fail-closed).
    PASS   -- every check ran and nothing known intersects this change.

    `renamed` ({old path: new path}) and `deleted` ([old path]) say what the
    change did to paths the database may hold findings at. A finding at a
    renamed path is judged against the new path, as direct: the code moved,
    the finding did not go away. A finding at a deleted path is a REVIEW:
    the code may have moved somewhere a rename could not be detected.
    Without these, renaming a file would take its findings out of the
    gate's sight, and renaming is cheaper than fixing.

    `include_coverage=False` keeps the coverage checks -- never scanned,
    index or database missing, paths outside the repository, ledger
    unreadable -- OUT of the verdict and returns them under `coverage_gaps`
    instead, for a caller that accounts for coverage itself and decides
    separately whether a gap fails its job. The verdict is then a function
    of findings only. The default folds them in as REVIEW, as before.
    """
    raw_changed: Dict[str, List[int]] = parse_unified_diff(diff)
    raw_hunks_by_file: Dict[str, List[Dict[str, Any]]] = parse_unified_diff_hunks(diff) if diff else {}
    diff_moves = parse_diff_moves(diff) if diff else {"renamed": {}, "deleted": []}
    for f in files or []:
        raw_changed.setdefault(str(f or ""), [])
    changed: Dict[str, List[int]] = {}
    hunks_by_file: Dict[str, List[Dict[str, Any]]] = {}
    rejected: List[str] = []
    for f, lines in raw_changed.items():
        r = state.rel(f)
        if r:
            changed.setdefault(r, []).extend(lines or [])
        elif f:
            rejected.append(f)
    for f, f_hunks in raw_hunks_by_file.items():
        r = state.rel(f)
        if r:
            hunks_by_file[r] = f_hunks
    changed = {f: sorted(set(lines)) for f, lines in changed.items()}

    merged_renamed: Dict[str, str] = dict(diff_moves.get("renamed") or {})
    merged_renamed.update(renamed or {})
    moved: Dict[str, str] = {}
    for old, new in merged_renamed.items():
        o, n = state.rel(old), state.rel(new)
        if o and n:
            moved[o] = n
            changed.setdefault(n, [])

    merged_deleted = list(
        dict.fromkeys(list(diff_moves.get("deleted") or []) + list(deleted or []))
    )
    removed = [r for r in (state.rel(d) for d in merged_deleted) if r]

    verdict = VERDICT_PASS
    reasons: List[str] = []
    next_actions: List[str] = []
    coverage_gaps: List[Dict[str, str]] = []

    def raise_to(level: str, reason: str, action: str = "") -> None:
        nonlocal verdict
        if _VERDICT_RANK[level] > _VERDICT_RANK[verdict]:
            verdict = level
        reasons.append(reason)
        if action and action not in next_actions:
            next_actions.append(action)

    def gap(reason: str, action: str = "", file: str = "") -> None:
        coverage_gaps.append({"file": file, "reason": reason, "action": action})
        if include_coverage:
            raise_to(VERDICT_REVIEW, reason, action)

    if not changed and not rejected and not removed:
        return {"verdict": VERDICT_REVIEW,
                "reasons": ["No changed files given: pass `files` or a unified `diff`."],
                "blast_radius": [], "findings": [], "next_actions": [],
                "coverage_gaps": [{"file": "", "reason": "No changed files given.", "action": ""}]}

    # A path the gate cannot map into this repo is named, not dropped:
    # silently narrowing the change set is the fail-open direction.
    for f in rejected:
        gap(f"'{f}' is outside this repository: not gated.",
            "Run the gate from the repository the change belongs to.", file=f)

    # Fail-closed context checks.
    idx = state.index()
    if not idx.available() and not idx.is_legitimately_empty():
        if idx.failure_reason() == "degraded_empty":
            gap("Structural index degraded (0 files indexed despite supported source files): blast radius unknown.",
                "Run mantis_reindex, then re-run mantis_check_change.")
        else:
            gap("Structural index missing: blast radius unknown.",
                "Run mantis_reindex, then re-run mantis_check_change.")
    if not state.db_exists():
        gap("No findings database: change set has never been audited.",
            "Run mantis_scan_change on the changed files.")

    disk_shas: Dict[str, str] = {
        rel_fp: _file_sha256(state.repo / rel_fp) for rel_fp in changed
    }

    # Blast radius: changed lines -> enclosing functions -> direct callers.
    blast: List[Dict[str, Any]] = []
    radius_files = set(changed)
    if idx.available():
        for rel_fp, lines in changed.items():
            file_hunks = hunks_by_file.get(rel_fp) or []
            # When the catalog was built BEFORE this diff edited rel_fp on disk,
            # its function boundaries sit at pre-diff line numbers: reverse-map
            # new-side diff lines to query enclosing_symbol, then project the
            # matched function's [start_line, end_line] forward onto new-side lines.
            index_is_old = bool(
                file_hunks and idx.file_matches_sha256(rel_fp, disk_shas.get(rel_fp, "")) is False
            )
            for line in lines or []:
                query_line = (
                    _reverse_translate_line_through_hunks(line, file_hunks)[0]
                    if index_is_old
                    else line
                )
                enc = idx.enclosing_symbol(rel_fp, query_line)
                if not enc.get("found"):
                    continue
                s_ln = enc.get("start_line")
                e_ln = enc.get("end_line")
                if index_is_old:
                    if isinstance(s_ln, int):
                        s_ln = translate_line_through_hunks(s_ln, file_hunks)[0]
                    if isinstance(e_ln, int):
                        e_ln = translate_line_through_hunks(e_ln, file_hunks)[0]
                entry = {
                    "file": enc.get("file_path", rel_fp),
                    "function": enc.get("qualified_name") or enc.get("signature"),
                    "start_line": s_ln,
                    "end_line": e_ln,
                    "callers": [],
                    "caller_files": [],
                }
                if any(b["file"] == entry["file"] and b["function"] == entry["function"]
                       for b in blast):
                    continue
                sym = {"symbol_id": enc.get("symbol_id"),
                       "name": str(enc.get("qualified_name") or "").split(".")[-1]}
                if sym["symbol_id"]:
                    callers = idx.find_callers(sym, limit=MAX_CALLERS_SHOWN)
                    for c in callers.get("results") or []:
                        entry["callers"].append({
                            "caller": c.get("caller") or c.get("callee_name"),
                            "file": c.get("file_path"),
                            "line": c.get("line"),
                        })
                        if c.get("file_path"):
                            radius_files.add(str(c["file_path"]))
                    all_caller_paths = idx.caller_file_paths(sym)
                    entry["caller_files"] = all_caller_paths
                    entry["callers_total"] = int(callers.get("total") or len(entry["callers"]))
                    entry["callers_truncated"] = bool(callers.get("truncated"))
                    radius_files.update(all_caller_paths)
                blast.append(entry)

    # Findings intersecting the change and its radius.
    hits: List[Dict[str, Any]] = []
    if state.db_exists():
        from core.database import (
            read_finding_resolutions,
            read_findings,
            run_belongs_to_active_target,
            run_target_roots,
        )

        roots_map = run_target_roots(state.db_path)
        repo_root = str(state.repo)
        resolutions = read_finding_resolutions(state.db_path, target_root=repo_root)
        run_shas = _run_covered_file_shas(state)

        # Deduplicate multiple open rows sharing a lineage_id across rescans,
        # preferring dynamic_confirmed, blocking severity, and newest row id.
        candidate_open: List[Dict[str, Any]] = []
        by_lineage: Dict[str, Dict[str, Any]] = {}
        for f in read_findings(state.db_path):
            if not run_belongs_to_active_target(
                state.db_path, f.get("run_id"), active_root=repo_root, roots_map=roots_map
            ):
                continue
            f_status = str(f.get("status") or "").strip().lower()
            if f_status not in OPEN_FINDING_STATUSES:
                continue
            lid = str(f.get("lineage_id") or "").strip()
            if lid and lid in resolutions:
                res_rec = resolutions[lid]
                res_kind = str(res_rec.get("resolution") or "").strip().lower()
                if res_kind == "false_positive":
                    if f_status not in ("dynamic_confirmed", "patch_verified"):
                        continue
                elif res_kind == "accepted_risk":
                    if f_status != "patch_verified":
                        continue
                elif res_kind == "mitigated" and f_status != "dynamic_confirmed":
                    res_sha = str(res_rec.get("resolved_file_sha256") or "")
                    f_rel = state.rel(str(f.get("filepath") or ""))
                    cur_sha = disk_shas.get(f_rel) or (_file_sha256(state.repo / f_rel) if f_rel else "")
                    if not res_sha or (cur_sha and cur_sha == res_sha):
                        continue
            if lid:
                prev = by_lineage.get(lid)
                if prev is not None:
                    prev_dyn = str(prev.get("status") or "").strip().lower() == "dynamic_confirmed"
                    cur_dyn = f_status == "dynamic_confirmed"
                    prev_blk = str(prev.get("severity") or prev.get("priority") or "").upper() in BLOCKING_SEVERITIES
                    cur_blk = str(f.get("severity") or f.get("priority") or "").upper() in BLOCKING_SEVERITIES
                    if (cur_dyn, cur_blk, int(f.get("id") or 0)) > (prev_dyn, prev_blk, int(prev.get("id") or 0)):
                        by_lineage[lid] = f
                    continue
                by_lineage[lid] = f
            else:
                candidate_open.append(f)
        candidate_open.extend(by_lineage.values())
        candidate_open.sort(key=lambda r: int(r.get("id") or 0))

        for f in candidate_open:
            f_fp = str(f.get("filepath") or "")
            matched_files = [c for c in changed if _finding_matches(state, f_fp, c)]
            # A finding at a path this change renamed belongs to the new
            # path now, and to every changed line of it: the lines it was
            # recorded at mean nothing after the move.
            via_rename = ""
            if not matched_files:
                for old, new in moved.items():
                    if _paths_match(f_fp, old) and new in changed:
                        matched_files = [new]
                        via_rename = old
                        break
            in_file = bool(matched_files)
            in_radius = not in_file and any(_finding_matches(state, f_fp, r) for r in radius_files)
            if not in_file and not in_radius:
                if any(_paths_match(f_fp, d) for d in removed):
                    sev = str(f.get("severity") or f.get("priority") or "").upper()
                    raise_to(VERDICT_REVIEW,
                             f"Open finding '{f.get('title')}' ({sev or 'unrated'}) was in "
                             f"{f_fp}, which this change deletes: confirm the code is gone, "
                             f"not moved.",
                             "Check where the deleted file's code went; dismiss the finding "
                             "with evidence if it is gone.")
                continue

            # When a diff gives changed line numbers and the finding records its
            # own lines, distinguish findings that intersect the modified
            # hunk/function ("direct", which BLOCKs on HIGH/CRITICAL) from
            # pre-existing file debt elsewhere in the same file
            # ("unrelated_in_file", which raises REVIEW instead of BLOCK so a
            # two-line registration in a legacy router does not block on eight
            # unrelated findings 400 lines away). Missing line info on either
            # side fails closed to "direct".
            direct = bool(via_rename)
            if in_file and not via_rename:
                primary_rel = matched_files[0]
                file_hunks = hunks_by_file.get(primary_rel) or []
                diff_lines = sorted({
                    ln for c in matched_files for ln in (changed.get(c) or [])
                })
                f_lines = [
                    int(x) for x in (f.get("line_numbers") or [])
                    if isinstance(x, int) and not isinstance(x, bool)
                ]
                if not diff_lines or not f_lines:
                    direct = True
                else:
                    f_id = int(f.get("id") or 0)
                    f_run = str(f.get("run_id") or "")
                    cur_disk_sha = disk_shas.get(primary_rel, "")
                    is_post_diff = (
                        (post_diff_min_id is not None and f_id >= post_diff_min_id)
                        or bool(cur_disk_sha and run_shas.get((f_run, primary_rel)) == cur_disk_sha)
                    )
                    effective_lines: List[int] = []
                    if file_hunks and not is_post_diff:
                        for fl in f_lines:
                            mapped_ln, was_mod = translate_line_through_hunks(fl, file_hunks)
                            if was_mod:
                                direct = True
                            effective_lines.append(mapped_ln)
                    else:
                        effective_lines = list(f_lines)
                    if not direct and any(
                        abs(fl - cl) <= DIFF_LINE_PROXIMITY
                        for fl in effective_lines
                        for cl in diff_lines
                    ):
                        direct = True
                    if not direct:
                        for b in blast:
                            b_file = str(b.get("file") or "")
                            b_start = b.get("start_line")
                            b_end = b.get("end_line")
                            if (isinstance(b_start, int) and isinstance(b_end, int)
                                    and any(_finding_matches(state, b_file, c) for c in matched_files)
                                    and any(b_start <= fl <= b_end for fl in effective_lines)):
                                direct = True
                                break

            view = _finding_view(f)
            if direct:
                view["relationship"] = "direct"
            elif in_file:
                view["relationship"] = "unrelated_in_file"
            else:
                view["relationship"] = "caller_radius"
            hits.append(view)
            sev = str(f.get("severity") or f.get("priority") or "").upper()
            if via_rename:
                view["filepath"] = matched_files[0]
                view["renamed_from"] = via_rename
            if direct and sev in BLOCKING_SEVERITIES:
                where = (f"{matched_files[0]} (renamed from {via_rename})" if via_rename else f_fp)
                raise_to(VERDICT_BLOCK,
                         f"Open {sev} finding '{f.get('title')}' touches changed file {where}.",
                         "Fix the finding (or mark it false_positive with evidence) before merging.")
            elif in_file:
                raise_to(VERDICT_REVIEW,
                         f"Open finding '{f.get('title')}' ({sev or 'unrated'}) in the "
                         f"{'change' if direct else f'same file (outside changed lines): {f_fp}'}"
                         + (f": {f_fp}." if direct else "."),
                         "Review the listed findings against this change.")
            else:
                raise_to(VERDICT_REVIEW,
                         f"Open finding '{f.get('title')}' ({sev or 'unrated'}) in the "
                         f"caller radius: {f_fp}.",
                         "Review the listed findings against this change.")

        # Archived findings on a touched file: found here once, shelved when
        # the code changed and a rescan did not report them again. Listed as
        # hits with their own relationship so the caller can show them as
        # notices; never a verdict, because an archived finding is a hint to
        # look again, not a claim about the current code.
        from core.database import ARCHIVED_STATUS

        for f in read_findings(state.db_path):
            if str(f.get("status") or "").lower() != ARCHIVED_STATUS:
                continue
            f_fp = str(f.get("filepath") or "")
            if not any(_finding_matches(state, f_fp, c) for c in changed):
                continue
            view = _finding_view(f)
            view["relationship"] = "archived"
            hits.append(view)

        # Coverage: a changed file no scan ever recorded is unknown ground.
        uncovered = _uncovered(state, list(changed))
        if uncovered is None:
            gap("Coverage ledger unreadable: scan history unknown.",
                "Check the knowledge database in the state directory, then run mantis_scan_change.")
        else:
            for rel_fp in uncovered:
                gap(f"'{rel_fp}' has never been scanned by Mantis.",
                    "Run mantis_scan_change on the changed files.", file=rel_fp)

    return {
        "verdict": verdict,
        "reasons": reasons,
        "blast_radius": blast,
        "findings": hits,
        "next_actions": next_actions,
        "coverage_gaps": coverage_gaps,
    }


# --- Tier 2: the parallel audit ----------------------------------------------------


def _scan_cmd(state: MantisState, target: str, max_llm_calls: int, model: str) -> List[str]:
    """The exact pipeline invocation for one changed file. Pure, for tests."""
    cmd = [sys.executable, str(_REF_ROOT / "main.py"), target,
           "--db", state.db_path, "--yes",
           # Anchor finding filepaths at the repository: a single-file scan
           # would otherwise store bare basenames ("login.ts"), which two
           # same-named files in one repo could cross-match at the gate.
           "--path-root", str(state.repo)]
    if max_llm_calls > 0:
        cmd += ["--max-llm-calls", str(max_llm_calls)]
    if model:
        cmd += ["--model", model]
    return cmd


def _mcp_repo_scan_cmd(
    state: MantisState, rels: List[str], max_llm_calls: int, model: str
) -> List[str]:
    """Single repo-rooted pipeline invocation for a changed-file set.

    Delegates to `_scan_cmd` so callers and tests overriding `_scan_cmd`
    intercept the base command, while real `main.py` invocations receive
    `--scan-mode changed`, `--changed-files=...`, and `--sandbox static-only`.
    """
    cmd = list(_scan_cmd(state, str(state.repo), max_llm_calls, model))
    if len(cmd) >= 2 and str(cmd[1]).endswith("main.py"):
        cmd += ["--scan-mode", "changed"]
        cmd += [f"--changed-files={r}" for r in rels]
        cmd += ["--sandbox", "static-only"]
    return cmd


_ACTIVE_SCAN_PROCS: set = set()
_ACTIVE_PROCS_LOCK = threading.Lock()
_SCAN_ID_RE = re.compile(r"^[0-9a-f]{8,32}$")


def _terminate_proc_group(proc: subprocess.Popen, grace: float = 0.5) -> None:
    """Terminates a `start_new_session=True` child and all its descendants."""
    pid = getattr(proc, "pid", None)
    if isinstance(pid, int) and pid > 0:
        try:
            os.killpg(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        proc.wait(timeout=max(0.05, grace))
    except subprocess.TimeoutExpired:
        pass
    if isinstance(pid, int) and pid > 0:
        try:
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    if proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            pass


def _cleanup_all_active_scans() -> None:
    with _ACTIVE_PROCS_LOCK:
        procs = list(_ACTIVE_SCAN_PROCS)
    for proc in procs:
        if proc.poll() is None:
            _terminate_proc_group(proc, grace=0.2)


atexit.register(_cleanup_all_active_scans)


def _persist_scan_record(scans_dir: Path, record: Dict[str, Any]) -> None:
    try:
        public = {k: v for k, v in record.items() if not k.startswith("_")}
        tmp = scans_dir / f".{record['scan_id']}.json.tmp"
        dst = scans_dir / f"{record['scan_id']}.json"
        tmp.write_text(json.dumps(public, indent=2, default=str), encoding="utf-8")
        os.replace(tmp, dst)
    except OSError:
        pass


def scan_change(state: MantisState, files: List[str],
                max_llm_calls: int = 150, model: str = "",
                timeout_seconds: float = MAX_SCAN_WALL_SECONDS) -> Dict[str, Any]:
    """Audits the changed files with the full pipeline, in the background."""
    rels: List[str] = []
    for f in files or []:
        r = state.rel(f)
        if not r:
            continue
        probe = state.repo / r
        try:
            # rel() refused the lexical escapes; this refuses the physical
            # one -- an in-repo symlink whose target lives outside the repo.
            probe.resolve().relative_to(state.repo)
        except (OSError, ValueError):
            continue
        if probe.is_file():
            rels.append(r)
    rels = list(dict.fromkeys(rels))
    if not rels:
        return {"error": "No scannable files inside the repository. "
                         "Pass repo-relative paths."}
    if len(rels) > MAX_SCAN_FILES:
        return {"error": f"{len(rels)} files requested; a scan takes at most "
                         f"{MAX_SCAN_FILES}. Split the change set."}
    try:
        max_llm_calls = int(max_llm_calls or 0)
    except (TypeError, ValueError):
        max_llm_calls = 0
    # 0 or less would drop the --max-llm-calls flag and with it the cap.
    max_llm_calls = min(max(max_llm_calls, 1), MAX_SCAN_LLM_CALLS)
    try:
        wall_cap = float(timeout_seconds)
        if wall_cap <= 0:
            wall_cap = MAX_SCAN_WALL_SECONDS
    except (TypeError, ValueError):
        wall_cap = MAX_SCAN_WALL_SECONDS

    with state._lock:
        running = sum(1 for s in state.scans.values() if s.get("status") == "running")
        if running >= MAX_CONCURRENT_SCANS:
            return {"error": f"{running} scan(s) already running (limit {MAX_CONCURRENT_SCANS}); "
                             "poll mantis_scan_status and retry when one finishes."}
        try:
            state.ensure_home()
        except PermissionError as exc:
            return {"error": str(exc)}
        scans_dir = state.home / "scans"
        scans_dir.mkdir(exist_ok=True)
        scan_id = uuid.uuid4().hex[:12]
        log_path = scans_dir / f"{scan_id}.log"
        done_event = threading.Event()
        record: Dict[str, Any] = {
            "scan_id": scan_id,
            "files": rels,
            "status": "running",
            "started": time.time(),
            "returncodes": [],
            "log": str(log_path),
        }
        state.scans[scan_id] = record
        state._scan_events[scan_id] = done_event
        state._scan_procs[scan_id] = None
        _persist_scan_record(scans_dir, record)

    def _run() -> None:
        index_restored = False
        timed_out = False
        proc: Optional[subprocess.Popen] = None
        try:
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            with os.fdopen(os.open(str(log_path), flags, 0o600), "ab") as log:
                cmd = _mcp_repo_scan_cmd(state, rels, max_llm_calls, model)
                log.write(f"\n=== mantis scan {', '.join(rels)} ===\n".encode())
                log.flush()
                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=log,
                        cwd=str(_REF_ROOT),
                        start_new_session=True,
                    )
                    with _ACTIVE_PROCS_LOCK:
                        _ACTIVE_SCAN_PROCS.add(proc)
                    cancel_now = False
                    with state._lock:
                        state._scan_procs[scan_id] = proc
                        record["_pid"] = proc.pid
                        cancel_now = bool(record.get("_cancel_requested"))
                    if cancel_now:
                        _terminate_proc_group(proc)
                        code = -15
                    else:
                        try:
                            code = proc.wait(timeout=wall_cap)
                        except subprocess.TimeoutExpired:
                            timed_out = True
                            _terminate_proc_group(proc)
                            log.write(
                                f"[mcp] scan timed out after {wall_cap:.1f}s; process group terminated\n".encode()
                            )
                            code = -9
                except Exception as exc:
                    if proc is not None and proc.poll() is None:
                        _terminate_proc_group(proc)
                    log.write(f"[mcp] scan failed to launch: {exc!r}\n".encode())
                    code = -1
                with state._lock:
                    record["returncodes"].append(code)

                if not timed_out and not record.get("_cancel_requested"):
                    try:
                        idx = state.index()
                        if (idx.available() or idx.is_legitimately_empty()) and (
                            idx.manifest.get("code_root") == os.path.realpath(str(state.repo))
                        ):
                            index_restored = True
                        else:
                            result = reindex(state)
                            index_restored = result.get("status") in ("complete", "partial") or (
                                result.get("status") == "empty" and (result.get("total_files") or 0) == 0
                            )
                    except Exception as exc:
                        log.write(f"[mcp] reindex after scan failed: {exc!r}\n".encode())
                        index_restored = False
        finally:
            if proc is not None:
                with _ACTIVE_PROCS_LOCK:
                    _ACTIVE_SCAN_PROCS.discard(proc)
            with state._lock:
                state._scan_procs.pop(scan_id, None)
                record["index_restored"] = index_restored
                codes = record["returncodes"]
                if record.get("_cancel_requested"):
                    record["status"] = "cancelled"
                elif timed_out:
                    record["status"] = "timed_out"
                elif codes and all(c == 0 for c in codes):
                    record["status"] = "done"
                elif codes and all(c in (0, 2) for c in codes):
                    record["status"] = "paused_at_budget"
                else:
                    record["status"] = "finished_with_errors"
                record["ended"] = time.time()
                _persist_scan_record(scans_dir, record)
                done_event.set()

    threading.Thread(target=_run, name=f"mantis-scan-{scan_id}", daemon=True).start()
    return {"scan_id": scan_id, "files": rels, "log": str(log_path),
            "hint": "Poll mantis_scan_status (pass wait_seconds to block); "
                    "findings land in the shared database and the next "
                    "mantis_check_change will see them."}


def cancel_scan(state: MantisState, scan_id: str) -> Dict[str, Any]:
    """Terminates a running background scan and its subprocess group."""
    with state._lock:
        rec = state.scans.get(scan_id)
        if rec is None:
            return {"error": f"Unknown scan_id '{scan_id}'."}
        if rec.get("status") != "running":
            return {"scan_id": scan_id, "status": rec.get("status"), "cancelled": False}
        rec["_cancel_requested"] = True
        proc = state._scan_procs.get(scan_id)
        done_event = state._scan_events.get(scan_id)
    if proc is not None:
        _terminate_proc_group(proc)
    if done_event is not None:
        done_event.wait(timeout=5.0)
    with state._lock:
        snap = {k: v for k, v in (state.scans.get(scan_id) or {}).items() if not k.startswith("_")}
    snap["cancelled"] = True
    return snap


def scan_status(state: MantisState, scan_id: str,
                wait_seconds: float = 0) -> Dict[str, Any]:
    with state._lock:
        raw_rec = state.scans.get(scan_id)
        record = {k: v for k, v in raw_rec.items() if not k.startswith("_")} if raw_rec else {}
        done_event = state._scan_events.get(scan_id)
    if not record and _SCAN_ID_RE.match(str(scan_id or "")):
        persisted = state.home / "scans" / f"{scan_id}.json"
        if persisted.is_file():
            try:
                loaded = json.loads(persisted.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    if loaded.get("status") == "running":
                        loaded["status"] = "interrupted"
                    record = loaded
            except (OSError, ValueError):
                record = {}
    if not record:
        return {"error": f"Unknown scan_id '{scan_id}' (scans do not survive server restarts; "
                         "findings they wrote do)."}
    try:
        wait_s = min(max(0.0, float(wait_seconds or 0)), MAX_WAIT_SECONDS)
    except (TypeError, ValueError):
        wait_s = 0.0
    if wait_s > 0 and record.get("status") == "running" and done_event is not None:
        done_event.wait(timeout=wait_s)
        with state._lock:
            raw_rec = state.scans.get(scan_id)
            record = {k: v for k, v in raw_rec.items() if not k.startswith("_")} if raw_rec else record
    out = dict(record)
    if state.db_exists():
        from core.database import read_findings

        rows = read_findings(state.db_path)
        out["findings_in_scanned_files"] = sum(
            1 for f in rows
            if any(_finding_matches(state, str(f.get("filepath") or ""), r) for r in (record.get("files") or []))
        )
    return out


# --- MCP wiring ---------------------------------------------------------------------


def build_server(state: MantisState):
    """Registers the tools on an MCP server. Import deferred so everything
    above stays testable without the SDK installed."""
    try:  # mcp >= 2.0
        from mcp.server.mcpserver import MCPServer
    except ImportError:  # mcp 1.x: the same class, named FastMCP. The 2.x
        # fastmcp module still exists but raises on import, so 2.x must be
        # probed first -- the fallback order is load-bearing.
        from mcp.server.fastmcp import FastMCP as MCPServer

    srv = MCPServer(
        "mantis",
        instructions=(
            "Mantis secure-development-loop server. For every change: call "
            "mantis_check_change with the unified diff (or changed files); "
            "resolve what it raises; run mantis_scan_change so the full audit "
            "pipeline reviews the change in parallel. PASS means no known "
            "issues intersect the change -- keep the index fresh with "
            "mantis_reindex after large pulls."
        ),
    )

    @srv.tool()
    def mantis_check_change(files: Optional[List[str]] = None, diff: str = "") -> dict:
        """Deterministic security gate for a change set. Give it the unified diff
        (preferred: enables line-level blast radius) or a list of changed files.
        Returns verdict PASS/REVIEW/BLOCK with reasons, blast radius, and
        intersecting findings. Fails closed: missing index or unscanned files
        yield REVIEW, never PASS."""
        return check_change(state, files, diff)

    @srv.tool()
    def mantis_scan_change(files: List[str], max_llm_calls: int = 150, model: str = "") -> dict:
        """Launches the full Mantis audit pipeline over the given files in the
        background (budget-capped). Findings accumulate in the repo's
        the per-repository knowledge database, where mantis_check_change reads them."""
        return scan_change(state, files, max_llm_calls=max_llm_calls, model=model)

    @srv.tool()
    def mantis_scan_status(scan_id: str, wait_seconds: int = 0) -> dict:
        """Status of a background scan started by mantis_scan_change. Pass
        wait_seconds (up to 60) to block until the scan finishes or the timeout
        elapses instead of polling in a tight loop."""
        return scan_status(state, scan_id, wait_seconds=wait_seconds)

    @srv.tool()
    def mantis_reindex() -> dict:
        """Builds or incrementally refreshes the structural index (tree-sitter
        symbol/call-graph catalog) for the repository."""
        return reindex(state)

    @srv.tool()
    def mantis_find_symbol(name: str, offset: int = 0) -> dict:
        """Looks up a function/class/macro definition by name in the catalog."""
        return find_symbol(state, name, offset=offset)

    @srv.tool()
    def mantis_find_callers(symbol: str, filepath: str = "") -> dict:
        """Direct call sites of a symbol: who can reach this code."""
        return find_callers(state, symbol, filepath=filepath)

    @srv.tool()
    def mantis_find_callees(symbol: str, filepath: str = "") -> dict:
        """Direct callees of a symbol: what this code reaches."""
        return find_callees(state, symbol, filepath=filepath)

    @srv.tool()
    def mantis_function_at(filepath: str, line: int) -> dict:
        """The innermost function enclosing file:line, with its exact extent."""
        return function_at(state, filepath, line)

    @srv.tool()
    def mantis_get_findings(filepath: str = "", status: str = "") -> dict:
        """Recorded findings, optionally filtered by file and status."""
        return get_findings(state, filepath=filepath, status=status)

    @srv.tool()
    def mantis_security_guidance(filepath: str, full: bool = False) -> dict:
        """Threat-model-informed security guidance for a file: active threats,
        invariants, historical vulnerabilities, and triaged false positives."""
        return security_guidance(state, filepath, full=full)

    @srv.tool()
    def mantis_scan_cancel(scan_id: str) -> dict:
        """Terminates a running background scan started by mantis_scan_change."""
        return cancel_scan(state, scan_id)

    @srv.tool()
    def mantis_resolve_finding(finding_id: int, resolution: str, reason: str) -> dict:
        """Closes a finding with an operator verdict: 'mitigated' / 'mark_resolved'
        (the defect was fixed), 'false_positive' (the report is wrong), or
        'accepted_risk' (explicit risk acceptance). Requires a reason, which is
        persisted across rescans and appended to resolutions.log in the state
        directory. Machine statuses (patch_verified, dynamic_confirmed) remain
        reserved for the verification pipeline, and a dismissal never
        overwrites machine-verified evidence."""
        return resolve_finding(state, finding_id, resolution, reason)

    return srv


class _GateArgumentParser(argparse.ArgumentParser):
    """Exits 3 on CLI usage errors so exit code 2 stays reserved for VERDICT_BLOCK."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(3, f"{self.prog}: error: {message}\n")


def main(argv: Optional[List[str]] = None) -> int:
    parser = _GateArgumentParser(description="Mantis MCP server (stdio)")
    parser.add_argument("--repo", default=os.environ.get("MANTIS_MCP_REPO", "."),
                        help="Repository root to serve (default: cwd)")
    parser.add_argument("--check", action="store_true",
                        help="One-shot gate instead of serving: read a unified "
                             "diff on stdin (or take --files), print the verdict "
                             "JSON, exit 0=PASS 1=REVIEW 2=BLOCK.")
    parser.add_argument("--files", nargs="*", default=None,
                        help="Changed files for --check when no diff is piped.")
    parser.add_argument("--renamed", action="append", default=[],
                        metavar="OLD=NEW",
                        help="Renamed path pair OLD=NEW for --check (repeatable).")
    parser.add_argument("--deleted", action="append", default=[],
                        metavar="PATH",
                        help="Deleted path for --check (repeatable).")
    parser.add_argument("--state-dir", default="",
                        help="Directory for this repository's knowledge database, catalog "
                             f"and logs; must be outside the repository (default: "
                             f"${MCP_STATE_DIR_ENV} or <workspace>/mcp, per repository)")
    args = parser.parse_args(argv)
    state = MantisState(args.repo, home=args.state_dir or None)
    if not state.repo.is_dir():
        print(f"error: --repo '{args.repo}' is not a directory", file=sys.stderr)
        return 3
    problem = state.check_home()
    if problem:
        print(f"error: {problem}", file=sys.stderr)
        return 3
    if args.check:
        try:
            renamed_map: Dict[str, str] = {}
            for item in args.renamed or []:
                if "=" not in item:
                    print(f"error: --renamed expects OLD=NEW, got {item!r}", file=sys.stderr)
                    return 3
                old_p, new_p = item.split("=", 1)
                renamed_map[old_p] = new_p
            diff = ""
            if args.files is None and not sys.stdin.isatty():
                diff = sys.stdin.read()
            out = check_change(
                state,
                files=args.files,
                diff=diff,
                renamed=renamed_map or None,
                deleted=args.deleted or None,
            )
            print(json.dumps(out, indent=2, default=str))
            return {VERDICT_PASS: 0, VERDICT_REVIEW: 1, VERDICT_BLOCK: 2}[out["verdict"]]
        except Exception as exc:
            print(f"error: gate failed: {exc}", file=sys.stderr)
            return 3
    build_server(state).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())

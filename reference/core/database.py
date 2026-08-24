import hashlib
import os
import sqlite3
import json
import uuid
from contextlib import contextmanager
from typing import Optional, List, Dict, Any

CURRENT_SCHEMA_VERSION = 2

@contextmanager
def _db(db_path: str, check_version: bool = True):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        if check_version:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
            if cursor.fetchone() is not None:
                cursor.execute("PRAGMA user_version")
                row = cursor.fetchone()
                v = row[0] if row else 0
                if v != CURRENT_SCHEMA_VERSION:
                    raise RuntimeError(
                        f"Database schema version mismatch in '{db_path}' (found version {v}, expected {CURRENT_SCHEMA_VERSION}). "
                        f"Schema changed: please delete '{db_path}' before running."
                    )
        yield conn
        conn.commit()
    finally:
        conn.close()

def canonical_filepath(fp: str, target_file: str = "") -> str:
    """Normalizes finding and risk score filepaths to a consistent repo-relative canonical representation."""
    if not fp and not target_file:
        return ""
    raw = (fp or target_file).strip().replace("\\", "/")
    while raw.startswith("./"):
        raw = raw[2:]

    tf_clean = (target_file or "").strip().replace("\\", "/")
    while tf_clean.startswith("./"):
        tf_clean = tf_clean[2:]

    # 1. Check relative suffix matching between raw and target_file
    if tf_clean:
        if raw == tf_clean:
            return os.path.basename(raw) if (os.path.isabs(raw) and not os.path.isdir(raw)) else (raw.lstrip("/") if os.path.isabs(raw) else raw)

        # If raw starts with tf_clean directory prefix
        if raw.startswith(tf_clean + "/"):
            return raw[len(tf_clean) + 1:]

        # If both are absolute paths
        if os.path.isabs(raw) and os.path.isabs(tf_clean):
            try:
                target_dir = tf_clean if os.path.isdir(tf_clean) else os.path.dirname(tf_clean)
                rel = os.path.relpath(raw, target_dir).replace("\\", "/")
                if not rel.startswith(".."):
                    return rel
            except Exception:
                pass

        # If raw is absolute and tf_clean is relative: e.g. raw="/repo/api/app.py", tf_clean="api/app.py"
        if os.path.isabs(raw) and not os.path.isabs(tf_clean):
            if raw.endswith("/" + tf_clean) or raw.endswith(tf_clean):
                return tf_clean

        # If raw is relative and tf_clean is absolute: e.g. raw="api/app.py", tf_clean="/repo/api/app.py"
        if not os.path.isabs(raw) and os.path.isabs(tf_clean):
            if tf_clean.endswith("/" + raw) or tf_clean.endswith(raw):
                return raw

    # 2. Check active execution context if raw is absolute
    if os.path.isabs(raw):
        try:
            from core.context import current_run_context
            ctx = current_run_context.get()
            if ctx:
                for cand in (ctx.jail_dir, ctx.target_file):
                    if cand:
                        cand_clean = str(cand).replace("\\", "/")
                        cand_dir = cand_clean if os.path.isdir(cand_clean) else os.path.dirname(cand_clean)
                        if os.path.isabs(cand_dir):
                            rel = os.path.relpath(raw, cand_dir).replace("\\", "/")
                            if not rel.startswith(".."):
                                return rel
        except Exception:
            pass

        return raw.lstrip("/")

    return raw

def init_db(db_path: str):
    """Initialize the SQLite database with tables, unique indexes, and enforce schema versioning."""
    with _db(db_path, check_version=False) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
        has_findings = cursor.fetchone() is not None

        cursor.execute("PRAGMA user_version")
        row = cursor.fetchone()
        v = row[0] if row else 0
        if has_findings and v != CURRENT_SCHEMA_VERSION:
            raise RuntimeError(
                f"Database schema version mismatch in '{db_path}' (found version {v}, expected {CURRENT_SCHEMA_VERSION}). "
                f"Schema changed: please delete '{db_path}' before running."
            )

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                filepath TEXT,
                title TEXT,
                severity TEXT,
                description TEXT,
                line_numbers TEXT NOT NULL DEFAULT '[]',
                remediation TEXT,
                status TEXT NOT NULL DEFAULT 'reported',
                mantis_risk_score REAL,
                impact_score INTEGER,
                likelihood_score INTEGER,
                priority TEXT,
                signature TEXT,
                lineage_id TEXT,
                cwe TEXT,
                triage_reasoning TEXT,
                patch_diff TEXT,
                patch_status TEXT,
                UNIQUE(filepath, title, description, line_numbers, run_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_filepath ON findings(filepath)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_lineage ON findings(lineage_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_signature ON findings(signature)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS risk_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                filepath TEXT,
                score REAL,
                reasoning TEXT,
                UNIQUE(filepath, run_id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaign_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                artifact_type TEXT,
                filepath TEXT,
                content TEXT,
                metadata_json TEXT DEFAULT '{}',
                UNIQUE(run_id, filepath)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS learnings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                category TEXT,
                learning TEXT,
                tags TEXT DEFAULT '[]'
            )
        """)
        cursor.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")


CWE_KEYWORDS = [
    (r"\b(sql|sqli|database query)\b", "CWE-89"),
    (r"\b(path traversal|directory traversal|arbitrary file read|file inclusion|lfi|rfi)\b", "CWE-22"),
    (r"\b(command injection|os injection|shell injection|subshell|os\.system|exec)\b", "CWE-78"),
    (r"\b(cross-site scripting|xss|reflected xss|stored xss|dom xss)\b", "CWE-79"),
    (r"\b(ssrf|server-side request forgery)\b", "CWE-918"),
    (r"\b(idor|insecure direct object reference|tenant override|tenant boundary)\b", "CWE-639"),
    (r"\b(auth|authentication bypass|unauthenticated|privilege escalation)\b", "CWE-287"),
    (r"\b(csrf|cross-site request forgery)\b", "CWE-352"),
    (r"\b(prototype pollution)\b", "CWE-1321"),
    (r"\b(deserialization|object injection|unpickle|pickle|yaml\.load)\b", "CWE-502"),
    (r"\b(timing discrepancy|timing side-channel|timing attack)\b", "CWE-208"),
    (r"\b(token expiration|session expiration|expired revoked)\b", "CWE-613"),
    (r"\b(race condition|concurrency race)\b", "CWE-362"),
    (r"\b(integer underflow|integer overflow|arithmetic underflow|negative total)\b", "CWE-191"),
    (r"\b(hardcoded secret|hardcoded password|api key|credential leak)\b", "CWE-798"),
    (r"\b(open redirect|url redirection)\b", "CWE-601"),
    (r"\b(dos|denial of service|memory consumption|memory exhaustion|resource exhaustion|infinite loop)\b", "CWE-400"),
]

def extract_canonical_cwe(cwe_val: str = "", title: str = "", description: str = "") -> str:
    """Extracts a normalized canonical CWE identifier from finding metadata, title, or description."""
    import re
    combined = f"{cwe_val} {title} {description}".lower()

    cwe_match = re.search(r"\bcwe[-_]?(\d+)\b", combined)
    if cwe_match:
        return f"CWE-{cwe_match.group(1)}"

    for pattern, cwe_id in CWE_KEYWORDS:
        if re.search(pattern, combined):
            return cwe_id

    return "CWE-UNKNOWN"


def extract_target_symbol(title: str = "", description: str = "", code_paths: Optional[list] = None) -> str:
    """Extracts the target function, endpoint, or sink identifier invariant to title formatting and backticks."""
    import re
    title_clean = title.strip()

    # 1. Backticked symbol anywhere in title: `get_user` -> get_user
    backtick_match = re.search(r"`([a-zA-Z0-9_\-/\.]+)(?:\(\))?`", title_clean)
    if backtick_match:
        return backtick_match.group(1).strip("/.()").lower()

    # 2. Endpoint notation: /view, /api/cart, /backup
    ep_match = re.search(r"(/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)*)", title_clean)
    if ep_match:
        return ep_match.group(1).strip("/").replace("/", "_").lower()

    # 3. Explicit symbol following preposition in title: 'in get_user', 'in list_orders', 'in function hydrate'
    prep_match = re.search(
        r"\b(?:in|at|within|inside|for)\s+(?:function\s+|method\s+|routine\s+|handler\s+|endpoint\s+|def\s+)?([a-zA-Z_][a-zA-Z0-9_]+)(?:\(\))?",
        title_clean,
        re.IGNORECASE
    )
    if prep_match:
        sym = prep_match.group(1).lower()
        stopwords_sym = {
            "the", "a", "an", "this", "all", "user", "file", "path", "order", "query", "input",
            "database", "system", "memory", "header", "comment", "token", "session", "request",
            "response", "cart", "service", "views", "controllers", "api"
        }
        if sym not in stopwords_sym and len(sym) >= 3:
            return sym

    # 4. Function call notation in title: get_user(), list_orders()
    fn_match = re.search(r"\b([a-zA-Z_][a-zA-Z0-9_]+)\(\)", title_clean)
    if fn_match:
        return fn_match.group(1).lower()

    # 5. Check description for backticked symbol, function <symbol>, or method <symbol>
    desc_backtick = re.search(r"`([a-zA-Z0-9_\-/\.]+)(?:\(\))?`", description)
    if desc_backtick:
        sym = desc_backtick.group(1).strip("/.()").lower()
        if len(sym) >= 3 and not sym.isdigit():
            return sym

    desc_fn = re.search(r"\b(?:function|method|handler|routine|def)\s+`?([a-zA-Z_][a-zA-Z0-9_]+)`?(?:\(\))?", description, re.IGNORECASE)
    if desc_fn:
        return desc_fn.group(1).lower()

    # 6. Check code_paths
    if code_paths and isinstance(code_paths, list):
        for cp in code_paths:
            if isinstance(cp, str) and not cp.startswith("http"):
                clean_cp = cp.split(":")[0].strip()
                if clean_cp and not os.path.isfile(clean_cp):
                    return clean_cp.strip("/.()").lower()

    # 7. Fallback: Normalized significant tokens (excluding vulnerability taxonomy and grammatical words)
    stopwords = {
        "in", "via", "the", "a", "an", "and", "or", "to", "for", "with", "by", "of", "on", "from", "at",
        "vulnerability", "potential", "flaw", "defect", "bug", "issue", "unsanitized", "improper", "missing",
        "unvalidated", "untrusted", "unsafe", "insecure", "unbounded", "arbitrary", "remote",
        "parameter", "input", "query", "value", "handling", "validation", "injection", "traversal",
        "sql", "sqli", "xss", "csrf", "ssrf", "rce", "dos", "idor", "lfi", "rfi", "auth", "authentication",
        "crosssite", "scripting", "sidechannel", "race", "condition", "underflow", "overflow",
        "execution", "consumption", "exhaustion", "pollution", "override", "bypass"
    }
    words = [re.sub(r"[^a-zA-Z0-9_]", "", w).lower() for w in title_clean.split()]
    meaningful = [w for w in words if w and w not in stopwords and len(w) > 2]
    if meaningful:
        return "_".join(sorted(meaningful))

    return ""


def compute_stable_signature(
    filepath: str,
    title: str,
    cwe: str = "",
    symbol: str = "",
    description: str = "",
) -> str:
    """Computes a deterministic content identity signature invariant to line shifts, backticks, and title phrasing."""
    norm_fp = canonical_filepath(filepath, target_file=filepath).lower()
    norm_cwe = extract_canonical_cwe(cwe, title, description)
    norm_sym = symbol.lower() if symbol else extract_target_symbol(title, description)

    sig_content = f"{norm_fp}|{norm_cwe}|{norm_sym}"
    return hashlib.sha256(sig_content.encode("utf-8")).hexdigest()[:16]


def resolve_ancestor_lineage(
    cursor: sqlite3.Cursor,
    filepath: str,
    signature: str,
    cwe: str = "",
    symbol: str = "",
    title: str = "",
    description: str = "",
    line_numbers: str = "[]",
) -> str:
    """Resolves ancestor lineage_id using a strict, fail-closed matching ladder that preserves negative controls."""
    norm_fp = canonical_filepath(filepath, target_file=filepath)
    base_name = os.path.basename(norm_fp)
    norm_cwe = extract_canonical_cwe(cwe, title, description)
    norm_sym = symbol.lower() if symbol else extract_target_symbol(title, description)

    # Tier 1: Exact Stable Signature Match
    cursor.execute("""
        SELECT lineage_id FROM findings
        WHERE signature = ? AND lineage_id IS NOT NULL AND lineage_id != ''
        ORDER BY id DESC LIMIT 1
    """, (signature,))
    row = cursor.fetchone()
    if row and row[0]:
        return row[0]

    # Tier 2: File + Normalized CWE + Exact Target Symbol Match (Fail-closed: requires exact filepath match)
    if norm_sym and norm_fp:
        cursor.execute("""
            SELECT lineage_id FROM findings
            WHERE filepath = ?
              AND (cwe = ? OR cwe = '')
              AND (title LIKE ? OR description LIKE ? OR signature LIKE ?)
              AND lineage_id IS NOT NULL AND lineage_id != ''
            ORDER BY id DESC LIMIT 1
        """, (norm_fp, norm_cwe, f"%{norm_sym}%", f"%{norm_sym}%", f"%{norm_sym}%"))
        row = cursor.fetchone()
        if row and row[0]:
            return row[0]

    # Tier 3: Strict Line Proximity Match on exact filepath if and only if symbol is empty
    if not norm_sym and norm_fp and line_numbers and line_numbers != "[]":
        try:
            curr_lines = json.loads(line_numbers)
            if curr_lines:
                cursor.execute("""
                    SELECT id, line_numbers, lineage_id FROM findings
                    WHERE filepath = ?
                      AND cwe = ?
                      AND lineage_id IS NOT NULL AND lineage_id != ''
                    ORDER BY id DESC
                """, (norm_fp, norm_cwe))
                candidate_rows = cursor.fetchall()
                for cand in candidate_rows:
                    cand_lines_raw = cand[1]
                    try:
                        cand_lines = json.loads(cand_lines_raw) if isinstance(cand_lines_raw, str) else cand_lines_raw
                        if cand_lines and any(abs(c - a) <= 3 for c in curr_lines for a in cand_lines):
                            return cand[2]
                    except Exception:
                        pass
        except Exception:
            pass

    # Tier 4: Fallback -> Fail closed, mint fresh UUIDv4 (never merge distinct functions or flaws)
    return str(uuid.uuid4())


def write_findings(db_path: str, filepath: str, findings: list, run_id: str = "", status: str = ""):
    """Write structured findings to the database contextually associated with their canonical filepaths, stable signatures, and lineages."""
    with _db(db_path) as conn:
        cursor = conn.cursor()
        for obj in findings:
            finding = obj.model_dump() if hasattr(obj, "model_dump") else (obj if isinstance(obj, dict) else dict(obj))
            raw_lines = finding.get("line_numbers")
            if raw_lines and isinstance(raw_lines, (list, tuple, set)):
                try:
                    line_numbers = json.dumps(sorted(list(raw_lines)))
                except Exception:
                    line_numbers = json.dumps(list(raw_lines))
            else:
                line_numbers = "[]"

            # Graph status authority: Initial status is owned by the graph/harness or finding (default 'reported')
            finding_status = status or finding.get("status") or "reported"
            raw_fp = finding.get("filepath") or filepath or ""
            finding_filepath = canonical_filepath(raw_fp, target_file=filepath)
            raw_sev = finding.get("severity") or "MEDIUM"
            normalized_severity = str(raw_sev).upper()

            raw_title = str(finding.get("title") or "")
            raw_desc = str(finding.get("description") or "")
            raw_cwe = str(finding.get("cwe") or "")
            canonical_cwe = extract_canonical_cwe(raw_cwe, raw_title, raw_desc)
            target_symbol = extract_target_symbol(raw_title, raw_desc, finding.get("code_paths"))

            # Compute or extract deterministic stable content signature
            signature = str(finding.get("signature") or "").strip()
            if not signature:
                signature = compute_stable_signature(
                    filepath=finding_filepath,
                    title=raw_title,
                    cwe=canonical_cwe,
                    symbol=target_symbol,
                    description=raw_desc,
                )

            # Compute or inherit cross-pass lineage identifier via multi-tier ladder
            lineage_id = str(finding.get("lineage_id") or "").strip()
            if not lineage_id:
                lineage_id = resolve_ancestor_lineage(
                    cursor=cursor,
                    filepath=finding_filepath,
                    signature=signature,
                    cwe=canonical_cwe,
                    symbol=target_symbol,
                    title=raw_title,
                    description=raw_desc,
                    line_numbers=line_numbers,
                )

            triage_reasoning = str(finding.get("reasoning") or finding.get("triage_reasoning") or finding.get("critic_reasoning") or "")
            patch_diff = str(finding.get("patch_diff") or "")
            patch_status = str(finding.get("patch_status") or "")

            cursor.execute("""
                INSERT OR REPLACE INTO findings (
                    run_id, filepath, title, severity, description, line_numbers,
                    remediation, status, mantis_risk_score, impact_score, likelihood_score,
                    priority, signature, lineage_id, cwe, triage_reasoning, patch_diff, patch_status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                run_id,
                finding_filepath,
                raw_title,
                normalized_severity,
                raw_desc,
                line_numbers,
                finding.get("remediation"),
                finding_status,
                finding.get("mantis_risk_score"),
                finding.get("impact_score"),
                finding.get("likelihood_score"),
                finding.get("priority"),
                signature,
                lineage_id,
                canonical_cwe,
                triage_reasoning,
                patch_diff,
                patch_status,
            ))

def update_finding_calibration(
    db_path: str,
    finding_id: int,
    mantis_risk_score: float,
    impact_score: Optional[int] = None,
    likelihood_score: Optional[int] = None,
    priority: Optional[str] = None,
    run_id: str = "",
):
    """Updates per-finding calibration metrics on the canonical 0.1 - 10.0 scale."""
    with _db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE findings
            SET mantis_risk_score = ?,
                impact_score = ?,
                likelihood_score = ?,
                priority = ?
            WHERE id = ? AND (run_id = ? OR run_id = '')
        """, (mantis_risk_score, impact_score, likelihood_score, priority, finding_id, run_id))

def update_status(db_path: str, filepath: str, run_id: str, status: str):
    """Update status for active candidate findings in a given run (preserving terminal/suppressed statuses)."""
    with _db(db_path) as conn:
        cursor = conn.cursor()
        norm_fp = canonical_filepath(filepath, target_file=filepath)
        terminal_clause = "AND status NOT IN ('duplicate_merged', 'false_positive', 'non_viable', 'sample_or_test', 'mitigated')"
        if norm_fp and not os.path.isdir(norm_fp):
            cursor.execute(f"""
                UPDATE findings
                SET status = ?
                WHERE filepath = ?
                  AND run_id = ?
                  {terminal_clause}
            """, (status, norm_fp, run_id))
        else:
            cursor.execute(f"""
                UPDATE findings
                SET status = ?
                WHERE run_id = ?
                  {terminal_clause}
            """, (status, run_id))


def read_findings(
    db_path: str,
    filepath: Optional[str] = None,
    run_id: Optional[str] = None,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Read findings from the database, optionally filtered by filepath, run_id, or status."""
    with _db(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        if filepath and not os.path.isdir(filepath):
            norm_fp = canonical_filepath(filepath, target_file=filepath)
            query += " AND filepath = ?"
            params.append(norm_fp)
        if run_id:
            query += " AND run_id = ?"
            params.append(run_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY id ASC"
        cursor.execute(query, params)
        rows = []
        for r in cursor.fetchall():
            row_dict = dict(r)
            if row_dict.get("line_numbers"):
                try:
                    parsed = json.loads(row_dict["line_numbers"])
                    row_dict["line_numbers"] = parsed if parsed else None
                except Exception:
                    row_dict["line_numbers"] = None
            else:
                row_dict["line_numbers"] = None
            rows.append(row_dict)
        return rows

def record_calibration(db_path: str, filepath: str, score: float, reasoning: str, run_id: str = ""):
    """Record final per-file risk calibration score (0.1 - 10.0 scale) into the database."""
    with _db(db_path) as conn:
        cursor = conn.cursor()
        cal_filepath = canonical_filepath(filepath, target_file=filepath)
        cursor.execute("""
            INSERT OR REPLACE INTO risk_scores (run_id, filepath, score, reasoning)
            VALUES (?, ?, ?, ?)
        """, (run_id, cal_filepath, float(score), reasoning))

def read_risk_scores(db_path: str, filepath: Optional[str] = None, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Read risk scores from the database, optionally filtered by filepath and run_id."""
    with _db(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM risk_scores WHERE 1=1"
        params = []
        if filepath:
            norm_fp = canonical_filepath(filepath, target_file=filepath)
            query += " AND filepath = ?"
            params.append(norm_fp)
        if run_id:
            query += " AND run_id = ?"
            params.append(run_id)
        query += " ORDER BY id ASC"
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]

def record_artifact(db_path: str, run_id: str, artifact_type: str, filepath: str, content: str, metadata: Optional[dict] = None):
    """Record a campaign artifact in the database, replacing prior rows for the same filepath in this run."""
    with _db(db_path) as conn:
        cursor = conn.cursor()
        meta_str = json.dumps(metadata or {})
        cursor.execute("DELETE FROM campaign_artifacts WHERE run_id = ? AND filepath = ?", (run_id, filepath))
        cursor.execute("""
            INSERT OR REPLACE INTO campaign_artifacts (run_id, artifact_type, filepath, content, metadata_json)
            VALUES (?, ?, ?, ?, ?)
        """, (run_id, artifact_type, filepath, content, meta_str))

def read_artifact(db_path: str, filepath: str = "", artifact_type: str = "", run_id: Optional[str] = None) -> Optional[str]:
    """Retrieve an artifact's content from the database by filepath or artifact_type strictly scoped to run_id when provided."""
    with _db(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT content FROM campaign_artifacts WHERE 1=1"
        params = []
        if filepath:
            query += " AND filepath = ?"
            params.append(filepath)
        elif artifact_type:
            query += " AND artifact_type = ?"
            params.append(artifact_type)
        if run_id:
            query += " AND run_id = ?"
            params.append(run_id)
        query += " ORDER BY id DESC LIMIT 1"
        cursor.execute(query, params)
        row = cursor.fetchone()
        if row:
            return row["content"]
        return None

def record_learning(db_path: str, run_id: str, category: str, learning: str, tags: Optional[list] = None):
    """Record a learning entry for cross-pass feedback."""
    with _db(db_path) as conn:
        cursor = conn.cursor()
        tags_str = json.dumps(tags or [])
        cursor.execute("""
            INSERT INTO learnings (run_id, category, learning, tags)
            VALUES (?, ?, ?, ?)
        """, (run_id, category, learning, tags_str))

def read_learnings(db_path: str, run_id: Optional[str] = None, category: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve recorded learnings from the database."""
    with _db(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM learnings WHERE 1=1"
        params = []
        if run_id:
            query += " AND run_id = ?"
            params.append(run_id)
        if category:
            query += " AND category = ?"
            params.append(category)
        query += " ORDER BY id ASC"
        cursor.execute(query, params)
        rows = []
        for r in cursor.fetchall():
            row = dict(r)
            try:
                row["tags"] = json.loads(row.get("tags") or "[]")
            except Exception:
                row["tags"] = []
            rows.append(row)
        return rows

def merge_findings(db_path: str, primary_title: str, duplicate_titles: List[str], reason: str, run_id: str = "") -> int:
    """Marks duplicate findings as suppressed/merged in the database."""
    with _db(db_path) as conn:
        cursor = conn.cursor()
        merged_count = 0
        for dup in duplicate_titles:
            cursor.execute("""
                UPDATE findings
                SET status = 'duplicate_merged',
                    description = description || '\n[MERGED: Duplicate of ' || ? || ' - Reason: ' || ? || ']'
                WHERE title = ? AND (run_id = ? OR ? = '')
            """, (primary_title, reason, dup, run_id, run_id))
            merged_count += cursor.rowcount
        return merged_count


def query_historical_lineage(
    db_path: str,
    signature: str = "",
    lineage_id: str = "",
    filepath: str = "",
) -> List[Dict[str, Any]]:
    """Retrieves all historical occurrences and lifecycle states of a finding lineage across runs."""
    with _db(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        if lineage_id:
            query += " AND lineage_id = ?"
            params.append(lineage_id)
        elif signature:
            query += " AND signature = ?"
            params.append(signature)
        elif filepath:
            norm_fp = canonical_filepath(filepath, target_file=filepath)
            query += " AND filepath = ?"
            params.append(norm_fp)
        else:
            return []
        query += " ORDER BY timestamp ASC, id ASC"
        cursor.execute(query, params)
        rows = []
        for r in cursor.fetchall():
            row_dict = dict(r)
            if row_dict.get("line_numbers"):
                try:
                    parsed = json.loads(row_dict["line_numbers"])
                    row_dict["line_numbers"] = parsed if parsed else None
                except Exception:
                    row_dict["line_numbers"] = None
            rows.append(row_dict)
        return rows


def query_security_guidance(db_path: str, filepath: str, run_id: Optional[str] = None) -> Dict[str, Any]:
    """Aggregates active threat models, historical vulnerabilities, triaged false positives,
    recurrent lineages, and learned invariants into actionable security guidance for a target file.
    """
    with _db(db_path) as conn:
        cursor = conn.cursor()
        norm_fp = canonical_filepath(filepath, target_file=filepath)

        # 1. Threat Model & Trust Boundaries
        threat_model_content = read_artifact(db_path, artifact_type="threat_model", run_id=run_id)
        if not threat_model_content:
            threat_model_content = read_artifact(db_path, filepath="workspace/kb/THREAT_MODEL.md", run_id=run_id)

        # 2. Confirmed & Active Vulnerabilities (with verified patches)
        if norm_fp:
            query_confirmed = """
                SELECT * FROM findings
                WHERE filepath = ?
                  AND status IN ('confirmed', 'viable', 'reproduced', 'dynamic_confirmed', 'reported', 'patch_verified')
                ORDER BY timestamp DESC, id DESC
            """
            cursor.execute(query_confirmed, (norm_fp,))
        else:
            query_confirmed = """
                SELECT * FROM findings
                WHERE status IN ('confirmed', 'viable', 'reproduced', 'dynamic_confirmed', 'reported', 'patch_verified')
                ORDER BY timestamp DESC, id DESC
            """
            cursor.execute(query_confirmed)
        confirmed_rows = [dict(r) for r in cursor.fetchall()]

        # 3. Triaged False Positives (to prevent re-introducing or mis-triaging known safe patterns)
        if norm_fp:
            query_fp = """
                SELECT * FROM findings
                WHERE filepath = ?
                  AND status IN ('false_positive', 'non_viable', 'sample_or_test')
                ORDER BY timestamp DESC, id DESC
            """
            cursor.execute(query_fp, (norm_fp,))
        else:
            query_fp = """
                SELECT * FROM findings
                WHERE status IN ('false_positive', 'non_viable', 'sample_or_test')
                ORDER BY timestamp DESC, id DESC
            """
            cursor.execute(query_fp)
        fp_rows = [dict(r) for r in cursor.fetchall()]

        # 4. Recurrent Lineages (lineage_ids appearing >= 2 times)
        if norm_fp:
            query_recurrent = """
                SELECT lineage_id, MIN(signature) as signature, MIN(title) as title, COUNT(*) as occurrence_count,
                       MIN(timestamp) as first_seen, MAX(timestamp) as last_seen,
                       GROUP_CONCAT(DISTINCT status) as observed_statuses
                FROM findings
                WHERE filepath = ?
                  AND lineage_id IS NOT NULL AND lineage_id != ''
                GROUP BY lineage_id
                HAVING COUNT(*) >= 2
                ORDER BY occurrence_count DESC
            """
            cursor.execute(query_recurrent, (norm_fp,))
        else:
            query_recurrent = """
                SELECT lineage_id, MIN(signature) as signature, MIN(title) as title, COUNT(*) as occurrence_count,
                       MIN(timestamp) as first_seen, MAX(timestamp) as last_seen,
                       GROUP_CONCAT(DISTINCT status) as observed_statuses
                FROM findings
                WHERE lineage_id IS NOT NULL AND lineage_id != ''
                GROUP BY lineage_id
                HAVING COUNT(*) >= 2
                ORDER BY occurrence_count DESC
            """
            cursor.execute(query_recurrent)
        recurrent_lineages = [dict(r) for r in cursor.fetchall()]

        # 5. Learned Invariants & Trajectory Rules
        learnings = read_learnings(db_path)

        # Build guidance summary
        guidance_lines = [
            f"# Security Advisory & Development Guidance for: {norm_fp or 'Repository Scope'}",
            "",
            "## 1. Threat Model & Trust Boundaries Context",
        ]
        if threat_model_content:
            guidance_lines.append(threat_model_content.strip())
        else:
            guidance_lines.append("No active threat model recorded. Treat all external network inputs as untrusted.")

        guidance_lines.extend(["", "## 2. Historical Vulnerabilities & Verified Remediation Patterns"])
        if confirmed_rows:
            for c in confirmed_rows:
                guidance_lines.append(f"- **[{c.get('severity', 'UNKNOWN')}] {c.get('title')}** (CWE: {c.get('cwe', 'N/A')}, Status: `{c.get('status')}`)")
                guidance_lines.append(f"  - **Description**: {c.get('description', '').strip()}")
                if c.get("remediation"):
                    guidance_lines.append(f"  - **Remediation Invariant**: {c.get('remediation').strip()}")
                if c.get("patch_diff"):
                    guidance_lines.append(f"  - **Verified Patch Diff**:\n```diff\n{c.get('patch_diff').strip()}\n```")
        else:
            guidance_lines.append("No historical vulnerabilities recorded for this file.")

        guidance_lines.extend(["", "## 3. Triaged False Positives & Legitimate Intentional Patterns"])
        if fp_rows:
            for fp_item in fp_rows:
                reason = fp_item.get("triage_reasoning") or "Triaged as intentional / safe functionality."
                guidance_lines.append(f"- **{fp_item.get('title')}** (Status: `{fp_item.get('status')}`)")
                guidance_lines.append(f"  - **Triage Rationale**: {reason.strip()}")
        else:
            guidance_lines.append("No historical false positive records for this file.")

        guidance_lines.extend(["", "## 4. Recurrent Pitfalls & Regression Alerts"])
        if recurrent_lineages:
            for rec in recurrent_lineages:
                guidance_lines.append(f"- **Lineage `{rec.get('lineage_id')}` ({rec.get('title')})**: recurred **{rec.get('occurrence_count')} times** across passes/runs.")
                guidance_lines.append(f"  - First seen: {rec.get('first_seen')}, Last seen: {rec.get('last_seen')}, Observed statuses: `{rec.get('observed_statuses')}`")
        else:
            guidance_lines.append("No recurring regressions detected.")

        guidance_lines.extend(["", "## 5. Verified Security Guardrails & Invariants"])
        if learnings:
            for l in learnings:
                guidance_lines.append(f"- **[{l.get('category', 'GENERAL')}]**: {l.get('learning')}")
        else:
            guidance_lines.append("No learned trajectory invariants recorded.")

        return {
            "filepath": norm_fp,
            "threat_model": threat_model_content,
            "confirmed_vulnerabilities": confirmed_rows,
            "false_positives": fp_rows,
            "recurrent_lineages": recurrent_lineages,
            "learned_invariants": learnings,
            "guidance_summary": "\n".join(guidance_lines),
        }



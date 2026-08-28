import hashlib
import os
import sqlite3
import json
import uuid
from contextlib import contextmanager
from typing import Optional, List, Dict, Any

CURRENT_SCHEMA_VERSION = 3

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
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS okf_concepts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                concept_id TEXT,
                type TEXT NOT NULL,
                title TEXT NOT NULL,
                resource TEXT,
                tags TEXT DEFAULT '[]',
                status TEXT DEFAULT 'stable',
                trust_tier TEXT NOT NULL DEFAULT 'unverified',
                verified_by TEXT DEFAULT '[]',
                generated_by TEXT,
                snapshot_id TEXT,
                description TEXT,
                sources TEXT DEFAULT '[]',
                body_markdown TEXT,
                raw_markdown TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(run_id, concept_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_okf_resource ON okf_concepts(resource)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_okf_type ON okf_concepts(type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_okf_concept_id ON okf_concepts(concept_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_okf_trust_tier ON okf_concepts(trust_tier)")
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

def parse_okf_markdown(content: str, default_concept_id: str = "") -> Optional[Dict[str, Any]]:
    """Parses an OKF v0.2 markdown document (YAML frontmatter + markdown body) into a structured concept dictionary."""
    if not content or not isinstance(content, str):
        return None

    content_clean = content.strip()
    frontmatter_dict: Dict[str, Any] = {}
    body = content_clean

    # 1. Match YAML frontmatter delimited strictly by '---' on its own line at the start of the file
    # and closed by '---' on its own line. Never split on '---' substrings inside diffs (e.g. '--- a/foo.py').
    lines = content_clean.splitlines(keepends=True)
    if lines and lines[0].strip() == "---":
        closing_idx = -1
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                closing_idx = i
                break
        if closing_idx != -1:
            fm_raw = "".join(lines[1:closing_idx]).strip()
            body = "".join(lines[closing_idx + 1:]).strip()
            try:
                import yaml
                loaded = yaml.safe_load(fm_raw)
                if isinstance(loaded, dict):
                    frontmatter_dict = loaded
            except Exception:
                # Robust fallback for key-value pairs, lists, and dicts
                current_list_key = None
                for line in fm_raw.splitlines():
                    line_str = line.strip()
                    if not line_str or line_str.startswith("#"):
                        continue
                    if line_str.startswith("- ") and current_list_key:
                        item_str = line_str[2:].strip()
                        if ":" in item_str:
                            sub_dict = {}
                            for sub_part in item_str.split(","):
                                if ":" in sub_part:
                                    sk, sv = sub_part.split(":", 1)
                                    sub_dict[sk.strip().strip("{}")] = sv.strip().strip("'\"{}")
                            frontmatter_dict.setdefault(current_list_key, []).append(sub_dict)
                        else:
                            frontmatter_dict.setdefault(current_list_key, []).append(item_str.strip("'\""))
                    elif ":" in line_str:
                        k, v = line_str.split(":", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if not v:
                            current_list_key = k
                            frontmatter_dict[k] = []
                        else:
                            current_list_key = None
                            if v.startswith("[") and v.endswith("]"):
                                frontmatter_dict[k] = [x.strip().strip("'\"") for x in v[1:-1].split(",") if x.strip()]
                            else:
                                frontmatter_dict[k] = v

    # 2. Derive concept type and title
    concept_type = str(frontmatter_dict.get("type") or "").strip()
    title = str(frontmatter_dict.get("title") or "").strip()

    if not concept_type:
        clean_cid = default_concept_id.replace("\\", "/")
        if clean_cid.startswith("workspace/kb/entities/") or "/entities/" in clean_cid:
            concept_type = "Component Entity"
        elif "THREAT_MODEL" in clean_cid or "threat_model" in clean_cid:
            concept_type = "Threat Model"
        elif "architecture" in clean_cid.lower() or "summary" in clean_cid.lower():
            concept_type = "Architecture Summary"
        elif clean_cid.startswith("workspace/kb/vulnerabilities/") or "/vulnerabilities/" in clean_cid:
            concept_type = "Vulnerability Pattern"
        elif "invariant" in clean_cid or "guardrail" in clean_cid:
            concept_type = "Security Invariant"
        else:
            concept_type = "Generic Concept"

    if not title:
        for line in body.splitlines():
            line_str = line.strip()
            if line_str.startswith("# ") and not line_str.startswith("##"):
                title = line_str.removeprefix("# ").strip()
                break
        if not title:
            title = os.path.basename(default_concept_id).removesuffix(".md") if default_concept_id else "Untitled Concept"

    # 3. Derive Trust Tier per OKF v0.2 §5.3
    verified_val = frontmatter_dict.get("verified") or []
    if isinstance(verified_val, dict):
        verified_list = [verified_val]
    elif isinstance(verified_val, list):
        verified_list = verified_val
    else:
        verified_list = []

    trust_tier = "unverified"
    if verified_list:
        has_human = False
        has_verifier = False
        for v in verified_list:
            if isinstance(v, dict):
                by_actor = str(v.get("by") or "")
                if by_actor.startswith("human:"):
                    has_human = True
                if by_actor:
                    has_verifier = True
            elif isinstance(v, str):
                if v.startswith("human:"):
                    has_human = True
                if v:
                    has_verifier = True
        if has_human:
            trust_tier = "human_reviewed"
        elif has_verifier:
            trust_tier = "machine_confirmed"

    # Parse tags
    tags_val = frontmatter_dict.get("tags") or []
    if isinstance(tags_val, str):
        tags_list = [t.strip() for t in tags_val.strip("[]").split(",") if t.strip()]
    elif isinstance(tags_val, list):
        tags_list = [str(t).strip() for t in tags_val]
    else:
        tags_list = []

    # Parse generated
    gen_val = frontmatter_dict.get("generated")
    if isinstance(gen_val, dict):
        gen_by = str(gen_val.get("by") or "")
    elif isinstance(gen_val, str):
        gen_by = gen_val
    else:
        gen_by = ""

    # Parse resource (canonical target file)
    raw_resource = str(frontmatter_dict.get("resource") or "").strip()
    norm_resource = canonical_filepath(raw_resource, target_file=raw_resource) if raw_resource else ""

    concept_id = default_concept_id or frontmatter_dict.get("id") or title.lower().replace(" ", "_")

    return {
        "concept_id": concept_id,
        "type": concept_type,
        "title": title,
        "resource": norm_resource,
        "tags": tags_list,
        "status": str(frontmatter_dict.get("status") or "stable"),
        "trust_tier": trust_tier,
        "verified_by": verified_list,
        "generated_by": gen_by,
        "snapshot_id": str(frontmatter_dict.get("snapshot_id") or ""),
        "description": str(frontmatter_dict.get("description") or ""),
        "sources": frontmatter_dict.get("sources") if isinstance(frontmatter_dict.get("sources"), list) else [],
        "body_markdown": body,
        "raw_markdown": content_clean,
    }


def record_okf_concept(db_path: str, run_id: str, concept: Dict[str, Any]):
    """Records or updates a structured OKF v0.2 concept in the okf_concepts table."""
    with _db(db_path) as conn:
        cursor = conn.cursor()
        concept_id = concept.get("concept_id") or concept.get("title") or "concept"
        c_type = concept.get("type") or "Generic Concept"
        title = concept.get("title") or concept_id
        res = concept.get("resource") or ""
        tags_str = json.dumps(concept.get("tags") or [])
        status = concept.get("status") or "stable"
        trust_tier = concept.get("trust_tier") or "unverified"
        ver_str = json.dumps(concept.get("verified_by") or [])
        gen_by = concept.get("generated_by") or ""
        snap_id = concept.get("snapshot_id") or ""
        desc = concept.get("description") or ""
        sources_str = json.dumps(concept.get("sources") or [])
        body = concept.get("body_markdown") or ""
        raw = concept.get("raw_markdown") or ""

        cursor.execute("DELETE FROM okf_concepts WHERE run_id = ? AND concept_id = ?", (run_id, concept_id))
        cursor.execute("""
            INSERT OR REPLACE INTO okf_concepts (
                run_id, concept_id, type, title, resource, tags, status,
                trust_tier, verified_by, generated_by, snapshot_id, description,
                sources, body_markdown, raw_markdown
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id, concept_id, c_type, title, res, tags_str, status,
            trust_tier, ver_str, gen_by, snap_id, desc,
            sources_str, body, raw
        ))


def read_okf_concepts(
    db_path: str,
    resource: str = "",
    concept_type: str = "",
    tag: str = "",
    trust_tier: str = "",
    run_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Queries OKF concepts from the database by resource, type, tag, trust_tier, or run_id."""
    with _db(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM okf_concepts WHERE 1=1"
        params = []
        if resource:
            norm_res = canonical_filepath(resource, target_file=resource)
            query += " AND resource = ?"
            params.append(norm_res)
        if concept_type:
            query += " AND type = ?"
            params.append(concept_type)
        if trust_tier:
            query += " AND trust_tier = ?"
            params.append(trust_tier)
        if run_id:
            query += " AND (run_id = ? OR run_id = '')"
            params.append(run_id)
        query += " ORDER BY id ASC"
        cursor.execute(query, params)
        rows = []
        for r in cursor.fetchall():
            row_dict = dict(r)
            for json_field in ("tags", "verified_by", "sources"):
                try:
                    row_dict[json_field] = json.loads(row_dict.get(json_field) or "[]")
                except Exception:
                    row_dict[json_field] = []
            if tag and tag not in row_dict.get("tags", []):
                continue
            rows.append(row_dict)
        return rows


def export_okf_bundle(db_path: str, output_dir: str, run_id: Optional[str] = None) -> List[str]:
    """Exports all okf_concepts from SQLite into a fully conformant OKF v0.2 directory bundle on disk."""
    concepts = read_okf_concepts(db_path, run_id=run_id)
    os.makedirs(output_dir, exist_ok=True)
    exported_files = []

    # Write root index.md catalog
    index_path = os.path.join(output_dir, "index.md")
    index_lines = [
        "---",
        'okf_version: "0.2"',
        "title: Mantis Knowledge Base Catalog",
        "---",
        "",
        "# Mantis Knowledge Base Concepts",
        ""
    ]

    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for c in concepts:
        by_type.setdefault(c.get("type", "General"), []).append(c)

    for c_type, items in by_type.items():
        index_lines.append(f"## {c_type}")
        for item in items:
            cid = item.get("concept_id") or "concept"
            rel_file = cid if cid.endswith(".md") else f"{cid}.md"
            if rel_file.startswith("workspace/kb/"):
                rel_file = rel_file.removeprefix("workspace/kb/")
            desc = item.get("description") or item.get("title")
            index_lines.append(f"* [{item.get('title')}]({rel_file}) - {desc}")
        index_lines.append("")

    with open(index_path, "w", encoding="utf-8") as f:
        f.write("\n".join(index_lines))
    exported_files.append(index_path)

    for c in concepts:
        cid = c.get("concept_id") or "concept"
        rel_path = cid if cid.endswith(".md") else f"{cid}.md"
        if rel_path.startswith("workspace/kb/"):
            rel_path = rel_path.removeprefix("workspace/kb/")
        full_dest = os.path.join(output_dir, rel_path)
        os.makedirs(os.path.dirname(full_dest), exist_ok=True)

        fm = {
            "type": c.get("type"),
            "title": c.get("title"),
            "status": c.get("status", "stable"),
        }
        if c.get("resource"):
            fm["resource"] = c.get("resource")
        if c.get("tags"):
            fm["tags"] = c.get("tags")
        if c.get("description"):
            fm["description"] = c.get("description")
        if c.get("snapshot_id"):
            fm["snapshot_id"] = c.get("snapshot_id")
        if c.get("generated_by"):
            fm["generated"] = {"by": c.get("generated_by")}
        if c.get("verified_by"):
            fm["verified"] = c.get("verified_by")
        if c.get("sources"):
            fm["sources"] = c.get("sources")

        try:
            import yaml
            fm_yaml = yaml.dump(fm, sort_keys=False).strip()
        except Exception:
            fm_yaml = f"type: {fm.get('type')}\ntitle: {fm.get('title')}"

        file_content = f"---\n{fm_yaml}\n---\n\n{c.get('body_markdown', '').strip()}\n"
        with open(full_dest, "w", encoding="utf-8") as f:
            f.write(file_content)
        exported_files.append(full_dest)

    return exported_files


def import_okf_bundle(db_path: str, bundle_dir: str, run_id: str = "imported") -> int:
    """Imports an OKF v0.2 directory bundle from disk into the SQLite okf_concepts table."""
    imported_count = 0
    if not os.path.isdir(bundle_dir):
        return 0

    for root, _, files in os.walk(bundle_dir):
        for f in files:
            if f.endswith(".md") and f != "index.md":
                full_p = os.path.join(root, f)
                rel_p = os.path.relpath(full_p, bundle_dir).replace("\\", "/")
                try:
                    with open(full_p, "r", encoding="utf-8") as fh:
                        content = fh.read()
                    parsed = parse_okf_markdown(content, default_concept_id=rel_p)
                    if parsed:
                        record_okf_concept(db_path, run_id, parsed)
                        record_artifact(db_path, run_id, parsed.get("type", "okf_concept"), rel_p, content)
                        imported_count += 1
                except Exception:
                    pass
    return imported_count


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

    # Also automatically index into okf_concepts if the artifact is markdown/KB documentation
    if (
        filepath.endswith((".md", ".markdown"))
        or "workspace/kb/" in filepath
        or artifact_type in ("threat_model", "summary", "entity", "architecture")
        or content.strip().startswith(("---", "#"))
    ):
        try:
            parsed = parse_okf_markdown(content, default_concept_id=filepath)
            if parsed:
                if artifact_type == "threat_model" and parsed["type"] in ("Generic Concept", "Untitled Concept"):
                    parsed["type"] = "Threat Model"
                elif artifact_type in ("summary", "architecture") and parsed["type"] in ("Generic Concept", "Untitled Concept"):
                    parsed["type"] = "Architecture Summary"
                record_okf_concept(db_path, run_id, parsed)
        except Exception:
            pass

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
    """Aggregates active threat models, OKF concepts, historical vulnerabilities, triaged false positives,
    recurrent lineages, and verified remediation patterns into actionable security guidance for a target file.
    """
    with _db(db_path) as conn:
        cursor = conn.cursor()
        norm_fp = canonical_filepath(filepath, target_file=filepath)

        # 1. OKF Concepts (Scoped to Target File)
        scoped_okf = read_okf_concepts(db_path, resource=norm_fp, run_id=run_id) if norm_fp else read_okf_concepts(db_path, run_id=run_id)
        
        # Extract scoped threat boundaries, component entities, architecture summaries, and security invariants
        threat_concepts = [c for c in scoped_okf if c.get("type") in ("Threat Boundary", "Threat Model")]
        entity_concepts = [c for c in scoped_okf if c.get("type") in ("Component Entity", "Software Entity", "Hardware Entity", "Architecture Summary")]
        invariant_concepts = [c for c in scoped_okf if c.get("type") in ("Security Invariant", "Guardrail")]

        # Fallback to system-wide threat model if no scoped threat boundary exists
        threat_model_content = ""
        if threat_concepts:
            threat_model_content = "\n\n".join(f"### {c.get('title')}\n{c.get('body_markdown', '').strip()}" for c in threat_concepts)
        else:
            threat_model_content = read_artifact(db_path, artifact_type="threat_model", run_id=run_id) or ""
            if not threat_model_content:
                threat_model_content = read_artifact(db_path, filepath="workspace/kb/THREAT_MODEL.md", run_id=run_id) or ""

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

        # Derive Highest Trust Tier for target file per OKF v0.2 §5.3
        trust_badge = "HEURISTIC"
        if any(c.get("trust_tier") == "human_reviewed" for c in scoped_okf):
            trust_badge = "HUMAN-REVIEWED"
        elif any(c.get("trust_tier") == "machine_confirmed" for c in scoped_okf) or any(f.get("status") in ("patch_verified", "dynamic_confirmed", "reproduced") for f in confirmed_rows):
            trust_badge = "SANDBOX-CONFIRMED"

        # Build guidance summary
        guidance_lines = [
            f"# Security Advisory & Development Guidance for: {norm_fp or 'Repository Scope'}",
            f"**[OKF TRUST TIER: {trust_badge}]**",
            "",
            "## 1. Threat Model & Trust Boundaries Context",
        ]
        if threat_model_content:
            guidance_lines.append(threat_model_content.strip())
        else:
            guidance_lines.append("No active threat model recorded. Treat all external network inputs as untrusted.")

        # Entity context if available
        if entity_concepts:
            guidance_lines.extend(["", "## 2. Component Architecture & Known Constraints"])
            for ent in entity_concepts:
                badge = f"[{ent.get('trust_tier', 'unverified').upper().replace('_', '-')}]"
                guidance_lines.append(f"### {ent.get('title')} {badge}")
                if ent.get("description"):
                    guidance_lines.append(f"*{ent.get('description')}*")
                if ent.get("body_markdown"):
                    guidance_lines.append(f"{ent.get('body_markdown').strip()}\n")

        # Security Invariants / Guardrails
        if invariant_concepts or learnings:
            guidance_lines.extend(["", "## 3. Verified Security Guardrails & Invariants"])
            for inv in invariant_concepts:
                tier = inv.get("trust_tier", "unverified").upper().replace("_", "-")
                guidance_lines.append(f"- ⛔ **[{tier}] {inv.get('title')}**: {inv.get('description') or inv.get('body_markdown', '').strip()}")
            for l in learnings:
                guidance_lines.append(f"- ℹ️ **[{l.get('category', 'GENERAL')}]**: {l.get('learning')}")

        guidance_lines.extend(["", "## 4. Historical Vulnerabilities & Verified Remediation Patterns"])
        if confirmed_rows:
            for c in confirmed_rows:
                guidance_lines.append(f"- **[{c.get('severity', 'UNKNOWN')}] {c.get('title')}** (CWE: {c.get('cwe', 'N/A')}, Status: `{c.get('status')}`)")
                guidance_lines.append(f"  - **Description**: {c.get('description', '').strip()}")
                if c.get("remediation"):
                    guidance_lines.append(f"  - **Remediation Invariant**: {c.get('remediation').strip()}")
                if c.get("patch_status"):
                    guidance_lines.append(f"  - **Patch Status**: `{c.get('patch_status')}`")
                if c.get("patch_diff"):
                    guidance_lines.append(f"  - **Verified Patch Diff (Few-Shot Pattern)**:\n```diff\n{c.get('patch_diff').strip()}\n```")
        else:
            guidance_lines.append("No historical vulnerabilities recorded for this file.")

        guidance_lines.extend(["", "## 5. Triaged False Positives & Legitimate Intentional Patterns"])
        if fp_rows:
            for fp_item in fp_rows:
                reason = fp_item.get("triage_reasoning") or "Triaged as intentional / safe functionality."
                guidance_lines.append(f"- **{fp_item.get('title')}** (Status: `{fp_item.get('status')}`)")
                guidance_lines.append(f"  - **Triage Rationale**: {reason.strip()}")
        else:
            guidance_lines.append("No historical false positive records for this file.")

        if recurrent_lineages:
            guidance_lines.extend(["", "## 6. Recurrent Pitfalls & Regression Alerts"])
            for rec in recurrent_lineages:
                guidance_lines.append(f"- **Lineage `{rec.get('lineage_id')}` ({rec.get('title')})**: recurred **{rec.get('occurrence_count')} times** across passes/runs.")
                guidance_lines.append(f"  - First seen: {rec.get('first_seen')}, Last seen: {rec.get('last_seen')}, Observed statuses: `{rec.get('observed_statuses')}`")

        return {
            "filepath": norm_fp,
            "trust_tier": trust_badge,
            "threat_model": threat_model_content,
            "okf_concepts": scoped_okf,
            "confirmed_vulnerabilities": confirmed_rows,
            "false_positives": fp_rows,
            "recurrent_lineages": recurrent_lineages,
            "learned_invariants": learnings,
            "guidance_summary": "\n".join(guidance_lines),
        }



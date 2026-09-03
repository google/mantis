import hashlib
import os
import sqlite3
import json
import uuid
import re
from contextlib import contextmanager
from typing import Optional, List, Dict, Any, Union

from core.embeddings import (
    compute_embedding,
    vector_to_blob,
    blob_to_vector,
    cosine_similarity,
    find_nearest_lineage,
    DEFAULT_SIMILARITY_THRESHOLD,
    _parse_similarity_threshold,
)
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
                rca_summary TEXT,
                embedding BLOB,
                UNIQUE(filepath, title, description, line_numbers, run_id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_filepath ON findings(filepath)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_lineage ON findings(lineage_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_signature ON findings(signature)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS lineage_vectors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lineage_id TEXT NOT NULL UNIQUE,
                filepath TEXT,
                cwe TEXT,
                rca_summary TEXT,
                model TEXT DEFAULT '',
                dimension INTEGER DEFAULT 0,
                embedding BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_lineage_vectors_lineage ON lineage_vectors(lineage_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_lineage_vectors_filepath ON lineage_vectors(filepath)")

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
    code_exts = (
        ".py", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".js", ".jsx", ".ts", ".tsx",
        ".go", ".java", ".rs", ".rb", ".php", ".cs", ".kt", ".swift", ".m", ".scala", ".sh", ".sql"
    )

    # 1. Backticked symbol anywhere in title: `get_user` -> get_user (skip file paths like `src/auth.py`)
    backtick_match = re.search(r"`([a-zA-Z0-9_\-/\.]+)(?:\(\))?`", title_clean)
    if backtick_match:
        sym = backtick_match.group(1).strip("/.()").lower()
        if not sym.endswith(code_exts) and "/" not in sym and "\\" not in sym:
            return sym

    # 2. Endpoint notation: /view, /api/cart, /backup (not file paths like src/parser.c)
    ep_match = re.search(r"(?:^|[\s`])(/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)*)", title_clean)
    if ep_match:
        ep_cand = ep_match.group(1).strip("/.()").replace("/", "_").lower()
        if not ep_cand.endswith(code_exts) and len(ep_cand) >= 2:
            return ep_cand

    # 3. Explicit symbol following preposition in title: 'in get_user', 'in list_orders', 'in function hydrate'
    prep_match = re.search(
        r"\b(?:in|at|within|inside|for)\s+(?:function\s+|method\s+|routine\s+|handler\s+|endpoint\s+|def\s+)?`?([a-zA-Z_][a-zA-Z0-9_/\.]+)(?:\(\))?`?",
        title_clean,
        re.IGNORECASE
    )
    if prep_match:
        raw_sym = prep_match.group(1).strip("/.()").lower()
        if not raw_sym.endswith(code_exts) and "/" not in raw_sym and "\\" not in raw_sym:
            stopwords_sym = {
                "the", "a", "an", "this", "all", "user", "file", "path", "order", "query", "input",
                "database", "system", "memory", "header", "comment", "token", "session", "request",
                "response", "cart", "service", "views", "controllers", "api"
            }
            if raw_sym not in stopwords_sym and len(raw_sym) >= 3:
                return raw_sym

    # 4. Function call notation in title: get_user(), list_orders()
    fn_match = re.search(r"\b([a-zA-Z_][a-zA-Z0-9_]+)\(\)", title_clean)
    if fn_match:
        return fn_match.group(1).lower()

    # 5. Check description for backticked symbol, function <symbol>, or method <symbol>
    desc_backtick = re.search(r"`([a-zA-Z0-9_\-/\.]+)(?:\(\))?`", description)
    if desc_backtick:
        sym = desc_backtick.group(1).strip("/.()").lower()
        if len(sym) >= 3 and not sym.isdigit() and not sym.endswith(code_exts) and "/" not in sym and "\\" not in sym:
            return sym

    desc_fn = re.search(r"\b(?:function|method|handler|routine|def)\s+`?([a-zA-Z_][a-zA-Z0-9_]+)`?(?:\(\))?", description, re.IGNORECASE)
    if desc_fn:
        return desc_fn.group(1).lower()

    # 6. Check code_paths
    if code_paths and isinstance(code_paths, list):
        for cp in code_paths:
            if isinstance(cp, str) and not cp.startswith("http"):
                parts = cp.split(":")
                # Case 1: file:line:symbol (e.g. auth.py:42:authenticate_user)
                if len(parts) > 2:
                    cand = parts[2].strip().strip("/.()").lower()
                    if cand and re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", cand):
                        return cand
                # Case 2: symbol directly in code_paths (no slashes, no code extension)
                clean_cp = parts[0].strip()
                if clean_cp and not clean_cp.endswith(code_exts) and "/" not in clean_cp and "\\" not in clean_cp:
                    if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", clean_cp):
                        return clean_cp.lower()
            elif isinstance(cp, dict):
                cand = cp.get("symbol") or cp.get("function") or cp.get("target_symbol")
                if cand and isinstance(cand, str):
                    clean_cand = cand.strip().strip("/.()").lower()
                    if clean_cand and not clean_cand.endswith(code_exts) and "/" not in clean_cand:
                        return clean_cand

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


def generate_rca_summary(finding: Union[dict, Any], model: Optional[str] = None, **kwargs) -> str:
    """Generates a standardized Root Cause Analysis (RCA) summary for a finding.

    Extracts:
    1. Component (canonical filepath / symbol)
    2. Vulnerability Class (canonical CWE)
    3. Root Cause Mechanism
    4. Failure Condition
    5. Taint Dataflow
    """
    f = finding.model_dump() if hasattr(finding, "model_dump") else (finding if isinstance(finding, dict) else dict(finding))

    # If already populated, return as-is
    if f.get("rca_summary") and str(f["rca_summary"]).strip():
        return str(f["rca_summary"]).strip()

    raw_fp = str(f.get("filepath") or "")
    norm_fp = canonical_filepath(raw_fp, target_file=raw_fp)
    raw_title = str(f.get("title") or "")
    raw_desc = str(f.get("description") or "")
    raw_cwe = str(f.get("cwe") or "")
    canonical_cwe = extract_canonical_cwe(raw_cwe, raw_title, raw_desc)
    target_symbol = extract_target_symbol(raw_title, raw_desc, f.get("code_paths"))

    # Check if live LLM extraction should be attempted
    should_use_llm = (
        not (
            os.environ.get("MOCK_EMBEDDINGS") == "1"
            or os.environ.get("MANTIS_OFFLINE_EMBEDDINGS") == "1"
            or os.environ.get("MANTIS_MOCK_EMBEDDINGS") == "1"
            or model in ("mock", "offline")
        )
        and bool(os.environ.get("VERTEXAI_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GEMINI_API_KEY"))
    )

    if should_use_llm:
        try:
            from core.config import get_llm_kwargs
            import litellm
            resolved_model, llm_kwargs = get_llm_kwargs(model_id=model)
            prompt = (
                "You are an expert security analyst. Extract a concise, standardized Root Cause Analysis (RCA) summary "
                "for this vulnerability finding. Output EXACTLY these 5 lines:\n"
                "Component: <filepath or function>\n"
                "Vulnerability Class: <canonical CWE and name>\n"
                "Root Cause Mechanism: <underlying programming/logic flaw>\n"
                "Failure Condition: <what specific input or state causes failure>\n"
                "Taint Dataflow: <source to sink flow>\n\n"
                f"Finding Details:\n"
                f"Title: {raw_title}\n"
                f"Filepath: {norm_fp}\n"
                f"CWE: {canonical_cwe}\n"
                f"Symbol: {target_symbol}\n"
                f"Description: {raw_desc}\n"
                f"Remediation: {f.get('remediation', '')}\n"
            )
            response = litellm.completion(
                model=resolved_model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=300,
                temperature=0.0,
                **llm_kwargs,
            )
            content = response.choices[0].message.content.strip()
            if "Component:" in content and "Vulnerability Class:" in content:
                return content
        except Exception:
            pass

    # Deterministic structural RCA extraction (fail-safe and offline)
    comp = norm_fp or target_symbol or "unknown_component"
    vuln_class = canonical_cwe if canonical_cwe != "CWE-UNKNOWN" else "CWE-SecurityFlaw"
    mechanism = raw_title or "Unspecified vulnerability mechanism"
    failure = raw_desc or f.get("remediation") or raw_title
    taint = f"{target_symbol} in {norm_fp}" if target_symbol else (norm_fp or "untrusted input")

    return (
        f"Component: {comp}\n"
        f"Vulnerability Class: {vuln_class}\n"
        f"Root Cause Mechanism: {mechanism}\n"
        f"Failure Condition: {failure}\n"
        f"Taint Dataflow: {taint}"
    )


def resolve_ancestor_lineage(
    cursor: sqlite3.Cursor,
    filepath: str,
    signature: str,
    cwe: str = "",
    symbol: str = "",
    title: str = "",
    description: str = "",
    line_numbers: str = "[]",
    rca_summary: str = "",
    embedding: Optional[Union[bytes, List[float]]] = None,
    threshold: Optional[float] = None,
) -> str:
    """Resolves ancestor lineage_id using the 3-Tier Deduplication Ladder.

    - Tier 1: Fast-Path Exact Heuristic Anchors (< 1ms, 0 tokens)
    - Tier 2: RCA Normalization (standardized Root Cause Analysis)
    - Tier 3: Vector Embedding & Cosine Similarity (nearest-neighbor scan >= threshold)
    """
    eff_threshold = _parse_similarity_threshold(threshold)
    norm_fp = canonical_filepath(filepath, target_file=filepath)
    base_name = os.path.basename(norm_fp)
    norm_cwe = extract_canonical_cwe(cwe, title, description)
    norm_sym = symbol.lower() if symbol else extract_target_symbol(title, description)

    # -------------------------------------------------------------------------
    # Tier 1: Fast-Path Exact Heuristic Anchors
    # -------------------------------------------------------------------------
    # 1a. Exact Stable Content Signature Match (< 1ms, 0 tokens)
    if signature:
        cursor.execute("""
            SELECT lineage_id FROM findings
            WHERE signature = ? AND lineage_id IS NOT NULL AND lineage_id != ''
            ORDER BY id DESC LIMIT 1
        """, (signature,))
        row = cursor.fetchone()
        if row and row[0]:
            return row[0]

    # 1b. File + Normalized CWE + Exact Target Symbol Match
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

    # 1c. Strict Line Proximity Match on exact filepath if and only if symbol is empty
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

    # -------------------------------------------------------------------------
    # Tier 2 & Tier 3: RCA Normalization & Vector Embedding Cosine Similarity
    # -------------------------------------------------------------------------
    if not rca_summary:
        rca_summary = generate_rca_summary({
            "filepath": norm_fp,
            "title": title,
            "description": description,
            "cwe": norm_cwe,
            "symbol": norm_sym,
            "line_numbers": line_numbers,
        })

    if embedding is None:
        emb_vec = compute_embedding(rca_summary)
        emb_blob = vector_to_blob(emb_vec)
    elif isinstance(embedding, bytes):
        emb_blob = embedding
        emb_vec = blob_to_vector(emb_blob)
    else:
        emb_vec = list(embedding)
        emb_blob = vector_to_blob(emb_vec)

    # Scan lineage vectors with cosine similarity >= eff_threshold
    matched_lineage = find_nearest_lineage(
        cursor=cursor,
        query_vector=emb_vec,
        threshold=eff_threshold,
        filepath=norm_fp,
        cwe=norm_cwe,
    )
    if matched_lineage:
        return matched_lineage

    # Tier 3 Fallback -> Fail closed, mint fresh UUIDv4 and register lineage vector
    new_lineage_id = str(uuid.uuid4())
    if emb_blob:
        try:
            emb_dim = len(emb_vec) if emb_vec else len(emb_blob) // 4
            cursor.execute("""
                INSERT OR REPLACE INTO lineage_vectors (lineage_id, filepath, cwe, rca_summary, model, dimension, embedding)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (new_lineage_id, norm_fp, norm_cwe, rca_summary, os.environ.get("EMBEDDING_MODEL", "vertex_ai/gemini-embedding-001"), emb_dim, emb_blob))
        except Exception:
            pass

    return new_lineage_id


def write_findings(db_path: str, filepath: str, findings: list, run_id: str = "", status: str = ""):
    """Write structured findings to the database contextually associated with their canonical filepaths, stable signatures, lineages, RCA summaries, and vector embeddings."""
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

            # Compute or inherit standardized RCA summary and vector embedding
            rca_summary = str(finding.get("rca_summary") or "").strip()
            if not rca_summary:
                rca_summary = generate_rca_summary({
                    "filepath": finding_filepath,
                    "title": raw_title,
                    "description": raw_desc,
                    "cwe": canonical_cwe,
                    "symbol": target_symbol,
                    "line_numbers": line_numbers,
                    "remediation": finding.get("remediation"),
                    "code_paths": finding.get("code_paths"),
                })

            raw_emb = finding.get("embedding")
            if raw_emb is None:
                emb_vec = compute_embedding(rca_summary)
                emb_blob = vector_to_blob(emb_vec)
            elif isinstance(raw_emb, bytes):
                emb_blob = raw_emb
                emb_vec = blob_to_vector(emb_blob)
            elif isinstance(raw_emb, (list, tuple)):
                emb_vec = list(raw_emb)
                emb_blob = vector_to_blob(emb_vec)
            else:
                emb_vec = compute_embedding(rca_summary)
                emb_blob = vector_to_blob(emb_vec)

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
                    rca_summary=rca_summary,
                    embedding=emb_vec,
                )

            # Ensure lineage vector is recorded in lineage_vectors table
            if lineage_id and emb_blob:
                try:
                    emb_dim = len(emb_vec) if emb_vec else len(emb_blob) // 4
                    cursor.execute("""
                        INSERT OR IGNORE INTO lineage_vectors (lineage_id, filepath, cwe, rca_summary, model, dimension, embedding)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (lineage_id, finding_filepath, canonical_cwe, rca_summary, os.environ.get("EMBEDDING_MODEL", "vertex_ai/gemini-embedding-001"), emb_dim, emb_blob))
                except Exception:
                    pass

            triage_reasoning = str(finding.get("reasoning") or finding.get("triage_reasoning") or finding.get("critic_reasoning") or "")
            patch_diff = str(finding.get("patch_diff") or "")
            patch_status = str(finding.get("patch_status") or "")

            cursor.execute("""
                INSERT OR REPLACE INTO findings (
                    run_id, filepath, title, severity, description, line_numbers,
                    remediation, status, mantis_risk_score, impact_score, likelihood_score,
                    priority, signature, lineage_id, cwe, triage_reasoning, patch_diff, patch_status,
                    rca_summary, embedding
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                rca_summary,
                emb_blob,
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

        # Upgrade OKF concepts trust tier on dynamic sandbox confirmation strictly for this specific resource
        if status in ("dynamic_confirmed", "patch_verified") and norm_fp and not os.path.isdir(norm_fp):
            from datetime import datetime, timezone
            now_iso = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                "SELECT id, trust_tier, verified_by FROM okf_concepts WHERE run_id = ? AND resource = ?",
                (run_id, norm_fp),
            )
            rows = [dict(r) for r in cursor.fetchall()]
            for r in rows:
                c_id = r["id"]
                current_tier = r.get("trust_tier") or "unverified"
                try:
                    ver_list = json.loads(r.get("verified_by") or "[]")
                except Exception:
                    ver_list = []
                by_key = f"process:sandbox_{status}"
                existing_entry = next((e for e in ver_list if isinstance(e, dict) and e.get("by") == by_key), None)
                if existing_entry is not None:
                    existing_entry["status"] = status
                    existing_entry["at"] = now_iso
                else:
                    ver_list.append({
                        "by": by_key,
                        "status": status,
                        "at": now_iso,
                    })
                # Never lower an existing tier (e.g. human_reviewed stays human_reviewed)
                new_tier = "human_reviewed" if current_tier == "human_reviewed" else "machine_confirmed"
                cursor.execute("""
                    UPDATE okf_concepts
                    SET trust_tier = ?,
                        verified_by = ?
                    WHERE id = ?
                """, (new_tier, json.dumps(ver_list), c_id))


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
            if row_dict.get("embedding") is not None and isinstance(row_dict["embedding"], bytes):
                row_dict["embedding"] = blob_to_vector(row_dict["embedding"]) if row_dict["embedding"] else None
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
        _iso_default = lambda o: o.isoformat() if hasattr(o, "isoformat") else str(o)
        res = canonical_filepath(concept.get("resource") or "", target_file=concept.get("resource") or "") if concept.get("resource") else ""
        tags_str = json.dumps(concept.get("tags") or [], default=_iso_default)
        status = concept.get("status") or "stable"
        trust_tier = concept.get("trust_tier") or "unverified"
        ver_str = json.dumps(concept.get("verified_by") or [], default=_iso_default)
        gen_by = concept.get("generated_by") or ""
        snap_id = concept.get("snapshot_id") or ""
        desc = concept.get("description") or ""
        sources_str = json.dumps(concept.get("sources") or [], default=_iso_default)
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
    run_id: Optional[str] = None,
    include_repo_wide: bool = False,
) -> List[Dict[str, Any]]:
    """Queries OKF concepts from the database by resource, type, tag, trust_tier, or run_id."""
    with _db(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM okf_concepts WHERE 1=1"
        params = []
        if resource:
            norm_res = canonical_filepath(resource, target_file=resource)
            if include_repo_wide:
                query += " AND (resource = ? OR resource = '' OR resource IS NULL)"
            else:
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

    out_root = os.path.realpath(output_dir)

    for c_type, items in by_type.items():
        index_lines.append(f"## {c_type}")
        for item in items:
            cid = item.get("concept_id") or "concept"
            rel_file = cid if cid.endswith(".md") else f"{cid}.md"
            if rel_file.startswith("workspace/kb/"):
                rel_file = rel_file.removeprefix("workspace/kb/")
            clean_rel = os.path.normpath(rel_file.lstrip("/\\"))
            cand_dest = os.path.realpath(os.path.join(out_root, clean_rel))
            try:
                if os.path.commonpath([out_root, cand_dest]) != out_root:
                    continue
            except ValueError:
                continue
            desc = item.get("description") or item.get("title")
            index_lines.append(f"* [{item.get('title')}]({clean_rel}) - {desc}")
        index_lines.append("")

    with open(index_path, "w", encoding="utf-8") as f:
        f.write("\n".join(index_lines))
    exported_files.append(index_path)

    for c in concepts:
        cid = c.get("concept_id") or "concept"
        rel_path = cid if cid.endswith(".md") else f"{cid}.md"
        if rel_path.startswith("workspace/kb/"):
            rel_path = rel_path.removeprefix("workspace/kb/")
        # SECURITY: Confine destination to output directory to prevent path traversal
        clean_rel = os.path.normpath(rel_path.lstrip("/\\"))
        full_dest = os.path.realpath(os.path.join(out_root, clean_rel))
        try:
            if os.path.commonpath([out_root, full_dest]) != out_root:
                logger.warning(f"Skipping unsafe concept_id escaping export directory: {cid}")
                continue
        except ValueError:
            logger.warning(f"Skipping concept_id on different drive/scope: {cid}")
            continue
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

    clean_fp = filepath.replace("\\", "/")
    base_name = os.path.basename(clean_fp).lower()

    # Skip reserved catalog/log files, archived passes, and non-markdown files
    if (
        "workspace/archive/" in clean_fp
        or "/archive/" in clean_fp
        or base_name in ("index.md", "log.md")
    ):
        return

    # Index into okf_concepts only for markdown documentation under workspace/kb/ or explicit semantic artifact types
    if clean_fp.endswith((".md", ".markdown")) and (
        "workspace/kb/" in clean_fp
        or artifact_type in ("threat_model", "summary", "entity", "architecture", "vulnerability")
    ):
        try:
            parsed = parse_okf_markdown(content, default_concept_id=filepath)
            if parsed:
                if artifact_type == "threat_model" and parsed["type"] in ("Generic Concept", "Untitled Concept"):
                    parsed["type"] = "Threat Model"
                elif artifact_type in ("summary", "architecture") and parsed["type"] in ("Generic Concept", "Untitled Concept"):
                    parsed["type"] = "Architecture Summary"

                if metadata:
                    candidate_resource = metadata.get("resource", "")
                    doc_type = parsed.get("type", "")
                    # Attach resource only for file-scoped documents (like Component Entity).
                    # Leave resource empty ("") for repo-wide documents (Threat Model, Architecture Summary).
                    is_file_scoped = (
                        doc_type in ("Component Entity", "Software Entity", "Hardware Entity", "Security Invariant", "Guardrail")
                        or "workspace/kb/entities/" in filepath
                        or artifact_type == "entity"
                    ) and doc_type not in ("Threat Model", "Architecture Summary", "Threat Boundary")
                    if not parsed.get("resource") and candidate_resource and is_file_scoped:
                        parsed["resource"] = canonical_filepath(candidate_resource, target_file=candidate_resource)
                    if not parsed.get("snapshot_id") and metadata.get("snapshot_id"):
                        parsed["snapshot_id"] = metadata["snapshot_id"]
                    if not parsed.get("trust_tier") and metadata.get("trust_tier"):
                        parsed["trust_tier"] = metadata["trust_tier"]
                    if metadata.get("verified_by") and not parsed.get("verified_by"):
                        parsed["verified_by"] = metadata["verified_by"]
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
            if row_dict.get("embedding") is not None and isinstance(row_dict["embedding"], bytes):
                row_dict["embedding"] = blob_to_vector(row_dict["embedding"]) if row_dict["embedding"] else None
            rows.append(row_dict)
        return rows


def _compact_threat_model(content: str) -> str:
    """Extracts a high-level summary and trust boundaries from a verbose threat model document."""
    if not content:
        return ""
    if len(content) < 1500:
        return content.strip()

    lines = []
    capture = False
    for line in content.splitlines():
        ls = line.strip()
        if any(ls.startswith(f"## {k}") for k in ("System Overview", "Overview", "Summary")):
            capture = True
            lines.append(line)
            continue
        if capture and ls.startswith("## ") and not any(k in ls for k in ("Trust Boundary", "Trust Boundaries", "Boundary", "Actor")):
            break
        if capture:
            lines.append(line)
            if len(lines) >= 30:
                break
    if lines:
        return "\n".join(lines).strip()
    return "\n".join([l for l in content.splitlines() if l.strip()][:20])


def _extract_first_sentence_or_bullet(text: str) -> str:
    """Extracts the first complete sentence or bullet from text, never truncating mid-sentence."""
    if not text:
        return ""
    text = " ".join(text.strip().split())
    if text.startswith(("- ", "* ", "• ")):
        text = text[2:].strip()
    match = re.search(r'(?<=[.!?])\s+', text)
    if match:
        return text[:match.start() + 1].strip()
    return text


def _compact_vulnerability_pattern(body: str, desc: str = "") -> str:
    """Extracts a concise description and complete remediation invariant from a Vulnerability Pattern concept."""
    overview = ""
    remediation = ""
    sections = {"header": []}
    current_sec = "header"

    for line in (body or "").splitlines():
        ls = line.strip()
        if ls.startswith("## "):
            h = ls.removeprefix("## ").strip().lower()
            if "overview" in h or "description" in h:
                current_sec = "overview"
            elif "remediation" in h or "fix" in h:
                current_sec = "remediation"
            else:
                current_sec = h
            sections[current_sec] = []
            continue
        sections[current_sec].append(line)

    if desc:
        overview = desc
    elif "overview" in sections:
        raw_ov = "\n".join(sections["overview"]).strip()
        paragraphs = [p.strip() for p in raw_ov.split("\n\n") if p.strip() and not p.strip().startswith(("#", "|"))]
        if paragraphs:
            p0 = paragraphs[0]
            if p0.startswith("**") and p0.endswith("**") and len(paragraphs) > 1:
                overview = _extract_first_sentence_or_bullet(paragraphs[1])
            else:
                overview = _extract_first_sentence_or_bullet(p0)

    if "remediation" in sections:
        raw_rem = "\n".join(sections["remediation"]).strip()
        paragraphs = [p.strip() for p in raw_rem.split("\n\n") if p.strip() and not p.strip().startswith(("#", "|"))]
        for idx, p in enumerate(paragraphs):
            if p.startswith("```"):
                continue
            first_sent = _extract_first_sentence_or_bullet(p)
            if first_sent:
                clean_sent = re.sub(r'^\*\*(?:Best fix|Remediation|Fix|Use parameterized queries):?\*\*\s*', '', first_sent, flags=re.IGNORECASE).strip()
                if not clean_sent:
                    label = first_sent.strip("*:").strip()
                    if idx + 1 < len(paragraphs) and paragraphs[idx + 1].startswith("```"):
                        code_lines = [l.strip() for l in paragraphs[idx + 1].splitlines() if l.strip() and not l.startswith("```")]
                        if code_lines:
                            clean_sent = f"{label}: `{code_lines[0]}`"
                    elif idx + 1 < len(paragraphs):
                        clean_sent = f"{label}: {_extract_first_sentence_or_bullet(paragraphs[idx + 1])}"
                if clean_sent:
                    remediation = clean_sent
                    break

    res = overview
    if remediation:
        res += ("\n  -> **Remediation**: " + remediation)
    return res.strip()


def query_security_guidance(db_path: str, filepath: str, run_id: Optional[str] = None, full: bool = False) -> Dict[str, Any]:
    """Aggregates active threat models, OKF concepts, historical vulnerabilities, triaged false positives,
    recurrent lineages, and verified remediation patterns into actionable security guidance for a target file.
    """
    with _db(db_path) as conn:
        cursor = conn.cursor()
        norm_fp = canonical_filepath(filepath, target_file=filepath)

        # 1. OKF Concepts (Scoped to Target File)
        scoped_okf = read_okf_concepts(db_path, resource=norm_fp, run_id=run_id, include_repo_wide=True) if norm_fp else read_okf_concepts(db_path, run_id=run_id)
        
        # Extract scoped threat boundaries, component entities, architecture summaries, security invariants, and vulnerability patterns
        threat_concepts = [c for c in scoped_okf if c.get("type") in ("Threat Boundary", "Threat Model")]
        entity_concepts = [c for c in scoped_okf if c.get("type") in ("Component Entity", "Software Entity", "Hardware Entity", "Architecture Summary")]
        invariant_concepts = [c for c in scoped_okf if c.get("type") in ("Security Invariant", "Guardrail")]
        pattern_concepts = [c for c in scoped_okf if c.get("type") in ("Vulnerability Pattern", "Weakness Pattern")]

        # Threat model content (compact or full)
        threat_model_content = ""
        if threat_concepts:
            if full:
                threat_model_content = "\n\n".join(f"### {c.get('title')}\n{c.get('body_markdown', '').strip()}" for c in threat_concepts)
            else:
                threat_model_content = "\n\n".join(f"### {c.get('title')}\n{_compact_threat_model(c.get('body_markdown', ''))}" for c in threat_concepts)
        else:
            raw_tm = read_artifact(db_path, artifact_type="threat_model", run_id=run_id) or ""
            if not raw_tm:
                raw_tm = read_artifact(db_path, filepath="workspace/kb/THREAT_MODEL.md", run_id=run_id) or ""
            threat_model_content = raw_tm.strip() if full else _compact_threat_model(raw_tm)

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
        for c in confirmed_rows:
            if c.get("embedding") is not None and isinstance(c["embedding"], bytes):
                c["embedding"] = blob_to_vector(c["embedding"]) if c["embedding"] else None

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
        for fp_item in fp_rows:
            if fp_item.get("embedding") is not None and isinstance(fp_item["embedding"], bytes):
                fp_item["embedding"] = blob_to_vector(fp_item["embedding"]) if fp_item["embedding"] else None

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
                is_scoped = bool(norm_fp and ent.get("resource") == norm_fp)
                if full or is_scoped:
                    guidance_lines.append(f"### {ent.get('title')} {badge}")
                    if ent.get("description"):
                        guidance_lines.append(f"*{ent.get('description')}*")
                    if ent.get("body_markdown"):
                        guidance_lines.append(f"{ent.get('body_markdown').strip()}\n")
                else:
                    desc = ent.get("description") or "Component entity"
                    ref_id = ent.get("concept_id") or "workspace/kb/entities"
                    guidance_lines.append(f"- **{ent.get('title')}** {badge}: {desc} *(See `{ref_id}`)*")

        # Security Invariants / Guardrails
        if invariant_concepts or learnings:
            guidance_lines.extend(["", "## 3. Verified Security Guardrails & Invariants"])
            for inv in invariant_concepts:
                tier = inv.get("trust_tier", "unverified").upper().replace("_", "-")
                guidance_lines.append(f"- ⛔ **[{tier}] {inv.get('title')}**: {inv.get('description') or inv.get('body_markdown', '').strip()}")
            for l in learnings:
                cat = f"**[{l.get('category')}]**: " if l.get("category") else ""
                l_text = l.get("learning", "") if full else _extract_first_sentence_or_bullet(l.get("learning", ""))
                guidance_lines.append(f"- ℹ️ {cat}{l_text}")

        guidance_lines.extend(["", "## 4. Historical Vulnerabilities & Verified Remediation Patterns"])
        if pattern_concepts:
            for p in pattern_concepts:
                guidance_lines.append(f"- ⚠️ **[KNOWN PATTERN] {p.get('title')}**")
                if full:
                    if p.get("description"):
                        guidance_lines.append(f"  *{p.get('description')}*")
                    if p.get("body_markdown"):
                        guidance_lines.append(f"  {p.get('body_markdown').strip()}\n")
                else:
                    p_summary = _compact_vulnerability_pattern(p.get("body_markdown", ""), p.get("description", ""))
                    if p_summary:
                        guidance_lines.append(f"  {p_summary}")
        if confirmed_rows:
            for c in confirmed_rows:
                guidance_lines.append(f"- **[{c.get('severity', 'UNKNOWN')}] {c.get('title')}** (CWE: {c.get('cwe', 'N/A')}, Status: `{c.get('status')}`)")
                guidance_lines.append(f"  - **Description**: {c.get('description', '').strip()}")
                if c.get("remediation"):
                    guidance_lines.append(f"  - **Remediation Invariant**: {c.get('remediation').strip()}")
                if c.get("patch_status"):
                    guidance_lines.append(f"  - **Patch Status**: `{c.get('patch_status')}`")
                if c.get("patch_diff"):
                    diff_content = c.get("patch_diff", "").strip()
                    if not full and diff_content.count("\n") > 12:
                        diff_lines = diff_content.splitlines()[:12]
                        guidance_lines.append(f"  - **Verified Patch Diff (Few-Shot Pattern)**:\n```diff\n" + "\n".join(diff_lines) + "\n... (truncated; use --full to view entire patch diff)\n```")
                    else:
                        guidance_lines.append(f"  - **Verified Patch Diff (Few-Shot Pattern)**:\n```diff\n{diff_content}\n```")
        elif not pattern_concepts:
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
            "vulnerability_patterns": pattern_concepts,
            "confirmed_vulnerabilities": confirmed_rows,
            "false_positives": fp_rows,
            "recurrent_lineages": recurrent_lineages,
            "learned_invariants": learnings,
            "guidance_summary": "\n".join(guidance_lines),
        }



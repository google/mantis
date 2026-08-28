import math
import os
import re
import struct
import hashlib
import sqlite3
from typing import Optional, List, Tuple, Union, Dict, Any

try:
    import litellm
    litellm.suppress_debug_info = True
except Exception:
    pass

try:
    from core.config import DEFAULT_EMBEDDING_MODEL
except ImportError:
    DEFAULT_EMBEDDING_MODEL = "vertex_ai/gemini-embedding-001"

# Domain stopwords for semantic weighting in offline/mock mode
_STOPWORDS = {
    "the", "a", "an", "and", "or", "to", "for", "with", "by", "of", "on", "from",
    "at", "is", "in", "it", "as", "via", "into", "component", "vulnerability",
    "class", "root", "cause", "mechanism", "failure", "condition", "taint", "dataflow",
}

def _parse_similarity_threshold(raw: Optional[Any] = None) -> float:
    if raw is None:
        raw = os.environ.get("EMBEDDING_SIMILARITY_THRESHOLD")
    if raw is not None:
        try:
            val = float(str(raw).strip())
            if 0.0 <= val <= 1.0:
                return val
            import sys

            print(
                f"⚠️  [CONFIG WARNING] EMBEDDING_SIMILARITY_THRESHOLD='{raw}' is outside valid range [0.0, 1.0]. "
                f"Falling back to default 0.90.",
                file=sys.stderr,
            )
        except (ValueError, TypeError):
            import sys

            print(
                f"⚠️  [CONFIG WARNING] Invalid EMBEDDING_SIMILARITY_THRESHOLD='{raw}'. "
                f"Falling back to default 0.90.",
                file=sys.stderr,
            )
    return 0.90


DEFAULT_SIMILARITY_THRESHOLD = _parse_similarity_threshold()
_WARNED_FALLBACK = False
_WARNED_DIM_MISMATCH = False


def _warn_embedding_fallback(model: str, err: Exception) -> None:
    """Emits a visible, non-duplicative warning when live vector embedding fails and degrades to mock."""
    global _WARNED_FALLBACK
    if not _WARNED_FALLBACK:
        _WARNED_FALLBACK = True
        import sys

        print(
            f"⚠️  [EMBEDDING FALLBACK] Failed to compute live vector embeddings via '{model}' ({err}). "
            f"Degrading to deterministic offline mock embeddings for deduplication.",
            file=sys.stderr,
        )


def _warn_dim_mismatch(query_dim: int, cand_dim: int, cand_model: str = "") -> None:
    """Emits a visible warning when stored vectors have different dimensions from the current query vector."""
    global _WARNED_DIM_MISMATCH
    if not _WARNED_DIM_MISMATCH:
        _WARNED_DIM_MISMATCH = True
        import sys

        model_info = f" (model: '{cand_model}')" if cand_model else ""
        print(
            f"⚠️  [EMBEDDING MISMATCH] Stored lineage vectors have dimension {cand_dim}{model_info}, "
            f"while query vector has dimension {query_dim}. Cross-dimension vector matching is disabled to prevent false merges.",
            file=sys.stderr,
        )


def vector_to_blob(vec: Union[List[float], Tuple[float, ...], Any]) -> bytes:
    """Serializes a float vector into a compact binary BLOB using float32."""
    if not vec:
        return b""
    try:
        vec_list = [float(x) for x in vec]
        return struct.pack(f"{len(vec_list)}f", *vec_list)
    except Exception:
        return b""


def blob_to_vector(blob: bytes) -> List[float]:
    """Deserializes a binary BLOB into a list of floats, tolerating truncation gracefully."""
    if not blob:
        return []
    count = len(blob) // 4
    if count == 0:
        return []
    try:
        return list(struct.unpack(f"{count}f", blob[: count * 4]))
    except Exception:
        return []


def cosine_similarity(vec_a: List[float], vec_b: List[float]) -> float:
    """Calculates cosine similarity between two float vectors bounded to [-1.0, 1.0]."""
    if not vec_a or not vec_b or len(vec_a) != len(vec_b):
        return 0.0
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    val = dot / (norm_a * norm_b)
    if math.isnan(val) or math.isinf(val):
        return 0.0
    return max(-1.0, min(1.0, float(val)))


def compute_mock_embedding(text: str, dim: int = 256) -> List[float]:
    """Computes a deterministic semantic mock embedding vector for offline testing."""
    if not text:
        return [0.0] * dim

    lines = text.strip().split("\n")
    features: Dict[str, str] = {}
    for line in lines:
        if ":" in line:
            k, v = line.split(":", 1)
            features[k.strip().lower()] = v.strip()

    vec = [0.0] * dim
    weighted_items: List[Tuple[str, float]] = []

    comp = features.get("component", "").strip().lower()
    vuln_class = features.get("vulnerability class", "").strip().lower()
    mechanism = features.get("root cause mechanism", "").strip().lower()
    failure = features.get("failure condition", "").strip().lower()
    taint = features.get("taint dataflow", "").strip().lower()

    if comp:
        norm_comp = comp.replace("\\", "/").strip("./")
        weighted_items.append((f"comp::{norm_comp}", 5.0))

    if vuln_class:
        cwe_match = re.search(r"cwe[-_]?(\d+)", vuln_class)
        cwe_norm = f"cwe-{cwe_match.group(1)}" if cwe_match else vuln_class
        weighted_items.append((f"vuln::{cwe_norm}", 10.0))

    # Extract target symbol specifically from component or taint
    target_sym = ""
    if taint:
        m = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\b", taint)
        if m and m.group(1) not in {"untrusted", "input", "source", "user"}:
            target_sym = m.group(1).lower()
    if not target_sym and comp:
        m = re.search(r"::([a-zA-Z_][a-zA-Z0-9_]*)$", comp)
        if m:
            target_sym = m.group(1).lower()

    if target_sym:
        weighted_items.append((f"target_sym::{target_sym}", 12.0))

    # Distinguish sub-types (e.g. stored vs reflected)
    mech_fail_lower = f"{mechanism} {failure}".lower()
    if "stored" in mech_fail_lower:
        weighted_items.append(("subtype::stored", 10.0))
    elif "reflected" in mech_fail_lower:
        weighted_items.append(("subtype::reflected", 10.0))
    elif "blind" in mech_fail_lower:
        weighted_items.append(("subtype::blind", 10.0))

    stopwords = {
        "the", "a", "an", "and", "or", "in", "via", "to", "for", "with", "by", "of", "on", "from",
        "at", "is", "it", "as", "into", "component", "vulnerability", "class", "root", "cause",
        "mechanism", "failure", "condition", "taint", "dataflow", "user", "parameter", "function",
        "flaw", "issue", "bug", "routine", "utility", "handler"
    }
    words = [re.sub(r"[^a-zA-Z0-9_]", "", w).lower() for w in f"{mechanism} {failure}".split()]
    for w in set(words):
        if len(w) > 3 and w not in stopwords and w != target_sym:
            weighted_items.append((f"kw::{w}", 0.8))

    if not weighted_items:
        for w in re.findall(r"[a-zA-Z0-9_\-]+", text.lower()):
            if len(w) > 2:
                weight = 0.2 if w in _STOPWORDS else 1.0
                weighted_items.append((f"word::{w}", weight))

    for item, weight in weighted_items:
        h = hashlib.sha256(item.encode("utf-8")).digest()
        for i in range(dim):
            byte_val = h[i % len(h)]
            val = ((byte_val / 127.5) - 1.0) * weight
            vec[i] += val

    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0:
        vec = [x / norm for x in vec]
    return vec


def get_embedding_kwargs(
    model: Optional[str] = None,
    api_base: Optional[str] = None,
    timeout: Optional[float] = None,
    api_key: Optional[str] = None,
    vertex_project: Optional[str] = None,
    vertex_location: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Tuple[str, dict]:
    """Resolves embedding model parameters and client configuration kwargs with precedence:
    function args > config dict > environment variables > default."""
    cfg = config or {}

    raw_model = (
        model
        or cfg.get("embedding_model")
        or cfg.get("default_embedding_model")
        or cfg.get("model")
        or os.environ.get("EMBEDDING_MODEL")
        or os.environ.get("MANTIS_EMBEDDING_MODEL")
        or DEFAULT_EMBEDDING_MODEL
    )
    resolved_model = raw_model.strip() if raw_model else DEFAULT_EMBEDDING_MODEL

    raw_api_base = (
        api_base
        or cfg.get("embedding_api_base")
        or cfg.get("api_base")
        or os.environ.get("EMBEDDING_API_BASE")
        or os.environ.get("LLM_API_BASE")
    )
    resolved_api_base = raw_api_base.strip() if raw_api_base else None

    raw_timeout = timeout if timeout is not None else (
        cfg.get("embedding_timeout")
        or cfg.get("timeout")
        or os.environ.get("EMBEDDING_TIMEOUT")
        or os.environ.get("LLM_TIMEOUT")
        or os.environ.get("LLM_REQUEST_TIMEOUT")
    )

    raw_api_key = (
        api_key
        or cfg.get("embedding_api_key")
        or cfg.get("api_key")
        or cfg.get("gemini_api_key")
        or os.environ.get("EMBEDDING_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
    )
    resolved_api_key = raw_api_key.strip() if raw_api_key else None

    kwargs: Dict[str, Any] = {}
    if resolved_api_base:
        kwargs["api_base"] = resolved_api_base
    if resolved_api_key:
        kwargs["api_key"] = resolved_api_key
    if raw_timeout is not None:
        try:
            val = float(raw_timeout)
            if val > 0:
                kwargs["timeout"] = val
        except (ValueError, TypeError):
            pass

    project = (
        vertex_project
        or cfg.get("vertex_project")
        or cfg.get("project")
        or os.environ.get("VERTEXAI_PROJECT", os.environ.get("GOOGLE_CLOUD_PROJECT"))
    )
    location = (
        vertex_location
        or cfg.get("vertex_location")
        or cfg.get("location")
        or os.environ.get("VERTEXAI_LOCATION", os.environ.get("GOOGLE_CLOUD_LOCATION", "global"))
    )

    # Route bare gemini models to vertex_ai when GCP credentials exist
    if (
        not resolved_model.startswith("vertex_ai/")
        and (resolved_model.startswith("gemini-") or resolved_model.startswith("text-embedding-"))
        and not resolved_api_key
        and (project or os.environ.get("VERTEXAI_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT"))
    ):
        resolved_model = f"vertex_ai/{resolved_model}"

    if resolved_model.startswith("vertex_ai/"):
        if not project:
            try:
                import google.auth
                _, project = google.auth.default()
            except Exception:
                pass

        if project:
            kwargs["vertex_project"] = project
            kwargs["vertex_location"] = location

    return resolved_model, kwargs


def compute_embedding(
    text: str,
    model: Optional[str] = None,
    api_base: Optional[str] = None,
    timeout: Optional[float] = None,
    api_key: Optional[str] = None,
    vertex_project: Optional[str] = None,
    vertex_location: Optional[str] = None,
    mock_mode: Optional[bool] = None,
    config: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> List[float]:
    """Generates vector embeddings for a given text using LiteLLM.

    Falls back safely to deterministic mock embeddings if offline or mock_mode is True,
    emitting a one-time diagnostic notice if a live network/credential error occurs.
    """
    is_mock = (
        mock_mode
        or os.environ.get("MANTIS_MOCK_EMBEDDINGS") == "1"
        or os.environ.get("MOCK_EMBEDDINGS") == "1"
        or model in ("mock", "offline")
        or (isinstance(config, dict) and config.get("mock_embeddings"))
    )

    if is_mock:
        return compute_mock_embedding(text)

    resolved_model, emb_kwargs = get_embedding_kwargs(
        model=model,
        api_base=api_base,
        timeout=timeout,
        api_key=api_key,
        vertex_project=vertex_project,
        vertex_location=vertex_location,
        config=config,
    )
    emb_kwargs.update(kwargs)

    try:
        from litellm import embedding
        response = embedding(model=resolved_model, input=[text], **emb_kwargs)
        if hasattr(response, "data") and len(response.data) > 0:
            emb = response.data[0]
            if isinstance(emb, dict) and "embedding" in emb:
                return emb["embedding"]
            elif hasattr(emb, "embedding"):
                return emb.embedding
        elif isinstance(response, dict) and "data" in response and len(response["data"]) > 0:
            return response["data"][0]["embedding"]
        return compute_mock_embedding(text)
    except Exception as e:
        _warn_embedding_fallback(resolved_model, e)
        return compute_mock_embedding(text)


def normalize_cwe(cwe: Optional[Union[str, int]]) -> Optional[str]:
    """Normalizes a CWE identifier to canonical 'CWE-XXX' format or uppercase string, returning None for unknown/empty values."""
    if cwe is None:
        return None
    cwe_str = str(cwe).strip()
    if not cwe_str or cwe_str.upper() in ("CWE-UNKNOWN", "UNKNOWN", "NONE", "NULL", "UNDEFINED", "N/A"):
        return None
    if cwe_str.isdigit():
        return f"CWE-{int(cwe_str)}"
    m = re.search(r"\bcwe[-_\s]?(\d+)\b", cwe_str, re.IGNORECASE)
    if m:
        return f"CWE-{int(m.group(1))}"
    return cwe_str.upper()


def _row_val(row: Any, idx: int, key: str, default: Any = None) -> Any:
    """Safely extracts a column value by name or index across tuple, list, sqlite3.Row, and dict objects."""
    if row is None:
        return default
    if isinstance(row, (tuple, list)):
        return row[idx] if len(row) > idx else default
    try:
        return row[key]
    except Exception:
        try:
            return row[idx]
        except Exception:
            return default


def find_nearest_lineage(
    cursor: sqlite3.Cursor,
    query_vector: List[float],
    threshold: Optional[float] = None,
    filepath: Optional[str] = None,
    cwe: Optional[Union[str, int]] = None,
) -> Optional[str]:
    """Nearest-neighbor search over SQLite vector records returning lineage_id if max cosine similarity >= threshold."""
    if not query_vector:
        return None

    eff_threshold = _parse_similarity_threshold(threshold)

    norm_fp = filepath.replace("\\", "/").strip() if filepath else None
    if norm_fp:
        while norm_fp.startswith("./"):
            norm_fp = norm_fp[2:]
        norm_fp = norm_fp.lstrip("/")
        base_fp = os.path.basename(norm_fp)
    else:
        norm_fp = None
        base_fp = None

    # 1. Check lineage_vectors table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='lineage_vectors'")
    has_lv = cursor.fetchone() is not None

    rows = []
    if has_lv:
        if norm_fp:
            cursor.execute(
                "SELECT lineage_id, embedding, filepath, cwe, model FROM lineage_vectors WHERE filepath = ? OR filepath = ? OR filepath = ? OR filepath = '' OR filepath IS NULL",
                (filepath, norm_fp, base_fp),
            )
        else:
            cursor.execute("SELECT lineage_id, embedding, filepath, cwe, model FROM lineage_vectors")
        rows = cursor.fetchall()

    # 2. Fallback to findings table if lineage_vectors has no rows
    if not rows:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
        has_findings = cursor.fetchone() is not None
        if has_findings:
            if norm_fp:
                cursor.execute(
                    "SELECT lineage_id, embedding, filepath, cwe, '' AS model FROM findings WHERE embedding IS NOT NULL AND lineage_id IS NOT NULL AND lineage_id != '' AND (filepath = ? OR filepath = ? OR filepath = ? OR filepath = '' OR filepath IS NULL)",
                    (filepath, norm_fp, base_fp),
                )
            else:
                cursor.execute(
                    "SELECT lineage_id, embedding, filepath, cwe, '' AS model FROM findings WHERE embedding IS NOT NULL AND lineage_id IS NOT NULL AND lineage_id != ''"
                )
            rows = cursor.fetchall()

    best_sim = -1.0
    best_lineage_id: Optional[str] = None
    query_dim = len(query_vector)
    norm_q_cwe = normalize_cwe(cwe)

    for r in rows:
        lid = _row_val(r, 0, "lineage_id")
        blob = _row_val(r, 1, "embedding")
        if not blob or not lid:
            continue

        # CWE Family & Class Structural Guard:
        # If both query finding and candidate row have explicit CWE classifications, normalize them.
        # If both have distinct, incompatible CWE IDs, skip candidate vector comparison entirely.
        cand_cwe = _row_val(r, 3, "cwe", "")
        norm_c_cwe = normalize_cwe(cand_cwe)
        if norm_q_cwe and norm_c_cwe and norm_q_cwe != norm_c_cwe:
            continue

        cand_dim = len(blob) // 4
        # Dimension safety guard: skip vectors with divergent dimensions
        if cand_dim != query_dim:
            cand_model = _row_val(r, 4, "model", "")
            _warn_dim_mismatch(query_dim, cand_dim, str(cand_model or ""))
            continue

        cand_vec = blob_to_vector(blob)
        if not cand_vec or len(cand_vec) != query_dim:
            continue
        sim = cosine_similarity(query_vector, cand_vec)
        if sim > best_sim:
            best_sim = sim
            best_lineage_id = lid

    if best_sim >= eff_threshold and best_lineage_id:
        return best_lineage_id

    return None

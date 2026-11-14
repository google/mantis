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

"""Deterministic AST & lexical sink/entrypoint audit checklist builder.

Extracts concrete high-risk security sinks and external entrypoints inside a
campaign's assigned target scope from the published structural index
(`catalog.sqlite`: `call_edges` + `symbols`), falling back to a bounded
deterministic regex scan when source files are not indexed.

Used to anchor `planner` and `researcher` on the same sorted inventory of
sinks and entrypoints on every run rather than relying on stochastic LLM file
sampling alone.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, List, Optional, Sequence, Tuple

from core.depth import DEFAULT_DEPTH, resolve_depth_profile
from core.environments.staging import get_vetted_staging_files
from core.llm_gateway import wrap_untrusted_content
from core.paths import resolve_db_path
from core.structural_index import resolve_state_dir_for_target, state_dir_for_db

MAX_CHECKLIST_SINKS = 35
MAX_SINKS_PER_FILE = 5
MAX_CHECKLIST_ENTRYPOINTS = 20
MAX_CHECKLIST_CHARS = 3600
MAX_FALLBACK_FILES = 40
MAX_FALLBACK_FILE_BYTES = 256 * 1024

_RTL_EXTS = frozenset({".v", ".vh", ".sv", ".svh", ".vhd", ".vhdl"})

# Ordered highest-risk first: `(category_label, tier_rank, exact_callee_names)`.
_SINK_TAXONOMY: Tuple[Tuple[str, int, frozenset[str]], ...] = (
    (
        "command_exec",
        1,
        frozenset({
            "system", "popen", "execve", "execvp", "execv", "execl", "execlp",
            "Popen", "check_output", "check_call", "create_subprocess_shell",
            "create_subprocess_exec", "execSync", "execFile", "execFileSync",
            "spawn", "spawnSync", "shell_exec", "passthru", "proc_open",
            "ProcessBuilder", "Command", "CommandContext",
            "Invoke-Expression", "Start-Process",
        }),
    ),
    (
        "code_eval_deser",
        2,
        frozenset({
            "eval", "exec", "unsafe_load", "Unpickler",
            "readObject", "readUnshared", "fromXML", "unserialize",
            "deserialize", "runInNewContext", "runInContext", "runInThisContext",
            "BinaryFormatter", "XmlSerializer", "XStream", "enableDefaultTyping",
            "load_model", "from_pretrained",
        }),
    ),
    (
        "sql_query",
        3,
        frozenset({
            "execute", "executemany", "executescript", "raw", "RawSQL",
            "query", "queryRow", "Query", "QueryRow", "QueryContext",
            "ExecContext", "createNativeQuery", "createQuery", "unsafeRaw",
            "$queryRawUnsafe", "$executeRawUnsafe",
            "FromSqlRaw", "ExecuteSqlRaw", "mysqli_query", "pg_query", "sp_executesql",
        }),
    ),
    (
        "memory_unsafe",
        4,
        frozenset({
            "strcpy", "strcat", "sprintf", "vsprintf", "gets", "memcpy",
            "memmove", "realloc", "alloca", "scanf", "sscanf", "transmute",
            "from_raw_parts", "from_raw_parts_mut", "get_unchecked",
            "get_unchecked_mut", "ptrCast", "alignCast",
        }),
    ),
    (
        "smart_contract",
        4,
        frozenset({
            "delegatecall", "selfdestruct", "ecrecover", "raw_call",
            "create_minimal_proxy_to",
        }),
    ),
    (
        "ssrf_network",
        5,
        frozenset({
            "urlopen", "urlretrieve", "fetch", "axios", "NewRequest",
            "NewRequestWithContext", "sendRedirect", "redirect",
            "curl_exec", "openURL",
        }),
    ),
    (
        "mobile_webview_ipc",
        6,
        frozenset({
            "addJavascriptInterface", "setJavaScriptEnabled", "setAllowFileAccess",
            "evaluateJavaScript", "loadHTMLString", "loadRequest",
        }),
    ),
    (
        "path_fs",
        6,
        frozenset({
            "send_file", "send_from_directory", "FileResponse", "ServeFile",
            "ServeContent", "extractall", "unpack_archive", "rmtree", "unlink",
            "chmod", "chown", "readFile", "readFileSync", "writeFile",
            "writeFileSync", "createReadStream", "createWriteStream",
        }),
    ),
    (
        "template_xss",
        7,
        frozenset({
            "render_template_string", "Template", "mark_safe", "Markup",
            "bypassSecurityTrustHtml", "bypassSecurityTrustUrl",
            "bypassSecurityTrustResourceUrl", "bypassSecurityTrustScript",
            "bypassSecurityTrustStyle", "insertAdjacentHTML", "HTML",
        }),
    ),
    (
        "crypto_auth",
        8,
        frozenset({
            "md5", "sha1", "createHash", "createCipher", "createDecipher",
            "set_cookie", "check_password", "verify_password", "compare_digest",
            "SecItemAdd", "SecItemUpdate",
        }),
    ),
)

_CALLEE_TO_CATEGORY: Dict[str, Tuple[str, int]] = {}
for _cat, _rank, _names in _SINK_TAXONOMY:
    for _n in _names:
        _CALLEE_TO_CATEGORY.setdefault(_n, (_cat, _rank))

_UNSAFE_DESER_QUALIFIERS = frozenset({
    "pickle", "cpickle", "_pickle", "dill", "cloudpickle", "marshal",
    "yaml", "ruamel", "shelve", "jsonpickle",
})
_AI_ML_DESER_QUALIFIERS = frozenset({
    "torch", "joblib", "np", "numpy", "keras", "models",
})
_BENIGN_SYSTEM_QUALIFIERS = frozenset({"platform"})
_QUALIFIED_ONLY_CALLEES = frozenset({
    "run", "call", "loads", "load", "decode", "compile", "verify", "sign",
    "postMessage", "write", "openExternal", "Copy", "Start", "on", "handle",
})


def _classify_edge_sink(callee: str, qualifier: str) -> Optional[Tuple[str, int]]:
    """Classifies `(callee, qualifier)` to `(category, tier_rank)` or `None` when benign."""
    q_low = (qualifier or "").strip().lower()
    if callee in ("run", "call"):
        if q_low == "subprocess":
            return ("command_exec", 1)
        return None
    if callee in ("loads", "load"):
        if q_low in _UNSAFE_DESER_QUALIFIERS:
            return ("code_eval_deser", 2)
        if q_low in _AI_ML_DESER_QUALIFIERS:
            return ("ai_ml_deser", 2)
        return None
    if callee == "decode":
        if q_low == "jsonpickle":
            return ("code_eval_deser", 2)
        if q_low in ("jwt", "jsonwebtoken"):
            return ("crypto_auth", 8)
        return None
    if callee in ("verify", "sign"):
        if q_low in ("jwt", "jsonwebtoken"):
            return ("crypto_auth", 8)
        return None
    if callee == "postMessage":
        if q_low in ("window", "self", "parent", "top", "opener", ""):
            return ("template_xss", 7)
        return None
    if callee == "write":
        if q_low == "document":
            return ("template_xss", 7)
        return None
    if callee == "openExternal":
        if q_low in ("shell", ""):
            return ("desktop_extension", 5)
        return None
    if callee in ("on", "handle"):
        if q_low == "ipcmain":
            return ("desktop_extension", 5)
        return None
    if callee == "Copy":
        if q_low == "marshal":
            return ("memory_unsafe", 4)
        return None
    if callee == "Start":
        if q_low == "process":
            return ("command_exec", 1)
        return None
    if callee == "compile":
        if q_low in ("", "builtins"):
            return ("code_eval_deser", 2)
        return None
    if callee == "system" and q_low in _BENIGN_SYSTEM_QUALIFIERS:
        return None
    return _CALLEE_TO_CATEGORY.get(callee)


_ENTRYPOINT_NAME_RE = re.compile(
    r"(?:^(?:handle|serve|route|on_|api_|rpc_|do(?:get|post|put|delete)|withdraw|deposit|transfer|execute|mint|burn)|"
    r"(?:handler|controller|endpoint|view|servlet|webhook|callback|middleware|graphql)$)",
    re.IGNORECASE,
)
_ENTRYPOINT_SIG_RE = re.compile(
    r"(?:@(?:app|router|bp|blueprint|api)\.(?:route|get|post|put|delete|patch|websocket)|"
    r"@(?:mcp\.tool|server\.call_tool|tool)\b|"
    r"@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|Get|Post|Put|Delete|Patch|All|Controller|RestController|Path)\b|"
    r"#\[(?:get|post|put|delete|patch|route)\s*\(|"
    r"\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route)\b|"
    r"\b(?:http\.ResponseWriter|gin\.Context|echo\.Context|fiber\.Ctx|express\.Request|FastAPI|APIRouter)\b|"
    r"\bfunction\s+\w+\s*\([^)]*\)\s*(?:external|public)\b|"
    r"\b(?:onCreate|onReceive|onBind|application\s*\([^)]*open)\b)",
)

_RTL_LEXICAL_SINK_RE = re.compile(
    r"\b(csr_\w+|regwen\w*|priv_lvl\w*|mstatus|pmpcfg\w*|pmpaddr\w*|sec_lvl\w*|"
    r"lock_reg\w*|wr_lock\w*|jtag\w*|debug_en\w*|dbg_en\w*|dft_en\w*|scan_en\w*|"
    r"lc_state\w*|rma_en\w*|test_mode\w*|key_reg\w*|secret_key\w*|root_key\w*|"
    r"otp_key\w*|keymgr\w*|zeroize\w*|full_case|parallel_case|translate_off)\b",
    re.IGNORECASE,
)

_SUPPLEMENTAL_LEXICAL_RES: Tuple[Tuple[str, int, re.Pattern[str]], ...] = (
    (
        "cicd_supply_chain",
        2,
        re.compile(
            r"(pull_request_target|workflow_run|\$\{\{\s*github\.event\.(?:issue|pull_request|comment|head_commit|discussion)\.[^}]+\}\}|"
            r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b)"
        ),
    ),
    (
        "ai_ml_security",
        2,
        re.compile(
            r"(torch\.load|joblib\.load|trust_remote_code\s*=\s*True|weights_only\s*=\s*False|"
            r"allow_dangerous_code\s*=\s*True|allow_dangerous_deserialization\s*=\s*True)"
        ),
    ),
    (
        "smart_contract",
        3,
        re.compile(
            r"(\.call\{value:|tx\.origin|\bdelegatecall\b|\bselfdestruct\b|\bassembly\s*\{)"
        ),
    ),
    (
        "memory_unsafe",
        4,
        re.compile(
            r"(\bunsafe\s*\{|std::mem::transmute|from_raw_parts(?:_mut)?)"
        ),
    ),
    (
        "mobile_security",
        5,
        re.compile(
            r"(android:exported\s*=\s*[\"']true[\"']|usesCleartextTraffic|NSAllowsArbitraryLoads|"
            r"addJavascriptInterface|evaluateJavaScript|kSecAttrAccessibleAlways)"
        ),
    ),
    (
        "desktop_extension",
        5,
        re.compile(
            r"(nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false|webSecurity\s*:\s*false|"
            r"shell\.openExternal|ipcMain\.(?:on|handle))"
        ),
    ),
    (
        "template_xss",
        7,
        re.compile(
            r"(render_template_string|jinja2\.Template|mark_safe|dangerouslySetInnerHTML|"
            r"bypassSecurityTrust(?:Html|Url|ResourceUrl|Script|Style)|"
            r"(?:innerHTML|outerHTML)\s*=|document\.write|insertAdjacentHTML|"
            r"v-html|\[innerHTML\]|\{\{\{|<%-|window\.postMessage)"
        ),
    ),
    (
        "config_iac",
        9,
        re.compile(
            r"(<!ENTITY|\bnoent\s*:\s*true\b|\brejectUnauthorized\s*:\s*false\b|"
            r"\bverify\s*=\s*False\b|0\.0\.0\.0/0|\bprivileged\s*:\s*true\b|"
            r"\b(?:hostNetwork|hostPID|allowPrivilegeEscalation)\s*:\s*true\b|"
            r"[\"']Action[\"']\s*:\s*[\"']\*[\"']|\bdefault\s+allow\s*=\s*true\b|"
            r"Access-Control-Allow-Origin[^\n]*\*)"
        ),
    ),
)

_FALLBACK_SINK_RES: Tuple[Tuple[str, int, re.Pattern[str]], ...] = (
    (
        "command_exec",
        1,
        re.compile(
            r"\b(os\.system|os\.popen|subprocess\.(?:Popen|run|call|check_output|check_call)|"
            r"exec\.Command(?:Context)?|"
            r"child_process\.(?:exec|execSync|spawn|execFile)|shell_exec|passthru|proc_open)\s*\("
        ),
    ),
    (
        "code_eval_deser",
        2,
        re.compile(
            r"\b(eval|exec|pickle\.loads?|yaml\.(?:load|unsafe_load)|marshal\.loads?|"
            r"ObjectInputStream|unserialize|vm\.runIn(?:New|This)?Context)\s*\("
        ),
    ),
    (
        "sql_query",
        3,
        re.compile(
            r"\b((?:cursor|db|conn|connection|session|engine)\.execute(?:many|script)?|"
            r"\.raw\s*\(|RawSQL|sequelize\.query|"
            r"\$queryRawUnsafe|\$executeRawUnsafe|createNativeQuery)\b"
        ),
    ),
    (
        "ssrf_network",
        5,
        re.compile(
            r"\b(urllib\.request\.urlopen|requests\.(?:get|post|put|delete|request)|"
            r"httpx\.(?:get|post|request)|http\.(?:Get|Post|NewRequest))\s*\("
        ),
    ),
    (
        "path_fs",
        6,
        re.compile(
            r"\b(send_file|send_from_directory|FileResponse|tarfile\.open|extractall|"
            r"shutil\.unpack_archive|fs\.(?:readFile|writeFile)(?:Sync)?)\b"
        ),
    ),
    *_SUPPLEMENTAL_LEXICAL_RES,
)


def _scope_rel_prefixes(
    code_root: str, target_file: str, group_targets: Sequence[str] = ()
) -> Tuple[List[str], bool]:
    """Returns `(sorted_rel_prefixes, is_whole_root)` for a campaign's scope."""
    root_real = os.path.realpath(str(code_root)).rstrip("/")
    raw_targets = [t for t in (list(group_targets) or ([target_file] if target_file else [])) if t]
    if not raw_targets:
        return [], True
    prefixes: set[str] = set()
    for raw in raw_targets:
        t_real = os.path.realpath(str(raw)).rstrip("/")
        if t_real == root_real:
            return [], True
        if t_real.startswith(root_real + os.sep):
            prefixes.add(os.path.relpath(t_real, root_real).replace(os.sep, "/"))
        elif os.path.isfile(t_real):
            prefixes.add(os.path.basename(t_real))
    return sorted(prefixes), False


def _path_in_prefixes(rel_path: str, prefixes: Sequence[str], is_whole: bool) -> bool:
    if is_whole:
        return True
    norm = str(rel_path or "").replace("\\", "/").lstrip("/")
    for p in prefixes:
        if norm == p or norm.startswith(p.rstrip("/") + "/"):
            return True
    return False


def _cap_per_file_sinks(
    sinks: Sequence[Tuple[int, str, int, str, str, str]],
    max_per_file: int = MAX_SINKS_PER_FILE,
) -> List[Tuple[int, str, int, str, str, str]]:
    """Caps sink bullets per file at `max_per_file` (highest-severity first)
    so a single noisy file cannot flood the slice checklist."""
    ordered = sorted(sinks, key=lambda item: (item[0], item[1], item[2], item[4]))
    counts: Dict[str, int] = {}
    kept: List[Tuple[int, str, int, str, str, str]] = []
    limit = max(1, int(max_per_file))
    for item in ordered:
        fp = item[1]
        cur = counts.get(fp, 0)
        if cur >= limit:
            continue
        counts[fp] = cur + 1
        kept.append(item)
    return kept


def _select_balanced_sinks(
    sinks: Sequence[Tuple[int, str, int, str, str, str]],
    max_sinks: int,
) -> List[Tuple[int, str, int, str, str, str]]:
    """Selects up to `max_sinks` deterministically across every present category
    so one high-volume sink class cannot crowd out XSS, RTL, or config sinks.

    Final output is sorted strictly by `(tier_rank, file_path, line, callee)`.
    """
    limit = max(1, int(max_sinks))
    if len(sinks) <= limit:
        return sorted(sinks, key=lambda item: (item[0], item[1], item[2], item[4]))

    buckets: Dict[Tuple[int, str], List[Tuple[int, str, int, str, str, str]]] = {}
    for item in sorted(sinks, key=lambda it: (it[0], it[1], it[2], it[4])):
        buckets.setdefault((item[0], item[3]), []).append(item)

    ordered_keys = sorted(buckets.keys())
    selected: List[Tuple[int, str, int, str, str, str]] = []
    round_idx = 0
    while len(selected) < limit:
        added = False
        for key in ordered_keys:
            items = buckets[key]
            if round_idx < len(items):
                selected.append(items[round_idx])
                added = True
                if len(selected) >= limit:
                    break
        if not added:
            break
        round_idx += 1

    return sorted(selected, key=lambda item: (item[0], item[1], item[2], item[4]))


def _query_catalog_checklist(
    catalog_path: Path,
    prefixes: Sequence[str],
    is_whole: bool,
    *,
    max_per_file: int = MAX_SINKS_PER_FILE,
) -> Tuple[List[Tuple[int, str, int, str, str, str]], List[Tuple[str, int, str, str]]]:
    """Returns `(sinks, entrypoints)` from `catalog.sqlite` in deterministic order."""
    sinks: List[Tuple[int, str, int, str, str, str]] = []
    entrypoints: List[Tuple[str, int, str, str]] = []
    if not catalog_path.exists():
        return sinks, entrypoints

    callee_names = sorted(set(_CALLEE_TO_CATEGORY) | _QUALIFIED_ONLY_CALLEES)
    placeholders = ",".join("?" for _ in callee_names)
    conn = sqlite3.connect(f"file:{catalog_path}?mode=ro", uri=True)
    try:
        cols = {
            str(r[1])
            for r in conn.execute("PRAGMA table_info(call_edges)").fetchall()
        }
        qual_expr = "COALESCE(e.qualifier, '')" if "qualifier" in cols else "''"
        edge_rows = conn.execute(
            f"SELECT e.file_path, e.line, e.callee_name, COALESCE(s.qualified_name, '<module>'), {qual_expr}"
            f" FROM call_edges e LEFT JOIN symbols s ON s.symbol_id = e.caller_id"
            f" WHERE e.callee_name IN ({placeholders})"
            f" ORDER BY e.file_path ASC, e.line ASC, e.callee_name ASC",
            tuple(callee_names),
        ).fetchall()
        seen_sinks: set[Tuple[str, int, str]] = set()
        for fp, line, callee, caller, qual in edge_rows:
            fp_s = str(fp or "")
            if not _path_in_prefixes(fp_s, prefixes, is_whole):
                continue
            callee_s = str(callee or "")
            classified = _classify_edge_sink(callee_s, str(qual or ""))
            if classified is None:
                continue
            key = (fp_s, int(line or 0), callee_s)
            if key in seen_sinks:
                continue
            seen_sinks.add(key)
            cat, rank = classified
            sinks.append((rank, fp_s, int(line or 0), cat, callee_s, str(caller or "<module>")))

        sym_rows = conn.execute(
            "SELECT file_path, start_line, name, qualified_name, COALESCE(signature, ''), kind, language"
            " FROM symbols WHERE kind IN ('function', 'method')"
            "   OR (kind = 'module' AND name != '<module>' AND language IN ('verilog', 'systemverilog', 'vhdl'))"
            " ORDER BY file_path ASC, start_line ASC, qualified_name ASC"
        ).fetchall()
        for fp, start_line, name, qname, sig, kind, lang in sym_rows:
            fp_s = str(fp or "")
            if not _path_in_prefixes(fp_s, prefixes, is_whole):
                continue
            name_s = str(name or "")
            sig_s = str(sig or "")
            is_rtl_mod = str(kind or "") == "module" and str(lang or "") in (
                "verilog", "systemverilog", "vhdl"
            )
            if is_rtl_mod or _ENTRYPOINT_NAME_RE.search(name_s) or _ENTRYPOINT_SIG_RE.search(sig_s):
                entrypoints.append((fp_s, int(start_line or 0), str(qname or name_s), sig_s[:100]))
    finally:
        conn.close()

    sinks = _cap_per_file_sinks(sinks, max_per_file=max_per_file)
    entrypoints.sort(key=lambda item: (item[0], item[1], item[2]))
    return sinks, entrypoints


def _fallback_lexical_checklist(
    code_root: str,
    prefixes: Sequence[str],
    is_whole: bool,
    *,
    max_files: int = MAX_FALLBACK_FILES,
    max_per_file: int = MAX_SINKS_PER_FILE,
    patterns: Sequence[Tuple[str, int, re.Pattern[str]]] = _FALLBACK_SINK_RES,
) -> List[Tuple[int, str, int, str, str, str]]:
    """Bounded deterministic lexical scan for fallback and non-AST/RTL/template sinks."""
    sinks: List[Tuple[int, str, int, str, str, str]] = []
    try:
        vetted = sorted(get_vetted_staging_files(code_root), key=lambda t: t[1])
    except Exception:
        return sinks
    matched_files = [
        (abs_p, rel_p)
        for abs_p, rel_p in vetted
        if _path_in_prefixes(rel_p, prefixes, is_whole)
    ][: max(1, int(max_files))]

    seen: set[Tuple[str, int, str]] = set()
    for abs_p, rel_p in matched_files:
        try:
            st = os.stat(abs_p)
            if st.st_size > MAX_FALLBACK_FILE_BYTES:
                continue
            text = Path(abs_p).read_bytes().decode("utf-8", errors="replace")
        except OSError:
            continue
        is_rtl = Path(rel_p).suffix.lower() in _RTL_EXTS
        for lineno, line_text in enumerate(text.splitlines(), 1):
            for cat, rank, pat in patterns:
                m = pat.search(line_text)
                if m:
                    callee = m.group(1)
                    key = (rel_p, lineno, callee)
                    if key not in seen:
                        seen.add(key)
                        sinks.append((rank, rel_p, lineno, cat, callee, "<lexical>"))
            if is_rtl:
                rm = _RTL_LEXICAL_SINK_RE.search(line_text)
                if rm:
                    sig_name = rm.group(1)
                    key = (rel_p, lineno, sig_name)
                    if key not in seen:
                        seen.add(key)
                        sinks.append((4, rel_p, lineno, "rtl_hw_security", sig_name, "<rtl>"))
    return _cap_per_file_sinks(sinks, max_per_file=max_per_file)


def build_slice_audit_checklist(ctx: Any) -> str:
    """Builds a deterministic, CP-4-fenced sink & entrypoint checklist for `ctx`.

    Caps scale smoothly with `ctx.depth` (default `30`), and sinks are balanced
    across present categories (backend, frontend/DOM/templates, configs/IaC,
    and hardware/RTL). Returns `""` when no context or no high-risk
    sinks/entrypoints are present in scope. Never raises (INV-6).
    """
    if ctx is None:
        return ""
    try:
        code_root = (
            str(getattr(ctx, "path_root", "") or "").strip()
            or str(getattr(ctx, "jail_dir", "") or "").strip()
        )
        target_file = str(getattr(ctx, "target_file", "") or "").strip()
        if not code_root and target_file:
            code_root = os.path.dirname(target_file) if os.path.isfile(target_file) else target_file
        if not code_root or not os.path.exists(code_root):
            return ""
        if os.path.isfile(code_root):
            code_root = os.path.dirname(code_root)
        import tempfile as _tempfile
        if os.path.realpath(code_root) == os.path.realpath(_tempfile.gettempdir()):
            return ""

        raw_depth = getattr(ctx, "depth", None)
        try:
            profile = resolve_depth_profile(DEFAULT_DEPTH if raw_depth is None else raw_depth)
        except Exception:
            profile = resolve_depth_profile(DEFAULT_DEPTH)

        max_sinks = profile.checklist_max_sinks
        max_eps = profile.checklist_max_entrypoints
        max_chars = profile.checklist_max_chars
        max_fb_files = profile.checklist_max_fallback_files
        max_per_file = profile.checklist_max_sinks_per_file

        prefixes, is_whole = _scope_rel_prefixes(
            code_root, target_file, getattr(ctx, "group_targets", ()) or ()
        )

        sinks: List[Tuple[int, str, int, str, str, str]] = []
        entrypoints: List[Tuple[str, int, str, str]] = []
        db_path = str(getattr(ctx, "db_path", "") or "").strip()
        if db_path:
            try:
                resolved_db = resolve_db_path(db_path)
                matched_state = resolve_state_dir_for_target(
                    resolved_db,
                    code_root,
                    snapshot_id=str(getattr(ctx, "snapshot_id", "") or ""),
                )
                if matched_state:
                    sinks, entrypoints = _query_catalog_checklist(
                        Path(matched_state) / "catalog.sqlite",
                        prefixes,
                        is_whole,
                        max_per_file=max_per_file,
                    )
            except Exception:
                sinks, entrypoints = [], []

        if not sinks:
            sinks = _fallback_lexical_checklist(
                code_root,
                prefixes,
                is_whole,
                max_files=max_fb_files,
                max_per_file=max_per_file,
            )
        else:
            # Always supplement AST call-edge sinks with bounded lexical hits
            # for non-call sinks (HTML/DOM templates, IaC/XML configs, RTL signals).
            supp = _fallback_lexical_checklist(
                code_root,
                prefixes,
                is_whole,
                max_files=max_fb_files,
                max_per_file=max_per_file,
                patterns=_SUPPLEMENTAL_LEXICAL_RES,
            )
            if supp:
                existing_loc_cat = {(fp, ln, cat) for _r, fp, ln, cat, _c, _caller in sinks}
                for item in supp:
                    if (item[1], item[2], item[3]) not in existing_loc_cat:
                        sinks.append(item)
                        existing_loc_cat.add((item[1], item[2], item[3]))
                sinks = _cap_per_file_sinks(sinks, max_per_file=max_per_file)

        if not sinks and not entrypoints:
            return ""

        lines: List[str] = ["# Deterministic Slice Sink & Entrypoint Inventory"]
        if sinks:
            shown_sinks = _select_balanced_sinks(sinks, max_sinks)
            lines.append(
                f"\n## Indexed Security-Sensitive Sinks ({len(shown_sinks)} of {len(sinks)} shown)"
            )
            for _rank, fp, lineno, cat, callee, caller in shown_sinks:
                caller_note = (
                    f" in {caller}"
                    if caller and caller not in ("<module>", "<lexical>", "<rtl>")
                    else ""
                )
                suffix = "" if caller == "<rtl>" else "()"
                lines.append(f"- [{cat}] {fp}:{lineno} -> {callee}{suffix}{caller_note}")
        if entrypoints:
            shown_eps = entrypoints[:max_eps]
            lines.append(
                f"\n## Indexed Entrypoints & Handlers ({len(shown_eps)} of {len(entrypoints)} shown)"
            )
            for fp, lineno, qname, _sig in shown_eps:
                lines.append(f"- [entrypoint] {fp}:{lineno} -> {qname}")

        body = "\n".join(lines)
        if len(body) > max_chars:
            body = body[:max_chars].rsplit("\n", 1)[0] + "\n... [checklist capped]"

        fenced = wrap_untrusted_content(body, filename="deterministic_slice_checklist")
        return (
            "\n\n"
            + fenced
            + "\n[DETERMINISTIC AUDIT CHECKLIST] The inventory above lists concrete "
            "high-risk sinks and entrypoints extracted deterministically from this "
            "slice's AST/source in sorted order. Account for every listed sink in "
            "your review plan and verify attacker reachability and sanitization for "
            "each before concluding this slice is clean (still inspect surrounding "
            "business logic via read_file; absence from the index is not proof of safety)."
        )
    except Exception:
        return ""

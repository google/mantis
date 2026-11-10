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

"""Deterministic structural code index: tree-sitter -> catalog.sqlite.

Replaces the LLM structural_index stage with a deterministic builder, and
backs the structural research tools (find_symbol, find_callers,
find_callees, get_function_boundary). The on-disk contract is the OSS
subset of the mantis-structural-index spec: a SQLite catalog with symbols,
call edges, function boundaries and per-file coverage, plus a manifest
written last as the atomic commit point.

Design rules, in order:

1. Fail safe. Build never raises: no tree-sitter, no grammar, unparseable
   source, or an unreadable state dir all degrade to an empty or partial
   index with the reason recorded. Consumers fall back to read_file.
2. The index is a HINT. It ranks and narrows reading; it never decides
   membership. "No callers" means "no indexed callers".
3. Read-only on the target. File enumeration goes through CP-1
   get_vetted_staging_files only; all writes land in the state directory.
4. Reuse on snapshot match. Rebuilding the same root with the same pinned
   snapshot_id reuses the published index; "unknown" (unpinned) always
   rebuilds, with per-file content-addressed unit reuse to keep that cheap.
   git_snapshot_id pins a clean checkout to its HEAD.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import stat
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    _fcntl = None  # type: ignore[assignment]

from core.environments.staging import get_vetted_staging_files

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
EXTRACTOR_NAME = "tree-sitter"
STATE_DIRNAME = "structural_index"

# Bounds. Deterministic: files are processed in sorted relative-path order,
# so truncation always drops the same tail.
MAX_UNITS = 10000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 200 * 1024 * 1024
MAX_TOTAL_SYMBOLS = 250000


def _resolve_index_limits() -> Tuple[int, int]:
    """Returns `(max_total_source_bytes, max_total_symbols)` honoring env overrides."""
    max_bytes = MAX_TOTAL_SOURCE_BYTES
    raw_bytes = os.environ.get("MANTIS_MAX_INDEX_BYTES", "").strip()
    if raw_bytes:
        try:
            parsed_b = int(raw_bytes)
            if parsed_b > 0:
                max_bytes = parsed_b
        except ValueError:
            pass
    max_syms = MAX_TOTAL_SYMBOLS
    raw_syms = os.environ.get("MANTIS_MAX_INDEX_SYMBOLS", "").strip()
    if raw_syms:
        try:
            parsed_s = int(raw_syms)
            if parsed_s > 0:
                max_syms = parsed_s
        except ValueError:
            pass
    return max_bytes, max_syms

_EXT_LANGUAGES = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "tsx",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c", ".h": "cpp",  # C++ headers do not parse as C; C headers do parse as C++
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".rs": "rust",
    ".kt": "kotlin", ".kts": "kotlin",
    ".cs": "csharp",
}

# Function-like definition node types across the grammars above, mapped to
# the symbol kind they produce. Anonymous forms (arrow functions, lambdas)
# are deliberately absent: a symbol nobody can name is not navigable.
_DEF_KINDS = {
    "function_definition": "function",     # python, c, cpp, php
    "function_declaration": "function",    # javascript, go, kotlin
    "function_item": "function",           # rust
    "method_definition": "method",         # javascript/typescript classes
    "method_declaration": "method",        # java, csharp, go receivers
    "constructor_declaration": "method",   # java, csharp
    "method": "method",                    # ruby
    "singleton_method": "method",          # ruby
    "class_definition": "class",           # python
    "class_declaration": "class",          # javascript, java, csharp
    "class": "class",                      # ruby
    "class_specifier": "class",            # cpp
    "interface_declaration": "interface",  # java, typescript
    "struct_item": "struct",               # rust
    "impl_item": "class",                  # rust impl blocks
    "preproc_def": "macro",                # c, cpp `#define FOO ...`
    "preproc_function_def": "macro",       # c, cpp `#define FOO(x) ...`
    "type_spec": "type",                   # go `type Foo struct/interface {...}`
    "type_alias": "type",                  # go `type Alias = Foo`
    "struct_specifier": "struct",          # c, cpp (definitions only; see _BODY_REQUIRED)
    "enum_specifier": "enum",              # c, cpp
    "union_specifier": "union",            # c, cpp
    "trait_item": "interface",             # rust `trait Foo { ... }`
    "enum_item": "enum",                   # rust
    "union_item": "union",                 # rust
    "mod_item": "module",                  # rust `mod foo { ... }`
    "type_item": "type",                   # rust `type Alias = Foo`
    "macro_definition": "macro",           # rust `macro_rules! foo`
    "object_declaration": "class",         # kotlin `object Foo { ... }`
    "generator_function_declaration": "function",  # js/ts `function* gen() {...}`
    "type_alias_declaration": "type",      # ts `type Alias = {...}`
    "abstract_class_declaration": "class", # ts `abstract class Foo {...}`
    "internal_module": "module",           # ts `namespace Ns {...}`
    "enum_declaration": "enum",            # ts, java, csharp, php 8.1
    "record_declaration": "class",         # java, csharp records
    "annotation_type_declaration": "interface",  # java `@interface Anno {...}`
    "struct_declaration": "struct",        # csharp
    "property_declaration": "property",    # csharp properties; php class fields
    "trait_declaration": "interface",      # php traits (mixin; kind matches rust trait_item)
    "module": "module",                    # ruby `module Foo ... end`
}

# C/C++ type specifiers appear both at definitions (`struct Foo { ... };`) and
# at every forward declaration or type reference (`struct Foo x;`). Only a
# node with a body is a definition; indexing the rest would mint one fake
# symbol per usage site.
_BODY_REQUIRED = frozenset({
    "class_specifier", "struct_specifier", "enum_specifier", "union_specifier",
})

# `const f = () => {...}` binds a NAME to a function: unlike a truly anonymous
# lambda it is navigable, so it earns a symbol. The declarator's `value` field
# type distinguishes it from ordinary variable initialization (`const x = 5`).
# Java/C# lambdas parse as `lambda_expression`, deliberately not listed here.
_FUNCTION_VALUE_TYPES = frozenset({
    "arrow_function", "function_expression", "generator_function",  # js/ts
})

_CALL_TYPES = frozenset({
    "call",                      # python, ruby
    "call_expression",           # js/ts, go, c, cpp, rust, kotlin
    "method_invocation",         # java
    "invocation_expression",     # csharp
    "function_call_expression",  # php
    "member_call_expression",    # php
    "object_creation_expression",  # java, csharp `new X()`
    "new_expression",            # js/ts `new X()`
    "macro_invocation",          # rust
})

_NAME_LEAF_TYPES = frozenset({
    "identifier", "property_identifier", "field_identifier",
    "type_identifier", "constant", "name", "word",
    "simple_identifier",  # kotlin: its grammar exposes no `name` field at all
})


# --- Extraction -----------------------------------------------------------------


def _language_for(rel_path: str) -> Optional[str]:
    return _EXT_LANGUAGES.get(Path(rel_path).suffix.lower())


def _load_parser(language: str):
    """Returns a parser or None. Import failure is a degradation, not an error."""
    try:
        from tree_sitter_language_pack import get_parser
        return get_parser(language)
    except Exception:
        return None


def _ts_version() -> str:
    try:
        import tree_sitter
        return getattr(tree_sitter, "__version__", "unknown")
    except Exception:
        return "absent"


def _node_name(node) -> str:
    """Best-effort symbol name for a definition node."""
    named = node.child_by_field_name("name")
    if named is None:
        # C/C++ bury the identifier inside the declarator chain.
        decl = node.child_by_field_name("declarator")
        probe, depth = decl, 0
        while probe is not None and depth < 6:
            if probe.type in _NAME_LEAF_TYPES or probe.type in ("operator_name", "destructor_name"):
                # operator_name / destructor_name: `T operator()(...)`,
                # `~Foo()` — the token IS the name (ctags does the same).
                # Without this, operators are inconsistently dropped
                # (bool operator==) or named after their return type
                # (T operator() -> "T"), and destructors either vanish or
                # collide with constructor names.
                named = probe
                break
            if probe.type == "operator_cast":
                # Conversion operator `operator bool() const`: the name is
                # "operator <type>" (ctags semantics); the node's text would
                # drag in the parameter list and qualifiers.
                type_child = probe.child_by_field_name("type")
                if type_child is not None:
                    try:
                        return "operator " + type_child.text.decode("utf-8", errors="replace")
                    except Exception:
                        return ""
                return ""
            nxt = probe.child_by_field_name("declarator") or probe.child_by_field_name("name")
            if nxt is None:
                # Some wrappers (cpp `reference_declarator`: `T& f(...)`)
                # expose NO fields; their declarator child continues the
                # chain. Without this, the fallback below grabs the return
                # type and names the function after it (e.g. "T").
                for child in probe.named_children:
                    if child.type.endswith("declarator") or child.type in _NAME_LEAF_TYPES:
                        nxt = child
                        break
            probe = nxt
            depth += 1
    if named is None:
        for child in node.named_children:
            if child.type in _NAME_LEAF_TYPES:
                named = child
                break
    if named is None:
        return ""
    try:
        return named.text.decode("utf-8", errors="replace")
    except Exception:
        return ""


# Ambient runtime/stdlib objects whose methods (console.log, JSON.parse, os.open)
# must not resolve as 'direct' call edges to an unrelated repository symbol
# merely because no local 'console' or 'JSON' class exists in the catalog.
_AMBIENT_RECEIVERS = frozenset({
    "console", "Math", "JSON", "Object", "Array", "Promise", "Number",
    "String", "Boolean", "Date", "RegExp", "Error", "Map", "Set", "WeakMap",
    "WeakSet", "Symbol", "Reflect", "Proxy", "Intl", "Buffer", "process",
    "window", "document", "localStorage", "sessionStorage", "navigator",
    "os", "sys", "re", "json", "time", "math", "logging", "pathlib", "shutil",
    "subprocess", "sqlite3", "hashlib", "uuid", "itertools", "functools",
    "collections", "typing", "asyncio", "threading", "tempfile", "unittest",
})


_MAX_SPINE_HOPS = 64


def _rightmost_name_leaf(node) -> str:
    """The called name inside a callee expression: a.b.c() calls 'c'.

    Walks the right spine of the callee: at each level, the rightmost
    direct name leaf wins (`c` in `(a.b).c`, `f` in `f<int>`), otherwise
    descend into the last named child. Constant work per call site.

    The previous breadth-first walk over the whole callee subtree was
    quadratic on chained calls (`a.b().b()...`: every callee contains every
    inner call), which let one file under the size cap stall the build for
    hours, and it returned the LAST leaf visited -- the deepest, which in a
    chain is the leftmost receiver, so `a.b.c()` resolved to `b`.
    """
    cur = node
    hops = 0
    while cur is not None and hops < _MAX_SPINE_HOPS:
        if cur.type in _NAME_LEAF_TYPES:
            try:
                return cur.text.decode("utf-8", errors="replace")
            except Exception:
                return ""
        kids = cur.named_children
        if not kids:
            return ""
        for kid in reversed(kids):
            if kid.type in _NAME_LEAF_TYPES:
                try:
                    return kid.text.decode("utf-8", errors="replace")
                except Exception:
                    return ""
        cur = kids[-1]
        hops += 1
    return ""


def _target_qualifier(target) -> str:
    """Immediate static receiver of a member/qualified call target, else ''."""
    if target is None or target.type in _NAME_LEAF_TYPES:
        return ""
    children = target.named_children
    if len(children) < 2:
        return ""
    recv = children[0]
    prop = children[-1]
    if prop.type not in _NAME_LEAF_TYPES:
        return ""
    if recv.type in _CALL_TYPES or "subscript" in recv.type or "index" in recv.type:
        return ""
    if recv.type in _NAME_LEAF_TYPES or recv.type in ("self", "this", "super"):
        try:
            return recv.text.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""
    # Chained member access (`models.sequelize.query`): take the immediate
    # receiver (`sequelize`) when the left spine is itself a member access.
    if len(recv.named_children) >= 2 and recv.named_children[-1].type in _NAME_LEAF_TYPES:
        try:
            return recv.named_children[-1].text.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""
    return ""


def _callee_parts(call_node) -> Tuple[str, str]:
    """Returns (qualifier, callee_name) for a call AST node."""
    for field in ("function", "name", "constructor", "type", "method"):
        target = call_node.child_by_field_name(field)
        if target is not None:
            return _target_qualifier(target), _rightmost_name_leaf(target)
    for child in call_node.named_children:
        leaf = _rightmost_name_leaf(child)
        if leaf:
            return _target_qualifier(child), leaf
    return "", ""


def _callee_name(call_node) -> str:
    return _callee_parts(call_node)[1]


def _signature_of(node, source: bytes) -> str:
    # Bounded slice: a definition on a single multi-megabyte line would
    # otherwise be copied in full for every nested definition inside it.
    end = min(node.end_byte, node.start_byte + _MAX_SIGNATURE_SCAN_BYTES)
    first_line = source[node.start_byte:end].split(b"\n", 1)[0]
    return first_line.decode("utf-8", errors="replace").strip()[:200]


_MAX_SIGNATURE_SCAN_BYTES = 4096

# Nesting deeper than this stops extending the qualified-name prefix. Real
# code nests a handful of levels; `function a(){` repeated 30k times is a
# 450 KB file whose qualified names total a gigabyte (quadratic in depth).
MAX_NEST_DEPTH = 64
_MAX_QUALIFIED_CHARS = 512


def _symbol_id(language: str, rel_path: str, qualified: str, start_line: int, signature: str) -> str:
    digest = hashlib.sha256(f"{qualified}|{start_line}|{signature}".encode()).hexdigest()[:16]
    return f"fallback:{language}:{rel_path}:{digest}"


def extract_unit(rel_path: str, source: bytes, language: str, parser) -> Dict[str, Any]:
    """Extracts one file's symbols and raw call edges. Pure, deterministic."""
    symbols: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    tree = parser.parse(source)
    module_sig = f"<module {rel_path}>"
    module_id = _symbol_id(language, rel_path, "<module>", 1, module_sig)
    symbols.append({
        "symbol_id": module_id,
        "name": "<module>",
        "qualified_name": "<module>",
        "language": language,
        "file_path": rel_path,
        "start_line": 1,
        "end_line": max(1, tree.root_node.end_point[0] + 1),
        "kind": "module",
        "signature": module_sig,
    })

    # Iterative walk with an explicit enclosing-definition stack, so every
    # call edge is attributed to its innermost named definition. The walk
    # starts BELOW the root: the file itself is already represented by the
    # synthetic <module> symbol, and python's root node type is literally
    # "module" — letting it match _DEF_KINDS would mint a spurious symbol
    # named after the first top-level bare identifier (this grammar keeps
    # bare-expression identifiers as DIRECT children of the root) and then
    # prefix every qualified name in the file with it.
    stack: List[Tuple[Any, List[Tuple[str, str]]]] = [
        (child, []) for child in reversed(tree.root_node.named_children)
    ]
    while stack:
        node, enclosing = stack.pop()
        kind = _DEF_KINDS.get(node.type)
        if kind is not None and node.type in _BODY_REQUIRED and node.child_by_field_name("body") is None:
            kind = None  # forward declaration / type reference, not a definition
        if kind is None and node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is not None and value.type in _FUNCTION_VALUE_TYPES:
                kind = "function"  # named `const f = () => ...` (js/ts)
        if kind is not None:
            name = _node_name(node)
            if name:
                # Bounded: the prefix stops growing past MAX_NEST_DEPTH and
                # the joined name is capped, so a pathological nesting depth
                # costs linear memory, not quadratic.
                prefix = [n for n, _ in enclosing[-MAX_NEST_DEPTH:]]
                qualified = ".".join(prefix + [name])[-_MAX_QUALIFIED_CHARS:]
                signature = _signature_of(node, source)
                sid = _symbol_id(language, rel_path, qualified, node.start_point[0] + 1, signature)
                symbols.append({
                    "symbol_id": sid,
                    "name": name,
                    "qualified_name": qualified,
                    "language": language,
                    "file_path": rel_path,
                    "start_line": node.start_point[0] + 1,
                    "end_line": node.end_point[0] + 1,
                    "kind": kind,
                    "signature": signature,
                })
                if len(enclosing) < MAX_NEST_DEPTH:
                    enclosing = enclosing + [(name, sid)]
                else:
                    # Past the cap the innermost definition still owns the
                    # calls beneath it; only the prefix stops growing.
                    enclosing = enclosing[:-1] + [(name, sid)]
        elif node.type in _CALL_TYPES:
            qualifier, callee = _callee_parts(node)
            if callee:
                caller_id = enclosing[-1][1] if enclosing else module_id
                edge_entry: Dict[str, Any] = {
                    "caller_id": caller_id,
                    "callee_name": callee,
                    "file_path": rel_path,
                    "line": node.start_point[0] + 1,
                }
                if qualifier:
                    edge_entry["qualifier"] = qualifier
                edges.append(edge_entry)
        for child in reversed(node.named_children):
            stack.append((child, enclosing))

    return {"file": rel_path, "language": language, "symbols": symbols, "edges": edges}


# --- Cognitive complexity ---------------------------------------------------------

# Control-flow node types across the grammars in _EXT_LANGUAGES, one union table,
# same approach as _DEF_KINDS and _CALL_TYPES: the names are distinct enough across
# grammars, a name that does not occur in some grammar simply never matches there,
# and a construct missing from this table under-counts rather than raises.
_CONTROL_TYPES = frozenset({
    # python
    "if_statement", "elif_clause", "for_statement", "while_statement",
    "except_clause", "conditional_expression", "boolean_operator", "match_statement",
    # javascript / typescript
    "for_in_statement", "do_statement", "switch_statement", "catch_clause",
    "ternary_expression",
    # java (if/for/while/do/catch shared above)
    "enhanced_for_statement", "switch_expression",
    # go
    "expression_switch_statement", "type_switch_statement", "select_statement",
    # ruby
    "if", "unless", "while", "until", "for", "case", "rescue", "conditional",
    # php (match_expression also rust)
    "foreach_statement", "match_expression",
    # rust
    "if_expression", "while_expression", "loop_expression", "for_expression",
    # kotlin
    "when_expression", "do_while_statement", "catch_block",
    # c / cpp / csharp share if/for/while/do/switch/conditional/catch above
    "for_range_loop",
})


def cognitive_complexity(source: bytes, language: str) -> Optional[Dict[str, int]]:
    """G = sum of (1 + nesting depth) over control-flow nodes. None on degradation.

    The simplified cognitive-complexity formulation: every control-flow construct
    costs 1 plus one per ENCLOSING control-flow construct, so deeply nested logic
    outweighs the same constructs laid flat. Deliberate simplifications against the
    full SonarSource definition, chosen because this feeds a RANKING and only
    monotonicity matters: else-if chains in grammars that nest them pay a nesting
    increment, and nested function bodies inherit their enclosing depth rather
    than resetting it.

    Returns {"complexity", "control_nodes", "functions"} summed over the whole
    file -- module-level control flow included, since a script's tangle is as real
    as a function's -- or None when the grammar is unavailable or the source does
    not parse. None, not zero: "could not measure" must stay distinguishable from
    "measured as trivial".
    """
    parser = _load_parser(language)
    if parser is None:
        return None
    try:
        tree = parser.parse(source)
    except Exception:
        return None
    total = controls = functions = 0
    stack: List[Tuple[Any, int]] = [(tree.root_node, 0)]
    while stack:
        node, depth = stack.pop()
        child_depth = depth
        if node.type in _CONTROL_TYPES:
            total += 1 + depth
            controls += 1
            child_depth = depth + 1
        elif _DEF_KINDS.get(node.type) in ("function", "method"):
            functions += 1
        for child in node.named_children:
            stack.append((child, child_depth))
    return {"complexity": total, "control_nodes": controls, "functions": functions}


def complexity_for_file(rel_path: str, source: bytes) -> Optional[Dict[str, int]]:
    """`cognitive_complexity` with the language resolved from the file extension.

    None for an extension with no grammar, same contract as above.
    """
    language = _language_for(rel_path)
    if language is None:
        return None
    return cognitive_complexity(source, language)


# --- Build ----------------------------------------------------------------------


_CATALOG_DDL = """
CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS symbols (
    symbol_id TEXT PRIMARY KEY, name TEXT NOT NULL, qualified_name TEXT NOT NULL,
    namespace TEXT, language TEXT NOT NULL, file_path TEXT NOT NULL,
    start_line INTEGER NOT NULL, end_line INTEGER, kind TEXT NOT NULL,
    signature TEXT, backend TEXT NOT NULL,
    precision TEXT NOT NULL CHECK (precision IN ('semantic','typecheck','ast','symbol-only','heuristic','deferred','coverage-only'))
);
CREATE TABLE IF NOT EXISTS call_edges (
    edge_id INTEGER PRIMARY KEY AUTOINCREMENT,
    caller_id TEXT NOT NULL, callee_id TEXT, callee_name TEXT NOT NULL,
    file_path TEXT NOT NULL, line INTEGER NOT NULL,
    edge_kind TEXT NOT NULL CHECK (edge_kind IN ('direct','indirect','virtual','macro','unresolved')),
    FOREIGN KEY (caller_id) REFERENCES symbols(symbol_id),
    FOREIGN KEY (callee_id) REFERENCES symbols(symbol_id)
);
CREATE TABLE IF NOT EXISTS function_boundaries (
    symbol_id TEXT PRIMARY KEY, file_path TEXT NOT NULL,
    start_line INTEGER NOT NULL, end_line INTEGER NOT NULL,
    signature TEXT, language TEXT NOT NULL,
    FOREIGN KEY (symbol_id) REFERENCES symbols(symbol_id)
);
CREATE TABLE IF NOT EXISTS coverage (
    file_path TEXT PRIMARY KEY, indexed INTEGER NOT NULL DEFAULT 0,
    backend TEXT, precision TEXT, unit_cache_key TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
);
CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_symbols_qualified ON symbols(qualified_name);
CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file_path, start_line);
CREATE INDEX IF NOT EXISTS idx_edges_caller ON call_edges(caller_id);
CREATE INDEX IF NOT EXISTS idx_edges_callee ON call_edges(callee_id);
CREATE INDEX IF NOT EXISTS idx_edges_callee_name ON call_edges(callee_name);
CREATE INDEX IF NOT EXISTS idx_boundaries_file ON function_boundaries(file_path, start_line, end_line);
"""


def _unit_cache_key(language: str, content_sha: str) -> str:
    return hashlib.sha256(
        f"{SCHEMA_VERSION}|{EXTRACTOR_NAME}@{_ts_version()}|{language}|{content_sha}".encode()
    ).hexdigest()


def _unit_cache_path(state_dir: Path, key: str) -> Path:
    return state_dir / "units" / key[:2] / key[2:4] / f"{key}.json"


def _read_manifest(state_dir: Path) -> Optional[Dict[str, Any]]:
    try:
        with open(state_dir / "manifest.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def git_snapshot_id(code_root: str) -> str:
    """`git:<HEAD>` when code_root is a clean git checkout, else "unknown".

    The pin is what lets a rebuild reuse the published index, so it must
    only ever name one tree. The index reads every file under code_root, not
    only tracked ones, so any untracked or ignored file -- not just a
    modified one -- counts as dirty. A code_root that is not the top of its
    repository, or any git failure, is "unknown": a full rebuild is the cost,
    never a stale catalog.
    """
    # Lazy, like the surveyor's: core must not import tools at module scope.
    try:
        from tools.research_tools import _run_safe_git_command, _validate_git_jail

        root = Path(code_root)
        valid, _ = _validate_git_jail(root, root)
        if not valid:
            return "unknown"
        head, ok = _run_safe_git_command(["rev-parse", "HEAD"], root)
        head = head.strip()
        if not ok or not re.fullmatch(r"[0-9a-f]{7,64}", head):
            return "unknown"
        dirty, ok = _run_safe_git_command(
            ["status", "--porcelain", "--ignored", "--untracked-files=normal", "--ignore-submodules=all"],
            root,
            timeout=60,
        )
        if not ok or dirty.strip():
            return "unknown"
        return f"git:{head}"
    except Exception:
        return "unknown"


_STATE_BUILD_LOCKS: Dict[str, threading.Lock] = {}
_STATE_BUILD_LOCKS_GUARD = threading.Lock()


@contextlib.contextmanager
def _acquire_state_build_lock(state: Path):
    """Serializes concurrent structural_index builds targeting the same state_dir."""
    try:
        lock_key = os.path.realpath(str(state))
    except Exception:
        lock_key = str(state)
    with _STATE_BUILD_LOCKS_GUARD:
        thread_lock = _STATE_BUILD_LOCKS.get(lock_key)
        if thread_lock is None:
            thread_lock = threading.Lock()
            _STATE_BUILD_LOCKS[lock_key] = thread_lock

    with thread_lock:
        lock_file = None
        if _fcntl is not None:
            try:
                state.mkdir(parents=True, exist_ok=True)
                lock_file = open(state / ".build.lock", "a+", encoding="utf-8")
                _fcntl.flock(lock_file.fileno(), _fcntl.LOCK_EX)
            except Exception:
                if lock_file is not None:
                    try:
                        lock_file.close()
                    except Exception:
                        pass
                    lock_file = None
        try:
            yield
        finally:
            if lock_file is not None:
                try:
                    _fcntl.flock(lock_file.fileno(), _fcntl.LOCK_UN)
                except Exception:
                    pass
                try:
                    lock_file.close()
                except Exception:
                    pass


def build_structural_index(
    code_root: str,
    state_dir: str,
    snapshot_id: str = "unknown",
) -> Dict[str, Any]:
    """Builds (or reuses) the structural index for code_root under state_dir.

    Returns the manifest dict. Never raises.
    """
    t0 = time.time()
    state = Path(state_dir)
    snapshot_id = (snapshot_id or "unknown").strip() or "unknown"

    try:
        with _acquire_state_build_lock(state):
            return _build(code_root, state, snapshot_id, t0)
    except Exception as exc:  # fail safe: an index is a hint, never a blocker
        logger.warning("structural index build failed: %r", exc)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "snapshot_id": snapshot_id,
            "status": "failed",
            "reason": repr(exc)[:200],
            "coverage": {"total_files": 0, "indexed_files": 0, "failed_files": 0},
            "units": {"total": 0, "reused": 0, "rebuild": 0, "failed": 0},
            "build_duration_ms": int((time.time() - t0) * 1000),
        }
        try:
            _commit_manifest(state, manifest)
        except Exception:
            pass
        return manifest


def _build(code_root: str, state: Path, snapshot_id: str, t0: float) -> Dict[str, Any]:
    # Step 1: reuse-on-match. "unknown" is a constant, not a freshness signal,
    # so an unpinned tree always rebuilds (unit cache keeps that cheap). The
    # root must match too: a catalog rooted at a subdirectory has different
    # relative paths and misses every caller outside it. So must the
    # extractor, as in the unit cache key: the same commit indexed by an
    # older build is a different catalog.
    real_root = os.path.realpath(code_root)
    extractor = f"{SCHEMA_VERSION}|{EXTRACTOR_NAME}@{_ts_version()}"
    existing = _read_manifest(state)
    if (
        existing is not None
        and snapshot_id != "unknown"
        and existing.get("snapshot_id") == snapshot_id
        and existing.get("code_root") == real_root
        and existing.get("extractor") == extractor
        and existing.get("status") in ("complete", "partial")
    ):
        existing["reused"] = True
        return existing

    state.mkdir(parents=True, exist_ok=True)
    (state / "tmp").mkdir(exist_ok=True)

    vetted = sorted(get_vetted_staging_files(code_root), key=lambda t: t[1])
    sources = [(abs_p, rel) for abs_p, rel in vetted if _language_for(rel)]
    truncated = len(sources) > MAX_UNITS
    sources = sources[:MAX_UNITS]

    parsers: Dict[str, Any] = {}
    units: List[Dict[str, Any]] = []
    coverage_rows: List[Tuple[str, int, str, str]] = []  # path, indexed, cache_key, status
    fingerprint = hashlib.sha256()
    reused = rebuilt = failed = 0
    languages_used: Dict[str, bool] = {}
    max_total_bytes, max_total_symbols = _resolve_index_limits()
    total_bytes_read = 0
    total_symbols = 0
    budget_exhausted = False

    for abs_path, rel_path in sources:
        if budget_exhausted or total_bytes_read >= max_total_bytes or total_symbols >= max_total_symbols:
            truncated = True
            budget_exhausted = True
            coverage_rows.append((rel_path, 0, "", "skipped_budget"))
            continue
        language = _language_for(rel_path)
        # Size and type are checked on the inode BEFORE reading: read_bytes()
        # on a multi-gigabyte sparse file pulled the whole thing into memory
        # before the cap was consulted, and on a FIFO it never returned.
        try:
            st = os.stat(abs_path)
        except OSError:
            failed += 1
            coverage_rows.append((rel_path, 0, "", "failed"))
            continue
        if not stat.S_ISREG(st.st_mode):
            failed += 1
            coverage_rows.append((rel_path, 0, "", "failed"))
            continue
        if st.st_size > MAX_FILE_BYTES:
            coverage_rows.append((rel_path, 0, "", "skipped_too_large"))
            continue
        if total_bytes_read + st.st_size > max_total_bytes:
            truncated = True
            budget_exhausted = True
            coverage_rows.append((rel_path, 0, "", "skipped_budget"))
            continue
        try:
            raw = Path(abs_path).read_bytes()
        except Exception:
            failed += 1
            coverage_rows.append((rel_path, 0, "", "failed"))
            continue
        if len(raw) > MAX_FILE_BYTES:
            coverage_rows.append((rel_path, 0, "", "skipped_too_large"))
            continue
        if total_bytes_read + len(raw) > max_total_bytes:
            truncated = True
            budget_exhausted = True
            coverage_rows.append((rel_path, 0, "", "skipped_budget"))
            continue
        content_sha = hashlib.sha256(raw).hexdigest()
        fingerprint.update(f"{rel_path}:{content_sha}\n".encode())
        cache_key = _unit_cache_key(language, content_sha)

        cached = None
        cache_path = _unit_cache_path(state, cache_key)
        if cache_path.exists():
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
            except Exception:
                cached = None
        if cached is not None:
            # The cache key is content-addressed, but a renamed file would
            # replay the old relative path; trust the cache only in place.
            if cached.get("file") == rel_path:
                cached_syms = len(cached.get("symbols") or ())
                if total_symbols + cached_syms > max_total_symbols:
                    truncated = True
                    budget_exhausted = True
                    coverage_rows.append((rel_path, 0, cache_key, "skipped_budget"))
                    continue
                total_bytes_read += len(raw)
                total_symbols += cached_syms
                units.append(cached)
                coverage_rows.append((rel_path, 1, cache_key, "indexed"))
                languages_used[language] = True
                reused += 1
                continue

        if language not in parsers:
            parsers[language] = _load_parser(language)
        parser = parsers[language]
        if parser is None:
            coverage_rows.append((rel_path, 0, cache_key, "no_backend"))
            continue
        try:
            unit = extract_unit(rel_path, raw, language, parser)
        except Exception:
            failed += 1
            coverage_rows.append((rel_path, 0, cache_key, "failed"))
            continue
        unit_syms = len(unit.get("symbols") or ())
        if total_symbols + unit_syms > max_total_symbols:
            truncated = True
            budget_exhausted = True
            coverage_rows.append((rel_path, 0, cache_key, "skipped_budget"))
            continue
        total_bytes_read += len(raw)
        total_symbols += unit_syms
        units.append(unit)
        coverage_rows.append((rel_path, 1, cache_key, "indexed"))
        languages_used[language] = True
        rebuilt += 1
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_unit = (state / "tmp") / f"unit.{os.getpid()}.{uuid.uuid4().hex}.json.tmp"
            tmp_unit.write_text(json.dumps(unit), encoding="utf-8")
            os.replace(tmp_unit, cache_path)
        except Exception:
            pass  # cache misses are a cost, not a correctness problem

    indexed = sum(1 for _, ok, _, _ in coverage_rows if ok)
    if indexed == 0:
        status = "empty"
    elif truncated or indexed < len(coverage_rows):
        # Any enumerated source file that is not indexed -- parse failure,
        # missing grammar, oversized skip -- is a coverage gap. "complete"
        # must mean "every source file is in the catalog" or consumers
        # would read a gap as proof of absence.
        status = "partial"
    else:
        status = "complete"

    _write_catalog(state, units, coverage_rows, snapshot_id)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "code_root": real_root,
        "extractor": extractor,
        "root_fingerprint": fingerprint.hexdigest(),
        "status": status,
        "provider": {
            "kind": "local-build",
            "catalog": "catalog.sqlite",
            "backend_versions": {
                lang: {"backend_name": EXTRACTOR_NAME, "backend_version": _ts_version(), "precision": "ast"}
                for lang in sorted(languages_used)
            },
        },
        "units": {"total": len(units), "reused": reused, "rebuild": rebuilt, "failed": failed},
        "coverage": {
            "total_files": len(sources),
            "indexed_files": indexed,
            "failed_files": failed,
        },
        "truncated": truncated,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "build_duration_ms": int((time.time() - t0) * 1000),
    }
    _commit_manifest(state, manifest)
    return manifest


class _CandidateLookup:
    """Per-name lookup tables over same-named candidates, built on first use.

    Qualifier matching used to scan every candidate of a name for every
    edge; a vendored tree has names (`String`, `Error`) with thousands of
    definitions and hundreds of thousands of edges calling them, which made
    each build -- even one with every unit cached -- quadratic. Each table
    maps a key to the candidate positions that the scan would have matched
    on it, so a lookup returns exactly the scan's match set:

    - `qualified`: the candidate's qualified_name, for `==` matches.
    - `dotted`: every suffix of qualified_name after a '.', so that
      `qualified_name.endswith("." + s)` holds exactly when s is a key.
    - `stem`: Path(file_path).stem.
    """

    def __init__(self, syms_by_name: Dict[str, List[Dict[str, Any]]]):
        self._syms_by_name = syms_by_name
        self._tables: Dict[str, Tuple[Dict[str, List[int]], ...]] = {}

    def tables(self, name: str) -> Tuple[Dict[str, List[int]], ...]:
        cached = self._tables.get(name)
        if cached is not None:
            return cached
        qualified: Dict[str, List[int]] = {}
        dotted: Dict[str, List[int]] = {}
        stem: Dict[str, List[int]] = {}
        for i, c in enumerate(self._syms_by_name.get(name, [])):
            q = c.get("qualified_name")
            if isinstance(q, str):
                qualified.setdefault(q, []).append(i)
            qs = str(q or "")
            pos = qs.find(".")
            while pos != -1:
                dotted.setdefault(qs[pos + 1:], []).append(i)
                pos = qs.find(".", pos + 1)
            stem.setdefault(Path(str(c.get("file_path") or "")).stem, []).append(i)
        self._tables[name] = (qualified, dotted, stem)
        return self._tables[name]


def _resolve_callee_id(
    edge: Dict[str, Any],
    syms_by_name: Dict[str, List[Dict[str, Any]]],
    sym_by_id: Dict[str, Dict[str, Any]],
    lookup: Optional[_CandidateLookup] = None,
) -> Optional[str]:
    """Resolves a call edge to a unique catalog symbol_id, else None (unresolved).

    A bare call (`helper()`) is 'direct' only when the name is unique across
    the catalog. A qualified call (`UserModel.findAll()`, `auth.login()`,
    `self.refresh()`) uses the receiver both positively -- to disambiguate
    between same-named methods/functions when the receiver names the owning
    class or module -- and negatively, refusing to link a PascalCase class/model
    receiver (`UserModel.findAll`) or an ambient runtime object (`console.log`)
    to an unrelated class's method (`RecycleComponent.findAll`).

    `lookup` is the catalog-wide _CandidateLookup a build shares across
    edges; without one a single-use lookup is built.
    """
    callee_name = edge.get("callee_name") or ""
    candidates = syms_by_name.get(callee_name, [])
    if not candidates:
        return None
    qual = (edge.get("qualifier") or "").strip()
    if not qual:
        return candidates[0]["symbol_id"] if len(candidates) == 1 else None

    qualified, dotted, stem = (lookup or _CandidateLookup(syms_by_name)).tables(callee_name)
    if qual in ("self", "this", "super", "cls"):
        caller_sym = sym_by_id.get(edge.get("caller_id") or "")
        caller_q = (caller_sym or {}).get("qualified_name") or ""
        if "." in caller_q:
            caller_owner = caller_q.rsplit(".", 1)[0]
            same_owner = qualified.get(f"{caller_owner}.{callee_name}", [])
            if len(same_owner) == 1:
                return candidates[same_owner[0]]["symbol_id"]
        return candidates[0]["symbol_id"] if len(candidates) == 1 else None

    # Explicit receiver (`Session.refresh`, `auth.login`, `UserModel.findAll`).
    suffix = f"{qual}.{callee_name}"
    matched = set(qualified.get(suffix, ()))
    matched.update(dotted.get(suffix, ()))
    matched.update(stem.get(qual, ()))
    if len(matched) == 1:
        return candidates[next(iter(matched))]["symbol_id"]
    if len(matched) > 1:
        return None

    # No candidate matched the qualifier. Refuse known ambient/stdlib objects
    # (`console.log`, `json.loads`) and PascalCase class/model receivers calling
    # a method owned by a different class (`UserModel.findAll` vs
    # `RecycleComponent.findAll`); lowercase instance variables (`s.refresh()`)
    # still resolve when the method name itself is unique in the catalog.
    if qual in _AMBIENT_RECEIVERS or qual[0].isupper():
        return None
    if len(candidates) == 1:
        return candidates[0]["symbol_id"]
    return None


def _write_catalog(state: Path, units: List[Dict[str, Any]], coverage_rows, snapshot_id: str) -> None:
    """Writes catalog.sqlite via unique tmp + atomic replace."""
    tmp_dir = state / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = tmp_dir / f"catalog.{os.getpid()}.{uuid.uuid4().hex}.sqlite.tmp"

    conn = sqlite3.connect(str(tmp_path))
    try:
        conn.executescript(_CATALOG_DDL)
        conn.execute("INSERT OR REPLACE INTO schema_meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
        conn.execute("INSERT OR REPLACE INTO schema_meta VALUES ('snapshot_id', ?)", (snapshot_id,))

        syms_by_name: Dict[str, List[Dict[str, Any]]] = {}
        sym_by_id: Dict[str, Dict[str, Any]] = {}
        for unit in units:
            for sym in unit["symbols"]:
                syms_by_name.setdefault(sym["name"], []).append(sym)
                sym_by_id[sym["symbol_id"]] = sym
        lookup = _CandidateLookup(syms_by_name)

        for unit in units:
            for sym in unit["symbols"]:
                conn.execute(
                    "INSERT OR REPLACE INTO symbols (symbol_id, name, qualified_name, namespace, language,"
                    " file_path, start_line, end_line, kind, signature, backend, precision)"
                    " VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, 'ast')",
                    (sym["symbol_id"], sym["name"], sym["qualified_name"], sym["language"],
                     sym["file_path"], sym["start_line"], sym["end_line"], sym["kind"],
                     sym["signature"], EXTRACTOR_NAME),
                )
                if sym["kind"] in ("function", "method", "macro"):
                    conn.execute(
                        "INSERT OR REPLACE INTO function_boundaries VALUES (?, ?, ?, ?, ?, ?)",
                        (sym["symbol_id"], sym["file_path"], sym["start_line"],
                         sym["end_line"], sym["signature"], sym["language"]),
                    )
            for edge in unit["edges"]:
                callee_id = _resolve_callee_id(edge, syms_by_name, sym_by_id, lookup)
                conn.execute(
                    "INSERT INTO call_edges (caller_id, callee_id, callee_name, file_path, line, edge_kind)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (edge["caller_id"], callee_id, edge["callee_name"], edge["file_path"],
                     edge["line"], "direct" if callee_id else "unresolved"),
                )

        for file_path, indexed, cache_key, row_status in coverage_rows:
            conn.execute(
                "INSERT OR REPLACE INTO coverage VALUES (?, ?, ?, ?, ?, ?)",
                (file_path, indexed, EXTRACTOR_NAME if indexed else None,
                 "ast" if indexed else None, cache_key or None, row_status),
            )
        conn.commit()
    except Exception:
        conn.close()
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise
    else:
        conn.close()

    try:
        os.replace(tmp_path, state / "catalog.sqlite")
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise


def _commit_manifest(state: Path, manifest: Dict[str, Any]) -> None:
    """The manifest is the atomic commit point: written to unique tmp, renamed last."""
    state.mkdir(parents=True, exist_ok=True)
    tmp_dir = state / "tmp"
    tmp_dir.mkdir(exist_ok=True)
    tmp_manifest = tmp_dir / f"manifest.{os.getpid()}.{uuid.uuid4().hex}.json.tmp"
    tmp_manifest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    os.replace(tmp_manifest, state / "manifest.json")


# --- Query ----------------------------------------------------------------------


class StructuralIndex:
    """Bounded, read-only queries against a published catalog.

    Every result carries precision and backend; empty results carry the
    partition status so a consumer can tell "no callers" from "not indexed".
    """

    def __init__(self, state_dir: str):
        self.state = Path(state_dir)
        self.manifest = _read_manifest(self.state) or {}
        self._catalog = self.state / "catalog.sqlite"

    def available(self) -> bool:
        return (
            self._catalog.exists()
            and self.manifest.get("status") in ("complete", "partial")
        )

    def partition_status(self) -> str:
        return str(self.manifest.get("status") or "empty")

    def _connect(self):
        return sqlite3.connect(f"file:{self._catalog}?mode=ro", uri=True)

    def _rows(self, query: str, params: tuple) -> List[Dict[str, Any]]:
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(query, params).fetchall()]
        finally:
            conn.close()

    def resolve_symbol(self, name: str, limit: int = 20, offset: int = 0) -> Dict[str, Any]:
        if not self.available():
            return {"results": [], "total": 0, "ambiguous": False,
                    "coverage": {"partition_status": self.partition_status()}}
        conn = self._connect()
        try:
            total = conn.execute(
                "SELECT COUNT(*) FROM symbols WHERE name = ? OR qualified_name = ?",
                (name, name),
            ).fetchone()[0]
        finally:
            conn.close()
        rows = self._rows(
            "SELECT symbol_id, name, qualified_name, language, file_path, start_line,"
            " end_line, kind, signature, backend, precision FROM symbols"
            " WHERE name = ? OR qualified_name = ?"
            " ORDER BY file_path, start_line LIMIT ? OFFSET ?",
            (name, name, limit, offset),
        )
        return {
            "results": rows,
            "total": total,
            "ambiguous": total > 1,
            "coverage": {"partition_status": self.partition_status()},
        }

    def find_callers(self, symbol: Dict[str, Any], limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        """Callers of a resolved symbol row. Includes unresolved same-name
        edges, explicitly marked, because dropping them would silently narrow
        the audit set."""
        if not self.available():
            return {"results": [], "total": 0, "has_more": False,
                    "coverage": {"partition_status": self.partition_status()}}
        where = "(e.callee_id = ? OR (e.callee_id IS NULL AND e.callee_name = ?))"
        params = (symbol["symbol_id"], symbol["name"])
        conn = self._connect()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) FROM call_edges e WHERE {where}", params
            ).fetchone()[0]
        finally:
            conn.close()
        rows = self._rows(
            "SELECT e.file_path, e.line, e.edge_kind, e.callee_name,"
            " s.symbol_id AS caller_id, s.qualified_name AS caller, s.kind AS caller_kind"
            " FROM call_edges e LEFT JOIN symbols s ON s.symbol_id = e.caller_id"
            f" WHERE {where} ORDER BY e.file_path, e.line LIMIT ? OFFSET ?",
            params + (limit, offset),
        )
        return {
            "results": rows,
            "total": total,
            "has_more": offset + len(rows) < total,
            "coverage": {"partition_status": self.partition_status()},
        }

    def find_callees(self, symbol: Dict[str, Any], limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        if not self.available():
            return {"results": [], "total": 0, "has_more": False,
                    "coverage": {"partition_status": self.partition_status()}}
        conn = self._connect()
        try:
            total = conn.execute(
                "SELECT COUNT(*) FROM call_edges WHERE caller_id = ?",
                (symbol["symbol_id"],),
            ).fetchone()[0]
        finally:
            conn.close()
        rows = self._rows(
            "SELECT e.callee_name, e.file_path, e.line, e.edge_kind,"
            " s.symbol_id AS callee_id, s.qualified_name AS callee,"
            " s.file_path AS callee_file, s.start_line AS callee_start_line"
            " FROM call_edges e LEFT JOIN symbols s ON s.symbol_id = e.callee_id"
            " WHERE e.caller_id = ? ORDER BY e.line LIMIT ? OFFSET ?",
            (symbol["symbol_id"], limit, offset),
        )
        return {
            "results": rows,
            "total": total,
            "has_more": offset + len(rows) < total,
            "coverage": {"partition_status": self.partition_status()},
        }

    def get_function_boundary(self, file_path: str, line: int) -> Dict[str, Any]:
        """Innermost function/method enclosing file:line, or the coverage
        status when there is none."""
        if not self.available():
            return {"found": False, "coverage": {"partition_status": self.partition_status()}}
        rows = self._rows(
            "SELECT b.symbol_id, b.file_path, b.start_line, b.end_line, b.signature,"
            " b.language, s.qualified_name, s.kind"
            " FROM function_boundaries b JOIN symbols s ON s.symbol_id = b.symbol_id"
            " WHERE b.file_path = ? AND b.start_line <= ? AND b.end_line >= ?"
            " ORDER BY b.start_line DESC LIMIT 1",
            (file_path, line, line),
        )
        if not rows:
            return {"found": False, "coverage": {"partition_status": self.partition_status()}}
        return {"found": True, **rows[0],
                "coverage": {"partition_status": self.partition_status()}}

    def enclosing_symbol(self, file_path: str, line: int) -> Dict[str, Any]:
        """`get_function_boundary` with component-suffix path tolerance.

        The catalog stores paths relative to the indexed root, while a caller
        may hold the same file relative to a different base (a canonicalized
        finding path, a deeper jail). Exact paths win; otherwise the two
        directions of a component-aligned suffix match are tried -- the
        caller's own suffixes against the column exactly, and the column as a
        suffix of the caller's path via an escaped LIKE. A suffix that matches
        MORE THAN ONE distinct catalog file is refused rather than guessed:
        a wrong symbol stamped onto a lineage is worse than no symbol.
        """
        empty = {"found": False, "coverage": {"partition_status": self.partition_status()}}
        if not self.available():
            return empty
        path = str(file_path or "").strip().lstrip("/")
        if not path:
            return empty

        exact = self.get_function_boundary(path, line)
        if exact.get("found"):
            return exact

        # Caller path longer than the catalog's: try its component suffixes
        # exactly. Caller path shorter: the catalog path ends with "/<caller>",
        # matched with LIKE under ESCAPE so '_' and '%' in real paths stay
        # literal.
        suffixes = []
        probe = path
        while "/" in probe:
            probe = probe.split("/", 1)[1]
            if probe:
                suffixes.append(probe)
        escaped = path.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        placeholders = ",".join("?" for _ in suffixes) or "''"
        rows = self._rows(
            f"SELECT DISTINCT file_path FROM function_boundaries"
            f" WHERE file_path IN ({placeholders})"
            f" OR file_path LIKE ? ESCAPE '\\'",
            (*suffixes, f"%/{escaped}"),
        )
        if len(rows) != 1:
            return empty
        return self.get_function_boundary(rows[0]["file_path"], line)

    def file_coverage(self, file_path: str) -> Dict[str, Any]:
        if not self._catalog.exists():
            return {"status": "empty"}
        rows = self._rows("SELECT * FROM coverage WHERE file_path = ?", (file_path,))
        return rows[0] if rows else {"status": "not_enumerated"}


def state_dir_for_db(db_path: str) -> str:
    """The catalog lives next to the campaign database, keyed by its filename.

    Keying by the database name (knowledge.db -> knowledge.structural_index/)
    keeps two campaign databases that share a directory from silently serving
    each other's catalogs with status "complete" (each build clobbered the
    shared <dir>/structural_index). Cost: pre-existing unkeyed state dirs are
    orphaned and rebuilt once on first use.
    """
    db = Path(db_path).resolve()
    return str(db.parent / f"{db.stem}.{STATE_DIRNAME}")

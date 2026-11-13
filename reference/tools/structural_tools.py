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

"""Deterministic structural navigation tools backed by the tree-sitter catalog.

These are read-only lookups against the structural index built next to the
campaign database. They are navigation HINTS layered on top of read_file and
list_files, never a replacement: an empty answer means "not in the index",
not "absent from the code", and every response says which. When the index is
missing or stale the tools degrade to a pointer back at the baseline tools,
so a researcher without an index behaves exactly as before these existed.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.context import current_run_context
from core.llm_gateway import wrap_untrusted_content
from core.structural_index import (
    StructuralIndex,
    resolve_state_dir_for_target,
    state_dir_for_db,
)
from core.truncation import split_truncation

logger = logging.getLogger(__name__)

# A function body returned by get_function_boundary is bounded the same way
# read_file bounds whole files, just tighter: a boundary read that returns
# more than this is cheaper done through read_file anyway. Must stay >=
# 10_000: the reviewer and critic read function bodies through this tool to
# check a guard, and a cut that hides the guard reads as a missing guard.
MAX_SNIPPET_BYTES = 32_768

_PAGE_SIZE = 20

_UNAVAILABLE = (
    "Structural index unavailable. Fall back to read_file and list_files; "
    "this changes nothing about what you can read, only how you navigate."
)

_HINT = (
    "NOTE: structural results are navigation hints. Absence here is not "
    "absence in the code; confirm anything load-bearing with read_file."
)


def _degraded_note(status: str) -> str:
    return (
        f"NOTE: index status is '{status}', so some files were not indexed; "
        "treat misses as unknown, not as proof of absence."
    )


def _unavailable_message(ctx: Any) -> str:
    """Context-aware fallback guidance when the structural index is unavailable."""
    if ctx is not None:
        tf = str(getattr(ctx, "target_file", "") or "").strip()
        if tf and os.path.isfile(tf):
            root = str(getattr(ctx, "path_root", "") or getattr(ctx, "jail_dir", "") or "").strip()
            rel_target = os.path.basename(tf)
            if root and os.path.isdir(root):
                try:
                    cand = os.path.relpath(os.path.realpath(tf), os.path.realpath(root)).replace(os.sep, "/")
                    if not cand.startswith(".."):
                        rel_target = cand
                except ValueError:
                    pass
            return (
                f"Structural index unavailable; in single-file mode only '{rel_target}' "
                f"is readable directly — use read_file('{rel_target}') to inspect it."
            )
    return _UNAVAILABLE


def _active_target_root(ctx: Any) -> str:
    if ctx is None:
        return ""
    path_root = str(getattr(ctx, "path_root", "") or "").strip()
    if path_root and os.path.exists(path_root):
        return os.path.realpath(path_root)
    jail_dir = str(getattr(ctx, "jail_dir", "") or "").strip()
    if jail_dir and os.path.exists(jail_dir):
        real_j = os.path.realpath(jail_dir)
        return os.path.dirname(real_j) if os.path.isfile(real_j) else real_j
    tf = str(getattr(ctx, "target_file", "") or "").strip()
    if tf and os.path.exists(tf):
        real_tf = os.path.realpath(tf)
        return os.path.dirname(real_tf) if os.path.isfile(real_tf) else real_tf
    return ""


def _open_index(ctx: Optional[Any] = None) -> Tuple[Optional[StructuralIndex], Optional[str]]:
    """Target-verified catalog for `ctx` (or active run context), or `(None, reason)`."""
    if ctx is None:
        ctx = current_run_context.get()
    if ctx is None:
        return None, "Error: No active execution context."
    if not getattr(ctx, "db_path", None):
        return None, _unavailable_message(ctx)
    try:
        from core.paths import resolve_db_path

        resolved_db = resolve_db_path(ctx.db_path)
        active_root = _active_target_root(ctx)
        snap = str(getattr(ctx, "snapshot_id", "") or "")
        if active_root:
            state_dir = resolve_state_dir_for_target(resolved_db, active_root, snapshot_id=snap)
        else:
            state_dir = state_dir_for_db(resolved_db)
        if not state_dir:
            return None, _unavailable_message(ctx)
        idx = StructuralIndex(state_dir)
        if not idx.available():
            return None, _unavailable_message(ctx)
        return idx, None
    except Exception:
        logger.warning("structural index load failed", exc_info=True)
        return None, _unavailable_message(ctx)


def _load_index() -> Tuple[Optional[StructuralIndex], Optional[str]]:
    """The catalog for the active run, or (None, reason). Never raises."""
    return _open_index()


def _clean_path(filepath: str) -> str:
    return (filepath or "").replace("\\", "/").removeprefix("./")


def _suffix_match(a: str, b: str) -> bool:
    """Component-aligned equality or suffix of each other, either direction."""
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _footer(idx: StructuralIndex) -> str:
    notes: List[str] = []
    status = idx.partition_status()
    if status != "complete":
        notes.append(_degraded_note(status))
    unsupported = int(((idx.manifest or {}).get("coverage") or {}).get("unsupported_source_files") or 0)
    if unsupported > 0:
        notes.append(
            f"NOTE: {unsupported} source file(s) in unsupported languages were not AST-indexed."
        )
    notes.append(_HINT)
    return "\n".join(notes)


def _symbol_line(row: Dict[str, Any]) -> str:
    sig = row.get("signature") or row.get("name") or ""
    return (
        f"{row.get('file_path')}:{row.get('start_line')}-{row.get('end_line')}"
        f" [{row.get('kind')}] {sig}"
    )


def _resolve_unique(
    idx: StructuralIndex, symbol: str, filepath: str
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """One definition row for `symbol`, or (None, message).

    An exact filepath match wins; otherwise candidates whose catalog path
    and the given path are component-aligned suffixes of each other are
    kept, so 'services/orders.py' finds 'app/services/orders.py' when that
    is unambiguous. Ambiguity is refused with the candidate list rather
    than silently picking one: a caller graph for the wrong overload reads
    as evidence.
    """
    want = _clean_path(filepath)
    resolved = idx.resolve_symbol(symbol, limit=50 if want else _PAGE_SIZE, filepath=want)
    rows = resolved["results"]
    if want:
        exact = [r for r in rows if r.get("file_path") == want]
        rows = exact or [
            r for r in rows if _suffix_match(r.get("file_path") or "", want)
        ]
    if not rows:
        where = f" in '{want}'" if want else ""
        return None, (
            f"No definition of '{symbol}'{where} in the structural index.\n"
            + _footer(idx)
        )
    if len(rows) > 1:
        listing = "\n".join(_symbol_line(r) for r in rows[:_PAGE_SIZE])
        return None, (
            f"'{symbol}' is ambiguous ({len(rows)} definitions). Narrow it "
            "with the filepath argument:\n"
            + wrap_untrusted_content(listing, filename="structural_index")
            + "\n" + _footer(idx)
        )
    return rows[0], None


def find_symbol(name: str, offset: int = 0, filepath: str = "") -> str:
    """Looks up where a function, method, or class is defined, by name or qualified name."""
    if not isinstance(name, str) or not name.strip():
        return "Error: symbol name must be a non-empty string."
    if filepath is None:
        filepath = ""
    if not isinstance(filepath, str):
        return "Error: filepath must be a string."
    try:
        idx, err = _load_index()
        if idx is None:
            return err
        offset = max(0, int(offset or 0))
        want = _clean_path(filepath)
        res = idx.resolve_symbol(name, limit=_PAGE_SIZE, offset=offset, filepath=want)
        if not res["results"]:
            return f"No definition of '{name}' in the structural index.\n" + _footer(idx)
        listing = "\n".join(_symbol_line(r) for r in res["results"])
        shown = len(res["results"])
        head = f"{res['total']} definition(s) of '{name}'"
        if res["total"] > shown:
            head += f" (showing {offset + 1}-{offset + shown}; pass offset={offset + shown} for more)"
        return (
            head + ":\n"
            + wrap_untrusted_content(listing, filename="structural_index")
            + "\n" + _footer(idx)
        )
    except Exception as e:
        logger.warning("find_symbol failed: %s", e, exc_info=True)
        return _UNAVAILABLE


def find_callers(symbol: str, filepath: str = "", offset: int = 0) -> str:
    """Lists call sites that invoke the given function or method."""
    if not isinstance(symbol, str) or not symbol.strip():
        return "Error: symbol must be a non-empty string."
    if filepath is None:
        filepath = ""
    if not isinstance(filepath, str):
        return "Error: filepath must be a string."
    try:
        idx, err = _load_index()
        if idx is None:
            return err
        row, msg = _resolve_unique(idx, symbol, filepath)
        if row is None:
            return msg
        offset = max(0, int(offset or 0))
        res = idx.find_callers(row, limit=_PAGE_SIZE, offset=offset)
        if not res["results"]:
            return (
                f"No recorded callers of '{symbol}' "
                f"({row['file_path']}:{row['start_line']}).\n"
                "Note: 0 direct call sites in the index. If this is an internal "
                "helper (not a route handler, exported API, or callback "
                "registered by reference), verify how untrusted input reaches "
                "it before reporting a finding against it.\n" + _footer(idx)
            )
        lines = []
        for e in res["results"]:
            caller = e.get("caller") or "<module>"
            mark = "" if e.get("edge_kind") == "direct" else " (name-only match)"
            lines.append(f"{e['file_path']}:{e['line']} in {caller}{mark}")
        head = f"{res['total']} call site(s) of '{symbol}'"
        if res.get("has_more"):
            shown = len(res["results"])
            head += f" (showing {offset + 1}-{offset + shown}; pass offset={offset + shown} for more)"
        return (
            head + ":\n"
            + wrap_untrusted_content("\n".join(lines), filename="structural_index")
            + "\n" + _footer(idx)
        )
    except Exception as e:
        logger.warning("find_callers failed: %s", e, exc_info=True)
        return _UNAVAILABLE


def find_callees(symbol: str, filepath: str = "", offset: int = 0) -> str:
    """Lists the functions a given function or method calls."""
    if not isinstance(symbol, str) or not symbol.strip():
        return "Error: symbol must be a non-empty string."
    if filepath is None:
        filepath = ""
    if not isinstance(filepath, str):
        return "Error: filepath must be a string."
    try:
        idx, err = _load_index()
        if idx is None:
            return err
        row, msg = _resolve_unique(idx, symbol, filepath)
        if row is None:
            return msg
        offset = max(0, int(offset or 0))
        res = idx.find_callees(row, limit=_PAGE_SIZE, offset=offset)
        if not res["results"]:
            return (
                f"No recorded callees in '{symbol}' "
                f"({row['file_path']}:{row['start_line']}).\n" + _footer(idx)
            )
        lines = []
        for e in res["results"]:
            if e.get("callee_id"):
                target = f" -> {e.get('callee_file')}:{e.get('callee_start_line')}"
            else:
                target = " (external or not indexed)"
            lines.append(f"line {e['line']}: {e['callee_name']}{target}")
        head = f"{res['total']} call(s) from '{symbol}'"
        if res.get("has_more"):
            shown = len(res["results"])
            head += f" (showing {offset + 1}-{offset + shown}; pass offset={offset + shown} for more)"
        return (
            head + ":\n"
            + wrap_untrusted_content("\n".join(lines), filename="structural_index")
            + "\n" + _footer(idx)
        )
    except Exception as e:
        logger.warning("find_callees failed: %s", e, exc_info=True)
        return _UNAVAILABLE


async def get_function_boundary(filepath: str, line: int) -> str:
    """Returns the innermost function enclosing file:line, with its source."""
    if not isinstance(filepath, str) or not filepath.strip():
        return "Error: filepath must be a non-empty string."
    try:
        idx, err = _load_index()
        if idx is None:
            return err
        ctx = current_run_context.get()
        clean = _clean_path(filepath)
        try:
            lineno = int(line)
        except (TypeError, ValueError):
            return f"Error: '{line}' is not a line number."

        res = idx.enclosing_symbol(clean, lineno)
        if not res.get("found"):
            return (
                f"No indexed function encloses {clean}:{lineno}. Use read_file "
                "to inspect that region directly.\n" + _footer(idx)
            )

        # Same single-file jail rule as read_file: a single-file scan may
        # only pull source from the scanned file. The check runs on the
        # catalog path that is actually read below, so a suffix spelling
        # of some other file cannot dodge the jail.
        resolved = res["file_path"]
        # The catalog is rooted at path_root when the operator declared one
        # (see create_structural_index_node), while this jail may be a
        # slice of that repository. Rebase the catalog path to the jail so
        # the gate and the sandbox read below judge the file it actually
        # names. A catalog row outside the jail is structural context, not
        # readable source: refuse it outright rather than hand the sandbox
        # a spelling that a same-named file inside the jail could alias.
        _root = str(getattr(ctx, "path_root", "") or "")
        if _root and resolved and ctx.jail_dir:
            try:
                _jail_real = os.path.realpath(ctx.jail_dir)
                _cand = os.path.realpath(os.path.join(_root, resolved))
                if (os.path.isfile(_cand)
                        and not os.path.exists(os.path.join(ctx.jail_dir, resolved))):
                    if not _cand.startswith(_jail_real + os.sep):
                        return (
                            "Error: Permission denied. "
                            f"'{resolved}' lies outside the scan target; it "
                            "is indexed for structural context only."
                        )
                    resolved = os.path.relpath(_cand, _jail_real).replace(os.sep, "/")
            except OSError:
                pass
        if ctx.target_file and os.path.isfile(ctx.target_file) and ctx.jail_dir and resolved:
            req_target = os.path.realpath(os.path.join(ctx.jail_dir, resolved))
            real_target = os.path.realpath(ctx.target_file)
            if os.path.exists(req_target) and req_target != real_target:
                return (
                    "Error: Permission denied. Single-file scans may only read "
                    f"the scanned file '{os.path.basename(real_target)}'."
                )

        header = (
            f"{res.get('qualified_name') or ''} [{res.get('kind')}] "
            f"{res['file_path']}:{res['start_line']}-{res['end_line']}"
        )

        # Read the body through the same sandbox path as read_file; a
        # boundary row is never an excuse to touch the host filesystem.
        sandbox = ctx.sandbox
        if sandbox is None or not hasattr(sandbox, "read_file"):
            target = ctx.jail_dir or ctx.target_file or ""
            from core.environments.static_env import StaticOnlyEnvironment
            sandbox = StaticOnlyEnvironment(target_path=target)
        try:
            content_bytes = await sandbox.read_file(Path(resolved))
        except Exception as e:
            if ctx.sandbox is not None:
                return f"Error: sandbox read failed for '{res['file_path']}': {type(e).__name__}: {e}"
            return f"Error reading file '{res['file_path']}': {e}"
        text = content_bytes.decode("utf-8", errors="replace")
        if text:
            raw_lines = text.split("\n")
            if text.endswith("\n"):
                raw_lines.pop()
            all_lines = [ln[:-1] if ln.endswith("\r") else ln for ln in raw_lines]
        else:
            all_lines = []
        start_ln = int(res["start_line"])
        selected = all_lines[start_ln - 1 : int(res["end_line"])]
        snippet = "\n".join(
            f"{ln_no}: {ln}" for ln_no, ln in enumerate(selected, start=start_ln)
        )
        snippet, cut_note = split_truncation(
            snippet, MAX_SNIPPET_BYTES,
            what=f"function body {res['file_path']}:{res['start_line']}-{res['end_line']}",
        )
        return (
            header + "\n"
            + wrap_untrusted_content(snippet, filename=res["file_path"])
            + cut_note
            + "\n" + _footer(idx)
        )
    except Exception as e:
        logger.warning("get_function_boundary failed: %s", e, exc_info=True)
        return _UNAVAILABLE

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

"""Tools a deployment declares for itself, and the limits they run under.

WHY THIS EXISTS
---------------
The 24 built-in tools are a closed set, and a workflow naming anything else fails
validation outright. So a site with an internal taint engine, a house SAST tool or a
proprietary fuzzer has exactly one option: fork. A fork never receives the next
security fix -- the same argument that stops `LocalCheckout` from reimplementing CP-1's
directory walk. Leaving the set closed does not prevent custom tools; it just makes the
unsafe way the only way.

WHAT MAKES THE BUILT-IN 24 SAFE, SO THIS CAN BE HONEST ABOUT NOT INHERITING IT
------------------------------------------------------------------------------
Not confinement. Most of them run on the host with the host's full privilege --
`read_file` could open `~/.ssh/id_rsa`; nothing in the process prevents it. They are
safe because they ARE the enforcement: `read_file` is the containment for reads,
`run_sandbox` is the containment for execution, `_run_safe_git_command` is the git jail.
A chokepoint is only a chokepoint while no path goes around it, and an unreviewed
function added to that dict IS a path around it.

A declared tool therefore inherits none of that trust, and the two lanes below are the
two ways to grant capability without granting it.

THE THREAT THAT HAS NO ANALOGUE IN EVIDENCE SOURCES
---------------------------------------------------
An evidence source is called once, by us, before analysis, with arguments we chose. A
tool is called repeatedly, BY THE MODEL, with arguments the model composed after reading
the target's source code. `acme_taint(query=<something the repository suggested>)` is
the shape of every injection-to-execution chain. So argument handling, not just
registration, is where the safety has to live.

THE TWO LANES
-------------
  LANE A (declarative) -- the integrator ships a SPECIFICATION, never code. We execute
      it with an audited primitive: a parameterised query against the knowledge base, a
      read through CP-3. No third-party code runs in this process, so no new path
      around CP-1/2/3/4 is created. This covers the most common real request ("let me
      ask my own findings database something") at close to zero risk.

  LANE B (executable) -- the integrator's own binary. It never becomes a Python entry
      point in our process. It is a command dispatched through `ctx.sandbox.execute()`,
      the same path `run_sandbox` already uses, and it may only run when the effective
      sandbox meets a declared floor (gvisor or stronger). `static-only` is not a weak
      sandbox, it is the NO-OP environment: running a third-party binary under it means
      running it on the host, in the process holding the LLM credentials. It is also the
      default, which is why the floor fails closed rather than warning.

WHAT A DECLARED TOOL CAN NEVER DO
---------------------------------
  * Set a verdict field. `may_set_verdict` remains the single audit point (INV-1/INV-2).
  * Widen the sandbox, the operator ceiling, or any trust tier. A floor is a condition
    for running, never a request for more capability.
  * Shadow a built-in. Rebinding `read_file` would redirect the audited chokepoint to
    unreviewed code, so a name collision is refused rather than resolved.
  * Reach the network. Lane A never executes; Lane B inherits the guest's networkless
    configuration.
"""

from __future__ import annotations

import logging
import re
import os
import posixpath
import shlex
from typing import Any, Callable, Dict, List, Optional, Tuple


def _connect(db_path: str, readonly: bool = False) -> sqlite3.Connection:
    """Knowledge-database connection with the shared busy timeout and journal
    settings (core.database.connect); imported lazily to keep module import
    order free of cycles."""
    from core.database import connect

    return connect(db_path, readonly=readonly)

logger = logging.getLogger(__name__)

LANE_DECLARATIVE = "declarative"
LANE_EXECUTABLE = "executable"
LANES = (LANE_DECLARATIVE, LANE_EXECUTABLE)

# Lane B may not run below this. Chosen because gVisor interposes on syscalls rather
# than relying on the host kernel's own isolation; `microsandbox` (hardware microVM) and
# `gce` (remote hardened VM) rank above it and therefore also qualify. `seatbelt` sits
# below it deliberately and is refused.
DEFAULT_SANDBOX_FLOOR = "gvisor"

# A declared name must look like an identifier. Tool names reach the model as callable
# function names, and a name carrying spaces, quotes or newlines is an injection vector
# into the tool-call surface itself rather than a naming-style question.
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,47}$")

# Lane A primitives. Each entry is an audited implementation; the configuration selects
# one and parameterises it, and cannot introduce a new one.
DECLARATIVE_KINDS = ("sql_query",)

# Tables a declarative query may read. An allow-list rather than a deny-list: the cost
# of forgetting to deny a table is silent exposure, while the cost of forgetting to
# allow one is an error message asking for it to be added.
_QUERYABLE_TABLES = ("findings", "risk_scores", "lineage_vectors", "learnings", "okf_concepts")

_FORBIDDEN_SQL = (
    "insert", "update", "delete", "drop", "alter", "create", "attach", "detach",
    "pragma", "vacuum", "replace", "trigger", "--", "/*", ";",
)


class CustomToolConfigError(ValueError):
    """A declared tool cannot be built as specified.

    Raised, never skipped. A tool that silently fails to load leaves the model without a
    capability the operator believes it has, and the report cannot distinguish "analysed
    and found nothing" from "never ran the analyser".
    """


def _validate_name(name: Any, builtin_names: Tuple[str, ...]) -> str:
    text = str(name or "").strip()
    if not _NAME_RE.match(text):
        raise CustomToolConfigError(
            f"Invalid tool name {name!r}. Expected 3-48 characters, lowercase letter "
            f"first, then letters, digits or underscore."
        )
    if text in builtin_names:
        raise CustomToolConfigError(
            f"Tool name {text!r} is already a built-in. Rebinding it would point an "
            f"audited chokepoint at unreviewed code; choose another name."
        )
    return text


def _validate_sql(query: str) -> str:
    """Accepts a single read-only SELECT against an allow-listed table.

    Deliberately crude. This is not a SQL parser and must not pretend to be one: it
    refuses anything it does not positively recognise, so the failure mode of an
    unusual-but-legitimate query is an error the operator can read, not a silent
    widening. Parameters are bound by the caller and never interpolated here.
    """
    text = str(query or "").strip()
    if not text:
        raise CustomToolConfigError("Declarative tool has an empty query.")

    lowered = text.lower()
    if not lowered.startswith("select "):
        raise CustomToolConfigError(
            f"Declarative queries must begin with SELECT; got {text[:40]!r}."
        )
    for bad in _FORBIDDEN_SQL:
        if bad in lowered:
            raise CustomToolConfigError(
                f"Declarative query contains {bad!r}, which is not permitted. These "
                f"tools are strictly read-only and single-statement."
            )
    # Check the tables the query actually READS FROM, not merely the ones it mentions.
    # Measured before this was written: a `\b<table>\b` search anywhere in the text
    # accepted `SELECT * FROM sqlite_master WHERE name = 'findings'`, which returns the
    # full schema of every table -- the allow-list was satisfied by a string in a WHERE
    # clause. Every FROM/JOIN target must be allow-listed, and a query whose targets
    # cannot be extracted is refused rather than assumed benign.
    targets = set(re.findall(r"\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_]*)", lowered))
    if not targets:
        raise CustomToolConfigError(
            "Declarative query reads no identifiable table. These tools accept a plain "
            "SELECT ... FROM <table>; anything this check cannot read is refused rather "
            "than assumed safe."
        )
    disallowed = sorted(targets - set(_QUERYABLE_TABLES))
    if disallowed:
        raise CustomToolConfigError(
            f"Declarative query reads {disallowed}, which is not permitted. Readable "
            f"tables are {list(_QUERYABLE_TABLES)}."
        )
    return text


def _build_declarative(name: str, cfg: Dict[str, Any]) -> Callable[..., str]:
    kind = str(cfg.get("kind", "") or "").strip()
    if kind not in DECLARATIVE_KINDS:
        raise CustomToolConfigError(
            f"Unknown declarative kind {kind!r} for tool {name!r}. Available: "
            f"{list(DECLARATIVE_KINDS)}."
        )

    query = _validate_sql(cfg.get("query", ""))
    params = cfg.get("params") or []
    if not isinstance(params, list):
        raise CustomToolConfigError(f"Tool {name!r}: 'params' must be a list.")
    try:
        limit = int(cfg.get("max_rows", 100))
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(limit, 1000))
    description = str(cfg.get("description", "") or f"Declarative query tool {name}.")

    def _run() -> str:
        # No arguments. A declarative tool is a fixed question with fixed parameters:
        # letting the model supply them would hand an attacker-influenced string to the
        # database, which is the injection path this lane exists to avoid.
        import sqlite3

        from core.context import current_run_context

        ctx = current_run_context.get()
        if ctx is None:
            return "Error: No active execution context."
        try:
            # Same anchor as every core.database access (INV-4): relative paths
            # resolve against the install, symlinks are refused. Opened
            # read-only so a missing database can never be created -- least
            # of all at a path the scanned repository chose.
            from core.paths import resolve_db_path

            db = resolve_db_path(ctx.db_path)
            if not os.path.exists(db):
                return "ERROR: query failed: knowledge database not found"
            conn = _connect(db, readonly=True)
            try:
                cur = conn.execute(query, tuple(params))
                rows = cur.fetchmany(limit)
                cols = [d[0] for d in (cur.description or [])]
            finally:
                conn.close()
        except Exception as exc:
            return f"ERROR: query failed: {exc}"

        if not rows:
            return "No rows."
        lines = [" | ".join(cols)]
        for row in rows:
            lines.append(" | ".join("" if v is None else str(v) for v in row))
        # Fenced through CP-4 like every other untrusted string. These rows are not
        # inert data: `findings.title` and friends were written by earlier LLM runs from
        # repository content, so this is model-authored prose arriving at a model as
        # tool output -- exactly what the delimiters exist to mark as data.
        from core.llm_gateway import wrap_untrusted_content

        return wrap_untrusted_content("\n".join(lines), filename=f"{name}_rows")

    _run.__name__ = name
    _run.__doc__ = description
    return _run


def _build_executable(name: str, cfg: Dict[str, Any]) -> Callable[..., Any]:
    command = str(cfg.get("command", "") or "").strip()
    if not command:
        raise CustomToolConfigError(f"Executable tool {name!r} declares no command.")

    floor = str(cfg.get("minimum_sandbox", DEFAULT_SANDBOX_FLOOR) or DEFAULT_SANDBOX_FLOOR)
    description = str(cfg.get("description", "") or f"Executable analysis tool {name}.")

    # Placeholders the caller may substitute. Fixed set: an open-ended template would let
    # the configuration reference arbitrary run state.
    allowed_placeholders = {"filepath"}
    used = set(re.findall(r"\{(\w+)\}", command))
    unknown = used - allowed_placeholders
    if unknown:
        raise CustomToolConfigError(
            f"Executable tool {name!r} uses unknown placeholder(s) {sorted(unknown)}. "
            f"Available: {sorted(allowed_placeholders)}."
        )

    async def _run(filepath: str = "") -> str:
        from core.context import current_run_context
        from core.synthesizer import meets_sandbox_floor

        ctx = current_run_context.get()
        if ctx is None:
            return "Error: No active execution context."
        sandbox = getattr(ctx, "sandbox", None)
        if sandbox is None:
            return f"ERROR: {name} requires a sandbox; none is active."

        # Re-checked at CALL time, not only at load time. The load-time check is what
        # refuses the run; this one exists because the effective backend is a property
        # of the live context, and a tool that verified its floor only once would be
        # trusting a value it read somewhere else, earlier.
        backend = getattr(sandbox, "backend_name", "") or type(sandbox).__name__
        backend = _normalize_backend(backend)
        ok, reason = meets_sandbox_floor(backend, floor)
        if not ok:
            return f"ERROR: {name} is not permitted to run: {reason}."

        # The model chose this path after reading the target's source, so it is treated
        # as hostile input and quoted as a single argument. Without this, a filename
        # containing shell metacharacters is command injection into the guest.
        fp = str(filepath or "").strip()
        # Quoting stops shell metacharacters; it does not stop a value that
        # IS an option. `--output=/workspace/x` or `-c<cfg>` arrives at the
        # operator's binary as a flag. Only a plain relative path inside the
        # guest's target mount is a file to analyze.
        norm = posixpath.normpath(fp.replace("\\", "/")) if fp else ""
        if (not fp or fp.startswith("-") or norm.startswith(("/", "../")) or norm == ".."
                or "\x00" in fp):
            return (f"ERROR: {name}: filepath must be a relative path inside the target "
                    f"(got {fp[:80]!r}).")
        # Validated, not rewritten: the value reaches the guest exactly as
        # given, as one argument. Normalization is only for the checks above.
        rendered = command.replace("{filepath}", shlex.quote(fp))
        try:
            result = await sandbox.execute(rendered)
        except Exception as exc:
            return f"ERROR: {name} failed: {exc}"
        # Scrubbed and fenced exactly as `run_sandbox` treats guest output. A
        # third-party binary's stdout is the least trustworthy string in the system: it
        # is unreviewed code reporting on hostile input. Returning it unmarked would
        # make this the one execution path whose output skipped both controls.
        from core.llm_gateway import SecretScrubber, wrap_untrusted_content

        raw = str(
            getattr(result, "stdout", "") or getattr(result, "output", "") or result
        )
        return wrap_untrusted_content(
            SecretScrubber.scrub(raw), filename=f"{name}_output"
        )

    _run.__name__ = name
    _run.__doc__ = description
    return _run


_ENV_CLASS_TO_BACKEND = {
    "StaticOnlyEnvironment": "static-only",
    "StaticOnlySandbox": "static-only",
    "SeatbeltEnvironment": "seatbelt",
    "GvisorEnvironment": "gvisor",
    "MicrosandboxEnvironment": "microsandbox",
    "GceEnvironment": "gce",
    "RemoteTargetEnvironment": "remote",
    "RemoteSandbox": "remote",
}


def _normalize_backend(value: str) -> str:
    """Maps an environment class name onto a capability-order name.

    Returns the input unchanged when unrecognised, so `meets_sandbox_floor` sees an
    unknown name and refuses it. Mapping an unknown class to a default would decide the
    containment question by accident.
    """
    return _ENV_CLASS_TO_BACKEND.get(str(value), str(value))


def build_custom_tools(
    config: Any,
    builtin_names: Tuple[str, ...] = (),
    effective_sandbox: str = "",
) -> Dict[str, Callable[..., Any]]:
    """Builds every declared tool. Raises `CustomToolConfigError` on any problem.

    `effective_sandbox` is the backend this run will actually use. Lane B tools are
    checked against it HERE, at load time, so a run that cannot honour a declared tool
    fails before any campaign starts rather than at the moment the model first reaches
    for it -- by which point the operator is reading a report that silently reflects
    less analysis than they configured.
    """
    entries = (config or {}).get("tools") or {}
    if not entries:
        return {}
    if not isinstance(entries, dict):
        raise CustomToolConfigError("'tools' must be an object mapping name -> config.")

    out: Dict[str, Callable[..., Any]] = {}
    for raw_name, cfg in entries.items():
        if not isinstance(cfg, dict):
            raise CustomToolConfigError(f"Tool {raw_name!r} must be an object.")
        name = _validate_name(raw_name, tuple(builtin_names))

        lane = str(cfg.get("lane", "") or "").strip()
        if lane not in LANES:
            raise CustomToolConfigError(
                f"Tool {name!r} must declare lane as one of {list(LANES)}; got {lane!r}."
            )

        if lane == LANE_DECLARATIVE:
            out[name] = _build_declarative(name, cfg)
            continue

        floor = str(cfg.get("minimum_sandbox", DEFAULT_SANDBOX_FLOOR) or DEFAULT_SANDBOX_FLOOR)
        if effective_sandbox:
            from core.synthesizer import meets_sandbox_floor

            ok, reason = meets_sandbox_floor(_normalize_backend(effective_sandbox), floor)
            if not ok:
                raise CustomToolConfigError(
                    f"Executable tool {name!r} cannot run: {reason}. Raise the sandbox "
                    f"to {floor} or stronger, or remove the tool. Executable tools are "
                    f"refused rather than skipped so the report cannot understate what "
                    f"was analysed."
                )
        out[name] = _build_executable(name, cfg)
    return out

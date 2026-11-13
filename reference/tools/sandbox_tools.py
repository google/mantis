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

from __future__ import annotations

import json
import os
import posixpath
import re
import secrets
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.context import current_run_context
from core.llm_gateway import SecretScrubber, wrap_untrusted_content
from core.poc_scaffold import _host_has
from core.truncation import is_truncation_marker_present
from google.adk.environment import ExecutionResult

MANTIS_SENTINEL_TOKEN = "MANTIS_REACHED_ENTRYPOINT"
DEFAULT_UNATTRIBUTED_SENTINEL_PATH = ".mantis_reached_sentinel"

# Reason prefix for "the output was cut before the sentinel could be
# confirmed". Deliberately distinct from EVIDENCE_ABSENT: absent means the
# whole trace was seen and carried no proof; truncated means the trace was
# not whole, so its silence proves nothing either way. Both are not-verified.
EVIDENCE_TRUNCATED_PREFIX = "EVIDENCE_TRUNCATED"

_UNSCOPED_REMOTE_TELEMETRY_RE = re.compile(
    r"\n?\[REMOTE TARGET TELEMETRY\]\n.*?(?:\n\[/REMOTE TARGET TELEMETRY\]|(?=\n<<<UNTRUSTED_SOURCE_CODE_DATA_END>>>)|\Z)",
    re.S,
)

_SANITIZER_SIGNALS = [
    re.compile(r"==\d+==ERROR:\s+(?:AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer|LeakSanitizer)", re.IGNORECASE),
    re.compile(r"SUMMARY:\s+(?:AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer):", re.IGNORECASE),
    re.compile(r"runtime error:\s+", re.IGNORECASE),
    re.compile(r"(?:Segmentation fault|SIGSEGV|SIGABRT|core dumped)", re.IGNORECASE),
    re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+([a-zA-Z0-9_:]+)", re.IGNORECASE),
]

# A sanitizer's own report header: the one crash signal that cannot be
# produced by printing text, short of the program being instrumented.
_SANITIZER_HEADER = _SANITIZER_SIGNALS[0]

# Where a sink symbol must appear to count: inside a backtrace frame. Plain
# substring matching accepted `echo 'SIGSEGV parse_header'` and a `cat` of the
# vulnerable source next to any crash-like line.
_FRAME_SYMBOL_RES = [
    re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+([A-Za-z_][\w:.$<>]*)"),        # ASan / gdb / lldb
    re.compile(r"^\s*File\s+\"[^\"]+\",\s+line\s+\d+,\s+in\s+([A-Za-z_]\w*)", re.M),  # Python
    re.compile(r"^\s*at\s+([A-Za-z_][\w.$]*)\s*\(", re.M),                       # JVM / Node
]

_GO_PANIC_HEADER_RE = re.compile(r"^panic:\s+", re.M)
_GO_GOROUTINE_RE = re.compile(r"^goroutine\s+\d+\s+\[", re.M)
_GO_FRAME_RE = re.compile(
    r"^(?:[A-Za-z0-9_./()-]+/)?([A-Za-z_][\w()*]*\.[A-Za-z_]\w*)\([^\n]*\)\r?\n\t[^\n]+\.go:\d+",
    re.M,
)

_RUST_PANIC_HEADER_RE = re.compile(r"^thread\s+'[^']+'\s+panicked\s+at\s+\S+:\d+:\d+:", re.M)
_RUST_BACKTRACE_HDR_RE = re.compile(r"^stack backtrace:\s*$", re.M)
_RUST_FRAME_RE = re.compile(
    r"^\s*\d+:\s+(?:0x[0-9a-fA-F]+\s+-\s+)?([A-Za-z_][\w:$<>]*?)(?:::h[0-9a-fA-F]{16})?\s*$",
    re.M,
)

_SHELL_LAUNCHER_FAIL_RE = re.compile(
    r"(?:^|\n)(?:(?:/usr)?/bin/)?(?:ba|da|z|k)?sh:\s*(?:line\s+\d+:\s*)?(?:\d+:\s*)?"
    r"(?:[^:\n]+:\s*){1,4}"
    r"(?:command not found|not found|No such file or directory|Permission denied|can't cd to\b)",
    re.I,
)
_ENV_LAUNCHER_FAIL_RE = re.compile(
    r"(?:^|\n)env:\s*['\"]?[^'\":\n]+['\"]?:\s*No such file or directory\b",
    re.I,
)
_CLI_MISSING_SCRIPT_RE = re.compile(
    r"(?:can't open file\s+['\"]?[^'\"]+['\"]?:\s*\[Errno 2\]\s*No such file or directory|"
    r"Error:\s*Cannot find module\s+['\"][^'\"]+['\"]|"
    r"(?:^|\n)(?:go:\s*)?(?:stat|open|lstat)\s+[^\n:]+:\s*no such file or directory)",
    re.I,
)
_PY_IMPORT_SYNTAX_EXC_RE = re.compile(
    r"(?:^|\n)\s*(?:ModuleNotFoundError|ImportError|SyntaxError)\s*(?::|$)"
)
_PY_TRACEBACK_FILE_RE = re.compile(r'^\s*File\s+"([^"]+)",\s+line\s+\d+', re.M)
_SHELL_SEP_RE = re.compile(r"(?:&&|\|\||[;|])")


def _strip_unscoped_remote_telemetry(output: str) -> str:
    if not output or "[REMOTE TARGET TELEMETRY]" not in output:
        return output or ""
    return _UNSCOPED_REMOTE_TELEMETRY_RE.sub("", output)


def _has_go_panic_trace(output: str) -> bool:
    return bool(
        output
        and _GO_PANIC_HEADER_RE.search(output)
        and _GO_GOROUTINE_RE.search(output)
        and _GO_FRAME_RE.search(output)
    )


def _has_rust_panic_trace(output: str, exit_code: int) -> bool:
    try:
        code = int(exit_code)
    except (TypeError, ValueError):
        return False
    return bool(
        code == 101
        and output
        and _RUST_PANIC_HEADER_RE.search(output)
        and _RUST_BACKTRACE_HDR_RE.search(output)
        and _RUST_FRAME_RE.search(output)
    )


def _invoked_script_relpaths(command: str, workdir: str, jail_root: str) -> set[str]:
    out: set[str] = set()
    if not command:
        return out
    wd = (workdir or "/workspace").replace("\\", "/").rstrip("/") or "/workspace"
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    for raw_tok in tokens:
        for tok in _SHELL_SEP_RE.split(raw_tok):
            t = tok.strip().strip("'\"")
            if not t or t.startswith("-") or ("=" in t and not t.startswith(("/", "."))):
                continue
            t = t.replace("\\", "/")
            if t.startswith(wd + "/"):
                rel = posixpath.normpath(t[len(wd) + 1:])
            elif jail_root and t.startswith(jail_root + "/"):
                rel = posixpath.normpath(t[len(jail_root) + 1:])
            elif not t.startswith("/"):
                rel = posixpath.normpath(t.removeprefix("./"))
            else:
                continue
            if rel and rel not in (".", "..") and not rel.startswith("../"):
                out.add(rel)
    return out


def _has_target_traceback_frame(
    text: str,
    *,
    command: str = "",
    jail_dir: str = "",
    workdir: str = "",
) -> bool:
    """True only when a Python traceback names a real staged file in the target
    repository (verified via ``_host_has``) that is not the invoked PoC script."""
    ctx = current_run_context.get()
    eff_jail = jail_dir or (str(getattr(ctx, "jail_dir", "") or "") if ctx is not None else "")
    if not eff_jail:
        return False
    try:
        jail_root = os.path.realpath(eff_jail)
        if os.path.isfile(jail_root):
            jail_root = os.path.dirname(jail_root)
        if not os.path.isdir(jail_root):
            return False
    except OSError:
        return False

    eff_workdir = workdir or (
        str(getattr(getattr(ctx, "sandbox", None), "working_dir", "") or "/workspace")
        if ctx is not None
        else "/workspace"
    )
    wd = (eff_workdir or "/workspace").replace("\\", "/").rstrip("/") or "/workspace"
    invoked = _invoked_script_relpaths(command, wd, jail_root)

    for match in _PY_TRACEBACK_FILE_RE.finditer(text or ""):
        fp = match.group(1).replace("\\", "/").strip()
        if not fp or fp.startswith("<") or fp.startswith("/tmp/"):
            continue
        if fp.startswith(wd + "/"):
            rel = posixpath.normpath(fp[len(wd) + 1:])
        elif fp.startswith(jail_root + "/"):
            rel = posixpath.normpath(fp[len(jail_root) + 1:])
        elif not fp.startswith("/"):
            rel = posixpath.normpath(fp.removeprefix("./"))
        else:
            continue
        if (
            not rel
            or rel in (".", "..", "workspace")
            or rel.startswith("../")
            or rel.startswith("workspace/")
            or any(part == ".." for part in rel.split("/"))
        ):
            continue
        if rel in invoked:
            continue
        if _host_has(jail_root, rel) and os.path.isfile(os.path.join(jail_root, rel)):
            return True
    return False


def _is_launcher_enoent(output: str, exit_code: int) -> bool:
    if exit_code not in (1, 2, 127):
        return False
    if "no such file or directory" not in (output or "").lower():
        return False
    if _SHELL_LAUNCHER_FAIL_RE.search(output) or _ENV_LAUNCHER_FAIL_RE.search(output) or _CLI_MISSING_SCRIPT_RE.search(output):
        return True
    return not _has_target_traceback_frame(output)


def _sentinel_verified(sentinel_content: str, expected_nonce: str = "") -> bool:
    if not sentinel_content or MANTIS_SENTINEL_TOKEN not in sentinel_content:
        return False
    if expected_nonce:
        tagged = f"{MANTIS_SENTINEL_TOKEN}:{expected_nonce}"
        if tagged in sentinel_content:
            return True
        # Reject tokens carrying a different invocation's nonce, while keeping
        # bare static MANTIS_REACHED_ENTRYPOINT instrumentation compatible on
        # pre-cleared guest sidecar files.
        for line in sentinel_content.splitlines():
            if f"{MANTIS_SENTINEL_TOKEN}:" in line:
                return False
    return True


def _frame_symbols(output: str, exit_code: int = 1) -> set:
    found: set = set()
    text = output or ""
    for pat in _FRAME_SYMBOL_RES:
        found.update(m.group(1) for m in pat.finditer(text))
    if _has_go_panic_trace(text):
        found.update(m.group(1) for m in _GO_FRAME_RE.finditer(text))
    if _has_rust_panic_trace(text, exit_code):
        found.update(m.group(1) for m in _RUST_FRAME_RE.finditer(text))
    return found


def _frame_names_sink(frames: set, sink_symbol: str) -> bool:
    sink = (sink_symbol or "").strip()
    if not sink:
        return False
    for sym in frames:
        if sym == sink or sym.endswith("::" + sink) or sym.endswith("." + sink):
            return True
    return False


def _crash_corroborated(output: str, exit_code: int) -> bool:
    """Whether crash-like text is backed by the process actually crashing.

    Text alone is not a crash: a changelog that says "fixed Segmentation
    fault", `cat` over a fixture, or `echo` all print the same words at exit
    0. Corroboration is a sanitizer report header, a signal exit (128+N), or
    a non-zero exit together with a backtrace frame.
    """
    try:
        code = int(exit_code)
    except (TypeError, ValueError):
        code = 0
    if _SANITIZER_HEADER.search(output or ""):
        return True
    if code >= 128 or code < 0:
        return True
    return code != 0 and bool(_frame_symbols(output, code))


def _no_evidence(output: str, detail: str) -> Tuple[bool, str]:
    """The negative verdict, worded for whether the trace was whole.

    A harness truncation marker in the output means the sandbox cut the
    trace (core.truncation). Not finding the sentinel in a cut trace is not
    finding it absent: it may sit in the part that was dropped. The verdict
    is still False -- INV-1 fails closed, a cut trace verifies nothing -- but
    the reason says so, because a reproducer that reads EVIDENCE_ABSENT
    writes "the PoC never reached the sink" when the honest conclusion is
    "run it again with less noise".
    """
    if is_truncation_marker_present(output):
        return False, (
            f"{EVIDENCE_TRUNCATED_PREFIX}: sandbox output was cut by the harness before "
            f"the sentinel could be confirmed ({detail}); not verified. Re-run with a "
            "narrower command (filter or tail the output, or send the sentinel to the "
            "sidecar file via sentinel_path) so the proof lands inside the output cap."
        )
    return False, f"EVIDENCE_ABSENT: {detail}"


def check_reached_sink_evidence(
    output: str,
    exit_code: int,
    sink_symbol: str = "",
    sentinel_content: str = "",
    expected_nonce: str = "",
    timed_out: bool = False,
) -> Tuple[bool, str]:
    """Deterministically checks whether reached-sink evidence is present per INV-1 and INV-2 invariants.

    Returns:
        Tuple of (evidence_present: bool, reason: str)
    """
    clean_output = _strip_unscoped_remote_telemetry(output or "")
    if "SANDBOX-UNAVAILABLE" in clean_output:
        return False, "EVIDENCE_ABSENT: sandbox environment unavailable"

    # Channel A: Guest Sidecar Sentinel File ONLY (sole Channel A authority per INV-1/INV-2).
    # Evaluated ahead of post-sink child exit/ENOENT/timeout checks so a target that
    # flushes the sidecar sentinel at the sink and then errors or hangs still counts.
    if _sentinel_verified(sentinel_content, expected_nonce=expected_nonce):
        return True, "EVIDENCE_PRESENT: in-path sentinel marker MANTIS_REACHED_ENTRYPOINT verified"

    # Fail-closed checks when sidecar sentinel was not written
    if "SANDBOX-ERROR" in clean_output:
        return False, "EVIDENCE_ABSENT: sandbox transport or runtime error"
    if timed_out or "SANDBOX-TIMEOUT" in clean_output:
        return False, "EVIDENCE_ABSENT: sandbox execution timed out"
    if exit_code == 127:
        return False, "EVIDENCE_ABSENT: exit code 127 (command not found)"
    if _is_launcher_enoent(clean_output, exit_code):
        return False, "EVIDENCE_ABSENT: target or harness file not found"

    # Channel B: Target-produced Sanitizer / Crash backtrace naming sink.
    # The crash must be real (see _crash_corroborated), and a sink symbol
    # must be named by a backtrace frame, not merely present in the output.
    # Positive verdicts stand whether or not the trace was cut: proof that
    # survived the cut is still proof. Only the negatives go through
    # _no_evidence, which says whether the silence came from a whole trace.
    has_sanitizer_or_crash = (
        any(pat.search(clean_output) for pat in _SANITIZER_SIGNALS)
        or _has_go_panic_trace(clean_output)
        or _has_rust_panic_trace(clean_output, exit_code)
    )
    if has_sanitizer_or_crash:
        if not _crash_corroborated(clean_output, exit_code):
            return _no_evidence(clean_output, (
                "crash-like text in output, but the process exited "
                f"{exit_code} with no sanitizer report; text alone is not a crash"))
        if sink_symbol:
            if _frame_names_sink(_frame_symbols(clean_output, exit_code), sink_symbol):
                return True, f"EVIDENCE_PRESENT: crash backtrace explicitly confirms sink '{sink_symbol}'"
            return _no_evidence(clean_output, f"crash occurred but no backtrace frame names target sink '{sink_symbol}'")
        return True, "EVIDENCE_PRESENT: sanitizer/crash frame detected in execution output"

    return _no_evidence(clean_output, "no sentinel token or target-produced crash backtrace observed")


def _is_non_repro_node(ctx) -> bool:
    if ctx is None:
        return False
    active = getattr(ctx, "active_node", "")
    return bool(active and active not in ("reproducer", "patcher"))


def can_write_sandbox_target(ctx: Any, filepath: str = "") -> Tuple[bool, str]:
    """Permits non-`workspace/` sandbox target writes only from `reproducer` or `patcher`."""
    if ctx is None:
        return True, ""
    active = str(getattr(ctx, "active_node", "") or "").strip()
    if not active or active in ("reproducer", "patcher") or active.startswith(("reproducer_", "patcher_")):
        return True, ""
    return (
        False,
        f"Error: Stage '{active}' is not permitted to modify target file '{filepath}'; "
        "only 'reproducer' and 'patcher' may write outside 'workspace/'. "
        "Store notes and artifacts under 'workspace/'.",
    )


def _note_dynamic_evidence(
    ctx,
    output: str,
    exit_code: int,
    sink_symbol: str = "",
    sentinel_content: str = "",
) -> None:
    """Sets ctx.sandbox_executed IFF reached-sink evidence is actually present.

    WHY THIS IS A CHOKEPOINT AND NOT AN INLINE ASSIGNMENT
    -----------------------------------------------------
    `ctx.sandbox_executed` is consumed downstream (main.py's status gate) as "dynamic
    evidence exists for this campaign": it is the sole thing standing between a
    model-asserted `dynamic_confirmed` / `patch_verified` verdict and the knowledge
    base recording it as machine-verified. The flag used to be set by ANY command
    whose exit code was not 127 -- `echo hi` counted as dynamic execution -- which
    made the evidence tier a statement about shell availability, not about the
    exploit reaching its sink. INV-1 requires reached-sink proof: the sentinel token
    flushed from inside the target's execution path, or a target-produced sanitizer
    or crash backtrace. `check_reached_sink_evidence` is the deterministic authority
    for exactly that question, so the flag is now derived from it and from nothing
    else. Every site that used to write the flag routes through here, which keeps
    the tightening un-forkable: a future call site cannot quietly reintroduce the
    "a command ran at all" standard without bypassing this function by hand.

    FAIL DIRECTION
    --------------
    The flag only ever moves False -> True, and only on a positive verdict. It is
    never cleared here: one sentinel-verified execution earlier in the campaign is
    not un-proven by a later failed command, and clearing would let an attacker (or
    an unlucky flake) erase real evidence by running one broken command afterwards.
    Conversely, an exception inside the checker leaves the flag untouched -- when
    the evidence question cannot be answered, the answer is "no evidence" (INV-1
    fail-closed), which costs a re-run rather than laundering a guess into a
    machine-verified status.
    """
    if ctx is None:
        return
    try:
        evidence_present, _reason = check_reached_sink_evidence(
            output=output,
            exit_code=exit_code,
            sink_symbol=sink_symbol,
            sentinel_content=sentinel_content,
        )
        if evidence_present:
            ctx.sandbox_executed = True
    except Exception:
        # Deliberately swallowed: the checker is pure string/regex work and should
        # never raise, but if it does, "could not verify" must degrade to "flag
        # stays as it was", never to "flag set". See FAIL DIRECTION above.
        pass


_SENTINEL_FINDING_ID = re.compile(r"sentinel[_-](\d+)(?:\.\w+)?$")


def finding_id_from_sentinel_path(sentinel_path: Optional[str]) -> Optional[int]:
    """The finding id a sentinel path names, by the convention the reproducer
    prompt gives (`sentinel_<finding_id>`), or None."""
    if not sentinel_path:
        return None
    m = _SENTINEL_FINDING_ID.search(Path(str(sentinel_path)).name)
    return int(m.group(1)) if m else None


def _record_finding_evidence(
    ctx,
    finding_id: Optional[int],
    evidence_present: bool,
    reason: str,
    sink_symbol: str = "",
    ran: Optional[bool] = None,
) -> None:
    """Attributes one evidence verdict to one finding on ctx.finding_evidence.

    `sandbox_executed` answers "did any PoC in this campaign reach a sink";
    the completion stamp used to turn that one bit into `dynamic_confirmed`
    for every finding in the campaign, so in a whole-tree run one sentinel
    upgraded sixteen findings. This records which finding each verdict was
    about, so the stamp can upgrade only those.

    Outside the patcher the record is monotonic like the flag: a finding
    once reproduced is not un-reproduced by a later failed attempt. In the
    patcher the LAST re-attack counts: a patch that is re-attacked, fixed
    again and re-attacked again is judged by the final run. A verdict with
    no finding id is left unattributed; it still moves `sandbox_executed`.

    `ran` is whether the PoC got as far as attacking (see poc_ran): absent
    evidence from a PoC that never ran is not evidence of a fix, and the
    regression-check tool refuses to call it one.
    """
    if ctx is None or finding_id is None:
        return
    try:
        key = str(int(finding_id))
        entries = getattr(ctx, "finding_evidence", None)
        if entries is None:
            return
        entry = entries.setdefault(key, {"reproduced": False, "reattacked": False,
                                         "reattack_present": False, "sink_symbol": "", "reason": ""})
        if getattr(ctx, "active_node", "") == "patcher":
            if evidence_present or ran is not False:
                entry["reattacked"] = True
                entry["reattack_present"] = bool(evidence_present)
                entry["last_reattack_inconclusive"] = False
            else:
                # Never overwrite a prior reattack_present=True bypass on a
                # timeout, transport failure, or PoC setup error (INV-1/INV-2).
                entry["last_reattack_inconclusive"] = True
        elif evidence_present:
            entry["reproduced"] = True
        if sink_symbol:
            entry["sink_symbol"] = str(sink_symbol)
        entry["reason"] = str(reason or "")
        if ran is not None:
            entry["ran"] = bool(ran)
        if (
            getattr(ctx, "active_node", "") != "patcher"
            and entry.get("reproduced")
            and getattr(ctx, "db_path", "")
            and getattr(ctx, "run_id", "")
        ):
            from core.database import record_artifact

            fid_int = int(finding_id)
            res_key = str(getattr(ctx, "artifact_resource", "") or getattr(ctx, "target_file", "") or "")
            record_artifact(
                ctx.db_path,
                ctx.run_id,
                "finding_evidence",
                f"workspace/.structured/evidence_{fid_int}.json",
                json.dumps(
                    {
                        "finding_id": fid_int,
                        "reproduced": True,
                        "sink_symbol": entry.get("sink_symbol", ""),
                        "reason": entry.get("reason", ""),
                    }
                ),
                metadata={"resource": res_key, "finding_id": fid_int},
            )
    except Exception:
        pass  # bookkeeping; never fails a run (and never sets anything on error)


def invalidate_patch_reattack_state(ctx: Any) -> None:
    """Marks prior patcher re-attack verdicts stale after code edits in patcher."""
    if ctx is None or getattr(ctx, "active_node", "") != "patcher":
        return
    entries = getattr(ctx, "finding_evidence", None)
    if not isinstance(entries, dict):
        return
    for entry in entries.values():
        if isinstance(entry, dict):
            entry["reattacked"] = False
            entry["reattack_present"] = False
            entry["last_reattack_inconclusive"] = False


#: Deterministic infrastructure, toolchain, or missing-scaffold substrings that
#: unconditionally mean the PoC never got as far as attacking the target.
POC_SETUP_FAILURE_MARKERS = (
    "SANDBOX-UNAVAILABLE",
    "SANDBOX-ERROR",
    "SANDBOX-TIMEOUT",
    "no Go files in",
    "cannot find package",
    "cannot find module",
    "no required module provides package",
    "directory not found",
    "is not in std",
    "go: cannot find main module",
    "executable file not found",
    "build failed",
    "setup failed",
)


def poc_ran(
    output: str,
    exit_code: int,
    timed_out: bool = False,
    *,
    command: str = "",
    jail_dir: str = "",
    workdir: str = "",
) -> bool:
    """Whether a PoC run got as far as attacking: not a missing interpreter
    (126/127), not a timeout or sandbox transport error, and not a launcher or
    PoC-harness startup failure. Absent evidence means a fix only when True."""
    try:
        code = int(exit_code)
    except (TypeError, ValueError):
        code = 1
    if code in (126, 127) or code < 0 or timed_out:
        return False
    text = _strip_unscoped_remote_telemetry(str(output or ""))
    if any(m in text for m in POC_SETUP_FAILURE_MARKERS):
        return False
    if (
        _SHELL_LAUNCHER_FAIL_RE.search(text)
        or _ENV_LAUNCHER_FAIL_RE.search(text)
        or _CLI_MISSING_SCRIPT_RE.search(text)
    ):
        return False
    has_target_frame = _has_target_traceback_frame(
        text, command=command, jail_dir=jail_dir, workdir=workdir
    )
    if "no such file or directory" in text.lower() and not has_target_frame:
        return False
    if _PY_IMPORT_SYNTAX_EXC_RE.search(text) and not has_target_frame:
        return False
    return True


def _has_dynamic_sandbox(ctx: Any) -> bool:
    """True only when an active dynamic guest sandbox (not static-only) is configured."""
    if ctx is None or getattr(ctx, "sandbox", None) is None:
        return False
    return type(ctx.sandbox).__name__ not in ("StaticOnlyEnvironment", "StaticOnlySandbox")


def _guest_file_reader(sandbox: Any):
    """Returns the dynamic-plane file reader for sidecar sentinels (INV-1/INV-4).

    Split-plane environments (RemoteTargetEnvironment) expose ``read_guest_file``
    so sidecar sentinels are read exclusively from the remote runtime rather than
    the local read-only checkout.
    """
    if getattr(type(sandbox), "read_guest_file", None) is not None:
        return sandbox.read_guest_file
    return sandbox.read_file


async def _run_sandbox_internal(command: str) -> Tuple[str, bool]:
    """Internal runner returning ``(formatted_transcript, timed_out)``."""
    ctx = current_run_context.get()
    if ctx is None or ctx.sandbox is None:
        return "exit=127\nSANDBOX-UNAVAILABLE: ERROR: No active sandbox environment (sandbox unavailable).", False

    try:
        sandbox_type = type(ctx.sandbox).__name__
        is_static = sandbox_type in ("StaticOnlyEnvironment", "StaticOnlySandbox")

        if is_static:
            ctx.static_sandbox_attempts = getattr(ctx, "static_sandbox_attempts", 0) + 1
            if ctx.static_sandbox_attempts >= 3:
                if not _is_non_repro_node(ctx):
                    return (
                        f"exit=127\n"
                        f"SANDBOX-UNAVAILABLE: ERROR: Sandbox execution permanently blocked in static-only mode (attempt {ctx.static_sandbox_attempts}). "
                        f"Dynamic execution is disabled. Do NOT call run_sandbox again. "
                        f"STOP calling tools immediately and submit your stage verdict using the 'set_model_response' tool "
                        f"(e.g. set_model_response(route='failed_repro', reason='Dynamic execution disabled in static-only mode')) "
                        f"or as structured JSON text (e.g. {{\"route\": \"failed_repro\", \"reason\": \"Dynamic execution disabled in static-only mode\"}}) "
                        f"in your model response to conclude this stage."
                    ), False
                return (
                    f"exit=127\n"
                    f"SANDBOX-UNAVAILABLE: ERROR: Sandbox execution permanently blocked in static-only mode (attempt {ctx.static_sandbox_attempts}). "
                    f"Dynamic execution is disabled. Do NOT call run_sandbox again."
                ), False
            if not _is_non_repro_node(ctx):
                return (
                    "exit=127\n"
                    "SANDBOX-UNAVAILABLE: static-only sandbox; dynamic execution is disabled.\n"
                    "Do NOT retry running sandbox commands. In static-only mode, dynamic execution cannot be run. "
                    "Please update candidate findings in workspace/findings/ with repro_status='not_attempted', "
                    "STOP calling tools immediately, and submit your stage verdict using the 'set_model_response' tool "
                    "or as structured JSON text (e.g. {\"route\": \"failed_repro\", \"reason\": \"Dynamic execution disabled in static-only mode\"}) "
                    "in your model response."
                ), False
            return (
                "exit=127\n"
                "SANDBOX-UNAVAILABLE: static-only sandbox; dynamic execution is disabled.\n"
                "Do NOT retry running sandbox commands."
            ), False

        res = await ctx.sandbox.execute(command)
        if isinstance(res, ExecutionResult):
            raw_output = f"{res.stdout}{res.stderr}".strip()
            is_unavail = "SANDBOX-UNAVAILABLE" in raw_output or "SANDBOX-UNAVAILABLE" in res.stderr
            if is_unavail:
                ctx.static_sandbox_attempts = getattr(ctx, "static_sandbox_attempts", 0) + 1
                if ctx.static_sandbox_attempts >= 3:
                    if not _is_non_repro_node(ctx):
                        return (
                            f"exit=127\n"
                            f"SANDBOX-UNAVAILABLE: ERROR: Sandbox execution permanently blocked (sandbox unavailable, attempt {ctx.static_sandbox_attempts}). "
                            f"Dynamic execution is disabled. Do NOT call run_sandbox again. "
                            f"STOP calling tools immediately and submit your stage verdict using the 'set_model_response' tool "
                            f"or as structured JSON text (e.g. {{\"route\": \"failed_repro\", \"reason\": \"Sandbox unavailable\"}}) "
                            f"in your model response to conclude this stage."
                        ), False
                    return (
                        f"exit=127\n"
                        f"SANDBOX-UNAVAILABLE: ERROR: Sandbox execution permanently blocked (sandbox unavailable, attempt {ctx.static_sandbox_attempts}). "
                        f"Dynamic execution is disabled. Do NOT call run_sandbox again."
                    ), False
            elif not _is_non_repro_node(ctx):
                _note_dynamic_evidence(ctx, raw_output, res.exit_code)

            if not raw_output:
                return f"exit={res.exit_code}", bool(res.timed_out)
            scrubbed_output = SecretScrubber.scrub(raw_output)
            wrapped_output = wrap_untrusted_content(scrubbed_output, filename="sandbox_output")
            return f"exit={res.exit_code}\n{wrapped_output}", bool(res.timed_out)
        if isinstance(res, str):
            is_unavail = "SANDBOX-UNAVAILABLE" in res
            if is_unavail:
                ctx.static_sandbox_attempts = getattr(ctx, "static_sandbox_attempts", 0) + 1
                if ctx.static_sandbox_attempts >= 3:
                    if not _is_non_repro_node(ctx):
                        return (
                            f"exit=127\n"
                            f"SANDBOX-UNAVAILABLE: ERROR: Sandbox execution permanently blocked (sandbox unavailable, attempt {ctx.static_sandbox_attempts}). "
                            f"Dynamic execution is disabled. Do NOT call run_sandbox again. "
                            f"STOP calling tools immediately and submit your stage verdict using the 'set_model_response' tool "
                            f"or as structured JSON text (e.g. {{\"route\": \"failed_repro\", \"reason\": \"Sandbox unavailable\"}}) "
                            f"in your model response to conclude this stage."
                        ), False
                    return (
                        f"exit=127\n"
                        f"SANDBOX-UNAVAILABLE: ERROR: Sandbox execution permanently blocked (sandbox unavailable, attempt {ctx.static_sandbox_attempts}). "
                        f"Dynamic execution is disabled. Do NOT call run_sandbox again."
                    ), False
            elif res.startswith("exit=") and not _is_non_repro_node(ctx):
                head, _, body = res.partition("\n")
                try:
                    parsed_exit = int(head.split("=", 1)[1].strip())
                except (ValueError, IndexError):
                    parsed_exit = None
                if parsed_exit is not None:
                    _note_dynamic_evidence(ctx, body, parsed_exit)
            return SecretScrubber.scrub(res), False
        return SecretScrubber.scrub(str(res)), False
    except Exception as e:
        return f"ERROR: Sandbox execution failed: {SecretScrubber.scrub(str(e))}", False


async def run_sandbox(command: str) -> str:
    """Executes a command securely inside the configured sandbox. Use this to compile or run the reproduction script."""
    out, _timed_out = await _run_sandbox_internal(command)
    return out


async def run_sandbox_with_evidence(
    command: str,
    sentinel_path: Optional[str] = None,
    sink_symbol: str = "",
    finding_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Executes a sandbox command and evaluates reached-sink evidence deterministically.

    `finding_id` is the database id of the finding this PoC is for (from
    get_findings). The verdict is recorded against that finding, and only
    findings with their own evidence are later marked dynamically confirmed.
    When omitted it is read from a `sentinel_<finding_id>` sentinel path."""
    if finding_id is None:
        finding_id = finding_id_from_sentinel_path(sentinel_path)
    else:
        try:
            finding_id = int(finding_id)
        except (TypeError, ValueError):
            finding_id = finding_id_from_sentinel_path(sentinel_path)

    if not sentinel_path:
        sentinel_path = (
            f"sentinel_{finding_id}"
            if finding_id is not None
            else DEFAULT_UNATTRIBUTED_SENTINEL_PATH
        )

    nonce = secrets.token_hex(16)
    ctx_pre = current_run_context.get()
    if sentinel_path:
        # A sentinel left by an earlier attempt must not satisfy this one. But
        # sentinel_path is model-controlled: blanking whatever file it names
        # would be a truncate-anything primitive inside the sandbox (a slip, or
        # a steer from the target, and the file under test is emptied before
        # the PoC runs). So: read first, and clear ONLY a file that already
        # carries the sentinel token -- i.e. is a stale sentinel. Anything
        # else is left alone; a file without the token cannot be evidence.
        if _has_dynamic_sandbox(ctx_pre):
            try:
                existing = await _guest_file_reader(ctx_pre.sandbox)(Path(sentinel_path))
                if MANTIS_SENTINEL_TOKEN in existing.decode("utf-8", errors="replace"):
                    await ctx_pre.sandbox.write_file(Path(sentinel_path), "")
            except Exception:
                pass  # no file: nothing stale to clear

    if _has_dynamic_sandbox(ctx_pre) and hasattr(ctx_pre.sandbox, "set_exec_env"):
        ctx_pre.sandbox.set_exec_env(
            {
                "MANTIS_SENTINEL_FILE": str(sentinel_path),
                "MANTIS_SENTINEL_NONCE": nonce,
                "RUST_BACKTRACE": "1",
            }
        )

    raw_res, timed_out = await _run_sandbox_internal(command)
    exit_code = 127
    output = raw_res

    if raw_res.startswith("exit="):
        parts = raw_res.split("\n", 1)
        try:
            exit_code = int(parts[0].split("=")[1])
            output = parts[1] if len(parts) > 1 else ""
        except (ValueError, IndexError):
            exit_code = 127

    sentinel_content = ""
    if sentinel_path:
        ctx = current_run_context.get()
        # SECURITY (INV-1/INV-4): the sentinel is read ONLY from inside a dynamic
        # guest sandbox. StaticOnlyEnvironment reads from the host target checkout,
        # which would allow a target file containing the sentinel token to satisfy
        # reached-sink evidence without any dynamic execution.
        if _has_dynamic_sandbox(ctx):
            try:
                content_bytes = await _guest_file_reader(ctx.sandbox)(Path(sentinel_path))
                sentinel_content = content_bytes.decode("utf-8", errors="replace")
            except Exception:
                pass

    evidence_present, reason = check_reached_sink_evidence(
        output=output,
        exit_code=exit_code,
        sink_symbol=sink_symbol,
        sentinel_content=sentinel_content,
        expected_nonce=nonce,
        timed_out=timed_out,
    )

    # This wrapper sees a channel the inner run_sandbox cannot: the sidecar sentinel
    # file, read from inside the sandbox above. A PoC whose sentinel reached the file
    # but never stdout is real reached-sink proof, so the verdict computed here --
    # with every channel populated -- is fed into the same chokepoint the inner call
    # used. The chokepoint is monotonic and positive-only, so a stricter negative
    # here (e.g. a crash that failed to name the requested sink) never erases
    # evidence an earlier verified execution already established.
    if evidence_present:
        _note_dynamic_evidence(
            current_run_context.get(),
            output,
            exit_code,
            sink_symbol=sink_symbol,
            sentinel_content=sentinel_content,
        )
    # Which finding this verdict was about -- present or absent, both are
    # recorded: an absent re-attack is what verifies a patch. Whether the
    # PoC ran at all travels with it: absent evidence from a PoC that never
    # attacked is not a fix.
    _record_finding_evidence(
        current_run_context.get(),
        finding_id,
        evidence_present,
        reason,
        sink_symbol=sink_symbol,
        ran=True
        if evidence_present
        else poc_ran(output, exit_code, timed_out=timed_out, command=command),
    )
    scaffold: List[str] = []
    if evidence_present and finding_id is not None:
        scaffold = await _keep_poc_scaffold(current_run_context.get(), int(finding_id))

    return {
        "raw": raw_res,
        "exit_code": exit_code,
        "output": output,
        "evidence_present": evidence_present,
        "evidence_reason": reason,
        "finding_id": finding_id,
        "scaffold_files_kept": scaffold,
    }


async def _keep_poc_scaffold(ctx, finding_id: int) -> List[str]:
    """Stores, against the finding, the files its PoC left in the guest's
    target tree (a harness built inside the module, a `_test.go` dropped
    into the package): see core.poc_scaffold. Reproduction only -- in the
    patcher evidence means the patch failed, and the tree holds the patch.
    Returns the target-relative paths kept; never raises."""
    import os
    import sys

    try:
        if ctx is None or ctx.sandbox is None or not ctx.db_path:
            return []
        if type(ctx.sandbox).__name__ in ("StaticOnlyEnvironment", "StaticOnlySandbox"):
            return []
        if getattr(ctx, "active_node", "") == "patcher":
            return []
        from core.database import record_artifact
        from core.poc_scaffold import capture_poc_scaffold

        host_root = str(getattr(ctx.sandbox, "target_path", "") or "")
        if host_root and os.path.isfile(host_root):
            host_root = os.path.dirname(host_root)
        meta_base = {
            "resource": getattr(ctx, "target_file", ""),
            "snapshot_id": getattr(ctx, "snapshot_id", ""),
            "agent_authored": True,
        }

        def _persist(artifact_path: str, content: str, rel: str) -> None:
            record_artifact(ctx.db_path, ctx.run_id, "workspace_file", artifact_path, content,
                            metadata={**meta_base, "poc_scaffold": rel})

        kept = await capture_poc_scaffold(ctx.sandbox, finding_id, _persist, host_root=host_root or None)
        if kept:
            print(f"[{getattr(ctx, 'active_node', '') or 'reproducer'}] kept {len(kept)} scaffold file(s) "
                  f"for finding {finding_id}: {', '.join(kept[:5])}{'...' if len(kept) > 5 else ''}",
                  file=sys.stderr)
        return kept
    except Exception:
        return []


async def apply_patch(diff_content: str) -> str:
    """Applies a specific code patch to the sandbox context. Code modifications only exist inside the sandbox."""
    ctx = current_run_context.get()
    if ctx is None or ctx.sandbox is None:
        return "ERROR: No active sandbox environment (sandbox unavailable)."
    try:
        sandbox_type = type(ctx.sandbox).__name__
        if sandbox_type in ("StaticOnlyEnvironment", "StaticOnlySandbox"):
            return "ERROR: Patch application failed: dynamic sandbox is disabled in static-only mode."
        res = await ctx.sandbox.apply_patch(diff_content)
        out_str = str(res)
        if out_str.startswith("exit=0"):
            invalidate_patch_reattack_state(ctx)
        return SecretScrubber.scrub(out_str)
    except Exception as e:
        return f"ERROR: Patch application failed: {SecretScrubber.scrub(str(e))}"

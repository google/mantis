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

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.context import current_run_context
from core.llm_gateway import SecretScrubber, wrap_untrusted_content
from core.truncation import is_truncation_marker_present
from google.adk.environment import ExecutionResult

MANTIS_SENTINEL_TOKEN = "MANTIS_REACHED_ENTRYPOINT"

# Reason prefix for "the output was cut before the sentinel could be
# confirmed". Deliberately distinct from EVIDENCE_ABSENT: absent means the
# whole trace was seen and carried no proof; truncated means the trace was
# not whole, so its silence proves nothing either way. Both are not-verified.
EVIDENCE_TRUNCATED_PREFIX = "EVIDENCE_TRUNCATED"

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


def _frame_symbols(output: str) -> set:
    found: set = set()
    for pat in _FRAME_SYMBOL_RES:
        found.update(m.group(1) for m in pat.finditer(output or ""))
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
    return code != 0 and bool(_frame_symbols(output))


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
) -> Tuple[bool, str]:
    """Deterministically checks whether reached-sink evidence is present per INV-1 and INV-2 invariants.

    Returns:
        Tuple of (evidence_present: bool, reason: str)
    """
    # Fail-closed checks: command not found or missing file is EVIDENCE ABSENT
    if exit_code == 127:
        return False, "EVIDENCE_ABSENT: exit code 127 (command not found)"
    if "No such file or directory" in output and exit_code in (1, 2, 127):
        return False, "EVIDENCE_ABSENT: target or harness file not found"
    if "SANDBOX-UNAVAILABLE" in output:
        return False, "EVIDENCE_ABSENT: sandbox environment unavailable"

    # Channel A: Sidecar Sentinel File / explicit in-path flush token
    if sentinel_content and MANTIS_SENTINEL_TOKEN in sentinel_content:
        return True, "EVIDENCE_PRESENT: in-path sentinel marker MANTIS_REACHED_ENTRYPOINT verified"
    if MANTIS_SENTINEL_TOKEN in output:
        return True, "EVIDENCE_PRESENT: in-path sentinel marker emitted in execution trace"

    # Channel B: Target-produced Sanitizer / Crash backtrace naming sink.
    # The crash must be real (see _crash_corroborated), and a sink symbol
    # must be named by a backtrace frame, not merely present in the output.
    # Positive verdicts stand whether or not the trace was cut: proof that
    # survived the cut is still proof. Only the negatives go through
    # _no_evidence, which says whether the silence came from a whole trace.
    has_sanitizer_or_crash = any(pat.search(output) for pat in _SANITIZER_SIGNALS)
    if has_sanitizer_or_crash:
        if not _crash_corroborated(output, exit_code):
            return _no_evidence(output, (
                "crash-like text in output, but the process exited "
                f"{exit_code} with no sanitizer report; text alone is not a crash"))
        if sink_symbol:
            if _frame_names_sink(_frame_symbols(output), sink_symbol):
                return True, f"EVIDENCE_PRESENT: crash backtrace explicitly confirms sink '{sink_symbol}'"
            return _no_evidence(output, f"crash occurred but no backtrace frame names target sink '{sink_symbol}'")
        return True, "EVIDENCE_PRESENT: sanitizer/crash frame detected in execution output"

    return _no_evidence(output, "no sentinel token or target-produced crash backtrace observed")


def _is_non_repro_node(ctx) -> bool:
    if ctx is None:
        return False
    active = getattr(ctx, "active_node", "")
    return bool(active and active not in ("reproducer", "patcher"))


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
        elif evidence_present:
            entry["reproduced"] = True
        if sink_symbol:
            entry["sink_symbol"] = str(sink_symbol)
        entry["reason"] = str(reason or "")
        if ran is not None:
            entry["ran"] = bool(ran)
    except Exception:
        pass  # bookkeeping; never fails a run (and never sets anything on error)


#: Output that means a PoC never got as far as attacking: a missing module
#: or file, a shell that cannot find the interpreter, a syntax error, a Go
#: or shell build that found no scaffold or no toolchain. An AssertionError
#: or an application error is NOT in this list: those are the exploit
#: failing, which is what a fix looks like from the PoC's side.
POC_SETUP_FAILURE_MARKERS = (
    "ModuleNotFoundError",
    "ImportError",
    "SyntaxError",
    "No such file or directory",
    "command not found",
    "SANDBOX-UNAVAILABLE",
    "SANDBOX-ERROR",
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


def poc_ran(output: str, exit_code: int, timed_out: bool = False) -> bool:
    """Whether a PoC run got as far as attacking: not a missing interpreter
    (126/127), not a timeout, none of the setup-failure markers in its
    output. Absent evidence means a fix only when this is True."""
    try:
        code = int(exit_code)
    except (TypeError, ValueError):
        code = 1
    if code in (126, 127) or timed_out:
        return False
    text = str(output or "")
    return not any(m in text for m in POC_SETUP_FAILURE_MARKERS)


def _has_dynamic_sandbox(ctx: Any) -> bool:
    """True only when an active dynamic guest sandbox (not static-only) is configured."""
    if ctx is None or getattr(ctx, "sandbox", None) is None:
        return False
    return type(ctx.sandbox).__name__ not in ("StaticOnlyEnvironment", "StaticOnlySandbox")


async def run_sandbox(command: str) -> str:
    """Executes a command securely inside the configured sandbox. Use this to compile or run the reproduction script."""
    ctx = current_run_context.get()
    if ctx is None or ctx.sandbox is None:
        return "exit=127\nSANDBOX-UNAVAILABLE: ERROR: No active sandbox environment (sandbox unavailable)."

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
                    )
                return (
                    f"exit=127\n"
                    f"SANDBOX-UNAVAILABLE: ERROR: Sandbox execution permanently blocked in static-only mode (attempt {ctx.static_sandbox_attempts}). "
                    f"Dynamic execution is disabled. Do NOT call run_sandbox again."
                )
            if not _is_non_repro_node(ctx):
                return (
                    "exit=127\n"
                    "SANDBOX-UNAVAILABLE: static-only sandbox; dynamic execution is disabled.\n"
                    "Do NOT retry running sandbox commands. In static-only mode, dynamic execution cannot be run. "
                    "Please update candidate findings in workspace/findings/ with repro_status='not_attempted', "
                    "STOP calling tools immediately, and submit your stage verdict using the 'set_model_response' tool "
                    "or as structured JSON text (e.g. {\"route\": \"failed_repro\", \"reason\": \"Dynamic execution disabled in static-only mode\"}) "
                    "in your model response."
                )
            return (
                "exit=127\n"
                "SANDBOX-UNAVAILABLE: static-only sandbox; dynamic execution is disabled.\n"
                "Do NOT retry running sandbox commands."
            )

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
                        )
                    return (
                        f"exit=127\n"
                        f"SANDBOX-UNAVAILABLE: ERROR: Sandbox execution permanently blocked (sandbox unavailable, attempt {ctx.static_sandbox_attempts}). "
                        f"Dynamic execution is disabled. Do NOT call run_sandbox again."
                    )
            else:
                # Evidence, not liveness: the flag is only set when THIS command's
                # own trace carries reached-sink proof (sentinel token or a
                # target-produced crash), via the chokepoint above. The old rule --
                # any exit code but 127 -- certified "a shell existed", and the
                # downstream status gate read that as "the exploit was dynamically
                # verified". Callers going through run_sandbox_with_evidence also
                # get the sidecar sentinel file considered; a bare run_sandbox call
                # only has its output to speak for it, which is exactly as much as
                # it proved.
                _note_dynamic_evidence(ctx, raw_output, res.exit_code)

            if not raw_output:
                return f"exit={res.exit_code}"
            scrubbed_output = SecretScrubber.scrub(raw_output)
            wrapped_output = wrap_untrusted_content(scrubbed_output, filename="sandbox_output")
            return f"exit={res.exit_code}\n{wrapped_output}"
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
                        )
                    return (
                        f"exit=127\n"
                        f"SANDBOX-UNAVAILABLE: ERROR: Sandbox execution permanently blocked (sandbox unavailable, attempt {ctx.static_sandbox_attempts}). "
                        f"Dynamic execution is disabled. Do NOT call run_sandbox again."
                    )
            elif res.startswith("exit="):
                # Same evidence standard as the ExecutionResult branch, applied to
                # the stringified transport some sandbox backends use. The exit code
                # is parsed out of the "exit=N" prefix so the checker sees the same
                # two inputs either way; an unparseable prefix falls through with
                # the flag untouched, because a malformed transcript is not proof
                # of anything (fail-closed, INV-1).
                head, _, body = res.partition("\n")
                try:
                    parsed_exit = int(head.split("=", 1)[1].strip())
                except (ValueError, IndexError):
                    parsed_exit = None
                if parsed_exit is not None:
                    _note_dynamic_evidence(ctx, body, parsed_exit)
            return SecretScrubber.scrub(res)
        return SecretScrubber.scrub(str(res))
    except Exception as e:
        return f"ERROR: Sandbox execution failed: {SecretScrubber.scrub(str(e))}"


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
    if sentinel_path:
        # A sentinel left by an earlier attempt must not satisfy this one. But
        # sentinel_path is model-controlled: blanking whatever file it names
        # would be a truncate-anything primitive inside the sandbox (a slip, or
        # a steer from the target, and the file under test is emptied before
        # the PoC runs). So: read first, and clear ONLY a file that already
        # carries the sentinel token -- i.e. is a stale sentinel. Anything
        # else is left alone; a file without the token cannot be evidence.
        ctx_pre = current_run_context.get()
        if _has_dynamic_sandbox(ctx_pre):
            try:
                existing = await ctx_pre.sandbox.read_file(Path(sentinel_path))
                if MANTIS_SENTINEL_TOKEN in existing.decode("utf-8", errors="replace"):
                    await ctx_pre.sandbox.write_file(Path(sentinel_path), "")
            except Exception:
                pass  # no file: nothing stale to clear

    raw_res = await run_sandbox(command)
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
                content_bytes = await ctx.sandbox.read_file(Path(sentinel_path))
                sentinel_content = content_bytes.decode("utf-8", errors="replace")
            except Exception:
                pass

    evidence_present, reason = check_reached_sink_evidence(
        output=output,
        exit_code=exit_code,
        sink_symbol=sink_symbol,
        sentinel_content=sentinel_content,
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
    _record_finding_evidence(current_run_context.get(), finding_id, evidence_present, reason,
                             sink_symbol=sink_symbol,
                             ran=True if evidence_present else poc_ran(output, exit_code))
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
        return SecretScrubber.scrub(str(res))
    except Exception as e:
        return f"ERROR: Patch application failed: {SecretScrubber.scrub(str(e))}"

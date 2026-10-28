#!/usr/bin/env python3
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

"""Mantis pull-request scan: the driver behind the GitHub Action.

Audits the files a pull request changes with the full Mantis pipeline, then
runs the deterministic check_change gate over the PR diff and reports the
verdict as GitHub workflow annotations plus a step summary. The engine is
the MCP server's scan tier and gate, unchanged; this file only decides what
to scan, runs it synchronously, and renders the result for a CI job.

Design rules, in force everywhere in this file:

- The pull request checkout is DATA. Nothing in it is imported, executed,
  or installed; the pipeline reads it (read-only target, INV-4) and the
  sandbox is pinned to static-only so no PR-supplied code ever runs on the
  runner.
- No GitHub token. Annotations and the summary go through the workflow
  command and step-summary files; the only credentials in the job are
  whatever the chosen model provider needs, and only the pipeline
  subprocess reads them. The provider is the consumer's choice: any model
  id the pipeline accepts (the Gemini Enterprise Agent Platform, the Gemini
  API, Anthropic, or an OpenAI-compatible endpoint via --api-base).
- Fail closed on infrastructure, never on the model's mood. A changed file
  left unscanned (over the cap, over budget, timed out, or failed) floors
  the verdict at REVIEW with a reason that names it. No base commit,
  missing or rejected credentials, or nothing launching exit 3 -- a setup
  failure for the workflow's owner, never a verdict code -- so a broken
  installation is a red check rather than a silent pass. What the model
  found or did not find is reported as-is: the verdict is a function of
  findings only.
- Spend is bounded by this process, in the unit the invoice uses. The run
  has one token budget; each scan gets an equal share of what is left,
  counts every token at full price, and reports what it spent; a scan that
  reports nothing is charged its whole share; a file the budget cannot
  reach is not launched. Each request is also capped in input tokens, so
  one call cannot cost more than a known amount whatever the model's
  window. The day has a budget too, read from the platform's own meter
  before the run starts, and the run gets only what is left of it. The
  arithmetic lives here, not in the model, and nothing in the pull request
  can raise any of the numbers.

Exit codes: 0 the gate ran and --fail-on is satisfied; 1 the gate ran and
--fail-on is not; 3 setup failure.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from core.config import EXIT_AUTH  # noqa: E402
from scripts.mcp_server import (  # noqa: E402
    BLOCKING_SEVERITIES,
    VERDICT_BLOCK,
    VERDICT_PASS,
    VERDICT_REVIEW,
    MantisState,
    _scan_cmd,
    check_change,
    parse_unified_diff,
    reindex,
)

EXIT_OK = 0
EXIT_FAILED_GATE = 1
EXIT_INFRA = 3

FAIL_ON_CHOICES = ("none", "block", "review")

# Two independent policies decide the job's exit status. `fail-on` is about
# what the FINDINGS say: none (advisory), block, or review. `fail-closed` is
# about whether Mantis could LOOK: when it is off (the default) a setup
# failure, a model outage, a file the run could not scan, or a crash in this
# code never fails the job -- the summary says what was not audited and the
# verdict carries REVIEW, but a broken scanner does not stop a merge. When it
# is on, a job is green only if every changed file was audited in full.
COVERAGE_COMPLETE = "complete"
COVERAGE_PARTIAL = "partial"
COVERAGE_NONE = "none"

# GitHub renders at most this many annotations per level per step; the
# rest are only in the summary, which says so.
MAX_ANNOTATIONS_PER_LEVEL = 10

# Changed files the pipeline cannot audit and should not be billed for.
# Ignored files leave both the scan list and the gate's diff, so a
# docs-only pull request is a PASS rather than a "never scanned" REVIEW.
# Consumers replace the list with --ignore; an empty value ignores nothing.
# Prose and binary assets only. Dependency manifests and lockfiles are NOT
# here: a change to requirements.txt, go.sum or yarn.lock is a supply-chain
# change, which is exactly what a reviewer wants looked at, and `*.txt`
# would also have swallowed CMakeLists.txt.
DEFAULT_IGNORE = (
    "*.md", "*.rst",
    "*.svg", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.pdf",
    "*.woff", "*.woff2", "*.ttf", "*.eot",
)

# Mantis's own state in the repository (a committed knowledge export). Never
# scanned or gated, whatever the ignore list says; read from the base commit.
TOOL_STATE_DIR = ".mantis"

# Pipeline exit statuses, mirroring scan_change's labels, plus the one the
# pipeline reserves for rejected credentials (core.config.EXIT_AUTH).
SCAN_DONE = "done"
SCAN_PAUSED = "paused_at_budget"
SCAN_FAILED = "finished_with_errors"
SCAN_TIMED_OUT = "timed_out"
SCAN_AUTH_REJECTED = "credentials_rejected"
# Never launched: the run's token budget had nothing left for it.
SCAN_OVER_BUDGET = "over_budget"

# A scan is not launched with less than this many tokens to spend. Measured
# at the default call cap, the smallest file costs about 250k: prompts and
# graph nodes before the file's size counts for anything. Below this a scan
# cannot get through its first pass; launching it would buy a pause, charged
# to the run, for a file the gate must still treat as unaudited.
MIN_SCAN_ALLOWANCE = 100_000

# Default per-request input ceiling handed to the pipeline
# (MANTIS_MAX_INPUT_TOKENS). The pipeline refuses a request above it before
# dispatch, whatever the model's window and even when litellm does not know
# the model, so one call has a cost ceiling that the run budget's one-call
# overshoot (the budget is checked after each response) cannot exceed.
DEFAULT_MAX_INPUT_TOKENS = 262_144

# Default run token budget. Tokens are counted at full price whether or not
# the provider served them from cache, so this bounds the worst-case bill
# per run rather than the expected one. Measured at the default call cap: an
# ordinary file (400 to 1,000 lines) costs 350k to 650k, a 2,000-line file
# 850k. Ten million lets a ten-file pull request finish whole and makes a
# twenty-five-file one pause its biggest files at their 400k share.
DEFAULT_MAX_TOKENS = 10_000_000

# Default budget for the project over any trailing 24 hours, read from the
# platform's own meter before a run starts. Sized so a repository's ordinary
# day never meets it and a misfiring trigger is stopped within hours rather
# than running until someone reads the invoice.
DEFAULT_DAILY_TOKEN_BUDGET = 100_000_000

# A scan still working at its timeout is not killed while its log keeps
# growing, up to TIMEOUT_EXTENSION_FACTOR times the timeout; one silent for
# TIMEOUT_STALL_SECONDS (or the timeout itself, when shorter) is. Measured on
# a shared model quota: of the scans killed at an hour, 27 to 49 minutes went
# to a handful of model turns of 8 to 20 minutes each, and the same files
# finished in about half an hour in a later, smaller wave. A file's
# size did not predict it: a 317-line file timed out twice. The timeout
# exists to end a hung scan; a slow one that keeps producing is not hung,
# and killing it throws away a pass that was nearly done. The token budget,
# not the clock, bounds what it spends.
TIMEOUT_EXTENSION_FACTOR = 2.0
TIMEOUT_STALL_SECONDS = 900.0

# Environment the pipeline subprocess never needs and must not inherit:
# GitHub's own runtime tokens. The pipeline runs model-steered tool calls
# over attacker-authored code; nothing in that process should be able to
# mint an OIDC token or talk to the Actions service. Provider credentials
# pass through untouched -- which ones a run needs is the consumer's
# choice of model, so there is no fixed allowlist to apply.
_STRIPPED_ENV = frozenset({
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_RUNTIME_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_RESULTS_URL",
    "ACTIONS_CACHE_URL",
    "ACTIONS_CACHE_SERVICE_V2",
})

# What a revision argument may look like. GitHub's event payload supplies
# full SHAs; a workflow_dispatch input is typed by a person. Either way the
# value reaches git as an argument, so it is validated before it does and
# every git call also terminates option parsing explicitly.
_REV_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")


class InfraError(Exception):
    """The run cannot produce a verdict; the caller exits 3."""


def parse_ignore(spec: Optional[str]) -> List[str]:
    """Comma- or newline-separated fnmatch patterns; None means the default."""
    if spec is None:
        return list(DEFAULT_IGNORE)
    return [p.strip() for p in spec.replace("\n", ",").split(",") if p.strip()]


def is_ignored(rel_path: str, patterns: List[str]) -> bool:
    """Matches a pattern against the whole repo-relative path or its basename."""
    import fnmatch

    p = str(rel_path or "").replace("\\", "/")
    base = p.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(p, pat) or fnmatch.fnmatch(base, pat) for pat in patterns)


def filter_diff(diff_text: str, keep: set) -> str:
    """The diff with every per-file section whose new path is not in `keep`
    removed, so the gate and the scan list agree on the change set.

    A section's path is read from its header, which ends at the first hunk.
    Lines inside hunks are content the diffed file's author wrote, and a
    content line that reads `+++ b/other.py` must not rename the section.
    """
    out: List[str] = []
    section: List[str] = []
    section_path = ""
    in_header = False

    def flush() -> None:
        if section and section_path in keep:
            out.extend(section)

    for raw in str(diff_text or "").splitlines(keepends=True):
        if raw.startswith("diff --git "):
            flush()
            section, section_path, in_header = [raw], "", True
            continue
        if in_header and raw.startswith("@@"):
            in_header = False
        elif in_header and raw.startswith("+++ "):
            path = raw[4:].strip().split("\t")[0]
            if path.startswith("b/"):
                path = path[2:]
            section_path = "" if path == "/dev/null" else path
        section.append(raw)
    flush()
    return "".join(out)


def subprocess_env(env: Dict[str, str]) -> Dict[str, str]:
    """The environment the pipeline runs with: the step's, minus GitHub's
    own runtime tokens."""
    return {k: v for k, v in env.items() if k not in _STRIPPED_ENV}


# --- Inputs ------------------------------------------------------------------------


def _git(repo: Path, *args: str, check: bool = True,
         text: bool = True) -> subprocess.CompletedProcess:
    # core.quotePath=false: file names reach us as bytes-as-UTF-8, not as
    # C-quoted strings that would never match what the pipeline is given.
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "core.quotePath=false", *args],
        capture_output=True, text=text, check=check,
    )


def _valid_rev(rev: str, allow_head: bool = False) -> bool:
    rev = str(rev or "").strip()
    if allow_head and rev == "HEAD":
        return True
    return bool(_REV_RE.match(rev))


def _commit_present(repo: Path, rev: str) -> bool:
    return _git(repo, "rev-parse", "--verify", "--quiet", "--end-of-options",
                f"{rev}^{{commit}}", check=False).returncode == 0


# --- Knowledge from the base commit ----------------------------------------------------

# The repository's committed knowledge export (core.knowledge), read from the
# BASE commit and never from the checkout: the checkout is the pull request's,
# and a pull request must not get to edit the memory of the scan that grades
# it. The scan uses the base's version; the pull request's edits to it are
# reported as a change for a person to review.
KNOWLEDGE_FILES = ("manifest.json", "findings.jsonl", "learnings.jsonl", "threat_model.json",
                   "threat_model.md", "architecture.md", "summary.json", "coverage.json", "runs.jsonl")
MAX_KNOWLEDGE_FILE_BYTES = 32 * 1024 * 1024


def knowledge_from_base(repo: Path, base: str, dest: Path) -> Tuple[Optional[Path], str]:
    """Extracts `.mantis/knowledge/*` as of `base` into `dest`.

    Returns (dest, "") when the base commit carries a manifest, (None, "") when
    it carries none (the ordinary case for a repository that has never
    exported), and (None, reason) when it carries one that could not be read
    whole. Only the known file names are read, each by blob from the commit,
    none larger than the import would accept.
    """
    from core.knowledge import KNOWLEDGE_DIR

    def blob(name: str) -> Optional[bytes]:
        spec = f"{base}:{KNOWLEDGE_DIR}/{name}"
        size = _git(repo, "cat-file", "-s", "--end-of-options", spec, check=False)
        if size.returncode != 0:
            return None
        try:
            if int(size.stdout.strip()) > MAX_KNOWLEDGE_FILE_BYTES:
                raise InfraError(f"{KNOWLEDGE_DIR}/{name} in the base commit exceeds "
                                 f"{MAX_KNOWLEDGE_FILE_BYTES} bytes")
        except ValueError:
            return None
        out = _git(repo, "cat-file", "blob", "--end-of-options", spec, check=False, text=False)
        return out.stdout if out.returncode == 0 else None

    try:
        manifest = blob("manifest.json")
    except InfraError as exc:
        return None, str(exc)
    if manifest is None:
        return None, ""
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "manifest.json").write_bytes(manifest)
    for name in KNOWLEDGE_FILES[1:]:
        try:
            data = blob(name)
        except InfraError as exc:
            return None, str(exc)
        if data is not None:
            (dest / name).write_bytes(data)
    return dest, ""


def knowledge_edits(repo: Path, base: str, head: str) -> List[str]:
    """What the pull request does to `.mantis/knowledge/`, as 'STATUS path'
    entries, deletions included: a removed findings file is the edit most
    worth a reviewer's attention."""
    from core.knowledge import KNOWLEDGE_DIR

    out = _git(repo, "diff", "--no-color", "--no-ext-diff", "--name-status", "-z",
               "--end-of-options", base, head, "--", KNOWLEDGE_DIR, check=False, text=False)
    if out.returncode != 0:
        return []
    fields = [f.decode("utf-8", "replace") for f in out.stdout.split(b"\0") if f]
    edits: List[str] = []
    i = 0
    while i < len(fields):
        status = fields[i][:1]
        if status in ("R", "C") and i + 2 < len(fields):
            edits.append(f"{status} {fields[i + 2]}")
            i += 3
        elif i + 1 < len(fields):
            edits.append(f"{status} {fields[i + 1]}")
            i += 2
        else:
            break
    return edits


def pr_changes(repo: Path, base: str, head: str = "HEAD") -> Tuple[Dict[str, List[int]], str, Dict[str, Any]]:
    """What the PR changes: {repo-relative path: new-side changed lines},
    the unified diff text for the gate, and the paths the change moved or
    removed: {"renamed": {old: new}, "deleted": [old, ...]}.

    Two git views are combined on purpose. `--name-status -z` is the
    authority on WHICH files changed: it does not depend on how git chose
    to render each file, so a `.gitattributes` line marking a file `-diff`,
    or a NUL byte that trips binary detection, cannot drop a file from the
    change set -- both are the pull request author's to arrange. The
    unified diff then supplies changed LINES where it has them; a file with
    no parsable hunk keeps an empty line list, which the gate treats as
    fail-closed (any finding in it is `direct`).

    Renames and deletions are reported rather than dropped. A finding the
    repository already knows about lives at a path; a change that moves or
    removes that path would otherwise take the finding out of the gate's
    sight, and renaming a file is cheaper than fixing it. The gate carries
    known findings across a rename and asks for a look when their file is
    deleted.

    On a pull_request event the checkout is GitHub's merge commit, so the
    two-dot diff against the base tip is exactly the PR's effect on the
    branch it targets. A shallow checkout may lack the base commit; one
    depth-1 fetch of that commit is enough, since a diff needs the two
    trees and no history.
    """
    base = str(base or "").strip()
    head = str(head or "HEAD").strip()
    if not base:
        raise InfraError("No base commit given: pass --base (the PR's base SHA).")
    if not _valid_rev(base):
        raise InfraError(f"--base must be a commit SHA (7 to 64 hex digits), got {base[:40]!r}.")
    if not _valid_rev(head, allow_head=True):
        raise InfraError(f"--head must be HEAD or a commit SHA, got {head[:40]!r}.")
    if not _commit_present(repo, base):
        _git(repo, "fetch", "--quiet", "--no-tags", "--depth=1", "--end-of-options",
             "origin", base, check=False)
    if not _commit_present(repo, base):
        raise InfraError(
            f"Base commit {base} is not in the checkout and could not be fetched; "
            "set actions/checkout fetch-depth: 0.")
    if not _commit_present(repo, head):
        raise InfraError(f"Head revision '{head}' is not in the checkout.")

    common = ["--no-color", "--no-ext-diff", "--no-textconv", "--find-renames"]
    names = _git(repo, "diff", *common, "--diff-filter=ACDMRT", "--name-status", "-z",
                 "--end-of-options", base, head, check=False, text=False)
    if names.returncode != 0:
        raise InfraError(f"git diff --name-status failed: "
                         f"{names.stderr.decode('utf-8', 'replace').strip()}")
    changed: Dict[str, List[int]] = {}
    renamed: Dict[str, str] = {}
    deleted: List[str] = []
    fields = [f.decode("utf-8", "replace") for f in names.stdout.split(b"\0") if f]
    i = 0
    while i < len(fields):
        status = fields[i]
        if status[:1] in ("R", "C") and i + 2 < len(fields):
            changed.setdefault(fields[i + 2], [])  # the NEW path of a rename/copy
            if status[:1] == "R":
                renamed[fields[i + 1]] = fields[i + 2]
            i += 3
        elif i + 1 < len(fields):
            if status[:1] == "D":
                deleted.append(fields[i + 1])
            else:
                changed.setdefault(fields[i + 1], [])
            i += 2
        else:
            break

    hunks = _git(repo, "diff", *common, "--diff-filter=ACMRT", "--unified=0",
                 "--end-of-options", base, head, check=False)
    if hunks.returncode != 0:
        raise InfraError(f"git diff failed: {hunks.stderr.strip()}")
    for path, lines in parse_unified_diff(hunks.stdout).items():
        if path in changed:
            changed[path] = lines
    return changed, hunks.stdout, {"renamed": renamed, "deleted": deleted}


def fresh_state_dir(repo: Path, requested: str = "") -> Path:
    """Where this run keeps its database, index, and log: never inside the
    checkout, and never pre-existing.

    Everything under the checkout is the pull request author's: a committed
    symlink at a predictable path like `.mantis/scans/pr_scan.log` would
    turn the log into an append primitive on any file the runner can write,
    and a committed `.mantis/knowledge.db` or index cache would be trusted
    as this run's own memory. A fresh directory per run has neither
    problem. Defaults to the runner's temp directory.
    """
    base = Path(requested or os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()).resolve()
    repo = repo.resolve()
    if base == repo or repo in base.parents:
        raise InfraError(f"--state-dir must be outside the repository, got {base}.")
    state = base / f"mantis-pr-scan-{uuid.uuid4().hex[:12]}"
    state.mkdir(parents=True, exist_ok=False)
    return state


def credential_preflight(env: Optional[Dict[str, str]] = None, api_base: str = "",
                         model: str = "") -> Optional[str]:
    """Why no scan can succeed, or None.

    Provider-agnostic: the model id is resolved the way the pipeline resolves
    it (bare gemini-* and claude-* route by which credentials are present),
    then each provider is asked for its own requirements. A custom endpoint
    is trusted to carry its own authentication, so --api-base skips the
    check. Anything this cannot classify passes through; the pipeline's own
    authentication error is the backstop and is reported as a setup failure.
    """
    env = os.environ if env is None else env
    try:
        from core.config import DEFAULT_MODEL, normalize_model_id
    except Exception:  # the reference tree is incomplete: let the pipeline say so
        return None
    with _scoped_environ(env):
        resolved = normalize_model_id(model or DEFAULT_MODEL)
        if api_base:
            # The Agent Platform route authenticates with the job's workload
            # identity credential, and litellm sends that bearer token to
            # whatever api_base names. An api_base off Google's domain with
            # a vertex_ai/ model is a credential sent to a third party; an
            # OpenAI-compatible gateway is the openai/ route.
            if resolved.startswith("vertex_ai/") and not _google_host(api_base):
                return (f"api-base '{api_base}' is not a *.googleapis.com host, and model "
                        f"'{resolved}' authenticates with the job's Google Cloud credential, "
                        "which would be sent there. Use an openai/ model id for a gateway.")
            return None
        if resolved.startswith("vertex_ai/"):
            if any(env.get(v) for v in ("VERTEXAI_PROJECT", "GOOGLE_CLOUD_PROJECT")):
                return None
            try:
                import google.auth

                _, project = google.auth.default()
                if project:
                    return None
            except Exception:
                pass
            return (f"No Google Cloud project for '{resolved}': set GOOGLE_CLOUD_PROJECT "
                    "and provide credentials (workload identity or a service account).")
        try:
            import litellm

            check = litellm.validate_environment(model=resolved)
        except Exception:
            return None
        if check.get("keys_in_environment", True):
            return None
        missing = [str(k) for k in check.get("missing_keys") or []]
        if not missing:
            return None
        return (f"Missing credentials for '{resolved}': set "
                + ", ".join(missing) + " on the step.")


def _google_host(api_base: str) -> bool:
    try:
        from urllib.parse import urlsplit

        host = (urlsplit(str(api_base)).hostname or "").lower()
    except ValueError:
        return False
    return bool(host) and (host == "googleapis.com" or host.endswith(".googleapis.com"))


class _scoped_environ:
    """Runs a block with os.environ replaced by `env`, then restores it.

    normalize_model_id and litellm read os.environ directly; the driver
    takes an explicit env so tests can describe a runner without touching
    the process they run in.
    """

    def __init__(self, env: Dict[str, str]):
        self._env = dict(env)
        self._saved: Optional[Dict[str, str]] = None

    def __enter__(self):
        self._saved = dict(os.environ)
        os.environ.clear()
        os.environ.update(self._env)
        return self

    def __exit__(self, *exc):
        os.environ.clear()
        os.environ.update(self._saved or {})
        return False


def select_scan_files(state: MantisState, changed: Dict[str, List[int]],
                      max_files: int) -> tuple[List[str], List[str]]:
    """Repo-relative files to scan, and the ones over the cap.

    Mirrors scan_change's admission rule: inside the repository after
    resolving symlinks, and a regular file. Order is the diff's order
    (git's: path-sorted), so the cap is deterministic for a given change.
    """
    rels: List[str] = []
    for f in changed:
        r = state.rel(f)
        if not r:
            continue
        probe = state.repo / r
        try:
            probe.resolve().relative_to(state.repo)
        except (OSError, ValueError):
            continue
        if probe.is_file():
            rels.append(r)
    rels = list(dict.fromkeys(rels))
    if max_files > 0 and len(rels) > max_files:
        return rels[:max_files], rels[max_files:]
    return rels, []


# --- The daily budget ----------------------------------------------------------------

# The platform's own count of tokens served to a project: input and output,
# every Gemini model, sampled each minute, a few minutes behind. The one
# source for "what has this project spent today" that does not depend on
# this code's own accounting or on any state between runs.
TOKEN_COUNT_METRIC = "aiplatform.googleapis.com/publisher/online_serving/token_count"
DAILY_WINDOW_SECONDS = 24 * 3600


class DailyMeterUnavailable(Exception):
    """The platform meter could not be read; the caller decides what that means."""


def _project_for_meter(env: Dict[str, str]) -> str:
    for key in ("VERTEXAI_PROJECT", "GOOGLE_CLOUD_PROJECT"):
        if env.get(key):
            return str(env[key])
    return ""


def tokens_served_today(env: Dict[str, str], now: Optional[float] = None,
                        session: Any = None) -> int:
    """Tokens the project consumed in the trailing 24 hours, from Cloud Monitoring.

    One request: the token_count metric summed across every model and both
    token types over the window, aligned to a single point. Raises
    DailyMeterUnavailable with a reason a workflow owner can act on when the
    project, credential, API, or role is missing; never guesses.
    """
    project = _project_for_meter(env)
    end = int(now if now is not None else time.time())
    start = end - DAILY_WINDOW_SECONDS
    try:
        if session is None:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession

            with _scoped_environ(env):
                credentials, adc_project = google.auth.default(
                    scopes=["https://www.googleapis.com/auth/monitoring.read"])
            project = project or str(adc_project or "")
            session = AuthorizedSession(credentials)
    except Exception as exc:
        raise DailyMeterUnavailable(
            f"no Google Cloud credentials to read the project's token meter with: {exc}") from exc
    if not project:
        raise DailyMeterUnavailable(
            "no Google Cloud project: set GOOGLE_CLOUD_PROJECT on the step.")
    params = {
        "filter": f'metric.type = "{TOKEN_COUNT_METRIC}"',
        "interval.startTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start)),
        "interval.endTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end)),
        "aggregation.alignmentPeriod": f"{DAILY_WINDOW_SECONDS}s",
        "aggregation.perSeriesAligner": "ALIGN_SUM",
        "aggregation.crossSeriesReducer": "REDUCE_SUM",
        "view": "FULL",
    }
    url = f"https://monitoring.googleapis.com/v3/projects/{project}/timeSeries"
    try:
        resp = session.get(url, params=params, timeout=30)
    except Exception as exc:
        raise DailyMeterUnavailable(
            f"could not reach Cloud Monitoring for the configured project: {exc}") from exc
    if resp.status_code == 403:
        raise DailyMeterUnavailable(
            f"Cloud Monitoring refused the read for the configured project (HTTP 403): grant "
            "the service account roles/monitoring.viewer and enable "
            "monitoring.googleapis.com, or set daily-token-budget to 0.")
    if resp.status_code != 200:
        raise DailyMeterUnavailable(
            f"Cloud Monitoring returned HTTP {resp.status_code} for the configured project.")
    try:
        body = resp.json()
    except ValueError as exc:
        raise DailyMeterUnavailable("Cloud Monitoring returned a non-JSON body.") from exc
    if not isinstance(body, dict):
        raise DailyMeterUnavailable("Cloud Monitoring returned an unexpected body.")
    total = 0
    for series in body.get("timeSeries") or []:
        for point in (series.get("points") or []) if isinstance(series, dict) else []:
            value = (point.get("value") or {}) if isinstance(point, dict) else {}
            raw = value.get("int64Value", value.get("doubleValue", 0))
            try:
                total += int(float(raw))
            except (TypeError, ValueError):
                raise DailyMeterUnavailable("Cloud Monitoring returned a non-numeric point.")
    return max(0, total)


def run_budget_for_today(max_tokens: int, daily_budget: int, used_today: int) -> int:
    """This run's token budget once the day's spend is taken into account.

    With a daily budget, a run may spend at most what is left of it; with a
    run budget too, the smaller of the two. Returns 0 when nothing is left,
    which the scan loop reads as "launch nothing". With no daily budget the
    run budget stands as given (0 meaning none).
    """
    if daily_budget <= 0:
        return max(0, max_tokens)
    left = max(0, daily_budget - max(0, used_today))
    if max_tokens <= 0:
        return left
    return min(max_tokens, left)


# --- The scan ----------------------------------------------------------------------


def caller_files(state: MantisState, changed: Dict[str, List[int]], diff: str) -> List[str]:
    """Files holding direct callers of the functions the change touched, from
    the structural index, excluding the changed files themselves. Empty when
    the index is unavailable: a radius the gate cannot compute is not guessed."""
    try:
        reindex(state)
        pre = check_change(state, files=list(changed), diff=diff)
    except Exception:
        return []
    out: List[str] = []
    for b in pre.get("blast_radius") or []:
        for c in b.get("callers") or []:
            rel = state.rel(str(c.get("file") or ""))
            if rel and rel not in changed and rel not in out:
                out.append(rel)
    return sorted(out)


def archive_rewritten(db_path: str, prior: List[Dict[str, Any]], changed: Dict[str, List[int]],
                      examined: Any, first_new_id: int, note: str,
                      kept: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Archives known findings whose cited lines this change rewrote and whose
    lineage a completed rescan of the file, BY THE MODEL THAT FOUND IT, did
    not report again.

    `prior` is the open findings as they stood before the scans; `first_new_id`
    the first row id this run could have written; `examined` the files whose
    researcher pass completed -- a list of files (any model), or
    {model: [files]} when the run knows which model examined what. A finding
    is archived only when all of: its file is in the change set, its lines
    sit within DIFF_LINE_PROXIMITY of a changed line (a file changed
    elsewhere says nothing about them), the file was examined by the
    finding's own model (or the finding's model is unknown and any model
    examined it), and no row for its lineage was written by this run. A
    weaker model's miss must not shelve a stronger model's finding; when a
    different model examined the file and did not re-report the lineage,
    the finding is left open and appended to `kept` with the model named.
    Returns what was archived.
    """
    from core.database import archive_finding, read_findings, run_models
    from scripts.mcp_server import DIFF_LINE_PROXIMITY

    models_of_runs = run_models(db_path)
    by_model: Dict[str, set] = {}
    if isinstance(examined, dict):
        by_model = {str(m): set(files or []) for m, files in examined.items()}
    else:
        by_model = {"": set(examined or [])}
    examined_any = set().union(*by_model.values()) if by_model else set()
    seen_now = {str(r.get("lineage_id") or "") for r in read_findings(db_path)
                if int(r.get("id") or 0) >= first_new_id and r.get("lineage_id")}
    archived: List[Dict[str, Any]] = []
    for f in prior:
        lineage = str(f.get("lineage_id") or "")
        fp = str(f.get("filepath") or "")
        if not lineage or fp not in changed or fp not in examined_any or lineage in seen_now:
            continue
        finder = models_of_runs.get(str(f.get("run_id") or ""), "")
        if finder and by_model and "" not in by_model and fp not in by_model.get(finder, set()):
            if kept is not None:
                kept.append({"lineage_id": lineage, "filepath": fp, "title": str(f.get("title") or ""),
                             "found_by": finder,
                             "not_refound_by": sorted(m for m, files in by_model.items() if fp in files)})
            continue
        diff_lines = changed.get(fp) or []
        f_lines = [int(x) for x in (f.get("line_numbers") or []) if isinstance(x, int) and not isinstance(x, bool)]
        if not diff_lines or not f_lines:
            continue  # no line information on one side: leave it open
        if not any(abs(fl - cl) <= DIFF_LINE_PROXIMITY for fl in f_lines for cl in diff_lines):
            continue
        if archive_finding(db_path, lineage, note):
            archived.append({"lineage_id": lineage, "filepath": fp, "title": str(f.get("title") or ""),
                             "line_numbers": f_lines})
    return archived


def scan_command(state: MantisState, rel_fp: Any, max_llm_calls: int,
                 model: str, api_base: str = "", max_tokens: int = 0,
                 spend_report: str = "", knowledge_dir: str = "",
                 max_campaign_tokens: int = 0) -> List[str]:
    """scan_change's invocation, over the repository, plus the CI pins. Pure, for tests.

    `rel_fp` is one changed file, or a list of them for a one-process run
    (--one-process): each is listed, and `max_campaign_tokens`, when above
    0, caps each campaign so one file cannot spend the others' share.
    """
    # The repository is the target and the file is the run's one changed
    # file: a campaign over the file's directory, scoped to the file, that
    # can read the callers and types it needs in other packages. A file
    # target is a single-file jail, where a changed sink is judged without
    # the code that reaches it. One file per run still: the budget share,
    # timeout and status are per file, and the campaign's directory is the
    # file's own, so run N never reviews runs 1..N-1's findings as its own.
    cmd = _scan_cmd(state, str(state.repo), max_llm_calls, model)
    # One token each, so a file named like a flag ("-x.py") stays a value.
    rels = [rel_fp] if isinstance(rel_fp, str) else list(rel_fp)
    cmd += ["--scan-mode", "changed"] + [f"--changed-files={r}" for r in rels]
    # Static analysis only: the runner never executes anything the PR
    # supplied, whatever the action's own workflow.local.json says.
    cmd += ["--sandbox", "static-only"]
    if api_base:
        cmd += ["--api-base", api_base]
    # Every token at full price, run budget or not: a ceiling on discounted
    # tokens would bound the bill only if every token were served from cache
    # at the discount assumed, and with no run budget the pipeline's own
    # ceiling still applies and must mean raw tokens too.
    cmd += ["--cache-discount", "1"]
    if max_tokens > 0:
        cmd += ["--max-tokens", str(max_tokens)]  # this file's share of the run budget
    if max_campaign_tokens > 0:
        cmd += ["--max-campaign-tokens", str(max_campaign_tokens)]
    if spend_report:
        cmd += ["--spend-report", spend_report]
    if knowledge_dir:
        # Each scan is its own run with its own id, and the threat model and
        # architecture are read per run; so each scan imports for itself.
        # Findings and coverage dedupe, so repeating it costs nothing.
        cmd += ["--import-knowledge", knowledge_dir]
    return cmd


def allowance(budget: int, spent: int, files_left: int) -> int:
    """Tokens the next scan may spend: an equal share of what is left.

    A fair share with carry-over, so a cheap file's unspent share passes to
    the files after it and one expensive file cannot take the whole run.
    With no budget (0) there is no allowance to compute.
    """
    if budget <= 0 or files_left <= 0:
        return 0
    return max(0, budget - spent) // files_left


def read_spend_report(path: Path) -> Optional[Dict[str, Any]]:
    """The pipeline's own account of what it spent, or None if it left none."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    out: Dict[str, Any] = {}
    for key in ("tokens", "fresh_tokens", "cached_tokens", "llm_calls"):
        v = data.get(key)
        out[key] = int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0 else 0
    out["pause_trigger"] = str(data.get("pause_trigger") or "")
    nodes = data.get("nodes")
    out["nodes"] = [str(n) for n in nodes if isinstance(n, str)] if isinstance(nodes, list) else []
    # Each campaign's outcome, for a one-process run. Absent when the
    # pipeline wrote no such block (an older pipeline), which is not the
    # same as a run that ended before any campaign did ([]).
    campaigns = data.get("campaigns")
    if isinstance(campaigns, list):
        out["campaigns"] = []
        for c in campaigns:
            if not isinstance(c, dict):
                continue
            entry: Dict[str, Any] = {}
            for key in ("tokens", "fresh_tokens", "cached_tokens", "llm_calls"):
                v = c.get(key)
                entry[key] = int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0 else 0
            secs = c.get("elapsed_seconds")
            entry["elapsed_seconds"] = (float(secs) if isinstance(secs, (int, float))
                                        and not isinstance(secs, bool) and secs >= 0 else 0.0)
            entry["status"] = str(c.get("status") or "")
            entry["pause_trigger"] = str(c.get("pause_trigger") or "")
            files, cnodes = c.get("files"), c.get("nodes")
            entry["files"] = [str(f) for f in files if isinstance(f, str)] if isinstance(files, list) else []
            entry["nodes"] = [str(n) for n in cnodes if isinstance(n, str)] if isinstance(cnodes, list) else []
            out["campaigns"].append(entry)
    return out


# The node whose completion means "this file has been examined": once the
# graph has moved from the researcher to whatever follows it, the pass over the
# file is done and its findings are stored, whatever happens to the run after.
RESEARCHER_NODE = "researcher"


def researcher_finished(nodes: List[str]) -> bool:
    """True when the graph reached a node after the researcher."""
    try:
        return len(nodes) > nodes.index(RESEARCHER_NODE) + 1
    except ValueError:
        return False


def charge(report: Optional[Dict[str, Any]], granted: int) -> int:
    """What a scan is charged against the run budget.

    Its own account when it left one, at the raw count (fresh plus cached:
    what a provider bills before any discount) or the budget-weighted
    count, whichever is larger. A scan that left no account, because it was
    killed or crashed before it could, is charged everything it was given:
    the budget may over-count, never under-count.
    """
    if report is None:
        return granted
    raw = report["fresh_tokens"] + report["cached_tokens"]
    return max(raw, report["tokens"])


def _classify(code: Optional[int], account: Optional[Dict[str, Any]] = None) -> str:
    if code is None:
        return SCAN_TIMED_OUT
    if code == 0:
        return SCAN_DONE
    if code == 2:
        # A graceful pause at a ceiling, with findings so far stored. Every
        # genuine pause names its trigger in the spend report; the pipeline
        # also exits 2 for a sandbox configuration error, which an account
        # with no trigger tells apart. No account at all (the report could
        # not be written) stays a pause: the conservative reading.
        if account is not None and not account.get("pause_trigger"):
            return SCAN_FAILED
        return SCAN_PAUSED
    if code == EXIT_AUTH:
        return SCAN_AUTH_REJECTED  # the provider refused the credentials
    return SCAN_FAILED


def charge_for(code: Optional[int], report: Optional[Dict[str, Any]], granted: int) -> int:
    """What a finished, killed or unlaunched process is charged.

    A process that never started spent nothing. One that was killed (code
    None) may have left an account, since the pipeline rewrites its report
    as each campaign ends; but that account stops at the last campaign that
    ended, not at the kill, so a killed process is charged at least its
    whole grant. Everything else is charge().
    """
    if code == -1:
        return 0
    if code is None:
        return max(granted, charge(report, granted))
    return charge(report, granted)


# --- One process for the pull request (--one-process) --------------------------------

# How a campaign's own outcome, from the pipeline's spend report, reads as a
# file's scan status.
_CAMPAIGN_STATUS = {"done": SCAN_DONE, "failed": SCAN_FAILED, "paused": SCAN_PAUSED}


def campaign_groups(state: MantisState, rels: List[str]) -> List[List[str]]:
    """The campaigns a one-process run makes of `rels`, each a list of
    repo-relative files, in `rels` order.

    The pipeline's own grouping (main.group_changed_files without the climb,
    as --changed-files runs it): a campaign per directory holding changed
    files, nested directories joined to their ancestor's. The driver splits
    the budget into per-campaign shares by it, so it has to be the grouping
    the run will use. When the pipeline cannot be imported every file is its
    own group: more groups, smaller shares, the safe direction.
    """
    order = {r: i for i, r in enumerate(rels)}
    groups: List[List[str]] = []
    try:
        from main import group_changed_files

        for g in group_changed_files([str(state.repo / r) for r in rels], str(state.repo), climb=False):
            files = [r for r in (state.rel(str(f)) for f in g.get("files") or []) if r in order]
            if files:
                groups.append(files)
    except Exception:
        groups = []
    placed = {f for g in groups for f in g}
    groups += [[r] for r in rels if r not in placed]
    groups = [sorted(dict.fromkeys(g), key=order.__getitem__) for g in groups]
    return sorted(groups, key=lambda g: order[g[0]])


def one_process_results(state: MantisState, rels: List[str], model: str, code: Optional[int],
                        account: Optional[Dict[str, Any]], cost: int, granted: int,
                        seconds: float) -> List[Dict[str, Any]]:
    """Per-file results of one pipeline run over several changed files.

    Each file takes its campaign's outcome from the spend report's
    per-campaign accounts: status, tokens, calls, time, and whether the
    researcher finished. One campaign can finish while the next stops at its
    own share, and a process killed after a campaign ended still leaves that
    campaign's account. A file with no campaign account takes the process's
    outcome: timed out when it was killed, paused when the run paused
    before reaching it, rejected credentials when the provider refused
    them, and failed otherwise (a finished run that left a file out made no
    campaign of it, e.g. not a source file). A report with no per-campaign
    block at all (an older pipeline) gives every file the run's outcome.

    Tokens and calls are shared out so the files' sum is the run's charge:
    a campaign's among its files, and what no campaign accounts for (the
    killed campaign, or the charge over the account) among the files with
    no campaign, else to the first file. A count with no account is None.
    """
    campaigns = account.get("campaigns") if account else None
    in_rels = set(rels)
    placed: Dict[str, Tuple[Dict[str, Any], int, int]] = {}
    for c in campaigns or []:
        files = [r for r in dict.fromkeys(state.rel(f) for f in c["files"]) if r in in_rels and r not in placed]
        for j, f in enumerate(files):
            placed[f] = (c, len(files), j)
    if code == -1:
        unplaced = SCAN_FAILED
    elif campaigns is None or code == EXIT_AUTH or code is None:
        unplaced = _classify(code, account)
    elif code == 2 and account and account.get("pause_trigger"):
        unplaced = SCAN_PAUSED
    else:
        unplaced = SCAN_FAILED

    def split(total: int, k: int, j: int) -> int:
        return total // k + (total % k if j == 0 else 0)

    results: List[Dict[str, Any]] = []
    for rel in rels:
        if rel in placed:
            c, k, j = placed[rel]
            status = _CAMPAIGN_STATUS.get(c["status"], SCAN_FAILED)
            if code == EXIT_AUTH and status != SCAN_DONE:
                status = SCAN_AUTH_REJECTED
            results.append({
                "file": rel, "model": model, "returncode": code, "status": status,
                "seconds": round(c["elapsed_seconds"], 1),
                "tokens": split(max(c["fresh_tokens"] + c["cached_tokens"], c["tokens"]), k, j),
                "llm_calls": split(c["llm_calls"], k, j) if account else None,
                "granted": granted,
                "pause_trigger": c["pause_trigger"] if status == SCAN_PAUSED else "",
                "examined": researcher_finished(c["nodes"]),
            })
        else:
            results.append({
                "file": rel, "model": model, "returncode": code, "status": unplaced,
                "seconds": round(seconds, 1) if campaigns is None else 0.0,
                "tokens": 0, "llm_calls": 0 if account else None, "granted": granted,
                "pause_trigger": (account or {}).get("pause_trigger", "") if unplaced == SCAN_PAUSED else "",
                # The run's nodes are every campaign's merged: they say a
                # file was examined only when the run had that one file.
                "examined": (len(rels) == 1 and code != -1 and bool(account)
                             and researcher_finished(account.get("nodes") or [])),
            })
    rest = [r for r in results if r["file"] not in placed] or results[:1]
    for key, total in (("tokens", cost), ("llm_calls", (account or {}).get("llm_calls"))):
        if total is None or not rest:
            continue
        left = int(total) - sum(int(r[key] or 0) for r in results)
        if left > 0:
            for j, r in enumerate(rest):
                r[key] = int(r[key] or 0) + split(left, len(rest), j)
    return results


def _open_log(log_path: Path):
    """Append handle on a log that must be a regular file we created: no
    following symlinks, no reuse of anything that was already there."""
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.fdopen(os.open(str(log_path), flags, 0o600), "ab")


def wait_for_scan(proc: "subprocess.Popen", timeout: float, progress: Callable[[], int],
                  log: Optional[Any] = None, clock: Callable[[], float] = time.monotonic,
                  stall_seconds: float = TIMEOUT_STALL_SECONDS,
                  extension_factor: float = TIMEOUT_EXTENSION_FACTOR) -> Optional[int]:
    """The scan's exit code, or None once it was killed for its timeout.

    Until `timeout` the scan runs as before. Past it, it keeps running only
    while it is producing: `progress()` (the size of the log it writes) has
    grown within the stall window -- stall_seconds, or the timeout itself
    when that is shorter -- and never beyond extension_factor times the
    timeout. A timeout of 0 or less waits for the scan to end.
    """
    if timeout <= 0:
        return proc.wait()
    start = clock()
    deadline = start + timeout
    cap = start + timeout * max(1.0, extension_factor)
    stall = min(stall_seconds, timeout)
    seen, seen_at = progress(), start
    poll = max(0.05, min(30.0, stall / 4))
    extended = False
    while True:
        now = clock()
        wait_for = poll if now >= deadline else min(poll, deadline - now)
        try:
            return proc.wait(timeout=max(0.01, min(wait_for, cap - now)))
        except subprocess.TimeoutExpired:
            pass
        now = clock()
        size = progress()
        if size != seen:
            seen, seen_at = size, now
        if now < deadline:
            continue
        if now >= cap or now - seen_at >= stall:
            break
        if not extended and log is not None:
            extended = True
            log.write(f"[pr_scan] still working at {timeout:.0f}s; running on while it writes "
                      f"(silent {stall:.0f}s, or {cap - start:.0f}s in all, ends it)\n".encode())
            log.flush()
            seen = progress()
    proc.kill()
    proc.wait()
    if log is not None:
        why = "its limit" if now >= cap else f"{now - seen_at:.0f}s without output"
        log.write(f"[pr_scan] timed out after {now - start:.0f}s ({why})\n".encode())
    return None


def run_scans(state: MantisState, rels: List[str], max_llm_calls: int, model: str,
              api_base: str, per_file_timeout: float, log_path: Path,
              env: Optional[Dict[str, str]] = None, max_tokens: int = 0,
              max_input_tokens: int = DEFAULT_MAX_INPUT_TOKENS,
              daily: Optional[Dict[str, Any]] = None,
              meter: Optional[Callable[[Dict[str, str]], int]] = None,
              knowledge_dir: str = "", models: Optional[List[str]] = None,
              one_process: bool = False) -> List[Dict[str, Any]]:
    """Runs the pipeline over each file in turn -- under each model in turn
    when `models` names more than one -- then makes sure the gate has a
    repo-rooted index: the scans index the repository and normally leave
    one, and when they did not (none launched, or the build failed) it is
    built here, so the gate's blast radius is never blind.

    With several models every file is scanned by every model: the models
    differ in what they find, and knowledge worth keeping is the union. The
    run budget is shared over all the (model, file) jobs left, so one
    model's spend narrows what the others get, not what the run spends.
    Each result carries its model.

    Spend is bounded by the run: each scan is launched with an equal share
    of the tokens still unspent, told to count every token at full price,
    and asked to report what it spent; a scan that reports nothing is
    charged its whole share. When the share left for a file falls below
    MIN_SCAN_ALLOWANCE the file is not launched at all and is reported
    over budget. The driver does the arithmetic, not the model, and a
    pull request has no way to raise the budget.

    A scan the provider rejected for credentials -- known from the exit
    status the pipeline reserves for it, not from anything in the log --
    ends the loop: every later file would fail the same way, and the caller
    reports a setup failure rather than N failed scans.

    With a daily budget in force the platform's meter is read again before
    each file, not only once at the start. The meter lags by minutes, so
    runs that start inside that window all see the same reading; re-reading
    bounds what N runs in flight can overspend to about one file's share
    each after the lag, instead of a whole run budget each. This run's own
    spend is not yet in the meter, so the floor is what the meter showed at
    the start plus what this run has charged since.

    With `one_process` each model's files are scanned in ONE pipeline run,
    every file listed, instead of one run per file: the stages a run does
    once (the index, and whatever a campaign can take from an earlier one)
    are not paid per file. The run gets the job's share of the budget and
    each campaign an equal part of it (--max-campaign-tokens), so a file
    still cannot spend the others' share; the timeout is the per-file one
    times the files; and each file's status, tokens and examined flag come
    from its campaign's account in the spend report (one_process_results).
    """
    results: List[Dict[str, Any]] = []
    daily_budget = int(daily["budget"]) if daily else 0
    used_start = int(daily.get("used_before_run") or 0) if daily else 0
    read_meter = meter or tokens_served_today
    # One process per model with every file listed, or one per (model, file).
    jobs: List[Tuple[str, Any]] = ([(m, list(rels)) for m in (models or [model])] if one_process
                                   else [(m, rel) for m in (models or [model]) for rel in rels])
    log_path.parent.mkdir(parents=True, exist_ok=True)
    child_env = subprocess_env(dict(os.environ if env is None else env))
    if max_input_tokens > 0:
        child_env["MANTIS_MAX_INPUT_TOKENS"] = str(int(max_input_tokens))
    else:
        child_env.pop("MANTIS_MAX_INPUT_TOKENS", None)
    spend_dir = log_path.parent / "spend"
    spend_dir.mkdir(mode=0o700, exist_ok=True)
    spent = 0
    with _open_log(log_path) as log:

        def launch(cmd: List[str], timeout: float) -> Optional[int]:
            """The pipeline's exit code; None when killed for its timeout
            (wait_for_scan: a scan still writing at `timeout` runs on, within
            bounds), -1 when it never started."""
            try:
                proc = subprocess.Popen(
                    cmd, stdout=log, stderr=log, cwd=str(_REF_ROOT), env=child_env)
            except Exception as exc:  # one bad file must not end the run
                log.write(f"[pr_scan] scan failed to launch: {exc!r}\n".encode())
                log.flush()
                return -1
            try:
                return wait_for_scan(proc, timeout, lambda: os.fstat(log.fileno()).st_size, log=log)
            except BaseException as exc:
                proc.kill()
                proc.wait()
                if not isinstance(exc, Exception):
                    raise
                log.write(f"[pr_scan] scan abandoned: {exc!r}\n".encode())
                return None  # unaudited and charged in full, as a timeout is
            finally:
                log.flush()

        for i, (job_model, rel_fp) in enumerate(jobs):
            budget_now = max_tokens
            if daily_budget > 0 and i > 0:
                try:
                    used_now = int(read_meter(dict(os.environ if env is None else env)))
                except DailyMeterUnavailable as exc:
                    # Readable at the start, not now: keep the run's own
                    # budget, which already fit under the day's when it was
                    # set, and say so in the log.
                    log.write(f"[pr_scan] daily meter unreadable mid-run ({exc}); "
                              f"holding to the run budget\n".encode())
                else:
                    day_left = max(0, daily_budget - max(used_now, used_start + spent))
                    budget_now = min(max_tokens, spent + day_left) if max_tokens > 0 else spent + day_left
            granted = allowance(budget_now, spent, len(jobs) - i)
            if one_process:
                # Every campaign gets an equal share of the grant, so one file
                # cannot spend the others'; campaigns whose share would fall
                # below MIN_SCAN_ALLOWANCE are not launched, from the last.
                groups = campaign_groups(state, rel_fp)
                while budget_now > 0 and groups and granted // len(groups) < MIN_SCAN_ALLOWANCE:
                    groups.pop()
                share = granted // len(groups) if groups and budget_now > 0 else 0
                listed = [f for f in rel_fp if any(f in g for g in groups)]
                for f in rel_fp:
                    if f not in listed:
                        log.write(f"\n=== mantis scan {f} [{job_model or 'default model'}]: not launched, "
                                  f"{granted} of {budget_now} run tokens left ===\n".encode())
                        results.append({"file": f, "model": job_model, "returncode": None,
                                        "status": SCAN_OVER_BUDGET, "seconds": 0.0,
                                        "tokens": 0, "llm_calls": 0, "granted": share,
                                        "pause_trigger": ""})
                if not listed:
                    continue
                spend_path = spend_dir / f"{i}.json"
                cmd = scan_command(state, listed, max_llm_calls, job_model, api_base,
                                   max_tokens=granted, spend_report=str(spend_path),
                                   knowledge_dir=knowledge_dir,
                                   max_campaign_tokens=share if len(groups) > 1 else 0)
                log.write(f"\n=== mantis scan {len(listed)} file(s) in {len(groups)} campaign(s) "
                          f"[{job_model or 'default model'}] ===\n".encode())
                log.flush()
                started = time.time()
                # One process for the files: the timeout is the files'.
                code = launch(cmd, per_file_timeout * len(listed))
                account = read_spend_report(spend_path)
                cost = charge_for(code, account, granted)
                spent += cost
                job = one_process_results(state, listed, job_model, code, account, cost,
                                          share, time.time() - started)
                order = {f: n for n, f in enumerate(rel_fp)}
                results.extend(sorted(job, key=lambda r: order[r["file"]]))
                if code == EXIT_AUTH:
                    break
                continue
            if budget_now > 0 and granted < MIN_SCAN_ALLOWANCE:
                log.write(f"\n=== mantis scan {rel_fp} [{job_model or 'default model'}]: not launched, "
                          f"{granted} of {budget_now} run tokens left ===\n".encode())
                results.append({"file": rel_fp, "model": job_model, "returncode": None,
                                "status": SCAN_OVER_BUDGET, "seconds": 0.0,
                                "tokens": 0, "llm_calls": 0, "granted": granted,
                                "pause_trigger": ""})
                continue
            spend_path = spend_dir / f"{i}.json"
            cmd = scan_command(state, rel_fp, max_llm_calls, job_model, api_base,
                               max_tokens=granted, spend_report=str(spend_path),
                               knowledge_dir=knowledge_dir)
            log.write(f"\n=== mantis scan {rel_fp} [{job_model or 'default model'}] ===\n".encode())
            log.flush()
            started = time.time()
            code = launch(cmd, per_file_timeout)
            account = read_spend_report(spend_path)
            # A process that never started spent nothing; everything else
            # that left no account is charged in full, and so is one killed.
            cost = charge_for(code, account, granted)
            spent += cost
            results.append({
                "file": rel_fp,
                "model": job_model,
                "returncode": code,
                "status": _classify(code, account),
                "seconds": round(time.time() - started, 1),
                "tokens": cost,
                "llm_calls": account["llm_calls"] if account else None,
                "granted": granted,
                "pause_trigger": account["pause_trigger"] if account else "",
                # The researcher's pass over the file is complete once the graph
                # has moved past it; a pause later (review, calibration) does
                # not undo what it reported or did not report.
                "examined": bool(account) and researcher_finished(account.get("nodes") or [])
                            if code != -1 else False,
            })
            if code == EXIT_AUTH:
                break
    if not index_is_repo_rooted(state):
        try:
            reindex(state)
        except Exception:
            pass  # the gate reports a missing index as REVIEW on its own
    return results


def index_is_repo_rooted(state: MantisState) -> bool:
    """Whether the published catalog is usable and rooted at the repository.

    The scans index the repository itself, so after them the catalog
    normally already is the one the gate needs, and rebuilding it -- minutes
    on a large tree -- buys nothing. The state directory is fresh per run,
    so a catalog found here was built over this checkout by this run.
    """
    try:
        idx = state.index()
        return idx.available() and idx.manifest.get("code_root") == str(state.repo)
    except Exception:
        return False


# --- The verdict ---------------------------------------------------------------------


def _gap(report: Dict[str, Any], file: str, reason: str, action: str) -> None:
    """A changed file this run did not fully audit. Recorded as coverage,
    shown as a REVIEW reason, and left to exit_code_for -- not fail-on -- to
    decide whether it fails the job."""
    report["coverage"]["unaudited"].append({"file": file, "reason": reason, "action": action})
    report["reasons"].append(reason)
    if action not in report["next_actions"]:
        report["next_actions"].append(action)


def _apply_knowledge(report: Dict[str, Any], knowledge: Dict[str, Any]) -> None:
    """The repository's knowledge, as it bears on the verdict.

    A knowledge edit is a security decision made in a pull request: a
    finding marked false positive, a boundary redrawn, a file of findings
    removed. The scan graded the change against the base's knowledge; the
    edit itself is for a person, so it is a REVIEW of the findings kind --
    it fails the job under `fail-on: review` -- even when nothing else in
    the pull request needed looking at. A knowledge export the run could
    not read is a coverage gap: the scan ran without what it should have
    known.
    """
    if knowledge.get("changed"):
        if report["verdict"] == VERDICT_PASS:
            report["verdict"] = VERDICT_REVIEW
        report["reasons"].append(
            f"This pull request changes Mantis's knowledge ({len(knowledge['changed'])} file(s) "
            f"under {knowledge['dir']}: " + ", ".join(knowledge["changed"]) + "); the scan "
            "used the base commit's version.")
        action = ("Review the knowledge change as you would code: a suppressed finding or a "
                  "redrawn trust boundary is a security decision.")
        if action not in report["next_actions"]:
            report["next_actions"].append(action)
    if knowledge.get("error"):
        _gap(report, "",
             f"The knowledge export in the base commit could not be read ({knowledge['error']}); "
             "the scan ran without it.",
             "Regenerate the export with scripts/knowledge.py export.")
    report["knowledge"] = knowledge


def build_report(state: MantisState, diff: str, changed: Dict[str, List[int]],
                 scan_results: List[Dict[str, Any]], skipped: List[str],
                 log_path: Path, fail_on: str, max_tokens: int = 0,
                 daily: Optional[Dict[str, Any]] = None,
                 moves: Optional[Dict[str, Any]] = None,
                 fail_closed: bool = False,
                 knowledge: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """check_change over the change set, plus what this run failed to cover.

    The gate gets both views: the diff text for changed lines, and the
    authoritative file list so a file git rendered without hunks is still
    gated (with no line information, which the gate treats as `direct`).
    It also gets the renames and deletions, so a known finding follows its
    file.

    Two verdicts come out. `findings_verdict` is what the findings say,
    nothing else. `verdict`, the one shown, is that floored to REVIEW when
    any changed file was not fully audited, because a person should know.
    Which of the two fails the job is `fail-on` and `fail-closed`'s business
    (exit_code_for).
    """
    moves = moves or {}
    report = check_change(state, files=list(changed), diff=diff,
                          renamed=moves.get("renamed"), deleted=moves.get("deleted"),
                          include_coverage=False)
    report.setdefault("reasons", [])
    report.setdefault("next_actions", [])
    report["findings_verdict"] = report["verdict"]
    report["coverage"] = {"status": COVERAGE_COMPLETE, "unaudited": []}
    over_budget = [r["file"] for r in scan_results if r["status"] == SCAN_OVER_BUDGET]
    # The gate reports a file with no coverage row as "never scanned". For a
    # file this run tried and could not finish, the scan result says why,
    # which is the better reason; the gate's is kept for everything else.
    accounted = {r["file"] for r in scan_results if r["status"] != SCAN_DONE} | set(skipped)
    for g in report.pop("coverage_gaps", None) or []:
        if g.get("file") and g["file"] in accounted:
            continue
        _gap(report, g.get("file") or "", g["reason"], g.get("action") or "")
    for r in scan_results:
        if r["status"] in (SCAN_FAILED, SCAN_TIMED_OUT):
            _gap(report, r["file"],
                 f"Scan of '{r['file']}' {r['status'].replace('_', ' ')}: its content is unaudited.",
                 "Check the scan log and re-run the workflow.")
        elif r["status"] == SCAN_PAUSED:
            # The pipeline stops cleanly at a ceiling with whatever it found
            # so far stored, but it records no coverage for a cut-off
            # campaign, so the gate cannot treat the file as audited.
            trigger = r.get("pause_trigger") or ""
            if trigger in ("token_budget", "campaign_tokens"):
                what, fix = "its share of the run token budget", "Raise max-tokens to let the scan finish."
            elif trigger == "llm_calls_limit":
                what, fix = "its LLM call ceiling", "Raise max-llm-calls to let the scan finish."
            else:
                what, fix = "a pipeline ceiling", "Check the scan log; raise max-tokens or max-llm-calls to let the scan finish."
            _gap(report, r["file"],
                 f"Scan of '{r['file']}' paused at {what} before finishing: coverage is partial.",
                 fix)
    if over_budget:
        if daily and daily["run_budget"] < MIN_SCAN_ALLOWANCE:
            reason = (f"The project's daily token budget is spent ({int(daily['used_before_run'] or 0):,} "
                      f"of {int(daily['budget']):,} tokens served in the last 24 hours), so "
                      f"{len(over_budget)} changed file(s) were not scanned: " + ", ".join(over_budget) + ".")
            action = "Wait for the window to pass, or raise daily-token-budget."
        else:
            reason = (f"{len(over_budget)} changed file(s) were not scanned because the run token "
                      f"budget was spent: " + ", ".join(over_budget) + ".")
            action = "Raise max-tokens or split the pull request."
        for f in over_budget:
            report["coverage"]["unaudited"].append({"file": f, "reason": reason, "action": action})
        report["reasons"].append(reason)
        if action not in report["next_actions"]:
            report["next_actions"].append(action)
    if skipped:
        reason = (f"{len(skipped)} changed file(s) over the max-files cap were not scanned: "
                  + ", ".join(skipped) + ".")
        action = "Raise max-files or split the pull request."
        for f in skipped:
            report["coverage"]["unaudited"].append({"file": f, "reason": reason, "action": action})
        report["reasons"].append(reason)
        if action not in report["next_actions"]:
            report["next_actions"].append(action)
    if knowledge:
        _apply_knowledge(report, knowledge)
        report["findings_verdict"] = report["verdict"]
    unaudited = report["coverage"]["unaudited"]
    if unaudited:
        audited_files = {r["file"] for r in scan_results if r["status"] == SCAN_DONE}
        report["coverage"]["status"] = COVERAGE_PARTIAL if audited_files else COVERAGE_NONE
        if report["verdict"] == VERDICT_PASS:
            report["verdict"] = VERDICT_REVIEW
    report["scan"] = {
        "files": [r["file"] for r in scan_results],
        "results": scan_results,
        "skipped": skipped,
        "over_budget": over_budget,
        "log": str(log_path),
    }
    report["usage"] = usage_summary(scan_results, max_tokens, daily)
    report["fail_on"] = fail_on
    report["fail_closed"] = bool(fail_closed)
    report["exit_code"] = exit_code_for(report["findings_verdict"], fail_on,
                                        fail_closed=fail_closed,
                                        coverage=report["coverage"]["status"])
    return report


def usage_summary(scan_results: List[Dict[str, Any]], max_tokens: int,
                  daily: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The run's model usage: what was charged against the budget, in total.

    `tokens` is the sum of what each scan was charged (its raw count, or its
    whole allowance when it left no account), so it is an upper bound on
    what the provider bills. `llm_calls` is None when any scan left no
    account, since a sum with a hole in it is not a count. `daily`, when a
    daily budget is in force, carries the platform's reading before the run
    and the run budget that resulted.
    """
    tokens = sum(int(r.get("tokens") or 0) for r in scan_results)
    calls: Optional[int] = 0
    for r in scan_results:
        if r["status"] == SCAN_OVER_BUDGET:
            continue
        c = r.get("llm_calls")
        if c is None:
            calls = None
            break
        calls += int(c)
    out = {
        "tokens": tokens,
        "llm_calls": calls,
        "max_tokens": int(max_tokens),
        "files_scanned": sum(1 for r in scan_results if r["status"] != SCAN_OVER_BUDGET),
        "files_over_budget": sum(1 for r in scan_results if r["status"] == SCAN_OVER_BUDGET),
    }
    if daily:
        out["daily"] = {"budget": int(daily["budget"]),
                        "used_before_run": int(daily["used_before_run"] or 0),
                        "run_budget": int(daily["run_budget"])}
    return out


def exit_code_for(findings_verdict: str, fail_on: str, fail_closed: bool = False,
                  coverage: str = COVERAGE_COMPLETE) -> int:
    """The job's exit status from the two policies.

    `fail_on` judges the findings: a BLOCK (or, under `review`, a REVIEW)
    that the findings themselves produced fails the job. `fail_closed`
    judges coverage: when on, anything short of every changed file audited
    in full fails the job too; when off, it does not, whatever the findings
    policy -- a scanner that could not look must not be the reason a merge
    stops, unless its owner asked for exactly that.
    """
    if fail_on == "block" and findings_verdict == VERDICT_BLOCK:
        return EXIT_FAILED_GATE
    if fail_on == "review" and findings_verdict in (VERDICT_REVIEW, VERDICT_BLOCK):
        return EXIT_FAILED_GATE
    if fail_closed and coverage != COVERAGE_COMPLETE:
        return EXIT_FAILED_GATE
    return EXIT_OK


# --- Rendering -----------------------------------------------------------------------


def _esc_data(s: Any) -> str:
    return str(s).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _esc_prop(s: Any) -> str:
    return _esc_data(s).replace(":", "%3A").replace(",", "%2C")


def annotation(level: str, message: str, file: str = "", line: Any = None,
               title: str = "") -> str:
    """One workflow command. Properties and data are escaped per GitHub's
    rules so a finding title cannot smuggle in a second command."""
    props = []
    if file:
        props.append(f"file={_esc_prop(file)}")
    if isinstance(line, int) and not isinstance(line, bool) and line > 0:
        props.append(f"line={line}")
    if title:
        props.append(f"title={_esc_prop(title)}")
    head = f"::{level}" + (" " + ",".join(props) if props else "")
    return f"{head}::{_esc_data(message)}"


def _severity(f: Dict[str, Any]) -> str:
    return str(f.get("severity") or f.get("priority") or "unrated").upper()


def _first_line(f: Dict[str, Any]) -> Optional[int]:
    for x in f.get("line_numbers") or []:
        if isinstance(x, int) and not isinstance(x, bool) and x > 0:
            return x
    return None


def render_annotations(report: Dict[str, Any]) -> List[str]:
    """Findings as annotations on the diff, infrastructure notes as plain ones.

    Levels: a direct HIGH/CRITICAL finding is an error when --fail-on would
    fail the job on it and a warning otherwise; other direct findings are
    warnings; same-file-elsewhere and caller-radius findings are notices.
    """
    strict = report.get("fail_on") in ("block", "review")
    buckets: Dict[str, List[str]] = {"error": [], "warning": [], "notice": []}
    for f in report.get("findings") or []:
        rel = f.get("relationship")
        sev = _severity(f)
        if rel == "archived":
            # Found here once; the code moved and a rescan did not report it
            # again. A hint to look, never a verdict: notice level, always.
            level = "notice"
        elif rel == "direct" and sev in BLOCKING_SEVERITIES and strict:
            level = "error"
        elif rel == "direct":
            level = "warning"
        else:
            level = "notice"
        where = {"direct": "in the changed lines",
                 "unrelated_in_file": "in the same file, outside the changed lines",
                 "caller_radius": "in a caller of changed code",
                 "archived": "archived: found here before, the code changed since; worth a second look"
                 }.get(rel, "")
        msg = f"{f.get('title')} [{sev}, {f.get('status')}] {where}.".strip()
        if f.get("cwe"):
            msg += f" {f['cwe']}."
        buckets[level].append(annotation(
            level, msg, file=str(f.get("filepath") or ""), line=_first_line(f),
            title=f"Mantis: {sev}"))
    scan = report.get("scan") or {}
    for r in scan.get("results") or []:
        if r.get("status") in (SCAN_FAILED, SCAN_TIMED_OUT):
            buckets["warning"].append(annotation(
                "warning", f"Mantis scan of {r['file']} {r['status'].replace('_', ' ')}; "
                           f"see the scan log in the step summary.",
                title="Mantis: unscanned"))
    if scan.get("skipped"):
        buckets["warning"].append(annotation(
            "warning", f"{len(scan['skipped'])} changed file(s) not scanned (max-files cap): "
                       + ", ".join(scan["skipped"]),
            title="Mantis: unscanned"))
    if scan.get("over_budget"):
        buckets["warning"].append(annotation(
            "warning", f"{len(scan['over_budget'])} changed file(s) not scanned (token "
                       f"budget spent): " + ", ".join(scan["over_budget"]),
            title="Mantis: unscanned"))
    for entry in (report.get("knowledge") or {}).get("changed") or []:
        status, _, path = str(entry).partition(" ")
        buckets["warning"].append(annotation(
            "warning", f"This pull request changes Mantis's knowledge ({status} {path}); the scan "
                       f"used the base commit's version. Review it as a security decision.",
            file=path if status != "D" else "", title="Mantis: knowledge changed"))
    out: List[str] = []
    for level, lines in buckets.items():
        out.extend(lines[:MAX_ANNOTATIONS_PER_LEVEL])
        if len(lines) > MAX_ANNOTATIONS_PER_LEVEL:
            out.append(annotation(
                level, f"{len(lines) - MAX_ANNOTATIONS_PER_LEVEL} more {level}-level "
                       f"Mantis annotations are listed in the step summary."))
    return out


def _md(value: Any) -> str:
    """Untrusted text made inert for one line of markdown.

    File names come from the pull request; titles, reasons, function names,
    and statuses come from the model or the index after reading it. Any of
    them can carry backticks, brackets, HTML, or newlines, and the step
    summary renders markdown. The repository's sanitizer neutralizes all of
    those and scrubs credentials; this adds only the table-cell separator.
    """
    from core.llm_gateway import safe_markdown_span

    text = safe_markdown_span(str(value if value is not None else ""))
    # The repository sanitizer neutralizes the tags that execute or load;
    # the summary also must not let a title open a heading, a link or a
    # collapsed block, so every angle bracket and ampersand is encoded.
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("|", "\\|")


def render_summary(report: Dict[str, Any]) -> str:
    verdict = report.get("verdict")
    icon = {VERDICT_PASS: "✅", VERDICT_REVIEW: "⚠️", VERDICT_BLOCK: "⛔"}.get(verdict, "")
    lines = [f"## {icon} Mantis PR scan: {verdict}", ""]
    coverage = report.get("coverage") or {}
    if report.get("fail_on") == "none":
        lines.append("Advisory run: the verdict does not fail the job "
                     "(set `fail-on: block` or `review` to change that).")
        lines.append("")
    if coverage.get("status") in (COVERAGE_PARTIAL, COVERAGE_NONE):
        n = len(coverage.get("unaudited") or [])
        what = "No changed file" if coverage["status"] == COVERAGE_NONE else f"{n} changed file(s)"
        if report.get("fail_closed"):
            lines.append(f"**Coverage {coverage['status']}:** {what} "
                         f"{'was' if coverage['status'] == COVERAGE_NONE else 'were'} not fully "
                         "audited, and `fail-closed` is on, so the job fails.")
        else:
            lines.append(f"**Coverage {coverage['status']}:** {what} "
                         f"{'was' if coverage['status'] == COVERAGE_NONE else 'were'} not fully "
                         "audited. The job does not fail for that (`fail-closed` is off); "
                         "the verdict is REVIEW so a person knows.")
        lines.append("")
    findings = report.get("findings") or []
    if findings:
        lines += ["### Findings", "",
                  "| Severity | Finding | Location | Status | Relation |",
                  "| --- | --- | --- | --- | --- |"]
        for f in findings:
            loc = str(f.get("filepath") or "")
            ln = _first_line(f)
            if ln:
                loc += f":{ln}"
            lines.append(f"| {_md(_severity(f))} | {_md(f.get('title'))} | `{_md(loc)}` "
                         f"| {_md(f.get('status'))} | {_md(f.get('relationship'))} |")
        lines.append("")
    reasons = report.get("reasons") or []
    if reasons:
        lines += ["### Why", ""] + [f"- {_md(r)}" for r in reasons] + [""]
    actions = report.get("next_actions") or []
    if actions:
        lines += ["### Next", ""] + [f"- {_md(a)}" for a in actions] + [""]
    blast = report.get("blast_radius") or []
    if blast:
        lines += ["### Changed functions", ""]
        for b in blast:
            callers = b.get("callers") or []
            tail = (f" — {len(callers)} caller(s): "
                    + ", ".join(f"`{_md(c.get('caller'))}`" for c in callers[:5])
                    + (" …" if len(callers) > 5 else "")) if callers else ""
            lines.append(f"- `{_md(b.get('function'))}` in `{_md(b.get('file'))}`{tail}")
        lines.append("")
    scan = report.get("scan") or {}
    results = scan.get("results") or []
    lines += ["### Scan", ""]
    if results:
        many = len({r.get("model") or "" for r in results}) > 1
        lines += (["| File | Model | Result | Tokens | Calls | Seconds |", "| --- | --- | --- | --- | --- | --- |"]
                  if many else ["| File | Result | Tokens | Calls | Seconds |", "| --- | --- | --- | --- | --- |"])
        for r in results:
            calls = r.get("llm_calls")
            model_cell = f" {_md(r.get('model') or '')} |" if many else ""
            lines.append(f"| `{_md(r['file'])}` |{model_cell} {_md(r['status'])} | {int(r.get('tokens') or 0):,} "
                         f"| {calls if calls is not None else '?'} | {r.get('seconds', '')} |")
    else:
        lines.append("No files were scanned.")
    usage = report.get("usage") or {}
    if usage:
        budget = int(usage.get("max_tokens") or 0)
        calls = usage.get("llm_calls")
        daily = usage.get("daily")
        if budget > 0:
            scope = f" of a {budget:,} budget"
        elif daily:
            scope = " (the daily budget left nothing for this run)"
        else:
            scope = " (no run budget)"
        lines.append("")
        lines.append(
            f"Model usage: {int(usage.get('tokens') or 0):,} tokens" + scope
            + (f", {calls} calls" if calls is not None else "")
            + ". Tokens are counted at full price, cached or not; a scan that left no "
              "account is charged its whole allowance.")
        if daily:
            used, cap = int(daily["used_before_run"]), int(daily["budget"])
            lines.append("")
            lines.append(
                f"Daily budget: {used:,} of {cap:,} tokens served to the project in the 24 "
                f"hours before this run; {max(0, cap - used):,} were left for it.")
    if scan.get("skipped"):
        lines.append("")
        lines.append("Not scanned (max-files cap): "
                     + ", ".join(f"`{_md(s)}`" for s in scan["skipped"]))
    if scan.get("over_budget"):
        lines.append("")
        lines.append("Not scanned (token budget spent): "
                     + ", ".join(f"`{_md(s)}`" for s in scan["over_budget"]))
    if report.get("ignored"):
        lines.append("")
        lines.append("Ignored (not code): "
                     + ", ".join(f"`{_md(s)}`" for s in report["ignored"]))
    knowledge = report.get("knowledge") or {}
    if knowledge:
        lines += ["", "### Knowledge", ""]
        imported = knowledge.get("imported")
        if imported:
            lines.append(f"Read from the base commit's `{_md(knowledge['dir'])}`: "
                         f"{int(imported.get('findings', 0)) + int(imported.get('findings_skipped', 0))} "
                         f"known finding(s), {int(imported.get('learnings', 0))} learning(s)"
                         + (", threat model" if imported.get("threat_model") or imported.get("threat_model_md") else "")
                         + (", architecture" if imported.get("architecture") else "")
                         + f", coverage for {int(imported.get('coverage_paths', 0))} path(s).")
        elif knowledge.get("error"):
            lines.append(f"The base commit's `{_md(knowledge['dir'])}` could not be read: "
                         f"{_md(knowledge['error'])}.")
        else:
            lines.append(f"No `{_md(knowledge['dir'])}` in the base commit; the scan started from "
                         "nothing. `scripts/knowledge.py export` after a full scan creates one.")
        if knowledge.get("changed"):
            lines.append("")
            lines.append("Changed by this pull request (reviewed as a security decision; the scan "
                         "used the base's version): "
                         + ", ".join(f"`{_md(c)}`" for c in knowledge["changed"]))
        if knowledge.get("archived"):
            lines.append("")
            lines.append(f"Archived by this refresh ({len(knowledge['archived'])}): the cited lines "
                         "changed and the rescan did not report them again. Not resolved, not "
                         "dismissed; the next look at these files should check:")
            for a in knowledge["archived"]:
                where = str(a.get("filepath") or "")
                if a.get("line_numbers"):
                    where += ":" + ",".join(str(x) for x in a["line_numbers"][:6])
                lines.append(f"- `{_md(where)}` {_md(a.get('title'))}")
        if knowledge.get("kept_open"):
            lines.append("")
            lines.append(f"Left open ({len(knowledge['kept_open'])}): the cited lines changed and a "
                         "rescan by a different model did not report them; only the model that found "
                         "a finding may shelve it.")
            for k in knowledge["kept_open"]:
                lines.append(f"- `{_md(k.get('filepath'))}` {_md(k.get('title'))} (found by "
                             f"{_md(k.get('found_by'))}; not re-found by "
                             f"{_md(', '.join(k.get('not_refound_by') or []))})")
        exported = knowledge.get("exported")
        if exported:
            lines.append("")
            lines.append(f"Knowledge written to `{_md(exported.get('dir'))}`"
                         + (f" as of `{_md(exported['head'][:12])}`" if exported.get("head") else "")
                         + f": {int(exported.get('findings', 0))} finding(s), coverage for "
                         f"{int(exported.get('coverage_paths', 0))} path(s).")
    if scan.get("log"):
        lines.append("")
        lines.append(f"Scan log: `{_md(scan['log'])}`")
    lines.append("")
    return "\n".join(lines)


def _append(path: str, text: str) -> None:
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(text)


def write_report_sarif(state: MantisState, report: Dict[str, Any], path: str) -> Dict[str, Any]:
    """Writes the report's findings as SARIF, descriptions included, and says
    what happened: `{"path", "results", "skipped"}` or `{"path", "error"}`.

    The report lists findings in the gate's short view, which leaves out the
    description; the rows are read back from the run's database by id for
    the export, keeping the view's path (a rename's new one) and status. The
    title and description are model-written from the pull request, so they
    go out through the repository's sanitizer for SARIF
    (sanitize_markdown_text: terminal control sequences stripped,
    credentials scrubbed, executable HTML tags entity-encoded) and then
    core.sarif's own, into SARIF's plain-text message; no markdown field is
    written. Never raises: the export is a copy of the verdict's inputs, and
    a failure to write it must not change the verdict or the exit code.
    """
    try:
        from core.database import read_findings
        from core.llm_gateway import sanitize_markdown_text
        from core.sarif import write_sarif

        # The findings the gate counted, as it counted them: its open set
        # includes 'reported', which core.database counts as suppressed, so
        # build_sarif's own filter is not re-applied; archived notices are
        # never a verdict input and stay out.
        views = [f for f in report.get("findings") or []
                 if isinstance(f, dict) and f.get("relationship") != "archived"]
        rows = {r.get("id"): r for r in read_findings(state.db_path)} if views else {}
        findings = []
        for v in views:
            row = rows.get(v.get("id"))
            if row is None:
                continue
            findings.append({**row, "filepath": v.get("filepath") or row.get("filepath"),
                             "status": v.get("status") or row.get("status"),
                             "title": sanitize_markdown_text(str(row.get("title") or "")),
                             "description": sanitize_markdown_text(str(row.get("description") or ""))})
        count, skipped = write_sarif(path, findings, scan_root=str(state.repo), include_suppressed=True)
        return {"path": path, "results": count, "skipped": skipped}
    except Exception as exc:
        return {"path": path, "error": f"{type(exc).__name__}: {exc}"}


# --- Entry point ---------------------------------------------------------------------


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Mantis pull-request scan (GitHub Action driver)")
    p.add_argument("--repo", default=os.environ.get("GITHUB_WORKSPACE") or ".",
                   help="Checkout of the pull request (default: $GITHUB_WORKSPACE or cwd)")
    p.add_argument("--base", default="", help="Base commit of the pull request")
    p.add_argument("--head", default="HEAD", help="Head revision (default: HEAD)")
    p.add_argument("--model", default="", help="Model id; empty uses the workflow default")
    p.add_argument("--models", default="",
                   help="Comma-separated model ids: every changed file is scanned by every "
                        "model, the run budget shared over all of it, and each finding and "
                        "coverage row keeps its model. For building knowledge with more than "
                        "one model; a pull-request check wants one. Overrides --model.")
    p.add_argument("--api-base", default="", help="Custom LLM API base URL")
    p.add_argument("--max-llm-calls", type=int, default=400,
                   help="LLM call ceiling per changed file: a loop guard, not the spend control "
                        "(that is --max-tokens). A scan that reaches it pauses with its findings so far "
                        "stored and the file is reported as partially covered. 0 = workflow default")
    p.add_argument("--max-tokens", default=str(DEFAULT_MAX_TOKENS),
                   help="Token budget for the whole run, e.g. 4M or 500k; every token "
                        "counts at full price, cached or not. Shared out equally over the "
                        "files still to scan; files the budget cannot reach are reported "
                        "unscanned. 0 removes the run budget (each scan keeps the "
                        f"pipeline's own ceiling). Default: {DEFAULT_MAX_TOKENS:,}")
    p.add_argument("--max-input-tokens", type=int, default=DEFAULT_MAX_INPUT_TOKENS,
                   help="Input tokens one model request may carry; larger requests are "
                        "refused before dispatch. 0 leaves only the model's own window. "
                        f"Default: {DEFAULT_MAX_INPUT_TOKENS:,}")
    p.add_argument("--daily-token-budget", default=str(DEFAULT_DAILY_TOKEN_BUDGET),
                   help="Tokens the Google Cloud project may be served in any 24 hours, "
                        "read from Cloud Monitoring before the run; the run's budget is "
                        "cut to what is left, and nothing is launched when nothing is. "
                        "Needs roles/monitoring.viewer; a budget that cannot be checked is "
                        f"a setup error. 0 disables the check. Default: {DEFAULT_DAILY_TOKEN_BUDGET:,}")
    p.add_argument("--max-files", type=int, default=25,
                   help="Changed files scanned per run; the rest are reported unscanned")
    p.add_argument("--ignore", default=None,
                   help="Comma-separated fnmatch patterns of changed files to leave out "
                        "of the scan and the gate (default: common non-code files; "
                        "pass '' to ignore nothing)")
    p.add_argument("--per-file-timeout", type=float, default=1800.0,
                   help="Seconds before one file's scan is abandoned (0 = none); with "
                        "--one-process, the run's timeout is this times the files. A scan "
                        "still writing output at its timeout runs on, up to "
                        f"{TIMEOUT_EXTENSION_FACTOR:g} times it, until it falls silent for "
                        f"{TIMEOUT_STALL_SECONDS:.0f}s (or the timeout, when shorter)")
    p.add_argument("--one-process", action="store_true",
                   help="Scan all the changed files in one pipeline run (per model) rather than "
                        "one run per file, so what a run does once is not paid per file. Each "
                        "campaign gets an equal share of the budget and each file its "
                        "campaign's status.")
    p.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="none",
                   help="What the findings do to the job. none: advisory; block: fail on "
                        "BLOCK; review: fail on REVIEW or BLOCK")
    p.add_argument("--fail-closed", action="store_true",
                   help="Fail the job when Mantis could not look: a setup failure, a model "
                        "outage, a changed file not fully scanned, a crash. Off by default, "
                        "so a broken scanner never stops a merge; on, a green check means "
                        "every changed file was audited.")
    p.add_argument("--output-json", default="", help="Write the full report here")
    p.add_argument("--output-sarif", default="",
                   help="Also write the gated findings, descriptions included, as SARIF 2.1.0 "
                        "here (for GitHub code scanning). A failed write is reported and never "
                        "changes the verdict.")
    p.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY", ""),
                   help="Append the markdown summary here (default: $GITHUB_STEP_SUMMARY)")
    p.add_argument("--github-output", default=os.environ.get("GITHUB_OUTPUT", ""),
                   help="Append verdict= and report= here (default: $GITHUB_OUTPUT)")
    p.add_argument("--no-annotations", action="store_true",
                   help="Do not print workflow-command annotations")
    p.add_argument("--state-dir", default="",
                   help="Parent directory for this run's database, index, and log; a fresh "
                        "subdirectory is created per run. Must be outside the repository "
                        "(default: $RUNNER_TEMP, else the system temp directory)")
    p.add_argument("--radius", type=int, default=0, choices=(0, 1),
                   help="Also scan the files of direct callers of changed functions (1), "
                        "subject to max-files. Default 0: changed files only.")
    p.add_argument("--export-knowledge", default="",
                   help="After the run, write the merged knowledge (the base commit's export plus "
                        "what this run found) as text to this directory, recording --head as the "
                        "commit it reflects, and archive known findings whose lines this change "
                        "rewrote and the rescan did not report again. For the refresh workflow on "
                        "trusted code; a pull-request scan must not set it.")
    return p.parse_args(argv)


def _not_run(summary_path: str, message: str, fail_closed: bool = False,
             github_output: str = "") -> int:
    """A setup failure: nothing was scanned and there is no verdict.

    Exit 3 under --fail-closed, so the check is red for the workflow's owner
    to fix. Otherwise exit 0: the summary and an annotation say what went
    wrong, and the pull request is not held up by it. Never a verdict,
    never a silent pass -- the output names it NOT_RUN.
    """
    level = "error" if fail_closed else "warning"
    print(annotation(level, message, title="Mantis: cannot scan"))
    policy = ("`fail-closed` is on, so the job fails." if fail_closed else
              "`fail-closed` is off, so the job passes without a verdict; "
              "set it to fail instead.")
    _append(summary_path, f"## ⛔ Mantis PR scan: not run\n\n{_md(message)}\n\n{policy}\n")
    _append(github_output, "verdict=NOT_RUN\nreport=\n")
    return EXIT_INFRA if fail_closed else EXIT_OK


def main(argv: Optional[List[str]] = None,
         env: Optional[Dict[str, str]] = None) -> int:
    args = parse_args(argv)
    env_map = dict(os.environ if env is None else env)
    repo = Path(args.repo).resolve()
    try:
        try:
            from core.budget import parse_token_budget

            max_tokens = parse_token_budget(args.max_tokens)
            daily_budget = parse_token_budget(args.daily_token_budget)
        except ValueError as exc:
            raise InfraError(f"--max-tokens / --daily-token-budget: {exc}")
        if args.max_input_tokens < 0:
            raise InfraError("--max-input-tokens cannot be negative.")
        if not repo.is_dir():
            raise InfraError(f"--repo '{args.repo}' is not a directory.")
        if _git(repo, "rev-parse", "--is-inside-work-tree", check=False).returncode != 0:
            raise InfraError(f"--repo '{args.repo}' is not a git checkout.")
        models = [m.strip() for m in str(args.models or "").split(",") if m.strip()] or [args.model]
        for m in models:
            reason = credential_preflight(env_map, api_base=args.api_base, model=m)
            if reason:
                raise InfraError(reason)
        # The day's spend, from the platform, before anything is launched. A
        # configured daily budget that cannot be checked is a setup failure:
        # running without the check would make the number a decoration.
        used_today: Optional[int] = None
        run_budget = max_tokens
        if daily_budget > 0:
            try:
                used_today = tokens_served_today(env_map)
            except DailyMeterUnavailable as exc:
                raise InfraError(
                    f"daily-token-budget is set but the project's token meter could not be "
                    f"read: {exc}")
            run_budget = run_budget_for_today(max_tokens, daily_budget, used_today)
        changed_all, diff, moves = pr_changes(repo, args.base, args.head)
        state_dir = fresh_state_dir(repo, args.state_dir)
    except InfraError as exc:
        return _not_run(args.summary, str(exc), fail_closed=args.fail_closed,
                        github_output=args.github_output)

    # All mutable state lives in the fresh directory, never in the checkout.
    state = MantisState(str(repo))
    state.home = state_dir
    state.db_path = str(state_dir / "knowledge.db")
    # Mantis's own state in the repository is never scanned or gated,
    # whatever the ignore list says; it is read below, as of the base.
    patterns = parse_ignore(args.ignore) + [f"{TOOL_STATE_DIR}/*"]
    ignored = [f for f in changed_all if is_ignored(f, patterns)]
    changed = {f: lines for f, lines in changed_all.items() if f not in ignored}
    if ignored:
        diff = filter_diff(diff, set(changed))
    rels, skipped = select_scan_files(state, changed, args.max_files)
    state.ensure_home()
    log_path = state.home / "pr_scan.log"
    # A radius of 1 adds the files of direct callers, after the changed files
    # so the max-files cap always favours the change itself.
    radius_files: List[str] = []
    if args.radius > 0 and changed:
        radius_files = caller_files(state, changed, diff)
        extra = [r for r in radius_files if r not in rels and r not in skipped]
        room = (args.max_files - len(rels)) if args.max_files > 0 else len(extra)
        rels += extra[:max(0, room)]
        skipped += extra[max(0, room):]

    # The repository's memory, as of the base commit. Imported into this
    # run's database so the gate sees known findings and coverage, and handed
    # to every scan so the model starts from the threat model and
    # architecture. The pull request's own edits to it are a finding.
    from core.knowledge import KNOWLEDGE_DIR, KnowledgeImportError, import_knowledge

    knowledge: Dict[str, Any] = {"dir": KNOWLEDGE_DIR, "source": None, "imported": None,
                                 "error": "", "changed": knowledge_edits(repo, args.base, args.head)}
    knowledge_dir = ""
    extracted, note = knowledge_from_base(repo, args.base, state_dir / "knowledge")
    if extracted is not None:
        try:
            knowledge["imported"] = import_knowledge(state.db_path, str(extracted), run_id="pr-scan",
                                                     repo_root=str(repo))
            knowledge["source"] = f"base commit {args.base[:12]}"
            knowledge_dir = str(extracted)
        except KnowledgeImportError as exc:
            knowledge["error"] = str(exc)
    elif note:
        knowledge["error"] = note
    # What the base knew before this run wrote anything: the refresh's archive
    # rule compares the rescan against it. A pull-request scan never archives
    # (an imported finding on rewritten lines stays open and blocks: the
    # change has to fix it or a person has to dismiss it), so this is only
    # read when --export-knowledge says the run is a trusted refresh.
    prior_open: List[Dict[str, Any]] = []
    first_new_id = 0
    if args.export_knowledge and knowledge_dir:
        from core.database import read_findings
        from scripts.mcp_server import OPEN_FINDING_STATUSES

        rows = read_findings(state.db_path)
        prior_open = [r for r in rows if str(r.get("status") or "").lower() in OPEN_FINDING_STATUSES]
        first_new_id = max([int(r.get("id") or 0) for r in rows] + [0]) + 1
    daily = {"budget": daily_budget, "used_before_run": used_today,
             "run_budget": run_budget} if daily_budget > 0 else None
    if rels and daily and run_budget < MIN_SCAN_ALLOWANCE:
        # The day's budget is spent before this run: launch nothing, report
        # every file over budget. The index is still built, at no model cost,
        # so the gate can report the blast radius it can see.
        results = [{"file": r, "returncode": None, "status": SCAN_OVER_BUDGET,
                    "seconds": 0.0, "tokens": 0, "llm_calls": 0, "granted": 0,
                    "pause_trigger": ""} for r in rels]
        try:
            reindex(state)
        except Exception:
            pass
    else:
        results = run_scans(state, rels, args.max_llm_calls, args.model, args.api_base,
                            args.per_file_timeout, log_path, env=env_map,
                            max_tokens=run_budget,
                            max_input_tokens=args.max_input_tokens,
                            daily=daily,
                            knowledge_dir=knowledge_dir,
                            models=models,
                            one_process=args.one_process) if rels else []
    rejected = next((r for r in results if r["status"] == SCAN_AUTH_REJECTED), None)
    if rejected:
        return _not_run(
            args.summary,
            f"The model provider rejected the credentials (pipeline exit {EXIT_AUTH}) while "
            f"scanning '{rejected['file']}'. Check the credentials and model configured on "
            f"the workflow step; the provider's message is in the scan log: {log_path}",
            fail_closed=args.fail_closed, github_output=args.github_output)
    if rels and all(r["status"] == SCAN_FAILED and r["returncode"] == -1 for r in results):
        return _not_run(args.summary, f"Every scan failed to launch; see the scan log: {log_path}",
                        fail_closed=args.fail_closed, github_output=args.github_output)

    # Refresh only: shelve what the change rewrote and the rescan did not
    # find again, then write the merged knowledge out for the next base.
    if args.export_knowledge:
        head_sha = _git(repo, "rev-parse", "--verify", "--quiet", "--end-of-options",
                        f"{args.head}^{{commit}}", check=False).stdout.strip()
        if prior_open:
            # A file counts as examined when its researcher pass completed,
            # even if the run paused afterwards: the pass's report is in.
            # A finished run counts regardless (older pipelines report no
            # nodes).
            # Per model: a finding is shelved only by the model that found
            # it. The scan's model id is what the pipeline recorded for its
            # run, so the two are compared in the same spelling.
            from core.config import normalize_model_id
            examined_by: Dict[str, List[str]] = {}
            for r in results:
                if r.get("examined") or r["status"] == SCAN_DONE:
                    examined_by.setdefault(normalize_model_id(r.get("model") or "") if r.get("model") else "",
                                           []).append(r["file"])
            kept: List[Dict[str, Any]] = []
            knowledge["archived"] = archive_rewritten(
                state.db_path, prior_open, changed, examined_by, first_new_id,
                note=(f"archived by knowledge refresh at {head_sha[:12]}: the cited lines changed "
                      f"between {args.base[:12]} and {head_sha[:12]} and a rescan of the file did "
                      "not report this finding again. Not resolved, not dismissed: check again."),
                kept=kept)
            if kept:
                knowledge["kept_open"] = kept
        try:
            from core.knowledge import export_knowledge

            knowledge["exported"] = export_knowledge(state.db_path, args.export_knowledge,
                                                     repo_root=str(repo), head=head_sha)
            knowledge["exported"]["dir"] = args.export_knowledge
        except Exception as exc:
            knowledge["error"] = (knowledge.get("error") or "") + f" export failed: {exc}"

    if changed_all and not changed:
        # Every changed file matched an ignore pattern: nothing the pipeline
        # could audit, by the consumer's explicit choice. Say so and pass,
        # rather than echoing check_change's "no changed files" REVIEW.
        report = {
            "verdict": VERDICT_PASS,
            "reasons": [f"All {len(ignored)} changed file(s) match the ignore patterns; "
                        "nothing to audit."],
            "blast_radius": [], "findings": [], "next_actions": [],
            "scan": {"files": [], "results": [], "skipped": [], "over_budget": [],
                     "log": str(log_path)},
            "usage": usage_summary([], run_budget, daily),
            "fail_on": args.fail_on, "fail_closed": bool(args.fail_closed), "exit_code": EXIT_OK,
            "findings_verdict": VERDICT_PASS,
            "coverage": {"status": COVERAGE_COMPLETE, "unaudited": []},
        }
        _apply_knowledge(report, knowledge)
        # A knowledge edit is a finding-class REVIEW; a knowledge read error
        # is a coverage gap. Both are decided the same way as everywhere else.
        report["findings_verdict"] = report["verdict"]
        if report["coverage"]["unaudited"]:
            report["coverage"]["status"] = COVERAGE_NONE
            if report["verdict"] == VERDICT_PASS:
                report["verdict"] = VERDICT_REVIEW
        report["exit_code"] = exit_code_for(report["findings_verdict"], args.fail_on,
                                            fail_closed=args.fail_closed,
                                            coverage=report["coverage"]["status"])
    else:
        report = build_report(state, diff, changed, results, skipped, log_path,
                              args.fail_on, max_tokens=run_budget, daily=daily,
                              moves=moves, fail_closed=args.fail_closed,
                              knowledge=knowledge)
        if not changed_all and not moves.get("deleted"):
            report["reasons"].insert(0, "The pull request changes no scannable files.")
    report["ignored"] = ignored
    report["renamed"] = moves.get("renamed") or {}
    report["deleted"] = moves.get("deleted") or []
    report["state_dir"] = str(state_dir)

    if args.output_sarif:
        # After the verdict and exit code are final: a SARIF failure is
        # recorded in the report and said on stdout, and changes neither.
        report["sarif"] = write_report_sarif(state, report, args.output_sarif)
        if report["sarif"].get("error"):
            from core.llm_gateway import sanitize_egress_text

            print(sanitize_egress_text(
                f"mantis: SARIF not written to {args.output_sarif}: {report['sarif']['error']}"))

    if args.output_json:
        from core.llm_gateway import sanitize_egress_data

        Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output_json).write_text(
            json.dumps(sanitize_egress_data(report), indent=2, default=str), encoding="utf-8")
    if not args.no_annotations:
        for line in render_annotations(report):
            print(line)
    _append(args.summary, render_summary(report))
    _append(args.github_output,
            f"verdict={report['verdict']}\nreport={args.output_json}\n")
    usage = report.get("usage") or {}
    print(f"mantis: verdict {report['verdict']} "
          f"({len(report.get('findings') or [])} finding(s), "
          f"{usage.get('files_scanned', len(results))} file(s) scanned, "
          f"{usage.get('files_over_budget', 0)} over budget, {len(skipped)} skipped; "
          f"{int(usage.get('tokens') or 0):,} tokens)")
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())

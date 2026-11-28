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

"""Export/import the knowledge base, inspect regressions, or render a cumulative risk report.

    scripts/knowledge.py report --db knowledge.db --repo /path/to/repo
    scripts/knowledge.py regressions --db knowledge.db
    scripts/knowledge.py export --db knowledge.db --repo /path/to/repo
    scripts/knowledge.py import --db knowledge.db --repo /path/to/repo

Export is a deliberate step after a scan, not something the scan does: the
pipeline never writes into the target it audits (INV-4), and the operator
decides what gets committed. The default location is `<repo>/.mantis/knowledge`.

Import here seeds a database with findings, learnings, and coverage. The
threat model and architecture are recorded under the run id given with
--run-id (default "imported"); a run that should see them through its own
tools imports at start with `main.py --import-knowledge` instead.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from core.knowledge import (  # noqa: E402
    KNOWLEDGE_DIR,
    KnowledgeImportError,
    build_posture_report,
    describe,
    export_knowledge,
    import_knowledge,
    read_head,
    render_posture_markdown,
)


def _atomic_write_output(path: Path, text: str) -> None:
    parent = path.parent
    if parent:
        parent.mkdir(parents=True, exist_ok=True)
    tmp_path = Path(f"{path}.{os.getpid()}.tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
        os.replace(tmp_path, path)
    except BaseException:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
        raise


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    ex = sub.add_parser("export", help="write the knowledge base as text")
    ex.add_argument("--db", default="knowledge.db", help="knowledge database (default: knowledge.db)")
    ex.add_argument("--repo", required=True, help="repository root the scan targeted; paths are made relative to it")
    ex.add_argument("--out", default="", help=f"output directory (default: <repo>/{KNOWLEDGE_DIR})")
    ex.add_argument("--head", default="", help="commit SHA to record as manifest `head` (default: repository HEAD)")
    ex.add_argument(
        "--preserve-head",
        action="store_true",
        help="keep the existing manifest.json `head` commit when present instead of advancing it to HEAD",
    )
    im = sub.add_parser("import", help="read a knowledge export into a database")
    im.add_argument("--db", default="knowledge.db")
    im.add_argument("--repo", required=True, help="repository root the paths are relative to")
    im.add_argument("--from", dest="src", default="", help=f"export directory (default: <repo>/{KNOWLEDGE_DIR})")
    im.add_argument("--run-id", default="imported", help="run id the threat model and architecture are recorded under")
    bf = sub.add_parser(
        "backfill-coverage",
        help="record, for completed campaigns that predate the content ledger, the content "
             "their files had, so --scan-mode changed can tell what moved without a fresh whole scan",
    )
    bf.add_argument("--db", default="knowledge.db")
    bf.add_argument("--repo", required=True, help="repository root the campaigns scanned")
    bf.add_argument("--at", default="", help="the git commit the campaigns scanned, when the run did not record one")
    bf.add_argument("--assume-unchanged", action="store_true",
                    help="no commit known: record the working tree as it is now, asserting nothing was edited since the scans")
    bf.add_argument("--exclude", action="append", default=[], help="exclude pattern, as given to the scan (repeatable)")
    bf.add_argument("--dry-run", action="store_true", help="say what would be recorded; write nothing")
    rg = sub.add_parser(
        "regressions",
        help="show per-finding regression check verdicts recorded by --scan-mode changed",
    )
    rg.add_argument("--db", default="knowledge.db", help="knowledge database (default: knowledge.db)")
    rg.add_argument("--run-id", default="", help="filter to a specific run_id (default: latest run with checks)")
    rg.add_argument(
        "--outcome",
        default="all",
        choices=("all", "fixed", "still_present", "inconclusive"),
        help="filter by recorded outcome (default: all)",
    )
    rp = sub.add_parser(
        "report",
        help="generate the cumulative open risk posture across all runs (deduplicated by lineage)",
    )
    rp.add_argument("--db", default="knowledge.db", help="knowledge database (default: knowledge.db)")
    rp.add_argument(
        "--repo",
        default="",
        help="optional repository (or subfolder) root to scope findings and normalize paths",
    )
    rp.add_argument(
        "--format",
        default="markdown",
        choices=("markdown", "md", "json", "sarif"),
        help="output format (default: markdown)",
    )
    rp.add_argument("--out", default="", help="write output to file instead of stdout")
    rp.add_argument(
        "--include-patch-verified",
        action="store_true",
        default=True,
        help="include patch_verified findings (default: on, since sandbox-verified patches are not applied to the host checkout)",
    )
    rp.add_argument(
        "--exclude-patch-verified",
        action="store_true",
        help="exclude patch_verified findings from the open posture",
    )
    rp.add_argument(
        "--include-unrooted",
        action="store_true",
        help="include legacy findings from runs with no recorded target_root when --repo is given",
    )
    rp.add_argument(
        "--all-repos",
        action="store_true",
        help="allow mixing findings across multiple repositories when --repo is omitted",
    )
    rp.add_argument(
        "--snapshot",
        action="store_true",
        help="read an offline read-only database snapshot with SQLite immutable=1 (refuses if -wal/-journal/-shm exists)",
    )
    args = p.parse_args(argv)

    if args.cmd == "report":
        import sqlite3
        from core.database import distinct_run_target_roots
        from core.paths import resolve_db_path, validate_data_path

        # Anchor relative --db paths strictly to the Mantis install directory
        # via resolve_db_path (matching `regressions` and `database.py`), never
        # preferring an untrusted `knowledge.db` sitting in the current working directory.
        try:
            resolved_db = resolve_db_path(str(args.db or ""))
        except (PermissionError, ValueError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not os.path.exists(resolved_db):
            print(f"error: no database at {args.db}", file=sys.stderr)
            return 2
        immutable_snap = bool(args.snapshot)
        repo_opt = ""
        if args.repo:
            repo_opt = os.path.realpath(args.repo)
            if not os.path.isdir(repo_opt):
                print(f"error: --repo {args.repo} is not a directory", file=sys.stderr)
                return 2
        elif not args.all_repos:
            try:
                recorded_roots = distinct_run_target_roots(resolved_db, immutable_snapshot=immutable_snap)
            except (RuntimeError, PermissionError, ValueError, OSError, sqlite3.Error) as exc:
                print(f"error: failed to read database {resolved_db}: {exc}", file=sys.stderr)
                return 2
            if len(recorded_roots) > 1:
                print(
                    "error: database contains runs for multiple repositories; pass --repo <path> "
                    "to scope to one repository (or --all-repos to combine them):\n  "
                    + "\n  ".join(recorded_roots),
                    file=sys.stderr,
                )
                return 2
        resolved_out: Path | None = None
        if args.out:
            resolved_out, out_err = validate_data_path(args.out)
            if out_err or resolved_out is None:
                print(f"error: {out_err or 'invalid --out path'}", file=sys.stderr)
                return 2

        include_pv = not bool(args.exclude_patch_verified)
        include_unrooted = bool(args.include_unrooted)
        fmt = "markdown" if args.format == "md" else args.format
        if fmt == "sarif":
            from core.database import current_open_findings
            from core.sarif import SarifExportError, build_sarif, validate_sarif, write_sarif

            try:
                raw = current_open_findings(
                    resolved_db,
                    repo_root=repo_opt or None,
                    include_patch_verified=include_pv,
                    include_unrooted=include_unrooted,
                    strict=True,
                    immutable_snapshot=immutable_snap,
                )
            except (RuntimeError, PermissionError, ValueError, OSError, sqlite3.Error) as exc:
                print(f"error: failed to read database {resolved_db}: {exc}", file=sys.stderr)
                return 2
            counts = raw.get("counts") or {}
            if (
                repo_opt
                and int(counts.get("total_db_findings", 0)) > 0
                and int(counts.get("open", 0)) == 0
                and int(counts.get("mitigated", 0)) == 0
                and int(counts.get("archived", 0)) == 0
            ):
                print(
                    f"warning: database holds {int(counts['total_db_findings'])} finding(s), but none "
                    f"matched --repo {repo_opt} ({int(counts.get('other_repo_omitted', 0))} from other "
                    f"repos, {int(counts.get('unrooted_omitted', 0))} unrooted legacy). Verify the "
                    "checkout path or pass --include-unrooted.",
                    file=sys.stderr,
                )
            run_props = {
                "cumulative_posture": True,
                "runs_included": int(counts.get("runs", 0)),
                "mitigated_closed": int(counts.get("mitigated", 0)),
                "archived_closed": int(counts.get("archived", 0)),
                "patch_verified_included": int(counts.get("patch_verified", 0)),
                "unrooted_omitted": int(counts.get("unrooted_omitted", 0)),
                "untriaged_omitted": int(counts.get("untriaged_omitted", 0)),
            }
            try:
                if resolved_out is not None:
                    count, skipped = write_sarif(
                        str(resolved_out),
                        raw["findings"],
                        scan_root=repo_opt,
                        run_properties=run_props,
                    )
                    print(f"Wrote SARIF report ({count} finding(s)) to {resolved_out}")
                else:
                    doc, skipped = build_sarif(
                        raw["findings"],
                        scan_root=repo_opt,
                        run_properties=run_props,
                    )
                    problems = validate_sarif(doc)
                    if problems:
                        raise SarifExportError("Refusing to emit invalid SARIF:\n  " + "\n  ".join(problems))
                    print(json.dumps(doc, indent=2, allow_nan=False))
            except (SarifExportError, OSError, ValueError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            for reason in skipped:
                print(f"warning: skipped finding in SARIF export: {reason}", file=sys.stderr)
            return 0

        try:
            posture = build_posture_report(
                resolved_db,
                repo_root=repo_opt or None,
                include_patch_verified=include_pv,
                include_unrooted=include_unrooted,
                strict=True,
                immutable_snapshot=immutable_snap,
            )
        except (RuntimeError, PermissionError, ValueError, OSError, sqlite3.Error) as exc:
            print(f"error: failed to read database {resolved_db}: {exc}", file=sys.stderr)
            return 2
        counts = posture.get("counts") or {}
        if (
            repo_opt
            and int(counts.get("total_db_findings", 0)) > 0
            and int(counts.get("open", 0)) == 0
            and int(counts.get("mitigated", 0)) == 0
            and int(counts.get("archived", 0)) == 0
        ):
            print(
                f"warning: database holds {int(counts['total_db_findings'])} finding(s), but none "
                f"matched --repo {repo_opt} ({int(counts.get('other_repo_omitted', 0))} from other "
                f"repos, {int(counts.get('unrooted_omitted', 0))} unrooted legacy). Verify the "
                "checkout path or pass --include-unrooted.",
                file=sys.stderr,
            )
        if fmt == "json":
            rendered = json.dumps(posture, indent=2, allow_nan=False) + "\n"
        else:
            rendered = render_posture_markdown(posture)
        if resolved_out is not None:
            try:
                _atomic_write_output(resolved_out, rendered)
            except OSError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            total = int((posture.get("risk_posture") or {}).get("total", 0))
            print(f"Wrote {fmt} posture report ({total} open finding(s)) to {resolved_out}")
        else:
            print(rendered, end="")
        return 0

    if args.cmd == "regressions":
        if not os.path.exists(args.db):
            print(f"error: no database at {args.db}", file=sys.stderr)
            return 2
        from core.database import read_findings, read_regression_checks
        from core.llm_gateway import sanitize_egress_text

        checks = read_regression_checks(args.db, run_id=args.run_id or None)
        if not checks:
            print("No regression checks recorded.")
            return 0
        target_run = str(args.run_id or "").strip()
        if not target_run:
            target_run = str(checks[0].get("run_id") or "")  # newest first
            checks = [c for c in checks if str(c.get("run_id") or "") == target_run]
        if args.outcome != "all":
            checks = [c for c in checks if str(c.get("outcome") or "").lower() == args.outcome]
        findings_by_id = {int(f["id"]): f for f in read_findings(args.db) if f.get("id") is not None}
        # Show the latest check per prior_finding_id (preferring still_present, then fixed, then inconclusive)
        latest: dict[int, dict] = {}
        rank = {"still_present": 3, "fixed": 2, "inconclusive": 1}
        for c in checks:
            pid = int(c.get("prior_finding_id") or 0)
            if pid not in latest or rank.get(str(c.get("outcome") or ""), 0) > rank.get(str(latest[pid].get("outcome") or ""), 0):
                latest[pid] = c
        print(f"Regression checks for run {target_run} ({len(latest)} finding(s)):")
        for pid in sorted(latest):
            c = latest[pid]
            f = findings_by_id.get(pid, {})
            cwe = sanitize_egress_text(str(f.get("cwe") or "no-CWE"))
            fp = sanitize_egress_text(str(f.get("filepath") or "?"))
            status = sanitize_egress_text(str(f.get("status") or "?"))
            title = sanitize_egress_text(str(f.get("title") or "").replace("\n", " ").strip()[:100])
            outcome = sanitize_egress_text(str(c.get("outcome") or "?"))
            evidence = sanitize_egress_text(str(c.get("evidence") or "none"))
            node = sanitize_egress_text(str(c.get("node") or ""))
            reason = sanitize_egress_text(str(c.get("reason") or "").replace("\n", " ").strip()[:180])
            print(f"  - #{pid} [{outcome}/{evidence}] (status={status}, {cwe}) {fp}: {title}")
            if reason:
                by_note = f" ({node})" if node else ""
                print(f"      reason{by_note}: {reason}")
        return 0

    repo = os.path.realpath(args.repo)
    if not os.path.isdir(repo):
        print(f"error: --repo {args.repo} is not a directory", file=sys.stderr)
        return 2
    if args.cmd == "backfill-coverage":
        if not os.path.exists(args.db):
            print(f"error: no database at {args.db}", file=sys.stderr)
            return 2
        from pathlib import Path

        from core.cost import backfill_coverage
        from core.exclusions import normalize_exclude_patterns
        from main import discover_files

        files = discover_files(
            Path(repo),
            args.db,
            exclude=normalize_exclude_patterns(args.exclude),
            path_root=Path(repo),
        )
        summary = backfill_coverage(args.db, repo, files, at=args.at or None,
                                    assume_unchanged=args.assume_unchanged, dry_run=args.dry_run)
        verb = "Would record" if args.dry_run else "Recorded"
        for run_id, target, n, source in summary["backfilled"]:
            print(f"{verb} {n} file(s) for {os.path.relpath(target, repo) or '.'} (run {str(run_id)[:8]}, from {source})")
        reasons: dict = {}
        for _run_id, _target, reason in summary["skipped"]:
            reasons[reason] = reasons.get(reason, 0) + 1
        for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
            print(f"Skipped {count} campaign(s): {reason}")
        print(f"{verb} content for {len(summary['backfilled'])} campaign(s), {summary['rows']} file row(s)."
              + ("" if args.dry_run else " A --scan-mode changed run now examines only what differs from this."))
        # Non-zero only when something was left undone that the operator can
        # act on (a missing commit); campaigns already recorded are not that.
        undone = [s for s in summary["skipped"] if s[2] != "already has content rows"]
        return 1 if (undone and not summary["backfilled"]) else 0
    if args.cmd == "export":
        out = args.out or os.path.join(repo, KNOWLEDGE_DIR)
        if not os.path.exists(args.db):
            print(f"error: no database at {args.db}", file=sys.stderr)
            return 2
        export_head = args.head.strip() or None
        if export_head is None and args.preserve_head:
            existing_head = read_head(out)
            if existing_head:
                export_head = existing_head
        try:
            counts = export_knowledge(args.db, out, repo_root=repo, head=export_head)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"Exported to {out}: {describe(counts)}.")
        return 0
    src = args.src or os.path.join(repo, KNOWLEDGE_DIR)
    try:
        counts = import_knowledge(args.db, src, run_id=args.run_id, repo_root=repo)
    except KnowledgeImportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Imported from {src}: {describe(counts)} ({counts.get('findings_skipped', 0)} finding(s) already known).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

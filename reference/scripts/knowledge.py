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

"""Export the knowledge base to `.mantis/knowledge/`, or read one back.

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
import os
import sys
from pathlib import Path

_REF_ROOT = Path(__file__).resolve().parent.parent
if str(_REF_ROOT) not in sys.path:
    sys.path.insert(0, str(_REF_ROOT))

from core.knowledge import (  # noqa: E402
    KNOWLEDGE_DIR,
    KnowledgeImportError,
    describe,
    export_knowledge,
    import_knowledge,
    read_head,
)


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
    args = p.parse_args(argv)

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

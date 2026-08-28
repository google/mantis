#!/usr/bin/env python3
"""Mantis Security Advisor: Standalone CLI to query threat models, verified patches, false positives, and lineage from knowledge.db."""

import argparse
import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

# Ensure reference root is on sys.path
sys_ref_dir = str(Path(__file__).resolve().parent.parent)
if sys_ref_dir not in sys.path:
    sys.path.insert(0, sys_ref_dir)


def find_default_db(custom_path: str = "") -> Optional[str]:
    """Auto-discovers knowledge.db across standard workspace and repository locations."""
    if custom_path and os.path.exists(custom_path):
        return custom_path

    candidates = [
        custom_path,
        os.path.join(os.getcwd(), "knowledge.db"),
        os.path.join(os.getcwd(), "workspace", "knowledge.db"),
        os.path.join(os.getcwd(), "reference", "knowledge.db"),
        os.path.join(Path(__file__).resolve().parent.parent, "knowledge.db"),
        os.path.join(Path(__file__).resolve().parent.parent, "workspace", "knowledge.db"),
        os.path.join(Path(__file__).resolve().parent.parent, "reference", "knowledge.db"),
        os.path.join(os.getcwd(), "findings.db"),
        os.path.join(os.getcwd(), "workspace", "findings.db"),
        os.path.join(Path(__file__).resolve().parent.parent, "findings.db"),
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return None


def canonical_filepath(fp: str, target_file: str = "") -> str:
    """Normalizes finding and risk score filepaths to a consistent repo-relative representation."""
    if not fp and not target_file:
        return ""
    raw = (fp or target_file).strip().replace("\\", "/")
    while raw.startswith("./"):
        raw = raw[2:]

    tf_clean = (target_file or "").strip().replace("\\", "/")
    while tf_clean.startswith("./"):
        tf_clean = tf_clean[2:]

    if tf_clean:
        if raw == tf_clean:
            return os.path.basename(raw) if (os.path.isabs(raw) and not os.path.isdir(raw)) else (raw.lstrip("/") if os.path.isabs(raw) else raw)
        if raw.startswith(tf_clean + "/"):
            return raw[len(tf_clean) + 1:]
        if os.path.isabs(raw) and os.path.isabs(tf_clean):
            try:
                target_dir = tf_clean if os.path.isdir(tf_clean) else os.path.dirname(tf_clean)
                rel = os.path.relpath(raw, target_dir).replace("\\", "/")
                if not rel.startswith(".."):
                    return rel
            except Exception:
                pass
        if os.path.isabs(raw) and not os.path.isabs(tf_clean):
            if raw.endswith("/" + tf_clean) or raw.endswith(tf_clean):
                return tf_clean
        if not os.path.isabs(raw) and os.path.isabs(tf_clean):
            if tf_clean.endswith("/" + raw) or tf_clean.endswith(raw):
                return raw

    if os.path.isabs(raw):
        return raw.lstrip("/")
    return raw


def query_guidance_standalone(db_path: str, filepath: str) -> Dict[str, Any]:
    """Queries knowledge.db directly using standard sqlite3 to generate an advisory dossier."""
    norm_fp = canonical_filepath(filepath, target_file=filepath)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. OKF Concepts & Scoped Threat Context
    scoped_okf = []
    try:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='okf_concepts'")
        if cursor.fetchone():
            if norm_fp:
                cursor.execute("""
                    SELECT * FROM okf_concepts
                    WHERE resource = ?
                    ORDER BY id ASC
                """, (norm_fp,))
            else:
                cursor.execute("SELECT * FROM okf_concepts ORDER BY id ASC")
            scoped_okf = [dict(r) for r in cursor.fetchall()]
    except Exception:
        pass

    threat_concepts = [c for c in scoped_okf if c.get("type") in ("Threat Boundary", "Threat Model")]
    entity_concepts = [c for c in scoped_okf if c.get("type") in ("Component Entity", "Software Entity", "Hardware Entity", "Architecture Summary")]
    invariant_concepts = [c for c in scoped_okf if c.get("type") in ("Security Invariant", "Guardrail")]

    # 1. Threat Model & Trust Boundaries
    threat_model_content = ""
    if threat_concepts:
        threat_model_content = "\n\n".join(f"### {c.get('title')}\n{c.get('body_markdown', '').strip()}" for c in threat_concepts)
    else:
        try:
            cursor.execute("SELECT content FROM campaign_artifacts WHERE artifact_type = 'threat_model' ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if row and row["content"]:
                threat_model_content = row["content"]
            else:
                cursor.execute("SELECT content FROM campaign_artifacts WHERE filepath LIKE '%THREAT_MODEL%' ORDER BY id DESC LIMIT 1")
                row = cursor.fetchone()
                if row and row["content"]:
                    threat_model_content = row["content"]
        except Exception:
            pass

    # 2. Confirmed Vulnerabilities & Verified Patches
    confirmed_rows = []
    try:
        if norm_fp:
            cursor.execute("""
                SELECT * FROM findings
                WHERE filepath = ?
                  AND status IN ('confirmed', 'viable', 'reproduced', 'dynamic_confirmed', 'reported', 'patch_verified')
                ORDER BY timestamp DESC, id DESC
            """, (norm_fp,))
        else:
            cursor.execute("""
                SELECT * FROM findings
                WHERE status IN ('confirmed', 'viable', 'reproduced', 'dynamic_confirmed', 'reported', 'patch_verified')
                ORDER BY timestamp DESC, id DESC
            """)
        confirmed_rows = [dict(r) for r in cursor.fetchall()]
    except Exception:
        pass

    # 3. False Positives
    fp_rows = []
    try:
        if norm_fp:
            cursor.execute("""
                SELECT * FROM findings
                WHERE filepath = ?
                  AND status IN ('false_positive', 'non_viable', 'sample_or_test')
                ORDER BY timestamp DESC, id DESC
            """, (norm_fp,))
        else:
            cursor.execute("""
                SELECT * FROM findings
                WHERE status IN ('false_positive', 'non_viable', 'sample_or_test')
                ORDER BY timestamp DESC, id DESC
            """)
        fp_rows = [dict(r) for r in cursor.fetchall()]
    except Exception:
        pass

    # 4. Recurrent Lineages
    recurrent_lineages = []
    try:
        if norm_fp:
            cursor.execute("""
                SELECT lineage_id, MIN(signature) as signature, MIN(title) as title, COUNT(*) as occurrence_count,
                       MIN(timestamp) as first_seen, MAX(timestamp) as last_seen,
                       GROUP_CONCAT(DISTINCT status) as observed_statuses
                FROM findings
                WHERE filepath = ?
                  AND lineage_id IS NOT NULL AND lineage_id != ''
                GROUP BY lineage_id
                HAVING COUNT(*) >= 2
                ORDER BY occurrence_count DESC
            """, (norm_fp,))
        else:
            cursor.execute("""
                SELECT lineage_id, MIN(signature) as signature, MIN(title) as title, COUNT(*) as occurrence_count,
                       MIN(timestamp) as first_seen, MAX(timestamp) as last_seen,
                       GROUP_CONCAT(DISTINCT status) as observed_statuses
                FROM findings
                WHERE lineage_id IS NOT NULL AND lineage_id != ''
                GROUP BY lineage_id
                HAVING COUNT(*) >= 2
                ORDER BY occurrence_count DESC
            """)
        recurrent_lineages = [dict(r) for r in cursor.fetchall()]
    except Exception:
        pass

    # 5. Learned Invariants
    learnings = []
    try:
        cursor.execute("SELECT * FROM learnings ORDER BY id ASC")
        learnings = [dict(r) for r in cursor.fetchall()]
    except Exception:
        pass

    conn.close()

    # Derive Highest Trust Tier per OKF v0.2 §5.3
    trust_badge = "HEURISTIC"
    if any(c.get("trust_tier") == "human_reviewed" for c in scoped_okf):
        trust_badge = "HUMAN-REVIEWED"
    elif any(c.get("trust_tier") == "machine_confirmed" for c in scoped_okf) or any(f.get("status") in ("patch_verified", "dynamic_confirmed", "reproduced") for f in confirmed_rows):
        trust_badge = "SANDBOX-CONFIRMED"

    # Format Guidance Markdown
    guidance_lines = [
        f"# Security Advisory & Development Guidance for: {norm_fp or 'Repository Scope'}",
        f"**[OKF TRUST TIER: {trust_badge}]**",
        "",
        "## 1. Threat Model & Trust Boundaries Context",
    ]
    if threat_model_content:
        guidance_lines.append(threat_model_content.strip())
    else:
        guidance_lines.append("No active threat model recorded. Treat all external network inputs as untrusted.")

    # Entity context
    if entity_concepts:
        guidance_lines.extend(["", "## 2. Component Architecture & Known Constraints"])
        for ent in entity_concepts:
            badge = f"[{ent.get('trust_tier', 'unverified').upper().replace('_', '-')}]"
            guidance_lines.append(f"### {ent.get('title')} {badge}")
            if ent.get("description"):
                guidance_lines.append(f"*{ent.get('description')}*")
            if ent.get("body_markdown"):
                guidance_lines.append(f"{ent.get('body_markdown').strip()}\n")

    # Invariants & Guardrails
    if invariant_concepts or learnings:
        guidance_lines.extend(["", "## 3. Verified Security Guardrails & Invariants"])
        for inv in invariant_concepts:
            tier = inv.get("trust_tier", "unverified").upper().replace("_", "-")
            guidance_lines.append(f"- ⛔ **[{tier}] {inv.get('title')}**: {inv.get('description') or inv.get('body_markdown', '').strip()}")
        for l in learnings:
            cat = f"[{l.get('category')}] " if l.get("category") else ""
            guidance_lines.append(f"- ℹ️ **{cat}{l.get('learning')}**")

    guidance_lines.extend(["", "## 4. Historical Vulnerabilities & Verified Remediation Patterns"])
    if confirmed_rows:
        for f in confirmed_rows:
            cwe_tag = f"[{f.get('cwe')}] " if f.get("cwe") else ""
            lineage_tag = f" (Lineage: `{f.get('lineage_id')}`)" if f.get("lineage_id") else ""
            guidance_lines.append(f"### ⚠️ {cwe_tag}{f.get('title')}{lineage_tag}")
            guidance_lines.append(f"- **File**: `{f.get('filepath')}` | **Severity**: {f.get('severity')} | **Status**: `{f.get('status')}`")
            if f.get("description"):
                guidance_lines.append(f"- **Description**: {f.get('description')}")
            if f.get("remediation"):
                guidance_lines.append(f"- **Remediation**: {f.get('remediation')}")
            if f.get("patch_status"):
                guidance_lines.append(f"- **Patch Status**: `{f.get('patch_status')}`")
            if f.get("patch_diff"):
                guidance_lines.append(f"- **Verified Patch Diff (Few-Shot Pattern)**:\n```diff\n{f.get('patch_diff').strip()}\n```")
            guidance_lines.append("")
    else:
        guidance_lines.append("No confirmed vulnerabilities previously recorded for this target.")

    guidance_lines.extend(["", "## 5. Triaged False Positives (Intentional / Safe Patterns)"])
    if fp_rows:
        for f in fp_rows:
            cwe_tag = f"[{f.get('cwe')}] " if f.get("cwe") else ""
            guidance_lines.append(f"### ℹ️ {cwe_tag}{f.get('title')}")
            guidance_lines.append(f"- **File**: `{f.get('filepath')}` | **Status**: `{f.get('status')}`")
            if f.get("description"):
                guidance_lines.append(f"- **Pattern**: {f.get('description')}")
            if f.get("triage_reasoning"):
                guidance_lines.append(f"- **Triage Rationale**: {f.get('triage_reasoning')}")
            guidance_lines.append("")
    else:
        guidance_lines.append("No false positive exemptions recorded for this target.")

    if recurrent_lineages:
        guidance_lines.extend(["", "## 6. Recurrent Pitfalls & Lineage Regressions"])
        for rec in recurrent_lineages:
            guidance_lines.append(
                f"- **Lineage `{rec.get('lineage_id')}`** (Seen {rec.get('occurrence_count')}x across passes): "
                f"`{rec.get('title')}` (Statuses: {rec.get('observed_statuses')})"
            )

    return {
        "filepath": norm_fp,
        "trust_tier": trust_badge,
        "threat_model": threat_model_content,
        "okf_concepts": scoped_okf,
        "confirmed_vulnerabilities": confirmed_rows,
        "false_positives": fp_rows,
        "recurrent_lineages": recurrent_lineages,
        "learned_invariants": learnings,
        "guidance_summary": "\n".join(guidance_lines),
    }


def query_lineage_standalone(db_path: str, lineage_id: str = "", signature: str = "", filepath: str = "") -> List[Dict[str, Any]]:
    """Queries lineage history directly from knowledge.db."""
    norm_fp = canonical_filepath(filepath, target_file=filepath) if filepath else ""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    if lineage_id:
        query += " AND lineage_id = ?"
        params.append(lineage_id)
    elif signature:
        query += " AND signature = ?"
        params.append(signature)
    elif norm_fp:
        query += " AND filepath = ?"
        params.append(norm_fp)
    else:
        conn.close()
        return []

    query += " ORDER BY timestamp ASC, id ASC"
    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def main():
    parser = argparse.ArgumentParser(
        description="Mantis Security Advisor: Query threat models, OKF concepts, verified patches, false positives, and lineage from knowledge.db."
    )
    parser.add_argument(
        "--file", "-f", "--target", "-t",
        default="",
        dest="file",
        help="Target source file to retrieve security guidance for (e.g. src/auth.py or api/app.py)."
    )
    parser.add_argument(
        "--db", "-d",
        default="",
        help="Path to Mantis SQLite database (default: auto-discover knowledge.db)."
    )
    parser.add_argument(
        "--lineage", "-l",
        default="",
        help="Query historical lifecycle and recurrence for a specific lineage UUID."
    )
    parser.add_argument(
        "--signature", "-s",
        default="",
        help="Query historical lifecycle for a specific content signature hash."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit raw structured JSON instead of human-readable markdown."
    )
    parser.add_argument(
        "--export-okf",
        default="",
        metavar="DIR",
        help="Export all knowledge concepts to an OKF v0.2 directory bundle on disk."
    )
    parser.add_argument(
        "--import-okf",
        default="",
        metavar="DIR",
        help="Import an OKF v0.2 directory bundle from disk into knowledge.db."
    )

    args = parser.parse_args()

    db_path = find_default_db(args.db)
    if not db_path and not args.import_okf:
        sys.stderr.write(
            f"Error: Database file not found (specified: '{args.db}'). "
            f"Searched knowledge.db and workspace/knowledge.db in working directory.\n"
        )
        sys.exit(1)

    if not db_path and args.import_okf:
        db_path = args.db or "knowledge.db"
        try:
            from core.database import init_db
            init_db(db_path)
        except Exception:
            pass

    if args.export_okf:
        try:
            from core.database import export_okf_bundle
            files = export_okf_bundle(db_path, args.export_okf)
            print(f"Exported {len(files)} OKF v0.2 concept files to '{args.export_okf}'.")
            return
        except Exception as e:
            sys.stderr.write(f"Error exporting OKF bundle: {e}\n")
            sys.exit(1)

    if args.import_okf:
        try:
            from core.database import import_okf_bundle
            count = import_okf_bundle(db_path, args.import_okf)
            print(f"Imported {count} OKF v0.2 concept files into '{db_path}'.")
            return
        except Exception as e:
            sys.stderr.write(f"Error importing OKF bundle: {e}\n")
            sys.exit(1)

    if args.lineage or args.signature:
        records = query_lineage_standalone(db_path, lineage_id=args.lineage, signature=args.signature, filepath=args.file)
        if args.json:
            print(json.dumps(records, indent=2))
        else:
            if not records:
                print(f"No lineage records found in '{db_path}' for lineage='{args.lineage}', signature='{args.signature}', file='{args.file}'.")
            else:
                print(f"# Lineage History ({len(records)} record(s))\n")
                for r in records:
                    print(f"- **[{r.get('timestamp')}] Lineage `{r.get('lineage_id')}` (Sig: `{r.get('signature')}`)**")
                    print(f"  - **File**: `{r.get('filepath')}` | **Severity**: {r.get('severity')} | **Status**: `{r.get('status')}`")
                    print(f"  - **Title**: {r.get('title')}")
                    if r.get("cwe"):
                        print(f"  - **CWE**: {r.get('cwe')}")
                    if r.get("triage_reasoning"):
                        print(f"  - **Triage Reasoning**: {r.get('triage_reasoning')}")
                    if r.get("patch_status"):
                        print(f"  - **Patch Status**: `{r.get('patch_status')}`")
                    if r.get("patch_diff"):
                        print(f"  - **Patch Diff**:\n```diff\n{r.get('patch_diff').strip()}\n```")
    else:
        try:
            from core.database import query_security_guidance
            guidance = query_security_guidance(db_path, filepath=args.file)
        except (ImportError, ModuleNotFoundError):
            guidance = query_guidance_standalone(db_path, filepath=args.file)

        if args.json:
            print(json.dumps(guidance, indent=2))
        else:
            print(guidance.get("guidance_summary", ""))


if __name__ == "__main__":
    main()

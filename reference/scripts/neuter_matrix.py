"""Neuter Matrix: Verifies all security regression controls fail when reverted.

Proves every defensive guard in Mantis is potent and non-vacuous by temporarily
reverting the control in an isolated copy of the repository and executing the
security regression test suite.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REF = Path(__file__).resolve().parent.parent
PY = str(REF / ".venv" / "bin" / "python3") if (REF / ".venv" / "bin" / "python3").exists() else sys.executable

SCENARIOS = {
    # ---- Round 2 Guards ----
    "revert_gpg_pins": [
        ("tools/research_tools.py",
         '        "-c",\n        "log.showSignature=false",\n        "-c",\n        "gpg.program=/usr/bin/false",\n        "-c",\n        "gpg.ssh.program=/usr/bin/false",\n        "-c",\n        "gpg.x509.program=/usr/bin/false",\n        "-c",\n        "gpg.ssh.allowedSignersFile=/dev/null",\n',
         ''),
        ("tools/research_tools.py", '        "--no-show-signature",\n', ''),
        ("tools/research_tools.py", '"show", "--no-show-signature", ', '"show", '),
    ],
    "revert_commondir_check": [
        ("tools/research_tools.py",
         '    common_out, common_ok = _run_safe_git_command(["rev-parse", "--git-common-dir"], repo_dir)',
         '    common_out, common_ok = ("x", True)\n    return True, ""  # NEUTERED'),
    ],
    "revert_midpath_walk": [
        ("core/paths.py",
         "    escaping = find_escaping_symlink_component(raw)",
         "    escaping = None  # NEUTERED"),
    ],
    "revert_egress_control_strip": [
        ("core/llm_gateway.py",
         '    return _CONTROL_CHAR_RE.sub("", _ANSI_ESCAPE_RE.sub("", str(text)))',
         '    return str(text)  # NEUTERED'),
    ],
    "revert_span_sanitizer": [
        ("core/llm_gateway.py",
         '    collapsed = " ".join(strip_terminal_control(str(text)).split())',
         '    return str(text)  # NEUTERED\n    collapsed = ""'),
    ],
    "revert_sentinel_host_read": [
        ("tools/sandbox_tools.py",
         "        if ctx and ctx.sandbox:\n            try:\n                content_bytes = await ctx.sandbox.read_file(Path(sentinel_path))\n                sentinel_content = content_bytes.decode(\"utf-8\", errors=\"replace\")\n            except Exception:\n                pass",
         "        if ctx and ctx.sandbox:\n            try:\n                content_bytes = await ctx.sandbox.read_file(Path(sentinel_path))\n                sentinel_content = content_bytes.decode(\"utf-8\", errors=\"replace\")\n            except Exception:\n                pass\n        if not sentinel_content and Path(sentinel_path).exists():\n            sentinel_content = Path(sentinel_path).read_text(errors=\"replace\")"),
    ],
    "revert_staging_vcs_and_hardlink": [
        ("core/environments/staging.py",
         "                if file in PROTECTED_VCS_DIRS:\n                    continue\n",
         ""),
        ("core/environments/staging.py",
         "                if st.st_nlink > 1:\n                    continue\n",
         ""),
    ],
    "revert_cwd_workflow_probe": [
        ("scripts/configure.py",
         "    for candidate in [package_wf, parent_ref_wf]:",
         "    repo_ref_wf = os.path.join(os.getcwd(), \"reference\", \"workflow.json\")\n    for candidate in [repo_ref_wf, package_wf, parent_ref_wf]:"),
    ],
    "revert_cwd_db_probe": [
        ("scripts/advise.py",
         "    ref_home = str(Path(__file__).resolve().parent.parent)",
         "    candidates.extend([\n        os.path.join(os.getcwd(), \"workspace\", \"knowledge.db\"),\n        os.path.join(os.getcwd(), \"knowledge.db\"),\n    ])\n    ref_home = str(Path(__file__).resolve().parent.parent)"),
    ],

    # ---- Round 3 Guards ----
    "r3_revert_gitdir_symlink_walk": [
        ("tools/research_tools.py",
         "    for base in {git_dir_real, common_dir_real}:\n        ok, err = _assert_no_symlinks_under(base, jail_real)\n        if not ok:\n            return False, err",
         "    pass  # NEUTERED"),
    ],
    "r3_revert_dotdot_refusal": [
        ("core/paths.py",
         '_REFUSED_PARTS = ("..",)',
         '_REFUSED_PARTS = ()  # NEUTERED'),
        ("core/paths.py",
         "    raw = Path(path)\n    if not raw.is_absolute():\n        # $CWD is the operator's shell, not attacker input; only the operand is.\n        raw = Path.cwd() / raw\n    return raw",
         "    return Path(os.path.abspath(str(path)))  # NEUTERED: re-introduces normpath"),
    ],
    "r3_revert_banner_install_anchor": [
        ("core/budget.py",
         '        launcher = install_root() / "run.sh"\n        if launcher.is_file():\n            base_launcher = shlex.quote(str(launcher))',
         '        launcher = Path("./run.sh")  # NEUTERED: probes $CWD\n        if launcher.is_file():\n            base_launcher = "./run.sh"'),
    ],
    "r3_revert_db_path_anchor": [
        ("core/database.py",
         "    db_path = resolve_db_path(db_path)",
         "    pass  # NEUTERED"),
        ("scripts/advise.py",
         "    conn = sqlite3.connect(resolve_db_path(db_path))",
         "    conn = sqlite3.connect(db_path)  # NEUTERED"),
    ],
    "r3_revert_okf_export_sanitizer": [
        ("core/database.py",
         '        body = sanitize_egress_text(str(c.get("body_markdown", "")).strip())',
         '        body = str(c.get("body_markdown", "")).strip()  # NEUTERED'),
    ],
    "r3_revert_seed_prompt_grammar": [
        ("core/graph_loader.py",
         "        for match in _SEED_FIELD_RE.finditer(v):",
         "        v.format(filepath='/p', run_id='r')  # NEUTERED\n        for match in []:"),
    ],
    "r3_revert_write_hardlink_check": [
        ("core/environments/static_env.py",
         "        if os.path.exists(resolved_target) and os.lstat(resolved_target).st_nlink > 1:",
         "        if False:  # NEUTERED"),
    ],
    "r3_revert_verbatim_crlf": [
        ("core/llm_gateway.py",
         '            if isinstance(k, str) and k in _VERBATIM_EGRESS_FIELDS and isinstance(v, str):',
         '            if False:  # NEUTERED'),
    ],
    "r3_revert_single_line_span": [
        ("scripts/advise.py",
         "    clean_title = safe_markdown_span(str(f_dict.get('title', '')))",
         "    clean_title = safe_markdown_inline(str(f_dict.get('title', '')))  # NEUTERED"),
    ],

    # ---- Round 4 Guards ----
    "r4_revert_lazy_fetch_env": [
        ("tools/research_tools.py",
         '    git_env["GIT_NO_LAZY_FETCH"] = "1"\n',
         ''),
    ],
    "r4_revert_config_allowlist": [
        ("tools/research_tools.py",
         "def _is_git_config_key_allowed(raw_key: str) -> bool:\n    \"\"\"Returns True if the git config key is in the vetted allowlist.\"\"\"\n    k = raw_key.strip().lower()",
         "def _is_git_config_key_allowed(raw_key: str) -> bool:\n    return True  # NEUTERED\n    k = raw_key.strip().lower()"),
    ],
    "r4_revert_git_hardlink_refusal": [
        ("tools/research_tools.py",
         "                    if st.st_nlink > 1:\n                        return False, (\n                            f\"Hardlinked git metadata '{entry.name}' is prohibited for security.\"\n                        )",
         "                    pass  # NEUTERED"),
    ],
    "r4_revert_okf_export_containment": [
        ("core/database.py",
         "        valid_dest, _ = validate_data_path(full_dest, anchor=out_root_path)\n        if not valid_dest:\n            continue\n\n        curr = out_root_path\n        has_symlink = False\n        for part in Path(rel_file).parts:\n            curr = curr / part\n            if curr.is_symlink():\n                has_symlink = True\n                break\n        if has_symlink:\n            continue",
         "        pass  # NEUTERED"),
    ],
    "r4_revert_okf_import_trust_tier": [
        ("core/database.py",
         '                    if parsed:\n                        parsed["trust_tier"] = trust_tier\n                        record_okf_concept(db_path, run_id, parsed)\n                        record_artifact(\n                            db_path,\n                            run_id,\n                            parsed.get("type", "okf_concept"),\n                            rel_p,\n                            content,\n                            metadata={"trust_tier": trust_tier, "agent_authored": True},\n                        )',
         '                    if parsed:\n                        record_okf_concept(db_path, run_id, parsed)\n                        record_artifact(\n                            db_path,\n                            run_id,\n                            parsed.get("type", "okf_concept"),\n                            rel_p,\n                            content,\n                        )  # NEUTERED'),
    ],
    "r4_revert_db_chokepoint_probe": [
        ("scripts/advise.py",
         "            resolved = resolve_db_path(custom_path)\n            if os.path.exists(resolved):\n                return resolved",
         "            if os.path.exists(custom_path):\n                return custom_path  # NEUTERED"),
    ],
    "r4_revert_multiline_sink_prefix": [
        ("core/llm_gateway.py",
         '    for line in scrubbed.splitlines():\n        lines.append(f"> {line}")',
         '    for line in scrubbed.splitlines():\n        lines.append(line)  # NEUTERED'),
    ],
    "r4_revert_pause_trigger_strip": [
        ("core/budget.py",
         '        clean_trigger = " ".join(str(trigger).split())',
         '        clean_trigger = str(trigger)  # NEUTERED'),
    ],

    # ---- Round 5 & 6 Guards ----
    "r5_revert_alias_bomb_loader": [
        ("core/database.py",
         "        if self.check_event(yaml.AliasEvent):\n            raise yaml.YAMLError(\"YAML aliases/anchors are prohibited in OKF frontmatter.\")",
         "        pass  # NEUTERED: allow aliases"),
    ],
    "r5_revert_span_heading_escape": [
        ("core/llm_gateway.py",
         "    if collapsed.startswith((\"#\", \">\", \"=\", \"-\")):\n        collapsed = \"\\\\\" + collapsed",
         "    pass  # NEUTERED"),
    ],
    "r5_revert_submodule_pins": [
        ("tools/research_tools.py",
         '        "-c",\n        "diff.submodule=short",\n        "-c",\n        "submodule.recurse=false",\n',
         ''),
        ("tools/research_tools.py",
         '"--no-textconv", "--submodule=short",',
         '"--no-textconv",'),
    ],
    "r5_revert_worktree_submodule_scan": [
        ("tools/research_tools.py",
         '        for name in candidates:\n            nested = Path(root) / name',
         '        for name in []:  # NEUTERED: skip nested .git inspection\n            nested = Path(root) / name'),
    ],
    "r6_revert_cr_splitlines_null_enum": [
        ("tools/research_tools.py",
         '["config", "--local", "--no-includes", "--name-only", "-z", "-l"]',
         '["config", "--local", "--no-includes", "--name-only", "-l"]'),
        ("tools/research_tools.py",
         '["config", "--file", str(cfg_candidate), "--no-includes", "--name-only", "-z", "-l"]',
         '["config", "--file", str(cfg_candidate), "--no-includes", "--name-only", "-l"]'),
        ("tools/research_tools.py",
         r'for line in cfg_out.split("\0"):',
         'for line in cfg_out.splitlines():'),
        ("tools/research_tools.py",
         r'for line in f_out.split("\0"):',
         'for line in f_out.splitlines():'),
    ],
}


def run_matrix(only_scenarios=None):
    results = {}
    selected = {k: v for k, v in SCENARIOS.items() if not only_scenarios or k in only_scenarios}
    total = len(selected)
    print(f"Running Neuter Matrix across {total} scenarios...")

    for idx, (name, patches) in enumerate(selected.items(), 1):
        work = Path(tempfile.mkdtemp(prefix=f"neuter_{name}_"))
        dst = work / "reference"
        shutil.copytree(
            REF, dst, symlinks=True,
            ignore=shutil.ignore_patterns(".venv", "__pycache__", "workspace", "*.db", ".git"),
        )
        ok_patch = True
        for rel, old, new in patches:
            p = dst / rel
            text = p.read_text(encoding="utf-8")
            if old not in text:
                print(f"  [{idx}/{total}] !! {name}: pattern not found in {rel}")
                ok_patch = False
                break
            p.write_text(text.replace(old, new, 1), encoding="utf-8")

        if not ok_patch:
            results[name] = "PATCH-FAILED"
            shutil.rmtree(work, ignore_errors=True)
            continue

        proc = subprocess.run(
            [PY, "-m", "unittest", "tests.test_security_regression", "-v"],
            cwd=dst, capture_output=True, text=True,
        )
        combined = proc.stdout + proc.stderr
        failed = re.findall(r"^(?:FAIL|ERROR): (\S+)", combined, re.M)
        if proc.returncode != 0:
            results[name] = "WENT RED: " + ", ".join(sorted(set(failed)))
            print(f"  [{idx}/{total}] {name:35s} -> WENT RED ({len(failed)} failure(s))")
        else:
            results[name] = "STILL GREEN (BAD)"
            print(f"  [{idx}/{total}] {name:35s} -> STILL GREEN (BAD)")

        shutil.rmtree(work, ignore_errors=True)

    print("\n" + "=" * 80)
    print(f" NEUTER MATRIX SUMMARY: {len(results)} SCENARIOS EVALUATED")
    print("=" * 80)
    red_count = sum(1 for v in results.values() if v.startswith("WENT RED"))
    bad_count = sum(1 for v in results.values() if "STILL GREEN" in v or "PATCH-FAILED" in v)

    for k, v in results.items():
        print(f"  {k:35s} {v}")

    print("-" * 80)
    print(f" Total: {len(results)} | Potent (Went Red): {red_count} | Inert/Failed: {bad_count}")
    print("=" * 80)
    return bad_count == 0


if __name__ == "__main__":
    success = run_matrix(sys.argv[1:])
    sys.exit(0 if success else 1)

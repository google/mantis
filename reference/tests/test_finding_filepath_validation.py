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

"""Deterministic finding filepath validation and canonicalization tests (GitHub #18)."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from core.context import RunContext, current_run_context  # noqa: E402
from core.database import (  # noqa: E402
    canonical_filepath,
    init_db,
    read_findings,
    write_findings,
)
from tools import research_tools as rt  # noqa: E402


class FindingFilepathValidationTests(unittest.TestCase):
    """Pins deterministic filepath resolution, disambiguation, and canonicalization."""

    PIPE_SCRIPT = "\n".join(
        [
            "#!/bin/bash",
            "set -euo pipefail",
            "PIPE_FILE=/tmp/ipc_cmd",
            "if [[ -f \"$PIPE_FILE\" ]]; then",
            "  cmd=$(cat \"$PIPE_FILE\")",
            "  # line 6",
            "  # line 7",
            "  # line 8",
            "  # line 9",
            "  eval \"$cmd\"",
            "  rm -f \"$PIPE_FILE\"",
            "  exit 0",
            "fi",
        ]
    ) + "\n"

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="mantis_fp_val_")
        self.root = Path(self.tmp_dir) / "scan_root"
        self.root.mkdir()
        self.db_path = str(Path(self.tmp_dir) / "knowledge.db")
        init_db(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _write_target_file(self, rel_path: str, content: str | None = None) -> Path:
        p = self.root / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content if content is not None else self.PIPE_SCRIPT, encoding="utf-8")
        return p

    def test_issue18_single_file_campaign_repairs_workspace_and_verifies_lines(self):
        """Issue #18: nested single-file campaigns never save 'workspace/<name>'."""
        rel = "xxx/aaa/bbb/ccc/files/db_container_pipe_processor.sh"
        target = self._write_target_file(rel)

        ctx = RunContext(
            jail_dir=str(self.root),
            target_file=str(target),
            db_path=self.db_path,
            run_id="run_single_18",
        )
        tok = current_run_context.set(ctx)
        try:
            for idx, cited in enumerate(
                [
                    "workspace/db_container_pipe_processor.sh",
                    "/workspace/db_container_pipe_processor.sh",
                    "db_container_pipe_processor.sh",
                    "files/db_container_pipe_processor.sh",
                    f"/workspace/{rel}",
                ]
            ):
                with self.subTest(cited=cited):
                    res = rt.report_findings(
                        [
                            {
                                "title": f"PipeEval-{idx}",
                                "filepath": cited,
                                "line_numbers": [10, 12],
                                "code_paths": [f"{cited}:10"],
                            }
                        ]
                    )
                    self.assertTrue(res.startswith("SUCCESS"), f"{cited}: {res}")

            # Out-of-range line numbers on 'workspace/<name>' must also be caught now!
            bad_res = rt.report_findings(
                [
                    {
                        "title": "OutOfRangeWorkspace",
                        "filepath": "workspace/db_container_pipe_processor.sh",
                        "line_numbers": [999],
                    }
                ]
            )
            self.assertIn("NOT saved", bad_res)
            self.assertIn("out of range", bad_res)
        finally:
            current_run_context.reset(tok)

        rows = read_findings(self.db_path, run_id="run_single_18")
        self.assertEqual(len(rows), 5)
        for row in rows:
            self.assertEqual(row["filepath"], rel)
            self.assertEqual(row["code_paths"], [f"{rel}:10"])

    def test_issue18_directory_campaign_repairs_unique_workspace_basename(self):
        """Directory scans repair 'workspace/<name>' or bare '<name>' when unique."""
        rel = "xxx/aaa/bbb/ccc/files/db_container_pipe_processor.sh"
        self._write_target_file(rel)

        ctx = RunContext(
            jail_dir=str(self.root),
            target_file=str(self.root),
            db_path=self.db_path,
            run_id="run_dir_unique",
        )
        tok = current_run_context.set(ctx)
        try:
            res = rt.report_findings(
                [
                    {
                        "title": "DirWorkspacePrefix",
                        "filepath": "workspace/db_container_pipe_processor.sh",
                        "line_numbers": [10, 12],
                        "code_paths": ["workspace/db_container_pipe_processor.sh:10"],
                    },
                    {
                        "title": "DirBareBasename",
                        "filepath": "db_container_pipe_processor.sh",
                        "line_numbers": [10],
                        "code_paths": ["files/db_container_pipe_processor.sh:10"],
                    },
                ]
            )
            self.assertTrue(res.startswith("SUCCESS"), res)
        finally:
            current_run_context.reset(tok)

        rows = {r["title"]: r for r in read_findings(self.db_path, run_id="run_dir_unique")}
        self.assertEqual(rows["DirWorkspacePrefix"]["filepath"], rel)
        self.assertEqual(rows["DirWorkspacePrefix"]["code_paths"], [f"{rel}:10"])
        self.assertEqual(rows["DirBareBasename"]["filepath"], rel)
        self.assertEqual(rows["DirBareBasename"]["code_paths"], [f"{rel}:10"])

    def test_ambiguous_same_named_files_rejected_in_directory_scan_resolved_in_single_file(self):
        """When multiple directories share a filename, directory scans reject bare or
        'workspace/<name>' citations as ambiguous instead of guessing, whereas
        single-file scans deterministically resolve to their own target file."""
        rel_a = "service_a/files/db_container_pipe_processor.sh"
        rel_b = "service_b/files/db_container_pipe_processor.sh"
        self._write_target_file(rel_a)
        target_b = self._write_target_file(rel_b)

        # Also create a root file + nested file with the same name ('runner.sh' and 'sub/runner.sh')
        self._write_target_file("runner.sh")
        self._write_target_file("sub/runner.sh")

        dir_ctx = RunContext(
            jail_dir=str(self.root),
            target_file=str(self.root),
            db_path=self.db_path,
            run_id="run_ambig_dir",
        )
        tok = current_run_context.set(dir_ctx)
        try:
            for cited in (
                "workspace/db_container_pipe_processor.sh",
                "/workspace/db_container_pipe_processor.sh",
                "db_container_pipe_processor.sh",
                "files/db_container_pipe_processor.sh",
                "workspace/runner.sh",
            ):
                with self.subTest(cited=cited):
                    res = rt.report_findings(
                        [{"title": "Ambiguous", "filepath": cited, "line_numbers": [10]}]
                    )
                    self.assertIn("NOT saved", res)
                    self.assertIn("ambiguous", res)

            # Ambiguous code_paths entry is also rejected
            cp_res = rt.report_findings(
                [
                    {
                        "title": "AmbiguousCodePath",
                        "filepath": rel_a,
                        "line_numbers": [10],
                        "code_paths": ["workspace/db_container_pipe_processor.sh:10"],
                    }
                ]
            )
            self.assertIn("NOT saved", cp_res)
            self.assertIn("ambiguous", cp_res)

            self.assertEqual(len(read_findings(self.db_path, run_id="run_ambig_dir")), 0)

            # Exact paths save cleanly without ambiguity
            ok_res = rt.report_findings(
                [
                    {"title": "ExactA", "filepath": rel_a, "line_numbers": [10]},
                    {"title": "ExactB", "filepath": rel_b, "line_numbers": [10]},
                    {"title": "ExactRoot", "filepath": "runner.sh", "line_numbers": [10]},
                    {"title": "ExactSub", "filepath": "sub/runner.sh", "line_numbers": [10]},
                ]
            )
            self.assertTrue(ok_res.startswith("SUCCESS"), ok_res)
        finally:
            current_run_context.reset(tok)

        saved = {r["title"]: r["filepath"] for r in read_findings(self.db_path, run_id="run_ambig_dir")}
        self.assertEqual(
            saved,
            {
                "ExactA": rel_a,
                "ExactB": rel_b,
                "ExactRoot": "runner.sh",
                "ExactSub": "sub/runner.sh",
            },
        )

        # Subdirectory slice campaign targeting 'service_b' disambiguates to service_b's file
        slice_ctx = RunContext(
            jail_dir=str(self.root),
            target_file=str(self.root / "service_b"),
            db_path=self.db_path,
            run_id="run_slice_b",
        )
        tok = current_run_context.set(slice_ctx)
        try:
            slice_res = rt.report_findings(
                [
                    {
                        "title": "SliceDisambiguated",
                        "filepath": "workspace/db_container_pipe_processor.sh",
                        "line_numbers": [10],
                    }
                ]
            )
            self.assertTrue(slice_res.startswith("SUCCESS"), slice_res)
        finally:
            current_run_context.reset(tok)
        slice_rows = read_findings(self.db_path, run_id="run_slice_b")
        self.assertEqual(len(slice_rows), 1)
        self.assertEqual(slice_rows[0]["filepath"], rel_b)

        # Single-file campaign targeting target_b resolves 'workspace/<name>' to rel_b
        # and lexically rejects rel_a!
        file_ctx = RunContext(
            jail_dir=str(self.root),
            target_file=str(target_b),
            db_path=self.db_path,
            run_id="run_single_b",
        )
        tok = current_run_context.set(file_ctx)
        try:
            wrong_sibling = rt.report_findings(
                [{"title": "WrongSibling", "filepath": rel_a, "line_numbers": [10]}]
            )
            self.assertIn("NOT saved", wrong_sibling)
            self.assertIn("single-file scans may only report findings", wrong_sibling)

            right_file = rt.report_findings(
                [
                    {
                        "title": "RightTargetB",
                        "filepath": "workspace/db_container_pipe_processor.sh",
                        "line_numbers": [10],
                    }
                ]
            )
            self.assertTrue(right_file.startswith("SUCCESS"), right_file)
        finally:
            current_run_context.reset(tok)

        single_rows = read_findings(self.db_path, run_id="run_single_b")
        self.assertEqual(len(single_rows), 1)
        self.assertEqual(single_rows[0]["filepath"], rel_b)

    def test_single_file_off_target_rejection_is_strictly_lexical_non_oracle(self):
        """Off-target paths in single-file mode fail with the same lexical message
        whether a sibling file exists or not."""
        target = self._write_target_file("pkg/app.py", "def login():\n    return 1\n")
        secret = self._write_target_file(".ssh/id_ed25519", "SECRET_KEY_MATERIAL\n")
        self.assertTrue(secret.is_file())

        ctx = RunContext(
            jail_dir=str(self.root),
            target_file=str(target),
            db_path=self.db_path,
            run_id="run_lexical_gate",
        )
        tok = current_run_context.set(ctx)
        try:
            res_exists = rt.report_findings(
                [{"title": "Probe", "filepath": ".ssh/id_ed25519", "line_numbers": [1]}]
            )
            res_missing = rt.report_findings(
                [{"title": "Probe", "filepath": ".ssh/does_not_exist", "line_numbers": [1]}]
            )
            self.assertIn("NOT saved", res_exists)
            self.assertIn("NOT saved", res_missing)
            # Identical template modulo the echoed path string: zero existence/line-count leak.
            self.assertEqual(
                res_exists.replace(".ssh/id_ed25519", "<P>"),
                res_missing.replace(".ssh/does_not_exist", "<P>"),
            )
            self.assertEqual(len(read_findings(self.db_path, run_id="run_lexical_gate")), 0)
        finally:
            current_run_context.reset(tok)

    def test_virtual_mantis_workspace_artifacts_are_rejected(self):
        """Virtual Mantis artifacts (workspace/findings/..., workspace/plan.json, etc.)
        cannot be recorded as finding filepaths."""
        target = self._write_target_file("src/handler.py", "def handle(x):\n    return eval(x)\n")

        for mode, tf in (("dir", str(self.root)), ("single", str(target))):
            ctx = RunContext(
                jail_dir=str(self.root),
                target_file=tf,
                db_path=self.db_path,
                run_id=f"run_virt_{mode}",
            )
            tok = current_run_context.set(ctx)
            try:
                for virt in (
                    "workspace/findings/870.json",
                    "workspace/kb/THREAT_MODEL.md",
                    "workspace/plan.json",
                    "mantis-summary.md",
                    "workspace/repro_1.py",
                ):
                    with self.subTest(mode=mode, virt=virt):
                        res = rt.report_findings(
                            [{"title": "Virt", "filepath": virt, "line_numbers": [1]}]
                        )
                        self.assertIn("NOT saved", res)
                self.assertEqual(len(read_findings(self.db_path, run_id=f"run_virt_{mode}")), 0)
            finally:
                current_run_context.reset(tok)

    def test_real_workspace_directory_in_target_repo_is_preserved(self):
        """If the scanned repository genuinely has a 'workspace/' directory on disk,
        findings against 'workspace/real_module.py' keep that path."""
        real_ws = self._write_target_file("workspace/real_module.py", "def run(cmd):\n    return eval(cmd)\n")

        ctx = RunContext(
            jail_dir=str(self.root),
            target_file=str(self.root),
            db_path=self.db_path,
            run_id="run_real_ws",
        )
        tok = current_run_context.set(ctx)
        try:
            self.assertEqual(
                canonical_filepath("workspace/real_module.py", target_file=str(real_ws)),
                "workspace/real_module.py",
            )
            res = rt.report_findings(
                [{"title": "RealWorkspacePkg", "filepath": "workspace/real_module.py", "line_numbers": [2]}]
            )
            self.assertTrue(res.startswith("SUCCESS"), res)
        finally:
            current_run_context.reset(tok)

        rows = read_findings(self.db_path, run_id="run_real_ws")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["filepath"], "workspace/real_module.py")

    def test_write_findings_id_update_never_degrades_existing_canonical_filepath(self):
        """Defense-in-depth in database.py: canonical_filepath strips synthetic
        workspace/ prefixes, and ID-based updates (e.g. deduplicator) never
        overwrite a canonical nested filepath with a degraded path."""
        rel = "xxx/aaa/bbb/ccc/files/db_container_pipe_processor.sh"
        target = self._write_target_file(rel)

        ctx = RunContext(
            jail_dir=str(self.root),
            target_file=str(target),
            db_path=self.db_path,
            run_id="run_db_guard",
        )
        tok = current_run_context.set(ctx)
        try:
            self.assertEqual(
                canonical_filepath("workspace/db_container_pipe_processor.sh", target_file=str(target)),
                rel,
            )
            self.assertEqual(
                canonical_filepath("/workspace/db_container_pipe_processor.sh", target_file=str(target)),
                rel,
            )

            write_findings(
                self.db_path,
                str(target),
                [
                    {
                        "title": "File-to-eval command bridge",
                        "filepath": rel,
                        "severity": "HIGH",
                        "cwe": "CWE-78",
                        "description": "Root command execution from writable IPC file.",
                        "line_numbers": [10, 12],
                    }
                ],
                run_id="run_db_guard",
            )
            initial = read_findings(self.db_path, run_id="run_db_guard")
            self.assertEqual(len(initial), 1)
            fid = initial[0]["id"]
            orig_sig = initial[0]["signature"]

            # Simulate a downstream stage updating by explicit id in directory mode
            # with a degraded 'workspace/<basename>' or bare basename filepath.
            write_findings(
                self.db_path,
                str(self.root),
                [
                    {
                        "id": fid,
                        "title": "File-to-eval command bridge",
                        "filepath": "workspace/db_container_pipe_processor.sh",
                        "severity": "HIGH",
                        "cwe": "CWE-78",
                        "status": "static_confirmed",
                        "description": "Root command execution from writable IPC file.",
                        "line_numbers": [10, 12],
                    }
                ],
                run_id="run_db_guard",
            )
            updated = read_findings(self.db_path, run_id="run_db_guard")
            self.assertEqual(len(updated), 1)
            self.assertEqual(updated[0]["id"], fid)
            self.assertEqual(updated[0]["filepath"], rel)
            self.assertEqual(updated[0]["signature"], orig_sig)
            self.assertEqual(updated[0]["status"], "static_confirmed")
        finally:
            current_run_context.reset(tok)

    def test_end_to_end_pipeline_file_by_file_with_duplicate_merge_and_advise(self):
        """End-to-end main.pipeline('file-by-file') across same-named nested files
        where researcher and deduplicator cite 'workspace/<name>' and merge duplicates."""
        import asyncio
        import json
        from unittest import mock
        from google.adk.models import BaseLlm, LlmResponse
        from google.genai import types
        import main as mantis_main
        from scripts.advise import query_remediation_standalone

        rel_vuln = "xxx/aaa/bbb/ccc/files/db_container_pipe_processor.sh"
        rel_clean = "yyy/files/db_container_pipe_processor.sh"
        self._write_target_file(rel_vuln)
        self._write_target_file(rel_clean, "#!/bin/bash\necho healthy\n")

        wf_path = str(Path(self.tmp_dir) / "mini_workflow.json")
        Path(wf_path).write_text(
            json.dumps(
                {
                    "name": "issue18_e2e_wf",
                    "config": {
                        "default_model": "openai/test-model",
                        "api_base": "http://localhost:11434/v1",
                        "sandbox": {"type": "static-only"},
                    },
                    "nodes": [
                        {
                            "id": "researcher",
                            "type": "agent",
                            "system_prompt": "Audit the target file and call report_findings.",
                            "tools": ["read_file", "report_findings"],
                        },
                        {
                            "id": "deduplicator",
                            "type": "agent",
                            "system_prompt": "Deduplicate findings in the campaign.",
                            "tools": ["get_findings", "dedupe_findings", "report_findings"],
                        },
                    ],
                    "edges": [
                        {"from": "START", "to": "researcher"},
                        {"from": "researcher", "to": "deduplicator"},
                    ],
                }
            ),
            encoding="utf-8",
        )

        scan_root = self.root

        class _ScriptedIssue18Llm(BaseLlm):
            model: str = "openai/test-model"

            async def generate_content_async(self, llm_request, stream: bool = False):
                ctx = current_run_context.get()
                sys_inst = str(getattr(llm_request.config, "system_instruction", "") or "")
                node_id = "researcher" if "Audit the target file" in sys_inst else "deduplicator"
                target_fp = str(getattr(ctx, "target_file", "") or "")
                fn_responses = [
                    p.function_response
                    for c in (llm_request.contents or [])
                    for p in (c.parts or [])
                    if getattr(p, "function_response", None) is not None
                ]

                if node_id == "researcher":
                    if len(fn_responses) == 0:
                        rel_t = (
                            Path(target_fp).relative_to(scan_root).as_posix()
                            if target_fp
                            else rel_vuln
                        )
                        part = types.Part.from_function_call(
                            name="read_file",
                            args={"filepath": rel_t},
                        )
                    elif len(fn_responses) == 1 and "xxx/aaa/bbb/ccc" in target_fp:
                        part = types.Part.from_function_call(
                            name="report_findings",
                            args={
                                "report": {
                                    "findings": [
                                        {
                                            "title": "File-to-eval command bridge primary",
                                            "filepath": "workspace/db_container_pipe_processor.sh",
                                            "severity": "HIGH",
                                            "cwe": "CWE-78",
                                            "description": "eval executes arbitrary IPC commands as root.",
                                            "line_numbers": [10, 12],
                                            "code_paths": [
                                                "workspace/db_container_pipe_processor.sh:10"
                                            ],
                                        },
                                        {
                                            "title": "File-to-eval command bridge duplicate",
                                            "filepath": "/workspace/db_container_pipe_processor.sh",
                                            "severity": "HIGH",
                                            "cwe": "CWE-78",
                                            "description": "Duplicate angle on IPC command bridge.",
                                            "line_numbers": [10, 12],
                                        },
                                    ]
                                }
                            },
                        )
                    else:
                        part = types.Part.from_text(text="Research complete.")
                else:
                    # deduplicator stage
                    if "xxx/aaa/bbb/ccc" not in target_fp:
                        part = types.Part.from_text(text="Nothing to deduplicate.")
                    elif len(fn_responses) == 0:
                        part = types.Part.from_function_call(name="get_findings", args={})
                    elif len(fn_responses) == 1:
                        part = types.Part.from_function_call(
                            name="dedupe_findings",
                            args={
                                "primary_title": "File-to-eval command bridge primary",
                                "primary_id": 1,
                                "duplicate_ids": [2],
                                "reason": "Consolidated IPC file-to-eval RCE.",
                            },
                        )
                    elif len(fn_responses) == 2:
                        # Deduplicator re-reports primary with 'workspace/<name>'
                        part = types.Part.from_function_call(
                            name="report_findings",
                            args={
                                "report": {
                                    "findings": [
                                        {
                                            "id": 1,
                                            "title": "File-to-eval command bridge primary",
                                            "filepath": "workspace/db_container_pipe_processor.sh",
                                            "severity": "HIGH",
                                            "cwe": "CWE-78",
                                            "description": "Consolidated IPC file-to-eval RCE.",
                                            "line_numbers": [10, 12],
                                        }
                                    ]
                                }
                            },
                        )
                    else:
                        part = types.Part.from_text(text="Deduplication complete.")

                yield LlmResponse(
                    content=types.Content(role="model", parts=[part]),
                    usage_metadata=types.GenerateContentResponseUsageMetadata(
                        prompt_token_count=50,
                        candidates_token_count=20,
                        total_token_count=70,
                    ),
                )

        with mock.patch("core.graph_loader.LiteLlm", side_effect=lambda **kw: _ScriptedIssue18Llm()):
            rc = asyncio.run(
                mantis_main.pipeline(
                    str(self.root),
                    workflow_path=wf_path,
                    db_override=self.db_path,
                    sandbox_override="static-only",
                    auto_configure=False,
                    load_local=False,
                    scan_mode_override="file-by-file",
                    assume_yes=True,
                    enable_replan=False,
                )
            )
        self.assertEqual(rc, 0)

        all_rows = read_findings(self.db_path)
        self.assertEqual(len(all_rows), 2)
        by_id = {r["id"]: r for r in all_rows}
        # Both primary AND duplicate_merged rows carry the exact nested filepath!
        self.assertEqual(by_id[1]["filepath"], rel_vuln)
        self.assertEqual(by_id[2]["filepath"], rel_vuln)
        self.assertEqual(by_id[2]["status"], "duplicate_merged")
        for r in all_rows:
            self.assertFalse(r["filepath"].startswith("workspace/"), r)

        dossier = query_remediation_standalone(self.db_path, "1")
        self.assertIn(f"`{rel_vuln}`", dossier["remediation_summary"])
        self.assertNotIn("workspace/db_container_pipe_processor.sh", dossier["remediation_summary"])


if __name__ == "__main__":
    unittest.main()

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

"""Tests for continuous `--depth N` (1..100), full-stack coverage, and Hardware/RTL support."""

from __future__ import annotations

import asyncio
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from core.checklist import build_slice_audit_checklist
from core.config import get_llm_kwargs
from core.context import RunContext, current_run_context
from core.cost import load_run_plan, record_run_plan
from core.database import init_db, read_findings, record_run
from core.depth import (
    DEFAULT_DEPTH,
    count_active_security_files,
    parse_depth,
    plan_depth_batches,
    render_depth_hunting_directive,
    resolve_depth_profile,
)
from core.environments.static_env import StaticOnlyEnvironment
from core.graph_loader import (
    DEPTH_DIRECTIVE_MARKER,
    REPO_DOCS_DIRECTIVE_MARKER,
    _make_campaign_directive_before_model_callback,
)
from core.repo_docs import discover_repo_docs, render_repo_docs_inventory
from core.structural_index import (
    StructuralIndex,
    build_structural_index,
    complexity_for_file,
    extract_unit,
    _load_parser,
    state_dir_for_db,
)
from core.surveyor import _ARCHETYPE_BY_TAG, _AUDIT_FOCUS, survey
import main as mantis_main
from scripts.launch import build_parser, main as launch_main, run_launch
from tools import research_tools as rt
from tools import structural_tools as st


class DepthProfileContractTest(unittest.TestCase):
    def test_parse_depth_bounds_and_rejections(self):
        self.assertEqual(parse_depth(1), 1)
        self.assertEqual(parse_depth(DEFAULT_DEPTH), 30)
        self.assertEqual(parse_depth(100), 100)
        self.assertEqual(parse_depth(" 42 "), 42)
        for bad in (0, -1, 101, 999, True, False, "", "abc", 3.5, None):
            with self.assertRaises(ValueError, msg=f"expected rejection for {bad!r}"):
                parse_depth(bad)

    def test_profile_monotonicity_across_full_range(self):
        effort_rank = {"low": 0, "medium": 1, "high": 2, "max": 3}
        prev = resolve_depth_profile(1)
        self.assertEqual(prev.reasoning_effort, "low")
        self.assertEqual(prev.passes, 1)

        for d in range(2, 101):
            cur = resolve_depth_profile(d)
            self.assertGreaterEqual(effort_rank[cur.reasoning_effort], effort_rank[prev.reasoning_effort], d)
            self.assertGreaterEqual(cur.passes, prev.passes, d)
            self.assertGreaterEqual(cur.small_target_passes, prev.small_target_passes, d)
            self.assertGreaterEqual(cur.coverage_fraction, prev.coverage_fraction, d)
            self.assertLessEqual(cur.target_batch_files, prev.target_batch_files, d)
            self.assertLessEqual(cur.whole_file_limit, prev.whole_file_limit, d)
            self.assertGreaterEqual(cur.checklist_max_sinks, prev.checklist_max_sinks, d)
            self.assertGreaterEqual(cur.checklist_max_entrypoints, prev.checklist_max_entrypoints, d)
            self.assertGreaterEqual(cur.checklist_max_chars, prev.checklist_max_chars, d)
            self.assertGreaterEqual(cur.checklist_max_sinks_per_file, prev.checklist_max_sinks_per_file, d)
            self.assertGreaterEqual(cur.explorer_max_turns, prev.explorer_max_turns, d)
            prev = cur

        p30 = resolve_depth_profile(30)
        self.assertEqual(p30.reasoning_effort, "medium")
        self.assertEqual(p30.passes, 1)
        self.assertEqual(p30.checklist_max_sinks_per_file, 5)

        p100 = resolve_depth_profile(100)
        self.assertEqual(p100.reasoning_effort, "max")
        self.assertEqual(p100.passes, 2)
        self.assertEqual(p100.small_target_passes, 3)
        self.assertEqual(p100.coverage_fraction, 1.0)
        self.assertEqual(p100.max_batches, 0)
        self.assertTrue(p100.explorer_read_all_batch)

    def test_cli_depth_validation_and_explicit_passes_tracking(self):
        parser = build_parser()
        default_args = parser.parse_args(["repo"])
        self.assertIsNone(default_args.depth)
        self.assertEqual(default_args.passes, 1)
        self.assertFalse(getattr(default_args, "_passes_explicit", False))

        explicit_args = parser.parse_args(["repo", "--depth", "90", "--passes", "1"])
        self.assertEqual(explicit_args.depth, 90)
        self.assertEqual(explicit_args.passes, 1)
        self.assertTrue(getattr(explicit_args, "_passes_explicit", False))

        for bad in ("0", "101", "-3"):
            with patch.object(sys, "argv", ["launch.py", "repo", "--depth", bad]), \
                 contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as cm:
                    launch_main()
            self.assertEqual(cm.exception.code, 64, bad)

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(run_launch(target=".", depth=0), 64)
            self.assertEqual(run_launch(target=".", depth=101), 64)

    def test_gemini_clamps_max_and_xhigh_reasoning_effort_while_claude_preserves_it(self):
        env = {"GEMINI_API_KEY": "dummy", "ANTHROPIC_API_KEY": "dummy"}
        with patch.dict(os.environ, env, clear=False):
            _, gem_max = get_llm_kwargs(
                model_id="gemini/gemini-2.5-pro",
                reasoning_effort="max",
            )
            _, gem_xhigh = get_llm_kwargs(
                model_id="gemini/gemini-2.5-pro",
                reasoning_effort="xhigh",
            )
            _, claude_max = get_llm_kwargs(
                model_id="anthropic/claude-opus-5-5",
                reasoning_effort="max",
            )
        self.assertEqual(gem_max.get("reasoning_effort"), "high")
        self.assertEqual(gem_xhigh.get("reasoning_effort"), "high")
        self.assertEqual(claude_max.get("reasoning_effort"), "max")


class FullStackAndRTLToolchainTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_depth_rtl_")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(os.path.realpath(self._tmp.name))
        self.repo = self.root / "fullstack_soc"
        self.db = str(self.root / "knowledge.db")
        init_db(self.db)
        self._build_synthetic_repo()

    def _build_synthetic_repo(self):
        # Backend routes (18 files)
        routes = self.repo / "routes"
        routes.mkdir(parents=True)
        for i in range(18):
            (routes / f"handler_{i:02d}.ts").write_text(
                f"export function handleRoute{i}(req: any, db: any) {{\n"
                f"  const q = req.query.id;\n"
                f"  return db.query('SELECT * FROM users WHERE id = ' + q);\n"
                f"}}\n",
                encoding="utf-8",
            )

        # Frontend Angular components + HTML templates (16 files)
        fe = self.repo / "frontend" / "src" / "app"
        fe.mkdir(parents=True)
        for i in range(8):
            (fe / f"view_{i:02d}.component.ts").write_text(
                f"export class View{i}Component {{\n"
                f"  render(s: any, val: string) {{\n"
                f"    localStorage.setItem('tok', val);\n"
                f"    return s.bypassSecurityTrustHtml(val);\n"
                f"  }}\n"
                f"}}\n",
                encoding="utf-8",
            )
            (fe / f"view_{i:02d}.component.html").write_text(
                f"<div [innerHTML]=\"userHtml_{i}\"></div>\n",
                encoding="utf-8",
            )

        # Hardware / RTL: Verilog, SystemVerilog, VHDL (12 files)
        rtl = self.repo / "hw" / "rtl"
        rtl.mkdir(parents=True)
        (rtl / "aes_core.v").write_text(
            "module aes_core (\n"
            "  input wire clk,\n"
            "  input wire rst_n,\n"
            "  input wire [127:0] key_reg\n"
            ");\n"
            "  function [31:0] mask_word;\n"
            "    input [31:0] din;\n"
            "    begin\n"
            "      if (rst_n) mask_word = din;\n"
            "      else mask_word = 32'h0;\n"
            "    end\n"
            "  endfunction\n"
            "endmodule\n",
            encoding="utf-8",
        )
        (rtl / "csr_regfile.v").write_text(
            "module csr_regfile (\n"
            "  input wire clk,\n"
            "  input wire rst_n,\n"
            "  input wire [1:0] priv_lvl,\n"
            "  input wire regwen,\n"
            "  input wire [127:0] secret_key\n"
            ");\n"
            "  always @(posedge clk) begin\n"
            "    if (priv_lvl == 2'b11) begin\n"
            "      // BUG: missing regwen check on CSR write\n"
            "    end\n"
            "  end\n"
            "  aes_core u_aes (.clk(clk), .rst_n(rst_n), .key_reg(secret_key));\n"
            "endmodule\n",
            encoding="utf-8",
        )
        (rtl / "otp_ctrl.sv").write_text(
            "module otp_ctrl (\n"
            "  input logic clk_i,\n"
            "  input logic rst_ni\n"
            ");\n"
            "  function automatic logic check_lock(input logic regwen_i);\n"
            "    if (regwen_i) return 1'b1;\n"
            "    else return 1'b0;\n"
            "  endfunction\n"
            "  task automatic zeroize_keys();\n"
            "    for (int i = 0; i < 4; i++) begin\n"
            "      check_lock(1'b1);\n"
            "    end\n"
            "  endtask\n"
            "endmodule\n",
            encoding="utf-8",
        )
        (rtl / "lc_ctrl.sv").write_text(
            "module lc_ctrl (\n"
            "  input logic clk_i,\n"
            "  input logic rst_ni,\n"
            "  input logic [3:0] lc_state,\n"
            "  output logic debug_en\n"
            ");\n"
            "  always_comb begin\n"
            "    if (lc_state == 4'hA) debug_en = 1'b1;\n"
            "    else debug_en = 1'b0;\n"
            "  end\n"
            "  otp_ctrl u_otp (.clk_i(clk_i), .rst_ni(rst_ni));\n"
            "endmodule\n",
            encoding="utf-8",
        )
        (rtl / "key_vault.vhd").write_text(
            "library ieee;\n"
            "use ieee.std_logic_1164.all;\n"
            "entity key_vault is\n"
            "  port (clk : in std_logic; zeroize : in std_logic);\n"
            "end entity key_vault;\n"
            "architecture rtl of key_vault is\n"
            "begin\n"
            "  p_zero: process(clk)\n"
            "  begin\n"
            "    if zeroize = '1' then\n"
            "      null;\n"
            "    end if;\n"
            "  end process;\n"
            "end architecture rtl;\n",
            encoding="utf-8",
        )
        (rtl / "jtag_tap.vhd").write_text(
            "library ieee;\n"
            "use ieee.std_logic_1164.all;\n"
            "entity jtag_tap is\n"
            "  port (tck : in std_logic; jtag_debug_en : in std_logic);\n"
            "end entity jtag_tap;\n"
            "architecture rtl of jtag_tap is\n"
            "  function unlock_ok(en : std_logic) return boolean is\n"
            "  begin\n"
            "    if en = '1' then\n"
            "      return true;\n"
            "    end if;\n"
            "    return false;\n"
            "  end function;\n"
            "begin\n"
            "  p_fsm: process(tck)\n"
            "  begin\n"
            "    case jtag_debug_en is\n"
            "      when '1' => null;\n"
            "      when others => null;\n"
            "    end case;\n"
            "  end process;\n"
            "  u_key: entity work.key_vault port map (clk => tck, zeroize => jtag_debug_en);\n"
            "end architecture rtl;\n",
            encoding="utf-8",
        )
        for i in range(6):
            (rtl / f"bus_guard_{i}.sv").write_text(
                f"module bus_guard_{i}(input logic axi_awvalid, input logic sec_lvl);\n"
                f"  always_comb begin\n"
                f"    if (axi_awvalid && !sec_lvl) ;\n"
                f"  end\n"
                f"endmodule\n",
                encoding="utf-8",
            )

        # Config / IaC (6 files)
        iac = self.repo / "infra"
        iac.mkdir(parents=True)
        for i in range(6):
            (iac / f"net_{i}.tf").write_text(
                f'resource "aws_security_group_rule" "open_{i}" {{\n'
                f'  cidr_blocks = ["0.0.0.0/0"]\n'
                f'}}\n',
                encoding="utf-8",
            )

        # Noise files (styling, locale, lockfile) -- should NOT consume primary risk batches
        i18n = self.repo / "frontend" / "src" / "assets" / "i18n"
        i18n.mkdir(parents=True)
        for i in range(15):
            (i18n / f"lang_{i}.json").write_text('{"HELLO": "world"}\n', encoding="utf-8")
            (fe / f"style_{i}.scss").write_text(".btn { color: red; }\n", encoding="utf-8")
        (self.repo / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")

    def test_surveyor_ranks_frontend_iac_and_rtl_and_audit_focus_is_exhaustive(self):
        for tag, archetype in _ARCHETYPE_BY_TAG.items():
            self.assertIn(archetype, _AUDIT_FOCUS, f"Missing _AUDIT_FOCUS entry for {tag} -> {archetype}")

        astm = survey(self.repo)
        by_root = {
            tuple(s["root_paths"]): s
            for s in astm["slices"]
        }
        # RTL, frontend, routes, and infra should all register positive attack surface!
        rtl_slice = by_root.get(("hw/rtl",))
        fe_slice = by_root.get(("frontend/src",))
        routes_slice = by_root.get(("routes",))
        infra_slice = by_root.get(("infra",))
        self.assertIsNotNone(rtl_slice, astm["slices"])
        self.assertIsNotNone(fe_slice, astm["slices"])
        self.assertIsNotNone(routes_slice, astm["slices"])
        self.assertIsNotNone(infra_slice, astm["slices"])
        self.assertGreater(rtl_slice["signals"]["attack_surface"], 0.0)
        self.assertGreater(fe_slice["signals"]["attack_surface"], 0.0)
        self.assertGreater(routes_slice["signals"]["attack_surface"], 0.0)
        self.assertGreater(infra_slice["signals"]["attack_surface"], 0.0)
        self.assertIn("rtl_", rtl_slice["domain_archetype"])

    async def test_structural_index_natively_indexes_verilog_systemverilog_and_vhdl(self):
        state = state_dir_for_db(self.db, str(self.repo))
        manifest = build_structural_index(str(self.repo), state, "unknown")
        self.assertIn(manifest["status"], ("complete", "partial"))

        idx = StructuralIndex(state)
        # Verilog: csr_regfile instantiates aes_core; aes_core has mask_word
        self.assertEqual(idx.resolve_symbol("csr_regfile")["total"], 1)
        aes_sym = idx.resolve_symbol("aes_core")
        self.assertEqual(aes_sym["total"], 1)
        self.assertEqual(idx.resolve_symbol("mask_word")["total"], 1)
        aes_callers = idx.find_callers(aes_sym["results"][0])
        self.assertTrue(
            any("csr_regfile" in (r.get("caller") or "") for r in aes_callers["results"]),
            aes_callers,
        )

        # SystemVerilog: lc_ctrl instantiates otp_ctrl; zeroize_keys calls check_lock
        self.assertEqual(idx.resolve_symbol("lc_ctrl")["total"], 1)
        otp_sym = idx.resolve_symbol("otp_ctrl")
        self.assertEqual(otp_sym["total"], 1)
        lock_sym = idx.resolve_symbol("check_lock")
        self.assertEqual(lock_sym["total"], 1)
        self.assertEqual(idx.resolve_symbol("zeroize_keys")["total"], 1)
        otp_callers = idx.find_callers(otp_sym["results"][0])
        self.assertTrue(
            any("lc_ctrl" in (r.get("caller") or "") for r in otp_callers["results"]),
            otp_callers,
        )
        lock_callers = idx.find_callers(lock_sym["results"][0])
        self.assertTrue(
            any("zeroize_keys" in (r.get("caller") or "") for r in lock_callers["results"]),
            lock_callers,
        )

        # VHDL: jtag_tap instantiates work.key_vault; unlock_ok + p_fsm indexed
        kv_sym = idx.resolve_symbol("key_vault")
        self.assertEqual(kv_sym["total"], 1)
        self.assertEqual(idx.resolve_symbol("jtag_tap")["total"], 1)
        self.assertEqual(idx.resolve_symbol("unlock_ok")["total"], 1)
        self.assertEqual(idx.resolve_symbol("p_fsm")["total"], 1)
        kv_callers = idx.find_callers(kv_sym["results"][0])
        self.assertTrue(
            any("jtag_tap" in (r.get("caller") or "") for r in kv_callers["results"]),
            kv_callers,
        )

        # Complexity works on all three RTL languages
        for rtl_file in ("hw/rtl/csr_regfile.v", "hw/rtl/lc_ctrl.sv", "hw/rtl/jtag_tap.vhd"):
            comp = complexity_for_file(rtl_file, (self.repo / rtl_file).read_bytes())
            self.assertIsNotNone(comp, rtl_file)
            self.assertGreater(comp["complexity"], 0, rtl_file)

        # get_function_boundary works on RTL modules directly
        ctx = RunContext(
            jail_dir=str(self.repo),
            db_path=self.db,
            target_file=str(self.repo),
            run_id="r_rtl",
        )
        tok = current_run_context.set(ctx)
        try:
            b_v = await st.get_function_boundary("hw/rtl/csr_regfile.v", 3)
            self.assertIn("csr_regfile", b_v)
            b_sv = await st.get_function_boundary("hw/rtl/otp_ctrl.sv", 6)
            self.assertIn("check_lock", b_sv)
            b_vhd = await st.get_function_boundary("hw/rtl/jtag_tap.vhd", 10)
            self.assertIn("unlock_ok", b_vhd)
        finally:
            current_run_context.reset(tok)

    def test_depth_batching_covers_fullstack_and_rtl_at_depth_30_and_all_files_at_100(self):
        files = mantis_main.discover_files(self.repo)
        active = count_active_security_files(self.repo, files)
        # 18 routes + 16 frontend (.ts + .html) + 12 rtl + 6 infra = 52 active files
        # (15 .json in i18n + 15 .scss + 1 package-lock.json excluded)
        self.assertEqual(active, 52)

        # Depth 1..10 -> single whole campaign
        targets_1, _a1, mode_1 = mantis_main.resolve_scan_targets(
            self.repo, {"depth": 10}, files
        )
        self.assertEqual(mode_1, mantis_main.SCAN_MODE_WHOLE)
        self.assertEqual(targets_1, [str(self.repo)])

        # Depth 30 -> risk-ranked full-stack + RTL batches under cross-functional
        scope_30: dict = {}
        targets_30, _a30, mode_30 = mantis_main.resolve_scan_targets(
            self.repo, {"depth": 30}, files, scope_out=scope_30
        )
        self.assertEqual(mode_30, mantis_main.SCAN_MODE_CROSS_FUNCTIONAL)
        batches_30 = scope_30.get("depth_groups") or []
        self.assertGreaterEqual(len(batches_30), 2)
        self.assertEqual(len(targets_30), len(batches_30))
        covered_30 = {
            os.path.relpath(f, self.repo).replace(os.sep, "/")
            for b in batches_30
            for f in b["targets"]
        }
        # Depth 30 MUST include RTL + backend + frontend (and ZERO noise files)
        self.assertTrue(any(p.startswith("hw/rtl/") for p in covered_30), covered_30)
        self.assertTrue(any(p.startswith("routes/") for p in covered_30), covered_30)
        self.assertTrue(any(p.startswith("frontend/") for p in covered_30), covered_30)
        self.assertFalse(any(p.endswith(".scss") or "i18n/" in p or p == "package-lock.json" for p in covered_30))

        # Depth 100 -> 100% of active Tier-1 security files in tight micro-batches
        scope_100: dict = {}
        _t100, _a100, mode_100 = mantis_main.resolve_scan_targets(
            self.repo, {"depth": 100}, files, scope_out=scope_100
        )
        self.assertEqual(mode_100, mantis_main.SCAN_MODE_CROSS_FUNCTIONAL)
        batches_100 = scope_100.get("depth_groups") or []
        covered_100 = [f for b in batches_100 for f in b["targets"]]
        self.assertEqual(len(covered_100), len(set(covered_100)))
        self.assertEqual(len(covered_100), active)
        self.assertTrue(all(len(b["targets"]) <= 8 for b in batches_100))

        # Explicit --scan-mode ALWAYS overrides depth
        _tw, _aw, mode_w = mantis_main.resolve_scan_targets(
            self.repo, {"depth": 100, "scan_mode": mantis_main.SCAN_MODE_WHOLE}, files
        )
        self.assertEqual(mode_w, mantis_main.SCAN_MODE_WHOLE)
        _tf, _af, mode_f = mantis_main.resolve_scan_targets(
            self.repo, {"depth": 1, "scan_mode": mantis_main.SCAN_MODE_FILE_BY_FILE}, files
        )
        self.assertEqual(mode_f, mantis_main.SCAN_MODE_FILE_BY_FILE)

    def test_category_balanced_depth_scaled_checklist_includes_xss_rtl_and_iac(self):
        build_structural_index(str(self.repo), state_dir_for_db(self.db, str(self.repo)), "unknown")
        ctx_30 = RunContext(
            jail_dir=str(self.repo),
            db_path=self.db,
            target_file=str(self.repo),
            run_id="r_cl30",
            depth=30,
        )
        cl_30 = build_slice_audit_checklist(ctx_30)
        self.assertIn("[sql_query]", cl_30)
        self.assertIn("[template_xss]", cl_30)
        self.assertIn("[rtl_hw_security]", cl_30)
        self.assertIn("[config_iac]", cl_30)
        # RTL modules also show up as indexed entrypoints
        self.assertIn("csr_regfile", cl_30)

        ctx_100 = RunContext(
            jail_dir=str(self.repo),
            db_path=self.db,
            target_file=str(self.repo),
            run_id="r_cl100",
            depth=100,
        )
        cl_100 = build_slice_audit_checklist(ctx_100)
        self.assertGreaterEqual(len(cl_100), len(cl_30))

    def test_depth_directive_respects_inv2_hunting_stages_only(self):
        from google.adk.models import LlmRequest

        profile = resolve_depth_profile(90)
        directive = render_depth_hunting_directive(profile, pass_index=2, total_passes=2, batch_file_count=6)
        self.assertIn("90/100", directive)
        self.assertIn("PASS 2/2 ORTHOGONAL LENS", directive)

        ctx = RunContext(
            jail_dir=str(self.repo),
            db_path=self.db,
            target_file=str(self.repo),
            run_id="r_inv2",
            depth=90,
            depth_directive=directive,
        )
        tok = current_run_context.set(ctx)
        self.addCleanup(current_run_context.reset, tok)

        for hunting_stage in ("architect", "threat_modeler", "planner", "explorer", "researcher"):
            req = LlmRequest()
            req.config.system_instruction = "base"
            _make_campaign_directive_before_model_callback(hunting_stage)(None, req)
            self.assertIn(DEPTH_DIRECTIVE_MARKER, str(req.config.system_instruction), hunting_stage)

        for judge_stage in ("reviewer", "critic", "reproducer", "patcher", "calibrator"):
            req = LlmRequest()
            req.config.system_instruction = "base"
            _make_campaign_directive_before_model_callback(judge_stage)(None, req)
            self.assertNotIn(DEPTH_DIRECTIVE_MARKER, str(req.config.system_instruction), judge_stage)

    async def test_multi_file_batch_tools_allow_all_batch_files_while_single_file_stays_jailed(self):
        build_structural_index(str(self.repo), state_dir_for_db(self.db, str(self.repo)), "unknown")
        f1 = str(self.repo / "hw" / "rtl" / "csr_regfile.v")
        f2 = str(self.repo / "hw" / "rtl" / "lc_ctrl.sv")
        sb = StaticOnlyEnvironment(target_path=str(self.repo))

        # 1. Multi-file depth batch in cross-functional mode
        batch_ctx = RunContext(
            jail_dir=str(self.repo),
            db_path=self.db,
            target_file=f1,
            group_targets=(f1, f2),
            sandbox=sb,
            scan_mode="cross-functional",
            active_node="researcher",
            run_id="r_batch",
        )
        tok = current_run_context.set(batch_ctx)
        try:
            listed = await rt.list_files("")
            self.assertIn("hw/rtl/csr_regfile.v", listed)
            self.assertIn("hw/rtl/lc_ctrl.sv", listed)

            read_second = await rt.read_file("hw/rtl/lc_ctrl.sv")
            self.assertIn("debug_en", read_second)
            self.assertNotIn("Permission denied", read_second)

            bound_second = await st.get_function_boundary("hw/rtl/lc_ctrl.sv", 5)
            self.assertIn("lc_ctrl", bound_second)
            self.assertNotIn("Permission denied", bound_second)

            rep = rt.report_findings({
                "findings": [
                    {
                        "title": "Missing regwen lock check on CSR write",
                        "filepath": "hw/rtl/csr_regfile.v",
                        "description": "CSR write ignores regwen lock bit",
                        "line_numbers": [9],
                        "severity": "HIGH",
                    },
                    {
                        "title": "Lifecycle debug_en active in production state",
                        "filepath": "hw/rtl/lc_ctrl.sv",
                        "description": "debug_en asserted without auth",
                        "line_numbers": [8],
                        "severity": "CRITICAL",
                    },
                ]
            })
            self.assertIn("SUCCESS", rep)
            saved = read_findings(self.db, run_id="r_batch")
            self.assertEqual(len(saved), 2)
        finally:
            current_run_context.reset(tok)

        # 2. True single-file campaign stays strictly locked to f1
        single_ctx = RunContext(
            jail_dir=str(self.repo),
            db_path=self.db,
            target_file=f1,
            group_targets=(f1,),
            sandbox=sb,
            scan_mode="file-by-file",
            active_node="researcher",
            run_id="r_single",
        )
        tok2 = current_run_context.set(single_ctx)
        try:
            denied_read = await rt.read_file("hw/rtl/lc_ctrl.sv")
            self.assertIn("Permission denied", denied_read)
            denied_bound = await st.get_function_boundary("hw/rtl/lc_ctrl.sv", 5)
            self.assertIn("Permission denied", denied_bound)
            denied_rep = rt.report_findings({
                "findings": [{
                    "title": "Out-of-scope file finding",
                    "filepath": "hw/rtl/lc_ctrl.sv",
                    "description": "Should be rejected",
                    "line_numbers": [8],
                    "severity": "HIGH",
                }]
            })
            self.assertIn("single-file scans may only report findings", denied_rep)
        finally:
            current_run_context.reset(tok2)

    def test_depth_plan_persists_and_resumes_with_member_files_intact(self):
        # Verify record_run_plan / load_run_plan round-trip depth + batch groups
        f1 = str(self.repo / "hw" / "rtl" / "csr_regfile.v")
        f2 = str(self.repo / "hw" / "rtl" / "aes_core.v")
        f3 = str(self.repo / "hw" / "rtl" / "lc_ctrl.sv")
        f4 = str(self.repo / "hw" / "rtl" / "otp_ctrl.sv")
        record_run(self.db, "run_depth_resume", model="openai/nonexistent")
        groups = [
            {"targets": [f1, f2], "hypothesis": None, "chain": None},
            {"targets": [f3, f4], "hypothesis": None, "chain": None},
        ]
        ok = record_run_plan(
            self.db,
            "run_depth_resume",
            targets=[f1, f3],
            target_root=str(self.repo),
            plan_groups=groups,
            depth=65,
        )
        self.assertTrue(ok)
        loaded = load_run_plan(self.db, "run_depth_resume", str(self.repo))
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["depth"], 65)
        self.assertEqual(len(loaded["plan_groups"]), 2)
        self.assertEqual(loaded["plan_groups"][1]["targets"], [f3, f4])

        # End-to-end pipeline override precedence: explicit --passes 1 overrides depth 90!
        seen_passes: list[int] = []
        seen_depths: list[int] = []

        async def _fake_exec(_runner, _ss, filepath, rid, **kw):
            ctx = current_run_context.get()
            seen_passes.append(ctx.pass_index)
            seen_depths.append(ctx.depth)
            kw["budget_controller"].audit_code_reads += 1
            return False

        tiny = self.root / "tiny_rtl"
        tiny.mkdir()
        (tiny / "lock.v").write_text("module lock(input regwen); endmodule\n", encoding="utf-8")
        db2 = str(self.root / "tiny.db")
        init_db(db2)
        env = {k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}
        env["OPENAI_API_KEY"] = "dummy"
        with patch.dict(os.environ, env, clear=True), \
             patch.object(mantis_main, "execute_sub_task", side_effect=_fake_exec), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            rc = asyncio.run(
                mantis_main.pipeline(
                    scan_target=str(tiny),
                    db_override=db2,
                    model_override="openai/nonexistent",
                    api_base_override="http://127.0.0.1:9",
                    sandbox_override="static-only",
                    auto_configure=False,
                    assume_yes=True,
                    depth=90,
                    passes=1,
                    passes_explicit=True,
                )
            )
        self.assertEqual(rc, 0)
        self.assertEqual(seen_passes, [1])
        self.assertEqual(seen_depths, [90])


class GenericDomainsAndRepoDocsTest(unittest.TestCase):
    """Tests TIER_INTENT doc discovery, blocklist-default depth planning,
    cross-domain Surveyor/Checklist coverage, and the 13 newly bundled grammars."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="mantis_generic_docs_")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(os.path.realpath(self._tmp.name))
        self.repo = self.root / "polyglot_repo"
        self.repo.mkdir()
        self.db = str(self.root / "knowledge.db")
        init_db(self.db)

    def test_repo_docs_discovery_priority_safety_and_inv2_isolation(self):
        from google.adk.models import LlmRequest

        # Create security, architecture, overview, noise, spoiler, and escaping symlink docs
        (self.repo / "README.md").write_text("# Polyglot Service\nOverview.\n", encoding="utf-8")
        (self.repo / "SECURITY.md").write_text("# Security Policy\nThreat boundaries.\n", encoding="utf-8")
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "THREAT_MODEL.md").write_text("# Threat Model\nInvariants.\n", encoding="utf-8")
        (self.repo / "docs" / "architecture.md").write_text("# Architecture\nComponents.\n", encoding="utf-8")
        (self.repo / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")
        (self.repo / "LICENSE.md").write_text("Apache 2.0\n", encoding="utf-8")
        (self.repo / "docs" / "solutions.md").write_text("Challenge answers\n", encoding="utf-8")
        (self.repo / "node_modules" / "pkg").mkdir(parents=True)
        (self.repo / "node_modules" / "pkg" / "SECURITY.md").write_text("vendored\n", encoding="utf-8")
        outside = self.root / "outside_secret.md"
        outside.write_text("TOP SECRET\n", encoding="utf-8")
        try:
            os.symlink(str(outside), str(self.repo / "docs" / "SECURITY_ESCAPE.md"))
        except OSError:
            pass

        docs = discover_repo_docs(str(self.repo))
        rels = [d["path"] for d in docs]
        self.assertIn("SECURITY.md", rels)
        self.assertIn("docs/THREAT_MODEL.md", rels)
        self.assertIn("docs/architecture.md", rels)
        self.assertIn("README.md", rels)
        # Excluded noise, spoilers, vendored dirs, and escaping symlinks
        self.assertNotIn("CHANGELOG.md", rels)
        self.assertNotIn("LICENSE.md", rels)
        self.assertNotIn("docs/solutions.md", rels)
        self.assertNotIn("node_modules/pkg/SECURITY.md", rels)
        self.assertNotIn("docs/SECURITY_ESCAPE.md", rels)
        # Security / threat model docs sort ahead of architecture & README
        self.assertLess(rels.index("SECURITY.md"), rels.index("docs/architecture.md"))
        self.assertLess(rels.index("docs/architecture.md"), rels.index("README.md"))

        inv = render_repo_docs_inventory(str(self.repo))
        self.assertIn(REPO_DOCS_DIRECTIVE_MARKER, inv)
        self.assertIn("TIER_INTENT", inv)
        self.assertIn("docs/THREAT_MODEL.md", inv)
        # Inventory lists paths/metadata ONLY, never raw document prose
        self.assertNotIn("Threat boundaries.", inv)
        self.assertNotIn("TOP SECRET", inv)

        # INV-2: injected ONLY into architect and threat_modeler, never reviewer/critic/researcher
        ctx = RunContext(
            jail_dir=str(self.repo),
            db_path=self.db,
            target_file=str(self.repo),
            run_id="r_docs",
        )
        tok = current_run_context.set(ctx)
        self.addCleanup(current_run_context.reset, tok)

        for allowed_stage in ("architect", "threat_modeler"):
            req = LlmRequest()
            req.config.system_instruction = "base"
            _make_campaign_directive_before_model_callback(allowed_stage)(None, req)
            self.assertIn(REPO_DOCS_DIRECTIVE_MARKER, str(req.config.system_instruction), allowed_stage)

        for excluded_stage in ("planner", "explorer", "researcher", "reviewer", "critic", "reproducer", "patcher", "calibrator"):
            req = LlmRequest()
            req.config.system_instruction = "base"
            _make_campaign_directive_before_model_callback(excluded_stage)(None, req)
            self.assertNotIn(REPO_DOCS_DIRECTIVE_MARKER, str(req.config.system_instruction), excluded_stage)

        # Single-file scans must NOT receive repo docs inventory (avoids widening single-file scope)
        single_file = self.repo / "app.py"
        single_file.write_text("print(1)\n", encoding="utf-8")
        single_ctx = RunContext(
            jail_dir=str(self.repo),
            db_path=self.db,
            target_file=str(single_file),
            group_targets=(str(single_file),),
            scan_mode="file-by-file",
            run_id="r_docs_single",
        )
        tok2 = current_run_context.set(single_ctx)
        self.addCleanup(current_run_context.reset, tok2)
        req_single = LlmRequest()
        req_single.config.system_instruction = "base"
        _make_campaign_directive_before_model_callback("architect")(None, req_single)
        self.assertNotIn(REPO_DOCS_DIRECTIVE_MARKER, str(req_single.config.system_instruction))

    def test_depth_blocklist_default_includes_unknown_dsl_while_excluding_noise(self):
        # Unknown text/DSL extensions (e.g. .p4, .customdsl) are kept as Priority 1,
        # while binary/media/lock/style/doc noise stays excluded.
        (self.repo / "net").mkdir()
        (self.repo / "net" / "switch.p4").write_text("parser MyParser() {}\n", encoding="utf-8")
        (self.repo / "net" / "rules.customdsl").write_text("allow * -> admin\n", encoding="utf-8")
        (self.repo / "logo.png").write_bytes(b"\x89PNG\r\n")
        (self.repo / "weights.safetensors").write_bytes(b"\x00\x01")
        (self.repo / "README.md").write_text("# hi\n", encoding="utf-8")
        (self.repo / "style.css").write_text("body{}\n", encoding="utf-8")

        files = mantis_main.discover_files(self.repo)
        self.assertEqual(count_active_security_files(self.repo, files), 2)
        batches = plan_depth_batches(self.repo, files, resolve_depth_profile(100))
        covered = {
            os.path.relpath(fp, self.repo).replace(os.sep, "/")
            for b in batches
            for fp in b["targets"]
        }
        self.assertEqual(covered, {"net/switch.p4", "net/rules.customdsl"})

    def test_cross_domain_surveyor_and_checklist_detect_new_domains(self):
        # Smart contract
        (self.repo / "contracts").mkdir()
        for i in range(5):
            (self.repo / "contracts" / f"Vault{i}.sol").write_text(
                "pragma solidity ^0.8.0;\n"
                f"contract Vault{i} {{\n"
                "  function withdraw(uint amt) external {\n"
                "    require(tx.origin == msg.sender);\n"
                "    (bool ok,) = msg.sender.call{value: amt}(\"\");\n"
                "    require(ok);\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )
        # CI/CD GitHub Actions workflow
        (self.repo / ".github" / "workflows").mkdir(parents=True)
        for i in range(5):
            (self.repo / ".github" / "workflows" / f"pr_{i}.yml").write_text(
                "on: pull_request_target\n"
                "jobs:\n  run:\n    steps:\n"
                "      - run: echo ${{ github.event.pull_request.title }}\n",
                encoding="utf-8",
            )
        # AI/ML model loader
        (self.repo / "ml").mkdir()
        for i in range(5):
            (self.repo / "ml" / f"loader_{i}.py").write_text(
                "import torch\n"
                "def load_weights(p):\n"
                "    return torch.load(p, weights_only=False)\n",
                encoding="utf-8",
            )
        # Mobile iOS/Swift
        (self.repo / "mobile").mkdir()
        for i in range(5):
            (self.repo / "mobile" / f"Bridge{i}.swift").write_text(
                f"class Bridge{i} {{\n"
                "  func open(u: String) {\n"
                "    webView.evaluateJavaScript(u)\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )
        # Electron desktop
        (self.repo / "desktop").mkdir()
        for i in range(5):
            (self.repo / "desktop" / f"main_{i}.js").write_text(
                "const opts = { nodeIntegration: true, contextIsolation: false };\n"
                "ipcMain.on('open', (e, url) => shell.openExternal(url));\n",
                encoding="utf-8",
            )
        # Rust unsafe FFI
        (self.repo / "native").mkdir()
        for i in range(5):
            (self.repo / "native" / f"ffi_{i}.rs").write_text(
                "pub fn copy_raw(ptr: *const u8, len: usize) -> &'static [u8] {\n"
                "    unsafe { std::slice::from_raw_parts(ptr, len) }\n"
                "}\n",
                encoding="utf-8",
            )

        astm = survey(self.repo, include_churn=False)
        by_root = {tuple(s["root_paths"]): s for s in astm["slices"]}
        self.assertEqual(by_root[("contracts",)]["domain_archetype"], "smart_contract_audit")
        self.assertEqual(by_root[(".github/workflows",)]["domain_archetype"], "cicd_supply_chain_audit")
        self.assertEqual(by_root[("ml",)]["domain_archetype"], "ai_ml_security_audit")
        self.assertEqual(by_root[("mobile",)]["domain_archetype"], "mobile_security_audit")
        self.assertEqual(by_root[("desktop",)]["domain_archetype"], "desktop_extension_audit")
        self.assertEqual(by_root[("native",)]["domain_archetype"], "memory_safety_audit")

        build_structural_index(str(self.repo), state_dir_for_db(self.db, str(self.repo)), "unknown")
        ctx = RunContext(
            jail_dir=str(self.repo),
            db_path=self.db,
            target_file=str(self.repo),
            run_id="r_poly_cl",
            depth=60,
        )
        cl = build_slice_audit_checklist(ctx)
        for cat in (
            "[cicd_supply_chain]",
            "[smart_contract]",
            "[memory_unsafe]",
            "[desktop_extension]",
            "[mobile_webview_ipc]",
        ):
            self.assertIn(cat, cl, cl)
        self.assertTrue(("[ai_ml_deser]" in cl) or ("[ai_ml_security]" in cl), cl)

    def test_structural_index_extracts_symbols_and_calls_for_13_new_bundled_grammars(self):
        cases = [
            ("a.swift", "swift", b"class Bridge {\n  func openUrl(u: String) {\n    if u.isEmpty { return }\n    webView.evaluateJavaScript(u)\n  }\n}\n", "Bridge.openUrl", ("webView", "evaluateJavaScript")),
            ("a.m", "objc", b"@implementation Auth\n- (void)handleUrl:(NSString *)u {\n  [webView loadRequest:u];\n}\n@end\n", "Auth.handleUrl", ("webView", "loadRequest")),
            ("a.dart", "dart", b"class Vault {\n  void withdraw(int x) {\n    bank.transfer(x);\n  }\n}\n", "Vault.withdraw", ("bank", "transfer")),
            ("a.sol", "solidity", b"contract Vault {\n  function withdraw(uint amt) external {\n    checkBalance(amt);\n    msg.sender.call{value: amt}(\"\");\n  }\n}\n", "Vault.withdraw", ("sender", "call")),
            ("a.zig", "zig", b"pub fn process(buf: []u8) void {\n  std.mem.copy(u8, buf, buf);\n}\n", "process", ("mem", "copy")),
            ("a.scala", "scala", b"object Main {\n  def handle(x: String): Unit = {\n    svc.exec(x)\n  }\n}\n", "Main.handle", ("svc", "exec")),
            ("a.ex", "elixir", b"defmodule App.Vault do\n  def withdraw(amt) do\n    Bank.send_funds(amt)\n  end\nend\n", "App.Vault.withdraw", ("Bank", "send_funds")),
            ("a.lua", "lua", b"function handle(u)\n  os.execute(u)\nend\n", "handle", ("os", "execute")),
            ("a.sh", "bash", b"run_cmd() {\n  eval \"$1\"\n}\n", "run_cmd", ("", "eval")),
            ("a.ps1", "powershell", b"function Invoke-Deploy($cmd) {\n  Invoke-Expression $cmd\n}\n", "Invoke-Deploy", ("", "Invoke-Expression")),
            ("a.tf", "hcl", b"resource \"aws_security_group\" \"open\" {\n  name = \"open\"\n}\n", "resource.aws_security_group.open", None),
            ("a.rego", "rego", b"package authz\nallow {\n  http.send({\"url\": input.u})\n}\n", "allow", ("http", "send")),
            ("a.sql", "sql", b"CREATE FUNCTION get_user(uid INT) RETURNS TEXT AS $$\nBEGIN\n  RETURN run_query(uid);\nEND;\n$$ LANGUAGE plpgsql;\n", "get_user", ("", "run_query")),
        ]
        for fname, lang, src, expected_sym, expected_edge in cases:
            parser = _load_parser(lang)
            self.assertIsNotNone(parser, f"bundled parser missing for {lang}")
            unit = extract_unit(fname, src, lang, parser)
            qnames = {s["qualified_name"] for s in unit["symbols"]}
            self.assertIn(expected_sym, qnames, f"{lang}: {qnames}")
            if expected_edge is not None:
                id_to_q = {s["symbol_id"]: s["qualified_name"] for s in unit["symbols"]}
                got_edges = {
                    (id_to_q.get(e["caller_id"]), e.get("qualifier", ""), e["callee_name"])
                    for e in unit["edges"]
                }
                self.assertIn((expected_sym, expected_edge[0], expected_edge[1]), got_edges, f"{lang}: {got_edges}")


if __name__ == "__main__":
    unittest.main()

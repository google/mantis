#!/usr/bin/env python3
"""Mantis Configuration Manager.

Configures workflow.json with sandboxes (static-only, gvisor, microsandbox, gce),
model selection (Gemini, Claude, GLM, OpenAI-compatible), and fast preflight testing.
Supports local configuration overlays via workflow.local.json.
"""

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Ensure reference root is in sys.path when script is run directly
_REF_ROOT = str(Path(__file__).resolve().parent.parent)
if _REF_ROOT not in sys.path:
    sys.path.insert(0, _REF_ROOT)

from core.config import (
    DEFAULT_MODEL,
    PLACEHOLDER_STRINGS,
    RECOMMENDED_MODELS,
    SUPPORTED_SANDBOXES,
    get_llm_kwargs,
    is_placeholder,
    normalize_model_id,
)


def get_local_workflow_path(base_workflow_path: str) -> str:
    """Returns path to workflow.local.json adjacent to base workflow path."""
    base_dir = os.path.dirname(os.path.abspath(base_workflow_path))
    return os.path.join(base_dir, "workflow.local.json")


def merge_dicts(base: dict, overlay: dict) -> dict:
    """Deeply merges overlay dictionary into base dictionary.
    
    Cleanly replaces sandbox configurations when switching sandbox mechanisms
    or resetting options to avoid inheriting incompatible base options.
    """
    merged = dict(base)
    for k, v in overlay.items():
        if k == "sandbox" and isinstance(v, dict):
            base_sb = merged.get("sandbox", {}) if isinstance(merged.get("sandbox"), dict) else {}
            base_type = base_sb.get("type")
            new_type = v.get("type", base_type)
            if new_type in ("static-only", "static"):
                merged["sandbox"] = {"type": new_type, "options": {}}
            elif new_type != base_type or ("options" in v and v["options"] == {}):
                merged["sandbox"] = dict(v)
                if "options" not in merged["sandbox"] or not isinstance(merged["sandbox"]["options"], dict):
                    merged["sandbox"]["options"] = {}
            else:
                merged["sandbox"] = {
                    "type": new_type,
                    "options": merge_dicts(
                        base_sb.get("options", {}) if isinstance(base_sb.get("options"), dict) else {},
                        v.get("options", {}) if isinstance(v.get("options"), dict) else {},
                    ),
                }
        elif k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
            merged[k] = merge_dicts(merged[k], v)
        else:
            merged[k] = v
    return merged


def find_workflow_json(custom_path: str = "") -> str:
    """Discovers workflow.json across standard workspace and repository locations."""
    if custom_path:
        return os.path.abspath(custom_path)

    candidates = [
        os.path.join(os.getcwd(), "workflow.json"),
        os.path.join(os.getcwd(), "reference", "workflow.json"),
        os.path.join(Path(__file__).resolve().parent.parent, "workflow.json"),
        os.path.join(Path(__file__).resolve().parent.parent.parent, "reference", "workflow.json"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)

    # Fallback to default in reference directory
    return os.path.abspath(
        os.path.join(Path(__file__).resolve().parent.parent, "workflow.json")
    )


def load_workflow_dict(workflow_path: str, load_local: bool = True) -> dict:
    """Loads workflow JSON dictionary from path or returns a default template.
    
    If load_local is True, checks for workflow.local.json (or .workflow.local.json)
    adjacent to workflow_path and merges its configuration on top.
    """
    data = None
    if os.path.exists(workflow_path):
        try:
            with open(workflow_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    data = loaded
        except Exception:
            pass

    if data is None:
        data = {
            "name": "mantis_vulnerability_pipeline",
            "config": {
                "db_path": "knowledge.db",
                "retry_attempts": 3,
                "default_model": DEFAULT_MODEL,
                "reasoning_effort": "medium",
                "seed_prompt": "Initial Task Input: Evaluate {filepath}",
                "sandbox": {"type": "static-only", "options": {}},
            },
            "nodes": [],
            "edges": [],
        }

    if load_local:
        base_dir = os.path.dirname(os.path.abspath(workflow_path))
        local_candidates = [
            os.path.join(base_dir, "workflow.local.json"),
            os.path.join(base_dir, ".workflow.local.json"),
        ]
        abs_wf = os.path.abspath(workflow_path)
        for cand in local_candidates:
            if os.path.exists(cand) and os.path.abspath(cand) != abs_wf:
                try:
                    with open(cand, "r", encoding="utf-8") as lf:
                        local_data = json.load(lf)
                    if isinstance(local_data, dict):
                        if "config" in local_data and isinstance(local_data["config"], dict):
                            data["config"] = merge_dicts(data.get("config", {}), local_data["config"])
                        for top_k in (
                            "sandbox",
                            "default_model",
                            "api_base",
                            "timeout",
                            "reasoning_effort",
                            "db_path",
                            "retry_attempts",
                            "seed_prompt",
                        ):
                            if top_k in local_data and (
                                "config" not in local_data
                                or top_k not in local_data.get("config", {})
                            ):
                                if top_k == "sandbox" and isinstance(local_data[top_k], dict):
                                    data.setdefault("config", {})["sandbox"] = merge_dicts(
                                        {"sandbox": data.get("config", {}).get("sandbox", {})},
                                        {"sandbox": local_data["sandbox"]},
                                    )["sandbox"]
                                elif isinstance(local_data[top_k], dict) and isinstance(data.get("config", {}).get(top_k), dict):
                                    data.setdefault("config", {})[top_k] = merge_dicts(
                                        data.get("config", {}).get(top_k, {}), local_data[top_k]
                                    )
                                else:
                                    data.setdefault("config", {})[top_k] = local_data[top_k]
                        for k in ("name", "nodes", "edges"):
                            if k in local_data:
                                data[k] = local_data[k]
                    break
                except Exception as e:
                    print(f"[CONFIG WARNING] Could not load local overlay {cand}: {e}")

    return data


def detect_capabilities() -> dict:
    """Inspects the local host environment to detect available sandboxes, tools, and credentials."""
    caps: dict[str, Any] = {
        "kvm": False,
        "docker": False,
        "podman": False,
        "container_tool": None,
        "runsc": False,
        "gcloud": False,
        "gcp_auth": False,
        "gcp_account": None,
        "gcp_project": None,
        "vertex_project": os.environ.get("VERTEXAI_PROJECT")
        or os.environ.get("GOOGLE_CLOUD_PROJECT"),
        "gemini_api_key": bool(
            os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        ),
        "anthropic_api_key": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "openai_api_key": bool(os.environ.get("OPENAI_API_KEY")),
        "llm_api_base": os.environ.get("LLM_API_BASE"),
        "recommended_sandbox": "static-only",
        "available_sandboxes": ["static-only"],
    }

    # 1. Check KVM for microsandbox
    if os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK):
        caps["kvm"] = True
        caps["available_sandboxes"].append("microsandbox")

    # 2. Check container engines and gVisor
    for tool in ("docker", "podman"):
        if shutil.which(tool):
            caps[tool] = True
            if not caps["container_tool"]:
                caps["container_tool"] = tool

            # Check runsc runtime
            try:
                out = subprocess.run(
                    [tool, "info", "--format", "{{json .Runtimes}}"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                if out.returncode == 0 and "runsc" in out.stdout:
                    caps["runsc"] = True
                    if "gvisor" not in caps["available_sandboxes"]:
                        caps["available_sandboxes"].append("gvisor")
            except Exception:
                pass

    # 3. Check gcloud CLI and GCP Auth
    gcloud_bin = shutil.which("gcloud")
    if gcloud_bin:
        caps["gcloud"] = True
        try:
            p_auth = subprocess.run(
                [
                    gcloud_bin,
                    "auth",
                    "list",
                    "--filter=status:ACTIVE",
                    "--format=value(account)",
                ],
                capture_output=True,
                text=True,
                timeout=4,
            )
            if p_auth.returncode == 0 and p_auth.stdout.strip():
                caps["gcp_auth"] = True
                caps["gcp_account"] = p_auth.stdout.strip().splitlines()[0].strip()

            p_proj = subprocess.run(
                [gcloud_bin, "config", "get-value", "project"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if p_proj.returncode == 0:
                val = p_proj.stdout.strip()
                if val and "unset" not in val and not is_placeholder(val):
                    caps["gcp_project"] = val
        except Exception:
            pass

    if caps["gcloud"] and caps["gcp_auth"] and (caps["gcp_project"] or caps["vertex_project"]):
        caps["available_sandboxes"].append("gce")

    # Select recommendation hierarchy
    if "gce" in caps["available_sandboxes"] and caps["gcp_project"]:
        caps["recommended_sandbox"] = "gce"
    elif "gvisor" in caps["available_sandboxes"]:
        caps["recommended_sandbox"] = "gvisor"
    elif "microsandbox" in caps["available_sandboxes"]:
        caps["recommended_sandbox"] = "microsandbox"
    else:
        caps["recommended_sandbox"] = "static-only"

    return caps


def is_default_or_unconfigured(config: dict) -> Tuple[bool, List[str]]:
    """Evaluates if workflow config contains default placeholders or unconfigured settings."""
    issues = []
    if not isinstance(config, dict):
        return True, ["Config is not a valid dictionary."]

    sb = config.get("sandbox", {})
    sb_type = sb.get("type", "static-only") if isinstance(sb, dict) else "static-only"
    sb_opts = sb.get("options", {}) if isinstance(sb, dict) else {}

    # Sandbox checks
    if sb_type == "gce":
        proj = sb_opts.get("project")
        if is_placeholder(proj):
            env_proj = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("VERTEXAI_PROJECT")
            if is_placeholder(env_proj):
                issues.append(
                    f"GCE Sandbox 'options.project' contains default placeholder ('{proj}')."
                )
        if not shutil.which("gcloud"):
            issues.append("GCE Sandbox requires 'gcloud' CLI on PATH.")
    elif sb_type == "gvisor":
        if not shutil.which("docker") and not shutil.which("podman"):
            issues.append("gVisor sandbox requires 'docker' or 'podman' on PATH.")
    elif sb_type == "microsandbox":
        if not os.path.exists("/dev/kvm"):
            issues.append("Microsandbox requires /dev/kvm virtualization device.")

    # Model checks
    model = config.get("default_model", DEFAULT_MODEL)
    if is_placeholder(model):
        issues.append(f"Model '{model}' contains placeholder string.")

    if str(model).startswith("vertex_ai/"):
        proj = (
            sb_opts.get("project")
            or os.environ.get("VERTEXAI_PROJECT")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or config.get("project")
        )
        if is_placeholder(proj):
            caps = detect_capabilities()
            if not caps.get("gcp_project") and not caps.get("vertex_project"):
                issues.append(
                    f"Vertex AI Model '{model}' requires VERTEXAI_PROJECT / GOOGLE_CLOUD_PROJECT or active gcloud project."
                )

    return bool(issues), issues


async def _check_sandbox_preflight(sandbox_cfg: dict, target_path: str = "") -> Tuple[bool, str]:
    """Runs the asynchronous preflight check on a sandbox configuration."""
    sb_type = sandbox_cfg.get("type", "static-only")
    if sb_type in ("static-only", "static"):
        return True, "Static-only sandbox ready (dynamic execution disabled)."

    if sb_type == "gce":
        opts = sandbox_cfg.get("options", {})
        proj = opts.get("project") or os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("VERTEXAI_PROJECT")
        if not proj or is_placeholder(proj):
            return False, f"GCE Project is unconfigured placeholder '{proj}'."
        if not shutil.which("gcloud"):
            return False, "'gcloud' CLI tool not found on PATH."
        # Fast gcloud auth test
        try:
            p = subprocess.run(
                ["gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=value(account)"],
                capture_output=True,
                text=True,
                timeout=5,
                cwd=tempfile.gettempdir(),
            )
            if p.returncode != 0 or not p.stdout.strip():
                return False, "No active GCP credentials found in gcloud auth list."
            return (
                True,
                f"GCE credentials & project verified (Project: {proj}). "
                f"(Note: Ephemeral VM creation requires pre-provisioned VPC/Subnet/Image per docs/gce_sandbox_setup.md).",
            )
        except Exception as e:
            return False, f"GCE gcloud check failed: {e}"

    if sb_type == "gvisor":
        raw_tool = sandbox_cfg.get("options", {}).get("container_tool")
        if raw_tool and raw_tool not in ("docker", "podman"):
            return False, f"Invalid container_tool '{raw_tool}'. Only 'docker' and 'podman' are allowed."
        tool = raw_tool or ("docker" if shutil.which("docker") else "podman")
        if not tool or not shutil.which(tool):
            return False, "Docker or Podman not installed for gVisor sandbox."
        try:
            p = subprocess.run(
                [tool, "info", "--format", "{{json .Runtimes}}"],
                capture_output=True,
                text=True,
                timeout=5,
                cwd=tempfile.gettempdir(),
            )
            if p.returncode != 0:
                return False, f"Cannot connect to {tool} daemon."
            if "runsc" not in p.stdout:
                return False, f"Runtime 'runsc' (gVisor) is not registered in {tool} runtimes."
            return True, f"gVisor Sandbox ready ({tool} + runsc)."
        except Exception as e:
            return False, f"gVisor check failed: {e}"

    if sb_type == "microsandbox":
        if not os.path.exists("/dev/kvm"):
            return False, "/dev/kvm device does not exist."
        if not os.access("/dev/kvm", os.R_OK | os.W_OK):
            return False, "Current user lacks read/write permissions on /dev/kvm."
        return True, "Microsandbox ready (/dev/kvm accessible)."

    return False, f"Unknown sandbox type '{sb_type}'."


def _check_llm_preflight(config: dict) -> Tuple[bool, str]:
    """Fast validation of LLM configuration and credentials in ~1s."""
    model = config.get("default_model", DEFAULT_MODEL)
    api_base = config.get("api_base")
    timeout = config.get("timeout")
    effort = config.get("reasoning_effort")

    try:
        resolved_model, kwargs = get_llm_kwargs(
            model_id=model,
            api_base=api_base,
            timeout=timeout,
            reasoning_effort=effort,
            config=config,
        )
    except Exception as e:
        return False, f"LLM Configuration Error: {e}"

    if resolved_model.startswith("vertex_ai/openai/"):
        proj = kwargs.get("vertex_project")
        if not proj or is_placeholder(proj):
            if not api_base:
                return False, "Vertex AI OpenAI model requires a valid GCP Project ID or --api-base endpoint."
        endpoint_info = f" @ {api_base}" if api_base else ""
        return True, f"Vertex AI OpenAI LLM configured (Model: {resolved_model}{endpoint_info})."

    if resolved_model.startswith("vertex_ai/"):
        proj = kwargs.get("vertex_project")
        if not proj or is_placeholder(proj):
            return False, "Vertex AI requires a valid GCP Project ID."
        return True, f"Vertex AI LLM configured (Model: {resolved_model}, Project: {proj})."

    if resolved_model.startswith("anthropic/"):
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False, "Anthropic model requires ANTHROPIC_API_KEY environment variable."
        return True, f"Anthropic LLM configured (Model: {resolved_model})."

    if resolved_model.startswith("openai/") or api_base:
        if not os.environ.get("OPENAI_API_KEY") and not api_base:
            return False, "OpenAI model requires OPENAI_API_KEY or --api-base endpoint."
        endpoint_info = f" @ {api_base}" if api_base else ""
        return True, f"OpenAI-compatible LLM configured (Model: {resolved_model}{endpoint_info})."

    if resolved_model.startswith("gemini-"):
        if not os.environ.get("GEMINI_API_KEY") and not os.environ.get("GOOGLE_API_KEY"):
            # Check if vertex credentials are available
            if not os.environ.get("GOOGLE_CLOUD_PROJECT") and not os.environ.get("VERTEXAI_PROJECT") and not kwargs.get("vertex_project"):
                return False, "Gemini model requires GEMINI_API_KEY or GCP Project ID for Vertex AI."
        return True, f"Gemini LLM configured (Model: {resolved_model})."

    return True, f"LLM configured (Model: {resolved_model})."


async def run_preflight_checks_async(
    config: dict,
    test_llm: bool = True,
    test_sandbox: bool = True,
    target_path: str = "",
) -> Tuple[bool, List[str]]:
    """Runs combined LLM and Sandbox preflight testing asynchronously in ~1-2s."""
    messages = []
    all_ok = True

    if test_llm:
        ok, msg = _check_llm_preflight(config)
        messages.append(f"[LLM PREFLIGHT] {'✅ PASSED' if ok else '❌ FAILED'}: {msg}")
        if not ok:
            all_ok = False

    if test_sandbox:
        sb_cfg = config.get("sandbox", {}) if isinstance(config, dict) else {}
        ok, msg = await _check_sandbox_preflight(sb_cfg, target_path=target_path)
        messages.append(f"[SANDBOX PREFLIGHT] {'✅ PASSED' if ok else '❌ FAILED'}: {msg}")
        if not ok:
            all_ok = False

    return all_ok, messages


def run_preflight_checks(
    config: dict,
    test_llm: bool = True,
    test_sandbox: bool = True,
    target_path: str = "",
) -> Tuple[bool, List[str]]:
    """Runs combined LLM and Sandbox preflight testing safely in sync contexts."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(
                asyncio.run,
                run_preflight_checks_async(
                    config,
                    test_llm=test_llm,
                    test_sandbox=test_sandbox,
                    target_path=target_path,
                ),
            ).result()
    else:
        return asyncio.run(
            run_preflight_checks_async(
                config,
                test_llm=test_llm,
                test_sandbox=test_sandbox,
                target_path=target_path,
            )
        )


def update_workflow_config(
    workflow_path: str,
    updates: dict,
    save: bool = True,
    update_all_nodes: bool = False,
    save_tracked: bool = False,
) -> dict:
    """Updates workflow configuration.
    
    If save_tracked is True, modifies base workflow.json directly.
    If save_tracked is False, applies updates to workflow data and saves local config
    to workflow.local.json, preserving tracked workflow.json.
    """
    wf_data = load_workflow_dict(workflow_path, load_local=not save_tracked)
    cfg = wf_data.setdefault("config", {})

    if "default_model" in updates:
        cfg["default_model"] = updates["default_model"]
    if "api_base" in updates:
        cfg["api_base"] = updates["api_base"]
    if "timeout" in updates:
        cfg["timeout"] = updates["timeout"]
    if "reasoning_effort" in updates:
        cfg["reasoning_effort"] = updates["reasoning_effort"]
    if "db_path" in updates:
        cfg["db_path"] = updates["db_path"]

    if "sandbox" in updates:
        sb_update = updates["sandbox"]
        if isinstance(sb_update, str):
            cfg["sandbox"] = {"type": sb_update, "options": {}}
        elif isinstance(sb_update, dict):
            current_sb = cfg.setdefault("sandbox", {})
            if "type" in sb_update:
                new_type = sb_update["type"]
                current_sb["type"] = new_type
                if new_type in ("static-only", "static"):
                    current_sb["options"] = {}
                elif "options" in sb_update and isinstance(sb_update["options"], dict):
                    current_sb["options"] = dict(sb_update["options"])
            elif "options" in sb_update and isinstance(sb_update["options"], dict):
                current_opts = current_sb.setdefault("options", {})
                current_opts.update(sb_update["options"])
            for k, v in sb_update.items():
                if k not in ("type", "options"):
                    current_sb.setdefault("options", {})[k] = v

    if update_all_nodes and "default_model" in updates:
        for node in wf_data.get("nodes", []):
            if node.get("type") == "agent":
                node["model"] = updates["default_model"]

    if save:
        if save_tracked:
            save_path = workflow_path
            os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(wf_data, f, indent=2)
                f.write("\n")
        else:
            save_path = get_local_workflow_path(workflow_path)
            os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
            local_payload = {"config": cfg}
            if update_all_nodes and "nodes" in wf_data:
                local_payload["nodes"] = wf_data["nodes"]
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(local_payload, f, indent=2)
                f.write("\n")

    return wf_data


def _refuse_silent_downgrade(reason: str) -> None:
    """Fails closed instead of silently downgrading a configured sandbox to static-only.

    In static-only mode dynamic isolation is absent. Downgrading must be an
    explicit operator decision via MANTIS_ALLOW_SANDBOX_DOWNGRADE=1.
    """
    if os.environ.get("MANTIS_ALLOW_SANDBOX_DOWNGRADE") == "1":
        return
    print(f"ERROR: {reason}", file=sys.stderr)
    print(
        "   Refusing to silently downgrade sandbox to 'static-only' "
        "(dynamic exploit reproduction and patch verification would be skipped).",
        file=sys.stderr,
    )
    print(
        "   To proceed with a degraded, session-only static scan, re-run with "
        "MANTIS_ALLOW_SANDBOX_DOWNGRADE=1. Downgrades are never persisted.",
        file=sys.stderr,
    )
    raise SystemExit(2)


async def ensure_configured_async(
    workflow_path: str = "",
    auto: bool = True,
    interactive: bool = False,
    overrides: Optional[dict] = None,
    save: bool = True,
    save_tracked: bool = False,
) -> dict:
    """Ensures workflow configuration is valid asynchronously. Auto-resolves defaults or prompts if needed."""
    target_wf = find_workflow_json(workflow_path)
    wf_data = load_workflow_dict(target_wf, load_local=not save_tracked)
    cfg = wf_data.get("config", {})

    overrides = overrides or {}
    if overrides:
        wf_data = update_workflow_config(
            target_wf, overrides, save=False, save_tracked=save_tracked
        )
        cfg = wf_data.get("config", {})

    is_unconf, issues = is_default_or_unconfigured(cfg)
    caps = detect_capabilities()

    sb_type = cfg.get("sandbox", {}).get("type", "static-only")
    sb_opts = dict(cfg.get("sandbox", {}).get("options", {}))
    sb_available = sb_type in caps.get("available_sandboxes", ["static-only"])

    if not is_unconf and not overrides and sb_available:
        ok, _ = await run_preflight_checks_async(cfg)
        if ok:
            return cfg

    updates: dict[str, Any] = {}

    if interactive:
        return run_interactive_wizard(target_wf)

    if auto:
        # Auto-resolve GCE project if unconfigured
        if sb_type == "gce":
            cur_proj = sb_opts.get("project", "")
            if is_placeholder(cur_proj):
                resolved_proj = caps.get("gcp_project") or caps.get("vertex_project")
                if resolved_proj and "gce" in caps.get("available_sandboxes", []):
                    sb_opts["project"] = resolved_proj
                    updates["sandbox"] = {"type": "gce", "options": sb_opts}
                    os.environ.setdefault("GOOGLE_CLOUD_PROJECT", resolved_proj)
                    os.environ.setdefault("VERTEXAI_PROJECT", resolved_proj)
                else:
                    _refuse_silent_downgrade(
                        "GCE sandbox credentials/project not configured or unavailable."
                    )
                    print(
                        "⚠️  [REPRO DISABLED] Operator-approved downgrade 'gce' -> 'static-only' for THIS SESSION ONLY."
                    )
                    # Session-only: not added to updates, so never persisted to workflow.local.json
                    cfg = {**cfg, "sandbox": {"type": "static-only", "options": {}}}
            elif "gce" not in caps.get("available_sandboxes", []):
                _refuse_silent_downgrade(
                    "Host lacks requirements for 'gce' sandbox (gcloud/auth missing)."
                )
                print(
                    "⚠️  [REPRO DISABLED] Operator-approved downgrade 'gce' -> 'static-only' for THIS SESSION ONLY."
                )
                cfg = {**cfg, "sandbox": {"type": "static-only", "options": {}}}
        elif sb_type not in caps.get("available_sandboxes", []):
            _refuse_silent_downgrade(
                f"Host lacks requirements for '{sb_type}' sandbox."
            )
            print(
                f"⚠️  [REPRO DISABLED] Operator-approved downgrade '{sb_type}' -> 'static-only' for THIS SESSION ONLY."
            )
            cfg = {**cfg, "sandbox": {"type": "static-only", "options": {}}}

        # Auto-resolve Model
        model = cfg.get("default_model", DEFAULT_MODEL)
        if is_placeholder(model):
            updates["default_model"] = DEFAULT_MODEL
        elif str(model).startswith("vertex_ai/"):
            if not os.environ.get("VERTEXAI_PROJECT") and not os.environ.get("GOOGLE_CLOUD_PROJECT"):
                resolved_proj = (
                    caps.get("gcp_project")
                    or caps.get("vertex_project")
                    or sb_opts.get("project")
                )
                if resolved_proj and not is_placeholder(resolved_proj):
                    os.environ.setdefault("VERTEXAI_PROJECT", resolved_proj)
                    os.environ.setdefault("GOOGLE_CLOUD_PROJECT", resolved_proj)

        if updates or overrides:
            all_updates = {**updates, **overrides}
            # Safety net: never allow a downgraded sandbox type to be persisted to disk
            if all_updates.get("sandbox", {}).get("type") == "static-only" and sb_type not in ("", "static-only"):
                del all_updates["sandbox"]
            if all_updates:
                wf_data = update_workflow_config(
                    target_wf,
                    all_updates,
                    save=save,
                    save_tracked=save_tracked,
                )
                return wf_data.get("config", {})

    return cfg


def ensure_configured(
    workflow_path: str = "",
    auto: bool = True,
    interactive: bool = False,
    overrides: Optional[dict] = None,
    save: bool = True,
    save_tracked: bool = False,
) -> dict:
    """Ensures workflow configuration is valid. Auto-resolves defaults or prompts if needed."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(
                asyncio.run,
                ensure_configured_async(
                    workflow_path=workflow_path,
                    auto=auto,
                    interactive=interactive,
                    overrides=overrides,
                    save=save,
                    save_tracked=save_tracked,
                ),
            ).result()
    else:
        return asyncio.run(
            ensure_configured_async(
                workflow_path=workflow_path,
                auto=auto,
                interactive=interactive,
                overrides=overrides,
                save=save,
                save_tracked=save_tracked,
            )
        )


def run_interactive_wizard(workflow_path: str) -> dict:
    """Guided terminal configuration wizard."""
    print("\n============================================================")
    print(" 🛠️  Mantis Security Pipeline Configuration Wizard")
    print("============================================================\n")

    caps = detect_capabilities()
    wf_data = load_workflow_dict(workflow_path)
    cfg = wf_data.get("config", {})

    print("Detected Host Capabilities:")
    print(f"  • KVM Virtualization: {'✅ Available' if caps['kvm'] else '❌ Not found'}")
    print(f"  • Container Engine:   {caps['container_tool'] or '❌ None'} (runsc: {'✅ Yes' if caps['runsc'] else '❌ No'})")
    print(f"  • Google Cloud SDK:   {'✅ Active (' + str(caps['gcp_account']) + ')' if caps['gcp_auth'] else '❌ No active auth'}")
    print(f"  • GCP Project:        {caps['gcp_project'] or '❌ Not set'}")
    print()

    # 1. Select Sandbox
    print("Step 1: Select Sandbox Execution Environment")
    sb_choices = [
        ("static-only", "Static Analysis only (Fastest, zero isolation requirement)"),
        ("gvisor", "gVisor Container Sandbox (Networkless OCI container with runsc)"),
        ("microsandbox", "Microsandbox VM (Hardware-accelerated KVM microVM)"),
        ("gce", "Google Compute Engine Sandbox (Hardened ephemeral cloud VM)"),
    ]
    for i, (k, desc) in enumerate(sb_choices, 1):
        avail = " [Available]" if k in caps["available_sandboxes"] else ""
        print(f"  {i}. {k:13} - {desc}{avail}")

    def_sb = cfg.get("sandbox", {}).get("type", caps["recommended_sandbox"])
    def_idx = 1
    for idx, (k, _) in enumerate(sb_choices, 1):
        if k == def_sb:
            def_idx = idx
            break

    try:
        choice = input(f"\nSelect sandbox [1-4] (default: {def_idx} -> {def_sb}): ").strip()
        idx = int(choice) if choice else def_idx
        selected_sb = sb_choices[idx - 1][0]
    except Exception:
        selected_sb = def_sb

    sb_options: dict[str, Any] = {}
    if selected_sb == "gce":
        cur_proj = cfg.get("sandbox", {}).get("options", {}).get("project")
        def_proj = cur_proj if (cur_proj and not is_placeholder(cur_proj)) else (caps.get("gcp_project") or "my-gcp-project")
        proj = input(f"Enter GCP Project ID (default: {def_proj}): ").strip() or def_proj
        zone = input("Enter GCP Zone (default: us-central1-b): ").strip() or "us-central1-b"
        image = input("Enter VM Image Name (default: mantis-sandbox-image): ").strip() or "mantis-sandbox-image"
        subnet = input("Enter Subnet Name (default: mantis-isolated-subnet): ").strip() or "mantis-isolated-subnet"
        sb_options = {
            "project": proj,
            "zone": zone,
            "image": image,
            "subnet": subnet,
            "workdir": "/workspace",
            "tunnel_through_iap": True,
            "no_service_account": True,
            "no_external_ip": True,
            "verify_isolation": True,
            "timeout_seconds": 600,
        }

    # 2. Select Model
    print("\nStep 2: Select AI Model")
    model_choices = [
        ("vertex_ai/gemini-3.7-flash", "Gemini 3.7 Flash via Vertex AI (Recommended)"),
        ("vertex_ai/gemini-3.5-flash-lite", "Gemini 3.5 Flash Lite via Vertex AI (Fast & Low Cost)"),
        ("vertex_ai/claude-opus-5", "Claude Opus 5 via Vertex AI Model Garden"),
        ("vertex_ai/zai_org/glm-5.2-maas", "GLM 5.2 via Vertex AI Model Garden"),
        ("custom_openai", "Custom OpenAI-compatible endpoint (vLLM / Ollama / Proxy)"),
    ]
    for i, (k, desc) in enumerate(model_choices, 1):
        print(f"  {i}. {k:32} - {desc}")

    def_model = cfg.get("default_model", DEFAULT_MODEL)
    def_m_idx = 1
    for idx, (k, _) in enumerate(model_choices, 1):
        if k == def_model:
            def_m_idx = idx
            break

    try:
        m_choice = input(f"\nSelect model [1-6] (default: {def_m_idx} -> {def_model}): ").strip()
        m_idx = int(m_choice) if m_choice else def_m_idx
        selected_model = model_choices[m_idx - 1][0]
    except Exception:
        selected_model = def_model

    api_base = None
    if selected_model == "custom_openai":
        custom_name = input("Enter model ID (e.g. openai/gpt-4o or custom-model): ").strip() or "openai/custom-model"
        selected_model = custom_name
        api_base = input("Enter OpenAI API base URL (e.g. http://localhost:8000/v1): ").strip()

    updates = {
        "sandbox": {"type": selected_sb, "options": sb_options},
        "default_model": selected_model,
    }
    if api_base:
        updates["api_base"] = api_base

    print("\nRunning preflight checks on configured settings...")
    preview_wf = update_workflow_config(workflow_path, updates, save=False)
    ok, messages = run_preflight_checks(preview_wf.get("config", {}))
    for m in messages:
        print(f"  {m}")

    save_choice = input("\nSave configuration locally (workflow.local.json)? [Y/n]: ").strip().lower()
    if save_choice in ("", "y", "yes"):
        update_workflow_config(workflow_path, updates, save=True, save_tracked=False)
        print(f"\n✅ Configuration saved to: {get_local_workflow_path(workflow_path)}\n")
    else:
        print("\nSkipped saving configuration.\n")

    return preview_wf.get("config", {})


def print_status(workflow_path: str, as_json: bool = False, config_override: Optional[dict] = None) -> None:
    """Prints current configuration and preflight test status."""
    target_wf = find_workflow_json(workflow_path)
    if config_override is not None:
        cfg = config_override
    else:
        wf_data = load_workflow_dict(target_wf, load_local=True)
        cfg = wf_data.get("config", {})
    caps = detect_capabilities()
    ok, messages = run_preflight_checks(cfg)
    is_unconf, issues = is_default_or_unconfigured(cfg)

    local_path = get_local_workflow_path(target_wf)
    has_local = os.path.exists(local_path)

    if as_json:
        payload = {
            "workflow_file": target_wf,
            "local_overlay_file": local_path if has_local else None,
            "config": cfg,
            "capabilities": caps,
            "is_unconfigured": is_unconf,
            "issues": issues,
            "preflight_passed": ok,
            "preflight_messages": messages,
        }
        print(json.dumps(payload, indent=2))
        return

    print("============================================================")
    print(" 📋 Mantis Workflow Configuration Status")
    print("============================================================")
    print(f"Base Workflow:   {target_wf}")
    if has_local:
        print(f"Local Overlay:   {local_path}")
    print(f"Default Model:   {cfg.get('default_model', DEFAULT_MODEL)}")
    if cfg.get("api_base"):
        print(f"API Base:        {cfg.get('api_base')}")
    print(f"Sandbox Type:    {cfg.get('sandbox', {}).get('type', 'static-only')}")
    if cfg.get("sandbox", {}).get("options"):
        print(f"Sandbox Options: {json.dumps(cfg.get('sandbox', {}).get('options'))}")
    print(f"Knowledge DB:    {cfg.get('db_path', 'knowledge.db')}")
    print("\nPreflight Diagnostics:")
    for msg in messages:
        print(f"  {msg}")
    if is_unconf:
        print("\n⚠️ Configuration Issues Found:")
        for iss in issues:
            print(f"  - {iss}")
        print("\nRun './scripts/configure.py --auto' or '--interactive' to fix.")
    print("============================================================\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mantis Pipeline Configuration Manager: configure sandboxes, models, and test preflight."
    )
    parser.add_argument("--workflow", "-w", type=str, default="", help="Path to workflow.json")
    parser.add_argument(
        "--sandbox",
        "-s",
        type=str,
        choices=["static-only", "static", "gvisor", "microsandbox", "gce"],
        help="Sandbox execution mechanism",
    )
    parser.add_argument(
        "--model",
        "-m",
        type=str,
        help="Default LLM model (e.g. gemini-3.7-flash, vertex_ai/claude-opus-5, openai/my-model)",
    )
    parser.add_argument("--api-base", type=str, help="Custom LLM API Base URL")
    parser.add_argument(
        "--reasoning-effort",
        type=str,
        choices=["low", "medium", "high"],
        help="Reasoning effort level",
    )
    parser.add_argument("--timeout", type=float, help="LLM request timeout in seconds")
    parser.add_argument("--db", "-d", type=str, help="Path to knowledge SQLite database")

    # GCE Sandbox Options
    parser.add_argument("--project", "-p", type=str, help="GCP Project ID for GCE sandbox or Vertex AI")
    parser.add_argument("--zone", "-z", type=str, help="GCP Zone (e.g. us-central1-b)")
    parser.add_argument("--image", "-i", type=str, help="Sandbox image name")
    parser.add_argument("--subnet", type=str, help="GCE Subnet name")
    parser.add_argument("--workdir", type=str, help="Sandbox working directory (/workspace)")

    # Operations
    parser.add_argument("--interactive", action="store_true", help="Launch interactive configuration wizard")
    parser.add_argument("--auto", action="store_true", help="Auto-detect capabilities and configure optimal settings")
    parser.add_argument(
        "--save",
        action="store_true",
        help="Explicitly save configuration changes (defaults to workflow.local.json)",
    )
    parser.add_argument(
        "--save-tracked",
        "--global",
        dest="save_tracked",
        action="store_true",
        help="Save configuration changes directly to base tracked workflow.json instead of workflow.local.json overlay",
    )
    parser.add_argument("--test", "--preflight", action="store_true", help="Run fast preflight validation tests (~1-2s)")
    parser.add_argument("--check-clean", action="store_true", help="Verify base workflow.json uses default unconfigured placeholders (for pre-commit)")
    parser.add_argument("--show", action="store_true", help="Display current configuration status")
    parser.add_argument("--dry-run", action="store_true", help="Show changes without writing to workflow.json or workflow.local.json")
    parser.add_argument("--update-nodes", action="store_true", help="Update all agent node models to match default_model")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    target_wf = find_workflow_json(args.workflow)
    save_tracked = bool(args.save_tracked)
    save = not args.dry_run

    # 0. Pre-commit check clean mode
    if args.check_clean:
        wf_data = load_workflow_dict(target_wf, load_local=False)
        cfg = wf_data.get("config", {})
        sb_opts = cfg.get("sandbox", {}).get("options", {})
        proj = sb_opts.get("project", "")
        if proj and not is_placeholder(proj):
            print(
                f"❌ PRE-COMMIT FAILURE: '{target_wf}' contains non-placeholder project: '{proj}'.\n"
                f"   Please revert 'options.project' to 'YOUR_PROJECT_ID' before committing:\n"
                f"   python3 reference/scripts/configure.py --project YOUR_PROJECT_ID --save-tracked",
                file=sys.stderr,
            )
            return 1
        print(f"✅ Pre-commit check passed: '{target_wf}' uses safe default placeholders.")
        return 0

    # 1. Interactive Mode
    if args.interactive:
        run_interactive_wizard(target_wf)
        return 0

    # 2. Status Only Mode
    if args.show:
        print_status(target_wf, as_json=args.json)
        return 0

    # Collect CLI overrides
    updates: dict[str, Any] = {}
    if args.model:
        updates["default_model"] = normalize_model_id(args.model)
    if args.api_base:
        updates["api_base"] = args.api_base
    if args.timeout is not None:
        updates["timeout"] = args.timeout
    if args.reasoning_effort:
        updates["reasoning_effort"] = args.reasoning_effort
    if args.db:
        updates["db_path"] = args.db

    # Sandbox updates
    if args.sandbox:
        sb_update: dict[str, Any] = {"type": args.sandbox, "options": {}}
        if args.project:
            sb_update["options"]["project"] = args.project
        if args.zone:
            sb_update["options"]["zone"] = args.zone
        if args.image:
            sb_update["options"]["image"] = args.image
        if args.subnet:
            sb_update["options"]["subnet"] = args.subnet
        if args.workdir:
            sb_update["options"]["workdir"] = args.workdir
        updates["sandbox"] = sb_update
    elif any([args.project, args.zone, args.image, args.subnet, args.workdir]):
        sb_opts = {}
        if args.project:
            sb_opts["project"] = args.project
        if args.zone:
            sb_opts["zone"] = args.zone
        if args.image:
            sb_opts["image"] = args.image
        if args.subnet:
            sb_opts["subnet"] = args.subnet
        if args.workdir:
            sb_opts["workdir"] = args.workdir
        updates["sandbox"] = {"options": sb_opts}

    # 3. Auto-Configure Mode
    if args.auto:
        cfg = ensure_configured(
            target_wf,
            auto=True,
            overrides=updates,
            save=save,
            save_tracked=save_tracked,
        )
        if not args.json:
            action = "Simulated auto-configuration for" if args.dry_run else "Auto-configured Mantis settings saved to"
            dest = target_wf if save_tracked else get_local_workflow_path(target_wf)
            print(f"✅ {action} {dest}")
        print_status(target_wf, as_json=args.json, config_override=cfg if args.dry_run else None)
        return 0

    # 4. CLI Updates Mode or Explicit --save
    if updates or args.save:
        updated_data = update_workflow_config(
            target_wf,
            updates,
            save=save,
            update_all_nodes=args.update_nodes,
            save_tracked=save_tracked,
        )
        if not args.json:
            action = "Simulated update for" if args.dry_run else "Saved updates to"
            dest = target_wf if save_tracked else get_local_workflow_path(target_wf)
            print(f"✅ {action} {dest}")
        if args.test:
            ok, msgs = run_preflight_checks(updated_data.get("config", {}))
            if args.json:
                print(json.dumps({"preflight_passed": ok, "messages": msgs}, indent=2))
            else:
                for m in msgs:
                    print(m)
            return 0 if ok else 1
        print_status(target_wf, as_json=args.json, config_override=updated_data.get("config") if args.dry_run else None)
        return 0

    # 5. Preflight Test Only
    if args.test:
        wf_data = load_workflow_dict(target_wf, load_local=True)
        ok, msgs = run_preflight_checks(wf_data.get("config", {}))
        if args.json:
            print(json.dumps({"preflight_passed": ok, "messages": msgs}, indent=2))
        else:
            print_status(target_wf)
        return 0 if ok else 1

    # Default action: show status
    print_status(target_wf, as_json=args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())

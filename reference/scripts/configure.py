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

"""Mantis Configuration Manager.

Configures workflow.json with sandboxes (static-only, gvisor, microsandbox, gce),
model selection (Gemini, Claude, GLM, OpenAI-compatible), and fast preflight testing.
Supports local configuration overlays via workflow.local.json.
"""

import argparse
import asyncio
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
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

# Guest images the microsandbox tier can run. The first is the operator-built
# image from ./install.sh (sandbox/Dockerfile); the fallbacks are the pinned
# base images install.sh pulls directly when no container builder is present
# (mirror.gcr.io first because some networks block Docker Hub). Keep this list
# in sync with the FALLBACK_IMAGES list in install.sh.
MICROSANDBOX_DEFAULT_IMAGE = "mantis-sandbox:latest"
MICROSANDBOX_FALLBACK_IMAGES = (
    "mirror.gcr.io/library/python:3-slim",
    "docker.io/library/python:3-slim",
)


def get_local_workflow_path(base_workflow_path: str) -> str:
    """Returns path to local workflow overlay adjacent to base workflow path."""
    base_dir = os.path.dirname(os.path.abspath(base_workflow_path))
    base_name = os.path.basename(base_workflow_path)
    stem = base_name[:-5] if base_name.endswith(".json") else base_name
    return os.path.join(base_dir, f"{stem}.local.json")


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
                sb_proj = v.get("options", {}).get("project") if isinstance(v.get("options"), dict) else None
                if sb_proj and not merged.get("project"):
                    merged["project"] = sb_proj
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
    """Discovers workflow.json across standard reference package locations.

    Never probes untrusted $CWD/workflow.json by default to prevent repository
    graph hijacking. Explicit custom paths must be supplied via CLI/argument.
    """
    if custom_path:
        return os.path.abspath(custom_path)

    # SECURITY (INV-4): every candidate below is derived from __file__ (the installed
    # package location). $CWD is never probed: launch.py resolves the operator's
    # configured sandbox through this function, so a workflow.json planted in an
    # untrusted checkout would otherwise dictate the execution graph and sandbox policy.
    package_wf = os.path.join(Path(__file__).resolve().parent.parent, "workflow.json")
    parent_ref_wf = os.path.join(Path(__file__).resolve().parent.parent.parent, "reference", "workflow.json")

    for candidate in [package_wf, parent_ref_wf]:
        if os.path.exists(candidate):
            return os.path.abspath(candidate)

    return os.path.abspath(package_wf)


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
        base_name = os.path.basename(workflow_path)
        stem = base_name[:-5] if base_name.endswith(".json") else base_name
        local_candidates = [
            os.path.join(base_dir, f"{stem}.local.json"),
            os.path.join(base_dir, f".{stem}.local.json"),
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


def check_microsandbox_virtualization() -> Tuple[bool, str]:
    """Platform-aware check that the microsandbox tier can boot microVMs here.

    Linux: requires a readable/writable /dev/kvm. macOS (Apple Silicon):
    libkrun rides Hypervisor.framework -- no /dev/kvm exists, the bundled
    libkrunfw in the microsandbox wheel is the requirement. Mirrors the
    platform guard in MicrosandboxEnvironment.__init__.
    """
    if sys.platform.startswith("linux"):
        if not os.path.exists("/dev/kvm"):
            return False, "/dev/kvm device does not exist."
        if not os.access("/dev/kvm", os.R_OK | os.W_OK):
            return False, "Current user lacks read/write permissions on /dev/kvm."
        return True, "KVM virtualization available (/dev/kvm accessible)."
    if sys.platform == "darwin":
        if platform.machine() != "arm64":
            return False, "microsandbox on macOS requires Apple Silicon (arm64)."
        try:
            import microsandbox as _msb  # noqa: F401
        except Exception as e:
            return False, f"microsandbox package not importable: {e}"
        return True, "Hypervisor.framework virtualization available (Apple Silicon + microsandbox wheel)."
    return False, f"microsandbox is not supported on platform '{sys.platform}'."


def find_cached_microsandbox_image(preferred: str = "") -> Optional[str]:
    """Returns the first locally cached guest image usable by the microsandbox tier.

    The runtime boots with PullPolicy.NEVER, so an image missing from the local
    cache means every reproducer campaign fails at first execute. Checks the
    operator's configured image first, then the install.sh-built image, then
    the pinned fallback base images. Returns None when nothing is cached.
    """
    candidates = []
    if preferred:
        candidates.append(preferred)
    candidates.append(MICROSANDBOX_DEFAULT_IMAGE)
    candidates.extend(MICROSANDBOX_FALLBACK_IMAGES)

    async def _probe() -> Optional[str]:
        from microsandbox import Image, ImageNotFoundError

        for cand in candidates:
            try:
                await Image.get(cand)
                return cand
            except ImageNotFoundError:
                continue
            except Exception:
                # Cache DB unavailable (locked/permissions): treat as no image
                # rather than crashing configuration.
                return None
        return None

    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                return executor.submit(asyncio.run, _probe()).result()
        return asyncio.run(_probe())
    except Exception:
        return None


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
        "microsandbox_image": None,
        "recommended_sandbox": "static-only",
        "available_sandboxes": ["static-only"],
    }

    # 1. Check virtualization for microsandbox (Linux KVM or macOS
    # Hypervisor.framework -- see check_microsandbox_virtualization).
    virt_ok, _ = check_microsandbox_virtualization()
    if virt_ok:
        caps["kvm"] = os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)
        caps["available_sandboxes"].append("microsandbox")
        caps["microsandbox_image"] = find_cached_microsandbox_image()

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

    # Select recommendation hierarchy. Microsandbox ranks first when a guest
    # image is cached: it is the only tier whose runnability is fully verified
    # client-side (hardware microVM + image present), whereas 'gce' merely
    # having gcloud auth says nothing about the pre-provisioned VPC/subnet/VM
    # image it needs, and gvisor shares the host kernel. Without a cached
    # image microsandbox is NOT recommended: the runtime never pulls
    # (PullPolicy.NEVER), so every campaign would fail at first execute.
    if "microsandbox" in caps["available_sandboxes"] and caps["microsandbox_image"]:
        caps["recommended_sandbox"] = "microsandbox"
    elif "gce" in caps["available_sandboxes"] and caps["gcp_project"]:
        caps["recommended_sandbox"] = "gce"
    elif "gvisor" in caps["available_sandboxes"]:
        caps["recommended_sandbox"] = "gvisor"
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
        virt_ok, virt_msg = check_microsandbox_virtualization()
        if not virt_ok:
            issues.append(f"Microsandbox virtualization unavailable: {virt_msg}")

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
        virt_ok, virt_msg = check_microsandbox_virtualization()
        if not virt_ok:
            return False, virt_msg
        configured_image = str(sandbox_cfg.get("options", {}).get("image", "") or "")
        cached = find_cached_microsandbox_image(preferred=configured_image)
        if configured_image and cached != configured_image:
            return False, (
                f"Configured guest image '{configured_image}' is not in the local cache "
                f"(the sandbox never pulls at run time). Run ./install.sh to provision it."
            )
        if not cached:
            return False, (
                "No microsandbox guest image found in the local cache "
                "(the sandbox never pulls at run time). Run ./install.sh to provision one."
            )
        return True, f"Microsandbox ready ({virt_msg} Guest image: {cached})."

    return False, f"Unknown sandbox type '{sb_type}'."


def _probe_llm_reachability(
    resolved_model: str,
    kwargs: dict,
    prompt: str = "test",
    max_tokens: int = 256,
    timeout: float = 15.0,
) -> Tuple[bool, str]:
    """Actively probes LLM endpoint reachability, credentials, and dependencies with a minimal test prompt."""
    try:
        import litellm
    except ImportError:
        return False, "LiteLLM is not installed in the current environment."

    # For Vertex AI partner models (e.g. vertex_ai/claude-*, vertex_ai/zai_org/*),
    # verify that required client dependencies are installed
    if resolved_model.startswith("vertex_ai/"):
        if "claude" in resolved_model:
            try:
                import anthropic  # noqa: F401
                import vertexai  # noqa: F401
            except ImportError as ie:
                return (
                    False,
                    f"Missing dependency for Vertex AI partner model '{resolved_model}': {ie}. "
                    f"Run 'pip install google-cloud-aiplatform anthropic' or re-run './install.sh'."
                )

    from core.config import (
        is_rate_limit_error,
        extract_retry_after,
        extract_rate_limit_detail,
        compute_full_jitter_delay,
        is_auth_error,
        format_auth_error_message,
    )

    call_kwargs = dict(kwargs)
    call_kwargs["max_tokens"] = max_tokens
    call_kwargs["timeout"] = timeout
    call_kwargs["model"] = resolved_model

    max_probe_attempts = 3
    for attempt in range(max_probe_attempts):
        try:
            response = litellm.completion(
                messages=[{"role": "user", "content": prompt}],
                **call_kwargs,
            )
            if response and getattr(response, "choices", None) and len(response.choices) > 0:
                return True, f"LLM reachability verified for '{resolved_model}'."
            return True, f"LLM probe received response for '{resolved_model}'."
        except Exception as e:
            err_msg = str(e)
            err_type = type(e).__name__
            if is_auth_error(e):
                return False, format_auth_error_message(e, model=resolved_model)
            if "No module named 'vertexai'" in err_msg or "No module named 'anthropic'" in err_msg:
                return (
                    False,
                    f"Missing dependency for Vertex AI partner models: {err_msg}. "
                    f"Run 'pip install google-cloud-aiplatform anthropic' or re-run './install.sh'."
                )
            if is_rate_limit_error(e):
                if attempt + 1 < max_probe_attempts:
                    retry_after = extract_retry_after(e)
                    delay = compute_full_jitter_delay(
                        attempt=attempt,
                        initial_delay=5.0,
                        max_delay=30.0,
                        min_offset=5.0,
                        retry_after=retry_after,
                    )
                    time.sleep(delay)
                    continue
                detail = extract_rate_limit_detail(e)
                return (
                    True,
                    f"LLM reachability verified for '{resolved_model}' (Endpoint & credentials verified; currently rate-limited: {detail}).",
                )
            return False, f"LLM reachability probe failed ({err_type}): {err_msg}"

    return False, f"LLM reachability probe failed after {max_probe_attempts} attempts."


def _check_llm_preflight(config: dict, probe: bool = False) -> Tuple[bool, str]:
    """Fast validation of LLM configuration and credentials in ~1s.
    
    If probe is True (or MANTIS_PROBE_LLM=1), actively tests model reachability
    and client dependencies by sending a test prompt with max_tokens=256.
    """
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
        static_msg = f"Vertex AI OpenAI LLM configured (Model: {resolved_model}{endpoint_info})."

    elif resolved_model.startswith("vertex_ai/"):
        proj = kwargs.get("vertex_project")
        if not proj or is_placeholder(proj):
            return False, "Vertex AI requires a valid GCP Project ID."
        static_msg = f"Vertex AI LLM configured (Model: {resolved_model}, Project: {proj})."

    elif resolved_model.startswith("anthropic/"):
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False, "Anthropic model requires ANTHROPIC_API_KEY environment variable."
        static_msg = f"Anthropic LLM configured (Model: {resolved_model})."

    elif resolved_model.startswith("openai/") or api_base:
        if not os.environ.get("OPENAI_API_KEY") and not api_base:
            return False, "OpenAI model requires OPENAI_API_KEY or --api-base endpoint."
        endpoint_info = f" @ {api_base}" if api_base else ""
        static_msg = f"OpenAI-compatible LLM configured (Model: {resolved_model}{endpoint_info})."

    elif resolved_model.startswith("gemini-"):
        if not os.environ.get("GEMINI_API_KEY") and not os.environ.get("GOOGLE_API_KEY"):
            # Check if vertex credentials are available
            if not os.environ.get("GOOGLE_CLOUD_PROJECT") and not os.environ.get("VERTEXAI_PROJECT") and not kwargs.get("vertex_project"):
                return False, "Gemini model requires GEMINI_API_KEY or GCP Project ID for Vertex AI."
        static_msg = f"Gemini LLM configured (Model: {resolved_model})."

    else:
        static_msg = f"LLM configured (Model: {resolved_model})."

    should_probe = probe or os.environ.get("MANTIS_PROBE_LLM") in ("1", "true", "True")
    if should_probe:
        probe_timeout = timeout if timeout is not None else 15.0
        probe_ok, probe_msg = _probe_llm_reachability(
            resolved_model, kwargs, prompt="test", max_tokens=256, timeout=probe_timeout
        )
        if not probe_ok:
            return False, probe_msg
        return True, f"{static_msg} [Live probe: OK]"

    return True, static_msg


_PINNED_RUNTIME_PACKAGES = ("google-adk", "litellm")


def check_pinned_dependencies(requirements_path: Optional[str] = None) -> Tuple[bool, str]:
    """Compares the installed runtime packages against requirements.txt's pins.

    Reported in the field: a fresh `git pull` on a venv that still carried the
    previous google-adk failed inside ADK's workflow replay with a traceback
    that no longer exists in the pinned release, and the report read as a
    Mantis regression. The check is a warning, not a gate -- an operator may
    run a newer ADK on purpose -- but it names the package, both versions and
    the command, so the next report says which it was.
    """
    try:
        from importlib import metadata
    except Exception:  # pragma: no cover
        return True, "dependency pins not checked (importlib.metadata unavailable)"

    req = Path(requirements_path) if requirements_path else Path(__file__).resolve().parent.parent / "requirements.txt"
    try:
        text = req.read_text(encoding="utf-8")
    except OSError:
        return True, f"dependency pins not checked ({req.name} not found)"

    pins: Dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)", line.strip())
        if m:
            pins[m.group(1).lower().replace("_", "-")] = m.group(2)

    stale = []
    for name in _PINNED_RUNTIME_PACKAGES:
        pinned = pins.get(name)
        if not pinned:
            continue
        try:
            installed = metadata.version(name)
        except metadata.PackageNotFoundError:
            stale.append(f"{name}: not installed (pinned {pinned})")
            continue
        if installed != pinned:
            stale.append(f"{name}: installed {installed}, pinned {pinned}")
    if stale:
        return False, (
            "installed packages differ from requirements.txt -- " + "; ".join(stale)
            + f". Reinstall with: pip install --require-hashes -r {req} "
            "(failures inside google.adk on a stale install are not Mantis bugs)."
        )
    return True, "installed google-adk and litellm match requirements.txt"


async def run_preflight_checks_async(
    config: dict,
    test_llm: bool = True,
    test_sandbox: bool = True,
    target_path: str = "",
    probe_llm: bool = False,
) -> Tuple[bool, List[str]]:
    """Runs combined LLM and Sandbox preflight testing asynchronously in ~1-2s."""
    messages = []
    all_ok = True

    # Advisory: stale runtime packages. Never fails the preflight.
    pins_ok, pins_msg = check_pinned_dependencies()
    messages.append(f"[DEPENDENCY PREFLIGHT] {'✅ PASSED' if pins_ok else '⚠️ WARNING'}: {pins_msg}")

    if test_llm:
        ok, msg = _check_llm_preflight(config, probe=probe_llm)
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
    probe_llm: bool = False,
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
                    probe_llm=probe_llm,
                ),
            ).result()
    else:
        return asyncio.run(
            run_preflight_checks_async(
                config,
                test_llm=test_llm,
                test_sandbox=test_sandbox,
                target_path=target_path,
                probe_llm=probe_llm,
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
    if "project" in updates:
        cfg["project"] = updates["project"]

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
    raise SystemExit(1)


def _sandbox_choice_is_explicit(workflow_path: str) -> bool:
    """True when the operator explicitly chose a sandbox tier.

    An explicit choice is a 'sandbox' key in the local overlay
    (workflow.local.json -- written by the wizard, --sandbox, or a previous
    auto-promotion) or a non-static sandbox committed in the base
    workflow.json. The tracked base file keeps a 'static-only' floor by
    design, so a bare static-only there is a default, not a decision.
    """
    try:
        if os.path.exists(workflow_path):
            with open(workflow_path, "r", encoding="utf-8") as f:
                base = json.load(f)
            if isinstance(base, dict):
                base_sb = (base.get("config", {}) or {}).get("sandbox", {})
                if isinstance(base_sb, dict) and base_sb.get("type") not in (
                    None,
                    "",
                    "static-only",
                    "static",
                ):
                    return True
    except Exception:
        pass

    base_dir = os.path.dirname(os.path.abspath(workflow_path))
    base_name = os.path.basename(workflow_path)
    stem = base_name[:-5] if base_name.endswith(".json") else base_name
    for cand in (
        os.path.join(base_dir, f"{stem}.local.json"),
        os.path.join(base_dir, f".{stem}.local.json"),
    ):
        if not os.path.exists(cand):
            continue
        try:
            with open(cand, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            # Unreadable overlay: treat as explicit so we never overwrite it.
            return True
        if isinstance(data, dict) and (
            "sandbox" in data or "sandbox" in (data.get("config", {}) or {})
        ):
            return True
    return False


def _print_static_floor_hint(caps: dict) -> None:
    """One-line, every-launch hint that dynamic reproduction is disabled."""
    if "microsandbox" in caps.get("available_sandboxes", []):
        print(
            "⚠️  Sandbox is 'static-only': this host supports microsandbox but no guest "
            "image is cached. Run ./install.sh to enable dynamic exploit reproduction."
        )
    else:
        print(
            "⚠️  Sandbox is 'static-only' (no supported isolation tier detected on this host). "
            "Dynamic exploit reproduction is DISABLED."
        )


async def ensure_configured_async(
    workflow_path: str = "",
    auto: bool = True,
    interactive: bool = False,
    overrides: Optional[dict] = None,
    save: bool = True,
    save_tracked: bool = False,
    probe_llm: bool = False,
    persist_overrides: bool = False,
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

    # Auto-promotion: a 'static-only' floor inherited from the tracked
    # workflow.json is a default, not an operator decision. When this host can
    # actually run microsandbox (virtualization + cached guest image verified),
    # promote to it and persist, instead of silently skipping dynamic
    # reproduction forever. An explicit operator choice (any sandbox key in
    # workflow.local.json, a non-static tracked type, or a --sandbox override
    # this invocation) is never second-guessed.
    promote_to_microsandbox = (
        auto
        and not interactive
        and sb_type in ("static-only", "static")
        and "sandbox" not in overrides
        and caps.get("recommended_sandbox") == "microsandbox"
        and bool(caps.get("microsandbox_image"))
        and not _sandbox_choice_is_explicit(target_wf)
    )

    preflight_ran = False
    preflight_msgs: List[str] = []
    if not is_unconf and not overrides and sb_available and not promote_to_microsandbox:
        preflight_ran = True
        ok, preflight_msgs = await run_preflight_checks_async(cfg, probe_llm=probe_llm)
        if ok:
            if sb_type in ("static-only", "static"):
                _print_static_floor_hint(caps)
            return cfg

    updates: dict[str, Any] = {}
    downgraded_sandbox: Optional[dict[str, Any]] = None

    if interactive:
        return run_interactive_wizard(target_wf)

    if auto:
        sb_preflight_failed = preflight_ran and any(
            m.startswith("[SANDBOX PREFLIGHT] ❌") for m in preflight_msgs
        )
        if (
            not preflight_ran
            and sb_available
            and sb_type not in ("static-only", "static")
            and os.environ.get("MANTIS_ALLOW_SANDBOX_DOWNGRADE") == "1"
        ):
            _, pf_msgs = await run_preflight_checks_async(
                cfg, test_llm=False, test_sandbox=True, probe_llm=False
            )
            sb_preflight_failed = any(
                m.startswith("[SANDBOX PREFLIGHT] ❌") for m in pf_msgs
            )
        if promote_to_microsandbox:
            msb_image = caps["microsandbox_image"]
            updates["sandbox"] = {
                "type": "microsandbox",
                "options": {"image": msb_image},
            }
            sb_type = "microsandbox"
            sb_opts = {"image": msb_image}
            cfg = {**cfg, "sandbox": {"type": "microsandbox", "options": dict(sb_opts)}}
            print(
                f"🔒 Auto-configured sandbox: 'microsandbox' (networkless hardware microVM, "
                f"guest image '{msb_image}'). Persisting to workflow.local.json; "
                f"override with --sandbox or configure.py."
            )
        elif sb_type in ("static-only", "static") and "sandbox" not in overrides:
            _print_static_floor_hint(caps)

        # Auto-resolve GCE project if unconfigured
        if sb_type == "gce":
            cur_proj = sb_opts.get("project", "")
            if is_placeholder(cur_proj):
                resolved_proj = caps.get("gcp_project") or caps.get("vertex_project")
                if resolved_proj and "gce" in caps.get("available_sandboxes", []) and not sb_preflight_failed:
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
                    downgraded_sandbox = {"type": "static-only", "options": {}}
                    cfg = {**cfg, "sandbox": dict(downgraded_sandbox)}
            elif "gce" not in caps.get("available_sandboxes", []) or sb_preflight_failed:
                _refuse_silent_downgrade(
                    "Host lacks requirements for 'gce' sandbox (gcloud/auth missing)."
                )
                print(
                    "⚠️  [REPRO DISABLED] Operator-approved downgrade 'gce' -> 'static-only' for THIS SESSION ONLY."
                )
                downgraded_sandbox = {"type": "static-only", "options": {}}
                cfg = {**cfg, "sandbox": dict(downgraded_sandbox)}
        elif sb_type not in caps.get("available_sandboxes", []) or (
            sb_type not in ("static-only", "static") and sb_preflight_failed
        ):
            _refuse_silent_downgrade(
                f"Host lacks requirements for '{sb_type}' sandbox."
            )
            print(
                f"⚠️  [REPRO DISABLED] Operator-approved downgrade '{sb_type}' -> 'static-only' for THIS SESSION ONLY."
            )
            downgraded_sandbox = {"type": "static-only", "options": {}}
            cfg = {**cfg, "sandbox": dict(downgraded_sandbox)}

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

        # One-shot CLI overrides are already live for THIS run (applied above
        # with save=False, and re-applied by main.py via
        # load_workflow_from_json(*_override)). A per-invocation flag must
        # never become sticky configuration unless the operator explicitly
        # opts in with --save-config; auto-resolution results always persist.
        if updates or overrides:
            all_updates = {**updates, **overrides} if persist_overrides else dict(updates)
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
                if overrides and not persist_overrides:
                    # The persisted auto-resolution was reloaded from disk
                    # without the one-shot overrides; put them back on top
                    # (together with the updates, in case save=False kept
                    # those in memory only) so the returned config is the
                    # one this run uses.
                    wf_data = update_workflow_config(
                        target_wf, {**all_updates, **overrides}, save=False, save_tracked=save_tracked
                    )
                ret_cfg = dict(wf_data.get("config", {}))
                if downgraded_sandbox is not None and "sandbox" not in overrides:
                    ret_cfg["sandbox"] = dict(downgraded_sandbox)
                return ret_cfg

    return cfg


def ensure_configured(
    workflow_path: str = "",
    auto: bool = True,
    interactive: bool = False,
    overrides: Optional[dict] = None,
    save: bool = True,
    save_tracked: bool = False,
    probe_llm: bool = False,
    persist_overrides: bool = False,
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
                    probe_llm=probe_llm,
                    persist_overrides=persist_overrides,
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
                probe_llm=probe_llm,
                persist_overrides=persist_overrides,
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
    print(f"  • MicroVM Support:    {'✅ Available' if 'microsandbox' in caps['available_sandboxes'] else '❌ Not found'} (guest image: {caps.get('microsandbox_image') or '❌ none cached'})")
    print(f"  • Container Engine:   {caps['container_tool'] or '❌ None'} (runsc: {'✅ Yes' if caps['runsc'] else '❌ No'})")
    print(f"  • Google Cloud SDK:   {'✅ Active (' + str(caps['gcp_account']) + ')' if caps['gcp_auth'] else '❌ No active auth'}")
    print(f"  • GCP Project:        {caps['gcp_project'] or '❌ Not set'}")
    print()

    # 1. Select Sandbox
    print("Step 1: Select Sandbox Execution Environment")
    sb_choices = [
        ("static-only", "Static Analysis only (Fastest, zero isolation requirement)"),
        ("gvisor", "gVisor Container Sandbox (Networkless OCI container with runsc)"),
        ("microsandbox", "Microsandbox VM (Hardware microVM: KVM on Linux, Hypervisor.framework on macOS)"),
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
        ("vertex_ai/gemini-3.8-flash", "Gemini 3.8 Flash via Vertex AI (Recommended)"),
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


def print_status(
    workflow_path: str,
    as_json: bool = False,
    config_override: Optional[dict] = None,
    probe_llm: bool = False,
) -> None:
    """Prints current configuration and preflight test status."""
    target_wf = find_workflow_json(workflow_path)
    if config_override is not None:
        cfg = config_override
    else:
        wf_data = load_workflow_dict(target_wf, load_local=True)
        cfg = wf_data.get("config", {})
    caps = detect_capabilities()
    ok, messages = run_preflight_checks(cfg, probe_llm=probe_llm)
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
        help="Default LLM model (e.g. gemini-3.8-flash, vertex_ai/claude-opus-5, openai/my-model)",
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
    parser.add_argument(
        "--probe",
        "--probe-llm",
        action="store_true",
        dest="probe_llm",
        help="Perform an active live reachability probe against the configured LLM endpoint",
    )
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
        print_status(target_wf, as_json=args.json, probe_llm=args.probe_llm)
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
    if args.project:
        updates["project"] = args.project

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
            probe_llm=args.probe_llm,
        )
        if not args.json:
            action = "Simulated auto-configuration for" if args.dry_run else "Auto-configured Mantis settings saved to"
            dest = target_wf if save_tracked else get_local_workflow_path(target_wf)
            print(f"✅ {action} {dest}")
        print_status(target_wf, as_json=args.json, config_override=cfg if args.dry_run else None, probe_llm=args.probe_llm)
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
        if args.test or args.probe_llm:
            ok, msgs = run_preflight_checks(updated_data.get("config", {}), probe_llm=args.probe_llm)
            if args.json:
                print(json.dumps({"preflight_passed": ok, "messages": msgs}, indent=2))
            else:
                for m in msgs:
                    print(m)
            return 0 if ok else 1
        print_status(target_wf, as_json=args.json, config_override=updated_data.get("config") if args.dry_run else None, probe_llm=args.probe_llm)
        return 0

    # 5. Preflight Test Only
    if args.test or args.probe_llm:
        wf_data = load_workflow_dict(target_wf, load_local=True)
        ok, msgs = run_preflight_checks(wf_data.get("config", {}), probe_llm=args.probe_llm)
        if args.json:
            print(json.dumps({"preflight_passed": ok, "messages": msgs}, indent=2))
        else:
            print_status(target_wf, probe_llm=args.probe_llm)
        return 0 if ok else 1

    # Default action: show status
    print_status(target_wf, as_json=args.json, probe_llm=args.probe_llm)
    return 0


if __name__ == "__main__":
    sys.exit(main())

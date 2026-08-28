import os
from typing import Any, Optional, Tuple

try:
    import litellm
    litellm.drop_params = True
except Exception:
    pass

DEFAULT_MODEL = "vertex_ai/gemini-3.7-flash"
DEFAULT_EMBEDDING_MODEL = "vertex_ai/gemini-embedding-001"
SUPPORTED_SANDBOXES = ("static-only", "static", "gvisor", "microsandbox", "gce")
RECOMMENDED_MODELS = (
    "gemini-3.7-flash",
    "gemini-3.5-flash-lite",
    "vertex_ai/gemini-3.7-flash",
    "vertex_ai/gemini-3.5-flash-lite",
    "vertex_ai/claude-opus-5",
    "vertex_ai/zai_org/glm-5.2-maas",
)

PLACEHOLDER_STRINGS = {
    "YOUR_PROJECT_ID",
    "YOUR_PROJECT",
    "YOUR_GCP_PROJECT",
    "<YOUR_PROJECT_ID>",
    "<PROJECT_ID>",
    "YOUR_API_KEY",
    "<YOUR_API_KEY>",
    "TODO",
    "CHANGE_ME",
    "REPLACE_ME",
    "",
}


def is_placeholder(val: Any) -> bool:
    """Checks if a string or value represents an unconfigured placeholder."""
    if val is None:
        return True
    s = str(val).strip()
    if not s or s.upper() in PLACEHOLDER_STRINGS:
        return True
    if s.upper().startswith(("YOUR_", "<YOUR_", "CHANGE_ME", "REPLACE_ME")):
        return True
    # Token-level check for composite paths/models (e.g. openai/YOUR_API_KEY)
    for token in s.upper().split("/"):
        t = token.strip()
        if t in PLACEHOLDER_STRINGS or t.startswith(("YOUR_", "<YOUR_", "CHANGE_ME", "REPLACE_ME")):
            return True
    return False


def normalize_model_id(model_id: str) -> str:
    """Normalizes model names and routes bare gemini models to vertex_ai when GCP credentials exist."""
    if not model_id:
        return DEFAULT_MODEL
    cleaned = model_id.strip()
    if cleaned.startswith("gemini-"):
        # If running in GCP / Vertex environment without explicit Google AI Studio API key, route to vertex_ai/
        if not os.environ.get("GEMINI_API_KEY") and (
            os.environ.get("VERTEXAI_PROJECT")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
        ):
            return f"vertex_ai/{cleaned}"
    if cleaned in (
        "glm-5.2-maas",
        "zai-org/glm-5.2-maas",
        "vertex_ai/glm-5.2-maas",
        "vertex_ai/zai_org/glm-5.2-maas",
        "vertex_ai/zai-org/glm-5.2-maas",
        "vertex_ai/openai/zai-org/glm-5.2-maas",
    ):
        return "vertex_ai/openai/zai-org/glm-5.2-maas"
    return cleaned


def get_llm_kwargs(
    model_id: Optional[str] = None,
    default_model: str = DEFAULT_MODEL,
    api_base: Optional[str] = None,
    default_api_base: Optional[str] = None,
    timeout: Optional[float] = None,
    default_timeout: Optional[float] = None,
    reasoning_effort: Optional[str] = None,
    default_reasoning_effort: Optional[str] = None,
    global_model_override: Optional[str] = None,
    config: Optional[dict] = None,
) -> Tuple[str, dict]:
    """Resolves the LLM mapping details cleanly with precedence: global_override > MANTIS_MODEL > node > MODEL_ID > default."""
    if global_model_override:
        raw_model = global_model_override
    elif os.environ.get("MANTIS_MODEL"):
        raw_model = os.environ.get("MANTIS_MODEL")
    else:
        raw_model = model_id or os.environ.get("MODEL_ID") or default_model

    resolved_model = normalize_model_id(raw_model)
    resolved_api_base = api_base or os.environ.get("LLM_API_BASE") or default_api_base
    raw_timeout = timeout if timeout is not None else (
        os.environ.get("LLM_TIMEOUT")
        or os.environ.get("LLM_REQUEST_TIMEOUT")
        or default_timeout
    )
    effort = reasoning_effort or os.environ.get("REASONING_EFFORT") or default_reasoning_effort

    llm_kwargs = {"model": resolved_model}
    if resolved_api_base:
        llm_kwargs["api_base"] = resolved_api_base
    if effort:
        llm_kwargs["reasoning_effort"] = str(effort).lower().strip()
    if raw_timeout is not None:
        try:
            timeout_val = float(raw_timeout)
            if timeout_val > 0:
                llm_kwargs["timeout"] = timeout_val
        except (ValueError, TypeError):
            pass

    if resolved_model.startswith("vertex_ai/"):
        project = os.environ.get("VERTEXAI_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
        if is_placeholder(project):
            project = None

        if not project and config and isinstance(config, dict):
            cfg_proj = config.get("project")
            if not cfg_proj or is_placeholder(cfg_proj):
                sb = config.get("sandbox")
                if isinstance(sb, dict):
                    sb_opts = sb.get("options")
                    if isinstance(sb_opts, dict):
                        cfg_proj = sb_opts.get("project")
            if cfg_proj and not is_placeholder(cfg_proj):
                project = str(cfg_proj)

        location = os.environ.get("VERTEXAI_LOCATION") or os.environ.get("GOOGLE_CLOUD_LOCATION") or "global"

        if not project:
            try:
                import google.auth
                _, project = google.auth.default()
                if is_placeholder(project):
                    project = None
            except Exception:
                pass

        if not project and not resolved_api_base:
            raise ValueError("ERROR: You must set VERTEXAI_PROJECT or GOOGLE_CLOUD_PROJECT env variables.")

        if project:
            llm_kwargs["vertex_project"] = project
            llm_kwargs["vertex_location"] = location
        # Relax safety filters that sometimes trigger erroneously on defensive security
        # analysis and vulnerability remediation workflows.
        if not resolved_model.startswith("vertex_ai/openai/"):
            llm_kwargs["safety_settings"] = [
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            ]

        if os.environ.get("VERTEX_FLEX") in ("1", "true", "True") or os.environ.get("VERTEXAI_SERVICE_TIER", "").lower() == "flex":
            headers = llm_kwargs.get("extra_headers") or {}
            headers["X-Vertex-AI-LLM-Request-Type"] = "shared"
            llm_kwargs["extra_headers"] = headers

    return resolved_model, llm_kwargs


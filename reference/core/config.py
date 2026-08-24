import os

from typing import Optional

DEFAULT_MODEL = "vertex_ai/gemini-3.7-flash"

def get_llm_kwargs(
    model_id: Optional[str] = None,
    default_model: str = DEFAULT_MODEL,
    api_base: Optional[str] = None,
    default_api_base: Optional[str] = None,
    timeout: Optional[float] = None,
    default_timeout: Optional[float] = None,
    reasoning_effort: Optional[str] = None,
    default_reasoning_effort: Optional[str] = None,
) -> tuple[str, dict]:
    """Resolves the LLM mapping details cleanly with precedence: node > ENV > config/default."""
    model_id = model_id or os.environ.get("MODEL_ID") or default_model
    api_base = api_base or os.environ.get("LLM_API_BASE") or default_api_base
    raw_timeout = timeout if timeout is not None else (os.environ.get("LLM_TIMEOUT") or os.environ.get("LLM_REQUEST_TIMEOUT") or default_timeout)
    effort = reasoning_effort or os.environ.get("REASONING_EFFORT") or default_reasoning_effort
        
    llm_kwargs = {"model": model_id}
    if api_base:
        llm_kwargs["api_base"] = api_base
    if effort:
        llm_kwargs["reasoning_effort"] = str(effort).lower().strip()
    if raw_timeout is not None:
        try:
            timeout_val = float(raw_timeout)
            if timeout_val > 0:
                llm_kwargs["timeout"] = timeout_val
        except (ValueError, TypeError):
            pass
    
    if model_id.startswith("vertex_ai/"):
        project = os.environ.get("VERTEXAI_PROJECT", os.environ.get("GOOGLE_CLOUD_PROJECT"))
        location = os.environ.get("VERTEXAI_LOCATION", os.environ.get("GOOGLE_CLOUD_LOCATION", "global"))
        
        if not project:
            try:
                import google.auth
                _, project = google.auth.default()
            except Exception:
                pass
                
        if not project:
            raise ValueError("ERROR: You must set VERTEXAI_PROJECT or GOOGLE_CLOUD_PROJECT env variables.")
        
        llm_kwargs["vertex_project"] = project
        llm_kwargs["vertex_location"] = location
        # Relax safety filters that sometimes trigger erroneously on defensive security
        # analysis and vulnerability remediation workflows.
        llm_kwargs["safety_settings"] = [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
        ]
        
    return model_id, llm_kwargs


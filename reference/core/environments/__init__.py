from .base import BaseEnvironment, ProxyEnvironment, get_shared_proxy_environment
from .microsandbox_env import MicrosandboxEnvironment
from .gvisor_env import GvisorEnvironment
from .static_env import StaticOnlyEnvironment
from .gce_env import GceEnvironment

ENVIRONMENTS: dict[str, type] = {
    "static-only": StaticOnlyEnvironment,
    "static": StaticOnlyEnvironment,
    "gvisor": GvisorEnvironment,
    "microsandbox": MicrosandboxEnvironment,
    "gce": GceEnvironment,
}


def build_environment(cfg: dict, target_path: str = "") -> BaseEnvironment:
    """Builds an ADK BaseEnvironment instance according to configuration."""
    kind = cfg.get("type", "static-only")
    if kind not in ENVIRONMENTS:
        raise ValueError(
            f"Unknown sandbox type '{kind}'. Available: {sorted(ENVIRONMENTS)}"
        )
    kwargs = dict(cfg.get("options", {}))
    for k, v in cfg.items():
        if k not in ("type", "options") and v is not None:
            kwargs[k] = v
    return ENVIRONMENTS[kind](target_path, **kwargs)


__all__ = [
    "BaseEnvironment",
    "ProxyEnvironment",
    "MicrosandboxEnvironment",
    "GvisorEnvironment",
    "StaticOnlyEnvironment",
    "GceEnvironment",
    "ENVIRONMENTS",
    "build_environment",
    "get_shared_proxy_environment",
]

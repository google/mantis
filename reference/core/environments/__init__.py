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

from .base import BaseEnvironment, ProxyEnvironment, get_shared_proxy_environment
from .microsandbox_env import MicrosandboxEnvironment
from .gvisor_env import GvisorEnvironment
from .static_env import StaticOnlyEnvironment
from .gce_env import GceEnvironment
from .remote_env import RemoteTargetEnvironment

ENVIRONMENTS: dict[str, type] = {
    "static-only": StaticOnlyEnvironment,
    "static": StaticOnlyEnvironment,
    "gvisor": GvisorEnvironment,
    "microsandbox": MicrosandboxEnvironment,
    "gce": GceEnvironment,
    "remote": RemoteTargetEnvironment,
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
    "RemoteTargetEnvironment",
    "ENVIRONMENTS",
    "build_environment",
    "get_shared_proxy_environment",
]

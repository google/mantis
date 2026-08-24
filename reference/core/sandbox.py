import os
from typing import Protocol
from core.environments import (
    BaseEnvironment,
    MicrosandboxEnvironment,
    GvisorEnvironment,
    StaticOnlyEnvironment,
    GceEnvironment,
    ENVIRONMENTS,
    build_environment,
)

# For backward compatibility with tests/callers referencing legacy class names
StaticOnlySandbox = StaticOnlyEnvironment
GvisorSandbox = GvisorEnvironment
MicrosandboxSandbox = MicrosandboxEnvironment
GceSandbox = GceEnvironment

class Sandbox(Protocol):
    """Executes commands in isolation on behalf of the reproducer and patcher nodes."""
    async def execute(self, command: str) -> str: ...
    async def apply_patch(self, diff: str) -> str: ...
    async def preflight(self) -> None: ...
    async def aclose(self) -> None: ...

SANDBOXES: dict[str, type] = ENVIRONMENTS

def build_sandbox(cfg: dict, target_path: str = "") -> BaseEnvironment:
    return build_environment(cfg, target_path)

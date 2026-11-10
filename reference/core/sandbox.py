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

import os
from typing import Protocol
from core.environments import (
    BaseEnvironment,
    MicrosandboxEnvironment,
    GvisorEnvironment,
    StaticOnlyEnvironment,
    GceEnvironment,
    RemoteTargetEnvironment,
    ENVIRONMENTS,
    build_environment,
)

# For backward compatibility with tests/callers referencing legacy class names
StaticOnlySandbox = StaticOnlyEnvironment
GvisorSandbox = GvisorEnvironment
MicrosandboxSandbox = MicrosandboxEnvironment
GceSandbox = GceEnvironment
RemoteSandbox = RemoteTargetEnvironment

class Sandbox(Protocol):
    """Executes commands in isolation on behalf of the reproducer and patcher nodes."""
    async def execute(self, command: str) -> str: ...
    async def apply_patch(self, diff: str) -> str: ...
    async def preflight(self) -> None: ...
    async def aclose(self) -> None: ...

SANDBOXES: dict[str, type] = ENVIRONMENTS

def build_sandbox(cfg: dict, target_path: str = "") -> BaseEnvironment:
    return build_environment(cfg, target_path)

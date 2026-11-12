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

"""Unit test package for Mantis ADK references and invariants."""


def ensure_reference_deps():
    """Fail closed, with a readable message, when the reference env is absent.

    These suites verify invariants enforced by the ADK runtime; without it
    there is nothing meaningful to test, so a missing environment is an
    error -- never a skip, never a pass.
    """
    import os

    try:
        import pydantic  # noqa: F401
        import google.adk  # noqa: F401
        if os.environ.get("MANTIS_CI_STRICT_DEPS") == "1":
            import litellm  # noqa: F401
            import mcp  # noqa: F401
            import tree_sitter  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "The Mantis reference test suites require the reference "
            "environment. Run reference/install.sh or `pip install -r "
            "reference/requirements.txt` first. For dependency-light skill "
            "checks, run `python test_skills_integrity.py` at the repo root "
            f"instead. (missing: {exc.name})"
        ) from exc


ensure_reference_deps()

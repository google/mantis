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

"""A structured transcript of a run: one JSONL row per prose, tool call, tool response, or error.

Shared by the researcher eval (``evals/research_eval.py --transcript-out``)
and the pipeline (``main.py --transcript-out``) so a reader -- a person, or
the Harness2 proposer reading ``context/rollouts/`` -- sees the same shape
either way: which stage spoke, which tools it called with what arguments,
and what came back, in order. The console stream is for a human watching
the run; it clips tool responses to a few hundred characters and is not a
record.

Clipping here keeps file dumps from drowning the trace; the clip marker says
how much was cut so nothing disappears silently. Per-row limits are generous
enough that a proposer can tell what a stage actually read.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

TRANSCRIPT_TEXT_LIMIT = 8_000
TRANSCRIPT_PAYLOAD_LIMIT = 20_000


def clip(value: Any, limit: int) -> str:
    text = str(value)
    if len(text) > limit:
        return text[:limit] + f"... [clipped {len(text) - limit} chars]"
    return text


def event_transcript_rows(event: Any, *, node: str = "",
                          campaign: str = "",
                          text_limit: int = TRANSCRIPT_TEXT_LIMIT,
                          payload_limit: int = TRANSCRIPT_PAYLOAD_LIMIT) -> List[Dict[str, Any]]:
    """Flattens one ADK event into ordered transcript rows. Never raises."""
    rows: List[Dict[str, Any]] = []
    try:
        author = str(getattr(event, "author", None) or "")
        if getattr(event, "partial", False):
            return rows
        base = {"author": author}
        if node:
            base["node"] = node
        if campaign:
            base["campaign"] = campaign
        error_code = getattr(event, "error_code", None)
        if error_code:
            rows.append({**base, "type": "error", "name": str(error_code),
                         "text": clip(getattr(event, "error_message", None) or "", text_limit)})
            return rows
        parts = getattr(getattr(event, "content", None), "parts", None) or []
        for part in parts:
            if getattr(part, "thought", False):
                continue
            text = getattr(part, "text", None)
            call = getattr(part, "function_call", None)
            resp = getattr(part, "function_response", None)
            if text:
                rows.append({**base, "type": "text", "text": clip(text, text_limit)})
            if call is not None:
                rows.append({**base, "type": "tool_call", "name": str(getattr(call, "name", "")),
                             "args": clip(getattr(call, "args", None), payload_limit)})
            if resp is not None:
                payload = getattr(resp, "response", None)
                if isinstance(payload, dict):
                    if "evidence_present" in payload and isinstance(payload.get("output"), str):
                        payload = (
                            f"[evidence_present={payload.get('evidence_present')} "
                            f"reason={payload.get('evidence_reason', '')}]\n{payload['output']}"
                        )
                    else:
                        inner = payload.get("result", payload.get("response", payload.get("output")))
                        payload = inner if isinstance(inner, str) else json.dumps(payload, default=str)
                rows.append({**base, "type": "tool_response", "name": str(getattr(resp, "name", "")),
                             "response": clip(payload, payload_limit)})
    except Exception:  # pragma: no cover - transcripts must never sink a run
        return rows
    return rows


class TranscriptWriter:
    """Appends rows to a JSONL file as they arrive; a crash loses at most the last row."""

    def __init__(self, path: Optional[Path | str]):
        self.path = Path(path) if path else None
        self._fh = None
        self.rows = 0
        if self.path is not None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._fh = self.path.open("a", encoding="utf-8")
            except OSError:
                self._fh = None

    def write(self, rows: List[Dict[str, Any]]) -> None:
        if self._fh is None or not rows:
            return
        try:
            for row in rows:
                self._fh.write(json.dumps(row, sort_keys=True, default=str) + "\n")
                self.rows += 1
            self._fh.flush()
        except OSError:
            pass

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None


def read_transcript(path: Path | str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return out

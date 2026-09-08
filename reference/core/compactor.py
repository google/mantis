"""Mantis domain-aware ADK event compactor.

Ensures that security audit invariants, discovered vulnerabilities, confirmed sinks,
and audited components are preserved and never lost or hallucinated during ADK trajectory compaction.
"""

from __future__ import annotations

import os
from typing import Optional, List
from google.adk.apps.llm_event_summarizer import LlmEventSummarizer
from google.adk.events.event import Event
from google.adk.models.base_llm import BaseLlm

MANTIS_COMPACTION_PROMPT_TEMPLATE = (
    "You are compacting the audit history for the Mantis security vulnerability analysis pipeline.\n"
    "The following is a conversation history between the pipeline harness and an analysis agent.\n"
    "CRITICAL COMPACTION INVARIANTS:\n"
    "1. FINDINGS ALREADY RECORDED: Explicitly enumerate all findings reported via `report_findings` or `dedupe_findings`.\n"
    "   Include their title, relative filepath, line numbers, and status under a header '[ALREADY RECORDED FINDINGS - DO NOT RE-REPORT]'.\n"
    "2. AUDITED COMPONENTS: List all files, functions, and endpoints that were already inspected.\n"
    "3. SINK REACHABILITY & HYGIENE: Summarize key taint tracking decisions, confirmed sinks, and false positives identified.\n"
    "4. UNFINISHED TASKS: State ONLY genuinely unresolved investigations or candidate vulnerabilities currently in-flight.\n"
    "Do NOT instruct the agent to re-audit or re-report findings that are already saved.\n\n"
    "{conversation_history}"
)


class MantisEventsSummarizer(LlmEventSummarizer):
    """Domain-aware security event summarizer that deterministically preserves recorded findings and audited files across compactions."""

    def __init__(self, llm: BaseLlm, prompt_template: Optional[str] = None):
        super().__init__(llm=llm, prompt_template=prompt_template or MANTIS_COMPACTION_PROMPT_TEMPLATE)

    def _format_events_for_prompt(self, events: list[Event]) -> str:
        """Formats events into prompt text, ensuring security-critical tool calls are untruncated."""
        formatted_history = []
        for event in events:
            if not (event.content and event.content.parts):
                continue
            is_compaction = bool(event.actions and event.actions.compaction)
            for part in event.content.parts:
                if part.thought and part.text:
                    if not is_compaction:
                        formatted_history.append(f"{event.author} (thought): {part.text}")
                elif part.text:
                    formatted_history.append(f"{event.author}: {part.text}")
                if part.function_call:
                    fn_name = part.function_call.name
                    # Critical finding and deduplication calls are never truncated
                    if fn_name in ("report_findings", "dedupe_findings", "get_findings"):
                        args_str = str(part.function_call.args)
                    else:
                        args_str = self._truncate(str(part.function_call.args))
                    formatted_history.append(f"{event.author} called tool: {fn_name}({args_str})")
                if part.function_response:
                    fn_name = part.function_response.name
                    if fn_name in ("report_findings", "dedupe_findings", "get_findings"):
                        resp_str = str(part.function_response.response)
                    else:
                        resp_str = self._truncate(str(part.function_response.response))
                    formatted_history.append(f"Tool response from {fn_name}: {resp_str}")
        return "\n".join(formatted_history)

    async def maybe_summarize_events(self, *, events: List[Event]) -> Optional[Event]:
        summary_event = await super().maybe_summarize_events(events=events)
        if summary_event is None:
            return None

        # Deterministic state injection from SQLite: ensure exact canonical findings are never lost or corrupted
        try:
            from core.context import current_run_context
            from core.database import read_findings

            ctx = current_run_context.get()
            if ctx is not None and ctx.db_path and os.path.exists(ctx.db_path):
                findings = read_findings(ctx.db_path, run_id=ctx.run_id)
                if findings:
                    findings_lines = [
                        f"  • Finding #{f.get('id')} [{f.get('severity', 'UNKNOWN')}] {f.get('filepath')}:{f.get('line_numbers') or '[]'} - {f.get('title')} (Status: {f.get('status')})"
                        for f in findings
                    ]
                    canonical_block = (
                        f"[CANONICAL DATABASE STATE: {len(findings)} FINDING(S) ALREADY RECORDED - DO NOT RE-REPORT]\n"
                        + "\n".join(findings_lines)
                        + "\n\n"
                    )
                    compacted = getattr(summary_event.actions, "compaction", None)
                    if compacted and compacted.compacted_content and compacted.compacted_content.parts:
                        for part in compacted.compacted_content.parts:
                            if getattr(part, "text", None):
                                part.text = canonical_block + part.text
                                break
        except Exception:
            pass

        return summary_event

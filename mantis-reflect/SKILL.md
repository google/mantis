---
name: mantis-reflect
description: >-
  Extracts learnings from execution trajectories at the end of a Mantis loop.
  Use to parse agent conversations, extract successes, failures, and false assumptions, and append them to workspace/learnings.jsonl.
  Don't use for analyzing source code or writing patches.
---

# Reflector (/mantis-reflect)

## System Goal

Execution Trajectory Analyst. Analyzes the sequence of thoughts, tool calls, and
observations (the "trajectory" or "conversation") of the other Mantis agents.
Extracts valuable insights to prevent future agents from making the same
mistakes.

## Command Definition

- **Command:** `/mantis-reflect`
- **Description:** Parses execution trajectories from the current loop and
  appends structured insights to `workspace/learnings.jsonl`.

## Input/Output Contract

- **Reads**:
  - `workspace/.mantis_state.json` (to track the current loop pass, and to read
    `active_snapshot.snapshot_id` for provenance stamping — see Instructions
    step 3). Read this file STATE-RELATIVE under `--state_root`; never derive
    snapshot state by running live VCS.
  - Subagent execution logs (`transcript.jsonl` files). The schema
    `execution_log_entry` defined in `schema.json` is the normalized
    representation. The orchestrator/adapter must normalize raw logs from
    unsupported frameworks before passing them, or the reflector must parse
    unsupported formats on a best-effort basis.
  - **Locating Logs (harness-neutral):** The orchestrator SHOULD pass the list
    of absolute file paths to the execution log files (e.g. `transcript.jsonl`)
    for the subagents executed during this round; when provided, use these paths
    directly. Do NOT hardcode any single framework's log layout. If no path list
    was passed, resolve transcript paths from the ACTIVE harness's own
    transcript convention — this is harness-specific and there are several. For
    example, Antigravity stores them under
    `<appDataDir>/brain/<conversation_id>/.system_generated/logs/transcript.jsonl`;
    other harnesses (e.g. Gemini CLI, the Google ADK, Claude Code) use different
    layouts. Antigravity is ONE example among several, not the default. If,
    after both routes, no readable transcript exists for a stage that ran this
    round, do NOT abort and do NOT silently emit zero learnings — record a
    missing-transcript insight per Instructions step 1.
- **Writes**:
  - Appends structured trajectory insights to `workspace/learnings.jsonl`.
- **Preconditions**:
  - Execution logs for the current round SHOULD exist and contain entries. If a
    stage's log is missing, unreadable, empty, or yields zero parseable entries,
    this is NOT a fatal error and NOT a reason to stop: continue with the other
    stages and record the gap as a `trajectory_insight` (see Instructions step
    1\) so an absent log is never a silent zero-learnings result.
- **Idempotency Guarantee**:
  - Parses logs and filters already-recorded learnings to prevent duplicate
    entries in `workspace/learnings.jsonl`. It should check existing lines in
    `workspace/learnings.jsonl` to ensure it doesn't duplicate the same insight
    if retried.
  - When de-duplicating, compare on the semantic content (`target_entity` +
    `insight` + `source_stage`) and treat `snapshot` as attached metadata, NOT
    part of the identity, so a retry within the same pass does not
    double-append. Missing-transcript insights (step 1) are de-duplicated the
    same way.

## Instructions

### 0. Locator Resolution (Block A — FINDINGS-ONLY role)

```
LOCATOR RESOLUTION (before reading ANY target code or artifact):
0. ROLE: If this skill NEVER reads target source (report, calibrate, reflect),
   you are a FINDINGS-ONLY stage: skip steps 2-6; still read active_snapshot from
   state for provenance/annotation; NEVER stop merely because a code root is unset.
1. Determine CODE_ROOT, in this priority order:
   a. If --target_root is passed on THIS invocation, CODE_ROOT = --target_root.
      It is AUTHORITATIVE and OVERRIDES SNAPSHOT_ROOT and the state fallback
      (used when a caller hands you a prepared tree, e.g. a patched shadow).
   b. Else if --snapshot_root (or SNAPSHOT_ROOT) is passed, use it.
   c. Else read state_root/workspace/.mantis_state.json (state_root from
      --state_root if passed, else ./workspace/... relative to the current dir)
      -> active_snapshot.root / .snapshot_id / .snapshot_pinned.
   d. Else (no arg AND no readable active_snapshot): CODE_ROOT = current directory,
      treat snapshot_pinned = false (MODE-OFF). Do NOT stop.
2. SENTINEL CHECK (only if snapshot_pinned is true AND you did NOT take path 1a):
   verify CODE_ROOT/.mantis_snapshot_id exists and equals SNAPSHOT_ID. If missing
   or different -> STOP "snapshot sentinel mismatch". (A --target_root tree (1a) is
   deliberately mutated and is sentinel-EXEMPT.)
3. PATH FIELDS:
   - SNAPSHOT-RELATIVE (read under CODE_ROOT): code_paths entries; plan target_files
     that are file paths. Strip ONLY a trailing ":<digits>". A code_paths entry
     containing "://" is a URL/endpoint, NOT a file read. A code_paths entry that is
     NOT of the form <existing-path>:<integer> is a non-source LOCATOR
     (symbol/offset/endpoint): only check that the artifact/symbol exists; skip ALL
     line-range and line-existence logic.
   - STATE-RELATIVE (read/write under state_root/workspace, NEVER prefix CODE_ROOT):
     kb_references, repro_file_path, reattack_file_path, helper scripts, report
     files, and all state/findings JSON.
4. Never WRITE under CODE_ROOT when snapshot_pinned is true. Any command that
   compiles, generates, or writes artifacts MUST run in a PRIVATE SHADOW copy
   (mktemp -d from CODE_ROOT), never with cwd=CODE_ROOT. Read-only inspection may
   cd into CODE_ROOT.
5. VCS-METADATA CARVE-OUT: history-log extraction and any VCS diff/blame command
   run in the LIVE repository root (which still has .git/.hg/.repo), NOT CODE_ROOT
   (the snapshot copy strips VCS metadata). Do NOT stop merely because CODE_ROOT
   lacks .git/.hg/.repo.
6. Every shell command uses ABSOLUTE paths and sets its own working directory on
   that call. Do NOT assume the working directory persists between calls.
```

Reflector is a FINDINGS-ONLY stage (same class as report and calibrate). Per
Block A step 0 it SKIPS steps 2-6 — it resolves NO CODE_ROOT, checks NO
`.mantis_snapshot_id` sentinel, and applies NO snapshot-relative path logic —
but it STILL reads `active_snapshot` from state for provenance and NEVER stops
because a code root is unset or unpinned. Reflector needs only `--state_root` to
locate `workspace/.mantis_state.json`, `workspace/learnings.jsonl`, and the
transcript log files; all of these are STATE-RELATIVE (Block A step 3) and MUST
NEVER be prefixed with CODE_ROOT. Reflector MUST NOT run any live VCS command
(`git`/`hg`/`repo`); its only snapshot signal is `active_snapshot.snapshot_id`
read from state.

Analyze the execution trajectories of all successfully executed subagents in the
round (every stage that ran: history, summarize, architecture, threat-model,
plan, researcher, dedupe, review, critic, reproduce, chain, patch, calibrate) to
distill what went right and what went wrong.

Execute the reflection stage as follows:

1. **Extract Trajectories (Token Optimization):**

   - Do not attempt to read the entire, raw `transcript.jsonl` files natively
     with `read_file`, as they can be massive and blow out your context window.

   - Use the absolute log file paths passed to you by the orchestrator to access
     the log files.

   - Instead of reading the full files, use your bash/command execution tools to
     parse and filter the logs. For example, write a short Python script or use
     `jq`/`grep` to extract key events (which should conform to the
     `execution_log_entry` schema; if raw logs from different frameworks are
     provided, parse them on a best-effort basis): tool error messages, final
     agent summaries, instances where an agent "gave up", or messages indicating
     a trust boundary assumption was incorrect.

   - **Missing / empty logs (never silent):** For each stage that ran this round
     whose transcript is missing, unreadable, empty, or yields zero parseable
     entries, append exactly one `trajectory_insight` with `action: "add"`,
     `source_stage: "mantis-reflect"`,
     `target_entity: "<stage-name> transcript"`, and an `insight` naming the
     stage and the reason (e.g. "no transcript file at <path>", "empty log", "0
     parseable entries"). Do this BEFORE synthesizing insights, so even a fully
     empty round produces auditable output instead of nothing.

2. **Synthesize Insights:** Review the extracted events. Look for:

   - **False Assumptions:** Did a researcher spend turns trying to exploit a
     parameter, only to realize it was sanitized upstream in another file?
   - **Tool Failures:** Did the reproducer fail consistently because of a
     missing library in the sandbox?
   - **Successful Strategies:** Did a patcher successfully fix a bug using a
     specific idiomatic pattern that should be reused?

3. **Append to the Inbox (`workspace/learnings.jsonl`):** For each distinct
   insight, append a structured JSON object to `workspace/learnings.jsonl`.

   ### Reflection Schema Format (`workspace/learnings.jsonl`)

   ```json
   {"type": "trajectory_insight", "action": "add | update | remove", "target_entity": "[e.g., auth_module.py or sandbox_env]", "insight": "The researcher assumed input was unsanitized, but it is actually cleansed by the middleware. Do not attempt XSS on this parameter.", "source_stage": "mantis-researcher", "snapshot": "<active_snapshot.snapshot_id from state; omit field entirely if unavailable>"}
   ```

   **Snapshot provenance stamp (never live VCS):** Before writing, read
   `active_snapshot.snapshot_id` from `workspace/.mantis_state.json`
   (STATE-RELATIVE, under `--state_root`). Set the OPTIONAL `snapshot` field on
   EVERY emitted `trajectory_insight` (including the missing-transcript insights
   from step 1) to that value, so each learning is attributable to the pass's
   pinned snapshot. Do NOT run `git`/`hg`/`repo` or any live VCS command to
   derive it. Backward-compat: if `active_snapshot` is absent, `snapshot` is
   empty/null, or state is unreadable, OMIT the `snapshot` field entirely and
   proceed (degraded) — never stop and never fabricate an id. `snapshot` is an
   OPTIONAL field: the `trajectory_insight` sub-schema in `schema.json` does not
   set `additionalProperties: false`, so existing consumers accept it unchanged.

   Ensure the file is appended to, not overwritten. When complete, notify the
   user.

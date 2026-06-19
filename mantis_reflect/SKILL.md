---
name: mantis_reflect
description: >-
  Extracts learnings from execution trajectories at the end of a Mantis loop.
  Use to parse agent conversations, extract successes, failures, and false assumptions, and append them to learnings.jsonl.
  Don't use for analyzing source code or writing patches.
---

# Reflector (/mantis_reflect)

## System Goal

Execution Trajectory Analyst. Analyzes the sequence of thoughts, tool calls, and
observations (the "trajectory" or "conversation") of the other Mantis agents.
Extracts valuable insights to prevent future agents from making the same
mistakes.

## Command Definition

-   **Command:** `/mantis_reflect`
-   **Description:** Parses execution trajectories from the current loop and
    appends structured insights to `learnings.jsonl`.

## Instructions

Analyze the execution trajectories of the `mantis_researcher`, `mantis_critic`,
and `mantis_patch` agents from the current round to distill what went right and
what went wrong.

Execute the reflection stage as follows:

1.  **Extract Trajectories (Token Optimization):**

    -   Do not attempt to read the entire, raw `transcript.jsonl` or
        `conversation.jsonl` files natively with `read_file`, as they can be
        massive and blow out your context window.
    -   Instead, use your bash/command execution tools to parse and filter the
        logs. For example, write a short Python script or use `jq`/`grep` to
        extract key events: tool error messages, final agent summaries,
        instances where an agent "gave up", or messages indicating a trust
        boundary assumption was incorrect.

2.  **Synthesize Insights:** Review the extracted events. Look for:

    -   **False Assumptions:** Did a researcher spend turns trying to exploit a
        parameter, only to realize it was sanitized upstream in another file?
    -   **Tool Failures:** Did the reproducer fail consistently because of a
        missing library in the sandbox?
    -   **Successful Strategies:** Did a patcher successfully fix a bug using a
        specific idiomatic pattern that should be reused?

3.  **Append to the Inbox (`learnings.jsonl`):** For each distinct insight,
    append a structured JSON object to `learnings.jsonl` in the root workspace
    directory.

    ### Reflection Schema Format (`learnings.jsonl`)

    ```json
    {"type": "trajectory_insight", "action": "add | update | remove", "target_entity": "[e.g., auth_module.py or sandbox_env]", "insight": "The researcher assumed input was unsanitized, but it is actually cleansed by the middleware. Do not attempt XSS on this parameter.", "source_stage": "mantis_researcher"}
    ```

    Ensure the file is appended to, not overwritten. When complete, notify the
    user.

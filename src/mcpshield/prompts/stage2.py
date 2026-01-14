"""Stage 2 prompts for MCPShield execution-time checks."""

from __future__ import annotations

import json
from typing import Any


def build_allowlist_prompt(
    query: str,
    tool_name: str,
    manifest: dict[str, Any],
    server_id: str | None,
) -> tuple[str, str]:
    system = (
        "You are MCPShield. Decide which network domains are required for this tool "
        "invocation. Return ONLY JSON with key: allowed_domains (list of strings)."
    )
    user = json.dumps(
        {
            "server_id": server_id,
            "query": query,
            "tool_name": tool_name,
            "manifest": manifest,
        },
        ensure_ascii=True,
    )
    return system, user


def build_exec_analysis_prompt(
    execution_events: list[dict[str, Any]],
    tool_name: str,
    args: dict[str, Any],
    server_id: str | None,
) -> tuple[str, str]:
    system = (
        "You are MCPShield. Analyze execution events for suspicious behavior. "
        "Return ONLY JSON with keys: trusted (boolean), reason, flags (list)."
    )
    user = json.dumps(
        {
            "server_id": server_id,
            "tool_name": tool_name,
            "arguments": args,
            "execution_events": execution_events,
        },
        ensure_ascii=True,
    )
    return system, user

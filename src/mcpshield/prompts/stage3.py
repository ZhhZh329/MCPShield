"""Stage 3 prompts for MCPShield periodic reasoning."""

from __future__ import annotations

import json
from typing import Any


def build_stage3_prompt(
    *,
    server_id: str | None,
    recent_window: list[dict[str, Any]],
    history_window: list[dict[str, Any]],
    global_signatures: list[dict[str, Any]],
) -> tuple[str, str]:
    system = (
        "You are MCPShield Stage3. Reason about behavioral drift across invocations. "
        "Return ONLY JSON with keys: trusted (bool), reason (string), "
        "flags (list), drift_score (number 0-1), signature (object)."
    )
    user = json.dumps(
        {
            "server_id": server_id,
            "recent_window": recent_window,
            "history_window": history_window,
            "global_signatures": global_signatures,
        },
        ensure_ascii=True,
    )
    return system, user

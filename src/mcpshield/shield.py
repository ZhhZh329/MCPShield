"""Minimal MCPShield wrapper with stage toggles."""

from __future__ import annotations

from typing import Any

from .client import MCPClient


class MCPShield:
    def __init__(self, client: MCPClient, stage_mode: list[str] | None = None) -> None:
        self._client = client
        self._stage_mode = set(stage_mode or [])

    def invoke(self, tool_name: str, args: dict, invocation_ctx: dict | None = None) -> Any:
        if "PRE" in self._stage_mode:
            _ = self._client.fetch_manifest()
        if "EXEC" in self._stage_mode:
            result = self._client.invoke(tool_name, args, invocation_ctx)
        else:
            result = self._client.invoke(tool_name, args, invocation_ctx)
        if "POST" in self._stage_mode:
            _ = None
        return result

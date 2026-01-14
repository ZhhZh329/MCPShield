"""Minimal MCP client wrapper."""

from __future__ import annotations

from typing import Any

from .types import MCPServerProtocol


class MCPClient:
    def __init__(self, server: MCPServerProtocol) -> None:
        self._server = server

    def fetch_manifest(self) -> dict:
        return self._server.fetch_manifest()

    def invoke(self, tool_name: str, args: dict, invocation_ctx: dict | None = None) -> Any:
        _ = invocation_ctx
        return self._server.invoke(tool_name, args)

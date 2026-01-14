"""Minimal type contracts."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

STAGE_TOKENS = ("PRE", "EXEC", "POST")


@runtime_checkable
class MCPServerProtocol(Protocol):
    def fetch_manifest(self) -> dict:
        ...

    def invoke(self, tool_name: str, args: dict) -> Any:
        ...

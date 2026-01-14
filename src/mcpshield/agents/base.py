"""Base agent contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseAgent(ABC):
    def __init__(self) -> None:
        self.tools: Any | None = None
        self._invocation_counter = 0
        self.server_whitelist: set[str] = set()
        self.server_blacklist: set[str] = set()

    @abstractmethod
    def run(self, task: str, run_ctx: dict) -> Any:
        ...

    def call_tool(self, tool_name: str, args: dict, run_ctx: dict) -> Any:
        if self.tools is None:
            raise RuntimeError("Agent tools are not set.")
        self._invocation_counter += 1
        invocation_ctx = {
            "run_ctx": run_ctx,
            "invocation_id": self._invocation_counter,
        }
        return self.tools.invoke(tool_name, args, invocation_ctx)

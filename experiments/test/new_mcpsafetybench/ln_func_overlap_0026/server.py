"""MCPSafetyBench adapter server for MCPShield v2 (in-process FastMCP)."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import re
import sys
import textwrap
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve()

def _find_mcpsafety_root() -> Path:
    for parent in HERE.parents:
        vendor = parent / "_vendor"
        if (vendor / "mcpuniverse").exists():
            return vendor
    for parent in HERE.parents:
        candidate = parent / "MCPShield" / "experiments" / "attackers" / "MCPSafety"
        if (candidate / "mcpuniverse").exists():
            return candidate
    raise RuntimeError("MCPSafety root not found")

MCPSAFETY_ROOT = _find_mcpsafety_root()
if str(MCPSAFETY_ROOT) not in sys.path:
    sys.path.insert(0, str(MCPSAFETY_ROOT))

BASE_MODULE = "mcpuniverse.mcp.servers.google_maps.server"
TASK_JSON = Path(__file__).with_name("task.json")


_ASYNC_LOOP: asyncio.AbstractEventLoop | None = None

def _run_async(coro: Any):
    global _ASYNC_LOOP
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise RuntimeError("Cannot call async tool from running event loop")
    if _ASYNC_LOOP is None or _ASYNC_LOOP.is_closed():
        _ASYNC_LOOP = asyncio.new_event_loop()
        asyncio.set_event_loop(_ASYNC_LOOP)
    return _ASYNC_LOOP.run_until_complete(coro)


def _extract_injection(mod_return: Any) -> str | None:
    if not isinstance(mod_return, str):
        return None
    matches = re.findall(r'([\'\"])(.*?)\1', mod_return, re.S)
    if not matches:
        return None
    return matches[-1][1]


def _wrap_tool_return(tool: Any, injection: str | None) -> None:
    if injection is None:
        return
    orig_run = tool.run

    async def injected_run(arguments: dict, context: Any = None, convert_result: bool = False):
        result = await orig_run(arguments, context=context, convert_result=convert_result)
        if result is None:
            return injection
        if isinstance(result, str):
            return result + injection
        return str(result) + injection

    tool.run = injected_run


def _apply_modifications(mcp: Any, task: dict) -> None:
    for mod in task.get("mcp_server_modifications", []) or []:
        tool_name = mod.get("tool_name")
        if not tool_name:
            continue
        tool = mcp._tool_manager.get_tool(tool_name)
        if not tool:
            continue
        desc = mod.get("modification_description")
        if desc:
            tool.description = desc
        mod_return = mod.get("modification_return")
        if mod_return:
            injection = _extract_injection(mod_return)
            _wrap_tool_return(tool, injection)


def _apply_additions(mcp: Any, task: dict) -> None:
    additions = task.get("mcp_server_additions")
    if not additions:
        return
    if isinstance(additions, dict) and "tools" in additions:
        tools = additions.get("tools", [])
    else:
        tools = [additions]

    for tool_def in tools:
        code = tool_def.get("implementation_code", "")
        if not code:
            continue
        code = textwrap.dedent(code).strip()
        namespace: dict[str, Any] = {}
        exec(code, namespace, namespace)
        tool_name = tool_def.get("tool_name")
        fn = namespace.get(tool_name)
        if fn is None:
            for value in namespace.values():
                if callable(value):
                    fn = value
                    break
        if fn is None:
            raise RuntimeError("Failed to load tool function for " + str(tool_name))
        mcp._tool_manager.add_tool(fn, name=tool_name, description=tool_def.get("description", ""))


class FastMCPAdapter:
    def __init__(self, mcp: Any, task: dict):
        self._mcp = mcp
        self._task = task or {}
        _apply_modifications(self._mcp, self._task)
        _apply_additions(self._mcp, self._task)

    def fetch_manifest(self) -> dict:
        tools = []
        for tool in self._mcp._tool_manager.list_tools():
            tools.append(
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.parameters,
                    "returns_example": getattr(tool, "output_schema", None),
                }
            )
        return {
            "server_name": self._mcp.name,
            "description": self._mcp.instructions or "",
            "tools": tools,
        }

    def invoke(self, tool_name: str, args: dict, invocation_ctx: dict | None = None):
        _ = invocation_ctx
        timeout_s = os.getenv("MCPSAFETY_TOOL_TIMEOUT", "20")
        try:
            timeout_s = float(timeout_s)
        except ValueError:
            timeout_s = 20.0
        coro = self._mcp._tool_manager.call_tool(tool_name, args)
        if timeout_s and timeout_s > 0:
            coro = asyncio.wait_for(coro, timeout=timeout_s)
        return _run_async(coro)


def build_server():
    module = importlib.import_module(BASE_MODULE)
    try:
        mcp = module.build_server()
    except TypeError as exc:
        if "port" in str(exc):
            mcp = module.build_server(8000)
        else:
            raise
    task = json.loads(TASK_JSON.read_text(encoding="utf-8"))
    return FastMCPAdapter(mcp, task)

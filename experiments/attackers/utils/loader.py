"""Generic server loader utilities for loading servers from JSON configs."""

import json
import random
from pathlib import Path
from typing import Any


class DynamicServer:
    """Dynamic server instance built from JSON configuration."""
    
    def __init__(self, config: dict, all_server_descriptions: list[str] | None = None):
        self.server_name = config.get("server_name", "unknown")
        self.server_index = config.get("server_index", 0)
        self.description = config.get("description", "")
        self._tools = self._convert_tools(config.get("tools", []))
        self._all_descriptions = all_server_descriptions or [self.description]
    
    def _convert_tools(self, tools: list[dict]) -> list[dict]:
        """Convert JSON tool definitions to MCP tool format."""
        mcp_tools = []
        for tool in tools:
            mcp_tool = {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "input_schema": self._convert_parameters(tool.get("parameters", [])),
            }
            mcp_tools.append(mcp_tool)
        return mcp_tools
    
    def _convert_parameters(self, params: list[dict]) -> dict:
        """Convert parameter list to input schema."""
        if not params:
            return {}
        
        schema = {"type": "object", "properties": {}, "required": []}
        for param in params:
            schema["properties"][param["name"]] = {
                "type": param.get("type", "string"),
                "description": param.get("description", ""),
            }
            if param.get("required", False):
                schema["required"].append(param["name"])
        
        return schema
    
    def fetch_manifest(self) -> dict:
        """Return server manifest with tools."""
        return {
            "server_name": self.server_name,
            "description": self.description,
            "tools": self._tools,
        }
    
    def invoke(self, tool_name: str, args: dict) -> Any:
        """Invoke a tool - returns a random server description to simulate mismatch attack."""
        tool = next((t for t in self._tools if t["name"] == tool_name), None)
        if tool is None:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        # Randomly select a description from the pool to simulate mismatch attack
        random_description = random.choice(self._all_descriptions)
        
        return {
            "status": "success",
            "tool": tool_name,
            "args": args,
            "description": random_description,
            "message": "Done",
        }


class ServerBuilder:
    def __init__(self, json_path: Path):
        """
        Args:
            json_path: Absolute path to the JSON file containing server configs
        """
        self.json_path = json_path
        self._servers_cache: dict[str, DynamicServer] | None = None
    
    def load_all_servers(self) -> dict[str, DynamicServer]:
        """Load all servers from JSON file and cache them."""
        if self._servers_cache is not None:
            return self._servers_cache
        
        if not self.json_path.exists():
            raise FileNotFoundError(f"JSON file not found: {self.json_path}")
        
        with self.json_path.open("r", encoding="utf-8") as f:
            server_configs = json.load(f)
        
        # Collect all descriptions first
        all_descriptions = [cfg.get("description", "") for cfg in server_configs]
        
        servers = {}
        for config in server_configs:
            server = DynamicServer(config, all_descriptions)
            servers[server.server_name] = server
        
        self._servers_cache = servers
        return servers
    
    def build_server(self, server_name: str) -> DynamicServer:
        """Build a specific server by name."""
        servers = self.load_all_servers()
        
        if server_name not in servers:
            available = list(servers.keys())
            raise ValueError(
                f"Server '{server_name}' not found. "
                f"Available servers: {available}"
            )
        
        return servers[server_name]
    
    def build_server_by_index(self, index: int) -> DynamicServer:
        """Build server by its index in the JSON file."""
        servers = self.load_all_servers()
        servers_list = list(servers.values())
        
        if not (0 <= index < len(servers_list)):
            raise IndexError(
                f"Server index {index} out of range (0-{len(servers_list)-1})"
            )
        
        return servers_list[index]
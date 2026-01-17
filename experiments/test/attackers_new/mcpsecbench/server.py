"""MCPSecBench benchmark servers - loads 11 attack servers from JSON configuration."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Add utils to path
ATTACKERS_DIR = Path(__file__).resolve().parent.parent
UTILS_DIR = ATTACKERS_DIR / "utils"
if str(UTILS_DIR) not in sys.path:
    sys.path.insert(0, str(UTILS_DIR))

from loader import ServerBuilder


def build_server() -> list[Any]:
    """
    Build all 11 MCPSecBench attack servers from JSON configuration.

    Returns:
        List of DynamicServer instances (11 servers total)
    """
    json_path = ATTACKERS_DIR / "json_assets" / "mcpsecbench_tools.json"
    builder = ServerBuilder(json_path)

    # Load all servers from JSON
    all_servers = builder.load_all_servers()

    # Return as list, sorted by server_index for consistency
    servers_list = sorted(all_servers.values(), key=lambda s: s.server_index)

    return servers_list


def build_single_server(server_name: str) -> Any:
    """
    Build a single server by name.

    Args:
        server_name: Name of the server to build (e.g., "tool_poisoning_attack", "rug_pull")

    Returns:
        Single DynamicServer instance
    """
    json_path = ATTACKERS_DIR / "json_assets" / "mcpsecbench_tools.json"
    builder = ServerBuilder(json_path)
    return builder.build_server(server_name)


def build_server_by_index(index: int) -> Any:
    """
    Build a single server by index.

    Args:
        index: Server index (0-10)

    Returns:
        Single DynamicServer instance
    """
    json_path = ATTACKERS_DIR / "json_assets" / "mcpsecbench_tools.json"
    builder = ServerBuilder(json_path)
    return builder.build_server_by_index(index)


if __name__ == "__main__":
    # Test the server loading
    servers = build_server()
    print(f"Loaded {len(servers)} servers:")
    for i, server in enumerate(servers):
        manifest = server.fetch_manifest()
        tools_count = len(manifest.get("tools", []))
        print(f"  [{i}] {manifest['server_name']}: {tools_count} tool(s) - {manifest.get('description', '')}")

    # Test invoking a tool
    if servers:
        print("\nTesting first attack server (index 0):")
        first_server = servers[0]
        manifest = first_server.fetch_manifest()
        tool_name = manifest["tools"][0]["name"]
        result = first_server.invoke(tool_name, {})
        print(f"  Tool: {tool_name}")
        print(f"  Result: {result}")

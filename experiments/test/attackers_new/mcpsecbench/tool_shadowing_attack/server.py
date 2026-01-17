"""MCPSecBench server wrapper for tool_shadowing_attack."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[2]
UTILS_DIR = BASE_DIR / "utils"
if str(UTILS_DIR) not in sys.path:
    sys.path.insert(0, str(UTILS_DIR))

from loader import ServerBuilder

_SERVER_NAME = "tool_shadowing_attack"


def build_server() -> Any:
    json_path = BASE_DIR / "json_assets" / "mcpsecbench_tools.json"
    builder = ServerBuilder(json_path)
    return builder.build_server(_SERVER_NAME)

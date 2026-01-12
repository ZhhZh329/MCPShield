"""California weather server."""

from __future__ import annotations

from typing import Any


_TOOLS = [
    {
        "name": "weather.ca.san_francisco",
        "description": "Weather for San Francisco, CA.",
        "input_schema": {"unit": "string"},
    },
    {
        "name": "weather.ca.los_angeles",
        "description": "Weather for Los Angeles, CA.",
        "input_schema": {"unit": "string"},
    },
    {
        "name": "weather.ca.san_diego",
        "description": "Weather for San Diego, CA.",
        "input_schema": {"unit": "string"},
    },
]

_DATA = {
    "weather.ca.san_francisco": {"city": "San Francisco", "temp_c": 18, "temp_f": 64, "condition": "foggy"},
    "weather.ca.los_angeles": {"city": "Los Angeles", "temp_c": 24, "temp_f": 75, "condition": "sunny"},
    "weather.ca.san_diego": {"city": "San Diego", "temp_c": 22, "temp_f": 72, "condition": "clear"},
}


class CAWeatherServer:
    def fetch_manifest(self) -> dict:
        return {"server_name": "weather_ca", "tools": _TOOLS}

    def invoke(self, tool_name: str, args: dict) -> Any:
        if tool_name not in _DATA:
            raise ValueError(f"Unknown tool: {tool_name}")
        unit = str(args.get("unit", "c")).lower()
        payload = dict(_DATA[tool_name])
        if unit == "f":
            payload["temperature"] = payload["temp_f"]
            payload["unit"] = "f"
        else:
            payload["temperature"] = payload["temp_c"]
            payload["unit"] = "c"
        return payload


def build_server() -> CAWeatherServer:
    return CAWeatherServer()

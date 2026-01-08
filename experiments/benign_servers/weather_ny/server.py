"""New York weather server."""

from __future__ import annotations

from typing import Any


_TOOLS = [
    {
        "name": "weather.ny.new_york_city",
        "description": "Weather for New York City, NY.",
        "input_schema": {"unit": "string"},
    },
    {
        "name": "weather.ny.buffalo",
        "description": "Weather for Buffalo, NY.",
        "input_schema": {"unit": "string"},
    },
    {
        "name": "weather.ny.albany",
        "description": "Weather for Albany, NY.",
        "input_schema": {"unit": "string"},
    },
]

_DATA = {
    "weather.ny.new_york_city": {"city": "New York City", "temp_c": 16, "temp_f": 61, "condition": "cloudy"},
    "weather.ny.buffalo": {"city": "Buffalo", "temp_c": 10, "temp_f": 50, "condition": "windy"},
    "weather.ny.albany": {"city": "Albany", "temp_c": 12, "temp_f": 54, "condition": "overcast"},
}


class NYWeatherServer:
    def fetch_manifest(self) -> dict:
        return {"server_name": "weather_ny", "tools": _TOOLS}

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


def build_server() -> NYWeatherServer:
    return NYWeatherServer()

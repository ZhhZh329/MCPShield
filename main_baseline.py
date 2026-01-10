"""Minimal debug entrypoint for MCPShield v2."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcpshield.agents.main_agent import MainAgent


def load_env(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


class _EmptyTools:
    def fetch_manifest(self) -> dict:
        return {"tools": []}

    def invoke(self, tool_name: str, args: dict, invocation_ctx: dict | None = None):
        raise RuntimeError("No tools available.")


def _build_agent_from_env() -> MainAgent:
    load_env(ROOT / ".env")
    model = os.environ.get("OPENROUTER_MODEL", "")
    base_url = os.environ.get("OPENROUTER_BASE_URL", "")
    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not model or not base_url or not api_key:
        raise RuntimeError("Missing OPENROUTER_MODEL/BASE_URL/API_KEY in .env")
    return MainAgent(model=model, base_url=base_url, api_key=api_key)


def run_agent_only(query: str) -> None:
    agent = _build_agent_from_env()
    agent.tools = _EmptyTools()
    result = agent.run(query, {"mode": "agent_only"})
    print(json.dumps(result, ensure_ascii=True, indent=2))


def run_exp_file(exp_path: Path) -> None:
    import run_exp

    out_dir = run_exp.run_exp(exp_path)
    print(f"[main] output_dir: {out_dir}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="MCPShield v2 debug entrypoint")
    parser.add_argument("--exp", type=Path, help="Run a single exp file")
    parser.add_argument("--agent-only", type=str, help="Answer without any server")
    args = parser.parse_args(argv[1:])

    if args.agent_only:
        run_agent_only(args.agent_only)
        return 0

    if args.exp:
        run_exp_file(args.exp)
        return 0

    default_exp = ROOT / "experiments" / "exp_weather.yaml"
    if default_exp.exists():
        run_exp_file(default_exp)
        return 0

    print("No exp provided and default exp not found.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

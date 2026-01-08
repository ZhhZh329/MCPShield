"""Run an experiment from a single exp YAML file."""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcpshield.agents.main_agent import MainAgent
from mcpshield.client import MCPClient
from mcpshield.shield import MCPShield


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


def read_yaml(path: Path) -> dict:
    try:
        import yaml  # type: ignore
    except Exception as exc:
        raise RuntimeError("PyYAML is required to read exp files") from exc
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def write_jsonl_line(path: Path, record: dict) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")


def load_server(server_id: str) -> Any:
    base_dirs = [
        ROOT / "experiments" / "benign_servers",
        ROOT / "experiments" / "attackers",
    ]
    server_path = None
    for base in base_dirs:
        candidate = base / server_id / "server.py"
        if candidate.exists():
            server_path = candidate
            break
    if server_path is None:
        raise FileNotFoundError(f"server_id not found: {server_id}")

    module_name = f"server_{server_id}"
    spec = spec_from_file_location(module_name, server_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load server module: {server_path}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)

    if hasattr(module, "build_server"):
        return module.build_server()
    if hasattr(module, "make_server"):
        return module.make_server()
    raise AttributeError("Server module must provide build_server() or make_server().")


def ensure_output_dir(exp_id: str, output_root: str) -> Path:
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    out_dir = ROOT / output_root / exp_id / timestamp
    out_dir.mkdir(parents=True, exist_ok=False)
    return out_dir


def run_exp(exp_path: Path) -> Path:
    load_env(ROOT / ".env")
    exp = read_yaml(exp_path)

    exp_id = exp["exp_id"]
    output_root = exp.get("output_root", "results")
    out_dir = ensure_output_dir(exp_id, output_root)
    shutil.copy2(exp_path, out_dir / exp_path.name)

    agent_cfg = exp.get("agent", {})
    model = agent_cfg.get("model") or os.environ.get("OPENROUTER_MODEL", "")
    base_url = agent_cfg.get("base_url") or os.environ.get("OPENROUTER_BASE_URL", "")
    api_key_env = agent_cfg.get("api_key_env", "OPENROUTER_API_KEY")
    api_key = os.environ.get(api_key_env, "")

    if not model or not base_url or not api_key:
        raise RuntimeError("Missing agent config: model/base_url/api_key")

    agent = MainAgent(model=model, base_url=base_url, api_key=api_key)

    shield_cfg = exp.get("shield", {})
    shield_enabled = bool(shield_cfg.get("enabled", False))
    stage_mode = shield_cfg.get("stage_mode", [])

    for run_case in exp.get("runs", []):
        run_id = run_case.get("run_id")
        query = run_case.get("query")
        server_id = run_case.get("server_id")
        run_ctx = {
            "exp_id": exp_id,
            "run_id": run_id,
            "server_id": server_id,
            "stage_mode": stage_mode,
            "start_ts": time.time(),
        }

        ok = True
        error = None
        output = None
        try:
            if server_id:
                server = load_server(server_id)
                client = MCPClient(server)
                tools = MCPShield(client, stage_mode) if shield_enabled else client
            else:
                tools = _EmptyTools()
            agent.tools = tools
            output = agent.run(query, run_ctx)
        except Exception as exc:
            ok = False
            error = str(exc)

        record = {
            "run_id": run_id,
            "server_id": server_id,
            "query": query,
            "ok": ok,
            "error": error,
            "output": output,
        }
        write_jsonl_line(out_dir / "run_records.jsonl", record)
        status = "ok" if ok else "error"
        print(f"[run_exp] {run_id} {status}")

    return out_dir


class _EmptyTools:
    def fetch_manifest(self) -> dict:
        return {"tools": []}

    def invoke(self, tool_name: str, args: dict, invocation_ctx: dict | None = None) -> Any:
        raise RuntimeError("No tools available.")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: python run_exp.py <exp.yaml>")
        return 2
    exp_path = Path(argv[1])
    out_dir = run_exp(exp_path)
    print(f"[run_exp] output_dir: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

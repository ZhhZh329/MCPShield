"""Run an experiment from a single exp YAML file."""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any, Callable, Protocol, runtime_checkable

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcpshield.agents.main_agent import MainAgent
from mcpshield.client import MCPClient
from mcpshield.shield import MCPShield, MCPShieldDeny

@runtime_checkable
class ServerToolsProtocol(Protocol):
    """实现两个方法就可以，不过严格检查了."""
    
    def fetch_manifest(self) -> dict:

        ...
    
    def invoke(self, tool_name: str, args: dict, invocation_ctx: dict | None = None) -> Any:
        ...

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


def resolve_allowed_paths(base_dir: Path, paths: list[str] | None) -> list[Path]:
    resolved: list[Path] = []
    for item in paths or []:
        path = Path(item)
        if not path.is_absolute():
            path = (base_dir / path).resolve()
        else:
            path = path.resolve()
        resolved.append(path)
    return resolved


def make_workspace(out_dir: Path, run_id: str | None) -> Path:
    workspaces_dir = out_dir / "workspaces"
    workspaces_dir.mkdir(parents=True, exist_ok=True)
    safe_name = str(run_id or f"run_{int(time.time() * 1000)}").replace(os.sep, "_")
    workspace_dir = workspaces_dir / safe_name
    workspace_dir.mkdir(parents=True, exist_ok=False)
    return workspace_dir


def link_inputs(workspace_dir: Path, allowed_paths: list[Path]) -> list[str]:
    if not allowed_paths:
        return []
    inputs_dir = workspace_dir / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    linked = []
    for idx, path in enumerate(allowed_paths):
        name = path.name or f"path_{idx}"
        link_path = inputs_dir / name
        if link_path.exists():
            link_path = inputs_dir / f"{name}_{idx}"
        try:
            os.symlink(path, link_path)
            linked.append(str(link_path))
        except Exception:
            continue
    return linked


def load_servers(server_id: str, server_path: str | None = None) -> list[Any]:
    """Load server(s) from a server_id or explicit server_path.
    
    Returns a list of server instances. Most servers return a single instance,
    but some (like mcpsafety) return multiple servers.
    """
    if server_path:
        candidate = Path(server_path)
        if not candidate.is_absolute():
            candidate = (ROOT / candidate).resolve()
        if candidate.is_dir():
            candidate = candidate / "server.py"
        if not candidate.exists():
            raise FileNotFoundError(f"server_path not found: {candidate}")
        server_path_obj = candidate
    else:
        base_dirs = [
            ROOT / "experiments" / "benign_servers",
            ROOT / "experiments" / "attackers",
            ROOT / "experiments" / "test" / "benign_servers",
            ROOT / "experiments" / "test" / "attackers",
            ROOT / "experiments" / "test",
        ]
        server_path_obj = None
        for base in base_dirs:
            candidate = base / server_id / "server.py"
            if candidate.exists():
                server_path_obj = candidate
                break
        if server_path_obj is None:
            raise FileNotFoundError(f"server_id not found: {server_id}")

    module_name = f"server_{server_id}"
    spec = spec_from_file_location(module_name, server_path_obj)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load server module: {server_path_obj}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)

    server_or_servers = None
    if hasattr(module, "build_server"):
        server_or_servers = module.build_server()
    elif hasattr(module, "make_server"):
        server_or_servers = module.make_server()
    else:
        raise AttributeError("Server module must provide build_server() or make_server().")
    
    # Normalize to list
    if isinstance(server_or_servers, list):
        return server_or_servers
    else:
        return [server_or_servers]


class MultiServerClient:
    """包装多个server为统一工具接口 - 满足 ServerToolsProtocol（结构化类型）."""
    
    def __init__(self, servers: list[Any]):
        self.servers = servers
        self._tools_cache = None
    
    def fetch_manifest(self) -> dict:
        """Merge all server manifests into one."""
        if self._tools_cache is not None:
            return {"tools": self._tools_cache}
        
        all_tools = []
        for server in self.servers:
            manifest = server.fetch_manifest()
            tools = manifest.get("tools", [])
            all_tools.extend(tools)
        
        self._tools_cache = all_tools
        return {"tools": all_tools}
    
    def invoke(self, tool_name: str, args: dict, invocation_ctx: dict | None = None) -> Any:
        """Find the server that has this tool and invoke it."""
        for server in self.servers:
            manifest = server.fetch_manifest()
            tool_names = {tool["name"] for tool in manifest.get("tools", [])}
            if tool_name in tool_names:
                # Check if server supports invocation_ctx parameter
                import inspect
                sig = inspect.signature(server.invoke)
                if "invocation_ctx" in sig.parameters:
                    return server.invoke(tool_name, args, invocation_ctx)
                else:
                    return server.invoke(tool_name, args)
        
        raise ValueError(f"Tool '{tool_name}' not found in any server")


def ensure_output_dir(exp_id: str, output_root: str) -> Path:
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    out_dir = ROOT / output_root / exp_id / timestamp
    out_dir.mkdir(parents=True, exist_ok=False)
    return out_dir


def run_exp_with_agent(
    exp_path: Path,
    exp: dict,
    agent: MainAgent,
    out_dir: Path,
    *,
    record_hook: Callable[[dict, dict], None] | None = None,
    copy_exp: bool = True,
    agent_id: str | None = None,
) -> Path:
    exp_id = exp["exp_id"]
    log_level = exp.get("log_level")
    debug = exp.get("debug", False)
    if log_level is not None:
        debug = str(log_level).lower() == "debug"

    out_dir.mkdir(parents=True, exist_ok=True)
    if copy_exp:
        shutil.copy2(exp_path, out_dir / exp_path.name)

    agent_cfg = exp.get("agent", {})
    model = agent_cfg.get("model") or os.environ.get("OPENROUTER_MODEL", "")
    base_url = agent_cfg.get("base_url") or os.environ.get("OPENROUTER_BASE_URL", "")
    api_key_env = agent_cfg.get("api_key_env", "OPENROUTER_API_KEY")
    api_key = os.environ.get(api_key_env, "")

    if not model or not base_url or not api_key:
        raise RuntimeError("Missing agent config: model/base_url/api_key")

    shield_cfg = exp.get("shield", {})
    shield_enabled = bool(shield_cfg.get("enabled", False))
    pre_enabled = bool(shield_cfg.get("pre", False))
    exec_enabled = bool(shield_cfg.get("exec", False))
    post_enabled = bool(shield_cfg.get("post", False))
    pre_mock_count = int(shield_cfg.get("pre_mock_count", 4))
    pre_deny_ratio = float(shield_cfg.get("pre_deny_ratio", 0.5))

    sandbox_cfg = exp.get("sandbox", {})
    sandbox_allowed_paths = resolve_allowed_paths(ROOT, sandbox_cfg.get("allowed_paths"))
    sandbox_allowed_domains = list(sandbox_cfg.get("allowed_domains") or [])
    sandbox_trace_mode = str(sandbox_cfg.get("trace_mode", "py"))
    sandbox_persist = bool(sandbox_cfg.get("persist_workspace", True))
    sandbox_link_inputs = bool(sandbox_cfg.get("link_inputs", True))

    for run_case in exp.get("runs", []):
        run_id = run_case.get("run_id")
        query = run_case.get("query")
        server_id = run_case.get("server_id")
        server_path = run_case.get("server_path")
        pre_logs: list[dict] = []
        exec_logs: list[dict] = []
        run_sandbox = run_case.get("sandbox", {})
        run_allowed_domains = (
            list(run_sandbox.get("allowed_domains") or [])
            if "allowed_domains" in run_sandbox
            else sandbox_allowed_domains
        )
        if "allowed_paths" in run_sandbox:
            run_allowed_paths = resolve_allowed_paths(ROOT, run_sandbox.get("allowed_paths"))
        else:
            run_allowed_paths = sandbox_allowed_paths
        workspace_dir = None
        input_links: list[str] = []
        if exec_enabled:
            workspace_dir = make_workspace(out_dir, run_id)
            if sandbox_link_inputs:
                input_links = link_inputs(workspace_dir, run_allowed_paths)
        run_ctx = {
            "exp_id": exp_id,
            "run_id": run_id,
            "server_id": server_id,
            "query": query,
            "agent_id": agent_id,
            "sandbox": {
                "workspace_dir": str(workspace_dir) if workspace_dir else None,
                "allowed_paths": [str(path) for path in run_allowed_paths],
                "allowed_domains": run_allowed_domains,
                "trace_mode": sandbox_trace_mode,
                "input_links": input_links,
            },
            "shield": {
                "enabled": shield_enabled,
                "pre": pre_enabled,
                "exec": exec_enabled,
                "post": post_enabled,
                "pre_mock_count": pre_mock_count,
            },
            "start_ts": time.time(),
        }

        ok = True
        error = None
        output = None
        deny = None
        try:
            if server_id:
                servers = load_servers(server_id, server_path)
                if len(servers) > 1:
                    client = MultiServerClient(servers)
                else:
                    client = MCPClient(servers[0])
                if shield_enabled:
                    sandbox_ctx = {
                        "workspace_dir": workspace_dir,
                        "allowed_paths": run_allowed_paths,
                        "allowed_domains": run_allowed_domains,
                        "trace_mode": sandbox_trace_mode,
                    }
                    tools = MCPShield(
                        client,
                        pre_enabled=pre_enabled,
                        exec_enabled=exec_enabled,
                        post_enabled=post_enabled,
                        model=model,
                        base_url=base_url,
                        api_key=api_key,
                        pre_mock_count=pre_mock_count,
                        pre_deny_ratio=pre_deny_ratio,
                        whitelist=agent.server_whitelist,
                        blacklist=agent.server_blacklist,
                        pre_logs=pre_logs,
                        exec_logs=exec_logs,
                        sandbox_cfg=sandbox_ctx,
                    )
                else:
                    tools = client
            else:
                tools = _EmptyTools()
            agent.tools = tools
            output = agent.run(query, run_ctx)
        except MCPShieldDeny as exc:
            ok = False
            deny = {
                "server_id": exc.server_id,
                "reason": exc.reason,
                "deny_stage": exc.deny_stage,
                "mock_matrix": exc.mock_matrix,
                "exec_event": exc.exec_event,
            }
        except Exception as exc:
            ok = False
            error = str(exc)
        finally:
            if exec_enabled and workspace_dir and not sandbox_persist:
                shutil.rmtree(workspace_dir, ignore_errors=True)

        record = {
            "run_id": run_id,
            "agent_id": agent_id,
            "server_id": server_id,
            "query": query,
            "ok": ok,
            "error": error,
            "output": output,
            "shield_pre": pre_logs if shield_enabled else None,
            "shield_exec": exec_logs if shield_enabled else None,
            "deny": deny,
        }
        write_jsonl_line(out_dir / "run_records.jsonl", record)
        if record_hook:
            record_hook(record, run_ctx)
        status = "ok" if ok else ("deny" if deny else "error")
        print(f"[run_exp] {run_id} {status}")
        if deny and debug:
            print("[debug] deny detail:")
            print(json.dumps(deny, ensure_ascii=True, indent=2))

    return out_dir


def run_exp(exp_path: Path) -> Path:
    load_env(ROOT / ".env")
    exp = read_yaml(exp_path)

    exp_id = exp["exp_id"]
    output_root = exp.get("output_root", "results")
    out_dir = ensure_output_dir(exp_id, output_root)

    agent_cfg = exp.get("agent", {})
    model = agent_cfg.get("model") or os.environ.get("OPENROUTER_MODEL", "")
    base_url = agent_cfg.get("base_url") or os.environ.get("OPENROUTER_BASE_URL", "")
    api_key_env = agent_cfg.get("api_key_env", "OPENROUTER_API_KEY")
    api_key = os.environ.get(api_key_env, "")

    if not model or not base_url or not api_key:
        raise RuntimeError("Missing agent config: model/base_url/api_key")

    agent = MainAgent(model=model, base_url=base_url, api_key=api_key)
    agent.server_whitelist = set()
    agent.server_blacklist = set()

    return run_exp_with_agent(exp_path, exp, agent, out_dir, copy_exp=True)


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

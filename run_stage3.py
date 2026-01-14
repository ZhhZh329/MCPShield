"""Run a Stage3 experiment with multiple agents."""

from __future__ import annotations

import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcpshield.agents.main_agent import MainAgent
from mcpshield.prompts.stage3 import build_stage3_prompt
from run_exp import (
    ensure_output_dir,
    load_env,
    read_yaml,
    run_exp_with_agent,
    write_jsonl_line,
)


def _normalize_base_url(base_url: str) -> str:
    suffix = "/chat/completions"
    if base_url.endswith(suffix):
        return base_url[: -len(suffix)]
    return base_url


def _extract_json(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3:
            text = "\n".join(lines[1:-1]).strip()
    return json.loads(text)


def _summarize_record(record: dict) -> dict[str, Any]:
    deny = record.get("deny")
    event_types: list[str] = []
    paths: list[str] = []
    domains: list[str] = []
    event_counts: dict[str, int] = {}
    tool_names: list[str] = []
    analysis_flags: list[str] = []

    exec_logs = record.get("shield_exec") or []
    for log in exec_logs:
        tool_name = log.get("tool_name")
        if tool_name:
            tool_names.append(tool_name)
        analysis = log.get("analysis") or {}
        flags = analysis.get("flags") or []
        for flag in flags:
            analysis_flags.append(str(flag))
        for event in log.get("events", []):
            event_type = event.get("type")
            if not event_type:
                continue
            event_types.append(event_type)
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
            target = event.get("target")
            if event_type.startswith("network"):
                if target:
                    domains.append(str(target))
            elif target:
                paths.append(str(target))

    deny_event = deny.get("exec_event") if isinstance(deny, dict) else None
    if deny_event and isinstance(deny_event, dict):
        event_type = deny_event.get("type")
        if event_type:
            event_types.append(event_type)
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
        target = deny_event.get("target")
        if event_type and event_type.startswith("network"):
            if target:
                domains.append(str(target))
        elif target:
            paths.append(str(target))

    return {
        "ts": time.time(),
        "run_id": record.get("run_id"),
        "server_id": record.get("server_id"),
        "ok": record.get("ok", False),
        "deny_stage": deny.get("deny_stage") if isinstance(deny, dict) else None,
        "deny_reason": deny.get("reason") if isinstance(deny, dict) else None,
        "tool_names": tool_names,
        "event_types": event_types,
        "event_counts": event_counts,
        "paths": paths,
        "domains": domains,
        "analysis_flags": analysis_flags,
    }


def _build_signature(summary: dict[str, Any], *, reason: str, source: str) -> dict[str, Any]:
    return {
        "server_id": summary.get("server_id"),
        "reason": reason,
        "source": source,
        "event_types": summary.get("event_types", []),
        "paths": summary.get("paths", []),
        "domains": summary.get("domains", []),
        "analysis_flags": summary.get("analysis_flags", []),
    }


def _append_signature(
    signatures: list[dict[str, Any]],
    signature_keys: set[str],
    signature: dict[str, Any],
    output_path: Path,
) -> None:
    key = f"{signature.get('server_id')}:{signature.get('reason')}"
    if key in signature_keys:
        return
    signature_keys.add(key)
    signatures.append(signature)
    write_jsonl_line(output_path, signature)


def _build_recent_ok(history: list[dict[str, Any]], k: int) -> list[dict[str, Any]]:
    recent = []
    for summary in reversed(history):
        if summary.get("ok"):
            recent.append(summary)
        if len(recent) >= k:
            break
    return list(reversed(recent))


def _truncate_history(history: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    if len(history) <= limit:
        return history
    return history[-limit:]


def _run_stage3_llm(
    *,
    llm: Any,
    model: str,
    server_id: str,
    recent_window: list[dict[str, Any]],
    history_window: list[dict[str, Any]],
    signatures: list[dict[str, Any]],
) -> tuple[str, dict[str, Any] | None]:
    system, user = build_stage3_prompt(
        server_id=server_id,
        recent_window=recent_window,
        history_window=history_window,
        global_signatures=signatures,
    )
    raw = llm.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0,
    ).choices[0].message.content or ""
    try:
        payload = _extract_json(raw)
    except Exception:
        payload = None
    return raw, payload


def run_stage3(exp_path: Path) -> Path:
    load_env(ROOT / ".env")
    stage3 = read_yaml(exp_path)

    stage3_id = stage3.get("stage3_id") or stage3.get("exp_id")
    if not stage3_id:
        raise RuntimeError("stage3_id is required")
    output_root = stage3.get("output_root", "results")
    k = int(stage3.get("k", 3))
    agents = stage3.get("agents", [])
    if not agents:
        raise RuntimeError("stage3 agents list is required")

    out_dir = ensure_output_dir(stage3_id, output_root)
    exp_copy = out_dir / exp_path.name
    exp_copy.write_text(Path(exp_path).read_text(encoding="utf-8"), encoding="utf-8")

    signatures: list[dict[str, Any]] = []
    signature_keys: set[str] = set()
    global_blacklist: set[str] = set()

    stage3_records = out_dir / "stage3_records.jsonl"
    signature_path = out_dir / "signatures.jsonl"

    for agent_entry in agents:
        agent_id = agent_entry.get("id")
        exp_file = agent_entry.get("exp")
        if not agent_id or not exp_file:
            raise RuntimeError("Each agent must have id and exp")
        exp_path_agent = Path(exp_file)
        if not exp_path_agent.is_absolute():
            exp_path_agent = (ROOT / exp_path_agent).resolve()
        exp = read_yaml(exp_path_agent)

        agent_cfg = exp.get("agent", {})
        model = agent_cfg.get("model") or os.environ.get("OPENROUTER_MODEL", "")
        base_url = agent_cfg.get("base_url") or os.environ.get("OPENROUTER_BASE_URL", "")
        api_key_env = agent_cfg.get("api_key_env", "OPENROUTER_API_KEY")
        api_key = os.environ.get(api_key_env, "")
        if not model or not base_url or not api_key:
            raise RuntimeError("Missing agent config: model/base_url/api_key")

        try:
            from openai import OpenAI  # type: ignore
        except Exception as exc:
            raise RuntimeError("openai package is required for Stage3") from exc
        llm = OpenAI(api_key=api_key, base_url=_normalize_base_url(base_url))

        agent = MainAgent(model=model, base_url=base_url, api_key=api_key)
        agent.server_whitelist = set()
        agent.server_blacklist = global_blacklist

        history: dict[str, list[dict[str, Any]]] = defaultdict(list)
        ok_counts: dict[str, int] = defaultdict(int)

        exp_id = exp.get("exp_id", "exp")
        agent_out_dir = out_dir / "agents" / agent_id / exp_id
        agent_out_dir.mkdir(parents=True, exist_ok=True)

        def record_hook(record: dict, run_ctx: dict) -> None:
            server_id = record.get("server_id")
            if not server_id:
                return
            summary = _summarize_record(record)
            history[server_id].append(summary)

            deny = record.get("deny")
            if deny:
                reason = deny.get("reason", "deny")
                signature = _build_signature(summary, reason=reason, source="stage1_2")
                _append_signature(signatures, signature_keys, signature, signature_path)
                global_blacklist.add(server_id)
                return

            if record.get("ok"):
                ok_counts[server_id] += 1
                if ok_counts[server_id] % k != 0:
                    return
                recent_ok = _build_recent_ok(history[server_id], k)
                history_window = history[server_id][:-len(recent_ok)] if recent_ok else history[server_id]
                history_window = _truncate_history(history_window)
                sig_window = _truncate_history(signatures, 20)
                raw, payload = _run_stage3_llm(
                    llm=llm,
                    model=model,
                    server_id=server_id,
                    recent_window=recent_ok,
                    history_window=history_window,
                    signatures=sig_window,
                )
                stage3_result = {
                    "agent_id": agent_id,
                    "server_id": server_id,
                    "trigger_run_id": record.get("run_id"),
                    "trusted": payload.get("trusted") if isinstance(payload, dict) else None,
                    "reason": payload.get("reason") if isinstance(payload, dict) else None,
                    "flags": payload.get("flags") if isinstance(payload, dict) else None,
                    "drift_score": payload.get("drift_score") if isinstance(payload, dict) else None,
                    "signature": payload.get("signature") if isinstance(payload, dict) else None,
                    "analysis_raw": raw,
                }
                write_jsonl_line(stage3_records, stage3_result)

                if isinstance(payload, dict) and not payload.get("trusted", True):
                    reason = payload.get("reason", "stage3_deny")
                    signature = payload.get("signature") or _build_signature(
                        summary, reason=reason, source="stage3"
                    )
                    _append_signature(signatures, signature_keys, signature, signature_path)
                    global_blacklist.add(server_id)

        run_exp_with_agent(
            exp_path_agent,
            exp,
            agent,
            agent_out_dir,
            record_hook=record_hook,
            copy_exp=True,
            agent_id=agent_id,
        )

    return out_dir


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: python run_stage3.py <stage3_exp.yaml>")
        return 2
    exp_path = Path(argv[1])
    out_dir = run_stage3(exp_path)
    print(f"[stage3] output_dir: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

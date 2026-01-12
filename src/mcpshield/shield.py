"""MCPShield invocation wrapper with staged checks."""

from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .client import MCPClient
from .prompts.stage1 import build_eval_prompt, build_mock_prompt


@runtime_checkable
class ServerToolsProtocol(Protocol):
    """结构化类型协议 - 任何有这些方法的对象都可以作为client使用."""
    
    def fetch_manifest(self) -> dict:
        """返回工具清单 {"tools": [...]}."""
        ...
    
    def invoke(self, tool_name: str, args: dict, invocation_ctx: dict | None = None) -> Any:
        """调用指定工具."""
        ...


class MCPShieldDeny(Exception):
    """Raised when MCPShield rejects a server/tool."""

    def __init__(
        self,
        server_id: str,
        reason: str,
        pre_log: dict | None = None,
        mock_matrix: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(reason)
        self.server_id = server_id
        self.reason = reason
        self.pre_log = pre_log
        self.mock_matrix = mock_matrix or []


class MCPShield:
    def __init__(
        self,
        client: ServerToolsProtocol,  # 接受任何满足Protocol的client
        *,
        pre_enabled: bool = False,
        exec_enabled: bool = False,
        post_enabled: bool = False,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        pre_mock_count: int = 2,
        pre_deny_ratio: float = 0.5,
        whitelist: set[str] | None = None,
        blacklist: set[str] | None = None,
        pre_logs: list[dict] | None = None,
    ) -> None:
        self._client = client
        self._pre_enabled = pre_enabled
        self._exec_enabled = exec_enabled
        self._post_enabled = post_enabled
        self._pre_mock_count = pre_mock_count
        self._pre_deny_ratio = pre_deny_ratio
        self._whitelist = whitelist if whitelist is not None else set()
        self._blacklist = blacklist if blacklist is not None else set()
        self._blacklist_reason: dict[str, str] = {}
        self._pre_logs = pre_logs if pre_logs is not None else []

        self._llm = None
        self._model = model
        if self._pre_enabled:
            if not model or not base_url or not api_key:
                raise RuntimeError("MCPShield pre requires model/base_url/api_key")
            try:
                from openai import OpenAI  # type: ignore
            except Exception as exc:
                raise RuntimeError("openai package is required for MCPShield") from exc
            self._llm = OpenAI(api_key=api_key, base_url=self._normalize_base_url(base_url))

    def fetch_manifest(self) -> dict:
        return self._client.fetch_manifest()

    def invoke(self, tool_name: str, args: dict, invocation_ctx: dict | None = None) -> Any:
        run_ctx = {}
        if invocation_ctx and isinstance(invocation_ctx, dict):
            run_ctx = invocation_ctx.get("run_ctx", {}) or {}
        server_id = run_ctx.get("server_id")

        if self._pre_enabled and server_id and server_id in self._blacklist:
            reason = self._blacklist_reason.get(server_id, "MCPShield deny (blacklist).")
            raise MCPShieldDeny(server_id, reason)

        if self._pre_enabled and server_id and server_id not in self._whitelist:
            pre_log = self._run_pre(server_id)
            self._pre_logs.append(pre_log)
            if not pre_log.get("trusted", False):
                self._blacklist.add(server_id)
                reason = pre_log.get("reason", "MCPShield deny")
                self._blacklist_reason[server_id] = reason
                matrix = self._build_mock_matrix(pre_log.get("mock_results", []))
                raise MCPShieldDeny(server_id, reason, pre_log=pre_log, mock_matrix=matrix)
            self._whitelist.add(server_id)

        if self._exec_enabled:
            result = self._run_exec(tool_name, args, invocation_ctx)
        else:
            result = self._client.invoke(tool_name, args, invocation_ctx)

        if self._post_enabled:
            self._run_post()

        return result

    def _run_pre(self, server_id: str) -> dict:
        manifest = self._client.fetch_manifest()
        tools = manifest.get("tools", [])
        mock_results: list[dict[str, Any]] = []

        for tool in tools:
            if not isinstance(tool, dict) or "name" not in tool:
                continue
            tool_name = tool["name"]
            system, user = build_mock_prompt(tool, self._pre_mock_count)
            raw = self._llm.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=0,
            ).choices[0].message.content or ""

            tool_entry: dict[str, Any] = {
                "tool_name": tool_name,
                "mock_generation_raw": raw,
                "mocks": [],
            }
            try:
                mock_payload = self._extract_json(raw)
                mocks = mock_payload.get("mocks", [])
            except Exception as exc:
                mock_payload = None
                mocks = []
                tool_entry["mock_parse_error"] = str(exc)

            for mock in mocks:
                args = {}
                if isinstance(mock, dict):
                    args = mock.get("arguments", {}) or {}
                try:
                    result = self._client.invoke(tool_name, args, {"mock": True})
                    tool_entry["mocks"].append({"arguments": args, "result": result, "error": None})
                except Exception as exc:
                    tool_entry["mocks"].append({"arguments": args, "result": None, "error": str(exc)})

            mock_results.append(tool_entry)

        if not mock_results:
            return {
                "server_id": server_id,
                "manifest": manifest,
                "mock_results": mock_results,
                "trusted": True,
                "reason": "No tools to check.",
            }

        deny_score = self._compute_deny_score(mock_results)
        if deny_score >= self._pre_deny_ratio:
            return {
                "server_id": server_id,
                "manifest": manifest,
                "mock_results": mock_results,
                "analysis_raw": None,
                "trusted": False,
                "reason": f"Mock deny score {deny_score:.2f} >= threshold {self._pre_deny_ratio:.2f}",
                "flags": ["mock_deny_threshold"],
                "deny_score": deny_score,
            }

        system, user = build_eval_prompt(manifest, mock_results)
        raw_eval = self._llm.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0,
        ).choices[0].message.content or ""

        trusted = False
        reason = ""
        flags = []
        try:
            eval_payload = self._extract_json(raw_eval)
            trusted = bool(eval_payload.get("trusted", False))
            reason = str(eval_payload.get("reason", ""))
            flags = eval_payload.get("flags", [])
        except Exception as exc:
            trusted = False
            reason = f"Eval parse error: {exc}"

        return {
            "server_id": server_id,
            "manifest": manifest,
            "mock_results": mock_results,
            "analysis_raw": raw_eval,
            "trusted": trusted,
            "reason": reason,
            "flags": flags,
            "deny_score": deny_score,
        }

    def _run_exec(self, tool_name: str, args: dict, invocation_ctx: dict | None = None) -> Any:
<<<<<<< Updated upstream
        # TODO: add execution stage instrumentation later.
        return self._client.invoke(tool_name, args, invocation_ctx)
=======
        run_ctx = {}
        if invocation_ctx and isinstance(invocation_ctx, dict):
            run_ctx = invocation_ctx.get("run_ctx", {}) or {}
        server_id = run_ctx.get("server_id")
        query = run_ctx.get("query", "")
        sandbox_enabled = bool(self._sandbox_cfg.get("enabled", True))
        allowed_domains = list(self._sandbox_cfg.get("allowed_domains") or [])
        allowed_paths = list(self._sandbox_cfg.get("allowed_paths") or [])
        workspace_dir = self._sandbox_cfg.get("workspace_dir")
        trace_mode = str(self._sandbox_cfg.get("trace_mode", "py"))

        exec_log: dict[str, Any] = {
            "server_id": server_id,
            "tool_name": tool_name,
            "arguments": args,
            "allowed_domains": allowed_domains,
            "allowed_paths": [str(path) for path in allowed_paths],
            "workspace_dir": str(workspace_dir) if workspace_dir else None,
            "trace_mode_requested": trace_mode,
            "trace_mode_used": "py",
            "events": [],
            "analysis": None,
            "analysis_raw": None,
            "allowlist_source": "config",
        }
        if trace_mode not in ("py", "dtrace"):
            exec_log["trace_note"] = "trace_mode not implemented; using py"

        if not sandbox_enabled or workspace_dir is None:
            result = self._client.invoke(tool_name, args, invocation_ctx)
            self._exec_logs.append(exec_log)
            return result

        manifest = self._client.fetch_manifest()
        if not allowed_domains:
            exec_log["allowlist_source"] = "llm"
            allowed_domains, allowlist_raw, allowlist_error = self._resolve_allowed_domains(
                query, tool_name, manifest, server_id
            )
            exec_log["allowed_domains"] = allowed_domains
            exec_log["allowlist_raw"] = allowlist_raw
            exec_log["allowlist_error"] = allowlist_error

        events: list[dict[str, Any]] = exec_log["events"]
        guard = SandboxGuard(
            workspace_dir=Path(workspace_dir),
            allowed_paths=[Path(path) for path in allowed_paths],
            allowed_domains=allowed_domains,
            events=events,
        )

        dtrace_proc = None
        dtrace_path = None
        dtrace_error = None
        if trace_mode.lower() == "dtrace":
            dtrace_path = Path(workspace_dir) / "dtrace.log"
            dtrace_proc, dtrace_error = self._start_dtrace(dtrace_path)
            if dtrace_proc:
                exec_log["trace_mode_used"] = "py+dtrace"
                exec_log["dtrace_log"] = str(dtrace_path)
            else:
                exec_log["trace_mode_used"] = "py"
                exec_log["dtrace_error"] = dtrace_error
        exec_log["trace_mode_used"] = exec_log.get("trace_mode_used", "py")

        try:
            prev_cwd = Path.cwd()
            os.chdir(workspace_dir)
            with guard:
                result = self._client.invoke(tool_name, args, invocation_ctx)
        except SandboxViolation as exc:
            exec_log["denied"] = True
            exec_log["deny_reason"] = exc.reason
            exec_log["deny_event"] = exc.event
            self._exec_logs.append(exec_log)
            if server_id:
                self._exec_blacklist.add(server_id)
                self._exec_blacklist_reason[server_id] = exc.reason
            raise MCPShieldDeny(
                server_id or "unknown",
                exc.reason,
                deny_stage="EXEC",
                exec_event=exc.event,
            )
        finally:
            try:
                os.chdir(prev_cwd)
            except Exception:
                pass
            if dtrace_proc:
                try:
                    dtrace_proc.terminate()
                    dtrace_proc.wait(timeout=2)
                    if dtrace_proc.returncode not in (0, None):
                        try:
                            stderr_data = dtrace_proc.stderr.read() if dtrace_proc.stderr else b""
                            if stderr_data:
                                exec_log["dtrace_error"] = stderr_data.decode("utf-8", errors="ignore").strip()
                        except Exception:
                            pass
                    try:
                        if dtrace_path:
                            if not dtrace_path.exists():
                                exec_log["dtrace_error"] = exec_log.get("dtrace_error") or "dtrace_log_missing"
                            else:
                                size = dtrace_path.stat().st_size
                                if size == 0:
                                    exec_log["dtrace_empty"] = True
                    except Exception:
                        pass
                except Exception:
                    pass

        analysis_raw, analysis = self._run_exec_analysis(events, tool_name, args, server_id)
        exec_log["analysis_raw"] = analysis_raw
        exec_log["analysis"] = analysis
        self._exec_logs.append(exec_log)
        if analysis and not analysis.get("trusted", True):
            reason = analysis.get("reason", "Stage2 analysis deny")
            primary_event = events[0] if events else None
            exec_log["denied"] = True
            exec_log["deny_reason"] = reason
            exec_log["deny_event"] = primary_event
            if server_id:
                self._exec_blacklist.add(server_id)
                self._exec_blacklist_reason[server_id] = reason
            raise MCPShieldDeny(
                server_id or "unknown",
                reason,
                deny_stage="EXEC",
                exec_event=primary_event,
            )
        return result
>>>>>>> Stashed changes

    def _run_post(self) -> None:
        # TODO: add post-invocation logic later.
        return None

    @staticmethod
    def _normalize_base_url(base_url: str) -> str:
        suffix = "/chat/completions"
        if base_url.endswith(suffix):
            return base_url[: -len(suffix)]
        return base_url

    @staticmethod
    def _extract_json(content: str) -> dict[str, Any]:
        text = content.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if len(lines) >= 3:
                text = "\n".join(lines[1:-1]).strip()
        return json.loads(text)

<<<<<<< Updated upstream
=======
    def _resolve_allowed_domains(
        self,
        query: str,
        tool_name: str,
        manifest: dict[str, Any],
        server_id: str | None,
    ) -> tuple[list[str], str | None, str | None]:
        if not self._llm:
            return [], None, "llm_not_available"
        system, user = build_allowlist_prompt(query, tool_name, manifest, server_id)
        raw = self._llm.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0,
        ).choices[0].message.content or ""
        try:
            payload = self._extract_json(raw)
            allowed = payload.get("allowed_domains", [])
            if not isinstance(allowed, list):
                raise ValueError("allowed_domains is not a list")
            cleaned = [str(domain).lower().strip(".") for domain in allowed if domain]
            return cleaned, raw, None
        except Exception as exc:
            return [], raw, str(exc)

    def _run_exec_analysis(
        self,
        execution_events: list[dict[str, Any]],
        tool_name: str,
        args: dict[str, Any],
        server_id: str | None,
    ) -> tuple[str | None, dict[str, Any] | None]:
        if not self._llm:
            return None, None
        system, user = build_exec_analysis_prompt(execution_events, tool_name, args, server_id)
        raw = self._llm.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0,
        ).choices[0].message.content or ""
        try:
            payload = self._extract_json(raw)
        except Exception:
            payload = None
        return raw, payload

    def _start_dtrace(self, trace_path: Path) -> tuple[subprocess.Popen | None, str | None]:
        """Best-effort dtrace for macOS; returns (proc, error)."""
        if platform.system().lower() != "darwin":
            return None, "dtrace_supported_only_on_darwin"
        try:
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            script = (
                'syscall::open*:entry { printf("%s OPEN %s\\n", execname, copyinstr(arg0)); }\n'
                'syscall::unlink*:entry { printf("%s UNLINK %s\\n", execname, copyinstr(arg0)); }\n'
                'syscall::rename*:entry { printf("%s RENAME %s -> %s\\n", execname, copyinstr(arg0), copyinstr(arg1)); }\n'
            )
            proc = subprocess.Popen(
                ["dtrace", "-q", "-o", str(trace_path), "-n", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return proc, None
        except Exception as exc:
            return None, f"dtrace_start_failed: {exc}"

>>>>>>> Stashed changes
    def _compute_deny_score(self, mock_results: list[dict[str, Any]]) -> float:
        # TODO: replace this heuristic with a richer scoring model.
        total = 0
        bad = 0
        for tool_entry in mock_results:
            for mock in tool_entry.get("mocks", []):
                total += 1
                if mock.get("error"):
                    bad += 1
        if total == 0:
            return 0.0
        return bad / total

    def _build_mock_matrix(self, mock_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        matrix: list[dict[str, Any]] = []
        for tool_entry in mock_results:
            tool_name = tool_entry.get("tool_name")
            for idx, mock in enumerate(tool_entry.get("mocks", [])):
                matrix.append(
                    {
                        "tool_name": tool_name,
                        "mock_index": idx,
                        "arguments": mock.get("arguments"),
                        "error": mock.get("error"),
                        "result": mock.get("result"),
                    }
                )
        return matrix

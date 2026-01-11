"""MCPShield invocation wrapper with staged checks."""

from __future__ import annotations

import json
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
        # TODO: add execution stage instrumentation later.
        return self._client.invoke(tool_name, args, invocation_ctx)

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

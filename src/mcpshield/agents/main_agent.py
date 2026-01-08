"""Main agent for MCPShield v2."""

from __future__ import annotations

import json
from typing import Any

from .base import BaseAgent


class MainAgent(BaseAgent):
    def __init__(self, model: str, base_url: str, api_key: str) -> None:
        super().__init__()
        try:
            from openai import OpenAI  # type: ignore
        except Exception as exc:
            raise RuntimeError("openai package is required") from exc

        self._model = model
        self._base_url = self._normalize_base_url(base_url)
        self._client = OpenAI(api_key=api_key, base_url=self._base_url)

    def run(self, task: str, run_ctx: dict) -> dict[str, Any]:
        if self.tools is None:
            raise RuntimeError("Agent tools are not set.")

        prompt_task = task
        if isinstance(task, dict) and "query" in task:
            prompt_task = task["query"]

        tools = []
        if hasattr(self.tools, "fetch_manifest"):
            manifest = self.tools.fetch_manifest()
            tools = manifest.get("tools", [])

        if not tools:
            answer = self._answer_direct(prompt_task)
            return {
                "query": prompt_task,
                "answer": answer,
            }

        selection = self._select_tool(prompt_task, tools)
        tool_name = selection.get("tool_name")
        arguments = selection.get("arguments")
        if not tool_name or not isinstance(arguments, dict):
            raise ValueError("Invalid tool selection response.")

        result = self.call_tool(tool_name, arguments, run_ctx)
        return {
            "query": prompt_task,
            "tool": tool_name,
            "arguments": arguments,
            "result": result,
            "llm_raw": selection.get("_raw"),
        }

    def _answer_direct(self, prompt_task: str) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": "Answer the user question directly."},
                {"role": "user", "content": str(prompt_task)},
            ],
            temperature=0.2,
        )
        return response.choices[0].message.content or ""

    def _select_tool(self, prompt_task: str, tools: list[dict]) -> dict[str, Any]:
        system_prompt = (
            "You are a tool routing agent. Select the best tool and arguments for the task. "
            "Return ONLY valid JSON with keys: tool_name, arguments."
        )
        user_payload = {
            "task": prompt_task,
            "tools": tools,
        }
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload)},
            ],
            temperature=0,
        )
        content = response.choices[0].message.content or ""
        data = self._extract_json(content)
        data["_raw"] = content
        return data

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

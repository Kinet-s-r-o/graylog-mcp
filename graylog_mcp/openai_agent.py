from __future__ import annotations

import asyncio
import json
from openai import AsyncOpenAI
from .audit import AuditStore, stopwatch
from .security import agent_context


class OpenAIAgent:
    def __init__(self, settings, tools, audit: AuditStore | None = None, metrics=None):
        kwargs = {"api_key": settings.openai_api_key}
        if settings.openai_base_url:
            kwargs["base_url"] = settings.openai_base_url
        self.client = AsyncOpenAI(**kwargs)
        self.model = settings.openai_model
        self.tools = tools
        self.max_rounds = settings.openai_max_tool_rounds
        self.max_response_chars = getattr(settings, "openai_max_response_chars", 12_000)
        self.audit = audit
        self.metrics = metrics
        self.last_result: dict[str, object] | None = None

    async def ask(self, question: str, executor):
        result = await self.ask_result(question, executor)
        return str(result["answer"])

    async def ask_result(self, question: str, executor) -> dict[str, object]:
        started = stopwatch()
        agent_context_data = agent_context.get() or {}
        agent_id = agent_context_data.get("agent_id")
        client_ip = agent_context_data.get("client_ip")
        tool_calls: list[str] = []
        tool_errors = 0
        if self.metrics:
            self.metrics.inc("graylog_mcp_ai_requests_total")
        messages = [{"role": "system", "content": """You are a careful Graylog incident analyst.
Use aggregate or specialized analysis tools before requesting raw messages. Keep time ranges narrow unless the question requires a longer period. Run independent tool calls in parallel when useful. State the exact time range, filters, and tools used. Separate observed facts from hypotheses, mention when results are truncated, and never invent log data. If no data is found, say so explicitly. If a tool fails, explain the failure and do not blindly repeat the same call."""},
                    {"role": "user", "content": question}]
        for _ in range(self.max_rounds):
            response = await self.client.chat.completions.create(model=self.model, messages=messages, tools=self.tools)
            msg = response.choices[0].message
            messages.append(msg.model_dump(exclude_none=True))
            if not msg.tool_calls:
                answer = (msg.content or "No answer returned by OpenAI.")[:self.max_response_chars]
                result = {"answer": answer, "model": self.model, "rounds": _ + 1, "tool_calls": tool_calls, "tool_errors": tool_errors, "truncated": len(msg.content or "") > self.max_response_chars}
                self.last_result = result
                if self.metrics:
                    self.metrics.inc("graylog_mcp_ai_rounds_total", _ + 1)
                    self.metrics.inc("graylog_mcp_ai_tool_calls_total", len(tool_calls))
                    self.metrics.inc("graylog_mcp_ai_tool_errors_total", tool_errors)
                    self.metrics.inc("graylog_mcp_ai_latency_ms_total", int((stopwatch()-started) * 1000))
                if self.audit: await self.audit.record(source="openai", operation="ask_graylog", request={"question": question, "model": self.model}, response=result, duration_ms=(stopwatch()-started)*1000, agent_id=agent_id, client_ip=client_ip)
                return result
            def call_arguments(call):
                try:
                    return json.loads(call.function.arguments or "{}")
                except (TypeError, json.JSONDecodeError):
                    return None

            def call_key(call):
                args = call_arguments(call)
                return (call.function.name, json.dumps(args, sort_keys=True, separators=(",", ":")))

            async def run_call(call):
                nonlocal tool_errors
                tool_calls.append(call.function.name)
                try:
                    args = call_arguments(call)
                    if args is None:
                        raise ValueError("Tool arguments must be valid JSON")
                    result = await executor(call.function.name, args)
                except Exception as exc:
                    tool_errors += 1
                    result = {"error": str(exc)}
                return call, result

            unique_calls = {}
            for call in msg.tool_calls:
                unique_calls.setdefault(call_key(call), call)
            results = await asyncio.gather(*(run_call(call) for call in unique_calls.values()))
            result_by_key = {call_key(call): result for call, result in results}
            for call in msg.tool_calls:
                messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result_by_key[call_key(call)], ensure_ascii=False, default=str)})
        answer = "OpenAI orchestration reached the configured tool-call limit."
        result = {"answer": answer, "model": self.model, "rounds": self.max_rounds, "tool_calls": tool_calls, "tool_errors": tool_errors, "truncated": False}
        self.last_result = result
        if self.metrics:
            self.metrics.inc("graylog_mcp_ai_rounds_total", self.max_rounds)
            self.metrics.inc("graylog_mcp_ai_tool_calls_total", len(tool_calls))
            self.metrics.inc("graylog_mcp_ai_tool_errors_total", tool_errors)
            self.metrics.inc("graylog_mcp_ai_latency_ms_total", int((stopwatch()-started) * 1000))
        if self.audit: await self.audit.record(source="openai", operation="ask_graylog", request={"question": question, "model": self.model}, response=result, duration_ms=(stopwatch()-started)*1000, success=False, error=answer, agent_id=agent_id, client_ip=client_ip)
        return result

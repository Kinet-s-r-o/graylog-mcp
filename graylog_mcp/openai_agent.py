from __future__ import annotations

import json
from openai import AsyncOpenAI
from .audit import AuditStore, stopwatch


class OpenAIAgent:
    def __init__(self, settings, tools, audit: AuditStore | None = None):
        kwargs = {"api_key": settings.openai_api_key}
        if settings.openai_base_url:
            kwargs["base_url"] = settings.openai_base_url
        self.client = AsyncOpenAI(**kwargs)
        self.model = settings.openai_model
        self.tools = tools
        self.max_rounds = settings.openai_max_tool_rounds
        self.audit = audit

    async def ask(self, question: str, executor):
        started = stopwatch()
        messages = [{"role": "system", "content": "You are a Graylog analyst. Use the available tools, state the time range and filters used, and return concise findings. Never invent log data."},
                    {"role": "user", "content": question}]
        for _ in range(self.max_rounds):
            response = await self.client.chat.completions.create(model=self.model, messages=messages, tools=self.tools)
            msg = response.choices[0].message
            messages.append(msg.model_dump(exclude_none=True))
            if not msg.tool_calls:
                answer = msg.content or "No answer returned by OpenAI."
                if self.audit: await self.audit.record(source="openai", operation="ask_graylog", request={"question": question, "model": self.model}, response=answer, duration_ms=(stopwatch()-started)*1000)
                return answer
            for call in msg.tool_calls:
                try:
                    args = json.loads(call.function.arguments or "{}")
                    result = await executor(call.function.name, args)
                except Exception as exc:
                    result = {"error": str(exc)}
                messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result, ensure_ascii=False, default=str)})
        answer = "OpenAI orchestration reached the configured tool-call limit."
        if self.audit: await self.audit.record(source="openai", operation="ask_graylog", request={"question": question, "model": self.model}, response=answer, duration_ms=(stopwatch()-started)*1000, success=False, error=answer)
        return answer

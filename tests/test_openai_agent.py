import asyncio
import time
from types import SimpleNamespace

from graylog_mcp.openai_agent import OpenAIAgent


class Settings:
    openai_api_key = "test-key"
    openai_base_url = None
    openai_model = "test-model"
    openai_max_tool_rounds = 3


class Message:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []

    def model_dump(self, exclude_none=True):
        return {"role": "assistant", "content": self.content, "tool_calls": self.tool_calls}


class FakeClient:
    def __init__(self):
        self.calls = 0

    class Chat:
        pass

    async def create(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            calls = [
                SimpleNamespace(id="1", function=SimpleNamespace(name="aggregate", arguments='{"query":"level:3"}')),
                SimpleNamespace(id="2", function=SimpleNamespace(name="aggregate", arguments='{"query":"level:3"}')),
                SimpleNamespace(id="3", function=SimpleNamespace(name="search_messages", arguments='{"query":"level:3"}')),
            ]
            return SimpleNamespace(choices=[SimpleNamespace(message=Message(tool_calls=calls))])
        return SimpleNamespace(choices=[SimpleNamespace(message=Message(content="done"))])


def test_openai_agent_deduplicates_and_runs_independent_calls_in_parallel():
    async def scenario():
        agent = OpenAIAgent(Settings(), [], None)
        fake = FakeClient()
        fake.chat = SimpleNamespace(completions=SimpleNamespace(create=fake.create))
        agent.client = fake
        seen = []

        async def executor(name, args):
            started = time.perf_counter()
            await asyncio.sleep(0.05)
            seen.append((name, args, time.perf_counter() - started))
            return {"ok": True}

        started = time.perf_counter()
        answer = await agent.ask("What failed?", executor)
        elapsed = time.perf_counter() - started
        assert answer == "done"
        assert len(seen) == 2
        assert elapsed < 0.09
        assert fake.calls == 2
        assert agent.last_result["tool_calls"] == ["aggregate", "search_messages"]

    asyncio.run(scenario())

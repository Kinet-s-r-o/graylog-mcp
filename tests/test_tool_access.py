import asyncio

import pytest

from graylog_mcp.security import agent_context
from graylog_mcp.tool_access import ToolAccessDenied, filter_tool_schemas, require_tool_access


def test_tool_access_defaults_to_all_without_agent_context():
    require_tool_access("aggregate")


def test_tool_access_denies_unlisted_tool():
    token = agent_context.set({"allowed_tools": ["aggregate"]})
    try:
        require_tool_access("aggregate")
        with pytest.raises(ToolAccessDenied):
            require_tool_access("search_messages")
    finally:
        agent_context.reset(token)


def test_tool_schema_filtering_uses_agent_allow_list():
    schemas = [
        {"function": {"name": "aggregate"}},
        {"function": {"name": "search_messages"}},
    ]
    token = agent_context.set({"allowed_tools": ["aggregate"]})
    try:
        assert filter_tool_schemas(schemas) == [schemas[0]]
    finally:
        agent_context.reset(token)


def test_agent_store_round_trips_allowed_tools(tmp_path):
    from graylog_mcp.audit import AuditStore

    async def scenario():
        store = AuditStore(tmp_path / "acl.db", 30, 1000, 10000)
        await store.open()
        try:
            server = await store.add_server("prod", "https://graylog.example.com", "token")
            created = await store.add_agent("restricted", server["id"], allowed_tools=["aggregate"])
            context = await store.authenticate_agent(created["api_key"])
            assert context["allowed_tools"] == ["aggregate"]
            assert (await store.list_agents())[0]["allowed_tools"] == ["aggregate"]
        finally:
            await store.close()

    asyncio.run(scenario())

import asyncio

from graylog_mcp.domain.models import QueryDefinition
from graylog_mcp.services.graylog_service import GraylogClientRegistry
from graylog_mcp.services.query_executors import QueryExecutorRegistry


class Settings:
    normalized_graylog_url = "https://graylog.example"
    graylog_api_token = "fallback"
    graylog_verify_tls = True
    graylog_timeout_seconds = 30
    graylog_max_limit = 1000
    graylog_default_limit = 100


def test_query_definition_is_versioned_and_accepts_legacy_storage():
    definition = QueryDefinition.from_storage(
        "errors",
        {"type": "messages", "query": "level:3", "minutes": 15},
    )
    assert definition.schema_version == 1
    assert definition.to_storage()["schema_version"] == 1


def test_executor_registry_is_additive():
    registry = QueryExecutorRegistry()
    assert set(registry.types()) == {"messages", "aggregate"}

    class FutureExecutor:
        query_type = "future"

    registry.register(FutureExecutor())
    assert registry.get("future").query_type == "future"


def test_client_registry_replaces_client_when_connection_changes():
    async def scenario():
        server = {
            "url": "https://graylog.example",
            "api_token": "token-a",
            "verify_tls": True,
            "timeout_seconds": 30,
        }

        class Repository:
            async def get_server(self, _server_id):
                return server

        registry = GraylogClientRegistry(Settings(), Repository())
        first = await registry.get(1)
        assert await registry.get(1) is first
        server["api_token"] = "token-b"
        second = await registry.get(1)
        assert second is not first
        assert 1 in registry.clients
        await registry.close()

    asyncio.run(scenario())

import asyncio

from graylog_mcp.graylog import GraylogClient


class DummySettings:
    normalized_graylog_url = "https://graylog.example.com"
    graylog_api_token = "token"
    graylog_verify_tls = True
    graylog_timeout_seconds = 5
    graylog_max_limit = 1000


def test_aggregate_does_not_mutate_caller_groupings():
    async def scenario():
        client = GraylogClient(DummySettings())
        captured = {}

        async def fake_request(method, path, *, params=None, json=None):
            captured["json"] = json
            return {"ok": True}

        client.request = fake_request
        groupings = [{"field": "service"}]
        try:
            await client.aggregate("*", group_by=groupings, interval="5m")
            assert groupings == [{"field": "service"}]
            assert captured["json"]["group_by"][-1] == {"field": "timestamp", "timeunit": "5m"}
        finally:
            await client.close()

    asyncio.run(scenario())

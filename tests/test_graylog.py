import asyncio

from graylog_mcp.graylog import GraylogClient, normalize_error_message, normalize_messages


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


def test_normalized_messages_are_compact_and_mark_truncation():
    result = normalize_messages(
        {"total_messages": 50, "messages": [{"message": {"message": "failed", "level": 3}}]},
        "level:3", 15, 50,
    )
    assert result["result_count"] == 50
    assert result["truncated"] is True
    assert result["items"] == [{"message": "failed", "level": 3}]


def test_error_message_normalization_removes_variable_parts():
    assert normalize_error_message("Request 123 for 550e8400-e29b-41d4-a716-446655440000 failed") == (
        "Request <N> for <UUID> failed"
    )


def test_error_patterns_and_window_comparison_are_structured():
    async def scenario():
        client = GraylogClient(DummySettings())

        async def fake_request(method, path, *, params=None, json=None, query_rule=None):
            if path.endswith("messages"):
                return {"messages": [
                    {"message": {"timestamp": "2026-01-01T00:00:00Z", "message": "failed request 123", "service": "api"}},
                    {"message": {"timestamp": "2026-01-01T00:01:00Z", "message": "failed request 456", "service": "api"}},
                ]}
            return {"datarows": [["api", 2]], "schema": [{"name": "service"}, {"name": "count"}]}

        client.request = fake_request
        try:
            patterns = await client.search_error_patterns("level:3", limit=10)
            assert patterns["patterns"][0]["count"] == 2
            assert patterns["patterns"][0]["services"] == ["api"]
            comparison = await client.compare_time_windows("level:3", minutes=15)
            assert comparison["current"]["groups"] == [{"service": "api", "count": 2}]
            assert comparison["previous"]["groups"] == [{"service": "api", "count": 2}]
        finally:
            await client.close()

    asyncio.run(scenario())

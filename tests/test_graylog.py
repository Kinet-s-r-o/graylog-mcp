import asyncio
import httpx

from graylog_mcp.graylog import GraylogClient, normalize_error_message, normalize_messages
from graylog_mcp.observability import MetricsRegistry


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


def test_graylog_retries_transient_http_errors_and_records_metrics():
    async def scenario():
        settings = type("Settings", (), {
            "normalized_graylog_url": "https://graylog.example", "graylog_api_token": "token",
            "graylog_verify_tls": True, "graylog_timeout_seconds": 5, "graylog_retry_attempts": 1,
            "graylog_retry_backoff_seconds": 0, "graylog_circuit_failure_threshold": 5,
            "graylog_circuit_recovery_seconds": 30,
        })()
        metrics = MetricsRegistry()
        client = GraylogClient(settings, metrics=metrics)
        attempts = 0

        async def handler(request):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(503, request=request)
            return httpx.Response(200, json={"ok": True}, request=request)

        await client.client.aclose()
        client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://graylog.example")
        try:
            assert await client.request("GET", "/api/cluster") == {"ok": True}
            rendered = metrics.render()
            assert "graylog_mcp_graylog_retries_total 1" in rendered
            assert "graylog_mcp_graylog_request_attempts_total 2" in rendered
        finally:
            await client.close()

    asyncio.run(scenario())


def test_graylog_circuit_breaker_short_circuits_repeated_outages():
    async def scenario():
        settings = type("Settings", (), {
            "normalized_graylog_url": "https://graylog.example", "graylog_api_token": "token",
            "graylog_verify_tls": True, "graylog_timeout_seconds": 5, "graylog_retry_attempts": 0,
            "graylog_retry_backoff_seconds": 0, "graylog_circuit_failure_threshold": 1,
            "graylog_circuit_recovery_seconds": 30,
        })()
        client = GraylogClient(settings)
        attempts = 0

        async def handler(request):
            nonlocal attempts
            attempts += 1
            raise httpx.ConnectError("offline", request=request)

        await client.client.aclose()
        client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://graylog.example")
        try:
            for expected in ("graylog_request_failed", "graylog_circuit_open"):
                try:
                    await client.request("GET", "/api/cluster")
                except Exception as exc:
                    assert exc.code == expected
            assert attempts == 1
        finally:
            await client.close()

    asyncio.run(scenario())

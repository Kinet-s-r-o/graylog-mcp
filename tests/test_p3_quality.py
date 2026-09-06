from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from graylog_mcp.app import create_app
from graylog_mcp.graylog import GraylogClient
from graylog_mcp.observability import MetricsRegistry
from graylog_mcp.settings import Settings


ROOT = Path(__file__).resolve().parents[1]


def test_readiness_and_metrics_are_operational(tmp_path):
    settings = Settings(
        ui_password="test-password",
        audit_db_path=tmp_path / "p3.db",
        query_catalog_path=ROOT / "queries.yaml",
    )
    app = create_app(settings)
    with TestClient(app, base_url=f"http://testserver:{settings.mcp_port}") as client:
        assert client.get("/health").json()["status"] == "ok"
        assert client.get("/ready").json()["status"] == "ready"
        response = client.get("/metrics")
        assert response.status_code == 200
        assert "graylog_mcp_active_sessions" in response.text


def test_graylog_contract_records_request_and_error_metrics():
    async def scenario():
        metrics = MetricsRegistry()
        client = GraylogClient(
            type("Settings", (), {
                "normalized_graylog_url": "https://graylog.example",
                "graylog_api_token": "token",
                "graylog_verify_tls": True,
                "graylog_timeout_seconds": 5,
            })(),
            metrics=metrics,
        )

        async def handler(request):
            return httpx.Response(200, json={"messages": []}, request=request)

        await client.client.aclose()
        client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://graylog.example")
        assert await client.request("GET", "/api/cluster") == {"messages": []}
        assert "graylog_mcp_graylog_requests_total 1" in metrics.render()
        await client.close()

    import asyncio

    asyncio.run(scenario())

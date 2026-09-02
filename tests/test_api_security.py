import importlib
import re
import sys
from functools import partial
from pathlib import Path

from fastapi.testclient import TestClient


def test_authorization_csrf_and_agent_scoped_audit(monkeypatch, tmp_path):
    project_queries = Path(__file__).resolve().parents[1] / "queries.yaml"
    monkeypatch.setenv("UI_USERNAME", "admin")
    monkeypatch.setenv("UI_PASSWORD", "a-strong-test-password")
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "api.db"))
    monkeypatch.setenv("QUERY_CATALOG_PATH", str(project_queries))
    monkeypatch.setenv("SECRET_ENCRYPTION_KEY", "api-test-master-key-with-32-characters")
    sys.modules.pop("graylog_mcp.server", None)
    server = importlib.import_module("graylog_mcp.server")
    mcp_url = lambda path: f"http://testserver:{server.settings.mcp_port}{path}"

    with TestClient(
        server.api,
        base_url=f"http://testserver:{server.settings.webui_port}",
    ) as client:
        assert client.get("/health").status_code == 200
        assert client.get(mcp_url("/health")).status_code == 200
        assert client.get(mcp_url("/"), follow_redirects=False).status_code == 404
        assert client.get(mcp_url("/login"), follow_redirects=False).status_code == 404
        assert client.get("/api/v1/queries").status_code == 404
        assert client.post("/mcp").status_code == 404
        unauthenticated_agent_calls = [
            client.post(mcp_url("/api/v1/search/messages"), json={"query": "*"}),
            client.post(mcp_url("/api/v1/search/aggregate"), json={"query": "*"}),
            client.get(mcp_url("/api/v1/streams")),
            client.get(mcp_url("/api/v1/queries")),
            client.post(mcp_url("/api/v1/queries/run"), json={"name": "errors_by_service"}),
            client.get(mcp_url("/api/v1/audit")),
            client.post(mcp_url("/mcp")),
        ]
        assert {response.status_code for response in unauthenticated_agent_calls} == {401}
        assert client.get("/").history[0].status_code == 303
        assert client.get("/ui/help").history[0].status_code == 303
        unauthenticated_admin_calls = [
            client.get("/ui/api/servers"),
            client.get("/ui/api/agents"),
            client.get("/ui/api/queries"),
            client.get("/ui/api/audit"),
            client.get("/ui/api/streams"),
            client.post("/ui/api/query"),
            client.post("/ui/api/saved"),
            client.post("/ui/api/servers"),
            client.put("/ui/api/servers"),
            client.delete("/ui/api/servers"),
            client.post("/ui/api/servers/test"),
            client.post("/ui/api/agents"),
            client.put("/ui/api/agents"),
            client.delete("/ui/api/agents"),
            client.post("/ui/api/queries"),
            client.delete("/ui/api/queries"),
        ]
        assert {response.status_code for response in unauthenticated_admin_calls} == {401}

        login = client.post(
            "/login",
            data={"username": "admin", "password": "a-strong-test-password"},
            follow_redirects=False,
        )
        assert login.status_code == 303
        assert "httponly" in login.headers["set-cookie"].lower()
        assert "samesite=strict" in login.headers["set-cookie"].lower()

        home = client.get("/")
        csrf = re.search(r'<meta name="csrf-token" content="([^"]+)">', home.text).group(1)
        admin_calls_without_csrf = [
            client.post("/ui/api/query"),
            client.post("/ui/api/saved"),
            client.post("/ui/api/servers"),
            client.put("/ui/api/servers"),
            client.delete("/ui/api/servers"),
            client.post("/ui/api/servers/test"),
            client.post("/ui/api/agents"),
            client.put("/ui/api/agents"),
            client.delete("/ui/api/agents"),
            client.post("/ui/api/queries"),
            client.delete("/ui/api/queries"),
        ]
        assert {response.status_code for response in admin_calls_without_csrf} == {403}
        server_payload = {
            "name": "production",
            "url": "https://graylog.example.com",
            "api_token": "graylog-token",
            "verify_tls": True,
            "timeout_seconds": 30,
        }
        assert client.post("/ui/api/servers", json=server_payload).status_code == 403
        created_server = client.post(
            "/ui/api/servers", json=server_payload, headers={"X-CSRF-Token": csrf}
        )
        assert created_server.status_code == 201

        created_agent = client.post(
            "/ui/api/agents",
            json={"name": "agent-one", "graylog_server_id": created_server.json()["id"]},
            headers={"X-CSRF-Token": csrf},
        )
        assert created_agent.status_code == 201
        api_key = created_agent.json()["api_key"]
        assert len(api_key) >= 24
        bearer = {"Authorization": f"Bearer {api_key}"}
        assert client.get(mcp_url("/api/v1/queries"), headers=bearer).status_code == 200

        restricted_agent = client.post(
            "/ui/api/agents",
            json={
                "name": "restricted-agent",
                "graylog_server_id": created_server.json()["id"],
                "allowed_ips": ["203.0.113.0/24"],
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert restricted_agent.status_code == 201
        restricted_bearer = {"Authorization": f"Bearer {restricted_agent.json()['api_key']}"}
        assert client.get(mcp_url("/api/v1/queries"), headers=restricted_bearer).status_code == 403

        agent = client.portal.call(server.audit.authenticate_agent, api_key)
        client.portal.call(partial(server.audit.record, source="mcp", operation="owned", agent_id=agent["agent_id"]))
        client.portal.call(partial(server.audit.record, source="mcp", operation="other", agent_id=agent["agent_id"] + 100))
        scoped = client.get(mcp_url("/api/v1/audit"), headers=bearer)
        assert scoped.status_code == 200
        assert [item["operation"] for item in scoped.json()["items"]] == ["owned"]

        assert client.get("/logout").status_code in {404, 405}
        assert client.post("/logout").status_code == 403
        assert client.post("/logout", headers={"X-CSRF-Token": csrf}).status_code == 200

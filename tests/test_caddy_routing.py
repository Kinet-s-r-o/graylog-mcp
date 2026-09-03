from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_mcp_http_is_a_caddy_listener_and_backend_ports_are_internal():
    caddyfile = (ROOT / "caddy" / "Caddyfile").read_text(encoding="utf-8")
    assert "http://:{$CADDY_MCP_HTTP_PORT}" in caddyfile
    assert "path {$MCP_PATH}* /api/v1* /docs* /openapi.json /redoc*" in caddyfile
    assert caddyfile.count("reverse_proxy graylog-mcp:{$MCP_PORT}") >= 4

    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    assert "ports" not in compose["services"]["graylog-mcp"]
    assert "${CADDY_MCP_HTTP_PORT:-8081}" in (ROOT / "docker-compose.yml").read_text(
        encoding="utf-8"
    )


def test_http_mcp_defaults_are_documented():
    for filename in (".env.example", "example.env"):
        text = (ROOT / filename).read_text(encoding="utf-8")
        assert "CADDY_MCP_HTTP_BIND=127.0.0.1" in text
        assert "CADDY_MCP_HTTP_PORT=8081" in text
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "http://localhost:8081/mcp" in readme
    assert "Natívny `MCP_PORT=8000` je interný Compose port" in readme
    assert "http://localhost:8000/mcp" not in readme


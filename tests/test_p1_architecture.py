import re
from pathlib import Path

from fastapi.testclient import TestClient

from graylog_mcp.app import create_app
from graylog_mcp.settings import Settings


ROOT = Path(__file__).resolve().parents[1]
WEBUI = ROOT / "graylog_mcp" / "webui"


def test_server_is_compatibility_only_and_webui_is_static_and_modular():
    server_source = (ROOT / "graylog_mcp" / "server.py").read_text(encoding="utf-8")
    assert len(server_source.splitlines()) < 120
    assert "UI_HTML" not in server_source
    assert "<html" not in server_source.lower()

    index = (WEBUI / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"\son[a-z]+=", index, flags=re.IGNORECASE)
    assert '<script type="module" src="/ui/assets/app.js"></script>' in index
    assert '/ui/assets/app.css' in index

    modules = {path.name for path in WEBUI.glob("*.js")}
    assert {
        "api.js",
        "app.js",
        "filters.js",
        "modals.js",
        "navigation.js",
        "notifications.js",
        "state.js",
        "tables.js",
    } <= modules
    functions = []
    for path in WEBUI.glob("*.js"):
        functions.extend(re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)", path.read_text(encoding="utf-8")))
    assert len(functions) == len(set(functions))
    assert "document.addEventListener(\"click\"" in (WEBUI / "app.js").read_text(encoding="utf-8")


def test_static_assets_request_ids_and_strict_csp(tmp_path):
    settings = Settings(
        ui_password="test-password",
        audit_db_path=tmp_path / "p1.db",
        query_catalog_path=ROOT / "queries.yaml",
    )
    app = create_app(settings)
    with TestClient(app, base_url=f"http://testserver:{settings.webui_port}") as client:
        response = client.get("/health", headers={"X-Request-ID": "p1-browser-check"})
        assert response.headers["X-Request-ID"] == "p1-browser-check"
        assert "'unsafe-inline'" not in response.headers["Content-Security-Policy"]

        assert client.get("/ui/assets/app.css").status_code == 200
        app_js = client.get("/ui/assets/app.js")
        assert app_js.status_code == 200
        assert app_js.headers["content-type"].startswith("text/javascript")

        login = client.post(
            "/login",
            data={"username": "admin", "password": "test-password"},
            follow_redirects=False,
        )
        assert login.status_code == 303
        home = client.get("/")
        assert "__CSRF_TOKEN__" not in home.text
        assert re.search(r'<meta name="csrf-token" content="[^"]+">', home.text)


def test_database_uses_versioned_migrations(tmp_path):
    settings = Settings(
        ui_password="test-password",
        audit_db_path=tmp_path / "migrations.db",
        query_catalog_path=ROOT / "queries.yaml",
    )
    app = create_app(settings)
    with TestClient(app):
        assert app.state.runtime["audit"].db is not None
    import sqlite3

    with sqlite3.connect(settings.audit_db_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] >= 2
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] >= 2

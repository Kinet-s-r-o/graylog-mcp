from graylog_mcp.catalog import QueryCatalog

def test_catalog_renders_parameters(tmp_path):
    path = tmp_path / "queries.yaml"
    path.write_text("queries:\n  q:\n    type: messages\n    query: 'service:${service}'\n    defaults: {service: api}\n", encoding="utf-8")
    catalog = QueryCatalog(path)
    assert catalog.render("q", {})["query"] == "service:api"
    assert catalog.render("q", {"service": "web"})["query"] == "service:web"

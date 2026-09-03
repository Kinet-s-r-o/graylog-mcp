import pytest
from pydantic import ValidationError

from graylog_mcp.schemas import AgentCreate, GraylogServerCreate, QueryDefinitionInput, SearchRequest


def test_graylog_server_rejects_unsafe_or_unsupported_urls():
    with pytest.raises(ValidationError):
        GraylogServerCreate(name="prod", url="file:///etc/passwd", api_token="token")
    with pytest.raises(ValidationError):
        GraylogServerCreate(name="prod", url="https://user:pass@example.com", api_token="token")


def test_agent_rejects_weak_user_supplied_key():
    with pytest.raises(ValidationError):
        AgentCreate(name="agent", graylog_server_id=1, api_key="too-short")


def test_request_models_reject_unknown_or_oversized_fields():
    with pytest.raises(ValidationError):
        GraylogServerCreate(
            name="prod",
            url="https://graylog.example.com",
            api_token="token",
            unexpected=True,
        )
    with pytest.raises(ValidationError):
        AgentCreate(name="agent", graylog_server_id=1, allowed_ips=["10.0.0.0/8"] * 513)
    with pytest.raises(ValidationError):
        SearchRequest(query="*", fields=["bad\nfield"])


def test_query_rule_validates_interval_grouping_and_metrics():
    valid = QueryDefinitionInput(
        name="errors",
        query="level:3",
        type="aggregate",
        interval="5m",
        group_by=[{"field": "service"}],
        metrics=[{"function": "count"}],
        fields=["timestamp", "message"],
    )
    assert valid.interval == "5m"

    with pytest.raises(ValidationError):
        QueryDefinitionInput(name="bad", query="*", interval="five minutes")
    with pytest.raises(ValidationError):
        QueryDefinitionInput(name="bad", query="*", group_by=[{}])
    with pytest.raises(ValidationError):
        QueryDefinitionInput(name="bad", query="*", metrics=[{"function": "average"}])


def test_query_rule_allows_empty_limit_for_aggregations():
    rule = QueryDefinitionInput(name="total", type="aggregate", query="*", limit=None)
    assert rule.limit is None

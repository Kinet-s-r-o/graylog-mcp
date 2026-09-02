from __future__ import annotations

import re
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


NAME_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]+$")
INTERVAL_PATTERN = re.compile(r"^[1-9]\d*(?:ms|s|m|h|d|w)$")
METRIC_FUNCTIONS = {
    "average", "count", "latest", "max", "min", "percentile",
    "stdDev", "sum", "sumOfSquares", "variance",
}


def _clean_name(value: str) -> str:
    value = value.strip()
    if not 1 <= len(value) <= 128 or not NAME_PATTERN.fullmatch(value):
        raise ValueError("Name must contain 1 to 128 printable characters")
    return value


def _clean_graylog_url(value: str) -> str:
    value = value.strip().rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Graylog URL must be an absolute http or https URL")
    if parsed.username or parsed.password:
        raise ValueError("Graylog URL must not contain embedded credentials")
    if parsed.fragment:
        raise ValueError("Graylog URL must not contain a fragment")
    return value


def _validate_groupings(value: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for item in value:
        field = item.get("field")
        if (
            not isinstance(field, str)
            or not field.strip()
            or len(field) > 255
            or not NAME_PATTERN.fullmatch(field)
        ):
            raise ValueError("Every grouping must contain a valid field")
    return value


def _validate_metrics(value: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    if value is None:
        return value
    for item in value:
        function = item.get("function")
        if function not in METRIC_FUNCTIONS:
            raise ValueError(f"Unsupported metric function: {function}")
        field = item.get("field")
        if function != "count" and (
            not isinstance(field, str)
            or not field.strip()
            or len(field) > 255
            or not NAME_PATTERN.fullmatch(field)
        ):
            raise ValueError(f"Metric {function} requires a field")
        metric_id = item.get("id")
        if metric_id is not None and (
            not isinstance(metric_id, str)
            or not metric_id.strip()
            or len(metric_id) > 255
            or not NAME_PATTERN.fullmatch(metric_id)
        ):
            raise ValueError("Metric id must contain 1 to 255 printable characters")
    return value


def _validate_fields(value: list[str] | None) -> list[str] | None:
    if value is not None and any(
        not field.strip() or len(field) > 255 or not NAME_PATTERN.fullmatch(field)
        for field in value
    ):
        raise ValueError("Fields must contain 1 to 255 printable characters")
    return value


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SearchRequest(StrictRequest):
    query: str = Field(min_length=1, max_length=20_000)
    minutes: int = Field(15, ge=1, le=525_600)
    limit: int | None = Field(None, ge=1, le=10_000)
    fields: list[str] | None = Field(None, max_length=200)

    @field_validator("fields")
    @classmethod
    def validate_fields(cls, value: list[str] | None) -> list[str] | None:
        return _validate_fields(value)


class AggregateRequest(StrictRequest):
    query: str = Field(min_length=1, max_length=20_000)
    minutes: int = Field(60, ge=1, le=525_600)
    group_by: list[dict[str, Any]] = Field(default_factory=list, max_length=50)
    metrics: list[dict[str, Any]] | None = Field(None, max_length=50)
    interval: str | None = Field(None, max_length=32)

    _groupings = field_validator("group_by")(_validate_groupings)
    _metrics = field_validator("metrics")(_validate_metrics)

    @field_validator("interval")
    @classmethod
    def validate_interval(cls, value: str | None) -> str | None:
        if value in (None, ""):
            return None
        if not INTERVAL_PATTERN.fullmatch(value):
            raise ValueError("Interval must use a compact value such as 30s, 5m, or 1h")
        return value


class SavedQueryRequest(StrictRequest):
    name: str
    parameters: dict[str, Any] = Field(default_factory=dict)

    _name = field_validator("name")(_clean_name)


class GraylogServerCreate(StrictRequest):
    name: str
    url: str
    api_token: str = Field(min_length=1, max_length=4096)
    verify_tls: bool = True
    timeout_seconds: float = Field(30, gt=0, le=600)

    _name = field_validator("name")(_clean_name)
    _url = field_validator("url")(_clean_graylog_url)


class GraylogServerUpdate(GraylogServerCreate):
    server_id: int = Field(gt=0)
    api_token: str | None = Field(None, max_length=4096)

    @field_validator("api_token", mode="before")
    @classmethod
    def empty_token_keeps_existing(cls, value: Any) -> Any:
        return None if value == "" else value


class GraylogServerTest(BaseModel):
    server_id: int | None = Field(None, gt=0)
    name: str | None = None
    url: str | None = None
    api_token: str | None = Field(None, max_length=4096)
    verify_tls: bool | None = None
    timeout_seconds: float | None = Field(None, gt=0, le=600)

    @field_validator("name")
    @classmethod
    def validate_optional_name(cls, value: str | None) -> str | None:
        return _clean_name(value) if value is not None else None

    @field_validator("url")
    @classmethod
    def validate_optional_url(cls, value: str | None) -> str | None:
        return _clean_graylog_url(value) if value else None

    @field_validator("api_token", mode="before")
    @classmethod
    def empty_test_token(cls, value: Any) -> Any:
        return None if value == "" else value

    @model_validator(mode="after")
    def require_target(self):
        if self.server_id is None and (not self.url or not self.api_token):
            raise ValueError("URL and API token are required for a new Graylog server")
        return self


class AgentCreate(StrictRequest):
    name: str
    graylog_server_id: int = Field(gt=0)
    api_key: str | None = Field(None, min_length=24, max_length=4096)
    allowed_ips: str | list[str] | None = None

    _name = field_validator("name")(_clean_name)

    @field_validator("api_key", mode="before")
    @classmethod
    def empty_key_generates(cls, value: Any) -> Any:
        return None if value == "" else value

    @field_validator("allowed_ips")
    @classmethod
    def validate_allowed_ips(cls, value: str | list[str] | None) -> str | list[str] | None:
        if isinstance(value, str) and len(value) > 20_000:
            raise ValueError("Allowed IP list is too long")
        if isinstance(value, list) and (
            len(value) > 512 or any(len(item) > 128 for item in value)
        ):
            raise ValueError("Allowed IP list may contain at most 512 CIDR entries")
        return value


class AgentUpdate(AgentCreate):
    agent_id: int = Field(gt=0)
    active: bool = True


class QueryDefinitionInput(StrictRequest):
    name: str
    description: str = Field("", max_length=1000)
    type: Literal["messages", "aggregate"] = "messages"
    query: str = Field(min_length=1, max_length=20_000)
    minutes: int = Field(60, ge=1, le=525_600)
    limit: int = Field(100, ge=1, le=10_000)
    interval: str | None = Field(None, max_length=32)
    group_by: list[dict[str, Any]] = Field(default_factory=list, max_length=50)
    metrics: list[dict[str, Any]] = Field(default_factory=lambda: [{"function": "count"}], max_length=50)
    defaults: dict[str, Any] = Field(default_factory=dict)
    instructions: str = Field("", max_length=10_000)
    fields: list[str] | None = Field(None, max_length=200)

    _name = field_validator("name")(_clean_name)
    _groupings = field_validator("group_by")(_validate_groupings)
    _metrics = field_validator("metrics")(_validate_metrics)
    _fields = field_validator("fields")(_validate_fields)

    @field_validator("interval")
    @classmethod
    def validate_interval(cls, value: str | None) -> str | None:
        if value in (None, ""):
            return None
        if not INTERVAL_PATTERN.fullmatch(value):
            raise ValueError("Interval must use a compact value such as 30s, 5m, or 1h")
        return value


class UIQueryRequest(BaseModel):
    server_id: int = Field(gt=0)
    query: str = Field(min_length=1, max_length=20_000)
    minutes: int = Field(60, ge=1, le=525_600)
    limit: int = Field(100, ge=1, le=10_000)
    group_by: list[dict[str, Any]] | None = Field(None, max_length=50)
    metrics: list[dict[str, Any]] | None = Field(None, max_length=50)
    interval: str | None = Field(None, max_length=32)

    _groupings = field_validator("group_by")(
        lambda value: _validate_groupings(value) if value is not None else value
    )
    _metrics = field_validator("metrics")(_validate_metrics)

    @field_validator("interval")
    @classmethod
    def validate_interval(cls, value: str | None) -> str | None:
        if value in (None, ""):
            return None
        if not INTERVAL_PATTERN.fullmatch(value):
            raise ValueError("Interval must use a compact value such as 30s, 5m, or 1h")
        return value


class UISavedQueryRequest(SavedQueryRequest):
    server_id: int = Field(gt=0)

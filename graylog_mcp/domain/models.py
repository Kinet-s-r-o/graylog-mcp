from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .validation import (
    INTERVAL_PATTERN,
    clean_name,
    validate_fields,
    validate_groupings,
    validate_metrics,
)


QUERY_SCHEMA_VERSION: Literal[1] = 1


class QueryDefinition(BaseModel):
    """Versioned, storage-independent representation of a managed query."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = QUERY_SCHEMA_VERSION
    name: str
    description: str = Field("", max_length=1000)
    type: Literal["messages", "aggregate"] = "messages"
    query: str = Field(min_length=1, max_length=20_000)
    minutes: int = Field(60, ge=1, le=525_600)
    limit: int | None = Field(None, ge=1, le=10_000)
    interval: str | None = Field(None, max_length=32)
    group_by: list[dict[str, Any]] = Field(default_factory=list, max_length=50)
    metrics: list[dict[str, Any]] = Field(
        default_factory=lambda: [{"function": "count"}], max_length=50
    )
    defaults: dict[str, Any] = Field(default_factory=dict)
    instructions: str = Field("", max_length=10_000)
    fields: list[str] | None = Field(None, max_length=200)

    _name = field_validator("name")(clean_name)
    _groupings = field_validator("group_by")(validate_groupings)
    _metrics = field_validator("metrics")(validate_metrics)
    _fields = field_validator("fields")(validate_fields)

    @field_validator("interval")
    @classmethod
    def validate_interval(cls, value: str | None) -> str | None:
        if value in (None, ""):
            return None
        assert value is not None
        if not INTERVAL_PATTERN.fullmatch(value):
            raise ValueError("Interval must use a compact value such as 30s, 5m, or 1h")
        return value

    @classmethod
    def from_storage(cls, name: str, value: dict[str, Any]) -> "QueryDefinition":
        payload = dict(value)
        payload.setdefault("name", name)
        # Version 0 was the pre-P2 unversioned JSON format.
        payload.setdefault("schema_version", QUERY_SCHEMA_VERSION)
        return cls.model_validate(payload)

    def to_storage(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"name"})

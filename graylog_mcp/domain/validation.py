from __future__ import annotations

import re
from typing import Any

NAME_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]+$")
INTERVAL_PATTERN = re.compile(r"^[1-9]\d*(?:ms|s|m|h|d|w)$")
METRIC_FUNCTIONS = {
    "average", "count", "latest", "max", "min", "percentile",
    "stdDev", "sum", "sumOfSquares", "variance",
}


def clean_name(value: str) -> str:
    value = value.strip()
    if not 1 <= len(value) <= 128 or not NAME_PATTERN.fullmatch(value):
        raise ValueError("Name must contain 1 to 128 printable characters")
    return value


def validate_groupings(value: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for item in value:
        field = item.get("field")
        if not isinstance(field, str) or not field.strip() or len(field) > 255 or not NAME_PATTERN.fullmatch(field):
            raise ValueError("Every grouping must contain a valid field")
    return value


def validate_metrics(value: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    if value is None:
        return value
    for item in value:
        function = item.get("function")
        if function not in METRIC_FUNCTIONS:
            raise ValueError(f"Unsupported metric function: {function}")
        field = item.get("field")
        if function != "count" and (not isinstance(field, str) or not field.strip() or len(field) > 255 or not NAME_PATTERN.fullmatch(field)):
            raise ValueError(f"Metric {function} requires a field")
        metric_id = item.get("id")
        if metric_id is not None and (not isinstance(metric_id, str) or not metric_id.strip() or len(metric_id) > 255 or not NAME_PATTERN.fullmatch(metric_id)):
            raise ValueError("Metric id must contain 1 to 255 printable characters")
    return value


def validate_fields(value: list[str] | None) -> list[str] | None:
    if value is not None and any(not field.strip() or len(field) > 255 or not NAME_PATTERN.fullmatch(field) for field in value):
        raise ValueError("Fields must contain 1 to 255 printable characters")
    return value

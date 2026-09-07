from __future__ import annotations

from typing import Any

from .security import agent_context


AGENT_TOOL_NAMES = (
    "search_messages",
    "aggregate",
    "list_streams",
    "list_saved_queries",
    "run_saved_query",
    "search_error_patterns",
    "compare_time_windows",
    "get_log_context",
    "ask_graylog",
)
AGENT_TOOL_SET = frozenset(AGENT_TOOL_NAMES)


class ToolAccessDenied(PermissionError):
    """Raised when an authenticated agent is not allowed to use a tool."""

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        super().__init__(f"Agent is not allowed to use tool '{tool_name}'")


def normalize_allowed_tools(value: Any) -> list[str]:
    """Validate and normalize an agent's allow-list without changing its order."""
    if value is None:
        return list(AGENT_TOOL_NAMES)
    if not isinstance(value, (list, tuple, set)):
        raise ValueError("allowed_tools must be a list")
    normalized = list(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))
    unknown = sorted(set(normalized) - AGENT_TOOL_SET)
    if unknown:
        raise ValueError(f"Unknown Graylog tools: {', '.join(unknown)}")
    return [name for name in AGENT_TOOL_NAMES if name in normalized]


def allowed_tools_from_context(context: dict | None = None) -> list[str]:
    current = agent_context.get() if context is None else context
    if not current or current.get("allowed_tools") is None:
        return list(AGENT_TOOL_NAMES)
    return normalize_allowed_tools(current["allowed_tools"])


def require_tool_access(tool_name: str) -> None:
    context = agent_context.get()
    if context and tool_name not in allowed_tools_from_context(context):
        raise ToolAccessDenied(tool_name)


def filter_tool_schemas(schemas: list[dict], context: dict | None = None) -> list[dict]:
    allowed = set(allowed_tools_from_context(context))
    return [schema for schema in schemas if schema.get("function", {}).get("name") in allowed]

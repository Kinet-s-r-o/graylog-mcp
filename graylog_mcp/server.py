"""Compatibility entry point for Graylog MCP.

Application construction lives in :mod:`graylog_mcp.app`; this module keeps
the original console entry point and public imports used by deployments and
integrations.
"""

from __future__ import annotations

from typing import Any

from .app import TOOL_SCHEMAS, create_app

api = create_app()
_runtime = api.state.runtime
settings = _runtime["settings"]
audit = _runtime["audit"]
catalog = _runtime["catalog"]
mcp = _runtime["mcp"]
graylog_service = _runtime["graylog"]
query_service = _runtime["queries"]
ui_sessions = _runtime["admin_auth"].sessions
login_throttle = _runtime["admin_auth"].throttle
clients = graylog_service.clients

search_messages = _runtime["tools"]["search_messages"]
aggregate = _runtime["tools"]["aggregate"]
list_streams = _runtime["tools"]["list_streams"]
list_saved_queries = _runtime["tools"]["list_saved_queries"]
run_saved_query = _runtime["tools"]["run_saved_query"]
ask_graylog = _runtime["tools"]["ask_graylog"]
execute = _runtime["tools"]["execute"]


async def get_client(server_id: int | None = None):
    return await graylog_service.client(server_id)


async def render_saved_query(name: str, parameters: dict[str, Any]):
    return await query_service.render(name, parameters)


async def query_summaries():
    return await query_service.summaries()


def main() -> None:
    import socket

    import uvicorn

    def listener(host: str, port: int):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        result = socket.socket(family, socket.SOCK_STREAM)
        result.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        result.bind((host, port))
        result.listen(2048)
        return result

    sockets = [
        listener(settings.mcp_host, settings.mcp_port),
        listener(settings.webui_host, settings.webui_port),
    ]
    try:
        config = uvicorn.Config(
            api,
            host=settings.mcp_host,
            port=settings.mcp_port,
            log_level=settings.log_level.lower(),
        )
        uvicorn.Server(config).run(sockets=sockets)
    finally:
        for bound_socket in sockets:
            bound_socket.close()


if __name__ == "__main__":
    main()

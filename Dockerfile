FROM ghcr.io/astral-sh/uv:0.8.15-python3.12-bookworm-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_NO_DEV=1

RUN groupadd --system app && useradd --system --gid app --create-home app \
    && mkdir -p /data \
    && chown -R app:app /app /data

COPY --chown=app:app pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project

COPY --chown=app:app graylog_mcp ./graylog_mcp
COPY --chown=app:app queries.yaml ./
RUN uv sync --locked --no-dev

USER app

EXPOSE 8000 8001
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/app/.venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"]
CMD ["/app/.venv/bin/graylog-mcp"]

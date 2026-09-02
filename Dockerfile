FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml ./
COPY graylog_mcp ./graylog_mcp
COPY queries.yaml README.md ./
RUN pip install --no-cache-dir .

EXPOSE 8000
CMD ["graylog-mcp"]

from __future__ import annotations

from pathlib import Path
import string
import yaml

from .domain.models import QueryDefinition


class QueryCatalog:
    def __init__(self, path: Path):
        self.path = path
        self.data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        raw_queries = self.data.get("queries", {})
        self.queries = {
            name: QueryDefinition.from_storage(name, definition).to_storage()
            for name, definition in raw_queries.items()
        }

    def names(self):
        return list(self.queries)

    def get(self, name: str):
        if name not in self.queries:
            raise KeyError(f"Unknown saved query '{name}'. Available: {', '.join(self.names())}")
        return self.queries[name]

    def render(self, name: str, args: dict):
        item = QueryDefinition.from_storage(name, self.get(name))
        values = {**item.defaults, **args}
        # Safe, explicit format substitution; query templates stay in a reviewed file.
        rendered = {k: string.Template(str(v)).safe_substitute(values) if isinstance(v, str) else v
                    for k, v in item.model_dump(mode="json").items()}
        rendered.pop("schema_version", None)
        rendered.pop("name", None)
        return rendered

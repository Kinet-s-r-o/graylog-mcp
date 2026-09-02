from __future__ import annotations

from pathlib import Path
import string
import yaml


class QueryCatalog:
    def __init__(self, path: Path):
        self.path = path
        self.data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        self.queries = self.data.get("queries", {})

    def names(self):
        return list(self.queries)

    def get(self, name: str):
        if name not in self.queries:
            raise KeyError(f"Unknown saved query '{name}'. Available: {', '.join(self.names())}")
        return self.queries[name]

    def render(self, name: str, args: dict):
        item = self.get(name)
        values = {**item.get("defaults", {}), **args}
        # Safe, explicit format substitution; query templates stay in a reviewed file.
        return {k: string.Template(str(v)).safe_substitute(values) if isinstance(v, str) else v
                for k, v in item.items()}

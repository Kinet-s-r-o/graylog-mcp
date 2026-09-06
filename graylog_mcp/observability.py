from __future__ import annotations

import threading
from collections import defaultdict


class MetricsRegistry:
    """Small dependency-free Prometheus text exporter for core service signals."""

    def __init__(self):
        self._counters: defaultdict[str, int] = defaultdict(int)
        self._gauges: dict[str, float] = {}
        self._lock = threading.Lock()

    def inc(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] += value

    def set(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def render(self, *, active_sessions: int = 0) -> str:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
        gauges["graylog_mcp_active_sessions"] = float(active_sessions)
        lines: list[str] = []
        for name, counter_value in sorted(counters.items()):
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {counter_value}")
        for name, gauge_value in sorted(gauges.items()):
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {gauge_value:g}")
        return "\n".join(lines) + "\n"

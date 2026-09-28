"""本地审计日志：关键认证/撤销事件以 JSON Lines 落盘。

- 每条事件一行 JSON，包含时间戳、事件名与判定依据字段；
- 同时在内存保留一份，方便测试断言与“单测日志打印关键事件”；
- 写盘加锁，多线程并发刷新时事件不交错、不丢行。
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from .clock import Clock


class AuditLogger:
    def __init__(self, path: str, clock: Clock) -> None:
        self.path = Path(path)
        self.clock = clock
        self._lock = threading.Lock()
        self._entries: list[dict] = []
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str, **fields: object) -> dict:
        entry = {"ts": round(self.clock.now(), 6), "event": event, **fields}
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
        with self._lock:
            self._entries.append(entry)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return entry

    def entries(self) -> list[dict]:
        with self._lock:
            return list(self._entries)

    def events(self) -> list[str]:
        return [e["event"] for e in self.entries()]

"""认证/撤销事件的本地记录：JSONL 追加写 + 内存镜像。

关键事件（``name``）：
- ``login_success`` / ``login_failed``
- ``refresh_success`` / ``refresh_failed``（reason 含 reused/expired/...）
- ``access_denied``（未登录与权限不足用 reason 区分）
- ``session_revoked`` / ``all_sessions_revoked``
- ``user_disabled_denied``

单测可通过 :meth:`events` 读取关键事件与判定依据。
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field

from .clock import Clock, SystemClock


@dataclass
class Event:
    ts: float
    name: str
    detail: dict = field(default_factory=dict)


class AuditLog:
    def __init__(self, path: str | None = None, clock: Clock | None = None) -> None:
        self._path = path
        self._clock = clock or SystemClock()
        self._lock = threading.Lock()
        self._events: list[Event] = []
        if path:
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)

    def record(self, name: str, **detail) -> Event:
        event = Event(ts=self._clock.now(), name=name, detail=detail)
        with self._lock:
            self._events.append(event)
            if self._path:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(
                        json.dumps(
                            {"ts": event.ts, "name": name, "detail": detail},
                            sort_keys=True,
                            ensure_ascii=False,
                        )
                        + "\n"
                    )
        return event

    def events(self) -> list[Event]:
        with self._lock:
            return list(self._events)

    def names(self) -> list[str]:
        return [e.name for e in self.events()]

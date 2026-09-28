"""可注入的时钟，便于测试过期与时钟偏差场景。"""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> float:
        """当前 Unix 时间戳（秒）。"""
        ...


class SystemClock:
    def now(self) -> float:
        return time.time()


class FixedClock:
    """测试用：固定时间，可通过 :meth:`advance` 前进。"""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self._t = start

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += seconds

    def set(self, value: float) -> None:
        self._t = value

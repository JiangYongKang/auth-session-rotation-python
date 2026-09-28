"""时钟抽象，便于测试中制造过期与时钟偏差场景。"""

from __future__ import annotations

import time


class Clock:
    """默认使用系统真实时间；测试可注入偏移量。"""

    def __init__(self) -> None:
        self._offset_seconds: float = 0.0

    def now(self) -> float:
        return time.time() + self._offset_seconds

    def set_offset(self, seconds: float) -> None:
        """把“当前时间”整体平移 seconds 秒（可为负）。"""
        self._offset_seconds = float(seconds)

    def advance(self, seconds: float) -> None:
        """让时间向前走 seconds 秒。"""
        self._offset_seconds += float(seconds)

    def reset(self) -> None:
        self._offset_seconds = 0.0

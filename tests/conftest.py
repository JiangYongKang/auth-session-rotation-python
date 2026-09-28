"""测试公共夹具：内存存储 + 固定时钟 + 短 TTL 的 AuthService。"""

from __future__ import annotations

import logging

import pytest

from authapp.audit import AuditLog
from authapp.clock import FixedClock
from authapp.seed import build_seed_store
from authapp.service import AuthService
from authapp.store import Store

logger = logging.getLogger("auth-tests")


def _log_events(events):
    """在单测日志中打印关键事件与判定依据。"""
    for e in events:
        logger.info("event %s @%.1f detail=%s", e.name, e.ts, e.detail)


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(start=1_000_000.0)


@pytest.fixture
def store() -> Store:
    return build_seed_store()


@pytest.fixture
def audit(clock) -> AuditLog:
    return AuditLog(path=None, clock=clock)


@pytest.fixture
def service(store, audit, clock) -> AuthService:
    return AuthService(
        store=store,
        audit=audit,
        secret="test-secret",
        clock=clock,
        access_ttl=300,       # 5 分钟，便于用 advance 模拟过期
        refresh_ttl=600,      # 10 分钟
        clock_skew_tolerance=30,
    )


@pytest.fixture(autouse=True)
def _print_audit_events(request, audit):
    """每个用例结束后把关键认证事件打印到单测日志。"""
    yield
    _log_events(audit.events())

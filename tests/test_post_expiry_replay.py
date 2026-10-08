"""已轮换旧刷新令牌在自身过期后被重放的检测、保留窗口与回收边界。

核心场景：攻击者把一张早已被轮换掉的刷新令牌攥在手里，拖到它自己
也失效（甚至失效很久）之后再拿出来重放 —— 必须仍按重放处理，
撤销整条会话；而一张从未被使用、只是单纯过期的刷新令牌，仍按普通
过期处理，两者在结论与本地记录中都严格区分。
"""

from __future__ import annotations

import json
import threading
from collections import Counter

import pytest
from fastapi.testclient import TestClient

from auth_app.api import create_app
from auth_app.bootstrap import build_service
from auth_app.config import Settings
from auth_app.errors import (
    AuthError,
    RefreshTokenReused,
    SessionRevoked,
    TokenExpired,
)
from auth_app.models import User
from auth_app.security import hash_password

# 测试用时间参数：访问令牌 1000s、刷新令牌 300s、容忍窗口 0（边界精确）
ACCESS_TTL = 1000
REFRESH_TTL = 300
RETENTION = 600  # 保留窗口：过期后再留 600s


def _make_settings(tmp_path, retention=RETENTION) -> Settings:
    return Settings(
        signing_key="test-signing-key",
        access_token_ttl=ACCESS_TTL,
        refresh_token_ttl=REFRESH_TTL,
        clock_skew_leeway=0,
        audit_log_path=str(tmp_path / "audit.log.jsonl"),
        seed_users=False,
        replay_retention_seconds=retention,
    )


@pytest.fixture
def renv(tmp_path):
    """带可平移时钟与短保留窗口的独立服务实例。"""
    settings = _make_settings(tmp_path)
    service = build_service(settings)
    service.store.upsert_user(User(
        user_id="u_alice", username="alice",
        password_hash=hash_password("alice123"), roles={"viewer"},
    ))
    bench = type("Bench", (), {})()
    bench.service = service
    bench.settings = settings
    bench.client = TestClient(create_app(service))
    bench.clock = service.clock
    yield bench

    events = service.audit.entries()
    print("\n================ 审计事件（判定依据） ================")
    for entry in events:
        print(json.dumps(entry, ensure_ascii=False, sort_keys=True))
    print(f"================ 共 {len(events)} 条事件 ================\n")


def _refresh_records(service):
    return service.store.snapshot_refresh_by_hash()


# --------------------------------------------------------------------- #
# 核心：已轮换旧令牌在自身过期之后被重放 -> 仍按重放处理
# --------------------------------------------------------------------- #
def test_rotated_token_replayed_after_expiry_revokes_session(renv):
    service = renv.service
    p1 = service.login("alice", "alice123")

    # t=100：正常轮换，p1 的刷新令牌被标记 used，拿到 p2
    renv.clock.advance(100)
    p2 = service.refresh(p1.refresh_token)

    # t=350：p1 的刷新令牌已过期（exp=300），攻击者此时才拿它重放
    renv.clock.advance(250)
    with pytest.raises(RefreshTokenReused) as exc_info:
        service.refresh(p1.refresh_token)
    assert exc_info.value.detail["reason"] == "used_after_expiry"

    # 整条会话被撤销，撤销原因与登出/管理员撤销明确区分
    sessions = service.list_sessions("u_alice")
    assert len(sessions) == 1 and sessions[0]["revoked"]
    assert sessions[0]["revoke_reason"] == "refresh_token_reuse:used_after_expiry"
    assert sessions[0]["revoke_reason"] not in ("logout", "manual_revoke")

    # 会话里仍在有效期内的令牌一起作废：p2 的访问令牌（exp=1100）立即失效
    with pytest.raises(SessionRevoked):
        service.authenticate_access_token(p2.access_token)
    # p2 的刷新令牌（exp=400，尚未过期）也不能再换到新令牌
    with pytest.raises(RefreshTokenReused):
        service.refresh(p2.refresh_token)

    # 重放没有顺手签发任何新令牌：仍只有 p1/p2 两条刷新令牌记录
    assert len(_refresh_records(service)) == 2

    # 审计：重放事件带判定依据
    reuse = [e for e in service.audit.entries()
             if e["event"] == "refresh_token_reuse_detected"]
    assert reuse and reuse[0]["reason"] == "used_after_expiry"
    assert reuse[0]["action"] == "whole_session_revoked"
    assert "used_at" in reuse[0]


def test_rotated_token_replayed_long_after_expiry_still_detected(renv):
    """失效很久（但仍在保留窗口内）才重放，结论不变。"""
    service = renv.service
    p1 = service.login("alice", "alice123")
    service.refresh(p1.refresh_token)

    # 过期后又过了很久：exp=300，现在 t=850（保留窗口 300+600=900 之内）
    renv.clock.advance(850)
    with pytest.raises(RefreshTokenReused):
        service.refresh(p1.refresh_token)
    sessions = service.list_sessions("u_alice")
    assert sessions[0]["revoke_reason"] == "refresh_token_reuse:used_after_expiry"


# --------------------------------------------------------------------- #
# 对照：从未被成功使用、只是单纯过期的刷新令牌 -> 普通过期
# --------------------------------------------------------------------- #
def test_never_used_expired_token_is_plain_expiry(renv):
    service = renv.service
    pair = service.login("alice", "alice123")

    # 刷新令牌从未使用，单纯放到过期（exp=300）
    renv.clock.advance(301)
    with pytest.raises(TokenExpired):
        service.refresh(pair.refresh_token)

    # 会话不被撤销，与重放结论明确区分
    sessions = service.list_sessions("u_alice")
    assert sessions[0]["revoked"] is False
    assert not [e for e in service.audit.entries()
                if e["event"] == "refresh_token_reuse_detected"]
    rejected = [e for e in service.audit.entries()
                if e["event"] == "refresh_rejected"]
    assert rejected and rejected[-1]["reason"] == "expired_unused"


def test_two_sessions_same_user_different_conclusions(renv):
    """同一用户两条会话：一条被重放撤销，一条单纯过期，互不影响。"""
    service = renv.service
    a1 = service.login("alice", "alice123")
    b1 = service.login("alice", "alice123")
    service.refresh(a1.refresh_token)  # A 会话发生轮换，a1 变 used

    renv.clock.advance(301)  # 两张旧刷新令牌都已过期
    with pytest.raises(RefreshTokenReused):
        service.refresh(a1.refresh_token)   # A：重放 -> 撤销
    with pytest.raises(TokenExpired):
        service.refresh(b1.refresh_token)   # B：单纯过期 -> 不动

    sessions = service.list_sessions("u_alice")
    revoked = [s for s in sessions if s["revoked"]]
    alive = [s for s in sessions if not s["revoked"]]
    assert len(revoked) == 1 and len(alive) == 1
    assert revoked[0]["revoke_reason"] == "refresh_token_reuse:used_after_expiry"


# --------------------------------------------------------------------- #
# HTTP 入口一致性
# --------------------------------------------------------------------- #
def test_http_entry_matches_service_layer(renv):
    client = renv.client
    r = client.post("/auth/login",
                    json={"username": "alice", "password": "alice123"})
    p1 = r.json()
    renv.clock.advance(100)
    r = client.post("/auth/refresh",
                    json={"refresh_token": p1["refresh_token"]})
    assert r.status_code == 200

    # 已轮换旧令牌过期后重放 -> 401 refresh_token_reused
    renv.clock.advance(250)
    r = client.post("/auth/refresh",
                    json={"refresh_token": p1["refresh_token"]})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "refresh_token_reused"
    assert r.json()["error"]["detail"]["reason"] == "used_after_expiry"


def test_http_never_used_expired_token_is_token_expired(renv):
    client = renv.client
    r = client.post("/auth/login",
                    json={"username": "alice", "password": "alice123"})
    p1 = r.json()
    renv.clock.advance(301)
    r = client.post("/auth/refresh",
                    json={"refresh_token": p1["refresh_token"]})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "token_expired"


# --------------------------------------------------------------------- #
# 保留窗口与回收边界
# --------------------------------------------------------------------- #
def test_history_retained_within_window_and_purged_after(renv):
    service = renv.service
    p1 = service.login("alice", "alice123")
    service.refresh(p1.refresh_token)
    old_hash = next(h for h, r in _refresh_records(service).items()
                    if r.used)

    # 窗口内（exp=300 + retention=600，截止 t=900）：t=899 记录仍在，
    # 重放仍按重放判定
    renv.clock.advance(899)
    assert old_hash in _refresh_records(service)
    assert service.cleanup_refresh_history() == 0
    with pytest.raises(RefreshTokenReused):
        service.refresh(p1.refresh_token)


def test_history_purged_only_after_retention_deadline(renv):
    service = renv.service
    p1 = service.login("alice", "alice123")
    service.refresh(p1.refresh_token)
    old_hash = next(h for h, r in _refresh_records(service).items()
                    if r.used)

    # 正好到保留截止时刻 t=900：记录被回收
    renv.clock.advance(900)
    purged = service.cleanup_refresh_history()
    assert purged == 2  # p1 与 p2 的记录（exp 都是 300）一起到期
    assert old_hash not in _refresh_records(service)

    purge_events = [e for e in service.audit.entries()
                    if e["event"] == "refresh_history_purged"]
    assert purge_events and purge_events[0]["purged_count"] == 2

    # 超出保留范围后的重放：安全兜底为普通过期拒绝，绝不签发新令牌
    with pytest.raises(TokenExpired):
        service.refresh(p1.refresh_token)
    assert len(_refresh_records(service)) == 0
    rejected = [e for e in service.audit.entries()
                if e["event"] == "refresh_rejected"]
    assert rejected[-1]["reason"] == "expired_no_record_or_purged"


def test_valid_unused_token_record_never_purged(renv):
    """还没过期的刷新令牌，记录绝不被回收。"""
    service = renv.service
    pair = service.login("alice", "alice123")
    renv.clock.advance(REFRESH_TTL - 1)  # 差 1 秒过期
    assert service.cleanup_refresh_history() == 0
    # 令牌仍可用，能正常轮换
    new_pair = service.refresh(pair.refresh_token)
    assert new_pair.refresh_token != pair.refresh_token


def test_cleanup_is_lazy_and_runs_on_refresh(renv):
    """回收随刷新惰性触发，不需要外部定时任务。"""
    service = renv.service
    p1 = service.login("alice", "alice123")
    service.refresh(p1.refresh_token)
    # 让 p1/p2 的记录都过保留期，再登录新会话并刷新 -> 触发惰性回收
    renv.clock.advance(900)
    p3 = service.login("alice", "alice123")
    service.refresh(p3.refresh_token)
    remaining = _refresh_records(service).values()
    assert all(r.expires_at > 900 for r in remaining)  # 旧记录已清，只剩新会话
    assert any(e["event"] == "refresh_history_purged"
               for e in service.audit.entries())


# --------------------------------------------------------------------- #
# 并发：重放、刷新、回收同时发生
# --------------------------------------------------------------------- #
def test_concurrent_post_expiry_replays_all_rejected(renv):
    """多个线程同时重放同一张过期旧令牌：全部判重放，只撤销一次，零签发。"""
    service = renv.service
    p1 = service.login("alice", "alice123")
    service.refresh(p1.refresh_token)
    renv.clock.advance(301)

    n = 16
    barrier = threading.Barrier(n)
    outcomes: list[str] = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            service.refresh(p1.refresh_token)
            with lock:
                outcomes.append("ok")
        except RefreshTokenReused:
            with lock:
                outcomes.append("reused")
        except AuthError:
            with lock:
                outcomes.append("other")

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    counter = Counter(outcomes)
    assert counter["ok"] == 0, "过期重放绝不允许成功签发"
    assert counter["reused"] == n
    assert len(_refresh_records(service)) == 2  # 没有产生任何新令牌
    sessions = service.list_sessions("u_alice")
    assert sessions[0]["revoked"]


def test_concurrent_refresh_and_cleanup_no_double_issue(renv):
    """并发刷新 + 并发回收同时进行：只有一个刷新成功，无重复签发。"""
    service = renv.service
    pair = service.login("alice", "alice123")

    n = 12
    barrier = threading.Barrier(n + 1)
    results: list[tuple[str, str]] = []
    lock = threading.Lock()

    def refresher():
        barrier.wait()
        try:
            new_pair = service.refresh(pair.refresh_token)
            with lock:
                results.append(("ok", new_pair.refresh_token))
        except (RefreshTokenReused, SessionRevoked) as exc:
            with lock:
                results.append(("fail", exc.code))

    def cleaner():
        barrier.wait()
        for _ in range(20):
            service.cleanup_refresh_history()

    threads = [threading.Thread(target=refresher) for _ in range(n)]
    threads.append(threading.Thread(target=cleaner))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    counter = Counter(status for status, _ in results)
    assert counter["ok"] == 1, f"成功数应为 1，实际：{counter}"
    winners = [tok for status, tok in results if status == "ok"]
    assert len(set(winners)) == 1
    # 有效令牌的记录在回收中存活（保留窗口远未到期）
    assert len(_refresh_records(service)) == 2

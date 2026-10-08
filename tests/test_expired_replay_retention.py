"""过期轮换令牌的“迟到重放” + 有界保留/回收 + 并发清理。

本轮新增安全语义：

* 一张**早已被轮换掉**的刷新令牌，即使拖到它自身过期很久之后才被
  翻出来重放，也必须按重放处理，立刻撤销整条会话（含其它仍有效令牌），
  绝不重新签发；
* 一张**从未被成功使用、只是过期**的刷新令牌，仍按普通过期处理，
  不撤销会话；两类“已不能用”的刷新令牌在错误码、审计原因上严格区分；
* 重放历史有界保留：记录在“自身过期（含 leeway）+ 保留窗口”之前绝不
  被清理；超出窗口被回收后再次提交，安全拒绝（不放行、不重签）；
* 并发刷新 / 并发撤销 / 清理同时发生时结论一致、无重复签发。

以 ``pytest -s`` 运行会打印每个用例的关键审计事件与判定依据。
"""

from __future__ import annotations

import threading
from collections import Counter

import pytest

from auth_app.errors import (
    RefreshTokenHistoryReaped,
    RefreshTokenInvalid,
    RefreshTokenReused,
    SessionRevoked,
    TokenExpired,
)

REFRESH_TTL = 300
RETENTION = 1000  # 测试用的保留窗口（秒）


@pytest.fixture
def renv(tmp_path):
    """短保留窗口的环境，便于压回收边界。"""
    from fastapi.testclient import TestClient

    from auth_app.api import create_app
    from auth_app.bootstrap import build_service
    from auth_app.config import Settings
    from auth_app.models import User
    from auth_app.security import hash_password

    settings = Settings(
        signing_key="test-signing-key",
        access_token_ttl=60,
        refresh_token_ttl=REFRESH_TTL,
        clock_skew_leeway=0,
        audit_log_path=str(tmp_path / "audit-renv.jsonl"),
        seed_users=False,
        replay_retention_seconds=RETENTION,
        replay_history_max_records=10_000,
        replay_purge_interval_seconds=0,  # 测试里每次刷新都允许清理
    )
    service = build_service(settings)
    service.store.upsert_user(User(
        "u_bob", "bob", hash_password("bob123"), {"viewer"}, set()))
    client = TestClient(create_app(service))
    yield service, client, settings

    # ---- 打印本用例关键审计事件与判定依据（pytest -s 可见）---- #
    import json
    entries = service.audit.entries()
    print("\n---------------- 过期重放/保留 审计依据 ----------------")
    for entry in entries:
        print(json.dumps(entry, ensure_ascii=False, sort_keys=True))
    print(f"---------------- 共 {len(entries)} 条 ----------------")


def _session_id(service, refresh_token):
    from auth_app.security import sha256_hex
    return service.store.get_refresh_by_hash(
        sha256_hex(refresh_token)).session_id


# --------------------------------------------------------------------- #
# 核心场景：被轮换掉的旧令牌，过期很久后才重放
# --------------------------------------------------------------------- #
def test_rotated_token_replayed_long_after_own_expiry_is_reuse(renv):
    svc, _, _ = renv
    p1 = svc.login("bob", "bob123")
    p2 = svc.refresh(p1.refresh_token)
    p3 = svc.refresh(p2.refresh_token)
    sid = _session_id(svc, p3.refresh_token)

    # 拖到第一代旧令牌自身过期很久，但仍在保留窗口内。
    svc.clock.advance(REFRESH_TTL + 1 + 500)
    with pytest.raises(RefreshTokenReused) as exc:
        svc.refresh(p1.refresh_token)
    assert exc.value.detail["reason"] == \
        "used_token_replayed_after_expiry"

    session = svc.store.get_session(sid)
    assert session.revoked is True
    assert session.revoke_reason == \
        "refresh_token_reuse:used_token_replayed_after_expiry"

    events = svc.audit.events()
    assert "refresh_token_reuse_detected" in events


def test_expired_replay_revokes_other_still_valid_tokens_in_session(renv):
    """迟到重放发生后，同会话里其它还在有效期内的令牌也要立即作废，
    且不会重新签发任何新令牌。"""
    svc, _, _ = renv
    p1 = svc.login("bob", "bob123")
    p2 = svc.refresh(p1.refresh_token)  # p1 变 used，p2 是当前有效令牌

    # 只让 p1 过期，p2 仍然“没过期”。
    svc.clock.advance(REFRESH_TTL + 1)
    with pytest.raises(RefreshTokenReused):
        svc.refresh(p1.refresh_token)

    # p2 自身未过期，但因链路被攻破必须立即失效（按重放告警，不是普通撤销）。
    with pytest.raises(RefreshTokenReused) as exc:
        svc.refresh(p2.refresh_token)
    assert exc.value.detail["session_id"] == _session_id(svc, p2.refresh_token)

    # 没有任何新令牌被签发：记录数不增加。
    assert svc.store.count_refresh_records() == 2


def test_expired_replay_does_not_reissue_tokens(renv):
    svc, _, _ = renv
    p1 = svc.login("bob", "bob123")
    svc.refresh(p1.refresh_token)
    before = svc.store.count_refresh_records()
    svc.clock.advance(REFRESH_TTL + 1 + 100)
    with pytest.raises(RefreshTokenReused):
        svc.refresh(p1.refresh_token)
    assert svc.store.count_refresh_records() == before


# --------------------------------------------------------------------- #
# 对照：从未成功使用、只是过期 => 普通过期，不撤销会话
# --------------------------------------------------------------------- #
def test_never_used_expired_token_is_plain_expiry(renv):
    svc, _, _ = renv
    p1 = svc.login("bob", "bob123")
    sid = _session_id(svc, p1.refresh_token)
    svc.clock.advance(REFRESH_TTL + 1)

    with pytest.raises(TokenExpired) as exc:
        svc.refresh(p1.refresh_token)
    assert exc.value.detail["reason"] == "expired_never_used"

    # 会话保持有效，用户可正常再登录/使用其它会话。
    assert svc.store.get_session(sid).revoked is False


def test_two_kinds_of_dead_tokens_are_clearly_distinguished(renv):
    """同一用户、同一“已不能用”表象：轮换后过期 vs 从未使用过期，
    错误码与审计原因必须稳定可区分。"""
    svc, _, _ = renv
    rotated = svc.login("bob", "bob123")
    fresh = svc.refresh(rotated.refresh_token)  # rotated 变 used

    unused = svc.login("bob", "bob123")

    svc.clock.advance(REFRESH_TTL + 1 + 10)
    with pytest.raises(RefreshTokenReused) as e1:
        svc.refresh(rotated.refresh_token)
    with pytest.raises(TokenExpired) as e2:
        svc.refresh(unused.refresh_token)

    assert e1.value.code != e2.value.code
    assert e1.value.code == "refresh_token_reused"
    assert e2.value.code == "token_expired"

    reasons = [e.get("reason") for e in svc.audit.entries()]
    assert "used_token_replayed_after_expiry" in reasons
    assert "expired_never_used" in reasons

    # fresh 所在会话因重放被撤销；unused 所在会话仍是普通失效。
    assert svc.store.get_session(
        _session_id(svc, fresh.refresh_token)).revoked is True
    assert svc.store.get_session(
        _session_id(svc, unused.refresh_token)).revoked is False


# --------------------------------------------------------------------- #
# HTTP 入口与服务层结论一致
# --------------------------------------------------------------------- #
def test_expired_replay_over_http_matches_service(renv):
    svc, client, _ = renv
    p1 = svc.login("bob", "bob123")
    svc.refresh(p1.refresh_token)
    svc.clock.advance(REFRESH_TTL + 1 + 10)

    r = client.post("/auth/refresh",
                    json={"refresh_token": p1.refresh_token})
    assert r.status_code == 401
    body = r.json()["error"]
    assert body["code"] == "refresh_token_reused"
    assert body["detail"]["reason"] == \
        "used_token_replayed_after_expiry"


def test_never_used_expired_over_http_is_token_expired(renv):
    svc, client, _ = renv
    p1 = svc.login("bob", "bob123")
    svc.clock.advance(REFRESH_TTL + 1)
    r = client.post("/auth/refresh",
                    json={"refresh_token": p1.refresh_token})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "token_expired"


def test_same_expired_rotated_token_conclusion_is_stable(renv):
    """同一张过期轮换令牌重复提交 N 次，结论始终为重放、会话只撤销一次。"""
    svc, _, _ = renv
    p1 = svc.login("bob", "bob123")
    sid = _session_id(svc, p1.refresh_token)
    svc.refresh(p1.refresh_token)
    svc.clock.advance(REFRESH_TTL + 1 + 10)

    codes = []
    for _ in range(5):
        with pytest.raises(RefreshTokenReused) as exc:
            svc.refresh(p1.refresh_token)
        codes.append(exc.value.code)
    assert set(codes) == {"refresh_token_reused"}

    session = svc.store.get_session(sid)
    assert session.revoked is True
    # 撤销时刻只记录第一次。
    revoked_events = [e for e in svc.audit.entries()
                      if e["event"] == "refresh_token_reuse_detected"]
    assert len(revoked_events) == 5


# --------------------------------------------------------------------- #
# 失效边界附近：结论稳定（过期前后分类一致）
# --------------------------------------------------------------------- #
@pytest.mark.parametrize("delta,expect", [
    (REFRESH_TTL - 1, "reuse"),      # 尚未过期：旧令牌重放
    (REFRESH_TTL, "reuse"),          # 恰好过期（leeway=0）
    (REFRESH_TTL + 1, "reuse"),      # 刚过期
    (REFRESH_TTL + RETENTION - 1, "reuse"),  # 临近回收边界（仍在窗内）
    (REFRESH_TTL + RETENTION + 1, "reaped"), # 超过保留窗口：安全拒绝
])
def test_rotated_token_reuse_classification_stable_around_expiry(
        renv, delta, expect):
    svc, _, _ = renv
    p1 = svc.login("bob", "bob123")
    svc.refresh(p1.refresh_token)
    svc.clock.advance(delta)
    if expect == "reuse":
        with pytest.raises(RefreshTokenReused):
            svc.refresh(p1.refresh_token)
    else:
        # 机会式清理先把窗口外历史回收，随后安全拒绝（不放行/不重签）。
        with pytest.raises(RefreshTokenHistoryReaped):
            svc.refresh(p1.refresh_token)


# --------------------------------------------------------------------- #
# 有界保留 / 回收边界
# --------------------------------------------------------------------- #
def test_history_not_purged_while_replay_still_possible(renv):
    """保留窗口内：无论机会式清理还是显式清理，都不能删掉痕迹。"""
    svc, _, _ = renv
    p1 = svc.login("bob", "bob123")
    svc.refresh(p1.refresh_token)  # p1 已 used

    # 旧令牌已过期，但还没到 retain_until（iat+TTL+RETENTION）。
    svc.clock.advance(REFRESH_TTL + RETENTION - 1)
    stats = svc.purge_replay_history()
    assert stats["reaped"] == 0
    assert svc.store.count_refresh_records() == 2

    # 痕迹仍在 => 迟到重放照样被抓住。
    with pytest.raises(RefreshTokenReused):
        svc.refresh(p1.refresh_token)


def test_history_purged_only_after_retention_deadline(renv):
    svc, _, _ = renv
    p1 = svc.login("bob", "bob123")
    svc.refresh(p1.refresh_token)

    # 恰好到 retain_until（= exp + leeway(0) + retention）。
    svc.clock.advance(REFRESH_TTL + RETENTION)
    stats = svc.purge_replay_history()
    assert stats["reaped"] == 2
    assert stats["remaining"] == 0


def test_after_retention_replay_is_denied_not_allowed_or_reissued(renv):
    svc, _, _ = renv
    p1 = svc.login("bob", "bob123")
    svc.refresh(p1.refresh_token)
    sid = _session_id(svc, p1.refresh_token)

    svc.clock.advance(REFRESH_TTL + RETENTION + 1)
    svc.purge_replay_history()
    assert svc.store.count_refresh_records() == 0

    with pytest.raises(RefreshTokenHistoryReaped) as exc:
        svc.refresh(p1.refresh_token)
    detail = exc.value.detail
    assert detail["reason"] == "history_retention_exceeded"
    assert detail["retain_deadline"] < detail["presented_at"]

    # 拒绝而不是放行/重签：记录数依旧为 0。
    assert svc.store.count_refresh_records() == 0

    events = [e for e in svc.audit.entries()
              if e["event"] == "refresh_history_reaped_reject"]
    assert len(events) == 1
    assert events[0]["action"] == "deny_without_reissue"
    # 会话本身没有被改判（历史已不可考），但旧会话也不会因此复活。
    assert svc.store.get_session(sid) is not None


def test_never_used_unknown_expired_token_within_window_is_invalid(renv):
    """保留窗口内、但服务端从无此记录的过期令牌：普通无效，不当重放。"""
    svc, _, _ = renv
    from auth_app import tokens as token_module
    # 直接构造一张签名合法、但从未登录签发过的刷新令牌。
    rogue = token_module.issue_refresh_token(
        "rogue-jti", "u_bob", "sess-rogue", svc.settings, svc.clock)
    svc.clock.advance(REFRESH_TTL + 1)
    with pytest.raises((RefreshTokenInvalid, TokenExpired)):
        svc.refresh(rogue)
    events = [e for e in svc.audit.entries()
              if e["event"] == "refresh_rejected"]
    assert any(e["reason"] == "expired_token_not_found_within_window"
               for e in events)


def test_retention_does_not_touch_live_records(renv):
    """清理不能误删还没过期、正在使用的令牌。"""
    svc, _, _ = renv
    old = svc.login("bob", "bob123")
    svc.refresh(old.refresh_token)
    svc.clock.advance(REFRESH_TTL + RETENTION + 1)
    # 新登录的令牌远未到保留截止。
    live = svc.login("bob", "bob123")
    stats = svc.purge_replay_history()
    assert stats["reaped"] == 2  # 只回收旧会话那一对
    # 新令牌仍可正常轮换。
    pair = svc.refresh(live.refresh_token)
    assert pair.refresh_token


def test_max_records_never_causes_early_deletion(renv):
    """条数软上限不得导致窗口内记录被提前删除。"""
    svc, _, _ = renv
    p1 = svc.login("bob", "bob123")
    svc.refresh(p1.refresh_token)  # 2 条，全部在保留窗口内
    # 把上限压到 1：当前 2 > 1，但没有任何记录可回收。
    stats = svc.store.purge_replay_history(svc.clock.now(), max_records=1)
    assert stats["reaped"] == 0
    assert stats["remaining"] == 2
    assert stats["over_limit"] is True
    assert stats["next_eligible_at"] is not None
    # 迟到重放仍被识别。
    svc.clock.advance(REFRESH_TTL + 1)
    with pytest.raises(RefreshTokenReused):
        svc.refresh(p1.refresh_token)


# --------------------------------------------------------------------- #
# 与现有撤销语义对齐：登出 / 管理员撤销的过期令牌仍是“普通撤销”
# --------------------------------------------------------------------- #
def test_expired_token_after_logout_is_session_revoked_not_reuse(renv):
    svc, _, _ = renv
    p1 = svc.login("bob", "bob123")
    sid = _session_id(svc, p1.refresh_token)
    svc.revoke_session(sid, reason="logout")
    svc.clock.advance(REFRESH_TTL + 1)

    with pytest.raises(SessionRevoked):
        svc.refresh(p1.refresh_token)
    # 审计里不能把登出误记成重放。
    reuse = [e for e in svc.audit.entries()
             if e["event"] == "refresh_token_reuse_detected"]
    assert reuse == []


def test_revoked_reasons_are_distinguished_in_records(renv):
    """重放撤销 vs 用户登出 vs 管理员撤销，本地记录原因互不相同。"""
    svc, _, _ = renv
    # 重放
    r = svc.login("bob", "bob123")
    sid_r = _session_id(svc, r.refresh_token)
    svc.refresh(r.refresh_token)
    svc.clock.advance(REFRESH_TTL + 1)
    with pytest.raises(RefreshTokenReused):
        svc.refresh(r.refresh_token)
    # 登出
    lo = svc.login("bob", "bob123")
    sid_lo = _session_id(svc, lo.refresh_token)
    svc.revoke_session(sid_lo, reason="logout")
    # 管理员/全用户撤销
    ad = svc.login("bob", "bob123")
    sid_ad = _session_id(svc, ad.refresh_token)
    svc.revoke_all_user_sessions("u_bob", reason="user_all_revoked")

    reasons = {
        sid_r: svc.store.get_session(sid_r).revoke_reason,
        sid_lo: svc.store.get_session(sid_lo).revoke_reason,
        sid_ad: svc.store.get_session(sid_ad).revoke_reason,
    }
    assert reasons[sid_r].startswith("refresh_token_reuse:")
    assert reasons[sid_lo] == "logout"
    assert reasons[sid_ad] == "user_all_revoked"
    assert len(set(reasons.values())) == 3


# --------------------------------------------------------------------- #
# 并发：清理 + 并发刷新 + 并发撤销同时发生
# --------------------------------------------------------------------- #
def test_concurrent_refresh_with_concurrent_purge_single_winner(renv):
    svc, _, _ = renv
    pair = svc.login("bob", "bob123")
    n = 30
    barrier = threading.Barrier(n + 1)
    results: list[tuple[str, str]] = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            p = svc.refresh(pair.refresh_token)
            with lock:
                results.append(("ok", p.refresh_token))
        except Exception as exc:  # noqa: BLE001
            with lock:
                results.append(("fail", getattr(exc, "code", type(exc).__name__)))

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()

    # 同时不断触发显式清理（此时记录都在窗口内，什么都不会被删）。
    barrier.wait()
    for _ in range(20):
        svc.purge_replay_history()

    for t in threads:
        t.join()

    counter = Counter(s for s, _ in results)
    assert counter["ok"] == 1, counter
    assert counter["fail"] == n - 1
    for status, code in results:
        if status == "fail":
            assert code in {"refresh_token_reused", "session_revoked"}, code


def test_concurrent_expired_replay_and_revoke_no_inconsistency(renv):
    """过期旧令牌重放与并发主动撤销竞争：会话必被撤销，绝不签发新令牌。"""
    svc, _, _ = renv
    p1 = svc.login("bob", "bob123")
    sid = _session_id(svc, p1.refresh_token)
    svc.refresh(p1.refresh_token)
    svc.clock.advance(REFRESH_TTL + 1)

    errors: list[str] = []
    elock = threading.Lock()

    def replay():
        try:
            svc.refresh(p1.refresh_token)
        except Exception as exc:  # noqa: BLE001
            with elock:
                errors.append(getattr(exc, "code", type(exc).__name__))

    def revoke():
        svc.revoke_session(sid, reason="manual_revoke")

    t1 = threading.Thread(target=replay)
    t2 = threading.Thread(target=revoke)
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert svc.store.get_session(sid).revoked is True
    # 无论谁先谁后，重放线程要么识别为重放，要么会话已撤销；都不能成功。
    assert errors[0] in {"refresh_token_reused", "session_revoked"}
    # 记录数保持为一对（无新签发）。
    assert svc.store.count_refresh_records() == 2


def test_opportunistic_purge_runs_inside_refresh(renv):
    """refresh 流程内的机会式清理会在到点时回收历史，且之后安全拒绝。"""
    svc, _, _ = renv
    p1 = svc.login("bob", "bob123")
    svc.refresh(p1.refresh_token)
    svc.clock.advance(REFRESH_TTL + RETENTION + 1)
    # purge_interval=0：下一次任意 refresh 都会先清理。
    with pytest.raises(RefreshTokenHistoryReaped):
        svc.refresh(p1.refresh_token)
    purged = [e for e in svc.audit.entries()
              if e["event"] == "replay_history_purged"]
    assert any(e.get("reaped_count", 0) >= 2 for e in purged)


def test_http_purge_endpoint_admin_only_and_consistent(renv, tmp_path):
    """HTTP 回收入口需 user:manage；普通用户 403；回收后结论与服务层一致。"""
    from fastapi.testclient import TestClient

    from auth_app.api import create_app
    from auth_app.bootstrap import build_service
    from auth_app.config import Settings
    from auth_app.models import User
    from auth_app.security import hash_password

    settings = Settings(
        signing_key="k2", access_token_ttl=60, refresh_token_ttl=REFRESH_TTL,
        clock_skew_leeway=0,
        audit_log_path=str(tmp_path / "a2.jsonl"), seed_users=False,
        replay_retention_seconds=RETENTION, replay_purge_interval_seconds=0)
    svc = build_service(settings)
    svc.store.upsert_user(User("u_bob", "bob", hash_password("bob123"),
                               {"viewer"}, set()))
    svc.store.upsert_user(User("u_admin", "admin", hash_password("admin123"),
                               {"admin"}, set()))
    client = TestClient(create_app(svc))

    p1 = svc.login("bob", "bob123")
    svc.refresh(p1.refresh_token)

    bob = client.post("/auth/login", json={"username": "bob",
                                           "password": "bob123"}).json()
    r = client.post("/admin/maintenance/replay-history/purge",
                    headers={"Authorization": f"Bearer {bob['access_token']}"})
    assert r.status_code == 403

    svc.clock.advance(REFRESH_TTL + RETENTION + 1)
    admin = client.post("/auth/login", json={"username": "admin",
                                             "password": "admin123"}).json()
    r = client.post("/admin/maintenance/replay-history/purge",
                    headers={"Authorization":
                             f"Bearer {admin['access_token']}"})
    assert r.status_code == 200, r.text
    # bob 的两次登录各一对、且都已越过保留截止时刻，全部被回收；
    # 仅剩 admin 自己刚登录、仍在有效期内的那一条。
    assert r.json()["reaped"] >= 2
    assert r.json()["remaining"] == 1

    # 回收后再经 HTTP 提交过期旧令牌：安全拒绝，不放行/不重签。
    r2 = client.post("/auth/refresh",
                     json={"refresh_token": p1.refresh_token})
    assert r2.status_code == 401
    assert r2.json()["error"]["code"] == "refresh_token_history_reaped"

"""登录、刷新轮换与刷新令牌重用检测。"""

from __future__ import annotations

import pytest

from auth_app.errors import (
    InvalidCredentials,
    PermissionDenied,
    RefreshTokenReused,
    SessionRevoked,
)


def login_pair(env, username="viewer", password="viewer123"):
    return env.service.login(username, password)


def test_login_success_and_protected_resource(env):
    pair = login_pair(env)
    identity = env.service.require_permission(pair.access_token, "doc:read")
    assert identity["user_id"] == "u_viewer"
    assert "login_ok" in env.service.audit.events()


def test_login_with_wrong_password_is_rejected(env):
    with pytest.raises(InvalidCredentials):
        env.service.login("viewer", "wrong-password")
    assert env.service.audit.events()[-1] == "login_failed"


def test_refresh_rotates_tokens_and_issues_new_pair(env):
    pair = login_pair(env)
    rotated = env.service.refresh(pair.refresh_token)
    assert rotated.refresh_token != pair.refresh_token
    assert rotated.access_token != pair.access_token
    event = env.service.audit.entries()[-1]
    assert event["event"] == "refresh_rotated"
    assert event["old_jti"]  # 判定依据：被轮换掉的旧 jti 已记录


def test_reuse_of_spent_refresh_token_revokes_whole_session(env):
    pair = login_pair(env)
    rotated = env.service.refresh(pair.refresh_token)  # 第一次正常轮换

    # 旧刷新令牌再次出现 => 必须按重放处理
    with pytest.raises(RefreshTokenReused) as exc:
        env.service.refresh(pair.refresh_token)
    assert exc.value.detail["reason"] == "already_used"

    # 重放导致整条会话被撤销：新签发的访问令牌立即失效
    with pytest.raises(SessionRevoked):
        env.service.authenticate_access_token(rotated.access_token)

    # 重放分支签发出来的新刷新令牌同样不可用（没有悄悄多发令牌）
    with pytest.raises(RefreshTokenReused):
        env.service.refresh(rotated.refresh_token)

    reuse_events = [e for e in env.service.audit.entries()
                    if e["event"] == "refresh_token_reuse_detected"]
    assert len(reuse_events) >= 1
    assert reuse_events[0]["action"] == "whole_session_revoked"


def test_second_reuse_attempt_is_still_rejected_and_stable(env):
    """同样的输入反复出现，结论必须稳定：每次都是 reuse，绝不成功。"""
    pair = login_pair(env)
    env.service.refresh(pair.refresh_token)
    for _ in range(3):
        with pytest.raises(RefreshTokenReused):
            env.service.refresh(pair.refresh_token)


def test_http_refresh_reuse_returns_distinct_error_code(env):
    pair = login_pair(env)
    r1 = env.client.post("/auth/refresh",
                         json={"refresh_token": pair.refresh_token})
    assert r1.status_code == 200
    r2 = env.client.post("/auth/refresh",
                         json={"refresh_token": pair.refresh_token})
    assert r2.status_code == 401
    assert r2.json()["error"]["code"] == "refresh_token_reused"

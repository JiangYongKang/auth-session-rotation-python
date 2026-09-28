"""撤销单个会话、撤销用户全部会话，以及跨入口结论一致性。"""

from __future__ import annotations

import pytest

from auth_app.errors import SessionRevoked


def auth(client, token):
    return {"Authorization": f"Bearer {token}"}


def test_revoke_single_session_invalidates_its_tokens(env):
    p1 = env.service.login("bob", "bob123")
    p2 = env.service.login("bob", "bob123")  # 同用户的第二个会话
    sid1 = env.service.authenticate_access_token(p1.access_token)["session_id"]
    sid2 = env.service.authenticate_access_token(p2.access_token)["session_id"]
    assert sid1 != sid2

    env.service.revoke_session(sid1, reason="test_single_revoke")

    # 被撤销的会话：访问令牌立即失效，刷新令牌也不可用
    with pytest.raises(SessionRevoked):
        env.service.authenticate_access_token(p1.access_token)
    with pytest.raises(SessionRevoked):
        env.service.refresh(p1.refresh_token)

    # 另一个会话不受影响
    assert env.service.authenticate_access_token(p2.access_token)["session_id"] == sid2


def test_revoke_all_user_sessions(env):
    pairs = [env.service.login("bob", "bob123") for _ in range(3)]
    revoked = env.service.revoke_all_user_sessions("u_bob")
    assert len(revoked) == 3

    for pair in pairs:
        with pytest.raises(SessionRevoked):
            env.service.authenticate_access_token(pair.access_token)
        with pytest.raises(SessionRevoked):
            env.service.refresh(pair.refresh_token)

    # 撤销之后新登录的会话是干净的，不受历史撤销影响
    fresh = env.service.login("bob", "bob123")
    assert env.service.authenticate_access_token(fresh.access_token)


def test_revoke_all_does_not_touch_other_users(env):
    bob = env.service.login("bob", "bob123")
    alice = env.service.login("viewer", "viewer123")
    env.service.revoke_all_user_sessions("u_bob")
    with pytest.raises(SessionRevoked):
        env.service.authenticate_access_token(bob.access_token)
    # 其他用户会话仍然有效
    assert env.service.authenticate_access_token(alice.access_token)


def test_http_revoke_own_and_admin_revoke_others(env):
    # 用户撤销自己的会话
    pair = env.service.login("bob", "bob123")
    sid = env.service.authenticate_access_token(pair.access_token)["session_id"]
    r = env.client.delete(f"/sessions/{sid}",
                          headers=auth(env.client, pair.access_token))
    assert r.status_code == 200
    assert env.client.get("/docs",
                          headers=auth(env.client, pair.access_token)).status_code == 401

    # bob 不能撤销别人的会话；admin 可以
    victim = env.service.login("viewer", "viewer123")
    victim_sid = env.service.authenticate_access_token(
        victim.access_token)["session_id"]
    attacker = env.service.login("bob", "bob123")
    r = env.client.delete(f"/sessions/{victim_sid}",
                          headers=auth(env.client, attacker.access_token))
    assert r.status_code == 403

    admin = env.service.login("admin", "admin123")
    r = env.client.post("/admin/users/u_viewer/revoke-sessions",
                        headers=auth(env.client, admin.access_token))
    assert r.status_code == 200 and victim_sid in r.json()["revoked_session_ids"]
    assert env.client.get("/docs",
                          headers=auth(env.client, victim.access_token)).status_code == 401


def test_logout_revokes_current_session(env):
    pair = env.service.login("bob", "bob123")
    r = env.client.post("/auth/logout",
                        headers=auth(env.client, pair.access_token))
    assert r.status_code == 200
    assert env.client.get("/docs",
                          headers=auth(env.client, pair.access_token)).status_code == 401


def test_consistent_conclusion_across_service_and_http(env):
    """同一会话撤销后，服务层与各个 HTTP 入口结论一致：都是 401 session_revoked。"""
    pair = env.service.login("bob", "bob123")
    sid = env.service.authenticate_access_token(pair.access_token)["session_id"]
    env.service.revoke_session(sid)

    with pytest.raises(SessionRevoked):
        env.service.require_permission(pair.access_token, "doc:read")

    for path, method in (("/docs", "get"), ("/me", "get"), ("/sessions", "get")):
        resp = getattr(env.client, method)(
            path, headers=auth(env.client, pair.access_token))
        assert resp.status_code == 401, (path, resp.text)
        assert resp.json()["error"]["code"] == "session_revoked", path

    resp = env.client.post("/auth/refresh",
                           json={"refresh_token": pair.refresh_token})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "session_revoked"

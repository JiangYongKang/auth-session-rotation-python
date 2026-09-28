"""HTTP 入口测试：状态码与错误码在 HTTP 层与服务层保持一致。"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from authapp import create_app
from authapp.audit import AuditLog
from authapp.clock import FixedClock
from authapp.service import AuthService

logger = logging.getLogger("auth-tests")


@pytest.fixture
def client():
    # 不写文件，全部事件保留在内存审计日志里
    app = create_app(audit_path=None)
    # 换成固定时钟，方便构造过期请求
    clock = FixedClock(start=2_000_000.0)
    old = app.state.auth_service
    app.state.auth_service = AuthService(
        store=app.state.store,
        audit=app.state.audit,
        secret=old.secret,
        clock=clock,
        access_ttl=300,
        refresh_ttl=600,
        clock_skew_tolerance=30,
    )
    return TestClient(app), clock, app.state.auth_service, app.state.audit


def _login(c, username="alice", password="password123"):
    r = c.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def test_health(client):
    c, *_ = client
    assert c.get("/health").json() == {"status": "ok"}


def test_login_and_me(client):
    c, _, svc, audit = client
    tokens = _login(c)
    r = c.get("/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 200
    body = r.json()
    assert body["user_id"] == "u_alice"
    assert "article:write" in body["permissions"]


def test_not_authenticated_vs_forbidden_are_distinct(client):
    c, *_ = client
    # 未携带令牌 => 401 not_authenticated
    r1 = c.get("/articles")
    assert r1.status_code == 401
    assert r1.json()["error"]["code"] == "not_authenticated"

    # viewer 已登录但权限不足 => 403 permission_denied
    tokens = _login(c, "carol")
    r2 = c.post("/articles", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r2.status_code == 403
    body = r2.json()["error"]
    assert body["code"] == "permission_denied"
    logger.info("权限不足判定依据: %s", body)


def test_malformed_authorization_header_is_unauthenticated(client):
    c, *_ = client
    r = c.get("/articles", headers={"Authorization": "Basic abc"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "not_authenticated"


def test_refresh_reuse_over_http_revokes_session(client):
    c, _, _, audit = client
    tokens = _login(c)
    r1 = c.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r1.status_code == 200

    r2 = c.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r2.status_code == 401
    assert r2.json()["error"]["code"] == "refresh_token_reused"

    # 会话已撤销：新刷新令牌与访问令牌都不能再用
    new_tokens = r1.json()
    r3 = c.post("/auth/refresh", json={"refresh_token": new_tokens["refresh_token"]})
    assert r3.status_code == 401
    assert r3.json()["error"]["code"] == "session_revoked"

    r4 = c.get("/articles", headers={"Authorization": f"Bearer {new_tokens['access_token']}"})
    assert r4.status_code == 401
    assert r4.json()["error"]["code"] == "session_revoked"

    assert audit.names().count("refresh_success") == 1


def test_expired_and_tampered_tokens_distinct_codes(client):
    c, clock, _, _ = client
    tokens = _login(c)

    clock.advance(301)
    r = c.get("/articles", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "token_expired"

    tampered = tokens["access_token"].rsplit(".", 1)[0] + ".AAAA"
    r2 = c.get("/articles", headers={"Authorization": f"Bearer {tampered}"})
    assert r2.status_code == 401
    assert r2.json()["error"]["code"] == "token_invalid"


def test_role_change_consistent_across_entries(client):
    """同一请求在服务层入口与 HTTP 入口的结论必须一致，且随角色实时变化。"""
    c, _, svc, _ = client
    tokens = _login(c, "carol")  # viewer
    at = tokens["access_token"]

    # HTTP 与服务层：都拒绝写
    assert c.post("/articles", headers={"Authorization": f"Bearer {at}"}).status_code == 403
    from authapp.errors import PermissionDenied

    with pytest.raises(PermissionDenied):
        svc.require_permission(at, "article:write")

    # 管理员通过 HTTP 提升 carol 为 editor
    admin = _login(c, "alice")
    r = c.post(
        "/admin/users/u_carol/roles",
        json={"roles": ["editor"]},
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert r.status_code == 200

    # 同一个旧令牌：两个入口都立刻放行
    assert c.post("/articles", headers={"Authorization": f"Bearer {at}"}).status_code == 200
    assert svc.require_permission(at, "article:write").user_id == "u_carol"


def test_revoke_single_and_all_sessions_over_http(client):
    c, *_ = client
    admin = _login(c, "alice")
    s1 = _login(c, "bob")
    s2 = _login(c, "bob")

    headers = {"Authorization": f"Bearer {admin['access_token']}"}

    r = c.post("/admin/sessions/revoke", json={"session_id": s1["session_id"]}, headers=headers)
    assert r.status_code == 200
    assert c.get("/articles", headers={"Authorization": f"Bearer {s1['access_token']}"}).status_code == 401
    assert c.get("/articles", headers={"Authorization": f"Bearer {s2['access_token']}"}).status_code == 200

    r2 = c.post(
        "/admin/users/revoke-sessions",
        json={"user_id": "u_bob", "reason": "cleanup"},
        headers=headers,
    )
    assert r2.status_code == 200
    assert r2.json()["revoked"] == 1
    assert c.get("/articles", headers={"Authorization": f"Bearer {s2['access_token']}"}).status_code == 401


def test_admin_endpoints_require_permission(client):
    c, *_ = client
    bob = _login(c, "bob")  # editor，没有 session:revoke
    r = c.post(
        "/admin/sessions/revoke",
        json={"session_id": "x"},
        headers={"Authorization": f"Bearer {bob['access_token']}"},
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "permission_denied"

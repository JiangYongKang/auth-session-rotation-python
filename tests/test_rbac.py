"""未登录 vs 权限不足的区分，以及角色/权限变更对已签发会话即时生效。"""

from __future__ import annotations

import pytest

from auth_app.errors import NotAuthenticated, PermissionDenied


def auth(client, token):
    return {"Authorization": f"Bearer {token}"}


def test_unauthenticated_and_forbidden_are_distinct(env):
    # 1) 完全未登录 -> 401 not_authenticated
    r = env.client.post("/docs")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "not_authenticated"

    # 2) 非法令牌 -> 401 token_tampered（仍是认证问题，不是权限问题）
    r = env.client.post("/docs", headers=auth(env.client, "garbage"))
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "token_tampered"

    # 3) 已登录的 viewer 尝试写 -> 403 permission_denied
    pair = env.service.login("viewer", "viewer123")
    r = env.client.post("/docs", headers=auth(env.client, pair.access_token))
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "permission_denied"
    # 判定依据：审计日志记录了所需权限与实际拥有的权限
    denied = [e for e in env.service.audit.entries()
              if e["event"] == "permission_denied"][-1]
    assert denied["required"] == "doc:write"
    assert "doc:read" in denied["granted"]


def test_role_escalation_takes_effect_immediately_on_existing_session(env):
    pair = env.service.login("viewer", "viewer123")
    token = pair.access_token

    # 变更前：写被拒绝（同一张令牌）
    with pytest.raises(PermissionDenied):
        env.service.require_permission(token, "doc:write")

    # 管理员实时把 viewer 提升为 editor
    admin = env.service.login("admin", "admin123")
    r = env.client.post(
        "/admin/users/u_viewer/roles",
        headers=auth(env.client, admin.access_token),
        json={"add_roles": ["editor"]})
    assert r.status_code == 200

    # 变更后：同一张已签发的访问令牌立即可以写 —— 无需重新登录
    identity = env.service.require_permission(token, "doc:write")
    assert identity["user_id"] == "u_viewer"
    assert env.client.post("/docs", headers=auth(env.client, token)).status_code == 200


def test_role_demotion_takes_effect_immediately(env):
    pair = env.service.login("editor", "editor123")
    token = pair.access_token
    assert env.service.require_permission(token, "doc:write")

    editor_user = env.service.store.get_user("u_editor")
    editor_user.roles.discard("editor")
    editor_user.roles.add("viewer")

    with pytest.raises(PermissionDenied):
        env.service.require_permission(token, "doc:write")


def test_extra_permission_grant_and_revoke(env):
    pair = env.service.login("bob", "bob123")
    token = pair.access_token
    with pytest.raises(PermissionDenied):
        env.service.require_permission(token, "doc:write")

    bob = env.service.store.get_user("u_bob")
    bob.permissions.add("doc:write")  # 直接授予单个权限
    assert env.service.require_permission(token, "doc:write")

    bob.permissions.discard("doc:write")
    with pytest.raises(PermissionDenied):
        env.service.require_permission(token, "doc:write")


def test_deactivated_user_is_rejected_everywhere(env):
    pair = env.service.login("bob", "bob123")
    token = pair.access_token
    assert env.service.require_permission(token, "doc:read")

    env.service.store.get_user("u_bob").active = False
    with pytest.raises(NotAuthenticated):
        env.service.require_authentication(token)
    r = env.client.get("/docs", headers=auth(env.client, token))
    assert r.status_code == 401


def test_admin_only_endpoints_reject_non_admin(env):
    pair = env.service.login("editor", "editor123")
    r = env.client.post("/admin/users/u_bob/revoke-sessions",
                        headers=auth(env.client, pair.access_token))
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "permission_denied"

"""服务层核心行为测试：所有入口共享的判定结论。"""

from __future__ import annotations

import logging

import pytest

from authapp.errors import (
    InvalidCredentials,
    NotAuthenticated,
    PermissionDenied,
    RefreshTokenReused,
    SessionRevoked,
    TokenClockSkew,
    TokenExpired,
    TokenInvalid,
    UserDisabled,
)
from authapp.security import decode_token

logger = logging.getLogger("auth-tests")


# ---------------- 登录 ----------------
def test_login_issues_token_pair(service):
    pair = service.login("alice", "password123")
    assert pair.access_token and pair.refresh_token
    assert pair.session_id.startswith("sess_")
    claims = decode_token(pair.access_token, service.secret)
    assert claims["sub"] == "u_alice"
    assert claims["sid"] == pair.session_id
    assert claims["typ"] == "access"
    assert [e.name for e in service.audit.events()].count("login_success") == 1


def test_login_wrong_password(service):
    with pytest.raises(InvalidCredentials) as exc:
        service.login("alice", "nope")
    assert exc.value.code == "invalid_credentials"


def test_login_disabled_user(service):
    with pytest.raises(UserDisabled) as exc:
        service.login("dave", "password123")
    assert exc.value.code == "user_disabled"


# ---------------- 刷新令牌轮换与重用 ----------------
def test_refresh_rotates_and_old_token_is_dead(service, clock):
    pair = service.login("alice", "password123")
    new_pair = service.refresh(pair.refresh_token)
    assert new_pair.refresh_token != pair.refresh_token
    assert new_pair.session_id == pair.session_id

    # 旧刷新令牌第二次出现 => 重用 => 撤销整条会话
    with pytest.raises(RefreshTokenReused) as exc:
        service.refresh(pair.refresh_token)
    assert exc.value.code == "refresh_token_reused"

    session = service.store.get_session(pair.session_id)
    assert session.revoked is True
    assert session.revoke_reason == "refresh_token_reuse"

    # 刚轮换出的新刷新令牌也必须立即失效
    with pytest.raises(SessionRevoked):
        service.refresh(new_pair.refresh_token)

    names = service.audit.names()
    assert names.count("refresh_success") == 1
    reused_fail = next(
        e for e in service.audit.events()
        if e.name == "refresh_failed" and e.detail["reason"] == "reused"
    )
    logger.info("重用判定依据: %s", reused_fail.detail)
    assert reused_fail.detail["decision"] == "revoke_entire_session"


def test_reuse_detection_is_stable_across_repeated_calls(service):
    """同一个被重用的令牌无论出现多少次，结论稳定：重用 + 会话已撤销。"""
    pair = service.login("bob", "password123")
    service.refresh(pair.refresh_token)

    for _ in range(3):
        with pytest.raises(RefreshTokenReused):
            service.refresh(pair.refresh_token)
    # 只成功轮换过一次
    assert service.audit.names().count("refresh_success") == 1


def test_normal_rotation_chain(service, clock):
    pair = service.login("alice", "password123")
    current_rt = pair.refresh_token
    for _ in range(4):
        pair = service.refresh(current_rt)
        current_rt = pair.refresh_token
        clock.advance(10)
    assert service.audit.names().count("refresh_success") == 4


# ---------------- 过期 / 篡改 / 时钟偏差 ----------------
def test_expired_access_token(service, clock):
    pair = service.login("alice", "password123")
    clock.advance(service.access_ttl + 1)
    with pytest.raises(TokenExpired) as exc:
        service.authenticate(pair.access_token)
    assert exc.value.code == "token_expired"


def test_expired_refresh_token(service, clock):
    pair = service.login("alice", "password123")
    clock.advance(service.refresh_ttl + 1)
    with pytest.raises(TokenExpired) as exc:
        service.refresh(pair.refresh_token)
    assert exc.value.code == "token_expired"
    # 单纯过期不应撤销会话，用户重新登录不受影响
    assert service.store.get_session(pair.session_id).revoked is False


def test_tampered_access_token(service):
    pair = service.login("alice", "password123")
    header, payload, signature = pair.access_token.split(".")
    from authapp.security import b64url_encode

    tampered = f"{header}.{b64url_encode(b'{\"typ\":\"access\"}')}.{signature}"
    with pytest.raises(TokenInvalid) as exc:
        service.authenticate(tampered)
    assert exc.value.code == "token_invalid"


def test_wrong_type_token_rejected(service):
    pair = service.login("alice", "password123")
    # 拿刷新令牌当访问令牌用
    with pytest.raises(TokenInvalid):
        service.authenticate(pair.refresh_token)
    # 拿访问令牌去刷新
    with pytest.raises(TokenInvalid):
        service.refresh(pair.access_token)


def test_clock_skew_detected(service, clock):
    """服务端时钟远早于令牌签发时间 => 可区分的时钟偏差错误。"""
    pair = service.login("alice", "password123")
    clock.set(clock.now() - service.skew_tolerance - 120)
    with pytest.raises(TokenClockSkew) as exc:
        service.authenticate(pair.access_token)
    assert exc.value.code == "token_clock_skew"
    with pytest.raises(TokenClockSkew):
        service.refresh(pair.refresh_token)


def test_clock_skew_within_tolerance_ok(service, clock):
    pair = service.login("alice", "password123")
    clock.advance(-service.skew_tolerance + 5)
    claims = service.authenticate(pair.access_token)
    assert claims.user_id == "u_alice"


# ---------------- 权限模型与实时生效 ----------------
def test_permission_allow_and_deny(service):
    alice = service.login("alice", "password123")
    carol = service.login("carol", "password123")

    assert service.require_permission(alice.access_token, "article:write")
    with pytest.raises(PermissionDenied) as exc:
        service.require_permission(carol.access_token, "article:write")
    assert exc.value.code == "permission_denied"
    # 拥有的权限仍然通过
    assert service.require_permission(carol.access_token, "article:read")


def test_permission_change_takes_effect_on_existing_session(service):
    """角色变化后，已签发会话的访问结论必须立刻改变，且各入口一致。"""
    pair = service.login("carol", "password123")  # viewer

    # 变更前：不能写
    with pytest.raises(PermissionDenied):
        service.require_permission(pair.access_token, "article:write")

    # 管理员把 carol 提升为 editor（令牌本身不变）
    user = service.store.get_user("u_carol")
    user.roles = ["editor"]

    # 变更后：同一个访问令牌立刻可写
    claims = service.require_permission(pair.access_token, "article:write")
    assert claims.user_id == "u_carol"

    # 再降回 viewer，立即失去写权限
    user.roles = ["viewer"]
    with pytest.raises(PermissionDenied):
        service.require_permission(pair.access_token, "article:write")


def test_disabling_user_revokes_access_effect(service):
    """用户被停用后，既有会话立即不能访问（语义：禁用即时生效）。"""
    pair = service.login("carol", "password123")
    service.require_permission(pair.access_token, "article:read")

    user = service.store.get_user("u_carol")
    user.enabled = False
    with pytest.raises(UserDisabled):
        service.authenticate(pair.access_token)


# ---------------- 会话撤销 ----------------
def test_revoke_single_session(service):
    p1 = service.login("alice", "password123")
    p2 = service.login("alice", "password123")  # 同用户另一条会话

    service.revoke_session(p1.session_id)
    with pytest.raises(SessionRevoked):
        service.authenticate(p1.access_token)
    with pytest.raises(SessionRevoked):
        service.refresh(p1.refresh_token)

    # 另一条会话不受影响
    assert service.authenticate(p2.access_token).session_id == p2.session_id


def test_revoke_all_user_sessions(service):
    p1 = service.login("alice", "password123")
    p2 = service.login("alice", "password123")
    bob = service.login("bob", "password123")

    count = service.revoke_all_user_sessions("u_alice")
    assert count == 2
    for p in (p1, p2):
        with pytest.raises(SessionRevoked):
            service.authenticate(p.access_token)
    # 其他用户不受影响
    assert service.authenticate(bob.access_token).user_id == "u_bob"


def test_revoke_all_is_idempotent(service):
    service.login("alice", "password123")
    assert service.revoke_all_user_sessions("u_alice") == 1
    assert service.revoke_all_user_sessions("u_alice") == 0


def test_audit_records_key_events(service):
    pair = service.login("alice", "password123")
    service.refresh(pair.refresh_token)
    with pytest.raises(RefreshTokenReused):
        service.refresh(pair.refresh_token)
    service.revoke_all_user_sessions("u_alice", reason="test")

    names = service.audit.names()
    for expected in [
        "login_success",
        "refresh_success",
        "refresh_failed",
        "session_revoked",
        "all_sessions_revoked",
    ]:
        assert expected in names, f"缺少事件 {expected}: {names}"

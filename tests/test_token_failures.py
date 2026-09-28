"""令牌过期 / 篡改 / 时钟偏差：失败原因必须可区分且稳定。"""

from __future__ import annotations

import base64
import json

import pytest

from auth_app import tokens as token_module
from auth_app.errors import ClockSkew, TokenExpired, TokenTampered


def test_access_token_expired_is_distinct(env):
    pair = env.service.login("viewer", "viewer123")
    env.service.clock.advance(env.settings.access_token_ttl + 1)
    with pytest.raises(TokenExpired):
        env.service.authenticate_access_token(pair.access_token)

    r = env.client.get("/docs",
                       headers={"Authorization": f"Bearer {pair.access_token}"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "token_expired"


def test_refresh_token_expired_is_distinct(env):
    pair = env.service.login("viewer", "viewer123")
    env.service.clock.advance(env.settings.refresh_token_ttl + 1)
    with pytest.raises(TokenExpired):
        env.service.refresh(pair.refresh_token)
    r = env.client.post("/auth/refresh",
                        json={"refresh_token": pair.refresh_token})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "token_expired"


def test_tampered_signature_is_distinct(env):
    pair = env.service.login("viewer", "viewer123")
    tampered = pair.access_token[:-3] + ("AAA" if pair.access_token[-3:] != "AAA" else "BBB")
    with pytest.raises(TokenTampered):
        env.service.authenticate_access_token(tampered)

    r = env.client.get("/docs", headers={"Authorization": f"Bearer {tampered}"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "token_tampered"


def test_malformed_token_shapes_are_tampered(env):
    for bad in ["", "not-a-jwt-like-token", "abc", "abc.def.ghi", "abc.", ".sig"]:
        with pytest.raises(TokenTampered):
            token_module.verify_token(bad, env.settings, env.service.clock,
                                      expected_type="access")


def test_token_signed_with_other_key_is_tampered(env):
    pair = token_module.issue_token_pair(
        "u_viewer", "sess-x", {"viewer"}, set(), "j1",
        env.settings, env.service.clock)
    other = type(env.settings)(signing_key="a-completely-different-key",
                               access_token_ttl=60, refresh_token_ttl=300,
                               clock_skew_leeway=0,
                               audit_log_path=env.audit_path, seed_users=False)
    with pytest.raises(TokenTampered):
        token_module.verify_token(pair.access_token, other, env.service.clock,
                                  expected_type="access")


def test_payload_modification_is_tampered(env):
    """修改 payload 但保留原签名 => 签名不匹配 => 篡改。"""
    pair = env.service.login("viewer", "viewer123")
    payload_b64, sig = pair.access_token.split(".")
    raw = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    raw["sub"] = "u_admin"  # 试图提权
    new_payload = base64.urlsafe_b64encode(
        json.dumps(raw, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=").decode()
    forged = f"{new_payload}.{sig}"
    with pytest.raises(TokenTampered):
        env.service.authenticate_access_token(forged)


def test_future_iat_is_clock_skew(env):
    # 用“正常时钟”签发，然后把服务时钟往回拨 => 令牌 iat 来自未来。
    pair = token_module.issue_token_pair(
        "u_viewer", "sess-x", set(), set(), "future-jti",
        env.settings, env.service.clock)
    env.service.clock.set_offset(-3600)
    with pytest.raises(ClockSkew) as exc:
        token_module.verify_token(pair.access_token, env.settings,
                                  env.service.clock, expected_type="access")
    assert exc.value.detail["iat"] > exc.value.detail["now"]

    r = env.client.get("/docs",
                       headers={"Authorization": f"Bearer {pair.access_token}"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "clock_skew"


def test_same_input_gives_same_result_repeatedly(env):
    """同一坏令牌重复判定 N 次，结论与错误码保持稳定。"""
    pair = env.service.login("viewer", "viewer123")
    env.service.clock.advance(env.settings.access_token_ttl + 1)
    for _ in range(5):
        with pytest.raises(TokenExpired):
            env.service.authenticate_access_token(pair.access_token)

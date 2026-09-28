"""审计事件落盘：关键认证/撤销事件必须可追溯、含判定依据。"""

from __future__ import annotations

import json

import pytest

from auth_app.errors import RefreshTokenReused


def auth(client, token):
    return {"Authorization": f"Bearer {token}"}


def test_audit_events_persisted_as_jsonl_with_reasons(env):
    pair = env.service.login("bob", "bob123")
    env.client.get("/docs", headers=auth(env.client, pair.access_token))
    env.client.post("/docs", headers=auth(env.client, pair.access_token))  # 403
    env.service.refresh(pair.refresh_token)
    with pytest.raises(RefreshTokenReused):
        env.service.refresh(pair.refresh_token)  # 重放

    with open(env.audit_path, encoding="utf-8") as fh:
        lines = [json.loads(line) for line in fh if line.strip()]

    events = {e["event"] for e in lines}
    assert "login_ok" in events
    assert "access_granted" in events
    assert "permission_denied" in events
    assert "refresh_rotated" in events
    assert "refresh_token_reuse_detected" in events

    # 每条事件都有时间戳；关键拒绝事件带判定依据
    assert all("ts" in e for e in lines)
    denied = [e for e in lines if e["event"] == "permission_denied"][0]
    assert denied["required"] == "doc:write"
    assert "granted" in denied

    reuse = [e for e in lines if e["event"] == "refresh_token_reuse_detected"][0]
    assert reuse["action"] == "whole_session_revoked"
    assert reuse["session_id"]


def test_revocation_events_are_logged(env):
    admin = env.service.login("admin", "admin123")
    bob = env.service.login("bob", "bob123")
    sid = env.service.authenticate_access_token(bob.access_token)["session_id"]
    env.client.post("/admin/users/u_bob/revoke-sessions",
                    headers=auth(env.client, admin.access_token))

    events = env.service.audit.entries()
    revoked = [e for e in events if e["event"] == "user_all_sessions_revoked"]
    assert len(revoked) == 1
    assert sid in revoked[0]["session_ids"]

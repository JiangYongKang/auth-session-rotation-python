"""pytest 公共夹具：隔离的临时服务实例与事件日志。

每个测试使用独立临时目录的审计日志，互不污染；测试结束后打印
本次产生的关键事件与判定依据（满足“单测日志打印关键事件”的要求）。
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from auth_app.api import create_app
from auth_app.bootstrap import build_service
from auth_app.config import Settings
from auth_app.models import User
from auth_app.security import hash_password
from auth_app.service import AuthService


@dataclass
class Env:
    service: AuthService
    client: TestClient
    audit_path: str
    settings: Settings


def _make_user(service: AuthService, user_id: str, username: str,
               password: str, roles=None, permissions=None) -> None:
    service.store.upsert_user(User(
        user_id=user_id, username=username,
        password_hash=hash_password(password),
        roles=set(roles or []), permissions=set(permissions or []),
    ))


@pytest.fixture
def env(tmp_path):
    audit_path = str(tmp_path / "audit.log.jsonl")
    # 短 TTL 便于测试过期；leeway=0 让过期边界精确。
    settings = Settings(
        signing_key="test-signing-key",
        access_token_ttl=60,
        refresh_token_ttl=300,
        clock_skew_leeway=0,
        audit_log_path=audit_path,
        seed_users=False,
    )
    service = build_service(settings)
    _make_user(service, "u_admin", "admin", "admin123", roles={"admin"})
    _make_user(service, "u_editor", "editor", "editor123", roles={"editor"})
    _make_user(service, "u_viewer", "viewer", "viewer123", roles={"viewer"})
    _make_user(service, "u_bob", "bob", "bob123", roles={"viewer"})
    client = TestClient(create_app(service))
    bench = Env(service=service, client=client, audit_path=audit_path,
                settings=settings)
    bench.make_user = lambda **kw: _make_user(service, **kw)  # type: ignore[attr-defined]
    yield bench

    # ---- 打印本次测试的关键审计事件与判定依据 ----
    events = service.audit.entries()
    print("\n================ 审计事件（判定依据） ================")
    for entry in events:
        print(json.dumps(entry, ensure_ascii=False, sort_keys=True))
    print(f"================ 共 {len(events)} 条事件 ================\n")

"""装配依赖并播种本地演示用户（无外部服务、无真实凭据）。"""

from __future__ import annotations

from .audit import AuditLogger
from .clock import Clock
from .config import Settings, get_settings
from .models import User
from .security import hash_password
from .service import AuthService
from .store import Store

# 演示用户：密码仅用于本地验证，非真实凭据。
SEED_USERS = [
    ("u_admin", "admin", "admin123", {"admin"}, set()),
    ("u_editor", "editor", "editor123", {"editor"}, set()),
    ("u_viewer", "viewer", "viewer123", {"viewer"}, set()),
]


def build_service(settings: Settings | None = None) -> AuthService:
    settings = settings or get_settings()
    store = Store()
    clock = Clock()
    audit = AuditLogger(settings.audit_log_path, clock)
    service = AuthService(store, settings, clock, audit)
    if settings.seed_users:
        for user_id, username, password, roles, perms in SEED_USERS:
            store.upsert_user(User(
                user_id=user_id, username=username,
                password_hash=hash_password(password),
                roles=set(roles), permissions=set(perms),
            ))
        audit.log("seed_users_loaded", count=len(SEED_USERS))
    return service

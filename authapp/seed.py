"""本地演示数据：角色、用户。

角色与权限：
- admin    -> {article:read, article:write, user:manage, session:revoke}
- editor   -> {article:read, article:write}
- viewer   -> {article:read}

演示账号（明文密码仅用于本地，存储的是 PBKDF2 哈希）：
- alice / password123  角色 admin
- bob   / password123  角色 editor
- carol / password123  角色 viewer
- dave  / password123  角色 viewer 且处于停用状态
"""

from __future__ import annotations

from .models import Role, User
from .security import hash_password
from .store import Store

_PERMISSIONS = {
    "admin": frozenset(
        {"article:read", "article:write", "user:manage", "session:revoke"}
    ),
    "editor": frozenset({"article:read", "article:write"}),
    "viewer": frozenset({"article:read"}),
}

_USERS = [
    ("u_alice", "alice", "password123", ["admin"], True),
    ("u_bob", "bob", "password123", ["editor"], True),
    ("u_carol", "carol", "password123", ["viewer"], True),
    ("u_dave", "dave", "password123", ["viewer"], False),
]


def build_seed_store() -> Store:
    store = Store()
    for name, perms in _PERMISSIONS.items():
        store.add_role(Role(name=name, permissions=perms))
    for user_id, username, password, roles, enabled in _USERS:
        store.add_user(
            User(
                id=user_id,
                username=username,
                password_hash=hash_password(password),
                roles=roles,
                enabled=enabled,
            )
        )
    return store

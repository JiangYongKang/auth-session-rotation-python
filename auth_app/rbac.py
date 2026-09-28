"""基于角色与权限的访问控制。

判定原则（保证“同一请求在不同入口结论一致”）：

1. 访问令牌只用于证明“是谁”（sub/sid），令牌内的 rol/perm 仅为
   签发时快照，**不参与授权判定**；
2. 每次权限校验都实时读取 Store 中用户当前的 roles / permissions，
   因此管理员调整角色或权限后，该用户所有已签发会话立刻按新语义生效；
3. 用户被停用（active=False）立即失去所有权限。
"""

from __future__ import annotations

from .models import User
from .store import Store

# 角色 -> 权限集合的静态映射
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {"doc:read", "doc:write", "doc:delete", "session:manage", "user:manage"},
    "editor": {"doc:read", "doc:write"},
    "viewer": {"doc:read"},
}


def role_permissions(role: str) -> set[str]:
    return set(ROLE_PERMISSIONS.get(role, set()))


def effective_permissions(user_roles: set[str], extra: set[str]) -> set[str]:
    """用户有效权限 = 各角色权限的并集 ∪ 单独授予的权限。"""
    result: set[str] = set()
    for role in user_roles:
        result |= role_permissions(role)
    result |= set(extra)
    return result


def get_live_user(store: Store, user_id: str) -> User | None:
    return store.get_user(user_id)


def user_has_permission(store: Store, user_id: str, permission: str) -> bool:
    user = get_live_user(store, user_id)
    if user is None or not user.active:
        return False
    return permission in effective_permissions(user.roles, user.permissions)

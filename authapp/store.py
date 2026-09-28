"""内存态存储：用户/角色/会话，外加一把全局锁保证并发安全。

关键不变量（服务层在同一把锁内完成"读-判定-写"）：
- 同一个刷新令牌并发刷新，只有一个请求成功；
- 会话撤销对所有入口立即生效。

权限不做令牌内快照，每次访问都基于这里的实时角色聚合，
所以角色/权限变化对已签发会话立即生效。
"""

from __future__ import annotations

import threading

from .models import Role, Session, User


class Store:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.users: dict[str, User] = {}
        self.roles: dict[str, Role] = {}
        self.sessions: dict[str, Session] = {}
        # refresh_token_id -> session_id，快速定位令牌归属
        self.refresh_index: dict[str, str] = {}

    # ---- 用户与角色 ----
    def add_user(self, user: User) -> None:
        with self.lock:
            self.users[user.id] = user

    def get_user(self, user_id: str) -> User | None:
        with self.lock:
            return self.users.get(user_id)

    def get_user_by_username(self, username: str) -> User | None:
        with self.lock:
            for user in self.users.values():
                if user.username == username:
                    return user
            return None

    def add_role(self, role: Role) -> None:
        with self.lock:
            self.roles[role.name] = role

    def effective_permissions(self, user: User) -> frozenset[str]:
        """实时聚合用户当前角色对应的权限。"""
        with self.lock:
            result: set[str] = set()
            for role_name in user.roles:
                role = self.roles.get(role_name)
                if role is not None:
                    result.update(role.permissions)
            return frozenset(result)

    # ---- 会话 ----
    def save_session(self, session: Session) -> None:
        with self.lock:
            self.sessions[session.id] = session

    def get_session(self, session_id: str) -> Session | None:
        with self.lock:
            return self.sessions.get(session_id)

    def list_sessions_for_user(self, user_id: str) -> list[Session]:
        with self.lock:
            return [s for s in self.sessions.values() if s.user_id == user_id]

"""领域模型：用户、会话、刷新令牌记录。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class User:
    user_id: str
    username: str
    password_hash: str
    roles: set[str] = field(default_factory=set)
    permissions: set[str] = field(default_factory=set)
    active: bool = True


@dataclass
class Session:
    session_id: str
    user_id: str
    created_at: float
    revoked: bool = False
    revoke_reason: str | None = None
    revoked_at: float | None = None


@dataclass
class RefreshTokenRecord:
    """刷新令牌在服务端的状态记录（只存哈希，不存明文）。"""

    jti: str
    session_id: str
    user_id: str
    token_hash: str
    issued_at: float
    expires_at: float
    used: bool = False
    used_at: float | None = None
    revoked: bool = False
    parent_jti: str | None = None
    # 重放痕迹保留截止时刻：在此之前（含过期后）记录都不得回收，
    # 保证过期的轮换旧令牌仍能被判定为重放。
    retain_until: float = 0.0


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"

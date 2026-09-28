"""领域模型：用户、角色、会话与认证结果。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Role:
    name: str
    permissions: frozenset[str] = frozenset()


@dataclass
class User:
    id: str
    username: str
    password_hash: str
    roles: list[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class RefreshTokenState:
    """刷新令牌的服务端状态（每次轮换都会产生一条新状态）。"""

    token_id: str
    issued_at: float
    expires_at: float
    used: bool = False
    revoked: bool = False
    next_token_id: str | None = None


@dataclass
class Session:
    """一条登录会话。会话撤销语义针对整条记录。"""

    id: str
    user_id: str
    created_at: float
    revoked: bool = False
    revoke_reason: str | None = None
    refresh_tokens: dict[str, RefreshTokenState] = field(default_factory=dict)
    current_refresh_token_id: str | None = None


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_in: int
    refresh_expires_in: int
    session_id: str
    token_id: str


@dataclass
class AccessClaims:
    user_id: str
    session_id: str
    token_id: str
    issued_at: float
    expires_at: float


@dataclass
class RefreshClaims:
    user_id: str
    session_id: str
    token_id: str
    issued_at: float
    expires_at: float

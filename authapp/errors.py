"""认证与访问控制的错误类型。

每一种失败都有独立的 ``code``，HTTP 层与服务层共用同一套判定结果，
保证不同入口下"同样的输入 -> 同样的结论与原因"。
"""

from __future__ import annotations


class AuthError(Exception):
    """所有认证/授权错误的基类。"""

    code: str = "auth_error"
    http_status: int = 401

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.code)
        self.message = message or self.code


class InvalidCredentials(AuthError):
    code = "invalid_credentials"
    http_status = 401


class TokenExpired(AuthError):
    code = "token_expired"
    http_status = 401


class TokenInvalid(AuthError):
    """签名错误、格式错误、被篡改等。"""

    code = "token_invalid"
    http_status = 401


class TokenClockSkew(AuthError):
    """令牌来自"未来"，时钟偏差超出可接受范围。"""

    code = "token_clock_skew"
    http_status = 401


class RefreshTokenReused(AuthError):
    """刷新令牌已被使用过却再次出现 => 判定为重用，整条会话撤销。"""

    code = "refresh_token_reused"
    http_status = 401


class SessionRevoked(AuthError):
    code = "session_revoked"
    http_status = 401


class SessionNotFound(AuthError):
    code = "session_not_found"
    http_status = 401


class UserNotFound(AuthError):
    code = "user_not_found"
    http_status = 401


class UserDisabled(AuthError):
    code = "user_disabled"
    http_status = 403


class NotAuthenticated(AuthError):
    """入口上没有携带任何令牌（区别于权限不足）。"""

    code = "not_authenticated"
    http_status = 401


class PermissionDenied(AuthError):
    code = "permission_denied"
    http_status = 403

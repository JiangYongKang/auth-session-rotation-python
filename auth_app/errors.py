"""统一的认证/授权错误类型。

每种失败原因对应一个独立的异常子类，保证各入口（HTTP 接口、
Service 直接调用）得到的结论可区分、可解释。
"""


class AuthError(Exception):
    """所有认证授权错误的基类。"""

    code: str = "auth_error"
    status_code: int = 400
    message: str = "认证失败"

    def __init__(self, message: str | None = None, *, detail: dict | None = None):
        super().__init__(message or self.message)
        self.detail = detail or {}
        if message:
            self.message = message


class InvalidCredentials(AuthError):
    """用户名或密码错误。"""

    code = "invalid_credentials"
    status_code = 401
    message = "用户名或密码错误"


class TokenExpired(AuthError):
    """令牌已过期。"""

    code = "token_expired"
    status_code = 401
    message = "令牌已过期"


class TokenTampered(AuthError):
    """令牌签名无效或格式被篡改。"""

    code = "token_tampered"
    status_code = 401
    message = "令牌无效或已被篡改"


class ClockSkew(AuthError):
    """令牌时间声明存在明显时钟偏差（来自未来或过早签发）。"""

    code = "clock_skew"
    status_code = 401
    message = "检测到明显的时钟偏差"


class NotAuthenticated(AuthError):
    """请求未携带有效访问令牌。"""

    code = "not_authenticated"
    status_code = 401
    message = "未登录或缺少访问令牌"


class RefreshTokenReused(AuthError):
    """刷新令牌已被轮换/撤销后再次出现，判定为重放，整条会话已撤销。"""

    code = "refresh_token_reused"
    status_code = 401
    message = "检测到刷新令牌重用，会话已被撤销"


class RefreshTokenInvalid(AuthError):
    """刷新令牌签名有效但在服务端无记录（例如会话已被撤销后的非重放分支）。"""

    code = "refresh_token_invalid"
    status_code = 401
    message = "刷新令牌无效"


class SessionRevoked(AuthError):
    """会话已被撤销（单个撤销或用户级撤销）。"""

    code = "session_revoked"
    status_code = 401
    message = "会话已被撤销"


class PermissionDenied(AuthError):
    """已登录但角色/权限不足。"""

    code = "permission_denied"
    status_code = 403
    message = "权限不足"


class NotFound(AuthError):
    """目标资源（如会话）不存在。"""

    code = "not_found"
    status_code = 404
    message = "资源不存在"

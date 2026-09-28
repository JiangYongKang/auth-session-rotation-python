"""FastAPI 依赖：把 HTTP 请求交给统一的服务层判定。

判定全部委托 :class:`~authapp.service.AuthService`，
HTTP 入口与直接调用服务层得到完全一致的结论。
"""

from __future__ import annotations

from fastapi import Depends, Request

from .errors import NotAuthenticated
from .models import AccessClaims
from .service import AuthService


def get_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def get_access_token(request: Request) -> str | None:
    """从 Authorization: Bearer <token> 提取令牌；没有则 None。"""
    header = request.headers.get("Authorization") or request.headers.get(
        "authorization"
    )
    if not header:
        return None
    parts = header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        return None
    return parts[1].strip()


def current_claims(
    request: Request, service: AuthService = Depends(get_service)
) -> AccessClaims:
    """必须登录：没有令牌 => NotAuthenticated；有令牌则交给服务层判定。"""
    token = get_access_token(request)
    if token is None:
        service.audit.record(
            "access_denied", reason="not_authenticated", path=request.url.path
        )
        raise NotAuthenticated("缺少访问令牌")
    return service.authenticate(token)


def require_permission(permission: str):
    """生成依赖：已登录且具备 ``permission``，否则 403 permission_denied。"""

    def _dependency(
        request: Request, service: AuthService = Depends(get_service)
    ) -> AccessClaims:
        token = get_access_token(request)
        if token is None:
            service.audit.record(
                "access_denied",
                reason="not_authenticated",
                permission=permission,
                path=request.url.path,
            )
            raise NotAuthenticated("缺少访问令牌")
        return service.require_permission(token, permission)

    return _dependency

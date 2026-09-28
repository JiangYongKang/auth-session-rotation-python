"""HTTP 入口（路由）。

职责仅限：解析请求、调用服务层、把 AuthError 映射成统一 JSON 响应。
任何认证/授权结论都来自服务层，保证各入口语义一致。

错误响应统一为 {"error": {"code": ..., "message": ...}}。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse

from .deps import current_claims, get_service, require_permission
from .errors import AuthError
from .models import AccessClaims
from .service import AuthService

router = APIRouter()


# ---------------- 请求/响应模型 ----------------
class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class RevokeRequest(BaseModel):
    session_id: str = Field(min_length=1)


class RevokeUserRequest(BaseModel):
    user_id: str = Field(min_length=1)
    reason: str = "admin_revoke_user"


class UpdateRolesRequest(BaseModel):
    roles: list[str]
    enabled: bool | None = None


# ---------------- 异常处理 ----------------
def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.http_status,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


# ---------------- 公开端点 ----------------
@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.post("/auth/login")
def login(body: LoginRequest, service: AuthService = Depends(get_service)) -> dict:
    pair = service.login(body.username, body.password)
    return {
        "access_token": pair.access_token,
        "refresh_token": pair.refresh_token,
        "token_type": "Bearer",
        "access_expires_in": pair.access_expires_in,
        "refresh_expires_in": pair.refresh_expires_in,
        "session_id": pair.session_id,
    }


@router.post("/auth/refresh")
def refresh(body: RefreshRequest, service: AuthService = Depends(get_service)) -> dict:
    pair = service.refresh(body.refresh_token)
    return {
        "access_token": pair.access_token,
        "refresh_token": pair.refresh_token,
        "token_type": "Bearer",
        "access_expires_in": pair.access_expires_in,
        "refresh_expires_in": pair.refresh_expires_in,
        "session_id": pair.session_id,
    }


# ---------------- 已登录端点 ----------------
@router.get("/me")
def me(
    claims: AccessClaims = Depends(current_claims),
    service: AuthService = Depends(get_service),
) -> dict:
    user = service.store.get_user(claims.user_id)
    permissions = sorted(service.store.effective_permissions(user))
    return {
        "user_id": claims.user_id,
        "session_id": claims.session_id,
        "roles": list(user.roles),
        "permissions": permissions,
    }


@router.get("/articles")
def list_articles(claims: AccessClaims = Depends(require_permission("article:read"))):
    return {"articles": [{"id": 1, "title": "welcome"}]}


@router.post("/articles")
def write_article(claims: AccessClaims = Depends(require_permission("article:write"))):
    return {"created": True}


# ---------------- 管理端点 ----------------
@router.post("/admin/sessions/revoke")
def revoke_session(
    body: RevokeRequest,
    service: AuthService = Depends(get_service),
    _: AccessClaims = Depends(require_permission("session:revoke")),
) -> dict:
    service.revoke_session(body.session_id)
    return {"revoked": body.session_id}


@router.post("/admin/users/revoke-sessions")
def revoke_user_sessions(
    body: RevokeUserRequest,
    service: AuthService = Depends(get_service),
    _: AccessClaims = Depends(require_permission("session:revoke")),
) -> dict:
    count = service.revoke_all_user_sessions(body.user_id, body.reason)
    return {"user_id": body.user_id, "revoked": count}


@router.post("/admin/users/{user_id}/roles")
def update_roles(
    user_id: str,
    body: UpdateRolesRequest,
    service: AuthService = Depends(get_service),
    _: AccessClaims = Depends(require_permission("user:manage")),
) -> dict:
    """直接修改用户角色/启停状态。权限实时聚合，已签发会话立即受影响。"""
    with service.store.lock:
        user = service.store.get_user(user_id)
        if user is None:
            from .errors import UserNotFound

            raise UserNotFound("用户不存在")
        user.roles = list(body.roles)
        if body.enabled is not None:
            user.enabled = body.enabled
        permissions = sorted(service.store.effective_permissions(user))
    service.audit.record(
        "roles_updated",
        user_id=user_id,
        roles=body.roles,
        effective_permissions=permissions,
    )
    return {"user_id": user_id, "roles": body.roles, "permissions": permissions}

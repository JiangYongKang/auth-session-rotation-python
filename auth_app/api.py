"""FastAPI 入口：登录、刷新、受保护资源、会话管理、权限变更。

所有认证/授权判定都委托给 AuthService —— HTTP 层不做任何
独立的安全判断，因此各入口结论与服务层/测试完全一致。
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .bootstrap import build_service
from .errors import AuthError, PermissionDenied
from .service import AuthService

_SERVICE: AuthService | None = None


def get_service() -> AuthService:
    """默认使用进程级单例；测试可通过 app.state.service 覆盖。"""
    return _SERVICE  # type: ignore[return-value]


# --------------------------------------------------------------------- #
# 请求/响应模型
# --------------------------------------------------------------------- #
class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"


class RoleChangeRequest(BaseModel):
    add_roles: list[str] = Field(default_factory=list)
    remove_roles: list[str] = Field(default_factory=list)
    add_permissions: list[str] = Field(default_factory=list)
    remove_permissions: list[str] = Field(default_factory=list)
    active: bool | None = None


# --------------------------------------------------------------------- #
# 依赖
# --------------------------------------------------------------------- #
def _service(request: Request) -> AuthService:
    return getattr(request.app.state, "service", None) or get_service()


def _bearer(authorization: Annotated[str | None, Header()] = None) -> str:
    if not authorization:
        return ""
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return ""


def require_auth():
    """仅要求已登录的 FastAPI 依赖（401 与 403 由服务层区分）。"""

    def _dep(request: Request,
             token: Annotated[str, Depends(_bearer)]) -> dict:
        return _service(request).require_authentication(token)

    return _dep


def require_permission(permission: str):
    """生成一个“要求指定权限”的 FastAPI 依赖。"""

    def _dep(request: Request,
             token: Annotated[str, Depends(_bearer)]) -> dict:
        service = _service(request)
        # 未登录/过期/篡改 -> 401 类；已登录但权限不足 -> 403，严格区分。
        return service.require_permission(token, permission)

    return _dep


# --------------------------------------------------------------------- #
# 应用工厂
# --------------------------------------------------------------------- #
def create_app(service: AuthService | None = None) -> FastAPI:
    global _SERVICE
    app = FastAPI(title="auth-session-rotation", version="0.1.0",
                  docs_url="/api-docs", redoc_url=None)

    if service is not None:
        app.state.service = service
        _SERVICE = service
    elif _SERVICE is None:
        _SERVICE = build_service()
        app.state.service = _SERVICE
    else:
        app.state.service = _SERVICE

    @app.exception_handler(AuthError)
    async def _auth_error_handler(request: Request, exc: AuthError):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {
                "code": exc.code,
                "message": exc.message,
                "detail": exc.detail,
            }},
        )

    # ---- 认证 ---- #
    @app.post("/auth/login", response_model=TokenResponse)
    def login(body: LoginRequest,
              service: Annotated[AuthService, Depends(_service)]):
        pair = service.login(body.username, body.password)
        return TokenResponse(access_token=pair.access_token,
                             refresh_token=pair.refresh_token)

    @app.post("/auth/refresh", response_model=TokenResponse)
    def refresh(body: RefreshRequest,
                service: Annotated[AuthService, Depends(_service)]):
        pair = service.refresh(body.refresh_token)
        return TokenResponse(access_token=pair.access_token,
                             refresh_token=pair.refresh_token)

    @app.post("/auth/logout")
    def logout(identity: Annotated[dict, Depends(require_auth())],
               service: Annotated[AuthService, Depends(_service)]):
        # 退出登录 = 撤销当前会话（任何已登录用户都可撤销自己的会话）。
        service.revoke_session(identity["session_id"], reason="logout")
        return {"status": "ok", "session_id": identity["session_id"]}

    @app.get("/me")
    def me(identity: Annotated[dict, Depends(require_auth())],
           service: Annotated[AuthService, Depends(_service)]):
        from .rbac import effective_permissions
        user = service.store.get_user(identity["user_id"])
        return {
            "user_id": identity["user_id"],
            "session_id": identity["session_id"],
            "roles": sorted(user.roles) if user else [],
            "permissions": sorted(effective_permissions(
                user.roles, user.permissions)) if user else [],
        }

    # ---- 受保护的示例资源（基于权限） ---- #
    @app.get("/docs")
    def read_docs(_: Annotated[dict, Depends(require_permission("doc:read"))]):
        return {"docs": ["welcome.md", "guide.md"]}

    @app.post("/docs")
    def write_doc(_: Annotated[dict, Depends(require_permission("doc:write"))]):
        return {"status": "created"}

    @app.delete("/docs/{doc_id}")
    def delete_doc(doc_id: str,
                   _: Annotated[dict, Depends(require_permission("doc:delete"))]):
        return {"status": "deleted", "doc_id": doc_id}

    # ---- 会话管理 ---- #
    @app.get("/sessions")
    def list_sessions(identity: Annotated[dict, Depends(require_auth())],
                      service: Annotated[AuthService, Depends(_service)]):
        return {"sessions": service.list_sessions(identity["user_id"])}

    @app.delete("/sessions/{session_id}")
    def revoke_one(session_id: str,
                   identity: Annotated[dict, Depends(require_auth())],
                   service: Annotated[AuthService, Depends(_service)]):
        session = service.store.get_session(session_id)
        if session is None:
            from .errors import NotFound
            raise NotFound("会话不存在")
        # 只能撤销自己的会话；admin 可撤销任意会话。
        if session.user_id != identity["user_id"]:
            from .rbac import user_has_permission
            if not user_has_permission(service.store, identity["user_id"],
                                       "session:manage"):
                raise PermissionDenied("只能撤销自己的会话")
        service.revoke_session(session_id, reason="revoked_by_owner_or_admin")
        return {"status": "ok", "session_id": session_id}

    # ---- 管理员：撤销用户全部会话 ---- #
    @app.post("/admin/users/{user_id}/revoke-sessions")
    def revoke_user_sessions(user_id: str,
                             _: Annotated[dict, Depends(require_permission("user:manage"))],
                             service: Annotated[AuthService, Depends(_service)]):
        ids = service.revoke_all_user_sessions(user_id)
        return {"status": "ok", "revoked_session_ids": ids}

    # ---- 管理员：有界回收过期的刷新令牌重放历史 ---- #
    @app.post("/admin/maintenance/replay-history/purge")
    def purge_replay_history(
            _: Annotated[dict, Depends(require_permission("user:manage"))],
            service: Annotated[AuthService, Depends(_service)]):
        stats = service.purge_replay_history()
        # 内部用的 jti 列表不必对外暴露。
        return {
            "status": "ok",
            "reaped": stats["reaped"],
            "remaining": stats["remaining"],
            "over_limit": stats["over_limit"],
            "next_eligible_at": stats["next_eligible_at"],
        }

    # ---- 管理员：实时变更角色/权限（立即对已签发会话生效） ---- #
    @app.post("/admin/users/{user_id}/roles")
    def change_roles(user_id: str, body: RoleChangeRequest,
                     _: Annotated[dict, Depends(require_permission("user:manage"))],
                     service: Annotated[AuthService, Depends(_service)]):
        from .errors import NotFound
        user = service.store.get_user(user_id)
        if user is None:
            raise NotFound("用户不存在")
        user.roles = (user.roles | set(body.add_roles)) - set(body.remove_roles)
        user.permissions = ((user.permissions | set(body.add_permissions))
                            - set(body.remove_permissions))
        if body.active is not None:
            user.active = body.active
        from .rbac import effective_permissions
        service.audit.log("roles_changed", user_id=user_id,
                          roles=sorted(user.roles),
                          permissions=sorted(effective_permissions(
                              user.roles, user.permissions)),
                          active=user.active)
        return {"status": "ok", "roles": sorted(user.roles),
                "permissions": sorted(user.permissions), "active": user.active}

    @app.get("/")
    def root():
        return {"service": "auth-session-rotation",
                "openapi_ui": "/api-docs", "health": "ok"}

    return app

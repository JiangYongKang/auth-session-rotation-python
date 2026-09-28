"""FastAPI 应用装配。"""

from __future__ import annotations

from fastapi import FastAPI

from .audit import AuditLog
from .clock import SystemClock
from .errors import AuthError
from .http import auth_error_handler, router
from .seed import build_seed_store
from .service import AuthService

AUDIT_FILE = "data/audit.log.jsonl"


def create_app(audit_path: str | None = AUDIT_FILE) -> FastAPI:
    app = FastAPI(title="Auth Session Rotation (local demo)")

    store = build_seed_store()
    audit = AuditLog(path=audit_path, clock=SystemClock())
    app.state.store = store
    app.state.audit = audit
    app.state.auth_service = AuthService(store=store, audit=audit)

    app.add_exception_handler(AuthError, auth_error_handler)
    app.include_router(router)
    return app

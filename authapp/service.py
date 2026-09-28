"""认证与访问控制核心逻辑。

HTTP 入口、测试以及未来的其他入口都只调用这里，保证结论一致：
同样的输入在任何入口下得到同样的结果与失败原因。

安全语义要点：
- 访问令牌只携带身份与会话标识（jti/sid），权限始终实时从用户存储
  聚合，所以角色/权限变更对已签发会话立即且持续生效；
- 刷新令牌一次性使用：每次刷新签发新的刷新令牌，旧令牌标记 used；
  一旦 used/已撤销的刷新令牌再次出现，判定为"重用"，立即撤销整条会话；
- 刷新的"定位-检查-标记-签发"全程持有存储锁，并发刷新只有一个成功；
- 失败原因通过独立的 AuthError 子类区分：过期 / 篡改 / 时钟偏差 /
  未登录 / 权限不足 / 会话已撤销 / 刷新令牌重用。
"""

from __future__ import annotations

import secrets

from .audit import AuditLog
from .clock import Clock, SystemClock
from .errors import (
    InvalidCredentials,
    PermissionDenied,
    RefreshTokenReused,
    SessionNotFound,
    SessionRevoked,
    TokenClockSkew,
    TokenExpired,
    TokenInvalid,
    UserDisabled,
    UserNotFound,
)
from .models import AccessClaims, RefreshClaims, RefreshTokenState, Session, TokenPair
from .security import decode_token, encode_token, verify_password
from .store import Store

_ACCESS = "access"
_REFRESH = "refresh"


class AuthService:
    def __init__(
        self,
        store: Store,
        audit: AuditLog,
        secret: str = "local-dev-secret",
        clock: Clock | None = None,
        access_ttl: int = 900,
        refresh_ttl: int = 1_209_600,
        clock_skew_tolerance: int = 60,
    ) -> None:
        self.store = store
        self.audit = audit
        self.secret = secret
        self.clock = clock or SystemClock()
        self.access_ttl = access_ttl
        self.refresh_ttl = refresh_ttl
        self.skew_tolerance = clock_skew_tolerance

    # ---------------- 登录 ----------------
    def login(self, username: str, password: str) -> TokenPair:
        user = self.store.get_user_by_username(username)
        if user is None or not verify_password(password, user.password_hash):
            self.audit.record(
                "login_failed", username=username, reason="invalid_credentials"
            )
            raise InvalidCredentials("用户名或密码错误")

        if not user.enabled:
            self.audit.record(
                "login_failed", username=username, reason="user_disabled"
            )
            raise UserDisabled("用户已被停用")

        now = self.clock.now()
        session = Session(
            id="sess_" + secrets.token_hex(12),
            user_id=user.id,
            created_at=now,
        )
        with self.store.lock:
            self.store.save_session(session)
            pair = self._issue_token_pair(session.id, user.id)
        self.audit.record(
            "login_success",
            user_id=user.id,
            session_id=session.id,
            refresh_token_id=pair.token_id,
        )
        return pair

    # ---------------- 刷新与轮换 ----------------
    def refresh(self, refresh_token: str) -> TokenPair:
        claims = self._decode_refresh(refresh_token)  # 签名/结构失败 -> TokenInvalid

        with self.store.lock:
            session = self.store.get_session(claims.session_id)
            state = (
                session.refresh_tokens.get(claims.token_id)
                if session is not None
                else None
            )
            if session is None or state is None:
                self.audit.record(
                    "refresh_failed",
                    session_id=claims.session_id,
                    token_id=claims.token_id,
                    reason="session_not_found",
                )
                raise SessionNotFound("刷新令牌对应的会话不存在")

            # 一次性令牌再次出现 => 重用：撤销整条会话（含刚轮换出的新令牌）。
            # 该判定优先于"会话已撤销"：同一个被用过的令牌无论重放多少次，
            # 结论都稳定为 refresh_token_reused。
            if state.used:
                already_revoked = session.revoked
                session.revoked = True
                session.revoke_reason = "refresh_token_reuse"
                session.current_refresh_token_id = None
                for item in session.refresh_tokens.values():
                    item.revoked = True
                self.audit.record(
                    "refresh_failed",
                    user_id=session.user_id,
                    session_id=session.id,
                    token_id=claims.token_id,
                    reason="reused",
                    decision="revoke_entire_session",
                )
                if not already_revoked:
                    self.audit.record(
                        "session_revoked",
                        session_id=session.id,
                        user_id=session.user_id,
                        reason="refresh_token_reuse",
                    )
                raise RefreshTokenReused("刷新令牌已被使用，整条会话已撤销")

            if session.revoked or state.revoked:
                self.audit.record(
                    "refresh_failed",
                    session_id=session.id,
                    token_id=claims.token_id,
                    reason="session_revoked",
                )
                raise SessionRevoked("会话已被撤销")

            now = self.clock.now()
            if claims.issued_at > now + self.skew_tolerance:
                self.audit.record(
                    "refresh_failed",
                    session_id=session.id,
                    token_id=claims.token_id,
                    reason="clock_skew",
                    iat=claims.issued_at,
                    now=now,
                )
                raise TokenClockSkew("刷新令牌签发时间在未来，时钟偏差过大")

            if now > claims.expires_at:
                self.audit.record(
                    "refresh_failed",
                    session_id=session.id,
                    token_id=claims.token_id,
                    reason="expired",
                    exp=claims.expires_at,
                    now=now,
                )
                raise TokenExpired("刷新令牌已过期")

            # 合法的一次性交换：先标记旧令牌，再签发新对（锁内原子完成）
            state.used = True
            pair = self._issue_token_pair(session.id, claims.user_id)
            state.next_token_id = pair.token_id

        self.audit.record(
            "refresh_success",
            user_id=claims.user_id,
            session_id=session.id,
            old_token_id=claims.token_id,
            new_token_id=pair.token_id,
        )
        return pair

    # ---------------- 访问令牌统一校验 ----------------
    def authenticate(self, access_token: str) -> AccessClaims:
        """校验访问令牌并检查会话/用户状态；不做权限判定。"""
        claims = self._decode_access(access_token)  # TokenInvalid
        now = self.clock.now()

        if claims.issued_at > now + self.skew_tolerance:
            raise TokenClockSkew("访问令牌签发时间在未来，时钟偏差过大")
        if now > claims.expires_at:
            raise TokenExpired("访问令牌已过期")

        with self.store.lock:
            session = self.store.get_session(claims.session_id)
            if session is None:
                raise SessionNotFound("会话不存在")
            if session.revoked:
                raise SessionRevoked("会话已被撤销")
            user = self.store.get_user(claims.user_id)
            if user is None:
                raise UserNotFound("用户不存在")
            if not user.enabled:
                raise UserDisabled("用户已被停用")
        return claims

    def require_permission(self, access_token: str, permission: str) -> AccessClaims:
        """统一的访问控制入口：认证 + 实时权限校验。"""
        try:
            claims = self.authenticate(access_token)
        except Exception as exc:
            self.audit.record(
                "access_denied",
                permission=permission,
                reason=getattr(exc, "code", "token_invalid"),
            )
            raise

        user = self.store.get_user(claims.user_id)
        assert user is not None  # authenticate 已确认用户存在
        permissions = self.store.effective_permissions(user)
        if permission not in permissions:
            self.audit.record(
                "access_denied",
                user_id=user.id,
                session_id=claims.session_id,
                permission=permission,
                reason="permission_denied",
                effective_permissions=sorted(permissions),
            )
            raise PermissionDenied(f"缺少权限: {permission}")
        return claims

    # ---------------- 撤销 ----------------
    def revoke_session(self, session_id: str, reason: str = "manual_revoke") -> None:
        with self.store.lock:
            session = self.store.get_session(session_id)
            if session is None:
                raise SessionNotFound("会话不存在")
            session.revoked = True
            session.revoke_reason = reason
            session.current_refresh_token_id = None
            for item in session.refresh_tokens.values():
                item.revoked = True
        self.audit.record(
            "session_revoked",
            session_id=session_id,
            user_id=session.user_id,
            reason=reason,
        )

    def revoke_all_user_sessions(
        self, user_id: str, reason: str = "user_all_revoked"
    ) -> int:
        with self.store.lock:
            targets = self.store.list_sessions_for_user(user_id)
            count = 0
            for session in targets:
                if session.revoked:
                    continue
                session.revoked = True
                session.revoke_reason = reason
                session.current_refresh_token_id = None
                for item in session.refresh_tokens.values():
                    item.revoked = True
                count += 1
        self.audit.record(
            "all_sessions_revoked", user_id=user_id, count=count, reason=reason
        )
        return count

    # ---------------- 内部辅助 ----------------
    def _issue_token_pair(self, session_id: str, user_id: str) -> TokenPair:
        """调用方必须持有 store.lock。"""
        now = self.clock.now()
        access_id = "at_" + secrets.token_hex(12)
        refresh_id = "rt_" + secrets.token_hex(12)

        access_claims = {
            "typ": _ACCESS,
            "sub": user_id,
            "sid": session_id,
            "jti": access_id,
            "iat": now,
            "exp": now + self.access_ttl,
        }
        refresh_claims = {
            "typ": _REFRESH,
            "sub": user_id,
            "sid": session_id,
            "jti": refresh_id,
            "iat": now,
            "exp": now + self.refresh_ttl,
        }

        session = self.store.get_session(session_id)
        assert session is not None
        session.refresh_tokens[refresh_id] = RefreshTokenState(
            token_id=refresh_id,
            issued_at=now,
            expires_at=now + self.refresh_ttl,
        )
        self.store.refresh_index[refresh_id] = session_id
        session.current_refresh_token_id = refresh_id

        return TokenPair(
            access_token=encode_token(access_claims, self.secret),
            refresh_token=encode_token(refresh_claims, self.secret),
            access_expires_in=self.access_ttl,
            refresh_expires_in=self.refresh_ttl,
            session_id=session_id,
            token_id=refresh_id,
        )

    def _decode_access(self, token: str) -> AccessClaims:
        claims = decode_token(token, self.secret)
        return self._to_claims(claims, _ACCESS, AccessClaims)

    def _decode_refresh(self, token: str) -> RefreshClaims:
        claims = decode_token(token, self.secret)
        return self._to_claims(claims, _REFRESH, RefreshClaims)

    @staticmethod
    def _to_claims(raw: dict, expected_type: str, cls):
        if raw.get("typ") != expected_type:
            raise TokenInvalid("unexpected token type")
        try:
            return cls(
                user_id=raw["sub"],
                session_id=raw["sid"],
                token_id=raw["jti"],
                issued_at=float(raw["iat"]),
                expires_at=float(raw["exp"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise TokenInvalid("missing or invalid claims") from exc

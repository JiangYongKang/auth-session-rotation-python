"""认证核心服务：登录、刷新轮换、访问令牌校验、权限校验、会话撤销。

这是所有入口（HTTP 接口 / 测试 / 程序化调用）共享的唯一判定来源。

刷新令牌轮换（rotation）语义：

* 每次刷新都会签发新的一对令牌，旧刷新令牌立即标记 used；
* 已 used 或已 revoked 的刷新令牌再次出现 => 判定为重放(reuse)，
  立即撤销其所属的**整条会话**（含该会话下所有刷新令牌），
  而不是再签发一份新令牌；
* 已被轮换掉的旧刷新令牌即使**在自身过期之后**才被重放，只要仍在
  保留窗口（过期时间 + replay_retention_seconds）内，同样按重放处理；
  从未被使用、只是单纯过期的刷新令牌仍按普通过期拒绝，不动会话；
* 刷新令牌记录按有界保留策略回收：只回收保留窗口已彻底结束、
  绝不可能再换到新令牌的历史；窗口之外的重放安全兜底为过期拒绝；
* “检查-判定-签发-落库”全程在 Store 的同一把锁内完成，
  多个并发请求拿同一刷新令牌时只有一个能成功。

权限语义：访问令牌只证明身份；每次授权实时读取用户当前
roles/permissions，角色/权限变化对所有已签发会话立即生效。
"""

from __future__ import annotations

import threading

from . import rbac, tokens
from .audit import AuditLogger
from .clock import Clock
from .config import Settings
from .errors import (
    InvalidCredentials,
    NotAuthenticated,
    PermissionDenied,
    RefreshTokenInvalid,
    RefreshTokenReused,
    SessionRevoked,
    TokenExpired,
)
from .models import RefreshTokenRecord, Session, TokenPair
from .security import (
    generate_jti,
    generate_session_id,
    sha256_hex,
    verify_password,
)
from .store import Store


class AuthService:
    def __init__(self, store: Store, settings: Settings,
                 clock: Clock, audit: AuditLogger) -> None:
        self.store = store
        self.settings = settings
        self.clock = clock
        self.audit = audit

    # ------------------------------------------------------------------ #
    # 登录
    # ------------------------------------------------------------------ #
    def login(self, username: str, password: str) -> TokenPair:
        user = self.store.get_user_by_username(username)
        # 无论用户是否存在都执行一次密码校验，避免通过响应时间判断用户是否存在。
        valid = verify_password(password, user.password_hash) if user else False
        if user is None or not valid:
            self.audit.log("login_failed", username=username,
                           reason="invalid_credentials")
            raise InvalidCredentials()
        if not user.active:
            self.audit.log("login_failed", username=username,
                           user_id=user.user_id, reason="user_inactive")
            raise InvalidCredentials("用户已被停用")

        now = self.clock.now()
        session_id = generate_session_id()
        session = Session(session_id=session_id, user_id=user.user_id,
                          created_at=now)
        self.store.add_session(session)

        pair = self._issue_tokens(session_id, user.user_id, parent_jti=None)
        self.audit.log("login_ok", user_id=user.user_id,
                       session_id=session_id,
                       permissions=sorted(rbac.effective_permissions(
                           user.roles, user.permissions)))
        return pair

    # ------------------------------------------------------------------ #
    # 刷新（轮换 + 重放检测 + 并发互斥）
    # ------------------------------------------------------------------ #
    def refresh(self, refresh_token: str) -> TokenPair:
        # 0) 惰性回收：保留窗口已彻底结束的刷新令牌历史在此清理。
        #    与下面的判定共用同一把锁，清理不会与刷新/撤销互相交错。
        self.cleanup_refresh_history()

        # 1) 先做纯密码学校验：过期/篡改/时钟偏差在这里严格区分。
        try:
            payload = tokens.verify_token(
                refresh_token, self.settings, self.clock, expected_type="refresh")
        except TokenExpired:
            # 过期令牌先过一遍本地历史：已被轮换掉的旧令牌在失效后重放，
            # 仍按重放处理并撤销整条会话；从未使用的单纯失效则原样抛出。
            self._handle_expired_refresh(refresh_token)
            raise

        token_hash = sha256_hex(refresh_token)

        # 2) 服务端状态判定与签发必须在同一临界区内原子完成。
        with self.store._lock:
            record = self.store.get_refresh_by_hash(token_hash)
            if record is None:
                # 签名有效但服务端无记录：会话已被撤销 / 令牌从未签发过。
                self.audit.log("refresh_rejected", user_id=payload.get("sub"),
                               jti=payload.get("jti"),
                               reason="refresh_token_not_found")
                raise RefreshTokenInvalid()

            if record.used:
                # 重放：已经被轮换过的刷新令牌再次出现 -> 撤销整条会话。
                self._revoke_session_locked(
                    record.session_id, "refresh_token_reuse:already_used",
                    triggered_jti=record.jti, user_id=record.user_id)
                self.audit.log(
                    "refresh_token_reuse_detected",
                    user_id=record.user_id, session_id=record.session_id,
                    jti=record.jti, reason="already_used",
                    action="whole_session_revoked")
                raise RefreshTokenReused(detail={
                    "session_id": record.session_id, "reason": "already_used"})

            session = self.store.get_session(record.session_id)
            if session is not None and session.revoked and (
                    session.revoke_reason or "").startswith(
                        "refresh_token_reuse"):
                # 该令牌本身未使用，但其所在会话链已因“别的刷新令牌重放”
                # 被整体撤销：同样按重放告警处理。
                self.audit.log(
                    "refresh_token_reuse_detected",
                    user_id=record.user_id, session_id=record.session_id,
                    jti=record.jti, reason=session.revoke_reason,
                    action="token_from_breached_chain")
                raise RefreshTokenReused(detail={
                    "session_id": record.session_id,
                    "reason": session.revoke_reason})

            if session is None or session.revoked or record.revoked:
                # 令牌本身尚未使用，但会话已被外部撤销（单撤销/全用户撤销/登出）。
                self.audit.log("refresh_rejected", user_id=record.user_id,
                               session_id=record.session_id,
                               jti=record.jti,
                               reason="session_revoked")
                raise SessionRevoked()

            # 正常轮换：旧令牌置 used，签发新的一对。
            now = self.clock.now()
            self.store.mark_refresh_used(record.jti, now)
            pair = self._issue_tokens_locked(
                record.session_id, record.user_id, parent_jti=record.jti)
            self.audit.log("refresh_rotated", user_id=record.user_id,
                           session_id=record.session_id,
                           old_jti=record.jti,
                           new_jti=payload_of_jti(pair.refresh_token))
            return pair

    # ------------------------------------------------------------------ #
    # 过期刷新令牌的本地历史判定 / 历史回收
    # ------------------------------------------------------------------ #
    def _handle_expired_refresh(self, refresh_token: str) -> None:
        """对密码学上已过期的刷新令牌做本地历史判定。

        进入本方法时令牌的签名已经校验通过（verify_token 先验签再判过期），
        因此可以信任令牌内容，只需查本地记录区分两类“已经不能用的令牌”：

        * 记录存在且 used：这张令牌曾被成功轮换，如今被人攥到失效后重放
          -> 判定为重放，立即撤销整条会话，抛 RefreshTokenReused；
        * 记录存在、未 used，但会话已因链上其他令牌重放被撤销
          -> 同样按重放告警；
        * 记录存在、未 used、会话正常：单纯失效 -> 原样按过期拒绝；
        * 记录不存在：从未签发，或保留窗口已过、历史已被回收
          -> 安全兜底，原样按过期拒绝，绝不签发新令牌。

        本方法只在判定为重放时抛 RefreshTokenReused；其余情况静默返回，
        由调用方把原始的 TokenExpired 继续抛出。
        """
        token_hash = sha256_hex(refresh_token)
        with self.store._lock:
            record = self.store.get_refresh_by_hash(token_hash)
            if record is None:
                self.audit.log(
                    "refresh_rejected", jti=payload_of_jti(refresh_token),
                    reason="expired_no_record_or_purged")
                return

            if record.used:
                # 已轮换旧令牌在失效后被重放：撤销整条会话（含仍有效的令牌）。
                self._revoke_session_locked(
                    record.session_id,
                    "refresh_token_reuse:used_after_expiry",
                    triggered_jti=record.jti, user_id=record.user_id)
                self.audit.log(
                    "refresh_token_reuse_detected",
                    user_id=record.user_id, session_id=record.session_id,
                    jti=record.jti, reason="used_after_expiry",
                    used_at=record.used_at,
                    action="whole_session_revoked")
                raise RefreshTokenReused(detail={
                    "session_id": record.session_id,
                    "reason": "used_after_expiry"})

            session = self.store.get_session(record.session_id)
            if session is not None and session.revoked and (
                    session.revoke_reason or "").startswith(
                        "refresh_token_reuse"):
                # 令牌本身未使用，但来自已因重放被攻破的会话链。
                self.audit.log(
                    "refresh_token_reuse_detected",
                    user_id=record.user_id, session_id=record.session_id,
                    jti=record.jti, reason=session.revoke_reason,
                    action="token_from_breached_chain")
                raise RefreshTokenReused(detail={
                    "session_id": record.session_id,
                    "reason": session.revoke_reason})

            # 从未被成功换走、只是单纯失效：普通过期，不动会话。
            self.audit.log("refresh_rejected", user_id=record.user_id,
                           session_id=record.session_id, jti=record.jti,
                           reason="expired_unused")

    def cleanup_refresh_history(self) -> int:
        """回收保留窗口已结束的刷新令牌历史，返回回收条数。

        保留窗口 = 令牌过期时间 + settings.replay_retention_seconds。
        在窗口内令牌仍可能被再次提交（重放判定依赖记录），绝不回收；
        窗口之外令牌早已无法通过过期校验，回收是安全的。
        每次刷新前也会自动执行一次（惰性回收），无需外部定时任务。
        """
        purged = self.store.purge_refresh_history(
            self.clock.now(), self.settings.replay_retention_seconds)
        if purged:
            self.audit.log("refresh_history_purged",
                           purged_count=len(purged),
                           purged_jtis=[r.jti for r in purged],
                           retention_seconds=
                           self.settings.replay_retention_seconds)
        return len(purged)

    # ------------------------------------------------------------------ #
    # 访问令牌认证 / 授权
    # ------------------------------------------------------------------ #
    def authenticate_access_token(self, access_token: str) -> dict:
        """只做认证（你是谁、属于哪个会话）。失败抛 NotAuthenticated 等。"""
        if not access_token:
            raise NotAuthenticated()
        # 密码学校验：过期 / 篡改 / 时钟偏差可区分。
        payload = tokens.verify_token(
            access_token, self.settings, self.clock, expected_type="access")

        session = self.store.get_session(payload["sid"])
        if session is None or session.revoked or session.user_id != payload["sub"]:
            self.audit.log("access_denied", user_id=payload.get("sub"),
                           session_id=payload.get("sid"),
                           reason="session_revoked_or_missing")
            raise SessionRevoked()
        return {"user_id": payload["sub"], "session_id": payload["sid"],
                "jti": payload["jti"]}

    def require_authentication(self, access_token: str) -> dict:
        """仅要求登录（401 类错误），不检查具体权限。"""
        identity = self.authenticate_access_token(access_token)
        user = rbac.get_live_user(self.store, identity["user_id"])
        if user is None or not user.active:
            self.audit.log("access_denied", **identity,
                           reason="user_missing_or_inactive")
            raise NotAuthenticated("用户不存在或已被停用")
        return identity

    def require_permission(self, access_token: str, permission: str) -> dict:
        """认证 + 实时权限判定。未登录 -> 401；权限不足 -> 403，严格区分。"""
        identity = self.authenticate_access_token(access_token)
        user = rbac.get_live_user(self.store, identity["user_id"])
        if user is None or not user.active:
            self.audit.log("access_denied", **identity,
                           reason="user_missing_or_inactive")
            raise NotAuthenticated("用户不存在或已被停用")
        granted = rbac.effective_permissions(user.roles, user.permissions)
        if permission not in granted:
            self.audit.log("permission_denied", **identity,
                           required=permission,
                           roles=sorted(user.roles),
                           granted=sorted(granted))
            raise PermissionDenied(detail={
                "required": permission,
                "granted": sorted(granted),
            })
        self.audit.log("access_granted", **identity, required=permission)
        return identity

    # ------------------------------------------------------------------ #
    # 会话撤销
    # ------------------------------------------------------------------ #
    def revoke_session(self, session_id: str, *,
                       reason: str = "manual_revoke") -> None:
        with self.store._lock:
            session = self.store.get_session(session_id)
            if session is None:
                from .errors import NotFound
                raise NotFound("会话不存在")
            self._revoke_session_locked(session_id, reason)
        self.audit.log("session_revoked", session_id=session_id, reason=reason)

    def revoke_all_user_sessions(self, user_id: str, *,
                                 reason: str = "user_all_revoked") -> list[str]:
        with self.store._lock:
            revoked_ids = self.store.revoke_all_user_sessions(
                user_id, reason, self.clock.now())
            for sid in revoked_ids:
                for jti in self.store.list_session_refresh_jtis(sid):
                    self.store.mark_refresh_revoked(jti)
        self.audit.log("user_all_sessions_revoked", user_id=user_id,
                       session_ids=revoked_ids, reason=reason)
        return revoked_ids

    def list_sessions(self, user_id: str) -> list[dict]:
        result = []
        for session in self.store.list_user_sessions(user_id):
            result.append({
                "session_id": session.session_id,
                "user_id": session.user_id,
                "created_at": session.created_at,
                "revoked": session.revoked,
                "revoke_reason": session.revoke_reason,
            })
        return result

    # ------------------------------------------------------------------ #
    # 内部辅助
    # ------------------------------------------------------------------ #
    def _issue_tokens(self, session_id: str, user_id: str,
                      parent_jti: str | None) -> TokenPair:
        with self.store._lock:
            return self._issue_tokens_locked(session_id, user_id, parent_jti)

    def _issue_tokens_locked(self, session_id: str, user_id: str,
                             parent_jti: str | None) -> TokenPair:
        user = self.store.get_user(user_id)
        roles = set(user.roles) if user else set()
        perms = rbac.effective_permissions(
            roles, set(user.permissions) if user else set())
        jti = generate_jti()
        pair = tokens.issue_token_pair(
            user_id, session_id, roles, perms, jti,
            self.settings, self.clock)
        now = self.clock.now()
        record = RefreshTokenRecord(
            jti=jti, session_id=session_id, user_id=user_id,
            token_hash=sha256_hex(pair.refresh_token),
            issued_at=now,
            expires_at=now + self.settings.refresh_token_ttl,
            parent_jti=parent_jti,
        )
        self.store.add_refresh_token(record)
        return pair

    def _revoke_session_locked(self, session_id: str, reason: str, *,
                               triggered_jti: str | None = None,
                               user_id: str | None = None) -> None:
        self.store.mark_session_revoked(session_id, reason, self.clock.now())
        for jti in self.store.list_session_refresh_jtis(session_id):
            self.store.mark_refresh_revoked(jti)


def payload_of_jti(refresh_token: str) -> str | None:
    """从刷新令牌中取 jti，仅用于审计日志（不做校验）。"""
    import base64
    import json
    try:
        head = refresh_token.split(".", 1)[0]
        raw = base64.urlsafe_b64decode(head + "=" * (-len(head) % 4))
        return json.loads(raw)["jti"]
    except Exception:
        return None

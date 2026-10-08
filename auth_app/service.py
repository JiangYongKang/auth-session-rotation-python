"""认证核心服务：登录、刷新轮换、访问令牌校验、权限校验、会话撤销。

这是所有入口（HTTP 接口 / 测试 / 程序化调用）共享的唯一判定来源。

刷新令牌轮换（rotation）语义：

* 每次刷新都会签发新的一对令牌，旧刷新令牌立即标记 used；
* 已 used 或已 revoked 的刷新令牌再次出现 => 判定为重放(reuse)，
  立即撤销其所属的**整条会话**（含该会话下所有刷新令牌），
  而不是再签发一份新令牌；
* “检查-判定-签发-落库”全程在 Store 的同一把锁内完成，
  多个并发请求拿同一刷新令牌时只有一个能成功。

权限语义：访问令牌只证明身份；每次授权实时读取用户当前
roles/permissions，角色/权限变化对所有已签发会话立即生效。
"""

from __future__ import annotations

from . import rbac, tokens
from .audit import AuditLogger
from .clock import Clock
from .config import Settings
from .errors import (
    InvalidCredentials,
    NotAuthenticated,
    PermissionDenied,
    RefreshTokenHistoryReaped,
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
        # 机会式清理重放历史的节流时间戳。
        self._last_purge_at: float = 0.0

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
        # 1) 先做纯密码学校验：篡改/时钟偏差在这里严格区分。
        #    注意：**过期的刷新令牌不能在这里直接挡回**——它可能是一张
        #    早已被轮换掉的旧令牌（过期后才被翻出来重放），必须进入
        #    服务端状态判定，才能与“从未用过、只是过期”区分清楚。
        expired_payload: dict | None = None
        try:
            payload = tokens.verify_token(
                refresh_token, self.settings, self.clock,
                expected_type="refresh")
        except TokenExpired as exc:
            expired_payload = exc.payload
            if expired_payload is None:
                # 兜底：签名/结构仍要可信，否则按篡改处理，绝不查库放行。
                expired_payload = tokens.decode_signed_token(
                    refresh_token, self.settings)
            payload = expired_payload

        token_hash = sha256_hex(refresh_token)
        is_expired = expired_payload is not None

        # 2) 服务端状态判定与签发必须在同一临界区内原子完成。
        with self.store._lock:
            self._maybe_purge_locked()
            record = self.store.get_refresh_by_hash(token_hash)
            now = self.clock.now()

            if is_expired:
                return self._classify_expired_locked(
                    record, payload, now)

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

    def _classify_expired_locked(self, record: RefreshTokenRecord | None,
                                 payload: dict, now: float) -> TokenPair:
        """对“密码学上已过期的刷新令牌”做服务端分类。

        结论必须和未过期时稳定一致，且三类严格分开：

        1. 记录存在且 ``used``（曾被成功轮换）-> 重放，撤销整条会话，
           抛 RefreshTokenReused，绝不重新签发；
        2. 记录存在但从未使用 -> 普通的“已过期”，抛 TokenExpired；
           若会话是被外部主动撤销（登出/管理员/单会话撤销），则仍是
           SessionRevoked；会话因别的令牌重放被撤 -> 仍算重放告警；
        3. 记录不存在：若仍在有界保留窗口内，说明它从未被成功签发/换走，
           属普通失效（RefreshTokenInvalid/TokenExpired）；若连保留窗口
           都过了，则历史已被安全回收，无法证明身份 ->
           RefreshTokenHistoryReaped，拒绝但绝不放行/重签。
        """
        jti = payload.get("jti")
        user_id = payload.get("sub")
        session_id = payload.get("sid")
        exp = float(payload.get("exp", 0.0))
        leeway = self.settings.clock_skew_leeway
        retention = self.settings.replay_retention_seconds
        # 该令牌“理论上最早可被回收”的时刻：自身过期（含 leeway）+ 保留窗口。
        retain_deadline = exp + leeway + retention

        if record is not None and record.used:
            # 核心场景：被轮换掉的旧令牌，自己也过期后才被翻出来 -> 重放。
            self._revoke_session_locked(
                record.session_id,
                "refresh_token_reuse:used_token_replayed_after_expiry",
                triggered_jti=record.jti, user_id=record.user_id)
            self.audit.log(
                "refresh_token_reuse_detected",
                user_id=record.user_id, session_id=record.session_id,
                jti=record.jti, reason="used_token_replayed_after_expiry",
                used_at=record.used_at, expired_at=exp, presented_at=now,
                action="whole_session_revoked")
            raise RefreshTokenReused(detail={
                "session_id": record.session_id,
                "reason": "used_token_replayed_after_expiry",
                "expired_at": exp, "used_at": record.used_at,
            })

        if record is not None:
            session = self.store.get_session(record.session_id)
            if session is not None and session.revoked and (
                    session.revoke_reason or "").startswith(
                        "refresh_token_reuse"):
                # 令牌本身未使用，但整条链已因别的令牌重放被撤销。
                self.audit.log(
                    "refresh_token_reuse_detected",
                    user_id=record.user_id, session_id=record.session_id,
                    jti=record.jti, reason=session.revoke_reason,
                    action="expired_token_from_breached_chain")
                raise RefreshTokenReused(detail={
                    "session_id": record.session_id,
                    "reason": session.revoke_reason})

            if (session is None or session.revoked or record.revoked):
                # 从未使用、但会话被外部主动撤销：仍按普通会话撤销处理。
                self.audit.log(
                    "refresh_rejected", user_id=record.user_id,
                    session_id=record.session_id, jti=record.jti,
                    reason="session_revoked", token_expired=True)
                raise SessionRevoked()

            # 从未被成功使用、只是单纯过期：普通失效，不撤销、不重签。
            self.audit.log(
                "refresh_rejected", user_id=record.user_id,
                session_id=record.session_id, jti=record.jti,
                reason="expired_never_used", expired_at=exp,
                presented_at=now)
            raise TokenExpired(detail={"exp": exp, "now": now,
                                       "leeway": leeway,
                                       "reason": "expired_never_used"})

        # record is None：区分“保留窗口内从未存在”与“超过保留窗口”。
        within_window = now < retain_deadline
        if within_window:
            # 还在保留范围内却查无此记录 => 从未被本服务成功签发/换走，
            # 属普通失效，不能当成重放，更不能重签。
            self.audit.log(
                "refresh_rejected", user_id=user_id, session_id=session_id,
                jti=jti, reason="expired_token_not_found_within_window",
                expired_at=exp, presented_at=now,
                retain_deadline=retain_deadline)
            raise RefreshTokenInvalid(
                "刷新令牌无效或已过期")

        # 超出有界保留范围：历史已被回收，无法证明这是不是重放。
        # 安全可解释的结论：拒绝（不放行、不重签）。
        self.audit.log(
            "refresh_history_reaped_reject", user_id=user_id,
            session_id=session_id, jti=jti, expired_at=exp,
            presented_at=now, retain_deadline=retain_deadline,
            reason="history_retention_exceeded",
            action="deny_without_reissue")
        raise RefreshTokenHistoryReaped(detail={
            "jti": jti, "expired_at": exp, "presented_at": now,
            "retain_deadline": retain_deadline,
            "retention_seconds": retention,
            "reason": "history_retention_exceeded",
        })

    # ------------------------------------------------------------------ #
    # 重放历史的有界回收
    # ------------------------------------------------------------------ #
    def purge_replay_history(self) -> dict:
        """显式回收过期的重放历史（也可供运维/测试直接调用）。"""
        now = self.clock.now()
        with self.store._lock:
            stats = self.store.purge_replay_history(
                now, self.settings.replay_history_max_records)
            self._last_purge_at = now
        self.audit.log("replay_history_purged", **{
            k: v for k, v in stats.items() if k != "reaped_jtis"
        }, reaped_jtis=stats["reaped_jtis"][:50],
            reaped_count=stats["reaped"])
        return stats

    def _maybe_purge_locked(self) -> None:
        """在刷新临界区内做节流的机会式回收。

        与查库/签发处于同一把锁，因此清理与并发刷新、并发撤销之间不会
        出现“先删后判/重复签发”的状态错乱。
        """
        now = self.clock.now()
        if now - self._last_purge_at < \
                self.settings.replay_purge_interval_seconds:
            return
        stats = self.store.purge_replay_history(
            now, self.settings.replay_history_max_records)
        self._last_purge_at = now
        if stats["reaped"] or stats["over_limit"]:
            self.audit.log("replay_history_purged", **{
                k: v for k, v in stats.items() if k != "reaped_jtis"
            }, reaped_count=stats["reaped"], trigger="opportunistic")

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
        expires_at = now + self.settings.refresh_token_ttl
        # 重放痕迹必须保留到“彻底不可能再换到新令牌”之后：自身过期
        # （含时钟容忍）+ 有界保留窗口。在此之前清理逻辑不得删除它。
        retain_until = (expires_at
                        + self.settings.clock_skew_leeway
                        + self.settings.replay_retention_seconds)
        record = RefreshTokenRecord(
            jti=jti, session_id=session_id, user_id=user_id,
            token_hash=sha256_hex(pair.refresh_token),
            issued_at=now,
            expires_at=expires_at,
            parent_jti=parent_jti,
            retain_until=retain_until,
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

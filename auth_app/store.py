"""线程安全的内存存储：用户、会话、刷新令牌。

数据保存在进程内存中（本地可复现，无需外部服务）；
审计事件另外以 JSONL 落盘。所有访问用一把 RLock 保护，
刷新轮换的“检查-判定-更新”在 service 层同一把锁内完成，
保证并发刷新时只有一个请求成功。
"""

from __future__ import annotations

import threading

from .models import RefreshTokenRecord, Session, User


class Store:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._sessions: dict[str, Session] = {}
        self._refresh_by_jti: dict[str, RefreshTokenRecord] = {}
        self._refresh_by_hash: dict[str, RefreshTokenRecord] = {}
        self._user_sessions: dict[str, set[str]] = {}
        self._lock = threading.RLock()

    # ---- 用户 ----
    def upsert_user(self, user: User) -> None:
        with self._lock:
            self._users[user.user_id] = user

    def get_user(self, user_id: str) -> User | None:
        with self._lock:
            return self._users.get(user_id)

    def get_user_by_username(self, username: str) -> User | None:
        with self._lock:
            for user in self._users.values():
                if user.username == username:
                    return user
            return None

    def all_users(self) -> list[User]:
        with self._lock:
            return list(self._users.values())

    # ---- 会话 ----
    def add_session(self, session: Session) -> None:
        with self._lock:
            self._sessions[session.session_id] = session
            self._user_sessions.setdefault(session.user_id, set()).add(session.session_id)

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def list_user_sessions(self, user_id: str) -> list[Session]:
        with self._lock:
            ids = self._user_sessions.get(user_id, set())
            return [self._sessions[i] for i in sorted(ids) if i in self._sessions]

    def mark_session_revoked(self, session_id: str, reason: str, now: float) -> bool:
        """返回是否发生了状态翻转（未撤销 -> 已撤销）。"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.revoked:
                return False
            session.revoked = True
            session.revoke_reason = reason
            session.revoked_at = now
            return True

    def revoke_all_user_sessions(self, user_id: str, reason: str, now: float) -> list[str]:
        """撤销用户的全部会话，返回本次实际撤销的会话 id。"""
        with self._lock:
            revoked: list[str] = []
            for session in self.list_user_sessions(user_id):
                if self.mark_session_revoked(session.session_id, reason, now):
                    revoked.append(session.session_id)
            return revoked

    # ---- 刷新令牌 ----
    def add_refresh_token(self, record: RefreshTokenRecord) -> None:
        with self._lock:
            self._refresh_by_jti[record.jti] = record
            self._refresh_by_hash[record.token_hash] = record

    def get_refresh_by_hash(self, token_hash: str) -> RefreshTokenRecord | None:
        with self._lock:
            return self._refresh_by_hash.get(token_hash)

    def get_refresh_by_jti(self, jti: str) -> RefreshTokenRecord | None:
        with self._lock:
            return self._refresh_by_jti.get(jti)

    def list_session_refresh_jtis(self, session_id: str) -> list[str]:
        with self._lock:
            return [r.jti for r in self._refresh_by_jti.values()
                    if r.session_id == session_id]

    def mark_refresh_used(self, jti: str, now: float) -> None:
        with self._lock:
            record = self._refresh_by_jti.get(jti)
            if record is not None:
                record.used = True
                record.used_at = now

    def mark_refresh_revoked(self, jti: str) -> None:
        with self._lock:
            record = self._refresh_by_jti.get(jti)
            if record is not None:
                record.revoked = True

    def snapshot_refresh_by_hash(self) -> dict[str, RefreshTokenRecord]:
        with self._lock:
            return dict(self._refresh_by_hash)

    def purge_replay_history(self, now: float,
                             max_records: int | None = None) -> dict:
        """有界回收刷新令牌历史。

        主策略是**时间**：只删除 ``now >= record.retain_until`` 的记录。
        一条记录的 retain_until 不早于其自身过期时刻（含 leeway）之后的
        保留窗口，因此只要某令牌还可能在保留范围内被再次提交，它的痕迹
        就不会在这里被清掉。

        ``max_records`` 是防御性背压：当记录总数仍超上限时，本方法也只
        回收已经可删（retain_until 已过）的部分，**绝不**提前删除尚在
        保留窗口内的记录——宁可暂时超上限，也不漏判重放。返回统计信息
        （删除条数、剩余条数、是否仍超限、下一条可回收时间）。
        """
        with self._lock:
            reaped_jtis: list[str] = []
            for jti, record in list(self._refresh_by_jti.items()):
                if now >= record.retain_until:
                    reaped_jtis.append(jti)
                    del self._refresh_by_jti[jti]
                    self._refresh_by_hash.pop(record.token_hash, None)

            remaining = len(self._refresh_by_jti)
            over_limit = (max_records is not None
                          and remaining > max_records)
            next_eligible: float | None = None
            if over_limit:
                candidates = [r.retain_until
                              for r in self._refresh_by_jti.values()]
                if candidates:
                    next_eligible = min(candidates)
            return {
                "reaped": len(reaped_jtis),
                "remaining": remaining,
                "reaped_jtis": reaped_jtis,
                "over_limit": over_limit,
                "next_eligible_at": next_eligible,
            }

    def count_refresh_records(self) -> int:
        with self._lock:
            return len(self._refresh_by_jti)

"""运行配置：全部可通过环境变量覆盖，默认值即可本地直接运行。"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    signing_key: str
    access_token_ttl: int            # 访问令牌有效期（秒）
    refresh_token_ttl: int           # 刷新令牌有效期（秒）
    clock_skew_leeway: int           # 允许的时钟偏差（秒）
    audit_log_path: str
    seed_users: bool
    # 重放痕迹有界保留：刷新令牌在自身过期（含 leeway）之后，其服务端
    # 记录至少再保留 replay_retention_seconds 秒，期间任何重放——哪怕
    # 令牌本身早已过期——都必须被识别。超过该窗口的记录才允许回收。
    replay_retention_seconds: int = 60 * 60 * 24 * 30
    # 重放历史条数软上限（防御性背压）：清理时只回收“已过保留窗口”
    # 的记录；若仍超上限也绝不提前删除尚在保留窗口内的痕迹（宁可内存
    # 暂时增长，也不漏判）。
    replay_history_max_records: int = 200_000
    # 机会式清理的最小间隔（秒），避免每次刷新都全表扫描。
    replay_purge_interval_seconds: int = 60


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else default


def get_settings() -> Settings:
    return Settings(
        signing_key=os.environ.get("AUTH_SIGNING_KEY", "local-dev-only-signing-key-change-me"),
        access_token_ttl=_env_int("AUTH_ACCESS_TTL", 900),
        refresh_token_ttl=_env_int("AUTH_REFRESH_TTL", 60 * 60 * 24 * 7),
        clock_skew_leeway=_env_int("AUTH_CLOCK_SKEW_LEEWAY", 60),
        audit_log_path=os.environ.get("AUTH_AUDIT_LOG", "data/audit.log.jsonl"),
        seed_users=os.environ.get("AUTH_SEED_USERS", "1") != "0",
        replay_retention_seconds=_env_int(
            "AUTH_REPLAY_RETENTION_SECONDS", 60 * 60 * 24 * 30),
        replay_history_max_records=_env_int(
            "AUTH_REPLAY_HISTORY_MAX_RECORDS", 200_000),
        replay_purge_interval_seconds=_env_int(
            "AUTH_REPLAY_PURGE_INTERVAL_SECONDS", 60),
    )

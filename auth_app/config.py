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
    )

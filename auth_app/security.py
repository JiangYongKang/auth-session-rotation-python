"""密码与令牌哈希工具（仅使用标准库，无外部依赖）。

密码使用 PBKDF2-HMAC-SHA256 + 随机盐；令牌摘要使用 SHA-256。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_PBKDF2_ROUNDS = 200_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        scheme, rounds, salt_hex, hash_hex = password_hash.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            bytes.fromhex(salt_hex), int(rounds),
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def generate_jti() -> str:
    return secrets.token_urlsafe(24)


def generate_session_id() -> str:
    return "sess_" + secrets.token_urlsafe(18)

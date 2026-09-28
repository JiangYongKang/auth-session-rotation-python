"""密码哈希与 HMAC 签名令牌基元（仅用标准库，本地可复现）。

令牌格式为 ``header.payload.signature``，均为 base64url：
- header  固定为 {"alg": "HS256", "typ": "signed"}；
- payload 为业务声明 JSON；
- signature = HMAC_SHA256(header_b64 + "." + payload_b64, secret)。

这里只负责"结构合法 + 签名有效"的判定；过期、时钟偏差、
刷新令牌是否已被使用等业务语义由服务层统一判定。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets

from .errors import TokenInvalid

_PBKDF2_ROUNDS = 200_000
_HEADER = '{"alg":"HS256","typ":"signed"}'


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS
    )
    return "pbkdf2_sha256${rounds}${salt}${digest}".format(
        rounds=_PBKDF2_ROUNDS,
        salt=b64url_encode(salt),
        digest=b64url_encode(digest),
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        scheme, rounds_text, salt_b64, digest_b64 = password_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        rounds = int(rounds_text)
        salt = b64url_decode(salt_b64)
        expected = b64url_decode(digest_b64)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, rounds
    )
    return hmac.compare_digest(actual, expected)


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def sign_payload(header_b64: str, payload_b64: str, secret: str) -> str:
    """对 header.payload 做 HMAC-SHA256，返回 base64url 签名。"""
    signed = (header_b64 + "." + payload_b64).encode("ascii")
    mac = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).digest()
    return b64url_encode(mac)


def encode_token(claims: dict, secret: str) -> str:
    header_b64 = b64url_encode(_HEADER.encode("utf-8"))
    payload = json.dumps(claims, separators=(",", ":"), sort_keys=True)
    payload_b64 = b64url_encode(payload.encode("utf-8"))
    signature_b64 = sign_payload(header_b64, payload_b64, secret)
    return header_b64 + "." + payload_b64 + "." + signature_b64


def decode_token(token: str, secret: str) -> dict:
    """验证结构与签名，返回声明字典。结构/签名非法一律抛 TokenInvalid。"""
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenInvalid("malformed token")
    header_b64, payload_b64, signature_b64 = parts

    expected_signature = sign_payload(header_b64, payload_b64, secret)
    # 签名不一致 => 被篡改或伪造
    if not hmac.compare_digest(expected_signature, signature_b64):
        raise TokenInvalid("signature mismatch")

    try:
        header = json.loads(b64url_decode(header_b64))
        claims = json.loads(b64url_decode(payload_b64))
    except (ValueError, TypeError) as exc:
        raise TokenInvalid("malformed payload") from exc

    if header.get("alg") != "HS256":
        raise TokenInvalid("unsupported header")
    if not isinstance(claims, dict):
        raise TokenInvalid("payload is not an object")
    return claims

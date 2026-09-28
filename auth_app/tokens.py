"""自签名令牌（HMAC-SHA256，紧凑序列化），签发与校验。

令牌结构::

    base64url(payload_json) + "." + base64url(hmac_sha256(payload_b64))

payload 字段：
    typ  : "access" / "refresh"
    sub  : 用户 id
    sid  : 会话 id
    jti  : 令牌唯一 id
    iat  : 签发时间（unix 秒）
    exp  : 过期时间（unix 秒）
    rol  : 签发时角色快照（仅展示/排查用，授权以服务端实时数据为准）
    perm : 签发时权限快照（同上）

校验顺序固定，失败原因严格区分：
    1. 结构/签名/字段不合法        -> TokenTampered
    2. iat 来自未来且超出容忍窗口   -> ClockSkew
    3. exp 已过且超出容忍窗口       -> TokenExpired
    4. 其余视为有效，返回 payload
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from .clock import Clock
from .config import Settings
from .errors import ClockSkew, TokenExpired, TokenTampered
from .models import TokenPair


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    try:
        padding = "=" * (-len(text) % 4)
        return base64.urlsafe_b64decode(text + padding)
    except (ValueError, TypeError) as exc:
        raise TokenTampered("令牌 base64 解码失败") from exc


def _sign(payload_b64: str, key: str) -> str:
    digest = hmac.new(key.encode("utf-8"), payload_b64.encode("ascii"),
                      hashlib.sha256).digest()
    return _b64encode(digest)


def _encode_payload(payload: dict, key: str) -> str:
    payload_b64 = _b64encode(json.dumps(payload, separators=(",", ":"),
                                        sort_keys=True).encode("utf-8"))
    return f"{payload_b64}.{_sign(payload_b64, key)}"


def _build_payload(typ: str, user_id: str, session_id: str, jti: str,
                   now: float, ttl: int,
                   roles: set[str], permissions: set[str]) -> dict:
    payload: dict = {
        "typ": typ,
        "sub": user_id,
        "sid": session_id,
        "jti": jti,
        "iat": int(now),
        "exp": int(now) + ttl,
    }
    if typ == "access":
        payload["rol"] = sorted(roles)
        payload["perm"] = sorted(permissions)
    return payload


def issue_access_token(user_id: str, session_id: str, roles: set[str],
                       permissions: set[str], settings: Settings,
                       clock: Clock, jti: str | None = None) -> str:
    import secrets
    access_jti = "access-" + (jti or secrets.token_urlsafe(18))
    payload = _build_payload("access", user_id, session_id, access_jti,
                             clock.now(), settings.access_token_ttl,
                             roles, permissions)
    return _encode_payload(payload, settings.signing_key)


def issue_refresh_token(jti: str, user_id: str, session_id: str,
                        settings: Settings, clock: Clock) -> str:
    payload = _build_payload("refresh", user_id, session_id, jti,
                             clock.now(), settings.refresh_token_ttl, set(), set())
    return _encode_payload(payload, settings.signing_key)


def issue_token_pair(user_id: str, session_id: str, roles: set[str],
                     permissions: set[str], jti: str,
                     settings: Settings, clock: Clock) -> TokenPair:
    now = clock.now()
    access_payload = _build_payload(
        "access", user_id, session_id, "access-" + jti,
        now, settings.access_token_ttl, roles, permissions,
    )
    refresh_payload = _build_payload(
        "refresh", user_id, session_id, jti,
        now, settings.refresh_token_ttl, set(), set(),
    )
    return TokenPair(
        access_token=_encode_payload(access_payload, settings.signing_key),
        refresh_token=_encode_payload(refresh_payload, settings.signing_key),
    )


_REQUIRED_FIELDS = ("typ", "sub", "sid", "jti", "iat", "exp")


def verify_token(token: str, settings: Settings, clock: Clock,
                 *, expected_type: str | None = None) -> dict:
    """返回 payload；失败时抛出 TokenTampered / ClockSkew / TokenExpired。"""
    if not isinstance(token, str) or token.count(".") != 1:
        raise TokenTampered("令牌结构不合法")

    payload_b64, sig_b64 = token.split(".", 1)
    expected_sig = _sign(payload_b64, settings.signing_key)
    if not hmac.compare_digest(expected_sig, sig_b64):
        raise TokenTampered("令牌签名校验失败")

    try:
        payload = json.loads(_b64decode(payload_b64).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise TokenTampered("令牌载荷解码失败") from exc

    if not isinstance(payload, dict):
        raise TokenTampered("令牌载荷不是对象")
    for field in _REQUIRED_FIELDS:
        if field not in payload:
            raise TokenTampered(f"令牌缺少字段 {field}")
    if payload["typ"] not in ("access", "refresh"):
        raise TokenTampered("令牌类型未知")
    if expected_type is not None and payload["typ"] != expected_type:
        raise TokenTampered(
            f"令牌类型不匹配：期望 {expected_type}，实际 {payload['typ']}")

    now = clock.now()
    leeway = settings.clock_skew_leeway
    iat = float(payload["iat"])
    exp = float(payload["exp"])

    # 明显的时钟偏差：签发时间来自“未来”，超出容忍窗口。
    if iat > now + leeway:
        raise ClockSkew(detail={"iat": iat, "now": now, "leeway": leeway})

    # 过期判定也给予同样的容忍窗口。
    if now > exp + leeway:
        raise TokenExpired(detail={"exp": exp, "now": now, "leeway": leeway})

    return payload
